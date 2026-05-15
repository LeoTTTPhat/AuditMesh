import argparse
import csv
import json
import os
import sys
import time
import tracemalloc
from dataclasses import dataclass
from typing import Callable, Dict, List

from attacks import AttackSuite
from baseline_csv import AppendOnlyCSVBaseline
from baseline_hashchain import HashChainBaseline
from common import Event, environment_snapshot, file_size, generate_events, sha256_hex, write_events_csv, write_json
from merkle_signed_log import KeyRegistry, MerkleSignedLog
from signed_baselines import SignedDigestBaseline, SignedHashChainBaseline


@dataclass
class EvalResult:
    method: str
    attack: str
    detected: int
    verification_latency_ms: float
    proof_size_bytes: int
    commitment_size_bytes: int
    attacked_log_size_bytes: int
    artifact_overhead_ratio: float
    commit_time_ms: float
    memory_peak_kb: float
    throughput_eps: float


AttackFn = Callable[[List[Event], int], List[Event]]


def evaluate_one_method(
    method_name: str,
    clean_events: List[Event],
    attacks: Dict[str, AttackFn],
    clean_log_path: str,
    output_dir: str,
    seed: int,
    registry: KeyRegistry,
    private_key_path: str,
) -> List[EvalResult]:
    results: List[EvalResult] = []

    # --- Measure commit time and memory ---
    tracemalloc.start()
    t_commit_start = time.perf_counter()

    if method_name == "csv":
        commitment = AppendOnlyCSVBaseline.commit(clean_events)
        verify_fn = lambda events: AppendOnlyCSVBaseline.verify(events, commitment)  # noqa: E731
        commitment_bytes = len(commitment.encode("utf-8"))
        sample_proof_bytes = 0
    elif method_name == "signed_digest":
        commitment = SignedDigestBaseline.commit(clean_events, private_key_path, registry.active_key_id)
        verify_fn = lambda events: SignedDigestBaseline.verify(events, commitment, registry)  # noqa: E731
        commitment_bytes = len(json.dumps(commitment.to_dict(), sort_keys=True).encode("utf-8"))
        sample_proof_bytes = 0
    elif method_name == "hashchain":
        commitment = HashChainBaseline.build_chain(clean_events)
        verify_fn = lambda events: HashChainBaseline.verify(events, commitment)  # noqa: E731
        commitment_bytes = len(commitment.head_hash.encode("utf-8"))
        sample_proof_bytes = 32
    elif method_name == "signed_hashchain":
        commitment = SignedHashChainBaseline.commit(clean_events, private_key_path, registry.active_key_id)
        verify_fn = lambda events: SignedHashChainBaseline.verify(events, commitment, registry)  # noqa: E731
        commitment_bytes = len(json.dumps(commitment.to_dict(), sort_keys=True).encode("utf-8"))
        sample_proof_bytes = 32
    elif method_name == "merkle_signed":
        commitment = MerkleSignedLog.commit(clean_events, private_key_path=private_key_path, key_id=registry.active_key_id)
        verify_fn = lambda events: MerkleSignedLog.verify(events, commitment, registry)  # noqa: E731
        sample_proof = MerkleSignedLog.gen_inclusion_proof(clean_events, 0)
        sample_proof_bytes = len(json.dumps(sample_proof).encode("utf-8"))
        commitment_bytes = len(json.dumps(commitment.to_dict(), sort_keys=True).encode("utf-8"))
    else:
        tracemalloc.stop()
        raise ValueError(f"Unknown method: {method_name}")

    commit_time_ms = (time.perf_counter() - t_commit_start) * 1000.0
    _, memory_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    memory_peak_kb = memory_peak / 1024.0
    throughput_eps = len(clean_events) / max(1e-9, commit_time_ms / 1000.0)

    clean_ok, _ = verify_fn(clean_events)
    if not clean_ok:
        raise RuntimeError(f"Clean verification failed for {method_name}")

    for attack_name, attack_fn in attacks.items():
        attacked_events = attack_fn(clean_events, seed)
        t0 = time.perf_counter()
        ok, _ = verify_fn(attacked_events)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        attacked_path = os.path.join(output_dir, f"{method_name}_{attack_name}.csv")
        write_events_csv(attacked_path, attacked_events)
        clean_size = file_size(clean_log_path)
        # Overhead: (clean log + commitment + proof) / clean log — always >= 1.0
        overhead = (clean_size + commitment_bytes + sample_proof_bytes) / max(1, clean_size)
        results.append(
            EvalResult(
                method=method_name,
                attack=attack_name,
                detected=0 if ok else 1,
                verification_latency_ms=latency_ms,
                proof_size_bytes=sample_proof_bytes,
                commitment_size_bytes=commitment_bytes,
                attacked_log_size_bytes=file_size(attacked_path),
                artifact_overhead_ratio=overhead,
                commit_time_ms=commit_time_ms,
                memory_peak_kb=memory_peak_kb,
                throughput_eps=throughput_eps,
            )
        )
    return results


def save_results(path: str, rows: List[EvalResult]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "method",
                "attack",
                "detected",
                "verification_latency_ms",
                "proof_size_bytes",
                "commitment_size_bytes",
                "attacked_log_size_bytes",
                "artifact_overhead_ratio",
                "commit_time_ms",
                "memory_peak_kb",
                "throughput_eps",
            ],
        )
        writer.writeheader()
        for r in rows:
            writer.writerow(r.__dict__)


def summarize(rows: List[EvalResult]) -> Dict:
    summary: Dict[str, Dict] = {}
    for method in sorted({r.method for r in rows}):
        subset = [r for r in rows if r.method == method]
        det_rate = sum(r.detected for r in subset) / max(1, len(subset))
        avg_latency = sum(r.verification_latency_ms for r in subset) / max(1, len(subset))
        avg_proof = sum(r.proof_size_bytes for r in subset) / max(1, len(subset))
        avg_commitment = sum(r.commitment_size_bytes for r in subset) / max(1, len(subset))
        avg_log = sum(r.attacked_log_size_bytes for r in subset) / max(1, len(subset))
        avg_overhead = sum(r.artifact_overhead_ratio for r in subset) / max(1, len(subset))
        avg_commit_time = sum(r.commit_time_ms for r in subset) / max(1, len(subset))
        avg_memory = sum(r.memory_peak_kb for r in subset) / max(1, len(subset))
        avg_throughput = sum(r.throughput_eps for r in subset) / max(1, len(subset))
        summary[method] = {
            "tamper_detection_rate": det_rate,
            "avg_verification_latency_ms": avg_latency,
            "avg_proof_size_bytes": avg_proof,
            "avg_commitment_size_bytes": avg_commitment,
            "avg_attacked_log_size_bytes": avg_log,
            "avg_artifact_overhead_ratio": avg_overhead,
            "avg_commit_time_ms": avg_commit_time,
            "avg_memory_peak_kb": avg_memory,
            "avg_throughput_eps": avg_throughput,
        }
    return summary


def write_manifest(path: str, args: argparse.Namespace, results_dir: str) -> None:
    result_csv = os.path.join(results_dir, "benchmark_results.csv")
    result_json = os.path.join(results_dir, "benchmark_summary.json")
    payload = {
        "run_config": {
            "num_events": args.num_events,
            "seed": args.seed,
            "run_id": args.run_id,
            "workload": args.workload,
            "event_source_path": args.event_source_path,
            "dataset_format": args.dataset_format,
        },
        "environment": environment_snapshot(),
        "checksums": {
            "benchmark_results_csv_sha256": sha256_hex(open(result_csv, "r", encoding="utf-8").read()),
            "benchmark_summary_json_sha256": sha256_hex(open(result_json, "r", encoding="utf-8").read()),
        },
    }
    write_json(path, payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-events", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--run-id", type=str, default=None)
    parser.add_argument("--workload", choices=["synthetic", "calibrated", "public_log"], default="synthetic")
    parser.add_argument("--event-source-path", default="")
    parser.add_argument(
        "--dataset-format",
        choices=["auditmesh_csv", "lanl_auth_simple", "lanl_auth_full"],
        default="auditmesh_csv",
    )
    args = parser.parse_args()
    if args.num_events <= 0:
        raise ValueError("--num-events must be > 0")

    run_id = args.run_id if args.run_id else str(int(time.time() * 1000))
    args.run_id = run_id
    processed_dir = os.path.join("data", "processed", run_id)
    results_dir = os.path.join("results", run_id)
    key_dir = os.path.join("configs", "keys")
    registry_path = os.path.join("configs", "key_registry.json")
    os.makedirs(processed_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)
    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_key_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")

    events = generate_events(
        args.num_events,
        args.seed,
        args.workload,
        event_source_path=args.event_source_path,
        dataset_format=args.dataset_format,
    )
    clean_path = os.path.join(processed_dir, "clean_events.csv")
    write_events_csv(clean_path, events)

    attacks: Dict[str, AttackFn] = {
        "insert": AttackSuite.insert,
        "delete": AttackSuite.delete,
        "modify": AttackSuite.modify,
        "replay": AttackSuite.replay,
        "truncate": AttackSuite.truncate,
        "reorder": AttackSuite.reorder,
        "timestamp": AttackSuite.timestamp_manipulate,
        "alternative_view": AttackSuite.alternative_view,
    }

    rows: List[EvalResult] = []
    for method in ["csv", "signed_digest", "hashchain", "signed_hashchain", "merkle_signed"]:
        rows.extend(
            evaluate_one_method(
                method,
                events,
                attacks,
                clean_path,
                processed_dir,
                seed=args.seed,
                registry=registry,
                private_key_path=private_key_path,
            )
        )

    save_results(os.path.join(results_dir, "benchmark_results.csv"), rows)
    summary = summarize(rows)
    write_json(os.path.join(results_dir, "benchmark_summary.json"), summary)
    write_manifest(os.path.join(results_dir, "repro_manifest.json"), args, results_dir)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
