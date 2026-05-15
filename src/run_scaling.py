import argparse
import csv
import json
import os
import statistics
import time
import tracemalloc
from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

from baseline_csv import AppendOnlyCSVBaseline
from baseline_hashchain import HashChainBaseline
from common import Event, environment_snapshot, generate_events
from merkle_signed_log import KeyRegistry, MerkleSignedLog
from signed_baselines import SignedDigestBaseline, SignedHashChainBaseline


@dataclass
class ScalingRow:
    method: str
    num_events: int
    seed: int
    commit_time_ms: float
    verify_time_ms: float
    memory_peak_kb: float
    throughput_eps: float
    commitment_size_bytes: int
    proof_size_bytes: int
    clean_verified: int
    trial: int


@dataclass
class ProofMicrobenchRow:
    proof_type: str
    num_events: int
    old_size: int
    new_size: int
    index: int
    seed: int
    trial: int
    proof_hashes: int
    proof_size_bytes_json: int
    proof_payload_bytes_raw: int
    generation_time_ms: float
    verification_time_ms: float
    verified: int


@dataclass
class SelectiveAuditRow:
    num_events: int
    index: int
    seed: int
    selected_event_bytes: int
    full_log_disclosure_bytes: int
    hashchain_prefix_disclosure_bytes: int
    merkle_proof_bytes_json: int
    merkle_proof_payload_bytes_raw: int
    merkle_selective_disclosure_bytes_json: int
    merkle_selective_disclosure_bytes_raw: int
    digest_vs_merkle_json_ratio: float
    hashchain_prefix_vs_merkle_json_ratio: float


CommitFn = Callable[[List[Event]], Tuple[object, int, int]]
VerifyFn = Callable[[List[Event], object], Tuple[bool, int]]


def measure_method(
    method: str,
    events: List[Event],
    seed: int,
    registry: KeyRegistry,
    private_key_path: str,
    trial: int,
) -> ScalingRow:
    def commit_csv(xs: List[Event]) -> Tuple[object, int, int]:
        c = AppendOnlyCSVBaseline.commit(xs)
        return c, len(c.encode("utf-8")), 0

    def verify_csv(xs: List[Event], c: object) -> Tuple[bool, int]:
        return AppendOnlyCSVBaseline.verify(xs, c)

    def commit_signed_digest(xs: List[Event]) -> Tuple[object, int, int]:
        c = SignedDigestBaseline.commit(xs, private_key_path, registry.active_key_id)
        return c, len(json.dumps(c.to_dict(), sort_keys=True).encode("utf-8")), 0

    def verify_signed_digest(xs: List[Event], c: object) -> Tuple[bool, int]:
        return SignedDigestBaseline.verify(xs, c, registry)

    def commit_hashchain(xs: List[Event]) -> Tuple[object, int, int]:
        c = HashChainBaseline.build_chain(xs)
        return c, len(c.head_hash.encode("utf-8")), 32

    def verify_hashchain(xs: List[Event], c: object) -> Tuple[bool, int]:
        return HashChainBaseline.verify(xs, c)

    def commit_signed_hashchain(xs: List[Event]) -> Tuple[object, int, int]:
        c = SignedHashChainBaseline.commit(xs, private_key_path, registry.active_key_id)
        return c, len(json.dumps(c.to_dict(), sort_keys=True).encode("utf-8")), 32

    def verify_signed_hashchain(xs: List[Event], c: object) -> Tuple[bool, int]:
        return SignedHashChainBaseline.verify(xs, c, registry)

    def commit_merkle(xs: List[Event]) -> Tuple[object, int, int]:
        c = MerkleSignedLog.commit(xs, private_key_path, registry.active_key_id)
        proof = MerkleSignedLog.gen_inclusion_proof(xs, 0)
        return c, len(json.dumps(c.to_dict(), sort_keys=True).encode("utf-8")), len(json.dumps(proof).encode("utf-8"))

    def verify_merkle(xs: List[Event], c: object) -> Tuple[bool, int]:
        return MerkleSignedLog.verify(xs, c, registry)

    committers: Dict[str, CommitFn] = {
        "csv": commit_csv,
        "signed_digest": commit_signed_digest,
        "hashchain": commit_hashchain,
        "signed_hashchain": commit_signed_hashchain,
        "merkle_signed": commit_merkle,
    }
    verifiers: Dict[str, VerifyFn] = {
        "csv": verify_csv,
        "signed_digest": verify_signed_digest,
        "hashchain": verify_hashchain,
        "signed_hashchain": verify_signed_hashchain,
        "merkle_signed": verify_merkle,
    }

    tracemalloc.start()
    t0 = time.perf_counter()
    commitment, commitment_size, proof_size = committers[method](events)
    commit_time_ms = (time.perf_counter() - t0) * 1000.0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    t1 = time.perf_counter()
    ok, verifier_proof = verifiers[method](events, commitment)
    verify_time_ms = (time.perf_counter() - t1) * 1000.0
    if verifier_proof and method != "merkle_signed":
        proof_size = verifier_proof

    return ScalingRow(
        method=method,
        num_events=len(events),
        seed=seed,
        commit_time_ms=commit_time_ms,
        verify_time_ms=verify_time_ms,
        memory_peak_kb=peak / 1024.0,
        throughput_eps=len(events) / max(1e-9, commit_time_ms / 1000.0),
        commitment_size_bytes=commitment_size,
        proof_size_bytes=proof_size,
        clean_verified=1 if ok else 0,
        trial=trial,
    )


def summarize(rows: List[ScalingRow]) -> List[Dict]:
    out = []
    keys = sorted({(row.method, row.num_events) for row in rows}, key=lambda x: (x[1], x[0]))
    for method, size in keys:
        subset = [row for row in rows if row.method == method and row.num_events == size]
        commits = [row.commit_time_ms for row in subset]
        verifies = [row.verify_time_ms for row in subset]
        memory = [row.memory_peak_kb for row in subset]
        throughput = [row.throughput_eps for row in subset]
        out.append(
            {
                "method": method,
                "num_events": size,
                "trials": len(subset),
                "commit_time_ms_median": statistics.median(commits),
                "commit_time_ms_mean": statistics.fmean(commits),
                "verify_time_ms_median": statistics.median(verifies),
                "verify_time_ms_mean": statistics.fmean(verifies),
                "memory_peak_kb_median": statistics.median(memory),
                "throughput_eps_median": statistics.median(throughput),
                "commitment_size_bytes": subset[0].commitment_size_bytes,
                "proof_size_bytes": subset[0].proof_size_bytes,
                "clean_verified_all": int(all(row.clean_verified for row in subset)),
            }
        )
    return out


def measure_proof_microbenchmarks(
    events: List[Event],
    commitment: object,
    seed: int,
    registry: KeyRegistry,
    private_key_path: str,
    trial: int,
) -> List[ProofMicrobenchRow]:
    if not events:
        return []

    index = len(events) // 2
    rows: List[ProofMicrobenchRow] = []

    t0 = time.perf_counter()
    inclusion_proof = MerkleSignedLog.gen_inclusion_proof(events, index)
    inclusion_generation_ms = (time.perf_counter() - t0) * 1000.0

    t1 = time.perf_counter()
    inclusion_ok = MerkleSignedLog.verify_inclusion_proof(
        events[index],
        index,
        inclusion_proof,
        commitment.root_hash,
    )
    inclusion_verification_ms = (time.perf_counter() - t1) * 1000.0

    rows.append(
        ProofMicrobenchRow(
            proof_type="inclusion",
            num_events=len(events),
            old_size=0,
            new_size=len(events),
            index=index,
            seed=seed,
            trial=trial,
            proof_hashes=len(inclusion_proof),
            proof_size_bytes_json=len(json.dumps(inclusion_proof, sort_keys=True).encode("utf-8")),
            proof_payload_bytes_raw=32 * len(inclusion_proof),
            generation_time_ms=inclusion_generation_ms,
            verification_time_ms=inclusion_verification_ms,
            verified=1 if inclusion_ok else 0,
        )
    )

    old_size = max(1, len(events) // 2)
    old_events = events[:old_size]

    t2 = time.perf_counter()
    consistency_proof = MerkleSignedLog.gen_consistency_proof(
        old_events,
        events,
        private_key_path=private_key_path,
        key_id=registry.active_key_id,
    )
    consistency_generation_ms = (time.perf_counter() - t2) * 1000.0
    consistency_json_bytes = len(json.dumps(consistency_proof, sort_keys=True).encode("utf-8"))
    consistency_raw_bytes = 32 * len(consistency_proof["proof_hashes"])

    t3 = time.perf_counter()
    consistency_internal_ok = MerkleSignedLog.verify_consistency_proof(consistency_proof, events)
    consistency_internal_ms = (time.perf_counter() - t3) * 1000.0
    rows.append(
        ProofMicrobenchRow(
            proof_type="consistency_internal",
            num_events=len(events),
            old_size=old_size,
            new_size=len(events),
            index=-1,
            seed=seed,
            trial=trial,
            proof_hashes=len(consistency_proof["proof_hashes"]),
            proof_size_bytes_json=consistency_json_bytes,
            proof_payload_bytes_raw=consistency_raw_bytes,
            generation_time_ms=consistency_generation_ms,
            verification_time_ms=consistency_internal_ms,
            verified=1 if consistency_internal_ok else 0,
        )
    )

    t4 = time.perf_counter()
    consistency_external_ok = MerkleSignedLog.verify_consistency_proof_external(consistency_proof, registry)
    consistency_external_ms = (time.perf_counter() - t4) * 1000.0
    rows.append(
        ProofMicrobenchRow(
            proof_type="consistency_external",
            num_events=len(events),
            old_size=old_size,
            new_size=len(events),
            index=-1,
            seed=seed,
            trial=trial,
            proof_hashes=len(consistency_proof["proof_hashes"]),
            proof_size_bytes_json=consistency_json_bytes,
            proof_payload_bytes_raw=consistency_raw_bytes,
            generation_time_ms=0.0,
            verification_time_ms=consistency_external_ms,
            verified=1 if consistency_external_ok else 0,
        )
    )

    return rows


def summarize_proof_microbenchmarks(rows: List[ProofMicrobenchRow]) -> List[Dict]:
    out = []
    keys = sorted({(row.proof_type, row.num_events) for row in rows}, key=lambda x: (x[1], x[0]))
    for proof_type, size in keys:
        subset = [row for row in rows if row.proof_type == proof_type and row.num_events == size]
        generations = [row.generation_time_ms for row in subset]
        verifications = [row.verification_time_ms for row in subset]
        out.append(
            {
                "proof_type": proof_type,
                "num_events": size,
                "old_size": subset[0].old_size,
                "new_size": subset[0].new_size,
                "trials": len(subset),
                "proof_hashes": subset[0].proof_hashes,
                "proof_size_bytes_json": subset[0].proof_size_bytes_json,
                "proof_payload_bytes_raw": subset[0].proof_payload_bytes_raw,
                "generation_time_ms_median": statistics.median(generations),
                "generation_time_ms_mean": statistics.fmean(generations),
                "verification_time_ms_median": statistics.median(verifications),
                "verification_time_ms_mean": statistics.fmean(verifications),
                "verified_all": int(all(row.verified for row in subset)),
            }
        )
    return out


def measure_selective_audit_overhead(events: List[Event], seed: int) -> SelectiveAuditRow:
    if not events:
        raise ValueError("events must be non-empty")

    index = len(events) // 2
    selected_event_bytes = len(events[index].canonical_json().encode("utf-8"))
    full_log_bytes = sum(len(event.canonical_json().encode("utf-8")) for event in events)
    prefix_bytes = sum(len(event.canonical_json().encode("utf-8")) for event in events[: index + 1])
    inclusion_proof = MerkleSignedLog.gen_inclusion_proof(events, index)
    proof_json_bytes = len(json.dumps(inclusion_proof, sort_keys=True).encode("utf-8"))
    proof_raw_bytes = 32 * len(inclusion_proof)
    merkle_json_bytes = selected_event_bytes + proof_json_bytes
    merkle_raw_bytes = selected_event_bytes + proof_raw_bytes

    return SelectiveAuditRow(
        num_events=len(events),
        index=index,
        seed=seed,
        selected_event_bytes=selected_event_bytes,
        full_log_disclosure_bytes=full_log_bytes,
        hashchain_prefix_disclosure_bytes=prefix_bytes,
        merkle_proof_bytes_json=proof_json_bytes,
        merkle_proof_payload_bytes_raw=proof_raw_bytes,
        merkle_selective_disclosure_bytes_json=merkle_json_bytes,
        merkle_selective_disclosure_bytes_raw=merkle_raw_bytes,
        digest_vs_merkle_json_ratio=full_log_bytes / max(1, merkle_json_bytes),
        hashchain_prefix_vs_merkle_json_ratio=prefix_bytes / max(1, merkle_json_bytes),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="1000,10000,100000")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--run-id", default="scale")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--workload", choices=["synthetic", "calibrated", "public_log"], default="synthetic")
    parser.add_argument("--event-source-path", default="")
    parser.add_argument(
        "--dataset-format",
        choices=["auditmesh_csv", "lanl_auth_simple", "lanl_auth_full"],
        default="auditmesh_csv",
    )
    args = parser.parse_args()

    sizes = [int(x.strip()) for x in args.sizes.split(",") if x.strip()]
    methods = ["csv", "signed_digest", "hashchain", "signed_hashchain", "merkle_signed"]
    registry_path = os.path.join("configs", "key_registry.json")
    key_dir = os.path.join("configs", "keys")
    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_key_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")
    out_dir = os.path.join("results", args.run_id)
    os.makedirs(out_dir, exist_ok=True)

    rows: List[ScalingRow] = []
    proof_rows: List[ProofMicrobenchRow] = []
    for size in sizes:
        events = generate_events(
            size,
            args.seed,
            args.workload,
            event_source_path=args.event_source_path,
            dataset_format=args.dataset_format,
        )
        for method in methods:
            for trial in range(args.trials):
                rows.append(measure_method(method, events, args.seed, registry, private_key_path, trial))
        commitment = MerkleSignedLog.commit(events, private_key_path, registry.active_key_id)
        for trial in range(args.trials):
            proof_rows.extend(
                measure_proof_microbenchmarks(
                    events,
                    commitment,
                    args.seed,
                    registry,
                    private_key_path,
                    trial,
                )
            )

    csv_path = os.path.join(out_dir, "scaling_results.csv")
    json_path = os.path.join(out_dir, "scaling_results.json")
    summary_csv_path = os.path.join(out_dir, "scaling_summary.csv")
    summary_json_path = os.path.join(out_dir, "scaling_summary.json")
    proof_csv_path = os.path.join(out_dir, "proof_microbench_results.csv")
    proof_json_path = os.path.join(out_dir, "proof_microbench_results.json")
    proof_summary_csv_path = os.path.join(out_dir, "proof_microbench_summary.csv")
    proof_summary_json_path = os.path.join(out_dir, "proof_microbench_summary.json")
    selective_csv_path = os.path.join(out_dir, "selective_audit_overhead.csv")
    selective_json_path = os.path.join(out_dir, "selective_audit_overhead.json")
    manifest_path = os.path.join(out_dir, "scaling_manifest.json")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].__dict__.keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row.__dict__)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump([row.__dict__ for row in rows], f, indent=2, sort_keys=True)
    summary = summarize(rows)
    with open(summary_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
        writer.writeheader()
        for row in summary:
            writer.writerow(row)
    with open(summary_json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    with open(proof_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(proof_rows[0].__dict__.keys()))
        writer.writeheader()
        for row in proof_rows:
            writer.writerow(row.__dict__)
    with open(proof_json_path, "w", encoding="utf-8") as f:
        json.dump([row.__dict__ for row in proof_rows], f, indent=2, sort_keys=True)
    proof_summary = summarize_proof_microbenchmarks(proof_rows)
    with open(proof_summary_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(proof_summary[0].keys()))
        writer.writeheader()
        for row in proof_summary:
            writer.writerow(row)
    with open(proof_summary_json_path, "w", encoding="utf-8") as f:
        json.dump(proof_summary, f, indent=2, sort_keys=True)
    selective_rows = [
        measure_selective_audit_overhead(
            generate_events(
                size,
                args.seed,
                args.workload,
                event_source_path=args.event_source_path,
                dataset_format=args.dataset_format,
            ),
            args.seed,
        )
        for size in sizes
    ]
    with open(selective_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(selective_rows[0].__dict__.keys()))
        writer.writeheader()
        for row in selective_rows:
            writer.writerow(row.__dict__)
    with open(selective_json_path, "w", encoding="utf-8") as f:
        json.dump([row.__dict__ for row in selective_rows], f, indent=2, sort_keys=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "run_config": {
                    "sizes": sizes,
                    "seed": args.seed,
                    "run_id": args.run_id,
                    "trials": args.trials,
                    "workload": args.workload,
                    "event_source_path": args.event_source_path,
                    "dataset_format": args.dataset_format,
                    "methods": methods,
                },
                "environment": environment_snapshot(),
                "measurement_scope": {
                    "full_log_scaling": True,
                    "inclusion_proof_microbenchmarks": True,
                    "consistency_proof_microbenchmarks": True,
                    "selective_audit_overhead": True,
                    "multi_commitment_consistency_scaling": False,
                    "proof_microbenchmark_notes": (
                        "Inclusion benchmarks verify the middle event against a committed root. "
                        "Consistency benchmarks use an old tree of floor(n/2) events and a new tree of n events; "
                        "internal verification checks against the new event list, while external verification "
                        "checks the signed proof object and key registry only. The artifact does not yet measure "
                        "long-lived rolling logs or many successive consistency proofs over multi-commit trajectories."
                    ),
                },
            },
            f,
            indent=2,
            sort_keys=True,
        )
    print(
        json.dumps(
            {
                "scaling_csv": csv_path,
                "scaling_json": json_path,
                "summary_csv": summary_csv_path,
                "summary_json": summary_json_path,
                "proof_microbench_csv": proof_csv_path,
                "proof_microbench_json": proof_json_path,
                "proof_microbench_summary_csv": proof_summary_csv_path,
                "proof_microbench_summary_json": proof_summary_json_path,
                "selective_audit_csv": selective_csv_path,
                "selective_audit_json": selective_json_path,
                "manifest": manifest_path,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
