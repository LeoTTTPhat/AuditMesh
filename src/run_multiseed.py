import argparse
import csv
import json
import math
import os
import subprocess
import sys
from typing import Dict, List


def mean(xs: List[float]) -> float:
    return sum(xs) / max(1, len(xs))


def stdev(xs: List[float]) -> float:
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    var = sum((x - m) ** 2 for x in xs) / (len(xs) - 1)
    return math.sqrt(var)


def ci95(xs: List[float]) -> float:
    if len(xs) < 2:
        return 0.0
    return 1.96 * stdev(xs) / math.sqrt(len(xs))


def load_summary(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-events", type=int, default=1000)
    parser.add_argument("--seeds", type=str, default="42,123,999")
    parser.add_argument("--run-prefix", type=str, default="ms")
    parser.add_argument("--workload", choices=["synthetic", "calibrated", "public_log"], default="synthetic")
    parser.add_argument("--event-source-path", default="")
    parser.add_argument(
        "--dataset-format",
        choices=["auditmesh_csv", "lanl_auth_simple", "lanl_auth_full"],
        default="auditmesh_csv",
    )
    args = parser.parse_args()

    seeds = [int(x.strip()) for x in args.seeds.split(",") if x.strip()]
    methods = ["csv", "signed_digest", "hashchain", "signed_hashchain", "merkle_signed"]
    metrics = [
        "tamper_detection_rate",
        "avg_verification_latency_ms",
        "avg_proof_size_bytes",
        "avg_commitment_size_bytes",
        "avg_attacked_log_size_bytes",
        "avg_artifact_overhead_ratio",
        "avg_commit_time_ms",
        "avg_memory_peak_kb",
        "avg_throughput_eps",
    ]

    per_seed: Dict[int, Dict] = {}
    for seed in seeds:
        run_id = f"{args.run_prefix}_s{seed}"
        cmd = [
            sys.executable,
            "src/run_benchmark.py",
            "--num-events",
            str(args.num_events),
            "--seed",
            str(seed),
            "--run-id",
            run_id,
            "--workload",
            args.workload,
            "--event-source-path",
            args.event_source_path,
            "--dataset-format",
            args.dataset_format,
        ]
        subprocess.run(cmd, check=True)
        summary_path = os.path.join("results", run_id, "benchmark_summary.json")
        per_seed[seed] = load_summary(summary_path)

    agg_rows = []
    for method in methods:
        row = {"method": method}
        for metric in metrics:
            values = [float(per_seed[s][method][metric]) for s in seeds]
            row[f"{metric}_mean"] = mean(values)
            row[f"{metric}_std"] = stdev(values)
            row[f"{metric}_ci95"] = ci95(values)
        agg_rows.append(row)

    out_csv = os.path.join("results", f"{args.run_prefix}_aggregate.csv")
    out_json = os.path.join("results", f"{args.run_prefix}_aggregate.json")
    os.makedirs("results", exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(agg_rows[0].keys()))
        writer.writeheader()
        for row in agg_rows:
            writer.writerow(row)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"seeds": seeds, "rows": agg_rows}, f, indent=2, sort_keys=True)
    print(json.dumps({"seeds": seeds, "aggregate_csv": out_csv, "aggregate_json": out_json}, indent=2))


if __name__ == "__main__":
    main()
