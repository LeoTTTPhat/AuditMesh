import argparse
import csv
import json
import os
from dataclasses import asdict
from typing import Dict, List

from attacks import AttackSuite
from common import environment_snapshot, generate_events, write_json
from merkle_signed_log import KeyRegistry, MerkleSignedLog
from non_equivocation import CommitmentObservation, MultiPartyNonEquivocationMonitor


def scenario_row(name: str, observations: List[CommitmentObservation], proofs: List[Dict], registry: KeyRegistry) -> Dict:
    findings = MultiPartyNonEquivocationMonitor.assess(observations, proofs, registry)
    return {
        "scenario": name,
        "auditors": len({obs.auditor_id for obs in observations}),
        "observed_commitments": len(observations),
        "signed_consistency_proofs": len(proofs),
        "findings": len(findings),
        "finding_types": ",".join(sorted({finding.finding_type for finding in findings})) or "none",
        "detected_non_equivocation_violation": int(bool(findings)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--num-events", type=int, default=1024)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--run-id", default="nonequivocation")
    parser.add_argument("--workload", choices=["synthetic", "calibrated", "public_log"], default="calibrated")
    parser.add_argument("--event-source-path", default="")
    parser.add_argument(
        "--dataset-format",
        choices=["auditmesh_csv", "lanl_auth_simple", "lanl_auth_full"],
        default="auditmesh_csv",
    )
    args = parser.parse_args()

    if args.num_events < 4:
        raise ValueError("--num-events must be at least 4")

    registry_path = os.path.join("configs", "key_registry.json")
    key_dir = os.path.join("configs", "keys")
    registry = KeyRegistry.init_or_load(registry_path, key_dir)
    private_key_path = os.path.join(key_dir, f"{registry.active_key_id}_private.pem")
    out_dir = os.path.join("results", args.run_id)
    os.makedirs(out_dir, exist_ok=True)

    events = generate_events(
        args.num_events,
        args.seed,
        args.workload,
        event_source_path=args.event_source_path,
        dataset_format=args.dataset_format,
    )
    half = args.num_events // 2
    prefix = events[:half]
    full = events
    fork = AttackSuite.alternative_view(full, args.seed)

    prefix_commitment = MerkleSignedLog.commit(prefix, private_key_path, registry.active_key_id)
    full_commitment = MerkleSignedLog.commit(full, private_key_path, registry.active_key_id)
    fork_commitment = MerkleSignedLog.commit(fork, private_key_path, registry.active_key_id)
    honest_proof = MerkleSignedLog.gen_consistency_proof(
        prefix,
        full,
        private_key_path=private_key_path,
        key_id=registry.active_key_id,
    )

    rows = [
        scenario_row(
            "honest_shared_append",
            [
                CommitmentObservation("auditor-a", 1, prefix_commitment),
                CommitmentObservation("auditor-b", 2, full_commitment),
            ],
            [honest_proof],
            registry,
        ),
        scenario_row(
            "same_size_split_view",
            [
                CommitmentObservation("auditor-a", 2, full_commitment),
                CommitmentObservation("auditor-b", 2, fork_commitment),
            ],
            [],
            registry,
        ),
        scenario_row(
            "unlinked_divergent_extension",
            [
                CommitmentObservation("auditor-a", 1, prefix_commitment),
                CommitmentObservation("auditor-b", 2, fork_commitment),
            ],
            [],
            registry,
        ),
    ]

    csv_path = os.path.join(out_dir, "nonequivocation_results.csv")
    json_path = os.path.join(out_dir, "nonequivocation_results.json")
    manifest_path = os.path.join(out_dir, "nonequivocation_manifest.json")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    write_json(json_path, rows)
    write_json(
        manifest_path,
        {
            "run_config": vars(args),
            "environment": environment_snapshot(),
            "scope": (
                "Local two-auditor witness/gossip simulation over signed Merkle commitments. "
                "This detects observed split views and missing/invalid consistency edges, but it is "
                "not a production monitor network."
            ),
        },
    )
    print(json.dumps({"csv": csv_path, "json": json_path, "manifest": manifest_path, "rows": rows}, indent=2))


if __name__ == "__main__":
    main()
