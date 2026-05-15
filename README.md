# AuditMesh

AuditMesh is a tamper-evident financial event logging project.
It benchmarks append-only logging designs and cryptographic verification pipelines under multiple attack scenarios.

## Core capabilities
- Baseline A: append-only CSV digest
- Baseline B: signed CSV digest
- Baseline C: hash-chain log
- Baseline D: signed hash-chain head
- Proposed: Merkle commitments + Ed25519 signatures + key registry
- Attack suite: insert, delete, modify, replay, truncate, reorder, timestamp manipulation, alternative view
- Workloads: uniform synthetic, calibrated financial-like synthetic, and public LANL authentication logs
- Streaming digest baselines and linear hash-chain prefix audit helpers
- Reproducible benchmark runner with multi-seed aggregation and scaling measurements

## Repository structure
```
.
├── src/
│   ├── baseline_csv.py
│   ├── baseline_hashchain.py
│   ├── signed_baselines.py
│   ├── merkle_signed_log.py
│   ├── attacks.py
│   ├── run_benchmark.py
│   ├── run_multiseed.py
│   └── run_scaling.py
├── tests/
│   ├── test_core.py
│   └── test_consistency_robustness.py
├── configs/
│   ├── key_registry.json
│   └── keys/
├── data/
│   ├── public/
│   └── processed/
├── results/
└── requirements.txt
```

## Quick start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -p "test_*.py"
python src/run_benchmark.py --num-events 1000 --seed 42 --run-id exp01
python src/run_multiseed.py --num-events 1000 --seeds 42,123,999 --run-prefix strengthened --workload calibrated
python src/run_scaling.py --sizes 1000,10000,100000 --seed 42 --run-id scale_strengthened --workload calibrated --trials 5
python src/run_scaling.py --sizes 1000000 --seed 42 --run-id scale_1m_calibrated --workload calibrated --trials 1
python src/run_nonequivocation.py --num-events 1024 --seed 42 --run-id nonequivocation_strengthened --workload calibrated
```

## Public Log-Like Dataset

AuditMesh can ingest the public LANL User-Computer Authentication Associations format (`time,user,computer`) and the LANL Comprehensive Multi-Source `auth.txt` format. The repository includes `data/public/lanl_auth_sample.csv`, a tiny LANL-format fixture for tests and smoke runs. For a full public-log run, download the LANL authentication data from `https://csr.lanl.gov/data/auth/` and pass the downloaded `.bz2`, `.gz`, or `.csv` file to the runner.

```bash
python src/run_benchmark.py --num-events 10 --seed 42 \
  --run-id lanl_public_smoke \
  --workload public_log \
  --event-source-path data/public/lanl_auth_sample.csv \
  --dataset-format lanl_auth_simple

python src/run_benchmark.py --num-events 10000 --seed 42 \
  --run-id lanl_public_10k \
  --workload public_log \
  --event-source-path /path/to/lanl-auth-dataset-1-00.bz2 \
  --dataset-format lanl_auth_simple

python src/run_scaling.py --sizes 1000,10000,100000 --seed 42 \
  --run-id lanl_public_scale --trials 5 \
  --workload public_log \
  --event-source-path /path/to/lanl-auth-dataset-1.bz2 \
  --dataset-format lanl_auth_simple

python src/run_scaling.py --sizes 1000000 --seed 42 \
  --run-id lanl_public_1m_scale --trials 1 \
  --workload public_log \
  --event-source-path data/public/lanl_full/lanl_auth_1m.csv \
  --dataset-format lanl_auth_simple
```

## Outputs
- `results/<run-id>/benchmark_results.csv`
- `results/<run-id>/benchmark_summary.json`
- `results/<run-id>/repro_manifest.json`
- `results/<run-prefix>_aggregate.csv`
- `results/<run-prefix>_aggregate.json`
- `results/<run-id>/scaling_results.csv`
- `results/<run-id>/scaling_results.json`
- `results/<run-id>/scaling_summary.csv`
- `results/<run-id>/scaling_summary.json`
- `results/<run-id>/proof_microbench_results.csv`
- `results/<run-id>/proof_microbench_results.json`
- `results/<run-id>/proof_microbench_summary.csv`
- `results/<run-id>/proof_microbench_summary.json`
- `results/<run-id>/selective_audit_overhead.csv`
- `results/<run-id>/selective_audit_overhead.json`
- `results/<run-id>/nonequivocation_results.csv`
- `results/<run-id>/nonequivocation_results.json`
- `results/<run-id>/nonequivocation_manifest.json`
- `results/<run-id>/scaling_manifest.json`

## Metrics
- tamper detection rate
- verification latency
- proof size
- storage/overhead ratios
- commitment time
- peak memory
- throughput
- inclusion-proof generation and verification latency
- consistency-proof generation and verification latency
- selected-record disclosure overhead for full-log, hash-chain prefix, and Merkle proof workflows
- two-auditor witness/gossip simulation for honest append, same-size split view, and unlinked divergent extension scenarios

## Notes
- CPU-only
- manifests include best-effort Python, OS, CPU, logical-core, filesystem, and storage-capacity metadata
- deterministic synthetic and calibrated financial-like event generation with fixed seed
- public-log workload support for LANL authentication rows and AuditMesh canonical CSV rows
- digest baselines stream events into SHA-256; hash-chain prefix audit is linear, not a compact Merkle-style proof
- scaling results include full-log verification plus Merkle inclusion-proof and consistency-proof microbenchmarks
- selective-audit overhead reports what must cross an audit boundary: full log for digest baselines, prefix for hash-chain baselines, and selected event plus Merkle inclusion proof for Merkle audit
- non-equivocation simulation detects observed split views after auditors exchange signed roots and consistency proofs; it is not a production monitor network
- consistency-proof microbenchmarks use one old-to-new pair per tree size, not long-lived rolling logs or many successive commitments
- tamper detection claims apply to the evaluated attack suite and implementation scope
