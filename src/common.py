import bz2
import csv
import gzip
import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Optional, TextIO


@dataclass
class Event:
    event_id: int
    timestamp: int
    account_id: str
    amount: float
    currency: str
    event_type: str
    reference: str

    def canonical_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _run_env_command(cmd: List[str]) -> Optional[str]:
    if not shutil.which(cmd[0]):
        return None
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=2)
    except Exception:
        return None
    return out.strip() or None


def environment_snapshot() -> Dict:
    """Best-effort hardware and runtime metadata for reproducibility."""
    cpu_model = platform.processor() or platform.machine()
    if platform.system() == "Darwin":
        cpu_model = _run_env_command(["sysctl", "-n", "machdep.cpu.brand_string"]) or cpu_model
    elif platform.system() == "Linux":
        lscpu = _run_env_command(["lscpu"])
        if lscpu:
            for line in lscpu.splitlines():
                if line.lower().startswith("model name:"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    disk = shutil.disk_usage(os.getcwd())
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_model": cpu_model,
        "cpu_count_logical": os.cpu_count(),
        "filesystem_cwd": os.getcwd(),
        "storage_total_bytes": disk.total,
        "storage_free_bytes": disk.free,
        "timing_notes": "CPU-only Python wall-clock timings; storage device model and background load are not controlled.",
    }


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def write_events_csv(path: str, events: List[Event]) -> None:
    ensure_parent_dir(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(events[0]).keys()))
        writer.writeheader()
        for e in events:
            writer.writerow(asdict(e))


def read_events_csv(path: str) -> List[Event]:
    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        out: List[Event] = []
        for row in reader:
            out.append(
                Event(
                    event_id=int(row["event_id"]),
                    timestamp=int(row["timestamp"]),
                    account_id=row["account_id"],
                    amount=float(row["amount"]),
                    currency=row["currency"],
                    event_type=row["event_type"],
                    reference=row["reference"],
                )
            )
    return out


def _open_text_auto(path: str) -> TextIO:
    if path.endswith(".bz2"):
        return bz2.open(path, "rt", encoding="utf-8", newline="")
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return open(path, "r", encoding="utf-8", newline="")


def _iter_rows(path: str, has_header: bool) -> Iterable[List[str]]:
    with _open_text_auto(path) as f:
        reader = csv.reader(f)
        if has_header:
            next(reader, None)
        for row in reader:
            if row:
                yield [cell.strip() for cell in row]


def read_lanl_auth_simple(path: str, max_events: int) -> List[Event]:
    """Read LANL User-Computer Authentication Associations rows.

    Public format: time,user,computer. The values are anonymized, so the
    benchmark maps them into the common Event schema without treating the
    numeric amount field as a financial value.
    """
    events: List[Event] = []
    for row in _iter_rows(path, has_header=False):
        if len(row) < 3:
            continue
        timestamp, user, computer = row[:3]
        events.append(
            Event(
                event_id=len(events) + 1,
                timestamp=int(timestamp),
                account_id=user,
                amount=1.0,
                currency="LOG",
                event_type="AUTH_SUCCESS",
                reference=computer,
            )
        )
        if len(events) >= max_events:
            break
    return events


def read_lanl_auth_full(path: str, max_events: int) -> List[Event]:
    """Read LANL Comprehensive Multi-Source auth.txt rows.

    Public format: time,source user,destination user,source computer,
    destination computer,authentication type,logon type,authentication
    orientation,success/failure.
    """
    events: List[Event] = []
    for row in _iter_rows(path, has_header=False):
        if len(row) < 9:
            continue
        timestamp, source_user, dest_user, source_computer, dest_computer, auth_type, logon_type, orientation, outcome = row[:9]
        normalized_outcome = outcome.upper().replace("/", "_").replace(" ", "_")
        events.append(
            Event(
                event_id=len(events) + 1,
                timestamp=int(timestamp),
                account_id=source_user,
                amount=1.0 if normalized_outcome == "SUCCESS" else 0.0,
                currency="LOG",
                event_type=f"AUTH_{normalized_outcome}",
                reference="|".join([dest_user, source_computer, dest_computer, auth_type, logon_type, orientation]),
            )
        )
        if len(events) >= max_events:
            break
    return events


def load_public_log_events(path: str, dataset_format: str, max_events: int) -> List[Event]:
    if max_events <= 0:
        raise ValueError("max_events must be > 0")
    if dataset_format == "lanl_auth_simple":
        events = read_lanl_auth_simple(path, max_events)
    elif dataset_format == "lanl_auth_full":
        events = read_lanl_auth_full(path, max_events)
    elif dataset_format == "auditmesh_csv":
        events = read_events_csv(path)[:max_events]
    else:
        raise ValueError(f"Unknown dataset format: {dataset_format}")
    if not events:
        raise ValueError(f"No events loaded from {path}")
    return events


def generate_synthetic_events(num_events: int, seed: int) -> List[Event]:
    random.seed(seed)
    # Deterministic timestamps derived only from seed and index.
    base_ts = 1700000000 + (seed % 100000)
    types = ["DEPOSIT", "WITHDRAWAL", "TRANSFER", "FEE"]
    currencies = ["USD", "EUR", "VND"]
    events = []
    for i in range(num_events):
        event = Event(
            event_id=i + 1,
            timestamp=base_ts + i,
            account_id=f"ACC-{random.randint(10000, 99999)}",
            amount=round(random.uniform(1, 5000), 2),
            currency=random.choice(currencies),
            event_type=random.choice(types),
            reference=f"REF-{random.randint(100000, 999999)}",
        )
        events.append(event)
    return events


def _weighted_choice(rng: random.Random, items: List[str], weights: List[float]) -> str:
    total = sum(weights)
    pick = rng.random() * total
    acc = 0.0
    for item, weight in zip(items, weights):
        acc += weight
        if pick <= acc:
            return item
    return items[-1]


def generate_calibrated_financial_events(num_events: int, seed: int) -> List[Event]:
    """Generate a deterministic financial-like workload.

    The distribution is still synthetic, but calibrated to resemble common
    retail-account logs: skewed account popularity, log-normal transaction
    amounts, dominant domestic currency, and event-type imbalance.
    """
    rng = random.Random(seed)
    base_ts = 1700000000 + (seed % 100000)
    accounts = [f"ACC-{10000 + i:05d}" for i in range(500)]
    account_weights = [1.0 / ((i + 1) ** 1.1) for i in range(len(accounts))]
    event_types = ["DEPOSIT", "WITHDRAWAL", "TRANSFER", "FEE"]
    event_weights = [0.18, 0.32, 0.42, 0.08]
    currencies = ["USD", "EUR", "VND"]
    currency_weights = [0.62, 0.13, 0.25]

    events: List[Event] = []
    ts = base_ts
    for i in range(num_events):
        event_type = _weighted_choice(rng, event_types, event_weights)
        currency = _weighted_choice(rng, currencies, currency_weights)
        account = _weighted_choice(rng, accounts, account_weights)
        if event_type == "FEE":
            amount = round(max(0.1, rng.lognormvariate(1.2, 0.45)), 2)
        elif event_type == "TRANSFER":
            amount = round(min(50000.0, rng.lognormvariate(6.0, 1.0)), 2)
        else:
            amount = round(min(25000.0, rng.lognormvariate(5.4, 0.9)), 2)
        ts += rng.randint(0, 5)
        events.append(
            Event(
                event_id=i + 1,
                timestamp=ts,
                account_id=account,
                amount=amount,
                currency=currency,
                event_type=event_type,
                reference=f"REF-{event_type[:2]}-{rng.randint(100000, 999999)}",
            )
        )
    return events


def generate_events(
    num_events: int,
    seed: int,
    workload: str = "synthetic",
    event_source_path: str = "",
    dataset_format: str = "auditmesh_csv",
) -> List[Event]:
    if workload == "public_log":
        if not event_source_path:
            raise ValueError("workload public_log requires event_source_path")
        return load_public_log_events(event_source_path, dataset_format, num_events)
    if workload == "synthetic":
        return generate_synthetic_events(num_events, seed)
    if workload == "calibrated":
        return generate_calibrated_financial_events(num_events, seed)
    raise ValueError(f"Unknown workload: {workload}")


def file_size(path: str) -> int:
    return os.path.getsize(path)


def write_json(path: str, payload: Dict) -> None:
    ensure_parent_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
