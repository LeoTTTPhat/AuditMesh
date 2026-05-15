import random
from typing import List

from common import Event


class AttackSuite:
    @staticmethod
    def insert(events: List[Event], seed: int) -> List[Event]:
        random.seed(seed + 1)
        out = events[:]
        idx = random.randint(0, len(out))
        out.insert(
            idx,
            Event(
                event_id=999999,
                timestamp=events[idx - 1].timestamp if idx > 0 else events[0].timestamp,
                account_id="ACC-ATTACK",
                amount=7777.77,
                currency="USD",
                event_type="TRANSFER",
                reference="REF-ATTACK-INSERT",
            ),
        )
        return out

    @staticmethod
    def delete(events: List[Event], seed: int) -> List[Event]:
        random.seed(seed + 2)
        out = events[:]
        if not out:
            return out
        idx = random.randint(0, len(out) - 1)
        del out[idx]
        return out

    @staticmethod
    def modify(events: List[Event], seed: int) -> List[Event]:
        random.seed(seed + 3)
        out = events[:]
        if not out:
            return out
        idx = random.randint(0, len(out) - 1)
        target = out[idx]
        out[idx] = Event(
            event_id=target.event_id,
            timestamp=target.timestamp,
            account_id=target.account_id,
            amount=round(target.amount * 1.5, 2),
            currency=target.currency,
            event_type=target.event_type,
            reference=target.reference + "-MOD",
        )
        return out

    @staticmethod
    def replay(events: List[Event], seed: int) -> List[Event]:
        random.seed(seed + 4)
        out = events[:]
        if not out:
            return out
        idx = random.randint(0, len(out) - 1)
        out.append(out[idx])
        return out

    @staticmethod
    def truncate(events: List[Event], seed: int) -> List[Event]:
        random.seed(seed + 5)
        if len(events) < 2:
            return events[:]
        cut = random.randint(1, len(events) - 1)
        return events[:cut]

    @staticmethod
    def reorder(events: List[Event], seed: int) -> List[Event]:
        """Swap two pseudorandom events, changing the committed order."""
        random.seed(seed + 6)
        out = events[:]
        if len(out) < 2:
            return out
        i = random.randint(0, len(out) - 2)
        j = random.randint(i + 1, len(out) - 1)
        out[i], out[j] = out[j], out[i]
        return out

    @staticmethod
    def timestamp_manipulate(events: List[Event], seed: int) -> List[Event]:
        """Alter the timestamp of one event without changing its position."""
        random.seed(seed + 7)
        out = events[:]
        if not out:
            return out
        idx = random.randint(0, len(out) - 1)
        target = out[idx]
        # Shift timestamp by a random offset (1–3600 seconds)
        offset = random.randint(1, 3600)
        out[idx] = Event(
            event_id=target.event_id,
            timestamp=target.timestamp + offset,
            account_id=target.account_id,
            amount=target.amount,
            currency=target.currency,
            event_type=target.event_type,
            reference=target.reference,
        )
        return out

    @staticmethod
    def alternative_view(events: List[Event], seed: int) -> List[Event]:
        """Replace one event with a plausible same-length alternative view."""
        random.seed(seed + 8)
        out = events[:]
        if not out:
            return out
        idx = random.randint(0, len(out) - 1)
        target = out[idx]
        out[idx] = Event(
            event_id=target.event_id,
            timestamp=target.timestamp,
            account_id=f"ACC-{random.randint(10000, 99999)}",
            amount=round(random.uniform(1, 5000), 2),
            currency=target.currency,
            event_type=target.event_type,
            reference=f"REF-{random.randint(100000, 999999)}",
        )
        return out

    # Backward-compatible alias for old result files/scripts.
    equivocation = alternative_view
