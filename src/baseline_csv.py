import hashlib
from typing import List, Tuple

from common import Event


class AppendOnlyCSVBaseline:
    @staticmethod
    def commit(events: List[Event]) -> str:
        # Baseline "commitment" is a single digest over full ordered content.
        hasher = hashlib.sha256()
        for event in events:
            hasher.update(event.canonical_json().encode("utf-8"))
        return hasher.hexdigest()

    @staticmethod
    def verify(events: List[Event], committed_digest: str) -> Tuple[bool, int]:
        current = AppendOnlyCSVBaseline.commit(events)
        return current == committed_digest, 0
