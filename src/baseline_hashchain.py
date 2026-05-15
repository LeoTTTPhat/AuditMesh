from dataclasses import dataclass
from typing import List, Tuple

from common import Event, sha256_hex


@dataclass
class HashChainCommitment:
    head_hash: str
    chain: List[str]


@dataclass
class HashChainPrefixProof:
    index: int
    event: Event
    prefix_events: List[Event]
    prefix_hash: str


class HashChainBaseline:
    @staticmethod
    def build_chain(events: List[Event]) -> HashChainCommitment:
        prev = "GENESIS"
        chain: List[str] = []
        for e in events:
            prev = sha256_hex(prev + "|" + e.canonical_json())
            chain.append(prev)
        return HashChainCommitment(head_hash=prev, chain=chain)

    @staticmethod
    def verify(events: List[Event], commitment: HashChainCommitment) -> Tuple[bool, int]:
        rebuilt = HashChainBaseline.build_chain(events)
        return rebuilt.head_hash == commitment.head_hash, 32

    @staticmethod
    def build_prefix_proof(events: List[Event], index: int) -> HashChainPrefixProof:
        if index < 0 or index >= len(events):
            raise IndexError("prefix proof index out of range")
        prefix_events = events[: index + 1]
        prefix = HashChainBaseline.build_chain(prefix_events)
        return HashChainPrefixProof(
            index=index,
            event=events[index],
            prefix_events=prefix_events,
            prefix_hash=prefix.head_hash,
        )

    @staticmethod
    def verify_prefix_proof(proof: HashChainPrefixProof, commitment: HashChainCommitment) -> bool:
        if proof.index < 0 or proof.index >= len(commitment.chain):
            return False
        if len(proof.prefix_events) != proof.index + 1:
            return False
        if proof.prefix_events[proof.index] != proof.event:
            return False
        rebuilt = HashChainBaseline.build_chain(proof.prefix_events)
        return rebuilt.head_hash == proof.prefix_hash == commitment.chain[proof.index]
