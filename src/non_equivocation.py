from dataclasses import dataclass
from typing import Dict, List, Tuple

from merkle_signed_log import KeyRegistry, MerkleCommitment, MerkleSignedLog


@dataclass(frozen=True)
class CommitmentObservation:
    auditor_id: str
    round_id: int
    commitment: MerkleCommitment


@dataclass(frozen=True)
class NonEquivocationFinding:
    finding_type: str
    detail: str
    auditor_a: str
    auditor_b: str
    old_size: int
    new_size: int
    old_root: str
    new_root: str


class MultiPartyNonEquivocationMonitor:
    """Local witness/gossip checker for signed Merkle commitment observations."""

    @staticmethod
    def assess(
        observations: List[CommitmentObservation],
        consistency_proofs: List[Dict],
        registry: KeyRegistry,
    ) -> List[NonEquivocationFinding]:
        findings: List[NonEquivocationFinding] = []
        valid_observations = [
            obs
            for obs in observations
            if MerkleSignedLog.verify_commitment_signature(obs.commitment, registry)
        ]

        proof_edges: Dict[Tuple[int, str, int, str], Dict] = {}
        for proof in consistency_proofs:
            if MerkleSignedLog.verify_consistency_proof_external(proof, registry):
                proof_edges[
                    (
                        int(proof["old_size"]),
                        proof["old_root"],
                        int(proof["new_size"]),
                        proof["new_root"],
                    )
                ] = proof

        by_size: Dict[int, Dict[str, List[CommitmentObservation]]] = {}
        for obs in valid_observations:
            by_size.setdefault(obs.commitment.tree_size, {}).setdefault(obs.commitment.root_hash, []).append(obs)

        for size, roots in by_size.items():
            if len(roots) <= 1:
                continue
            root_items = list(roots.items())
            for i, (root_a, obs_a_list) in enumerate(root_items):
                for root_b, obs_b_list in root_items[i + 1 :]:
                    obs_a = obs_a_list[0]
                    obs_b = obs_b_list[0]
                    findings.append(
                        NonEquivocationFinding(
                            finding_type="same_size_split_view",
                            detail="Different signed roots were observed for the same tree size.",
                            auditor_a=obs_a.auditor_id,
                            auditor_b=obs_b.auditor_id,
                            old_size=size,
                            new_size=size,
                            old_root=root_a,
                            new_root=root_b,
                        )
                    )

        for old in valid_observations:
            for new in valid_observations:
                if old.commitment.tree_size >= new.commitment.tree_size:
                    continue
                edge = (
                    old.commitment.tree_size,
                    old.commitment.root_hash,
                    new.commitment.tree_size,
                    new.commitment.root_hash,
                )
                if edge in proof_edges:
                    continue
                findings.append(
                    NonEquivocationFinding(
                        finding_type="missing_or_invalid_consistency",
                        detail="No valid signed consistency proof links the older observed root to the newer observed root.",
                        auditor_a=old.auditor_id,
                        auditor_b=new.auditor_id,
                        old_size=old.commitment.tree_size,
                        new_size=new.commitment.tree_size,
                        old_root=old.commitment.root_hash,
                        new_root=new.commitment.root_hash,
                    )
                )

        return findings
