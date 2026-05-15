import json
import os
from dataclasses import asdict, dataclass
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from baseline_csv import AppendOnlyCSVBaseline
from baseline_hashchain import HashChainBaseline
from common import Event
from merkle_signed_log import KeyRegistry


def _load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        private = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("Private key must be Ed25519")
    return private


def _load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as f:
        public = serialization.load_pem_public_key(f.read())
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("Public key must be Ed25519")
    return public


def _message(payload: Dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class SignedDigestCommitment:
    digest_hex: str
    signature_hex: str
    key_id: str
    tree_size: int

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SignedHashChainCommitment:
    head_hash: str
    signature_hex: str
    key_id: str
    tree_size: int

    def to_dict(self) -> Dict:
        return asdict(self)


class SignedDigestBaseline:
    @staticmethod
    def _payload(digest_hex: str, key_id: str, tree_size: int) -> Dict:
        return {
            "scheme": "auditmesh_signed_digest_v1",
            "digest_hex": digest_hex,
            "key_id": key_id,
            "tree_size": int(tree_size),
        }

    @staticmethod
    def commit(events: List[Event], private_key_path: str, key_id: str) -> SignedDigestCommitment:
        digest = AppendOnlyCSVBaseline.commit(events)
        private = _load_private_key(private_key_path)
        sig = private.sign(_message(SignedDigestBaseline._payload(digest, key_id, len(events)))).hex()
        return SignedDigestCommitment(digest_hex=digest, signature_hex=sig, key_id=key_id, tree_size=len(events))

    @staticmethod
    def verify(events: List[Event], commitment: SignedDigestCommitment, registry: KeyRegistry) -> Tuple[bool, int]:
        if commitment.key_id in registry.revoked_keys or commitment.tree_size != len(events):
            return False, 0
        pub_path = registry.keys.get(commitment.key_id)
        if not pub_path or not os.path.exists(pub_path):
            return False, 0
        digest = AppendOnlyCSVBaseline.commit(events)
        try:
            pub = _load_public_key(pub_path)
            pub.verify(
                bytes.fromhex(commitment.signature_hex),
                _message(SignedDigestBaseline._payload(commitment.digest_hex, commitment.key_id, commitment.tree_size)),
            )
        except Exception:
            return False, 0
        return digest == commitment.digest_hex, 0


class SignedHashChainBaseline:
    @staticmethod
    def _payload(head_hash: str, key_id: str, tree_size: int) -> Dict:
        return {
            "scheme": "auditmesh_signed_hashchain_v1",
            "head_hash": head_hash,
            "key_id": key_id,
            "tree_size": int(tree_size),
        }

    @staticmethod
    def commit(events: List[Event], private_key_path: str, key_id: str) -> SignedHashChainCommitment:
        chain = HashChainBaseline.build_chain(events)
        private = _load_private_key(private_key_path)
        sig = private.sign(_message(SignedHashChainBaseline._payload(chain.head_hash, key_id, len(events)))).hex()
        return SignedHashChainCommitment(
            head_hash=chain.head_hash,
            signature_hex=sig,
            key_id=key_id,
            tree_size=len(events),
        )

    @staticmethod
    def verify(events: List[Event], commitment: SignedHashChainCommitment, registry: KeyRegistry) -> Tuple[bool, int]:
        if commitment.key_id in registry.revoked_keys or commitment.tree_size != len(events):
            return False, 0
        pub_path = registry.keys.get(commitment.key_id)
        if not pub_path or not os.path.exists(pub_path):
            return False, 0
        rebuilt = HashChainBaseline.build_chain(events)
        try:
            pub = _load_public_key(pub_path)
            pub.verify(
                bytes.fromhex(commitment.signature_hex),
                _message(SignedHashChainBaseline._payload(commitment.head_hash, commitment.key_id, commitment.tree_size)),
            )
        except Exception:
            return False, 0
        return rebuilt.head_hash == commitment.head_hash, 32
