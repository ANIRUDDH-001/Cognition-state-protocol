"""Canonical JSON, Ed25519 identity, hashing, hash-chain helpers.

Doc 2 §2 (conventions) + §11 (crypto spec). Everything that is hashed or signed
goes through canonical() first -- never hand-serialize.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS_HASH = "0" * 64


def canonical(obj) -> bytes:
    """UTF-8, keys sorted at every level, no insignificant whitespace.

    Python's json emits shortest round-trip float repr, which is what the spec
    asks for. allow_nan=False so a NaN can never silently enter a signature.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data) -> str:
    if not isinstance(data, (bytes, bytearray)):
        data = canonical(data)
    return hashlib.sha256(data).hexdigest()


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Identity:
    """An Ed25519 keypair bound to an id (agent persona or fabric node)."""

    def __init__(self, entity_id: str, priv: Ed25519PrivateKey):
        self.entity_id = entity_id
        self._priv = priv

    @classmethod
    def deterministic(cls, entity_id: str) -> "Identity":
        # Demo keys are derived from the id so every run -- and every replay --
        # pins the same public keys. Production path is per-node key generation
        # plus a PKI/attestation service (Doc 3 §2.1); pinning is the Phase 1 answer.
        seed = hashlib.sha256(f"csp-phase2/key/{entity_id}".encode()).digest()
        return cls(entity_id, Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_b64(self) -> str:
        raw = self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return b64e(raw)

    def sign(self, payload) -> str:
        if not isinstance(payload, (bytes, bytearray)):
            payload = canonical(payload)
        return b64e(self._priv.sign(bytes(payload)))


class Keyring:
    """Pinned public keys. Nothing is trusted that is not pinned here."""

    def __init__(self):
        self._pins: dict[str, str] = {}

    def pin(self, entity_id: str, public_b64: str) -> None:
        self._pins[entity_id] = public_b64

    def pin_identity(self, ident: Identity) -> None:
        self.pin(ident.entity_id, ident.public_b64)

    def known(self, entity_id: str) -> bool:
        return entity_id in self._pins

    def verify(self, entity_id: str, sig_b64: str, payload) -> bool:
        pub_b64 = self._pins.get(entity_id)
        if pub_b64 is None or not sig_b64:
            return False
        if not isinstance(payload, (bytes, bytearray)):
            payload = canonical(payload)
        try:
            pub = Ed25519PublicKey.from_public_bytes(b64d(pub_b64))
            pub.verify(b64d(sig_b64), bytes(payload))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


def sign_envelope(ident: Identity, env: dict) -> dict:
    """sig = Ed25519(canonical(envelope minus sig)). Doc 2 §4 field 9."""
    body = {k: v for k, v in env.items() if k != "sig"}
    out = dict(body)
    out["sig"] = ident.sign(canonical(body))
    return out


def verify_envelope(keyring: Keyring, env: dict) -> bool:
    body = {k: v for k, v in env.items() if k != "sig"}
    return keyring.verify(env.get("from", ""), env.get("sig", ""), canonical(body))


def sign_body(ident: Identity, body: dict) -> str:
    return ident.sign(canonical(body))


def chain_hash(prev_hash: str, body: dict) -> str:
    """Hash-chain link for fabric log entries (Doc 4 §7.1)."""
    return sha256_hex(canonical({"prev_hash": prev_hash, "body": body}))
