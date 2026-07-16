"""The Insight -- the unit of collective memory (Doc 4 §6.1).

An insight is not free-form text. It is a typed, signed, bounded claim with
replayable evidence attached. That shape is the whole anti-poisoning story:
there is no field in which an attacker can express "ignore your safety
constraints", because no such field exists.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from core.crypto import Identity, canonical, sha256_hex
from core.types import STATUS_LOCAL


@dataclass
class Insight:
    id: str
    version: int
    scope: dict  # {"ns": "netops", "context": {"link_quality": "lossy"}} -- exact-match key
    claim: dict  # ONLY whitelisted keys: {"params": {...}, "warm_start": {dim: val}}
    evidence: dict  # {"scenario": {...replayable...}, "metric_before", "metric_after",
    #                  "claimed_improvement"}
    provenance: dict  # {"discovered_by", "analyzer", "derived_from": [ids], "sig"}
    status: str = STATUS_LOCAL
    attestations: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Insight":
        return cls(
            id=d["id"],
            version=d["version"],
            scope=d["scope"],
            claim=d["claim"],
            evidence=d["evidence"],
            provenance=d["provenance"],
            status=d.get("status", STATUS_LOCAL),
            attestations=list(d.get("attestations", [])),
        )


def signing_body(d: dict) -> dict:
    """Exactly what the discovering node signs, and exactly what the id binds to.

    Excludes id, sig, status and attestations -- those are assigned by the
    fabric, not claimed by the author. An author cannot self-declare VERIFIED.
    """
    prov = d["provenance"]
    return {
        "version": d["version"],
        "scope": d["scope"],
        "claim": d["claim"],
        "evidence": d["evidence"],
        "provenance": {
            "discovered_by": prov["discovered_by"],
            "analyzer": prov["analyzer"],
            "derived_from": sorted(prov.get("derived_from", [])),
        },
    }


def compute_id(d: dict) -> str:
    return "ins-" + sha256_hex(canonical(signing_body(d)))[:12]


def make_insight(
    scope: dict,
    claim: dict,
    evidence: dict,
    identity: Identity,
    discovered_by: str,
    analyzer: str = "rules",
    derived_from: list | None = None,
    version: int = 1,
) -> Insight:
    draft = {
        "version": version,
        "scope": scope,
        "claim": claim,
        "evidence": evidence,
        "provenance": {
            "discovered_by": discovered_by,
            "analyzer": analyzer,
            "derived_from": sorted(derived_from or []),
        },
    }
    body = signing_body(draft)
    draft["id"] = compute_id(draft)
    draft["provenance"]["sig"] = identity.sign(canonical(body))
    return Insight.from_dict(draft)


def scope_key(scope: dict) -> str:
    """Exact-match key. Two fixes valid in different contexts get different keys
    and therefore coexist -- that is the answer to 'conflicting fixes' (Doc 4 §7.5)."""
    return canonical({"ns": scope.get("ns", "netops"), "context": scope.get("context", {})}).decode()


def scope_matches(scope: dict, task_ctx: dict) -> bool:
    """An insight applies when every key it scopes on matches the task context."""
    for k, v in scope.get("context", {}).items():
        if task_ctx.get(k) != v:
            return False
    return True
