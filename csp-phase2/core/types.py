"""Frozen interfaces (Doc 4 §5.6 / §12). Nothing changes a signature here.

DEVIATION FROM DOC 4, owned deliberately: `negotiate` and `replay` are
synchronous, not `async`. The protocol is strictly alternating request/response,
so asyncio buys no concurrency here -- but it costs determinism, and `replay()`
being byte-for-byte deterministic is the anti-hallucination primitive the whole
verification story rests on. Time is virtual (core/bus.Clock), so a 1200 ms link
delay costs zero wall-clock in a replay. Envelopes, crypto and fault semantics
are identical to what a websocket adapter would carry (Doc 1 §3 / L0).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

SCHEMA = "csp/1.0"

# Message catalog actually used by the mini core (Doc 4 §5: HELLO/ontology
# negotiation collapsed away -- both nodes carry the identical registry here).
MSG_INTENT_DECLARE = "INTENT_DECLARE"
MSG_PROPOSE = "PROPOSE"
MSG_COUNTER = "COUNTER"
MSG_ACCEPT = "ACCEPT"
MSG_SETTLE = "SETTLE"
MSG_COMMIT = "COMMIT"
MSG_COMMIT_ACK = "COMMIT_ACK"
MSG_ABORT = "ABORT"

# Fabric / gossip envelopes
MSG_INSIGHT_ANNOUNCE = "INSIGHT_ANNOUNCE"
MSG_GOSSIP_HEAD = "GOSSIP_HEAD"
MSG_GOSSIP_PULL = "GOSSIP_PULL"
MSG_GOSSIP_PUSH = "GOSSIP_PUSH"

ABORT_REASONS = (
    "TIMEOUT",
    "SCHEMA_MISMATCH",
    "EMPTY_FEASIBLE",
    "INVALID_SIG",
    "REPLAY_DETECTED",
    "CONCESSION_VIOLATION",
    "POLICY_VIOLATION",
)


@dataclass
class NegotiationResult:
    contract: Optional[dict]  # IntentContract (Doc 2 §7), or None if aborted
    rounds: int
    duration_ms: float  # virtual wall time incl. simulated transport delays
    aborted: bool
    abort_reason: Optional[str] = None
    transcript_hash: str = ""
    messages: int = 0
    # Every signed envelope of the session, in order. Audit + demo material.
    # Deliberately NOT part of summary(): the replay hash must depend on the
    # negotiation's OUTCOME, not on nonces and timestamps that legitimately
    # differ between two nodes verifying the same claim.
    transcript: list = field(default_factory=list)

    def summary(self) -> dict:
        """Everything a peer must reproduce byte-identically to attest."""
        return {
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "rounds": self.rounds,
            "duration_ms": round(self.duration_ms, 3),
            "messages": self.messages,
            "agreed": (self.contract or {}).get("agreed"),
            "resolved_by": (self.contract or {}).get("provenance", {}).get("resolved_by"),
        }


@dataclass
class Incident:
    """Emitted by the SLO evaluator, consumed by the analyzer (Doc 4 §8.1)."""

    id: str
    breached_slo: str  # message_latency | contract_duration | abort_rate
    window_stats: dict
    worst_spans: list = field(default_factory=list)
    task_ctx: dict = field(default_factory=dict)
    node: str = ""
    scenario: dict = field(default_factory=dict)  # replayable recording


@dataclass
class Allow:
    ok: bool = True
    reason: Optional[str] = None


@dataclass
class Deny:
    reason: str
    detail: str = ""
    ok: bool = False


# Insight lifecycle. Ordered as a join-semilattice: folding the fabric log takes
# the max, which is what makes convergence order-independent (Doc 4 §7.1).
STATUS_LOCAL = "LOCAL"
STATUS_CANDIDATE = "CANDIDATE"
STATUS_VERIFIED = "VERIFIED"
STATUS_QUARANTINED = "QUARANTINED"
STATUS_REVOKED = "REVOKED"

STATUS_RANK = {
    STATUS_LOCAL: 0,
    STATUS_CANDIDATE: 1,
    STATUS_VERIFIED: 2,
    STATUS_QUARANTINED: 3,
    STATUS_REVOKED: 4,
}
