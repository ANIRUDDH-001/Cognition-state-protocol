"""Rule-based incident analyzer -- PRIMARY, always on (Doc 4 §9.1).

The analyzer is an advisor, not an authority. It drafts a hypothesis; it cannot
write to the fabric, and it cannot promote anything. Everything it produces still
faces the guardrail, peer replay, and quorum.

The discipline that matters: the analyzer runs the SAME verification its peers
will run, locally, BEFORE submitting. If its own replay does not reproduce the
improvement it is about to claim, it returns None and says nothing. We never ask
the network to check a claim we have not checked ourselves.
"""
from __future__ import annotations

from core.registry import DEFAULT_PARAMS
from insights.pipeline import verify
from metrics.telemetry import SLO_MSG_LATENCY_P95_MS

# A latency breach only becomes a "the link is broken" hypothesis when it is
# an order of magnitude out, not merely over. 60 ms is a bad window; 800 ms is
# a different world and deserves a different negotiation strategy.
GROSS_BREACH_FACTOR = 10.0


def _rule(incident, last_agreed: dict | None) -> dict | None:
    """The rule table. Deliberately small enough to read in the defence."""
    ws = incident.window_stats
    slo = incident.breached_slo

    # latency breach -> raise timeout, cut rounds, and open from what we
    # already know settles in this context.
    if slo == "message_latency" and ws["p95"] > GROSS_BREACH_FACTOR * SLO_MSG_LATENCY_P95_MS:
        claim = {"params": {"negotiate_timeout_ms": 30000, "r_max": 6, "eps": 0.08}}
        if last_agreed:
            claim["warm_start"] = dict(last_agreed)
        return claim

    # abort spike -> the budget is wrong, not the strategy.
    if slo == "abort_rate":
        return {"params": {"negotiate_timeout_ms": 30000}}

    # slow but succeeding -> don't touch the budget, just stop re-deriving the
    # answer from scratch.
    if slo == "contract_duration" and last_agreed:
        return {"warm_start": dict(last_agreed)}

    return None


def analyze(incident, last_agreed: dict | None = None, defaults: dict | None = None) -> dict | None:
    """incident -> draft insight body, or None. Never returns an unreproduced claim."""
    base = dict(DEFAULT_PARAMS if defaults is None else defaults)
    claim = _rule(incident, last_agreed)
    if not claim:
        return None

    stub = {"claim": claim, "evidence": {"scenario": incident.scenario}}
    ok, _replay_hash, before, after = verify(stub, base)
    if not ok:
        return None  # our own replay refused it -- do not waste the network's time

    return {
        "scope": {"ns": "netops", "context": {"link_quality": incident.task_ctx["link_quality"]}},
        "claim": claim,
        "evidence": {
            "scenario": incident.scenario,
            "metric_before": before,
            "metric_after": after,
            "claimed_improvement": {
                "rounds": after["rounds"] - before["rounds"],
                "duration_ms": round(after["duration_ms"] - before["duration_ms"], 3),
            },
        },
        "analyzer": "rules",
        "hypothesis": _hypothesis(incident),
        "cited_span_ids": [s["span_id"] for s in incident.worst_spans],
    }


def _hypothesis(incident) -> str:
    ws = incident.window_stats
    return (
        f"{incident.breached_slo} p95={ws['p95']:.0f} vs SLO {ws.get('threshold')} under "
        f"link_quality={incident.task_ctx.get('link_quality')}: per-hop cost dominates, so the "
        f"fix is fewer hops (warm start) and a budget that fits the link, not a cheaper strategy."
    )
