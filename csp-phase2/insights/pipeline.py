"""The Accelerator -- deliverable 3, and the anti-hallucination core (Doc 4 §7.3-7.5).

    LOCAL -> guardrail ALLOW -> INSIGHT_ANNOUNCE -> CANDIDATE
          -> each peer INDEPENDENTLY: guardrail again + deterministic replay
          -> ATTEST(ok, replay_hash)
          -> >=2 distinct nodes with MATCHING replay hashes -> VERIFIED -> applied
          -> any peer that fails to reproduce -> >=2 such -> QUARANTINED

The load-bearing idea: a breakthrough is a claim with reproducible evidence.
The insight carries a replayable scenario; peers re-execute it themselves and
compare. Quorum requires the replay HASHES to match, not just the verdicts -- so
a confidently fabricated `metric_after` with a perfectly valid signature dies
here, because the numbers a peer actually measures are not the numbers claimed.
That is chaos fault F2d.
"""
from __future__ import annotations

from core.crypto import canonical, sha256_hex
from core.csp_mini import replay
from core.registry import DEFAULT_PARAMS
from core.types import STATUS_VERIFIED
from fabric.model import scope_key, scope_matches

# An insight must earn its place: >=20% faster, no new aborts, no extra rounds.
# The margin is a tolerance guard -- noise never clears this bar, and the replay
# is deterministic so there is no noise to begin with.
IMPROVEMENT_RATIO = 0.8


def apply_claim(defaults: dict, claim: dict) -> tuple[dict, dict | None]:
    """Merge a claim over a parameter set. Returns (params, warm_start)."""
    p = dict(defaults)
    p.update(claim.get("params") or {})
    return p, claim.get("warm_start")


def summarize(r) -> dict:
    return r.summary()


def verify(insight: dict, defaults: dict | None = None) -> tuple[bool, str, dict, dict]:
    """Replay verification (Doc 4 §7.4). Pure: no I/O, no clock, no network.

    Returns (improved, replay_hash, before_summary, after_summary).
    Two honest nodes running this on the same insight MUST get the same
    replay_hash -- that equality is what quorum actually checks.
    """
    base = dict(DEFAULT_PARAMS if defaults is None else defaults)
    scen = insight["evidence"]["scenario"]

    r_before = replay(scen, base)
    params_after, warm = apply_claim(base, insight["claim"])
    r_after = replay(scen, params_after, warm_start=warm)

    improved = (
        not r_after.aborted
        and r_after.duration_ms <= r_before.duration_ms * IMPROVEMENT_RATIO
        # An abort has no meaningful round count, so only compare rounds when the
        # baseline actually completed. Turning an abort into a contract is an
        # improvement regardless of how many rounds it took.
        and (r_before.aborted or r_after.rounds <= r_before.rounds)
    )
    replay_hash = sha256_hex(canonical({"a": r_after.summary(), "b": r_before.summary()}))
    return improved, replay_hash, r_before.summary(), r_after.summary()


def _preference(ins: dict) -> tuple:
    """Same-scope conflict resolution (Doc 4 §7.5): biggest claimed improvement
    wins, tie -> newer version, tie -> lower id hash. Total order, no coin flips."""
    imp = ins.get("evidence", {}).get("claimed_improvement", {})
    return (float(imp.get("duration_ms", 0.0)), -int(ins.get("version", 1)), ins["id"])


def active_params(state: dict, task_ctx: dict, defaults: dict | None = None) -> tuple:
    """Fold VERIFIED insights matching this task's context into runtime config.

    Returns (params, warm_start, insight_ids, config_epoch).

    Scoped consistency: `scope.context` is part of the key, so two fixes that are
    each valid in a different context are not a conflict -- they live under
    different keys and coexist. Only a same-scope collision needs a tie-break.

    Sessions read config once, at start (epoch semantics). A mid-flight fabric
    update never mutates a running negotiation.
    """
    base = dict(DEFAULT_PARAMS if defaults is None else defaults)
    cands = [
        ins
        for ins in state.values()
        if ins.get("status") == STATUS_VERIFIED and scope_matches(ins.get("scope", {}), task_ctx)
    ]
    best: dict[str, dict] = {}
    for ins in cands:
        k = scope_key(ins["scope"])
        if k not in best or _preference(ins) < _preference(best[k]):
            best[k] = ins

    chosen = [best[k] for k in sorted(best)]
    params, warm, ids = base, None, []
    for ins in chosen:
        p, w = apply_claim({}, ins["claim"])
        params.update(p)
        if w:
            warm = w
        ids.append(ins["id"])
    return params, warm, sorted(ids), len(ids)
