"""Autonomous Guardrail -- deliverable 4 (Doc 4 §6.2).

Deterministic. No model in the loop. Every check is a line you can read out loud.
It runs on the discovering node BEFORE announce, and again independently on every
peer that receives an announce -- a peer trusts nothing it did not check itself.

The most important property here is what is ABSENT. There is no whitelist key for
guardrail configuration, crypto parameters, constraint classes, or priority
lattice. An insight cannot express "disable the guardrail" because the claim
schema has nowhere to put it. Absence is the mechanism.
"""
from __future__ import annotations

from collections import defaultdict, deque

from core.crypto import Keyring, canonical
from core.registry import DIM, POLICY_FLOOR, TUNABLE_BOUNDS, coupling_ok, levels
from core.types import Allow, Deny
from fabric.model import signing_body

RATE_LIMIT_N = 5
RATE_LIMIT_WINDOW_MS = 60_000

REASONS = (
    "INVALID_SIG",
    "UNKNOWN_SOURCE",
    "NOT_WHITELISTED",
    "BOUNDS_VIOLATION",
    "POLICY_VIOLATION",
    "MALFORMED_EVIDENCE",
    "RATE_LIMITED",
)


class Guardrail:
    def __init__(self, keyring: Keyring, clock=None):
        self.keyring = keyring
        self.clock = clock
        self._submissions: dict[str, deque] = defaultdict(deque)

    def check(self, ins: dict) -> Allow | Deny:
        """Ordered checks. First failure wins; the reason code is the audit record."""
        prov = ins.get("provenance") or {}
        src = prov.get("discovered_by")

        # 1. Identity: signature verifies against the PINNED key of the claimed source.
        if not src or not self.keyring.known(src):
            return Deny("UNKNOWN_SOURCE", f"no pinned key for {src!r}")
        if not self.keyring.verify(src, prov.get("sig", ""), canonical(signing_body(ins))):
            return Deny("INVALID_SIG", f"signature does not verify for {src}")

        claim = ins.get("claim") or {}
        if not isinstance(claim, dict) or not claim:
            return Deny("MALFORMED_EVIDENCE", "empty claim")
        if set(claim) - {"params", "warm_start"}:
            return Deny("NOT_WHITELISTED", f"claim keys {sorted(set(claim) - {'params', 'warm_start'})}")

        # 2. Tunables: every key whitelisted, every value inside bounds.
        for k, v in (claim.get("params") or {}).items():
            if k not in TUNABLE_BOUNDS:
                return Deny("NOT_WHITELISTED", f"param {k!r} is not a tunable")
            lo, hi = TUNABLE_BOUNDS[k]
            if not isinstance(v, (int, float)) or isinstance(v, bool):
                return Deny("BOUNDS_VIOLATION", f"{k}={v!r} is not numeric")
            if not (lo <= v <= hi):
                return Deny("BOUNDS_VIOLATION", f"{k}={v} outside [{lo}, {hi}]")

        # 3. warm_start: inside registry domains AND above the policy floor.
        #    THIS is the POLICY_VIOLATION catch -- an insight may make negotiation
        #    faster, never less safe.
        ws = claim.get("warm_start") or {}
        if ws:
            for d, v in ws.items():
                if d not in DIM:
                    return Deny("NOT_WHITELISTED", f"unknown dimension {d!r}")
                bad = _domain_error(d, v)
                if bad:
                    return Deny("BOUNDS_VIOLATION", bad)
            if ws.get("netops/tls_version") not in POLICY_FLOOR["netops/tls_version"]:
                return Deny("POLICY_VIOLATION",
                            f"tls_version must stay in {POLICY_FLOOR['netops/tls_version']}")
            if ws.get("netops/log_export") not in POLICY_FLOOR["netops/log_export"]:
                return Deny("POLICY_VIOLATION", "log_export must remain true")
            depth = ws.get("netops/inspection_depth")
            floor = POLICY_FLOOR["netops/inspection_depth_min"]
            lv = levels("netops/inspection_depth")
            if depth not in lv or lv.index(depth) < lv.index(floor):
                return Deny("POLICY_VIOLATION", f"inspection_depth {depth!r} below floor {floor!r}")
            if not coupling_ok(ws):
                return Deny("POLICY_VIOLATION", "warm_start is not physically realizable")

        # 4. Evidence must be replayable, not merely present.
        ev = ins.get("evidence") or {}
        scen = ev.get("scenario") or {}
        if not all(k in scen for k in ("agents", "task_ctx", "seed", "faults")):
            return Deny("MALFORMED_EVIDENCE", "scenario is not replayable")
        if not ev.get("metric_before") or not ev.get("metric_after"):
            return Deny("MALFORMED_EVIDENCE", "missing before/after metrics")

        # 5. Rate limit per source -- anti-flooding.
        if not self._rate_ok(src):
            return Deny("RATE_LIMITED", f"{src} exceeded {RATE_LIMIT_N}/{RATE_LIMIT_WINDOW_MS}ms")

        return Allow()

    def _rate_ok(self, src: str) -> bool:
        if self.clock is None:
            return True
        now = self.clock.now()
        q = self._submissions[src]
        while q and now - q[0] > RATE_LIMIT_WINDOW_MS:
            q.popleft()
        if len(q) >= RATE_LIMIT_N:
            return False
        q.append(now)
        return True


def _domain_error(dim_id: str, v) -> str | None:
    d = DIM[dim_id]
    t = d["type"]
    if t == "continuous":
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return f"{dim_id}={v!r} is not numeric"
        if not (d["domain"]["min"] <= v <= d["domain"]["max"]):
            return f"{dim_id}={v} outside [{d['domain']['min']}, {d['domain']['max']}]"
    elif t == "ordinal":
        if v not in d["domain"]["levels"]:
            return f"{dim_id}={v!r} is not a level"
    elif t == "categorical":
        if v not in d["domain"]["values"]:
            return f"{dim_id}={v!r} is not a permitted value"
    elif not isinstance(v, bool):
        return f"{dim_id}={v!r} is not boolean"
    return None
