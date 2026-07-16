"""Telemetry + SLO evaluation (Doc 4 §8.1).

JSONL spans and metrics with OpenTelemetry-convention-shaped names and
attributes. We emit the wire shape, not the SDK: no collector, no exporter, no
background threads to make deterministic. Swapping `Telemetry` for an OTel
tracer is a file-sized change and is the documented production path.

The SLO evaluator is the thing that turns raw numbers into a decision. "10 ms a
hop is fine; 1 s a hop is an incident" is not a human judgement here -- it is
`p95 message latency <= 50 ms` over a rolling window, and when it trips, the
evaluator hands the analyzer the window stats AND the worst spans, so the
analyzer can say WHERE it went slow rather than merely that it did.
"""
from __future__ import annotations

import json
import math
import os
from collections import defaultdict, deque

from core.types import Incident

# Hardcoded SLO table. These are the numbers the demo is judged against.
SLO_MSG_LATENCY_P95_MS = 50.0
SLO_CONTRACT_DURATION_MS = 5000.0
SLO_ABORT_RATE = 0.10
SLO_WINDOW = 5

SLO_TABLE = {
    "message_latency": {"metric": "csp.message.latency_ms", "stat": "p95",
                        "threshold": SLO_MSG_LATENCY_P95_MS, "window": SLO_WINDOW},
    "contract_duration": {"metric": "csp.contract.duration_ms", "stat": "p95",
                          "threshold": SLO_CONTRACT_DURATION_MS, "window": SLO_WINDOW},
    "abort_rate": {"metric": "csp.abort.count", "stat": "rate",
                   "threshold": SLO_ABORT_RATE, "window": SLO_WINDOW},
}


def p95(values: list) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    # Nearest-rank p95: the smallest value at or above 95% of the sample.
    # math.ceil, not round(): round() is banker's rounding, so at n=20 it took
    # rank 20 of 20 and reported the MAX as the p95.
    k = max(0, min(len(s) - 1, math.ceil(0.95 * len(s)) - 1))
    return s[k]


class Telemetry:
    """Every observable event funnels through _write(), which is why `on_record`
    is the only hook the live UI needs: spans, metrics, SLO breaches, guardrail
    denials and revokes all pass through here already. A subscriber renders the
    system; it is never in the trust path, and it must never be able to break a
    run -- hence the try/except around it.
    """

    def __init__(self, out_path: str | None = None, clock=None, on_record=None):
        self.clock = clock
        self.records: list = []
        self.by_session: dict = defaultdict(list)  # session -> [latency_ms]
        self.counters: dict = defaultdict(int)
        self.out_path = out_path
        self.on_record = on_record
        if out_path:
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            open(out_path, "w").close()

    def _write(self, rec: dict) -> None:
        self.records.append(rec)
        if self.out_path:
            with open(self.out_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
        if self.on_record is not None:
            try:
                self.on_record(rec)
            except Exception:
                pass  # a broken viewer never breaks the fabric

    def metric(self, name: str, value: float, attrs: dict | None = None) -> None:
        attrs = attrs or {}
        self._write({"kind": "metric", "name": name, "value": value,
                     "ts_ms": self.clock.now() if self.clock else None, "attrs": attrs})
        if name == "csp.message.latency_ms" and attrs.get("session"):
            self.by_session[attrs["session"]].append(value)

    def count(self, name: str, attrs: dict | None = None, value: int = 1) -> None:
        self.counters[name] += value
        self._write({"kind": "metric", "name": name, "value": value,
                     "ts_ms": self.clock.now() if self.clock else None, "attrs": attrs or {}})

    def span(self, name: str, attrs: dict, start_ms: float, duration_ms: float) -> None:
        self._write({"kind": "span", "name": name, "start_ms": start_ms,
                     "duration_ms": duration_ms, "attrs": attrs})

    def event(self, name: str, attrs: dict) -> None:
        self._write({"kind": "event", "name": name,
                     "ts_ms": self.clock.now() if self.clock else None, "attrs": attrs})

    def session_latencies(self, session: str) -> list:
        return list(self.by_session.get(session, []))


def scope_ctx(task_ctx: dict) -> dict:
    """The context an incident -- and therefore an insight -- is scoped to."""
    return {"link_quality": task_ctx.get("link_quality")}


class SLOEvaluator:
    """Rolling-window SLO checks, evaluated PER CONTEXT. on_task_end -> Incident | None.

    Windows are keyed by the same context an insight is scoped to: we detect in
    the scope we remember in. A single global window silently mixes conditions --
    a healthy 60 ms task arriving right after a lossy era inherits the era's p95,
    fires a bogus incident, and mints an insight scoped to `normal` built on
    `lossy` evidence. Slicing by context is also just what you would do in
    production: you do not alert on one p95 across every route.
    """

    def __init__(self, telemetry: Telemetry, window: int = SLO_WINDOW):
        self.tel = telemetry
        self.window = window
        self.win: dict = {}
        self._n = 0

    def _window_for(self, ctx: dict) -> dict:
        key = repr(sorted(scope_ctx(ctx).items()))
        if key not in self.win:
            self.win[key] = {"lat": deque(maxlen=self.window),
                             "dur": deque(maxlen=self.window),
                             "ab": deque(maxlen=self.window)}
        return self.win[key]

    def on_task_end(self, node: str, task_ctx: dict, result, session: str,
                    scenario: dict) -> Incident | None:
        self._n += 1
        w = self._window_for(task_ctx)
        lats = self.tel.session_latencies(session)
        # One entry per task, not per message: the window is 5 TASKS wide.
        w["lat"].append(lats)
        w["dur"].append(result.duration_ms)
        w["ab"].append(1 if result.aborted else 0)

        self.tel.metric("csp.contract.duration_ms", result.duration_ms,
                        {"node": node, "session": session, **_ctx_attrs(task_ctx)})
        self.tel.metric("csp.contract.rounds", result.rounds,
                        {"node": node, "session": session, **_ctx_attrs(task_ctx)})
        if result.aborted:
            self.tel.count("csp.abort.count",
                           {"node": node, "reason": result.abort_reason, **_ctx_attrs(task_ctx)})

        if len(w["dur"]) < self.window:
            return None  # never fire on a window we have not filled

        flat = [x for lst in w["lat"] for x in lst]
        lat_p95 = p95(flat)
        dur_p95 = p95(list(w["dur"]))
        abort_rate = sum(w["ab"]) / len(w["ab"])

        stats = {"p95": lat_p95, "n": len(flat),
                 "duration_p95": dur_p95, "abort_rate": abort_rate,
                 "window": self.window}

        breach = None
        if lat_p95 > SLO_MSG_LATENCY_P95_MS:
            breach, stats["threshold"] = "message_latency", SLO_MSG_LATENCY_P95_MS
        elif abort_rate > SLO_ABORT_RATE:
            breach, stats["p95"] = "abort_rate", abort_rate
            stats["threshold"] = SLO_ABORT_RATE
        elif dur_p95 > SLO_CONTRACT_DURATION_MS:
            breach, stats["p95"] = "contract_duration", dur_p95
            stats["threshold"] = SLO_CONTRACT_DURATION_MS
        if breach is None:
            return None

        worst = sorted(
            [r for r in self.tel.records
             if r.get("kind") == "metric" and r["name"] == "csp.message.latency_ms"
             and r["attrs"].get("session") == session],
            key=lambda r: -r["value"],
        )[:3]
        worst_spans = [
            {"span_id": f"{r['attrs'].get('session')}/{r['attrs'].get('type')}/{i}",
             "from": r["attrs"].get("from"), "to": r["attrs"].get("to"),
             "type": r["attrs"].get("type"), "latency_ms": round(r["value"], 1)}
            for i, r in enumerate(worst)
        ]

        inc = Incident(
            # Node-qualified: each node runs its own evaluator, so a bare counter
            # collides across nodes.
            id=f"inc-{node}-{self._n:02d}",
            breached_slo=breach,
            window_stats=stats,
            worst_spans=worst_spans,
            task_ctx=dict(task_ctx),
            node=node,
            scenario=scenario,
        )
        self.tel.event("slo.breach", {"incident": inc.id, "slo": breach,
                                      "value": round(stats["p95"], 1),
                                      "threshold": stats["threshold"], "node": node})
        return inc


def _ctx_attrs(ctx: dict) -> dict:
    return {"link_quality": ctx.get("link_quality"), "workload": ctx.get("workload")}
