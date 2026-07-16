"""The LLM analyzer's grounding gate, and the UI's event seam (Doc 5 §2, §3).

The gate is the whole reason an LLM is allowed near this system, so it is tested
offline and without an API key -- which is the only way to know it actually fires
rather than merely existing. `ground()` is pure by design for exactly this reason.
"""
from __future__ import annotations

import pytest

from analyzer import gemini, rules
from core.registry import DEFAULT_PARAMS
from core.types import Incident
from demo.run_demo import fabric_event, run

GOOD_WARM = {
    "netops/latency_ms": 7.875, "netops/throughput_mbps": 8762.5,
    "netops/inspection_depth": "full_deep", "netops/sample_rate": 0.25,
    "netops/tls_version": "1.3", "netops/log_export": True,
}


def incident() -> Incident:
    return Incident(
        id="inc-N1-13",
        breached_slo="message_latency",
        window_stats={"p95": 1716.0, "threshold": 50.0, "n": 30},
        worst_spans=[{"span_id": "t13-N1xN2/COUNTER/0", "from": "N1.throughput",
                      "to": "N2.security", "type": "COUNTER", "latency_ms": 1716.0}],
        task_ctx={"link_quality": "lossy", "workload": "steady", "pair": ["N1", "N2"], "seed": 7},
        node="N1",
        scenario={},
    )


def model(**over) -> dict:
    out = {
        "hypothesis": "per-hop cost dominates",
        "cited_span_ids": ["t13-N1xN2/COUNTER/0"],
        "claim": {"params": {"negotiate_timeout_ms": 30000, "r_max": 6}, "use_warm_start": True},
    }
    out.update(over)
    return out


# --- the grounding gate -------------------------------------------------------


def test_gate_accepts_a_grounded_output():
    claim, hypothesis, why = gemini.ground(model(), incident(), GOOD_WARM)
    assert why == "" and claim is not None
    assert claim["params"] == {"negotiate_timeout_ms": 30000, "r_max": 6}
    assert hypothesis.startswith("gemini: ")


def test_gate_rejects_an_invented_span_id():
    """The model may not cite evidence we never showed it."""
    out = model(cited_span_ids=["t13-N1xN2/COUNTER/0", "span-i-made-up"])
    claim, _h, why = gemini.ground(out, incident(), GOOD_WARM)
    assert claim is None and "span-i-made-up" in why


def test_gate_rejects_a_non_whitelisted_knob():
    """Absence is the mechanism: there is no key for guardrail config, so the model
    cannot ask for one -- and if it invents one, the gate refuses the whole output."""
    out = model(claim={"params": {"guardrail_enabled": 0}, "use_warm_start": False})
    claim, _h, why = gemini.ground(out, incident(), GOOD_WARM)
    assert claim is None and "not a tunable" in why


@pytest.mark.parametrize("params,frag", [
    ({"eps": 0.9}, "outside"),                       # out of bounds
    ({"r_max": "six"}, "not numeric"),               # wrong type
    ({}, "no usable tunables"),                      # empty
])
def test_gate_rejects_bad_tunables(params, frag):
    out = model(claim={"params": params, "use_warm_start": False})
    claim, _h, why = gemini.ground(out, incident(), GOOD_WARM)
    assert claim is None and frag in why


@pytest.mark.parametrize("missing", ["hypothesis", "cited_span_ids", "claim"])
def test_gate_rejects_malformed_output(missing):
    out = model()
    del out[missing]
    claim, _h, why = gemini.ground(out, incident(), GOOD_WARM)
    assert claim is None and missing in why


def test_gate_rejects_a_non_response():
    assert gemini.ground(None, incident(), GOOD_WARM)[0] is None
    assert gemini.ground("not json", incident(), GOOD_WARM)[0] is None


def test_the_model_never_supplies_the_warm_start_point_itself():
    """It votes on WHETHER to warm start. The point comes from what we actually
    settled on before -- a hallucinated settlement is a class of bug we do not
    permit to exist, rather than one we catch downstream."""
    out = model()
    out["claim"]["warm_start"] = {"netops/inspection_depth": "none"}  # ignored entirely
    claim, _h, _why = gemini.ground(out, incident(), GOOD_WARM)
    assert claim["warm_start"] == GOOD_WARM

    # No remembered settlement -> no warm start, whatever the model wants.
    claim2, _h2, _w2 = gemini.ground(model(), incident(), None)
    assert "warm_start" not in claim2


def test_use_warm_start_false_means_no_warm_start():
    out = model(claim={"params": {"r_max": 6}, "use_warm_start": False})
    claim, _h, _why = gemini.ground(out, incident(), GOOD_WARM)
    assert "warm_start" not in claim


# --- fallback -----------------------------------------------------------------


def test_gemini_falls_back_to_rules_without_a_key(monkeypatch):
    """The demo must never wait on, or depend on, a model. Rehearsed unplugged."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    claim, _h, why = gemini.propose_claim(incident(), GOOD_WARM)
    assert claim is None and "no key" in why

    logged = []
    inc = incident()
    inc.scenario = _real_scenario()
    draft = gemini.analyze(inc, GOOD_WARM, DEFAULT_PARAMS, log=logged.append)
    assert draft is not None and draft["analyzer"] == "rules", "must fall back, not fail"
    assert any("gemini output rejected" in m for m in logged), "the gate must say so out loud"


def _real_scenario() -> dict:
    from core.bus import LOSSY_DELAY_MS, FaultState
    from core.csp_mini import build_scenario, make_agent
    return build_scenario(make_agent("N1.throughput", "throughput"),
                          make_agent("N2.security", "security"),
                          {"link_quality": "lossy", "workload": "steady",
                           "pair": ["N1", "N2"], "seed": 7},
                          7, FaultState(default_delay_ms=LOSSY_DELAY_MS))


# --- the shared self-verify gate ----------------------------------------------


def test_every_analyzer_faces_the_same_self_replay_gate():
    """Whatever drafted it, an unreproducible claim is never submitted."""
    inc = incident()
    inc.scenario = _real_scenario()
    # A claim that genuinely helps survives.
    good = rules.build_draft(inc, {"params": {"negotiate_timeout_ms": 30000, "r_max": 6,
                                              "eps": 0.08}, "warm_start": dict(GOOD_WARM)},
                             DEFAULT_PARAMS, "gemini")
    assert good is not None and good["analyzer"] == "gemini"
    ev = good["evidence"]
    assert ev["metric_after"]["duration_ms"] <= ev["metric_before"]["duration_ms"] * 0.8

    # A ruinous one does not, no matter who proposed it.
    assert rules.build_draft(inc, {"params": {"negotiate_timeout_ms": 1000}},
                             DEFAULT_PARAMS, "gemini") is None


# --- the UI's seam ------------------------------------------------------------


def test_run_emits_the_events_the_ui_renders(tmp_path):
    """The UI subscribes to run()'s on_event -- the same code path the terminal demo
    and every other test exercises. If this drifts, the UI is showing fiction."""
    events = []
    mesh, rows, _marks = run(42, True, quiet=True, out_dir=str(tmp_path), on_event=events.append)

    kinds = [e["type"] for e in events]
    assert kinds[0] == "run_start" and kinds[-1] == "run_end"
    tasks = [e for e in events if e["type"] == "task"]
    assert len(tasks) == 30
    assert all({"idx", "rounds", "duration_ms", "aborted", "insight_ids", "warm"} <= set(t)
               for t in tasks)

    # The ratchet must be visible in the stream, not just in the summary.
    assert any(t["warm"] and t["rounds"] == 1 for t in tasks)
    n3 = [t for t in tasks if t["node"] == "N3" and t["insight_ids"]]
    assert n3 and all(t["rounds"] == 1 for t in n3), "cross-node reuse must reach the UI"

    pipes = [e for e in events if e["type"] == "pipeline" and e.get("id")]
    assert pipes and pipes[0]["status"] == "VERIFIED"
    # The lifecycle panel must show a PEER's measurement, never the author's claim.
    assert pipes[0]["measured_by"] in ("N2", "N3")
    assert len(pipes[0]["attestations"]) >= 2

    fabs = [e for e in events if e["type"] == "fabric"]
    assert fabs and fabs[-1]["converged"] is True
    assert set(fabs[-1]["nodes"]) == {"N1", "N2", "N3"}


def test_fabric_event_is_json_safe_and_reflects_node_state(tmp_path):
    mesh, _rows, _m = run(42, True, quiet=True, out_dir=str(tmp_path))
    import json
    e = fabric_event(mesh)
    json.dumps(e)  # must not raise: it goes down a websocket
    assert e["converged"] is True
    assert any(i["status"] == "VERIFIED" for i in e["nodes"]["N3"]["insights"])


def test_ui_server_imports_without_a_running_loop():
    """A broken import is a black screen in front of judges."""
    from ui import server
    assert server.app is not None and callable(server.hub.publish)
