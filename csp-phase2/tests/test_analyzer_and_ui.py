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
    assert claim is None and "GEMINI_API_KEY not set" in why

    logged = []
    inc = incident()
    inc.scenario = _real_scenario()
    draft = gemini.analyze(inc, GOOD_WARM, DEFAULT_PARAMS, log=logged.append)
    assert draft is not None and draft["analyzer"] == "rules", "must fall back, not fail"
    assert any("gemini output rejected" in m for m in logged), "the gate must say so out loud"


def test_gemini_falls_back_to_rules_when_its_claim_fails_our_own_replay(monkeypatch):
    """The OTHER rejection path, and the one that bites live.

    A grounded, in-bounds, perfectly plausible claim that simply does not
    reproduce is still a rejection. Returning None here means the node draws a
    blank on this incident and the ratchet only fires if a later incident happens
    to arrive -- observed live: gemini's task-13 claim failed self-replay and the
    run was rescued purely by task 14 breaching again. On the last incident of an
    era there is no rescue.
    """
    # Grounded and legal, but it changes nothing that matters: no warm start, and
    # a round cap the negotiation never reaches. Self-replay must refuse it.
    monkeypatch.setattr(gemini, "propose_claim",
                        lambda *_a, **_k: ({"params": {"r_max": 12}}, "gemini: a hunch", ""))
    logged = []
    inc = incident()
    inc.scenario = _real_scenario()
    draft = gemini.analyze(inc, GOOD_WARM, DEFAULT_PARAMS, log=logged.append)

    assert draft is not None, "a claim we refused must fall back, not silence the node"
    assert draft["analyzer"] == "rules"
    assert draft["claim"].get("warm_start"), "the rules draft must be the real one"
    assert any("did not reproduce" in m for m in logged), "the discard must stay visible"


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


# --- per-task drill-down + step gate -------------------------------------------


def test_task_detail_reconstructs_the_whole_handshake_from_a_row(tmp_path):
    """The UI's task click. Feasibility is recomputed from the two declarations
    rather than logged during the run, so it cannot drift from what the engine
    did -- but that only holds if it reconstructs the SAME negotiation."""
    from demo.run_demo import run, task_detail

    rows = []
    run(42, True, quiet=True, out_dir=str(tmp_path), on_row=rows.append)
    assert len(rows) == 30

    d = task_detail(rows[0])
    assert [a["agent"] for a in d["declared"]] == ["N1.throughput", "N2.security"]
    assert d["relaxed"] == [] and d["feasible_points"] > 0
    # The declared region must be the one the personas actually imply.
    dom = {r["dim"]: r["domain"] for r in d["region"]}
    assert dom["tls_version"] == "{1.3}" and dom["log_export"] == "{True}"
    assert dom["inspection_depth"] == "{selective_deep, full_deep}"

    # Every signed envelope, in order, with utilities recomputed from public info.
    assert len(d["messages"]) == rows[0]["result"].messages
    assert d["messages"][0]["type"] == "INTENT_DECLARE"
    offers = [m for m in d["messages"] if "point" in m]
    assert offers and all(0.0 <= m["u_a"] <= 1.0 and 0.0 <= m["u_b"] <= 1.0 for m in offers)
    assert all(m["sig"] for m in d["messages"]), "every envelope is signed"

    c = d["contract"]
    assert c and c["contract_id"] == rows[0]["result"].contract["contract_id"]
    assert all(c["enforced"].values()), "the enforcement guard must re-pass here"


def test_task_detail_shows_the_reuse_on_the_cross_node_task(tmp_path):
    """Task 25 is the one a judge will click: N3 opening on N1's remembered point."""
    from demo.run_demo import run, task_detail

    rows = []
    run(42, True, quiet=True, out_dir=str(tmp_path), on_row=rows.append)
    d = task_detail(rows[24])  # task 25

    assert d["idx"] == 25 and d["pair"] == "N3xN2" and d["era"] == "act3-crossnode"
    assert d["config"]["epoch"] == 1 and d["config"]["insight_ids"], "must be applying an insight"
    assert d["config"]["warm_start"], "the remembered settlement must be visible"
    assert d["contract"]["warm_started"] is True
    assert d["result"]["rounds"] == 1, "the whole point: one round"
    # The opening PROPOSE should already be at the remembered point.
    first = next(m for m in d["messages"] if m["type"] == "PROPOSE")
    assert first["point"] == d["config"]["warm_start"]


def test_task_detail_survives_an_aborted_task(tmp_path):
    """Aborted tasks have no contract. The panel must render them, not throw --
    tasks 10/12/13 abort on seed 42 and they are IN the clickable stream."""
    from demo.run_demo import run, task_detail

    rows = []
    run(42, True, quiet=True, out_dir=str(tmp_path), on_row=rows.append)
    aborted = [r for r in rows if r["result"].aborted]
    assert aborted, "seed 42 must still produce cold-era timeouts"
    d = task_detail(aborted[0])
    assert d["contract"] is None
    assert d["result"]["aborted"] and d["result"]["abort_reason"] == "TIMEOUT"
    assert d["declared"] and d["region"], "intent and region exist even without a contract"


def test_task_detail_is_json_safe(tmp_path):
    """It goes over HTTP. A set or a dataclass in here is a 500 mid-demo."""
    import json as _json
    from demo.run_demo import run, task_detail

    rows = []
    run(42, True, quiet=True, out_dir=str(tmp_path), on_row=rows.append)
    for r in (rows[0], rows[24]):
        _json.dumps(task_detail(r))  # raises on anything unserialisable


def test_the_gate_can_single_step_and_cannot_change_the_outcome(tmp_path):
    """Step mode is presentation. Gating every task must not move a single number."""
    from demo.run_demo import run, summarize

    a_mesh, a_rows, _ = run(42, True, quiet=True, out_dir=str(tmp_path / "free"))

    seen = []
    b_mesh, b_rows, _ = run(42, True, quiet=True, out_dir=str(tmp_path / "gated"),
                            gate=seen.append)
    assert seen == list(range(1, 31)), "the gate must be offered every task, in order"
    assert summarize(a_mesh, a_rows) == summarize(b_mesh, b_rows)
    assert [r["result"].transcript_hash for r in a_rows] == \
           [r["result"].transcript_hash for r in b_rows]


def test_pace_is_honoured_even_when_quiet(monkeypatch, tmp_path):
    """The UI runs quiet. With the sleep inside the `not quiet` guard the pace
    control silently did nothing and a 30-task run flashed past in under a second.
    """
    from demo import run_demo

    slept = []
    monkeypatch.setattr(run_demo.time, "sleep", lambda s: slept.append(s))
    run_demo.run(42, True, quiet=True, out_dir=str(tmp_path), pace=0.25)
    assert len(slept) == 30 and all(s == 0.25 for s in slept)
