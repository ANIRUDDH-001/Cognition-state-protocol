"""Phase 1 verification: the CSP handshake core (Doc 2 §15 test plan).

These are the properties the Phase 2 fabric is allowed to assume. If any of them
break, no amount of fabric machinery is defensible -- an insight is only safe to
apply because negotiation is fail-closed underneath it.
"""
from __future__ import annotations

import random

import pytest

from core.bus import LOSSY_DELAY_MS, NORMAL_DELAY_MS, Bus, Clock, FaultState
from core.crypto import Identity, Keyring, canonical, sign_envelope, verify_envelope
from core.csp_mini import (
    AgentConfig,
    build_scenario,
    feasible_box,
    feasible_points,
    hard_ok,
    make_agent,
    negotiate,
    replay,
    validate_descriptor,
    descriptor,
    authority_map,
)
from core.registry import DEFAULT_PARAMS, DIM_IDS, NEVER_RELAX


def mesh(link="normal", seed=42):
    rng = random.Random(seed)
    faults = FaultState(default_delay_ms=LOSSY_DELAY_MS if link == "lossy" else NORMAL_DELAY_MS)
    return Bus(Clock(0.0), faults, rng), faults


def run(link="normal", seed=42, warm=None, params=None, a=None, b=None):
    bus, _ = mesh(link, seed)
    A = a or make_agent("N1.throughput", "throughput")
    B = b or make_agent("N2.security", "security")
    ctx = {"link_quality": link, "workload": "steady", "pair": ["N1", "N2"], "seed": seed}
    p = dict(DEFAULT_PARAMS)
    p.update(params or {})
    return negotiate(bus, A, B, ctx, p, warm_start=warm)


# --- canonical JSON + crypto (Doc 2 §2, §11) ---------------------------------


def test_canonical_json_is_key_order_independent():
    assert canonical({"b": 1, "a": {"y": 2, "x": 3}}) == canonical({"a": {"x": 3, "y": 2}, "b": 1})


def test_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        canonical({"x": float("nan")})


def test_signature_roundtrip_and_tamper_detection():
    ident = Identity.deterministic("agent-A")
    kr = Keyring()
    kr.pin_identity(ident)
    env = sign_envelope(ident, {"schema": "csp/1.0", "type": "PROPOSE", "from": "agent-A",
                                "to": "agent-B", "seq": 0, "payload": {"round": 1}})
    assert verify_envelope(kr, env)

    tampered = dict(env)
    tampered["payload"] = {"round": 2}
    assert not verify_envelope(kr, tampered), "payload tamper must not verify"


def test_unpinned_source_never_verifies():
    ident = Identity.deterministic("rogue")
    env = sign_envelope(ident, {"from": "rogue", "to": "x", "payload": {}})
    assert not verify_envelope(Keyring(), env), "empty keyring must trust nothing"


def test_deterministic_identity_is_stable_across_processes():
    assert Identity.deterministic("N1").public_b64 == Identity.deterministic("N1").public_b64
    assert Identity.deterministic("N1").public_b64 != Identity.deterministic("N2").public_b64


# --- feasibility per type (Doc 2 §9.1) ---------------------------------------


def test_feasibility_intersects_every_dimension_type():
    A, B = make_agent("a", "throughput"), make_agent("b", "security")
    box, relaxed = feasible_box([A, B])
    assert relaxed == [], "standard personas must not need relaxation"
    assert box["netops/latency_ms"][1] == 12.0          # continuous: A's le 12
    assert box["netops/inspection_depth"][0] == 2       # ordinal: B's ge selective_deep
    assert box["netops/tls_version"] == {"1.3"}         # categorical: {1.2,1.3} ∩ {1.3}
    assert box["netops/log_export"] == {True}           # boolean: B's eq true
    assert box["netops/sample_rate"][0] == 0.25         # continuous: B's coverage floor


def test_feasible_points_respect_the_coupling_model():
    from core.registry import coupling_ok
    box, _ = feasible_box([make_agent("a", "throughput"), make_agent("b", "security")])
    F = feasible_points(box, DEFAULT_PARAMS["grid_k"])
    assert F, "feasible region must be non-empty for the standard scenario"
    assert all(coupling_ok(p) for p in F)


def test_relaxation_drops_lowest_class_first_and_records_it():
    A = make_agent("a", "throughput")
    B = make_agent("b", "security")
    # Manufacture an impasse between two OPERATIONAL constraints.
    A.hard = [{"dim": "netops/latency_ms", "op": "le", "value": 5.0, "class": "operational"}]
    B.hard = [{"dim": "netops/latency_ms", "op": "ge", "value": 20.0, "class": "operational"}]
    box, relaxed = feasible_box([A, B])
    assert box is not None, "an operational impasse must be relaxable"
    assert relaxed and all(r["class"] not in NEVER_RELAX for r in relaxed)


def test_safety_and_regulatory_are_never_relaxed_and_we_fail_closed():
    A = make_agent("a", "throughput")
    B = make_agent("b", "security")
    A.hard = [{"dim": "netops/tls_version", "op": "in", "value": ["1.2"], "class": "regulatory"}]
    B.hard = [{"dim": "netops/tls_version", "op": "in", "value": ["1.3"], "class": "regulatory"}]
    box, relaxed = feasible_box([A, B])
    assert box is None, "regulatory conflict must NOT be resolved by relaxing"
    assert all(r["class"] not in NEVER_RELAX for r in relaxed)

    r = run(a=A, b=B)
    assert r.aborted and r.abort_reason == "EMPTY_FEASIBLE"


# --- descriptor validation (Doc 2 §5) ----------------------------------------


def test_competence_budget_over_one_is_rejected():
    A = make_agent("a", "throughput")
    A.competence = {d: 0.5 for d in list(A.competence)}  # sums to 2.0
    assert validate_descriptor(descriptor(A)) == "POLICY_VIOLATION"


def test_objective_weights_must_sum_to_one():
    A = make_agent("a", "throughput")
    A.objectives[0]["weight"] = 0.9  # 0.9 + 0.4 != 1.0
    assert validate_descriptor(descriptor(A)) == "POLICY_VIOLATION"


def test_standard_personas_validate():
    for p in ("throughput", "security"):
        assert validate_descriptor(descriptor(make_agent("x", p))) is None


# --- the handshake itself -----------------------------------------------------


def test_handshake_reaches_a_signed_contract_bound_by_both_parties():
    r = run()
    assert not r.aborted, r.abort_reason
    c = r.contract
    assert set(c["agreed"]) == set(DIM_IDS), "every shared dim must have a concrete value"
    assert len(c["signatures"]) == 2, "both parties must countersign"
    assert c["transcript_hash"] and c["contract_id"].startswith("csp-")
    assert c["ontology_hash"], "contract must pin what every word meant"


def test_outcome_always_satisfies_both_agents_hard_constraints():
    """The enforcement property. This is what 'bound their behavior by' means."""
    A, B = make_agent("N1.throughput", "throughput"), make_agent("N2.security", "security")
    for seed in range(12):
        r = run(seed=seed, a=A, b=B)
        assert not r.aborted, f"seed {seed}: {r.abort_reason}"
        assert hard_ok(A, r.contract["agreed"]), f"seed {seed} violates A"
        assert hard_ok(B, r.contract["agreed"]), f"seed {seed} violates B"


def test_negotiation_terminates_within_the_round_cap():
    for seed in range(12):
        for r_max in (2, 4, 8, 12):
            r = run(seed=seed, params={"r_max": r_max})
            assert r.rounds <= r_max, f"seed {seed} r_max {r_max} -> {r.rounds} rounds"
            assert not r.aborted


def test_concession_settles_by_acceptance_not_by_the_cap():
    """The cap is a guarantee, not the normal path. If this flips to settlement
    the concession schedule has stopped converging and the Doc 4 §5 claim is dead."""
    resolved = [run(seed=s).contract["provenance"]["resolved_by"] for s in range(12)]
    assert all(x == "acceptance" for x in resolved), resolved


def test_opposing_agents_actually_conflict():
    """Guards the scenario, not the engine: if the personas settle at each other's
    optimum in one round there is no negotiation to demonstrate."""
    r = run()
    assert r.rounds >= 3, "a one-round cold settlement means the personas do not conflict"
    agreed = r.contract["agreed"]
    assert agreed["netops/sample_rate"] > 0.0, "depth without coverage is not a real settlement"


def test_authority_map_is_argmax_competence():
    A, B = make_agent("N1.throughput", "throughput"), make_agent("N2.security", "security")
    am = authority_map([A, B])
    assert am["netops/latency_ms"] == "N1.throughput"
    assert am["netops/inspection_depth"] == "N2.security"


# --- determinism (Doc 2 §15) --------------------------------------------------


def test_same_seed_yields_identical_transcript_hash():
    a, b = run(seed=7), run(seed=7)
    assert a.transcript_hash == b.transcript_hash
    assert a.contract["contract_id"] == b.contract["contract_id"]
    assert a.duration_ms == b.duration_ms


def test_different_seeds_change_timing_but_never_the_settlement():
    """Transport jitter must not move the agreed point -- only the clock."""
    base = run(seed=1).contract["agreed"]
    for seed in range(2, 8):
        assert run(seed=seed).contract["agreed"] == base


def test_replay_is_byte_identical_and_independent_of_wall_clock():
    """THE verification primitive. Two nodes must reach the same bytes."""
    A, B = make_agent("N1.throughput", "throughput"), make_agent("N2.security", "security")
    ctx = {"link_quality": "lossy", "workload": "steady", "pair": ["N1", "N2"], "seed": 99}
    scen = build_scenario(A, B, ctx, 99, FaultState(default_delay_ms=LOSSY_DELAY_MS))
    r1, r2 = replay(scen, DEFAULT_PARAMS), replay(scen, DEFAULT_PARAMS)
    assert r1.summary() == r2.summary()
    assert r1.transcript_hash == r2.transcript_hash


# --- transport faults ---------------------------------------------------------


def test_lossy_link_is_slow_but_still_correct():
    fast, slow = run("normal"), run("lossy")
    assert slow.duration_ms > 20 * fast.duration_ms, "lossy era must actually hurt"
    assert slow.contract["agreed"] == fast.contract["agreed"], "latency must not move the outcome"


def test_a_dead_peer_aborts_on_timeout_rather_than_hanging():
    bus, faults = mesh("normal")
    faults.node_down.add("N2")
    A, B = make_agent("N1.throughput", "throughput"), make_agent("N2.security", "security")
    ctx = {"link_quality": "normal", "workload": "steady", "pair": ["N1", "N2"], "seed": 1}
    r = negotiate(bus, A, B, ctx, DEFAULT_PARAMS)
    assert r.aborted and r.abort_reason == "TIMEOUT"
    assert r.contract is None, "fail closed: no contract without a counterparty"


def test_budget_too_small_aborts_and_never_half_commits():
    r = run("lossy", params={"negotiate_timeout_ms": 1200})
    assert r.aborted and r.abort_reason == "TIMEOUT"
    assert r.contract is None


# --- warm start: the property Phase 2 rests on --------------------------------


def test_warm_start_cuts_rounds_without_changing_what_is_enforced():
    A, B = make_agent("N1.throughput", "throughput"), make_agent("N2.security", "security")
    cold = run("lossy", a=A, b=B)
    warm = run("lossy", warm=cold.contract["agreed"], a=A, b=B)
    assert warm.rounds < cold.rounds
    assert warm.duration_ms < cold.duration_ms * 0.8, "must clear the 20% verification bar"
    assert warm.contract["warm_started"] is True
    assert hard_ok(A, warm.contract["agreed"]) and hard_ok(B, warm.contract["agreed"])


def test_a_stale_warm_start_costs_rounds_but_never_correctness():
    """Invariant 4. A poisoned or stale insight must degrade to the cold path."""
    A, B = make_agent("N1.throughput", "throughput"), make_agent("N2.security", "security")
    junk = {"netops/latency_ms": 1.0, "netops/throughput_mbps": 10000.0,
            "netops/inspection_depth": "none", "netops/sample_rate": 0.0,
            "netops/tls_version": "1.2", "netops/log_export": False}
    r = run("normal", warm=junk, a=A, b=B)
    assert not r.aborted
    assert r.contract["warm_started"] is False, "infeasible warm start must be discarded"
    assert hard_ok(A, r.contract["agreed"]) and hard_ok(B, r.contract["agreed"])
    assert r.contract["agreed"]["netops/tls_version"] == "1.3"
    assert r.contract["agreed"]["netops/log_export"] is True
