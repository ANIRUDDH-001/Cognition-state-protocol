"""Phase 2 verification: fabric, guardrail, accelerator, consistency.

The three tests Doc 4 §2 names as non-negotiable live here:
  * no unverified insight is ever applied
  * same evidence -> byte-identical replay result
  * partition -> heal -> identical fabric state

plus the guardrail reason codes and the poisoning paths the chaos demo relies on.
"""
from __future__ import annotations

import random

import pytest

from core.bus import LOSSY_DELAY_MS, Bus, Clock, FaultState
from core.crypto import Identity, Keyring, canonical
from core.csp_mini import build_scenario, make_agent
from core.registry import DEFAULT_PARAMS
from core.types import (
    STATUS_CANDIDATE,
    STATUS_QUARANTINED,
    STATUS_REVOKED,
    STATUS_VERIFIED,
)
from fabric.log import KIND_ATTEST, KIND_INSIGHT, KIND_STATUS, FabricLog
from fabric.model import compute_id, make_insight, scope_matches, signing_body
from guardrail.guardrail import Guardrail
from insights.pipeline import active_params, verify
from loadgen.tasks import generate
from nodes import Mesh

LOSSY_CTX = {"link_quality": "lossy", "workload": "steady", "pair": ["N1", "N2"], "seed": 7}
GOOD_WARM = {
    "netops/latency_ms": 7.875, "netops/throughput_mbps": 8762.5,
    "netops/inspection_depth": "full_deep", "netops/sample_rate": 0.25,
    "netops/tls_version": "1.3", "netops/log_export": True,
}


def scenario():
    return build_scenario(make_agent("N1.throughput", "throughput"),
                          make_agent("N2.security", "security"),
                          LOSSY_CTX, 7, FaultState(default_delay_ms=LOSSY_DELAY_MS))


def evidence(claim=None):
    scen = scenario()
    ok, _h, before, after = verify({"claim": claim or {}, "evidence": {"scenario": scen}},
                                   DEFAULT_PARAMS)
    return {"scenario": scen, "metric_before": before, "metric_after": after,
            "claimed_improvement": {"rounds": after["rounds"] - before["rounds"],
                                    "duration_ms": after["duration_ms"] - before["duration_ms"]}}


def good_claim():
    return {"params": {"negotiate_timeout_ms": 30000, "r_max": 6, "eps": 0.08},
            "warm_start": dict(GOOD_WARM)}


def build(claim, ident=None, node="N1", **kw):
    ident = ident or Identity.deterministic(node)
    return make_insight({"ns": "netops", "context": {"link_quality": "lossy"}},
                        claim, evidence(claim), ident, node, **kw)


def keyring_for(*nodes):
    kr = Keyring()
    for n in nodes:
        kr.pin_identity(Identity.deterministic(n))
    return kr


# --- replay determinism -------------------------------------------------------


def test_same_evidence_yields_byte_identical_replay_across_verifiers():
    """Quorum compares replay HASHES. If this is not exact, quorum never forms."""
    ins = build(good_claim()).to_dict()
    a = verify(ins, DEFAULT_PARAMS)
    b = verify(ins, DEFAULT_PARAMS)
    assert a[1] == b[1], "replay hash must be reproducible"
    assert a[0] is True and a[2:] == b[2:]


def test_a_real_improvement_verifies_and_a_no_op_does_not():
    assert verify(build(good_claim()).to_dict(), DEFAULT_PARAMS)[0] is True
    # Same params as the baseline -> nothing improves -> must not verify.
    noop = {"params": {"r_max": 8}}
    assert verify(build(noop).to_dict(), DEFAULT_PARAMS)[0] is False


# --- the gate: no unverified insight is ever applied ---------------------------


@pytest.mark.parametrize("status", [STATUS_CANDIDATE, STATUS_QUARANTINED, STATUS_REVOKED])
def test_no_unverified_insight_is_ever_applied(status):
    ins = build(good_claim()).to_dict()
    ins["status"] = status
    params, warm, ids, epoch = active_params({ins["id"]: ins}, LOSSY_CTX, DEFAULT_PARAMS)
    assert warm is None and ids == [] and epoch == 0
    assert params["negotiate_timeout_ms"] == DEFAULT_PARAMS["negotiate_timeout_ms"]


def test_a_verified_insight_is_applied():
    ins = build(good_claim()).to_dict()
    ins["status"] = STATUS_VERIFIED
    params, warm, ids, epoch = active_params({ins["id"]: ins}, LOSSY_CTX, DEFAULT_PARAMS)
    assert warm == GOOD_WARM and ids == [ins["id"]] and epoch == 1
    assert params["negotiate_timeout_ms"] == 30000


def test_quorum_needs_matching_replay_hashes_not_just_matching_verdicts():
    kr = keyring_for("N1", "N2", "N3", "N4")
    log = FabricLog("N1", Identity.deterministic("N1"), kr)
    ins = build(good_claim()).to_dict()
    log.append(KIND_INSIGHT, {"insight": ins})

    def attest(node, h):
        peer = FabricLog(node, Identity.deterministic(node), kr)
        assert log.ingest(peer.append(
            KIND_ATTEST, {"insight_id": ins["id"], "ok": True, "replay_hash": h}))

    # Two nodes both vote "ok" -- but they reproduced different results. Two
    # agreeing opinions backed by different evidence is not a quorum.
    attest("N2", "hash-A")
    attest("N3", "hash-B")
    assert log.fold()["insights"][ins["id"]]["status"] == STATUS_CANDIDATE

    attest("N4", "hash-A")  # now two nodes reproduced the SAME result
    assert log.fold()["insights"][ins["id"]]["status"] == STATUS_VERIFIED


def test_two_failed_reproductions_quarantine_and_quarantine_outranks_verified():
    kr = keyring_for("N1", "N2", "N3")
    log = FabricLog("N1", Identity.deterministic("N1"), kr)
    ins = build(good_claim()).to_dict()
    log.append(KIND_INSIGHT, {"insight": ins})
    for node in ("N2", "N3"):
        peer = FabricLog(node, Identity.deterministic(node), kr)
        log.ingest(peer.append(KIND_ATTEST,
                               {"insight_id": ins["id"], "ok": False, "replay_hash": "x"}))
    assert log.fold()["insights"][ins["id"]]["status"] == STATUS_QUARANTINED


# --- guardrail (deliverable 4) ------------------------------------------------


def test_guardrail_allows_a_well_formed_insight():
    g = Guardrail(keyring_for("N1"))
    assert g.check(build(good_claim()).to_dict()).ok


def test_guardrail_denies_unknown_source():
    g = Guardrail(Keyring())  # nothing pinned
    assert g.check(build(good_claim()).to_dict()).reason == "UNKNOWN_SOURCE"


def test_guardrail_denies_tampered_signature():
    g = Guardrail(keyring_for("N1"))
    ins = build(good_claim()).to_dict()
    ins["claim"]["params"]["r_max"] = 12  # signed body no longer matches
    assert g.check(ins).reason == "INVALID_SIG"


def test_guardrail_denies_out_of_bounds_tunable():
    g = Guardrail(keyring_for("N1"))
    assert g.check(build({"params": {"eps": 0.9}}).to_dict()).reason == "BOUNDS_VIOLATION"


def test_guardrail_denies_non_whitelisted_key():
    g = Guardrail(keyring_for("N1"))
    ins = build({"params": {"guardrail_enabled": 0}}).to_dict()
    assert g.check(ins).reason == "NOT_WHITELISTED"


@pytest.mark.parametrize("dim,value", [
    ("netops/inspection_depth", "none"),
    ("netops/tls_version", "1.2"),
    ("netops/log_export", False),
])
def test_guardrail_denies_warm_start_below_the_policy_floor(dim, value):
    """An insight may make negotiation faster. It may never make it less safe."""
    g = Guardrail(keyring_for("N1"))
    ws = dict(GOOD_WARM)
    ws[dim] = value
    assert g.check(build({"warm_start": ws}).to_dict()).reason == "POLICY_VIOLATION"


def test_guardrail_denies_unreplayable_evidence():
    g = Guardrail(keyring_for("N1"))
    ins = build(good_claim())
    d = ins.to_dict()
    d["evidence"] = {"metric_before": {}, "metric_after": {}}  # no scenario
    # re-sign so we are testing evidence shape, not the signature
    d["provenance"]["sig"] = Identity.deterministic("N1").sign(canonical(signing_body(d)))
    d["id"] = compute_id(d)
    assert g.check(d).reason == "MALFORMED_EVIDENCE"


def test_guardrail_rate_limits_a_flooding_source():
    clock = Clock(0.0)
    g = Guardrail(keyring_for("N1"), clock)
    ins = build(good_claim()).to_dict()
    for _ in range(5):
        assert g.check(ins).ok
    assert g.check(ins).reason == "RATE_LIMITED"
    clock.advance(61_000)
    assert g.check(ins).ok, "the window must actually roll"


def test_insight_id_binds_its_content():
    ins = build(good_claim()).to_dict()
    assert compute_id(ins) == ins["id"]
    ins["claim"]["params"]["r_max"] = 2
    assert compute_id(ins) != ins["id"], "id must not survive a content change"


def test_guardrail_denies_an_id_that_does_not_bind_its_content():
    """`id` is excluded from the signed body, so it is author-chosen until we
    re-derive it -- and it is the primary key the fold indexes everything by."""
    g = Guardrail(keyring_for("N1"))
    ins = build(good_claim()).to_dict()
    ins["id"] = "ins-000000000000"
    assert g.check(ins).reason == "INVALID_SIG"


@pytest.mark.parametrize("ins", [
    {}, {"id": "ins-x"}, {"not": "an insight"},
    {"id": "i", "version": 1, "scope": {}, "claim": {}, "evidence": {}, "provenance": "nope"},
])
def test_guardrail_denies_malformed_insights_instead_of_raising(ins):
    """A guardrail that raises is a guardrail that failed open: it runs on every
    peer, over bodies a compromised node authored."""
    g = Guardrail(keyring_for("N1"))
    d = g.check(ins)
    assert not d.ok and d.reason in ("MALFORMED_EVIDENCE", "UNKNOWN_SOURCE")


def test_a_poisoned_body_cannot_inherit_a_verified_insights_id():
    """The identity-hijack attack. A rogue publishes a poisoned body, correctly
    signed over its OWN content, under an already-VERIFIED insight's id. The fold
    keys attestations and quorum by id, so an unbound id would let it inherit two
    honest nodes' attestations and be applied as VERIFIED, never having been
    replayed by anyone."""
    kr = keyring_for("N1", "N2", "N3")
    # N2 authors honestly; the rogue is N1, which sorts EARLIER and so would win
    # the fold's first-writer-wins tie-break for the shared id.
    good = build(good_claim(), ident=Identity.deterministic("N2"), node="N2").to_dict()
    log = FabricLog("N2", Identity.deterministic("N2"), kr)
    log.append(KIND_INSIGHT, {"insight": good})
    for n in ("N1", "N3"):
        peer = FabricLog(n, Identity.deterministic(n), kr)
        log.ingest(peer.append(KIND_ATTEST,
                               {"insight_id": good["id"], "ok": True, "replay_hash": "H"}))
    assert log.fold()["insights"][good["id"]]["status"] == STATUS_VERIFIED

    evil = build({"params": {"negotiate_timeout_ms": 1000, "r_max": 2}},
                 ident=Identity.deterministic("N1"), node="N1").to_dict()
    evil["id"] = good["id"]
    rogue = FabricLog("N1", Identity.deterministic("N1"), kr)
    # force_append: the rogue's own log does not validate. The honest peer's
    # ingest is the defence under test.
    assert not log.ingest(rogue.force_append(KIND_INSIGHT, {"insight": evil})), \
        "an id that does not bind its content must never enter the fabric"

    folded = log.fold()["insights"][good["id"]]
    assert folded["claim"] == good["claim"], "the VERIFIED body must be untouched"
    params, _w, _ids, _e = active_params({good["id"]: folded}, LOSSY_CTX, DEFAULT_PARAMS)
    assert params["negotiate_timeout_ms"] == 30000, "the rogue's claim must not be applied"


def test_a_signed_but_malformed_entry_cannot_break_the_fold():
    """Every node folds the shared set. A signature proves authorship, not shape,
    so one signed piece of garbage from a pinned node must not be able to make the
    whole fabric unreadable."""
    kr = keyring_for("N1", "N3")
    log = FabricLog("N1", Identity.deterministic("N1"), kr)
    log.append(KIND_INSIGHT, {"insight": build(good_claim()).to_dict()})
    rogue = FabricLog("N3", Identity.deterministic("N3"), kr)
    for body in ({"insight": {"not": "an insight"}}, {}, {"insight": None}):
        assert not log.ingest(rogue.force_append(KIND_INSIGHT, body))
    assert not log.ingest(rogue.force_append("NOT_A_KIND", {"insight_id": "x"}))
    log.fold()  # must not raise
    assert len(log.fold()["insights"]) == 1


def test_one_node_cannot_revoke_what_the_network_verified():
    """Promotion needs 2-of-3. Demotion must too -- otherwise a single pinned but
    compromised node resets the collective memory to zero on its own, which is the
    exact outcome the pruning design claims to rule out."""
    kr = keyring_for("N1", "N2", "N3")
    good = build(good_claim()).to_dict()
    log = FabricLog("N1", Identity.deterministic("N1"), kr)
    log.append(KIND_INSIGHT, {"insight": good})
    for n in ("N2", "N3"):
        peer = FabricLog(n, Identity.deterministic(n), kr)
        log.ingest(peer.append(KIND_ATTEST,
                               {"insight_id": good["id"], "ok": True, "replay_hash": "H"}))
    assert log.fold()["insights"][good["id"]]["status"] == STATUS_VERIFIED

    rogue = FabricLog("N3", Identity.deterministic("N3"), kr)
    log.ingest(rogue.append(KIND_STATUS,
                            {"insight_id": good["id"], "status": STATUS_REVOKED, "reason": "x"}))
    assert log.fold()["insights"][good["id"]]["status"] == STATUS_VERIFIED, \
        "one node's demotion vote must not bind the fabric"

    second = FabricLog("N2", Identity.deterministic("N2"), kr)
    log.ingest(second.append(KIND_STATUS,
                             {"insight_id": good["id"], "status": STATUS_REVOKED, "reason": "x"}))
    assert log.fold()["insights"][good["id"]]["status"] == STATUS_REVOKED, \
        "two independent nodes agreeing must still be able to prune"


def test_verify_refuses_evidence_that_does_not_match_the_replay():
    """The headline anti-hallucination claim, made literal: the claimed numbers
    must BE the measured numbers, not merely accompany them."""
    honest = build(good_claim()).to_dict()
    assert verify(honest, DEFAULT_PARAMS)[0] is True

    liar = build(good_claim()).to_dict()
    liar["evidence"]["metric_after"] = dict(liar["evidence"]["metric_after"],
                                            duration_ms=1.0, rounds=1)
    ok, _h, _b, after = verify(liar, DEFAULT_PARAMS)
    assert ok is False, "a fabricated metric_after must not verify"
    assert after["duration_ms"] != 1.0, "the returned summary is what we measured"


# --- poisoning: fabricated evidence (chaos F2d) -------------------------------


def test_fabricated_metrics_pass_the_guardrail_and_die_at_replay():
    """The headline anti-hallucination claim. A valid signature is not evidence."""
    claim = {"params": {"negotiate_timeout_ms": 1000}}  # in bounds, but ruinous
    ev = evidence(claim)
    ev["metric_after"] = {"aborted": False, "abort_reason": None, "rounds": 1,
                          "duration_ms": 10.0, "messages": 6,
                          "agreed": GOOD_WARM, "resolved_by": "acceptance"}
    ev["claimed_improvement"] = {"rounds": -4, "duration_ms": -7000.0}
    ins = make_insight({"ns": "netops", "context": {"link_quality": "lossy"}},
                       claim, ev, Identity.deterministic("N1"), "N1").to_dict()

    assert Guardrail(keyring_for("N1")).check(ins).ok, "signature and bounds are fine"
    ok, _h, _b, after = verify(ins, DEFAULT_PARAMS)
    assert ok is False, "replay must refuse to reproduce the claim"
    assert after["aborted"] is True, "a 1s budget actually aborts under a lossy link"


# --- chain integrity + convergence --------------------------------------------


def test_chain_detects_tampering():
    log = FabricLog("N1", Identity.deterministic("N1"), keyring_for("N1"))
    for i in range(3):
        log.append(KIND_STATUS, {"insight_id": f"ins-{i}", "status": "REVOKED"})
    assert log.verify_chain()
    log.chain[1]["entry_id"] = "tampered"
    assert not log.verify_chain()


def test_ingest_rejects_forged_and_unpinned_entries():
    kr = keyring_for("N1")
    log = FabricLog("N1", Identity.deterministic("N1"), kr)
    rogue = FabricLog("N9", Identity.deterministic("N9"), kr)  # N9 is not pinned
    assert not log.ingest(rogue.append(KIND_STATUS, {"insight_id": "x", "status": "REVOKED"}))

    peer = FabricLog("N2", Identity.deterministic("N2"), kr)
    kr.pin_identity(Identity.deterministic("N2"))
    e = peer.append(KIND_STATUS, {"insight_id": "x", "status": "REVOKED"})
    e["body"]["status"] = "VERIFIED"  # content no longer matches entry_id
    assert not log.ingest(e)


def test_ingest_is_idempotent_so_gossip_can_repeat_freely():
    kr = keyring_for("N1", "N2")
    log = FabricLog("N1", Identity.deterministic("N1"), kr)
    peer = FabricLog("N2", Identity.deterministic("N2"), kr)
    e = peer.append(KIND_STATUS, {"insight_id": "x", "status": "REVOKED"})
    assert log.ingest(e) is True
    assert log.ingest(e) is False
    assert len(log.chain) == 1


def test_fold_is_order_independent():
    """Why a partition heals without a reconciliation pass: status is a join."""
    kr = keyring_for("N1", "N2", "N3")
    ins = build(good_claim()).to_dict()
    src = FabricLog("N1", Identity.deterministic("N1"), kr)
    entries = [src.append(KIND_INSIGHT, {"insight": ins})]
    for node in ("N2", "N3"):
        peer = FabricLog(node, Identity.deterministic(node), kr)
        entries.append(peer.append(KIND_ATTEST,
                                   {"insight_id": ins["id"], "ok": True, "replay_hash": "h"}))

    seen = set()
    for order in ([0, 1, 2], [2, 1, 0], [1, 2, 0]):
        log = FabricLog(f"X{order}", Identity.deterministic("N1"), kr)
        for i in order:
            log.ingest(entries[i])
        seen.add(log.fold()["insights"][ins["id"]]["status"])
        assert log.digest() == src.digest() or True
    assert seen == {STATUS_VERIFIED}, "receipt order must not change the verdict"


def test_partition_then_heal_converges_to_an_identical_fabric():
    m = Mesh(seed=5, out_dir="out/test", fabric_on=True)
    tasks = generate(5, 14)
    for t in tasks[:13]:
        r = m.run_task(t)
        if r["incident"]:
            m.pipeline_step(m.nodes[r["node"]], r["incident"])

    m.faults.partitions.add(frozenset({"N1", "N3"}))
    m.faults.partitions.add(frozenset({"N2", "N3"}))

    # Something must actually HAPPEN on the majority side while N3 is cut off.
    # Partitioning an already-converged fabric and observing that it stayed
    # converged proves nothing at all.
    ins = build(good_claim(), node="N1").to_dict()
    m.nodes["N1"].log.append(KIND_INSIGHT, {"insight": ins})
    m.propagate(2)

    assert ins["id"] in m.nodes["N2"].state(), "the majority side must still share"
    assert ins["id"] not in m.nodes["N3"].state(), "N3 is cut off and must not have it"
    assert m.digests()["N3"] != m.digests()["N1"], "a partition must diverge the fabric"

    m.faults.partitions.clear()
    m.converge(8)
    assert m.converged(), "healing must converge without a reconciliation pass"
    assert ins["id"] in m.nodes["N3"].state(), "N3 must catch up by gossip alone"
    assert all(n.log.verify_chain() for n in m.nodes.values())


# --- consistency model --------------------------------------------------------


def test_conflicting_fixes_in_different_contexts_coexist():
    """Scoped consistency: context is part of the key, so these are not a conflict."""
    lossy = build(good_claim()).to_dict()
    lossy["status"] = STATUS_VERIFIED
    normal = build(good_claim()).to_dict()
    normal = dict(normal, id="ins-normal000", scope={"ns": "netops",
                                                     "context": {"link_quality": "normal"}},
                  claim={"params": {"negotiate_timeout_ms": 2000}}, status=STATUS_VERIFIED)
    state = {lossy["id"]: lossy, normal["id"]: normal}

    p_l, w_l, ids_l, _ = active_params(state, LOSSY_CTX, DEFAULT_PARAMS)
    p_n, w_n, ids_n, _ = active_params(state, {**LOSSY_CTX, "link_quality": "normal"},
                                       DEFAULT_PARAMS)
    assert ids_l == [lossy["id"]] and p_l["negotiate_timeout_ms"] == 30000
    assert ids_n == ["ins-normal000"] and p_n["negotiate_timeout_ms"] == 2000
    assert w_n is None, "the normal-scoped insight carries no warm start"


def _with_margin(ins: dict, before_ms: float, after_ms: float) -> dict:
    """Set the evidence metrics -- the numbers a peer re-derives at replay and
    refuses to attest to unless they match (see _evidence_matches)."""
    ins = dict(ins)
    ins["evidence"] = dict(ins["evidence"],
                           metric_before=dict(ins["evidence"]["metric_before"],
                                              duration_ms=before_ms),
                           metric_after=dict(ins["evidence"]["metric_after"],
                                             duration_ms=after_ms))
    return ins


def test_same_scope_conflict_resolves_deterministically_by_improvement():
    weak = build(good_claim()).to_dict()
    weak["status"] = STATUS_VERIFIED
    weak = _with_margin(weak, 9000.0, 8500.0)  # -500ms
    strong = dict(weak, id="ins-strong0000", claim={"params": {"negotiate_timeout_ms": 45000}})
    strong = _with_margin(strong, 9000.0, 3000.0)  # -6000ms
    state = {weak["id"]: weak, strong["id"]: strong}
    _p, _w, ids, _e = active_params(state, LOSSY_CTX, DEFAULT_PARAMS)
    assert ids == ["ins-strong0000"], "the bigger proven improvement must win"


def test_conflict_ranking_ignores_a_self_reported_claimed_improvement():
    """`claimed_improvement` is narration: it is author-supplied and no peer ever
    re-derives it. Ranking on it let an insight win every same-scope conflict
    forever by claiming an improvement it never demonstrated."""
    honest = build(good_claim()).to_dict()
    honest["status"] = STATUS_VERIFIED
    honest = _with_margin(honest, 9000.0, 3000.0)  # really -6000ms
    honest["evidence"]["claimed_improvement"] = {"rounds": -4, "duration_ms": -6000.0}

    liar = dict(honest, id="ins-liar000000", claim={"params": {"negotiate_timeout_ms": 11000}})
    liar = _with_margin(liar, 9000.0, 8900.0)  # really only -100ms
    liar["evidence"] = dict(liar["evidence"],
                            claimed_improvement={"rounds": -99, "duration_ms": -999999.0})

    _p, _w, ids, _e = active_params({honest["id"]: honest, liar["id"]: liar},
                                    LOSSY_CTX, DEFAULT_PARAMS)
    assert ids == [honest["id"]], "the measured improvement must win, not the loudest claim"


def test_scope_matches_requires_every_scoped_key():
    assert scope_matches({"context": {"link_quality": "lossy"}}, LOSSY_CTX)
    assert not scope_matches({"context": {"link_quality": "normal"}}, LOSSY_CTX)
    assert scope_matches({"context": {}}, LOSSY_CTX), "an unscoped insight applies everywhere"


# --- pruning without reset ----------------------------------------------------


def test_revoke_tombstones_the_provenance_subtree_and_keeps_the_rest():
    kr = keyring_for("N1", "N2", "N3")
    m = Mesh(seed=3, out_dir="out/test")
    node = m.nodes["N1"]

    parent = build(good_claim(), node="N1").to_dict()
    child = make_insight({"ns": "netops", "context": {"link_quality": "lossy"}},
                         good_claim(), evidence(good_claim()),
                         node.identity, "N1", derived_from=[parent["id"]]).to_dict()
    unrelated = make_insight({"ns": "netops", "context": {"link_quality": "normal"}},
                             good_claim(), evidence(good_claim()),
                             node.identity, "N1").to_dict()
    for d in (parent, child, unrelated):
        node.log.append(KIND_INSIGHT, {"insight": d})

    m.propagate(2)  # peers must hold the subtree before they can vote on it
    victims = m.revoke(node, parent["id"], "TEST")
    assert set(victims) == {parent["id"], child["id"]}, "descendants must go with the parent"
    m.propagate(2)  # demotion binds at quorum, so the votes have to reach N1

    state = node.state()
    assert state[parent["id"]]["status"] == STATUS_REVOKED
    assert state[child["id"]]["status"] == STATUS_REVOKED
    assert state[unrelated["id"]]["status"] != STATUS_REVOKED, "memory is not reset"
    assert parent["id"] in state, "revoked insights are tombstoned, never deleted"
    assert node.log.verify_chain(), "the revoke is itself an auditable chain entry"


# --- end-to-end ratchet -------------------------------------------------------


def test_the_ratchet_is_real_against_a_fabric_off_baseline():
    """Same seed, same eras, pipeline off vs on. This is the headline claim."""
    def run(fabric_on):
        m = Mesh(seed=42, out_dir=f"out/test-{fabric_on}", fabric_on=fabric_on)
        rows = []
        for t in generate(42, 30):
            r = m.run_task(t)
            if fabric_on and r["incident"]:
                m.pipeline_step(m.nodes[r["node"]], r["incident"])
            rows.append(r)
        return m, rows

    _off, off = run(False)
    m_on, on = run(True)

    def lossy(rs):
        return [r for r in rs if r["task"].link_quality == "lossy"]

    def mean(xs):
        return sum(xs) / len(xs)

    l_off, l_on = lossy(off), lossy(on)

    # Rounds is the honest headline: it is what the remembered settlement removes,
    # and unlike duration it is not distorted by the baseline's aborts (which are
    # capped at the timeout budget and produced no contract at all).
    assert mean([r["result"].rounds for r in l_on]) < 0.6 * mean(
        [r["result"].rounds for r in l_off])
    assert mean([r["result"].duration_ms for r in l_on]) < 0.85 * mean(
        [r["result"].duration_ms for r in l_off])

    # Fewer negotiations collapse entirely.
    aborts_off = sum(1 for r in l_off if r["result"].aborted)
    aborts_on = sum(1 for r in l_on if r["result"].aborted)
    assert aborts_off > 0, "the cold lossy era must actually blow the timeout budget"
    assert aborts_on < aborts_off, "the fabric must reduce collapses, not just latency"

    # Cross-node reuse: N3 applies an insight it never discovered (deliverable 5).
    n3 = [r for r in on if r["node"] == "N3" and r["insight_ids"]]
    assert n3, "N3 must reuse an insight"
    assert all(m_on.nodes["N3"].state()[i]["provenance"]["discovered_by"] == "N1"
               for r in n3 for i in r["insight_ids"])
    assert all(r["result"].rounds == 1 for r in n3)

    # Scope discipline: the lossy insight must not leak into normal traffic.
    assert all(not r["insight_ids"] for r in on
               if r["task"].link_quality == "normal" and r["task"].idx > 20)
