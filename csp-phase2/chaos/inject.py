"""Chaos Injector -- the bonus deliverable (Doc 4 §10).

Every fault follows the same shape: DETECT -> BLOCK or REPAIR -> prove INTEGRITY.

Threat model note that matters for F2: the poisoned insights are appended to the
rogue node's log WITHOUT passing its own guardrail. That is the point. A
compromised node does not politely run its own checks first, so a demo where the
attacker's own guardrail catches the attack proves nothing. Here the rogue node
broadcasts freely and the PEERS' guardrails are what stop it -- which is the
property we actually claim: no node trusts an insight because of who sent it.
"""
from __future__ import annotations

from core.bus import LOSSY_DELAY_MS, NORMAL_DELAY_MS, FaultState
from core.crypto import canonical
from core.csp_mini import build_scenario
from core.registry import DEFAULT_PARAMS
from core.types import STATUS_QUARANTINED, STATUS_VERIFIED
from fabric.log import KIND_INSIGHT
from fabric.model import Insight, compute_id, make_insight, signing_body
from insights.pipeline import verify

GOOD_WARM = {
    "netops/latency_ms": 7.875, "netops/throughput_mbps": 8762.5,
    "netops/inspection_depth": "full_deep", "netops/sample_rate": 0.25,
    "netops/tls_version": "1.3", "netops/log_export": True,
}


def _scenario(mesh, a="N1", b="N2", link="lossy", seed=7) -> dict:
    ctx = {"link_quality": link, "workload": "steady", "pair": [a, b], "seed": seed}
    faults = FaultState(default_delay_ms=LOSSY_DELAY_MS if link == "lossy" else NORMAL_DELAY_MS)
    return build_scenario(mesh.nodes[a].agents["throughput"],
                          mesh.nodes[b].agents["security"], ctx, seed, faults)


def _evidence(mesh, claim: dict) -> dict:
    """Honest evidence: actually replay, and record what really happened."""
    scen = _scenario(mesh)
    _ok, _h, before, after = verify({"claim": claim, "evidence": {"scenario": scen}},
                                    DEFAULT_PARAMS)
    return {"scenario": scen, "metric_before": before, "metric_after": after,
            "claimed_improvement": {
                "rounds": after["rounds"] - before["rounds"],
                "duration_ms": round(after["duration_ms"] - before["duration_ms"], 3)}}


def craft(mesh, node_id: str, claim: dict, scope_ctx: dict | None = None,
          evidence: dict | None = None, derived_from=None) -> dict:
    ins = make_insight({"ns": "netops", "context": scope_ctx or {"link_quality": "lossy"}},
                       claim, evidence or _evidence(mesh, claim),
                       mesh.nodes[node_id].identity, node_id, "rules",
                       derived_from=derived_from)
    return ins.to_dict()


# --- F1: a node is down while an insight propagates ---------------------------


def f1_node_down(mesh, victim: str = "N3", author: str = "N1") -> dict:
    """The node misses the announce entirely, then catches up on gossip alone.
    There is no recovery code path -- anti-entropy IS the recovery."""
    mesh.faults.node_down.add(victim)

    claim = {"params": {"negotiate_timeout_ms": 25000}, "warm_start": dict(GOOD_WARM)}
    ins = craft(mesh, author, claim, {"link_quality": "lossy", "workload": "bursty"})
    # F1 is not an attack: this is an honest node announcing an honest insight
    # through the normal guardrailed path, while a peer happens to be offline.
    mesh.announce(mesh.nodes[author], Insight.from_dict(ins))
    mesh.propagate(2)
    mesh.attest_round()
    mesh.propagate(2)

    missed = ins["id"] not in mesh.nodes[victim].state()
    detect = {"victim_down": True, "victim_missing_insight": missed,
              "digest_diverged": mesh.nodes[victim].log.digest() != mesh.nodes[author].log.digest()}

    mesh.faults.node_down.discard(victim)
    rounds = mesh.converge(8)
    mesh.attest_round()
    mesh.propagate(2)

    return {
        "fault": "F1 node down during propagation",
        "detect": detect,
        "repair": {"gossip_rounds_to_catch_up": rounds,
                   "victim_has_insight": ins["id"] in mesh.nodes[victim].state()},
        "integrity": {"digests": mesh.digests(), "converged": mesh.converged(),
                      "chains_valid": all(n.log.verify_chain() for n in mesh.nodes.values())},
        "insight_id": ins["id"],
    }


# --- F2: four poisoned updates ------------------------------------------------


def f2_poisoned(mesh, rogue: str = "N3") -> dict:
    """Four attacks, four different defences. (a)-(c) die at the peers' guardrail;
    (d) is the interesting one -- it is perfectly signed, perfectly in-bounds, and
    lies about its results. Only replay catches it."""
    node = mesh.nodes[rogue]
    attacks = []

    # (a) tampered after signing -> the signature no longer covers the content.
    a = craft(mesh, rogue, {"params": {"negotiate_timeout_ms": 30000}})
    a["claim"]["params"]["negotiate_timeout_ms"] = 59000
    attacks.append(("a", "tampered claim, stale signature", "INVALID_SIG", a))

    # (b) a tunable pushed outside its bounds.
    b = craft(mesh, rogue, {"params": {"eps": 0.9}})
    attacks.append(("b", "eps=0.9 (bounds are [0.01, 0.2])", "BOUNDS_VIOLATION", b))

    # (c) attacks a security_baseline dimension through the warm start.
    ws = dict(GOOD_WARM, **{"netops/inspection_depth": "none"})
    c = craft(mesh, rogue, {"warm_start": ws})
    attacks.append(("c", "warm_start disables inspection", "POLICY_VIOLATION", c))

    # (d) valid signature, in-bounds claim, FABRICATED metric_after.
    d_claim = {"params": {"negotiate_timeout_ms": 1000}}
    d_ev = _evidence(mesh, d_claim)
    d_ev["metric_after"] = {"aborted": False, "abort_reason": None, "rounds": 1,
                            "duration_ms": 12.0, "messages": 6,
                            "agreed": dict(GOOD_WARM), "resolved_by": "acceptance"}
    d_ev["claimed_improvement"] = {"rounds": -4, "duration_ms": -7100.0}
    d = craft(mesh, rogue, d_claim, evidence=d_ev)
    attacks.append(("d", "valid signature, fabricated metric_after", "REPLAY_DIVERGENCE", d))

    rows = []
    for tag, desc, expected, ins in attacks:
        # The rogue node broadcasts WITHOUT running its own guardrail.
        mesh.inject_raw(node, ins)
        mesh.propagate(2)
        reports = mesh.attest_round()
        mesh.propagate(2)
        mine = [r for r in reports if r["insight"] == ins["id"]]
        status = mesh.nodes["N1"].state().get(ins["id"], {}).get("status", "?")
        rows.append({
            "tag": tag, "desc": desc, "expected": expected, "id": ins["id"],
            "status": status,
            "stage": mine[0]["stage"] if mine else "-",
            "reason": mine[0].get("reason") if mine else "-",
            "verdicts": [(r["node"], r["ok"], r.get("reason") or r.get("stage")) for r in mine],
            "blocked": status != STATUS_VERIFIED,
        })

    # Pruning: tombstone (d) and anything derived from it. The good insight stays.
    child = craft(mesh, rogue, {"params": {"negotiate_timeout_ms": 1200}},
                  derived_from=[attacks[3][3]["id"]])
    mesh.inject_raw(node, child)
    mesh.propagate(2)
    victims = mesh.tombstone(mesh.nodes["N1"], attacks[3][3]["id"], "POISONED_SOURCE")
    mesh.propagate(2)

    survivors = {i: s["status"] for i, s in mesh.nodes["N1"].state().items()
                 if s["status"] == STATUS_VERIFIED}
    return {
        "fault": "F2 poisoned updates",
        "rows": rows,
        "prune": {"tombstoned": victims, "descendant": child["id"],
                  "surviving_verified": sorted(survivors)},
        "integrity": {"converged": mesh.converged(),
                      "chains_valid": all(n.log.verify_chain() for n in mesh.nodes.values()),
                      "entries_deleted": 0},
    }


# --- F3: partition and heal ---------------------------------------------------


def f3_partition(mesh, minority: str = "N3", author: str = "N1") -> dict:
    """Scoped eventual consistency, priced out loud: the partitioned node keeps
    negotiating on stale config. It pays rounds. It never gets a wrong answer."""
    others = [n for n in mesh.nodes if n != minority]
    for o in others:
        mesh.faults.partitions.add(frozenset({o, minority}))

    claim = {"params": {"negotiate_timeout_ms": 28000}, "warm_start": dict(GOOD_WARM)}
    ins = craft(mesh, author, claim, {"link_quality": "lossy", "workload": "steady"})
    mesh.inject_raw(mesh.nodes[author], ins)
    mesh.propagate(2)
    mesh.attest_round()
    mesh.propagate(2)

    detect = {
        "partition": [sorted(p) for p in sorted(mesh.faults.partitions, key=sorted)],
        "majority_has": ins["id"] in mesh.nodes[others[0]].state(),
        "minority_has": ins["id"] in mesh.nodes[minority].state(),
        "digest_split": len({mesh.nodes[n].log.digest() for n in mesh.nodes}) > 1,
    }

    mesh.faults.partitions.clear()
    rounds = mesh.converge(8)
    mesh.attest_round()
    mesh.propagate(2)

    return {
        "fault": "F3 partition / heal",
        "detect": detect,
        "repair": {"gossip_rounds_to_converge": rounds,
                   "minority_has": ins["id"] in mesh.nodes[minority].state()},
        "integrity": {"digests": mesh.digests(), "converged": mesh.converged(),
                      "chains_valid": all(n.log.verify_chain() for n in mesh.nodes.values())},
        "insight_id": ins["id"],
    }
