"""Node = agent personas + fabric replica + guardrail + analyzer. Mesh wires them.

There is no orchestrator here. A Node does not ask permission to negotiate, and
no component can promote an insight by itself: promotion is peer replay plus
quorum, propagation is gossip, and the analyzer is a per-node advisor with no
write path. There is deliberately no component whose compromise silently poisons
the fabric.
"""
from __future__ import annotations

import os
import random

from analyzer import rules
from core.bus import Bus, Clock, FaultState
from core.crypto import Identity, Keyring
from core.csp_mini import build_scenario, make_agent, negotiate
from core.registry import DEFAULT_PARAMS
from core.types import STATUS_CANDIDATE, STATUS_VERIFIED
from fabric.gossip import Gossip
from fabric.log import (
    KIND_ATTEST,
    KIND_GUARDRAIL_DENY,
    KIND_INSIGHT,
    KIND_STATUS,
    KIND_TOMBSTONE,
    FabricLog,
)
from fabric.model import Insight, make_insight
from guardrail.guardrail import Guardrail
from insights.pipeline import IMPROVEMENT_RATIO, active_params, verify
from loadgen.tasks import delay_for
from metrics.telemetry import SLOEvaluator, Telemetry

PERSONAS = ("throughput", "security")

# Probation: watch N live applications, revoke on FAIL regressions.
PROBATION_N = 3
PROBATION_FAIL = 2


class Node:
    def __init__(self, node_id: str, bus: Bus, keyring: Keyring, telemetry: Telemetry,
                 out_dir: str | None = None):
        self.id = node_id
        self.identity = Identity.deterministic(node_id)
        self.agents = {p: make_agent(f"{node_id}.{p}", p) for p in PERSONAS}
        self.agent_identities = {
            cfg.agent_id: Identity.deterministic(cfg.agent_id) for cfg in self.agents.values()
        }
        self.log = FabricLog(node_id, self.identity, keyring, out_dir)
        self.guardrail = Guardrail(keyring, bus.clock)
        self.slo = SLOEvaluator(telemetry)
        self.last_agreed: dict = {}  # link_quality -> remembered settlement point
        self.probation: dict = {}  # insight_id -> [slo_ok, ...]

    def state(self) -> dict:
        return self.log.fold()["insights"]

    def active(self, task_ctx: dict) -> tuple:
        """(params, warm_start, insight_ids, config_epoch) for this task context."""
        return active_params(self.state(), task_ctx, DEFAULT_PARAMS)

    def has_insight_for(self, scope_ctx: dict) -> bool:
        """Already know (or are checking) an answer for this context? Then don't
        re-draft one -- that is the ratchet doing its job."""
        for ins in self.state().values():
            if ins["status"] in (STATUS_CANDIDATE, STATUS_VERIFIED) and \
                    ins["scope"].get("context") == scope_ctx:
                return True
        return False


class Mesh:
    def __init__(self, seed: int = 42, out_dir: str = "out", node_ids=("N1", "N2", "N3"),
                 fabric_on: bool = True, log=print, analyzer: str = "rules",
                 on_record=None):
        self.seed = seed
        self.out_dir = out_dir
        self.fabric_on = fabric_on
        self.log_fn = log
        self.analyzer = analyzer
        os.makedirs(out_dir, exist_ok=True)

        self.rng = random.Random(seed)
        self.clock = Clock(0.0)
        self.faults = FaultState()
        self.keyring = Keyring()
        self.telemetry = Telemetry(os.path.join(out_dir, "telemetry.jsonl"), self.clock,
                                   on_record=on_record)
        self.bus = Bus(self.clock, self.faults, self.rng, self.keyring, self.telemetry)

        self.nodes = {n: Node(n, self.bus, self.keyring, self.telemetry, out_dir) for n in node_ids}

        # Pin every public key: nodes and agent personas. Phase 1 answer to PKI --
        # keys are exchanged out of band and pinned; nothing unpinned is ever trusted.
        self.identities: dict = {}
        for node in self.nodes.values():
            self.keyring.pin_identity(node.identity)
            self.identities[node.id] = node.identity
            for aid, ident in node.agent_identities.items():
                self.keyring.pin_identity(ident)
                self.identities[aid] = ident

        self.gossip = Gossip(self.bus, {n: self.nodes[n].identity for n in node_ids}, self.keyring)
        self.insights_seen: dict = {}
        self.events: list = []

    # --- task execution -------------------------------------------------------

    def run_task(self, task) -> dict:
        a_node, b_node = task.pair
        na, nb = self.nodes[a_node], self.nodes[b_node]
        cfg_a = na.agents[task.personas[0]]
        cfg_b = nb.agents[task.personas[1]]

        # The era changes the world under the agents. Nobody tells them.
        self.faults.set_link(a_node, b_node, *delay_for(task.ctx["link_quality"]))
        self.clock.advance(task.inter_arrival_ms)

        if self.fabric_on:
            params, warm, ids, epoch = na.active(task.ctx)
        else:
            params, warm, ids, epoch = dict(DEFAULT_PARAMS), None, [], 0

        session = f"t{task.idx:02d}-{a_node}x{b_node}"
        scenario = build_scenario(cfg_a, cfg_b, task.ctx, task.ctx["seed"], self.faults)
        start = self.clock.now()

        res = negotiate(
            self.bus, cfg_a, cfg_b, task.ctx, params,
            warm_start=warm, identities=self.identities, keyring=self.keyring,
            session=session, insight_ids=ids, config_epoch=epoch,
        )

        self.telemetry.span("csp.negotiate", {
            "session": session, "task_idx": task.idx, "node": a_node, "peer": b_node,
            "link_quality": task.ctx["link_quality"], "workload": task.ctx["workload"],
            "rounds": res.rounds, "epoch": epoch, "insight_ids": ids,
            "duration_ms": round(res.duration_ms, 1), "aborted": res.aborted,
            "abort_reason": res.abort_reason, "warm_started": bool(warm),
        }, start, res.duration_ms)

        if res.contract:
            na.last_agreed[task.ctx["link_quality"]] = res.contract["agreed"]
            nb.last_agreed[task.ctx["link_quality"]] = res.contract["agreed"]
            self.telemetry.count("fabric.insight.applied", {"n": len(ids)}, len(ids))

        incident = na.slo.on_task_end(a_node, task.ctx, res, session, scenario)
        self._probation_tick(na, ids, res)

        return {"task": task, "result": res, "incident": incident, "params": params,
                "warm": warm, "insight_ids": ids, "epoch": epoch, "node": a_node, "peer": b_node,
                # The two personas that negotiated. Carried so a reader can
                # reconstruct the handshake -- declared intent, the intersection,
                # every offer -- from the row alone (demo.run_demo.task_detail).
                "cfg_a": cfg_a, "cfg_b": cfg_b}

    # --- the accelerator ------------------------------------------------------

    def _draft(self, incident, last_agreed):
        """Pick the hypothesis source. Rules is primary and always available; the
        LLM is an upgrade behind a flag that falls back to rules on any failure.
        Both return the same shape and both go through the same self-replay gate
        in rules.build_draft -- the analyzer choice cannot widen what may be
        claimed, only what may be guessed (Doc 5 §2)."""
        if self.analyzer == "gemini":
            from analyzer import gemini  # imported lazily: rules must never need it
            return gemini.analyze(incident, last_agreed, DEFAULT_PARAMS, log=self.log_fn)
        return rules.analyze(incident, last_agreed, DEFAULT_PARAMS)

    def draft_and_submit(self, node: Node, incident) -> tuple:
        """analyzer -> guardrail -> announce. Returns (insight|None, decision|None, draft|None).

        The draft is returned for narration ONLY. Its `hypothesis` and
        `cited_span_ids` are prose from an advisor and are deliberately NOT part of
        the insight: the schema is closed on purpose (Doc 1 DR-3 -- "no free-text
        field exists"), which is what stops an analyzer, human or model, from
        smuggling unverifiable semantics into signed collective memory.
        """
        scope_ctx = {"link_quality": incident.task_ctx["link_quality"]}
        if node.has_insight_for(scope_ctx):
            return None, None, None
        last = node.last_agreed.get(incident.task_ctx["link_quality"]) or \
            next(iter(node.last_agreed.values()), None)
        draft = self._draft(incident, last)
        if draft is None:
            return None, None, None
        ins = make_insight(draft["scope"], draft["claim"], draft["evidence"],
                           node.identity, node.id, draft.get("analyzer", "rules"))
        got, decision = self.announce(node, ins)
        return got, decision, draft

    def announce(self, node: Node, ins: Insight) -> tuple:
        """Guardrail on the discovering node, then append -> gossip carries it."""
        d = node.guardrail.check(ins.to_dict())
        if not d.ok:
            node.log.append(KIND_GUARDRAIL_DENY, {
                "insight_id": ins.id, "reason": d.reason, "detail": d.detail, "source": node.id})
            self.telemetry.count("fabric.deny.count", {"reason": d.reason, "node": node.id})
            return None, d
        node.log.append(KIND_INSIGHT, {"insight": ins.to_dict()})
        self.insights_seen[ins.id] = ins.to_dict()
        return ins, d

    def inject_raw(self, node: Node, ins_dict: dict) -> None:
        """Append an insight WITHOUT the local guardrail or the local schema gate --
        i.e. what a compromised node does. The peers' ingest and guardrail are what
        must catch it. Used by chaos."""
        node.log.force_append(KIND_INSIGHT, {"insight": ins_dict})
        self.insights_seen[ins_dict["id"]] = ins_dict

    def attest_round(self) -> list:
        """Every node independently re-checks and replays every CANDIDATE it has
        not yet ruled on. A peer trusts nothing it did not verify itself."""
        out = []
        for nid in sorted(self.nodes):
            node = self.nodes[nid]
            if self.faults.down(nid):
                continue
            for iid, ins in sorted(node.state().items()):
                if ins["status"] != STATUS_CANDIDATE:
                    continue
                if ins["provenance"]["discovered_by"] == nid:
                    continue  # you do not vote on your own claim
                if any(a["node"] == nid for a in ins.get("attestations", [])):
                    continue

                d = node.guardrail.check(ins)
                if not d.ok:
                    node.log.append(KIND_GUARDRAIL_DENY, {
                        "insight_id": iid, "reason": d.reason, "detail": d.detail, "source": nid})
                    node.log.append(KIND_ATTEST, {
                        "insight_id": iid, "ok": False, "replay_hash": f"guardrail:{d.reason}"})
                    self.telemetry.count("fabric.deny.count", {"reason": d.reason, "node": nid})
                    out.append({"node": nid, "insight": iid, "ok": False,
                                "reason": d.reason, "detail": d.detail, "stage": "guardrail"})
                    continue

                ok, rh, before, after = verify(ins, DEFAULT_PARAMS)
                node.log.append(KIND_ATTEST, {"insight_id": iid, "ok": ok, "replay_hash": rh})
                out.append({"node": nid, "insight": iid, "ok": ok, "replay_hash": rh,
                            "before": before, "after": after, "stage": "replay"})
        return out

    def propagate(self, rounds: int = 2) -> None:
        logs = {n: self.nodes[n].log for n in self.nodes if not self.faults.down(n)}
        for _ in range(rounds):
            self.gossip.round(logs)

    def converge(self, max_rounds: int = 6) -> int:
        logs = {n: self.nodes[n].log for n in self.nodes if not self.faults.down(n)}
        return self.gossip.converge(logs, max_rounds)

    def pipeline_step(self, node: Node, incident) -> dict:
        """One full accelerator pass: draft -> guardrail -> gossip -> peers replay
        -> attest -> gossip -> status derived. Returns a report for the narration."""
        ins, decision, draft = self.draft_and_submit(node, incident)
        if ins is None:
            return {"insight": None, "decision": decision, "attestations": [], "draft": None}
        self.propagate()
        atts = self.attest_round()
        self.propagate()
        state = node.state().get(ins.id, {})
        return {"insight": ins.to_dict(), "decision": decision, "attestations": atts,
                "status": state.get("status"), "id": ins.id, "draft": draft}

    # --- probation / revoke (cheap canary, Doc 4 §7.4) ------------------------

    def _probation_tick(self, node: Node, ids: list, res) -> None:
        """Watch the first 3 live applications of a VERIFIED insight; revoke it and
        its derived_from descendants if 2 of 3 regress.

        The bar is the one it already cleared to get verified: it proved it beats
        the cold baseline by IMPROVEMENT_RATIO, so we check that it still does, in
        the live world. We deliberately do NOT test it against the absolute SLO.
        An insight that takes a 9s negotiation down to 6s is delivering exactly
        what it proved, even though 6s is still over a 5s SLO -- on a 1800ms/hop
        link no negotiation can fit in 5s, because six messages have to cross it.
        Revoking on the absolute SLO throws away real verified knowledge for
        failing to fix the weather, and the node then re-derives the same insight
        forever. Regression is the signal; environment is not.

        Rollback = fold the log without it. Nothing is deleted, and the revoke is
        itself a signed, auditable entry.
        """
        state = node.state()
        for iid in ids:
            ins = state.get(iid)
            if not ins:
                continue
            hist = node.probation.setdefault(iid, [])
            if len(hist) >= PROBATION_N:
                continue
            before = (ins.get("evidence", {}).get("metric_before", {}) or {}).get("duration_ms")
            if not before:
                continue
            hist.append(bool(res.aborted or res.duration_ms > before * IMPROVEMENT_RATIO))
            if len(hist) == PROBATION_N and sum(hist) >= PROBATION_FAIL:
                # This node's OWN vote, on this node's OWN evidence. Probation data
                # is local and peers cannot re-derive it, so one node's regression
                # is a vote, not a verdict: the fold demotes at quorum, meaning two
                # nodes must independently watch the insight regress. One unlucky
                # node does not get to erase what the network verified.
                self.vote_revoke(node, iid, "PROBATION_REGRESSION")

    def vote_revoke(self, node: Node, insight_id: str, reason: str) -> list:
        """One node's signed demotion vote for an insight and its descendants."""
        victims = sorted({insight_id} | node.log.descendants(insight_id))
        for v in victims:
            node.log.append(KIND_STATUS, {"insight_id": v, "status": "REVOKED", "reason": reason})
        self.telemetry.event("fabric.revoke_vote",
                             {"node": node.id, "ids": victims, "reason": reason})
        return victims

    def revoke(self, node: Node, insight_id: str, reason: str) -> list:
        """Prune by provenance subtree. Tombstone, never rewrite.

        Every healthy node re-derives the subtree from its own replica and signs
        its own entry. That is not a rubber stamp: `derived_from` lives in the
        shared, signed entry set, so the subtree is a deterministic function of
        data every node already holds -- honest nodes independently reach the same
        verdict. Quorum then makes the demotion binding (see FabricLog.fold).
        """
        for peer in self._healthy():
            self.vote_revoke(peer, insight_id, reason)
        victims = sorted({insight_id} | node.log.descendants(insight_id))
        self.telemetry.event("fabric.revoke", {"node": node.id, "ids": victims, "reason": reason})
        return victims

    def tombstone(self, node: Node, insight_id: str, reason: str) -> list:
        for peer in self._healthy():
            for v in sorted({insight_id} | peer.log.descendants(insight_id)):
                peer.log.append(KIND_TOMBSTONE, {"insight_id": v, "reason": reason})
        return sorted({insight_id} | node.log.descendants(insight_id))

    def _healthy(self) -> list:
        return [self.nodes[n] for n in sorted(self.nodes) if not self.faults.down(n)]

    # --- reporting ------------------------------------------------------------

    def heads(self) -> dict:
        return {n: self.nodes[n].log.head() for n in sorted(self.nodes)}

    def digests(self) -> dict:
        return {n: self.nodes[n].log.digest() for n in sorted(self.nodes)}

    def converged(self) -> bool:
        live = [self.nodes[n].log.digest() for n in sorted(self.nodes) if not self.faults.down(n)]
        return len(set(live)) <= 1

    def fabric_summary(self) -> dict:
        """Fabric-wide view. Every node holds a replica of the same entry set once
        gossip has converged, so this must count DISTINCT events -- summing the
        replicas reported each denial three times (once per node) and inflated the
        headline number by 3x."""
        state = {}
        denies: dict = {}
        for n in sorted(self.nodes):
            folded = self.nodes[n].log.fold()
            for iid, ins in folded["insights"].items():
                state.setdefault(iid, ins)
            for d in folded["denies"]:
                # The deny is identified by who authored it and what it is about,
                # not by which replica we happened to read it from.
                denies.setdefault((d["node"], d["insight_id"], d.get("reason")), d)
        return {"insights": state, "denies": [denies[k] for k in sorted(denies)]}
