"""THE deliverable: one scripted, narrated run of the Cognition Fabric.

    python -m demo.run_demo --seed 42 [--fabric off] [--chaos] [--charts]

Acts:
  1  normal ops           -- what healthy looks like
  2  lossy era            -- conditions change; the SLO notices; ONE insight is born
  3  the ratchet          -- reuse, scope discipline, and cross-node propagation
  4  chaos                -- F1 node down, F2 four poisoned updates, F3 partition
  5  summary + charts

Everything printed is measured, not narrated from a script. Same seed, same run.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from chaos import inject
from core.registry import DEFAULT_PARAMS
from core.types import STATUS_QUARANTINED, STATUS_REVOKED, STATUS_VERIFIED
from demo.console import NO, OK, C, banner, rule, setup
from insights.pipeline import IMPROVEMENT_RATIO
from loadgen.tasks import ERAS, generate
from metrics.telemetry import (
    SLO_ABORT_RATE,
    SLO_CONTRACT_DURATION_MS,
    SLO_MSG_LATENCY_P95_MS,
    SLO_WINDOW,
    p95,
)
from nodes import Mesh

ACT_OF_ERA = {"act1-normal": 1, "act2-lossy": 2, "act3-normal": 3, "act3-crossnode": 3}


def task_line(r, note: str = "") -> str:
    res, t = r["result"], r["task"]
    lq = t.ctx["link_quality"]
    col = C["warn"] if lq == "lossy" else C["dim"]
    if res.aborted:
        outcome = f"{C['bad']}ABORT({res.abort_reason}){C['x']}"
    else:
        slow = res.duration_ms > SLO_CONTRACT_DURATION_MS
        dc = C["bad"] if slow else C["ok"]
        outcome = f"rounds={res.rounds} dur={dc}{res.duration_ms:6.0f}ms{C['x']}"
    ins = ",".join(i.replace("ins-", "") for i in r["insight_ids"])
    warm = f" {C['cy']}(warm-start){C['x']}" if r["warm"] else ""
    return (f"  task {t.idx:02d} {col}[{lq:6}]{C['x']} {r['node']}x{r['peer']} {outcome} "
            f"epoch={r['epoch']} insights=[{ins}]{warm}{note}")


def narrate_pipeline(rep: dict, inc) -> None:
    ins = rep["insight"]
    if ins is None:
        return
    claim = ins["claim"]
    ev = ins["evidence"]
    b, a = ev["metric_before"], ev["metric_after"]

    who = ins["provenance"].get("analyzer", "rules")
    draft = rep.get("draft") or {}
    print(f"\n  {C['b']}ANALYZER{C['x']} ({who}, node {ins['provenance']['discovered_by']}) "
          f"drafts a hypothesis")
    if who == "gemini" and draft.get("hypothesis"):
        print(f"    {C['dim']}{draft['hypothesis']}{C['x']}")
        print(f"    {C['dim']}the model drafted this; it has no write path and no accept")
        print(f"    authority. What follows is what decides (Doc 5 §2).{C['x']}")
    print(f"    cited spans : {', '.join(s['span_id'] for s in inc.worst_spans) or '-'}")
    print(f"    claim.params: {json.dumps(claim.get('params', {}))}")
    print(f"    warm_start  : {'yes -- the settlement we already know for this context' if claim.get('warm_start') else 'no'}")
    print(f"    {C['dim']}the analyzer replayed this itself before submitting; it never asks the")
    print(f"    network to check a claim it has not checked (Doc 4 §9.1){C['x']}")

    print(f"\n  {C['b']}GUARDRAIL{C['x']} on the discovering node")
    print(f"    signature verifies against pinned key ....... {C['ok']}{OK}{C['x']}")
    print(f"    every claim.params key whitelisted + in bounds {C['ok']}{OK}{C['x']}")
    print(f"    warm_start above the policy floor .......... {C['ok']}{OK}{C['x']}")
    print(f"    evidence carries a replayable scenario ..... {C['ok']}{OK}{C['x']}")
    print(f"    -> {C['ok']}ALLOW{C['x']}  (id {ins['id']})")

    # Show what a PEER measured, not what the author claimed. On an honest insight
    # they are equal -- but printing the claim under a "peer replay" heading would
    # be showing the attacker's own numbers back as if they were verification
    # output, which is exactly the thing this act exists to disprove.
    replayed = next((at for at in rep["attestations"]
                     if at["insight"] == ins["id"] and at["stage"] == "replay"), None)
    src = "as re-measured by peer " + replayed["node"] if replayed else "as claimed (unverified)"
    if replayed:
        b, a = replayed["before"], replayed["after"]
    print(f"\n  {C['b']}PEER REPLAY{C['x']} -- each node re-executes the recorded scenario itself")
    print(f"    {C['dim']}{src}{C['x']}")
    print(f"    before: rounds={b['rounds']} dur={b['duration_ms']:.0f}ms aborted={b['aborted']}")
    print(f"    after : rounds={a['rounds']} dur={a['duration_ms']:.0f}ms aborted={a['aborted']}")
    ratio = a["duration_ms"] / b["duration_ms"] if b["duration_ms"] else 1
    print(f"    ratio : {ratio:.2f}  (must be <= {IMPROVEMENT_RATIO} to be an improvement at all)")
    for at in rep["attestations"]:
        if at["insight"] != ins["id"]:
            continue
        mark = f"{C['ok']}{OK}{C['x']}" if at["ok"] else f"{C['bad']}{NO}{C['x']}"
        detail = at.get("replay_hash", "")[:16] if at["ok"] else at.get("reason", "")
        print(f"    ATTEST {at['node']} {mark} {C['dim']}{detail}{C['x']}")

    if rep["status"] == STATUS_VERIFIED:
        print(f"    {C['dim']}two independent nodes produced the SAME replay hash{C['x']}")
        print(f"    -> {C['ok']}{C['b']}VERIFIED {ins['id']}{C['x']} -- now collective memory")
    else:
        print(f"    -> {C['warn']}{rep['status']}{C['x']}")


def fabric_event(mesh) -> dict:
    """A snapshot of every replica: what the UI's node columns render."""
    nodes = {}
    for n in sorted(mesh.nodes):
        idx, head = mesh.nodes[n].log.head()
        state = mesh.nodes[n].state()
        nodes[n] = {
            "chain_idx": idx,
            "head": head[:12],
            "digest": mesh.nodes[n].log.digest()[:12],
            "down": mesh.faults.down(n),
            "insights": sorted(
                ({"id": i, "status": s["status"],
                  "scope": s.get("scope", {}).get("context", {}),
                  "analyzer": s.get("provenance", {}).get("analyzer", "rules"),
                  "discovered_by": s.get("provenance", {}).get("discovered_by", "?")}
                 for i, s in state.items()),
                key=lambda x: x["id"]),
        }
    summary = mesh.fabric_summary()
    return {"type": "fabric", "nodes": nodes, "converged": mesh.converged(),
            "denies": summary["denies"]}


def run(seed: int, fabric_on: bool, quiet: bool = False, out_dir: str = "out",
        pace: float = 0.0, analyzer: str = "rules", on_event=None, on_record=None) -> tuple:
    """Run the 30-task flow. `on_event(dict)` receives structured beats -- the same
    ones the narration prints -- so the live UI renders this exact code path rather
    than a parallel one built to look like it. `on_record` forwards raw telemetry."""
    emit = on_event or (lambda _e: None)
    mesh = Mesh(seed=seed, out_dir=out_dir, fabric_on=fabric_on, analyzer=analyzer,
                log=(lambda *a: None) if quiet else print, on_record=on_record)
    rows, first_warm, verified_at = [], None, None
    act = 0
    emit({"type": "run_start", "seed": seed, "fabric_on": fabric_on,
          "analyzer": analyzer, "tasks": 30})

    for t in generate(seed, 30):
        a = ACT_OF_ERA[t.era]
        if a != act and not quiet:
            act = a
            titles = {1: "ACT 1 -- NORMAL OPS  (tasks 1-8): the baseline",
                      2: "ACT 2 -- LOSSY ERA  (tasks 9-20): conditions change underneath the agents",
                      3: "ACT 3 -- THE RATCHET  (tasks 21-30): scope discipline, then cross-node reuse"}
            banner(titles[a])
            if a == 2:
                print(f"  {C['dim']}N1<->N2 link degrades to 400-1200ms/hop. Nobody tells the agents.")
                print(f"  SLO table: p95 msg latency <= {SLO_MSG_LATENCY_P95_MS}ms | contract <= "
                      f"{SLO_CONTRACT_DURATION_MS}ms | abort rate <= {SLO_ABORT_RATE:.0%} "
                      f"| window {SLO_WINDOW} tasks{C['x']}\n")

        r = mesh.run_task(t)
        rows.append(r)
        note = ""

        res = r["result"]
        emit({"type": "task", "idx": t.idx, "era": t.era, "act": ACT_OF_ERA[t.era],
              "link_quality": t.ctx["link_quality"], "workload": t.ctx["workload"],
              "node": r["node"], "peer": r["peer"], "rounds": res.rounds,
              "duration_ms": round(res.duration_ms, 1), "aborted": res.aborted,
              "abort_reason": res.abort_reason, "epoch": r["epoch"],
              "insight_ids": r["insight_ids"], "warm": bool(r["warm"]),
              "p95_latency_ms": round(p95(mesh.telemetry.session_latencies(
                  f"t{t.idx:02d}-{r['node']}x{r['peer']}")), 1),
              "fabric_on": fabric_on})

        if not fabric_on:
            if not quiet:
                print(task_line(r))
            continue

        # Narration beats worth calling out by name.
        if r["warm"] and first_warm is None:
            first_warm = t.idx
            note = f"  {C['ok']}<- first reuse{C['x']}"
        if t.era == "act3-normal" and not r["insight_ids"]:
            note = f"  {C['mg']}<- lossy insight NOT applied: different context{C['x']}"
        if t.era == "act3-crossnode" and r["insight_ids"]:
            note = f"  {C['ok']}<- N3 reuses N1's insight{C['x']}"

        if not quiet:
            print(task_line(r, note))
            if pace:
                time.sleep(pace)

        emit(fabric_event(mesh))

        inc = r["incident"]
        if not inc:
            continue
        node = mesh.nodes[r["node"]]
        known = node.has_insight_for({"link_quality": t.ctx["link_quality"]})
        if known:
            if not quiet and t.idx == first_warm:
                print(f"    {C['dim']}SLO still breached: the LINK is still slow. An insight cannot")
                print(f"    fix the network -- it fixes how many times we cross it.{C['x']}")
            continue

        if not quiet:
            rule(f"INCIDENT {inc.id}")
            print(f"  {C['bad']}{inc.breached_slo} p95 = {inc.window_stats['p95']:.0f}ms > SLO "
                  f"{inc.window_stats['threshold']}ms{C['x']}  over the last {SLO_WINDOW} "
                  f"[{t.ctx['link_quality']}] tasks")
            for s in inc.worst_spans:
                print(f"    worst span {s['type']:<14} {s['from']} -> {s['to']}  {s['latency_ms']}ms")

        emit({"type": "incident", "id": inc.id, "node": inc.node,
              "breached_slo": inc.breached_slo, "p95": round(inc.window_stats["p95"], 1),
              "threshold": inc.window_stats.get("threshold"),
              "worst_spans": inc.worst_spans, "task_idx": t.idx})

        rep = mesh.pipeline_step(node, inc)
        if not quiet:
            narrate_pipeline(rep, inc)
            rule()
        if rep.get("status") == STATUS_VERIFIED:
            verified_at = t.idx
        emit(pipeline_event(rep, inc))
        emit(fabric_event(mesh))

    emit({"type": "run_end", "first_warm": first_warm, "verified_at": verified_at})
    return mesh, rows, {"first_warm": first_warm, "verified_at": verified_at}


def pipeline_event(rep: dict, inc) -> dict:
    """The insight lifecycle beat: analyzer -> guardrail -> peer replay -> status."""
    ins = rep.get("insight")
    if ins is None:
        d = rep.get("decision")
        return {"type": "pipeline", "insight": None,
                "denied": {"reason": d.reason, "detail": d.detail} if d and not d.ok else None}
    atts = [a for a in rep["attestations"] if a["insight"] == ins["id"]]
    replayed = next((a for a in atts if a["stage"] == "replay"), None)
    draft = rep.get("draft") or {}
    return {
        "type": "pipeline",
        "id": ins["id"],
        "incident": inc.id,
        "analyzer": ins["provenance"].get("analyzer", "rules"),
        "discovered_by": ins["provenance"]["discovered_by"],
        # Narration only: prose from an advisor, never part of the signed insight.
        "hypothesis": draft.get("hypothesis", ""),
        "claim": ins["claim"],
        "cited_span_ids": draft.get("cited_span_ids", []),
        # What a PEER measured, never what the author claimed (Doc 5 §3).
        "before": replayed["before"] if replayed else ins["evidence"]["metric_before"],
        "after": replayed["after"] if replayed else ins["evidence"]["metric_after"],
        "measured_by": replayed["node"] if replayed else None,
        "attestations": [{"node": a["node"], "ok": a["ok"],
                          "replay_hash": (a.get("replay_hash") or "")[:16],
                          "stage": a["stage"], "reason": a.get("reason")} for a in atts],
        "status": rep.get("status"),
    }


def summarize(mesh, rows, base_rows=None) -> dict:
    def stats(rs, pred):
        sel = [r for r in rs if pred(r)]
        d = [r["result"].duration_ms for r in sel]
        rd = [r["result"].rounds for r in sel if not r["result"].aborted]
        return {"n": len(sel), "mean_ms": sum(d) / len(d) if d else 0,
                "mean_rounds": sum(rd) / len(rd) if rd else 0,
                "aborts": sum(1 for r in sel if r["result"].aborted)}

    lossy = lambda r: r["task"].link_quality == "lossy"
    state = mesh.fabric_summary()
    by_status = {}
    for ins in state["insights"].values():
        by_status[ins["status"]] = by_status.get(ins["status"], 0) + 1

    out = {
        "contracts": sum(1 for r in rows if not r["result"].aborted),
        "aborts": sum(1 for r in rows if r["result"].aborted),
        "insights": by_status,
        "denies": len(state["denies"]),
        "lossy_on": stats(rows, lossy),
        "converged": mesh.converged(),
        "chains_valid": all(n.log.verify_chain() for n in mesh.nodes.values()),
        "digest": mesh.nodes["N1"].log.digest(),
    }
    if base_rows is not None:
        out["lossy_off"] = stats(base_rows, lossy)
    return out


def write_summary(path: str, s: dict, chaos_reports: list) -> None:
    L = ["# Cognition Fabric -- run summary", ""]
    L.append(f"- contracts: **{s['contracts']}**, aborts: **{s['aborts']}**")
    L.append(f"- insights: {s['insights'] or 'none'}, guardrail denials: **{s['denies']}**")
    L.append(f"- fabric converged: **{s['converged']}**, chains valid: **{s['chains_valid']}**")
    L.append(f"- fabric digest: `{s['digest'][:32]}...`")
    L.append("")
    if "lossy_off" in s:
        off, on = s["lossy_off"], s["lossy_on"]
        L += ["## The ratchet (lossy tasks only, same seed, same eras)", "",
              "| | fabric OFF | fabric ON | change |",
              "|---|---|---|---|",
              f"| mean contract duration | {off['mean_ms']:.0f} ms | {on['mean_ms']:.0f} ms | "
              f"**{(on['mean_ms'] / off['mean_ms'] - 1) * 100:+.0f}%** |",
              f"| mean rounds | {off['mean_rounds']:.2f} | {on['mean_rounds']:.2f} | "
              f"**{(on['mean_rounds'] / off['mean_rounds'] - 1) * 100:+.0f}%** |",
              f"| timed out entirely | {off['aborts']} / {off['n']} | {on['aborts']} / {on['n']} | "
              f"**{on['aborts'] - off['aborts']:+d}** |", ""]
    for rep in chaos_reports or []:
        L.append(f"## {rep['fault']}")
        if "rows" in rep:
            L += ["", "| # | attack | expected | caught at | status |", "|---|---|---|---|---|"]
            for r in rep["rows"]:
                L.append(f"| {r['tag']} | {r['desc']} | {r['expected']} | {r['stage']} | "
                         f"**{r['status']}** |")
            L.append(f"\nPruned `{rep['prune']['tombstoned']}` (incl. descendant "
                     f"`{rep['prune']['descendant']}`); still-verified: "
                     f"`{rep['prune']['surviving_verified']}` -- pruning is not a reset.")
        else:
            L.append(f"\n```json\n{json.dumps(rep, indent=1, default=str)}\n```")
        L.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Cognition Fabric demo")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--fabric", choices=["on", "off"], default="on")
    ap.add_argument("--chaos", action="store_true")
    ap.add_argument("--charts", action="store_true")
    ap.add_argument("--pace", type=float, default=0.0, help="seconds to pause per task")
    ap.add_argument("--analyzer", choices=["rules", "gemini"], default="rules",
                    help="hypothesis source; gemini falls back to rules on any failure")
    ap.add_argument("--out", default="out")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)
    setup(args.no_color)
    fabric_on = args.fabric == "on"
    os.makedirs(args.out, exist_ok=True)

    banner("COGNITION FABRIC -- Phase 2: The Continuous Mesh & The Ratchet Effect")
    print(f"  seed={args.seed}  fabric={args.fabric}  analyzer={args.analyzer}  "
          f"nodes=N1,N2,N3  tasks=30  transport=in-proc (virtual clock)")
    print(f"  {C['dim']}Every number below is measured. Same seed reproduces this run exactly.{C['x']}")

    base_rows = None
    if fabric_on:
        # The baseline costs nothing to run: time is virtual. Always `rules` --
        # the baseline exists to isolate the FABRIC's effect, so the only thing
        # that may differ between the two runs is whether the pipeline is on.
        _bm, base_rows, _ = run(args.seed, False, quiet=True,
                                out_dir=os.path.join(args.out, "baseline"))

    mesh, rows, marks = run(args.seed, fabric_on, out_dir=args.out, pace=args.pace,
                            analyzer=args.analyzer)

    chaos_reports = []
    if args.chaos and fabric_on:
        banner("ACT 4 -- CHAOS INJECTOR")
        chaos_reports = narrate_chaos(mesh)

    banner("ACT 5 -- SUMMARY")
    s = summarize(mesh, rows, base_rows)
    if base_rows is not None and fabric_on:
        off, on = s["lossy_off"], s["lossy_on"]
        print(f"  {C['b']}The ratchet, measured on lossy tasks (same seed, same eras):{C['x']}")
        print(f"    {'':<22}{'fabric OFF':>12}{'fabric ON':>12}{'change':>10}")
        print(f"    {'mean duration':<22}{off['mean_ms']:>10.0f}ms{on['mean_ms']:>10.0f}ms"
              f"{C['ok']}{(on['mean_ms'] / off['mean_ms'] - 1) * 100:>9.0f}%{C['x']}")
        print(f"    {'mean rounds':<22}{off['mean_rounds']:>12.2f}{on['mean_rounds']:>12.2f}"
              f"{C['ok']}{(on['mean_rounds'] / off['mean_rounds'] - 1) * 100:>9.0f}%{C['x']}")
        print(f"    {'timed out entirely':<22}{off['aborts']:>10} /{off['n']:<2}{on['aborts']:>8} "
              f"/{on['n']:<2}{C['ok']}{on['aborts'] - off['aborts']:>+9}{C['x']}")
        print(f"    {C['dim']}Rounds is the honest headline: it is exactly what the remembered")
        print(f"    settlement removes. Duration understates the win, because the baseline's")
        print(f"    timeouts are capped at the budget and produced no contract at all.{C['x']}")
    print(f"\n  contracts={s['contracts']}  aborts={s['aborts']}  "
          f"insights={s['insights'] or '{}'}  guardrail_denials={s['denies']}")
    print(f"  fabric converged={C['ok'] if s['converged'] else C['bad']}{s['converged']}{C['x']}"
          f"  chains_valid={C['ok'] if s['chains_valid'] else C['bad']}{s['chains_valid']}{C['x']}")
    for n in sorted(mesh.nodes):
        idx, h = mesh.nodes[n].log.head()
        print(f"    {n}: chain idx={idx:<3} head={h[:12]}...  digest={mesh.nodes[n].log.digest()[:12]}...")
    print(f"  {C['dim']}Heads differ by design -- they record the order each node LEARNED things.")
    print(f"  The digest over the signed entry set is what must converge, and does.{C['x']}")

    write_summary(os.path.join(args.out, "summary.md"), s, chaos_reports)
    print(f"\n  wrote {args.out}/summary.md, {args.out}/telemetry.jsonl, {args.out}/fabric_N*.jsonl")

    if args.charts:
        from demo import charts
        made = charts.render(os.path.join(args.out, "telemetry.jsonl"),
                             os.path.join(args.out, "baseline", "telemetry.jsonl"),
                             os.path.join(args.out, "charts"), s, chaos_reports)
        print(f"  wrote {len(made)} charts to {args.out}/charts/")
    return 0


def narrate_chaos(mesh) -> list:
    reports = []

    rule("F1 -- node down during propagation")
    r = inject.f1_node_down(mesh)
    print(f"  DETECT  N3 offline; announce lands on N1,N2 only "
          f"-> N3 missing insight={r['detect']['victim_missing_insight']}, "
          f"digest diverged={r['detect']['digest_diverged']}")
    print(f"  REPAIR  N3 restored -> caught up in {r['repair']['gossip_rounds_to_catch_up']} "
          f"gossip rounds {C['dim']}(anti-entropy IS the recovery -- no catch-up code path){C['x']}")
    print(f"  INTEGRITY  converged={C['ok']}{r['integrity']['converged']}{C['x']}  "
          f"chains_valid={r['integrity']['chains_valid']}")
    reports.append(r)

    rule("F2 -- four poisoned updates from a COMPROMISED node (N3 skips its own guardrail)")
    r = inject.f2_poisoned(mesh)
    print(f"  {C['dim']}{'#':<3}{'attack':<44}{'expected':<20}{'caught at':<12}status{C['x']}")
    for row in r["rows"]:
        st = f"{C['ok']}{row['status']}{C['x']}" if row["blocked"] else f"{C['bad']}{row['status']}{C['x']}"
        print(f"  {row['tag']:<3}{row['desc']:<44}{row['expected']:<20}{row['stage']:<12}{st}")
    print(f"\n  {C['b']}(d) is the one that matters.{C['x']} Valid signature, in-bounds params, "
          f"confident numbers.")
    print(f"  It passed every guardrail. It died because {C['b']}two peers replayed it and the")
    print(f"  numbers were not real{C['x']}. A signature proves who said it, never that it is true.")
    print(f"\n  PRUNE  tombstoned {r['prune']['tombstoned']}")
    print(f"         (incl. descendant {r['prune']['descendant']} via derived_from)")
    print(f"         still VERIFIED: {C['ok']}{r['prune']['surviving_verified']}{C['x']}")
    print(f"         entries deleted: {r['integrity']['entries_deleted']} "
          f"{C['dim']}-- pruning is tombstoning. Memory is never reset, and the removal")
    print(f"         is itself a signed, auditable entry.{C['x']}")
    reports.append(r)

    rule("F3 -- partition and heal")
    r = inject.f3_partition(mesh)
    print(f"  DETECT  {r['detect']['partition']} -> majority has insight="
          f"{r['detect']['majority_has']}, minority has={r['detect']['minority_has']}, "
          f"digest split={r['detect']['digest_split']}")
    print(f"  REPAIR  healed -> converged in {r['repair']['gossip_rounds_to_converge']} rounds; "
          f"N3 has it={r['repair']['minority_has']}")
    print(f"  INTEGRITY  converged={C['ok']}{r['integrity']['converged']}{C['x']}  "
          f"chains_valid={r['integrity']['chains_valid']}")
    print(f"  {C['dim']}Cost of the partition: N3 negotiated on stale config -- it paid extra")
    print(f"  rounds. It never produced an incorrect contract. That is scoped eventual")
    print(f"  consistency, chosen deliberately: insights are advisory performance knowledge,")
    print(f"  and safety lives in the priority lattice inside each fail-closed negotiation.{C['x']}")
    reports.append(r)
    return reports


if __name__ == "__main__":
    sys.exit(main())
