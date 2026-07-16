"""Phase 1 deliverable: one end-to-end semantic handshake, fully narrated.

    python -m demo.run_handshake [--seed 42] [--link normal|lossy] [--flip]

Two agents on opposing optimization targets discover each other's declared
state, negotiate, and bind themselves to a single machine-readable intent
contract -- with no coordinator and no human in the loop.

Everything printed is recomputed from the disclosed descriptors and the signed
transcript, which is the point: both sides (and any auditor) reconstruct the
same utilities from public information, so arbitration is deterministic without
anyone revealing a private bottom line.
"""
from __future__ import annotations

import argparse
import json
import random
import sys

from core.bus import LOSSY_DELAY_MS, NORMAL_DELAY_MS, Bus, Clock, FaultState
from core.crypto import Identity, Keyring, canonical
from core.csp_mini import (
    effective_weights,
    feasible_box,
    feasible_points,
    hard_ok,
    make_agent,
    negotiate,
    utility,
)
from core.registry import DEFAULT_PARAMS, DIM, DIM_IDS, REGISTRY_HASH

from demo.console import C, banner, setup


def short(d: str) -> str:
    return d.split("/", 1)[1]


def fmt_point(p: dict) -> str:
    return "  ".join(f"{short(d)}={p[d]}" for d in DIM_IDS)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--link", choices=["normal", "lossy"], default="normal")
    ap.add_argument("--flip", action="store_true",
                    help="swap competence profiles: same conflict, different settlement (P6)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)
    setup(args.no_color)

    A = make_agent("agent-A.throughput", "throughput")
    B = make_agent("agent-B.security", "security")
    if args.flip:
        A.competence, B.competence = B.competence, A.competence

    banner("PHASE 1 -- SEMANTIC HANDSHAKE & INTENT ALIGNMENT")
    print(f"registry netops/1.0.0  hash={REGISTRY_HASH[:16]}...  dims={len(DIM_IDS)}")
    print(f"transport: in-proc adapter, {args.link} link, seed={args.seed}")

    banner("1. DECLARED INTENT  (this is the entire disclosure -- no prompt history)")
    for cfg in (A, B):
        w = effective_weights(cfg)
        print(f"\n{C['b']}{cfg.agent_id}{C['x']}  ({cfg.persona})")
        print(f"  objectives : " + ", ".join(
            f"{o['direction']} {short(o['dim'])} w={o['weight']}" for o in cfg.objectives))
        print(f"  competence : " + ", ".join(f"{short(d)}={v}" for d, v in sorted(cfg.competence.items())))
        print(f"  eff.weights: " + ", ".join(f"{short(d)}={v:.3f}" for d, v in sorted(w.items())))
        for h in cfg.hard:
            print(f"  hard       : {short(h['dim'])} {h['op']} {h['value']}  [{h['class']}]")
    payload = len(canonical({"a": [o for o in A.objectives], "h": A.hard, "c": A.competence}))
    print(f"\n{C['dim']}intent descriptor payload: {payload} bytes. The semantics travel as typed")
    print(f"structure, not as tokens -- there is no transcript to ship.{C['x']}")

    banner("2. FEASIBLE REGION  (intersection of hard constraints, per dimension type)")
    box, relaxed = feasible_box([A, B])
    if box is None:
        print(f"{C['warn']}EMPTY after relaxation -> ABORT(EMPTY_FEASIBLE). Fail closed.{C['x']}")
        return 1
    for d in DIM_IDS:
        t, b = DIM[d]["type"], box[d]
        rendered = f"[{b[0]}, {b[1]}]" if isinstance(b, list) else "{" + ", ".join(map(str, sorted(b))) + "}"
        if t == "ordinal":
            lv = DIM[d]["domain"]["levels"]
            rendered = "{" + ", ".join(lv[b[0]:b[1] + 1]) + "}"
        print(f"  {short(d):<18} {t:<12} {rendered}")
    print(f"  relaxed: {relaxed or 'nothing -- the region was non-empty on first intersection'}")
    F = feasible_points(box, DEFAULT_PARAMS["grid_k"])
    print(f"  {len(F)} physically realizable settlement points "
          f"{C['dim']}(grid filtered by the registry coupling model){C['x']}")

    banner("3. NEGOTIATION")
    rng = random.Random(args.seed)
    faults = FaultState(default_delay_ms=LOSSY_DELAY_MS if args.link == "lossy" else NORMAL_DELAY_MS)
    bus = Bus(Clock(0.0), faults, rng)
    idents = {c.agent_id: Identity.deterministic(c.agent_id) for c in (A, B)}
    kr = Keyring()
    for i in idents.values():
        kr.pin_identity(i)

    ctx = {"link_quality": args.link, "workload": "steady",
           "pair": ["agent-A", "agent-B"], "seed": args.seed}
    res = negotiate(bus, A, B, ctx, DEFAULT_PARAMS, identities=idents, keyring=kr,
                    session=f"demo-{args.seed}")

    wa, wb = effective_weights(A), effective_weights(B)
    print(f"{C['dim']}{'msg':<16}{'from':<24}{'rnd':<5}{'u_A':<7}{'u_B':<7} point / detail{C['x']}")
    for env in res.transcript:
        pay = env["payload"]
        pt = pay.get("point")
        ua = f"{utility(A, pt, box, wa):.3f}" if pt else ""
        ub = f"{utility(B, pt, box, wb):.3f}" if pt else ""
        rnd = str(pay.get("round", ""))
        if pt:
            detail = fmt_point(pt)
        elif env["type"] == "ACCEPT":
            detail = f"{C['ok']}point_hash={pay['point_hash']}{C['x']}"
        elif env["type"] == "COMMIT":
            detail = f"contract {pay['contract']['contract_id']} (+1 sig)"
        elif env["type"] == "COMMIT_ACK":
            detail = f"countersigned by {sorted(pay['contract']['signatures'])[-1]}"
        else:
            detail = f"{C['dim']}descriptor: {len(canonical(pay))} bytes{C['x']}"
        print(f"  {env['type']:<14}{env['from']:<24}{rnd:<5}{ua:<7}{ub:<7} {detail}")
    print(f"\n{C['dim']}u_A / u_B above are recomputed here from the DISCLOSED descriptors alone.")
    print(f"Both agents -- and you -- derive the same numbers, which is why the outcome is")
    print(f"deterministic without either side revealing its private bottom line.{C['x']}")

    if res.aborted:
        print(f"\n{C['warn']}ABORT({res.abort_reason}) after {res.duration_ms:.0f}ms{C['x']}")
        return 1

    banner("4. SHARED INTENT CONTRACT  (the machine-readable state both are bound by)")
    c = res.contract
    print(f"  contract_id   : {c['contract_id']}")
    print(f"  parties       : {', '.join(c['parties'])}")
    print(f"  resolved_by   : {c['provenance']['resolved_by']}  in {c['provenance']['rounds']} rounds")
    print(f"  ontology_hash : {c['ontology_hash'][:16]}...  (pins what every word meant)")
    print(f"  transcript    : {c['transcript_hash'][:16]}...  ({res.messages} signed envelopes)")
    print(f"  signatures    : {', '.join(sorted(c['signatures']))}")
    print(f"\n  {C['b']}agreed{C['x']}")
    for d in DIM_IDS:
        print(f"    {short(d):<18} = {str(c['agreed'][d]):<16} authority: {c['authority_map'][d]}")

    banner("5. ENFORCEMENT  (agreement without enforcement is just logging)")
    for cfg in (A, B):
        ok = hard_ok(cfg, c["agreed"])
        mark = f"{C['ok']}SATISFIED{C['x']}" if ok else f"{C['warn']}VIOLATED{C['x']}"
        print(f"  {cfg.agent_id:<24} every hard constraint {mark}")
    print(f"\n  u_A={utility(A, c['agreed'], box, wa):.3f}   u_B={utility(B, c['agreed'], box, wb):.3f}"
          f"   {C['dim']}neither got its optimum; both are bound{C['x']}")
    print(f"\n{C['dim']}Contract JSON (Q4 raw material):{C['x']}")
    print(json.dumps({k: c[k] for k in ("contract_id", "parties", "agreed", "provenance",
                                        "config_epoch", "transcript_hash")},
                     indent=2, sort_keys=True)[:900])
    return 0


if __name__ == "__main__":
    sys.exit(main())
