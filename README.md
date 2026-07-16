# Cognition Fabric — Code with Cisco, Problem Statement 1

A working prototype of the **Internet of Cognition**: heterogeneous agents that align
without a coordinator (Phase 1), on top of a **Cognition Fabric** that remembers what they
learned and propagates it — the ratchet effect (Phase 2).

Everything below is measured by the code in this repo. Nothing is mocked.

## Run it

Python 3.11+ and a venv. Everything is in `csp-phase2/requirements.txt`.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r csp-phase2/requirements.txt
cd csp-phase2
```

> `uvicorn[standard]` is not optional — plain `uvicorn` ships no WebSocket library, so the
> UI renders perfectly and streams nothing. Only `cryptography` is needed for the protocol
> itself; matplotlib is charts, pytest is tests, fastapi/uvicorn are the UI.

```bash
# Phase 1 — one semantic handshake, fully narrated
python -m demo.run_handshake --seed 42
python -m demo.run_handshake --seed 42 --flip     # flip competence -> different settlement

# Phase 2 — THE demo: 30 tasks, chaos, charts
python -m demo.run_demo --seed 42 --chaos --charts

# baseline for comparison (same seed, pipeline disabled)
python -m demo.run_demo --seed 42 --fabric off

pytest -q                                          # 94 tests
```

Artifacts land in `csp-phase2/out/`: `summary.md`, `telemetry.jsonl`,
`fabric_N{1,2,3}.jsonl`, `charts/*.png`.

Add `--no-color` for a plain terminal, `--pace 0.15` to slow the narration down for a
live audience, `--analyzer gemini` to draft hypotheses with an LLM (see below).

## Run the live UI

```bash
cd csp-phase2
python -m ui.server                 # -> http://127.0.0.1:8000
```

Open the page and **press ▶ Run 30 tasks**. Nothing runs until you do — the server starts
idle so you control when the demo begins in front of an audience.

What happens, in order:

1. The **baseline** runs first, silently (same seed, pipeline off). It costs nothing —
   time is virtual — and it is what the grey bars are measured against.
2. The **task stream** fills top-down. Watch rounds collapse **5 → 1** at task ~14 while
   the era stays lossy: the link is still slow, the fabric just stopped re-deriving the
   answer. Tasks 21–24 show the lossy insight *correctly not applied* to normal traffic;
   tasks 25–30 show **N3 reusing N1's insight, having never seen the incident**.
3. The **insight lifecycle** panel fills on the SLO breach: analyzer → guardrail → peer
   replay → two matching replay hashes → VERIFIED.
4. The **three node columns** converge on one digest. Chain heads differ by design.

Then press the chaos buttons — **F1 node down**, **F2 poison ×4**, **F3 partition**.
They stay disabled until a run finishes, because they fire at the *live* mesh that run
built. F2 is the one to hand a judge: four poisoned updates die at four different layers,
and the fabric stays converged.

| control | does |
|---|---|
| `seed` | any seed; 42 is the rehearsed one |
| `analyzer` | `rules` (deterministic, rehearse on this) or `gemini` |
| `pace` | seconds per task — presentation only, never physics. The numbers come from the virtual clock and do not move when you slow it down. |

The UI is a **subscriber**, not a component: it renders `run()`'s `on_event` and
`Telemetry.on_record` — the same code path the terminal demo and the tests exercise. Pull
it out and the fabric behaves identically; it cannot sign, vote, or promote anything.
If it dies mid-demo, `python -m demo.run_demo --seed 42 --chaos` is the same run.

## What it does

Three nodes (N1, N2, N3), each with two agent personas on opposing goals — `throughput`
(minimise latency, maximise throughput) vs `security` (maximise inspection depth and
coverage). Deep inspection genuinely costs latency and throughput, so the conflict is
real rather than decorative. 30 enterprise tasks arrive under changing conditions.

| tasks | condition | rounds | duration | what you are watching |
|---|---|---|---|---|
| 1–8 | normal | 4–5 | ~60 ms | the baseline |
| 9–13 | **lossy** | 4–5 | ~9 300 ms, 3 time out | conditions change; nobody tells the agents |
| **13** | | | | SLO trips → analyzer drafts → guardrail ALLOW → **N2 and N3 independently replay** → matching hashes → **VERIFIED** |
| 14–20 | lossy | **1** | ~5 800 ms | the ratchet: warm start from collective memory |
| 21–24 | normal | 4 | ~60 ms | **the lossy insight is correctly NOT applied** |
| 25–30 | lossy, **N3**×N2 | **1** | ~6 000 ms | **N3 reuses N1's insight — it never saw the incident** |

Measured against the same-seed baseline, on lossy tasks: **mean rounds 4.67 → 1.53
(−67 %)**, mean duration **−25 %**, negotiations that time out entirely **6/18 → 3/18**
(and all three remaining are before the insight existed).

Rounds is the honest headline — it is exactly what the remembered settlement removes.
Duration *understates* the win, because the baseline's timeouts are capped at the budget
and produced no contract at all.

## The five deliverables

| # | Deliverable | Where | Proof |
|---|---|---|---|
| 1 | Dynamic task/incident flow | `loadgen/tasks.py` | seeded 30-task flow with condition eras |
| 2 | Fabric layer | `fabric/log.py`, `fabric/gossip.py` | signed content-addressed entries; hash chain + gossip |
| 3 | Accelerator | `insights/pipeline.py` | LOCAL → CANDIDATE → replay-verify → 2-of-3 quorum → VERIFIED |
| 4 | Autonomous Guardrail | `guardrail/guardrail.py` | deterministic checks, signed DENY entries |
| 5 | Visible reuse (ratchet) | `nodes.py`, `core/csp_mini.py` | tasks 25–30: N3 reuses N1's insight |
| B | Chaos Injector | `chaos/inject.py` | F1 node down, F2 four poisoned updates, F3 partition |

## The three defence questions

**Innovation vs hallucination.** A breakthrough is a claim with reproducible evidence.
Every insight carries a replayable scenario; two independent nodes deterministically
re-execute it and must produce **matching replay hashes** before quorum forms. Agreeing
opinions are not a quorum — agreeing *evidence* is. Watch chaos fault **F2(d)**: a
perfectly signed, in-bounds insight with confidently fabricated `metric_after` passes
every guardrail and dies at replay, because the numbers two peers actually measure are
not the numbers it claimed. A signature proves who said it, never that it is true.

**Poisoning and drift.** Free-form memory writes do not exist. Insights are typed,
signed, whitelisted and bounds-checked, and promoted through untrusted → verified tiers.
There is no whitelist key for guardrail config, crypto params, or constraint classes — an
insight cannot express "disable the guardrail" because the schema has nowhere to put it.
*Absence is the mechanism.* Detection is layered: guardrail (structure/policy), replay
divergence (fabrication), probation (live regression). Isolation is a QUARANTINED status
in the chain. Pruning tombstones the provenance subtree via `derived_from` — memory is
never reset, and the removal is itself a signed, auditable entry. F2 shows two verified
insights surviving the prune.

**Consistency.** Scoped eventual consistency. `scope.context` is part of the insight key,
so two fixes that are each valid in a different context are not a conflict — they coexist
under different keys. Tasks 21–24 show this: the lossy insight is *visibly not applied*
to normal traffic. Same-scope collisions resolve by a total order (largest proven
improvement → newer version → lower id hash). We can afford eventual consistency because
insights are **advisory performance knowledge**: safety lives in the priority lattice
inside each fail-closed negotiation, so a stale insight costs rounds, never correctness.
F3 prices it out loud — the partitioned node paid extra rounds and produced zero
incorrect contracts. Semantic locking would buy nothing here and cost availability.

## Design decisions worth defending

**Synchronous engine on a virtual clock, not asyncio.** The protocol is strictly
alternating request/response, so asyncio buys no concurrency — but it costs the exact
determinism that replay verification depends on. Virtual time also means a negotiation
over a 1 800 ms/hop link costs microseconds of wall clock, which is what makes replay a
cheap primitive instead of a five-second wait. Phase 1 defined transport as a pluggable
L0 adapter; we run the in-proc one for determinism and fault injectability. Envelopes and
crypto are identical on any adapter.

**Convergence is proven by a digest, not by identical chain heads.** Three nodes that
author concurrently cannot share a chain head unless you re-order and re-link on merge —
and re-linking is log rewriting, which the audit story forbids. So the two concerns are
separated: the **chain** gives per-node tamper evidence (heads legitimately differ; they
record the order each node *learned* things), and the **entry set** — content-addressed,
signed, grow-only — is a CRDT whose union is commutative, associative and idempotent.
`digest()` over that set is what converges. Status is derived by folding the set, and the
fold is a join over a status lattice, so receipt order cannot change the verdict. That is
why a healed partition needs no reconciliation pass.

**The LLM has no write path.** The rule-based analyzer is primary and always on. It is an
advisor: it drafts a hypothesis and cannot promote anything. It also runs the same
verification its peers will run, *before* submitting — we never ask the network to check a
claim we have not checked ourselves.

## Known limits (deliberate, not accidental)

- **In-proc transport.** Real sockets are an adapter swap; nothing above L0 changes.
- **Gossip advertises the full entry-id list**, O(n) per round. n is in the tens here; the
  production path is a Merkle/IBLT digest exchange — same protocol, sublinear payload.
- **Pinned keys, no PKI.** The Phase 1 answer; production path is attestation/VC.
- **Quorum is 2-of-3 over a fixed, pinned membership.** No dynamic membership, no Sybil
  resistance — pinning is what stands in for it.
- **A peer can quarantine a good insight** by attesting `ok=False`. That is an
  availability attack, not an integrity one, and the entry is signed so it is
  attributable. Owned, not solved.
- **Telemetry is OTel-*shaped* JSONL**, not the OTel SDK.
- **The UI has no auth and binds to localhost.** It is a demo viewer, not a product; it
  also has no write path into the fabric, so there is nothing in it to authorise.

## Layout

```
csp-phase2/
  core/       crypto (canonical JSON, Ed25519, pinned keyring), netops registry,
              virtual-clock bus with fault hooks, negotiation engine + replay()
  fabric/     insight model, hash-chained signed log (grow-only set), gossip
  guardrail/  deterministic pre-admission checks + signed DENY entries
  insights/   replay-verify, quorum, scoped conflict resolution
  analyzer/   rules.py (primary, always on) + gemini.py (optional, grounding-gated)
  ui/         FastAPI + websocket live view; a subscriber, never in the trust path
  metrics/    OTel-shaped JSONL + per-context rolling-window SLO evaluator
  loadgen/    seeded task flow with condition eras
  chaos/      F1 node down, F2 poisoned updates, F3 partition/heal
  demo/       run_handshake.py (Phase 1), run_demo.py (Phase 2), charts.py
  tests/      94 tests: Phase 1 core, Phase 2 fabric, chaos + demo, analyzer + UI
  nodes.py    Node = personas + fabric replica + guardrail + analyzer; Mesh
```

## Is there a real AI in this?

Yes, in exactly one place, and the placement is the argument. `--analyzer gemini` lets a
model draft incident *hypotheses* behind a grounding gate that rejects invented span ids
and non-whitelisted knobs; it votes on *whether* to warm-start, never on the settlement
point. It has no write path and no accept authority. Everything it drafts is rebuilt as
typed bounded fields, replayed by the drafting node, then independently replayed by two
peers who must reproduce our exact numbers.

It is deliberately **not** in the negotiation loop. `replay()` being byte-identical across
nodes *is* the anti-hallucination gate — an LLM inside `negotiate()` would put
non-determinism inside the verification primitive the whole argument rests on. Here, being
wrong is free: a bad hypothesis costs one replay and dies. Rules stay primary and always
on; any failure (no key, timeout, bad JSON, ungrounded output) falls back to them, loudly.
Rehearse it with `GEMINI_API_KEY` unset — the gate firing is the point.

```bash
export GEMINI_API_KEY=...            # optional; without it, rules, loudly
python -m demo.run_demo --seed 42 --analyzer gemini
```

Note that `--analyzer gemini` makes *drafting* non-deterministic, so the same seed no
longer reproduces byte-identically. That is correct, not a regression: reproducibility is
a property of the verification plane, not of the hypothesis. **Demo on `rules`; show
`gemini` as the upgrade.** Every prompt and response is logged to `out/gemini_log.jsonl`.

## The docs

The build plans this implements are `04_phase2_implementation_plan.md` (the fabric) and
`05_phase2_agents_and_ui_plan.md` (the analyzer and UI). Docs 01–03
(architecture, Phase 1 prototype spec, scalability roadmap) are the Phase 1 blueprint and
are currently excluded by `.gitignore`, as are the Cisco-Confidential problem statements.

Where code and the docs diverge, the divergence is documented in-file at the point of
departure, and summarised in "Design decisions worth defending" above.
