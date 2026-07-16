# Cognition Fabric — Code with Cisco, Problem Statement 1

A working prototype of the **Internet of Cognition**: heterogeneous agents that align
without a coordinator (Phase 1), on top of a **Cognition Fabric** that remembers what they
learned and propagates it — the ratchet effect (Phase 2).

Everything below is measured by the code in this repo. Nothing is mocked.

## Run it

Python 3.11+. Dependencies: `cryptography`, `matplotlib` (charts only), `pytest` (tests only).

```bash
cd csp-phase2

# Phase 1 — one semantic handshake, fully narrated
python -m demo.run_handshake --seed 42
python -m demo.run_handshake --seed 42 --flip     # flip competence -> different settlement

# Phase 2 — THE demo: 30 tasks, chaos, charts
python -m demo.run_demo --seed 42 --chaos --charts

# baseline for comparison (same seed, pipeline disabled)
python -m demo.run_demo --seed 42 --fabric off

pytest -q                                          # 67 tests
```

Artifacts land in `csp-phase2/out/`: `summary.md`, `telemetry.jsonl`,
`fabric_N{1,2,3}.jsonl`, `charts/*.png`.

Add `--no-color` for a plain terminal, `--pace 0.15` to slow the narration down for a
live audience.

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
- No web dashboard; the terminal and the charts are the interface.

## Layout

```
csp-phase2/
  core/       crypto (canonical JSON, Ed25519, pinned keyring), netops registry,
              virtual-clock bus with fault hooks, negotiation engine + replay()
  fabric/     insight model, hash-chained signed log (grow-only set), gossip
  guardrail/  deterministic pre-admission checks + signed DENY entries
  insights/   replay-verify, quorum, scoped conflict resolution
  analyzer/   rule-based incident analyzer (primary, no write path)
  metrics/    OTel-shaped JSONL + per-context rolling-window SLO evaluator
  loadgen/    seeded task flow with condition eras
  chaos/      F1 node down, F2 poisoned updates, F3 partition/heal
  demo/       run_handshake.py (Phase 1), run_demo.py (Phase 2), charts.py
  tests/      67 tests: Phase 1 core, Phase 2 fabric, chaos + demo
  nodes.py    Node = personas + fabric replica + guardrail + analyzer; Mesh
```

The build plan this implements is `04_phase2_implementation_plan.md`. Docs 01–03
(architecture, Phase 1 prototype spec, scalability roadmap) are the Phase 1 blueprint and
are currently excluded by `.gitignore`, as are the Cisco-Confidential problem statements.

Where code and Doc 4 diverge, the divergence is documented in-file at the point of
departure, and summarised in "Design decisions worth defending" above.
