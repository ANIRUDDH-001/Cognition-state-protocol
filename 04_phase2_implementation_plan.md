# Doc 4 — Phase 2 Final Implementation Plan (Cognition Fabric — 5-hour build)
**Project:** Code with Cisco · Problem Statement 1 · Phase 2 — Continuous Mesh & Ratchet Effect
**Constraint:** code freeze in 5 hours · live demo next day · team of 3 (P1, P2, P3) working in parallel with Claude Code
**Companion docs:** Doc 1 (architecture), Doc 2 (Phase 1 spec — envelope/crypto/negotiation conventions carry over), Doc 3 (con register)
**This document is the single source of truth for the build. If code and this doc disagree during the freeze window, the doc wins unless the doc is physically impossible in remaining time — then cut per §12.**

---

## 0. Hour-0 decision gate (5 minutes, whole team)

**Does the Phase 1 repo (Doc 2 milestones M1–M4) exist and run end-to-end right now?**
- **NO (assume this; plan is written for it):** build the compressed CSP core in §5 (`core/csp_mini.py`). It preserves the properties the defense needs (typed dims, feasibility ∩, ε-concession, bounded rounds, signed envelopes, transcript hash) and drops what the demo doesn't need (arbitration, websockets, progressive disclosure tiers, commitments).
- **YES:** P1 skips §5 build, instead wraps the existing engine behind the exact interface in §5.6 and adds the metrics hooks (§8). Everything else unchanged. Bank the time into rehearsal.

## 1. Scope lock — what we build and what we cut

**BUILD (maps 1:1 to the five deliverables + bonus):**
| # | Brief deliverable | Our component |
|---|---|---|
| 1 | Dynamic task/incident flow | `loadgen/` — seeded stochastic task generator with condition "eras" |
| 2 | Fabric layer | `fabric/` — per-node hash-chained append-only insight log + gossip anti-entropy |
| 3 | Accelerator | `insights/pipeline.py` — LOCAL → CANDIDATE → replay-verify → 2-of-3 quorum → VERIFIED → propagate |
| 4 | Autonomous Guardrail | `guardrail/` — deterministic policy checks, signed DENY audit events |
| 5 | Visible reuse (ratchet) | warm-start negotiation from fabric insights; rounds/time-to-contract drop on charts |
| B | Chaos Injector | `chaos/` — node kill, poisoned updates ×4, partition/heal — all via transport + fabric hooks |

**CUT (say "production path" if asked, never pretend it exists):** OTel SDK (we emit OTel-convention-shaped JSONL instead), second domain registry, web dashboard, websocket transport, arbitration in the mini core, canary percentage rollout (replaced by simpler probation counter, §7.4), mTLS/PKI (Phase 1 answer: pinned keys), real network.

**Non-negotiable invariants (the defense rests on these — never cut):**
1. No insight is ever applied without: valid signature → guardrail ALLOW → deterministic replay reproduction → 2-of-3 quorum attestations.
2. The LLM (Gemini) has **no write path** to the fabric and **no accept/reject authority**. It only drafts candidate insights. Rule-based analyzer is primary; Gemini is an optional upgrade behind a flag.
3. Insights never modify safety/regulatory-class constraints, crypto params, or guardrail rules (whitelist, §6.2).
4. Negotiation stays fail-closed regardless of fabric state. A missing/stale insight costs rounds, never correctness.
5. Every fabric mutation (append, quarantine, revoke) is a signed event in the hash chain. Pruning is tombstoning, never log rewriting.

## 2. Repo layout

```
csp-phase2/
├── core/
│   ├── crypto.py          # canonical JSON, Ed25519, sha256, hash-chain helpers   (P1)
│   ├── registry.py        # netops dims (from Doc 2 §3.2) + tunable-param bounds  (P1)
│   ├── csp_mini.py        # compressed negotiation engine (§5)                    (P1)
│   └── bus.py             # in-proc transport with fault-injection hooks (§4)     (P1)
├── fabric/
│   ├── model.py           # Insight dataclass + statuses (§6)                     (P2)
│   ├── log.py             # per-node hash-chained log + JSONL persistence (§7.1)  (P2)
│   └── gossip.py          # anti-entropy sync (§7.2)                              (P2)
├── insights/
│   └── pipeline.py        # validate → replay → attest → promote (§7.3–7.5)       (P2)
├── guardrail/
│   └── guardrail.py       # deterministic checks + audit events (§6.2)            (P2)
├── analyzer/
│   ├── rules.py           # rule-based incident analyzer — PRIMARY (§9.1)         (P3)
│   └── gemini.py          # optional LLM diagnostician, strict JSON + grounding   (P3)
├── loadgen/
│   └── tasks.py           # seeded task generator + eras (§8.2)                   (P3)
├── metrics/
│   └── telemetry.py       # spans/metrics JSONL, SLO evaluator (§8.1)             (P1)
├── chaos/
│   └── inject.py          # faults F1–F3 (§10)                                    (P3)
├── demo/
│   ├── run_demo.py        # THE deliverable: scripted narrated run (§11)          (P3)
│   └── charts.py          # matplotlib PNGs from telemetry JSONL                  (P3)
├── nodes.py               # Node = agent(s) + fabric replica + analyzer wiring    (P2)
├── tests/
│   ├── test_pipeline_gate.py      # "no unverified insight ever applied"
│   ├── test_replay_determinism.py # same evidence → byte-identical result
│   └── test_chain_converge.py     # partition → heal → identical log heads
└── out/                   # telemetry.jsonl, fabric logs, charts/, demo transcript
```

Python 3.11+, deps: `cryptography`, `matplotlib`, `requests` (Gemini only). Nothing else. No pydantic (dataclasses + manual checks — saves time), no DB (JSONL), no websockets.

## 3. System shape

One asyncio process. Three logical **nodes** N1, N2, N3. Each node owns: one Ed25519 keypair (pinned in config, Phase 1 style), one or more CSP agents (we use two agent personas per node: `throughput` and `security`, configs from Doc 2 §14 scenario 1), one fabric replica, one analyzer. Nodes exchange **only signed envelopes** over `core/bus.py`. Tasks arrive from `loadgen`; each task is assigned to a node pair (e.g. N1.throughput vs N2.security), producing a negotiation, an executed contract, and telemetry. Defense line for in-proc: *"Phase 1 defined transport as a pluggable L0 adapter (websocket / tcp / in-proc queue). We demo on the in-proc adapter for determinism and fault injectability; envelopes and crypto are identical on any adapter."* — this is literally Doc 1 §3/L0, quote it.

## 4. `core/bus.py` — transport with chaos hooks (P1, hour 0–0.5)

```python
class Bus:
    def __init__(self): self.queues = {}; self.faults = FaultState()
    def register(node_id) -> asyncio.Queue
    async def send(env: dict):            # env already signed
        f = self.faults
        if f.partitioned(env["from"], env["to"]): return          # silently dropped
        if f.down(env["to"]): return
        d = f.delay_ms(env["from"], env["to"])                    # normal era: ~5–10ms
        await asyncio.sleep(d/1000); self.queues[env["to"]].put_nowait(env)

class FaultState:  # mutated by loadgen eras and chaos/inject.py
    node_down: set[str]
    partitions: set[frozenset[str,str]]
    link_delay_ms: dict[tuple, tuple[float,float]]   # (lo,hi) uniform sample
```
Per-message latency is *measured* at the receiver (`recv_ts - env["ts"]`) and emitted as a metric — this is what makes the "10ms fine, 1s is an incident" story real and visible.

## 5. `core/csp_mini.py` — compressed CSP engine (P1, hour 0.5–2.5)

Preserves from Doc 2: dimension types and netops registry values (§3.2), envelope fields `{schema:"csp/1.0", type, session, seq, from, to, ts, nonce, payload, sig}` with Ed25519 over canonical JSON (Doc 2 §4, §11), priority classes and the never-relax rule (§8), feasibility per type (§9.1), ε-concession bound (§9.4), transcript hash into the contract (§7).

Simplifications (document in code comments, own them if asked): message flow collapsed to `DECLARE → PROPOSE/COUNTER* → ACCEPT → COMMIT` (no HELLO ontology negotiation — both registries identical here; say "shared-dim negotiation demonstrated in Phase 1 design"); no commitments/disclosure tiers; at `R_max` without ACCEPT → deterministic settlement at the per-dimension midpoint of the feasible region (replaces Nash arbitration; deterministic, bounded, tie-break-free) — *"Phase 1 specified competence-weighted Nash arbitration; the demo core substitutes a deterministic midpoint fallback; concession settles before the cap in all demo scenarios anyway."*

### 5.6 THE interface (everyone codes against this — freeze it first)
```python
@dataclass
class NegotiationResult:
    contract: dict          # {agreed:{dim:val}, parties, provenance:{rounds,resolved_by},
                            #  transcript_hash, config_epoch, insight_ids:[...], signatures:{}}
    rounds: int
    duration_ms: float      # wall time incl. simulated transport delays
    aborted: bool
    abort_reason: str|None

async def negotiate(bus, node_a, node_b, task_ctx: dict, params: dict,
                    warm_start: dict|None) -> NegotiationResult
# params = {"eps":0.05, "r_max":8, "negotiate_timeout_ms":10000}  (tunables — insights change these)
# warm_start = {dim: value} opening point from a fabric insight, or None (open at own optimum)
# task_ctx = {"link_quality":"normal"|"lossy", "workload":"steady"|"bursty", "pair":(...), "seed":int}

def replay(scenario: dict, params: dict) -> NegotiationResult
# scenario = recorded {agent configs, task_ctx, seed}; runs SYNCHRONOUSLY on a fresh in-proc bus
# with the recorded fault profile. Deterministic: same scenario+params → identical result.
# THIS is the verification primitive for the pipeline (§7.4).
```
Utilities: weighted-linear per Doc 2 §9.3 over the demo dims (latency_ms, throughput_mbps, inspection_depth, sample_rate, tls_version, log_export). Timeout: any wait beyond `negotiate_timeout_ms` → retransmit once, then `aborted=True, reason="TIMEOUT"`. Timeouts under lossy eras are the incident source.

## 6. Insight model + guardrail (P2, hour 0–1.5)

### 6.1 `fabric/model.py`
```python
@dataclass
class Insight:
    id: str                  # "ins-" + sha256(canonical(body))[:12]
    version: int
    scope: dict              # {"ns":"netops", "context":{"link_quality":"lossy"}}  — exact-match key
    claim: dict              # ONLY whitelisted keys (§6.2), e.g.
                             # {"params":{"negotiate_timeout_ms":30000,"r_max":6,"eps":0.08},
                             #  "warm_start": {"netops/latency_ms":8.5, ...}}
    evidence: dict           # {"scenario":{...replayable...}, "metric_before":{...},
                             #  "metric_after":{...}, "claimed_improvement":{"rounds":-3,"duration_ms":-2100}}
    provenance: dict         # {"discovered_by":"N1","analyzer":"rules"|"gemini","sig":b64,
                             #  "derived_from":[insight_ids]}
    status: str              # LOCAL|CANDIDATE|VERIFIED|QUARANTINED|REVOKED
    attestations: list       # [{"node":"N2","replay_hash":..., "sig":...}]
```

### 6.2 `guardrail/guardrail.py` — deterministic, ~120 lines, be able to read it aloud
`check(insight) -> Allow | Deny(reason_code)`; reason codes: `INVALID_SIG, UNKNOWN_SOURCE, NOT_WHITELISTED, BOUNDS_VIOLATION, POLICY_VIOLATION, MALFORMED_EVIDENCE, RATE_LIMITED`.
Checks in order: (1) signature verifies against pinned key of `discovered_by`; (2) every `claim.params` key ∈ WHITELIST with value inside bounds: `eps∈[0.01,0.2], r_max∈[2,12], negotiate_timeout_ms∈[1000,60000]`; (3) `warm_start` values inside registry domains AND violate no safety/regulatory-class constraint of either standard persona (hardcode the check: `tls_version` must remain "1.3", `log_export` must remain true, `inspection_depth ≥ selective_deep`) — **this is the demo's POLICY_VIOLATION catch**; (4) evidence contains a replayable scenario + before/after metrics; (5) source rate limit: ≤ 5 submissions / 60 s. Every DENY → signed `GUARDRAIL_DENY` event appended to the local chain (visible guardrail logic — deliverable 4). Insights NEVER touch guardrail config: no such key exists in the whitelist — absence is the mechanism, say that.

## 7. Fabric log, gossip, pipeline (P2, hour 1.5–3.25)

### 7.1 `fabric/log.py` — hash-chained append-only log per node
Entry: `{idx, prev_hash, entry_hash, kind: INSIGHT|ATTEST|STATUS|GUARDRAIL_DENY|TOMBSTONE, body, node_sig}` with `entry_hash = sha256(canonical(entry minus entry_hash,node_sig))`, `prev_hash` = previous entry's hash. Genesis fixed constant. Persist JSONL to `out/fabric_<node>.jsonl`. `head()` returns `(idx, entry_hash)` — the convergence proof for the chaos demo is three identical heads printed side by side. Derived state (current status per insight id) is rebuilt by folding the log — REVOKED/QUARANTINED are just later entries; nothing is deleted (defense: prune without reset).

### 7.2 `fabric/gossip.py`
Every 500 ms each node sends `GOSSIP_HEAD {idx, hash}` to peers; a peer behind requests `GOSSIP_PULL since_idx`; entries are verified (chain continuity + signatures) then appended. A node that was down catches up automatically on restart — that IS chaos fault F1's resolution, no extra code.

### 7.3 Lifecycle (the Accelerator — deliverable 3)
`LOCAL` (analyzer drafted, on discovering node only) → guardrail ALLOW → broadcast `INSIGHT_ANNOUNCE` → `CANDIDATE` → each peer independently: guardrail check (again — trust nothing) + **replay verification** → `ATTEST` entries → when attestations from ≥2 distinct nodes with **matching replay result hashes** exist → `STATUS: VERIFIED` → applied by all nodes for matching scopes. Any peer replay that fails to reproduce → `STATUS: QUARANTINED` + reason.

### 7.4 Replay verification (the anti-hallucination core — defense Q1)
```python
def verify(insight) -> (bool, replay_hash):
    r_before = replay(insight.evidence["scenario"], params=CURRENT_DEFAULTS)
    r_after  = replay(insight.evidence["scenario"], params=merged(CURRENT_DEFAULTS, insight.claim))
    improved = (r_after.duration_ms <= r_before.duration_ms * 0.8      # ≥20% better, tolerance guard
                and not r_after.aborted
                and r_after.rounds <= r_before.rounds)
    return improved, sha256(canonical({"a":summary(r_after),"b":summary(r_before)}))
```
Quorum requires equal `replay_hash` across attesters — a fabricated-evidence insight fails here even with a valid signature (chaos fault F2d). Probation (cheap canary replacement): first 3 live applications of a VERIFIED insight are watched; if ≥2 of 3 breach SLO, node emits `STATUS: REVOKED` (+ its `derived_from` descendants) — rollback = fold log without it, config epoch decrements.

### 7.5 Application (loop closure + deliverable 5)
`node.active_params(task_ctx)`: fold VERIFIED insights whose `scope.context` exact-matches `task_ctx` subset → merge claims over defaults → `(params, warm_start, insight_ids, epoch)`. Sessions read config at start only (epoch semantics); the contract records `config_epoch` + `insight_ids` — auditability line for the defense. Scoped consistency: scope is part of the key, so "conflicting fixes valid in different contexts" have different keys and coexist (defense Q3); same-scope conflict → higher `claimed_improvement.duration_ms` wins, tie → newer version, tie → lower id hash (Phase 1 tie-break discipline, cite it).

## 8. Telemetry + task flow (P1 §8.1 hour 2.5–3; P3 §8.2 hour 0–1)

### 8.1 `metrics/telemetry.py`
JSONL spans + metrics, OTel-convention-shaped names (defense: "attribute naming aligned with OpenTelemetry GenAI/agent semantic conventions; SDK+collector is the production path"):
spans: `csp.negotiate` (attrs: session, task_idx, ctx, rounds, epoch, insight_ids, duration_ms, aborted), child spans per phase; metrics: `csp.message.latency_ms` (per envelope, from bus), `csp.contract.duration_ms`, `csp.contract.rounds`, `csp.abort.count`, `fabric.deny.count`, `fabric.insight.applied`.
**SLO table (hardcode):** `p95 message latency ≤ 50 ms`, `contract duration ≤ 5000 ms`, `abort rate ≤ 10% over window 5`. `SLOEvaluator.on_task_end()` checks windows → emits `Incident{breached_slo, window_stats, worst_spans[], task_ctx}` → analyzer. This is exactly the user-story: 10 ms is fine; 1 s per message trips `p95 ≤ 50ms` and surfaces WHERE (span tree) it went slow.

### 8.2 `loadgen/tasks.py`
Seeded RNG (`--seed 42` everywhere; rehearse with the same seed). 30 tasks, Poisson-ish inter-arrival 0.5–1.5 s (compress to 0.1–0.3 s via `--fast` for rehearsal). Eras: tasks 1–8 `link_quality=normal` (delay 5–10 ms); tasks 9–20 **lossy era** on N1↔N2 and N2↔N3 links (delay 400–1200 ms) → timeouts/retransmits → SLO breaches → THE incident; tasks 21–30 back to normal but include ≥4 tasks with `link_quality=lossy` context on N3 pairs → N3 reuses N1's insight (cross-node ratchet, deliverable 5). Baseline mode `--fabric off`: identical seed/eras, pipeline disabled → the comparison chart.

## 9. Analyzer (P3, hour 1–2.5)

### 9.1 `analyzer/rules.py` — PRIMARY, always on
```python
def analyze(incident) -> draft_insight|None:
    if incident.breached_slo == "message_latency" and incident.window_stats.p95 > 10*SLO:
        return Insight(scope={"context":{"link_quality": incident.task_ctx["link_quality"]}},
                       claim={"params":{"negotiate_timeout_ms":30000,"r_max":6,"eps":0.08},
                              "warm_start": last_successful_contract_agreed(incident.task_ctx)},
                       evidence=build_evidence(incident))   # incl. replayable scenario + before metrics
```
Rule table: latency-breach→timeout+fewer-rounds+warm-start; abort-spike→raise timeout; slow-but-ok→warm-start only. The analyzer runs `replay` locally BEFORE submitting (fills `metric_after`) — never submit unreproduced claims yourself.

### 9.2 `analyzer/gemini.py` — optional, flag `--analyzer gemini`, fallback to rules on ANY failure
`POST https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=$GEMINI_API_KEY`, `generationConfig: {"response_mime_type":"application/json"}`, 10 s timeout, ONE retry, then rules. Prompt: system text = "You are a network incident diagnostician. Output ONLY JSON matching this schema {hypothesis, cited_span_ids[], claim{params{...whitelist...}, use_warm_start:bool}}. Cite only span ids present in the input."; user text = incident JSON + worst spans + SLO table + whitelist bounds. **Grounding gate:** reject output if any `cited_span_ids` not in input, any claim key not whitelisted, or JSON invalid → fall back to rules (print `[analyzer] gemini output rejected: <reason> — using rules`, judges LOVE seeing the gate fire). Gemini output only fills the *draft*; evidence/replay/submission path identical to rules. Log every prompt+response to `out/gemini_log.jsonl` (Q5 discipline).

## 10. `chaos/inject.py` (P3, hour 2.5–3.25) — bonus deliverable
Runs as demo act 4, each fault printed with DETECT → BLOCK/REPAIR → INTEGRITY proof:
- **F1 node down:** `faults.node_down={"N3"}` for 10 s during propagation → N3 misses insight → restore → gossip catch-up → print three identical heads.
- **F2 poisoned updates (×4, one line each in a result table):** (a) unsigned/garbage-key insight → DENY INVALID_SIG; (b) `eps=0.9` → DENY BOUNDS_VIOLATION; (c) warm_start with `inspection_depth="none"` (attacks a security_baseline dim) → DENY POLICY_VIOLATION; (d) valid-signed insight with fabricated `metric_after` → passes guardrail → **fails replay on both peers** → QUARANTINED. Then revoke path: tombstone (d)'s source insights + descendants; show fabric still serves the good insight (prune ≠ reset).
- **F3 partition/heal:** partition {N1,N2}|{N3} for 8 s while an insight lands on the majority side → N3 diverges → heal → converged heads printed. Trade-off line ready: "N3 negotiated 2 tasks on stale config during the partition — cost: +2 rounds each; correctness: untouched. That's scoped eventual consistency, chosen deliberately."

## 11. `demo/run_demo.py` — the artifact judges watch (P3 + all, hour 3.25–4.5)
Single command: `python -m demo.run_demo --seed 42 [--fabric off] [--analyzer gemini] [--chaos]`. Narrated acts with banner prints:
**Act 1 (tasks 1–8):** normal ops — per task one line: `task 07 [normal] N1×N2 rounds=4 dur=612ms epoch=0 insights=[]`.
**Act 2 (tasks 9–12):** lossy era — visible timeouts, `p95 msg latency 812ms > SLO 50ms → INCIDENT inc-01`; analyzer draft; guardrail ALLOW; replay before/after numbers; `ATTEST N2 ✔ N3 ✔ (replay hashes match) → VERIFIED ins-4f9e21`.
**Act 3 (tasks 13–30):** ratchet — `task 14 [lossy] rounds=1 dur=980ms epoch=1 insights=[ins-4f9e21] (warm-start)`; later `task 24 N3×N2 [lossy] REUSED ins-4f9e21 — node N3 never saw incident inc-01` ← say this sentence out loud in the demo.
**Act 4:** `--chaos` faults F1–F3.
**Act 5:** `charts.py` writes `out/charts/`: (1) duration_ms per task, fabric-off vs on, same seed (headline ratchet chart); (2) rounds per task; (3) p95 message latency with era shading + incident marker; (4) guardrail outcome table PNG. Also `out/summary.md` table: contracts, aborts, insights verified/quarantined/denied, mean duration before/after ratchet.

## 12. Team plan — 3 people × 5 hours

Freeze §5.6 interfaces + §6.1 dataclass + envelope shape in `core/types.py` in the FIRST 15 minutes, together. After that nobody changes a signature without shouting.

| Hour | P1 (protocol) | P2 (fabric) | P3 (loop/demo) |
|---|---|---|---|
| 0–0.5 | types.py + crypto.py + bus.py | model.py + guardrail skeleton | loadgen + eras (mock ctx objects) |
| 0.5–1.5 | csp_mini: feasibility + utilities | guardrail complete + unit-tested vs F2a–c fixtures | rules analyzer + evidence builder (mock replay) |
| 1.5–2.5 | csp_mini: concession loop + timeouts + replay() | log.py chain + persistence + gossip | gemini.py + grounding gate (fallback tested by unplugging key) |
| 2.5–3.25 | telemetry + SLO evaluator wired into bus/engine | pipeline: candidate→replay→attest→verify (uses P1 replay) | chaos/inject.py |
| 3.25–4.25 | **INTEGRATION (all three, one machine):** nodes.py wiring → full run seed 42 → fix | ← | ← + run_demo acts |
| 4.25–4.75 | tests §2 green; fabric-off baseline run recorded | charts + summary from real run | demo narration script + freeze |
| 4.75–5 | tag release; NO commits after this | rehearse Act 2–3 once | rehearse chaos once |

**Claude Code usage:** each person opens their module set with this doc + Doc 2 in context; prompt pattern: "Implement `<file>` exactly per Doc 4 §<n>; interfaces in core/types.py are frozen; no new dependencies; deterministic under fixed seed." Commit small; integration owner is P1.

**Cut ladder if behind (drop top-first, never touch invariants §1):** 1) Gemini (rules-only, mention API path); 2) F3 partition (keep F1, F2); 3) charts 2–4 (keep headline chart 1); 4) probation/revoke path (keep quarantine); 5) two agent personas per node → one pair reused. If csp_mini itself is behind at hour 2.5: drop ordinal/categorical negotiation to fixed values, negotiate only latency_ms + sample_rate (the demo story survives fully).

## 13. Defense mapping (rehearse verbatim)
- **Innovation vs hallucination:** "A breakthrough is a claim with reproducible evidence. Insights must carry a replayable scenario; two independent nodes deterministically re-execute it and must produce matching results before quorum-signing. The LLM only drafts hypotheses behind a grounding gate — it has no write path and no accept authority. Watch fault F2d: a convincing fabricated claim with a valid signature dies at replay." 
- **Poisoning/drift:** "Free-form memory writes don't exist — insights are typed, signed, whitelisted, bounds-checked, and promoted through untrusted→verified tiers. Detection: guardrail (structure/policy), replay divergence (fabrication), probation (live regression). Isolation: quarantine status in the chain. Pruning: tombstone by provenance subtree via `derived_from` — memory is never reset, and the removal itself is an auditable signed event."
- **Consistency:** "Scoped eventual consistency: context is part of the insight key, so context-valid conflicting fixes aren't conflicts — they coexist under different keys. Same-scope conflicts resolve by the same deterministic tie-break discipline as our Phase 1 arbitration. We can afford eventual consistency because insights are advisory performance knowledge — safety lives in the priority lattice inside each fail-closed negotiation. During fault F3 you saw the cost: a few extra rounds on the partitioned node, zero incorrect contracts. Semantic locking would buy nothing here and cost availability."
- **Why no central orchestrator:** "Phase 1 proved two agents align without a coordinator; Phase 2 keeps that: verification is peer replay + quorum, propagation is gossip, the analyzer is a per-node advisor. There is no component whose compromise poisons the fabric silently."
