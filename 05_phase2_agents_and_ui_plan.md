# Doc 5 — Real Agents & Live UI (60-minute build)
**Project:** Code with Cisco · Problem Statement 1 · Phase 2 — extending the verified prototype
**Constraint:** ~60 minutes to code freeze · live judged demo · Docs 1–4 are the source of truth for everything already built
**Status of the base:** Doc 4 §1's five deliverables + chaos bonus are built, tested (77 tests) and reproducible under `--seed 42`. This doc only adds what Doc 4 deliberately cut: the LLM analyzer (§9.2, cut-ladder item 1) and a visual surface.

---

## 0. The hinge — read this before writing any code

`replay()` being **byte-identical across nodes** is not a nice-to-have. It *is* the anti-hallucination gate (Doc 4 §7.4) and the whole answer to defence question 1. Two things we are now adding are natively non-deterministic: an LLM, and a real network.

So the system splits into two planes, and the split is the design:

| Plane | What runs there | Determinism |
|---|---|---|
| **Live plane** | task flow, negotiation, gossip, the UI | may become real/async/slow |
| **Verification plane** | `replay()` → guardrail → quorum | **must stay pure, in-proc, virtual-clock** |

`core/csp_mini.replay()` already builds its *own* `Bus`, `Clock`, `FaultState` and RNG from the recorded scenario. It touches nothing global. **That is what makes all of this safe** — the live plane can get as messy as we like and verification stays a pure function.

**Invariant added to Doc 4 §1 (never cut):**
> 6. Non-determinism is confined to *hypothesis generation*. Nothing non-deterministic may sit between an insight and its verification.

This is exactly why the answer to "real agents" below is *analyzer, not negotiator*: an LLM drafting a hypothesis is verified by deterministic replay before it can matter. An LLM inside `negotiate()` would put non-determinism **inside the verification primitive** and collapse the Q1 defence. Say that out loud if a judge asks why the LLM isn't negotiating — it is a stronger answer than doing it.

## 1. Scope lock

**BUILD (60 min):**
| # | Item | Where | Minutes |
|---|---|---|---|
| A | LLM analyzer + grounding gate (Doc 4 §9.2, previously cut) | `analyzer/gemini.py` | 20 |
| B | Live web UI + chaos buttons | `ui/server.py`, `ui/static/index.html` | 30 |
| C | Freeze: rehearse both, `requirements.txt` | — | 10 |

**STRETCH — only if A+B are green with time left (they will not be; this is honest):**
| D | Websocket transport, 3 real OS processes | `core/ws_bus.py`, `run_node.py` | 90+ |

**CUT, and say "production path" if asked:** multi-process demo (§5), auth on the UI, persistence beyond JSONL, chart libraries.

## 2. Workstream A — the LLM analyzer (20 min)

Doc 4 §9.2 already specifies this precisely. It is the *only* planned component never built, so this is finishing the plan, not extending it.

### 2.1 What must not change
`analyzer/rules.py::analyze()` does three things today, and only the **first** is LLM-replaceable:
1. `_rule(incident, last_agreed) -> claim | None` ← the hypothesis. **This is the LLM's job.**
2. build evidence (replayable scenario + before/after metrics)
3. **self-verify**: run `verify()` locally and return `None` if our own replay refuses the claim

Step 3 is the discipline line in the defence — *"we never ask the network to check a claim we have not checked ourselves."* Gemini output goes through steps 2 and 3 **unchanged**. It is not a parallel path; it is a different way to produce the same `claim` dict.

### 2.2 The refactor (do this first, it is 5 minutes)
In `analyzer/rules.py`, split the post-claim half out so both analyzers share it:

```python
def build_draft(incident, claim, defaults=None, analyzer="rules") -> dict | None:
    """claim -> evidence -> SELF-VERIFY -> draft. Shared by every analyzer."""
    # (body of today's analyze() from `stub = {...}` onward, with
    #  "analyzer": analyzer instead of the hardcoded "rules")

def analyze(incident, last_agreed=None, defaults=None) -> dict | None:
    claim = _rule(incident, last_agreed)
    return build_draft(incident, claim, defaults, "rules") if claim else None
```
Nothing else moves. `provenance.analyzer` is already part of `signing_body()`, so a gemini-drafted insight gets a different id and is attributable in the chain for free — no work needed.

### 2.3 `analyzer/gemini.py`
```python
def propose_claim(incident, last_agreed) -> tuple[dict | None, str]:
    """Returns (claim, note). Never raises. Never returns an ungrounded claim."""
```
- `POST https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent?key=$GEMINI_API_KEY`
  with `generationConfig: {"response_mime_type": "application/json"}`. `MODEL` is a config string, not a literal scattered through the code.
- **10 s timeout, ONE retry, then rules.** No key / no network / bad JSON → rules, instantly and visibly.
- System text: *"You are a network incident diagnostician. Output ONLY JSON matching `{hypothesis, cited_span_ids[], claim{params{...}, use_warm_start:bool}}`. Cite only span ids present in the input."*
- User text: incident JSON + worst spans + the SLO table + `TUNABLE_BOUNDS` from `core/registry.py`.

**Grounding gate — reject the output if any of:**
| Check | Why |
|---|---|
| JSON invalid / missing keys | it isn't a claim |
| any `cited_span_ids` ∉ input span ids | it invented evidence |
| any `claim.params` key ∉ `TUNABLE_BOUNDS` | it invented a knob |
| any value outside its bound | it invented a range |

On rejection print `[analyzer] gemini output rejected: <reason> — using rules` and fall back. **Rehearse a run with the key unset**: the gate firing on stage is worth more than the LLM succeeding, because it *shows* the containment rather than asserting it.

`use_warm_start: bool` — the LLM says *whether* to warm-start; the **warm-start point itself comes from `node.last_agreed`, never from the model.** A hallucinated settlement point is a class of bug we simply do not permit to exist. (It would be caught — guardrail policy floor + replay — but not permitting it is better than catching it.)

Log every prompt + raw response to `out/gemini_log.jsonl` (Doc 4 §9.2, Q5 discipline).

### 2.4 Wiring
- `Mesh.__init__(..., analyzer: str = "rules")`; `Mesh.draft_and_submit` picks the claim source, then calls the shared `build_draft`.
- `demo/run_demo.py`: `--analyzer {rules,gemini}`, default **rules**.
- `--analyzer gemini` makes drafting non-deterministic, so `test_the_demo_is_reproducible` holds only for the default. That is correct, not a regression: reproducibility is a property of the *verification* plane. Note it in the test file so nobody "fixes" it later.

**Defence line:** *"The LLM has no write path and no accept authority. It drafts a hypothesis behind a grounding gate; the claim is then rebuilt as typed, bounded, whitelisted fields, replayed by the drafting node, replayed independently by two peers, and only then does it exist. Its non-determinism is confined to the one place where being wrong is free."*

## 3. Workstream B — the live UI (30 min)

### 3.1 The seam — do not re-plumb the demo
`metrics/telemetry.py::Telemetry._write()` is already the single funnel every observable event passes through: `csp.negotiate` spans, `csp.message.latency_ms`, `csp.contract.*`, `slo.breach`, `fabric.deny.count`, `fabric.revoke`. **One callback there feeds the entire UI.**

```python
class Telemetry:
    def __init__(self, out_path=None, clock=None, on_record=None):
        self.on_record = on_record
    def _write(self, rec):
        ...
        if self.on_record:
            self.on_record(rec)      # never let a UI subscriber break the run
```
That is the only change to existing core code. Two lines. Everything else is additive — which is why this is a 30-minute job and not a rewrite.

Fabric state is not a stream, it is a snapshot: push `mesh.fabric_summary()` + `mesh.digests()` + `mesh.heads()` after each task.

### 3.2 `ui/server.py` (FastAPI)
| Route | Purpose |
|---|---|
| `GET /` | the single page |
| `WS /stream` | every telemetry record + fabric snapshots, pushed live |
| `POST /run` | `{seed, fabric: on\|off, analyzer, pace}` → runs the demo in a worker thread |
| `POST /chaos/{f1\|f2\|f3}` | fires `chaos.inject.*` against the **live** mesh |
| `GET /state` | full snapshot, so a late-joining browser catches up |

The demo loop is synchronous and CPU-cheap (time is virtual): run it in a `threading.Thread`, hand records to the event loop with `asyncio.run_coroutine_threadsafe` onto a broadcast queue. Use the existing `--pace` to make it watchable — **pacing is presentation, never physics**: the numbers come from the virtual clock and do not change.

### 3.3 The page (one HTML file, no CDN — assume the venue wifi is hostile)
Vanilla JS, CSS-grid, bars drawn as `<div>`s. No chart library.

```
┌────────────────────────────────────────────────────────────┐
│ seed 42 · fabric ON · analyzer rules · epoch 1   [F1][F2][F3]│
├───────────────────────────┬────────────────────────────────┤
│ TASK STREAM (live rows)   │ N1 │ N2 │ N3   ← fabric replicas │
│ 14 [lossy] N1xN2 r=1 ...  │ chain idx / digest / insights   │
│    warm-start ins-35400c  │ status badges, colour-coded     │
├───────────────────────────┼────────────────────────────────┤
│ INSIGHT LIFECYCLE         │ GUARDRAIL DENIALS               │
│ ANALYZER → GUARDRAIL ✔    │ a INVALID_SIG      N3           │
│ → REPLAY N2 ✔ N3 ✔        │ b BOUNDS_VIOLATION N3           │
│   (hashes match) VERIFIED │ c POLICY_VIOLATION N3           │
├───────────────────────────┴────────────────────────────────┤
│ ROUNDS per task: baseline ▁▄▄▄▄▄  fabric ▁▄▄▁▁▁  ← the ratchet│
└────────────────────────────────────────────────────────────┘
```

**Priority order if the clock beats us — build strictly top-down:**
1. task stream + rounds bars (this *is* the ratchet; nothing else matters as much)
2. three node columns with converging digests
3. insight lifecycle panel
4. chaos buttons
5. guardrail table

**The two money moments to design for:** (a) rounds collapsing 5→1 mid-stream while the era stays lossy; (b) a judge pressing **F2** and watching four poisoned updates die at four different layers. Make those two legible from the back of the room; everything else is garnish.

### 3.4 Deps
Add `requirements.txt` — currently the deps live only in prose:
```
cryptography
matplotlib
pytest
fastapi
uvicorn[standard]
requests        # gemini only
```
Note for whoever runs this: this repo needs **Python 3.11+** per Doc 2 §1; a 3.10 box works today but is not what we target. Use a venv — the deps are not system-wide.

## 4. Sequencing (60 minutes, 3 people)

| Min | P1 (protocol) | P2 (fabric/agents) | P3 (UI) |
|---|---|---|---|
| 0–5 | **together:** freeze `on_record` + `propose_claim` signatures. Nobody changes them after. | ← | ← |
| 5–25 | `Telemetry.on_record`; `requirements.txt` | `rules.build_draft` refactor → `gemini.py` + grounding gate | `server.py` skeleton + `/stream` + task stream panel |
| 25–45 | help UI; keep `pytest -q` green | wire `--analyzer`; rehearse with key **unset** | node columns, lifecycle, chaos buttons |
| 45–55 | **integration on one machine**, seed 42, both modes | ← | ← |
| 55–60 | tag; **no commits after this** | rehearse Act 2–3 | rehearse a judge pressing F2 |

**Cut ladder (drop top-first, never touch invariants):** 1) guardrail table → 2) chaos buttons (fire them from the CLI in a second window) → 3) lifecycle panel → 4) gemini (rules-only; the API path is documented and defensible) → 5) UI entirely (the terminal demo already works and is already rehearsed).

**The floor:** `python -m demo.run_demo --seed 42 --chaos --charts` is green, tested, and reproducible **right now**. Everything in this doc is upside. If minute 55 arrives and the UI is half-built, ship the terminal demo and say the UI is a viewer over the same JSONL — because it is.

## 5. Stretch — websocket + 3 real processes (NOT in the hour)

Agreed as a stretch goal, so here is the honest map. `core/bus.py` is already the pluggable L0 adapter Doc 1 §3 describes; a `WsBus` implements the same `send`/`recv`/`register` shape and nothing above it changes. **Three things bite, and they are why this is not a 60-minute job:**

1. **The virtual clock dies.** Durations become wall-clock, so today's `9311 ms → 7023 ms` headline and the whole SLO table (`p95 ≤ 50 ms`, `contract ≤ 5000 ms`) need retuning against real time. The measured ratchet stays real; the *numbers on the rehearsed slide* do not survive.
2. **`replay()` must stay in-proc — and already does.** It builds its own `Bus`/`Clock`/`FaultState`. Do not "helpfully" make it use the live transport: that is the one change that would break the Q1 defence. This is the single most important line in this section.
3. **A latent bug surfaces the moment we split.** `Mesh.run_task` calls `na.active(task_ctx)` — **only node A's fabric replica** — and passes one `warm_start` into a `negotiate()` that configures *both* agents. In-proc that is invisible. Split into processes and each side reads its own replica and they can disagree. The fix is small and the property is good: a warm start is only an *opening aspiration*, never a constraint, so disagreement costs **rounds, not correctness** (Doc 4 §1, invariant 4) — which is a demo beat, not a defect. Fix it by having each agent read its own replica and open where its own fabric says.

**Defence line if we don't build it:** *"Phase 1 defined transport as a pluggable L0 adapter — websocket, tcp, or in-proc queue. We demo on the in-proc adapter because it is deterministic and fault-injectable; the envelopes, signatures, and fault semantics are identical on any adapter, and verification is deliberately in-proc no matter what the live plane runs on."* That is Doc 1 §3/L0 verbatim, and it is a design position, not an excuse.

## 6. Defence deltas (rehearse these two)

- **"Is there a real AI in this?"** — *"Yes, and deliberately in one place. Gemini drafts incident hypotheses behind a grounding gate that rejects invented span ids and non-whitelisted knobs. It has no write path and no accept authority. Everything it drafts is rebuilt as typed bounded fields, replayed by us, then independently replayed by two peers who must reproduce our exact numbers. We chose not to put it in the negotiation loop, because that would put non-determinism inside the verification primitive that the whole anti-hallucination argument rests on."*
- **"Is the UI the system?"** — *"No. The UI is a subscriber on the telemetry stream — the same JSONL the charts and the summary are built from. Pull it out and the fabric behaves identically. It renders the system; it is not in the trust path."*
