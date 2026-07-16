"""Optional LLM diagnostician -- Doc 4 §9.2, Doc 5 §2. Flag: `--analyzer gemini`.

The model drafts a HYPOTHESIS. That is the entire extent of its authority.

It has no write path to the fabric and no accept/reject power (Doc 4 §1,
invariant 2). What it returns is not trusted, not stored, and not propagated: it
is run through the grounding gate below, rebuilt as typed bounded fields, and
then handed to `rules.build_draft`, which replays it locally and drops it if our
own replay will not reproduce the improvement. After that it still faces every
peer's guardrail and two independent peer replays whose hashes must match.

Why the LLM is HERE and not in the negotiation loop (Doc 5 §0): `replay()` being
byte-identical across nodes IS the anti-hallucination gate. An LLM inside
negotiate() would put non-determinism inside the verification primitive itself
and collapse the whole argument. Here, being wrong is free -- a bad hypothesis
costs one replay and dies. Non-determinism is confined to the one place where it
cannot hurt.

Fails safe, always: no key, no network, a timeout, malformed JSON, an invented
span id, an invented knob -> print why and fall back to rules. Rehearse with
GEMINI_API_KEY unset; the gate firing on stage proves the containment.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from analyzer import rules
from core.registry import TUNABLE_BOUNDS
from metrics.telemetry import SLO_MSG_LATENCY_P95_MS

def _load_env() -> None:
    """Read `.env` (repo root or csp-phase2/) into os.environ if not already set.

    Ten lines instead of a python-dotenv dependency. The file is gitignored: the
    key belongs on the demo machine, never in the history of a repo that gets
    handed to judges. A real environment variable always wins over the file.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (os.path.join(here, "..", ".env"), os.path.join(here, "..", "..", ".env")):
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        except OSError:
            pass


_load_env()

# Doc 4 §9.2 named gemini-2.0-flash; we default to the `-latest` ALIAS instead.
# Two things bite a pinned model id here, both observed on this project's own keys:
#   * 404 "no longer available to new users" -- a pinned version can be LISTED by the
#     models endpoint and still refuse generateContent for a newer project. Listing
#     is not callability.
#   * 429 -- free-tier quota is per-project-PER-MODEL, so one model can be dead while
#     another answers fine.
# An alias resolves to a current model and survives both. Configurable rather than
# literal: the model id is deployment config, not a design decision. `GEMINI_MODEL`
# overrides it -- and if that 404s or 429s, the fallback to rules still holds.
#
# The default is pinned to 3.1-flash-lite rather than the `gemini-flash-latest`
# alias, for two MEASURED reasons on this project's free tier:
#   latency -- flash-latest answered this prompt in 15.6s, past TIMEOUT_S below.
#              A model slower than the timeout does not fail loudly; it silently
#              becomes a rules run wearing a gemini badge. 3.1-flash-lite: 1.0s.
#   quota   -- 500 RPD / 15 RPM, against 20 RPD for 2.5-flash / 3-flash /
#              3.5-flash. One demo run costs a call; 20/day does not survive a
#              rehearsal day plus the demo.
# An alias also silently repoints, which is the one thing you do not want between
# rehearsal and demo. A small model is safe here precisely because it only guesses
# a hypothesis: the grounding gate and our own replay decide whether it is true.
MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite")
ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
# Doc 4 §9.2 said 10 s. Measured: a real grounded call on gemini-flash-latest takes
# ~15 s, because the current flash models THINK before answering (454 thinking tokens
# on our prompt) -- the 10 s budget predates that and timed out every single call,
# silently demoting every run to rules. 30 s is sized to the model that exists.
TIMEOUT_S = 30.0
RETRIES = 1  # one retry, then rules. The demo never waits on a model.

SYSTEM = (
    "You are a network incident diagnostician. Output ONLY JSON matching this schema: "
    '{"hypothesis": string, "cited_span_ids": [string], '
    '"claim": {"params": {...}, "use_warm_start": boolean}}. '
    "Cite only span ids present in the input. Use only the tunable parameters listed, "
    "each within its stated bounds. Do not invent parameters or span ids."
)

LOG_PATH = os.path.join("out", "gemini_log.jsonl")


def _log(rec: dict) -> None:
    """Every prompt and raw response (Doc 4 §9.2 -- Q5 disclosure discipline)."""
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
    except OSError:
        pass


def _prompt(incident) -> str:
    return json.dumps({
        "incident": {
            "id": incident.id,
            "breached_slo": incident.breached_slo,
            "window_stats": incident.window_stats,
            "task_ctx": incident.task_ctx,
        },
        "worst_spans": incident.worst_spans,
        "slo_table": {"message_latency_p95_ms": SLO_MSG_LATENCY_P95_MS},
        "tunable_bounds": {k: list(v) for k, v in TUNABLE_BOUNDS.items()},
    }, sort_keys=True, default=str)


def _call(prompt: str) -> tuple[dict | None, str]:
    """POST to the API. Returns (parsed model JSON, note). Never raises.

    The note carries the REAL reason on failure. "no key / no response" for
    everything is useless at 3am before a demo: a 429 (free-tier quota, which is
    per-project-per-model -- try GEMINI_MODEL=gemini-2.0-flash) and a 403 (bad key)
    need completely different fixes, and the fallback hides both by design.
    """
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        return None, "GEMINI_API_KEY not set"
    body = json.dumps({
        "systemInstruction": {"parts": [{"text": SYSTEM}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"response_mime_type": "application/json"},
    }).encode()
    url = ENDPOINT.format(model=MODEL) + "?key=" + key

    note = "no response"
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(
                url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = json.loads(resp.read().decode())
            text = raw["candidates"][0]["content"]["parts"][0]["text"]
            out = json.loads(text)
            _log({"prompt": prompt, "response": text, "model": MODEL, "attempt": attempt})
            return out, ""
        except urllib.error.HTTPError as e:
            # Never let the key reach a log line or the terminal: the URL carries it.
            note = f"HTTP {e.code} from {MODEL}"
            if e.code == 429:
                note += " (free-tier quota exhausted -- try another GEMINI_MODEL)"
            elif e.code in (401, 403):
                note += " (key rejected)"
            _log({"prompt": prompt, "error": note, "attempt": attempt})
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            reason = getattr(e, "reason", e)
            timed_out = isinstance(e, TimeoutError) or isinstance(reason, TimeoutError)
            note = (f"timed out after {TIMEOUT_S:.0f}s on {MODEL}" if timed_out
                    else f"network: {type(e).__name__}")
            _log({"prompt": prompt, "error": note, "attempt": attempt})
            if timed_out:
                # Retrying a timeout just doubles the stall in front of an audience,
                # and rules answers instantly. The retry is for transient faults.
                break
        except (KeyError, IndexError, ValueError) as e:
            note = f"unparseable response: {type(e).__name__}"
            _log({"prompt": prompt, "error": note, "attempt": attempt})
    return None, note


def ground(out, incident, last_agreed: dict | None) -> tuple[dict | None, str, str]:
    """THE GATE. Model output -> a typed claim we are willing to test, or a refusal.

    Pure and offline: unit-testable without an API key, which is the only way to
    know it actually fires. Returns (claim, hypothesis, reason_if_rejected).
    """
    if not isinstance(out, dict):
        return None, "", "no response"
    for k in ("hypothesis", "cited_span_ids", "claim"):
        if k not in out:
            return None, "", f"missing key {k!r}"
    if not isinstance(out["claim"], dict):
        return None, "", "claim is not an object"

    # 1. It may not invent evidence. Every citation must exist in what we sent.
    known = {s["span_id"] for s in incident.worst_spans}
    cited = out["cited_span_ids"]
    if not isinstance(cited, list):
        return None, "", "cited_span_ids is not a list"
    invented = [c for c in cited if c not in known]
    if invented:
        return None, "", f"cited span ids not in input: {invented}"

    # 2. It may not invent knobs or ranges. The whitelist is the schema.
    params = out["claim"].get("params") or {}
    if not isinstance(params, dict):
        return None, "", "claim.params is not an object"
    clean: dict = {}
    for k, v in params.items():
        if k not in TUNABLE_BOUNDS:
            return None, "", f"param {k!r} is not a tunable"
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return None, "", f"param {k}={v!r} is not numeric"
        lo, hi = TUNABLE_BOUNDS[k]
        if not (lo <= v <= hi):
            return None, "", f"param {k}={v} outside [{lo}, {hi}]"
        clean[k] = v
    if not clean:
        return None, "", "no usable tunables in claim"

    claim: dict = {"params": clean}
    # The model's own words, kept for the narration -- as an annotation on a
    # verified claim, never as a reason to believe it. Truncated: it is prose from
    # an untrusted source landing in a signed record.
    hypothesis = ("gemini: " + str(out["hypothesis"]).replace("\n", " ").strip())[:300]

    # 3. It may not invent a settlement point. The model votes on WHETHER to warm
    #    start; the point itself comes from what we actually settled on before.
    #    A hallucinated warm start would be caught (policy floor, then replay) --
    #    but not permitting it beats catching it.
    if out["claim"].get("use_warm_start") and last_agreed:
        claim["warm_start"] = dict(last_agreed)
    return claim, hypothesis, ""


def propose_claim(incident, last_agreed: dict | None = None) -> tuple[dict | None, str, str]:
    """(claim, hypothesis, reason_if_rejected). Never raises."""
    out, note = _call(_prompt(incident))
    if out is None:
        return None, "", note
    return ground(out, incident, last_agreed)


def analyze(incident, last_agreed: dict | None = None, defaults: dict | None = None,
            log=None) -> dict | None:
    """Same signature as rules.analyze. Falls back to rules on ANY rejection."""
    claim, hypothesis, why = propose_claim(incident, last_agreed)
    if claim is None:
        if log:
            log(f"[analyzer] gemini output rejected: {why} -- using rules")
        return rules.analyze(incident, last_agreed, defaults)
    if log:
        log("[analyzer] gemini hypothesis grounded -- replaying it before submitting")
    # Identical path from here: evidence, self-replay, and drop-if-unreproduced.
    draft = rules.build_draft(incident, claim, defaults, "gemini", hypothesis=hypothesis)
    if draft is not None:
        return draft

    # A grounded claim that our own replay will not reproduce is still a rejection,
    # and this function promises to fall back to rules on ANY rejection. Returning
    # None here instead means the node draws a blank on this incident and the
    # ratchet only fires if a LATER incident happens to arrive -- observed live:
    # gemini's task-13 claim failed self-replay, and the run was rescued purely by
    # task 14 breaching again. On the last incident of an era there is no rescue,
    # and the demo silently has no insight at all. The rule table's hypothesis is
    # right there and costs nothing; the discard stays visible in the log either way.
    if log:
        log("[analyzer] gemini claim did not reproduce on our own replay "
            "-- discarded, using rules")
    return rules.analyze(incident, last_agreed, defaults)
