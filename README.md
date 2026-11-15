# Cognition Fabric

Cognition Fabric is a Python simulation of three autonomous nodes negotiating under competing throughput and security constraints. It lets developers study how agents can reuse a verified settlement when similar network conditions recur.

## How it works

- **Negotiate.** Agents exchange proposals and look for a settlement that satisfies the hard constraints. The transport runs in process on a virtual clock, so experiments can be replayed deterministically.
- **Verify.** An analyzer drafts an insight from a failed or slow negotiation. The guardrail checks its structure and allowed scope. Two nodes independently replay the evidence and compare hashes before the insight becomes eligible for reuse.
- **Share.** Nodes gossip signed, content-addressed entries. They compare a digest of the entry set to check convergence. The individual hash chains retain each node’s own receipt order.
- **Reuse.** Nodes use verified insights as a starting point for negotiations with matching conditions. Fault injection exercises node loss, poisoned insights, and partitions.

| Component | Location |
| --- | --- |
| Transport, constraints, signatures | [core](csp-phase2/core/) |
| Signed log and gossip | [fabric](csp-phase2/fabric/) |
| Insight discovery, replay, and guardrails | [insights](csp-phase2/insights/), [guardrail](csp-phase2/guardrail/) |
| Scenarios and fault injection | [loadgen](csp-phase2/loadgen/), [chaos](csp-phase2/chaos/) |
| Terminal scenario and browser UI | [demo](csp-phase2/demo/), [ui](csp-phase2/ui/) |

## Run locally

Use Python 3.11 or newer. Create a virtual environment and activate it for your shell.

```bash
python -m venv .venv
# POSIX: source .venv/bin/activate
# PowerShell: .\.venv\Scripts\Activate.ps1
python -m pip install -r csp-phase2/requirements.txt
cd csp-phase2

python -m demo.run_handshake --seed 42
python -m demo.run_demo --seed 42 --chaos --charts
python -m demo.run_demo --seed 42 --fabric off --out out/baseline
python -m pytest -q
```

The simulator writes summaries, telemetry, and per-node logs to `out/` by default. Use `--out` to keep runs separate. The baseline uses the same seed with the insight pipeline disabled.

For the browser interface, run `python -m ui.server` from `csp-phase2/` and open [localhost:8000](http://127.0.0.1:8000). Start a 30-task run to inspect negotiations, replay votes, and node digests. The UI streams updates over WebSockets.

## Configuration and limits

The default rules-based analyzer runs offline. To try Gemini suggestions, set `GEMINI_API_KEY` in the environment and pass `--analyzer gemini`. Suggested insights go through the same checks and replay process.

This is an in-process prototype with a fixed three-node topology and simulated network conditions. Timing in the reports comes from the virtual clock. The project is intended for protocol experiments and deterministic fault scenarios.
