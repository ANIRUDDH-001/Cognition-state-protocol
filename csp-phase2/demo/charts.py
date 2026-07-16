"""Charts from the telemetry JSONL (Doc 4 §11, Act 5).

Reads what the run actually emitted -- nothing here recomputes or re-simulates.
If a chart and the terminal disagree, the JSONL is the arbiter.
"""
from __future__ import annotations

import json
import os

import matplotlib

matplotlib.use("Agg")  # headless: never try to open a window mid-demo
import matplotlib.pyplot as plt  # noqa: E402

from loadgen.tasks import ERAS  # noqa: E402
from metrics.telemetry import SLO_CONTRACT_DURATION_MS, SLO_MSG_LATENCY_P95_MS, p95  # noqa: E402

ON, OFF, INK, WARN = "#1f77b4", "#aaaaaa", "#333333", "#d62728"


def load(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def spans(recs: list) -> list:
    out = [r for r in recs if r.get("kind") == "span" and r["name"] == "csp.negotiate"]
    return sorted(out, key=lambda r: r["attrs"]["task_idx"])


def _era_shading(ax) -> None:
    for lo, hi, name, lq, _pair in ERAS:
        if lq == "lossy":
            ax.axvspan(lo - 0.5, hi + 0.5, color=WARN, alpha=0.07, zorder=0)
            ax.text((lo + hi) / 2, ax.get_ylim()[1] * 0.97, f"{lq} era",
                    ha="center", va="top", fontsize=7, color=WARN)


def _finish(fig, ax, title, xlabel, ylabel, path) -> str:
    ax.set_title(title, fontsize=11, color=INK)
    ax.set_xlabel(xlabel, fontsize=9)
    ax.set_ylabel(ylabel, fontsize=9)
    ax.grid(alpha=0.25, linewidth=0.5)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def chart_duration(on: list, off: list, path: str) -> str:
    fig, ax = plt.subplots(figsize=(9, 4))
    for recs, color, label in ((off, OFF, "fabric OFF (baseline)"), (on, ON, "fabric ON")):
        if not recs:
            continue
        x = [r["attrs"]["task_idx"] for r in recs]
        y = [r["attrs"]["duration_ms"] for r in recs]
        ax.plot(x, y, marker="o", ms=3.5, lw=1.5, color=color, label=label,
                zorder=3 if color == ON else 2)
        ab = [(r["attrs"]["task_idx"], r["attrs"]["duration_ms"]) for r in recs
              if r["attrs"].get("aborted")]
        if ab:
            ax.scatter(*zip(*ab), marker="x", s=55, color=color, zorder=4,
                       label=f"{label.split(' (')[0]} timed out")
    ax.axhline(SLO_CONTRACT_DURATION_MS, ls="--", lw=1, color=WARN,
               label=f"SLO {SLO_CONTRACT_DURATION_MS:.0f}ms")
    _era_shading(ax)
    ax.legend(fontsize=7, framealpha=0.9)
    return _finish(fig, ax, "Contract duration per task -- same seed, same eras",
                   "task", "duration (ms, virtual)", path)


def chart_rounds(on: list, off: list, path: str) -> str:
    fig, ax = plt.subplots(figsize=(9, 3.2))
    for recs, color, label in ((off, OFF, "fabric OFF"), (on, ON, "fabric ON")):
        if recs:
            ax.plot([r["attrs"]["task_idx"] for r in recs],
                    [r["attrs"]["rounds"] for r in recs],
                    marker="o", ms=3.5, lw=1.5, color=color, label=label)
    warm = [r["attrs"]["task_idx"] for r in on if r["attrs"].get("warm_started")]
    if warm:
        ax.axvline(min(warm), ls=":", lw=1.2, color="#2ca02c")
        ax.text(min(warm) + 0.2, ax.get_ylim()[1] * 0.85, "insight VERIFIED\n-> warm start",
                fontsize=7, color="#2ca02c")
    _era_shading(ax)
    ax.legend(fontsize=7)
    return _finish(fig, ax, "Negotiation rounds per task -- what the fabric actually removes",
                   "task", "rounds", path)


def chart_latency(on: list, path: str) -> str:
    by_task: dict = {}
    for r in on:
        if r.get("kind") != "metric" or r["name"] != "csp.message.latency_ms":
            continue
        sess = (r["attrs"] or {}).get("session") or ""
        if not sess.startswith("t"):
            continue
        try:
            idx = int(sess[1:3])
        except ValueError:
            continue
        by_task.setdefault(idx, []).append(r["value"])

    if not by_task:
        return ""
    x = sorted(by_task)
    y = [p95(by_task[i]) for i in x]
    fig, ax = plt.subplots(figsize=(9, 3.2))
    ax.plot(x, y, marker="o", ms=3.5, lw=1.5, color=ON, label="p95 message latency")
    ax.axhline(SLO_MSG_LATENCY_P95_MS, ls="--", lw=1, color=WARN,
               label=f"SLO {SLO_MSG_LATENCY_P95_MS:.0f}ms")
    ax.set_yscale("log")
    _era_shading(ax)
    ax.legend(fontsize=7)
    ax.text(0.99, 0.04, "the link stays slow all era: an insight cannot fix the\n"
                        "network, only how many times we cross it",
            transform=ax.transAxes, ha="right", fontsize=6.5, color=INK, alpha=0.75)
    return _finish(fig, ax, "p95 message latency -- the signal the SLO evaluator fires on",
                   "task", "ms (log scale)", path)


def chart_guardrail(chaos_reports: list, path: str) -> str:
    rows = []
    for rep in chaos_reports or []:
        rows.extend(rep.get("rows", []))
    if not rows:
        return ""
    fig, ax = plt.subplots(figsize=(9, 0.5 * len(rows) + 1.5))
    ax.axis("off")
    table = ax.table(
        cellText=[[r["tag"], r["desc"], r["expected"], r["stage"], r["status"]] for r in rows],
        colLabels=["#", "poisoned update", "expected defence", "caught at", "outcome"],
        cellLoc="left", loc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(7.5)
    table.scale(1, 1.5)
    for i, r in enumerate(rows, start=1):
        table[i, 4].set_facecolor("#d4edda" if r["blocked"] else "#f8d7da")
    for j in range(5):
        table[0, j].set_facecolor("#eeeeee")
    ax.set_title("Guardrail + replay outcomes -- every poisoned update, and what stopped it",
                 fontsize=11, color=INK, pad=14)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def render(tel_on_path: str, tel_off_path: str, out_dir: str, summary: dict,
           chaos_reports: list | None = None) -> list:
    os.makedirs(out_dir, exist_ok=True)
    recs_on, recs_off = load(tel_on_path), load(tel_off_path)
    s_on, s_off = spans(recs_on), spans(recs_off)

    made = [
        chart_duration(s_on, s_off, os.path.join(out_dir, "1_duration.png")),
        chart_rounds(s_on, s_off, os.path.join(out_dir, "2_rounds.png")),
        chart_latency(recs_on, os.path.join(out_dir, "3_latency_p95.png")),
        chart_guardrail(chaos_reports, os.path.join(out_dir, "4_guardrail.png")),
    ]
    return [m for m in made if m]
