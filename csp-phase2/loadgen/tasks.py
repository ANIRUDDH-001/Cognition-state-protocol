"""Dynamic enterprise task flow -- deliverable 1 (Doc 4 §8.2).

Seeded, so `--seed 42` is the same 30 incidents every rehearsal and every demo.
Conditions change underneath the agents in eras; the agents are never told an era
boundary happened, they only feel it as latency, and the SLO evaluator is what
notices.

Era plan (the whole demo narrative lives in this table):
    1-8    normal   N1 x N2   baseline: this is what healthy looks like
    9-20   LOSSY    N1 x N2   the incident; ratchet becomes visible from ~13
    21-24  normal   N1 x N2   the insight is scoped to lossy, so it correctly
                              does NOT apply here -- scoped consistency, visible
    25-30  LOSSY    N3 x N2   N3 hits the same conditions having never seen the
                              incident. It reuses N1's insight. That is deliverable 5.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from core.bus import LOSSY_DELAY_MS, NORMAL_DELAY_MS


@dataclass
class Task:
    idx: int
    era: str
    pair: tuple  # (node_a, node_b)
    personas: tuple  # (persona_a, persona_b)
    ctx: dict  # link_quality, workload, pair, seed
    inter_arrival_ms: float

    @property
    def link_quality(self) -> str:
        return self.ctx["link_quality"]


ERAS = [
    # (first_idx, last_idx, era_name, link_quality, pair)
    (1, 8, "act1-normal", "normal", ("N1", "N2")),
    (9, 20, "act2-lossy", "lossy", ("N1", "N2")),
    (21, 24, "act3-normal", "normal", ("N1", "N2")),
    (25, 30, "act3-crossnode", "lossy", ("N3", "N2")),
]


def era_for(idx: int):
    for lo, hi, name, lq, pair in ERAS:
        if lo <= idx <= hi:
            return name, lq, pair
    raise ValueError(idx)


def delay_for(link_quality: str) -> tuple:
    return LOSSY_DELAY_MS if link_quality == "lossy" else NORMAL_DELAY_MS


def generate(seed: int = 42, n: int = 30, fast: bool = False) -> list[Task]:
    rng = random.Random(seed)
    out = []
    for idx in range(1, n + 1):
        era, lq, pair = era_for(idx)
        # Poisson-ish arrivals. Virtual time, so --fast is only about how long a
        # human watches the narration, never about what the numbers say.
        gap = rng.uniform(0.1, 0.3) if fast else rng.uniform(0.5, 1.5)
        out.append(
            Task(
                idx=idx,
                era=era,
                pair=pair,
                personas=("throughput", "security"),
                ctx={
                    "link_quality": lq,
                    "workload": "bursty" if rng.random() < 0.3 else "steady",
                    "pair": list(pair),
                    "seed": seed * 1000 + idx,
                },
                inter_arrival_ms=gap * 1000.0,
            )
        )
    return out
