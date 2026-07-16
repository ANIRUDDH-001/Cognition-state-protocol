"""netops dimension registry (Doc 2 §3.2) + tunable-parameter bounds (Doc 4 §6.2).

The engine understands nothing about "networking" -- it only switches on
`type`. Swapping this file for triage.json is the generality proof (Doc 2 §3.3);
no negotiation code changes.
"""
from __future__ import annotations

from .crypto import canonical, sha256_hex

NS = "netops"

DIMENSIONS = [
    {
        "id": "netops/latency_ms",
        "type": "continuous",
        "domain": {"min": 1.0, "max": 100.0, "step": 0.5},
        "unit": "ms",
        "quantization": {"buckets": 5},
        "default_class": "operational",
        "description": "end-to-end added latency budget",
    },
    {
        "id": "netops/throughput_mbps",
        "type": "continuous",
        "domain": {"min": 100.0, "max": 10000.0},
        "unit": "mbps",
        "quantization": {"buckets": 5},
        "default_class": "operational",
        "description": "sustained throughput floor",
    },
    {
        "id": "netops/inspection_depth",
        "type": "ordinal",
        "domain": {"levels": ["none", "header", "selective_deep", "full_deep"]},
        "default_class": "security_baseline",
        "description": "traffic inspection level",
    },
    {
        "id": "netops/sample_rate",
        "type": "continuous",
        "domain": {"min": 0.0, "max": 1.0, "step": 0.05},
        "quantization": {"buckets": 5},
        "default_class": "operational",
        "description": "fraction of flows deep-inspected",
    },
    {
        "id": "netops/tls_version",
        "type": "categorical",
        "domain": {"values": ["1.2", "1.3"]},
        "default_class": "regulatory",
        "description": "permitted TLS versions",
    },
    {
        "id": "netops/log_export",
        "type": "boolean",
        "domain": {},
        "default_class": "security_baseline",
        "description": "export flow logs to SIEM",
    },
]

REGISTRY = {"ns": NS, "ver": "1.0.0", "dimensions": DIMENSIONS}
REGISTRY_HASH = sha256_hex(canonical(REGISTRY))
DIM = {d["id"]: d for d in DIMENSIONS}
DIM_IDS = [d["id"] for d in DIMENSIONS]

# Ascending relaxation order. The top two are NEVER relaxed (Doc 2 §8).
CLASS_ORDER = ["preference", "operational", "security_baseline", "safety", "regulatory"]
NEVER_RELAX = {"safety", "regulatory"}


def class_rank(cls: str) -> int:
    return CLASS_ORDER.index(cls)


def levels(dim_id: str) -> list[str]:
    return DIM[dim_id]["domain"]["levels"]


def level_index(dim_id: str, value: str) -> int:
    return levels(dim_id).index(value)


# --- Domain physics -----------------------------------------------------------
# Without a coupling model the two personas are not actually in conflict: the
# throughput agent is indifferent to inspection, so every dimension would settle
# at its owner's optimum in one round and there would be nothing to negotiate.
# Deep inspection costs latency and throughput -- that cost IS the conflict.
# Both agents evaluate this identically (it is registry-declared, not private),
# so determinism of the shared feasibility check is preserved.

# Per-flow inspection cost in ms. full_deep is 20, not 30, and the difference
# matters: at 30 the throughput agent's 12 ms budget admits exactly ONE feasible
# sample_rate under full_deep, so the security agent has no intermediate move --
# it can only hold its optimum or collapse to selective_deep, and the transcript
# shows it repeating an identical offer until the other side caves. At 20 it can
# trade coverage away gradually, which is what a negotiation is supposed to look like.
INSPECTION_COST_MS = {"none": 0.0, "header": 1.0, "selective_deep": 12.0, "full_deep": 20.0}
BASE_LATENCY_MS = 2.0
THROUGHPUT_CEILING_MBPS = 10000.0
THROUGHPUT_COST_PER_MS = 200.0


def inspection_load(point: dict) -> float:
    """Inspection work per flow = per-flow cost x fraction of flows inspected."""
    depth = point["netops/inspection_depth"]
    return INSPECTION_COST_MS[depth] * float(point["netops/sample_rate"])


def min_latency_ms(point: dict) -> float:
    return BASE_LATENCY_MS + inspection_load(point)


def max_throughput_mbps(point: dict) -> float:
    return THROUGHPUT_CEILING_MBPS - THROUGHPUT_COST_PER_MS * inspection_load(point)


def coupling_ok(point: dict) -> bool:
    """Physical realizability of a candidate settlement point."""
    return (
        float(point["netops/latency_ms"]) >= min_latency_ms(point) - 1e-9
        and float(point["netops/throughput_mbps"]) <= max_throughput_mbps(point) + 1e-9
    )


# --- Tunables that an insight is allowed to touch (Doc 4 §6.2) ----------------
# Absence is the mechanism: there is no key here for guardrail config, crypto
# params, or constraint classes, so no insight can express a change to them.
TUNABLE_BOUNDS = {
    "eps": (0.01, 0.2),
    "r_max": (2, 12),
    "negotiate_timeout_ms": (1000, 60000),
}

DEFAULT_PARAMS = {
    "eps": 0.05,
    "delta": 0.01,
    "r_max": 8,
    "negotiate_timeout_ms": 10000,
    "msg_wait_ms": 3000,
    "grid_k": 9,
}

# Hard floor on what any settlement may look like, regardless of fabric state.
# Mirrors the standard personas' safety/regulatory + security_baseline constraints.
POLICY_FLOOR = {
    "netops/tls_version": ["1.3"],
    "netops/log_export": [True],
    "netops/inspection_depth_min": "selective_deep",
}
