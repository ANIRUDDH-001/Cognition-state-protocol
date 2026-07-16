"""Compressed CSP negotiation engine (Doc 4 §5).

Preserved from Doc 2: typed dimensions, per-type feasibility intersection (§9.1),
deterministic relaxation order that never touches safety/regulatory (§9.2),
competence-weighted utilities (§9.3), bounded concession (§9.4), signed envelopes
over canonical JSON (§4, §11), transcript hash folded into the contract (§7).

Simplifications, owned deliberately (Doc 4 §5):
  * No HELLO/ontology negotiation -- both nodes carry the identical registry in
    this demo. Shared-dim negotiation is a Phase 1 design artifact.
  * No commitments / progressive disclosure tiers. Disclosed utility == true
    utility here, so both sides reconstruct each other exactly and every
    decision is deterministic.
  * At R_max without ACCEPT we settle at the per-dimension midpoint of the
    feasible region instead of running competence-weighted Nash arbitration.
    Deterministic, bounded, tie-break-free. Concession settles before the cap in
    every demo scenario anyway -- the cap is a guarantee, not a code path we lean on.

Concession model: time-dependent (Faratin-style) monotone concession. Each side
walks its own aspiration down a linear schedule from its opening aspiration to
its reservation over at most r_max steps, and among all points still meeting its
aspiration offers the one best for the opponent. `eps` is the floor on the
per-round concession step, so raising eps converges faster -- which is exactly
the knob a fabric insight is allowed to turn.

WARM START is the ratchet: when a verified fabric insight supplies a remembered
settlement point for this context, an agent's OPENING ASPIRATION becomes that
point's utility instead of its own unilateral optimum. Both agents read the same
insight from the shared fabric, so both open at the remembered point and agree in
one round instead of walking the schedule. If the remembered point is stale or
infeasible it is discarded and the cold schedule runs -- costing rounds, never
correctness (Doc 4 §1, invariant 4).
"""
from __future__ import annotations

import copy
import itertools
import random
from dataclasses import asdict, dataclass, field

from .bus import Bus, Clock, FaultState, LOSSY_DELAY_MS, NORMAL_DELAY_MS
from .crypto import Identity, Keyring, b64e, canonical, sha256_hex, sign_envelope, verify_envelope
from .registry import (
    DEFAULT_PARAMS,
    DIM,
    DIM_IDS,
    NEVER_RELAX,
    REGISTRY_HASH,
    class_rank,
    coupling_ok,
    levels,
)
from .types import (
    MSG_ABORT,
    MSG_ACCEPT,
    MSG_COMMIT,
    MSG_COMMIT_ACK,
    MSG_COUNTER,
    MSG_INTENT_DECLARE,
    MSG_PROPOSE,
    MSG_SETTLE,
    SCHEMA,
    NegotiationResult,
)

COMPETENCE_FLOOR = 0.02  # keeps an objective from vanishing when competence is 0


# --- Agent configuration ------------------------------------------------------


@dataclass
class AgentConfig:
    agent_id: str
    persona: str
    objectives: list = field(default_factory=list)  # {dim, direction, weight, value?}
    hard: list = field(default_factory=list)  # {dim, op, value, class}
    competence: dict = field(default_factory=dict)  # dim -> [0,1], sum <= 1.0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AgentConfig":
        return cls(
            agent_id=d["agent_id"],
            persona=d["persona"],
            objectives=[dict(o) for o in d["objectives"]],
            hard=[dict(h) for h in d["hard"]],
            competence=dict(d["competence"]),
        )


# Doc 2 §14 scenario 1 personas. Competence mass is spread over all four
# contested dims (Doc 2 lists three per agent); without a little mass on
# throughput its objective would be multiplied to zero and the agent would stop
# caring about a dimension it explicitly optimizes for.
def make_agent(agent_id: str, persona: str) -> AgentConfig:
    if persona == "throughput":
        return AgentConfig(
            agent_id=agent_id,
            persona="throughput",
            objectives=[
                {"dim": "netops/latency_ms", "direction": "min", "weight": 0.6},
                {"dim": "netops/throughput_mbps", "direction": "max", "weight": 0.4},
            ],
            hard=[
                {"dim": "netops/latency_ms", "op": "le", "value": 12.0, "class": "operational"},
                {"dim": "netops/tls_version", "op": "in", "value": ["1.2", "1.3"], "class": "regulatory"},
            ],
            competence={
                "netops/latency_ms": 0.5,
                "netops/throughput_mbps": 0.2,
                "netops/sample_rate": 0.15,
                "netops/inspection_depth": 0.15,
            },
        )
    if persona == "security":
        return AgentConfig(
            agent_id=agent_id,
            persona="security",
            objectives=[
                {"dim": "netops/inspection_depth", "direction": "max", "weight": 0.7},
                {"dim": "netops/sample_rate", "direction": "max", "weight": 0.3},
            ],
            hard=[
                {"dim": "netops/inspection_depth", "op": "ge", "value": "selective_deep",
                 "class": "security_baseline"},
                # Depth without coverage is theatre: full_deep at sample_rate 0
                # inspects nothing. This floor is what makes the two personas
                # genuinely conflict rather than settle at each other's optimum.
                {"dim": "netops/sample_rate", "op": "ge", "value": 0.25,
                 "class": "security_baseline"},
                {"dim": "netops/tls_version", "op": "in", "value": ["1.3"], "class": "regulatory"},
                {"dim": "netops/log_export", "op": "eq", "value": True,
                 "class": "security_baseline"},
            ],
            competence={
                "netops/inspection_depth": 0.5,
                "netops/sample_rate": 0.3,
                "netops/latency_ms": 0.1,
                "netops/throughput_mbps": 0.1,
            },
        )
    raise ValueError(f"unknown persona {persona}")


def descriptor(cfg: AgentConfig) -> dict:
    """Payload of INTENT_DECLARE (Doc 2 §5). This is the whole disclosure."""
    return {
        "agent": cfg.agent_id,
        "ontologies": [{"ns": "netops", "ver": "1.0.0", "hash": REGISTRY_HASH}],
        "capabilities": [
            {"dim": d, "competence": c} for d, c in sorted(cfg.competence.items())
        ],
        "objectives": cfg.objectives,
        "hard_constraints": cfg.hard,
        "disclosure_tier": 1,
    }


def validate_descriptor(desc: dict) -> str | None:
    """Receiver-side validation. Returns an abort reason or None."""
    budget = sum(c["competence"] for c in desc["capabilities"])
    if budget > 1.0 + 1e-9:
        return "POLICY_VIOLATION"
    wsum = sum(o["weight"] for o in desc["objectives"])
    if abs(wsum - 1.0) > 1e-6:
        return "POLICY_VIOLATION"
    for h in desc["hard_constraints"]:
        if h["dim"] not in DIM:
            return "SCHEMA_MISMATCH"
    return None


# --- Feasibility (Doc 2 §9.1) -------------------------------------------------


def _initial_box() -> dict:
    box = {}
    for d in DIM_IDS:
        t = DIM[d]["type"]
        if t == "continuous":
            box[d] = [float(DIM[d]["domain"]["min"]), float(DIM[d]["domain"]["max"])]
        elif t == "ordinal":
            box[d] = [0, len(levels(d)) - 1]
        elif t == "categorical":
            box[d] = set(DIM[d]["domain"]["values"])
        else:
            box[d] = {True, False}
    return box


def _apply(box: dict, c: dict) -> None:
    d, op, v = c["dim"], c["op"], c["value"]
    t = DIM[d]["type"]
    if t in ("continuous", "ordinal"):
        if t == "ordinal":
            to_i = lambda x: levels(d).index(x) if isinstance(x, str) else int(x)
        else:
            to_i = float
        if op == "le":
            box[d][1] = min(box[d][1], to_i(v))
        elif op == "ge":
            box[d][0] = max(box[d][0], to_i(v))
        elif op == "range":
            box[d][0] = max(box[d][0], to_i(v[0]))
            box[d][1] = min(box[d][1], to_i(v[1]))
    elif t == "categorical":
        box[d] &= set(v) if op == "in" else {v}
    else:  # boolean
        box[d] &= {bool(v)}


def _empty(box: dict) -> bool:
    for d in DIM_IDS:
        b = box[d]
        if isinstance(b, list):
            if b[0] > b[1] + 1e-9:
                return True
        elif not b:
            return True
    return False


def feasible_box(cfgs: list[AgentConfig]) -> tuple[dict | None, list]:
    """Intersect both agents' hard constraints. On empty, relax lowest class
    first, one constraint at a time, lexicographic within class -- never
    touching safety/regulatory (Doc 2 §9.2). Fail closed."""
    constraints = []
    for cfg in cfgs:
        constraints.extend(cfg.hard)

    def build(active):
        box = _initial_box()
        for c in active:
            _apply(box, c)
        return box

    active = list(constraints)
    box = build(active)
    if not _empty(box):
        return box, []

    relaxed = []
    droppable = sorted(
        [c for c in constraints if c["class"] not in NEVER_RELAX],
        key=lambda c: (class_rank(c["class"]), c["dim"]),
    )
    for c in droppable:
        active = [x for x in active if x is not c]
        relaxed.append({"dim": c["dim"], "class": c["class"]})
        box = build(active)
        if not _empty(box):
            return box, relaxed
    return None, relaxed  # ABORT(EMPTY_FEASIBLE)


def _grid_values(d: str, box: dict, k: int) -> list:
    t = DIM[d]["type"]
    b = box[d]
    if t == "continuous":
        lo, hi = b
        if hi - lo < 1e-9:
            return [round(lo, 6)]
        return [round(lo + (hi - lo) * i / (k - 1), 6) for i in range(k)]
    if t == "ordinal":
        return levels(d)[b[0] : b[1] + 1]
    if t == "categorical":
        return sorted(b)
    return sorted(b)  # boolean -> [False, True]


def feasible_points(box: dict, k: int) -> list[dict]:
    """Box grid filtered by the registry's coupling model. This is the set both
    agents search; both compute it identically -> determinism."""
    axes = [_grid_values(d, box, k) for d in DIM_IDS]
    out = []
    for combo in itertools.product(*axes):
        p = dict(zip(DIM_IDS, combo))
        if coupling_ok(p):
            out.append(p)
    return out


def hard_ok(cfg: AgentConfig, point: dict) -> bool:
    """Contract enforcement guard (Doc 2 §7). Runs on the final point, always --
    this is what makes 'bound their behavior by' true, and it is why no fabric
    insight can produce an unsafe contract."""
    box = _initial_box()
    for c in cfg.hard:
        _apply(box, c)
    for d in DIM_IDS:
        b, v = box[d], point[d]
        t = DIM[d]["type"]
        if t == "continuous":
            if not (b[0] - 1e-9 <= float(v) <= b[1] + 1e-9):
                return False
        elif t == "ordinal":
            if not (b[0] <= levels(d).index(v) <= b[1]):
                return False
        elif v not in b:
            return False
    return True


# --- Utility (Doc 2 §9.3) -----------------------------------------------------


def _norm(d: str, value, box: dict) -> float:
    t = DIM[d]["type"]
    b = box[d]
    if t == "continuous":
        lo, hi = b
        return 1.0 if hi - lo < 1e-9 else (float(value) - lo) / (hi - lo)
    if t == "ordinal":
        lo, hi = b
        return 1.0 if hi == lo else (levels(d).index(value) - lo) / (hi - lo)
    return 1.0


def effective_weights(cfg: AgentConfig) -> dict:
    """w' = w * c / Σ  -- competence-weighted and renormalized."""
    raw = {}
    for o in cfg.objectives:
        c = cfg.competence.get(o["dim"], 0.0) + COMPETENCE_FLOOR
        raw[o["dim"]] = o["weight"] * c
    tot = sum(raw.values()) or 1.0
    return {d: v / tot for d, v in raw.items()}


def utility(cfg: AgentConfig, point: dict, box: dict, weights: dict | None = None) -> float:
    w = weights if weights is not None else effective_weights(cfg)
    u = 0.0
    for o in cfg.objectives:
        d = o["dim"]
        if o["direction"] == "max":
            s = _norm(d, point[d], box)
        elif o["direction"] == "min":
            s = 1.0 - _norm(d, point[d], box)
        else:  # prefer
            s = 1.0 if point[d] == o.get("value") else 0.0
        u += w[d] * s
    return u


def authority_map(cfgs: list[AgentConfig]) -> dict:
    """argmax competence per dim, tie -> lexicographic agent id (Doc 2 §7.8)."""
    out = {}
    for d in DIM_IDS:
        best = sorted(
            ((-cfg.competence.get(d, 0.0), cfg.agent_id) for cfg in cfgs)
        )[0]
        out[d] = best[1]
    return out


def point_hash(p: dict) -> str:
    return sha256_hex(canonical(p))[:16]


def snap_point(warm: dict, box: dict, k: int) -> dict | None:
    """Project a remembered settlement point onto the current feasible grid."""
    out = {}
    for d in DIM_IDS:
        if d not in warm:
            return None
        vals = _grid_values(d, box, k)
        v = warm[d]
        t = DIM[d]["type"]
        if t == "continuous":
            out[d] = min(vals, key=lambda x: (abs(x - float(v)), x))
        elif t == "ordinal":
            if v not in levels(d):
                return None
            tgt = levels(d).index(v)
            if not vals:
                return None
            out[d] = min(vals, key=lambda x: (abs(levels(d).index(x) - tgt), x))
        else:
            if v not in box[d]:
                return None
            out[d] = v
    return out if coupling_ok(out) else None


def _midpoint(box: dict, F: list[dict]) -> dict:
    """Deterministic R_max settlement: per-dim midpoint, snapped to the nearest
    physically realizable point if the coupling model forbids the midpoint."""
    mid = {}
    for d in DIM_IDS:
        t, b = DIM[d]["type"], box[d]
        if t == "continuous":
            mid[d] = round((b[0] + b[1]) / 2.0, 6)
        elif t == "ordinal":
            mid[d] = levels(d)[(b[0] + b[1]) // 2]
        else:
            vals = sorted(b)
            mid[d] = vals[len(vals) // 2]
    if coupling_ok(mid) and any(canonical(p) == canonical(mid) for p in F):
        return mid

    def dist(p):
        s = 0.0
        for d in DIM_IDS:
            t = DIM[d]["type"]
            if t in ("continuous", "ordinal"):
                s += abs(_norm(d, p[d], box) - _norm(d, mid[d], box))
            else:
                s += 0.0 if p[d] == mid[d] else 1.0
        return s

    return min(F, key=lambda p: (round(dist(p), 9), point_hash(p)))


# --- The protocol -------------------------------------------------------------


class _Abort(Exception):
    def __init__(self, reason: str):
        self.reason = reason


def _nonce(rng) -> str:
    return b64e(bytes(rng.getrandbits(8) for _ in range(16)))


def negotiate(
    bus: Bus,
    cfg_a: AgentConfig,
    cfg_b: AgentConfig,
    task_ctx: dict,
    params: dict,
    warm_start: dict | None = None,
    identities: dict | None = None,
    keyring: Keyring | None = None,
    session: str | None = None,
    insight_ids: list | None = None,
    config_epoch: int = 0,
) -> NegotiationResult:
    p = dict(DEFAULT_PARAMS)
    p.update(params or {})
    eps, delta = float(p["eps"]), float(p["delta"])
    r_max, k = int(p["r_max"]), int(p["grid_k"])
    msg_wait = float(p["msg_wait_ms"])

    a, b = cfg_a.agent_id, cfg_b.agent_id
    if identities is None:
        identities = {a: Identity.deterministic(a), b: Identity.deterministic(b)}
    if keyring is None:
        keyring = Keyring()
        for ident in identities.values():
            keyring.pin_identity(ident)
    bus.register(a)
    bus.register(b)
    session = session or "sess-" + sha256_hex(canonical([a, b, task_ctx]))[:12]

    start = bus.clock.now()
    deadline = start + float(p["negotiate_timeout_ms"])
    transcript: list[dict] = []
    seq = {a: 0, b: 0}
    seen = {a: set(), b: set()}
    last_sent: dict = {}

    def send(frm: str, to: str, mtype: str, payload: dict) -> dict:
        env = {
            "schema": SCHEMA,
            "type": mtype,
            "session": session,
            "seq": seq[frm],
            "from": frm,
            "to": to,
            "ts_ms": bus.clock.now(),
            "nonce": _nonce(bus.rng),
            # Deep copy: an envelope is immutable the instant it is signed. The
            # contract keeps being countersigned after COMMIT goes out, and
            # without this the sender mutates a payload it has already signed --
            # the envelope then fails verification at the receiver.
            "payload": copy.deepcopy(payload),
        }
        env = sign_envelope(identities[frm], env)
        transcript.append(env)
        seq[frm] += 1
        bus.send(env)
        last_sent[frm] = env
        return env

    def recv(agent: str):
        """Bounded wait. Retransmits its own last envelope once, then gives up."""
        retransmitted = False
        while True:
            remaining = deadline - bus.clock.now()
            if remaining <= 0:
                return None
            env = bus.recv(agent, min(remaining, msg_wait))
            if env is None:
                if not retransmitted and last_sent.get(agent) is not None:
                    bus.send(last_sent[agent])
                    retransmitted = True
                    continue
                return None
            if env.get("schema") != SCHEMA:
                raise _Abort("SCHEMA_MISMATCH")
            if not verify_envelope(keyring, env):
                raise _Abort("INVALID_SIG")
            if env.get("session") != session:
                # A dead envelope from an earlier session on the same channel.
                # `session` is constant within a session (Doc 2 §4), so anything
                # else is not ours: discard it rather than parse it as our next
                # expected message.
                continue
            key = (env["from"], env["seq"])
            if key in seen[agent]:
                continue  # replay guard: duplicates are idempotent drops
            seen[agent].add(key)
            return env

    def result(contract, rounds, aborted, reason, thash=""):
        return NegotiationResult(
            contract=contract,
            rounds=rounds,
            duration_ms=bus.clock.now() - start,
            aborted=aborted,
            abort_reason=reason,
            transcript_hash=thash,
            messages=len(transcript),
            transcript=list(transcript),
        )

    try:
        # --- 1. INTENT_DECLARE, both directions, concurrently ----------------
        env_a = send(a, b, MSG_INTENT_DECLARE, {"descriptor": descriptor(cfg_a)})
        env_b = send(b, a, MSG_INTENT_DECLARE, {"descriptor": descriptor(cfg_b)})
        got_a, got_b = recv(a), recv(b)
        if got_a is None or got_b is None:
            return result(None, 0, True, "TIMEOUT")
        for got in (got_a, got_b):
            bad = validate_descriptor(got["payload"]["descriptor"])
            if bad:
                raise _Abort(bad)

        # --- 2. Feasibility ---------------------------------------------------
        box, relaxed = feasible_box([cfg_a, cfg_b])
        if box is None:
            return result(None, 0, True, "EMPTY_FEASIBLE")
        F = feasible_points(box, k)
        if not F:
            return result(None, 0, True, "EMPTY_FEASIBLE")

        wa, wb = effective_weights(cfg_a), effective_weights(cfg_b)
        ua = [utility(cfg_a, pt, box, wa) for pt in F]
        ub = [utility(cfg_b, pt, box, wb) for pt in F]
        U = {a: ua, b: ub}

        # --- 3. Aspiration schedules (warm start = the ratchet) ---------------
        anchor_i = None
        if warm_start:
            snapped = snap_point(warm_start, box, k)
            if snapped is not None:
                cs = canonical(snapped)
                for i, pt in enumerate(F):
                    if canonical(pt) == cs:
                        anchor_i = i
                        break
        u_max = {}
        u_min = {}
        for x in (a, b):
            u_min[x] = min(U[x])
            u_max[x] = U[x][anchor_i] if anchor_i is not None else max(U[x])
        # r_max caps TOTAL rounds, but a side only offers on every other round, so
        # its schedule must complete within its own share of the cap. Dividing by
        # r_max instead of r_max/2 leaves both sides still halfway up their
        # schedules when the cap hits, and every negotiation lands on the midpoint
        # fallback instead of converging by acceptance.
        steps_per_side = max(1, r_max // 2)
        step = {x: max(eps, (u_max[x] - u_min[x]) / steps_per_side) for x in (a, b)}

        def target(x: str, n: int) -> float:
            return u_max[x] - step[x] * (n - 1)

        offers_made = {a: 0, b: 0}

        def make_offer(x: str) -> int:
            offers_made[x] += 1
            t = target(x, offers_made[x])
            opp = b if x == a else a
            cands = [i for i in range(len(F)) if U[x][i] >= t - 1e-9] or list(range(len(F)))
            # Among everything still meeting my aspiration, hand the opponent the
            # best deal. Tie-break on point hash -> byte-identical every run.
            cands.sort(key=lambda i: (-round(U[opp][i], 9), point_hash(F[i])))
            return cands[0]

        # --- 4. Deterministic proposer selection (Doc 2 §6) -------------------
        h_a = sha256_hex(env_a["nonce"] + env_b["nonce"])
        h_b = sha256_hex(env_b["nonce"] + env_a["nonce"])
        proposer, responder = (a, b) if h_a < h_b else (b, a)

        # --- 5. Bounded concession loop --------------------------------------
        rounds = 1
        idx = make_offer(proposer)
        send(proposer, responder, MSG_PROPOSE,
             {"round": rounds, "point": F[idx], "expires_in_s": 60})
        prev_offer = {proposer: idx}
        last_recv = {}
        agreed_idx = None
        resolved_by = None
        cur, other = responder, proposer

        while True:
            got = recv(cur)
            if got is None:
                return result(None, rounds, True, "TIMEOUT")
            pay = got["payload"]
            pt = pay["point"]
            try:
                ridx = next(i for i, q in enumerate(F) if canonical(q) == canonical(pt))
            except StopIteration:
                raise _Abort("POLICY_VIOLATION")  # offer outside the feasible region

            # Concession check: the sender must never walk MY utility backwards.
            if other in last_recv and U[cur][ridx] < U[cur][last_recv[other]] - delta:
                agreed_idx = _idx_of(F, _midpoint(box, F))
                resolved_by = "settlement:CONCESSION_VIOLATION"
                send(cur, other, MSG_SETTLE,
                     {"round": rounds, "point": F[agreed_idx], "reason": "CONCESSION_VIOLATION"})
                break
            last_recv[other] = ridx

            if U[cur][ridx] >= target(cur, offers_made[cur] + 1) - delta:
                agreed_idx = ridx
                resolved_by = "acceptance"
                send(cur, other, MSG_ACCEPT,
                     {"round": rounds, "point_hash": point_hash(pt)})
                break

            if rounds >= r_max:
                agreed_idx = _idx_of(F, _midpoint(box, F))
                resolved_by = "settlement:ROUND_CAP"
                send(cur, other, MSG_SETTLE,
                     {"round": rounds, "point": F[agreed_idx], "reason": "ROUND_CAP"})
                break

            rounds += 1
            my = make_offer(cur)
            send(cur, other, MSG_COUNTER, {"round": rounds, "point": F[my]})
            prev_offer[cur] = my
            cur, other = other, cur

        # `cur` has just sent ACCEPT or SETTLE. `other` must actually consume it:
        # leaving it queued desynchronises the channel, and the COMMIT below gets
        # dequeued in its place.
        if recv(other) is None:
            return result(None, rounds, True, "TIMEOUT")

        agreed = F[agreed_idx]

        # --- 6. Fail-closed enforcement (never trusts the path that got here) --
        for cfg in (cfg_a, cfg_b):
            if not hard_ok(cfg, agreed):
                return result(None, rounds, True, "POLICY_VIOLATION")

        # --- 7. Contract + countersignature -----------------------------------
        thash = sha256_hex(canonical(transcript))
        contract = {
            "contract_id": "csp-" + thash[:8],
            "schema": SCHEMA,
            "session": session,
            "parties": sorted([a, b]),
            "ontology_hash": REGISTRY_HASH,
            "shared_dims": list(DIM_IDS),
            "agreed": agreed,
            "authority_map": authority_map([cfg_a, cfg_b]),
            "provenance": {"resolved_by": resolved_by, "rounds": rounds, "relaxed": relaxed},
            "ttl_s": 600,
            "renegotiate_on": ["constraint_violation", "ttl_expiry", "capability_change"],
            "version": 1,
            "prev_contract_id": None,
            "created_ms": bus.clock.now(),
            "transcript_hash": thash,
            "config_epoch": config_epoch,
            "insight_ids": sorted(insight_ids or []),
            "warm_started": anchor_i is not None,
            "signatures": {},
        }
        body = {kk: vv for kk, vv in contract.items() if kk != "signatures"}
        contract["signatures"] = {cur: identities[cur].sign(canonical(body))}
        send(cur, other, MSG_COMMIT, {"contract": contract})
        if recv(other) is None:
            return result(None, rounds, True, "TIMEOUT")
        contract["signatures"][other] = identities[other].sign(canonical(body))
        send(other, cur, MSG_COMMIT_ACK, {"contract": contract})
        if recv(cur) is None:
            return result(None, rounds, True, "TIMEOUT")

        return result(contract, rounds, False, None, thash)

    except _Abort as e:
        try:
            send(a, b, MSG_ABORT, {"reason_code": e.reason, "at_state": "NEGOTIATING"})
        except Exception:
            pass
        return result(None, 0, True, e.reason)


def _idx_of(F: list[dict], point: dict) -> int:
    c = canonical(point)
    for i, q in enumerate(F):
        if canonical(q) == c:
            return i
    return 0


# --- Replay: THE verification primitive (Doc 4 §5.6 / §7.4) -------------------


def build_scenario(cfg_a: AgentConfig, cfg_b: AgentConfig, task_ctx: dict, seed: int,
                   faults: FaultState) -> dict:
    """A self-contained, re-executable recording of one negotiation."""
    return {
        "agents": {"a": cfg_a.to_dict(), "b": cfg_b.to_dict()},
        "task_ctx": {k: v for k, v in sorted(task_ctx.items())},
        "seed": int(seed),
        "faults": faults.snapshot(),
    }


def replay(scenario: dict, params: dict, warm_start: dict | None = None) -> NegotiationResult:
    """Re-execute a recorded negotiation on a fresh in-proc bus with the recorded
    fault profile. Same scenario + params -> byte-identical result, on any node.

    This is what turns "I found an optimization" into a checkable claim: a peer
    runs this, and its result must match the claimer's before it will attest.
    """
    cfg_a = AgentConfig.from_dict(scenario["agents"]["a"])
    cfg_b = AgentConfig.from_dict(scenario["agents"]["b"])
    rng = random.Random(scenario["seed"])
    clock = Clock(0.0)
    faults = FaultState.from_snapshot(scenario["faults"])
    bus = Bus(clock, faults, rng, telemetry=None)
    session = "replay-" + sha256_hex(canonical(scenario))[:12]
    return negotiate(
        bus, cfg_a, cfg_b, scenario["task_ctx"], params,
        warm_start=warm_start, session=session,
    )
