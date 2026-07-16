"""In-proc transport with fault-injection hooks and a virtual clock (Doc 4 §4).

Phase 1 defined transport as a pluggable L0 adapter (websocket / tcp / in-proc
queue). We run the in-proc adapter because it is deterministic and fault-
injectable; the envelopes and crypto above it are identical on any adapter.

Time is virtual. `Clock.now()` is advanced by message delivery, not by the OS,
so a negotiation over a 1200 ms/hop lossy link costs microseconds of wall clock
and produces the exact same numbers every run. This is what makes replay
verification (the anti-hallucination gate) a cheap primitive instead of a
5-second wait.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class Clock:
    """Virtual millisecond clock. Monotonic; only ever moves forward."""

    def __init__(self, start_ms: float = 0.0):
        self.t = float(start_ms)

    def now(self) -> float:
        return self.t

    def advance(self, ms: float) -> None:
        self.t += max(0.0, float(ms))

    def advance_to(self, ms: float) -> None:
        # max(), not assignment: two messages in flight on parallel links must
        # not rewind the clock when the later one is dequeued first.
        self.t = max(self.t, float(ms))


def node_of(entity_id: str) -> str:
    """'N1.throughput' -> 'N1'. Faults are expressed at node granularity."""
    return entity_id.split(".", 1)[0]


NORMAL_DELAY_MS = (5.0, 10.0)
LOSSY_DELAY_MS = (400.0, 1200.0)


@dataclass
class FaultState:
    """Mutated by loadgen eras and chaos/inject.py."""

    node_down: set = field(default_factory=set)
    partitions: set = field(default_factory=set)  # of frozenset({nodeA, nodeB})
    link_delay_ms: dict = field(default_factory=dict)  # frozenset({a,b}) -> (lo,hi)
    default_delay_ms: tuple = NORMAL_DELAY_MS

    def down(self, node: str) -> bool:
        return node in self.node_down

    def partitioned(self, a: str, b: str) -> bool:
        return a != b and frozenset({a, b}) in self.partitions

    def delay(self, a: str, b: str) -> tuple:
        if a == b:
            return (0.0, 0.0)
        return self.link_delay_ms.get(frozenset({a, b}), self.default_delay_ms)

    def set_link(self, a: str, b: str, lo: float, hi: float) -> None:
        self.link_delay_ms[frozenset({a, b})] = (float(lo), float(hi))

    def clear_links(self) -> None:
        self.link_delay_ms.clear()

    def snapshot(self) -> dict:
        """Recorded into an insight's evidence so a peer replays the same world."""
        return {
            "node_down": sorted(self.node_down),
            "partitions": sorted(sorted(p) for p in self.partitions),
            "link_delay_ms": sorted(
                [sorted(k) + [v[0], v[1]] for k, v in self.link_delay_ms.items()]
            ),
            "default_delay_ms": list(self.default_delay_ms),
        }

    @classmethod
    def from_snapshot(cls, snap: dict) -> "FaultState":
        fs = cls()
        fs.node_down = set(snap.get("node_down", []))
        fs.partitions = {frozenset(p) for p in snap.get("partitions", [])}
        for row in snap.get("link_delay_ms", []):
            fs.link_delay_ms[frozenset(row[:2])] = (row[2], row[3])
        fs.default_delay_ms = tuple(snap.get("default_delay_ms", NORMAL_DELAY_MS))
        return fs


class Bus:
    """Deterministic message bus. send() is fire-and-forget; recv() drives time."""

    def __init__(self, clock: Clock, faults: FaultState, rng, keyring=None, telemetry=None):
        self.clock = clock
        self.faults = faults
        self.rng = rng
        self.keyring = keyring
        self.telemetry = telemetry
        self.inbox: dict[str, list] = {}
        self._ctr = 0
        self.dropped = 0
        self.delivered = 0

    def register(self, entity_id: str) -> None:
        self.inbox.setdefault(entity_id, [])

    def send(self, env: dict) -> bool:
        src, dst = node_of(env["from"]), node_of(env["to"])
        f = self.faults
        if f.down(src) or f.down(dst) or f.partitioned(src, dst):
            self.dropped += 1
            return False
        lo, hi = f.delay(src, dst)
        delay = self.rng.uniform(lo, hi)
        self.inbox.setdefault(env["to"], []).append(
            (self.clock.now() + delay, self._ctr, env)
        )
        self._ctr += 1
        return True

    def recv(self, entity_id: str, timeout_ms: float):
        """Return the next envelope for `entity_id`, advancing the virtual clock.

        Returns None on timeout, having burned the full timeout -- callers treat
        that as a lost message (retransmit once, then ABORT(TIMEOUT)).
        """
        box = self.inbox.setdefault(entity_id, [])
        if box:
            # (deliver_at, arrival counter) is a total order -> no tie ambiguity.
            box.sort(key=lambda x: (x[0], x[1]))
            deliver_at, _, env = box[0]
            if deliver_at <= self.clock.now() + timeout_ms:
                box.pop(0)
                self.clock.advance_to(deliver_at)
                self.delivered += 1
                if self.telemetry is not None:
                    self.telemetry.metric(
                        "csp.message.latency_ms",
                        self.clock.now() - env["ts_ms"],
                        {
                            "from": env["from"],
                            "to": env["to"],
                            "type": env["type"],
                            "session": env.get("session"),
                        },
                    )
                return env
        self.clock.advance(timeout_ms)
        return None

    def drain(self, entity_id: str) -> list:
        """Non-blocking: everything already deliverable at the current instant."""
        box = self.inbox.setdefault(entity_id, [])
        box.sort(key=lambda x: (x[0], x[1]))
        out, keep = [], []
        for deliver_at, ctr, env in box:
            if deliver_at <= self.clock.now():
                out.append(env)
                self.delivered += 1
            else:
                keep.append((deliver_at, ctr, env))
        self.inbox[entity_id] = keep
        return out

    def clear(self, entity_id: str) -> None:
        self.inbox[entity_id] = []
