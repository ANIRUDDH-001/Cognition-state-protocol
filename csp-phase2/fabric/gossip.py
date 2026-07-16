"""Anti-entropy gossip (Doc 4 §7.2).

Set reconciliation, not log shipping. Each node advertises the digest and ids of
its entry set; a peer holding entries the sender lacks pushes exactly those.
Because entries are content-addressed, signed, and unioned, the exchange is
idempotent and order-free -- a node that was down or partitioned catches up by
simply running a round, with no leader, no reconciliation pass, and no special
case. That IS the resolution of chaos faults F1 and F3; there is no extra code.

Gossip rides the same faulted bus as everything else, so a partition really does
stop it, and a healed partition really does converge it.

Scale note: advertising the full id list is O(n) per round. n is in the tens here.
The production path is a Merkle/IBLT digest exchange -- same protocol, sublinear
payload. We did not build it because it changes nothing about the demo's claims.
"""
from __future__ import annotations

from core.crypto import Keyring, canonical, sign_envelope, verify_envelope
from core.types import MSG_GOSSIP_HEAD, MSG_GOSSIP_PUSH, SCHEMA


class Gossip:
    def __init__(self, bus, identities: dict, keyring: Keyring):
        self.bus = bus
        self.identities = identities  # node_id -> Identity
        self.keyring = keyring
        self._seq: dict = {}

    def _send(self, frm: str, to: str, mtype: str, payload: dict) -> None:
        n = self._seq.get(frm, 0)
        self._seq[frm] = n + 1
        env = {
            "schema": SCHEMA,
            "type": mtype,
            "session": "gossip",
            "seq": n,
            "from": frm,
            "to": to,
            "ts_ms": self.bus.clock.now(),
            "nonce": "gossip-%s-%d" % (frm, n),
            "payload": payload,
        }
        self.bus.send(sign_envelope(self.identities[frm], env))

    def _settle(self) -> None:
        """Advance the virtual clock past the slowest link so in-flight gossip lands."""
        hi = max(
            [self.bus.faults.default_delay_ms[1]]
            + [v[1] for v in self.bus.faults.link_delay_ms.values()]
            + [1.0]
        )
        self.bus.clock.advance(hi + 1.0)

    def round(self, logs: dict) -> dict:
        """One anti-entropy round across every node. Returns {'applied': n}."""
        ids = sorted(logs)
        for x in ids:
            self.bus.register(x)

        # 1. Advertise.
        for x in ids:
            for y in ids:
                if x != y:
                    self._send(x, y, MSG_GOSSIP_HEAD,
                               {"digest": logs[x].digest(), "entry_ids": logs[x].entry_ids()})
        self._settle()

        # 2. Anyone holding entries the advertiser lacks pushes the delta back.
        for y in ids:
            for env in self.bus.drain(y):
                if env.get("type") != MSG_GOSSIP_HEAD or not verify_envelope(self.keyring, env):
                    continue
                delta = logs[y].entries_since(env["payload"]["entry_ids"])
                if delta:
                    self._send(y, env["from"], MSG_GOSSIP_PUSH, {"entries": delta})
        self._settle()

        # 3. Ingest. Every entry is re-verified here; a relay is never trusted.
        applied = 0
        for x in ids:
            for env in self.bus.drain(x):
                if env.get("type") != MSG_GOSSIP_PUSH or not verify_envelope(self.keyring, env):
                    continue
                for e in env["payload"]["entries"]:
                    if logs[x].ingest(e):
                        applied += 1
        return {"applied": applied}

    def converge(self, logs: dict, max_rounds: int = 6) -> int:
        """Run rounds until every reachable node holds the same set."""
        for i in range(1, max_rounds + 1):
            before = {k: v.digest() for k, v in logs.items()}
            self.round(logs)
            after = {k: v.digest() for k, v in logs.items()}
            if before == after and len(set(after.values())) == 1:
                return i
        return max_rounds
