"""Per-node hash-chained append-only fabric log (Doc 4 §7.1).

DEVIATION FROM DOC 4, owned deliberately. Doc 4 asks for "three identical heads"
as the convergence proof. Three nodes that author entries concurrently cannot
have identical chain heads unless we re-order and re-link on merge -- and
re-linking IS log rewriting, which invariant 5 forbids. So the structure is split
into the two things that were being conflated:

  * The CHAIN gives per-node tamper evidence. Entries are linked in local receipt
    order; verify_chain() recomputes every link. Heads legitimately differ by
    node -- they record the order THIS node learned things.
  * The ENTRY SET gives convergence. Entries are content-addressed and signed by
    their author, so they are a grow-only set (a CRDT): union is commutative,
    associative and idempotent. `digest()` over the sorted entry ids is what
    converges after a partition heals, and it is what the chaos demo prints.

Status is derived by folding the set, and the fold is a join over a
status lattice (max by rank), so it is order-independent too. That is why a node
that receives entries in a different order after a partition still computes the
same status for every insight -- no split brain, no reconciliation pass.

Nothing is ever deleted. QUARANTINED and REVOKED are later entries, not edits.
Pruning is tombstoning (Doc 4 §1 invariant 5).
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict

from core.crypto import GENESIS_HASH, Identity, Keyring, canonical, sha256_hex
from core.types import (
    STATUS_CANDIDATE,
    STATUS_LOCAL,
    STATUS_QUARANTINED,
    STATUS_RANK,
    STATUS_REVOKED,
    STATUS_VERIFIED,
)

KIND_INSIGHT = "INSIGHT"
KIND_ATTEST = "ATTEST"
KIND_STATUS = "STATUS"
KIND_GUARDRAIL_DENY = "GUARDRAIL_DENY"
KIND_TOMBSTONE = "TOMBSTONE"

QUORUM = 2  # 2-of-3 distinct attesting nodes


class FabricLog:
    def __init__(self, node_id: str, identity: Identity, keyring: Keyring, out_dir: str | None = None):
        self.node_id = node_id
        self.identity = identity
        self.keyring = keyring
        self.chain: list[dict] = []  # local order, tamper-evident
        self.by_id: dict[str, dict] = {}  # the grow-only set
        self._seq = 0
        self.out_path = None
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            self.out_path = os.path.join(out_dir, f"fabric_{node_id}.jsonl")
            open(self.out_path, "w").close()

    # --- authoring / replication ---------------------------------------------

    def append(self, kind: str, body: dict) -> dict:
        """Author a new entry locally and sign it."""
        content = {"author": self.node_id, "kind": kind, "seq": self._seq, "body": body}
        self._seq += 1
        entry = dict(content)
        entry["entry_id"] = sha256_hex(canonical(content))
        entry["sig"] = self.identity.sign(canonical(content))
        self._add(entry)
        return entry

    def ingest(self, entry: dict) -> bool:
        """Accept an entry authored elsewhere. Verify before anything else."""
        try:
            content = {k: entry[k] for k in ("author", "kind", "seq", "body")}
        except KeyError:
            return False
        if entry.get("entry_id") != sha256_hex(canonical(content)):
            return False  # id must bind the content
        if not self.keyring.verify(entry["author"], entry.get("sig", ""), canonical(content)):
            return False  # unpinned author or bad signature
        if entry["entry_id"] in self.by_id:
            return False  # idempotent: union of a set
        self._add(entry)
        return True

    def _add(self, entry: dict) -> None:
        prev = self.chain[-1]["link_hash"] if self.chain else GENESIS_HASH
        link = {"idx": len(self.chain), "prev_hash": prev, "entry_id": entry["entry_id"]}
        link["link_hash"] = sha256_hex(canonical(link))
        self.chain.append(link)
        self.by_id[entry["entry_id"]] = entry
        if self.out_path:
            with open(self.out_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"link": link, "entry": entry}, sort_keys=True) + "\n")

    # --- integrity / convergence ---------------------------------------------

    def head(self) -> tuple:
        if not self.chain:
            return (-1, GENESIS_HASH)
        return (self.chain[-1]["idx"], self.chain[-1]["link_hash"])

    def verify_chain(self) -> bool:
        prev = GENESIS_HASH
        for i, link in enumerate(self.chain):
            recomputed = sha256_hex(
                canonical({"idx": i, "prev_hash": prev, "entry_id": link["entry_id"]})
            )
            if link["idx"] != i or link["prev_hash"] != prev or link["link_hash"] != recomputed:
                return False
            prev = link["link_hash"]
        return True

    def digest(self) -> str:
        """Convergence proof: identical across nodes iff they hold the same set."""
        return sha256_hex(canonical(sorted(self.by_id.keys())))

    def entries_since(self, known_ids: list) -> list:
        have = set(known_ids)
        return [self.by_id[k] for k in sorted(self.by_id) if k not in have]

    def entry_ids(self) -> list:
        return sorted(self.by_id.keys())

    # --- fold: derived state --------------------------------------------------

    def fold(self) -> dict:
        """Rebuild current state from the entry set. Order-independent."""
        insights: dict[str, dict] = {}
        attests: dict[str, dict] = defaultdict(dict)  # id -> author -> attestation
        explicit: dict[str, int] = defaultdict(lambda: 0)
        reasons: dict[str, str] = {}
        denies: list = []

        for entry in sorted(self.by_id.values(), key=lambda e: (e["author"], e["seq"])):
            kind, body, author = entry["kind"], entry["body"], entry["author"]
            if kind == KIND_INSIGHT:
                iid = body["insight"]["id"]
                if iid not in insights:
                    insights[iid] = dict(body["insight"])
            elif kind == KIND_ATTEST:
                attests[body["insight_id"]][author] = {
                    "node": author,
                    "ok": bool(body["ok"]),
                    "replay_hash": body["replay_hash"],
                }
            elif kind == KIND_STATUS:
                r = STATUS_RANK.get(body["status"], 0)
                if r >= explicit[body["insight_id"]]:
                    explicit[body["insight_id"]] = r
                    reasons[body["insight_id"]] = body.get("reason", "")
            elif kind == KIND_TOMBSTONE:
                explicit[body["insight_id"]] = STATUS_RANK[STATUS_REVOKED]
                reasons[body["insight_id"]] = body.get("reason", "tombstoned")
            elif kind == KIND_GUARDRAIL_DENY:
                denies.append({"node": author, **body})

        out = {}
        for iid, ins in insights.items():
            a = attests.get(iid, {})
            # An insight only reaches the log by being announced, so anything we
            # can fold is at least CANDIDATE. LOCAL exists only pre-announce, on
            # the discovering node's bench.
            derived = STATUS_CANDIDATE

            oks = [x for x in a.values() if x["ok"]]
            bad = [x for x in a.values() if not x["ok"]]
            if oks:
                # Quorum needs MATCHING replay hashes, not just matching opinions.
                top_hash, n = Counter(x["replay_hash"] for x in oks).most_common(1)[0]
                if n >= QUORUM:
                    derived = STATUS_VERIFIED
            if len({x["node"] for x in bad}) >= QUORUM:
                derived = STATUS_QUARANTINED  # outranks VERIFIED: fail closed

            rank = max(STATUS_RANK[derived], explicit[iid])
            status = next(s for s, r in STATUS_RANK.items() if r == rank)
            ins = dict(ins)
            ins["status"] = status
            ins["attestations"] = sorted(a.values(), key=lambda x: x["node"])
            ins["status_reason"] = reasons.get(iid, "")
            out[iid] = ins
        return {"insights": out, "denies": denies}

    def descendants(self, insight_id: str) -> set:
        """Provenance subtree via derived_from -- what a revoke must take with it."""
        state = self.fold()["insights"]
        kids = defaultdict(set)
        for iid, ins in state.items():
            for parent in ins.get("provenance", {}).get("derived_from", []):
                kids[parent].add(iid)
        out, stack = set(), [insight_id]
        while stack:
            cur = stack.pop()
            for c in kids.get(cur, ()):
                if c not in out:
                    out.add(c)
                    stack.append(c)
        return out
