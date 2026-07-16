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
from fabric.model import compute_id

KIND_INSIGHT = "INSIGHT"
KIND_ATTEST = "ATTEST"
KIND_STATUS = "STATUS"
KIND_GUARDRAIL_DENY = "GUARDRAIL_DENY"
KIND_TOMBSTONE = "TOMBSTONE"

QUORUM = 2  # 2-of-3 distinct attesting nodes

_INSIGHT_FIELDS = ("id", "version", "scope", "claim", "evidence", "provenance")


def valid_body(kind: str, body) -> bool:
    """Schema gate at the log boundary. An entry whose signature verifies is
    authentic, not well-formed: a pinned-but-compromised node can sign anything.
    Everything downstream (fold, guardrail, pipeline) indexes into these shapes,
    so a body that does not match one is refused here rather than raising deep
    inside a fold that every node runs. Fail closed (Doc 1 §2.3).

    The id check is the load-bearing one. `id` is excluded from the signed body
    (fabric/model.signing_body) precisely because it is derived from it -- so an
    author can name its insight anything unless we re-derive and compare. Without
    this, a rogue node can publish a poisoned body carrying an already-VERIFIED
    insight's id and inherit that insight's attestations wholesale, since the
    fold keys attestations by id.
    """
    if not isinstance(body, dict):
        return False
    if kind == KIND_INSIGHT:
        ins = body.get("insight")
        if not isinstance(ins, dict) or not all(k in ins for k in _INSIGHT_FIELDS):
            return False
        if not isinstance(ins["provenance"], dict):
            return False
        try:
            return compute_id(ins) == ins["id"]
        except (KeyError, TypeError, ValueError):
            return False
    if kind == KIND_ATTEST:
        return (isinstance(body.get("insight_id"), str)
                and isinstance(body.get("ok"), bool)
                and isinstance(body.get("replay_hash"), str))
    if kind == KIND_STATUS:
        return (isinstance(body.get("insight_id"), str)
                and body.get("status") in STATUS_RANK)
    if kind == KIND_TOMBSTONE:
        return isinstance(body.get("insight_id"), str)
    if kind == KIND_GUARDRAIL_DENY:
        return isinstance(body.get("insight_id"), str) and isinstance(body.get("reason"), str)
    return False  # unknown kinds are not a thing we replicate


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
        if not valid_body(kind, body):
            raise ValueError(f"refusing to author a malformed {kind} entry")
        content = {"author": self.node_id, "kind": kind, "seq": self._seq, "body": body}
        self._seq += 1
        entry = dict(content)
        entry["entry_id"] = sha256_hex(canonical(content))
        entry["sig"] = self.identity.sign(canonical(content))
        self._add(entry)
        return entry

    def force_append(self, kind: str, body: dict) -> dict:
        """Author an entry WITHOUT the local schema gate.

        Chaos only. A compromised node does not run our validation before
        broadcasting -- assuming it does would make the guardrail look good by
        assuming away the attacker. This models the rogue's own log; every honest
        peer still puts the result through ingest(), which is where the claim
        that matters ("no node trusts an entry because of who sent it") is tested.
        """
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
        if not valid_body(entry["kind"], entry["body"]):
            return False  # authentic but malformed -- a signature is not a schema
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
        # iid -> status -> {authors who voted for it}. Demotion is a VOTE, not a
        # command: an explicit status only binds the fabric at QUORUM, exactly like
        # promotion. One pinned-but-compromised node signing STATUS:REVOKED for
        # every id would otherwise reset the collective memory to zero on its own
        # -- the precise outcome the pruning design is supposed to rule out.
        votes: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
        reasons: dict[str, dict[str, str]] = defaultdict(dict)
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
                votes[body["insight_id"]][body["status"]].add(author)
                reasons[body["insight_id"]][body["status"]] = body.get("reason", "")
            elif kind == KIND_TOMBSTONE:
                votes[body["insight_id"]][STATUS_REVOKED].add(author)
                reasons[body["insight_id"]][STATUS_REVOKED] = body.get("reason", "tombstoned")
            elif kind == KIND_GUARDRAIL_DENY:
                denies.append({"node": author, **body})

        def explicit_for(iid: str) -> tuple:
            """Highest status that reached quorum, with the reason its voters gave."""
            rank, reason = 0, ""
            for status, authors in votes[iid].items():
                if len(authors) >= QUORUM and STATUS_RANK[status] > rank:
                    rank, reason = STATUS_RANK[status], reasons[iid].get(status, "")
            return rank, reason

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

            exp_rank, exp_reason = explicit_for(iid)
            rank = max(STATUS_RANK[derived], exp_rank)
            status = next(s for s, r in STATUS_RANK.items() if r == rank)
            ins = dict(ins)
            ins["status"] = status
            ins["attestations"] = sorted(a.values(), key=lambda x: x["node"])
            ins["status_reason"] = exp_reason if exp_rank == rank else ""
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
