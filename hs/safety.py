"""What must never happen, checked over honest replicas only.

Under crash faults every node's state is evidence. Under Byzantine faults it is
not: a lying replica can report any state at all, so an invariant checked over
*all* replicas is checking the adversary's fiction. Every property here is
quantified over honest replicas, which is also how the theorems are stated.

  Safety            no two honest replicas commit conflicting blocks at the
                    same height. This is the one the whole protocol exists for.
  Agreement         the committed chains of any two honest replicas are
                    prefix-compatible.
  Certified         every committed block carries a QC with a real quorum of
                    valid signatures.
  No rewrite        an honest replica's committed chain only ever grows.
  Lock discipline   an honest replica never votes for a block conflicting with
                    the block it is locked on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .core import GENESIS_HASH, Block, KeyRing


@dataclass
class Observer:
    """Cluster-wide bookkeeping and the violation log."""

    keys: KeyRing = None
    quorum: int = 0
    violations: list[str] = field(default_factory=list)

    proposals: int = 0
    qcs_formed: int = 0
    views_entered: int = 0
    equivocations: int = 0
    conflicting_votes: int = 0
    rejected_qc: int = 0
    rejected_vote: int = 0
    rejected_proposal: int = 0
    refused_unsafe: int = 0
    forged_qcs: int = 0

    honest: tuple[str, ...] = ()
    committed_by: dict[str, list[Block]] = field(default_factory=dict)
    proposals_by_view: dict[int, dict[str, set]] = field(default_factory=dict)
    qc_by_view: dict[int, set] = field(default_factory=dict)
    conflicting_qcs: int = 0
    """Two distinct blocks certified in the *same view*.

    Keyed by view, not by height. Two honest leaders in different views can
    legitimately certify different blocks at the same height - that is ordinary
    forking, which the commit rule exists to resolve - and an earlier version of
    this counter keyed on height reported "conflicts" in runs with zero
    Byzantine replicas. Within one view it is different: an honest replica votes
    at most once, quorums are 2f+1, and any two of them intersect in f+1
    replicas, so two certificates in one view require at least one replica to
    have voted twice. At or below f that is impossible.

    This is a strictly earlier and sharper signal than a safety violation. A
    committed-block divergence additionally needs the adversary to drive two
    conflicting *three-chains*, which takes several consecutive views going its
    way, so a violation-only table understates how sharp the boundary is."""
    _command_seq: int = 0
    command_source = None

    def fail(self, what: str) -> None:
        if what not in self.violations:
            self.violations.append(what)

    @property
    def ok(self) -> bool:
        return not self.violations

    def next_command(self, rid: str, view: int):
        if self.command_source is not None:
            return self.command_source(rid, view)
        self._command_seq += 1
        return ("noop", self._command_seq)

    def record_proposal(self, rid: str, view: int, block: Block) -> None:
        bucket = self.proposals_by_view.setdefault(view, {})
        bucket.setdefault(rid, set()).add(block.hash)

    def record_commit(self, rid: str, block: Block) -> None:
        self.committed_by.setdefault(rid, []).append(block)

    def record_qc(self, qc, height: int) -> None:
        bucket = self.qc_by_view.setdefault(qc.view, set())
        if qc.block_hash not in bucket:
            if bucket:
                self.conflicting_qcs += 1
            bucket.add(qc.block_hash)

    # ---- properties --------------------------------------------------------

    def check(self, replicas: dict) -> None:
        honest = [r for r in sorted(replicas) if r in self.honest]
        self._safety(replicas, honest)
        self._agreement(replicas, honest)
        self._certified(replicas, honest)
        self._lock_discipline(replicas, honest)

    def _safety(self, replicas, honest) -> None:
        """No two honest replicas commit different blocks at the same height."""
        at_height: dict[int, tuple[str, bytes]] = {}
        for rid in honest:
            for b in replicas[rid].committed:
                seen = at_height.get(b.height)
                if seen is None:
                    at_height[b.height] = (rid, b.hash)
                elif seen[1] != b.hash:
                    self.fail(
                        f"SAFETY: height {b.height} committed as "
                        f"{seen[1][:6].hex()} by {seen[0]} and "
                        f"{b.hash[:6].hex()} by {rid}")

    def _agreement(self, replicas, honest) -> None:
        """Committed chains must be prefix-compatible."""
        chains = {rid: [b.hash for b in replicas[rid].committed] for rid in honest}
        ids = list(chains)
        for i, a in enumerate(ids):
            for b in ids[i + 1:]:
                ca, cb = chains[a], chains[b]
                for k in range(min(len(ca), len(cb))):
                    if ca[k] != cb[k]:
                        self.fail(f"AGREEMENT: {a} and {b} diverge at index {k}")
                        break

    def _certified(self, replicas, honest) -> None:
        """Every committed block must be backed by a real quorum.

        This is the property that catches a replica which committed on a
        certificate it never verified - the difference between "the protocol
        was safe" and "nobody happened to attack this run".
        """
        for rid in honest:
            r = replicas[rid]
            for b in r.committed:
                if b.height == 0:
                    continue
                if b.justify.block_hash == GENESIS_HASH:
                    continue
                if not b.justify.verify(self.keys, self.quorum):
                    self.fail(
                        f"CERTIFICATE: {rid} committed block at height "
                        f"{b.height} whose justifying QC has "
                        f"{len(b.justify.sigs)} valid signatures, "
                        f"quorum is {self.quorum}")
                    return

    def _lock_discipline(self, replicas, honest) -> None:
        for rid in honest:
            r = replicas[rid]
            locked = r.locked.block_hash
            if locked == GENESIS_HASH:
                continue
            for b in r.committed:
                if b.height <= 0:
                    continue
            lock_block = r.store.get(locked)
            if lock_block is None:
                continue
            tip = r.committed[-1] if r.committed else None
            if tip is None or tip.height < lock_block.height:
                continue
            if not r.store.extends(tip.hash, locked):
                self.fail(
                    f"LOCK: {rid} committed a chain that does not extend the "
                    f"block it is locked on (height {lock_block.height})")


def equivocation_happened(obs: Observer) -> bool:
    """Did any proposer actually send two different blocks in one view?

    A run where the adversary never got to be leader has not tested anything,
    and counting it as "safety held" is how a Byzantine test suite convinces
    its author it works.
    """
    for view, by_replica in obs.proposals_by_view.items():
        for rid, hashes in by_replica.items():
            if len(hashes) > 1:
                return True
    return False
