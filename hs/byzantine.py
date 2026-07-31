"""Replicas that lie.

A Byzantine replica here is not a broken honest replica. It runs different code,
chosen to attack a specific part of the protocol, and it is bound by exactly one
constraint: it cannot forge a signature under another replica's key. Everything
else is permitted - equivocating, voting for conflicting blocks, proposing out of
turn, replaying stale certificates, staying silent at the worst moment.

The strategies below are not decoration. `equivocate` combined with
`vote_conflicting` is the attack HotStuff's quorum intersection argument exists
to stop: with n = 3f+1 and quorums of 2f+1, any two quorums share at least f+1
replicas, so at least one honest replica would have to vote for both branches -
which the safety rule forbids. Take the adversary to f+1 and the arithmetic
flips, and the attack should succeed.

`scripts/threshold_study.py` runs exactly that comparison, because "safety held
over N seeds" is worth nothing unless the same adversary demonstrably breaks
safety when the threshold is exceeded. Otherwise the result is a statement about
a weak adversary, not about the protocol.
"""

from __future__ import annotations

from .core import GENESIS_HASH, Block, QC
from .replica import Replica

STRATEGIES = (
    "silent",
    "equivocate",
    "vote_conflicting",
    "stale_qc",
    "fork_from_ancestor",
    "propose_out_of_turn",
    "withhold_qc",
    "double_vote",
    "forge_qc",
    "everything",
)


class ByzantineReplica(Replica):
    """An adversarial replica. `strategy` selects what it does wrong."""

    def __init__(self, *args, strategy: str = "equivocate", **kwargs):
        super().__init__(*args, **kwargs)
        self.strategy = strategy
        self.byzantine = True
        self.equivocations = 0
        self.conflicting_votes = 0
        # Indexed rather than rescanned. Equivocation doubles the block store
        # every view it happens in, so a linear scan per proposal is quadratic
        # in the number of blocks and the run stops terminating well before it
        # stops being interesting.
        self._qc_index: dict[bytes, QC] = {}
        self._oldest: QC | None = None

    def _note_qc(self, qc: QC) -> None:
        if qc.block_hash == GENESIS_HASH:
            return
        prev = self._qc_index.get(qc.block_hash)
        if prev is None or qc.view < prev.view:
            self._qc_index[qc.block_hash] = qc
        if self._oldest is None or qc.view < self._oldest.view:
            self._oldest = qc

    def _update_qc(self, qc: QC) -> None:
        self._note_qc(qc)
        super()._update_qc(qc)

    PASSIVE = ("silent", "withhold_qc")
    """Attacks that consist of not doing something. `everything` deliberately
    excludes them: a replica that is silent cannot also equivocate, so folding
    them in produces the *weakest* adversary rather than the strongest, and a
    threshold study run against it would report that safety held for a reason
    that has nothing to do with the protocol."""

    def does(self, what: str) -> bool:
        if self.strategy == "everything":
            return what not in self.PASSIVE
        return self.strategy == what

    # ---- proposing ---------------------------------------------------------

    def _maybe_propose(self) -> None:
        if not self.alive:
            return
        if self.does("silent"):
            return
        if self.leader_of(self.view) != self.id and not self.does("propose_out_of_turn"):
            return
        self.propose(self.next_command())

    def propose(self, cmd) -> Block | None:
        if not self.alive or self.does("silent"):
            return None

        justify = self.high_qc
        if self.does("forge_qc"):
            # A certificate that was never collected: one real self-signature
            # padded out with garbage attributed to other replicas. An honest
            # replica must reject it on the signature check alone. Without this
            # attack in the adversary's repertoire the `skip_qc_check` mutant is
            # unreachable, and the harness would report "not caught" about a
            # rule that is genuinely load-bearing.
            target = self.high_qc.block_hash
            fake = [(self.id, self.keys.sign(self.id, QC(
                target, self.view, 0, ()).message()))]
            for p in self.peers:
                if p != self.id and len(fake) < self.quorum():
                    fake.append((p, b"\x00" * 16))
            justify = QC(target, self.view, self.high_qc.height,
                         tuple(sorted(fake)))
            self.obs.forged_qcs += 1
        elif self.does("stale_qc"):
            # Reach back for an older certificate. Honest replicas should
            # refuse to vote on this via the safety rule.
            justify = self._oldest_known_qc()

        parent_hash = justify.block_hash
        if self.does("fork_from_ancestor"):
            parent_hash = self._ancestor_of(justify.block_hash, back=2)
            justify = self._qc_for(parent_hash) or justify
            parent_hash = justify.block_hash

        parent = self.store.get(parent_hash)
        if parent is None:
            return None

        first = Block(parent=parent_hash, height=parent.height + 1,
                      view=self.view, cmd=cmd, justify=justify,
                      proposer=self.id)
        self.store.put(first)
        self.obs.proposals += 1
        self.obs.record_proposal(self.id, self.view, first)

        if not self.does("equivocate"):
            for p in self.peers:
                self.net.send(self.id, p, "Proposal", {"block": first})
            return first

        # Two conflicting blocks in the same view, each sent to a different half
        # of the cluster. Both are correctly signed and correctly formed; they
        # simply cannot both be committed.
        forked = ("byz", self.id, self.view, "fork")
        second = Block(parent=parent_hash, height=parent.height + 1,
                       view=self.view, cmd=forked, justify=justify,
                       proposer=self.id)
        self.store.put(second)
        self.equivocations += 1
        self.obs.equivocations += 1
        self.obs.record_proposal(self.id, self.view, second)

        order = self.sim.rng.shuffled(self.peers)
        half = len(order) // 2
        for p in order[:half]:
            self.net.send(self.id, p, "Proposal", {"block": first})
        for p in order[half:]:
            self.net.send(self.id, p, "Proposal", {"block": second})
        return first

    # ---- voting ------------------------------------------------------------

    def _on_proposal(self, block: Block, src: str) -> None:
        if self.does("silent"):
            return
        if not (self.does("vote_conflicting") or self.does("double_vote")):
            super()._on_proposal(block, src)
            return

        # Vote for anything, including a second block in a view already voted
        # in. This is the vote that a correct replica refuses to cast, and the
        # reason quorum intersection is stated over *honest* replicas.
        if not self.store.has(block.parent) and block.parent != GENESIS_HASH:
            return
        self.store.put(block)
        if block.view <= self.last_voted_view:
            self.conflicting_votes += 1
            self.obs.conflicting_votes += 1
        self.last_voted_view = max(self.last_voted_view, block.view)

        qc = QC(block.hash, block.view, block.height, ())
        sig = self.keys.sign(self.id, qc.message())
        for target in ({self.leader_of(block.view + 1), block.proposer}
                       if self.does("double_vote")
                       else {self.leader_of(block.view + 1)}):
            self.net.send(self.id, target, "Vote", {
                "block_hash": block.hash, "view": block.view,
                "height": block.height, "sig": sig, "voter": self.id})

    def _on_vote(self, body, src: str) -> None:
        if self.does("silent") or self.does("withhold_qc"):
            # Collect votes and never form a certificate. A liveness attack, and
            # by design one that safety checking should not react to at all.
            return
        super()._on_vote(body, src)

    def handle(self, m):
        if self.does("silent"):
            return
        super().handle(m)

    # ---- helpers -----------------------------------------------------------

    def _oldest_known_qc(self) -> QC:
        return self._oldest or self.high_qc

    def _ancestor_of(self, h: bytes, back: int) -> bytes:
        cur = h
        for _ in range(back):
            b = self.store.get(cur)
            if b is None or cur == GENESIS_HASH:
                break
            cur = b.parent
        return cur

    def _qc_for(self, h: bytes) -> QC | None:
        return self._qc_index.get(h)
