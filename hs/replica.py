"""Chained HotStuff, honest implementation.

Three rules do all the work, and it is worth being precise about which one
provides what, because the mutation catalogue removes them one at a time and
they fail differently.

**The safety rule.** A replica votes for a block only if the block extends the
block it is locked on, *or* the block's justifying QC is from a later view than
the lock. The first clause is safety: you cannot vote for something conflicting
with what you promised. The second is liveness: without it, a replica locked on
a block that the rest of the network abandoned would never vote again. Deleting
the first clause breaks safety directly. Deleting the second breaks nothing that
a safety checker can see, and hangs the cluster.

**The lock rule.** On seeing a QC for a block whose parent also has a QC - a
two-chain - the replica locks on the parent. This is the commitment that makes
the safety rule bite.

**The commit rule.** Three consecutive QCs on blocks that are directly linked -
b'' <- b' <- b, each the immediate parent of the next - commit b. The
"directly linked" part is essential: a chain of QCs with a gap does not commit,
because a gap means some view failed to reach a quorum and an equivocating
proposer may have gotten a conflicting block certified in it.

Everything here is checked before it is believed. A QC arriving from any replica
is verified against the key ring and the quorum size before being used, because
under Byzantine faults a message is a claim rather than a fact.
"""

from __future__ import annotations

from dataclasses import dataclass

from dst.core import Sim
from dst.disk import Disk
from dst.net import Message, Network

from .core import (GENESIS, GENESIS_HASH, GENESIS_QC, Block, BlockStore, KeyRing,
                   QC, u64)


@dataclass
class HotStuffConfig:
    view_timeout: int = 260
    """Virtual ms a replica waits for progress before moving to the next view.
    Chained HotStuff needs this to be longer than a round trip or the cluster
    outruns its own messages and never certifies anything."""
    proposal_delay: int = 5
    persist: bool = True


class Replica:
    def __init__(self, rid: str, peers: list[str], sim: Sim, net: Network,
                 disk: Disk, keys: KeyRing, observer, apply_fn,
                 cfg: HotStuffConfig | None = None,
                 mutations: frozenset[str] = frozenset()):
        self.id = rid
        self.peers = sorted(peers)
        self.n = len(self.peers)
        self.f = (self.n - 1) // 3
        self.sim = sim
        self.net = net
        self.disk = disk
        self.keys = keys
        self.obs = observer
        self.apply_fn = apply_fn
        self.cfg = cfg or HotStuffConfig()
        self.mut = mutations

        self.store = BlockStore()
        self.view = 1
        self.locked = GENESIS_QC
        self.high_qc = GENESIS_QC
        self.last_voted_view = 0
        self.committed_height = 0
        self.committed: list[Block] = []

        self.votes: dict[bytes, dict[str, bytes]] = {}
        self.pending: list[tuple] = []
        self.alive = True
        self._view_gen = 0

        net.register(rid, self.handle)
        self._arm_view_timer()

    # ---- quorum ------------------------------------------------------------

    def quorum(self) -> int:
        if "weak_quorum" in self.mut:
            return self.n - self.f - 1
        return self.n - self.f          # 2f+1 when n = 3f+1

    def leader_of(self, view: int) -> str:
        return self.peers[view % self.n]

    # ---- timers ------------------------------------------------------------

    def _arm_view_timer(self) -> None:
        self._view_gen += 1
        gen = self._view_gen
        jitter = self.sim.rng.between(0, self.cfg.view_timeout // 4)
        self.sim.after(self.cfg.view_timeout + jitter,
                       lambda: self._view_timeout(gen), f"{self.id}:view")

    def _view_timeout(self, gen: int) -> None:
        if not self.alive or gen != self._view_gen:
            return
        self.advance_view(self.view + 1)

    def advance_view(self, view: int) -> None:
        if view <= self.view:
            return
        self.view = view
        self.obs.views_entered += 1
        self._arm_view_timer()
        # Tell the new leader what the highest certificate we know is. That is
        # the whole of view change in chained HotStuff: no separate new-view
        # protocol, just the QC riding along.
        leader = self.leader_of(view)
        self.net.send(self.id, leader, "NewView",
                      {"view": view, "qc": self.high_qc, "from": self.id})
        if leader == self.id:
            self.sim.after(self.cfg.proposal_delay, self._maybe_propose,
                           f"{self.id}:propose")

    # ---- proposing ---------------------------------------------------------

    def next_command(self):
        return self.obs.next_command(self.id, self.view)

    def _maybe_propose(self) -> None:
        if not self.alive or self.leader_of(self.view) != self.id:
            return
        self.propose(self.next_command())

    def propose(self, cmd) -> Block | None:
        if not self.alive:
            return None
        parent_block = self.store.get(self.high_qc.block_hash)
        if parent_block is None:
            return None
        block = Block(parent=self.high_qc.block_hash,
                      height=parent_block.height + 1,
                      view=self.view, cmd=cmd, justify=self.high_qc,
                      proposer=self.id)
        self.store.put(block)
        self.obs.proposals += 1
        self.obs.record_proposal(self.id, self.view, block)
        for p in self.peers:
            self.net.send(self.id, p, "Proposal", {"block": block})
        return block

    # ---- message handling --------------------------------------------------

    def handle(self, m: Message) -> None:
        if not self.alive:
            return
        if m.kind == "Proposal":
            self._on_proposal(m.body["block"], m.src)
        elif m.kind == "Vote":
            self._on_vote(m.body, m.src)
        elif m.kind == "NewView":
            self._on_new_view(m.body)

    def _valid_qc(self, qc: QC) -> bool:
        if qc.block_hash == GENESIS_HASH:
            # Genesis carries no signatures, so it is exempt from the quorum
            # check - but only at view 0. An earlier version returned True for
            # any QC naming genesis, which let an adversary attach an arbitrary
            # view to an unsigned certificate. The safety rule's liveness clause
            # is `qc.view > lockedQC.view`, so a genesis QC claiming view 999
            # made every honest replica willing to vote for a block conflicting
            # with everything it was locked on. Found at seed 182 - see BUGS.md.
            if "genesis_any_view" in self.mut:
                return True
            return qc.view == 0 and not qc.sigs
        if "skip_qc_check" in self.mut:
            return True
        return qc.verify(self.keys, self.quorum())

    def _on_new_view(self, body) -> None:
        qc = body["qc"]
        if not self._valid_qc(qc):
            self.obs.rejected_qc += 1
            return
        self._update_qc(qc)
        if body["view"] > self.view:
            self.advance_view(body["view"])
        elif self.leader_of(self.view) == self.id:
            self.sim.after(self.cfg.proposal_delay, self._maybe_propose,
                           f"{self.id}:propose")

    def safe_node(self, block: Block) -> bool:
        """The rule the whole protocol rests on."""
        qc = block.justify
        safety = self.store.extends(block.parent, self.locked.block_hash) or \
            block.parent == self.locked.block_hash
        liveness = qc.view > self.locked.view

        if "no_safety_rule" in self.mut:
            return True
        if "no_liveness_rule" in self.mut:
            return safety
        return safety or liveness

    def _on_proposal(self, block: Block, src: str) -> None:
        if block.proposer != src and "trust_forwarded_proposals" not in self.mut:
            # A proposal is only valid from the replica that made it. Without
            # this, any replica can replay somebody else's proposal into a view
            # where it does not belong.
            self.obs.rejected_proposal += 1
            return
        if not self._valid_qc(block.justify):
            self.obs.rejected_qc += 1
            return
        if block.parent != block.justify.block_hash:
            self.obs.rejected_proposal += 1
            return
        if not self.store.has(block.parent):
            self.pending.append((block, src))
            return

        self.store.put(block)
        self._update_qc(block.justify)

        if block.view > self.view:
            self.advance_view(block.view)

        already_voted = block.view <= self.last_voted_view
        if "vote_twice_per_view" in self.mut:
            already_voted = False

        if already_voted or self.leader_of(block.view) != block.proposer:
            self._drain_pending()
            return
        if not self.safe_node(block):
            self.obs.refused_unsafe += 1
            self._drain_pending()
            return

        self.last_voted_view = block.view
        qc = QC(block.hash, block.view, block.height, ())
        sig = self.keys.sign(self.id, qc.message())
        leader = self.leader_of(block.view + 1)

        def send_vote():
            if self.alive:
                self.net.send(self.id, leader, "Vote", {
                    "block_hash": block.hash, "view": block.view,
                    "height": block.height, "sig": sig, "voter": self.id})

        if self.cfg.persist and "unpersisted_vote" not in self.mut:
            # The vote is a promise. Promising before the promise is durable is
            # the Byzantine-setting version of the same bug crash-fault systems
            # have, and it is in the catalogue for that reason.
            self.disk.put("state", self._encode_state(block.view))
            self.disk.fsync(send_vote)
        else:
            send_vote()

        self._drain_pending()

    def _drain_pending(self) -> None:
        if not self.pending:
            return
        ready = [(b, s) for b, s in self.pending if self.store.has(b.parent)]
        if not ready:
            return
        self.pending = [(b, s) for b, s in self.pending
                        if not self.store.has(b.parent)]
        for b, s in ready:
            self._on_proposal(b, s)

    def _on_vote(self, body, src: str) -> None:
        if body["voter"] != src:
            return
        bh = body["block_hash"]
        probe = QC(bh, body["view"], body["height"], ())
        if not self.keys.verify(src, probe.message(), body["sig"]):
            self.obs.rejected_vote += 1
            return

        bucket = self.votes.setdefault((bh, body["view"]), {})
        bucket[src] = body["sig"]
        if len(bucket) < self.quorum():
            return

        qc = QC(bh, body["view"], body["height"],
                tuple(sorted(bucket.items())))
        self.obs.qcs_formed += 1
        self.obs.record_qc(qc, body["height"])
        self._update_qc(qc)

        if self.leader_of(self.view) == self.id:
            self.sim.after(self.cfg.proposal_delay, self._maybe_propose,
                           f"{self.id}:propose")

    # ---- the lock and commit rules ----------------------------------------

    def _update_qc(self, qc: QC) -> None:
        if qc.block_hash != GENESIS_HASH and not self.store.has(qc.block_hash):
            return
        if qc.view > self.high_qc.view:
            self.high_qc = qc

        block = self.store.get(qc.block_hash)
        if block is None or block.height == 0:
            return

        parent = self.store.get(block.parent)
        if parent is None:
            return

        # two-chain: lock on the parent
        if parent.height > 0 and parent.view > self.locked.view:
            if "no_lock_rule" not in self.mut:
                self.locked = block.justify

        # Three-chain: commit the grandparent. Two conditions, and both are
        # load-bearing.
        #
        # Structurally direct - each block is the immediate parent of the next,
        # and each justifies the one below it.
        #
        # *Consecutive views* - the three blocks were certified in views v-2,
        # v-1, v with no gap. This is the one that is easy to leave out and
        # that the safety argument actually rests on. A gap means some view
        # produced no certificate on this branch, and a conflicting block can
        # have been certified in exactly that view; committing across the gap
        # then lets two branches each complete a structurally-direct chain and
        # both commit. Found at seed 182 - see BUGS.md.
        grand = self.store.get(parent.parent)
        if grand is None or grand.height == 0:
            return
        direct = (block.parent == parent.hash and parent.parent == grand.hash
                  and parent.justify.block_hash == grand.hash)
        consecutive = (block.view == parent.view + 1
                       and parent.view == grand.view + 1)
        if "allow_gaps_in_chain" in self.mut:
            consecutive = True
        if direct and consecutive:
            self._commit(grand)

    def _commit(self, block: Block) -> None:
        if block.height <= self.committed_height:
            return
        chain = self.store.chain_to(block.hash)
        for b in chain:
            if b.height <= self.committed_height or b.height == 0:
                continue
            self.committed_height = b.height
            self.committed.append(b)
            self.obs.record_commit(self.id, b)
            if b.cmd is not None:
                self.apply_fn(self.id, b.height, b)

    # ---- persistence -------------------------------------------------------

    def _encode_state(self, voted_view: int) -> bytes:
        return (u64(self.view) + u64(voted_view) + u64(self.locked.view)
                + self.locked.block_hash + u64(self.high_qc.view)
                + self.high_qc.block_hash)

    # ---- lifecycle ---------------------------------------------------------

    def crash(self) -> None:
        self.alive = False
        self.disk.crash()
        self.net.crash(self.id)
        self.votes.clear()
        self.pending.clear()

    def restart(self) -> None:
        self.alive = True
        self.net.restart(self.id)
        self.last_voted_view = max(self.last_voted_view, self.view)
        self._arm_view_timer()
