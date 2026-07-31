"""Blocks, quorum certificates, and the signatures that make them mean anything.

The move from crash faults to Byzantine faults is not "add more failure cases".
It changes what a message *is*. Under crash faults a message you received is
true, because the only thing a broken node can do is stop. Under Byzantine
faults a message is a claim, and the only reason to believe it is that it
carries evidence you can check yourself.

So signatures here are real HMAC-SHA256, not a boolean flag saying "this is
signed". A Byzantine replica gets its own key and can sign anything it likes -
including two conflicting blocks in the same view, which is exactly the attack
worth testing - and cannot produce a signature under anybody else's key. Modelling
signatures as a flag would let the adversary forge, which makes the protocol
trivially broken and the result meaningless; modelling them as unforgeable-by-
assumption without any check would let *my own bugs* pass a QC that never had
the votes.

Block hashes commit to the parent, the height, the command and the justifying
QC, so a Byzantine node cannot swap a block's contents under a certificate that
was collected for something else.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

GENESIS_HASH = b"\x00" * 32


def _h(*parts: bytes) -> bytes:
    d = hashlib.sha256()
    for p in parts:
        d.update(len(p).to_bytes(8, "big"))
        d.update(p)
    return d.digest()


def u64(n: int) -> bytes:
    return int(n).to_bytes(8, "big", signed=False)


class KeyRing:
    """One secret key per replica.

    Keys are derived from the replica id and a run-wide salt, so a run stays a
    pure function of its seed. Real deployments would use threshold signatures
    and aggregate a QC into one object; that is a size optimisation and changes
    nothing about what is being verified here.
    """

    def __init__(self, replicas: list[str], salt: bytes = b"hotstuff"):
        self.keys = {r: _h(salt, r.encode()) for r in sorted(replicas)}

    def sign(self, replica: str, message: bytes) -> bytes:
        key = self.keys.get(replica)
        if key is None:
            return b""
        return hmac.new(key, message, hashlib.sha256).digest()[:16]

    def verify(self, replica: str, message: bytes, sig: bytes) -> bool:
        key = self.keys.get(replica)
        if key is None or not sig:
            return False
        want = hmac.new(key, message, hashlib.sha256).digest()[:16]
        return hmac.compare_digest(want, sig)


@dataclass(frozen=True)
class QC:
    """A quorum certificate: n-f signatures on the same (block, view).

    `verify` is the only thing standing between the protocol and an adversary
    who claims a quorum it never had, so it checks three things independently:
    every signature is valid under its claimed signer's key, the signers are
    distinct, and there are enough of them.
    """

    block_hash: bytes
    view: int
    height: int
    sigs: tuple[tuple[str, bytes], ...] = ()

    def message(self) -> bytes:
        return _h(b"vote", self.block_hash, u64(self.view))

    def verify(self, keys: KeyRing, quorum: int) -> bool:
        seen = set()
        msg = self.message()
        for replica, sig in self.sigs:
            if replica in seen:
                return False          # the same signer counted twice
            if not keys.verify(replica, msg, sig):
                return False
            seen.add(replica)
        return len(seen) >= quorum

    def __repr__(self) -> str:
        return (f"QC(view={self.view} h={self.height} "
                f"blk={self.block_hash[:4].hex()} sigs={len(self.sigs)})")


GENESIS_QC = QC(GENESIS_HASH, 0, 0, ())


@dataclass(frozen=True)
class Block:
    parent: bytes
    height: int
    view: int
    cmd: tuple | None
    justify: QC
    proposer: str

    @property
    def hash(self) -> bytes:
        # Genesis is identified by a fixed constant rather than by a digest,
        # because every replica has to agree on it without having received it.
        # Leaving it to the generic hash means `GENESIS.hash != GENESIS_HASH`,
        # so the block stored under the well-known key reports a different
        # identity than the key - which silently breaks any ancestry check that
        # compares a block's own hash against a store key.
        if self.height == 0 and self.parent == GENESIS_HASH and self.cmd is None:
            return GENESIS_HASH
        return _h(b"block", self.parent, u64(self.height), u64(self.view),
                  repr(self.cmd).encode(), self.justify.block_hash,
                  u64(self.justify.view))

    def __repr__(self) -> str:
        return (f"Block(h={self.height} v={self.view} "
                f"{self.hash[:4].hex()} <- {self.parent[:4].hex()})")


GENESIS = Block(GENESIS_HASH, 0, 0, None, GENESIS_QC, "genesis")


@dataclass
class BlockStore:
    """Every block this replica has seen, by hash, plus ancestry queries.

    A replica cannot evaluate the safety rule without walking a block's ancestry,
    and under a Byzantine proposer the ancestry may be missing, cyclic, or
    absurdly long. `extends` bounds its walk for that reason: an adversary that
    can make an honest replica loop forever has a denial of service even if it
    cannot break safety.
    """

    blocks: dict[bytes, Block] = field(default_factory=dict)

    def __post_init__(self):
        self.blocks[GENESIS_HASH] = GENESIS

    def put(self, b: Block) -> None:
        self.blocks.setdefault(b.hash, b)

    def get(self, h: bytes) -> Block | None:
        return self.blocks.get(h)

    def has(self, h: bytes) -> bool:
        return h in self.blocks

    def extends(self, descendant: bytes, ancestor: bytes,
                limit: int = 10_000) -> bool:
        cur = descendant
        for _ in range(limit):
            if cur == ancestor:
                return True
            b = self.blocks.get(cur)
            if b is None or cur == GENESIS_HASH:
                return False
            if b.parent == cur:
                return False          # self-parent; a malformed block
            cur = b.parent
        return False

    def chain_to(self, h: bytes, limit: int = 10_000) -> list[Block]:
        out = []
        cur = h
        for _ in range(limit):
            b = self.blocks.get(cur)
            if b is None:
                break
            out.append(b)
            if cur == GENESIS_HASH:
                break
            cur = b.parent
        return list(reversed(out))
