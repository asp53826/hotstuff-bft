"""Cryptography and certificate validation.

Under Byzantine faults, `QC.verify` is the only thing standing between the
protocol and a replica that claims a quorum it never had. Everything above it
assumes it works, so it is tested against forgery, reuse, padding, and every
other shortcut an adversary would actually take.
"""

import pytest

from hs.core import (GENESIS, GENESIS_HASH, GENESIS_QC, Block, BlockStore,
                     KeyRing, QC)

REPLICAS = [f"r{i}" for i in range(7)]
QUORUM = 5   # n - f with n = 7, f = 2


def keys():
    return KeyRing(REPLICAS)


def good_qc(k, block_hash=b"\x11" * 32, view=3, signers=None):
    signers = signers or REPLICAS[:QUORUM]
    probe = QC(block_hash, view, 1, ())
    msg = probe.message()
    return QC(block_hash, view, 1, tuple((r, k.sign(r, msg)) for r in signers))


# ---- signatures -----------------------------------------------------------

def test_a_signature_verifies_under_its_own_key():
    k = keys()
    sig = k.sign("r0", b"hello")
    assert k.verify("r0", b"hello", sig)


def test_a_signature_does_not_verify_under_another_key():
    """The one thing the adversary may not do."""
    k = keys()
    sig = k.sign("r0", b"hello")
    for other in REPLICAS[1:]:
        assert not k.verify(other, b"hello", sig)


def test_a_signature_is_bound_to_its_message():
    k = keys()
    sig = k.sign("r0", b"hello")
    assert not k.verify("r0", b"goodbye", sig)


def test_signing_is_deterministic():
    """A run has to be a pure function of its seed, so nothing here may use
    randomness."""
    assert keys().sign("r3", b"x") == keys().sign("r3", b"x")


def test_an_unknown_replica_cannot_sign():
    k = keys()
    assert k.sign("nobody", b"x") == b""
    assert not k.verify("nobody", b"x", b"anything")


# ---- quorum certificates --------------------------------------------------

def test_a_real_quorum_verifies():
    k = keys()
    assert good_qc(k).verify(k, QUORUM)


def test_too_few_signatures_is_rejected():
    k = keys()
    qc = good_qc(k, signers=REPLICAS[:QUORUM - 1])
    assert not qc.verify(k, QUORUM)


def test_forged_signatures_are_rejected():
    """Padding a genuine signature out to a quorum with garbage. This is
    exactly what the `forge_qc` adversary sends."""
    k = keys()
    real = good_qc(k, signers=["r0"])
    padded = QC(real.block_hash, real.view, real.height,
                real.sigs + tuple((r, b"\x00" * 16) for r in REPLICAS[1:QUORUM]))
    assert len(padded.sigs) >= QUORUM
    assert not padded.verify(k, QUORUM)


def test_the_same_signer_cannot_be_counted_twice():
    """Otherwise one cooperative replica is a quorum."""
    k = keys()
    one = good_qc(k, signers=["r0"])
    stuffed = QC(one.block_hash, one.view, one.height, one.sigs * QUORUM)
    assert len(stuffed.sigs) >= QUORUM
    assert not stuffed.verify(k, QUORUM)


def test_a_certificate_cannot_be_moved_to_another_block():
    k = keys()
    qc = good_qc(k, block_hash=b"\xaa" * 32)
    moved = QC(b"\xbb" * 32, qc.view, qc.height, qc.sigs)
    assert not moved.verify(k, QUORUM)


def test_a_certificate_cannot_be_moved_to_another_view():
    k = keys()
    qc = good_qc(k, view=3)
    replayed = QC(qc.block_hash, 9, qc.height, qc.sigs)
    assert not replayed.verify(k, QUORUM)


def test_an_empty_certificate_is_rejected():
    k = keys()
    assert not QC(b"\x11" * 32, 1, 1, ()).verify(k, QUORUM)


# ---- blocks ---------------------------------------------------------------

def test_the_block_hash_commits_to_its_contents():
    base = Block(GENESIS_HASH, 1, 1, ("a",), GENESIS_QC, "r0")
    for altered in (
        Block(b"\x99" * 32, 1, 1, ("a",), GENESIS_QC, "r0"),
        Block(GENESIS_HASH, 2, 1, ("a",), GENESIS_QC, "r0"),
        Block(GENESIS_HASH, 1, 2, ("a",), GENESIS_QC, "r0"),
        Block(GENESIS_HASH, 1, 1, ("b",), GENESIS_QC, "r0"),
        Block(GENESIS_HASH, 1, 1, ("a",), QC(b"\x77" * 32, 5, 1, ()), "r0"),
    ):
        assert altered.hash != base.hash


def test_the_hash_is_stable():
    a = Block(GENESIS_HASH, 1, 1, ("a",), GENESIS_QC, "r0")
    b = Block(GENESIS_HASH, 1, 1, ("a",), GENESIS_QC, "r0")
    assert a.hash == b.hash


# ---- ancestry -------------------------------------------------------------

def chain(store, n):
    prev = GENESIS_HASH
    out = []
    for i in range(1, n + 1):
        b = Block(prev, i, i, ("c", i), GENESIS_QC, "r0")
        store.put(b)
        out.append(b)
        prev = b.hash
    return out


def test_extends_follows_the_parent_chain():
    s = BlockStore()
    blocks = chain(s, 5)
    assert s.extends(blocks[-1].hash, GENESIS_HASH)
    assert s.extends(blocks[-1].hash, blocks[0].hash)
    assert not s.extends(blocks[0].hash, blocks[-1].hash)


def test_extends_stops_on_a_missing_parent():
    s = BlockStore()
    orphan = Block(b"\x55" * 32, 4, 4, ("x",), GENESIS_QC, "r0")
    s.put(orphan)
    assert not s.extends(orphan.hash, GENESIS_HASH)


def test_extends_does_not_loop_on_a_self_parent():
    """A Byzantine proposer can send a block claiming to be its own parent. An
    unbounded walk here is a denial of service even though it is not a safety
    break."""
    s = BlockStore()
    weird = Block(b"\x33" * 32, 1, 1, ("x",), GENESIS_QC, "r0")
    s.blocks[b"\x33" * 32] = weird
    assert not s.extends(b"\x33" * 32, GENESIS_HASH)


def test_conflicting_branches_do_not_extend_each_other():
    s = BlockStore()
    a = Block(GENESIS_HASH, 1, 1, ("a",), GENESIS_QC, "r0")
    b = Block(GENESIS_HASH, 1, 1, ("b",), GENESIS_QC, "r0")
    s.put(a)
    s.put(b)
    assert a.hash != b.hash
    assert not s.extends(a.hash, b.hash)
    assert not s.extends(b.hash, a.hash)


def test_chain_to_returns_genesis_first():
    s = BlockStore()
    blocks = chain(s, 4)
    got = s.chain_to(blocks[-1].hash)
    assert got[0].hash == GENESIS_HASH
    assert [b.height for b in got] == [0, 1, 2, 3, 4]
