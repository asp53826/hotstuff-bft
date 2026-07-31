# Bugs

Two real defects the harness found in this HotStuff implementation, and one gap
it found in the adversary that was hiding a third. All three are recorded with
reproducing seeds.

---

## 1. A genesis certificate was accepted at any view

**Found by** seed 182, n=7, f=2 Byzantine replicas running `everything`
**Caught by** Safety: two different blocks committed at height 1
**Fixed in** `hs/replica.py`, `_valid_qc`
**Pinned by** the `genesis_any_view` mutant, which still reproduces at seed 182

The genesis block has no signatures on it, so certificate validation exempted it
from the quorum check:

```python
if qc.block_hash == GENESIS_HASH:
    return True          # wrong
```

That is right about signatures and wrong about everything else. A quorum
certificate carries a *view* as well as a block, and nothing here checked it. A
Byzantine replica could construct `QC(GENESIS_HASH, view=999)` — unsigned,
uncollected, entirely fabricated — and have every honest replica accept it.

What makes that fatal is the liveness clause of the safety rule:

```python
safety  = block extends lockedQC.node
liveness = block.justify.view > lockedQC.view
return safety or liveness
```

`liveness` exists so a replica locked on an abandoned branch can eventually vote
again. Handing it a genesis QC claiming view 999 makes it true unconditionally,
which makes `safeNode` true unconditionally, which means every honest replica
will vote for a block conflicting with the one it is locked on. The lock stops
meaning anything, and two branches can each complete a three-chain and commit.

The diagnostic that gave it away was a dump of the height-1 blocks:

```
h1 block dfaa84dafc view 2 proposer r2 justify view 0
h1 block fc779acf44 view 6 proposer r6 justify view 6   <-- height 1, justify view 6
h1 block 656a66bd9d view 7 proposer r0 justify view 6
```

A height-1 block's parent is genesis, so its justifying QC must be the genesis
QC at view 0. Blocks claiming `justify view 6` at height 1 were impossible, and
the only way to build one was through the exemption.

The fix is one line:

```python
if qc.block_hash == GENESIS_HASH:
    return qc.view == 0 and not qc.sigs
```

Before: 1 safety violation in 300 seeds. After: 0 in 400.

This is a Byzantine-specific bug in the exact sense that matters. Under crash
faults it is unreachable — nobody constructs a certificate that was never
collected — so no amount of partition and crash testing would have found it.

---

## 2. The commit rule did not require consecutive views

**Found by** reasoning while chasing bug 1, confirmed by the `allow_gaps_in_chain` mutant
**Fixed in** `hs/replica.py`, `_update_qc`

The three-chain commit rule checked that the blocks were *structurally* direct —
each the immediate parent of the next, each justifying the one below:

```python
direct = (block.parent == parent.hash and parent.parent == grand.hash)
if direct:
    self._commit(grand)
```

It never checked that the three certificates were formed in **consecutive
views**, which is the condition the safety argument actually rests on. A gap
means some view produced no certificate on this branch, and a conflicting block
may have been certified in exactly that view; committing across the gap lets two
branches each complete a structurally-direct chain.

```python
consecutive = (block.view == parent.view + 1
               and parent.view == grand.view + 1)
```

Honest about the sequence: fixing this did *not* fix seed 182 — bug 1 was the
cause of that one. This was found on the way, and it is a real defect regardless.
It is the kind of condition that is easy to drop because the structural check
looks like it already says the same thing, and on a run without an adversary it
does.

---

## 3. The adversary could not forge certificates, which hid a real check

**Found by** `skip_qc_check` surviving 40 seeds
**Fixed in** `hs/byzantine.py`, the `forge_qc` strategy

`skip_qc_check` removes signature verification on incoming certificates. It is
obviously a safety-critical rule, and the mutation report reported it NOT
CAUGHT.

The rule was fine. The adversary was the problem: none of the Byzantine
strategies ever *sent* an invalid certificate. Every QC in flight had been
honestly collected, so a replica that skipped verifying them saw nothing
different. The mutation report was measuring the adversary's imagination, not
the protocol.

Adding `forge_qc` — one real self-signature padded out to quorum size with
zero bytes attributed to other replicas — makes the rule load-bearing. It is now
caught at seed 1, and in a clean run the adversary sends 69 forged certificates
and honest replicas reject 477 of them.

This is the same lesson as the fault-model gap in `dst-harness`: **a rule that
no attack targets will be reported as unnecessary, and the report will be
wrong.** The mutation catalogue is the only thing that surfaces it, because it
is the only part of the harness that deliberately breaks something and then
checks whether anyone noticed.
