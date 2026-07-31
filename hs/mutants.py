"""Bugs in *my* HotStuff, as opposed to lies from the adversary.

The threshold study measures whether the protocol survives a strong adversary.
It cannot measure whether the checks would have noticed a broken implementation,
because a correct-looking run and a run where nothing was ever verified look the
same from the outside.

So: remove one rule at a time and count seeds to first catch. Every entry is a
line of the HotStuff paper, and the two marked as safety-preserving are the
interesting ones - a harness that reports them as caught is reporting a false
positive, and one that reports them as clean is telling the truth.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Mutant:
    key: str
    title: str
    breaks: str
    expected: str
    note: str


CATALOGUE: tuple[Mutant, ...] = (
    Mutant(
        "no_safety_rule", "vote for anything", "Safety", "violated",
        "Removes safeNode entirely. A replica votes for blocks conflicting "
        "with the one it is locked on, which is the exact vote quorum "
        "intersection assumes no honest replica ever casts.",
    ),
    Mutant(
        "no_lock_rule", "never update the lock", "Safety", "violated",
        "The two-chain rule stops updating lockedQC. The safety rule still "
        "runs, but it is checking against genesis forever, so it permits "
        "everything.",
    ),
    Mutant(
        "weak_quorum", "quorum of 2f instead of 2f+1", "Safety", "violated",
        "Off by one in the quorum size. Two quorums of 2f no longer have to "
        "intersect in an honest replica, so conflicting certificates become "
        "possible with f Byzantine replicas rather than f+1.",
    ),
    Mutant(
        "skip_qc_check", "believe any certificate", "Certificate", "violated",
        "Signatures on incoming QCs are not verified. The adversary can then "
        "manufacture a certificate for a block nobody voted for, which is the "
        "whole difference between crash-fault and Byzantine reasoning.",
    ),
    Mutant(
        "vote_twice_per_view", "no per-view vote limit", "Safety", "violated",
        "Honest replicas forget they already voted. Equivocation by a single "
        "faulty leader then gets both branches certified without the adversary "
        "needing any extra replicas.",
    ),
    Mutant(
        "allow_gaps_in_chain", "commit on a non-contiguous chain", "Safety",
        "violated",
        "The three-chain commit rule stops requiring the blocks to be directly "
        "linked. A gap means some view failed to reach a quorum, and an "
        "equivocating proposer may have gotten a conflicting block certified "
        "in exactly that view.",
    ),
    Mutant(
        "trust_forwarded_proposals", "accept relayed proposals", "Safety",
        "violated",
        "A proposal is accepted from any sender rather than only from the "
        "replica that signed it, so anyone can replay a proposal into a view "
        "where it does not belong.",
    ),
    Mutant(
        "unpersisted_vote", "vote before it is durable", "Safety", "violated",
        "The vote is sent beside the fsync instead of from inside its "
        "callback. A crash in the window loses the record of a promise the "
        "replica already made, so on restart it can vote again in that view.",
    ),
    Mutant(
        "genesis_any_view", "accept a genesis QC at any view", "Safety",
        "violated",
        "Genesis carries no signatures and is rightly exempt from the quorum "
        "check - but only at view 0. Accepting it at any view lets an adversary "
        "attach an arbitrary view to an unsigned certificate, and since the "
        "liveness clause of safeNode is `qc.view > lockedQC.view`, a genesis QC "
        "claiming a high view makes every honest replica willing to vote "
        "against its own lock. This was a real bug in this implementation, "
        "found at seed 182; the mutant exists to keep it fixed.",
    ),
    Mutant(
        "no_liveness_rule", "drop the liveness clause of safeNode", "Liveness",
        "safe",
        "SAFETY-PRESERVING BY DESIGN. Removing `qc.view > lockedQC.view` "
        "cannot cause a violation - it only ever refuses more votes. A replica "
        "locked on an abandoned branch stops voting forever and the cluster "
        "stalls. If the safety checker reports this one, the checker is wrong.",
    ),
)

BY_KEY = {m.key: m for m in CATALOGUE}

SAFETY_PRESERVING = tuple(m.key for m in CATALOGUE if m.expected == "safe")
"""Mutants that must NOT be caught by a safety check. They are the control on
the control: a harness that flags these is producing false positives, and every
'caught' in the rest of the table is worth less than it looks."""


def get(key: str) -> Mutant:
    if key not in BY_KEY:
        raise KeyError(f"unknown mutant {key!r}; have {sorted(BY_KEY)}")
    return BY_KEY[key]
