"""Protocol-level tests.

The threshold study is the headline measurement, but a failing campaign points
at everything at once. These are the small deterministic cases that say which
part.
"""

import pytest

from hs.byzantine import STRATEGIES
from hs.cluster import Cluster, ClusterConfig
from hs.core import GENESIS_HASH, QC
from hs.mutants import CATALOGUE, SAFETY_PRESERVING
from hs.runner import RunConfig, run_once
from hs.safety import equivocation_happened


def build(seed=1, n=4, byz=0, strategy="equivocate", **kw):
    cfg = ClusterConfig(replicas=n, byzantine=byz, strategy=strategy, **kw)
    cl = Cluster(seed, cfg)
    cl.run(6000)
    cl.quiesce(3000)
    cl.check()
    return cl


# ---- the happy path -------------------------------------------------------

def test_an_honest_cluster_commits():
    cl = build(byz=0)
    assert cl.progress() > 5
    assert cl.obs.ok, cl.obs.violations


def test_all_honest_replicas_agree():
    cl = build(byz=0)
    chains = {r: [b.hash for b in cl.replicas[r].committed] for r in cl.honest}
    ref = max(chains.values(), key=len)
    for rid, c in chains.items():
        assert c == ref[:len(c)], rid


def test_committed_blocks_carry_real_quorums():
    cl = build(byz=0)
    for rid in cl.honest:
        for b in cl.replicas[rid].committed:
            if b.height == 0 or b.justify.block_hash == GENESIS_HASH:
                continue
            assert b.justify.verify(cl.keys, cl.obs.quorum)


# ---- Byzantine faults within the threshold -------------------------------

@pytest.mark.parametrize("strategy", [s for s in STRATEGIES if s != "silent"])
def test_safety_holds_against_each_strategy(strategy):
    for seed in range(1, 6):
        cl = build(seed=seed, n=7, byz=2, strategy=strategy)
        assert cl.obs.ok, (strategy, seed, cl.obs.violations)


def test_the_adversary_actually_equivocates():
    """A campaign where the Byzantine replica never got to be leader tested the
    happy path with extra steps."""
    cl = build(n=7, byz=2, strategy="equivocate")
    assert equivocation_happened(cl.obs)
    assert cl.obs.equivocations > 0


def test_no_conflicting_certificates_within_the_threshold():
    """Quorum intersection: two certificates in one view need a replica to have
    voted twice, which at or below f is impossible."""
    for seed in range(1, 11):
        cl = build(seed=seed, n=7, byz=2, strategy="everything")
        assert cl.obs.conflicting_qcs == 0, seed


def test_forged_certificates_are_rejected():
    cl = build(n=7, byz=2, strategy="forge_qc")
    assert cl.obs.forged_qcs > 0, "the adversary never tried"
    assert cl.obs.rejected_qc > 0, "nothing was rejected"
    assert cl.obs.ok


def test_a_silent_minority_does_not_stop_progress():
    cl = build(n=7, byz=2, strategy="silent")
    assert cl.progress() > 0
    assert cl.obs.ok


# ---- the genesis certificate bug -----------------------------------------

def test_a_genesis_qc_is_only_valid_at_view_zero():
    """The bug found at seed 182. Genesis is exempt from the signature check
    because it has no signatures; it is not exempt from having a view."""
    cl = Cluster(1, ClusterConfig(replicas=4, byzantine=0))
    r = cl.replicas["r0"]
    assert r._valid_qc(QC(GENESIS_HASH, 0, 0, ()))
    assert not r._valid_qc(QC(GENESIS_HASH, 99, 0, ()))
    assert not r._valid_qc(QC(GENESIS_HASH, 0, 0, (("r1", b"x" * 16),)))


@pytest.mark.slow
def test_the_genesis_bug_is_caught_when_reintroduced():
    """Reproduces at seed 182, which is the seed the original bug was found on.
    Nothing closer: the attack needs the adversary to be leader at the right
    moment with the right partition, and that combination is rare."""
    cfg = RunConfig()
    cfg.cluster = ClusterConfig(replicas=7, byzantine=2, strategy="everything")
    for seed in range(1, 200):
        r = run_once(seed, cfg, frozenset(["genesis_any_view"]))
        if r.broke_safety:
            assert seed == 182, f"expected seed 182, got {seed}"
            return
    pytest.fail("genesis_any_view survived 199 seeds; the check has regressed")


# ---- the catalogue --------------------------------------------------------

def test_every_mutant_is_wired_into_the_code():
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = "\n".join((root / p).read_text()
                    for p in ("hs/replica.py", "hs/byzantine.py", "hs/core.py"))
    for m in CATALOGUE:
        assert f'"{m.key}"' in src, f"{m.key} is catalogued but not implemented"


def test_the_safety_preserving_mutant_does_not_trip_the_checker():
    """A false positive here devalues every 'caught' in the report."""
    cfg = RunConfig()
    cfg.cluster = ClusterConfig(replicas=7, byzantine=2, strategy="everything")
    for key in SAFETY_PRESERVING:
        for seed in range(1, 25):
            r = run_once(seed, cfg, frozenset([key]))
            assert not r.broke_safety, (key, seed, r.detail)


def test_control_is_clean():
    cfg = RunConfig()
    cfg.cluster = ClusterConfig(replicas=7, byzantine=2, strategy="everything")
    for seed in range(1, 40):
        r = run_once(seed, cfg)
        assert not r.broke_safety, (seed, r.detail)


# ---- determinism ----------------------------------------------------------

def test_the_same_seed_replays():
    cfg = RunConfig()
    cfg.cluster = ClusterConfig(replicas=7, byzantine=2, strategy="everything")
    a = run_once(9, cfg)
    b = run_once(9, cfg)
    assert (a.status, a.progress, a.qcs, a.equivocations) == \
           (b.status, b.progress, b.qcs, b.equivocations)
