"""One run, many runs, and the outcomes that are not passes.

Four things a run can be, and conflating any of them with "safe" is how a
Byzantine test suite ends up proving nothing:

  safe        honest replicas committed, and no property was violated
  violated    a safety, agreement or certificate property broke
  no progress the run completed with nothing committed. Not a pass: an idle
              cluster satisfies every safety property trivially
  budget      the event budget ran out. Not a pass either - the run did not
              finish, so it demonstrated nothing

The campaign report prints all four, plus how many runs the adversary actually
got to equivocate in. A seed where the Byzantine replica never became leader
tested the happy path with extra steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dst.core import StepBudgetExceeded
from dst.disk import DiskConfig
from dst.linearizability import VIOLATION, check
from dst.net import NetConfig

from .cluster import Cluster, ClusterConfig
from .replica import HotStuffConfig
from .safety import equivocation_happened

SAFE = "safe"
VIOLATED = "violated"
NO_PROGRESS = "no-progress"
BUDGET = "budget"
CRASHED = "crashed"


@dataclass
class RunConfig:
    duration: int = 8_000
    settle: int = 3_000
    cluster: ClusterConfig = field(default_factory=ClusterConfig)
    net: NetConfig = field(default_factory=lambda: NetConfig(
        min_latency=1, max_latency=20, drop_rate=0.01,
        duplicate_rate=0.01, slow_rate=0.03))
    disk: DiskConfig = field(default_factory=DiskConfig)
    hotstuff: HotStuffConfig = field(default_factory=HotStuffConfig)


@dataclass
class RunResult:
    seed: int
    status: str
    detail: str = ""
    progress: int = 0
    qcs: int = 0
    views: int = 0
    equivocations: int = 0
    equivocated: bool = False
    conflicting_qcs: int = 0
    refused_unsafe: int = 0
    rejected_qc: int = 0
    linearizable: bool = True

    @property
    def broke_safety(self) -> bool:
        return self.status == VIOLATED


def run_once(seed: int, cfg: RunConfig | None = None,
             mutations: frozenset[str] = frozenset()) -> RunResult:
    cfg = cfg or RunConfig()
    cl = Cluster(seed, cfg.cluster, cfg.net, cfg.disk, cfg.hotstuff, mutations)

    def finish(status: str, detail: str = "", lin: bool = True) -> RunResult:
        return RunResult(
            seed=seed, status=status, detail=detail,
            progress=cl.progress(), qcs=cl.obs.qcs_formed,
            views=cl.obs.views_entered, equivocations=cl.obs.equivocations,
            equivocated=equivocation_happened(cl.obs),
            conflicting_qcs=cl.obs.conflicting_qcs,
            refused_unsafe=cl.obs.refused_unsafe,
            rejected_qc=cl.obs.rejected_qc, linearizable=lin)

    try:
        cl.run(cfg.duration)
        cl.quiesce(cfg.settle)
    except StepBudgetExceeded as exc:
        return finish(BUDGET, str(exc))
    except Exception as exc:  # noqa: BLE001
        return finish(CRASHED, f"{type(exc).__name__}: {exc}")

    cl.check()
    if not cl.obs.ok:
        return finish(VIOLATED, cl.obs.violations[0])

    lin = check(cl.history, 100_000)
    if lin.status == VIOLATION:
        return finish(VIOLATED, f"linearizability: key {lin.key}", False)

    if cl.progress() == 0:
        return finish(NO_PROGRESS)
    return finish(SAFE)


@dataclass
class Campaign:
    runs: list[RunResult] = field(default_factory=list)

    def add(self, r: RunResult) -> None:
        self.runs.append(r)

    def count(self, status: str) -> int:
        return sum(1 for r in self.runs if r.status == status)

    @property
    def violations(self) -> list[RunResult]:
        return [r for r in self.runs if r.broke_safety]

    def summary(self) -> str:
        n = len(self.runs) or 1
        rows = [
            ("runs", len(self.runs)),
            ("safe", self.count(SAFE)),
            ("SAFETY VIOLATIONS", len(self.violations)),
            ("no progress", self.count(NO_PROGRESS)),
            ("event budget exhausted", self.count(BUDGET)),
            ("unhandled exceptions", self.count(CRASHED)),
            ("runs where equivocation happened", sum(1 for r in self.runs if r.equivocated)),
            ("blocks committed (mean)", round(sum(r.progress for r in self.runs) / n, 1)),
            ("QCs formed", sum(r.qcs for r in self.runs)),
            ("conflicting QCs (impossible at or below f)",
             sum(r.conflicting_qcs for r in self.runs)),
            ("votes refused by the safety rule", sum(r.refused_unsafe for r in self.runs)),
            ("QCs rejected as unverifiable", sum(r.rejected_qc for r in self.runs)),
        ]
        w = max(len(k) for k, _ in rows)
        return "\n".join(f"  {k.ljust(w)}  {v}" for k, v in rows)


def campaign(seeds, cfg: RunConfig | None = None,
             mutations: frozenset[str] = frozenset()) -> Campaign:
    out = Campaign()
    for seed in seeds:
        out.add(run_once(seed, cfg, mutations))
    return out
