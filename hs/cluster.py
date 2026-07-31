"""Wiring: n replicas, some of them lying, on the dst-harness simulator.

The virtual clock, network and disk come from `dst-harness` rather than being
rewritten here. That is deliberate and it is also the test of whether that repo
is a library or a one-off: the fault model it provides - partitions, one-way
cuts, drops, duplication, reordering, crashes, torn writes - is exactly what an
adversarial scheduler needs underneath it, and none of it needed changing to
carry a Byzantine protocol.

What this repo adds on top is the part crash-fault simulation cannot express:
replicas that send different things to different peers.
"""

from __future__ import annotations

from dataclasses import dataclass

from dst.core import Sim
from dst.disk import Disk, DiskConfig
from dst.history import History
from dst.net import Network, NetConfig

from .byzantine import ByzantineReplica
from .core import KeyRing
from .replica import HotStuffConfig, Replica
from .safety import Observer


@dataclass
class ClusterConfig:
    replicas: int = 4          # n = 3f+1
    byzantine: int = 1
    strategy: str = "equivocate"
    clients: int = 2
    keys_in_workload: int = 1
    max_steps: int = 400_000
    """Event budget for a run.

    Byzantine replicas that propose out of turn amplify traffic: every proposal
    draws votes, every vote can trigger another proposal, and an equivocating
    proposer emits two blocks each time. Below roughly n/3 honest replicas that
    becomes a runaway, and a run stops being a test of the protocol and becomes
    a test of how long you are willing to wait. Exhausting the budget is
    reported as its own outcome rather than as a pass - a run that never
    finished did not demonstrate safety."""


class Cluster:
    def __init__(self, seed: int, cfg: ClusterConfig | None = None,
                 net_cfg: NetConfig | None = None,
                 disk_cfg: DiskConfig | None = None,
                 hs_cfg: HotStuffConfig | None = None,
                 mutations: frozenset[str] = frozenset()):
        self.cfg = cfg or ClusterConfig()
        self.mut = mutations
        self.sim = Sim(seed, max_steps=self.cfg.max_steps)
        self.net = Network(self.sim, net_cfg or NetConfig(
            min_latency=1, max_latency=20, drop_rate=0.01,
            duplicate_rate=0.01, slow_rate=0.03))
        self.ids = [f"r{i}" for i in range(self.cfg.replicas)]
        self.keys = KeyRing(self.ids)

        self.f = (self.cfg.replicas - 1) // 3
        # Byzantine replicas are chosen deterministically from the seed, and
        # deliberately include r0 when possible so the adversary gets to be
        # leader in view 0 rather than waiting for a rotation that may not come.
        self.faulty = tuple(sorted(
            self.sim.rng.sample(self.ids, self.cfg.byzantine)))
        self.honest = tuple(r for r in self.ids if r not in self.faulty)

        self.obs = Observer(keys=self.keys,
                            quorum=self.cfg.replicas - self.f,
                            honest=self.honest)
        self.obs.command_source = self._next_command
        self.history = History()
        self.stopped = False
        self._seq = 0
        self._inflight: dict[tuple, object] = {}

        self.disks: dict[str, Disk] = {}
        self.replicas: dict[str, Replica] = {}
        for rid in self.ids:
            disk = Disk(self.sim, disk_cfg or DiskConfig())
            self.disks[rid] = disk
            common = dict(peers=self.ids, sim=self.sim, net=self.net,
                          disk=disk, keys=self.keys, observer=self.obs,
                          apply_fn=self._apply, cfg=hs_cfg,
                          mutations=mutations)
            if rid in self.faulty:
                self.replicas[rid] = ByzantineReplica(
                    rid, strategy=self.cfg.strategy, **common)
            else:
                self.replicas[rid] = Replica(rid, **common)

        self.applied: dict[str, dict[str, str]] = {r: {} for r in self.ids}

    # ---- workload ----------------------------------------------------------

    def _next_command(self, rid: str, view: int):
        """Commands come from the cluster rather than from a client loop.

        A closed-loop client needs to know who the leader is, and under a
        Byzantine leader that question has no honest answer. Driving the
        workload from the proposer keeps the history well defined while still
        producing distinguishable commands.
        """
        if self.stopped:
            return None
        self._seq += 1
        key = f"k{self._seq % max(1, self.cfg.keys_in_workload)}"
        value = f"<{rid}.{view}.{self._seq}>"
        op = self.history.invoke(rid, key, "append", value, self.sim.now)
        self._inflight[(rid, self._seq)] = op
        return ("append", key, value, rid, self._seq)

    def _apply(self, rid: str, height: int, block) -> None:
        cmd = block.cmd
        if not isinstance(cmd, tuple) or len(cmd) != 5 or cmd[0] != "append":
            return
        _, key, value, origin, seq = cmd
        state = self.applied[rid]
        state[key] = state.get(key, "") + value

        # The history only records the first honest commit of a command, since
        # every honest replica applies the same sequence and recording all of
        # them would turn one operation into n.
        if rid in self.honest:
            op = self._inflight.pop((origin, seq), None)
            if op is not None:
                self.history.complete(op, "", self.sim.now)

    # ---- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        leader = self.replicas[self.ids[1 % len(self.ids)]]
        for rid in self.ids:
            self.replicas[rid].advance_view(1)

    def run(self, duration: int) -> None:
        self.start()
        self.sim.run_until(duration)

    def quiesce(self, extra: int) -> None:
        self.net.heal()
        for rid in self.ids:
            if not self.replicas[rid].alive:
                self.replicas[rid].restart()
        self.sim.run_until(self.sim.now + extra)
        self.stopped = True

    def crash(self, rid: str) -> None:
        self.replicas[rid].crash()

    def restart(self, rid: str) -> None:
        self.replicas[rid].restart()

    def live(self) -> list[str]:
        return [r for r in self.ids if self.replicas[r].alive]

    def down(self) -> list[str]:
        return [r for r in self.ids if not self.replicas[r].alive]

    def check(self) -> None:
        self.obs.check(self.replicas)

    def committed_heights(self) -> dict[str, int]:
        return {r: self.replicas[r].committed_height for r in self.honest}

    def progress(self) -> int:
        """Highest height committed by any honest replica."""
        heights = self.committed_heights()
        return max(heights.values()) if heights else 0
