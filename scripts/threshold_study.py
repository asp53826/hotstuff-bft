"""The study that makes "safety held" mean something.

A Byzantine consensus repository that reports "no safety violations in N seeds"
has reported nothing, because the same sentence is true of an implementation
that never commits anything, and of a test harness whose adversary does not
attack. The claim only becomes evidence when the *same* adversary, the *same*
seeds and the *same* protocol are shown to break safety once the fault threshold
is exceeded.

HotStuff tolerates f Byzantine replicas out of n = 3f+1. The argument is quorum
intersection: quorums are 2f+1, any two of them share at least f+1 replicas, so
at least one *honest* replica would have to vote for both branches of an
equivocation - and the safety rule forbids that. At f+1 Byzantine the arithmetic
stops working: the adversary alone can supply f+1 votes to each branch, and two
conflicting quorums can form without any honest replica voting twice.

So the expected shape of this table is a cliff at f, not a slope. If safety
holds everywhere, the adversary is too weak and the left half of the table is
worthless. If it breaks below f, the implementation is wrong.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hs.cluster import ClusterConfig                      # noqa: E402
from hs.runner import (BUDGET, NO_PROGRESS, RunConfig,    # noqa: E402
                       SAFE, campaign)


def study(n: int, seeds: int, strategy: str, duration: int):
    f = (n - 1) // 3
    rows = []
    print(f"\nn = {n}, so f = {n // 3} tolerated (n = 3f+1 gives f = {f})")
    header = (f"  {'byzantine':>9} {'safe':>6} {'VIOLATED':>9} "
              f"{'conflicting QCs':>16} {'no prog':>8} {'budget':>7} "
              f"{'equivocated':>12} {'blocks':>8}")
    print(header)
    print("  " + "-" * (len(header) - 2))

    for byz in range(0, f + 3):
        if byz >= n:
            break
        cfg = RunConfig(duration=duration, settle=duration // 2)
        cfg.cluster = ClusterConfig(replicas=n, byzantine=byz,
                                    strategy=strategy)
        c = campaign(range(1, seeds + 1), cfg)
        violated = len(c.violations)
        equiv = sum(1 for r in c.runs if r.equivocated)
        mean_blocks = sum(r.progress for r in c.runs) / max(1, len(c.runs))
        flag = "" if byz <= f else "   <- exceeds f"
        conf_runs = sum(1 for r in c.runs if r.conflicting_qcs)
        conf_total = sum(r.conflicting_qcs for r in c.runs)
        print(f"  {byz:>9} {c.count(SAFE):>6} {violated:>9} "
              f"{f'{conf_runs} runs / {conf_total}':>16} "
              f"{c.count(NO_PROGRESS):>8} {c.count(BUDGET):>7} "
              f"{equiv:>12} {mean_blocks:>8.1f}{flag}")
        rows.append({
            "n": n, "f": f, "byzantine": byz, "seeds": seeds,
            "safe": c.count(SAFE), "violated": violated,
            "no_progress": c.count(NO_PROGRESS), "budget": c.count(BUDGET),
            "equivocated_runs": equiv, "mean_blocks": round(mean_blocks, 2),
            "runs_with_conflicting_qcs": conf_runs,
            "conflicting_qcs": conf_total,
            "first_violation": (c.violations[0].seed if c.violations else None),
            "first_violation_detail": (c.violations[0].detail
                                       if c.violations else ""),
        })
        if c.violations:
            v = c.violations[0]
            print(f"            first at seed {v.seed}: {v.detail[:96]}")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=120)
    ap.add_argument("--strategy", default="everything")
    ap.add_argument("--duration", type=int, default=8000)
    ap.add_argument("--sizes", default="4,7,10")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    if args.quick:
        args.seeds = 20
        args.sizes = "4,7"

    print("Byzantine threshold study")
    print(f"adversary: {args.strategy};  {args.seeds} seeds per cell")
    print("Safety must hold at and below f, and must break above it. A table "
          "that is\nclean everywhere means the adversary is too weak to have "
          "tested anything.")

    out = []
    for n in [int(x) for x in args.sizes.split(",")]:
        out += study(n, args.seeds, args.strategy, args.duration)

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
