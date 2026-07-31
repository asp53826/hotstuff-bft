"""Seeds-to-first-catch for each protocol rule, removed one at a time.

Run at f Byzantine replicas - the number the protocol is supposed to tolerate -
so a catch means "this rule was load-bearing at a fault level the protocol
claims to survive", not "the adversary was over budget".

Two rows matter more than the rest. The control at the top runs unmutated code:
if that reports a violation, nothing below it means anything. And
`no_liveness_rule` must come back NOT CAUGHT, because removing that clause
cannot break safety - it only makes replicas refuse more votes. A checker that
flags it is producing false positives.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hs.cluster import ClusterConfig                                # noqa: E402
from hs.mutants import BY_KEY, CATALOGUE, SAFETY_PRESERVING         # noqa: E402
from hs.runner import RunConfig, run_once                           # noqa: E402


def config(n: int, byz: int, strategy: str, duration: int) -> RunConfig:
    cfg = RunConfig(duration=duration, settle=duration // 2)
    cfg.cluster = ClusterConfig(replicas=n, byzantine=byz, strategy=strategy)
    return cfg


def hunt(key, budget, cfg):
    muts = frozenset([key]) if key else frozenset()
    started = time.time()
    for seed in range(1, budget + 1):
        r = run_once(seed, cfg, muts)
        if r.broke_safety:
            return seed, r, time.time() - started
    return None, None, time.time() - started


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=400)
    ap.add_argument("--replicas", type=int, default=7)
    ap.add_argument("--strategy", default="everything")
    ap.add_argument("--duration", type=int, default=8000)
    ap.add_argument("--only", default="")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    if args.quick:
        args.budget = 40

    n = args.replicas
    f = (n - 1) // 3
    cfg = config(n, f, args.strategy, args.duration)

    print(f"n = {n}, f = {f} Byzantine replicas running '{args.strategy}'")
    print(f"budget {args.budget} seeds per mutant\n")
    header = f"{'mutant':<28} {'seed':>6} {'secs':>7}  outcome"
    print(header)
    print("-" * (len(header) + 20))

    seed, r, secs = hunt(None, args.budget, cfg)
    if seed is None:
        print(f"{'(control: unmutated)':<28} {'-':>6} {secs:>7.1f}  "
              f"clean over {args.budget} seeds")
    else:
        print(f"{'(control: unmutated)':<28} {seed:>6} {secs:>7.1f}  "
              f"!! CLEAN CODE FAILED: {r.detail[:70]}")

    targets = ([BY_KEY[k] for k in args.only.split(",")]
               if args.only else list(CATALOGUE))
    rows = []
    for m in targets:
        seed, r, secs = hunt(m.key, args.budget, cfg)
        expected_clean = m.key in SAFETY_PRESERVING
        if seed is None:
            verdict = ("as expected: safety-preserving" if expected_clean
                       else f"NOT CAUGHT in {args.budget} seeds")
            print(f"{m.key:<28} {'-':>6} {secs:>7.1f}  {verdict}")
            rows.append({"mutant": m.key, "seed": None, "expected_clean": expected_clean})
        else:
            flag = "  <-- FALSE POSITIVE" if expected_clean else ""
            print(f"{m.key:<28} {seed:>6} {secs:>7.1f}  "
                  f"{r.detail[:64]}{flag}")
            rows.append({"mutant": m.key, "seed": seed,
                         "detail": r.detail, "expected_clean": expected_clean})

    caught = sum(1 for x in rows if x["seed"] is not None and not x["expected_clean"])
    should_catch = sum(1 for x in rows if not x["expected_clean"])
    false_pos = sum(1 for x in rows if x["seed"] is not None and x["expected_clean"])
    print(f"\ncaught {caught}/{should_catch} safety-breaking mutants; "
          f"{false_pos} false positives")

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w") as fh:
            json.dump(rows, fh, indent=2)
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
