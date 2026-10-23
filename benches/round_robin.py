#!/usr/bin/env python3
r"""Round-robin A/B driver for the live_events benchmarks.

Wall-clock timing on a developer machine cannot resolve small parser changes by
running one build after the other. Measured on this host, over the 2836-event
registry capture:

  * a single arm's per-run median drifts 5-13% across repeated runs;
  * two benches measured ~8s apart *inside one process* disagree by 14.6%
    (stdev 4.12%), statistically indistinguishable from the cross-process
    figure -- so the drift is on the seconds timescale and running both arms in
    one process buys nothing;
  * the second arm of a back-to-back pair is penalised roughly 1%, because the
    machine is warmer by then.

What does work is a paired design with enough pairs. The per-pair ratio has a
stdev of ~3.8%, so the standard error falls as 3.8%/sqrt(pairs): 15 pairs buys
+/-1%, which resolves a 5% effect at 5 sigma. This driver therefore reports the
mean paired ratio together with its standard error, so a result states its own
resolving power instead of implying false precision.

Two details matter and are easy to get wrong:

  * **Use each run's median, not its fastest sample.** Under criterion's Linear
    sampling `iters` ramps 1..N, so `times[i]/iters[i]` for the low-iteration
    samples is dominated by timer granularity. The minimum is therefore the
    *most* quantisation-contaminated sample, not the least: its spread across
    runs measured 26-33% against 5-11% for the median.
  * **Alternate which arm goes first (ABBA).** Always running base-then-cand
    hands the ~1% warm-up penalty to the same arm every round, which shows up
    as a systematic delta between identical binaries.

See "Comparing two builds" in benches/README.md for how to use it.

Usage:
    python benches/round_robin.py \
        --baseline  target/baseline-live_events.exe \
        --candidate target/release/deps/live_events-<hash>.exe \
        --filter "registry_create_key/etw-rs-static" \
        --pairs 15
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import statistics
import subprocess
import sys
from pathlib import Path


def run_arm(exe: Path, label: str, filt: str, extra: list[str]) -> str:
    """Run one bench binary, returning its stdout.

    `--save-baseline label` is still passed for the criterion-based bench targets,
    which park their results on disk under that name. `live_events` times itself
    and ignores the flag, reporting on stdout instead; see `parse_rows`.
    """
    env = dict(os.environ)
    # The C++ arm compares against krabsetw/TDH and costs about a minute; it is
    # irrelevant when comparing two Rust builds against each other.
    env["ETW_BENCH_SKIP_CPP"] = "1"
    # This driver does its own repetition -- paired rounds across two binaries -- so
    # the harness's built-in multi-pass validation would multiply the work without
    # adding anything, and --save-baseline would keep only the last pass regardless.
    env["ETW_BENCH_PASSES"] = "1"
    # Resolve to an absolute native path: CreateProcess on Windows rejects the
    # relative form even where pathlib will happily stat it.
    cmd = [str(exe.resolve()), "--bench", filt, "--save-baseline", label, *extra]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"{exe.name} ({label}) failed:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    return proc.stdout


def parse_rows(stdout: str) -> dict[tuple[str, str], float]:
    """Per-event medians a self-timing bench reported, keyed by (group, arm).

    `live_events` prints one `RSBENCH<TAB>group<TAB>arm<TAB>events<TAB>median` row
    per arm. Per-event rather than per-iteration, which is immaterial here: this
    driver only ever forms ratios of the two arms, and the event count is the same
    constant in both.

    Empty for the criterion-based bench targets, which is the signal to fall back
    to reading their stored estimates.
    """
    rows: dict[tuple[str, str], float] = {}
    for line in stdout.splitlines():
        parts = line.rstrip().split("\t")
        if len(parts) == 5 and parts[0] == "RSBENCH":
            try:
                rows[(parts[1], parts[2])] = float(parts[4])
            except ValueError:
                continue
    return rows


def run_median_ns(criterion_dir: Path, group: str, bench_id: str, label: str) -> float | None:
    """Per-iteration median cost, in ns, for one stored criterion run.

    The median is criterion's own point estimate over that run's samples. It is
    used in preference to the fastest raw sample because Linear sampling makes
    the low-iteration samples timer-quantised; see the module docstring.
    """
    path = criterion_dir / group / bench_id / label / "estimates.json"
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return float(data["median"]["point_estimate"])
    except (KeyError, TypeError, ValueError):
        return None


def discover(criterion_dir: Path, label: str) -> list[tuple[str, str]]:
    """Find every (group, bench_id) that produced a sample set for `label`."""
    found = []
    if not criterion_dir.is_dir():
        return found
    for group_dir in sorted(criterion_dir.iterdir()):
        if not group_dir.is_dir() or group_dir.name == "report":
            continue
        for id_dir in sorted(group_dir.iterdir()):
            if (id_dir / label / "sample.json").is_file():
                found.append((group_dir.name, id_dir.name))
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", required=True, type=Path)
    ap.add_argument("--candidate", required=True, type=Path)
    ap.add_argument("--filter", required=True, help="criterion benchmark filter")
    ap.add_argument(
        "--pairs",
        type=int,
        default=15,
        help="paired rounds (default 15, which buys about +/-1% standard error)",
    )
    ap.add_argument("--target-dir", type=Path, default=Path("target"))
    ap.add_argument(
        "--bench-arg",
        action="append",
        default=[],
        help="extra arg passed to both bench binaries; repeat per token, e.g. "
        "--bench-arg=--sample-size --bench-arg=50",
    )
    args = ap.parse_args()

    for exe in (args.baseline, args.candidate):
        if not exe.is_file():
            print(f"not a file: {exe}", file=sys.stderr)
            return 2

    criterion_dir = args.target_dir / "criterion"

    # Purge every prior arm directory before starting. `discover` looks for any
    # bench carrying a base_r1, so leftovers from an earlier invocation with a
    # different filter or pair count would otherwise be reported as if they came
    # from this run -- with a stale pair count and a stale delta.
    purged = 0
    if criterion_dir.is_dir():
        for group_dir in criterion_dir.iterdir():
            if not group_dir.is_dir():
                continue
            for id_dir in group_dir.iterdir():
                if not id_dir.is_dir():
                    continue
                for arm_dir in id_dir.iterdir():
                    if arm_dir.is_dir() and re.fullmatch(r"(base|cand)_r\d+", arm_dir.name):
                        shutil.rmtree(arm_dir, ignore_errors=True)
                        purged += 1
    if purged:
        print(f"  purged {purged} stale arm directories")

    # ABBA: base-then-cand on odd rounds, cand-then-base on even ones, so each
    # arm spends half its rounds in the warmer second slot. Always ordering
    # base-then-cand hands that ~1% penalty to the candidate every time.
    reported: dict[tuple[str, int], dict[tuple[str, str], float]] = {}
    for r in range(1, args.pairs + 1):
        order = ("base", "cand") if r % 2 else ("cand", "base")
        for arm in order:
            exe = args.baseline if arm == "base" else args.candidate
            print(f"  round {r}/{args.pairs}  {arm} ... ", end="", flush=True)
            reported[(arm, r)] = parse_rows(run_arm(exe, f"{arm}_r{r}", args.filter, args.bench_arg))
            print("done")

    # A bench that times itself reports every arm on stdout; one built on criterion
    # reports none and leaves its estimates on disk instead.
    self_timed = bool(reported.get(("base", 1)))

    def median_ns(arm: str, r: int, group: str, bench_id: str) -> float | None:
        if self_timed:
            return reported.get((arm, r), {}).get((group, bench_id))
        return run_median_ns(criterion_dir, group, bench_id, f"{arm}_r{r}")

    benches = sorted(reported[("base", 1)]) if self_timed else discover(criterion_dir, "base_r1")
    if not benches:
        print("no sample data found; did the filter match?", file=sys.stderr)
        return 1

    print()
    print(f"{'bench':<40}{'pairs':>6}{'delta':>10}{'std err':>10}  verdict")
    print("-" * 82)
    exit_code = 0
    for group, bench_id in benches:
        ratios = []
        for r in range(1, args.pairs + 1):
            base = median_ns("base", r, group, bench_id)
            cand = median_ns("cand", r, group, bench_id)
            if base and cand:
                ratios.append(cand / base)
        name = f"{group}/{bench_id}"
        if len(ratios) < 2:
            print(f"{name:<40}{len(ratios):>6}{'-':>10}{'-':>10}  insufficient data")
            exit_code = 1
            continue
        delta = statistics.fmean(ratios) - 1.0
        # Standard error of the mean paired ratio. Reported alongside the delta
        # because a delta smaller than its own standard error is not a result.
        stderr_pct = statistics.stdev(ratios) / math.sqrt(len(ratios)) * 100
        verdict = "resolved" if abs(delta) * 100 > 2 * stderr_pct else "within noise"
        print(
            f"{name:<40}{len(ratios):>6}{delta:>+9.2%}{stderr_pct:>9.2f}%  {verdict}"
        )
    print("-" * 82)
    print("delta = mean(cand/base) - 1 over paired rounds, ABBA-ordered.")
    print("'resolved' means |delta| exceeds two standard errors.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
