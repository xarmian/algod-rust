#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""bench-compare tier runner: the engine behind `make bench-compare`.

Issue #2102 (epic #2101). One run:

  1. resolves TIERS against scripts/bench/tiers/<tier>.{py,sh};
  2. creates the run directory (default bench-results/<utc-ts>/);
  3. writes fingerprint.json (fingerprint.py);
  4. runs build_both.sh when a selected tier declares
     `# bench-tier-needs: build` in its first lines (or --build always);
  5. runs every tier with the tier-contract environment (BENCH_TIER,
     BENCH_RUNS, BENCH_OUT, ...; see docs/BENCHMARK_COMPARISON.md), logging
     to logs/<tier>.log and recording tier-status.json;
  6. calls report.py to write report.json + report.md.

A failing tier does not stop the others; the run exits 1 if any tier, the
build or the report failed, 2 on a usage error (unknown tier, bad RUNS).

Usage:
    python3 scripts/bench/run.py --tiers selftest --runs 5
        [--run-dir DIR | --out-root bench-results] [--build auto|always|never]
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
TIERS_DIR = os.path.join(HERE, "tiers")
TIER_NAME = re.compile(r"^[a-z][a-z0-9_-]*$")
NEEDS = re.compile(r"bench-tier-needs:\s*(.+)")

sys.path.insert(0, HERE)
import fingerprint  # noqa: E402
import report  # noqa: E402


def discover_tiers(tiers_dir=TIERS_DIR):
    tiers = {}
    for fn in sorted(os.listdir(tiers_dir)):
        name, ext = os.path.splitext(fn)
        if ext not in (".py", ".sh") or name.startswith(("_", "test_")):
            continue
        if name in tiers:
            raise ValueError(f"tier {name!r} defined twice in {tiers_dir}")
        tiers[name] = os.path.join(tiers_dir, fn)
    return tiers


def parse_tiers(spec):
    out = []
    for t in (spec or "").split(","):
        t = t.strip()
        if not t:
            continue
        if not TIER_NAME.match(t):
            raise ValueError(f"invalid tier name {t!r}")
        if t not in out:
            out.append(t)
    if not out:
        raise ValueError("no tiers selected")
    return out


def tier_needs_build(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for _, line in zip(range(30), f):
            m = NEEDS.search(line)
            if m and "build" in re.split(r"[\s,]+", m.group(1).strip()):
                return True
    return False


def _command(path):
    return [sys.executable, path] if path.endswith(".py") else ["bash", path]


def _stream(cmd, env, log_path, cwd):
    """Run cmd, teeing combined stdout/stderr to the console and log_path."""
    with open(log_path, "w", encoding="utf-8", newline="\n") as log:
        try:
            p = subprocess.Popen(cmd, env=env, cwd=cwd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                 errors="replace")
        except OSError as e:
            log.write(f"cannot start {cmd}: {e}\n")
            print(f"  cannot start {cmd}: {e}", file=sys.stderr)
            return 127
        with p:
            for line in p.stdout:
                sys.stdout.write("  " + line)
                sys.stdout.flush()
                log.write(line)
            return p.wait()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tiers", default=os.environ.get("TIERS", "selftest"))
    ap.add_argument("--runs", type=int, default=int(os.environ.get("RUNS", "5")))
    ap.add_argument("--run-dir", help="exact output directory (default <out-root>/<utc-ts>)")
    ap.add_argument("--out-root", default=os.path.join(REPO_ROOT, "bench-results"))
    ap.add_argument("--build", choices=("auto", "always", "never"), default="auto")
    ap.add_argument("--tiers-dir", default=TIERS_DIR)
    ap.add_argument("--go-algorand", default=os.environ.get(
        "GO_ALGORAND_DIR", os.path.join(os.path.dirname(REPO_ROOT), "go-algorand")))
    ap.add_argument("--bin-dir", default=os.environ.get(
        "BENCH_BIN_DIR", os.path.join(REPO_ROOT, "target", "bench-compare")))
    args = ap.parse_args(argv)

    try:
        available = discover_tiers(args.tiers_dir)
        selected = parse_tiers(args.tiers)
    except ValueError as e:
        print(f"bench-compare: {e}", file=sys.stderr)
        return 2
    unknown = [t for t in selected if t not in available]
    if unknown:
        print(f"bench-compare: unknown tier(s) {', '.join(unknown)}; available: "
              f"{', '.join(sorted(available)) or '(none)'}", file=sys.stderr)
        return 2
    if args.runs < 1:
        print("bench-compare: RUNS must be >= 1", file=sys.stderr)
        return 2

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = os.path.abspath(args.run_dir or os.path.join(args.out_root, ts))
    os.makedirs(os.path.join(run_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(run_dir, "results"), exist_ok=True)
    print(f"bench-compare: tiers={','.join(selected)} runs={args.runs} -> {run_dir}")

    expected_tag = os.environ.get("GO_ALGORAND_REV") or fingerprint.read_pin()
    fp = fingerprint.collect(REPO_ROOT, args.go_algorand, expected_tag)
    with open(os.path.join(run_dir, "fingerprint.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(fp, f, indent=2)
        f.write("\n")
    for w in fp["warnings"]:
        print(f"  fairness warning: {w}")

    status = []
    build_info = os.path.join(run_dir, "build-info.json")
    needs = {t: tier_needs_build(available[t]) for t in selected}
    built = None
    if args.build == "always" or (args.build == "auto" and any(needs.values())):
        print("== build (build_both.sh)")
        t0 = time.monotonic()
        rc = _stream(["bash", os.path.join(HERE, "build_both.sh"), "--out", run_dir,
                      "--bin-dir", args.bin_dir, "--go-algorand", args.go_algorand],
                     dict(os.environ, GO_ALGORAND_REV=expected_tag),
                     os.path.join(run_dir, "logs", "build.log"), REPO_ROOT)
        status.append({"tier": "build", "exit_code": rc,
                       "duration_s": round(time.monotonic() - t0, 3), "log": "logs/build.log"})
        built = rc == 0

    for t in selected:
        out = os.path.join(run_dir, "results", t)
        os.makedirs(out, exist_ok=True)
        log_rel = f"logs/{t}.log"
        if needs[t] and not built:
            reason = "build failed" if built is False else "build skipped (--build never)"
            print(f"== {t}: SKIPPED ({reason})")
            with open(os.path.join(run_dir, log_rel), "w", encoding="utf-8") as f:
                f.write(f"skipped: {reason}\n")
            status.append({"tier": t, "exit_code": "skipped", "duration_s": 0.0,
                           "log": log_rel, "reason": reason})
            continue
        env = dict(os.environ,
                   BENCH_TIER=t, BENCH_RUNS=str(args.runs), BENCH_OUT=out,
                   BENCH_RUN_DIR=run_dir, BENCH_REPO_ROOT=REPO_ROOT,
                   BENCH_GO_ALGORAND_DIR=os.path.abspath(args.go_algorand),
                   BENCH_BIN_DIR=os.path.abspath(args.bin_dir),
                   BENCH_GO_BIN_DIR=os.path.join(os.path.abspath(args.bin_dir), "go"),
                   BENCH_RUST_BIN_DIR=os.path.join(os.path.abspath(args.bin_dir), "rust"),
                   BENCH_BUILD_INFO=build_info,
                   BENCH_SCHEMA=os.path.join(HERE, "schema", "result-v1.json"))
        print(f"== {t}")
        t0 = time.monotonic()
        rc = _stream(_command(available[t]), env, os.path.join(run_dir, log_rel), REPO_ROOT)
        status.append({"tier": t, "exit_code": rc,
                       "duration_s": round(time.monotonic() - t0, 3), "log": log_rel})
        print(f"== {t}: exit {rc}")

    with open(os.path.join(run_dir, "tier-status.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(status, f, indent=2)
        f.write("\n")
    rc = report.main([run_dir])
    failed = any(s["exit_code"] != 0 for s in status)
    return 1 if failed or rc != 0 else 0


if __name__ == "__main__":
    sys.exit(main())
