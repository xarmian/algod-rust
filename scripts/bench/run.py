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
        [--run-dir DIR [--clean] | --out-root bench-results] [--build auto|always|never]
"""
import argparse
import datetime
import json
import os
import re
import shutil
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


# Everything a run writes. --clean removes exactly these, nothing else.
RUN_ARTIFACTS = ("results", "logs", "fingerprint.json", "build-info.json",
                 "tier-status.json", "report.json", "report.md")


def prepare_run_dir(run_dir, clean):
    """Make sure no artifact of an earlier run can leak into this one.

    report.py merges every results/**/*.json and reads build-info.json, so a
    reused directory would silently mix two runs. A missing or empty
    directory is fine; a non-empty one needs clean=True, which removes the
    run artifacts (and refuses if anything else is in there).
    """
    if not os.path.isdir(run_dir) or not os.listdir(run_dir):
        return
    if not clean:
        raise ValueError(f"run dir {run_dir} is not empty; pass --clean (make: BENCH_CLEAN=1) "
                         "to clear the previous run, or choose another directory")
    other = sorted(set(os.listdir(run_dir)) - set(RUN_ARTIFACTS))
    if other:
        raise ValueError(f"run dir {run_dir} contains non-run files {other}; refusing to clean it")
    for name in RUN_ARTIFACTS:
        p = os.path.join(run_dir, name)
        if os.path.isdir(p):
            shutil.rmtree(p)
        elif os.path.exists(p):
            os.remove(p)


def use_prebuilt(bin_dir, dest):
    """Adopt <bin_dir>/build-info.json (from build_both.sh) as the run's build info.

    Returns an error string, or None when build-info.json exists and every
    binary it lists is present under bin_dir.
    """
    src = os.path.join(bin_dir, "build-info.json")
    try:
        with open(src, encoding="utf-8") as f:
            info = json.load(f)
    except (OSError, ValueError) as e:
        return f"cannot read {src}: {e}"
    for side in ("go_algorand", "algod_rust"):
        for rel in (info.get(side) or {}).get("binaries") or []:
            if not os.path.isfile(os.path.join(bin_dir, rel)):
                return f"{side} binary {rel} listed in {src} is missing"
    shutil.copyfile(src, dest)
    return None


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
    # The env default stays a string: argparse only converts it (type=int,
    # exit 2 on garbage) when --runs is absent, so a bad RUNS env var cannot
    # break an explicit --runs.
    ap.add_argument("--runs", type=int, default=os.environ.get("RUNS", "5"))
    ap.add_argument("--run-dir", help="exact output directory (default <out-root>/<utc-ts>)")
    ap.add_argument("--clean", action="store_true",
                    help="clear a reused --run-dir's previous artifacts first "
                         "(a non-empty run dir is refused otherwise)")
    ap.add_argument("--out-root", default=os.path.join(REPO_ROOT, "bench-results"))
    ap.add_argument("--build", choices=("auto", "always", "never", "prebuilt"), default="auto",
                    help="prebuilt: binaries and build-info.json were already made by "
                         "build_both.sh into --bin-dir (CI builds once, e.g. to make the "
                         "Docker image from the same binary); no build, tiers are not skipped")
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
    try:
        prepare_run_dir(run_dir, args.clean)
    except ValueError as e:
        print(f"bench-compare: {e}", file=sys.stderr)
        return 2
    os.makedirs(os.path.join(run_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(run_dir, "results"), exist_ok=True)
    print(f"bench-compare: tiers={','.join(selected)} runs={args.runs} -> {run_dir}")

    expected_tag = os.environ.get("GO_ALGORAND_REV") or fingerprint.read_pin()

    def write_fingerprint():
        fp = fingerprint.collect(REPO_ROOT, args.go_algorand, expected_tag)
        with open(os.path.join(run_dir, "fingerprint.json"), "w", encoding="utf-8",
                  newline="\n") as f:
            json.dump(fp, f, indent=2)
            f.write("\n")
        return fp

    for w in write_fingerprint()["warnings"]:
        print(f"  fairness warning: {w}")

    status = []
    build_info = os.path.join(run_dir, "build-info.json")
    needs = {t: tier_needs_build(available[t]) for t in selected}
    built = None
    if args.build == "prebuilt":
        err = use_prebuilt(args.bin_dir, build_info)
        if err:
            print(f"bench-compare: --build prebuilt: {err}", file=sys.stderr)
            return 2
        built = True
        write_fingerprint()
    elif args.build == "always" or (args.build == "auto" and any(needs.values())):
        print("== build (build_both.sh)")
        t0 = time.monotonic()
        rc = _stream(["bash", os.path.join(HERE, "build_both.sh"), "--out", run_dir,
                      "--bin-dir", args.bin_dir, "--go-algorand", args.go_algorand],
                     dict(os.environ, GO_ALGORAND_REV=expected_tag),
                     os.path.join(run_dir, "logs", "build.log"), REPO_ROOT)
        status.append({"tier": "build", "exit_code": rc,
                       "duration_s": round(time.monotonic() - t0, 3), "log": "logs/build.log"})
        built = rc == 0
        if built:
            write_fingerprint()  # the build may have cloned / checked out go-algorand

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
