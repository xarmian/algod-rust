#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""bench-compare `micro` tier: paired Go/Rust micro-benchmarks (issue #2103,
epic #2101).

For every benchmarks/pairs.toml pair it times the go-algorand function with
Go's testing.B (benchmarks/go-micro) and the algod-rust function with
criterion (crates/tools/algo-bench-pairs, bench target `pairs`) on the same
fixture bytes, and writes one schema-v1 result per side, so the report shows
a Rust/Go ratio for every pair.

No `bench-tier-needs: build`: it needs no algod binaries, only `go` and
`cargo`. It builds the Go side against $BENCH_GO_ALGORAND_DIR (pinned tag
enforced, libsodium built when missing) through a generated go.work.

Steps (the tier fails at the first one that fails):
  1. fixture sha256s against the registry;
  2. output equivalence: every pair once on both sides, identical digests
     required (scripts/bench/micro_equiv.py);
  3. BENCH_MICRO_WARMUP (default 1) discarded warm-up rounds;
  4. BENCH_RUNS measured rounds, alternating which side goes first. A Go
     round is `go test -run '^$' -bench <regex> -benchmem -count=1`, one
     ns/op per pair; a Rust round is one `cargo bench`, whose sample per pair
     is the median of criterion's per-sample times (new/sample.json, time /
     iterations), so each side contributes BENCH_RUNS real samples measured
     in interleaved rounds;
  5. results/micro/micro.json.

Knobs: BENCH_MICRO_FILTER (regex on pair ids), BENCH_MICRO_GO_BENCHTIME (go
-benchtime, e.g. 500ms), BENCH_MICRO_CRITERION_ARGS (e.g. "--warm-up-time 1
--measurement-time 2"), BENCH_MICRO_WARMUP.
"""
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
sys.path.insert(0, BENCH)
import bench_schema  # noqa: E402
import micro_convert as mc  # noqa: E402
import micro_equiv as eq  # noqa: E402

TIER = "micro"


def stream(cmd, cwd, env):
    """Run cmd, echoing its output; return (exit code, captured text)."""
    print("$ " + " ".join(shlex.quote(c) for c in cmd), flush=True)
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                         errors="replace")
    lines = []
    with p:
        for line in p.stdout:
            sys.stdout.write(line)
            lines.append(line)
    sys.stdout.flush()
    return p.wait(), "".join(lines)


def go_round(pairs, env):
    cmd = ["go", "test", "-run", "^$", "-bench", mc.go_bench_regex(p["go_bench"] for p in pairs),
           "-benchmem", "-count=1", "-timeout", "120m"]
    if os.environ.get("BENCH_MICRO_GO_BENCHTIME"):
        cmd += ["-benchtime", os.environ["BENCH_MICRO_GO_BENCHTIME"]]
    rc, out = stream(cmd + ["."], eq.GO_MODULE, env)
    if rc != 0:
        raise eq.SetupError(f"go test -bench exited {rc}")
    parsed = mc.parse_go_bench(out)
    res = {}
    for p in pairs:
        d = parsed.get(p["go_bench"])
        if not d or len(d["ns_op"]) != 1:
            raise eq.SetupError(f"{p['id']}: no single {p['go_bench']} result in go output")
        res[p["id"]] = {k: (v[0] if v else None) for k, v in d.items()}
    return res, " ".join(cmd)


def rust_round(pairs, work, n, selected_all):
    home = os.path.join(work, f"criterion-{n}")
    cmd = ["cargo", "bench", "--locked", "-p", "algo-bench-pairs", "--bench", "pairs", "--",
           "--noplot"] + shlex.split(os.environ.get("BENCH_MICRO_CRITERION_ARGS", ""))
    if not selected_all:
        cmd.append("^(" + "|".join(re.escape(p["id"]) for p in pairs) + ")$")
    rc, _ = stream(cmd, eq.REPO, dict(os.environ, CRITERION_HOME=home))
    if rc != 0:
        raise eq.SetupError(f"cargo bench exited {rc}")
    runs = mc.criterion_runs(home)
    res = {}
    for p in pairs:
        if p["rust_bench"] not in runs:
            raise eq.SetupError(f"{p['id']}: criterion wrote no result for {p['rust_bench']}")
        res[p["id"]] = runs[p["rust_bench"]]
    return res, " ".join(cmd)


def main():
    runs = int(os.environ.get("BENCH_RUNS", "5"))
    warmup = int(os.environ.get("BENCH_MICRO_WARMUP", "1"))
    out = os.environ.get("BENCH_OUT") or os.getcwd()
    if runs < 1 or warmup < 0:
        print("micro: BENCH_RUNS must be >= 1 and BENCH_MICRO_WARMUP >= 0", file=sys.stderr)
        return 2
    os.makedirs(out, exist_ok=True)

    reg = mc.load_registry(eq.REGISTRY)
    pairs = reg["pair"]
    filt = os.environ.get("BENCH_MICRO_FILTER")
    if filt:
        pairs = [p for p in pairs if re.search(filt, p["id"])]
        if not pairs:
            print(f"micro: BENCH_MICRO_FILTER={filt!r} selects no pair", file=sys.stderr)
            return 2
    selected_all = len(pairs) == len(reg["pair"])
    fixture_dir = os.path.join(eq.REPO, reg["fixture_dir"])

    errors = mc.check_fixtures(reg, eq.REPO)
    if errors:
        print("micro: fixture check failed:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1

    go_dir = eq.default_go_algorand()
    try:
        tag, go_commit = eq.check_pin(go_dir)
        eq.ensure_libsodium(go_dir)
        with tempfile.TemporaryDirectory(prefix="bench-micro-") as work:
            env = eq.go_env(go_dir, work)

            print(f"== micro: output equivalence ({len(pairs)} pairs, go-algorand {tag})",
                  flush=True)
            go_d = eq.go_digests(env, fixture_dir)
            rust_d = eq.rust_digests(fixture_dir)
            ids = [p["id"] for p in pairs]
            diffs = eq.check(ids, go_d, rust_d)
            if diffs:
                print("micro: output equivalence FAILED, not benchmarking:\n  "
                      + "\n  ".join(diffs), file=sys.stderr)
                return 1

            samples = {p["id"]: {"go": [], "rust": [], "go_runs": [], "rust_runs": []}
                       for p in pairs}
            commands = {}
            total = warmup + runs
            for i in range(total):
                measured = i >= warmup
                label = f"run {i - warmup + 1}/{runs}" if measured else f"warm-up {i + 1}/{warmup}"
                order = ("go", "rust") if i % 2 == 0 else ("rust", "go")
                for impl in order:
                    print(f"== micro: {label}: {impl}", flush=True)
                    if impl == "go":
                        res, commands["go"] = go_round(pairs, env)
                    else:
                        res, commands["rust"] = rust_round(pairs, work, i, selected_all)
                    if not measured:
                        continue
                    for pid, r in res.items():
                        value = r["ns_op"] if impl == "go" else r["value"]
                        samples[pid][impl].append(value)
                        samples[pid][impl + "_runs"].append(r)
    except eq.SetupError as e:
        print(f"micro: {e}", file=sys.stderr)
        return 1

    results = []
    for p in pairs:
        s = samples[p["id"]]
        common = {"input": f"{reg['fixture_dir']}/{p['fixture']}",
                  "input_sha256": p["fixture_sha256"], "output_digest": go_d[p["id"]],
                  "warmup_rounds": warmup, "interleaved": True}
        results.append(mc.make_result(p, "go", s["go"], dict(
            common, harness="go testing.B", package=p["go_package"], benchmark=p["go_bench"],
            api=p["go_api"], go_algorand_tag=tag, go_algorand_commit=go_commit,
            command=commands["go"], benchtime=os.environ.get("BENCH_MICRO_GO_BENCHTIME", "1s"),
            iterations=[r["iterations"] for r in s["go_runs"]],
            bytes_per_op=[r["b_op"] for r in s["go_runs"]],
            allocs_per_op=[r["allocs_op"] for r in s["go_runs"]])))
        results.append(mc.make_result(p, "rust", s["rust"], dict(
            common, harness="criterion", package="algo-bench-pairs", benchmark=p["rust_bench"],
            api=p["rust_api"], command=commands["rust"],
            sample_value="median of new/sample.json per-iteration times",
            criterion_samples=[r.get("samples") for r in s["rust_runs"]],
            sampling_mode=[r.get("sampling_mode") for r in s["rust_runs"]])))

    errs = [e for r in results for e in bench_schema.validate_result(r)]
    if errs:
        print("micro: produced invalid results:\n  " + "\n  ".join(errs), file=sys.stderr)
        return 1
    path = os.path.join(out, "micro.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(results, f, indent=2)
        f.write("\n")
    print(f"micro: {len(pairs)} pairs x {runs} run(s) per side -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
