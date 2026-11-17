#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""bench-compare `teal-corpus` tier: go-algorand's TEAL assembler/disassembler
against algod-rust's on the real-world ARC56Registry corpus, behind an
output-equality gate (issue #2371, epic #2364).

The corpus is the one `make teal-corpus-fetch` extracts (a fresh clone of the
registry at a recorded SHA; scripts/teal-corpus/). Both sides are the batch
drivers of tools/teal-corpus (Go, built against the pinned go-algorand) and
crates/tools/teal-corpus (Rust), run single-threaded (`--jobs 1`), one process
per run, over the same inputs:

  disassemble/all             every program, disassembled
  assemble-disassembled/all   go's disassembly of every program, assembled
  assemble-sources/all        every original ARC-56 source, assembled
  disassemble/top<N>          the N largest programs (stable micro row)
  assemble-sources/top<N>     the N largest sources (stable micro row)

Equality gate: after every run of a workload both sides' JSONL rows (header
excluded) must be byte-identical and neither may record a timeout or a
panic that the other side does not reproduce; otherwise the workload's
timings are WITHHELD (no result row is written for it) and the tier exits 1.
Per workload and side the rows are wall_s (batch wall clock), programs_per_s,
MB_per_s (input bytes), and the per-program p50_us / p99_us (measured around
the work itself inside the worker). A discarded warm-up pair precedes the
BENCH_RUNS measured pairs, which alternate which side goes first.

Inputs (environment; plus the tier contract BENCH_RUNS, BENCH_OUT,
BENCH_GO_ALGORAND_DIR, see docs/BENCHMARK_COMPARISON.md):
  BENCH_TEAL_CORPUS_DIR     corpus directory (default teal-corpus-work/corpus)
  BENCH_TEAL_TOPN           size of the largest-programs subset (default 20)
  BENCH_TEAL_WARMUP         discarded warm-up pairs (default 1)
  BENCH_TEAL_GO_DRIVER      a prebuilt Go driver (default: built here)
  BENCH_TEAL_RUST_DRIVER    a prebuilt Rust driver (default: cargo build --release)
  BENCH_TEAL_CORRUPT        negative test: alter one Rust output row before the
                            gate; the tier must fail and withhold the timings
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(BENCH))
sys.path.insert(0, BENCH)
import bench_schema  # noqa: E402,F401

TIER = "teal-corpus"
MB = 1e6
TIMEOUT_MS = "60000"
SCRATCH_PANIC = "runtime error: index out of range ["


class TierError(Exception):
    pass


def log(msg):
    print(f"teal-corpus: {msg}", flush=True)


# ---- pure helpers (unit-tested) ----------------------------------------------

def percentile(sorted_vals, p):
    """Nearest-rank percentile of an ascending list."""
    if not sorted_vals:
        return 0
    import math
    return sorted_vals[max(0, math.ceil(p / 100 * len(sorted_vals)) - 1)]


def metrics_from_timings(t):
    """The measured numbers of one driver run from its --timings document."""
    wall_s = t["wall_ns"] / 1e9
    per_us = sorted(v / 1e3 for v in t["per_program_ns"].values())
    return {
        "wall_s": ("s", "lower", wall_s),
        "programs_per_s": ("programs/s", "higher", t["inputs"] / wall_s if wall_s > 0 else 0.0),
        "MB_per_s": ("MB/s", "higher", t["input_bytes"] / MB / wall_s if wall_s > 0 else 0.0),
        "p50_us": ("us", "lower", percentile(per_us, 50)),
        "p99_us": ("us", "lower", percentile(per_us, 99)),
    }


def read_output(path):
    """(header dict, list of row lines) of a driver JSONL file."""
    with open(path, "rb") as f:
        lines = [ln for ln in f.read().split(b"\n") if ln]
    header = json.loads(lines[0])["header"] if lines else {}
    return header, lines[1:]


def gate_errors(go_rows, rust_rows):
    """Why the two sides' outputs are not interchangeable ([] when they are)."""
    errs = []
    robust = []
    for side, rows in (("go", go_rows), ("rust", rust_rows)):
        for ln in rows:
            v = json.loads(ln)
            if v.get("timeout") is True:
                robust.append(f"{side} timeout on {v.get('sha256')}")
            elif v.get("panic") is not None and not (
                    go_rows == rust_rows and str(v["panic"]).startswith(SCRATCH_PANIC)):
                robust.append(f"{side} panic on {v.get('sha256')}: {v['panic']}")
    errs.extend(robust[:5])
    if go_rows != rust_rows:
        shas_g = {json.loads(r)["sha256"]: r for r in go_rows}
        shas_r = {json.loads(r)["sha256"]: r for r in rust_rows}
        bad = sorted(s for s in set(shas_g) | set(shas_r) if shas_g.get(s) != shas_r.get(s))
        errs.append(f"{len(bad)} of {len(set(shas_g) | set(shas_r))} rows differ, first {bad[0]}")
    return errs


def select_largest(manifest, n, key="size"):
    """sha256s of the n largest entries, ties broken by sha256 (deterministic)."""
    return [m["sha256"] for m in sorted(manifest, key=lambda m: (-m[key], m["sha256"]))[:n]]


def read_manifest(corpus):
    with open(os.path.join(corpus, "manifest.jsonl"), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def stage_subset(src_dir, ext, shas, dst):
    os.makedirs(dst, exist_ok=True)
    for s in shas:
        shutil.copyfile(os.path.join(src_dir, f"{s}.{ext}"), os.path.join(dst, f"{s}.{ext}"))
    return dst


def largest_sources(corpus, n):
    """sha256s of the n largest distinct source files by byte length."""
    d = os.path.join(corpus, "sources")
    files = [(os.path.getsize(os.path.join(d, f)), f[:-5]) for f in os.listdir(d) if f.endswith(".teal")]
    return [s for _, s in sorted(files, key=lambda x: (-x[0], x[1]))[:n]]


def write_texts(disassemble_out, dst):
    """go's disassembly texts as an assemble input directory; returns the count."""
    os.makedirs(dst, exist_ok=True)
    n = 0
    _, rows = read_output(disassemble_out)
    for ln in rows:
        v = json.loads(ln)
        if v.get("ok") and v.get("text") is not None:
            data = v["text"].encode("utf-8")
            with open(os.path.join(dst, hashlib.sha256(data).hexdigest() + ".teal"), "wb") as f:
                f.write(data)
            n += 1
    return n


def result_rows(workload, per_side, meta):
    """schema-v1 rows of one gated workload: per_side[impl] = list of metrics dicts (one per run)."""
    rows = []
    for impl in ("go", "rust"):
        names = per_side[impl][0].keys()
        for m in names:
            unit, better, _ = per_side[impl][0][m]
            rows.append({
                "schema": "bench-result/v1", "tier": TIER, "name": f"{workload}/{m}", "impl": impl,
                "unit": unit, "better": better,
                "samples": [round(run[m][2], 6) for run in per_side[impl]],
                "metadata": dict(meta, workload=workload),
            })
    return rows


# ---- running -----------------------------------------------------------------

def run_driver(exe, side, op, corpus, input_dir, work, tag):
    out = os.path.join(work, f"{tag}.{side}.jsonl")
    tim = os.path.join(work, f"{tag}.{side}.timings.json")
    cmd = [exe, op, "--corpus", corpus, "--input-dir", input_dir, "--out", out, "--jobs", "1",
           "--timeout-ms", TIMEOUT_MS, "--timings", tim]
    rc = subprocess.run(cmd).returncode
    if rc not in (0, 3):  # 3: a panic/timeout row was recorded; the gate judges it
        raise TierError(f"{side} driver exited {rc}: {' '.join(cmd)}")
    with open(tim, encoding="utf-8") as f:
        return out, json.load(f), " ".join(cmd)


def corrupt_rust(path):
    header, rows = read_output(path)
    if not rows:
        raise TierError("BENCH_TEAL_CORRUPT: nothing to corrupt")
    v = json.loads(rows[0])
    v["ok"] = not v.get("ok", False)
    rows[0] = json.dumps(v, sort_keys=True).encode()
    with open(path, "wb") as f:
        f.write(json.dumps({"header": header}).encode() + b"\n" + b"\n".join(rows) + b"\n")


def measure(drivers, workload, op, corpus, input_dir, work, runs, warmup, corrupt):
    """Run the gated pair `warmup + runs` times. Returns (metrics per side, meta, go output path)."""
    per_side = {"go": [], "rust": []}
    meta = {}
    go_out = None
    for i in range(warmup + runs):
        order = ("go", "rust") if i % 2 == 0 else ("rust", "go")
        res = {}
        for side in order:
            res[side] = run_driver(drivers[side], side, op, corpus, input_dir, work,
                                   workload.replace("/", "-"))
        if corrupt:
            corrupt_rust(res["rust"][0])
        gh, grows = read_output(res["go"][0])
        _, rrows = read_output(res["rust"][0])
        errs = gate_errors(grows, rrows)
        if errs:
            raise TierError(f"{workload}: equality gate FAILED (timings withheld):\n  " + "\n  ".join(errs))
        kind = "warm-up" if i < warmup else f"run {i - warmup + 1}/{runs}"
        gw, rw = res["go"][1]["wall_ns"] / 1e9, res["rust"][1]["wall_ns"] / 1e9
        log(f"{workload}: {kind}: go {gw:.3f}s, rust {rw:.3f}s, {len(grows)} rows identical")
        if i >= warmup:
            for side in ("go", "rust"):
                per_side[side].append(metrics_from_timings(res[side][1]))
            meta = {"inputs": res["go"][1]["inputs"], "input_bytes": res["go"][1]["input_bytes"],
                    "rows": len(grows), "rows_sha256": hashlib.sha256(b"\n".join(grows)).hexdigest(),
                    "go_command": res["go"][2], "rust_command": res["rust"][2],
                    "go_algorand_tag": gh.get("go_algorand_tag"),
                    "go_algorand_commit": gh.get("go_algorand_commit")}
            go_out = res["go"][0]
    return per_side, meta, go_out


def build_drivers(work):
    env_go, env_rs = os.environ.get("BENCH_TEAL_GO_DRIVER"), os.environ.get("BENCH_TEAL_RUST_DRIVER")
    exe = ".exe" if os.name == "nt" else ""
    if not env_go:
        import micro_equiv as eq
        go_dir = os.path.abspath(os.environ.get("BENCH_GO_ALGORAND_DIR")
                                 or os.path.join(os.path.dirname(REPO), "go-algorand"))
        eq.check_pin(go_dir)
        eq.ensure_libsodium(go_dir)
        module = os.path.join(REPO, "tools", "teal-corpus")
        gowork = os.path.join(work, "go.work")
        go_line = next(line.strip() for line in open(os.path.join(module, "go.mod"), encoding="utf-8")
                       if line.startswith("go "))
        with open(gowork, "w", encoding="utf-8", newline="\n") as f:
            f.write(f"{go_line}\n\nuse {module}\n\nreplace github.com/algorand/go-algorand => {go_dir}\n")
        env_go = os.path.join(work, "teal-corpus-go" + exe)
        env = dict(os.environ, GOWORK=gowork, GO_ALGORAND_DIR=go_dir,
                   GOFLAGS=os.environ.get("GOFLAGS", "-buildvcs=false"))
        rc = subprocess.run(["bash", os.path.join(module, "build.sh"), env_go], env=env).returncode
        if rc != 0:
            raise TierError(f"building the Go driver exited {rc}")
    if not env_rs:
        rc = subprocess.run(["cargo", "build", "-p", "teal-corpus", "--release"], cwd=REPO).returncode
        if rc != 0:
            raise TierError(f"cargo build -p teal-corpus exited {rc}")
        target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(REPO, "target")
        env_rs = os.path.join(target, "release", "teal-corpus" + exe)
    for p in (env_go, env_rs):
        if not os.path.isfile(p):
            raise TierError(f"driver {p} missing")
    return {"go": env_go, "rust": env_rs}


def git_head():
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    runs = int(os.environ.get("BENCH_RUNS", "5"))
    warmup = int(os.environ.get("BENCH_TEAL_WARMUP", "1"))
    topn = int(os.environ.get("BENCH_TEAL_TOPN", "20"))
    out_dir = os.environ.get("BENCH_OUT") or os.getcwd()
    corrupt = bool(os.environ.get("BENCH_TEAL_CORRUPT"))
    if runs < 1 or warmup < 0 or topn < 1:
        print("teal-corpus: BENCH_RUNS >= 1, BENCH_TEAL_WARMUP >= 0, BENCH_TEAL_TOPN >= 1", file=sys.stderr)
        return 2
    os.makedirs(out_dir, exist_ok=True)
    corpus = os.path.abspath(os.environ.get("BENCH_TEAL_CORPUS_DIR")
                             or os.path.join(REPO, "teal-corpus-work", "corpus"))
    failures, results = [], []
    try:
        if not os.path.isfile(os.path.join(corpus, "manifest.jsonl")):
            raise TierError(f"no corpus at {corpus}: run `make teal-corpus-fetch` (network) or set "
                            "BENCH_TEAL_CORPUS_DIR")
        manifest = read_manifest(corpus)
        info = {}
        try:
            with open(os.path.join(corpus, "corpus.json"), encoding="utf-8") as f:
                info = json.load(f)
        except (OSError, ValueError):
            pass
        base_meta = {"corpus_dir": corpus, "registry_sha": info.get("registry_sha"),
                     "manifest_sha256": sha256_file(os.path.join(corpus, "manifest.jsonl")),
                     "programs": len(manifest), "jobs": 1, "warmup": warmup,
                     "algod_rust_commit": git_head()}
        with tempfile.TemporaryDirectory(prefix="bench-teal-corpus-") as work:
            drivers = build_drivers(work)
            top_programs = stage_subset(os.path.join(corpus, "programs"), "bin",
                                        select_largest(manifest, topn), os.path.join(work, "top-programs"))
            top_sources = stage_subset(os.path.join(corpus, "sources"), "teal",
                                       largest_sources(corpus, topn), os.path.join(work, "top-sources"))
            texts = os.path.join(work, "texts")
            plan = [("disassemble/all", "disassemble", os.path.join(corpus, "programs")),
                    ("assemble-disassembled/all", "assemble", texts),
                    ("assemble-sources/all", "assemble", os.path.join(corpus, "sources")),
                    (f"disassemble/top{topn}", "disassemble", top_programs),
                    (f"assemble-sources/top{topn}", "assemble", top_sources)]
            disassembled = None
            for workload, op, input_dir in plan:
                try:
                    if workload == "assemble-disassembled/all":
                        if disassembled is None:
                            raise TierError("needs a passing disassemble/all (go's texts are its input)")
                        n = write_texts(disassembled, texts)
                        log(f"{workload}: {n} disassembly texts staged")
                    per_side, meta, go_out = measure(drivers, workload, op, corpus, input_dir, work,
                                                     runs, warmup, corrupt)
                    if workload == "disassemble/all":
                        disassembled = go_out
                    results.extend(result_rows(workload, per_side, dict(base_meta, **meta)))
                except TierError as e:
                    failures.append(str(e))
                    log(f"FAILED {e}")
    except TierError as e:
        failures.append(str(e))
        log(f"FAILED {e}")
    if results:
        with open(os.path.join(out_dir, "teal-corpus.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(results, f, indent=1)
    if failures:
        print(f"teal-corpus: {len(failures)} workload(s) failed; their timings were withheld", file=sys.stderr)
        return 1
    log(f"equality gate passed for every workload ({runs} runs per side)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
