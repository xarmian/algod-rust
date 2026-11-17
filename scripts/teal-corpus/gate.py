#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Pass condition, job summary and tracking-issue text of the nightly TEAL corpus
parity workflow (issue #2372, epic #2364; .github/workflows/teal-corpus-parity.yml).

  gate.py extraction CORPUS_DIR [--min-programs N] [--max-skip-ratio R]
  gate.py verdict STATS_JSON [--require-rest]
  gate.py summary [--stats STATS_JSON] [--corpus CORPUS_DIR] [--bench REPORT_MD] [--require-rest]
  gate.py bench-table RESULT_JSON
  gate.py bundle CORPUS_DIR OUT_DIR DEST_DIR [--max N]
  gate.py issue-body --stats STATS_JSON --run-url URL [--registry-ref REF] [--go-ref REF] [--require-rest]

The job is green only when the registry was extracted (at least --min-programs
programs, skipped entries at most --max-skip-ratio of all entries: an empty corpus
or a changed registry layout must not pass), every offline stage (disassemble,
reassemble, source) is present and compared every program it should, and no stage
(nor the REST sample when it ran or is required) has a mismatch, a panic or a
timeout. There is no allow-list: identical errors and the go assembler
scratch-index panic the port mirrors (#2381) are agreement, everything else is a
failure.

Exit 0 when the check passes, 1 when it fails, 2 on a usage error.
"""
import argparse
import glob
import json
import os
import shutil
import sys

OFFLINE_STAGES = ("disassemble", "reassemble", "source")
REST_STAGE = "rest_sample"
DEFAULT_MIN_PROGRAMS = int(os.environ.get("TEAL_CORPUS_MIN_PROGRAMS", "1000"))
DEFAULT_MAX_SKIP_RATIO = float(os.environ.get("TEAL_CORPUS_MAX_SKIP_RATIO", "0.05"))


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def check_extraction(corpus_dir, min_programs=DEFAULT_MIN_PROGRAMS, max_skip_ratio=DEFAULT_MAX_SKIP_RATIO):
    """Failures (empty list = pass) of the extractor's output."""
    info = _read_json(os.path.join(corpus_dir, "corpus.json"))
    if not isinstance(info, dict):
        return [f"extraction: {corpus_dir}/corpus.json is missing or unreadable"]
    counts = info.get("counts") or {}
    programs = counts.get("programs", 0)
    entries = counts.get("entries", 0)
    skipped = sum((info.get("skipped") or {}).values())
    fails = []
    if programs < min_programs:
        fails.append(f"extraction: only {programs} programs extracted (need at least {min_programs}); "
                     "the registry layout may have changed")
    if entries and skipped / entries > max_skip_ratio:
        fails.append(f"extraction: {skipped} of {entries} registry entries skipped "
                     f"({skipped / entries:.1%} > {max_skip_ratio:.1%}): {info.get('skipped')}")
    try:
        with open(os.path.join(corpus_dir, "manifest.jsonl"), encoding="utf-8") as f:
            rows = sum(1 for line in f if line.strip())
    except OSError:
        return fails + ["extraction: manifest.jsonl is missing"]
    if rows != programs:
        fails.append(f"extraction: manifest has {rows} rows but corpus.json counts {programs} programs")
    return fails


def check_stats(stats, require_rest=False):
    """Failures (empty list = pass) of a stats.json (stats.py `build`)."""
    fails = []
    stages = stats.get("stages") or {}
    programs = (stats.get("corpus") or {}).get("programs", 0)
    wanted = list(OFFLINE_STAGES) + ([REST_STAGE] if require_rest else [])
    for name in wanted:
        if name not in stages:
            fails.append(f"{name}: stage missing from stats (it did not run)")
    for name, s in stages.items():
        if s.get("compared", 0) == 0:
            fails.append(f"{name}: compared 0 rows")
        for key in ("mismatched", "panics", "timeouts"):
            if s.get(key, 0):
                fails.append(f"{name}: {s[key]} {key}")
    dis = stages.get("disassemble")
    if dis and programs and dis.get("compared") != programs:
        fails.append(f"disassemble: compared {dis.get('compared')} rows for {programs} corpus programs")
    return fails


def _cell(v):
    return "" if v is None else str(v)


def summary_markdown(stats, bench_md, failures, registry_ref=None):
    out = ["## TEAL corpus parity: " + ("PASS" if not failures else "FAIL"), ""]
    if stats:
        run, corpus = stats.get("run") or {}, stats.get("corpus") or {}
        out += ["| | |", "|---|---|",
                f"| registry SHA | `{_cell(corpus.get('registry_sha'))}` |"]
        if registry_ref:
            out.append(f"| registry ref | `{registry_ref}` |")
        out += [f"| go-algorand pin | `{_cell(run.get('go_algorand_tag'))}` (`{_cell(run.get('go_algorand_commit'))}`) |",
                f"| algod-rust commit | `{_cell(run.get('algod_rust_commit'))}` |",
                f"| programs | {_cell(corpus.get('programs'))} |", "",
                "| stage | compared | identical | identical error | mirrored panic | mismatched | panics | timeouts |",
                "|---|---|---|---|---|---|---|---|"]
        for name, s in sorted((stats.get("stages") or {}).items()):
            out.append(f"| {name} | {s.get('compared')} | {s.get('identical')} | {s.get('identical_error')} | "
                       f"{s.get('identical_panic_mirrored')} | {s.get('mismatched')} | {s.get('panics')} | "
                       f"{s.get('timeouts')} |")
        out.append("")
    if failures:
        out += ["### Failures", ""] + [f"- {f}" for f in failures] + [""]
    if bench_md:
        out += ["### Benchmark (informational, never a gate)", "", bench_md.strip(), ""]
    return "\n".join(out) + "\n"


def issue_body(stats, failures, run_url, registry_ref=None, go_ref=None):
    corpus = (stats or {}).get("corpus") or {}
    run = (stats or {}).get("run") or {}
    lines = [
        "The nightly TEAL corpus parity check (`.github/workflows/teal-corpus-parity.yml`, epic #2364) failed.",
        "",
        f"- Run (artifacts: `stats.json`, `mismatches.jsonl`, reproducer bundles): {run_url}",
        f"- Registry: ref `{registry_ref or 'main'}`, SHA `{_cell(corpus.get('registry_sha')) or 'unknown'}`",
        f"- go-algorand: `{go_ref or _cell(run.get('go_algorand_tag'))}`; algod-rust `{_cell(run.get('algod_rust_commit'))}`",
        "",
        "### Failures",
        "",
    ]
    lines += [f"- {f}" for f in failures] or ["- (the job failed before a verdict; see the run)"]
    if stats:
        lines += ["", "### Per-stage counts", "", "| stage | compared | mismatched | panics | timeouts |",
                  "|---|---|---|---|---|"]
        for name, s in sorted((stats.get("stages") or {}).items()):
            lines.append(f"| {name} | {s.get('compared')} | {s.get('mismatched')} | {s.get('panics')} | "
                         f"{s.get('timeouts')} |")
    lines += ["", "The Go side is the oracle: a mismatch is an algod-rust bug unless it is a registered "
              "`docs/DIVERGENCES.md` entry (there is none for the TEAL assembler/disassembler). Reproduce locally with "
              "`TEAL_CORPUS_REGISTRY_REF=<registry sha> make teal-corpus-fetch teal-corpus-parity`.",
              "", "This issue is updated by every failing nightly and closed by the first green one."]
    return "\n".join(lines) + "\n"


def bench_table(rows):
    """Markdown table (median of the samples per side) of the teal-corpus bench tier's rows."""
    by = {}
    for r in rows:
        samples = sorted(r.get("samples") or [])
        if not samples:
            continue
        median = samples[len(samples) // 2]
        by.setdefault(r["name"], {})[r["impl"]] = (median, r.get("unit", ""))
    out = ["| workload/metric | unit | go | rust | rust/go |", "|---|---|---|---|---|"]
    for name in sorted(by):
        go, rs = by[name].get("go"), by[name].get("rust")
        unit = (go or rs)[1]
        ratio = f"{rs[0] / go[0]:.2f}" if go and rs and go[0] else ""
        out.append(f"| {name} | {unit} | {go[0] if go else ''} | {rs[0] if rs else ''} | {ratio} |")
    return "\n".join(out) + "\n"


def bundle(corpus_dir, out_dir, dest, max_programs=50):
    """Reproducer bundles: for every sha256 in OUT_DIR/*.mismatches.jsonl (at most
    max_programs) DEST/<sha>/ holds the corpus program/source (and the reassembly
    texts) with that hash and every driver row that mentions it. Returns the shas."""
    shas = []
    for path in sorted(glob.glob(os.path.join(out_dir, "*.mismatches.jsonl"))):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    sha = json.loads(line).get("sha256")
                except ValueError:
                    continue
                if isinstance(sha, str) and len(sha) == 64 and sha not in shas:
                    shas.append(sha)
    shas = shas[:max_programs]
    sources = [(os.path.join(corpus_dir, "programs", "{}.bin"), "program.bin"),
               (os.path.join(corpus_dir, "sources", "{}.teal"), "source.teal"),
               (os.path.join(out_dir, "reasm-go", "sources", "{}.teal"), "reassembly-input.go-text.teal"),
               (os.path.join(out_dir, "reasm-rust", "sources", "{}.teal"), "reassembly-input.rust-text.teal")]
    rows_files = sorted(glob.glob(os.path.join(out_dir, "*.go.jsonl")) + glob.glob(os.path.join(out_dir, "*.rust.jsonl")))
    for sha in shas:
        d = os.path.join(dest, sha)
        os.makedirs(d, exist_ok=True)
        for pattern, name in sources:
            src = pattern.format(sha)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(d, name))
        for rf in rows_files:
            with open(rf, encoding="utf-8") as f:
                hits = [line for line in f if sha in line and not line.startswith('{"header"')]
            if hits:
                with open(os.path.join(d, "rows." + os.path.basename(rf)), "w", encoding="utf-8", newline="\n") as f:
                    f.writelines(hits)
    return shas


def _failures(stats_path, corpus_dir, require_rest):
    fails = []
    if corpus_dir:
        fails += check_extraction(corpus_dir)
    stats = _read_json(stats_path) if stats_path else None
    if stats is None:
        fails.append("stats: stats.json is missing (the parity stages or `make teal-corpus-stats` did not complete)")
    else:
        fails += check_stats(stats, require_rest)
    return stats, fails


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extraction")
    e.add_argument("corpus")
    e.add_argument("--min-programs", type=int, default=DEFAULT_MIN_PROGRAMS)
    e.add_argument("--max-skip-ratio", type=float, default=DEFAULT_MAX_SKIP_RATIO)
    v = sub.add_parser("verdict")
    v.add_argument("stats")
    v.add_argument("--require-rest", action="store_true")
    s = sub.add_parser("summary")
    s.add_argument("--stats")
    s.add_argument("--corpus")
    s.add_argument("--bench")
    s.add_argument("--registry-ref")
    s.add_argument("--require-rest", action="store_true")
    r = sub.add_parser("bundle")
    r.add_argument("corpus")
    r.add_argument("out")
    r.add_argument("dest")
    r.add_argument("--max", type=int, default=50)
    b = sub.add_parser("bench-table")
    b.add_argument("results")
    i = sub.add_parser("issue-body")
    i.add_argument("--stats")
    i.add_argument("--corpus")
    i.add_argument("--run-url", required=True)
    i.add_argument("--registry-ref")
    i.add_argument("--go-ref")
    i.add_argument("--require-rest", action="store_true")
    try:
        a = ap.parse_args(argv)
    except SystemExit as ex:
        return 2 if ex.code else 0
    if a.cmd == "bundle":
        shas = bundle(a.corpus, a.out, a.dest, a.max)
        print(f"reproducer bundles: {len(shas)} program(s) in {a.dest}")
        return 0
    if a.cmd == "bench-table":
        rows = _read_json(a.results)
        if not isinstance(rows, list):
            print("FAIL bench: no results to tabulate", file=sys.stderr)
            return 1
        sys.stdout.write(bench_table(rows))
        return 0
    if a.cmd == "extraction":
        fails = check_extraction(a.corpus, a.min_programs, a.max_skip_ratio)
    elif a.cmd == "verdict":
        stats = _read_json(a.stats)
        fails = ["stats: stats.json is missing or unreadable"] if stats is None else check_stats(stats, a.require_rest)
    else:
        stats, fails = _failures(a.stats, a.corpus, a.require_rest)
        if a.cmd == "summary":
            bench = None
            if a.bench and os.path.isfile(a.bench):
                with open(a.bench, encoding="utf-8") as f:
                    bench = f.read()
            sys.stdout.write(summary_markdown(stats, bench, fails, a.registry_ref))
        else:
            sys.stdout.write(issue_body(stats, fails, a.run_url, a.registry_ref, a.go_ref))
        return 0
    for f in fails:
        print("FAIL " + f, file=sys.stderr)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
