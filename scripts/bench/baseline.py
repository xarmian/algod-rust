#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Published-baseline file and regression check for bench-compare.

Issue #2109 (epic #2101). The baseline file (benchmarks/baseline.json) holds,
per named section (one section per `make bench-compare` profile), the paired
rows of a published report: median of each side and the Rust/Go ratio. The
check compares a fresh report.json with a section and WARNS about Rust
regressions above a tolerance; it only fails with --fail-on-regression.

The comparison uses the Rust/Go ratio, not the absolute medians: a CI runner
and the machine that produced the baseline differ in speed, and that moves
both sides, so only a change of the ratio says something about algod-rust.
A ratio is still noisy on shared runners, hence warn, not fail, and a wide
default tolerance (25%).

Usage:
    python3 scripts/bench/baseline.py compare <report.json> --baseline FILE --section NAME
        [--tolerance 0.25] [--fail-on-regression]
"""
import argparse
import json
import os
import sys

BASELINE_SCHEMA = "bench-baseline/v1"
DEFAULT_TOLERANCE = 0.25
DEFAULT_BASELINE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "benchmarks", "baseline.json")


def extract_rows(rep):
    """Paired rows of a report that have a usable Rust/Go ratio."""
    out = []
    for r in rep.get("rows", []):
        if r.get("status") != "paired" or not r.get("ratio") or not r.get("go") or not r.get("rust"):
            continue
        if not isinstance(r.get("unit"), str):
            continue
        out.append({
            "tier": r["tier"], "name": r["name"], "unit": r["unit"], "better": r["better"],
            "go_median": r["go"]["median"], "rust_median": r["rust"]["median"],
            "ratio": r["ratio"], "faster": r.get("faster"),
            "n_go": r["go"]["n"], "n_rust": r["rust"]["n"],
        })
    return out


def compare_rows(current, base, tolerance):
    """Per-row verdicts of `current` against `base` (both lists of extract_rows rows).

    change is the relative degradation of the Rust/Go ratio: positive means
    Rust got relatively worse. verdict is one of ok, regression, improved,
    new (no baseline row), missing (baseline row not in the run) or
    incomparable (unit or direction differ).
    """
    bmap = {(r["tier"], r["name"]): r for r in base}
    cmap = {(r["tier"], r["name"]): r for r in current}
    out = []
    for key in sorted(set(bmap) | set(cmap)):
        c, b = cmap.get(key), bmap.get(key)
        row = {"tier": key[0], "name": key[1], "unit": (c or b)["unit"],
               "better": (c or b)["better"],
               "base_ratio": b["ratio"] if b else None,
               "ratio": c["ratio"] if c else None, "change": None}
        if c is None:
            row["verdict"] = "missing"
        elif b is None:
            row["verdict"] = "new"
        elif c["unit"] != b["unit"] or c["better"] != b["better"]:
            row["verdict"] = "incomparable"
        else:
            if c["better"] == "lower":
                change = c["ratio"] / b["ratio"] - 1.0
            else:
                change = b["ratio"] / c["ratio"] - 1.0
            row["change"] = change
            row["verdict"] = ("regression" if change > tolerance
                              else "improved" if change < -tolerance else "ok")
        out.append(row)
    return out


def load_baseline_file(path):
    if not os.path.exists(path):
        return {"schema": BASELINE_SCHEMA, "sections": {}}
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or doc.get("schema") != BASELINE_SCHEMA:
        raise ValueError(f"{path}: not a {BASELINE_SCHEMA} file")
    doc.setdefault("sections", {})
    return doc


def update_baseline_file(path, section, rep, date):
    """Write/replace `section` of the baseline file from report dict `rep`."""
    doc = load_baseline_file(path)
    fp = rep.get("fingerprint") or {}
    commits = fp.get("commits") or {}
    cpu = fp.get("cpu") or {}
    doc["sections"][section] = {
        "date": date,
        "run_dir": rep.get("run_dir"),
        "cpu": cpu.get("model"),
        "logical_cpus": cpu.get("logical_cpus"),
        "go_commit": (commits.get("go_algorand") or {}).get("commit"),
        "rust_commit": (commits.get("algod_rust") or {}).get("commit"),
        "rows": extract_rows(rep),
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")


def _pct(x):
    return "n/a" if x is None else f"{x * 100:+.0f}%"


def render_table(rows, tolerance):
    lines = ["| Tier | Benchmark | Baseline Rust/Go | Now Rust/Go | Change | Verdict |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        bs = "n/a" if r["base_ratio"] is None else f"{r['base_ratio']:.3g}"
        cs = "n/a" if r["ratio"] is None else f"{r['ratio']:.3g}"
        lines.append(f"| {r['tier']} | {r['name']} | {bs} | {cs} | {_pct(r['change'])} | "
                     f"{r['verdict']} |")
    lines.append("")
    lines.append(f"Change is the relative worsening of the Rust/Go ratio (tolerance "
                 f"{tolerance * 100:.0f}%). Runner noise moves ratios too: a warning is a "
                 f"prompt to re-run on quiet hardware, not a verdict.")
    return "\n".join(lines)


def cmd_compare(args):
    with open(args.report, encoding="utf-8") as f:
        rep = json.load(f)
    doc = load_baseline_file(args.baseline)
    sec = doc["sections"].get(args.section)
    if sec is None:
        print(f"no baseline section {args.section!r} in {args.baseline}: nothing to compare")
        return 0
    rows = compare_rows(extract_rows(rep), sec["rows"], args.tolerance)
    regs = [r for r in rows if r["verdict"] == "regression"]
    table = render_table(rows, args.tolerance)
    head = (f"## Regression check vs baseline `{args.section}` ({sec.get('date', 'undated')}): "
            f"{len(regs)} regression(s) above {args.tolerance * 100:.0f}%")
    print(head)
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8", newline="\n") as f:
            f.write(head + "\n\n" + table + "\n")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for r in regs:
            print(f"::warning title=bench-compare regression::{r['tier']}/{r['name']}: Rust/Go "
                  f"ratio {r['base_ratio']:.3g} -> {r['ratio']:.3g} ({_pct(r['change'])}) vs "
                  f"baseline {args.section}")
    return 1 if regs and args.fail_on_regression else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compare", help="compare a report.json with a baseline section")
    c.add_argument("report")
    c.add_argument("--baseline", default=DEFAULT_BASELINE)
    c.add_argument("--section", required=True)
    c.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE)
    c.add_argument("--fail-on-regression", action="store_true")
    args = ap.parse_args(argv)
    return cmd_compare(args)


if __name__ == "__main__":
    sys.exit(main())
