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
        [--tolerance 0.25] [--zero-threshold 0] [--fail-on-regression]
"""
import argparse
import json
import math
import os
import sys

BASELINE_SCHEMA = "bench-baseline/v1"
DEFAULT_TOLERANCE = 0.25
DEFAULT_BASELINE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "benchmarks", "baseline.json")


# Units that measure resources of the host (memory, disk, CPU), not the
# speed of the node: a runner and the baseline machine differ in them even
# for identical code, so they are only compared within one host class.
RESOURCE_UNITS = frozenset({"MB", "cores"})
# Quantised units: a step of one unit is measurement granularity (a localnet
# step commits whole rounds), not a change of speed.
QUANTISED_STEP = {"rounds": 1.0}


def host_class(fingerprint):
    """Coarse class of the machine a report came from."""
    if not fingerprint:
        return "unknown"
    ci = fingerprint.get("ci") or {}
    if ci.get("is_ci"):
        return "ci-" + (ci.get("provider") or "unknown")
    return "dev-host"


def extract_rows(rep):
    """Every paired row of a report (a zero or undefined ratio is kept).

    A row whose Go median is 0 has no ratio, and a Rust median of 0 gives
    ratio 0; both are real measurements (an error rate going from 0 to N must
    not vanish from the baseline), compared by their medians.
    """
    out = []
    for r in rep.get("rows", []):
        if r.get("status") != "paired" or not r.get("go") or not r.get("rust"):
            continue
        if not isinstance(r.get("unit"), str):
            continue
        out.append({
            "tier": r["tier"], "name": r["name"], "unit": r["unit"], "better": r["better"],
            "go_median": r["go"]["median"], "rust_median": r["rust"]["median"],
            "ratio": r.get("ratio"), "faster": r.get("faster"),
            "go_lo": r["go"]["spread_low"], "go_hi": r["go"]["spread_high"],
            "rust_lo": r["rust"]["spread_low"], "rust_hi": r["rust"]["spread_high"],
            "n_go": r["go"]["n"], "n_rust": r["rust"]["n"],
        })
    return out


def _worsening(c, b, zero_threshold):
    """Relative worsening of Rust in row c against row b (positive = worse)."""
    better = c["better"]
    if c.get("ratio") and b.get("ratio"):
        # Both ratios usable: compare Rust relative to Go, so a faster or
        # slower host (it moves both sides) does not matter.
        return (c["ratio"] / b["ratio"] - 1.0) if better == "lower" else (b["ratio"] / c["ratio"] - 1.0)
    cr, br = c["rust_median"], b["rust_median"]
    if better == "lower":
        if br == 0:
            return math.inf if cr > zero_threshold else 0.0
        return cr / br - 1.0
    if cr == 0:
        return 0.0 if br == 0 else math.inf
    return br / cr - 1.0


def _ranges_overlap(c, b):
    keys = ("rust_lo", "rust_hi")
    if not all(k in c and k in b for k in keys):
        return True  # unknown spread: treat as overlapping (not eligible by range)
    return not (c["rust_hi"] < b["rust_lo"] or b["rust_hi"] < c["rust_lo"])


def compare_rows(current, base, tolerance, zero_threshold=0.0, same_host=True):
    """Per-row verdicts of `current` against `base` (lists of extract_rows rows).

    change is the relative worsening of Rust (positive = worse), on the
    Rust/Go ratio when both ratios exist, else on the Rust medians (relative
    for a nonzero baseline; for a zero baseline any value above
    `zero_threshold` is an infinite worsening, so "was 0, now N" regresses).
    verdict is one of:
      ok / improved        within tolerance / better by more than tolerance;
      regression           worse than tolerance AND eligible (see below);
      noise                worse than tolerance but not eligible: the
                           baseline row was inconclusive and the current Rust
                           min-max range overlaps the baseline's (a jump
                           from a zero baseline is always eligible);
      new / missing        row only in the run / only in the baseline;
      incomparable         unit or direction differ;
      skipped-host         resource-unit row from another host class.
    A quantised row (rounds) moving by at most one step is ok.
    """
    bmap = {(r["tier"], r["name"]): r for r in base}
    cmap = {(r["tier"], r["name"]): r for r in current}
    out = []
    for key in sorted(set(bmap) | set(cmap)):
        c, b = cmap.get(key), bmap.get(key)
        row = {"tier": key[0], "name": key[1], "unit": (c or b)["unit"],
               "better": (c or b)["better"],
               "base_ratio": b.get("ratio") if b else None,
               "ratio": c.get("ratio") if c else None, "change": None}
        if c is None:
            row["verdict"] = "missing"
        elif b is None:
            row["verdict"] = "new"
        elif c["unit"] != b["unit"] or c["better"] != b["better"]:
            row["verdict"] = "incomparable"
        elif not same_host and c["unit"] in RESOURCE_UNITS:
            row["verdict"] = "skipped-host"
        else:
            change = _worsening(c, b, zero_threshold)
            row["change"] = change
            step = QUANTISED_STEP.get(c["unit"])
            if step is not None and abs(c["rust_median"] - b["rust_median"]) <= step:
                row["verdict"] = "ok"
            elif change > tolerance:
                eligible = (b.get("faster") != "inconclusive" or math.isinf(change)
                            or not _ranges_overlap(c, b))
                row["verdict"] = "regression" if eligible else "noise"
            elif change < -tolerance:
                row["verdict"] = "improved"
            else:
                row["verdict"] = "ok"
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


def render_baseline_file(path, section, rep, date):
    """Text of baseline file `path` with `section` replaced from report `rep`.

    Pure: nothing is written, so a caller can compute every output of a
    publish before touching any file.
    """
    doc = load_baseline_file(path)
    fp = rep.get("fingerprint") or {}
    commits = fp.get("commits") or {}
    cpu = fp.get("cpu") or {}
    doc["sections"][section] = {
        "date": date,
        "run_dir": rep.get("run_dir"),
        "host_class": host_class(rep.get("fingerprint")),
        "cpu": cpu.get("model"),
        "logical_cpus": cpu.get("logical_cpus"),
        "go_commit": (commits.get("go_algorand") or {}).get("commit"),
        "rust_commit": (commits.get("algod_rust") or {}).get("commit"),
        "rows": extract_rows(rep),
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def update_baseline_file(path, section, rep, date):
    """Write/replace `section` of the baseline file from report dict `rep`."""
    text = render_baseline_file(path, section, rep, date)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def _pct(x):
    if x is None:
        return "n/a"
    return "was 0, now more" if math.isinf(x) else f"{x * 100:+.0f}%"


def _g(x):
    return "n/a" if x is None else f"{x:.3g}"


def render_table(rows, tolerance):
    lines = ["| Tier | Benchmark | Baseline Rust/Go | Now Rust/Go | Change | Verdict |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['tier']} | {r['name']} | {_g(r['base_ratio'])} | {_g(r['ratio'])} | "
                     f"{_pct(r['change'])} | {r['verdict']} |")
    lines.append("")
    lines.append(f"Change is the relative worsening of Rust (on the Rust/Go ratio, or on the Rust "
                 f"medians when a ratio is 0 or undefined); tolerance {tolerance * 100:.0f}%. "
                 f"`noise`: worse than the tolerance, but the baseline row was inconclusive and "
                 f"the ranges overlap. `skipped-host`: a memory/CPU row from another host class. "
                 f"Runner noise moves ratios too: a warning is a prompt to re-run on quiet "
                 f"hardware, not a verdict.")
    return "\n".join(lines)


def cmd_compare(args):
    with open(args.report, encoding="utf-8") as f:
        rep = json.load(f)
    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    doc = load_baseline_file(args.baseline)
    sec = doc["sections"].get(args.section)
    if sec is None:
        print(f"no baseline section {args.section!r} in {args.baseline}: nothing to compare")
        if gha:
            print(f"::warning title=bench-compare baseline::no baseline section {args.section!r}")
        # A typo or a renamed section must not silently disable the gate.
        return 1 if args.fail_on_regression else 0
    here, there = host_class(rep.get("fingerprint")), sec.get("host_class", "unknown")
    same_host = here == there
    rows = compare_rows(extract_rows(rep), sec["rows"], args.tolerance,
                        zero_threshold=args.zero_threshold, same_host=same_host)
    regs = [r for r in rows if r["verdict"] == "regression"]
    gone = [r for r in rows if r["verdict"] == "missing"]
    table = render_table(rows, args.tolerance)
    head = (f"## Regression check vs baseline `{args.section}` ({sec.get('date', 'undated')}, "
            f"host class {there}; this run: {here}): {len(regs)} regression(s) above "
            f"{args.tolerance * 100:.0f}%, {len(gone)} baseline row(s) missing from the run")
    print(head)
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8", newline="\n") as f:
            f.write(head + "\n\n" + table + "\n")
    if gha:
        for r in regs:
            print(f"::warning title=bench-compare regression::{r['tier']}/{r['name']}: "
                  f"Rust/Go ratio {_g(r['base_ratio'])} -> {_g(r['ratio'])} ({_pct(r['change'])}) "
                  f"vs baseline {args.section}")
        for r in gone:
            print(f"::warning title=bench-compare missing row::{r['tier']}/{r['name']} is in "
                  f"baseline {args.section} but not in this run")
    # A baseline row that vanished from the run is as bad as a regression for a gate.
    return 1 if (regs or gone) and args.fail_on_regression else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compare", help="compare a report.json with a baseline section")
    c.add_argument("report")
    c.add_argument("--baseline", default=DEFAULT_BASELINE)
    c.add_argument("--section", required=True)
    c.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE)
    c.add_argument("--zero-threshold", type=float, default=0.0,
                   help="a value above this, from a zero baseline, is a regression (default 0)")
    c.add_argument("--fail-on-regression", action="store_true")
    args = ap.parse_args(argv)
    return cmd_compare(args)


if __name__ == "__main__":
    sys.exit(main())
