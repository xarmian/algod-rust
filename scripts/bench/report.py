#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Merge bench-compare tier results into report.json + report.md.

Issue #2102 (epic #2101). Reads a run directory written by run.py:

    <run-dir>/results/<tier>/*.json   schema-v1 results (bench_schema.py)
    <run-dir>/fingerprint.json        environment (fingerprint.py)
    <run-dir>/build-info.json         pinned builds (build_both.sh), optional
    <run-dir>/tier-status.json        per-tier exit codes (run.py), optional

and writes <run-dir>/report.json and <run-dir>/report.md. Results pair up by
(tier, name). For each side it reports the median, a distribution-free 95%
confidence interval of the median when there are enough samples (n >= 6),
otherwise the min/max range, and for each pair the Rust/Go ratio of medians
and which side is faster. A side is only declared faster when the two
intervals do not overlap; otherwise the row says "inconclusive".

Exit status: 0 when every result validated, every pair is consistent and
every tier exited 0; 1 otherwise (the report files are written either way).

Usage: python3 scripts/bench/report.py <run-dir>
"""
import argparse
import datetime
import glob
import json
import math
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench_schema  # noqa: E402

METHODOLOGY_URL = "https://github.com/xarmian/algod-rust/blob/main/docs/BENCHMARK_COMPARISON.md"
REPORT_SCHEMA = "bench-report/v1"


# --------------------------------------------------------------------------
# statistics


def median(xs):
    return statistics.median(xs)


EXACT_CI_MAX_N = 1000


def _median_ci_rank(n, alpha):
    """Largest r with P(X <= r-1) <= alpha/2, X ~ Bin(n, 1/2), and its coverage.

    Exact for n <= EXACT_CI_MAX_N: the CDF is accumulated incrementally with
    integer binomial coefficients (O(n) big-int steps, not O(n^2)). Above
    that, the normal approximation N(n/2, n/4) with continuity correction.
    """
    if n > EXACT_CI_MAX_N:
        nd = statistics.NormalDist(n / 2, math.sqrt(n) / 2)
        z = statistics.NormalDist().inv_cdf(1 - alpha / 2)
        r = int(math.floor(n / 2 - z * math.sqrt(n) / 2))
        # P(X <= r-1) ~ Phi(r - 1 + 0.5); step down if the approximation is too generous.
        while r > 0 and nd.cdf(r - 0.5) > alpha / 2:
            r -= 1
        return r, (1 - 2 * nd.cdf(r - 0.5)) if r > 0 else None
    total = 2 ** n
    coef = 1  # C(n, k)
    cum = 0   # sum_{i<=k-1} C(n, i) for the candidate r = k
    r = 0
    cum_at_r = 0
    for k in range(0, n // 2):
        cum += coef  # now cum = P(X <= k) * 2^n
        if cum / total > alpha / 2:
            break
        r = k + 1
        cum_at_r = cum
        coef = coef * (n - k) // (k + 1)
    if r == 0:
        return 0, None
    return r, 1 - 2 * (cum_at_r / total)


def median_ci(xs, alpha=0.05):
    """Distribution-free (order-statistic) CI for the median.

    Returns (low, high, coverage) with coverage >= 1 - alpha, or None when n
    is too small for any order-statistic interval to reach that coverage
    (n < 6 for 95%). Uses the largest r with P(X <= r-1) <= alpha/2 for
    X ~ Bin(n, 1/2); the interval is [x_(r), x_(n-r+1)] (1-based).
    """
    s = sorted(xs)
    n = len(s)
    r, coverage = _median_ci_rank(n, alpha)
    if r == 0:
        return None
    return s[r - 1], s[n - r], coverage


def summarize(samples):
    xs = [float(x) for x in samples]
    s = {
        "n": len(xs),
        "median": median(xs),
        "mean": statistics.fmean(xs),
        "min": min(xs),
        "max": max(xs),
        "stdev": statistics.stdev(xs) if len(xs) > 1 else 0.0,
    }
    ci = median_ci(xs)
    if ci is not None:
        s["spread_method"] = "ci95-median"
        s["spread_low"], s["spread_high"], s["ci_coverage"] = ci
    else:
        s["spread_method"] = "range"
        s["spread_low"], s["spread_high"] = s["min"], s["max"]
    return s


def infer_better(unit):
    return "higher" if unit.strip().endswith("/s") else "lower"


def compare(go, rust, better):
    """Ratio of medians (Rust/Go), faster side and its speedup."""
    gm, rm = go["median"], rust["median"]
    ratio = rm / gm if gm else None
    overlap = not (rust["spread_high"] < go["spread_low"] or go["spread_high"] < rust["spread_low"])
    if overlap or gm == rm:
        faster = "inconclusive"
    elif better == "lower":
        faster = "rust" if rm < gm else "go"
    else:
        faster = "rust" if rm > gm else "go"
    lo, hi = min(gm, rm), max(gm, rm)
    speedup = hi / lo if lo else None
    return {"ratio": ratio, "faster": faster, "speedup": speedup}


# --------------------------------------------------------------------------
# report assembly


def build_report(results, fingerprint=None, build_info=None, tier_status=None,
                 load_errors=None, run_dir=None):
    errors = list(load_errors or [])
    warnings = []
    if fingerprint is None:
        warnings.append("fingerprint.json missing: results are not comparable across machines")
    groups = {}
    for r in results:
        groups.setdefault((r["tier"], r["name"]), []).append(r)

    rows = []
    for (tier, name) in sorted(groups):
        rs = groups[(tier, name)]
        units = sorted({r["unit"] for r in rs})
        explicit = sorted({r["better"] for r in rs if "better" in r})
        row = {
            "tier": tier,
            "name": name,
            "unit": units[0] if len(units) == 1 else units,
            "better": None,
            "status": None,
            "go": None,
            "rust": None,
            "ratio": None,
            "faster": None,
            "speedup": None,
            "synthetic": any(bool(r["metadata"].get("synthetic")) for r in rs),
            "metadata": {impl: [r["metadata"] for r in rs if r["impl"] == impl]
                         for impl in ("go", "rust")},
        }
        samples = {"go": [], "rust": []}
        for r in rs:
            samples[r["impl"]].extend(r["samples"])
        for impl in ("go", "rust"):
            if samples[impl]:
                row[impl] = summarize(samples[impl])
        if len(units) > 1:
            row["status"] = "unit-mismatch"
            errors.append(f"{tier}/{name}: Go and Rust use different units {units}")
        elif len(explicit) > 1:
            row["status"] = "better-mismatch"
            errors.append(f"{tier}/{name}: conflicting 'better' values {explicit}")
        else:
            row["better"] = explicit[0] if explicit else infer_better(units[0])
            if row["go"] and row["rust"]:
                row["status"] = "paired"
                row.update(compare(row["go"], row["rust"], row["better"]))
            else:
                row["status"] = "unpaired"
                row["missing"] = "go" if row["go"] is None else "rust"
        rows.append(row)

    for t in tier_status or []:
        if t.get("exit_code") == "skipped":
            errors.append(f"tier {t.get('tier')} skipped: {t.get('reason', 'unknown reason')}")
        elif t.get("exit_code") != 0:
            errors.append(f"tier {t.get('tier')} exited with status {t.get('exit_code')}")

    paired = [r for r in rows if r["status"] == "paired"]
    summary = {
        "rows": len(rows),
        "paired": len(paired),
        "unpaired": sum(1 for r in rows if r["status"] == "unpaired"),
        "rust_faster": sum(1 for r in paired if r["faster"] == "rust"),
        "go_faster": sum(1 for r in paired if r["faster"] == "go"),
        "inconclusive": sum(1 for r in paired if r["faster"] == "inconclusive"),
        "errors": len(errors),
    }
    return {
        "schema": REPORT_SCHEMA,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run_dir": run_dir,
        "methodology": METHODOLOGY_URL,
        "ok": not errors,
        "summary": summary,
        "fingerprint": fingerprint,
        "build_info": build_info,
        "tier_status": tier_status or [],
        "rows": rows,
        "errors": errors,
        "warnings": warnings + list((fingerprint or {}).get("warnings") or []),
    }


# --------------------------------------------------------------------------
# markdown


def fmt(x):
    if x is None:
        return "n/a"
    if abs(x) >= 1e4:
        return f"{x:,.0f}"
    if isinstance(x, float) and x.is_integer():
        return str(int(x))
    return f"{x:.4g}"


def _spread(s):
    if s is None:
        return "n/a"
    kind = "95% CI" if s["spread_method"] == "ci95-median" else "range"
    return f"[{fmt(s['spread_low'])}, {fmt(s['spread_high'])}] {kind}, n={s['n']}"


def _faster_cell(row):
    st = row["status"]
    if st == "unpaired":
        return f"{row['missing']} missing"
    if st == "unit-mismatch":
        return "unit mismatch"
    if st == "better-mismatch":
        return "direction mismatch"
    if row["faster"] == "inconclusive":
        return "inconclusive"
    side = "Rust" if row["faster"] == "rust" else "Go"
    return f"**{side}** {fmt(row['speedup'])}x" if row["speedup"] else f"**{side}**"


def _commit_info(report):
    """(go, rust) dicts of commit/tag/pin, from build-info else fingerprint."""
    b = report.get("build_info") or {}
    c = (report.get("fingerprint") or {}).get("commits") or {}
    go = dict(c.get("go_algorand") or {})
    rust = dict(c.get("algod_rust") or {})
    go.update({k: v for k, v in (b.get("go_algorand") or {}).items() if v is not None})
    rust.update({k: v for k, v in (b.get("algod_rust") or {}).items() if v is not None})
    return go, rust


def render_markdown(report):
    out = []
    w = out.append
    fpr = report.get("fingerprint") or {}
    w("# algod Go vs Rust benchmark report")
    w("")
    w(f"Generated {report['generated_utc']}. Methodology and fairness rules: "
      f"[docs/BENCHMARK_COMPARISON.md]({report['methodology']}).")
    w("")
    status = "OK" if report["ok"] else f"FAILED ({len(report['errors'])} error(s), see Errors)"
    sm = report["summary"]
    w(f"**Status: {status}.** {sm['paired']} paired row(s): Rust faster {sm['rust_faster']}, "
      f"Go faster {sm['go_faster']}, inconclusive {sm['inconclusive']}; "
      f"{sm['unpaired']} unpaired.")
    w("")

    go, rust = _commit_info(report)
    w("## Builds")
    w("")
    w("| | go-algorand | algod-rust |")
    w("|---|---|---|")
    w(f"| Commit | `{go.get('commit') or 'n/a'}` | `{rust.get('commit') or 'n/a'}` |")
    w(f"| Describe | `{go.get('describe') or go.get('tag') or 'n/a'}` | "
      f"`{rust.get('describe') or 'n/a'}` |")
    if "expected_tag" in go or "pin_ok" in go:
        w(f"| Pin | expected `{go.get('expected_tag', 'n/a')}`, "
          f"{'matches' if go.get('pin_ok') else 'MISMATCH'} | |")
    w(f"| Dirty tree | {fmt_bool(go.get('dirty'))} | {fmt_bool(rust.get('dirty'))} |")
    if go.get("binaries") or rust.get("binaries"):
        w(f"| Binaries | {', '.join(go.get('binaries') or []) or 'n/a'} | "
          f"{', '.join(rust.get('binaries') or []) or 'n/a'} |")
    if not report.get("build_info"):
        w("")
        w("No `build-info.json`: the selected tiers did not need `build_both.sh`; "
          "commits come from the fingerprint.")
    w("")

    cpu = fpr.get("cpu") or {}
    osi = fpr.get("os") or {}
    tc = fpr.get("toolchains") or {}
    ci = fpr.get("ci") or {}
    mem = (fpr.get("memory") or {}).get("total_bytes")
    w("## Environment")
    w("")
    w("| Item | Value |")
    w("|---|---|")
    w(f"| CPU model | {cpu.get('model') or 'n/a'} |")
    w(f"| Sockets / physical cores / logical CPUs | {fmt(cpu.get('sockets'))} / "
      f"{fmt(cpu.get('physical_cores'))} / {fmt(cpu.get('logical_cpus'))} |")
    w(f"| Max MHz | {fmt(cpu.get('max_mhz'))} |")
    w(f"| Frequency governor | {cpu.get('governor') or 'n/a'} |")
    w(f"| Hypervisor | {cpu.get('hypervisor') or 'none detected'} |")
    w(f"| RAM | {fmt(round(mem / 2**30, 1)) + ' GiB' if mem else 'n/a'} |")
    w(f"| OS | {osi.get('distro') or osi.get('system') or 'n/a'} "
      f"({osi.get('machine') or 'n/a'}) |")
    w(f"| Kernel | {osi.get('kernel') or 'n/a'} |")
    for k in ("rustc", "go", "docker", "python"):
        w(f"| {k} | {tc.get(k) or 'n/a'} |")
    ci_txt = "no"
    if ci.get("is_ci"):
        ci_txt = f"yes ({ci.get('provider')}" + (f", {ci['runner']}" if ci.get("runner") else "") + ")"
    w(f"| CI runner | {ci_txt} |")
    w("")
    if report["warnings"]:
        w("Fairness warnings:")
        w("")
        for x in report["warnings"]:
            w(f"- {x}")
        w("")

    w("## Results")
    w("")
    if not report["rows"]:
        w("No results.")
        w("")
    tiers = []
    for r in report["rows"]:
        if r["tier"] not in tiers:
            tiers.append(r["tier"])
    for tier in tiers:
        w(f"### {tier}")
        w("")
        w("| Benchmark | Unit | Go median | Go spread | Rust median | Rust spread | Rust/Go | Faster |")
        w("|---|---|---|---|---|---|---|---|")
        for r in report["rows"]:
            if r["tier"] != tier:
                continue
            unit = r["unit"] if isinstance(r["unit"], str) else "/".join(r["unit"])
            arrow = {"lower": " (lower is better)", "higher": " (higher is better)"}.get(r["better"], "")
            name = r["name"] + (" (synthetic)" if r["synthetic"] else "")
            w(f"| {name} | {unit}{arrow} | {fmt((r['go'] or {}).get('median'))} | {_spread(r['go'])} | "
              f"{fmt((r['rust'] or {}).get('median'))} | {_spread(r['rust'])} | "
              f"{fmt(r['ratio'])} | {_faster_cell(r)} |")
        w("")
    w("Rust/Go is the ratio of the medians. For lower-is-better units a value below 1 "
      "means Rust is faster; for higher-is-better units a value above 1 means Rust is "
      "faster. A side is only marked faster when the two spreads (95% CI of the median "
      "for n >= 6, else min/max) do not overlap. Rows marked (synthetic) come from the "
      "selftest tier and measure the harness, not either node.")
    w("")

    if report["tier_status"]:
        w("## Tiers")
        w("")
        w("| Tier | Exit | Duration (s) |")
        w("|---|---|---|")
        for t in report["tier_status"]:
            w(f"| {t.get('tier')} | {t.get('exit_code')} | {fmt(t.get('duration_s'))} |")
        w("")
    if report["errors"]:
        w("## Errors")
        w("")
        for e in report["errors"]:
            w(f"- {e}")
        w("")
    return "\n".join(out)


def fmt_bool(v):
    return "n/a" if v is None else ("yes" if v else "no")


# --------------------------------------------------------------------------
# CLI


def _load_optional(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_run_results(run_dir):
    """Load every results/<tier>/**/*.json of a run dir.

    The directory a file sits in is authoritative: a result whose own `tier`
    field disagrees with its results/<tier>/ directory (or a file not inside
    any tier directory) is dropped and reported, so one tier can never inject
    rows into another tier's table.
    """
    results, errors = [], []
    for p in sorted(glob.glob(os.path.join(run_dir, "results", "**", "*.json"), recursive=True)):
        rel = os.path.relpath(p, run_dir).replace(os.sep, "/")
        parts = rel.split("/")
        if len(parts) < 3:
            errors.append(f"{rel}: result file is not inside a results/<tier>/ directory")
            continue
        dir_tier = parts[1]
        rs, errs = bench_schema.load_result_file(p)
        errors.extend(e.replace(p, rel, 1) for e in errs)
        for r in rs:
            if r["tier"] != dir_tier:
                errors.append(f"{rel}: result {r['name']!r} declares tier {r['tier']!r} "
                              f"but was written by tier {dir_tier!r}; dropped")
            else:
                results.append(r)
    return results, errors


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dir")
    args = ap.parse_args(argv)
    d = args.run_dir
    results, load_errors = load_run_results(d)
    extra_errors = []
    meta = {}
    for key, fname in (("fingerprint", "fingerprint.json"), ("build_info", "build-info.json"),
                       ("tier_status", "tier-status.json")):
        try:
            meta[key] = _load_optional(os.path.join(d, fname))
        except (OSError, ValueError) as e:
            meta[key] = None
            extra_errors.append(f"{fname}: cannot load: {e}")
    rep = build_report(results, load_errors=load_errors + extra_errors,
                       run_dir=os.path.basename(os.path.abspath(d)), **meta)
    with open(os.path.join(d, "report.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, allow_nan=False)
        f.write("\n")
    with open(os.path.join(d, "report.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(render_markdown(rep))
        f.write("\n")
    sm = rep["summary"]
    print(f"report: {os.path.join(d, 'report.md')} ({sm['rows']} rows, {sm['paired']} paired, "
          f"{sm['errors']} error(s))")
    for e in rep["errors"]:
        print(f"  error: {e}", file=sys.stderr)
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
