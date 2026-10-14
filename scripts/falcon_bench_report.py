#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Render the Falcon det1024 Rust-vs-C benchmark table from Criterion output.

`cargo bench -p algo-falcon` (benches/falcon_bench.rs, Phase 21 / DIV-001)
writes one `estimates.json` per (operation, backend) under
`target/criterion/falcon/`. This script turns those into the Markdown table
used by docs/falcon/BENCHMARK_RUST_VS_C.md, so the published numbers are
generated rather than typed in.

Usage:
    python3 scripts/falcon_bench_report.py [CRITERION_DIR] [--json]

CRITERION_DIR defaults to target/criterion. `--json` prints the raw table as
JSON instead of Markdown (for archiving next to the report).
"""
import json
import os
import sys

# (criterion directory, label, unit-of-work shown in the "per second" column)
OPERATIONS = [
    ("keygen", "keygen (seed → key pair)"),
    ("sign_32b", "sign, 32-byte message"),
    ("sign_1000b", "sign, 1000-byte message"),
    ("verify_32b", "verify, 32-byte message"),
    ("verify_1000b", "verify, 1000-byte message"),
    ("convert_to_ct", "compressed → CT signature"),
]


def load(criterion_dir, op, backend):
    path = os.path.join(criterion_dir, "falcon", op, backend, "new", "estimates.json")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        est = json.load(f)
    med = est["median"]
    return {
        "median_ns": med["point_estimate"],
        "lo_ns": med["confidence_interval"]["lower_bound"],
        "hi_ns": med["confidence_interval"]["upper_bound"],
        "mean_ns": est["mean"]["point_estimate"],
        "std_ns": est["std_dev"]["point_estimate"],
    }


def fmt_time(ns):
    if ns >= 1e6:
        return "{:.2f} ms".format(ns / 1e6)
    if ns >= 1e3:
        return "{:.1f} µs".format(ns / 1e3)
    return "{:.0f} ns".format(ns)


def fmt_rate(ns):
    per_s = 1e9 / ns
    if per_s >= 1000:
        return "{:,.0f}/s".format(per_s)
    return "{:.1f}/s".format(per_s)


def collect(criterion_dir):
    rows = []
    for op, label in OPERATIONS:
        c = load(criterion_dir, op, "c")
        r = load(criterion_dir, op, "rust")
        rows.append({"op": op, "label": label, "c": c, "rust": r})
    return rows


def render(rows):
    out = [
        "| Operation | C (vendored `falcon-c`) | Rust (`rs/`) | Rust speed-up | Rust throughput |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        c, r = row["c"], row["rust"]
        if c is None or r is None:
            out.append("| {} | _not measured_ | | | |".format(row["label"]))
            continue
        ratio = c["median_ns"] / r["median_ns"]
        if ratio >= 1.0:
            speed = "**{:.2f}×** faster".format(ratio)
        else:
            speed = "{:.2f}× (C faster by {:.0f}%)".format(ratio, (1 / ratio - 1) * 100)
        out.append(
            "| {} | {} [{} – {}] | {} [{} – {}] | {} | {} |".format(
                row["label"],
                fmt_time(c["median_ns"]), fmt_time(c["lo_ns"]), fmt_time(c["hi_ns"]),
                fmt_time(r["median_ns"]), fmt_time(r["lo_ns"]), fmt_time(r["hi_ns"]),
                speed,
                fmt_rate(r["median_ns"]),
            )
        )
    return "\n".join(out)


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    criterion_dir = args[0] if args else "target/criterion"
    rows = collect(criterion_dir)
    if "--json" in argv:
        print(json.dumps(rows, indent=2))
    else:
        print(render(rows))
        print("\n_Median with 95% confidence interval in brackets (Criterion bootstrap)._")
    return 0


if __name__ == "__main__":
    # Windows consoles default to a legacy code page that cannot encode "→"/"µ".
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main(sys.argv))
