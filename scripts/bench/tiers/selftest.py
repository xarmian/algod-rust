#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""bench-compare built-in `selftest` tier (issue #2102, epic #2101).

Exercises the whole harness (tier contract, schema, pairing, statistics,
report) without building or running either node, so it works on any machine
with Python 3 and is what CI runs. Both "impl" halves run the SAME Python
workload and every row is tagged metadata.synthetic=true: the numbers
measure the harness, not go-algorand or algod-rust.

It still follows the rules real tiers must follow (docs/BENCHMARK_COMPARISON.md):
one discarded warm-up, BENCH_RUNS measured runs with the two sides
interleaved (alternating which goes first), and an output-equality gate (the
two sides' digests must match, the analogue of a macro tier's final-state
check). Rows: a paired lower-is-better time, a paired higher-is-better
throughput, and a deliberately unpaired Rust-only row so the report's
missing-pair path is always exercised.
"""
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import bench_schema  # noqa: E402

TIER = "selftest"
PAYLOAD = bytes(range(256)) * 4096  # 1 MiB, deterministic
ITERATIONS = 8


def workload():
    t0 = time.perf_counter()
    h = None
    for _ in range(ITERATIONS):
        h = hashlib.sha256(PAYLOAD).hexdigest()
    return time.perf_counter() - t0, h


def main():
    runs = int(os.environ.get("BENCH_RUNS", "5"))
    out = os.environ.get("BENCH_OUT") or os.getcwd()
    if runs < 1:
        print("selftest: BENCH_RUNS must be >= 1", file=sys.stderr)
        return 2
    os.makedirs(out, exist_ok=True)

    workload()  # warm-up, discarded
    secs = {"go": [], "rust": []}
    digests = {"go": set(), "rust": set()}
    for i in range(runs):
        order = ("go", "rust") if i % 2 == 0 else ("rust", "go")
        for impl in order:
            t, h = workload()
            secs[impl].append(t)
            digests[impl].add(h)
    if len(digests["go"] | digests["rust"]) != 1:
        print(f"selftest: output divergence {digests}", file=sys.stderr)
        return 1
    digest = digests["go"].pop()

    mb = ITERATIONS * len(PAYLOAD) / 1e6
    meta = {
        "synthetic": True,
        "workload": f"{ITERATIONS} x sha256 of a 1 MiB deterministic buffer (Python hashlib)",
        "output_sha256": digest,
        "note": "both impls run the same Python code; harness self-test only",
    }
    results = []
    for impl in ("go", "rust"):
        results.append({"schema": "bench-result/v1", "tier": TIER, "name": "sha256-1MiB",
                         "impl": impl, "unit": "s", "better": "lower",
                         "samples": secs[impl], "metadata": dict(meta)})
        results.append({"schema": "bench-result/v1", "tier": TIER, "name": "sha256-throughput",
                         "impl": impl, "unit": "MB/s",
                         "samples": [mb / t if t > 0 else 0.0 for t in secs[impl]],
                         "metadata": dict(meta)})
    results.append({"schema": "bench-result/v1", "tier": TIER, "name": "unpaired-probe",
                    "impl": "rust", "unit": "s", "samples": secs["rust"][:1],
                    "metadata": dict(meta, note="intentionally Rust-only: exercises missing-pair handling")})

    errs = [e for r in results for e in bench_schema.validate_result(r)]
    if errs:
        print("selftest: produced invalid results:\n  " + "\n  ".join(errs), file=sys.stderr)
        return 1
    path = os.path.join(out, "selftest.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(results, f, indent=2)
        f.write("\n")
    print(f"selftest: {runs} run(s) per side, wrote {len(results)} results to {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
