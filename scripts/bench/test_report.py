#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests for report.py and bench_schema.py (issue #2102, epic #2101).

Covers the statistics (median, order-statistic 95% CI of the median), the
Rust/Go ratio and faster-side marker, result-schema validation and the
handling of unpaired / mismatched results. Stdlib only, no Docker.

Run: python3 -m unittest discover -s scripts/bench -p 'test_*.py'
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench_schema  # noqa: E402
import report  # noqa: E402


def result(name, impl, samples, unit="s", tier="t", **extra):
    r = {
        "schema": "bench-result/v1",
        "tier": tier,
        "name": name,
        "impl": impl,
        "unit": unit,
        "samples": samples,
        "metadata": {},
    }
    r.update(extra)
    return r


class StatsTest(unittest.TestCase):
    def test_median_odd_even(self):
        self.assertEqual(report.median([3, 1, 2]), 2)
        self.assertEqual(report.median([4, 1, 3, 2]), 2.5)

    def test_median_ci_needs_six_samples(self):
        # With n<6 even [min, max] covers the median with < 95% probability
        # (1 - 2 * 0.5**n), so no 95% CI exists.
        self.assertIsNone(report.median_ci([1, 2, 3, 4, 5]))
        lo, hi, cov = report.median_ci([6, 1, 5, 2, 4, 3])
        self.assertEqual((lo, hi), (1, 6))
        self.assertAlmostEqual(cov, 1 - 2 / 64)

    def test_median_ci_narrows_with_n(self):
        xs = list(range(1, 21))  # n=20: r=6 -> [x6, x15], coverage 95.9%
        lo, hi, cov = report.median_ci(xs)
        self.assertEqual((lo, hi), (6, 15))
        self.assertGreaterEqual(cov, 0.95)
        self.assertAlmostEqual(cov, 0.9586, places=3)

    def test_summarize_small_n_falls_back_to_range(self):
        s = report.summarize([2.0, 1.0, 3.0])
        self.assertEqual(s["n"], 3)
        self.assertEqual(s["median"], 2.0)
        self.assertEqual((s["min"], s["max"]), (1.0, 3.0))
        self.assertEqual(s["spread_method"], "range")
        self.assertEqual((s["spread_low"], s["spread_high"]), (1.0, 3.0))

    def test_summarize_large_n_uses_ci(self):
        s = report.summarize([float(x) for x in range(1, 8)])
        self.assertEqual(s["spread_method"], "ci95-median")
        self.assertEqual((s["spread_low"], s["spread_high"]), (1.0, 7.0))

    def test_median_ci_exact_matches_reference_up_to_1000(self):
        # The incremental CDF must give the same r as the from-scratch sum.
        import math
        for n in (6, 7, 10, 50, 101, 500, 1000):
            ref = 0
            while ref + 1 <= n // 2 and sum(math.comb(n, i) for i in range(ref + 1)) / 2 ** n <= 0.025:
                ref += 1
            lo, hi, _ = report.median_ci(list(range(1, n + 1)))
            self.assertEqual((lo, hi), (ref, n - ref + 1), n)

    def test_median_ci_large_n_is_fast_and_sane(self):
        import time
        xs = [float(i) for i in range(20000)]
        t0 = time.perf_counter()
        lo, hi, cov = report.median_ci(xs)
        self.assertLess(time.perf_counter() - t0, 1.0)
        self.assertLess(lo, 10000)
        self.assertGreater(hi, 10000)
        self.assertGreaterEqual(cov, 0.95)
        self.assertLess(cov, 0.96)
        # normal approximation: half-width ~ 1.96 * sqrt(n)/2 ~ 138.6
        self.assertAlmostEqual((hi - lo) / 2, 138.6, delta=2)

    def test_summarize_single_sample(self):
        s = report.summarize([5.0])
        self.assertEqual(s["median"], 5.0)
        self.assertEqual(s["stdev"], 0.0)


class CompareTest(unittest.TestCase):
    def go_rust(self, go, rust):
        return report.summarize(go), report.summarize(rust)

    def test_lower_is_better_rust_faster(self):
        g, r = self.go_rust([10, 11, 12], [4, 5, 6])
        c = report.compare(g, r, "lower")
        self.assertAlmostEqual(c["ratio"], 5 / 11)
        self.assertEqual(c["faster"], "rust")
        self.assertAlmostEqual(c["speedup"], 11 / 5)

    def test_lower_is_better_go_faster(self):
        g, r = self.go_rust([4, 5, 6], [10, 11, 12])
        c = report.compare(g, r, "lower")
        self.assertEqual(c["faster"], "go")
        self.assertAlmostEqual(c["speedup"], 11 / 5)

    def test_higher_is_better(self):
        g, r = self.go_rust([100, 110, 120], [200, 210, 220])
        c = report.compare(g, r, "higher")
        self.assertAlmostEqual(c["ratio"], 210 / 110)
        self.assertEqual(c["faster"], "rust")

    def test_overlapping_spread_is_inconclusive(self):
        g, r = self.go_rust([1, 5, 9], [2, 4, 8])
        c = report.compare(g, r, "lower")
        self.assertEqual(c["faster"], "inconclusive")

    def test_zero_go_median(self):
        g, r = self.go_rust([0, 0, 0], [1, 1, 1])
        c = report.compare(g, r, "lower")
        self.assertIsNone(c["ratio"])

    def test_infer_better(self):
        self.assertEqual(report.infer_better("ns/op"), "lower")
        self.assertEqual(report.infer_better("s"), "lower")
        self.assertEqual(report.infer_better("bytes"), "lower")
        self.assertEqual(report.infer_better("MB/s"), "higher")
        self.assertEqual(report.infer_better("txn/s"), "higher")
        self.assertEqual(report.infer_better("ops/s"), "higher")


class SchemaTest(unittest.TestCase):
    def test_valid_result(self):
        self.assertEqual(bench_schema.validate_result(result("a", "go", [1.0])), [])

    def test_missing_required_field(self):
        r = result("a", "go", [1.0])
        del r["unit"]
        errs = bench_schema.validate_result(r)
        self.assertTrue(any("unit" in e for e in errs), errs)

    def test_bad_impl_enum(self):
        errs = bench_schema.validate_result(result("a", "python", [1.0]))
        self.assertTrue(any("impl" in e for e in errs), errs)

    def test_empty_samples(self):
        errs = bench_schema.validate_result(result("a", "go", []))
        self.assertTrue(any("samples" in e for e in errs), errs)

    def test_non_numeric_and_negative_samples(self):
        self.assertTrue(bench_schema.validate_result(result("a", "go", ["1"])))
        self.assertTrue(bench_schema.validate_result(result("a", "go", [-1])))
        self.assertTrue(bench_schema.validate_result(result("a", "go", [True])))

    def test_wrong_schema_version(self):
        r = result("a", "go", [1.0])
        r["schema"] = "bench-result/v2"
        self.assertTrue(bench_schema.validate_result(r))

    def test_unknown_top_level_field_rejected(self):
        r = result("a", "go", [1.0], typo_field=1)
        errs = bench_schema.validate_result(r)
        self.assertTrue(any("typo_field" in e for e in errs), errs)

    def test_better_enum(self):
        self.assertEqual(bench_schema.validate_result(result("a", "go", [1], better="higher")), [])
        self.assertTrue(bench_schema.validate_result(result("a", "go", [1], better="faster")))

    def test_bad_tier_name(self):
        self.assertTrue(bench_schema.validate_result(result("a", "go", [1], tier="Bad Tier")))

    def test_pattern_rejects_trailing_newline(self):
        # re.search('^x$') matches 'x\n'; fullmatch must be used.
        self.assertTrue(bench_schema.validate_result(result("a", "go", [1], tier="selftest\n")))
        self.assertTrue(bench_schema.validate_result(result("a\n", "go", [1])))

    def test_non_finite_samples_rejected_in_memory(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            self.assertTrue(bench_schema.validate_result(result("a", "go", [1.0, bad])), bad)

    def test_non_finite_samples_rejected_from_file(self):
        with tempfile.TemporaryDirectory() as d:
            for i, tok in enumerate(("NaN", "Infinity", "-Infinity")):
                p = os.path.join(d, f"r{i}.json")
                with open(p, "w") as f:
                    f.write('{"schema": "bench-result/v1", "tier": "t", "name": "a", '
                            '"impl": "go", "unit": "s", "samples": [1, %s], "metadata": {}}' % tok)
                rs, errs = bench_schema.load_result_file(p)
                self.assertEqual(rs, [], tok)
                self.assertEqual(len(errs), 1, tok)

    def test_load_file_object_array_and_garbage(self):
        with tempfile.TemporaryDirectory() as d:
            one = os.path.join(d, "one.json")
            many = os.path.join(d, "many.json")
            bad = os.path.join(d, "bad.json")
            with open(one, "w") as f:
                json.dump(result("a", "go", [1]), f)
            with open(many, "w") as f:
                json.dump([result("a", "go", [1]), result("a", "rust", [1])], f)
            with open(bad, "w") as f:
                f.write("{not json")
            rs, errs = bench_schema.load_result_file(one)
            self.assertEqual((len(rs), errs), (1, []))
            rs, errs = bench_schema.load_result_file(many)
            self.assertEqual((len(rs), errs), (2, []))
            rs, errs = bench_schema.load_result_file(bad)
            self.assertEqual(rs, [])
            self.assertEqual(len(errs), 1)

    def test_invalid_entry_in_array_is_dropped_with_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "mixed.json")
            with open(p, "w") as f:
                json.dump([result("a", "go", [1]), result("b", "go", [])], f)
            rs, errs = bench_schema.load_result_file(p)
            self.assertEqual(len(rs), 1)
            self.assertEqual(len(errs), 1)
            self.assertIn("[1]", errs[0])


class BuildReportTest(unittest.TestCase):
    FP = {"schema": "bench-fingerprint/v1", "cpu": {"model": "X"}, "warnings": []}

    def test_paired_and_unpaired_rows(self):
        rs = [
            result("pair", "go", [10, 10, 10]),
            result("pair", "rust", [5, 5, 5]),
            result("go-only", "go", [1]),
            result("rust-only", "rust", [1]),
        ]
        rep = report.build_report(rs, fingerprint=self.FP)
        rows = {r["name"]: r for r in rep["rows"]}
        self.assertEqual(rows["pair"]["status"], "paired")
        self.assertEqual(rows["pair"]["faster"], "rust")
        self.assertEqual(rows["go-only"]["status"], "unpaired")
        self.assertIsNone(rows["go-only"]["ratio"])
        self.assertIsNone(rows["go-only"]["rust"])
        self.assertEqual(rows["rust-only"]["status"], "unpaired")
        self.assertEqual(rep["summary"]["paired"], 1)
        self.assertEqual(rep["summary"]["unpaired"], 2)
        self.assertEqual(rep["errors"], [])
        md = report.render_markdown(rep)
        self.assertIn("go missing", md)
        self.assertIn("rust missing", md)

    def test_unit_mismatch_is_an_error_row(self):
        rs = [result("x", "go", [1], unit="s"), result("x", "rust", [1], unit="ms")]
        rep = report.build_report(rs, fingerprint=self.FP)
        self.assertEqual(rep["rows"][0]["status"], "unit-mismatch")
        self.assertIsNone(rep["rows"][0]["ratio"])
        self.assertTrue(rep["errors"])

    def test_duplicate_results_merge_samples(self):
        rs = [result("x", "go", [1, 2]), result("x", "go", [3]), result("x", "rust", [1])]
        rep = report.build_report(rs, fingerprint=self.FP)
        self.assertEqual(rep["rows"][0]["go"]["n"], 3)

    def test_explicit_better_overrides_unit(self):
        rs = [
            result("x", "go", [10, 10, 10], unit="score", better="higher"),
            result("x", "rust", [20, 20, 20], unit="score", better="higher"),
        ]
        rep = report.build_report(rs, fingerprint=self.FP)
        self.assertEqual(rep["rows"][0]["faster"], "rust")

    def test_conflicting_better_is_error(self):
        rs = [
            result("x", "go", [1], better="higher"),
            result("x", "rust", [1], better="lower"),
        ]
        rep = report.build_report(rs, fingerprint=self.FP)
        self.assertEqual(rep["rows"][0]["status"], "better-mismatch")
        self.assertTrue(rep["errors"])

    def test_markdown_contains_methodology_fingerprint_and_ratio(self):
        rs = [result("pair", "go", [10, 10, 10]), result("pair", "rust", [5, 5, 5])]
        build = {"go_algorand": {"commit": "927ae0863cbb", "tag": "v5.0.4-stable"},
                 "algod_rust": {"commit": "ffdff50d1234"}}
        rep = report.build_report(rs, fingerprint=self.FP, build_info=build)
        md = report.render_markdown(rep)
        self.assertIn("BENCHMARK_COMPARISON.md", md)
        self.assertIn("927ae0863cbb", md)
        self.assertIn("ffdff50d1234", md)
        self.assertIn("0.5", md)  # Rust/Go ratio
        self.assertIn("Rust", md)
        self.assertIn("| X", md.replace("|  X", "| X"))  # CPU model in env table

    def test_tier_failure_and_load_errors_surface(self):
        rep = report.build_report(
            [], fingerprint=self.FP,
            tier_status=[{"tier": "micro", "exit_code": 2, "duration_s": 1.0}],
            load_errors=["results/micro/x.json: bad"])
        self.assertFalse(rep["ok"])
        md = report.render_markdown(rep)
        self.assertIn("micro", md)
        self.assertIn("bad", md)

    def test_ok_when_clean(self):
        rep = report.build_report([result("p", "go", [1]), result("p", "rust", [1])],
                                  fingerprint=self.FP,
                                  tier_status=[{"tier": "t", "exit_code": 0, "duration_s": 0.1}])
        self.assertTrue(rep["ok"])


class MainTest(unittest.TestCase):
    def test_main_writes_report_files(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "results", "t"))
            with open(os.path.join(d, "results", "t", "r.json"), "w") as f:
                json.dump([result("p", "go", [2, 2, 2]), result("p", "rust", [1, 1, 1])], f)
            with open(os.path.join(d, "fingerprint.json"), "w") as f:
                json.dump(self_fp(), f)
            rc = report.main([d])
            self.assertEqual(rc, 0)
            with open(os.path.join(d, "report.json")) as f:
                rep = json.load(f)
            self.assertEqual(rep["schema"], "bench-report/v1")
            self.assertEqual(rep["rows"][0]["faster"], "rust")
            self.assertTrue(os.path.exists(os.path.join(d, "report.md")))

    def _write(self, d, rel, obj):
        p = os.path.join(d, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            json.dump(obj, f)

    def test_tier_field_must_match_directory(self):
        with tempfile.TemporaryDirectory() as d:
            # a micro-tier file claiming to be selftest must not merge into selftest
            self._write(d, "results/selftest/a.json", [result("p", "go", [2], tier="selftest")])
            self._write(d, "results/micro/b.json", [result("p", "rust", [1], tier="selftest")])
            rs, errs = report.load_run_results(d)
            self.assertEqual(len(rs), 1)
            self.assertEqual(rs[0]["impl"], "go")
            self.assertEqual(len(errs), 1)
            self.assertIn("results/micro/b.json", errs[0])
            self.assertIn("micro", errs[0])
            rc = report.main([d])
            self.assertEqual(rc, 1)
            with open(os.path.join(d, "report.json")) as f:
                rep = json.load(f)
            self.assertEqual(rep["rows"][0]["status"], "unpaired")

    def test_result_outside_tier_directory_is_error(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "results/loose.json", [result("p", "go", [2])])
            rs, errs = report.load_run_results(d)
            self.assertEqual(rs, [])
            self.assertEqual(len(errs), 1)

    def test_report_json_is_strict_json(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "results/t/r.json", [result("p", "go", [0, 0, 0]),
                                               result("p", "rust", [1, 1, 1])])
            report.main([d])
            with open(os.path.join(d, "report.json")) as f:
                text = f.read()

            def bad(tok):
                raise ValueError(tok)
            json.loads(text, parse_constant=bad)  # raises on NaN/Infinity
            self.assertNotIn("NaN", text)

    def test_main_nonzero_on_invalid_result(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "results", "t"))
            with open(os.path.join(d, "results", "t", "r.json"), "w") as f:
                json.dump(result("p", "go", []), f)
            rc = report.main([d])
            self.assertEqual(rc, 1)
            self.assertTrue(os.path.exists(os.path.join(d, "report.md")))


def self_fp():
    return {"schema": "bench-fingerprint/v1", "cpu": {"model": "Y"}, "warnings": []}


if __name__ == "__main__":
    unittest.main()
