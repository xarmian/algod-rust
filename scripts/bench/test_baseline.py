#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests for baseline.py and `report.py --publish` (issue #2109, epic #2101).

Covers the baseline extraction, the direction-aware regression check (warn by
default, fail only with --fail-on-regression), the publish of a generated
block into docs/BENCHMARK_RESULTS.md, and the baseline JSON file.
Stdlib only, no Docker.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import baseline  # noqa: E402
import report  # noqa: E402
from test_report import result  # noqa: E402


def make_report(rows):
    """rows: (tier, name, unit, go_samples, rust_samples)."""
    rs = []
    for tier, name, unit, go, rust in rows:
        rs.append(result(name, "go", go, unit=unit, tier=tier))
        rs.append(result(name, "rust", rust, unit=unit, tier=tier))
    fp = {"cpu": {"model": "Test CPU", "logical_cpus": 4}, "os": {"distro": "TestOS"},
          "memory": {"total_bytes": 8 * 2**30}, "toolchains": {}, "ci": {"is_ci": False},
          "commits": {"go_algorand": {"commit": "g" * 40}, "algod_rust": {"commit": "r" * 40}},
          "warnings": []}
    return report.build_report(rs, fingerprint=fp, tier_status=[], run_dir="run1")


class ExtractTest(unittest.TestCase):
    def test_extract_keeps_paired_rows_only(self):
        rep = make_report([("replay", "small/wall_s", "s", [10.0], [20.0])])
        rep["rows"].append({"tier": "x", "name": "u", "status": "unpaired", "unit": "s"})
        rows = baseline.extract_rows(rep)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["tier"], r["name"], r["better"]), ("replay", "small/wall_s", "lower"))
        self.assertEqual((r["go_median"], r["rust_median"], r["ratio"]), (10.0, 20.0, 2.0))

    def test_extract_skips_rows_without_ratio(self):
        rep = make_report([("t", "a", "s", [0.0], [1.0])])
        self.assertEqual(baseline.extract_rows(rep), [])


class CompareTest(unittest.TestCase):
    def base(self, ratio, better="lower", name="a"):
        return {"tier": "t", "name": name, "unit": "s", "better": better,
                "go_median": 1.0, "rust_median": ratio, "ratio": ratio}

    def test_lower_is_better_regression_when_ratio_grows(self):
        cur = [self.base(1.6)]
        out = baseline.compare_rows(cur, [self.base(1.0)], tolerance=0.25)
        self.assertEqual([r["verdict"] for r in out], ["regression"])
        self.assertAlmostEqual(out[0]["change"], 0.6)

    def test_within_tolerance_is_ok(self):
        out = baseline.compare_rows([self.base(1.2)], [self.base(1.0)], tolerance=0.25)
        self.assertEqual(out[0]["verdict"], "ok")

    def test_higher_is_better_regression_when_ratio_shrinks(self):
        out = baseline.compare_rows([self.base(0.5, "higher")], [self.base(1.0, "higher")],
                                    tolerance=0.25)
        self.assertEqual(out[0]["verdict"], "regression")
        # relative degradation is baseline/current - 1 for higher-is-better
        self.assertAlmostEqual(out[0]["change"], 1.0)

    def test_improvement_is_reported_not_flagged(self):
        out = baseline.compare_rows([self.base(0.5)], [self.base(1.0)], tolerance=0.25)
        self.assertEqual(out[0]["verdict"], "improved")

    def test_rows_missing_on_one_side_are_new_or_gone(self):
        out = baseline.compare_rows([self.base(1.0, name="new")], [self.base(1.0, name="old")],
                                    tolerance=0.25)
        self.assertEqual(sorted((r["name"], r["verdict"]) for r in out),
                         [("new", "new"), ("old", "missing")])

    def test_rust_only_ahead_baseline_still_compares_ratio_not_absolute(self):
        # A slower runner moves both medians; only the ratio matters.
        cur = {"tier": "t", "name": "a", "unit": "s", "better": "lower",
               "go_median": 10.0, "rust_median": 20.0, "ratio": 2.0}
        base = {"tier": "t", "name": "a", "unit": "s", "better": "lower",
                "go_median": 1.0, "rust_median": 2.0, "ratio": 2.0}
        self.assertEqual(baseline.compare_rows([cur], [base], 0.25)[0]["verdict"], "ok")

    def test_unit_or_direction_change_is_incomparable(self):
        cur = self.base(1.0)
        cur["unit"] = "ms"
        out = baseline.compare_rows([cur], [self.base(1.0)], 0.25)
        self.assertEqual(out[0]["verdict"], "incomparable")


class BaselineFileTest(unittest.TestCase):
    def test_update_and_load_roundtrip(self):
        rep = make_report([("replay", "small/wall_s", "s", [10.0], [20.0])])
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "baseline.json")
            baseline.update_baseline_file(p, "ci-small", rep, date="2026-10-31")
            baseline.update_baseline_file(p, "other", rep, date="2026-11-01")
            doc = baseline.load_baseline_file(p)
            self.assertEqual(sorted(doc["sections"]), ["ci-small", "other"])
            sec = doc["sections"]["ci-small"]
            self.assertEqual(sec["date"], "2026-10-31")
            self.assertEqual(sec["rows"][0]["ratio"], 2.0)
            self.assertEqual(sec["go_commit"], "g" * 40)
            self.assertEqual(sec["rust_commit"], "r" * 40)
            with open(p, "rb") as f:
                self.assertNotIn(b"\r", f.read())

    def test_load_missing_file_is_empty(self):
        self.assertEqual(baseline.load_baseline_file("/nonexistent/x.json")["sections"], {})

    def test_load_rejects_wrong_schema(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "b.json")
            with open(p, "w") as f:
                json.dump({"schema": "nope"}, f)
            with self.assertRaises(ValueError):
                baseline.load_baseline_file(p)


class CliTest(unittest.TestCase):
    def write_report(self, d, name, rows):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            json.dump(make_report(rows), f)
        return p

    def run_cli(self, args, env=None):
        out, err = io.StringIO(), io.StringIO()
        old = dict(os.environ)
        os.environ.update(env or {})
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = baseline.main(args)
        finally:
            os.environ.clear()
            os.environ.update(old)
        return rc, out.getvalue(), err.getvalue()

    def setup_pair(self, d, cur_rust):
        base_rep = os.path.join(d, "base.json")
        with open(base_rep, "w") as f:
            json.dump(make_report([("replay", "small/wall_s", "s", [10.0], [10.0])]), f)
        bl = os.path.join(d, "baseline.json")
        with open(base_rep) as f:
            baseline.update_baseline_file(bl, "ci", json.load(f), date="2026-10-31")
        cur = self.write_report(d, "cur.json", [("replay", "small/wall_s", "s", [10.0], [cur_rust])])
        return bl, cur

    def test_regression_warns_but_exits_zero(self):
        with tempfile.TemporaryDirectory() as d:
            bl, cur = self.setup_pair(d, 20.0)
            rc, out, _ = self.run_cli(["compare", cur, "--baseline", bl, "--section", "ci"],
                                      env={"GITHUB_ACTIONS": "true"})
            self.assertEqual(rc, 0)
            self.assertIn("::warning", out)
            self.assertIn("small/wall_s", out)
            self.assertIn("regression", out)

    def test_fail_on_regression_exits_one(self):
        with tempfile.TemporaryDirectory() as d:
            bl, cur = self.setup_pair(d, 20.0)
            rc, _, _ = self.run_cli(["compare", cur, "--baseline", bl, "--section", "ci",
                                     "--fail-on-regression"])
            self.assertEqual(rc, 1)

    def test_no_regression_is_quiet_and_zero(self):
        with tempfile.TemporaryDirectory() as d:
            bl, cur = self.setup_pair(d, 10.5)
            rc, out, _ = self.run_cli(["compare", cur, "--baseline", bl, "--section", "ci"],
                                      env={"GITHUB_ACTIONS": "true"})
            self.assertEqual(rc, 0)
            self.assertNotIn("::warning", out)

    def test_missing_section_is_a_notice_not_a_failure(self):
        with tempfile.TemporaryDirectory() as d:
            bl, cur = self.setup_pair(d, 20.0)
            rc, out, _ = self.run_cli(["compare", cur, "--baseline", bl, "--section", "nope",
                                       "--fail-on-regression"])
            self.assertEqual(rc, 0)
            self.assertIn("no baseline section", out)

    def test_markdown_table_written_to_summary_file(self):
        with tempfile.TemporaryDirectory() as d:
            bl, cur = self.setup_pair(d, 20.0)
            summ = os.path.join(d, "summary.md")
            self.run_cli(["compare", cur, "--baseline", bl, "--section", "ci"],
                         env={"GITHUB_STEP_SUMMARY": summ})
            with open(summ) as f:
                text = f.read()
            self.assertIn("| replay | small/wall_s |", text)


class PublishTest(unittest.TestCase):
    DOC = ("# Results\n\nintro\n\n<!-- bench-baseline:begin ci -->\nOLD\n<!-- bench-baseline:end ci -->\n\n"
           "keep me\n")

    def test_publish_replaces_only_the_named_block(self):
        rep = make_report([("replay", "small/wall_s", "s", [10.0], [20.0])])
        text = report.publish_block(self.DOC, "ci", rep, command="make bench-compare TIERS=replay")
        self.assertIn("keep me", text)
        self.assertNotIn("OLD", text)
        self.assertIn("make bench-compare TIERS=replay", text)
        self.assertIn("| small/wall_s |", text)
        self.assertIn("Test CPU", text)
        # headings are demoted below the doc's own structure and the report title is dropped
        self.assertNotIn("\n# algod Go vs Rust", text)
        self.assertNotIn("\n## Results", text)
        self.assertEqual(text.count("bench-baseline:begin ci"), 1)
        # idempotent for the same report
        self.assertEqual(report.publish_block(text, "ci", rep, command="make bench-compare TIERS=replay"), text)

    def test_publish_without_markers_is_an_error(self):
        rep = make_report([("t", "a", "s", [1.0], [1.0])])
        with self.assertRaises(ValueError):
            report.publish_block("# no markers\n", "ci", rep, command="x")

    def test_publish_refuses_a_failed_report(self):
        rep = make_report([("t", "a", "s", [1.0], [1.0])])
        rep["ok"] = False
        rep["errors"] = ["gate failed"]
        with self.assertRaises(ValueError):
            report.publish_block(self.DOC, "ci", rep, command="x")

    def test_cli_publish_writes_doc_and_baseline_json(self):
        rep = make_report([("replay", "small/wall_s", "s", [10.0], [20.0])])
        with tempfile.TemporaryDirectory() as d:
            run = os.path.join(d, "run")
            os.makedirs(run)
            with open(os.path.join(run, "report.json"), "w") as f:
                json.dump(rep, f)
            doc = os.path.join(d, "RESULTS.md")
            with open(doc, "w", newline="\n") as f:
                f.write(self.DOC)
            bl = os.path.join(d, "baseline.json")
            rc = report.publish_main([run, "--doc", doc, "--section", "ci", "--command", "cmd",
                                      "--baseline", bl])
            self.assertEqual(rc, 0)
            with open(doc, "rb") as f:
                raw = f.read()
            self.assertNotIn(b"\r", raw)
            self.assertIn(b"small/wall_s", raw)
            self.assertIn("ci", baseline.load_baseline_file(bl)["sections"])


if __name__ == "__main__":
    unittest.main()
