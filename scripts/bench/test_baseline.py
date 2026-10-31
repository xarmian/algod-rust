#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests for baseline.py and `report.py --publish` (issue #2109, epic #2101).

Covers the baseline extraction (every paired row, including zero and
undefined ratios), the direction-aware regression check (noise rules,
quantised rows, host classes, missing rows and sections), the publish of a
generated block into docs/BENCHMARK_RESULTS.md (atomic, CRLF-safe, headline
derived from the same rows) and the baseline JSON file.
Stdlib only, no Docker.
"""
import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import baseline  # noqa: E402
import report  # noqa: E402
from test_report import result  # noqa: E402

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def make_report(rows, ci=False):
    """rows: (tier, name, unit, go_samples, rust_samples)."""
    rs = []
    for tier, name, unit, go, rust in rows:
        rs.append(result(name, "go", go, unit=unit, tier=tier))
        rs.append(result(name, "rust", rust, unit=unit, tier=tier))
    fp = {"cpu": {"model": "Test CPU", "logical_cpus": 4}, "os": {"distro": "TestOS"},
          "memory": {"total_bytes": 8 * 2**30}, "toolchains": {},
          "ci": {"is_ci": ci, "provider": "github-actions" if ci else None},
          "commits": {"go_algorand": {"commit": "g" * 40}, "algod_rust": {"commit": "r" * 40}},
          "warnings": []}
    return report.build_report(rs, fingerprint=fp, tier_status=[], run_dir="run1")


def row(ratio=None, better="lower", name="a", unit="s", go=1.0, rust=None, faster="go",
        rust_range=None, tier="t"):
    """A baseline/current row as extract_rows produces it."""
    if rust is None:
        rust = (ratio if ratio is not None else 0.0) * go
    r = {"tier": tier, "name": name, "unit": unit, "better": better, "go_median": go,
         "rust_median": rust, "ratio": ratio, "faster": faster}
    if rust_range:
        r["rust_lo"], r["rust_hi"] = rust_range
    return r


class ExtractTest(unittest.TestCase):
    def test_extract_keeps_paired_rows_only(self):
        rep = make_report([("replay", "small/wall_s", "s", [10.0], [20.0])])
        rep["rows"].append({"tier": "x", "name": "u", "status": "unpaired", "unit": "s"})
        rows = baseline.extract_rows(rep)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["tier"], r["name"], r["better"]), ("replay", "small/wall_s", "lower"))
        self.assertEqual((r["go_median"], r["rust_median"], r["ratio"]), (10.0, 20.0, 2.0))
        self.assertEqual((r["rust_lo"], r["rust_hi"]), (20.0, 20.0))

    def test_extract_keeps_rows_with_zero_or_undefined_ratio(self):
        rep = make_report([("t", "go0", "s", [0.0], [1.0]),       # ratio undefined (Go 0)
                           ("t", "rust0", "s", [1.0], [0.0]),     # ratio 0
                           ("t", "both0", "ratio", [0.0], [0.0])])
        rows = {r["name"]: r for r in baseline.extract_rows(rep)}
        self.assertEqual(sorted(rows), ["both0", "go0", "rust0"])
        self.assertIsNone(rows["go0"]["ratio"])
        self.assertEqual(rows["rust0"]["ratio"], 0.0)

    def test_extract_count_equals_paired_rows(self):
        rep = make_report([("t", "a", "s", [0.0], [0.0]), ("t", "b", "s", [1.0], [2.0])])
        self.assertEqual(len(baseline.extract_rows(rep)), rep["summary"]["paired"])


class CompareTest(unittest.TestCase):
    def test_lower_is_better_regression_when_ratio_grows(self):
        out = baseline.compare_rows([row(1.6)], [row(1.0)], tolerance=0.25)
        self.assertEqual([r["verdict"] for r in out], ["regression"])
        self.assertAlmostEqual(out[0]["change"], 0.6)

    def test_within_tolerance_is_ok(self):
        out = baseline.compare_rows([row(1.2)], [row(1.0)], tolerance=0.25)
        self.assertEqual(out[0]["verdict"], "ok")

    def test_higher_is_better_regression_when_ratio_shrinks(self):
        out = baseline.compare_rows([row(0.5, "higher")], [row(1.0, "higher")], tolerance=0.25)
        self.assertEqual(out[0]["verdict"], "regression")
        self.assertAlmostEqual(out[0]["change"], 1.0)

    def test_improvement_is_reported_not_flagged(self):
        out = baseline.compare_rows([row(0.5)], [row(1.0)], tolerance=0.25)
        self.assertEqual(out[0]["verdict"], "improved")

    def test_rows_missing_on_one_side_are_new_or_missing(self):
        out = baseline.compare_rows([row(1.0, name="new")], [row(1.0, name="old")], tolerance=0.25)
        self.assertEqual(sorted((r["name"], r["verdict"]) for r in out),
                         [("new", "new"), ("old", "missing")])

    def test_ratio_not_absolute_is_compared(self):
        # A slower runner moves both medians; only the ratio matters.
        cur = row(2.0, go=10.0, rust=20.0)
        base = row(2.0, go=1.0, rust=2.0)
        self.assertEqual(baseline.compare_rows([cur], [base], 0.25)[0]["verdict"], "ok")

    def test_unit_or_direction_change_is_incomparable(self):
        cur = row(1.0, unit="ms")
        out = baseline.compare_rows([cur], [row(1.0)], 0.25)
        self.assertEqual(out[0]["verdict"], "incomparable")

    # --- finding 1: zero and undefined ratios -------------------------------

    def test_collapse_to_zero_for_a_higher_is_better_row_is_a_regression(self):
        cur = row(0.0, "higher", unit="req/s", go=100.0, rust=0.0, faster="go")
        base = row(1.0, "higher", unit="req/s", go=100.0, rust=100.0, faster="go")
        out = baseline.compare_rows([cur], [base], 0.25)
        self.assertEqual(out[0]["verdict"], "regression")

    def test_error_rate_from_zero_to_nonzero_is_a_regression(self):
        # Go is 0 too, so the ratio is undefined on both sides: medians decide.
        base = row(None, unit="ratio", go=0.0, rust=0.0, faster="inconclusive",
                   rust_range=(0.0, 0.0))
        cur = row(None, unit="ratio", go=0.0, rust=0.2, faster="go", rust_range=(0.1, 0.3))
        out = baseline.compare_rows([cur], [base], 0.25)
        self.assertEqual(out[0]["verdict"], "regression")

    def test_zero_to_zero_is_ok(self):
        base = row(None, unit="ratio", go=0.0, rust=0.0, faster="inconclusive")
        cur = row(None, unit="ratio", go=0.0, rust=0.0, faster="inconclusive")
        self.assertEqual(baseline.compare_rows([cur], [base], 0.25)[0]["verdict"], "ok")

    def test_zero_baseline_threshold_is_absolute(self):
        base = row(None, unit="ratio", go=0.0, rust=0.0, faster="inconclusive")
        cur = row(None, unit="ratio", go=0.0, rust=0.01, faster="go")
        out = baseline.compare_rows([cur], [base], 0.25, zero_threshold=0.05)
        self.assertEqual(out[0]["verdict"], "ok")
        out = baseline.compare_rows([cur], [base], 0.25, zero_threshold=0.0)
        self.assertEqual(out[0]["verdict"], "regression")

    def test_undefined_ratio_with_nonzero_medians_uses_relative_median_change(self):
        base = row(None, go=0.0, rust=2.0, faster="go")
        cur = row(None, go=0.0, rust=3.0, faster="go")
        out = baseline.compare_rows([cur], [base], 0.25)
        self.assertEqual(out[0]["verdict"], "regression")
        self.assertAlmostEqual(out[0]["change"], 0.5)

    def test_rust_zero_ratio_row_that_stays_zero_is_ok(self):
        base = row(0.0, go=1.0, rust=0.0, faster="rust")
        cur = row(0.0, go=1.0, rust=0.0, faster="rust")
        self.assertEqual(baseline.compare_rows([cur], [base], 0.25)[0]["verdict"], "ok")

    # --- finding 4: noise rules ----------------------------------------------

    def test_inconclusive_baseline_with_overlapping_ranges_is_noise_not_regression(self):
        base = row(1.0, faster="inconclusive", rust_range=(0.8, 1.4))
        cur = row(1.6, faster="inconclusive", rust_range=(1.2, 2.0))
        out = baseline.compare_rows([cur], [base], 0.25)
        self.assertEqual(out[0]["verdict"], "noise")

    def test_inconclusive_baseline_with_clear_separation_is_a_regression(self):
        base = row(1.0, faster="inconclusive", rust_range=(0.9, 1.1))
        cur = row(2.0, faster="go", rust_range=(1.9, 2.2))
        self.assertEqual(baseline.compare_rows([cur], [base], 0.25)[0]["verdict"], "regression")

    def test_conclusive_baseline_is_eligible_even_when_ranges_overlap(self):
        base = row(1.0, faster="rust", rust_range=(0.8, 1.4))
        cur = row(1.6, faster="inconclusive", rust_range=(1.2, 2.0))
        self.assertEqual(baseline.compare_rows([cur], [base], 0.25)[0]["verdict"], "regression")

    def test_quantised_rounds_step_does_not_flag(self):
        base = row(1.0, unit="rounds", go=3.0, rust=3.0, faster="inconclusive",
                   rust_range=(3.0, 3.0))
        cur = row(1.33, unit="rounds", go=3.0, rust=4.0, faster="go", rust_range=(4.0, 4.0))
        self.assertEqual(baseline.compare_rows([cur], [base], 0.25)[0]["verdict"], "ok")
        cur2 = row(2.0, unit="rounds", go=3.0, rust=6.0, faster="go", rust_range=(6.0, 6.0))
        self.assertEqual(baseline.compare_rows([cur2], [base], 0.25)[0]["verdict"], "regression")

    # --- finding 8: host classes ---------------------------------------------

    def test_other_host_class_skips_absolute_unit_rows_only(self):
        mb = row(5.0, unit="MB", go=1.0, rust=5.0)
        cores = row(5.0, unit="cores", name="c", go=1.0, rust=5.0)
        tm = row(1.6, unit="s", name="t")
        base = [row(1.0, unit="MB"), row(1.0, unit="cores", name="c"), row(1.0, unit="s", name="t")]
        out = {r["name"]: r["verdict"] for r in
               baseline.compare_rows([mb, cores, tm], base, 0.25, same_host=False)}
        self.assertEqual(out, {"a": "skipped-host", "c": "skipped-host", "t": "regression"})

    def test_same_host_class_compares_absolute_unit_rows(self):
        out = baseline.compare_rows([row(5.0, unit="MB")], [row(1.0, unit="MB")], 0.25,
                                    same_host=True)
        self.assertEqual(out[0]["verdict"], "regression")

    def test_host_class_from_fingerprint(self):
        self.assertEqual(baseline.host_class(make_report([("t", "a", "s", [1.0], [1.0])])["fingerprint"]),
                         "dev-host")
        fp = make_report([("t", "a", "s", [1.0], [1.0])], ci=True)["fingerprint"]
        self.assertEqual(baseline.host_class(fp), "ci-github-actions")
        self.assertEqual(baseline.host_class(None), "unknown")


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
            self.assertEqual(sec["host_class"], "dev-host")
            self.assertEqual(sec["rows"][0]["ratio"], 2.0)
            self.assertEqual(sec["go_commit"], "g" * 40)
            self.assertEqual(sec["rust_commit"], "r" * 40)
            with open(p, "rb") as f:
                self.assertNotIn(b"\r", f.read())

    def test_ci_section_records_ci_host_class(self):
        rep = make_report([("t", "a", "s", [1.0], [1.0])], ci=True)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "b.json")
            baseline.update_baseline_file(p, "ci-runner-main", rep, date="2026-11-07")
            self.assertEqual(baseline.load_baseline_file(p)["sections"]["ci-runner-main"]["host_class"],
                             "ci-github-actions")

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
    def write_report(self, d, name, rows, ci=False):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            json.dump(make_report(rows, ci=ci), f)
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

    def setup_pair(self, d, cur_rust, cur_ci=False, base_rows=None):
        base_rep = os.path.join(d, "base.json")
        with open(base_rep, "w") as f:
            json.dump(make_report(base_rows or
                                  [("replay", "small/wall_s", "s", [10.0, 10.1], [10.0, 10.1])]), f)
        bl = os.path.join(d, "baseline.json")
        with open(base_rep) as f:
            baseline.update_baseline_file(bl, "ci", json.load(f), date="2026-10-31")
        cur = self.write_report(d, "cur.json",
                                [("replay", "small/wall_s", "s", [10.0, 10.1], [cur_rust, cur_rust + 0.1])],
                                ci=cur_ci)
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
            rc, out, _ = self.run_cli(["compare", cur, "--baseline", bl, "--section", "ci",
                                       "--fail-on-regression"], env={"GITHUB_ACTIONS": "true"})
            self.assertEqual(rc, 0)
            self.assertNotIn("::warning", out)

    def test_missing_section_is_zero_without_the_flag_and_failure_with_it(self):
        with tempfile.TemporaryDirectory() as d:
            bl, cur = self.setup_pair(d, 20.0)
            rc, out, _ = self.run_cli(["compare", cur, "--baseline", bl, "--section", "nope"])
            self.assertEqual(rc, 0)
            self.assertIn("no baseline section", out)
            rc, out, _ = self.run_cli(["compare", cur, "--baseline", bl, "--section", "nope",
                                       "--fail-on-regression"])
            self.assertEqual(rc, 1)
            self.assertIn("no baseline section", out)

    def test_row_missing_from_the_run_fails_under_the_flag(self):
        with tempfile.TemporaryDirectory() as d:
            bl, _ = self.setup_pair(d, 10.0)
            cur = self.write_report(d, "cur2.json", [("replay", "other", "s", [1.0], [1.0])])
            rc, out, _ = self.run_cli(["compare", cur, "--baseline", bl, "--section", "ci"])
            self.assertEqual(rc, 0)
            self.assertIn("missing", out)
            rc, _, _ = self.run_cli(["compare", cur, "--baseline", bl, "--section", "ci",
                                     "--fail-on-regression"])
            self.assertEqual(rc, 1)

    def test_other_host_class_skips_resource_rows(self):
        rows = [("replay", "small/peak_rss_mb", "MB", [10.0, 10.1], [10.0, 10.1])]
        with tempfile.TemporaryDirectory() as d:
            bl, _ = self.setup_pair(d, 10.0, base_rows=rows)
            cur = self.write_report(d, "c.json",
                                    [("replay", "small/peak_rss_mb", "MB", [10.0, 10.1], [90.0, 90.1])],
                                    ci=True)
            rc, out, _ = self.run_cli(["compare", cur, "--baseline", bl, "--section", "ci",
                                       "--fail-on-regression"])
            self.assertEqual(rc, 0)
            self.assertIn("skipped-host", out)

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

    def rep(self):
        return make_report([("replay", "small/wall_s", "s", [10.0], [20.0]),
                            ("replay", "small/err", "ratio", [0.0], [0.0]),
                            ("micro", "codec/x", "ns/op", [10.0], [5.0])])

    def test_publish_replaces_only_the_named_block(self):
        rep = self.rep()
        text = report.publish_block(self.DOC, "ci", rep, command="make bench-compare TIERS=replay")
        self.assertIn("keep me", text)
        self.assertNotIn("OLD", text)
        self.assertIn("make bench-compare TIERS=replay", text)
        self.assertIn("| small/wall_s |", text)
        self.assertIn("Test CPU", text)
        self.assertNotIn("\n# algod Go vs Rust", text)
        self.assertNotIn("\n## Results", text)
        self.assertEqual(text.count("bench-baseline:begin ci"), 1)
        self.assertEqual(report.publish_block(text, "ci", rep, command="make bench-compare TIERS=replay"), text)

    def test_publish_without_markers_is_an_error(self):
        with self.assertRaises(ValueError):
            report.publish_block("# no markers\n", "ci", self.rep(), command="x")

    def test_publish_refuses_a_failed_report(self):
        rep = self.rep()
        rep["ok"] = False
        rep["errors"] = ["gate failed"]
        with self.assertRaises(ValueError):
            report.publish_block(self.DOC, "ci", rep, command="x")

    # --- finding 5: the headline is generated from the same rows ------------

    @staticmethod
    def parse_block(text):
        """(summary counts per tier, table counts per tier) of one generated block."""
        summary, tables, tier = {}, {}, None
        in_summary = False
        for line in text.splitlines():
            if line.startswith("#### Summary by tier"):
                in_summary = True
                continue
            if line.startswith("#### "):
                in_summary = False
                tier = None  # a later section (e.g. Tiers) is not a result table
            m = re.match(r"##### (\S+)", line)
            if m:
                tier = m.group(1)
            if in_summary and line.startswith("| ") and not line.startswith(("| Tier", "|---")):
                c = [x.strip() for x in line.strip("|").split("|")]
                summary[c[0]] = tuple(int(x) for x in c[1:5])
            elif tier and line.startswith("| ") and not line.startswith(("| Benchmark", "|---")):
                last = line.strip().strip("|").split("|")[-1].strip()
                t = tables.setdefault(tier, [0, 0, 0, 0])
                t[0] += 1
                if last.startswith("**Rust**"):
                    t[1] += 1
                elif last.startswith("**Go**"):
                    t[2] += 1
                elif last == "inconclusive":
                    t[3] += 1
        return summary, {k: tuple(v) for k, v in tables.items()}

    def test_headline_counts_equal_the_blocks_table_counts(self):
        text = report.publish_block(self.DOC, "ci", self.rep(), command="x")
        summary, tables = self.parse_block(text)
        self.assertEqual(summary, {"micro": (1, 1, 0, 0), "replay": (2, 0, 1, 1)})
        self.assertEqual(summary, tables)

    def test_headline_counts_cover_every_paired_row(self):
        rep = self.rep()
        text = report.publish_block(self.DOC, "ci", rep, command="x")
        summary, _ = self.parse_block(text)
        self.assertEqual(sum(v[0] for v in summary.values()), rep["summary"]["paired"])
        self.assertIn("0 paired row(s) excluded", text)

    def test_published_doc_headline_matches_its_blocks(self):
        path = os.path.join(ROOT, "docs", "BENCHMARK_RESULTS.md")
        with open(path, encoding="utf-8") as f:
            doc = f.read()
        blocks = re.findall(r"<!-- bench-baseline:begin (\S+) -->\n(.*?)<!-- bench-baseline:end \1 -->",
                            doc, re.S)
        self.assertTrue(blocks)
        for name, body in blocks:
            summary, tables = self.parse_block(body)
            self.assertTrue(summary, name)
            self.assertEqual(summary, tables, name)
            with open(os.path.join(ROOT, "benchmarks", "baseline.json"), encoding="utf-8") as f:
                rows = json.load(f)["sections"][name]["rows"]
            self.assertEqual(sum(v[0] for v in summary.values()), len(rows), name)

    # --- finding 6: atomic publish, CRLF -------------------------------------

    def test_cli_publish_writes_doc_and_baseline_json(self):
        rep = self.rep()
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
            self.assertEqual(sorted(os.listdir(d)), ["RESULTS.md", "baseline.json", "run"])

    def test_failing_baseline_update_leaves_both_files_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            run = os.path.join(d, "run")
            os.makedirs(run)
            with open(os.path.join(run, "report.json"), "w") as f:
                json.dump(self.rep(), f)
            doc = os.path.join(d, "RESULTS.md")
            with open(doc, "w", newline="\n") as f:
                f.write(self.DOC)
            bl = os.path.join(d, "baseline.json")
            with open(bl, "w") as f:
                json.dump({"schema": "wrong"}, f)
            before = (read_bytes(doc), read_bytes(bl))
            rc = report.publish_main([run, "--doc", doc, "--section", "ci", "--command", "cmd",
                                      "--baseline", bl])
            self.assertEqual(rc, 1)
            self.assertEqual((read_bytes(doc), read_bytes(bl)), before)
            self.assertEqual(sorted(os.listdir(d)), ["RESULTS.md", "baseline.json", "run"])

    def test_crlf_doc_is_updated_and_keeps_its_line_endings(self):
        crlf = self.DOC.replace("\n", "\r\n")
        text = report.publish_block(crlf, "ci", self.rep(), command="cmd")
        self.assertNotIn("OLD", text)
        self.assertIn("small/wall_s", text)
        self.assertNotRegex(text, r"(?<!\r)\n")
        self.assertIn("keep me\r\n", text)

    def test_cli_publish_on_a_crlf_doc(self):
        with tempfile.TemporaryDirectory() as d:
            run = os.path.join(d, "run")
            os.makedirs(run)
            with open(os.path.join(run, "report.json"), "w") as f:
                json.dump(self.rep(), f)
            doc = os.path.join(d, "RESULTS.md")
            with open(doc, "wb") as f:
                f.write(self.DOC.replace("\n", "\r\n").encode())
            rc = report.publish_main([run, "--doc", doc, "--section", "ci", "--command", "cmd",
                                      "--baseline", os.path.join(d, "b.json")])
            self.assertEqual(rc, 0)
            raw = read_bytes(doc)
            self.assertNotIn(b"OLD", raw)
            self.assertIsNone(re.search(rb"(?<!\r)\n", raw))


if __name__ == "__main__":
    unittest.main()
