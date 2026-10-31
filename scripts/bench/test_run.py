#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for the bench-compare tier runner, run.py (issue #2102, epic #2101).

Includes an end-to-end run of the built-in `selftest` tier into a temporary
directory (the same path `make bench-compare TIERS=selftest` takes).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run  # noqa: E402


class TierDiscoveryTest(unittest.TestCase):
    def test_selftest_tier_is_discovered(self):
        tiers = run.discover_tiers(os.path.join(HERE, "tiers"))
        self.assertIn("selftest", tiers)

    def test_parse_tiers(self):
        self.assertEqual(run.parse_tiers("micro, replay,,micro"), ["micro", "replay"])
        with self.assertRaises(ValueError):
            run.parse_tiers("")
        with self.assertRaises(ValueError):
            run.parse_tiers("Bad/Name")

    def test_needs_build_header(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.sh")
            b = os.path.join(d, "b.py")
            with open(a, "w") as f:
                f.write("#!/usr/bin/env bash\n# bench-tier-needs: build\necho\n")
            with open(b, "w") as f:
                f.write("#!/usr/bin/env python3\nprint()\n")
            self.assertTrue(run.tier_needs_build(a))
            self.assertFalse(run.tier_needs_build(b))
            self.assertFalse(run.tier_needs_build(os.path.join(HERE, "tiers", "selftest.py")))

    def test_unknown_tier_fails_fast(self):
        with tempfile.TemporaryDirectory() as d:
            rc = run.main(["--tiers", "nosuchtier", "--runs", "1", "--run-dir", d,
                           "--build", "never"])
            self.assertEqual(rc, 2)

    def test_duplicate_tier_names_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            for n in ("x.sh", "x.py"):
                with open(os.path.join(d, n), "w") as f:
                    f.write("\n")
            with self.assertRaises(ValueError):
                run.discover_tiers(d)


class RunDirReuseTest(unittest.TestCase):
    """A reused run dir must never merge stale results into a new report."""

    def _seed_stale(self, d):
        os.makedirs(os.path.join(d, "results", "oldtier"))
        with open(os.path.join(d, "results", "oldtier", "stale.json"), "w") as f:
            json.dump({"schema": "bench-result/v1", "tier": "oldtier", "name": "stale",
                       "impl": "go", "unit": "s", "samples": [1], "metadata": {}}, f)
        with open(os.path.join(d, "build-info.json"), "w") as f:
            json.dump({"schema": "bench-build-info/v1", "stale": True}, f)

    def test_non_empty_run_dir_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            self._seed_stale(d)
            rc = run.main(["--tiers", "selftest", "--runs", "1", "--run-dir", d,
                           "--build", "never"])
            self.assertEqual(rc, 2)
            self.assertFalse(os.path.exists(os.path.join(d, "report.json")))

    def test_clean_clears_stale_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            self._seed_stale(d)
            rc = run.main(["--tiers", "selftest", "--runs", "1", "--run-dir", d,
                           "--build", "never", "--clean"])
            self.assertEqual(rc, 0)
            self.assertFalse(os.path.exists(os.path.join(d, "results", "oldtier")))
            self.assertFalse(os.path.exists(os.path.join(d, "build-info.json")))
            with open(os.path.join(d, "report.json")) as f:
                rep = json.load(f)
            self.assertNotIn("oldtier", {r["tier"] for r in rep["rows"]})
            self.assertIsNone(rep["build_info"])

    def test_two_runs_into_same_dir_do_not_merge(self):
        with tempfile.TemporaryDirectory() as d:
            for _ in range(2):
                rc = run.main(["--tiers", "selftest", "--runs", "2", "--run-dir", d,
                               "--build", "never", "--clean"])
                self.assertEqual(rc, 0)
            with open(os.path.join(d, "report.json")) as f:
                rep = json.load(f)
            row = [r for r in rep["rows"] if r["name"] == "sha256-1MiB"][0]
            self.assertEqual(row["go"]["n"], 2)

    def test_empty_existing_dir_is_fine(self):
        with tempfile.TemporaryDirectory() as d:
            rc = run.main(["--tiers", "selftest", "--runs", "1", "--run-dir", d,
                           "--build", "never"])
            self.assertEqual(rc, 0)


class RunsEnvTest(unittest.TestCase):
    def test_bad_runs_env_ignored_when_flag_given(self):
        old = os.environ.get("RUNS")
        os.environ["RUNS"] = "not-a-number"
        try:
            with tempfile.TemporaryDirectory() as d:
                rc = run.main(["--tiers", "selftest", "--runs", "1", "--run-dir", d,
                               "--build", "never"])
                self.assertEqual(rc, 0)
                with self.assertRaises(SystemExit) as cm:
                    run.main(["--tiers", "selftest", "--run-dir", d, "--build", "never"])
                self.assertEqual(cm.exception.code, 2)
        finally:
            if old is None:
                del os.environ["RUNS"]
            else:
                os.environ["RUNS"] = old


class SelftestEndToEndTest(unittest.TestCase):
    def test_selftest_writes_report(self):
        with tempfile.TemporaryDirectory() as d:
            proc = subprocess.run(
                [sys.executable, os.path.join(HERE, "run.py"), "--tiers", "selftest",
                 "--runs", "3", "--run-dir", d, "--build", "auto"],
                capture_output=True, text=True, timeout=300)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            for f in ("report.json", "report.md", "fingerprint.json", "tier-status.json"):
                self.assertTrue(os.path.exists(os.path.join(d, f)), f)
            with open(os.path.join(d, "report.json")) as f:
                rep = json.load(f)
            self.assertTrue(rep["ok"])
            self.assertEqual(rep["errors"], [])
            names = {(r["tier"], r["name"]): r for r in rep["rows"]}
            self.assertEqual(names[("selftest", "sha256-1MiB")]["status"], "paired")
            self.assertEqual(names[("selftest", "sha256-1MiB")]["go"]["n"], 3)
            self.assertEqual(names[("selftest", "sha256-throughput")]["better"], "higher")
            self.assertEqual(names[("selftest", "unpaired-probe")]["status"], "unpaired")
            self.assertIn("cpu", rep["fingerprint"])
            with open(os.path.join(d, "report.md"), encoding="utf-8") as f:
                md = f.read()
            self.assertIn("sha256-1MiB", md)
            self.assertIn("Environment", md)

    def test_failing_tier_makes_run_fail_but_still_reports(self):
        with tempfile.TemporaryDirectory() as tiers, tempfile.TemporaryDirectory() as d:
            with open(os.path.join(tiers, "boom.py"), "w") as f:
                f.write("import sys\nsys.exit(3)\n")
            rc = run.main(["--tiers", "boom", "--runs", "1", "--run-dir", d,
                           "--build", "never", "--tiers-dir", tiers])
            self.assertEqual(rc, 1)
            with open(os.path.join(d, "tier-status.json")) as f:
                st = json.load(f)
            self.assertEqual(st[0]["exit_code"], 3)
            self.assertTrue(os.path.exists(os.path.join(d, "report.md")))


class PrebuiltBuildTest(unittest.TestCase):
    """--build prebuilt (issue #2109): binaries and build-info.json already
    exist in --bin-dir (made by build_both.sh), so the run neither compiles
    again nor skips the tiers that need a build."""

    def make_bin_dir(self, d, with_binary=True):
        bin_dir = os.path.join(d, "bin")
        os.makedirs(os.path.join(bin_dir, "rust"))
        if with_binary:
            with open(os.path.join(bin_dir, "rust", "algod-rust"), "w") as f:
                f.write("x")
        info = {"schema": "bench-build-info/v1", "expected_tag": "v1",
                "go_algorand": {"built": False},
                "algod_rust": {"built": True, "commit": "c" * 40, "describe": "c", "dirty": False,
                               "binaries": ["rust/algod-rust"], "sha256": {"rust/algod-rust": "0"}}}
        with open(os.path.join(bin_dir, "build-info.json"), "w") as f:
            json.dump(info, f)
        return bin_dir

    def make_tier(self, d):
        tiers = os.path.join(d, "tiers")
        os.makedirs(tiers)
        with open(os.path.join(tiers, "needs.py"), "w") as f:
            f.write("# bench-tier-needs: build\nimport os, sys\n"
                    "sys.exit(0 if os.path.exists(os.path.join(os.environ['BENCH_RUST_BIN_DIR'], "
                    "'algod-rust')) else 9)\n")
        return tiers

    def test_prebuilt_runs_a_build_tier_and_keeps_the_build_info(self):
        with tempfile.TemporaryDirectory() as d:
            bin_dir, tiers = self.make_bin_dir(d), self.make_tier(d)
            out = os.path.join(d, "out")
            rc = run.main(["--tiers", "needs", "--runs", "1", "--run-dir", out, "--build", "prebuilt",
                           "--bin-dir", bin_dir, "--tiers-dir", tiers])
            self.assertEqual(rc, 0)
            with open(os.path.join(out, "tier-status.json")) as f:
                st = json.load(f)
            self.assertEqual([(s["tier"], s["exit_code"]) for s in st], [("needs", 0)])
            with open(os.path.join(out, "build-info.json")) as f:
                self.assertEqual(json.load(f)["algod_rust"]["commit"], "c" * 40)
            self.assertFalse(os.path.exists(os.path.join(out, "logs", "build.log")))

    def test_prebuilt_without_build_info_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as d:
            tiers = self.make_tier(d)
            rc = run.main(["--tiers", "needs", "--runs", "1", "--run-dir", os.path.join(d, "o"),
                           "--build", "prebuilt", "--bin-dir", os.path.join(d, "nobin"),
                           "--tiers-dir", tiers])
            self.assertEqual(rc, 2)

    def test_prebuilt_with_a_missing_binary_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as d:
            bin_dir = self.make_bin_dir(d, with_binary=False)
            tiers = self.make_tier(d)
            rc = run.main(["--tiers", "needs", "--runs", "1", "--run-dir", os.path.join(d, "o"),
                           "--build", "prebuilt", "--bin-dir", bin_dir, "--tiers-dir", tiers])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
