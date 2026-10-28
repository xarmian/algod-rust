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


if __name__ == "__main__":
    unittest.main()
