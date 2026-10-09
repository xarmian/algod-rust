#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for rust_config_merge.py (issue #1777).  No Docker.

    python3 ops/mixed-cluster/scripts/rust_config_merge_test.py
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rust_config_merge import main, merge  # noqa: E402


class Merge(unittest.TestCase):
    def test_sets_and_preserves_other_keys(self):
        self.assertEqual(
            merge({"EnableLedgerService": True}, True),
            {"EnableLedgerService": True, "Archival": True},
        )

    def test_clears_a_stale_value(self):
        self.assertEqual(merge({"Archival": True, "X": 1}, False), {"X": 1})

    def test_idempotent(self):
        self.assertEqual(merge(merge({}, True), True), {"Archival": True})


class Cli(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "config.json")

    def read(self):
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def test_reuse_netroot_stale_true_is_cleared_when_not_archival(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"Archival": True, "CatchpointInterval": 4}, f)
        self.assertEqual(main(["x", self.path, "0"]), 0)
        self.assertEqual(self.read(), {"CatchpointInterval": 4})

    def test_creates_file_when_archival(self):
        self.assertEqual(main(["x", self.path, "1"]), 0)
        self.assertEqual(self.read(), {"Archival": True})

    def test_no_file_created_when_not_archival(self):
        self.assertEqual(main(["x", self.path, "0"]), 0)
        self.assertFalse(os.path.exists(self.path))

    def test_empty_file_is_treated_as_empty_object(self):
        open(self.path, "w").close()
        self.assertEqual(main(["x", self.path, "1"]), 0)
        self.assertEqual(self.read(), {"Archival": True})

    def test_stdin_filter_mode(self):
        import subprocess
        here = os.path.dirname(os.path.abspath(__file__))
        out = subprocess.run(
            [sys.executable, os.path.join(here, "rust_config_merge.py"), "-", "0"],
            input='{"Archival": true, "A": 1}', capture_output=True, text=True,
        )
        self.assertEqual(json.loads(out.stdout), {"A": 1})

    def test_bad_args(self):
        self.assertEqual(main(["x", self.path, "2"]), 2)


if __name__ == "__main__":
    unittest.main()
