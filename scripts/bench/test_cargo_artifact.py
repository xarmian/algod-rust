#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for cargo_artifact.py (issue #2102): build_both.sh must take the
algod-rust binary path from cargo's own JSON messages, so CARGO_TARGET_DIR /
build.target-dir / --target are honoured."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cargo_artifact  # noqa: E402


def msg(name, kind, executable, reason="compiler-artifact"):
    return json.dumps({"reason": reason, "target": {"name": name, "kind": kind},
                       "executable": executable, "filenames": []})


class CargoArtifactTest(unittest.TestCase):
    def test_picks_bin_executable_from_custom_target_dir(self):
        stream = "\n".join([
            msg("algo-types", ["lib"], None),
            json.dumps({"reason": "build-script-executed", "package_id": "x"}),
            msg("algod-rust", ["bin"], "/custom/tgt/release/algod-rust"),
            json.dumps({"reason": "build-finished", "success": True}),
        ])
        self.assertEqual(cargo_artifact.find_executable(io.StringIO(stream), "algod-rust"),
                         "/custom/tgt/release/algod-rust")

    def test_windows_exe_path(self):
        stream = msg("algod-rust", ["bin"], "C:\\t\\release\\algod-rust.exe")
        self.assertEqual(cargo_artifact.find_executable(io.StringIO(stream), "algod-rust"),
                         "C:\\t\\release\\algod-rust.exe")

    def test_ignores_non_json_and_other_bins(self):
        stream = "\n".join(["warning: not json", msg("goal-rust", ["bin"], "/t/goal-rust"),
                            msg("algod-rust", ["lib"], None)])
        self.assertIsNone(cargo_artifact.find_executable(io.StringIO(stream), "algod-rust"))

    def test_main_exit_status(self):
        old_in, old_out = sys.stdin, sys.stdout
        try:
            sys.stdin = io.StringIO(msg("algod-rust", ["bin"], "/t/algod-rust"))
            sys.stdout = io.StringIO()
            self.assertEqual(cargo_artifact.main(["algod-rust"]), 0)
            self.assertEqual(sys.stdout.getvalue().strip(), "/t/algod-rust")
            sys.stdin = io.StringIO("")
            self.assertEqual(cargo_artifact.main(["algod-rust"]), 1)
        finally:
            sys.stdin, sys.stdout = old_in, old_out


if __name__ == "__main__":
    unittest.main()
