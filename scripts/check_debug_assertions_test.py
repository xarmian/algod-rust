#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests for check_debug_assertions.py (issue #1787)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_debug_assertions as c  # noqa: E402


class CheckTest(unittest.TestCase):
    def scan_src(self, src):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.rs"), "w") as f:
                f.write(src)
            return c.scan([d])

    def test_unannotated_cfg_macro_is_flagged(self):
        self.assertEqual(len(self.scan_src("fn f() { if cfg!(debug_assertions) {} }\n")), 1)

    def test_unannotated_attribute_is_flagged(self):
        self.assertEqual(len(self.scan_src("#[cfg(not(debug_assertions))]\nfn f() {}\n")), 1)

    def test_annotation_on_same_line_or_line_above_passes(self):
        self.assertEqual(self.scan_src("if cfg!(debug_assertions) {} // debug-assertions-ok: test\n"), [])
        self.assertEqual(self.scan_src("// debug-assertions-ok: both profiles tested\nif cfg!(debug_assertions) {}\n"), [])

    def test_debug_assert_macro_and_comments_are_not_flagged(self):
        self.assertEqual(self.scan_src("fn f() { debug_assert!(true); }\n// mentions debug_assertions\n"), [])

    def test_marker_in_multi_line_comment_block_above_passes(self):
        src = "\n".join(
            ["// debug-assertions-ok: x", "// more detail", "if cfg!(debug_assertions) {}", ""])
        self.assertEqual(self.scan_src(src), [])

    def test_annotation_separated_by_a_blank_line_does_not_count(self):
        src = "// debug-assertions-ok: x\n\nif cfg!(debug_assertions) {}\n"
        self.assertEqual(len(self.scan_src(src)), 1)

    def test_repository_is_clean(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cwd = os.getcwd()
        os.chdir(root)
        try:
            self.assertEqual(c.main(["x"]), 0)
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
