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


def lines(*ls):
    return "\n".join(ls) + "\n"


class CheckTest(unittest.TestCase):
    def scan_src(self, src, name="a.rs"):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, name), "w") as f:
                f.write(src)
            return c.scan([d])

    def test_unannotated_cfg_macro_is_flagged(self):
        self.assertEqual(len(self.scan_src("fn f() { if cfg!(debug_assertions) {} }\n")), 1)

    def test_unannotated_attribute_is_flagged(self):
        self.assertEqual(len(self.scan_src("#[cfg(not(debug_assertions))]\nfn f() {}\n")), 1)

    def test_annotation_on_same_line_or_line_above_passes(self):
        self.assertEqual(self.scan_src("if cfg!(debug_assertions) {} // debug-assertions-ok: test\n"), [])
        self.assertEqual(self.scan_src(lines("// debug-assertions-ok: both tested", "if cfg!(debug_assertions) {}")), [])

    def test_debug_assert_macro_and_comments_are_not_flagged(self):
        self.assertEqual(self.scan_src("fn f() { debug_assert!(true); }\n// mentions debug_assertions\n"), [])

    def test_marker_in_multi_line_comment_block_above_passes(self):
        src = lines("// debug-assertions-ok: x", "// more detail", "if cfg!(debug_assertions) {}")
        self.assertEqual(self.scan_src(src), [])

    def test_annotation_separated_by_a_blank_line_does_not_count(self):
        src = lines("// debug-assertions-ok: x", "", "if cfg!(debug_assertions) {}")
        self.assertEqual(len(self.scan_src(src)), 1)

    def test_marker_without_reason_does_not_count(self):
        self.assertEqual(len(self.scan_src(lines("// debug-assertions-ok:", "if cfg!(debug_assertions) {}"))), 1)

    def test_marker_inside_a_string_does_not_count(self):
        src = 'let s = "// debug-assertions-ok: x"; if cfg!(debug_assertions) {}\n'
        self.assertEqual(len(self.scan_src(src)), 1)

    def test_slashes_inside_a_string_do_not_hide_a_cfg(self):
        self.assertEqual(len(self.scan_src('let u = "http://x"; if cfg!(debug_assertions) {}\n')), 1)

    def test_rustfmt_wrapped_attribute_uses_the_note_above_its_start(self):
        src = lines("// debug-assertions-ok: x", "#[cfg(any(", "    debug_assertions,", "    test", "))]", "fn f() {}")
        self.assertEqual(self.scan_src(src), [])
        self.assertEqual(len(self.scan_src(lines("#[cfg(any(", "    debug_assertions,", "    test", "))]"))), 1)

    def test_attribute_between_note_and_cfg_is_allowed(self):
        src = lines("// debug-assertions-ok: x", "#[test]", "#[cfg(debug_assertions)]", "fn f() {}")
        self.assertEqual(self.scan_src(src), [])

    def test_single_line_block_comment_mention_is_not_flagged(self):
        self.assertEqual(self.scan_src(lines("let a = 1; /* debug_assertions */")), [])

    def test_rustflags_and_inline_table_overrides_are_flagged(self):
        flags = lines('rustflags = ["-C debug-assertions=on"]')
        self.assertEqual(len(self.scan_src(flags, "config.toml")), 1)
        inline = lines("profile.release = { debug-assertions = true }")
        self.assertEqual(len(self.scan_src(inline, "Cargo.toml")), 1)
        self.assertEqual(len(self.scan_src(lines("env:", "  RUSTFLAGS: -Cdebug-assertions=off"), "w.yml")), 1)

    def test_cargo_profile_override_needs_a_note(self):
        toml = lines("[profile.release]", "debug-assertions = true")
        self.assertEqual(len(self.scan_src(toml, "Cargo.toml")), 1)
        ok = lines("[profile.release]", "# debug-assertions-ok: tests pass in both", "overflow-checks = true")
        self.assertEqual(self.scan_src(ok, "Cargo.toml"), [])


if __name__ == "__main__":
    unittest.main()
