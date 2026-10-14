#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests for check_divergences.py (issue #1927, epic #1926)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_divergences as c  # noqa: E402

REGISTER_HEAD = """# Intended divergences from go-algorand

| ID | Title | Area | Status | Since |
|---|---|---|---|---|
"""


def register(rows, sections=None):
    """Build a register document from (id, status) rows; every row gets a
    `### DIV-NNN` section unless `sections` lists the ids that should."""
    text = REGISTER_HEAD
    for did, status in rows:
        text += "| {} | t | crypto | {} | 2026-10-14 |\n".format(did, status)
    text += "\n## Entries\n\n"
    for did, _ in rows:
        if sections is None or did in sections:
            text += "### {} - title\n\nbody\n\n".format(did)
    return text


class Repo:
    """A throwaway tree with a register and some source files."""

    def __init__(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = self.dir.name
        os.makedirs(os.path.join(self.root, "docs"))

    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def check(self):
        return c.check(self.root, os.path.join(self.root, "docs", "DIVERGENCES.md"))

    def close(self):
        self.dir.cleanup()


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()
        self.addCleanup(self.repo.close)

    def test_marker_and_landed_row_pair_is_clean(self):
        self.repo.write("docs/DIVERGENCES.md", register([("DIV-001", "landed")]))
        self.repo.write("crates/x/src/lib.rs", "// DIVERGENCE DIV-001: rust falcon\nfn f() {}\n")
        self.assertEqual(self.repo.check(), [])

    def test_marker_without_register_row_fails(self):
        self.repo.write("docs/DIVERGENCES.md", register([("DIV-001", "landed")]))
        self.repo.write("crates/x/src/lib.rs", "// DIVERGENCE DIV-001: a\n// DIVERGENCE DIV-999: b\n")
        problems = self.repo.check()
        self.assertTrue(any("DIV-999" in p and "not in the register" in p for p in problems), problems)

    def test_landed_row_without_marker_fails(self):
        self.repo.write("docs/DIVERGENCES.md", register([("DIV-001", "landed")]))
        self.repo.write("crates/x/src/lib.rs", "fn f() {}\n")
        problems = self.repo.check()
        self.assertTrue(any("DIV-001" in p and "no source marker" in p for p in problems), problems)

    def test_reserved_row_needs_no_marker(self):
        self.repo.write("docs/DIVERGENCES.md", register([("DIV-001", "reserved")]))
        self.repo.write("crates/x/src/lib.rs", "fn f() {}\n")
        self.assertEqual(self.repo.check(), [])

    def test_row_without_section_fails_and_vice_versa(self):
        self.repo.write("docs/DIVERGENCES.md", register([("DIV-001", "landed")], sections=[]))
        self.repo.write("crates/x/src/lib.rs", "// DIVERGENCE DIV-001: a\n")
        problems = self.repo.check()
        self.assertTrue(any("DIV-001" in p and "section" in p for p in problems), problems)
        orphan = register([("DIV-001", "landed")]) + "### DIV-002 - orphan\n\nbody\n"
        self.repo.write("docs/DIVERGENCES.md", orphan)
        problems = self.repo.check()
        self.assertTrue(any("DIV-002" in p and "table row" in p for p in problems), problems)

    def test_ids_must_be_sequential_from_001(self):
        self.repo.write("docs/DIVERGENCES.md", register([("DIV-001", "landed"), ("DIV-003", "landed")]))
        self.repo.write("crates/x/src/lib.rs", "// DIVERGENCE DIV-001: a\n// DIVERGENCE DIV-003: b\n")
        problems = self.repo.check()
        self.assertTrue(any("sequential" in p for p in problems), problems)

    def test_unknown_status_fails(self):
        self.repo.write("docs/DIVERGENCES.md", register([("DIV-001", "done")]))
        self.repo.write("crates/x/src/lib.rs", "// DIVERGENCE DIV-001: a\n")
        problems = self.repo.check()
        self.assertTrue(any("status" in p for p in problems), problems)

    def test_markers_in_any_comment_style_and_language_are_found(self):
        self.repo.write("docs/DIVERGENCES.md", register([("DIV-001", "landed"), ("DIV-002", "landed"), ("DIV-003", "landed")]))
        self.repo.write("tools/t/main.go", "// DIVERGENCE DIV-001: go\n")
        self.repo.write("scripts/s.py", "# DIVERGENCE DIV-002: py\n")
        self.repo.write("crates/x/src/lib.rs", "/// DIVERGENCE DIV-003: doc comment\n")
        self.assertEqual(self.repo.check(), [])

    def test_skipped_directories_and_register_itself_are_not_scanned(self):
        self.repo.write("docs/DIVERGENCES.md", register([("DIV-001", "landed")]))
        self.repo.write("crates/x/src/lib.rs", "// DIVERGENCE DIV-001: a\n")
        self.repo.write("target/debug/x.rs", "// DIVERGENCE DIV-777: stale build output\n")
        self.repo.write("crates/core/algo-falcon/falcon-c/x.c", "// DIVERGENCE DIV-888: vendored\n")
        self.assertEqual(self.repo.check(), [])

    def test_marker_must_have_a_description(self):
        self.repo.write("docs/DIVERGENCES.md", register([("DIV-001", "landed")]))
        self.repo.write("crates/x/src/lib.rs", "// DIVERGENCE DIV-001:\n")
        problems = self.repo.check()
        self.assertTrue(any("description" in p for p in problems), problems)

    def test_missing_register_is_reported(self):
        self.repo.write("crates/x/src/lib.rs", "// DIVERGENCE DIV-001: a\n")
        problems = self.repo.check()
        self.assertTrue(any("DIVERGENCES.md" in p for p in problems), problems)

    def test_real_repo_is_clean(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.assertEqual(c.check(here, os.path.join(here, "docs", "DIVERGENCES.md")), [])


if __name__ == "__main__":
    unittest.main()
