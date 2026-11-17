#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for scripts/teal-corpus/tracking_issue.py (issue #2372) with a fake `gh`:
one issue is opened on the first failure, later failures comment on it, the first
green run comments and closes it, a green run with no open issue does nothing.
Run: python3 -I scripts/teal-corpus/test_tracking_issue.py"""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("teal_corpus_tracking", os.path.join(HERE, "tracking_issue.py"))
ti = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ti)


class FakeGh:
    def __init__(self, open_issues):
        self.open_issues = open_issues
        self.calls = []

    def __call__(self, cmd, capture_output=True, text=True):
        self.calls.append(cmd[1:])
        out = ""
        if cmd[1:3] == ["issue", "list"]:
            out = json.dumps(self.open_issues)
        elif cmd[1:3] == ["issue", "create"]:
            out = "https://github.com/o/r/issues/99\n"
        return subprocess.CompletedProcess(cmd, 0, out, "")

    def verbs(self):
        return [c[1] for c in self.calls]


class Tracking(unittest.TestCase):
    def test_first_failure_creates_one_labelled_issue(self):
        gh = FakeGh([])
        self.assertEqual(ti.on_failure("o/r", "body", "https://run/1", run=gh), ("created", "https://github.com/o/r/issues/99"))
        create = [c for c in gh.calls if c[1] == "create"][0]
        labels = [create[i + 1] for i, x in enumerate(create) if x == "--label"]
        self.assertIn("conformance", labels)
        self.assertIn("avm", labels)
        self.assertEqual(create[create.index("--title") + 1], ti.TITLE)

    def test_later_failure_comments_instead_of_creating(self):
        gh = FakeGh([{"number": 7, "title": ti.TITLE}])
        self.assertEqual(ti.on_failure("o/r", "body", "https://run/2", run=gh), ("commented", 7))
        self.assertEqual(gh.verbs(), ["list", "comment"])

    def test_other_issues_with_a_similar_title_are_not_matched(self):
        gh = FakeGh([{"number": 3, "title": ti.TITLE + " (old)"}])
        self.assertEqual(ti.on_failure("o/r", "b", "u", run=gh)[0], "created")

    def test_green_closes_the_open_issue(self):
        gh = FakeGh([{"number": 7, "title": ti.TITLE}])
        self.assertEqual(ti.on_green("o/r", "https://run/3", run=gh), ("closed", 7))
        self.assertEqual(gh.verbs(), ["list", "comment", "close"])

    def test_green_without_an_open_issue_does_nothing(self):
        gh = FakeGh([])
        self.assertEqual(ti.on_green("o/r", "u", run=gh), ("none", None))
        self.assertEqual(gh.verbs(), ["list"])

    def test_dry_run_never_writes(self):
        gh = FakeGh([{"number": 7, "title": ti.TITLE}])
        ti.on_failure("o/r", "b", "u", dry_run=True, run=gh)
        ti.on_green("o/r", "u", dry_run=True, run=gh)
        self.assertEqual(set(gh.verbs()), {"list"})

    def test_cli_dry_run(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "body.md")
        with open(p, "w") as f:
            f.write("x")
        gh = FakeGh([])
        self.assertEqual(ti.main(["fail", "--repo", "o/r", "--body-file", p, "--run-url", "u", "--dry-run"], run=gh), 0)
        self.assertEqual(ti.main(["fail", "--repo", "o/r", "--body-file", p + "x", "--run-url", "u"], run=gh), 2)


if __name__ == "__main__":
    unittest.main()
