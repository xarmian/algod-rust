#!/usr/bin/env python3

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for issue #1598's `file_issue.py` (dedup + templating).

`gh` calls are mocked throughout (`unittest.mock.patch` on
`subprocess.run`) -- these tests never touch the real tracker, matching
`--dry-run`'s own no-network guarantee for the workflow's own dry-run
path (case (f) in `monitor_test.py`'s docstring: dedup against an
existing open issue picks the comment path, not create).
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import file_issue  # noqa: E402

TEMPLATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "issue_template.md")

STUCK_VERDICT = {
    "status": "stuck",
    "phase": "follow",
    "round": 50_123_456,
    "message": "node made no progress for 400s during follow while the peer kept advancing",
    "stalled_since_s": 400.0,
    "node_last_round": 50_123_456,
    "node_time_since_last_round": 400_000_000_000,
    "peer_last_round": 50_123_460,
}


class RenderTemplateTest(unittest.TestCase):
    def test_renders_real_template_with_all_fields_substituted(self):
        fields = file_issue.build_fields(
            STUCK_VERDICT, "https://example/run/1", "https://example/artifacts/1", "some log", "https://peer"
        )
        body = file_issue.render_template(TEMPLATE_PATH, fields)
        self.assertIn("50123456", body.replace(",", ""))
        self.assertIn("mainnet-soak:round=50123456", body)
        self.assertIn("https://example/run/1", body)
        self.assertNotIn("{round}", body)
        self.assertNotIn("{phase}", body)

    def test_missing_field_degrades_to_literal_placeholder_not_a_crash(self):
        # build_fields always supplies every placeholder the real template
        # uses, but render_template itself must not crash on a template
        # with an extra unknown field (defensive: a future template edit
        # that adds a field shouldn't hard-crash the filer).
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.md")
            with open(p, "w") as f:
                f.write("round {round}, mystery {totally_unknown_field}")
            out = file_issue.render_template(p, {"round": 5})
            self.assertIn("round 5", out)
            self.assertIn("{totally_unknown_field}", out)


class IssueTitleTest(unittest.TestCase):
    def test_title_includes_round(self):
        title = file_issue.issue_title(50_123_456)
        self.assertIn("50123456", title.replace(",", ""))
        self.assertIn("halted at round", title)

    def test_title_handles_unknown_round(self):
        title = file_issue.issue_title(None)
        self.assertIn("unknown", title)


class FindExistingIssueTest(unittest.TestCase):
    @patch("file_issue.subprocess.run")
    def test_returns_none_when_no_round(self, mock_run):
        self.assertIsNone(file_issue.find_existing_issue("owner/repo", None))
        mock_run.assert_not_called()

    @patch("file_issue.subprocess.run")
    def test_matches_issue_with_marker_in_body(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "number": 42,
                        "url": "https://github.com/owner/repo/issues/42",
                        "title": "sync: mainnet participation node halted at round 50123456",
                        "body": "<!-- mainnet-soak:round=50123456 -->\nsome body",
                    }
                ]
            ),
            stderr="",
        )
        found = file_issue.find_existing_issue("owner/repo", 50_123_456)
        self.assertEqual(found, {"number": 42, "url": "https://github.com/owner/repo/issues/42"})

    @patch("file_issue.subprocess.run")
    def test_no_match_when_marker_absent(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                [{"number": 7, "url": "https://x/7", "title": "unrelated", "body": "no marker here"}]
            ),
            stderr="",
        )
        self.assertIsNone(file_issue.find_existing_issue("owner/repo", 50_123_456))

    @patch("file_issue.subprocess.run")
    def test_gh_failure_returns_none_not_raise(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not authenticated")
        self.assertIsNone(file_issue.find_existing_issue("owner/repo", 1))


class FileOrCommentTest(unittest.TestCase):
    """Case (f): dedup against an existing open issue for the round picks
    the comment path, never creates a duplicate."""

    @patch("file_issue.subprocess.run")
    def test_dedup_comments_instead_of_creating(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                [
                    {
                        "number": 42,
                        "url": "https://github.com/owner/repo/issues/42",
                        "title": "...",
                        "body": "<!-- mainnet-soak:round=50123456 -->",
                    }
                ]
            ),
            stderr="",
        )
        result = file_issue.file_or_comment(
            repo="owner/repo",
            template_path=TEMPLATE_PATH,
            verdict=STUCK_VERDICT,
            run_url="https://run",
            artifacts_url="https://artifacts",
            log_excerpt="",
            peer_url="https://peer",
            dry_run=False,
        )
        self.assertEqual(result["action"], "commented")
        self.assertEqual(result["number"], 42)
        # First call was the dedup search (issue list), second the comment --
        # `gh issue create` must never be invoked in this path.
        calls = [c.args[0] for c in mock_run.call_args_list]
        self.assertTrue(any(c[:2] == ["gh", "issue"] and "comment" in c for c in calls))
        self.assertFalse(any("create" in c for c in calls))

    @patch("file_issue.subprocess.run")
    def test_no_existing_issue_creates_a_new_one(self, mock_run):
        def side_effect(args, **kwargs):
            if "list" in args:
                return MagicMock(returncode=0, stdout="[]", stderr="")
            return MagicMock(
                returncode=0, stdout="https://github.com/owner/repo/issues/99\n", stderr=""
            )

        mock_run.side_effect = side_effect
        result = file_issue.file_or_comment(
            repo="owner/repo",
            template_path=TEMPLATE_PATH,
            verdict=STUCK_VERDICT,
            run_url="https://run",
            artifacts_url="https://artifacts",
            log_excerpt="panic: boom",
            peer_url="https://peer",
            dry_run=False,
        )
        self.assertEqual(result["action"], "created")
        self.assertEqual(result["number"], 99)

    @patch("file_issue.subprocess.run")
    def test_dry_run_never_calls_gh_create_or_comment(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
        result = file_issue.file_or_comment(
            repo="owner/repo",
            template_path=TEMPLATE_PATH,
            verdict=STUCK_VERDICT,
            run_url="https://run",
            artifacts_url="https://artifacts",
            log_excerpt="",
            peer_url="https://peer",
            dry_run=True,
        )
        self.assertEqual(result["action"], "dry_run_create")
        # Only the dedup search (list) ran -- no create/comment call.
        calls = [c.args[0] for c in mock_run.call_args_list]
        self.assertEqual(len(calls), 1)
        self.assertIn("list", calls[0])

    @patch("file_issue.subprocess.run")
    def test_dry_run_with_existing_issue_reports_comment_would_happen(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                [{"number": 5, "url": "https://x/5", "title": "...", "body": "<!-- mainnet-soak:round=50123456 -->"}]
            ),
            stderr="",
        )
        result = file_issue.file_or_comment(
            repo="owner/repo",
            template_path=TEMPLATE_PATH,
            verdict=STUCK_VERDICT,
            run_url="https://run",
            artifacts_url="https://artifacts",
            log_excerpt="",
            peer_url="https://peer",
            dry_run=True,
        )
        self.assertEqual(result["action"], "dry_run_comment")
        self.assertEqual(result["number"], 5)


class NetworkScopedFilingTest(unittest.TestCase):
    """Issue #2071: a non-mainnet soak must never dedup against, nor be
    titled/labelled/templated as, a mainnet one."""

    def test_title_names_the_network(self):
        title = file_issue.issue_title(77, "voimain")
        self.assertIn("voimain participation node halted at round 77", title)
        self.assertIn("nightly voimain soak", title)
        self.assertNotIn("mainnet", title)

    def test_default_network_title_is_the_unchanged_mainnet_title(self):
        self.assertEqual(file_issue.issue_title(5), file_issue.issue_title(5, "mainnet"))
        self.assertIn("mainnet participation node halted at round 5", file_issue.issue_title(5))

    def test_labels_and_dedup_label_are_network_scoped(self):
        self.assertEqual(file_issue.dedup_label("voimain"), "voimain-soak")
        self.assertIn("voimain-soak", file_issue.issue_labels("voimain"))
        self.assertNotIn("mainnet-soak", file_issue.issue_labels("voimain"))
        # mainnet keeps its historical label set byte-for-byte
        self.assertEqual(file_issue.issue_labels("mainnet"), file_issue.ISSUE_LABELS)
        self.assertEqual(file_issue.dedup_label("mainnet"), "mainnet-soak")

    def test_template_marker_and_text_are_network_scoped(self):
        fields = file_issue.build_fields(STUCK_VERDICT, "r", "a", "log", "https://peer", network="aramidmain")
        body = file_issue.render_template(TEMPLATE_PATH, fields)
        self.assertIn("<!-- aramidmain-soak:round=50123456 -->", body)
        self.assertIn("participate --network aramidmain", body)
        self.assertIn("replay --network aramidmain", body)
        self.assertNotIn("mainnet", body)

    def test_mainnet_body_is_unchanged_by_parameterisation(self):
        fields = file_issue.build_fields(STUCK_VERDICT, "r", "a", "log", "https://peer")
        body = file_issue.render_template(TEMPLATE_PATH, fields)
        self.assertTrue(body.startswith("<!-- mainnet-soak:round=50123456 -->"))
        self.assertIn("`.github/workflows/mainnet-node-soak.yml`", body)
        self.assertIn("participate --network mainnet`", body)

    @patch("file_issue.subprocess.run")
    def test_voimain_halt_does_not_dedup_against_mainnet_issue(self, mock_run):
        # Same round number, the open issue carries the *mainnet* marker.
        mainnet_issue = {
            "number": 10,
            "url": "https://x/10",
            "title": "t",
            "body": "<!-- mainnet-soak:round=50123456 -->",
        }

        def side_effect(args, **kwargs):
            if "list" in args:
                # honour the --label filter like gh does
                label = args[args.index("--label") + 1]
                issues = [mainnet_issue] if label == "mainnet-soak" else []
                return MagicMock(returncode=0, stdout=json.dumps(issues), stderr="")
            return MagicMock(returncode=0, stdout="https://github.com/owner/repo/issues/11\n", stderr="")

        mock_run.side_effect = side_effect
        result = file_issue.file_or_comment(
            repo="owner/repo",
            template_path=TEMPLATE_PATH,
            verdict=STUCK_VERDICT,
            run_url="r",
            artifacts_url="a",
            log_excerpt="",
            peer_url="p",
            dry_run=False,
            network="voimain",
        )
        self.assertEqual(result["action"], "created")
        create = [c.args[0] for c in mock_run.call_args_list if "create" in c.args[0] and "issue" in c.args[0]]
        self.assertEqual(len(create), 1)
        self.assertIn("voimain-soak", create[0])
        self.assertNotIn("mainnet-soak", create[0])

    @patch("file_issue.subprocess.run")
    def test_marker_match_ignores_other_networks_even_if_label_filter_leaks(self, mock_run):
        # Even if the label filter returned a foreign issue, the marker
        # regex must not match (and "net-soak" must not match inside
        # "mainnet-soak").
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps([{"number": 3, "url": "u", "title": "t", "body": "<!-- mainnet-soak:round=9 -->"}]),
            stderr="",
        )
        self.assertIsNone(file_issue.find_existing_issue("o/r", 9, "voimain"))
        self.assertIsNone(file_issue.find_existing_issue("o/r", 9, "net"))
        self.assertEqual(file_issue.find_existing_issue("o/r", 9, "mainnet")["number"], 3)

    @patch("file_issue.subprocess.run")
    def test_main_accepts_network_flag(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "v.json")
            with open(p, "w") as f:
                json.dump(STUCK_VERDICT, f)
            rc = file_issue.main(
                ["--repo", "o/r", "--verdict-json", p, "--template", TEMPLATE_PATH,
                 "--run-url", "r", "--artifacts-url", "a", "--network", "voimain", "--dry-run"]
            )
        self.assertEqual(rc, 0)
        list_call = mock_run.call_args_list[0].args[0]
        self.assertEqual(list_call[list_call.index("--label") + 1], "voimain-soak")


class MainSkipsNonHaltVerdictsTest(unittest.TestCase):
    def test_ok_verdict_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as d:
            verdict_path = os.path.join(d, "verdict.json")
            with open(verdict_path, "w") as f:
                json.dump({"status": "ok"}, f)
            rc = file_issue.main(
                [
                    "--repo",
                    "owner/repo",
                    "--verdict-json",
                    verdict_path,
                    "--template",
                    TEMPLATE_PATH,
                    "--run-url",
                    "https://run",
                    "--artifacts-url",
                    "https://artifacts",
                    "--dry-run",
                ]
            )
            self.assertEqual(rc, 0)

    def test_source_outage_verdict_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as d:
            verdict_path = os.path.join(d, "verdict.json")
            with open(verdict_path, "w") as f:
                json.dump({"status": "source_outage"}, f)
            rc = file_issue.main(
                [
                    "--repo",
                    "owner/repo",
                    "--verdict-json",
                    verdict_path,
                    "--template",
                    TEMPLATE_PATH,
                    "--run-url",
                    "https://run",
                    "--artifacts-url",
                    "https://artifacts",
                    "--dry-run",
                ]
            )
            self.assertEqual(rc, 0)


class MainFilesInvalidBlockStallTest(unittest.TestCase):
    """PR #1762 review: an invalid_block_stall verdict (exit 1) must file."""

    def test_invalid_block_stall_verdict_files_through_main(self):
        import contextlib
        import io

        verdict = {
            "status": "invalid_block_stall",
            "phase": "follow",
            "round": 65_668_288,
            "message": "node stalled on invalid block 65668288",
            "stalled_since_s": 0.0,
            "invalid_block_stall": {
                "round": 65_668_288,
                "error": "boom",
                "consecutive_failures": 4,
                "since_unix_secs": 1,
            },
        }
        with tempfile.TemporaryDirectory() as d:
            verdict_path = os.path.join(d, "verdict.json")
            with open(verdict_path, "w") as f:
                json.dump(verdict, f)
            out = io.StringIO()
            with patch("file_issue.subprocess.run") as run, contextlib.redirect_stdout(out):
                run.return_value = MagicMock(returncode=0, stdout="[]", stderr="")
                rc = file_issue.main(
                    [
                        "--repo", "owner/repo",
                        "--verdict-json", verdict_path,
                        "--template", TEMPLATE_PATH,
                        "--run-url", "https://run",
                        "--artifacts-url", "https://artifacts",
                        "--dry-run",
                    ]
                )
        self.assertEqual(rc, 0)
        self.assertIn("would CREATE issue", out.getvalue())
        self.assertIn("round: 65668288", out.getvalue().replace(",", ""))


if __name__ == "__main__":
    unittest.main()
