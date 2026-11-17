#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Structural tests of .github/workflows/teal-corpus-parity.yml (issue #2372):
the triggers, the go-algorand build through `make libsodium`, and above all that
no gate is soft (`continue-on-error` is allowed only on the informational steps).
Text based on purpose: no YAML dependency.
Run: python3 -I scripts/teal-corpus/test_workflow.py"""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(HERE, "..", "..", ".github", "workflows", "teal-corpus-parity.yml")

# Steps that may be soft: the benchmark is informational by design and the
# Docker Hub login only avoids a pull rate limit.
SOFT_STEPS = {"Benchmark tier (informational)", "Log in to Docker Hub (avoid the unauthenticated pull rate limit)"}


def load():
    with open(WORKFLOW, encoding="utf-8") as f:
        return f.read()


def steps(text):
    """[(name, block)] of the job's steps."""
    blocks = re.split(r"\n      - name: ", text)[1:]
    return [(b.split("\n", 1)[0].strip(), b) for b in blocks]


class Workflow(unittest.TestCase):
    def setUp(self):
        self.text = load()
        self.steps = steps(self.text)

    def test_triggers(self):
        self.assertRegex(self.text, r"(?m)^  schedule:\n    - cron:")
        self.assertRegex(self.text, r"(?m)^  workflow_dispatch:")
        for inp in ("registry_ref", "go_ref", "rest_sample_size"):
            self.assertIn("      " + inp + ":", self.text)
        pr = self.text.split("  pull_request:\n", 1)[1].split("\nconcurrency:", 1)[0]
        for path in ("tools/teal-corpus/**", "crates/tools/teal-corpus/**", "scripts/teal-corpus/**",
                     "crates/core/algo-avm/src/assembler.rs", "crates/core/algo-avm/src/disassembler.rs",
                     "crates/core/algo-avm/src/sourcemap.rs"):
            self.assertIn(f'"{path}"', pr)

    def test_pull_requests_use_a_pinned_registry_sha(self):
        self.assertRegex(self.text, r'PR_REGISTRY_SHA: "[0-9a-f]{40}"')
        self.assertIn('pull_request) REF="$PR_REGISTRY_SHA"', self.text)

    def test_go_algorand_is_built_through_make_libsodium_at_the_pin(self):
        self.assertRegex(self.text, r'GO_ALGORAND_REV: "v\d+\.\d+\.\d+-stable"')
        self.assertIn('libsodium', self.text)
        self.assertRegex(self.text, r"make -C \"\$GO_ALGORAND_DIR\" libsodium")
        self.assertIn("make teal-corpus-parity", self.text)  # builds the driver via tools/teal-corpus/build.sh
        self.assertNotRegex(self.text, r"go build ")

    def test_no_gate_is_soft(self):
        for name, block in self.steps:
            if "continue-on-error" in block:
                self.assertIn(name, SOFT_STEPS, f"step {name!r} must not be continue-on-error")
        self.assertNotIn("|| true", "\n".join(b for n, b in self.steps if "Verdict" in n or "parity stages" in n))

    def test_gates_are_present_and_ordered(self):
        names = [n for n, _ in self.steps]
        order = ["Extraction sanity gate", "Offline parity stages (go driver vs rust driver)",
                 "Statistics (stats.json)", "Verdict (zero mismatches, panics, timeouts; nothing empty)"]
        idx = [next(i for i, n in enumerate(names) if n == o) for o in order]
        self.assertEqual(idx, sorted(idx))
        verdict = dict(self.steps)[order[-1]]
        self.assertIn("gate.py verdict", verdict)
        self.assertIn("gate.py extraction", verdict)

    def test_artifacts_summary_history_and_tracking_issue(self):
        for needle in ("stats.json", "*.mismatches.jsonl", "teal-corpus-work/repro/", "$GITHUB_STEP_SUMMARY",
                       "stats.py history", "tracking_issue.py fail", "tracking_issue.py green", "issues: write"):
            self.assertIn(needle, self.text)
        # the tracking issue is a scheduled/dispatch-on-main concern, never a PR's
        self.assertEqual(self.text.count("github.event_name != 'pull_request' && github.ref == 'refs/heads/main'"), 2)

    def test_license_header(self):
        self.assertTrue(self.text.startswith("# Copyright (c) 2026 Algod DAO\n# SPDX-License-Identifier: MIT\n"))


if __name__ == "__main__":
    unittest.main()
