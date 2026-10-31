#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Workflow-interface tests for .github/workflows/bench-compare.yml (issue #2109).

Proves, without a live run, that the workflow
  * is scheduled / dispatched and is not a PR check (the only pull_request
    trigger is a path filter on its own tooling),
  * declares every input it reads, uses every input it declares, and its tier
    list matches the tiers in scripts/bench/tiers,
  * builds go-algorand with the libsodium step and runs `make bench-compare`
    for every tier and for the testnet-prefix50 corpus,
  * lets an equality-gate failure fail the job (no continue-on-error on the
    bench steps; the dry-run input drives BENCH_REPLAY_CORRUPT),
  * only warns on regressions unless fail_on_regression is set, against
    baseline sections that exist in benchmarks/baseline.json,
  * uploads the run directories and the reports (artifact + job summary),
and exercises the input-validation shell step of the workflow with bash.

Run: python3 scripts/bench/test_bench_compare_workflow.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WF = os.path.join(ROOT, ".github", "workflows", "bench-compare.yml")
BASELINE = os.path.join(ROOT, "benchmarks", "baseline.json")
RESULTS_DOC = os.path.join(ROOT, "docs", "BENCHMARK_RESULTS.md")


def load():
    with open(WF, encoding="utf-8") as f:
        text = f.read()
    return yaml.safe_load(text), text


def triggers(doc):
    # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
    return doc.get("on", doc.get(True))


class WorkflowInterfaceTest(unittest.TestCase):
    def setUp(self):
        self.doc, self.text = load()
        self.on = triggers(self.doc)
        self.job = self.doc["jobs"]["bench-compare"]
        self.steps = self.job["steps"]

    def step(self, name_part):
        hits = [s for s in self.steps if name_part in s.get("name", "")]
        self.assertEqual(len(hits), 1, f"{name_part!r}: {len(hits)} steps")
        return hits[0]

    def test_scheduled_and_dispatchable(self):
        self.assertIn("schedule", self.on)
        self.assertIn("workflow_dispatch", self.on)
        self.assertEqual(len(self.on["schedule"]), 1)
        self.assertRegex(self.on["schedule"][0]["cron"], r"^\S+ \S+ \S+ \S+ \S+$")

    def test_not_a_pr_check_beyond_its_own_tooling(self):
        # Never a required PR check: no push trigger, and the pull_request
        # trigger is a path filter on this workflow's own files only.
        self.assertNotIn("push", self.on)
        paths = set(self.on["pull_request"]["paths"])
        self.assertEqual(paths, {".github/workflows/bench-compare.yml",
                                 "scripts/bench/baseline.py",
                                 "scripts/bench/test_bench_compare_workflow.py"})

    def test_read_only_token(self):
        self.assertEqual(self.doc["permissions"], {"contents": "read"})

    def test_every_input_reference_is_declared_and_used(self):
        declared = set(self.on["workflow_dispatch"]["inputs"])
        used = set(re.findall(r"\$\{\{\s*inputs\.([A-Za-z0-9_]+)", self.text))
        self.assertLessEqual(used, declared, used - declared)
        self.assertEqual(declared - used, set(), "declared but unused inputs")

    def test_dispatch_input_shapes(self):
        ins = self.on["workflow_dispatch"]["inputs"]
        self.assertEqual(ins["tiers"]["default"], "micro,replay,rest,localnet")
        self.assertEqual(ins["runs"]["default"], "3")
        self.assertEqual(ins["profile"]["options"], ["smoke", "full"])
        for name in ("fail_on_regression", "dry_run_gate_failure"):
            self.assertEqual(ins[name]["type"], "boolean")
            self.assertIs(ins[name]["default"], False)

    def test_tier_list_matches_tier_files(self):
        tier_files = {os.path.splitext(f)[0] for f in os.listdir(os.path.join(HERE, "tiers"))}
        m = re.search(r"case \"\$t\" in ([a-z|]+\)) ;;", self.text)
        self.assertTrue(m, "tier whitelist not found")
        allowed = set(m.group(1).rstrip(")").split("|"))
        self.assertEqual(allowed, {"micro", "replay", "rest", "localnet"})
        self.assertLessEqual(allowed, tier_files)
        default = self.on["workflow_dispatch"]["inputs"]["tiers"]["default"].split(",")
        self.assertEqual(set(default), allowed)

    def test_builds_go_algorand_with_libsodium_at_the_pin(self):
        clone = self.step("Clone pinned go-algorand")
        self.assertIn("make -C \"$GO_ALGORAND_DIR\" libsodium", clone["run"])
        self.assertIn("scripts/bench/go-algorand.pin", self.step("Resolve the pinned tag")["run"])
        self.assertIn("autoconf", self.step("libsodium build tools")["run"])

    def test_runs_make_bench_compare_for_main_and_testnet_prefix(self):
        main = self.step("small corpus")
        self.assertIn("make bench-compare TIERS=\"$TIERS\" CORPUS=small", main["run"])
        self.assertIn("bench-results/main", main["run"])
        tn = self.step("testnet-prefix50")
        self.assertIn("CORPUS=testnet-prefix50", tn["run"])
        self.assertIn("bench-results/testnet-prefix50", tn["run"])
        # the real-certificate corpus is a replay-only extra
        self.assertIn("has_replay == 'true'", tn["if"])

    def test_gate_failure_fails_the_job(self):
        for s in self.steps:
            self.assertNotIn("continue-on-error", s, s.get("name"))
        self.assertNotIn("continue-on-error", self.job)
        main = self.step("small corpus")
        self.assertIn("set -euo pipefail", main["run"])
        # the dry-run input drives the negative-test hook of the replay tier
        self.assertIn("BENCH_REPLAY_CORRUPT", main["env"])
        self.assertIn("dry_run == 'true'", main["env"]["BENCH_REPLAY_CORRUPT"])
        self.assertIn("'expected'", main["env"]["BENCH_REPLAY_CORRUPT"])
        # ... which exists in the tier
        with open(os.path.join(HERE, "tiers", "replay.py"), encoding="utf-8") as f:
            self.assertIn("BENCH_REPLAY_CORRUPT", f.read())

    def test_regressions_warn_unless_asked_to_fail(self):
        chk = self.step("Regression check")
        self.assertIn("baseline.py compare", chk["run"])
        self.assertIn("--fail-on-regression", chk["run"])
        self.assertIn("steps.cfg.outputs.fail_on_regression", chk["env"]["FAIL_ON_REGRESSION"])
        # the flag is only added when the input says so
        self.assertIn('[ "$FAIL_ON_REGRESSION" = true ] && flag="--fail-on-regression"', chk["run"])

    def test_baseline_sections_exist_in_baseline_file_and_doc(self):
        sections = set(re.findall(r"--section (\S+)", self.step("Regression check")["run"]))
        self.assertEqual(sections, {"local-main", "local-testnet-prefix50"})
        with open(BASELINE, encoding="utf-8") as f:
            base = json.load(f)
        self.assertEqual(base["schema"], "bench-baseline/v1")
        with open(RESULTS_DOC, encoding="utf-8") as f:
            doc = f.read()
        for s in sections:
            self.assertIn(s, base["sections"])
            self.assertTrue(base["sections"][s]["rows"], s)
            self.assertIn(f"<!-- bench-baseline:begin {s} -->", doc)
            self.assertIn(f"<!-- bench-baseline:end {s} -->", doc)
        self.assertIn(f"BENCH_BASELINE: {os.path.relpath(BASELINE, ROOT).replace(os.sep, '/')}",
                      self.text)

    def test_uploads_run_dirs_and_job_summary(self):
        up = self.step("Upload run directories")
        self.assertEqual(up["if"], "always()")
        self.assertTrue(up["uses"].startswith("actions/upload-artifact@"))
        self.assertEqual(up["with"]["path"], "bench-results")
        summ = self.step("Reports to job summary")
        self.assertEqual(summ["if"], "always()")
        self.assertIn("GITHUB_STEP_SUMMARY", summ["run"])
        self.assertIn("report.md", summ["run"])

    def test_docker_image_only_when_a_container_tier_is_selected(self):
        for name in ("Set up Docker Buildx", "Build the algod-rust node image"):
            self.assertIn("has_docker == 'true'", self.step(name)["if"])
        env = self.step("small corpus")["env"]
        self.assertEqual(env["BENCH_REST_RUST_IMAGE"], env["BENCH_LOCALNET_RUST_IMAGE"])
        tag = self.step("Build the algod-rust node image")["with"]["tags"]
        self.assertEqual(env["BENCH_REST_RUST_IMAGE"], tag)

    def test_make_variables_exist(self):
        with open(os.path.join(ROOT, "Makefile"), encoding="utf-8") as f:
            mk = f.read()
        for var in ("TIERS", "RUNS", "CORPUS", "BENCH_RUN_DIR"):
            self.assertRegex(mk, rf"(?m)^{var} \?=")


class ResolveInputsStepTest(unittest.TestCase):
    """Run the workflow's own validation script with bash."""

    @classmethod
    def setUpClass(cls):
        if not shutil.which("bash"):
            raise unittest.SkipTest("bash not available")
        doc, _ = load()
        steps = doc["jobs"]["bench-compare"]["steps"]
        cls.script = next(s for s in steps if s.get("id") == "cfg")["run"]

    def run_step(self, **env):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out")
            open(out, "w").close()
            e = {k: v for k, v in os.environ.items()
                 if not k.startswith(("IN_", "EVENT", "GITHUB_"))}
            e.update(GITHUB_OUTPUT=out, EVENT=env.pop("EVENT", "schedule"))
            e.update({f"IN_{k.upper()}": v for k, v in env.items()})
            p = subprocess.run(["bash", "-c", self.script], env=e, capture_output=True, text=True)
            with open(out, encoding="utf-8") as f:
                kv = dict(l.rstrip("\n").split("=", 1) for l in f if "=" in l)
            return p.returncode, kv, p.stdout + p.stderr

    def test_schedule_defaults(self):
        rc, kv, _ = self.run_step()
        self.assertEqual(rc, 0)
        self.assertEqual(kv["tiers"], "micro,replay,rest,localnet")
        self.assertEqual(kv["runs"], "3")
        self.assertEqual(kv["profile"], "smoke")
        self.assertEqual((kv["has_replay"], kv["has_docker"], kv["dry_run"]), ("true", "true", "false"))

    def test_pull_request_is_one_run(self):
        rc, kv, _ = self.run_step(EVENT="pull_request")
        self.assertEqual((rc, kv["runs"]), (0, "1"))

    def test_micro_only_needs_no_docker_and_no_replay(self):
        rc, kv, _ = self.run_step(tiers="micro")
        self.assertEqual(rc, 0)
        self.assertEqual((kv["has_docker"], kv["has_replay"], kv["has_micro"]),
                         ("false", "false", "true"))

    def test_rejects_unknown_tier_bad_runs_and_injection(self):
        for bad in ({"tiers": "micro,catchup"}, {"tiers": "micro;rm -rf /"}, {"runs": "0"},
                    {"runs": "3; echo hi"}, {"tiers": "Micro"}):
            rc, _, out = self.run_step(**bad)
            self.assertNotEqual(rc, 0, bad)
            self.assertIn("::error::", out)

    def test_dry_run_needs_replay(self):
        rc, _, out = self.run_step(tiers="micro", dry="true")
        self.assertNotEqual(rc, 0)
        self.assertIn("replay", out)
        rc, kv, _ = self.run_step(tiers="replay", dry="true")
        self.assertEqual((rc, kv["dry_run"]), (0, "true"))


if __name__ == "__main__":
    unittest.main()
