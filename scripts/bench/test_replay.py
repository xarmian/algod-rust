# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests of the `replay` tier's final-state gate, its negative-test
corpora and its result rows (scripts/bench/tiers/replay.py, issue #2105).
No go, no cargo: the replays themselves are covered by
benchmarks/go-replay's go tests, the Rust bench_replay tests and CI."""
import copy
import json
import os
import re
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:  # pragma: no cover - CI runners ship PyYAML
    yaml = None

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tiers"))
sys.path.insert(0, os.path.join(HERE, "corpus"))
import bench_schema  # noqa: E402
import corpus_tool as ct  # noqa: E402
import replay  # noqa: E402

SMALL = os.path.join(os.path.dirname(os.path.dirname(HERE)), "benchmarks", "corpus", "small")
RECORDED = os.path.join(os.path.dirname(os.path.dirname(HERE)), "benchmarks", "go-replay",
                        "testdata", "small-final-state.json")


def result(state, corpus_match=True, write_bytes=None):
    return {
        "schema": "bench-replay-run/v1", "rounds": 2000, "final_state": state,
        "corpus_match": corpus_match, "_cmd": "x",
        "metrics": {"blocks_per_s": 1000.0, "txns_per_s": 6000.0, "wall_s": 2.0,
                    "peak_rss_bytes": 200 * 1024 * 1024, "cpu_user_s": 1.5, "cpu_sys_s": 0.5,
                    "db_bytes": 10 * 1024 * 1024, "write_bytes": write_bytes, "blocks": 2000,
                    "txns": 12332},
    }


class GateTest(unittest.TestCase):
    def setUp(self):
        with open(RECORDED, encoding="utf-8") as f:
            self.state = json.load(f)

    def test_equal_states_pass(self):
        r = {"go": result(self.state), "rust": result(copy.deepcopy(self.state))}
        self.assertEqual(replay.gate([r, copy.deepcopy(r)], True), [])

    def test_go_rust_divergence_fails_and_names_the_field(self):
        bad = copy.deepcopy(self.state)
        bad["totals"]["not_participating"]["money"] += 1
        errs = replay.gate([{"go": result(self.state), "rust": result(bad)}], True)
        self.assertTrue(errs)
        self.assertIn("go and rust final states differ", errs[0])
        self.assertIn("totals.not_participating.money", errs[0])

    def test_corpus_mismatch_fails_even_when_both_sides_agree(self):
        r = {"go": result(self.state, corpus_match=False),
             "rust": result(self.state, corpus_match=False)}
        r["go"]["corpus_mismatches"] = ["accounts_sha256: replay a, corpus.json b"]
        errs = replay.gate([r], True)
        self.assertTrue(any("accounts_sha256" in e for e in errs), errs)
        # A prefix replay has no corpus.json state to match.
        self.assertEqual(replay.gate([r], False), [])

    def test_runs_must_agree_with_each_other(self):
        other = copy.deepcopy(self.state)
        other["round"] = 1999
        runs = [{"go": result(self.state), "rust": result(self.state)},
                {"go": result(other), "rust": result(other)}]
        self.assertTrue(any("run 0's" in e for e in replay.gate(runs, False)))

    def test_state_sha256_ignores_key_order(self):
        rev = dict(reversed(list(self.state.items())))
        self.assertEqual(replay.state_sha256(self.state), replay.state_sha256(rev))


class RunPairTest(unittest.TestCase):
    """Both sides always run, so a corrupted corpus proves each side fails
    on its own (issue #2105 review)."""

    def test_a_rust_only_failure_is_reported_after_go_ran(self):
        calls = []

        def run(side):
            calls.append(side)
            if side == "rust":
                raise replay.TierError("rust replay exited 1")
            return {"side": side}

        with self.assertRaises(replay.SideFailures) as cm:
            replay.run_pair(("go", "rust"), run)
        self.assertEqual(calls, ["go", "rust"])
        self.assertEqual(sorted(cm.exception.failed), ["rust"])
        self.assertIn("rust replay exited 1", str(cm.exception))

    def test_a_go_failure_does_not_skip_the_rust_side(self):
        calls = []

        def run(side):
            calls.append(side)
            raise replay.TierError(f"{side} replay exited 1")

        with self.assertRaises(replay.SideFailures) as cm:
            replay.run_pair(("go", "rust"), run)
        self.assertEqual(calls, ["go", "rust"])
        self.assertEqual(sorted(cm.exception.failed), ["go", "rust"])

    def test_both_sides_succeeding_returns_both_results(self):
        r = replay.run_pair(("rust", "go"), lambda side: {"side": side})
        self.assertEqual(r, {"go": {"side": "go"}, "rust": {"side": "rust"}})


class CorruptCorpusTest(unittest.TestCase):
    def test_txn_corruption_flips_one_byte_and_rehashes_the_manifest(self):
        with tempfile.TemporaryDirectory() as t:
            d = replay.corrupt_corpus(SMALL, os.path.join(t, "c"), "txn")
            self.assertEqual(ct.verify_manifest(d), [])
            with open(os.path.join(SMALL, "blocks.bin"), "rb") as f:
                a = f.read()
            with open(os.path.join(d, "blocks.bin"), "rb") as f:
                b = f.read()
            self.assertEqual(len(a), len(b))
            self.assertEqual(sum(x != y for x, y in zip(a, b)), 1)

    def test_expected_corruption_changes_only_the_accounts_digest(self):
        with tempfile.TemporaryDirectory() as t:
            d = replay.corrupt_corpus(SMALL, os.path.join(t, "c"), "expected")
            self.assertEqual(ct.verify_manifest(d), [])
            want = ct.load_corpus_json(SMALL)
            got = ct.load_corpus_json(d)
            self.assertNotEqual(got["final_state"]["accounts_sha256"],
                                want["final_state"]["accounts_sha256"])
            got["final_state"]["accounts_sha256"] = want["final_state"]["accounts_sha256"]
            self.assertEqual(got, want)

    def test_unknown_kind_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(replay.TierError):
                replay.corrupt_corpus(SMALL, os.path.join(t, "c"), "bogus")


class ResultsTest(unittest.TestCase):
    def test_rows_are_schema_v1_and_paired(self):
        with open(RECORDED, encoding="utf-8") as f:
            state = json.load(f)
        runs = [{"go": result(state), "rust": result(state, write_bytes=5 * 1024 * 1024)}]
        rows = replay.results(runs, "small", {"corpus": "small"})
        for row in rows:
            bench_schema.validate_result(row)
        names = {(r["name"], r["impl"]) for r in rows}
        for k in ("blocks_per_s", "txns_per_s", "wall_s", "peak_rss_mb", "cpu_s", "db_mb"):
            self.assertIn((f"small/{k}", "go"), names)
            self.assertIn((f"small/{k}", "rust"), names)
        # write_mb only where /proc/self/io exists.
        self.assertIn(("small/write_mb", "rust"), names)
        self.assertNotIn(("small/write_mb", "go"), names)
        cpu = next(r for r in rows if r["name"] == "small/cpu_s" and r["impl"] == "go")
        self.assertEqual(cpu["samples"], [2.0])
        self.assertEqual(cpu["better"], "lower")


REPO = os.path.dirname(os.path.dirname(HERE))
WORKFLOW = os.path.join(REPO, ".github", "workflows", "bench-replay.yml")


def _glob_re(pattern):
    """GitHub path-filter glob (`**` crosses directories, `*` does not)."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + "$")


@unittest.skipIf(yaml is None, "PyYAML not installed")
class WorkflowPathsTest(unittest.TestCase):
    """bench-replay.yml must fire on every file the tier imports or runs, and
    on the production code the replay drives (issue #2105 review)."""

    REQUIRED = [
        "scripts/bench/tiers/replay.py", "scripts/bench/test_replay.py",
        "scripts/bench/run.py", "scripts/bench/build_both.sh", "scripts/bench/micro_equiv.py",
        "scripts/bench/fingerprint.py", "scripts/bench/bench_schema.py",
        "scripts/bench/schema/result-v1.json", "scripts/bench/corpus/corpus_tool.py",
        "scripts/bench/fetch_corpus.sh", "scripts/bench/go-algorand.pin", "Makefile",
        "benchmarks/go-replay/main.go", "benchmarks/go-replay/state.go",
        "benchmarks/go-replay/testdata/small-final-state.json",
        "benchmarks/corpus/small/blocks.bin", "benchmarks/corpus/large.ref",
        "bin/algod-rust/Cargo.toml", "bin/algod-rust/src/main.rs", "bin/algod-rust/src/cli.rs",
        "bin/algod-rust/src/falcon_backend.rs", "bin/algod-rust/src/commands/bench_replay.rs",
        "bin/algod-rust/src/commands/participate.rs",
        "crates/tools/algo-bench/src/replay_state.rs", "crates/core/algo-ledger/src/apply.rs",
        "crates/core/algo-ledger/src/catchup_service.rs", "crates/core/algo-validate/src/lib.rs",
        "crates/core/algo-codec/src/lib.rs", "crates/node/algo-config/src/lib.rs", "Cargo.lock",
        ".github/workflows/bench-replay.yml",
    ]

    def setUp(self):
        with open(WORKFLOW, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        self.on = doc.get("on", doc.get(True))

    def test_pull_request_and_push_filters_are_identical(self):
        self.assertEqual(self.on["pull_request"]["paths"], self.on["push"]["paths"])

    def test_every_dependency_triggers_the_workflow(self):
        pats = [_glob_re(p) for p in self.on["pull_request"]["paths"] if not p.startswith("!")]
        missing = [f for f in self.REQUIRED if not any(p.match(f) for p in pats)]
        self.assertEqual(missing, [], "files that change the replay tier but do not trigger it")
        for f in self.REQUIRED:
            if "*" not in f:
                self.assertTrue(os.path.exists(os.path.join(REPO, f)), f"stale entry {f}")


if __name__ == "__main__":
    unittest.main()
