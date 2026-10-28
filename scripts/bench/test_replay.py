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
import sys
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
