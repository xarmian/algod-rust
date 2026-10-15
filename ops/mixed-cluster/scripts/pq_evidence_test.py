#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for pq_evidence.py (issue #1958).  No cluster needed."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pq_evidence as pe  # noqa: E402


def write_run(d, pq_ok=True, bad_blocks=0, result="PASS"):
    steps = [
        {"kind": "workload_step", "op": "pay", "outcome": "confirmed", "ok": True, "round": 9, "txids": ["A"]},
        {"kind": "workload_step", "op": "pq_pay_via_go-node-1", "outcome": "confirmed", "ok": True, "round": 155,
         "txids": ["T1"], "submissions": [{"node": "go-node-1", "status": 200}]},
        {"kind": "workload_step", "op": "pq_pay_via_rust-node-4", "outcome": "confirmed" if pq_ok else "rejected",
         "ok": pq_ok, "round": 157 if pq_ok else None, "txids": ["T2"] if pq_ok else [],
         "submissions": [{"node": "rust-node-4", "status": 200 if pq_ok else 400}]},
        {"kind": "workload_summary", "steps": 3, "confirmed": 2, "rejected": 1, "unexpected": 0, "submit_divergence": 0},
    ]
    with open(os.path.join(d, "workload.jsonl"), "w") as f:
        f.write("\n".join(json.dumps(s) for s in steps) + "\n")
    blocks = [{"kind": "block_compare", "round": r, "identical": r > bad_blocks, "complete": True} for r in range(1, 6)]
    with open(os.path.join(d, "blockcompare.jsonl"), "w") as f:
        f.write("\n".join(json.dumps(b) for b in blocks) + "\n")
    with open(os.path.join(d, "summary.json"), "w") as f:
        json.dump({"result": result, "checks_total": 18, "checks_failed": 0 if result == "PASS" else 1}, f)


class PqEvidenceTest(unittest.TestCase):
    def test_extracts_pq_steps_blocks_and_conformance(self):
        with tempfile.TemporaryDirectory() as d:
            write_run(d)
            ev = pe.build(d, "rust (default)", "abc1234", "make x")
        self.assertEqual([s["op"] for s in ev["pq_steps"]], ["pq_pay_via_go-node-1", "pq_pay_via_rust-node-4"])
        self.assertEqual([s["submit_status"] for s in ev["pq_steps"]], [[200], [200]])
        self.assertEqual(ev["block_compare"], {"rounds": 5, "not_identical_or_incomplete": 0})
        self.assertEqual(ev["conformance"]["result"], "PASS")
        self.assertEqual(ev["workload"]["unexpected"], 0)
        self.assertEqual((ev["commit"], ev["falcon_backend"], ev["command"]), ("abc1234", "rust (default)", "make x"))

    def test_counts_blocks_that_differ(self):
        with tempfile.TemporaryDirectory() as d:
            write_run(d, bad_blocks=2)
            ev = pe.build(d, "c", "abc", "cmd")
        self.assertEqual(ev["block_compare"]["not_identical_or_incomplete"], 2)

    def test_ok_requires_both_pq_payments_committed_all_blocks_identical_and_a_pass(self):
        with tempfile.TemporaryDirectory() as d:
            write_run(d)
            self.assertTrue(pe.build(d, "r", "c", "x")["ok"])
        for kw in ({"pq_ok": False}, {"bad_blocks": 1}, {"result": "FAIL"}):
            with tempfile.TemporaryDirectory() as d:
                write_run(d, **kw)
                self.assertFalse(pe.build(d, "r", "c", "x")["ok"], kw)

    def test_a_run_without_both_pq_steps_is_not_ok(self):
        with tempfile.TemporaryDirectory() as d:
            write_run(d)
            lines = [l for l in open(os.path.join(d, "workload.jsonl")) if "rust-node-4" not in l]
            open(os.path.join(d, "workload.jsonl"), "w").writelines(lines)
            self.assertFalse(pe.build(d, "r", "c", "x")["ok"])


if __name__ == "__main__":
    unittest.main()
