#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for blockcompare.py (issue #1674).  No Docker, no network.

    python3 ops/mixed-cluster/scripts/blockcompare_test.py
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import blockcompare as bc  # noqa: E402


def pack(v):
    """Tiny msgpack encoder covering what a block response needs."""
    if v is None:
        return b"\xc0"
    if v is True:
        return b"\xc3"
    if v is False:
        return b"\xc2"
    if isinstance(v, int):
        if 0 <= v <= 0x7F:
            return bytes([v])
        if -32 <= v < 0:
            return bytes([v & 0xFF])
        if 0 <= v <= 0xFF:
            return b"\xcc" + bytes([v])
        if 0 <= v <= 0xFFFF:
            return b"\xcd" + struct.pack(">H", v)
        if 0 <= v <= 0xFFFFFFFF:
            return b"\xce" + struct.pack(">I", v)
        if v >= 0:
            return b"\xcf" + struct.pack(">Q", v)
        return b"\xd3" + struct.pack(">q", v)
    if isinstance(v, bytes):
        return (b"\xc4" + bytes([len(v)]) + v) if len(v) < 256 else b"\xc5" + struct.pack(">H", len(v)) + v
    if isinstance(v, str):
        e = v.encode()
        if len(e) < 32:
            return bytes([0xA0 | len(e)]) + e
        return b"\xd9" + bytes([len(e)]) + e
    if isinstance(v, list):
        head = bytes([0x90 | len(v)]) if len(v) < 16 else b"\xdc" + struct.pack(">H", len(v))
        return head + b"".join(pack(x) for x in v)
    if isinstance(v, dict):
        head = bytes([0x80 | len(v)]) if len(v) < 16 else b"\xde" + struct.pack(">H", len(v))
        return head + b"".join(pack(k) + pack(x) for k, x in v.items())
    raise TypeError(type(v))


def block_with(txns, rnd=7):
    return {"rnd": rnd, "txns": txns} if txns else {"rnd": rnd}


def response(block, cert=None):
    return pack({"block": block, "cert": cert or {"vote": [b"v" * 8]}})


PAY = {"txn": {"type": "pay", "amt": 5}, "sig": b"s" * 64}
APPL_INNER_BOX = {
    "txn": {"type": "appl", "apid": 9, "apbx": [{"i": 0, "n": b"bx"}]},
    "dt": {"itx": [{"txn": {"type": "pay"}}], "ld": {}},
}


class MsgpackTest(unittest.TestCase):
    def test_roundtrip_values(self):
        v = {"a": [1, -3, 70000, 2 ** 40, "hé", b"\x00\x01", None, True, False], "b": {"c": 300}}
        out, end = bc.decode(pack(v))
        self.assertEqual(out, v)
        self.assertEqual(end, len(pack(v)))

    def test_skip_matches_decode_end(self):
        raw = pack({"x": list(range(40)), "y": {"k" * 40: b"z" * 300}})
        self.assertEqual(bc.skip(raw, 0), len(raw))

    def test_map_entry_slice_isolates_block_from_cert(self):
        blk = block_with([PAY])
        a = response(blk, cert={"vote": [b"A" * 8]})
        b = response(blk, cert={"vote": [b"B" * 20], "extra": 1})
        self.assertNotEqual(a, b)
        self.assertEqual(bc.map_entry_slice(a, "block"), bc.map_entry_slice(b, "block"))
        self.assertEqual(bc.map_entry_slice(a, "block"), pack(blk))
        self.assertIsNone(bc.map_entry_slice(a, "nope"))

    def test_truncated_input_raises(self):
        with self.assertRaises(bc.MsgpackError):
            bc.skip(pack({"a": [1, 2, 3]})[:-1], 0)

    def test_top_level_must_be_map(self):
        with self.assertRaises(bc.MsgpackError):
            bc.map_entry_slice(pack([1]), "block")


class DiffTest(unittest.TestCase):
    def test_reports_first_differing_path(self):
        a = block_with([{"txn": {"type": "pay"}, "dt": {"ca": 7}}])
        b = block_with([{"txn": {"type": "pay"}, "dt": {"ca": 8}}])
        d = bc.diff_paths(a, b)
        self.assertEqual(len(d), 1)
        self.assertIn("$.txns[0].dt.ca", d[0])

    def test_missing_key_and_length(self):
        d = bc.diff_paths({"txns": [1, 2]}, {"txns": [1], "extra": 1})
        self.assertTrue(any("length 2 != 1" in x for x in d))
        self.assertTrue(any("extra: missing on left" in x for x in d))

    def test_int_vs_bool_is_a_difference(self):
        self.assertTrue(bc.diff_paths({"a": 1}, {"a": True}))


class FactsTest(unittest.TestCase):
    def test_empty_block(self):
        f = bc.block_facts(block_with([]))
        self.assertEqual(f["txn_count"], 0)
        self.assertFalse(f["non_payment"])

    def test_payment_only(self):
        f = bc.block_facts(block_with([PAY, PAY]))
        self.assertEqual(f["txn_count"], 2)
        self.assertEqual(f["types"], {"pay": 2})
        self.assertFalse(f["non_payment"])

    def test_inner_and_box_evidence(self):
        f = bc.block_facts(block_with([PAY, APPL_INNER_BOX]))
        self.assertTrue(f["non_payment"])
        self.assertEqual(f["inner_txn_txns"], 1)
        self.assertEqual(f["box_ref_txns"], 1)


class CompareRoundTest(unittest.TestCase):
    NODES = (("go-node-1", 1), ("go-node-2", 2), ("go-node-3", 3), ("rust-node-4", 4))

    def run_round(self, blocks, hashes=None, fail=()):
        def fetch(port, rnd):
            name = {p: n for n, p in self.NODES}[port]
            if name in fail:
                raise OSError("down")
            return blocks[name]

        def fetch_h(port, rnd):
            name = {p: n for n, p in self.NODES}[port]
            return (hashes or {}).get(name, "blk-same")

        return bc.compare_round(7, fetch, fetch_h, self.NODES, sleep=lambda s: None)

    def same(self, blk):
        # certs differ per node on purpose
        return {n: response(blk, cert={"vote": [n.encode()]}) for n, _ in self.NODES}

    def test_identical_blocks_with_different_certs_pass(self):
        rec = self.run_round(self.same(block_with([PAY, APPL_INNER_BOX])))
        self.assertTrue(rec["identical"])
        self.assertTrue(rec["hash_match"])
        self.assertTrue(rec["non_payment"])
        self.assertEqual(rec["txn_count"], 2)

    def test_rust_applydata_difference_is_detected_with_path(self):
        good = block_with([APPL_INNER_BOX])
        bad = block_with([{"txn": APPL_INNER_BOX["txn"], "dt": {"itx": [], "ld": {}}}])
        blocks = self.same(good)
        blocks["rust-node-4"] = response(bad)
        rec = self.run_round(blocks)
        self.assertFalse(rec["identical"])
        self.assertEqual(rec["mismatch_nodes"], ["rust-node-4"])
        self.assertTrue(any("dt" in d for d in rec["diff"]))

    def test_hash_mismatch(self):
        rec = self.run_round(self.same(block_with([PAY])), hashes={"rust-node-4": "blk-other"})
        self.assertFalse(rec["hash_match"])

    def test_one_node_down_is_incomplete_and_never_identical(self):
        rec = self.run_round(self.same(block_with([PAY])), fail=("go-node-3",))
        self.assertFalse(rec["complete"])
        self.assertFalse(rec["identical"])
        self.assertEqual(rec["missing"], ["go-node-3"])
        self.assertNotIn("mismatch_nodes", rec)

    def test_rust_node_down_is_incomplete(self):
        rec = self.run_round(self.same(block_with([PAY])), fail=("rust-node-4",))
        self.assertFalse(rec["complete"])
        self.assertFalse(rec["identical"])
        self.assertEqual(rec["missing"], ["rust-node-4"])

    def test_complete_round_is_marked_complete(self):
        rec = self.run_round(self.same(block_with([PAY])))
        self.assertTrue(rec["complete"])
        self.assertTrue(rec["identical"])

    def test_node_without_a_hash_is_not_a_hash_match(self):
        def fetch_h(port, rnd):
            if port == 4:
                raise OSError("no hash endpoint")
            return "blk-same"

        blocks = self.same(block_with([PAY]))
        rec = bc.compare_round(7, lambda p, r: blocks[{v: k for k, v in dict(self.NODES).items()}[p]],
                               fetch_h, self.NODES)
        self.assertFalse(rec["hash_match"])
        self.assertEqual(rec["hash_missing"], ["rust-node-4"])

    def test_transient_fetch_failure_is_retried(self):
        calls = {"n": 0}
        blocks = self.same(block_with([PAY]))
        names = {v: k for k, v in dict(self.NODES).items()}

        def fetch(port, rnd):
            if port == 4:
                calls["n"] += 1
                if calls["n"] < 3:
                    raise OSError("blip")
            return blocks[names[port]]

        rec = bc.compare_round(7, fetch, lambda p, r: "blk-same", self.NODES, retries=3, sleep=lambda s: None)
        self.assertTrue(rec["complete"])
        self.assertEqual(calls["n"], 3)

    def test_persistent_failure_exhausts_retries(self):
        rec = self.run_round(self.same(block_with([PAY])), fail=("rust-node-4",))
        self.assertFalse(rec["complete"])

    def test_reference_down_is_degraded(self):
        rec = self.run_round(self.same(block_with([PAY])), fail=("go-node-1",))
        self.assertTrue(rec["degraded"])


class SummaryTest(unittest.TestCase):
    def test_aggregation(self):
        recs = [
            {"kind": "block_compare", "round": 1, "txn_count": 0, "identical": True, "hash_match": True},
            {"kind": "block_compare", "round": 2, "txn_count": 2, "identical": True, "hash_match": True,
             "non_payment": True, "types": {"pay": 1, "appl": 1}, "inner_txn_txns": 1, "box_ref_txns": 1},
            {"kind": "block_compare", "round": 3, "txn_count": 1, "identical": False, "mismatch_nodes": ["rust-node-4"],
             "diff": ["$.x"], "hash_match": False, "hashes": {"a": "1"}},
            {"kind": "block_compare", "round": 4, "degraded": True, "missing": ["go-node-1"]},
            {"kind": "workload_step"},
        ]
        s = bc.summarize_records(recs)
        self.assertEqual(s["rounds_compared"], 3)
        self.assertEqual(s["rounds_with_txns"], 2)
        self.assertEqual(s["rounds_non_payment"], 1)
        self.assertEqual(s["degraded_rounds"], 1)
        self.assertEqual(s["txn_types"], {"pay": 1, "appl": 1})
        self.assertEqual([m["round"] for m in s["mismatches"]], [3])
        self.assertEqual([m["round"] for m in s["hash_mismatches"]], [3])

    def test_incomplete_rounds_and_per_node_missing_are_counted(self):
        recs = [
            {"kind": "block_compare", "round": 1, "txn_count": 0, "complete": True, "identical": True, "hash_match": True},
            {"kind": "block_compare", "round": 2, "txn_count": 0, "complete": False, "identical": False,
             "missing": ["rust-node-4"], "hash_match": True},
            {"kind": "block_compare", "round": 3, "txn_count": 0, "complete": False, "identical": False,
             "missing": ["rust-node-4", "go-node-3"], "hash_match": False, "hash_missing": ["rust-node-4"],
             "hashes": {}},
            {"kind": "block_compare", "round": 4, "degraded": True, "missing": ["go-node-1"]},
        ]
        s = bc.summarize_records(recs)
        self.assertEqual(s["rounds_compared"], 1)
        self.assertEqual(s["incomplete_rounds"], 2)
        self.assertEqual(s["degraded_rounds"], 1)
        self.assertEqual(s["nodes_missing"], {"rust-node-4": 2, "go-node-3": 1, "go-node-1": 1})
        # an incomplete round is not a byte mismatch
        self.assertEqual(s["mismatches"], [])
        self.assertEqual(s["missing_rounds"], 3)
        self.assertEqual([m["round"] for m in s["hash_mismatches"]], [3])

    def test_close_txns_are_aggregated(self):
        recs = [{"kind": "block_compare", "round": 1, "txn_count": 1, "complete": True, "identical": True,
                 "hash_match": True, "close_txns": 2, "nodes_compared": ["a"]}]
        self.assertEqual(bc.summarize_records(recs)["close_txns"], 2)

    def test_facts_count_close_to(self):
        pay_close = {"txn": {"type": "pay", "close": b"x" * 32}}
        axfer_close = {"txn": {"type": "axfer", "aclose": b"x" * 32}}
        self.assertEqual(bc.block_facts(block_with([PAY, pay_close, axfer_close]))["close_txns"], 2)


class ExitCodeTest(unittest.TestCase):
    def summ(self, *recs):
        return bc.summarize_records(list(recs))

    OK = {"kind": "block_compare", "round": 1, "txn_count": 0, "complete": True, "identical": True,
          "hash_match": True, "nodes_compared": ["rust-node-4"]}

    def test_clean_is_zero(self):
        self.assertEqual(bc.exit_code(self.summ(self.OK)), 0)

    def test_missing_node_fails_unless_allowed(self):
        miss = {"kind": "block_compare", "round": 2, "txn_count": 0, "complete": False, "identical": False,
                "missing": ["rust-node-4"], "hash_match": True}
        s = self.summ(self.OK, miss)
        self.assertEqual(bc.exit_code(s), 3)
        self.assertEqual(bc.exit_code(s, allow_missing=True), 0)

    def test_missing_hash_fails_unless_allowed(self):
        h = dict(self.OK, round=2, hash_match=False, hash_missing=["rust-node-4"], hashes={})
        s = self.summ(self.OK, h)
        self.assertEqual(bc.exit_code(s), 3)
        self.assertEqual(bc.exit_code(s, allow_missing=True), 0)

    def test_real_mismatch_is_two_even_when_missing_allowed(self):
        bad = dict(self.OK, round=2, identical=False, mismatch_nodes=["rust-node-4"], diff=["$.x"])
        self.assertEqual(bc.exit_code(self.summ(self.OK, bad), allow_missing=True), 2)

    def test_nothing_compared_is_three(self):
        self.assertEqual(bc.exit_code(self.summ()), 3)


class RunLoopTest(unittest.TestCase):
    def test_common_tip_ignores_unreachable_nodes(self):
        self.assertEqual(bc.common_tip([10, None, 12, 11]), 10)
        self.assertIsNone(bc.common_tip([None, None]))

    def test_batch_run_compares_reachable_nodes_when_one_is_unreachable(self):
        import io
        import types
        seen = []
        orig = (bc.node_round, bc.compare_round)
        rounds = {4001: 5, 4002: 5, 4003: 6, 4004: None}
        bc.node_round = lambda port: rounds[port]

        def fake(rnd, **kw):
            seen.append(rnd)
            return {"kind": "block_compare", "round": rnd, "txn_count": 0, "complete": False, "identical": False,
                    "missing": ["rust-node-4"], "hash_match": True}

        bc.compare_round = fake
        try:
            args = types.SimpleNamespace(from_round=1, to_round=0, follow=False, stop_file=None,
                                         poll_interval=0, max_idle_s=0, retries=1)
            s = bc.run(args, io.StringIO())
        finally:
            bc.node_round, bc.compare_round = orig
        self.assertEqual(seen, [1, 2, 3, 4, 5])
        self.assertEqual(s["incomplete_rounds"], 5)
        self.assertEqual(s["nodes_missing"], {"rust-node-4": 5})


if __name__ == "__main__":
    unittest.main()
