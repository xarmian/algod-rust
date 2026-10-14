#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for stateproof_check.py's cross-node logic (no cluster needed)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stateproof_check as sc  # noqa: E402

NODES = ["go-node-1", "go-node-2", "go-node-3", "rust-node-4"]
PROOF = {"Message": {"BlockHeadersCommitment": "AAAA", "LastAttestedRound": 512},
         "StateProof": "BBBB"}


def fake(proofs=None, hashes=None, spt=None):
    """Build a fetch() over per-node proof / per-round hash / spt tables."""
    proofs = proofs if proofs is not None else {n: PROOF for n in NODES}

    def fetch(node, path):
        if path.startswith("/v2/stateproofs/"):
            p = proofs.get(node)
            return (200, p) if p is not None else (404, None)
        if path.endswith("/hash"):
            rnd = int(path.split("/")[3])
            h = (hashes or {}).get((node, rnd), "blk-{}".format(rnd))
            return (200, {"blockHash": h}) if h is not None else (404, None)
        if path.startswith("/v2/blocks/"):
            n = (spt or {}).get(node)
            if n is None:
                return (200, {"block": {}})
            return (200, {"block": {"spt": {"0": {"n": n}}}})
        return (404, None)

    return fetch


def mp_str(text):
    b = text.encode()
    assert len(b) < 32
    return bytes([0xA0 | len(b)]) + b


def mp_map(*pairs):
    out = bytes([0x80 | len(pairs)])
    for k, v in pairs:
        out += k + v
    return out


def mp_block(txn_types, extra=b""):
    """A minimal msgpack `{"block": {"txns": [{"txn": {"type": T}}...]}, "cert": X}` response."""
    txns = bytes([0x90 | len(txn_types)])
    for t in txn_types:
        txns += mp_map((mp_str("txn"), mp_map((mp_str("type"), mp_str(t)))))
    block = mp_map((mp_str("txns"), txns))
    return mp_map((mp_str("block"), block), (mp_str("cert"), mp_str("cert" + extra.decode())))


def fake_raw(per_node):
    """fetch_raw over {node: raw-bytes-or-None}."""
    def fetch_raw(node, path):
        raw = per_node.get(node)
        return (200, raw) if raw is not None else (404, None)
    return fetch_raw


def by_name(checks):
    return {c["name"]: c for c in checks}


class CheckTest(unittest.TestCase):
    def test_all_identical_passes(self):
        checks = by_name(sc.run_checks(fake(spt={n: 768 for n in NODES}), NODES, 512, 4, 530))
        for name, c in checks.items():
            self.assertTrue(c["ok"], (name, c))
        self.assertIn("state_proof_tracking_advanced_identically", checks)
        self.assertIn("rounds 512..534 (23 rounds)", checks["block_hashes_identical_around_proof"]["detail"])

    def test_missing_proof_on_a_go_node_fails_both_proof_checks(self):
        proofs = {n: PROOF for n in NODES}
        del proofs["go-node-2"]
        checks = by_name(sc.run_checks(fake(proofs=proofs), NODES, 512, 2))
        self.assertFalse(checks["state_proof_served_by_go_nodes"]["ok"])
        self.assertIn("go-node-2", checks["state_proof_served_by_go_nodes"]["detail"])
        self.assertFalse(checks["state_proof_identical_on_go_nodes"]["ok"])

    def test_divergent_proof_bytes_between_go_nodes_fail(self):
        proofs = {n: PROOF for n in NODES}
        proofs["go-node-3"] = dict(PROOF, StateProof="CCCC")
        checks = by_name(sc.run_checks(fake(proofs=proofs), NODES, 512, 2))
        self.assertTrue(checks["state_proof_served_by_go_nodes"]["ok"])
        self.assertFalse(checks["state_proof_identical_on_go_nodes"]["ok"])
        self.assertIn("2 distinct", checks["state_proof_identical_on_go_nodes"]["detail"])

    def test_rust_endpoint_gap_is_informational_not_a_failure(self):
        proofs = {n: PROOF for n in NODES}
        del proofs["rust-node-4"]  # 404, issue #1952
        checks = by_name(sc.run_checks(fake(proofs=proofs), NODES, 512, 2))
        self.assertTrue(checks["state_proof_served_by_go_nodes"]["ok"])
        c = checks["rust_state_proof_endpoint_rust-node-4"]
        self.assertTrue(c["ok"])
        self.assertIn("1952", c["detail"])

    def test_rust_endpoint_serving_the_same_proof_is_reported(self):
        checks = by_name(sc.run_checks(fake(), NODES, 512, 2))
        self.assertIn("identical", checks["rust_state_proof_endpoint_rust-node-4"]["detail"])

    def test_commit_block_identical_with_stpf_on_every_node_passes(self):
        # the `cert` differs per node (extra), the `block` must not
        raw = {n: mp_block(["pay", "stpf"], extra=n[-1:].encode()) for n in NODES}
        checks = by_name(sc.run_checks(fake(), NODES, 512, 2, 530, fake_raw(raw)))
        self.assertTrue(checks["commit_block_carries_state_proof_txn_on_every_node"]["ok"], checks)
        self.assertTrue(checks["commit_block_bytes_identical_on_every_node"]["ok"], checks)

    def test_commit_block_without_stpf_fails(self):
        raw = {n: mp_block(["pay"]) for n in NODES}
        checks = by_name(sc.run_checks(fake(), NODES, 512, 2, 530, fake_raw(raw)))
        self.assertFalse(checks["commit_block_carries_state_proof_txn_on_every_node"]["ok"])

    def test_commit_block_bytes_differing_on_one_node_fail(self):
        raw = {n: mp_block(["stpf"]) for n in NODES}
        raw["rust-node-4"] = mp_block(["stpf", "pay"])
        checks = by_name(sc.run_checks(fake(), NODES, 512, 2, 530, fake_raw(raw)))
        self.assertTrue(checks["commit_block_carries_state_proof_txn_on_every_node"]["ok"])
        self.assertFalse(checks["commit_block_bytes_identical_on_every_node"]["ok"])
        self.assertIn("2 distinct", checks["commit_block_bytes_identical_on_every_node"]["detail"])

    def test_commit_block_unreadable_on_the_rust_node_fails(self):
        raw = {n: mp_block(["stpf"]) for n in NODES}
        raw["rust-node-4"] = None
        checks = by_name(sc.run_checks(fake(), NODES, 512, 2, 530, fake_raw(raw)))
        self.assertFalse(checks["commit_block_carries_state_proof_txn_on_every_node"]["ok"])
        self.assertIn("rust-node-4", checks["commit_block_carries_state_proof_txn_on_every_node"]["detail"])

    def test_block_hash_mismatch_in_window_fails(self):
        hashes = {("rust-node-4", 514): "blk-FORK"}
        checks = by_name(sc.run_checks(fake(hashes=hashes), NODES, 512, 4))
        self.assertFalse(checks["block_hashes_identical_around_proof"]["ok"])
        self.assertIn("514", checks["block_hashes_identical_around_proof"]["detail"])

    def test_mismatch_outside_window_is_ignored(self):
        hashes = {("rust-node-4", 600): "blk-OTHER"}
        checks = by_name(sc.run_checks(fake(hashes=hashes), NODES, 512, 4))
        self.assertTrue(checks["block_hashes_identical_around_proof"]["ok"])

    def test_unreadable_hash_fails(self):
        hashes = {("go-node-2", 513): None}
        checks = by_name(sc.run_checks(fake(hashes=hashes), NODES, 512, 4))
        self.assertFalse(checks["block_hashes_identical_around_proof"]["ok"])

    def test_tracking_not_advanced_is_reported(self):
        checks = by_name(sc.run_checks(fake(spt={n: 512 for n in NODES}), NODES, 512, 2))
        self.assertFalse(checks["state_proof_tracking_advanced_identically"]["ok"])

    def test_tracking_that_differs_between_nodes_fails(self):
        spt = {n: 768 for n in NODES}
        spt["rust-node-4"] = 1024
        checks = by_name(sc.run_checks(fake(spt=spt), NODES, 512, 2))
        self.assertFalse(checks["state_proof_tracking_advanced_identically"]["ok"])

    def test_missing_tracking_everywhere_fails(self):
        checks = by_name(sc.run_checks(fake(), NODES, 512, 2))
        self.assertFalse(checks["state_proof_tracking_advanced_identically"]["ok"])
        self.assertIn("no node exposed", checks["state_proof_tracking_advanced_identically"]["detail"])

    def test_hash_mismatch_between_proof_and_commit_is_caught(self):
        # Mismatch at 520, commit at 530: the whole range is compared, not just the edges.
        hashes = {("rust-node-4", 520): "blk-FORK"}
        checks = by_name(sc.run_checks(fake(hashes=hashes), NODES, 512, 4, 530))
        self.assertFalse(checks["block_hashes_identical_around_proof"]["ok"])
        self.assertIn("520", checks["block_hashes_identical_around_proof"]["detail"])

    def test_find_commit_round_binary_search(self):
        def spt_for(rnd):  # tracking advances at block 540
            return 768 if rnd >= 540 else 512

        def fetch(node, path):
            rnd = int(path.rstrip("/").split("/")[-1])
            return 200, {"block": {"spt": {"0": {"n": spt_for(rnd)}}}}

        self.assertEqual(sc.find_commit_round(fetch, "go-node-1", 512, 600), 540)
        self.assertEqual(sc.find_commit_round(fetch, "go-node-1", 512, 540), 540)
        self.assertIsNone(sc.find_commit_round(fetch, "go-node-1", 512, 539))

    def test_normalized_proof_ignores_key_order_and_extras(self):
        a = sc.normalized_proof({"Message": {"a": 1, "b": 2}, "StateProof": "x", "extra": 1})
        b = sc.normalized_proof({"StateProof": "x", "Message": {"b": 2, "a": 1}})
        self.assertEqual(a, b)
        self.assertIsNone(sc.normalized_proof(None))


if __name__ == "__main__":
    unittest.main()
