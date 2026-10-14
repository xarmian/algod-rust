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


def by_name(checks):
    return {c["name"]: c for c in checks}


class CheckTest(unittest.TestCase):
    def test_all_identical_passes(self):
        checks = by_name(sc.run_checks(fake(spt={n: 768 for n in NODES}), NODES, 512, 4))
        for name, c in checks.items():
            self.assertTrue(c["ok"], (name, c))
        self.assertIn("state_proof_tracking_advanced", checks)

    def test_missing_proof_on_one_node_fails_both_proof_checks(self):
        proofs = {n: PROOF for n in NODES}
        del proofs["rust-node-4"]
        checks = by_name(sc.run_checks(fake(proofs=proofs), NODES, 512, 2))
        self.assertFalse(checks["state_proof_served_by_every_node"]["ok"])
        self.assertIn("rust-node-4", checks["state_proof_served_by_every_node"]["detail"])
        self.assertFalse(checks["state_proof_identical_on_every_node"]["ok"])

    def test_divergent_proof_bytes_fail(self):
        proofs = {n: PROOF for n in NODES}
        proofs["rust-node-4"] = dict(PROOF, StateProof="CCCC")
        checks = by_name(sc.run_checks(fake(proofs=proofs), NODES, 512, 2))
        self.assertTrue(checks["state_proof_served_by_every_node"]["ok"])
        self.assertFalse(checks["state_proof_identical_on_every_node"]["ok"])
        self.assertIn("2 distinct", checks["state_proof_identical_on_every_node"]["detail"])

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
        self.assertFalse(checks["state_proof_tracking_advanced"]["ok"])

    def test_normalized_proof_ignores_key_order_and_extras(self):
        a = sc.normalized_proof({"Message": {"a": 1, "b": 2}, "StateProof": "x", "extra": 1})
        b = sc.normalized_proof({"StateProof": "x", "Message": {"b": 2, "a": 1}})
        self.assertEqual(a, b)
        self.assertIsNone(sc.normalized_proof(None))


if __name__ == "__main__":
    unittest.main()
