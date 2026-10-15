#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for sig_failure_parity.py (issue #1969).  No cluster needed."""
import base64
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sig_failure_parity as sfp  # noqa: E402


class AddressTest(unittest.TestCase):
    def test_address_is_base32_of_key_plus_checksum(self):
        key = bytes([1]) * 32
        addr = sfp.address(key)
        self.assertEqual(len(addr), 58)
        raw = base64.b32decode(addr + "======")
        self.assertEqual(raw[:32], key)
        self.assertEqual(raw[32:], hashlib.new("sha512_256", key).digest()[-4:])


class BodiesTest(unittest.TestCase):
    def test_every_case_has_a_body_a_path_and_a_content_type(self):
        cases = sfp.cases()
        self.assertEqual(set(cases), {"submit", "simulate_msgpack", "simulate_json",
                                      "submit_early", "submit_dead", "submit_bad_sig_and_early"})
        for name, c in cases.items():
            self.assertTrue(c["path"].startswith("/v2/transactions"), name)
            self.assertTrue(c["body"], name)

    def test_the_json_body_carries_the_same_bogus_signature(self):
        body = json.loads(sfp.cases()["simulate_json"]["body"])
        stxn = body["txn-groups"][0]["txns"][0]
        self.assertEqual(base64.b64decode(stxn["sig"]), bytes([7]) * 64)
        self.assertEqual(stxn["txn"]["type"], "pay")


class WindowCasesTest(unittest.TestCase):
    def test_bodies_are_signed_by_the_seed_account_and_the_bogus_one_is_not(self):
        import ed25519_py as ed
        good = sfp.window_cases()["submit_early"][0]
        bad = sfp.window_cases()["submit_bad_sig_and_early"][0]
        pk = ed.public_key(sfp.SEED)
        self.assertIn(pk, good)
        self.assertIn(pk, bad)
        # the txn bytes are identical; only the signature differs
        self.assertNotEqual(good, bad)
        self.assertIn(bytes([7]) * 64, bad)
        self.assertNotIn(bytes([7]) * 64, good)

    def test_the_round_of_a_txn_dead_message_is_normalised(self):
        msg = "TransactionPool.Remember: txn dead: round 17 outside of 500--900"
        self.assertEqual(sfp.normalise(msg), "TransactionPool.Remember: txn dead: round N outside of 500--900")
        self.assertTrue(sfp.DEAD_RE.match(msg))

    def test_expectations(self):
        self.assertEqual(sfp.expected_message("submit"), sfp.GO_MESSAGE)
        self.assertEqual(sfp.expected_message("submit_bad_sig_and_early"), sfp.GO_MESSAGE)
        self.assertIn("500--900", sfp.expected_message("submit_early"))


class KnownGapsTest(unittest.TestCase):
    def test_known_gaps_name_real_cases_and_an_issue(self):
        for name, why in sfp.KNOWN_GAPS.items():
            self.assertIn(name, sfp.cases())
            self.assertRegex(why, r"^#[0-9]+: ")


class CompareTest(unittest.TestCase):
    GO = "At least one signature didn't pass verification"

    def test_identical_answers_pass(self):
        r = (400, json.dumps({"message": self.GO}))
        self.assertEqual(sfp.compare("x", r, r), [])

    def test_a_different_message_fails(self):
        go = (400, json.dumps({"message": self.GO}))
        rust = (400, json.dumps({"message": "simulate: invalid request: validation error: ed25519 signature verification failed"}))
        self.assertTrue(sfp.compare("x", go, rust))


if __name__ == "__main__":
    unittest.main()
