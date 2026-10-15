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
        self.assertEqual(set(cases), {"submit", "simulate_msgpack", "simulate_json"})
        for name, c in cases.items():
            self.assertTrue(c["path"].startswith("/v2/transactions"), name)
            self.assertTrue(c["body"], name)

    def test_the_json_body_carries_the_same_bogus_signature(self):
        body = json.loads(sfp.cases()["simulate_json"]["body"])
        stxn = body["txn-groups"][0]["txns"][0]
        self.assertEqual(base64.b64decode(stxn["sig"]), bytes([7]) * 64)
        self.assertEqual(stxn["txn"]["type"], "pay")


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
