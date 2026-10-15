#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for simulate_parity.py (issues #1967, #1968).  No cluster needed."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import simulate_parity as sp  # noqa: E402


class BodiesTest(unittest.TestCase):
    def test_every_body_is_a_msgpack_map_with_the_expected_unknown_key(self):
        bodies = sp.bodies()
        self.assertEqual(set(bodies), {"clean", "request", "group", "stxn", "txn", "hgi"})
        for name, body in bodies.items():
            self.assertEqual(body[0] & 0xF0, 0x80, name)  # fixmap
        self.assertNotIn(b"zzz", bodies["clean"])
        for name in ("request", "group", "stxn", "txn"):
            self.assertIn(b"\xa3zzz", bodies[name], name)
        self.assertIn(b"\xa3hgi", bodies["hgi"])

    def test_expectation_is_go_fixed_text_for_every_rejected_body(self):
        for name in ("request", "group", "stxn", "txn", "hgi"):
            self.assertEqual(sp.expected(name), (400, sp.GO_REJECTION), name)
        self.assertEqual(sp.expected("clean"), (400, "At least one signature didn't pass verification"))

    def test_compare_reports_status_and_message_differences(self):
        go = (400, '{"message":"m"}\n')
        self.assertEqual(sp.compare("x", go, (400, '{"message":"m"}')), [])
        self.assertTrue(sp.compare("x", go, (200, "{}")))
        self.assertTrue(sp.compare("x", go, (400, '{"message":"n"}')))


if __name__ == "__main__":
    unittest.main()
