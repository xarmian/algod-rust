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

    def test_json_bodies_are_compact_json_with_the_unknown_key_in_stream_order(self):
        cases = sp.json_cases()
        self.assertEqual(set(cases), {"json_request", "json_group", "json_stxn", "json_txn", "json_hgi",
                                      "json_first_wins"})
        for name, (body, key) in cases.items():
            self.assertIn(('"%s":' % key).encode(), body, name)
            self.assertNotIn(b": ", body, name)  # compact separators

    def test_json_offset_is_just_after_the_colon_following_the_key(self):
        # the shape and offsets go reported for the same text (see simulate_strict tests)
        body = b'{"txn-groups":[{"txns":[{"txn":{"type":"pay"},"zzz":1}]}]}'
        status, message = sp.json_expected(body, "zzz")
        self.assertEqual(status, 400)
        self.assertIn("[pos 52]", message)
        self.assertTrue(message.endswith("key zzz"))

    def test_json_first_unknown_key_in_text_order_is_expected(self):
        body, key = sp.json_cases()["json_first_wins"]
        self.assertEqual(key, "aaa")
        self.assertLess(body.index(b'"aaa":'), body.index(b'"ccc":'))

    def test_expectation_is_go_fixed_text_for_every_rejected_body(self):
        for name in ("request", "group", "stxn", "txn", "hgi"):
            self.assertEqual(sp.expected(name), (400, sp.GO_REJECTION), name)
        self.assertEqual(sp.expected("clean"), (400, None))

    def test_compare_reports_status_and_message_differences(self):
        go = (400, '{"message":"m"}\n')
        self.assertEqual(sp.compare("x", go, (400, '{"message":"m"}')), [])
        self.assertTrue(sp.compare("x", go, (200, "{}")))
        self.assertTrue(sp.compare("x", go, (400, '{"message":"n"}')))

    def test_clean_body_only_requires_status_and_no_decode_error(self):
        go = (400, "{" + chr(34) + "message" + chr(34) + ":" + chr(34) + "At least one signature didn" + chr(39) + "t pass verification" + chr(34) + "}")
        rust = (400, '{"message":"simulate: invalid request: validation error: ed25519 signature verification failed"}')
        self.assertEqual(sp.compare("clean", go, rust), [])
        broken = (400, '{"message":"could not decode simulate request: x"}')
        self.assertTrue(sp.compare("clean", go, broken))
        self.assertTrue(sp.compare("clean", broken, rust))
        self.assertTrue(sp.compare("clean", go, (400, "")), "an empty body proves nothing")


if __name__ == "__main__":
    unittest.main()
