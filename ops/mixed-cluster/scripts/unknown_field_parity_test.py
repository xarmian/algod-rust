#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for unknown_field_parity.py (issue #1962).  No cluster needed."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unknown_field_parity as up  # noqa: E402

# Offsets captured from a real go-algorand v5.0.3-stable node for these bodies.
GO_POS = {"top": 226, "txn": 156, "lsig": 169, "msig": 216, "pqsig": 171,
          "group_ok_top": 448, "group_top_ok": 226, "group_ok_txn": 378,
          "hgi": 5, "hgh": 5, "ca": 4, "apid": 6, "both": 5}


class BodiesTest(unittest.TestCase):
    def test_every_body_puts_its_unknown_key_where_go_reported_it(self):
        bodies = up.bodies()
        self.assertEqual(set(bodies), set(GO_POS))
        for name, (body, key) in bodies.items():
            end = body.index(bytes([0xA0 + len(key)]) + key.encode()) + 1 + len(key)
            self.assertEqual(end, GO_POS[name], name)

    def test_expected_message_matches_go_text(self):
        self.assertEqual(
            up.expected_message(226, "zzz"),
            "msgpack decode error [pos 226]: no matching struct field found when decoding stream map with key zzz")

    def test_compare_requires_identical_status_and_message(self):
        go = (400, '{"message":"m"}\n')
        self.assertEqual(up.compare("x", go, (400, '{"message":"m"}')), [])
        self.assertTrue(up.compare("x", go, (400, '{"message":"other"}')))
        self.assertTrue(up.compare("x", go, (200, '{"txId":"T"}')))

    def test_message_of_reads_the_json_message_or_raw_text(self):
        self.assertEqual(up.message_of('{"message":"abc"}\n'), "abc")
        self.assertEqual(up.message_of("plain"), "plain")


if __name__ == "__main__":
    unittest.main()
