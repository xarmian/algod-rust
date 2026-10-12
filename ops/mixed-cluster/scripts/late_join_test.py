#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for late_join.py (issue #1821): the pure planning/parsing logic."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import late_join as lj  # noqa: E402


class Lookback(unittest.TestCase):
    def test_balance_lookback_is_two_seed_refresh_times_seed_lookback(self):
        # crates/core/algo-agreement/src/lookback.rs; go agreement/selector.go
        self.assertEqual(lj.balance_lookback({"SeedLookback": 2, "SeedRefreshInterval": 80}), 320)
        self.assertEqual(lj.balance_lookback({"SeedLookback": 3, "SeedRefreshInterval": 100}), 600)

    def test_activation_round_is_keyreg_round_plus_lookback(self):
        self.assertEqual(lj.activation_round(keyreg_round=140, lookback=320), 460)


class Stake(unittest.TestCase):
    def test_late_joiner_gets_a_tenth_of_supply_by_default(self):
        self.assertEqual(lj.stake_amount(total_money=10_000_000_000, percent=10), 1_000_000_000)

    def test_rejects_absurd_percent(self):
        for bad in (0, -1, 51, 100):
            with self.assertRaises(ValueError):
                lj.stake_amount(10_000, bad)


class Parsing(unittest.TestCase):
    def test_extract_confirmed_round(self):
        out = "Sent 1000 MicroAlgos from account A to address B, transaction ID: T. Fee set to 1000\nTransaction T still pending as of round 41\nTransaction T committed in round 42\n"
        self.assertEqual(lj.committed_round(out), 42)

    def test_committed_round_missing(self):
        self.assertIsNone(lj.committed_round("error: nope"))

    def test_count_votes_by_sender_in_go_logs(self):
        acct = "ABC"
        lines = [
            '{"Type":"VoteAccepted","Sender":"ABC","ObjectRound":10,"ObjectStep":2}',
            '{"Type":"VoteAccepted","Sender":"XYZ","ObjectRound":10,"ObjectStep":2}',
            '{"Type":"VoteAccepted","Sender":"ABC","ObjectRound":501,"ObjectStep":2}',
            'not json ABC VoteAccepted',
        ]
        self.assertEqual(lj.votes_by_round(lines, acct), {10: 1, 501: 1})

    def test_votes_before_and_after_activation(self):
        votes = {10: 1, 459: 2, 460: 1, 500: 3}
        before, after = lj.split_votes(votes, activation=460)
        self.assertEqual(before, 3)   # rounds < 460
        self.assertEqual(after, 4)    # rounds >= 460


if __name__ == "__main__":
    unittest.main()
