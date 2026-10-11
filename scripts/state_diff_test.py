#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for state_diff.py, the public-node vs local-node divergence tool (issue #1771)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import state_diff as sd  # noqa: E402


def acct(**kw):
    base = {
        "address": "AAA",
        "amount": 1000,
        "min-balance": 100000,
        "status": "Offline",
        "round": 10,
        "assets": [{"asset-id": 5, "amount": 7, "is-frozen": False}],
        "apps-local-state": [{"id": 9, "schema": {"num-uint": 1, "num-byte-slice": 0}}],
        "created-apps": [{"id": 9, "params": {"global-state-schema": {"num-uint": 1}}}],
    }
    base.update(kw)
    return base


class DiffAccounts(unittest.TestCase):
    def test_identical_accounts_have_no_diff(self):
        self.assertEqual(sd.diff_accounts(acct(), acct()), [])

    def test_ignores_round_and_indexer_only_fields(self):
        # The indexer wraps the account and stamps extra bookkeeping fields.
        pub = acct(**{"deleted": False, "created-at-round": 1, "round": 99})
        self.assertEqual(sd.diff_accounts(pub, acct()), [])

    def test_scalar_difference_is_reported(self):
        out = sd.diff_accounts(acct(amount=1000), acct(amount=999))
        self.assertEqual(len(out), 1)
        self.assertIn("amount", out[0])
        self.assertIn("1000", out[0])
        self.assertIn("999", out[0])

    def test_list_order_is_irrelevant_keyed_by_id(self):
        a = acct(assets=[{"asset-id": 1, "amount": 1}, {"asset-id": 2, "amount": 2}])
        b = acct(assets=[{"asset-id": 2, "amount": 2}, {"asset-id": 1, "amount": 1}])
        self.assertEqual(sd.diff_accounts(a, b), [])

    def test_missing_and_changed_list_entries(self):
        a = acct(assets=[{"asset-id": 1, "amount": 1}, {"asset-id": 2, "amount": 2}])
        b = acct(assets=[{"asset-id": 2, "amount": 3}])
        out = "\n".join(sd.diff_accounts(a, b))
        self.assertIn("assets[1]", out)
        self.assertIn("only in public", out)
        self.assertIn("assets[2]", out)

    def test_zero_valued_fields_equal_absent(self):
        # algod omits zero values; indexer may emit them.
        self.assertEqual(sd.diff_accounts(acct(**{"total-boxes": 0}), acct()), [])



if __name__ == "__main__":
    unittest.main()
