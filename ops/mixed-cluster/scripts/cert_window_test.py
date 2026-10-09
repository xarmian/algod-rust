#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for cert_window.py (issue #1777).  No Docker, no network.

    python3 ops/mixed-cluster/scripts/cert_window_test.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cert_window import cert_from, retain_margin, DEFAULT_UNKNOWN_WINDOW  # noqa: E402


class CertWindow(unittest.TestCase):
    def test_archival_run_covers_everything(self):
        # Archival Rust node keeps round 1: nothing is clamped.
        self.assertEqual(cert_from(1, 2702, 1, 100, 0), (1, ""))

    def test_short_run_unaffected(self):
        self.assertEqual(cert_from(1, 300, 1, 100, 0), (1, ""))

    def test_non_archival_long_run_starts_at_retained_round(self):
        # The #1777 shape: 2702 rounds, ~1001 retained.
        lo, why = cert_from(1, 2702, 1702, 100, 0)
        self.assertEqual(lo, 1802)
        self.assertIn("retains blocks from round 1702", why)

    def test_unknown_earliest_falls_back_to_explicit_window_only(self):
        lo, why = cert_from(1, 2702, None, 100, 900)
        self.assertEqual(lo, 1802)
        self.assertIn("CERT_WINDOW=900", why)

    def test_explicit_window_narrower_than_retention_wins(self):
        lo, why = cert_from(1, 2702, 1702, 100, 300)
        self.assertEqual(lo, 2402)
        self.assertIn("CERT_WINDOW=300", why)
        self.assertIn("retains blocks", why)

    def test_window_wider_than_range_is_not_a_clamp(self):
        self.assertEqual(cert_from(1, 500, 1, 100, 900), (1, ""))

    def test_requested_from_already_inside_retention(self):
        self.assertEqual(cert_from(2000, 2702, 1702, 100, 0), (2000, ""))

    def test_never_beyond_to_round(self):
        lo, _ = cert_from(1, 50, 49, 100, 0)
        self.assertLessEqual(lo, 50)

    def test_margin_is_derived_from_the_lookback_formula(self):
        # agreement/lookback.rs: BalanceLookback = 2 * SeedRefreshInterval *
        # SeedLookback (= 320 at v41: 80, 2). A cert at round r also needs the
        # seed round (<= SeedRefreshInterval + SeedLookback back). + 20 slack.
        self.assertEqual(retain_margin(2, 80), 2 * 80 * 2 + 80 + 2 + 20)
        self.assertEqual(retain_margin(2, 80), 422)
        self.assertEqual(retain_margin(3, 100, slack=0), 600 + 103)

    def test_margin_defaults_match_the_rust_consensus_table(self):
        import re
        here = os.path.dirname(os.path.abspath(__file__))
        src = os.path.join(here, "..", "..", "..", "crates", "core", "algo-types", "src", "consensus.rs")
        if not os.path.exists(src):
            self.skipTest("consensus.rs not present")
        text = open(src, encoding="utf-8").read()
        self.assertRegex(text, r"seed_lookback: 2,")
        self.assertTrue(re.search(r"v8\.seed_refresh_interval = 80;", text))

    def test_unknown_earliest_defaults_to_last_900_and_says_so(self):
        lo, why = cert_from(1, 2702, None, 422, 0)
        self.assertEqual(lo, 2702 - DEFAULT_UNKNOWN_WINDOW)
        self.assertIn("earliest unknown", why)

    def test_unknown_earliest_uses_explicit_window(self):
        lo, why = cert_from(1, 2702, None, 422, 300)
        self.assertEqual(lo, 2402)
        self.assertIn("earliest unknown", why)
        self.assertIn("CERT_WINDOW=300", why)

    def test_unknown_earliest_short_run_still_flags_clamp_free_range(self):
        # Range already inside the default window: nothing to clamp, but the
        # unknown earliest is still reported.
        lo, why = cert_from(1, 300, None, 422, 0)
        self.assertEqual(lo, 1)
        self.assertIn("earliest unknown", why)

    def test_empty_range_after_clamp_is_flagged(self):
        lo, why = cert_from(1, 50, 49, 100, 0)
        self.assertEqual(lo, 50)
        self.assertIn("empty", why)

    def test_from_after_to_is_flagged(self):
        lo, why = cert_from(900, 100, 1, 100, 0)
        self.assertEqual(lo, 100)
        self.assertIn("empty", why)


if __name__ == "__main__":
    unittest.main()
