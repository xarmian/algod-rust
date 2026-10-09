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
from cert_window import cert_from  # noqa: E402


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
        self.assertEqual(cert_from(1, 2702, None, 100, 0), (1, ""))
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
        self.assertEqual(lo, 50)


if __name__ == "__main__":
    unittest.main()
