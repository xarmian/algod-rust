#!/usr/bin/env python3

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for the issue #471 equivocation detector.

These are the negative controls for the cluster suite: before the
restart-rejoin scenarios are allowed to report "no equivocation", the
detector has to be shown to actually *catch* a double vote. Without
these, a green `no_equivocation_rust` check could just mean the regex
never matched anything.

Run: python3 ops/mixed-cluster/scripts/equivocation_test.py
"""

import unittest

from equivocation import scan

ADDR = "3004d34a3af1796b"


def attest(rnd, period, step, block_digest, encoding_digest=None):
    """One `attested to ...` line in the exact shape the node emits."""
    enc = encoding_digest or ("f" * 64)
    return (
        "2026-08-22T14:44:33.024815Z  INFO algo_agreement::service: "
        "attested to ProposalValue {{ original_period: Period(0), "
        "original_proposer: Address({addr}), block_digest: Digest({bd}), "
        "encoding_digest: Digest({ed}) }} at ({r}, {p}, {s})"
    ).format(addr=ADDR, bd=block_digest, ed=enc, r=rnd, p=period, s=step)


class DetectorTest(unittest.TestCase):
    def test_clean_log_is_ok(self):
        log = "\n".join(
            [
                attest(100, 0, "soft", "aa" * 32),
                attest(100, 0, "cert", "aa" * 32),
                attest(101, 0, "soft", "bb" * 32),
            ]
        )
        result = scan([log])
        self.assertTrue(result["ok"])
        self.assertEqual(result["attests_scanned"], 3)
        self.assertEqual(result["coordinates"], 3)
        self.assertEqual(result["first_round"], 100)
        self.assertEqual(result["last_round"], 101)

    def test_double_vote_at_one_coordinate_is_caught(self):
        """THE test: two different block digests at (100, 0, soft)."""
        log = "\n".join(
            [
                attest(100, 0, "soft", "aa" * 32),
                attest(100, 0, "soft", "cc" * 32),
            ]
        )
        result = scan([log])
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["equivocations"]), 1)
        conflict = result["equivocations"][0]
        self.assertEqual((conflict["round"], conflict["period"], conflict["step"]),
                         (100, 0, "soft"))
        self.assertEqual(len(conflict["values"]), 2)

    def test_same_value_twice_is_a_replay_not_an_equivocation(self):
        """Crash recovery legitimately replays the persisted attest."""
        line = attest(100, 0, "soft", "aa" * 32)
        result = scan(["\n".join([line, line, line])])
        self.assertTrue(result["ok"])
        self.assertEqual(result["attests_scanned"], 3)
        self.assertEqual(result["coordinates"], 1)

    def test_differing_encoding_digest_alone_is_caught(self):
        """Same block, two encodings, one coordinate — still a double vote."""
        log = "\n".join(
            [
                attest(7, 1, "cert", "aa" * 32, encoding_digest="11" * 32),
                attest(7, 1, "cert", "aa" * 32, encoding_digest="22" * 32),
            ]
        )
        self.assertFalse(scan([log])["ok"])

    def test_same_value_at_different_steps_is_fine(self):
        log = "\n".join(
            [
                attest(5, 0, "soft", "aa" * 32),
                attest(5, 0, "cert", "aa" * 32),
                attest(5, 1, "soft", "dd" * 32),
                attest(5, 0, "next", "00" * 32),
            ]
        )
        self.assertTrue(scan([log])["ok"])

    def test_different_values_in_different_periods_is_fine(self):
        """Period advancement legitimately changes what the node votes for."""
        log = "\n".join(
            [
                attest(9, 0, "soft", "aa" * 32),
                attest(9, 1, "soft", "bb" * 32),
                attest(9, 2, "soft", "cc" * 32),
            ]
        )
        self.assertTrue(scan([log])["ok"])

    def test_ansi_coloured_lines_are_parsed(self):
        raw = (
            "\x1b[2m2026-08-22T14:44:33.024815Z\x1b[0m \x1b[32m INFO\x1b[0m "
            "\x1b[2malgo_agreement::service\x1b[0m\x1b[2m:\x1b[0m " + attest(3, 0, "soft", "ab" * 32)
        )
        result = scan([raw])
        self.assertEqual(result["attests_scanned"], 1)

    def test_next_plus_n_steps_are_distinct_coordinates(self):
        log = "\n".join(
            [
                attest(4, 0, "next", "aa" * 32),
                attest(4, 0, "next+1", "bb" * 32),
            ]
        )
        self.assertTrue(scan([log])["ok"])

    def test_conflict_spanning_two_log_files_is_caught(self):
        """Pre-restart and post-restart captures scanned together."""
        before = attest(50, 0, "soft", "aa" * 32)
        after = attest(50, 0, "soft", "bb" * 32)
        result = scan([before, after])
        self.assertFalse(result["ok"])

    def test_empty_input_reports_zero_and_no_false_pass(self):
        result = scan([""])
        self.assertEqual(result["attests_scanned"], 0)
        self.assertIsNone(result["first_round"])
        # `ok` is vacuously true here, which is exactly why the shell
        # caller separately requires attests_scanned > 0 before treating
        # a pass as meaningful.
        self.assertTrue(result["ok"])

    def test_unrelated_log_noise_is_ignored(self):
        log = "\n".join(
            [
                "INFO some other subsystem: attested to nothing in particular",
                "WARN pseudonode.make_votes failed for reproposal(attest): boom",
                attest(1, 0, "soft", "aa" * 32),
            ]
        )
        result = scan([log])
        self.assertEqual(result["attests_scanned"], 1)
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
