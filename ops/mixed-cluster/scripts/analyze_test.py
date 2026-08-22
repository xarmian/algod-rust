#!/usr/bin/env python3
"""Unit tests for the issue #470 verifier logic added to analyze.py.

Run directly (no pytest dependency):

    python3 ops/mixed-cluster/scripts/analyze_test.py
    # or
    make consensus-analyzer-test

The TDD requirement in issue #470 is "each new verifier assertion first
demonstrated failing against a recorded soak from the *non*-participating
topology (or a doctored dataset), then passing on the participating one".
Every check below therefore has BOTH a negative case built from the
observer topology's data shape (Rust address absent from the proposer
histogram / no attest lines in the log) and a positive case built from
the real numbers observed on the participating cluster.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import analyze  # noqa: E402

# The 30/30/30/10 template.json split: three Go accounts and the Rust one.
GO1 = "A" * 58
GO2 = "B" * 58
GO3 = "C" * 58
RUST = "GACNGSR26F4WW5CDFQ2MOFWEUN2BVAVNBI5OCOV7LRHIE2KSWIV22PKQC4"

ANALYZE_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analyze.py")


class ProposerShareTest(unittest.TestCase):
    """#470 §1 — proposer-share statistics."""

    def test_observer_topology_zero_rust_proposals_fails(self):
        """Negative case: the pre-#469 observer topology.

        The Rust node held no participation keys, so its address never
        appears in the proposer histogram at all. That MUST fail, and
        must fail on the explicit zero gate rather than only on sigma.
        """
        hist = {GO1: 70, GO2: 65, GO3: 65}
        res = analyze.proposer_share_check(hist, RUST, 0.10, 3.0)
        self.assertFalse(res["ok"])
        self.assertEqual(res["rust_proposals"], 0)
        self.assertEqual(len(res["failures"]), 1)
        self.assertIn("ZERO", res["failures"][0])

    def test_real_participating_run_passes(self):
        """Positive case: the actual #482 soak — 13 of 200 at p=0.10.

        mu = 20, sd = 4.243, z = -1.65. Must pass at the 3σ default.
        """
        hist = {GO1: 64, GO2: 62, GO3: 61, RUST: 13}
        self.assertEqual(sum(hist.values()), 200)
        res = analyze.proposer_share_check(hist, RUST, 0.10, 3.0)
        self.assertTrue(res["ok"], res["failures"])
        self.assertEqual(res["rust_proposals"], 13)
        self.assertAlmostEqual(res["expected"], 20.0)
        self.assertAlmostEqual(res["sd"], 4.2426, places=3)
        self.assertAlmostEqual(res["z"], -1.6499, places=3)
        self.assertFalse(res["normal_approx_weak"])

    def test_two_sigma_would_have_flagged_the_real_run(self):
        """Documents *why* the default is 3 sigma and not 2 sigma."""
        hist = {GO1: 64, GO2: 62, GO3: 61, RUST: 13}
        res2 = analyze.proposer_share_check(hist, RUST, 0.10, 2.0)
        self.assertTrue(res2["ok"], "2 sigma still accepts z=-1.65, but barely")
        self.assertLess(abs(res2["z"]), 2.0)
        self.assertLess(2.0 - abs(res2["z"]), 0.36, "only 0.35 sigma of headroom")
        # Two fewer wins on the same 200-round window and a 2-sigma gate
        # would have failed a healthy run: 11/200 gives z = -2.12.
        hist_two_less = {GO1: 66, GO2: 62, GO3: 61, RUST: 11}
        res3 = analyze.proposer_share_check(hist_two_less, RUST, 0.10, 2.0)
        self.assertFalse(res3["ok"])
        # The same data is comfortably inside the 3-sigma default.
        res4 = analyze.proposer_share_check(hist_two_less, RUST, 0.10, 3.0)
        self.assertTrue(res4["ok"], res4["failures"])

    def test_over_proposing_also_fails(self):
        """The bound is two-sided: a 50% share at p=0.10 is a bug too."""
        hist = {GO1: 50, GO2: 25, GO3: 25, RUST: 100}
        res = analyze.proposer_share_check(hist, RUST, 0.10, 3.0)
        self.assertFalse(res["ok"])
        self.assertIn("out of bound", res["failures"][0])
        self.assertGreater(res["z"], 3.0)

    def test_small_sample_flags_weak_normal_approximation(self):
        hist = {GO1: 27, RUST: 3}
        res = analyze.proposer_share_check(hist, RUST, 0.10, 3.0)
        self.assertTrue(res["normal_approx_weak"])
        self.assertTrue(res["ok"], res["failures"])

    def test_no_proposer_data_fails_rather_than_dividing_by_zero(self):
        res = analyze.proposer_share_check({}, RUST, 0.10, 3.0)
        self.assertFalse(res["ok"])
        self.assertIsNone(res["observed_fraction"])
        self.assertIn("no blocks", res["failures"][0])

    def test_malformed_stake_fraction_rejected(self):
        for bad in (0.0, 1.0, -0.5, 2.0):
            res = analyze.proposer_share_check({GO1: 10, RUST: 1}, RUST, bad, 3.0)
            self.assertFalse(res["ok"], f"stake_fraction={bad} should be rejected")
            self.assertIn("stake-fraction", res["failures"][0])


class ParticipationLogTest(unittest.TestCase):
    """#470 §3 — vote-step coverage parsed from the Rust node log."""

    # Verbatim shape of a real line (ANSI escapes included, as they
    # survive `docker logs > file`).
    ATTEST_LINE = (
        "2026-08-22T13:37:52.276556Z \x1b[32m INFO\x1b[0m "
        "algo_agreement::service: attested to ProposalValue {{ "
        "original_period: Period(0), original_proposer: Address(3004d34a3af1796b), "
        "block_digest: Digest(99194c69), encoding_digest: Digest(648df563) }} "
        "at ({round}, {period}, {step})"
    )

    def line(self, rnd, period, step):
        return self.ATTEST_LINE.format(round=rnd, period=period, step=step)

    def test_observer_topology_log_has_no_attests(self):
        """Negative case: a node with no partkeys never attests."""
        text = "\n".join(
            [
                "2026-08-22T13:37:23Z  INFO algod_rust: starting consensus participation",
                "2026-08-22T13:37:25Z  INFO algo_agreement::player: round start round=10",
                "2026-08-22T13:37:27Z  INFO algo_agreement::service: committed round 10",
            ]
        )
        parsed = analyze.parse_rust_participation_log(text)
        self.assertEqual(parsed["attests_total"], 0)
        check = analyze.step_coverage_check(parsed, ["soft", "cert"])
        self.assertFalse(check["ok"])
        self.assertIn("no 'attested to", check["failures"][0])

    def test_soft_and_cert_coverage_passes(self):
        text = "\n".join(
            [self.line(r, 0, "soft") for r in range(100, 110)]
            + [self.line(r, 0, "cert") for r in range(100, 110)]
        )
        parsed = analyze.parse_rust_participation_log(text)
        self.assertEqual(parsed["attests_total"], 20)
        self.assertEqual(parsed["steps"], {"soft": 10, "cert": 10})
        self.assertEqual(parsed["rounds_attested"], 10)
        self.assertEqual(parsed["first_round"], 100)
        self.assertEqual(parsed["last_round"], 109)
        self.assertEqual(parsed["period_advanced_rounds"], [])
        check = analyze.step_coverage_check(parsed, ["soft", "cert"])
        self.assertTrue(check["ok"], check["failures"])
        self.assertFalse(check["period_advancement_observed"])

    def test_cert_only_log_fails_the_soft_requirement(self):
        text = "\n".join(self.line(r, 0, "cert") for r in range(100, 110))
        parsed = analyze.parse_rust_participation_log(text)
        check = analyze.step_coverage_check(parsed, ["soft", "cert"])
        self.assertFalse(check["ok"])
        self.assertEqual(check["missing_steps"], ["soft"])

    def test_next_step_and_period_advancement_detected(self):
        text = "\n".join(
            [
                self.line(200, 0, "soft"),
                self.line(200, 0, "cert"),
                self.line(200, 0, "next"),
                self.line(200, 1, "soft"),
                self.line(200, 1, "cert"),
            ]
        )
        parsed = analyze.parse_rust_participation_log(text)
        self.assertEqual(parsed["period_advanced_rounds"], [200])
        self.assertEqual(parsed["periods"], {0: 3, 1: 2})
        check = analyze.step_coverage_check(parsed, ["soft", "cert", "next"])
        self.assertTrue(check["ok"], check["failures"])
        self.assertTrue(check["period_advancement_observed"])

    def test_next_plus_n_satisfies_a_next_requirement(self):
        """Step's Display renders steps > 3 as `next+N`."""
        text = "\n".join(
            [
                self.line(300, 0, "soft"),
                self.line(300, 0, "cert"),
                self.line(300, 2, "next+2"),
            ]
        )
        parsed = analyze.parse_rust_participation_log(text)
        self.assertIn("next+2", parsed["steps"])
        check = analyze.step_coverage_check(parsed, ["soft", "cert", "next"])
        self.assertTrue(check["ok"], check["failures"])

    def test_reproposals_counted(self):
        text = (
            "INFO algo_agreement::service: repropose to ProposalValue { x } "
            "at (400, 1, propose)"
        )
        parsed = analyze.parse_rust_participation_log(text)
        self.assertEqual(parsed["reproposals"], 1)
        self.assertEqual(parsed["period_advanced_rounds"], [400])

    def test_malformed_input_does_not_raise(self):
        for junk in ("", "\x00\x01\x02", "attested to at (,,)", "at (1, 2, )"):
            parsed = analyze.parse_rust_participation_log(junk)
            self.assertEqual(parsed["attests_total"], 0)


class CadenceTest(unittest.TestCase):
    """#470 §4 — block cadence gate."""

    def test_disabled_by_default(self):
        res = analyze.cadence_check({"n": 5, "mean": 99.0, "p95": 120.0}, 0.0, 0.0)
        self.assertTrue(res["ok"])

    def test_mean_and_p95_bounds(self):
        bt = {"n": 199, "mean": 2.6, "p95": 3.4}
        self.assertTrue(analyze.cadence_check(bt, 5.0, 6.0)["ok"])
        self.assertFalse(analyze.cadence_check(bt, 2.0, 0.0)["ok"])
        self.assertFalse(analyze.cadence_check(bt, 0.0, 3.0)["ok"])

    def test_no_samples_but_bound_requested_fails(self):
        res = analyze.cadence_check({"n": 0, "mean": None, "p95": None}, 5.0, 0.0)
        self.assertFalse(res["ok"])
        self.assertIn("no consecutive block pairs", res["failures"][0])


class EndToEndCliTest(unittest.TestCase):
    """Drive analyze.py as a subprocess over a synthetic JSONL soak."""

    def _write_soak(self, path, rust_proposals, total=40):
        recs = [
            {"kind": "run_meta", "phase": "start"},
            {
                "kind": "run_meta",
                "phase": "baseline",
                "start_max_round": 0,
                "target_max_round": total,
                "start_round_by_node": {"go-node-1": 0},
                "nodes_rest": ["go-node-1"],
            },
        ]
        for r in range(1, total + 1):
            proposer = RUST if r <= rust_proposals else GO1
            recs.append(
                {
                    "kind": "node_round",
                    "round": r,
                    "node": "go-node-1",
                    "commit_ts_utc": "2026-08-22T13:00:{:02d}+00:00".format(r % 60),
                }
            )
            recs.append(
                {
                    "kind": "node_round",
                    "round": r,
                    "node": "go-node-2",
                    "commit_ts_utc": "2026-08-22T13:00:{:02d}+00:00".format(r % 60),
                }
            )
            recs.append(
                {
                    "kind": "block",
                    "round": r,
                    "proposer": proposer,
                    "block_ts_unix": 1000 + 3 * r,
                }
            )
        recs.append(
            {"kind": "run_meta", "phase": "target_reached", "total_elapsed_s": 1.0}
        )
        with open(path, "w") as f:
            for rec in recs:
                f.write(json.dumps(rec) + "\n")

    def _run(self, soak_path, extra):
        return subprocess.run(
            [sys.executable, ANALYZE_PY, soak_path] + extra,
            capture_output=True,
            text=True,
        )

    def test_cli_fails_on_zero_rust_proposals_and_passes_with_them(self):
        with tempfile.TemporaryDirectory() as d:
            none_path = os.path.join(d, "observer.jsonl")
            some_path = os.path.join(d, "participating.jsonl")
            self._write_soak(none_path, rust_proposals=0)
            self._write_soak(some_path, rust_proposals=4)

            bad = self._run(none_path, ["--rust-account", RUST])
            self.assertEqual(bad.returncode, 1, bad.stdout)
            self.assertIn("ZERO", bad.stdout)

            good = self._run(some_path, ["--rust-account", RUST])
            self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
            self.assertIn("Rust proposer share", good.stdout)

            with open(some_path + ".summary.json") as f:
                sidecar = json.load(f)
            self.assertTrue(sidecar["acceptance_ok"])
            self.assertEqual(sidecar["rust_proposer_share"]["rust_proposals"], 4)
            self.assertTrue(sidecar["cadence"]["ok"])

    def test_cli_cadence_gate(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.jsonl")
            self._write_soak(path, rust_proposals=4)
            # Blocks are 3s apart by construction.
            ok = self._run(path, ["--max-mean-block-time", "5"])
            self.assertEqual(ok.returncode, 0, ok.stdout)
            bad = self._run(path, ["--max-mean-block-time", "2"])
            self.assertEqual(bad.returncode, 1, bad.stdout)

    def test_cli_missing_rust_log_reports_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.jsonl")
            self._write_soak(path, rust_proposals=4)
            res = self._run(path, ["--rust-log", os.path.join(d, "nope.log")])
            self.assertEqual(res.returncode, 2)
            self.assertIn("cannot read --rust-log", res.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2, buffer=isinstance(sys.stdout, io.TextIOBase))
