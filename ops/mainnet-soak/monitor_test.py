#!/usr/bin/env python3

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for issue #1598's mainnet-soak verdict logic (`monitor.py`).

Run directly (no pytest dependency), or via `monitor.py self-test`:

    python3 ops/mainnet-soak/monitor_test.py

Every case below is pure over synthetic sample lists -- no network I/O, no
live node -- so the workflow can trust `classify()`'s verdict before ever
running it against a real 60-minute mainnet soak.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import monitor  # noqa: E402


def node_catchup(ts, acquired=0, processed_accts=0, processed_kvs=0, verified_accts=0, verified_kvs=0):
    return {
        "ts": ts,
        "node": {
            "ok": True,
            "catchpoint": "40000000#AAAA",
            "catchpoint_acquired_blocks": acquired,
            "catchpoint_processed_accounts": processed_accts,
            "catchpoint_processed_kvs": processed_kvs,
            "catchpoint_verified_accounts": verified_accts,
            "catchpoint_verified_kvs": verified_kvs,
            "last_round": 0,
        },
        "peer": {"ok": True, "last_round": 40000000 + int(ts)},
    }


def node_follow(ts, round_, peer_round=None):
    return {
        "ts": ts,
        "node": {"ok": True, "catchpoint": None, "last_round": round_},
        "peer": {"ok": True, "last_round": peer_round if peer_round is not None else round_},
    }


class ClassifyStuckDuringCatchupTest(unittest.TestCase):
    """(a) Frozen catchpoint counters, peer healthy and advancing -> stuck,
    phase=catchup, round = the frozen acquired-blocks count."""

    def test_frozen_catchpoint_counters_with_advancing_peer_is_stuck(self):
        samples = [node_catchup(0, acquired=100)]
        # Peer advances every second; node's catchpoint counters freeze at
        # t=0 and never move again, for 400s (> the 300s default halt).
        for t in range(1, 400, 10):
            s = node_catchup(t, acquired=100)
            samples.append(s)
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "stuck")
        self.assertEqual(verdict.phase, "catchup")
        self.assertEqual(verdict.round, 100)
        self.assertIsNotNone(verdict.stalled_since_s)
        self.assertGreaterEqual(verdict.stalled_since_s, 300)

    def test_advancing_catchpoint_counters_are_not_stuck(self):
        samples = []
        for i, t in enumerate(range(0, 400, 10)):
            samples.append(node_catchup(t, acquired=i * 5))
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "ok")
        self.assertEqual(verdict.phase, "catchup")


class ClassifyStuckDuringFollowTest(unittest.TestCase):
    """(b) Frozen last-round after catch-up while the peer advances ->
    stuck, phase=follow."""

    def test_frozen_round_with_advancing_peer_is_stuck(self):
        samples = [node_follow(0, round_=50_000_000)]
        for t in range(1, 400, 10):
            samples.append(node_follow(t, round_=50_000_000, peer_round=50_000_000 + t))
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "stuck")
        self.assertEqual(verdict.phase, "follow")
        self.assertEqual(verdict.round, 50_000_000)


class ClassifySourceOutageTest(unittest.TestCase):
    """(c) Same freeze, but the peer is unreachable / its own tip is also
    frozen -> source_outage, never an issue."""

    def test_peer_unreachable_throughout_is_source_outage_not_stuck(self):
        samples = [
            {
                "ts": t,
                "node": {"ok": True, "catchpoint": None, "last_round": 50_000_000},
                "peer": {"ok": False, "error": "connection refused", "last_round": None},
            }
            for t in range(0, 400, 10)
        ]
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "source_outage")
        self.assertEqual(verdict.round, 50_000_000)

    def test_peer_reachable_but_its_own_tip_frozen_is_source_outage(self):
        samples = [
            node_follow(t, round_=50_000_000, peer_round=61_234_567)
            for t in range(0, 400, 10)
        ]
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "source_outage")

    def test_transient_peer_blip_inside_an_otherwise_advancing_window_is_not_outage(self):
        samples = [node_follow(0, round_=50_000_000, peer_round=50_000_000)]
        samples.append(
            {
                "ts": 10,
                "node": {"ok": True, "catchpoint": None, "last_round": 50_000_000},
                "peer": {"ok": False, "error": "timeout", "last_round": None},
            }
        )
        for t in range(20, 400, 10):
            samples.append(node_follow(t, round_=50_000_000, peer_round=50_000_000 + t))
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "stuck")


class ClassifyNodeFailureTest(unittest.TestCase):
    """(d) The node process/REST is unreachable at the end of the stream ->
    node_failure, with the last observed round and an error excerpt."""

    def test_node_unreachable_at_stream_end_is_node_failure(self):
        samples = [node_follow(0, round_=50_000_000)]
        samples.append(node_follow(10, round_=50_000_010))
        samples.append(
            {
                "ts": 20,
                "node": {"ok": False, "error": "connection refused"},
                "peer": {"ok": True, "last_round": 50_000_020},
            }
        )
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "node_failure")
        self.assertEqual(verdict.round, 50_000_010)
        self.assertIn("connection refused", verdict.message)

    def test_node_unreachable_at_stream_start_with_no_prior_round(self):
        samples = [{"ts": 0, "node": {"ok": False, "error": "startup failed"}, "peer": {"ok": True}}]
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "node_failure")
        self.assertIsNone(verdict.round)

    def test_a_recovered_mid_stream_blip_is_not_a_node_failure(self):
        samples = [node_follow(0, round_=50_000_000)]
        samples.append({"ts": 10, "node": {"ok": False, "error": "timeout"}, "peer": {"ok": True, "last_round": 50_000_010}})
        samples.append(node_follow(20, round_=50_000_020))
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "ok")


class ClassifyHealthyRunTest(unittest.TestCase):
    """(e) Healthy run -> exit 0, with throughput/timing stats from
    `summarize()`."""

    def test_healthy_catchup_then_follow_reports_fast_catchup_and_lag(self):
        samples = []
        for i, t in enumerate(range(0, 100, 10)):
            samples.append(node_catchup(t, acquired=i * 10, processed_accts=i * 5))
        catchup_end = 100
        samples.append(
            {
                "ts": catchup_end,
                "node": {"ok": True, "catchpoint": None, "last_round": 50_000_000},
                "peer": {"ok": True, "last_round": 50_000_001},
            }
        )
        for t in range(110, 200, 10):
            samples.append(node_follow(t, round_=50_000_000 + (t - catchup_end), peer_round=50_000_000 + (t - catchup_end)))

        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "ok")

        summary = monitor.summarize(samples)
        self.assertAlmostEqual(summary["fast_catchup_seconds"], 100.0, delta=0.01)
        self.assertTrue(summary["reached_tip"])
        self.assertGreater(summary["lag_rounds"]["n"], 0)
        self.assertIn("blocks", summary["phase_seconds"])
        self.assertIn("accounts", summary["phase_seconds"])

    def test_still_catching_up_at_budget_end_with_continuous_progress_is_ok(self):
        # Ran out of the CI time budget while still downloading -- must NOT
        # be classified as stuck, since progress never stopped.
        samples = [node_catchup(t, acquired=t) for t in range(0, 3600, 10)]
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "ok")
        summary = monitor.summarize(samples)
        self.assertIsNone(summary["fast_catchup_seconds"])
        self.assertFalse(summary["reached_tip"])


class ExitCodeTest(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(monitor.exit_code_for(monitor.Verdict("ok", None, None, "", None)), 0)
        self.assertEqual(monitor.exit_code_for(monitor.Verdict("stuck", "follow", 1, "", 1)), 1)
        self.assertEqual(monitor.exit_code_for(monitor.Verdict("node_failure", None, None, "", None)), 1)
        self.assertEqual(monitor.exit_code_for(monitor.Verdict("source_outage", "follow", 1, "", 1)), 2)


class NoSamplesTest(unittest.TestCase):
    def test_empty_sample_list_is_ok(self):
        verdict = monitor.classify([], halt_minutes=5.0)
        self.assertEqual(verdict.status, "ok")
        summary = monitor.summarize([])
        self.assertIsNone(summary["fast_catchup_seconds"])
        self.assertFalse(summary["reached_tip"])


class CollectEarlyStopTest(unittest.TestCase):
    """`collect()`'s live loop must stop as soon as `classify()` on the
    samples-so-far reports non-ok, rather than burning the full duration
    -- and must treat `process_alive() -> False` as an immediate
    node_failure sample without waiting for a failed poll."""

    def test_collect_stops_early_on_dead_process(self):
        import tempfile

        calls = {"n": 0}

        def fake_take_ok(*_a, **_kw):
            calls["n"] += 1
            return {"ok": True, "catchpoint": None, "last_round": 1000 + calls["n"]}

        orig_fetch = monitor.fetch_status
        monitor.fetch_status = lambda *a, **kw: fake_take_ok()
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "out.jsonl")
                verdict = monitor.collect(
                    node_url="http://node",
                    node_token="",
                    peer_url="http://peer",
                    peer_token="",
                    duration_s=3600,
                    halt_minutes=5.0,
                    poll_interval_s=0.01,
                    out_path=out,
                    process_alive=lambda: calls["n"] < 3,
                )
                self.assertEqual(verdict.status, "node_failure")
                with open(out) as f:
                    lines = [l for l in f if l.strip()]
                # Stopped promptly, nowhere near the 3600s budget's sample count.
                self.assertLess(len(lines), 20)
        finally:
            monitor.fetch_status = orig_fetch


if __name__ == "__main__":
    unittest.main()
