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
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import monitor  # noqa: E402


def node_catchup(
    ts,
    acquired=0,
    processed_accts=0,
    processed_kvs=0,
    verified_accts=0,
    verified_kvs=0,
    total_blocks=None,
    total_accts=None,
    total_kvs=None,
):
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
            "catchpoint_total_blocks": total_blocks,
            "catchpoint_total_accounts": total_accts,
            "catchpoint_total_kvs": total_kvs,
            "last_round": 0,
        },
        "peer": {"ok": True, "last_round": 40000000 + int(ts)},
    }


def node_verifying(ts, total_blocks=100, total_accts=1000, total_kvs=200, verified_accts=0, verified_kvs=0):
    """A sample shaped like the real `run_verify_ledger` window (issue
    #1623): import counters fully caught up to their totals, verify
    counters not yet (or just-frozen partway)."""
    return node_catchup(
        ts,
        acquired=total_blocks,
        processed_accts=total_accts,
        processed_kvs=total_kvs,
        verified_accts=verified_accts,
        verified_kvs=verified_kvs,
        total_blocks=total_blocks,
        total_accts=total_accts,
        total_kvs=total_kvs,
    )


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


class IsVerifyingSignatureTest(unittest.TestCase):
    def test_import_done_verify_not_done_is_verifying(self):
        s = node_verifying(0, verified_accts=0, verified_kvs=0)
        self.assertTrue(monitor.is_verifying_signature(s))

    def test_still_importing_is_not_verifying(self):
        s = node_catchup(0, acquired=50, processed_accts=500, processed_kvs=100, total_blocks=100, total_accts=1000, total_kvs=200)
        self.assertFalse(monitor.is_verifying_signature(s))

    def test_verify_also_done_is_not_verifying(self):
        s = node_verifying(0, verified_accts=1000, verified_kvs=200)
        self.assertFalse(monitor.is_verifying_signature(s))

    def test_no_catchpoint_is_not_verifying(self):
        s = node_follow(0, round_=50_000_000)
        self.assertFalse(monitor.is_verifying_signature(s))

    def test_missing_totals_is_not_verifying(self):
        # No total_* fields known -- can't tell import is actually done, so
        # this must not get the longer allowance.
        s = node_catchup(0, acquired=100, processed_accts=1000, processed_kvs=200)
        self.assertFalse(monitor.is_verifying_signature(s))


class ClassifyVerifyPhaseAllowanceTest(unittest.TestCase):
    """Issue #1623: a frozen catchpoint signature that looks like the
    single-shot `run_verify_ledger` window must NOT be classified as a
    halt within the default 5-minute `halt_minutes`, but must still be
    classified as `stuck` once it exceeds the longer, finite
    `verify_halt_minutes` allowance."""

    def test_frozen_verify_counters_within_verify_allowance_is_ok(self):
        # Import fully done, verify counters frozen at 0 for 400s -- past
        # the default 5-minute halt_minutes, but well inside the default
        # 45-minute verify_halt_minutes.
        samples = [node_verifying(0)]
        for t in range(1, 400, 10):
            samples.append(node_verifying(t))
        verdict = monitor.classify(samples, halt_minutes=5.0, verify_halt_minutes=45.0)
        self.assertEqual(verdict.status, "ok")
        self.assertEqual(verdict.phase, "catchup")

    def test_frozen_verify_counters_past_verify_allowance_is_stuck(self):
        samples = [node_verifying(0)]
        for t in range(1, 3000, 10):
            samples.append(node_verifying(t))
        verdict = monitor.classify(samples, halt_minutes=5.0, verify_halt_minutes=45.0)
        self.assertEqual(verdict.status, "stuck")
        self.assertEqual(verdict.phase, "catchup")
        self.assertIn("verify-phase allowance", verdict.message)

    def test_verify_phase_then_final_jump_and_follow_is_ok(self):
        # Realistic shape: import completes, verify counters sit frozen at
        # 0 for a while (< verify_halt_minutes), then jump straight to the
        # final counts (the actual non-incremental behavior), then follow
        # mode proceeds normally.
        samples = [node_verifying(t) for t in range(0, 400, 10)]
        samples.append(node_verifying(400, verified_accts=1000, verified_kvs=200))
        samples.append(
            {
                "ts": 410,
                "node": {"ok": True, "catchpoint": None, "last_round": 50_000_000},
                "peer": {"ok": True, "last_round": 50_000_000},
            }
        )
        for t in range(420, 500, 10):
            samples.append(node_follow(t, round_=50_000_000 + (t - 410), peer_round=50_000_000 + (t - 410)))
        verdict = monitor.classify(samples, halt_minutes=5.0, verify_halt_minutes=45.0)
        self.assertEqual(verdict.status, "ok")

    def test_verify_looking_freeze_still_needs_advancing_peer_to_be_stuck_not_outage(self):
        # Past the verify allowance, but the peer itself never proves the
        # network was alive -> source_outage, not stuck (same priority
        # rule as every other phase).
        samples = [
            {
                "ts": t,
                "node": node_verifying(t)["node"],
                "peer": {"ok": False, "error": "connection refused", "last_round": None},
            }
            for t in range(0, 3000, 10)
        ]
        verdict = monitor.classify(samples, halt_minutes=5.0, verify_halt_minutes=45.0)
        self.assertEqual(verdict.status, "source_outage")


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


class CollectUnreachableGraceTest(unittest.TestCase):
    """Issue #1623 live dispatch (run 36204923591): the node's REST
    endpoint went genuinely unreachable (timed out) during/after the
    non-incremental verify pass under CI-runner CPU contention. A live
    `collect()` loop must not treat a single unreachable poll (process
    still alive) as an immediate NODE_FAILURE -- it needs a grace window
    to reconnect, longer if the last known-good sample looked like the
    verify window."""

    def _run_collect(self, scripted, **kwargs):
        import itertools
        import tempfile

        it = iter(scripted)
        tail = scripted[-1]

        def fake_take_sample(*_a, **_kw):
            nonlocal it
            try:
                s = next(it)
            except StopIteration:
                s = tail
            return {"ts": time.time(), "node": s["node"], "peer": s["peer"]}

        orig = monitor.take_sample
        monitor.take_sample = fake_take_sample
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "out.jsonl")
                return monitor.collect(
                    node_url="http://node",
                    node_token="",
                    peer_url="http://peer",
                    peer_token="",
                    out_path=out,
                    process_alive=lambda: True,
                    **kwargs,
                )
        finally:
            monitor.take_sample = orig

    def test_transient_unreachable_poll_recovering_within_grace_is_not_failure(self):
        unreachable = {"node": {"ok": False, "error": "timeout"}, "peer": {"ok": True, "last_round": 101}}
        scripted = (
            [{"node": {"ok": True, "catchpoint": None, "last_round": 100}, "peer": {"ok": True, "last_round": 100}}]
            + [unreachable] * 3
            + [{"node": {"ok": True, "catchpoint": None, "last_round": 105}, "peer": {"ok": True, "last_round": 105}}]
        )
        verdict = self._run_collect(
            scripted,
            duration_s=0.4,
            halt_minutes=5.0,
            verify_halt_minutes=0.05,
            unreachable_grace_minutes=0.05,
            poll_interval_s=0.02,
        )
        self.assertEqual(verdict.status, "ok")

    def test_unreachable_past_generic_grace_is_node_failure(self):
        scripted = [
            {"node": {"ok": True, "catchpoint": None, "last_round": 100}, "peer": {"ok": True, "last_round": 100}},
            {"node": {"ok": False, "error": "timeout"}, "peer": {"ok": True, "last_round": 200}},
        ]
        verdict = self._run_collect(
            scripted,
            duration_s=1.0,
            halt_minutes=5.0,
            verify_halt_minutes=0.05,
            unreachable_grace_minutes=0.01,
            poll_interval_s=0.02,
        )
        self.assertEqual(verdict.status, "node_failure")

    def test_unreachable_after_verify_signature_gets_the_longer_verify_allowance(self):
        verifying_ok = {
            "node": {
                "ok": True,
                "catchpoint": "40000000#AAAA",
                "catchpoint_acquired_blocks": 100,
                "catchpoint_processed_accounts": 1000,
                "catchpoint_processed_kvs": 200,
                "catchpoint_verified_accounts": 0,
                "catchpoint_verified_kvs": 0,
                "catchpoint_total_blocks": 100,
                "catchpoint_total_accounts": 1000,
                "catchpoint_total_kvs": 200,
                "last_round": 0,
            },
            "peer": {"ok": True, "last_round": 40000100},
        }
        unreachable = {"node": {"ok": False, "error": "timeout"}, "peer": {"ok": True, "last_round": 40000200}}
        scripted = [verifying_ok, unreachable]
        # Past the short generic grace, but well inside the longer verify
        # allowance -- must still be tolerated, not classified as a halt.
        verdict = self._run_collect(
            scripted,
            duration_s=0.3,
            halt_minutes=5.0,
            verify_halt_minutes=10.0,
            unreachable_grace_minutes=0.001,
            poll_interval_s=0.02,
        )
        self.assertEqual(verdict.status, "ok")

    def test_confirmed_dead_process_is_never_given_the_grace_window(self):
        # Sanity: process_alive() -> False must still fail immediately,
        # exactly as before this change (covered directly in
        # CollectEarlyStopTest, re-asserted here against the new grace
        # bookkeeping too).
        import tempfile

        calls = {"n": 0}
        monitor_fetch_orig = monitor.fetch_status
        monitor.fetch_status = lambda *a, **kw: {"ok": True, "catchpoint": None, "last_round": 1}
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "out.jsonl")
                verdict = monitor.collect(
                    node_url="http://node",
                    node_token="",
                    peer_url="http://peer",
                    peer_token="",
                    duration_s=10.0,
                    halt_minutes=5.0,
                    verify_halt_minutes=45.0,
                    unreachable_grace_minutes=45.0,
                    poll_interval_s=0.01,
                    out_path=out,
                    process_alive=lambda: (calls.__setitem__("n", calls["n"] + 1), calls["n"] < 2)[1],
                )
                self.assertEqual(verdict.status, "node_failure")
        finally:
            monitor.fetch_status = monitor_fetch_orig


if __name__ == "__main__":
    unittest.main()
