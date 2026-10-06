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


class ClassifyDownloadPhaseAllowanceTest(unittest.TestCase):
    """Issue #1650 live dispatch: the catchpoint *file download* leaves every
    counter at zero; a slow relay must not trip the 5-minute stuck rule."""

    def test_all_zero_counters_with_catchpoint_is_downloading(self):
        s = node_catchup(0, acquired=0, processed_accts=0, processed_kvs=0, total_blocks=0, total_accts=0, total_kvs=0)
        self.assertTrue(monitor.is_downloading_signature(s))

    def test_nonzero_total_is_not_downloading(self):
        s = node_catchup(0, acquired=0, processed_accts=10, processed_kvs=0, total_blocks=0, total_accts=1000, total_kvs=0)
        self.assertFalse(monitor.is_downloading_signature(s))

    def test_frozen_download_for_ten_minutes_is_not_stuck(self):
        samples = [
            node_catchup(t, acquired=0, processed_accts=0, processed_kvs=0, total_blocks=0, total_accts=0, total_kvs=0)
            for t in range(0, 600, 10)
        ]
        verdict = monitor.classify(samples, halt_minutes=5.0)
        self.assertEqual(verdict.status, "ok")


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


class ClassifyPostVerifyAllowanceTest(unittest.TestCase):
    """Issue #1663: once import AND verify counters are complete, the node
    still has the lookback block download, the go-catchpoint window replay
    and WAL checkpointing to do (~4 min each on mainnet) with every
    `catchpoint-*` counter frozen. A healthy nightly was killed at ~303s."""

    def _done(self, ts):
        return node_verifying(ts, verified_accts=1000, verified_kvs=200)

    def test_all_counters_complete_is_post_verify(self):
        self.assertTrue(monitor.is_post_verify_signature(self._done(0)))
        self.assertFalse(monitor.is_post_verify_signature(node_verifying(0)))
        self.assertFalse(monitor.is_post_verify_signature(node_catchup(0, total_blocks=0)))
        self.assertFalse(monitor.is_post_verify_signature(node_follow(0, 5)))

    def test_frozen_post_verify_for_eight_minutes_then_follow_is_ok(self):
        samples = [self._done(t) for t in range(0, 480, 10)]
        samples.append(node_follow(480, 50_000_000, peer_round=50_000_010))
        for t in range(490, 560, 10):
            samples.append(node_follow(t, 50_000_000 + (t - 480), peer_round=50_000_100 + t))
        self.assertEqual(monitor.classify(samples).status, "ok")

    def test_frozen_post_verify_eight_minutes_still_catching_up_is_ok(self):
        samples = [self._done(t) for t in range(0, 480, 10)]
        verdict = monitor.classify(samples, halt_minutes=5.0, post_verify_halt_minutes=30.0)
        self.assertEqual(verdict.status, "ok")

    def test_frozen_post_verify_past_allowance_is_stuck(self):
        samples = [self._done(t) for t in range(0, 2000, 10)]
        verdict = monitor.classify(samples, halt_minutes=5.0, post_verify_halt_minutes=30.0)
        self.assertEqual(verdict.status, "stuck")
        self.assertEqual(verdict.phase, "catchup")
        self.assertIn("post-verify", verdict.message)

    def test_frozen_before_verify_completes_keeps_short_threshold(self):
        # Mid-import freeze: not verifying, not post-verify -> 5 min rule.
        samples = [node_catchup(t, acquired=5, processed_accts=10, total_blocks=100,
                                total_accts=1000, total_kvs=200)
                   for t in range(0, 400, 10)]
        verdict = monitor.classify(samples, halt_minutes=5.0, post_verify_halt_minutes=30.0)
        self.assertEqual(verdict.status, "stuck")

    def test_frozen_follow_phase_still_stuck(self):
        samples = [node_follow(t, 100, peer_round=100 + t) for t in range(0, 400, 10)]
        self.assertEqual(monitor.classify(samples).status, "stuck")


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


# --- nodelog: detailed phases, scan, follow window ---------------------------

import nodelog  # noqa: E402

ANSI = "\x1b[2m"
RST = "\x1b[0m"


def L(ts, level, msg, ansi=False):
    t = f"2026-10-04T{ts}Z"
    if ansi:
        return f"{ANSI}{t}{RST} {level} {msg}\n"
    return f"{t} {level:>5} {msg}\n"


PHASE_LOG = [
    L("16:48:42.000000", "INFO", "algod_rust::commands::participate: starting"),
    L("16:49:47.000000", "INFO", "algo_ledger::sync: sync state transition from=Idle to=Downloading ledger snapshot", True),
    L("16:51:20.000000", "INFO", "algo_ledger::sync: sync state transition from=Downloading ledger snapshot to=Importing ledger into database"),
    L("17:09:00.000000", "INFO", "algo_ledger::sync: sync state transition from=Importing ledger into database to=Verifying ledger integrity"),
    L("17:18:00.000000", "INFO", "algo_ledger::catchpoint::verify: catchpoint verify: trie rebuild pending-hashes staged elapsed_s=540.5"),
    L("17:24:00.000000", "INFO", "algo_ledger::catchpoint::verify: catchpoint verify: trie rebuild pending-hashes indexed elapsed_s=900.0"),
    L("17:36:00.000000", "INFO", "algo_ledger::catchpoint::verify: catchpoint verify: trie rebuild complete (final commit done) total_elements_added=1 total_elapsed_s=1620.0"),
    L("17:37:00.000000", "INFO", "algo_ledger::sync: sync state transition from=Verifying ledger integrity to=Downloading lookback blocks"),
    L("17:43:00.000000", "INFO", "algo_ledger::sync: sync state transition from=Downloading lookback blocks to=Replaying blocks"),
    L("17:46:00.000000", "INFO", 'algo_ledger::sync: post-sync WAL checkpoint (PASSIVE): x db="tracker" elapsed_secs=2.8022e-5 result=Some((0, 1, 1))'),
    L("17:46:10.000000", "INFO", 'algo_ledger::sync: post-sync WAL checkpoint (TRUNCATE) db="block" attempt=1 elapsed_secs=0.001 result=None'),
    L("17:48:00.000000", "INFO", "algo_ledger::sync: ledger invariant validation: all checks passed"),
    L("17:48:00.000000", "INFO", "algo_ledger::sync: sync state transition from=Replaying blocks to=Sync complete"),
    L("17:48:00.000100", "INFO", "algo_ledger::sync: catchpoint sync completed elapsed=3493.5s"),
    L("17:52:30.000000", "INFO", 'algo_ledger::sync: WAL checkpoint: (busy, wal frames, checkpointed frames) db="tracker" pragma="PRAGMA wal_checkpoint(PASSIVE)" elapsed_secs=270.0 result=None'),
    L("17:52:35.000000", "INFO", 'algo_ledger::sync: WAL checkpoint: x db="tracker" pragma="TRUNCATE" elapsed_secs=5.0 result=None'),
    # A later, unrelated periodic checkpoint must not extend the chain.
    L("19:00:00.000000", "INFO", 'algo_ledger::sync: WAL checkpoint: x db="tracker" pragma="PASSIVE" elapsed_secs=1.0 result=None'),
]


class PhaseLogTest(unittest.TestCase):
    def test_full_timeline_sums_to_the_covered_window(self):
        d = nodelog.parse_phase_log(PHASE_LOG)
        self.assertEqual(d["startup_s"], 65.0)
        self.assertEqual(d["download_s"], 93.0)
        self.assertEqual(d["import_s"], 1060.0)
        self.assertEqual(d["verify_s"], 1680.0)
        self.assertEqual(d["verify_staging_s"], 540.5)
        self.assertEqual(d["verify_indexing_s"], 359.5)
        self.assertEqual(d["verify_trie_build_s"], 720.0)
        self.assertEqual(d["verify_tail_s"], 60.0)
        self.assertEqual(d["lookback_download_s"], 360.0)
        self.assertEqual(d["replay_s"], 180.0)
        self.assertEqual(d["post_sync_wal_checkpoint_s"], 10.0)
        self.assertEqual(d["invariant_validation_s"], 110.0)
        self.assertEqual(d["final_wal_checkpoint_s"], 275.0)
        self.assertEqual(d["sync_reported_elapsed_s"], 3493.5)
        parts = [
            d[k]
            for k in (
                "download_s",
                "import_s",
                "verify_s",
                "lookback_download_s",
                "replay_s",
                "post_sync_wal_checkpoint_s",
                "invariant_validation_s",
                "final_wal_checkpoint_s",
            )
        ]
        self.assertAlmostEqual(sum(parts), d["catchup_log_total_s"], places=1)
        self.assertEqual(d["sync_attempts"], 1)

    def test_empty_and_garbage_logs_degrade_to_null(self):
        for lines in ([], ["not a log line\n", "\n"]):
            d = nodelog.parse_phase_log(lines)
            self.assertIsNone(d["download_s"])
            self.assertIsNone(d["catchup_log_total_s"])
            self.assertEqual(d["sync_attempts"], 0)

    def test_truncated_log_only_fills_what_it_saw(self):
        d = nodelog.parse_phase_log(PHASE_LOG[:3])
        self.assertEqual(d["download_s"], 93.0)
        self.assertIsNone(d["import_s"])
        self.assertIsNone(d["verify_s"])
        self.assertIsNone(d["final_wal_checkpoint_s"])

    def test_missing_verify_markers_leave_substeps_null(self):
        log = [x for x in PHASE_LOG if "pending-hashes" not in x and "trie rebuild" not in x]
        d = nodelog.parse_phase_log(log)
        self.assertEqual(d["verify_s"], 1680.0)
        self.assertIsNone(d["verify_staging_s"])
        self.assertIsNone(d["verify_tail_s"])

    def test_restarted_sync_uses_final_attempt_and_reports_earlier_time(self):
        second = L("16:50:30.000000", "INFO", "algo_ledger::sync: sync state transition from=Failed to=Downloading ledger snapshot")
        d = nodelog.parse_phase_log(PHASE_LOG[:2] + [second] + PHASE_LOG[2:])
        self.assertEqual(d["sync_attempts"], 2)
        self.assertEqual(d["earlier_attempts_s"], 43.0)
        self.assertEqual(d["download_s"], 50.0)

    def test_build_result_adds_detailed_phases_and_residual(self):
        import tempfile

        with tempfile.TemporaryDirectory() as dd:
            path = os.path.join(dd, "node.log")
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(PHASE_LOG)
            samples = [node_catchup(1000.0), node_follow(1000.0 + 3500.0, 100, 100)]
            samples[0]["node"]["catchpoint"] = "x#y"
            r = monitor.build_result(samples, monitor.classify(samples), 0.0, path)
            d = r["phase_seconds_detailed"]
            self.assertEqual(d["catchup_wall_s"], 3500.0)
            self.assertAlmostEqual(d["unaccounted_s"], 3500.0 - d["catchup_log_total_s"], places=1)
            self.assertEqual(d["download_s"], 93.0)
            missing = monitor.build_result(samples, monitor.classify(samples), 0.0, path + ".nope")
            self.assertIsNone(missing["phase_seconds_detailed"]["download_s"])
            self.assertIsNone(missing["phase_seconds_detailed"]["unaccounted_s"])
            self.assertIn("blocks", r["phase_seconds"] or {"blocks": 0})


NOISE_LINES = [
    L("01:00:00.000000", "WARN", "algo_network::tx_tag_handler: TxTagHandler: pool rejected inbound TX group sender=r-1 error=TransactionPool.Remember: validation error: account X balance 5 below minimum balance 100000"),
    L("01:00:00.000000", "WARN", "algo_network::tx_syncer: TxSyncer sync round failed error=handler rejected transaction group: insufficient balance"),
    L("01:00:00.000000", "WARN", "algo_network::tx_sync_pool_adapter: PoolSolicitedTxHandler: pool rejected pulled TX group error=TransactionPool.ingest: insufficient balance"),
    L("01:00:00.000000", "ERROR", "hickory_proto::dnssec::dnssec_dns_handle: exceeded max validation depth"),
]


class ScanLogTest(unittest.TestCase):
    def test_noise_lines_never_fail_the_job(self):
        scan = nodelog.scan_lines(NOISE_LINES * 5)
        self.assertEqual(scan["hard_total"], 0)
        self.assertEqual(scan["hard"], {})
        self.assertEqual(scan["noise"]["dnssec_max_validation_depth"], 5)
        self.assertEqual(scan["noise"]["gossip_tx_rejections"], 15)

    def _hard(self, lines):
        return nodelog.scan_lines(lines)["hard_failures"]

    def test_each_hard_signature_is_detected(self):
        cases = {
            "permanent_error_writing_block": L("01:00:00.000000", "ERROR", "algo_ledger::agreement_bridge: ensure_block: permanent error writing block 5 to ledger: boom"),
            "apply_block_failed": L("01:00:00.000000", "WARN", "algod_rust::commands::node: follow: apply_block failed round=5"),
            "panic": L("01:00:00.000000", "ERROR", "thread 'tokio-runtime-worker' panicked at src/x.rs:1:1:"),
            "invariant_check_error": L("01:00:00.000000", "ERROR", "algo_ledger::sync: invariant check: error name=x detail=y"),
            "resource_temporarily_unavailable": L("01:00:00.000000", "ERROR", "io: Resource temporarily unavailable (os error 11)"),
            "shadow_execute_mismatch": L("01:00:00.000000", "WARN", "algo_ledger::shadow_execute: shadow_execute_mismatch round=7 diffs=1 [account txn=0 field=micro_algos replay=1 execute=2]"),
            "block_apply_balance_error": L("01:00:00.000000", "WARN", "algo_ledger::apply: account Z balance 3 below minimum balance 100000 while applying block 9"),
        }
        for key, line in cases.items():
            self.assertEqual(self._hard([line]), {key: 1}, key)

    def test_shadow_mismatch_with_balance_text_counts_once(self):
        line = L("01:00:00.000000", "WARN", "algo_ledger::shadow_execute: shadow_execute_mismatch round=7 diffs=1 [execute_error execute=below minimum balance]")
        self.assertEqual(self._hard([line]), {"shadow_execute_mismatch": 1})

    def test_shadow_rate_limited_summary_is_not_a_hard_mismatch(self):
        line = L("01:00:00.000000", "WARN", "algo_ledger::shadow_execute: shadow_execute_mismatch kind=rate_limited suppressed_lines=12")
        scan = nodelog.scan_lines([line])
        self.assertEqual(scan["hard_failures"], {})
        self.assertEqual(scan["warn"], {"shadow_execute_rate_limited": 1})

    def test_shadow_execute_error_with_panic_text_counts_once(self):
        line = L("01:00:00.000000", "WARN", "algo_ledger::shadow_execute: shadow_execute_mismatch round=7 diffs=1 [execute_error field=error replay=ok execute=shadow Execute evaluation panicked; apply_block failed]")
        self.assertEqual(self._hard([line]), {"shadow_execute_mismatch": 1})

    def test_shadow_unsupported_store_is_hard(self):
        line = L("01:00:00.000000", "WARN", "algo_ledger::shadow_execute: shadow_execute_unsupported_store: this store cannot roll back")
        self.assertEqual(self._hard([line]), {"shadow_execute_unsupported_store": 1})

    def test_shadow_progress_with_nothing_checked_is_hard(self):
        line = L("01:00:00.000000", "INFO", "algo_ledger::shadow_execute: shadow_execute_progress state_checked_blocks=0 state_mismatched_blocks=0 state_skipped_unsupported_store=100 state_avg_check_us=0 apply_data_compared_blocks=0 apply_data_compared_txns=0")
        self.assertEqual(self._hard([line]), {"shadow_execute_nothing_verified": 1})

    def test_shadow_progress_with_checked_blocks_is_clean(self):
        for tail in ("state_checked_blocks=5 state_mismatched_blocks=0 apply_data_compared_blocks=0 x=1",
                     "state_checked_blocks=0 state_mismatched_blocks=0 apply_data_compared_blocks=7 x=1"):
            line = L("01:00:00.000000", "INFO", "algo_ledger::shadow_execute: shadow_execute_progress " + tail)
            self.assertEqual(self._hard([line]), {}, tail)

    def test_shadow_progress_line_is_not_hard(self):
        line = L("01:00:00.000000", "INFO", "algo_ledger::shadow_execute: shadow_execute_progress checked=1000 mismatched_blocks=0")
        self.assertEqual(self._hard([line]), {})

    def test_ansi_coloured_lines_match(self):
        line = L("01:00:00.000000", "ERROR", "algo_ledger::agreement_bridge: ensure_block: permanent error writing block 1", True)
        self.assertIn("permanent_error_writing_block", self._hard([line]))

    def test_ensure_block_not_advancing_needs_repetition(self):
        line = L("01:00:00.000000", "WARN", "catchup: ensure_block round=9 did not advance")
        self.assertEqual(self._hard([line]), {})
        self.assertEqual(self._hard([line] * 3), {"ensure_block_not_advancing": 3})

    def test_invariant_info_and_passed_lines_are_not_hard(self):
        scan = nodelog.scan_lines(
            [
                L("01:00:00.000000", "INFO", "algo_ledger::sync: ledger invariant validation: all checks passed"),
                L("01:00:00.000000", "INFO", "algo_ledger::sync: invariant check: info name=x"),
                L("01:00:00.000000", "WARN", "algo_ledger::sync: invariant check: warning name=x"),
            ]
        )
        self.assertEqual(scan["hard_total"], 0)
        self.assertEqual(scan["warn"], {"invariant_check_warning": 1})

    def test_group_id_mismatch_is_a_counted_warning_with_distinct_proposals(self):
        def gid(stored):
            return L(
                "01:00:00.000000",
                "WARN",
                "algo_agreement::demux: dropping proposal with a transaction group that fails "
                f"group-ID verification: validation error: group ID mismatch: stored {stored} != computed {'f' * 64} len=1",
            )

        scan = nodelog.scan_lines([gid("a" * 64), gid("a" * 64), gid("b" * 64)])
        self.assertEqual(scan["hard_total"], 0)
        self.assertEqual(scan["warn"]["proposal_group_id_mismatch"], 3)
        self.assertEqual(scan["proposal_group_id_mismatch_distinct"], 2)

    def test_missing_log_file_is_not_an_error(self):
        scan = nodelog.scan_file("/definitely/not/here.log")
        self.assertFalse(scan["log_found"])
        self.assertEqual(scan["hard_total"], 0)

    def test_scan_log_cli_merges_into_summary_and_sets_exit_code(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as dd:
            log = os.path.join(dd, "node.log")
            summ = os.path.join(dd, "summary.json")
            with open(summ, "w") as f:
                json.dump({"status": "ok"}, f)
            with open(log, "w", encoding="utf-8") as f:
                f.writelines(NOISE_LINES)
            self.assertEqual(monitor.main(["scan-log", log, "--summary", summ]), 0)
            with open(summ) as f:
                self.assertEqual(json.load(f)["log_scan"]["hard_total"], 0)
            with open(log, "a", encoding="utf-8") as f:
                f.write("thread 'x' panicked at y\n")
            self.assertEqual(monitor.main(["scan-log", log, "--summary", summ]), 1)
            with open(summ) as f:
                d = json.load(f)
            self.assertEqual(d["status"], "ok")
            self.assertEqual(d["log_scan"]["hard_failures"], {"panic": 1})

    def test_render_markdown_lists_hits(self):
        scan = nodelog.scan_lines(NOISE_LINES + ["thread 'x' panicked at y\n"])
        md = nodelog.render_markdown({"log_scan": scan})
        self.assertIn("1 hard signature", md)
        self.assertIn("`panic`", md)


class FollowWindowTest(unittest.TestCase):
    def _collect(self, node, peer, **kw):
        import tempfile

        orig = monitor.take_sample
        monitor.take_sample = lambda *a, **k: {"ts": time.time(), "node": dict(node), "peer": dict(peer)}
        try:
            with tempfile.TemporaryDirectory() as d:
                t0 = time.time()
                v = monitor.collect(
                    node_url="n",
                    node_token="",
                    peer_url="p",
                    peer_token="",
                    halt_minutes=5.0,
                    poll_interval_s=0.02,
                    out_path=os.path.join(d, "o.jsonl"),
                    **kw,
                )
                return v, time.time() - t0
        finally:
            monitor.take_sample = orig

    def test_follow_window_ends_the_run_after_first_tip(self):
        node = {"ok": True, "catchpoint": None, "last_round": 100}
        peer = {"ok": True, "last_round": 100}
        v, took = self._collect(node, peer, duration_s=30.0, follow_s=0.3)
        self.assertEqual(v.status, "ok")
        self.assertGreaterEqual(took, 0.3)
        self.assertLess(took, 3.0)

    def test_follow_zero_runs_until_the_duration_cap(self):
        node = {"ok": True, "catchpoint": None, "last_round": 100}
        peer = {"ok": True, "last_round": 100}
        _v, took = self._collect(node, peer, duration_s=0.5, follow_s=0.0)
        self.assertGreaterEqual(took, 0.5)

    def test_duration_is_the_hard_cap_when_the_tip_is_never_reached(self):
        node = {"ok": True, "catchpoint": None, "last_round": 10}
        peer = {"ok": True, "last_round": 100}
        _v, took = self._collect(node, peer, duration_s=0.4, follow_s=0.05)
        self.assertGreaterEqual(took, 0.4)

    def test_duration_cap_wins_over_a_longer_follow_window(self):
        node = {"ok": True, "catchpoint": None, "last_round": 100}
        peer = {"ok": True, "last_round": 100}
        _v, took = self._collect(node, peer, duration_s=0.4, follow_s=60.0)
        self.assertLess(took, 3.0)

    def test_build_result_reports_follow_window_and_lag(self):
        t0 = 1000.0
        samples = [node_catchup(t0)]
        samples[0]["node"]["catchpoint"] = "x#y"
        samples += [node_follow(t0 + 100 + i * 10, 500 + i, 500 + i) for i in range(31)]
        r = monitor.build_result(samples, monitor.classify(samples), 5.0)
        self.assertEqual(r["follow"]["requested_s"], 300.0)
        self.assertEqual(r["follow"]["observed_s"], 300.0)
        self.assertEqual(r["follow"]["time_to_tip_s"], 100.0)
        self.assertTrue(r["follow"]["completed"])
        self.assertEqual(r["lag_rounds"]["n"], 31)
        self.assertNotIn("follow", monitor.build_result(samples, monitor.classify(samples)))


if __name__ == "__main__":
    unittest.main()
