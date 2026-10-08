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
import nodelog  # noqa: E402


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


def _hist_text(name, buckets, total, sum_s):
    """Render one histogram exactly as the node's /metrics does."""
    fam = "algod_rust_follow_block_%s_seconds" % name
    lines = ["# HELP %s help" % fam, "# TYPE %s histogram" % fam]
    for le, cum in buckets:
        lines.append('%s_bucket{le="%s"} %d' % (fam, le, cum))
    lines.append('%s_bucket{le="+Inf"} %d' % (fam, total))
    lines.append("%s_sum %s" % (fam, sum_s))
    lines.append("%s_count %d" % (fam, total))
    return "\n".join(lines) + "\n"


def _exposition(counts):
    """counts: {key: (bucket_list, total, sum)}"""
    return "algod_rust_other_metric 4\n" + "".join(
        _hist_text(k, b, t, s) for k, (b, t, s) in counts.items()
    )


class FollowTimingTest(unittest.TestCase):
    """Issue #1678: follow-path histograms and lag percentiles in summary.json."""

    BOUNDS = [0.001, 0.01, 0.1, 1.0, 10.0]

    def _timing(self, cums, total, sum_s):
        return monitor.parse_follow_timing(
            _exposition({"apply": (list(zip(self.BOUNDS, cums)), total, sum_s)})
        )

    def test_parse_extracts_cumulative_buckets_count_and_sum(self):
        t = self._timing([0, 5, 9, 10, 10], 10, 0.9)
        self.assertEqual(set(t), {"apply"})
        self.assertEqual(t["apply"]["count"], 10)
        self.assertAlmostEqual(t["apply"]["sum"], 0.9)
        self.assertEqual(t["apply"]["buckets"][1], [0.01, 5.0])
        self.assertEqual(len(t["apply"]["buckets"]), 5)  # +Inf folded into count

    def test_parse_ignores_incomplete_families(self):
        text = 'algod_rust_follow_block_avm_seconds_bucket{le="1"} 3\n'
        self.assertEqual(monitor.parse_follow_timing(text), {})

    def test_summary_reports_p50_p95_max_as_bucket_upper_bounds(self):
        t0 = 1000.0
        s0 = node_catchup(t0)
        s0["node"]["catchpoint"] = "x#y"
        samples = [s0] + [node_follow(t0 + 100 + i * 10, 500 + i, 500 + i) for i in range(5)]
        # 10 blocks: 5 <=10ms, 4 <=100ms, 1 in (1s,10s].
        samples[-1]["follow_timing"] = self._timing([0, 5, 9, 9, 10], 10, 12.0)
        r = monitor.summarize(samples)
        a = r["follow_block_timing"]["apply"]
        self.assertEqual(a["count"], 10)
        self.assertEqual(a["p50_s"], 0.01)
        self.assertEqual(a["p95_s"], 10.0)
        self.assertEqual(a["max_s"], 10.0)
        self.assertAlmostEqual(a["mean_s"], 1.2)

    def test_summary_uses_the_delta_since_the_first_tip_scrape(self):
        t0 = 1000.0
        samples = [node_follow(t0 + i * 10, 500 + i, 500 + i) for i in range(4)]
        # Before the follow window: one 10 s block already counted.
        samples[0]["follow_timing"] = self._timing([0, 0, 0, 0, 1], 1, 10.0)
        samples[3]["follow_timing"] = self._timing([0, 3, 4, 4, 5], 5, 10.04)
        a = monitor.summarize(samples)["follow_block_timing"]["apply"]
        self.assertEqual(a["baseline"], "delta")
        self.assertFalse(a["restarted"])
        self.assertEqual(a["count"], 4)
        self.assertEqual(a["max_s"], 0.1)
        self.assertEqual(a["p95_s"], 0.1)

    def test_overflow_bucket_reports_last_finite_bound(self):
        samples = [node_follow(1.0, 5, 5)]
        samples[0]["follow_timing"] = self._timing([0, 0, 0, 0, 0], 2, 90.0)
        a = monitor.summarize(samples)["follow_block_timing"]["apply"]
        self.assertEqual(a["max_s"], 10.0)

    def test_no_scrape_yields_empty_timing_and_json_serialisable_result(self):
        import json

        r = monitor.summarize([node_follow(1.0, 5, 5)])
        self.assertEqual(r["follow_block_timing"], {})
        samples = [node_follow(1.0, 5, 5)]
        samples[0]["follow_timing"] = self._timing([1, 1, 1, 1, 1], 1, 0.0005)
        json.dumps(monitor.build_result(samples, monitor.classify(samples)))

    def test_lag_rounds_gain_p50_and_p99(self):
        samples = [node_follow(i * 10.0, 500 + i, 500 + i + (50 if i == 99 else i % 2)) for i in range(100)]
        lag = monitor.summarize(samples)["lag_rounds"]
        self.assertEqual(lag["n"], 100)
        self.assertEqual(lag["p50"], 1)
        self.assertEqual(lag["max"], 50)
        self.assertIn("p99", lag)
        self.assertEqual(monitor.summarize([])["lag_rounds"]["p50"], None)

    def test_baseline_that_is_the_last_scrape_falls_back_to_absolute(self):
        # Only the final scrape is at/after the tip: subtracting it from
        # itself would give count 0 and all-None percentiles.
        samples = [node_follow(1000.0 + i * 10, 500 + i, 500 + i) for i in range(3)]
        samples[2]["follow_timing"] = self._timing([0, 5, 9, 9, 10], 10, 12.0)
        a = monitor.summarize(samples)["follow_block_timing"]["apply"]
        self.assertEqual(a["baseline"], "absolute")
        self.assertFalse(a["restarted"])
        self.assertEqual(a["count"], 10)
        self.assertEqual(a["p95_s"], 10.0)

    def test_single_scrape_is_absolute(self):
        samples = [node_follow(1.0, 5, 5)]
        samples[0]["follow_timing"] = self._timing([1, 1, 1, 1, 1], 1, 0.0005)
        a = monitor.summarize(samples)["follow_block_timing"]["apply"]
        self.assertEqual((a["baseline"], a["count"]), ("absolute", 1))

    def _restart_case(self, first, second):
        samples = [node_follow(1000.0 + i * 10, 500 + i, 500 + i) for i in range(3)]
        samples[0]["follow_timing"] = first
        samples[2]["follow_timing"] = second
        return monitor.summarize(samples)["follow_block_timing"]["apply"]

    def test_restart_detected_when_count_goes_backwards(self):
        a = self._restart_case(
            self._timing([0, 5, 9, 9, 10], 10, 12.0), self._timing([0, 1, 1, 1, 1], 1, 0.005)
        )
        self.assertTrue(a["restarted"])
        self.assertEqual((a["baseline"], a["count"]), ("absolute", 1))

    def test_restart_detected_when_a_single_bucket_goes_backwards(self):
        # Count and sum grew, but the 0.01 s bucket shrank (5 -> 2): a
        # restart that then outgrew the old totals must still be caught.
        a = self._restart_case(
            self._timing([0, 5, 6, 6, 6], 6, 1.0), self._timing([0, 2, 9, 9, 12], 12, 2.0)
        )
        self.assertTrue(a["restarted"])
        self.assertEqual(a["baseline"], "absolute")
        self.assertEqual(a["count"], 12)

    def test_restart_detected_when_sum_goes_backwards(self):
        a = self._restart_case(
            self._timing([0, 1, 1, 1, 1], 1, 5.0), self._timing([0, 2, 2, 2, 2], 2, 0.02)
        )
        self.assertTrue(a["restarted"])

    def test_restart_detected_when_cumulative_buckets_are_not_monotonic(self):
        a = self._restart_case(
            self._timing([0, 1, 1, 1, 1], 1, 0.01), self._timing([0, 3, 2, 2, 4], 4, 0.5)
        )
        self.assertTrue(a["restarted"])

    def test_scrape_runs_at_most_once_per_interval(self):
        orig_status, orig_fetch = monitor.fetch_status, monitor.fetch_follow_timing
        monitor._follow_scrape_state.update(last_ts=0.0, failures=0, logged=False)
        calls = []
        try:
            monitor.fetch_status = lambda *a, **kw: {"ok": True, "catchpoint": None, "last_round": 1}
            monitor.fetch_follow_timing = lambda url, timeout=1.0: calls.append(url) or {"apply": {}}
            first = monitor.take_sample("n", "", "p", "")
            second = monitor.take_sample("n", "", "p", "")
            self.assertIn("follow_timing", first)
            self.assertNotIn("follow_timing", second)
            self.assertEqual(len(calls), 1)
            monitor._follow_scrape_state["last_ts"] -= monitor.FOLLOW_TIMING_SCRAPE_INTERVAL_S
            self.assertIn("follow_timing", monitor.take_sample("n", "", "p", ""))
            self.assertEqual(len(calls), 2)
        finally:
            monitor.fetch_status, monitor.fetch_follow_timing = orig_status, orig_fetch

    def test_scrape_uses_a_short_timeout_and_logs_persistent_failure_once(self):
        import contextlib
        import io
        import urllib.request

        seen = []
        orig_open = urllib.request.urlopen

        def boom(req, timeout=None):
            seen.append(timeout)
            raise OSError("refused")

        urllib.request.urlopen = boom
        monitor._follow_scrape_state.update(last_ts=0.0, failures=0, logged=False)
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                for _ in range(5):
                    self.assertIsNone(monitor.fetch_follow_timing("http://node"))
        finally:
            urllib.request.urlopen = orig_open
        self.assertEqual(set(seen), {monitor.FOLLOW_TIMING_SCRAPE_TIMEOUT_S})
        self.assertLessEqual(monitor.FOLLOW_TIMING_SCRAPE_TIMEOUT_S, 1.0)
        self.assertEqual(err.getvalue().count("scrape"), 1, err.getvalue())
        self.assertIn("refused", err.getvalue())

    def test_take_sample_attaches_scrape_only_when_out_of_catchup(self):
        orig_status, orig_fetch = monitor.fetch_status, monitor.fetch_follow_timing
        monitor._follow_scrape_state.update(last_ts=0.0, failures=0, logged=False)
        try:
            monitor.fetch_follow_timing = lambda url, timeout=3.0: {"apply": {"count": 1}}
            monitor.fetch_status = lambda *a, **kw: {"ok": True, "catchpoint": None, "last_round": 1}
            self.assertIn("follow_timing", monitor.take_sample("n", "", "p", ""))
            monitor.fetch_status = lambda *a, **kw: {"ok": True, "catchpoint": "1#X", "last_round": 0}
            monitor._follow_scrape_state["last_ts"] = 0.0
            self.assertNotIn("follow_timing", monitor.take_sample("n", "", "p", ""))
        finally:
            monitor.fetch_status, monitor.fetch_follow_timing = orig_status, orig_fetch


STALL = {
    "round": 65_668_288,
    "error": "account balance below minimum",
    "consecutive_failures": 7,
    "since_unix_secs": 1_700_000_000,
}


def node_follow_stalled(ts, round_, peer_round=None, stall=None):
    s = node_follow(ts, round_, peer_round)
    s["node"]["stalled_on_invalid_block"] = dict(stall or STALL)
    return s


class _FakeResp:
    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class InvalidBlockStallTest(unittest.TestCase):
    """Issue #1715: stalled-on-invalid-block is a hard failure."""

    def _fetch(self, body):
        import json
        import urllib.request

        orig = urllib.request.urlopen
        urllib.request.urlopen = lambda req, timeout=None: _FakeResp(json.dumps(body).encode())
        try:
            return monitor.fetch_status("http://n", "")
        finally:
            urllib.request.urlopen = orig

    def test_fetch_status_extracts_the_stall_payload(self):
        st = self._fetch(
            {
                "last-round": 5,
                "stalled-on-invalid-block": {
                    "round": 6,
                    "error": "boom",
                    "consecutive-failures": 3,
                    "since-unix-secs": 99,
                },
            }
        )
        self.assertEqual(
            st["stalled_on_invalid_block"],
            {"round": 6, "error": "boom", "consecutive_failures": 3, "since_unix_secs": 99},
        )

    def test_fetch_status_without_the_field_is_none(self):
        self.assertIsNone(self._fetch({"last-round": 5})["stalled_on_invalid_block"])

    def test_classify_hard_fails_with_round_error_and_failures(self):
        samples = [node_follow(1000.0 + i * 10, 100 + i, 100 + i) for i in range(3)]
        samples.append(node_follow_stalled(1030.0, 103, 104))
        v = monitor.classify(samples)
        self.assertEqual(v.status, "invalid_block_stall")
        self.assertEqual(v.round, STALL["round"])
        self.assertIn(str(STALL["round"]), v.message)
        self.assertIn("account balance below minimum", v.message)
        self.assertIn("7", v.message)
        self.assertEqual(monitor.exit_code_for(v), 1)

    def test_healthy_node_without_stall_stays_ok(self):
        samples = [node_follow(1000.0 + i * 10, 100 + i, 100 + i) for i in range(30)]
        self.assertEqual(monitor.classify(samples).status, "ok")

    def test_stall_reported_by_the_gauge_on_an_unreachable_sample_wins(self):
        samples = [node_follow_stalled(1000.0, 103, 104)]
        samples.append(
            {
                "ts": 1010.0,
                "node": {"ok": False, "error": "refused", "stalled_on_invalid_block": {"round": 9, "source": "gauge"}},
                "peer": {"ok": True, "last_round": 105},
            }
        )
        self.assertEqual(monitor.classify(samples).status, "invalid_block_stall")

    def test_gauge_alone_hard_fails_when_status_is_unavailable(self):
        orig_status, orig_gauge = monitor.fetch_status, monitor.fetch_stall_gauge
        monitor._follow_scrape_state["gauge_last_ts"] = 0.0
        try:
            monitor.fetch_status = lambda *a, **k: {"ok": False, "error": "timeout"}
            monitor.fetch_stall_gauge = lambda url, timeout=1.0: {"round": 42}
            sample = monitor.take_sample("n", "", "p", "")
        finally:
            monitor.fetch_status, monitor.fetch_stall_gauge = orig_status, orig_gauge
        self.assertEqual(sample["node"]["stalled_on_invalid_block"], {"round": 42, "source": "gauge"})
        v = monitor.classify([sample])
        self.assertEqual(v.status, "invalid_block_stall")
        self.assertEqual(v.round, 42)

    def test_gauge_is_not_scraped_while_status_answers(self):
        orig_status, orig_gauge = monitor.fetch_status, monitor.fetch_stall_gauge
        calls = []
        try:
            monitor.fetch_status = lambda *a, **k: {"ok": True, "catchpoint": "1#X", "last_round": 0}
            monitor.fetch_stall_gauge = lambda url, timeout=1.0: calls.append(url) or None
            monitor.take_sample("n", "", "p", "")
        finally:
            monitor.fetch_status, monitor.fetch_stall_gauge = orig_status, orig_gauge
        self.assertEqual(calls, [])

    def test_parse_stall_gauge(self):
        on = "algod_rust_sync_stalled_on_invalid_block 1\nalgod_rust_sync_stalled_block_round 42\n"
        off = "algod_rust_sync_stalled_on_invalid_block 0\nalgod_rust_sync_stalled_block_round 0\n"
        self.assertEqual(monitor.parse_stall_gauge(on), {"round": 42})
        self.assertIsNone(monitor.parse_stall_gauge(off))
        self.assertIsNone(monitor.parse_stall_gauge("other 1\n"))

    def test_summary_and_issue_carry_the_status_payload(self):
        import json

        samples = [node_follow(1000.0 + i * 10, 100 + i, 100 + i) for i in range(3)]
        samples.append(node_follow_stalled(1030.0, 103, 104))
        v = monitor.classify(samples)
        r = monitor.build_result(samples, v)
        json.dumps(r)
        self.assertEqual(r["status"], "invalid_block_stall")
        self.assertEqual(r["invalid_block_stall"], STALL)
        import file_issue

        fields = file_issue.build_fields(r, "run", "art", "", "peer")
        self.assertIn("account balance below minimum", fields["invalid_block_stall_line"])
        self.assertIn("65668288", fields["invalid_block_stall_line"].replace(",", ""))
        healthy = monitor.build_result(samples[:3], monitor.classify(samples[:3]))
        self.assertIsNone(healthy["invalid_block_stall"])
        self.assertEqual(file_issue.build_fields(healthy, "r", "a", "", "p")["invalid_block_stall_line"], "")

    def test_collect_stops_early_on_the_stall(self):
        import tempfile

        orig = monitor.take_sample
        monitor.take_sample = lambda *a, **k: node_follow_stalled(time.time(), 100, 101)
        try:
            with tempfile.TemporaryDirectory() as d:
                t0 = time.time()
                v = monitor.collect("n", "", "p", "", 30.0, 5.0, 0.02, os.path.join(d, "o.jsonl"))
        finally:
            monitor.take_sample = orig
        self.assertEqual(v.status, "invalid_block_stall")
        self.assertLess(time.time() - t0, 3.0)

    def test_step_summary_row_shows_the_stall(self):
        samples = [node_follow_stalled(1000.0, 103, 104)]
        r = monitor.build_result(samples, monitor.classify(samples))
        text = "\n".join(monitor.render_step_summary_lines(r))
        self.assertIn("stalled-on-invalid-block", text)
        self.assertIn("account balance below minimum", text)

    def test_nodelog_stalled_log_line_is_hard(self):
        line = (
            "2026-01-01T01:00:00.000000Z ERROR algo_ledger::agreement_bridge: ensure_block: "
            "stalled on invalid block 9: two failed attempts for the same round"
        )
        self.assertEqual(nodelog.scan_lines([line])["hard_failures"], {"stalled_on_invalid_block": 1})


class LagBeforeStallTest(unittest.TestCase):
    """Issue #1759: lag excludes the trailing frozen-node window."""

    def _halted(self):
        samples = [node_follow(1000.0 + i * 10, 500 + i, 500 + i + (i % 2)) for i in range(40)]
        frozen_round = 539
        for j in range(31):
            samples.append(node_follow(1400.0 + j * 10, frozen_round, 540 + j))
        return samples

    def test_halt_verdict_separates_the_stall_window(self):
        samples = self._halted()
        v = monitor.classify(samples)
        self.assertEqual(v.status, "stuck")
        r = monitor.build_result(samples, v)
        before = r["lag_rounds_before_stall"]
        self.assertEqual(before["n"], 40)
        self.assertLessEqual(before["max"], 2)
        self.assertEqual(r["lag_rounds"]["n"], 71)  # unchanged, compatible
        self.assertGreater(r["lag_rounds"]["max"], 20)
        self.assertEqual(r["stall_window"]["seconds"], v.stalled_since_s)
        self.assertIsNotNone(r["stall_window"]["start_ts"])

    def test_without_a_halt_both_views_agree(self):
        samples = [node_follow(1000.0 + i * 10, 500 + i, 500 + i + (i % 2)) for i in range(40)]
        r = monitor.build_result(samples, monitor.classify(samples))
        self.assertEqual(r["lag_rounds_before_stall"], r["lag_rounds"])
        self.assertIsNone(r["stall_window"])

    def test_step_summary_renders_both_numbers(self):
        samples = self._halted()
        r = monitor.build_result(samples, monitor.classify(samples))
        text = "\n".join(monitor.render_step_summary_lines(r))
        self.assertIn("Lag before stall", text)
        self.assertIn("Stall window", text)


class FollowTimingLeftoversTest(unittest.TestCase):
    """Issue #1761 follow-ups."""

    BOUNDS = [0.001, 0.01, 0.1, 1.0, 10.0]

    def _t(self, key, cums, total, sum_s, start=None):
        text = _exposition({key: (list(zip(self.BOUNDS, cums)), total, sum_s)})
        out = monitor.parse_follow_timing(text)
        if start is not None:
            out["process_start_time_seconds"] = float(start)
        return out

    def test_failed_path_series_reach_the_summary(self):
        for k in ("apply_failed", "ensure_block_failed", "commit_failed"):
            self.assertIn(k, monitor.FOLLOW_TIMING_KEYS)
        samples = [node_follow(1.0, 5, 5)]
        samples[0]["follow_timing"] = self._t("apply_failed", [0, 1, 1, 1, 1], 1, 0.005)
        a = monitor.summarize(samples)["follow_block_timing"]["apply_failed"]
        self.assertEqual(a["count"], 1)

    def test_process_start_time_is_parsed(self):
        self.assertEqual(
            monitor.parse_process_start_time(
                "# TYPE x gauge\nalgod_rust_process_start_time_seconds 1700000000\n"
            ),
            1700000000.0,
        )
        self.assertIsNone(monitor.parse_process_start_time("nothing 1\n"))

    def test_restart_with_more_blocks_than_baseline_is_caught_by_start_time(self):
        samples = [node_follow(1000.0 + i * 10, 500 + i, 500 + i) for i in range(3)]
        samples[0]["follow_timing"] = self._t("apply", [0, 1, 1, 1, 1], 1, 0.005, start=100)
        # Restarted, then processed far more blocks: every counter grew.
        samples[2]["follow_timing"] = self._t("apply", [0, 50, 90, 99, 100], 100, 9.0, start=900)
        a = monitor.summarize(samples)["follow_block_timing"]["apply"]
        self.assertTrue(a["restarted"])
        self.assertEqual((a["baseline"], a["count"]), ("absolute", 100))

    def test_same_start_time_keeps_the_delta(self):
        samples = [node_follow(1000.0 + i * 10, 500 + i, 500 + i) for i in range(3)]
        samples[0]["follow_timing"] = self._t("apply", [0, 1, 1, 1, 1], 1, 0.005, start=100)
        samples[2]["follow_timing"] = self._t("apply", [0, 5, 5, 5, 5], 5, 0.02, start=100)
        a = monitor.summarize(samples)["follow_block_timing"]["apply"]
        self.assertFalse(a["restarted"])
        self.assertEqual((a["baseline"], a["count"]), ("delta", 4))

    def test_baseline_scrape_is_forced_at_the_tip_transition(self):
        orig_status, orig_fetch = monitor.fetch_status, monitor.fetch_follow_timing
        monitor._follow_scrape_state.update(last_ts=0.0, failures=0, logged=False, tip_scraped=False)
        calls = []
        try:
            monitor.fetch_follow_timing = lambda url, timeout=1.0: calls.append(url) or {"apply": {}}
            # Behind the tip: scrape (interval elapsed).
            monitor.fetch_status = lambda url, *a, **k: {
                "ok": True,
                "catchpoint": None,
                "last_round": 90 if url == "n" else 100,
            }
            self.assertIn("follow_timing", monitor.take_sample("n", "", "p", ""))
            self.assertEqual(len(calls), 1)
            # Reaches the tip inside the 30 s rate-limit window: still scraped.
            monitor.fetch_status = lambda url, *a, **k: {"ok": True, "catchpoint": None, "last_round": 100}
            self.assertIn("follow_timing", monitor.take_sample("n", "", "p", ""))
            self.assertEqual(len(calls), 2)
            # Only once: the next in-window sample is rate limited again.
            self.assertNotIn("follow_timing", monitor.take_sample("n", "", "p", ""))
            self.assertEqual(len(calls), 2)
        finally:
            monitor.fetch_status, monitor.fetch_follow_timing = orig_status, orig_fetch

    def test_step_summary_prints_baseline_and_restarted(self):
        samples = [node_follow(1.0, 5, 5)]
        samples[0]["follow_timing"] = self._t("apply", [0, 1, 1, 1, 1], 1, 0.005)
        r = monitor.build_result(samples, monitor.classify(samples))
        text = "\n".join(monitor.render_step_summary_lines(r))
        self.assertIn("Follow block apply", text)
        self.assertIn("baseline=absolute", text)
        self.assertIn("restarted=False", text)


class StallLifecycleTest(unittest.TestCase):
    """PR #1762 review: a cleared stall must not hard-fail forever."""

    def _run(self, tail):
        samples = [node_follow(1000.0 + i * 10, 100 + i, 100 + i) for i in range(3)]
        samples.append(node_follow_stalled(1030.0, 103, 104))
        return samples + tail

    def test_cleared_stall_does_not_fail_and_is_reported(self):
        samples = self._run([node_follow(1040.0 + i * 10, 104 + i, 104 + i) for i in range(5)])
        v = monitor.classify(samples)
        self.assertEqual(v.status, "ok")
        r = monitor.build_result(samples, v)
        self.assertIsNone(r["invalid_block_stall"])
        cleared = r["invalid_block_stall_cleared"]
        self.assertEqual(cleared["round"], STALL["round"])
        self.assertEqual(cleared["first_ts"], 1030.0)
        self.assertEqual(cleared["last_ts"], 1030.0)
        text = "\n".join(monitor.render_step_summary_lines(r))
        self.assertIn("cleared", text)

    def test_stall_persisting_to_the_end_fails(self):
        samples = self._run([node_follow_stalled(1040.0, 103, 105)])
        v = monitor.classify(samples)
        self.assertEqual(v.status, "invalid_block_stall")
        self.assertEqual(v.stalled_since_s, 10.0)  # contiguous run only

    def test_stall_then_node_failure_is_node_failure(self):
        samples = self._run(
            [{"ts": 1040.0, "node": {"ok": False, "error": "refused"}, "peer": {"ok": True, "last_round": 105}}]
        )
        self.assertEqual(monitor.classify(samples).status, "node_failure")

    def test_no_cleared_key_content_for_a_healthy_run(self):
        samples = [node_follow(1000.0 + i * 10, 100 + i, 100 + i) for i in range(3)]
        self.assertIsNone(monitor.build_result(samples, monitor.classify(samples))["invalid_block_stall_cleared"])


class GaugeScrapeTest(unittest.TestCase):
    """PR #1762 review: the gauge is rate limited and only read while status is down."""

    def test_gauge_scrape_is_rate_limited(self):
        orig_status, orig_gauge = monitor.fetch_status, monitor.fetch_stall_gauge
        calls = []
        monitor._follow_scrape_state["gauge_last_ts"] = 0.0
        try:
            monitor.fetch_status = lambda *a, **k: {"ok": False, "error": "timeout"}
            monitor.fetch_stall_gauge = lambda url, timeout=1.0: calls.append(url) or None
            monitor.take_sample("n", "", "p", "")
            monitor.take_sample("n", "", "p", "")
            self.assertEqual(len(calls), 1)
            monitor._follow_scrape_state["gauge_last_ts"] -= monitor.FOLLOW_TIMING_SCRAPE_INTERVAL_S
            monitor.take_sample("n", "", "p", "")
            self.assertEqual(len(calls), 2)
        finally:
            monitor.fetch_status, monitor.fetch_stall_gauge = orig_status, orig_gauge

    def test_one_metrics_text_feeds_timing_and_gauge(self):
        text = (
            _exposition({"apply": ([(0.001, 1), (0.01, 1), (0.1, 1), (1.0, 1), (10.0, 1)], 1, 0.0005)})
            + "algod_rust_process_start_time_seconds 1700000000.123\n"
            + "algod_rust_sync_stalled_on_invalid_block 1\nalgod_rust_sync_stalled_block_round 42\n"
        )
        import urllib.request

        orig = urllib.request.urlopen
        n = []
        urllib.request.urlopen = lambda req, timeout=None: n.append(1) or _FakeResp(text.encode())
        try:
            timing = monitor.fetch_follow_timing("http://n")
        finally:
            urllib.request.urlopen = orig
        self.assertEqual(len(n), 1)
        self.assertEqual(timing["process_start_time_seconds"], 1700000000.123)
        self.assertEqual(monitor.parse_stall_gauge(text), {"round": 42})


class RestartPreTipTest(unittest.TestCase):
    BOUNDS = [0.001, 0.01, 0.1, 1.0, 10.0]

    def _t(self, cums, total, sum_s, start):
        out = monitor.parse_follow_timing(
            _exposition({"apply": (list(zip(self.BOUNDS, cums)), total, sum_s)})
        )
        out["process_start_time_seconds"] = start
        return out

    def _samples(self, post_restart_lag):
        samples = [node_follow(1000.0 + i * 10, 500 + i, 500 + i) for i in range(4)]
        samples[0]["follow_timing"] = self._t([0, 1, 1, 1, 1], 1, 0.005, 100.5)
        # First post-restart scrape: node still behind the peer.
        samples[2] = node_follow(1020.0, 500, 500 + post_restart_lag)
        samples[2]["follow_timing"] = self._t([0, 5, 5, 5, 5], 5, 0.02, 900.25)
        samples[3]["follow_timing"] = self._t([0, 50, 90, 99, 100], 100, 9.0, 900.25)
        return samples

    def test_restart_while_behind_the_tip_flags_pre_tip_included(self):
        a = monitor.summarize(self._samples(50))["follow_block_timing"]["apply"]
        self.assertTrue(a["restarted"])
        self.assertTrue(a["pre_tip_included"])
        self.assertEqual(a["count"], 100)

    def test_restart_at_the_tip_does_not_flag_pre_tip(self):
        a = monitor.summarize(self._samples(0))["follow_block_timing"]["apply"]
        self.assertTrue(a["restarted"])
        self.assertFalse(a["pre_tip_included"])

    def test_no_restart_has_no_pre_tip_flag(self):
        samples = self._samples(0)
        samples[3]["follow_timing"] = self._t([0, 6, 6, 6, 6], 6, 0.03, 100.5)
        samples[2].pop("follow_timing")
        a = monitor.summarize(samples)["follow_block_timing"]["apply"]
        self.assertFalse(a["restarted"])
        self.assertFalse(a["pre_tip_included"])


class StallTextEscapingTest(unittest.TestCase):
    NASTY = {
        "round": 7,
        "error": "bad `block`\nline2 | pipe " + "x" * 600,
        "consecutive_failures": 3,
        "since_unix_secs": 99,
    }

    def test_sanitize_strips_backticks_newlines_and_truncates(self):
        out = nodelog.sanitize_text(self.NASTY["error"])
        self.assertNotIn("`", out)
        self.assertNotIn("\n", out)
        self.assertLessEqual(len(out), 500)
        cell = nodelog.sanitize_text("a|b", table=True)
        self.assertNotIn("|", cell)

    def test_step_summary_cell_is_one_clean_table_row(self):
        samples = [node_follow_stalled(1000.0, 103, 104, stall=self.NASTY)]
        r = monitor.build_result(samples, monitor.classify(samples))
        lines = monitor.render_step_summary_lines(r)
        row = [l for l in lines if l.startswith("| stalled-on-invalid-block")]
        self.assertEqual(len(row), 1)
        self.assertEqual(row[0].count("|"), 3)
        self.assertNotIn("`", row[0])
        self.assertIn("round: 7", row[0])
        self.assertNotIn("{'", row[0])  # formatted text, not a dict repr
        verdict_line = [l for l in lines if l.startswith("**Verdict:**")][0]
        self.assertNotIn("`block`", verdict_line)
        self.assertNotIn("\n", r["message"])
        self.assertLessEqual(len(r["message"]), 700)

    def test_issue_body_has_verdict_specific_intro_and_escaped_text(self):
        import file_issue

        samples = [node_follow_stalled(1000.0, 103, 104, stall=self.NASTY)]
        r = monitor.build_result(samples, monitor.classify(samples))
        fields = file_issue.build_fields(r, "run", "art", "", "peer")
        body = file_issue.render_template(os.path.join(os.path.dirname(os.path.abspath(__file__)), "issue_template.md"), fields)
        self.assertIn("stalled-on-invalid-block", fields["halt_intro"])
        self.assertNotIn("no observable progress", body)
        line = fields["invalid_block_stall_line"]
        self.assertIn("round: 7", line)
        self.assertNotIn("bad `block`", line)
        self.assertNotIn("{'", line)
        self.assertLessEqual(len(line), 900)
        stuck = file_issue.build_fields(
            {"status": "stuck", "phase": "follow", "round": 5, "stalled_since_s": 400.0}, "r", "a", "", "p"
        )
        self.assertIn("no observable progress", stuck["halt_intro"])


if __name__ == "__main__":
    unittest.main()
