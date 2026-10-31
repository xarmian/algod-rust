# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests of the `catchup` tier (scripts/bench/catchup_lib.py and
scripts/bench/tiers/catchup.py, issue #2108, epic #2101): configuration,
catchpoint-label handling, catchup stage detection and phase durations, the
block-hash equality gate, the external-network vs node failure classification,
the resource summary, the result rows, and the whole tier against the
hermetic mock network (BENCH_CATCHUP_MODE=mock). No Docker, no go, no cargo,
and never the public network: the live run is the tier itself
(docs/BENCHMARK_COMPARISON.md, "The catchup tier")."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tiers"))
import bench_schema  # noqa: E402
import catchup_lib as cl  # noqa: E402
import report  # noqa: E402

LABEL = "40500000#" + "A" * 52


def status(catchpoint="", total=0, processed=0, verified=0, tblocks=0, ablocks=0,
           last_round=0, **extra):
    d = {"last-round": last_round, "catchpoint": catchpoint,
         "catchpoint-total-accounts": total, "catchpoint-processed-accounts": processed,
         "catchpoint-verified-accounts": verified, "catchpoint-total-blocks": tblocks,
         "catchpoint-acquired-blocks": ablocks}
    d.update(extra)
    return d


class LabelTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(cl.parse_label(LABEL), (40500000, "A" * 52))

    def test_rejects_garbage(self):
        for bad in ("", "12", "x#ABC", "0#ABC", "12#", "12#abc!", "-5#AAAA"):
            with self.assertRaises(ValueError, msg=bad):
                cl.parse_label(bad)

    def test_index_text_is_stripped(self):
        self.assertEqual(cl.parse_index_text(f" {LABEL}\r\n"), LABEL)

    def test_index_text_html_error_page_is_rejected(self):
        with self.assertRaises(ValueError):
            cl.parse_index_text("<html>AccessDenied</html>")


class SettingsTest(unittest.TestCase):
    def test_defaults(self):
        s = cl.parse_settings({})
        self.assertEqual((s["network"], s["mode"], s["profile"]), ("testnet", "live", "full"))
        self.assertEqual((s["cpus"], s["mem"]), (2.0, "3g"))
        self.assertGreater(s["follow_secs"], 60)

    def test_smoke_profile_is_short(self):
        s = cl.parse_settings({"BENCH_CATCHUP_PROFILE": "smoke"})
        self.assertLessEqual(s["follow_secs"], 30)

    def test_network_choices(self):
        for n in ("testnet", "mainnet", "betanet"):
            self.assertEqual(cl.parse_settings({"BENCH_CATCHUP_NETWORK": n})["network"], n)
        with self.assertRaisesRegex(cl.CatchupError, "voimain"):
            cl.parse_settings({"BENCH_CATCHUP_NETWORK": "voimain"})

    def test_explicit_label_is_validated_and_must_match_the_round_scale(self):
        s = cl.parse_settings({"BENCH_CATCHUP_LABEL": LABEL})
        self.assertEqual(s["label"], LABEL)
        with self.assertRaises(cl.CatchupError):
            cl.parse_settings({"BENCH_CATCHUP_LABEL": "nope"})

    def test_bad_numbers_name_the_variable(self):
        for var, val in (("BENCH_CATCHUP_FOLLOW_SECS", "x"), ("BENCH_CATCHUP_CPUS", "0"),
                         ("BENCH_CATCHUP_MEM", "lots"), ("BENCH_CATCHUP_PORT_BASE", "80"),
                         ("BENCH_CATCHUP_MODE", "fake"), ("BENCH_CATCHUP_PROFILE", "huge"),
                         ("BENCH_CATCHUP_FOLLOW_SECS", "-1"), ("BENCH_CATCHUP_HASH_CAP", "0"),
                         ("BENCH_CATCHUP_MIN_GATE_ROUNDS", "0")):
            with self.assertRaisesRegex(cl.CatchupError, var, msg=val):
                cl.parse_settings({var: val})

    def test_mock_fault_only_in_mock_mode(self):
        with self.assertRaisesRegex(cl.CatchupError, "MOCK_FAULT"):
            cl.parse_settings({"BENCH_CATCHUP_MOCK_FAULT": "diverge"})
        s = cl.parse_settings({"BENCH_CATCHUP_MODE": "mock", "BENCH_CATCHUP_MOCK_FAULT": "stall"})
        self.assertEqual(s["mock_fault"], "stall")
        with self.assertRaises(cl.CatchupError):
            cl.parse_settings({"BENCH_CATCHUP_MODE": "mock", "BENCH_CATCHUP_MOCK_FAULT": "boom"})


class StageTest(unittest.TestCase):
    def test_stages(self):
        self.assertEqual(cl.stage_of(status()), "idle")
        self.assertEqual(cl.stage_of(status(LABEL)), "ledger")
        self.assertEqual(cl.stage_of(status(LABEL, total=100, processed=40)), "ledger")
        self.assertEqual(cl.stage_of(status(LABEL, total=100, processed=100, verified=10)),
                         "verify")
        self.assertEqual(cl.stage_of(status(LABEL, total=100, processed=100, verified=100)),
                         "blocks")
        self.assertEqual(cl.stage_of(status(LABEL, total=100, processed=100, verified=100,
                                            tblocks=320, ablocks=7)), "blocks")

    def test_kvs_count_with_accounts(self):
        st = status(LABEL, total=10, processed=10, verified=10)
        st.update({"catchpoint-total-kvs": 5, "catchpoint-processed-kvs": 2})
        self.assertEqual(cl.stage_of(st), "ledger")
        st["catchpoint-processed-kvs"] = 5
        self.assertEqual(cl.stage_of(st), "verify")

    def test_missing_fields_are_zero(self):
        self.assertEqual(cl.stage_of({"last-round": 0, "catchpoint": LABEL}), "ledger")


class TrackerTest(unittest.TestCase):
    def run_tracker(self, t0=100.0):
        tr = cl.PhaseTracker(t0)
        seq = [
            (101, status(last_round=0), None),
            (103, status(LABEL), None),
            (110, status(LABEL, total=100, processed=50), None),
            (120, status(LABEL, total=100, processed=100, verified=20), None),
            (130, status(LABEL, total=100, processed=100, verified=100, tblocks=10, ablocks=3), None),
            (135, status(last_round=40500000, time_since=1), 3000.0),
            (140, status(last_round=40500600), 600.0),
            (150, status(last_round=40501100), 5.0),
            (151, status(last_round=40501101), 3.0),
        ]
        for t, st, lag in seq:
            tr.observe(t, st, lag)
        return tr

    def test_durations(self):
        d = self.run_tracker().durations()
        self.assertEqual(d["phase_ledger_s"], 20.0)     # trigger 100 -> verify seen at 120
        self.assertEqual(d["phase_verify_s"], 10.0)     # 120 -> 130
        self.assertEqual(d["phase_blocks_s"], 5.0)      # 130 -> catchpoint cleared at 135
        self.assertEqual(d["phase_replay_s"], 15.0)     # 135 -> within slack at 150
        self.assertEqual(d["total_to_head_s"], 50.0)

    def test_replay_rate(self):
        tr = self.run_tracker()
        self.assertAlmostEqual(tr.replay_blocks_per_s(), (40501100 - 40500000) / 15.0)

    def test_the_catchpoint_label_seen_is_recorded(self):
        self.assertEqual(self.run_tracker().catchpoint_seen, LABEL)

    def test_a_skipped_stage_gets_a_zero_duration(self):
        tr = cl.PhaseTracker(0.0)
        tr.observe(1, status(LABEL), None)
        tr.observe(9, status(LABEL, total=1, processed=1, verified=1, tblocks=5, ablocks=1), None)
        tr.observe(12, status(last_round=10), 0.5)
        d = tr.durations()
        self.assertEqual(d["phase_ledger_s"], 9.0)
        self.assertEqual(d["phase_verify_s"], 0.0)
        self.assertEqual(d["phase_blocks_s"], 3.0)
        self.assertEqual(d["phase_replay_s"], 0.0)

    def test_unreached_phases_are_absent_and_head_is_not_reached(self):
        tr = cl.PhaseTracker(0.0)
        tr.observe(1, status(LABEL, total=10, processed=3), None)
        self.assertEqual(tr.durations(), {})
        self.assertFalse(tr.at_head())
        self.assertIsNone(tr.replay_blocks_per_s())

    def test_head_requires_a_finished_catchup(self):
        tr = cl.PhaseTracker(0.0)
        # a lag of zero while the catchpoint is still running is not "at head"
        tr.observe(1, status(LABEL, total=10, processed=3, last_round=5), 0.1)
        self.assertFalse(tr.at_head())

    def test_no_lag_sample_means_not_at_head(self):
        tr = cl.PhaseTracker(0.0)
        tr.observe(1, status(LABEL), None)
        tr.observe(2, status(last_round=7), None)
        self.assertFalse(tr.at_head())
        self.assertNotIn("total_to_head_s", tr.durations())

    def test_progressed_flag(self):
        tr = cl.PhaseTracker(0.0)
        self.assertFalse(tr.progressed)
        tr.observe(1, status(LABEL), None)
        self.assertFalse(tr.progressed)
        tr.observe(2, status(LABEL, total=10, processed=1), None)
        self.assertTrue(tr.progressed)


class FollowTest(unittest.TestCase):
    def test_stats(self):
        s = cl.follow_stats([(0, 100, 2.0), (10, 104, 4.0), (20, 110, 3.0)])
        self.assertAlmostEqual(s["follow_rounds_per_s"], 0.5)
        self.assertAlmostEqual(s["follow_lag_s_mean"], 3.0)
        self.assertEqual(s["follow_lag_s_max"], 4.0)

    def test_too_few_samples(self):
        self.assertEqual(cl.follow_stats([]), {})
        self.assertEqual(cl.follow_stats([(0, 1, 1.0)]), {})

    def test_rounds_behind_the_other_node(self):
        go = [(0, 100), (1, 102), (2, 105)]
        rust = [(0, 100), (1, 101), (2, 105)]
        self.assertEqual(cl.rounds_behind_max(go, rust), {"go": 0, "rust": 1})

    def test_rounds_behind_pairs_samples_by_index_and_ignores_the_tail(self):
        self.assertEqual(cl.rounds_behind_max([(0, 5)], []), {"go": 0, "rust": 0})


class SampleRoundsTest(unittest.TestCase):
    def test_all_rounds_below_the_cap(self):
        self.assertEqual(cl.sample_rounds(5, 9, 100), [5, 6, 7, 8, 9])

    def test_empty_range(self):
        self.assertEqual(cl.sample_rounds(9, 5, 100), [])

    def test_capped_range_keeps_both_ends_and_is_sorted_unique(self):
        r = cl.sample_rounds(1000, 1_000_999, 50)
        self.assertLessEqual(len(r), 50)
        self.assertEqual((r[0], r[-1]), (1000, 1_000_999))
        self.assertEqual(r, sorted(set(r)))

    def test_cap_one_is_the_tip(self):
        self.assertEqual(cl.sample_rounds(1, 10, 1), [10])


class OldestAvailableTest(unittest.TestCase):
    """Non-archival nodes keep only the newest rounds (a live testnet run found
    both nodes answering none of the first 8970 of 9969 rounds after the
    catchpoint): the gate range starts at the oldest round both still serve."""

    def test_finds_the_start_of_the_retained_suffix(self):
        for first in (100, 101, 150, 199, 200):
            self.assertEqual(cl.oldest_available(100, 200, lambda r, f=first: r >= f), first)

    def test_everything_retained(self):
        self.assertEqual(cl.oldest_available(5, 9, lambda r: True), 5)

    def test_tip_missing_means_none(self):
        self.assertIsNone(cl.oldest_available(5, 9, lambda r: False))

    def test_empty_range(self):
        self.assertIsNone(cl.oldest_available(9, 5, lambda r: True))

    def test_probe_count_is_logarithmic(self):
        probes = []

        def avail(r):
            probes.append(r)
            return r >= 700_000
        self.assertEqual(cl.oldest_available(1, 1_000_000, avail), 700_000)
        self.assertLessEqual(len(probes), 25)


class GateTest(unittest.TestCase):
    def hashes(self, lo, hi, salt=""):
        return {r: f"blk-{r}{salt}" for r in range(lo, hi + 1)}

    def test_equal_passes(self):
        errs, n = cl.hash_gate(self.hashes(5, 9), self.hashes(5, 9), [5, 6, 7, 8, 9])
        self.assertEqual((errs, n), ([], 5))

    def test_first_divergence_is_named(self):
        go = self.hashes(5, 9)
        rust = self.hashes(5, 9)
        rust[7] = "blk-FORK"
        rust[9] = "blk-FORK2"
        errs, _ = cl.hash_gate(go, rust, [5, 6, 7, 8, 9])
        self.assertEqual(len(errs), 1)
        self.assertIn("round 7", errs[0])
        self.assertIn("2 of 5", errs[0])

    def test_a_missing_hash_is_an_error_not_a_pass(self):
        go = self.hashes(5, 7)
        rust = self.hashes(5, 6)
        errs, _ = cl.hash_gate(go, rust, [5, 6, 7])
        self.assertTrue(any("rust" in e and "7" in e for e in errs), errs)

    def test_nothing_compared_fails(self):
        errs, n = cl.hash_gate({}, {}, [])
        self.assertEqual(n, 0)
        self.assertTrue(errs)

    def test_label_gate(self):
        self.assertEqual(cl.label_gate(LABEL, {"go": LABEL, "rust": LABEL}), [])
        errs = cl.label_gate(LABEL, {"go": LABEL, "rust": "1#B"})
        self.assertEqual(len(errs), 1)
        self.assertIn("rust", errs[0])
        self.assertTrue(cl.label_gate(LABEL, {"go": None, "rust": LABEL}))


class ClassifyTest(unittest.TestCase):
    def side(self, **kw):
        d = {"progressed": False, "panicked": False, "exited": False, "relay_error": False}
        d.update(kw)
        return d

    def test_label_fetch_failure_is_external(self):
        cls, _ = cl.classify_failure({}, label_error=True)
        self.assertEqual(cls, cl.EXTERNAL)

    def test_nobody_progressed_with_relay_errors_is_external(self):
        sides = {"go": self.side(relay_error=True), "rust": self.side()}
        self.assertEqual(cl.classify_failure(sides, kind="timeout")[0], cl.EXTERNAL)

    def test_nobody_progressed_without_evidence_is_a_node_failure(self):
        sides = {"go": self.side(), "rust": self.side()}
        self.assertEqual(cl.classify_failure(sides, kind="timeout")[0], cl.NODE)

    def test_a_panic_or_exit_is_always_the_node(self):
        for k in ("panicked", "exited"):
            sides = {"go": self.side(relay_error=True), "rust": self.side(**{k: True})}
            cls, detail = cl.classify_failure(sides, kind="timeout")
            self.assertEqual(cls, cl.NODE)
            self.assertIn("rust", detail)

    def test_one_side_stuck_while_the_other_progressed_is_the_node(self):
        sides = {"go": self.side(progressed=True), "rust": self.side(relay_error=True)}
        cls, detail = cl.classify_failure(sides, kind="timeout")
        self.assertEqual(cls, cl.NODE)
        self.assertIn("rust", detail)

    def test_gate_failure_is_never_external(self):
        sides = {"go": self.side(progressed=True, relay_error=True),
                 "rust": self.side(progressed=True, relay_error=True)}
        self.assertEqual(cl.classify_failure(sides, kind="gate")[0], cl.NODE)

    def test_timeout_while_progressing_with_relay_errors_is_external(self):
        sides = {"go": self.side(progressed=True, relay_error=True),
                 "rust": self.side(progressed=True, relay_error=True)}
        self.assertEqual(cl.classify_failure(sides, kind="timeout")[0], cl.EXTERNAL)

    def test_failure_text_uses_the_smoke_script_vocabulary(self):
        self.assertEqual(cl.format_failure(cl.EXTERNAL, "x"),
                         "FAILURE CLASS: external network: x")
        self.assertEqual(cl.format_failure(cl.NODE, "y"), "FAILURE CLASS: node: y")


class LogScanTest(unittest.TestCase):
    def test_transport_errors(self):
        self.assertTrue(cl.log_has_relay_error("WARN error: Connection refused (os error 111)"))
        self.assertTrue(cl.log_has_relay_error("dial tcp: i/o timeout... connection timed out"))
        self.assertTrue(cl.log_has_relay_error("error sending request for url: dns error: x"))

    def test_a_builder_error_is_not_a_relay_error(self):
        self.assertFalse(cl.log_has_relay_error("error sending request: builder error: bad url"))

    def test_routine_ws_warning_is_ignored(self):
        self.assertFalse(cl.log_has_relay_error("WS block fetch failed: connection reset"))

    def test_5xx_only_on_relay_lines(self):
        self.assertTrue(cl.log_has_relay_error("catchpoint GET failed: status 503"))
        self.assertFalse(cl.log_has_relay_error("unrelated line says HTTP 500"))

    def test_fatal_panics(self):
        self.assertTrue(cl.log_has_fatal_panic("thread 'main' panicked at src/x.rs:1"))
        self.assertTrue(cl.log_has_fatal_panic("a timer: it is being shutdown"))
        self.assertFalse(cl.log_has_fatal_panic("thread 'tokio-worker' panicked at x"))
        self.assertTrue(cl.log_has_fatal_panic("panic: runtime error: nil pointer dereference\n"
                                               "goroutine 1 [running]:"))


class ResourceTest(unittest.TestCase):
    def samples(self):
        mib = 1024 * 1024
        return [
            {"start": 0, "t": 1, "node": "n", "cpu_pct": 100.0, "mem_bytes": 100 * mib,
             "blk_read": 10 * mib, "blk_write": 5 * mib},
            {"start": 1, "t": 2, "node": "n", "cpu_pct": 200.0, "mem_bytes": 300 * mib,
             "blk_read": 30 * mib, "blk_write": 25 * mib},
            {"start": 2, "t": 3, "node": "n", "cpu_pct": 300.0, "mem_bytes": 200 * mib,
             "blk_read": 50 * mib, "blk_write": 45 * mib},
        ]

    def test_summary(self):
        s = cl.resources_over(self.samples(), 0, 10)
        self.assertAlmostEqual(s["cpu_cores"], 2.0)
        self.assertAlmostEqual(s["rss_mb_peak"], 300.0)
        self.assertAlmostEqual(s["blockio_read_mb"], 40.0)
        self.assertAlmostEqual(s["blockio_write_mb"], 40.0)

    def test_window_selects_samples(self):
        s = cl.resources_over(self.samples(), 1.5, 3)
        self.assertAlmostEqual(s["cpu_cores"], 2.5)

    def test_empty(self):
        self.assertEqual(cl.resources_over([], 0, 1), {})


class RowsTest(unittest.TestCase):
    def runs(self):
        a = {"phase_ledger_s": 20.0, "total_to_head_s": 50.0, "replay_blocks_per_s": 70.0,
             "follow_rounds_per_s": 0.36, "follow_lag_s_mean": 3.1, "rss_mb_peak": 800.0}
        b = {"phase_ledger_s": 24.0, "total_to_head_s": 60.0, "replay_blocks_per_s": 66.0,
             "follow_rounds_per_s": 0.35, "follow_lag_s_mean": 3.3, "rss_mb_peak": 810.0}
        return [{"go": dict(a), "rust": dict(b)}, {"go": dict(b), "rust": dict(a)}]

    def test_rows_validate_and_carry_one_sample_per_run(self):
        rows = cl.result_rows(self.runs(), {"network": "testnet"})
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(bench_schema.validate_result(r), [], r)
            self.assertEqual(len(r["samples"]), 2)
            self.assertEqual(r["tier"], "catchup")
            self.assertIs(r["metadata"]["nondeterministic"], True)
            self.assertEqual(r["metadata"]["network"], "testnet")
        names = {(r["impl"], r["name"]) for r in rows}
        self.assertIn(("go", "phase_ledger_s"), names)
        self.assertIn(("rust", "phase_ledger_s"), names)

    def test_direction_and_units(self):
        by = {r["name"]: r for r in cl.result_rows(self.runs(), {}) if r["impl"] == "go"}
        self.assertEqual(by["phase_ledger_s"]["unit"], "s")
        self.assertEqual(by["phase_ledger_s"]["better"], "lower")
        self.assertEqual(by["replay_blocks_per_s"]["better"], "higher")
        self.assertEqual(by["follow_rounds_per_s"]["unit"], "blocks/s")
        self.assertEqual(by["rss_mb_peak"]["unit"], "MB")

    def test_a_metric_missing_in_one_run_is_not_padded(self):
        runs = self.runs()
        del runs[1]["go"]["replay_blocks_per_s"]
        rows = {(r["impl"], r["name"]): r for r in cl.result_rows(runs, {})}
        self.assertEqual(len(rows[("go", "replay_blocks_per_s")]["samples"]), 1)
        self.assertEqual(len(rows[("rust", "replay_blocks_per_s")]["samples"]), 2)

    def test_unknown_metric_is_rejected(self):
        runs = self.runs()
        runs[0]["go"]["mystery"] = 1.0
        with self.assertRaises(cl.CatchupError):
            cl.result_rows(runs, {})


class ReportMarkingTest(unittest.TestCase):
    def test_report_marks_nondeterministic_rows(self):
        results = cl.result_rows([{"go": {"total_to_head_s": 5.0}, "rust": {"total_to_head_s": 6.0}}],
                                 {"network": "testnet"})
        rep = report.build_report(results)
        self.assertTrue(all(r["nondeterministic"] for r in rep["rows"]))
        md = report.render_markdown(rep)
        self.assertIn("non-deterministic", md)
        self.assertIn("real network", md)

    def test_deterministic_rows_are_not_marked(self):
        rep = report.build_report([{"schema": "bench-result/v1", "tier": "t", "name": "n",
                                    "impl": "go", "unit": "s", "samples": [1], "metadata": {}}])
        self.assertFalse(rep["rows"][0]["nondeterministic"])
        self.assertNotIn("non-deterministic", report.render_markdown(rep))


class NetworkTableTest(unittest.TestCase):
    def test_every_network_has_genesis_and_index(self):
        for n, spec in cl.NETWORKS.items():
            self.assertTrue(spec["index_url"].startswith("https://"), n)
            self.assertTrue(spec["genesis_rel"].endswith("genesis.json"), n)

    def test_genesis_ships_with_the_pinned_checkout_layout(self):
        # same file the docker `algod` image vendors, so both sides get one genesis
        repo = os.path.dirname(os.path.dirname(HERE))
        for n in ("testnet", "mainnet", "betanet"):
            self.assertTrue(os.path.isfile(os.path.join(repo, "docker", "algod", "genesis", n,
                                                        "genesis.json")), n)


class MockTierTest(unittest.TestCase):
    """The whole tier against the hermetic mock network: both 'nodes' are
    in-process HTTP servers, no Docker, nothing external."""

    def run_tier(self, **env):
        import catchup as tier
        out = tempfile.mkdtemp(prefix="catchup-test-")
        base = {"BENCH_CATCHUP_MODE": "mock", "BENCH_CATCHUP_PROFILE": "smoke",
                "BENCH_CATCHUP_FOLLOW_SECS": "2", "BENCH_RUNS": "2", "BENCH_OUT": out,
                "BENCH_CATCHUP_PORT_BASE": "0", "BENCH_CATCHUP_POLL_S": "0.1"}
        base.update(env)
        with mock.patch.dict(os.environ, base, clear=False):
            for k in [k for k in os.environ if k.startswith("BENCH_CATCHUP_") and k not in base]:
                del os.environ[k]
            rc = tier.main()
        return rc, out

    def test_passes_and_writes_valid_nondeterministic_rows(self):
        rc, out = self.run_tier()
        self.assertEqual(rc, 0)
        path = os.path.join(out, "catchup.json")
        rows, errs = bench_schema.load_result_file(path)
        self.assertEqual(errs, [])
        names = {r["name"] for r in rows}
        for want in ("phase_ledger_s", "phase_verify_s", "phase_blocks_s", "phase_replay_s",
                     "total_to_head_s", "replay_blocks_per_s", "follow_rounds_per_s",
                     "follow_lag_s_mean", "gate_rounds_compared"):
            self.assertIn(want, names)
        self.assertEqual({len(r["samples"]) for r in rows}, {2})
        self.assertTrue(all(r["metadata"]["nondeterministic"] for r in rows))
        meta = rows[0]["metadata"]
        self.assertEqual(meta["mode"], "mock")
        self.assertEqual(meta["runs"], 2)
        self.assertRegex(meta["agreed_block_hash"], r"^blk-")
        # the mock nodes prune like real ones: the gate range starts at the oldest
        # round both still serve, not at the catchpoint
        lo, hi = meta["runs_detail"][0]["gate_range"]
        self.assertGreater(lo, meta["label_round"] + 1)
        self.assertEqual(meta["runs_detail"][0]["rounds_compared"], hi - lo + 1)

    def test_too_short_a_retained_range_fails_the_gate(self):
        rc, out = self.run_tier(BENCH_CATCHUP_MIN_GATE_ROUNDS="100000")
        self.assertNotEqual(rc, 0)
        self.assertFalse(os.path.exists(os.path.join(out, "catchup.json")))

    def test_a_diverging_block_hash_fails_the_gate(self):
        rc, out = self.run_tier(BENCH_CATCHUP_MOCK_FAULT="diverge")
        self.assertNotEqual(rc, 0)
        self.assertFalse(os.path.exists(os.path.join(out, "catchup.json")))

    def test_a_stalled_network_is_classified_external_not_node(self):
        import io
        buf = io.StringIO()
        with mock.patch("sys.stderr", buf):
            rc, _ = self.run_tier(BENCH_CATCHUP_MOCK_FAULT="stall",
                                  BENCH_CATCHUP_STAGE_TIMEOUT="3")
        self.assertNotEqual(rc, 0)
        self.assertIn("FAILURE CLASS: external network", buf.getvalue())
        self.assertNotIn("FAILURE CLASS: node", buf.getvalue())

    def test_a_diverging_hash_is_classified_node(self):
        import io
        buf = io.StringIO()
        with mock.patch("sys.stderr", buf):
            self.run_tier(BENCH_CATCHUP_MOCK_FAULT="diverge")
        self.assertIn("FAILURE CLASS: node", buf.getvalue())
        self.assertIn("round", buf.getvalue())

    def test_the_report_marks_the_group(self):
        rc, out = self.run_tier()
        self.assertEqual(rc, 0)
        results, errs = bench_schema.load_result_file(os.path.join(out, "catchup.json"))
        rep = report.build_report(results)
        self.assertTrue(rep["ok"], rep["errors"])
        md = report.render_markdown(rep)
        self.assertIn("non-deterministic", md)
        self.assertIn("n=2", md)


if __name__ == "__main__":
    unittest.main()
