# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests of the `localnet` tier's pure logic (scripts/bench/localnet_lib.py
and the tier's gate wiring, issue #2106). No Docker, no network: the clusters
themselves are exercised by the live runs documented in
docs/BENCHMARK_COMPARISON.md and the CI smoke."""
import copy
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tiers"))
import bench_schema  # noqa: E402
import localnet_lib as ll  # noqa: E402
import report  # noqa: E402

DATA = os.path.join(HERE, "testdata", "localnet")
SHA_A = "a" * 64
SHA_B = "b" * 64


def read(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        return f.read()


def topo(impl, **kw):
    args = dict(project="bl-" + impl, go_image="algorand/algod:5.0.4-stable",
                rust_image="algod-rust:bench", cpus=1.5, mem="2g", port_base=4300,
                netroot="/w/" + impl, genesis_id="benchnet-v1",
                partkeys={s: f"{ll.NODE_DIRS[s]}/benchnet-v1/W.0.100.partkey"
                          for s in ll.PARTICIPATION})
    args.update(kw)
    return ll.topology(impl, **args)


class TopologyTest(unittest.TestCase):
    def test_both_clusters_have_the_same_shape_and_limits(self):
        go, rust = topo("go"), topo("rust")
        self.assertEqual(set(go["services"]), set(ll.SERVICES))
        self.assertEqual(len(ll.SERVICES), 5)  # 1 relay + 4 participation nodes
        # Same ports, limits, restart policy, network and dependency graph.
        a, b = ll.shape(go), ll.shape(rust)
        self.assertEqual(json.dumps(a["services"], sort_keys=True),
                         json.dumps(b["services"], sort_keys=True))
        # Both topologies use the same logical network name (the compose network
        # key); the real network name differs only by project, which is unique
        # per cluster by design.
        self.assertEqual(a["networks"], b["networks"])
        self.assertEqual(a["networks"], [ll.NETWORK_NAME])
        for top in (go, rust):
            for s in top["services"].values():
                self.assertEqual(s["cpus"], 1.5)
                self.assertEqual(s["mem_limit"], "2g")
                self.assertEqual(s["restart"], "no")

    def test_limits_apply_to_every_container_of_both_clusters(self):
        for impl in ("go", "rust"):
            top = topo(impl, cpus=3, mem="512m")
            self.assertEqual({(s["cpus"], s["mem_limit"]) for s in top["services"].values()},
                             {(3, "512m")})

    def test_each_cluster_uses_its_own_implementation_only(self):
        go, rust = topo("go"), topo("rust")
        self.assertEqual({s["image"] for s in go["services"].values()},
                         {"algorand/algod:5.0.4-stable"})
        self.assertEqual({s["image"] for s in rust["services"].values()},
                         {"algod-rust:bench"})
        self.assertTrue(all("entrypoint" not in s for s in go["services"].values()))
        self.assertTrue(all(s["entrypoint"][:2] == ["algod-rust", "participate"]
                            for s in rust["services"].values()))

    def test_rust_participation_nodes_import_their_own_key_and_the_relay_none(self):
        top = topo("rust")
        for svc in ll.PARTICIPATION:
            cmd = top["services"][svc]["entrypoint"]
            self.assertIn(f"--import-partkey=/netroot/{ll.NODE_DIRS[svc]}/benchnet-v1/"
                          "W.0.100.partkey", cmd)
            self.assertIn("--peers=relay:4161", cmd)
            self.assertNotIn("--relay-messages", cmd)
        relay = top["services"]["relay"]["entrypoint"]
        self.assertFalse([a for a in relay if a.startswith("--import-partkey")])
        self.assertIn("--relay-messages", relay)
        self.assertIn("--listen-address=0.0.0.0:4161", relay)
        self.assertIn("--genesis-id=benchnet-v1", relay)

    def test_go_nodes_mount_only_their_own_node_dir(self):
        top = topo("go")
        for svc, d in ll.NODE_DIRS.items():
            vols = top["services"][svc]["volumes"]
            self.assertEqual(vols, [{"type": "bind", "source": f"/w/go/{d}",
                                     "target": "/algod/data"}])
        env = top["services"]["relay"]["environment"]
        self.assertEqual(env["GOSSIP_PORT"], "4161")
        self.assertNotIn("PEER_ADDRESS", env)
        self.assertEqual(top["services"]["part1"]["environment"]["PEER_ADDRESS"], "relay:4161")
        self.assertNotIn("GOSSIP_PORT", top["services"]["part1"]["environment"])

    def test_ports_are_distinct_and_loopback_only(self):
        top = topo("go", port_base=4400)
        ports = [s["ports"][0] for s in top["services"].values()]
        self.assertEqual(len(set(ports)), 5)
        self.assertTrue(all(p.startswith("127.0.0.1:44") for p in ports))
        self.assertEqual(ll.host_port(4400, "part4"), 4404)

    def test_compose_is_valid_json_and_names_the_project_network(self):
        top = topo("rust")
        parsed = json.loads(ll.render_compose(top))
        self.assertEqual(parsed["name"], "bl-rust")
        self.assertEqual(parsed["networks"]["benchnet"]["name"], ll.network_name("bl-rust"))

    def test_unknown_impl_is_refused(self):
        with self.assertRaises(ValueError):
            topo("java")


class GenesisTest(unittest.TestCase):
    G = json.dumps({"network": "benchnet", "id": "v1", "proto": "future",
                    "alloc": [{"addr": "OLD", "comment": "w1",
                               "state": {"algo": 5, "onl": 1}}]})

    def test_load_accounts_are_added_not_participating(self):
        out = json.loads(ll.genesis_with_alloc(self.G, ["A1", "A2"], 1000))
        self.assertEqual([a["addr"] for a in out["alloc"]], ["OLD", "A1", "A2"])
        self.assertEqual(out["alloc"][1]["state"], {"algo": 1000, "onl": 2})
        self.assertEqual(out["alloc"][0]["state"], {"algo": 5, "onl": 1})
        self.assertEqual(out["proto"], "future")

    def test_an_already_allocated_address_is_refused(self):
        with self.assertRaises(ValueError):
            ll.genesis_with_alloc(self.G, ["OLD"], 1)

    def test_genesis_id(self):
        self.assertEqual(ll.genesis_id_of(self.G), "benchnet-v1")

    def test_node_config_overlay_keeps_other_keys(self):
        cfg = json.loads(ll.node_config('{"Archival": true, "TxPoolSize": 1}'))
        self.assertTrue(cfg["Archival"])
        self.assertEqual(cfg["TxPoolSize"], 150000)
        self.assertEqual(cfg["DNSBootstrapID"], "")

    def test_template_has_equal_online_stake_for_four_nodes(self):
        t = ll.template(1000)
        self.assertEqual([w["Stake"] for w in t["Genesis"]["Wallets"]], [25] * 4)
        self.assertEqual(len(t["Nodes"]), 5)
        self.assertEqual([n["Name"] for n in t["Nodes"]],
                         [ll.NODE_DIRS[s] for s in ll.SERVICES])


class StatsTest(unittest.TestCase):
    def lines(self):
        return [ll.parse_stats_line(x) for x in read("docker-stats.jsonl").splitlines()]

    def test_sizes(self):
        self.assertEqual(ll.parse_size("30.5MiB"), int(30.5 * 1024 * 1024))
        self.assertEqual(ll.parse_size("1.5MB"), 1_500_000)
        self.assertEqual(ll.parse_size("0B"), 0)
        self.assertEqual(ll.parse_size("2GiB"), 2 * 1024 ** 3)
        for bad in ("", "x", "12 parsecs"):
            with self.assertRaises(ValueError):
                ll.parse_size(bad)

    def test_parse_docker_stats_fixture(self):
        rows = self.lines()
        self.assertEqual([r["name"] for r in rows], ["bl-relay", "bl-part1", "bl-part2"])
        self.assertEqual(rows[1]["cpu_pct"], 87.25)
        self.assertEqual(rows[1]["mem_bytes"], int(204.8 * 1024 * 1024))
        self.assertEqual(rows[1]["blk_read"], 1_500_000)
        self.assertEqual(rows[2]["blk_write"], 10_000_000)
        self.assertEqual(rows[2]["mem_bytes"], int(1.5 * 1024 ** 3))

    def samples(self):
        out = []
        for t, cpu, mem, wr in ((0, 100, 100, 1000), (1, 300, 200, 5000), (2, 200, 150, 9000)):
            out.append({"t": t, "node": "a", "cpu_pct": cpu, "mem_bytes": mem * ll.MIB,
                        "blk_write": wr})
            out.append({"t": t, "node": "b", "cpu_pct": cpu / 2, "mem_bytes": mem * ll.MIB * 2,
                        "blk_write": wr * 2})
        return out

    def test_resource_summary_sums_nodes(self):
        r = ll.resource_summary(self.samples(), 0, 2)
        # a: mean 200% -> 2 cores; b: mean 100% -> 1 core
        self.assertAlmostEqual(r["cpu_cores"], 3.0)
        # peak RSS a 200 MiB + b 400 MiB
        self.assertAlmostEqual(r["rss_mb_peak"], 600.0)
        # written bytes: a 8000, b 16000
        self.assertAlmostEqual(r["blockio_write_mb"], 24000 / ll.MIB)
        self.assertEqual(r["nodes_sampled"], 2)

    def test_resource_summary_window_and_counter_reset(self):
        r = ll.resource_summary(self.samples(), 1, 1)
        self.assertAlmostEqual(r["cpu_cores"], 3.0 + 1.5)
        self.assertEqual(r["blockio_write_mb"], 0.0)
        reset = [{"t": 0, "node": "a", "cpu_pct": 1, "mem_bytes": 1, "blk_write": 900},
                 {"t": 1, "node": "a", "cpu_pct": 1, "mem_bytes": 1, "blk_write": 10}]
        self.assertEqual(ll.resource_summary(reset, 0, 1)["blockio_write_mb"], 0.0)

    def test_empty_window_has_no_summary(self):
        self.assertEqual(ll.resource_summary(self.samples(), 50, 60), {})


class WindowTest(unittest.TestCase):
    def test_confirmed_tps_and_round_time_from_two_block_headers(self):
        p0 = ll.block_point(json.loads(read("block-2.json")))
        p1 = ll.block_point(json.loads(read("block-12.json")))
        self.assertEqual(p0, {"round": 2, "ts": 1700000000, "tc": 0})
        w = ll.window_stats(p0, p1)
        self.assertEqual(w["txns"], 1500)
        self.assertEqual(w["secs"], 40)
        self.assertEqual(w["rounds"], 10)
        self.assertAlmostEqual(w["confirmed_tps"], 37.5)
        self.assertAlmostEqual(w["round_time_s"], 4.0)

    def test_no_chain_time_gives_no_rates(self):
        p = {"round": 3, "ts": 10, "tc": 5}
        w = ll.window_stats(p, dict(p, round=4, tc=9))
        self.assertIsNone(w["confirmed_tps"])
        self.assertIsNone(w["round_time_s"])
        self.assertEqual(w["txns"], 4)

    def test_missing_tc_defaults_to_zero(self):
        self.assertEqual(ll.block_point({"block": {"rnd": 1, "ts": 5}})["tc"], 0)


def loadgen(p50=120, samples=10, failed=0, drops=0, tps=480.0):
    return {"submission": {"achieved_submit_tps": tps, "failed_groups": failed,
                           "backpressure_drops_groups": drops},
            "confirmation": {"samples": samples, "p50_ms": p50, "p95_ms": p50 * 2,
                             "p99_ms": p50 * 3}}


class SubmitWindowTest(unittest.TestCase):
    def rep(self, **kw):
        sub = {"start_round": 10, "end_round": 30, "first_submit_unix_ms": 1_000_000,
               "last_submit_unix_ms": 1_060_000}
        sub.update(kw)
        return {"submission": sub}

    def test_window_is_the_generators_submission_interval(self):
        w = ll.submit_window(self.rep())
        self.assertEqual(w, {"start_round": 10, "end_round": 30, "t0": 1000.0, "t1": 1060.0})

    def test_container_startup_and_confirm_tail_do_not_dilute_the_rate(self):
        # The generator's window is 20 rounds / 60 s; a window padded by 25 s of
        # container start-up and a 30 s confirm tail would read far lower.
        blocks = {10: {"round": 10, "ts": 100, "tc": 1000},
                  30: {"round": 30, "ts": 160, "tc": 4000}}
        w = ll.submit_window(self.rep())
        stats = ll.window_stats(blocks[w["start_round"]], blocks[w["end_round"]])
        self.assertAlmostEqual(stats["confirmed_tps"], 50.0)
        padded = ll.window_stats(blocks[10], {"round": 40, "ts": 215, "tc": 4000})
        self.assertLess(padded["confirmed_tps"], stats["confirmed_tps"])

    def test_missing_rounds_or_instants_give_none(self):
        w = ll.submit_window(self.rep(start_round=None, end_round=None,
                                      first_submit_unix_ms=0, last_submit_unix_ms=0))
        self.assertEqual(w, {"start_round": None, "end_round": None, "t0": None, "t1": None})
        self.assertEqual(ll.submit_window({"submission": {}})["start_round"], None)


class RetryTest(unittest.TestCase):
    def test_a_flaky_call_is_retried_with_backoff(self):
        import urllib.error
        calls, sleeps = [], []

        def flaky():
            calls.append(1)
            if len(calls) < 3:
                raise urllib.error.URLError("connection reset")
            return 5

        self.assertEqual(ll.with_retry(flaky, attempts=4, delay=1.0, sleep=sleeps.append), 5)
        self.assertEqual(sleeps, [1.0, 2.0])

    def test_a_persistent_failure_raises_the_last_error_after_the_attempts(self):
        import urllib.error
        sleeps = []

        def down():
            raise urllib.error.URLError("refused")

        with self.assertRaises(urllib.error.URLError):
            ll.with_retry(down, attempts=3, delay=0.5, sleep=sleeps.append)
        self.assertEqual(sleeps, [0.5, 1.0])

    def test_a_real_failure_is_not_retried(self):
        import urllib.error
        sleeps = []

        def missing():
            raise urllib.error.HTTPError("u", 404, "not found", {}, None)

        with self.assertRaises(urllib.error.HTTPError):
            ll.with_retry(missing, attempts=4, delay=1.0, sleep=sleeps.append)
        self.assertEqual(sleeps, [])

    def test_transient_classification(self):
        import socket
        import urllib.error
        self.assertTrue(ll.is_transient(urllib.error.URLError("x")))
        self.assertTrue(ll.is_transient(socket.timeout()))
        self.assertTrue(ll.is_transient(ConnectionResetError()))
        self.assertTrue(ll.is_transient(urllib.error.HTTPError("u", 503, "x", {}, None)))
        self.assertFalse(ll.is_transient(urllib.error.HTTPError("u", 400, "x", {}, None)))
        self.assertFalse(ll.is_transient(ValueError("x")))


class DrainTest(unittest.TestCase):
    class Clock:
        t = 0.0

        def now(self):
            return self.t

        def sleep(self, d):
            self.t += d

    def test_a_drained_pool_returns_zero(self):
        c = self.Clock()
        seq = iter([50, 20, 0])
        self.assertEqual(ll.wait_drained(lambda: next(seq), 60, sleep=c.sleep, now=c.now), 0)

    def test_a_pool_that_never_drains_reports_the_backlog_instead_of_hiding_it(self):
        c = self.Clock()
        self.assertEqual(ll.wait_drained(lambda: 1234, 10, sleep=c.sleep, now=c.now), 1234)

    def test_unknown_pool_size_is_none(self):
        c = self.Clock()
        self.assertIsNone(ll.wait_drained(lambda: None, 5, sleep=c.sleep, now=c.now))

    def test_backlog_is_a_row_so_a_dirty_start_is_visible(self):
        self.assertEqual(ll.backlog_metrics(0), {"start_backlog_txns": ("txns", "lower", 0.0)})
        self.assertEqual(ll.backlog_metrics(900)["start_backlog_txns"][2], 900.0)
        self.assertEqual(ll.backlog_metrics(None), {})


class MetricsTest(unittest.TestCase):
    def test_latency_percentiles_tps_and_resources(self):
        window = {"confirmed_tps": 450.0, "round_time_s": 2.8}
        res = {"cpu_cores": 2.5, "rss_mb_peak": 900.0, "blockio_write_mb": 12.0}
        m = ll.step_metrics(loadgen(), window, res)
        self.assertEqual(m["confirmed_tps"], ("txn/s", "higher", 450.0))
        self.assertEqual(m["latency_p50_ms"], ("ms", "lower", 120.0))
        self.assertEqual(m["latency_p95_ms"][2], 240.0)
        self.assertEqual(m["latency_p99_ms"][2], 360.0)
        self.assertEqual(m["round_time_s"][2], 2.8)
        self.assertEqual(m["rejected_groups"][2], 0.0)
        self.assertEqual(m["rss_mb_peak"], ("MB", "lower", 900.0))

    def test_rejections_count_failures_and_drops(self):
        m = ll.step_metrics(loadgen(failed=3, drops=4), {}, {})
        self.assertEqual(m["rejected_groups"][2], 7.0)
        self.assertNotIn("confirmed_tps", m)  # no chain window -> no value, no row
        self.assertNotIn("cpu_cores", m)

    def test_no_confirmation_samples_means_no_latency_rows(self):
        m = ll.step_metrics(loadgen(samples=0), {}, {})
        self.assertFalse([k for k in m if k.startswith("latency")])

    def test_commit_span_comes_from_block_headers_not_polling(self):
        p0 = {"round": 4, "ts": 1000, "tc": 1000}
        last = {"round": 22, "ts": 1054, "tc": 1200}
        self.assertEqual(ll.commit_span(p0, last), {"secs": 54, "rounds": 18})

    def test_fixed_metrics_report_commit_time_rounds_and_set_tps(self):
        lg = loadgen()
        lg["fixed"] = {"confirmed_txns": 200}
        m = ll.fixed_metrics(lg, {}, {}, {"secs": 4, "rounds": 2})
        self.assertEqual(m["commit_time_s"], ("s", "lower", 4.0))
        self.assertEqual(m["commit_rounds"], ("rounds", "lower", 2.0))
        self.assertEqual(m["set_tps"], ("txn/s", "higher", 50.0))

    def test_fixed_metrics_without_chain_time_keep_the_round_count(self):
        lg = loadgen()
        lg["fixed"] = {"confirmed_txns": 200}
        m = ll.fixed_metrics(lg, {}, {}, {"secs": 0, "rounds": 1})
        self.assertNotIn("commit_time_s", m)
        self.assertNotIn("set_tps", m)
        self.assertEqual(m["commit_rounds"][2], 1.0)

    def test_the_generator_no_longer_reports_a_poll_based_commit_time(self):
        self.assertNotIn("all_confirmed_after_secs", json.dumps(ll.fixed_metrics(
            dict(loadgen(), fixed={"confirmed_txns": 1}), {}, {}, {"secs": 1, "rounds": 1})))


def side(txids=SHA_A, confirmed=None, n=200, **kw):
    r = {"fixed": {"expected_txns": n, "submitted_txns": n, "confirmed_txns": n,
                   "unconfirmed_txns": 0,
                   "submitted_txid_set_sha256": txids,
                   "confirmed_txid_set_sha256": confirmed or txids},
         "failed_groups": 0, "final_tc": n, "balances_sha256": SHA_A, "genesis_hash": "GH",
         "restarts": {s: {"restart_count": 0, "oom": False} for s in ll.SERVICES},
         "consistency": {"round": 9, "hashes": {s: "H" for s in ll.SERVICES}}}
    r.update(kw)
    return r


class GateTest(unittest.TestCase):
    def test_equal_runs_pass(self):
        self.assertEqual(ll.gate(side(), side(), 200), [])

    def test_different_submitted_sets_fail(self):
        errs = ll.gate(side(), side(txids=SHA_B), 200)
        self.assertTrue(any("fed different transaction sets" in e for e in errs))

    def test_different_committed_sets_fail_even_when_each_matches_its_own_input(self):
        errs = ll.gate(side(), side(confirmed=SHA_B), 200)
        self.assertTrue(any("committed different txid sets" in e for e in errs))
        self.assertTrue(any("rust: the confirmed txid set differs" in e for e in errs))

    def test_unconfirmed_txns_fail(self):
        bad = side()
        bad["fixed"].update(confirmed_txns=190, unconfirmed_txns=10)
        errs = ll.gate(side(), bad, 200)
        self.assertTrue(any("10 of 200" in e for e in errs))

    def test_expected_count_is_fixed_count_times_group_size(self):
        self.assertEqual(ll.expected_txns(200, 1), 200)
        self.assertEqual(ll.expected_txns(50, 4), 200)
        with self.assertRaises(ValueError):
            ll.expected_txns(0, 1)

    def test_generator_that_ran_another_count_fails_the_gate(self):
        bad = side()
        bad["fixed"]["expected_txns"] = 800  # e.g. a CLI default changed group size
        errs = ll.gate(side(), bad, 200)
        self.assertTrue(any("rust: the generator was asked for 800 txns" in e for e in errs))

    def test_wrong_submitted_count_fails(self):
        errs = ll.gate(side(n=199), side(n=199), 200)
        self.assertTrue(any("expected 200" in e for e in errs))

    def test_extra_txns_on_chain_fail(self):
        errs = ll.gate(side(), side(final_tc=201), 200)
        self.assertTrue(any("exactly 200" in e for e in errs))

    def test_balance_divergence_fails(self):
        errs = ll.gate(side(), side(balances_sha256=SHA_B), 200)
        self.assertTrue(any("different load-account balances" in e for e in errs))

    def test_genesis_mismatch_fails(self):
        errs = ll.gate(side(), side(genesis_hash="OTHER"), 200)
        self.assertTrue(any("different genesis hashes" in e for e in errs))

    def test_failed_groups_fail(self):
        errs = ll.gate(side(failed_groups=2), side(), 200)
        self.assertTrue(any("go: 2 groups were never accepted" in e for e in errs))

    def test_a_restarted_node_fails(self):
        bad = side()
        bad["restarts"]["part2"] = {"restart_count": 1, "oom": True}
        errs = ll.gate(side(), bad, 200)
        self.assertTrue(any("part2 restarted 1 time(s) (OOM killed)" in e for e in errs))

    def test_a_forked_cluster_fails(self):
        bad = side()
        bad["consistency"]["hashes"]["part3"] = "OTHER"
        errs = ll.gate(side(), bad, 200)
        self.assertTrue(any("disagree on block 9" in e for e in errs))

    def test_missing_node_in_consistency_check_fails(self):
        bad = side()
        del bad["consistency"]["hashes"]["part4"]
        errs = ll.gate(side(), bad, 200)
        self.assertTrue(any("not every node reported" in e for e in errs))

    def test_balances_digest_is_order_independent(self):
        a = ll.balances_digest({"A": 1, "B": 2})
        self.assertEqual(a, ll.balances_digest({"B": 2, "A": 1}))
        self.assertNotEqual(a, ll.balances_digest({"A": 1, "B": 3}))


class WaitTest(unittest.TestCase):
    class Clock:
        def __init__(self):
            self.t = 0.0

        def now(self):
            return self.t

        def sleep(self, d):
            self.t += d

    def test_returns_once_the_round_is_reached(self):
        c = self.Clock()
        seq = iter([None, 5, 7, 9, 12])
        got = ll.wait_for_round(lambda: next(seq), 9, 60, sleep=c.sleep, now=c.now)
        self.assertEqual(got, 9)
        self.assertGreater(c.t, 0)  # it waited (None and lagging rounds)

    def test_times_out_with_a_clear_error(self):
        c = self.Clock()
        with self.assertRaises(ll.RoundWaitError) as cm:
            ll.wait_for_round(lambda: 3, 10, 5, sleep=c.sleep, now=c.now)
        self.assertIn("round 10", str(cm.exception))
        self.assertIn("last saw 3", str(cm.exception))
        self.assertLessEqual(c.t, 7)

    def test_a_node_that_never_answers_times_out_too(self):
        c = self.Clock()
        with self.assertRaises(ll.RoundWaitError) as cm:
            ll.wait_for_round(lambda: None, 1, 3, sleep=c.sleep, now=c.now)
        self.assertIn("no answer", str(cm.exception))

    def test_no_target_returns_the_current_round_and_never_a_silent_none(self):
        self.assertEqual(ll.wait_for_round(lambda: 2, None, 1), 2)
        with self.assertRaises(ll.RoundWaitError):
            ll.wait_for_round(lambda: None, None, 1)

    def test_require_round_rejects_none(self):
        self.assertEqual(ll.require_round(4, "relay"), 4)
        with self.assertRaises(ll.RoundWaitError):
            ll.require_round(None, "relay")


class RowsTest(unittest.TestCase):
    def runs(self):
        def one(scale):
            return {"fixed": {"confirmed_tps": ("txn/s", "higher", 100.0 * scale)},
                    "ladder-500": {"confirmed_tps": ("txn/s", "higher", 400.0 * scale),
                                   "latency_p95_ms": ("ms", "lower", 800.0 / scale)}}
        return [{"go": one(1.0), "rust": one(2.0)}, {"go": one(1.1), "rust": one(2.2)}]

    def test_rows_are_valid_schema_v1_and_paired(self):
        rows = ll.result_rows(self.runs(), "localnet", {"profile": "smoke"})
        for r in rows:
            self.assertEqual(bench_schema.validate_result(r), [], r["name"])
        names = {(r["impl"], r["name"]) for r in rows}
        for n in ("fixed/confirmed_tps", "ladder-500/confirmed_tps",
                  "ladder-500/latency_p95_ms"):
            self.assertIn(("go", n), names)
            self.assertIn(("rust", n), names)
        go = next(r for r in rows if r["impl"] == "go" and r["name"] == "fixed/confirmed_tps")
        self.assertEqual(go["samples"], [100.0, 110.0])  # one per run, in run order
        self.assertEqual(go["better"], "higher")
        self.assertEqual(go["metadata"]["profile"], "smoke")

    def test_report_computes_a_rust_over_go_ratio(self):
        rows = ll.result_rows(self.runs(), "localnet", {})
        rep = report.build_report(rows)
        row = next(r for r in rep["rows"] if r["name"] == "fixed/confirmed_tps")
        self.assertAlmostEqual(row["ratio"], 2.0)


class ProfileTest(unittest.TestCase):
    def test_ladder_parsing(self):
        self.assertEqual(ll.parse_ladder("100, 500,1000"), [100, 500, 1000])
        self.assertEqual(ll.parse_ladder(""), [])
        for bad in ("0", "-5", "1.5", "x"):
            with self.assertRaises(ValueError):
                ll.parse_ladder(bad)

    def test_smoke_is_much_smaller_than_full(self):
        s, f = ll.PROFILES["smoke"], ll.PROFILES["full"]
        self.assertLess(s["fixed_count"], f["fixed_count"])
        self.assertLess(s["step_secs"] * len(s["ladder"]), f["step_secs"] * len(f["ladder"]))
        self.assertFalse(s["max_step"])
        self.assertEqual(f["ladder"], [100, 500, 1000, 2000])  # the issue's ladder
        self.assertTrue(f["max_step"])


class TierWiringTest(unittest.TestCase):
    """The tier script's own logic that needs no Docker."""

    def setUp(self):
        import importlib
        self.tier = importlib.import_module("localnet")
        self._env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)

    def test_settings_profiles_and_overrides(self):
        for k in [k for k in os.environ if k.startswith("BENCH_LOCALNET_")]:
            del os.environ[k]
        os.environ["BENCH_LOCALNET_PROFILE"] = "smoke"
        c = self.tier.settings()
        self.assertEqual(c["ladder"], [50])
        self.assertEqual(c["go_image"], "algorand/algod:" + self.tier.pinned_tag().lstrip("v"))
        self.assertFalse(c["go_image"].split(":")[1].startswith("v"))
        os.environ.update(BENCH_LOCALNET_LADDER="10,20", BENCH_LOCALNET_CPUS="3",
                          BENCH_LOCALNET_MAX_STEP="1", BENCH_LOCALNET_GO_IMAGE="x:y")
        c = self.tier.settings()
        self.assertEqual((c["ladder"], c["cpus"], c["max_step"], c["go_image"]),
                         ([10, 20], 3.0, True, "x:y"))

    def test_unknown_profile_and_bad_ladder_are_refused(self):
        os.environ["BENCH_LOCALNET_PROFILE"] = "turbo"
        with self.assertRaises(self.tier.TierError):
            self.tier.settings()
        os.environ["BENCH_LOCALNET_PROFILE"] = "smoke"
        os.environ["BENCH_LOCALNET_LADDER"] = "5,x"
        with self.assertRaises(ValueError):
            self.tier.settings()

    def test_check_report_demands_a_ratio_for_the_fixed_step(self):
        import tempfile
        rep = {"ok": True, "rows": [{"tier": "localnet", "name": "fixed/confirmed_tps",
                                     "ratio": 0.5}]}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "report.json")
            for r, bad in ((rep, False),
                           ({"ok": True, "rows": []}, True),
                           ({"ok": False, "errors": ["x"], "rows": []}, True),
                           ({"ok": True, "rows": [dict(rep["rows"][0], ratio=None)]}, True)):
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(r, f)
                self.assertEqual(bool(self.tier.check_report(p)), bad, r)

    def clean_env(self):
        for k in [k for k in os.environ if k.startswith("BENCH_LOCALNET_")]:
            del os.environ[k]
        os.environ["BENCH_LOCALNET_PROFILE"] = "smoke"

    def test_numeric_settings_are_validated_before_any_cluster_starts(self):
        for name, bad in (("FIXED_TPS", "0"), ("FIXED_TPS", "-3"), ("STEP_SECS", "0"),
                          ("FIXED_COUNT", "0"), ("ACCOUNTS", "0"), ("CPUS", "0"),
                          ("MEM", "lots"), ("PORT_BASE", "70000"), ("NUM_ROUNDS", "5")):
            self.clean_env()
            os.environ["BENCH_LOCALNET_" + name] = bad
            with self.assertRaises(self.tier.TierError, msg=f"{name}={bad}"):
                self.tier.settings()
        self.clean_env()
        os.environ["BENCH_LOCALNET_MEM"] = "512m"
        self.assertEqual(self.tier.settings()["mem"], "512m")

    def test_non_numeric_setting_is_a_tier_error(self):
        self.clean_env()
        os.environ["BENCH_LOCALNET_FIXED_TPS"] = "fast"
        with self.assertRaises(self.tier.TierError):
            self.tier.settings()

    def test_a_timed_out_loadgen_container_is_killed(self):
        import subprocess
        calls = []

        def fake(*args, **kw):
            calls.append(args)
            if args[0] == "run":
                raise subprocess.TimeoutExpired("docker", 5)

        with self.assertRaises(subprocess.TimeoutExpired):
            self.tier.run_container(fake, "bench-lg", ["img", "x"], 5)
        self.assertEqual(calls[0][:4], ("run", "--rm", "--name", "bench-lg"))
        self.assertEqual(calls[1][:3], ("rm", "-f", "bench-lg"))

    def test_a_clean_loadgen_container_is_not_force_removed(self):
        calls = []
        self.tier.run_container(lambda *a, **k: calls.append(a), "n", [], 5)
        self.assertEqual([c[0] for c in calls], ["run"])

    def test_completed_runs_are_written_when_a_later_run_fails(self):
        import tempfile
        runs = [{"go": {"fixed": {"confirmed_tps": ("txn/s", "higher", 10.0)}},
                 "rust": {"fixed": {"confirmed_tps": ("txn/s", "higher", 5.0)}}}]
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(self.tier.write_partial(d, runs, {"profile": "smoke"}, 2,
                                                    "gate failed"))
            with open(os.path.join(d, "localnet.json"), encoding="utf-8") as f:
                rows = json.load(f)
            self.assertEqual(len(rows), 2)
            for r in rows:
                self.assertEqual(bench_schema.validate_result(r), [])
                self.assertTrue(r["metadata"]["incomplete"])
                self.assertEqual(r["metadata"]["failed_run"], 2)
                self.assertEqual(r["metadata"]["failure"], "gate failed")

    def test_nothing_is_written_when_no_run_completed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(self.tier.write_partial(d, [], {}, 1, "x"))
            self.assertFalse(os.path.exists(os.path.join(d, "localnet.json")))

    def test_the_tier_is_discovered_by_the_runner(self):
        import run
        self.assertIn("localnet", run.discover_tiers())


if __name__ == "__main__":
    unittest.main()
