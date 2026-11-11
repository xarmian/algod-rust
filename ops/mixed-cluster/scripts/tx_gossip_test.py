#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for tx_gossip.py (issue #2154).  No cluster needed: the network
is a fake that delivers each submitted transaction to the other nodes' pools
after a per-node delay."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tx_gossip as tg  # noqa: E402

NODES = ("go-node-1", "go-node-2", "go-node-3", "rust-node-4")


class FakeNet:
    """A clock and four nodes. `delay[(source, target)]` is the seconds until a
    transaction submitted to `source` is in `target`'s pool (None: never), and
    `commit_after` the seconds until it is confirmed everywhere."""

    def __init__(self, delay=None, commit_after=2.7, round0=100, round_s=2.7):
        self.t = 0.0
        self.delay = delay or {}
        self.commit_after = commit_after
        self.round0 = round0
        self.round_s = round_s
        self.submitted = {}  # txid -> (source, t)
        self.n = 0
        self.posts = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s

    def round_of(self, node):
        return self.round0 + int(self.t / self.round_s)

    def submit(self, node, raw):
        self.n += 1
        txid = "TX{:03d}".format(self.n)
        self.submitted[txid] = (node, self.t)
        self.posts.append((node, raw))
        return 200, '{"txId":"%s"}' % txid

    def pending(self, node, txid):
        """(status, confirmed_round) as /v2/transactions/pending/{txid}."""
        if txid not in self.submitted:
            return 404, 0
        source, t0 = self.submitted[txid]
        age = self.t - t0
        if age >= self.commit_after:
            return 200, self.round0 + int((t0 + self.commit_after) / self.round_s)
        d = 0.0 if node == source else self.delay.get((source, node), 0.2)
        if d is not None and age >= d:
            return 200, 0
        return 404, 0


def run(net, sources=("go-node-1", "rust-node-4"), count=3, within=6.0):
    return tg.run_check(net, nodes=NODES, sources=sources, count=count, within_s=within,
                        build=lambda src, i: ("raw-{}-{}".format(src, i)).encode(), poll_s=0.05)


class PerNodeTest(unittest.TestCase):
    def test_every_target_sees_every_txn_in_its_pool_within_a_round(self):
        net = FakeNet()
        res = run(net)
        self.assertTrue(res["pass"], res)
        for pair in res["pairs"]:
            self.assertEqual(pair["absent"], 0, pair)
            self.assertEqual(pair["in_pool_first"], 3, pair)
            self.assertLessEqual(pair["max_latency_s"], 1.0, pair)
        # Both Go-origin and Rust-origin sets reached the other three nodes.
        self.assertEqual({(p["source"], p["target"]) for p in res["pairs"]},
                         {(s, t) for s in ("go-node-1", "rust-node-4")
                          for t in NODES if t != s})

    def test_a_node_that_never_receives_the_txns_fails_the_check(self):
        net = FakeNet(delay={("go-node-1", "rust-node-4"): None})
        res = run(net)
        self.assertFalse(res["pass"])
        bad = [p for p in res["pairs"] if not p["ok"]]
        self.assertEqual([(p["source"], p["target"]) for p in bad],
                         [("go-node-1", "rust-node-4")])
        self.assertEqual(bad[0]["absent"], 0 if bad[0]["confirmed_first"] else 3)

    def test_a_late_arrival_beyond_the_budget_fails_even_though_it_arrived(self):
        net = FakeNet(delay={("rust-node-4", "go-node-2"): 2.0}, commit_after=30.0)
        res = run(net, within=1.0)
        self.assertFalse(res["pass"])
        bad = [p for p in res["pairs"] if not p["ok"]]
        self.assertEqual([(p["source"], p["target"]) for p in bad],
                         [("rust-node-4", "go-node-2")])
        self.assertGreater(bad[0]["max_latency_s"], 1.0)

    def test_confirmed_before_it_was_ever_seen_in_the_pool_is_not_gossip_evidence(self):
        # The txn reaches target only as a committed block (not in a pool at any
        # poll): not counted as pool receipt, and the pair needs >= 1 pool sighting.
        net = FakeNet(delay={("go-node-1", "go-node-3"): 99.0}, commit_after=0.3)
        res = run(net, sources=("go-node-1",))
        pair = [p for p in res["pairs"] if p["target"] == "go-node-3"][0]
        self.assertEqual(pair["in_pool_first"], 0)
        self.assertEqual(pair["confirmed_first"], 3)
        self.assertFalse(pair["ok"])
        self.assertFalse(res["pass"])

    def test_commit_rounds_are_recorded_per_source(self):
        net = FakeNet()
        res = run(net)
        for s in res["sources"]:
            self.assertGreaterEqual(s["commit_rounds"], 0, s)
            self.assertEqual(s["submitted"], 3)
            self.assertEqual(s["confirmed"], 3)

    def test_a_rejected_submission_aborts_with_the_node_response(self):
        class Rejecting(FakeNet):
            def submit(self, node, raw):
                return 400, "txn rejected"

        with self.assertRaises(tg.CheckError) as cm:
            run(Rejecting())
        self.assertIn("txn rejected", str(cm.exception))


class TopologyOptionsTest(unittest.TestCase):
    """Issue #2280: the sources come from the cluster topology, and the result
    says which topology produced it."""

    def test_sources_default_to_the_historical_pair(self):
        a = tg.parse_args(["--out", "x.json"])
        self.assertEqual(tg.resolve_sources(a), ("go-node-1", "rust-node-4"))
        self.assertEqual(a.topology, "default")

    def test_an_isolated_topology_adds_the_node_behind_the_relay_as_a_source(self):
        for topo in ("rust-relay", "go-relay"):
            a = tg.parse_args(["--out", "x.json", "--topology", topo])
            self.assertEqual(tg.resolve_sources(a), ("go-node-3", "go-node-1", "rust-node-4"))

    def test_explicit_sources_win_and_must_be_cluster_nodes(self):
        a = tg.parse_args(["--out", "x.json", "--sources", "go-node-2,rust-node-4"])
        self.assertEqual(tg.resolve_sources(a), ("go-node-2", "rust-node-4"))
        a = tg.parse_args(["--out", "x.json", "--sources", "go-node-9"])
        with self.assertRaises(tg.CheckError):
            tg.resolve_sources(a)

    def test_the_result_names_its_topology(self):
        net = FakeNet()
        res = tg.run_check(net, nodes=NODES, sources=("go-node-1",), count=2, within_s=6.0,
                           build=lambda s, i: b"x", poll_s=0.05, topology="rust-relay")
        self.assertEqual(res["topology"], "rust-relay")

    def test_a_source_behind_the_relay_is_checked_against_every_other_node(self):
        net = FakeNet()
        res = run(net, sources=("go-node-3", "go-node-1", "rust-node-4"))
        self.assertTrue(res["pass"], res)
        self.assertEqual({(p["source"], p["target"]) for p in res["pairs"]
                          if p["source"] == "go-node-3"},
                         {("go-node-3", t) for t in NODES if t != "go-node-3"})


class ParsingTest(unittest.TestCase):
    def test_the_txid_is_read_from_the_submit_response(self):
        self.assertEqual(tg.parse_txid('{"txId":"ABC"}'), "ABC")
        self.assertEqual(tg.parse_txid('{"txId": "ABC"}\n'), "ABC")
        with self.assertRaises(tg.CheckError):
            tg.parse_txid("no json")
        with self.assertRaises(tg.CheckError):
            tg.parse_txid("{}")

    def test_pending_states(self):
        self.assertEqual(tg.pending_state(404, 0), "absent")
        self.assertEqual(tg.pending_state(200, 0), "pool")
        self.assertEqual(tg.pending_state(200, 17), "confirmed")
        self.assertEqual(tg.pending_state(0, 0), "absent")


if __name__ == "__main__":
    unittest.main()
