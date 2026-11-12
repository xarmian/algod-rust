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

    def __init__(self, delay=None, commit_after=2.7, round0=100, round_s=2.7,
                 bulk=True, pending_stall=0.0, post_stall=0.0):
        self.bulk = bulk                    # False: the bulk pool list is unavailable
        self.pending_stall = pending_stall  # seconds each per-txid lookup takes
        self.post_stall = post_stall        # seconds each POST /v2/transactions takes
        self.commit_nodes = []              # nodes committed_rounds was asked for
        self.pending_calls = 0
        self.t = 0.0
        self.delay = delay or {}
        self.commit_after = commit_after
        self.round0 = round0
        self.round_s = round_s
        self.submitted = {}  # txid -> (source, t)
        self.n = 0
        self.posts = []
        self.raws = {}  # txid -> note

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s

    def round_of(self, node):
        return self.round0 + int(self.t / self.round_s)

    def submit(self, node, raw):
        self.n += 1
        txid = "TX{:03d}".format(self.n)
        self.t += self.post_stall   # the node answers, then gossips
        self.submitted[txid] = (node, self.t)
        self.posts.append((node, raw))
        self.raws[txid] = raw.decode()
        return 200, '{"txId":"%s"}' % txid

    def note_of(self, raw):
        return raw.decode()

    def pool_notes(self, node):
        """The notes in `node`'s pool as the bulk list (fast, never stalls);
        None when the bulk list is unavailable."""
        if not self.bulk:
            return None
        notes = set()
        for n, (txid, (source, t0)) in enumerate(self.submitted.items()):
            age = self.t - t0
            if age >= self.commit_after:
                continue
            d = 0.0 if node == source else self.delay.get((source, node), 0.2)
            if d is not None and age >= d:
                notes.add(self.raws[txid])
        return notes

    def committed_rounds(self, node, notes, from_round, wait_s):
        """note -> round it was committed in (what the blocks of `node` say)."""
        self.commit_nodes.append(node)
        out = {}
        end = self.t + wait_s
        while len(out) < len(notes) and self.t < end:
            for txid, (source, t0) in self.submitted.items():
                note = self.raws[txid]
                if note in notes and self.t - t0 >= self.commit_after:
                    out[note] = self.round0 + int((t0 + self.commit_after) / self.round_s)
            if len(out) < len(notes):
                self.t += 1.0
        return out

    def pending(self, node, txid):
        """(status, confirmed_round) as /v2/transactions/pending/{txid}."""
        self.pending_calls += 1
        self.t += self.pending_stall
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


class BulkPollTest(unittest.TestCase):
    """The first sighting is read from the bulk pool list, not per txid: a Go
    node's GET /v2/transactions/pending/{txid} takes 0.1 to 2.5 s and stalls
    (#2301), which made a Go-only control flake over the 6 s budget."""

    def test_a_stalling_per_txid_endpoint_does_not_matter_while_the_bulk_list_is_fast(self):
        net = FakeNet(pending_stall=8.0)
        res = run(net)
        self.assertTrue(res["pass"], res)
        for pair in res["pairs"]:
            self.assertLessEqual(pair["max_latency_s"], 1.0, pair)
        self.assertEqual(net.pending_calls, 0)

    def test_a_node_that_never_gets_the_txns_still_fails_with_a_fast_bulk_list(self):
        net = FakeNet(delay={("go-node-1", "go-node-3"): None}, pending_stall=8.0)
        res = run(net, sources=("go-node-1",))
        self.assertFalse(res["pass"])
        bad = [p for p in res["pairs"] if not p["ok"]]
        self.assertEqual([(p["source"], p["target"]) for p in bad], [("go-node-1", "go-node-3")])
        self.assertEqual(bad[0]["in_pool_first"], 0)  # never seen in its pool

    def test_a_txn_that_arrives_late_via_the_bulk_list_is_late(self):
        net = FakeNet(delay={("rust-node-4", "go-node-2"): 2.0}, commit_after=30.0)
        res = run(net, within=1.0)
        self.assertFalse(res["pass"])
        bad = [p for p in res["pairs"] if not p["ok"]]
        self.assertEqual([(p["source"], p["target"]) for p in bad], [("rust-node-4", "go-node-2")])

    def test_commit_rounds_come_from_the_blocks_not_from_per_txid_lookups(self):
        net = FakeNet(pending_stall=8.0)
        res = run(net)
        for s in res["sources"]:
            self.assertEqual(s["confirmed"], 3, s)
            self.assertGreaterEqual(s["commit_rounds"], 0, s)
        self.assertEqual(net.pending_calls, 0)

    def test_without_a_bulk_list_the_per_txid_path_still_works(self):
        net = FakeNet(bulk=False)
        res = run(net)
        self.assertTrue(res["pass"], res)
        self.assertGreater(net.pending_calls, 0)


class LatencyBaselineTest(unittest.TestCase):
    """A Go node's POST /v2/transactions can take seconds (its pool lock is held
    while it assembles a proposal); the gossip latency starts when the node has
    ANSWERED the submission, not when the request was sent."""

    def test_a_slow_post_is_not_gossip_latency(self):
        net = FakeNet(post_stall=3.0, commit_after=60.0)   # 3 payments: 9 s of POSTs
        res = run(net, within=6.0)
        self.assertTrue(res["pass"], res)
        for pair in res["pairs"]:
            self.assertLessEqual(pair["max_latency_s"], 1.0, pair)

    def test_a_real_gossip_delay_after_a_fast_post_still_fails(self):
        net = FakeNet(delay={("go-node-1", "go-node-3"): 7.0}, commit_after=60.0)
        res = run(net, sources=("go-node-1",), within=6.0)
        self.assertFalse(res["pass"])

    def test_the_slowest_post_is_reported_per_source(self):
        net = FakeNet(post_stall=2.0)
        res = run(net)
        for s in res["sources"]:
            self.assertEqual(s["max_post_s"], 2.0, s)

    def test_commit_rounds_are_read_from_the_reference_node(self):
        net = FakeNet()
        res = tg.run_check(net, nodes=NODES, sources=("go-node-3", "rust-node-4"), count=2,
                           within_s=6.0, build=lambda s, i: ("raw-{}-{}".format(s, i)).encode(),
                           poll_s=0.05, commit_node="go-node-1")
        self.assertEqual(set(net.commit_nodes), {"go-node-1"})
        self.assertTrue(all(s["confirmed"] == 2 for s in res["sources"]), res["sources"])


class KmdPrepareTest(unittest.TestCase):
    """`goal kmd start` kills the PID in kmd-v0.5/kmd.pid first (go
    nodecontrol StopKMD). The file left by `goal network create` holds a pid of
    ANOTHER container's process namespace; in go-node-1 it can be the entrypoint's
    or algod's own pid, so the first `goal kmd start` SIGTERMed the node (docker
    events: `container die exitCode=1` right after the exec, a crash loop)."""

    class FakeEnv:
        user = "root"

        def __init__(self):
            self.calls = []

        def sh(self, cmd):
            self.calls.append(("sh", cmd))
            return 0, ""

        def goal(self, cmd):
            self.calls.append(("goal", cmd))
            if cmd == "account list":
                return 0, "[online]	AAA	" + "A" * 58 + "	1 microAlgos"
            return 0, "wallets"

    def warm(self):
        net = tg.ClusterNet.__new__(tg.ClusterNet)
        net.env = self.FakeEnv()
        net.workload = type("W", (), {"DATA_DIR": "/algod/data"})
        net.funder = None
        net.warm()
        return net.env.calls

    def test_the_stale_kmd_pid_file_is_removed_before_kmd_is_started(self):
        calls = self.warm()
        first_goal = next(i for i, c in enumerate(calls) if c[0] == "goal")
        before = " ".join(c[1] for c in calls[:first_goal] if c[0] == "sh")
        self.assertIn("rm -f /algod/data/kmd-v0.5/kmd.pid", before)

    def test_the_work_dir_is_prepared_too(self):
        calls = self.warm()
        self.assertTrue(any("mkdir -p /tmp/w" in c[1] for c in calls if c[0] == "sh"))


class NoteDecodingTest(unittest.TestCase):
    def test_notes_are_read_from_go_and_rust_json_shapes(self):
        import base64
        go = {"top-transactions": [{"sig": "x", "txn": {"note": base64.b64encode(b"n-1").decode()}}]}
        rust = {"top-transactions": [{"txn": {"note": list(b"n-2")}}]}
        none = {"top-transactions": [{"txn": {"fee": 1}}]}
        self.assertEqual(tg.notes_of_pending(go), {"n-1"})
        self.assertEqual(tg.notes_of_pending(rust), {"n-2"})
        self.assertEqual(tg.notes_of_pending(none), set())
        self.assertEqual(tg.notes_of_pending({}), set())

    def test_notes_of_a_block_are_read_from_its_txns(self):
        import base64
        block = {"block": {"txns": [{"txn": {"note": base64.b64encode(b"n-3").decode()}},
                                    {"txn": {}}]}}
        self.assertEqual(tg.notes_of_block(block), {"n-3"})
        self.assertEqual(tg.notes_of_block({"block": {}}), set())


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
