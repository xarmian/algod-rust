#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for topology.py (issue #2280): the peer graphs of the mixed
cluster's default topology and of the two opt-in "isolated Go participation
node" topologies."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import topology as tp  # noqa: E402

NODES = ("go-node-1", "go-node-2", "go-node-3", "rust-node-4")


def graph(plan):
    """Undirected peer graph: an edge when either side lists the other."""
    edges = set()
    for node, peers in plan.peers.items():
        for peer in peers:
            edges.add(frozenset((node, peer.split(":")[0])))
    return edges


def reachable(edges, start, without):
    seen, todo = {start}, [start]
    while todo:
        cur = todo.pop()
        for e in edges:
            if cur in e:
                (other,) = e - {cur}
                if other != without and other not in seen:
                    seen.add(other)
                    todo.append(other)
    return seen


class DefaultTopologyTest(unittest.TestCase):
    def test_the_default_plan_is_exactly_what_docker_compose_hardcoded(self):
        plan = tp.plan("default")
        self.assertEqual(plan.peers["go-node-1"], ["go-node-2:4161", "go-node-3:4161"])
        self.assertEqual(plan.peers["go-node-2"], ["go-node-1:4161", "go-node-3:4161"])
        self.assertEqual(plan.peers["go-node-3"], ["go-node-1:4161", "go-node-2:4161"])
        self.assertEqual(plan.peers["rust-node-4"],
                         ["go-node-1:4161", "go-node-2:4161", "go-node-3:4161"])
        self.assertEqual(plan.go3_net_address, "0.0.0.0:4161")
        self.assertFalse(plan.rust_force_relay)
        self.assertEqual(plan.sources, ("go-node-1", "rust-node-4"))

    def test_the_default_env_lines_equal_the_compose_defaults(self):
        env = dict(line.split("=", 1) for line in tp.env_lines(tp.plan("default")))
        self.assertEqual(env["PHASE6_GO1_PEERS"], "go-node-2:4161;go-node-3:4161")
        self.assertEqual(env["PHASE6_GO2_PEERS"], "go-node-1:4161;go-node-3:4161")
        self.assertEqual(env["PHASE6_GO3_PEERS"], "go-node-1:4161;go-node-2:4161")
        self.assertEqual(env["PHASE6_RUST_PEERS"],
                         "go-node-1:4161,go-node-2:4161,go-node-3:4161")


class ComposeTest(unittest.TestCase):
    """docker-compose.yml interpolates the plan's variables; with none set it
    must still be the default topology (issue #2280: the default is unchanged)."""

    def compose_defaults(self):
        import re
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docker-compose.yml")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        return dict(re.findall(r"\$\{(PHASE6_(?:GO[123]|RUST)_PEERS):-([^}]*)\}", text))

    def test_every_peer_list_is_interpolated_with_the_default_plan_as_its_default(self):
        defaults = self.compose_defaults()
        env = dict(line.split("=", 1) for line in tp.env_lines(tp.plan("default")))
        for key in ("PHASE6_GO1_PEERS", "PHASE6_GO2_PEERS", "PHASE6_GO3_PEERS", "PHASE6_RUST_PEERS"):
            self.assertIn(key, defaults)
            self.assertEqual(defaults[key], env[key], key)


class IsolatedGoNodeTest(unittest.TestCase):
    def test_behind_a_rust_relay_go_node_3_reaches_nobody_without_the_rust_node(self):
        plan = tp.plan("rust-relay")
        self.assertEqual(plan.peers["go-node-3"], ["rust-node-4:4162"])
        for node in ("go-node-1", "go-node-2", "rust-node-4"):
            self.assertFalse(any(p.startswith("go-node-3:") for p in plan.peers[node]),
                             "%s must not dial go-node-3" % node)
        self.assertEqual(reachable(graph(plan), "go-node-3", without="rust-node-4"),
                         {"go-node-3"})
        # ...and through the Rust node it reaches everyone.
        self.assertEqual(reachable(graph(plan), "go-node-3", without=None), set(NODES))
        self.assertTrue(plan.rust_force_relay)
        self.assertEqual(plan.go3_net_address, "")

    def test_the_control_puts_a_go_relay_where_the_rust_relay_was(self):
        plan = tp.plan("go-relay")
        self.assertEqual(plan.peers["go-node-3"], ["go-node-1:4161"])
        self.assertEqual(reachable(graph(plan), "go-node-3", without="go-node-1"),
                         {"go-node-3"})
        self.assertEqual(reachable(graph(plan), "go-node-3", without=None), set(NODES))
        for node in ("go-node-2", "rust-node-4"):
            self.assertFalse(any(p.startswith("go-node-3:") for p in plan.peers[node]))
        self.assertFalse(plan.rust_force_relay)
        self.assertEqual(plan.go3_net_address, "")

    def test_the_two_isolated_topologies_check_the_same_sources(self):
        # Comparable: the Go node behind the relay, a Go relay and the Rust node.
        a, b = tp.plan("rust-relay"), tp.plan("go-relay")
        self.assertEqual(a.sources, b.sources)
        self.assertEqual(a.sources, ("go-node-3", "go-node-1", "rust-node-4"))

    def test_rest_of_the_cluster_stays_connected_without_go_node_3(self):
        for name in ("rust-relay", "go-relay"):
            plan = tp.plan(name)
            edges = {e for e in graph(plan) if "go-node-3" not in e}
            self.assertEqual(reachable(edges, "go-node-1", without=None),
                             {"go-node-1", "go-node-2", "rust-node-4"}, name)


class CliTest(unittest.TestCase):
    def test_an_unknown_topology_is_rejected_naming_the_choices(self):
        with self.assertRaises(ValueError) as cm:
            tp.plan("mesh")
        for name in tp.TOPOLOGIES:
            self.assertIn(name, str(cm.exception))

    def test_env_lines_are_shell_safe_assignments(self):
        for name in tp.TOPOLOGIES:
            for line in tp.env_lines(tp.plan(name)):
                key, _, value = line.partition("=")
                self.assertRegex(key, r"^PHASE6_[A-Z0-9_]+$")
                self.assertNotRegex(value, r"[\s'\"$`]")

    def test_the_cli_prints_the_env_lines_and_the_sources(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(tp.main(["env", "rust-relay"]), 0)
        self.assertIn("PHASE6_GO3_PEERS=rust-node-4:4162", buf.getvalue().splitlines())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(tp.main(["sources", "rust-relay"]), 0)
        self.assertEqual(buf.getvalue().strip(), "go-node-3,go-node-1,rust-node-4")


if __name__ == "__main__":
    unittest.main()
