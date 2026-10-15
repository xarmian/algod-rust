#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for ports.py, the shared host-port table (issue #1956), and for
every checker deriving its node table from it (no cluster needed)."""
import importlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ports  # noqa: E402

DEFAULT = {"go-node-1": 4001, "go-node-2": 4002, "go-node-3": 4003,
           "rust-node-4": 4004, "go-node-5": 4005}


class HostPortBase(unittest.TestCase):
    def test_default_is_4000(self):
        self.assertEqual(ports.host_port_base(environ={}, env_file=None), 4000)

    def test_env_var_overrides(self):
        self.assertEqual(
            ports.host_port_base(environ={"PHASE6_HOST_PORT_BASE": "5000"}, env_file=None), 5000)

    def test_empty_env_var_means_unset(self):
        self.assertEqual(
            ports.host_port_base(environ={"PHASE6_HOST_PORT_BASE": ""}, env_file=None), 4000)

    def test_env_file_persisted_by_start_sh_is_the_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, ".phase6-env")
            with open(f, "w") as fh:
                fh.write("PHASE6_GENESIS_ID=phase6net-v1\nPHASE6_HOST_PORT_BASE=6000\r\n")
            self.assertEqual(ports.host_port_base(environ={}, env_file=f), 6000)
            # the environment wins over the file
            self.assertEqual(
                ports.host_port_base(environ={"PHASE6_HOST_PORT_BASE": "7000"}, env_file=f), 7000)

    def test_leading_zeros_are_decimal(self):
        # ports.sh normalises with $((10#...)); both sides must agree
        self.assertEqual(
            ports.host_port_base(environ={"PHASE6_HOST_PORT_BASE": "04000"}, env_file=None), 4000)

    def test_env_file_path_override_matches_ports_sh(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "elsewhere.env")
            with open(f, "w") as fh:
                fh.write("PHASE6_HOST_PORT_BASE=6000" + chr(10))
            self.assertEqual(ports.host_port_base(environ={"PHASE6_ENV_FILE": f}), 6000)
            # an explicit env_file argument is not overridden
            self.assertEqual(ports.host_port_base(environ={"PHASE6_ENV_FILE": f}, env_file=None), 4000)

    def test_missing_env_file_is_default(self):
        self.assertEqual(ports.host_port_base(environ={}, env_file="/nonexistent/.phase6-env"), 4000)

    def test_invalid_values_are_rejected(self):
        for bad in ("abc", "-1", "0", "65531", "4000.5", " 4000"):
            with self.assertRaises(ValueError, msg=bad):
                ports.host_port_base(environ={"PHASE6_HOST_PORT_BASE": bad}, env_file=None)
        self.assertEqual(ports.parse_base("65530"), 65530)
        self.assertEqual(ports.parse_base("1"), 1)


class CliTable(unittest.TestCase):
    def test_invalid_base_is_a_clean_error_not_a_traceback(self):
        import subprocess
        here = os.path.dirname(os.path.abspath(__file__))
        env = dict(os.environ, PHASE6_HOST_PORT_BASE="65531")
        for script in ("blockcompare.py", "stateproof_check.py", "workload.py", "metrics.py"):
            p = subprocess.run([sys.executable, os.path.join(here, script), "--help"],
                               env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 2, script)
            self.assertIn("error: PHASE6_HOST_PORT_BASE='65531'", p.stderr, script)
            self.assertNotIn("Traceback", p.stderr, script)


class NodeTable(unittest.TestCase):
    def test_default_table_matches_docker_compose(self):
        self.assertEqual(ports.node_ports(base=4000), DEFAULT)

    def test_table_is_base_plus_node_number(self):
        t = ports.node_ports(base=5000)
        self.assertEqual(t, {n: p + 1000 for n, p in DEFAULT.items()})
        self.assertEqual(ports.node_port("rust-node-4", base=5000), 5004)

    def test_unknown_node_is_an_error(self):
        with self.assertRaises(KeyError):
            ports.node_port("go-node-9", base=4000)

    def test_nodes_keeps_order(self):
        self.assertEqual(
            ports.nodes(("go-node-1", "rust-node-4"), base=4000),
            (("go-node-1", 4001), ("rust-node-4", 4004)))


class CheckersUseTheSharedTable(unittest.TestCase):
    """Each checker's module-level node table must come from ports.py so one
    PHASE6_HOST_PORT_BASE moves every script together."""

    def _reload(self, name, base):
        old = os.environ.get("PHASE6_HOST_PORT_BASE")
        os.environ["PHASE6_HOST_PORT_BASE"] = str(base)
        try:
            importlib.reload(ports)
            mod = importlib.import_module(name)
            return importlib.reload(mod)
        finally:
            if old is None:
                del os.environ["PHASE6_HOST_PORT_BASE"]
            else:
                os.environ["PHASE6_HOST_PORT_BASE"] = old
            importlib.reload(ports)

    def test_blockcompare(self):
        bc = self._reload("blockcompare", 5000)
        self.assertEqual(dict(bc.NODES), {n: DEFAULT[n] + 1000 for n in
                                          ("go-node-1", "go-node-2", "go-node-3", "rust-node-4")})
        bc = self._reload("blockcompare", 4000)
        self.assertEqual(dict(bc.NODES)["go-node-1"], 4001)

    def test_stateproof_check(self):
        sc = self._reload("stateproof_check", 5000)
        self.assertEqual(dict(sc.NODES)["rust-node-4"], 5004)
        self._reload("stateproof_check", 4000)

    def test_workload(self):
        wl = self._reload("workload", 5000)
        self.assertEqual(wl.NODE_PORTS["go-node-3"], 5003)
        self._reload("workload", 4000)

    def test_metrics(self):
        m = self._reload("metrics", 5000)
        self.assertEqual([n["port"] for n in m.NODES_REST], [5001, 5002, 5003])
        self.assertEqual(m.NODES_PARTICIPATION[0]["port"], 5004)
        self._reload("metrics", 4000)


if __name__ == "__main__":
    unittest.main()
