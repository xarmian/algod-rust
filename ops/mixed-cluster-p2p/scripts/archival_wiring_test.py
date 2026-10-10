#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Wiring checks for the mixed-cluster-p2p archival opt-in (issue #1782).

start.sh and verify-soak.sh need Docker, so these assert the contract
statically: the P2P harness must expose the same archival knob as
ops/mixed-cluster (PHASE6_GO_ARCHIVAL -> P2PINTEROP_GO_ARCHIVAL) and its
verifier must derive the cert window like mixed-cluster's verify-soak.sh
(#1777) instead of starting at round 1 of a pruned ledger. The helpers it
reuses are unit-tested in ops/mixed-cluster/scripts (rust_config_merge_test.py,
cert_window_test.py, cert_window_shell_test.sh).
"""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def read(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read().replace("\r\n", "\n")


class ArchivalWiringTest(unittest.TestCase):
    def test_start_sets_archival_on_go_nodes_and_rust_node(self):
        s = read("start.sh")
        self.assertIn("P2PINTEROP_GO_ARCHIVAL", s)
        # Written explicitly on every start (true or false), so a reused
        # netroot cannot carry a stale value.
        self.assertIn('"Archival=${GO_ARCHIVAL}"', s)
        self.assertRegex(s, r"mixed-cluster/scripts/rust_config_merge\.py\" - \"\$RUST_ARCHIVAL\"")
        # The merge runs before the Rust container is started.
        self.assertLess(s.index("rust_config_merge.py"), s.index("docker compose up -d --build rust-node-4"))

    def test_helper_scripts_exist(self):
        for name in ("rust_config_merge.py", "cert_window.sh", "cert_window.py"):
            self.assertTrue(
                os.path.exists(os.path.join(HERE, "..", "..", "mixed-cluster", "scripts", name)), name)

    def test_verify_soak_derives_the_cert_window_from_the_snapshot(self):
        v = read("verify-soak.sh")
        self.assertIn("mixed-cluster/scripts/cert_window.sh", v)
        self.assertIn("probe_earliest_container", v)
        self.assertIn("resolve_cert_window", v)
        # The cert pass starts at the derived round, not the raw FROM_ROUND.
        start = v.find('"$CERT_BIN" ' + chr(92) + chr(10))
        end = v.find("cert_rc=$?", start)
        self.assertTrue(0 <= start < end, "cert-crossverify invocation not found")
        cert_call = v[start:end]
        self.assertIn('--from-round "$CERT_FROM"', cert_call)
        self.assertNotRegex(cert_call, r'--from-round "\$FROM_ROUND"')
        # The fork detector keeps covering the whole range.
        self.assertRegex(v, r'--from-round "\$FROM_ROUND"')
        # The --cert-ledger override branch feeds the earliest-round probe.
        self.assertRegex(v, r'BLOCK_PATH="\$\{CERT_PREFIX_CANDIDATE\}\.block\.sqlite"')

    def test_runbook_documents_the_knob(self):
        with open(os.path.join(HERE, "..", "..", "..", "docs", "MIXED_CLUSTER_RUNBOOK.md"), encoding="utf-8") as f:
            self.assertIn("P2PINTEROP_GO_ARCHIVAL", f.read())


if __name__ == "__main__":
    unittest.main()
