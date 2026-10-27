#!/usr/bin/env python3
#
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Issue #2071 (epic #2068): proves the node-soak parameterisation without
# a live run. `.github/workflows/network-node-soak.yml` is the reusable
# (`workflow_call`) soak; every `*-node-soak.yml` caller must
#   * pass only inputs the reusable workflow declares, and all required ones,
#   * pass a network-consistent genesis id / path,
# and the reusable workflow must not hard-code any network (no literal
# `mainnet` outside comments, apart from the documented ops/mainnet-soak
# directory name), so a voimain / aramidmain caller can never silently run
# mainnet parameters.
#
# The mainnet caller is additionally pinned to its historical parameters so
# the refactor cannot drift mainnet behaviour unnoticed.
#
# Run: python3 scripts/test_node_soak_callers.py

import glob
import os
import re
import sys
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF_DIR = os.path.join(ROOT, ".github", "workflows")
REUSABLE_PATH = os.path.join(WF_DIR, "network-node-soak.yml")
REUSABLE_USES = "./.github/workflows/network-node-soak.yml"


def load(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return yaml.safe_load(text), text


def triggers(doc):
    # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
    return doc.get("on", doc.get(True))


def callers():
    out = []
    for path in sorted(glob.glob(os.path.join(WF_DIR, "*.yml"))):
        if os.path.abspath(path) == os.path.abspath(REUSABLE_PATH):
            continue
        doc, _ = load(path)
        for name, job in (doc.get("jobs") or {}).items():
            if job.get("uses") == REUSABLE_USES:
                out.append((os.path.basename(path), name, job, doc))
    return out


class ReusableWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.doc, self.text = load(REUSABLE_PATH)
        self.inputs = triggers(self.doc)["workflow_call"]["inputs"]

    def test_declares_the_network_inputs(self):
        for name in ("network", "genesis_id", "genesis_path", "peer_url", "relay_discovery",
                     "catchpoint_index_url", "consensus_json", "probe_catchpoint_file"):
            self.assertIn(name, self.inputs)
        for name in ("network", "genesis_id", "genesis_path", "peer_url", "relay_discovery"):
            self.assertTrue(self.inputs[name].get("required"), name)

    def test_is_not_triggered_by_anything_but_workflow_call(self):
        self.assertEqual(list(triggers(self.doc).keys()), ["workflow_call"])

    def test_every_input_reference_is_declared(self):
        used = set(re.findall(r"\$\{\{\s*inputs\.([A-Za-z0-9_]+)", self.text))
        self.assertTrue(used)
        self.assertLessEqual(used, set(self.inputs), used - set(self.inputs))

    def test_every_declared_input_is_used(self):
        used = set(re.findall(r"\$\{\{\s*inputs\.([A-Za-z0-9_]+)", self.text))
        self.assertEqual(set(self.inputs) - used, set())

    def test_no_hardcoded_network_outside_comments(self):
        offenders = []
        for n, line in enumerate(self.text.splitlines(), 1):
            if re.match(r"\s*#", line):
                continue
            code = re.sub(r"ops/mainnet-soak", "", line)  # historical directory name
            if re.search(r"mainnet", code, re.I):
                offenders.append((n, line.strip()))
        self.assertEqual(offenders, [])

    def test_artifacts_and_temp_dirs_are_network_scoped(self):
        self.assertIn("${{ inputs.network }}-soak-artifacts", self.text)
        self.assertIn("/tmp/${NET}-soak-", self.text)
        self.assertIn("name: ${{ inputs.network }}-node-soak-${{ github.run_id }}", self.text)
        self.assertIn('--network "$NET"', self.text)

    def test_catchpoint_probe_is_opt_in_and_uses_the_base36_ledger_path(self):
        self.assertEqual(self.inputs["probe_catchpoint_file"]["default"], "false")
        self.assertIn('PROBE_PATH="/v1/$GENESIS_ID/ledger/$PROBE_B36"', self.text)

    def test_probe_mode_pins_the_proven_relay_as_gossip_peer(self):
        self.assertIn('PEER_ARGS=(--peers "${CATCHUP_PEER_URL#http://}")', self.text)
        self.assertIn('if [ "$PROBE_CATCHPOINT_FILE" = "true" ]', self.text)

    def test_file_issue_receives_the_network(self):
        self.assertRegex(self.text, r'file_issue\.py[\s\S]*?--network "\$NET"')

    def test_http_code_captures_survive_bash_e(self):
        # Issue #2099: steps run under `bash -e`, so a curl that times out
        # (exit 28 -- the expected outcome of the streaming catchpoint-file
        # probe) or fails to connect must not abort the step before the
        # captured `%{http_code}` is checked.
        captures = list(re.finditer(r'[A-Z_]*CODE="\$\(curl\b', self.text))
        self.assertGreaterEqual(len(captures), 5)
        offenders = []
        for m in captures:
            end = self.text.index(')"', m.end())
            if not self.text[end + 2:].startswith(" || true"):
                offenders.append(self.text.count("\n", 0, m.start()) + 1)
        self.assertEqual(offenders, [], "curl http_code captures without `|| true` at lines")


class CallerTest(unittest.TestCase):
    def test_at_least_the_mainnet_caller_exists(self):
        self.assertIn("mainnet-node-soak.yml", [c[0] for c in callers()])

    def test_voimain_caller_parameters(self):
        (_, _, spec, doc), = [c for c in callers() if c[0] == "voimain-node-soak.yml"]
        w = spec["with"]
        self.assertEqual(w["network"], "voimain")
        self.assertEqual(w["genesis_id"], "voimain-v1.0")
        self.assertEqual(w["genesis_path"], "bin/algod-rust/genesis/voimain-genesis.json")
        self.assertEqual(w["relay_discovery"], "srv:_algobootstrap._tcp.voimain.mainnet-voi.network")
        # the public gateway does not serve catchpoint files: relays must be probed
        self.assertEqual(w["probe_catchpoint_file"], "true")
        self.assertIn("https://mainnet-api.voi.nodely.dev", w["peer_url"])
        self.assertIn("vars.VOIMAIN_ALGOD_URL", w["peer_url"])
        self.assertEqual(doc["concurrency"]["group"], "voimain-node-soak")
        t = triggers(doc)
        self.assertIn("workflow_dispatch", t)
        self.assertNotIn("pull_request", t)
        self.assertNotIn("push", t)
        self.assertEqual(t["schedule"], [{"cron": "40 5 * * *"}])

    def test_aramidmain_caller_parameters(self):
        (_, _, spec, doc), = [c for c in callers() if c[0] == "aramidmain-node-soak.yml"]
        w = spec["with"]
        self.assertEqual(w["network"], "aramidmain")
        self.assertEqual(w["genesis_id"], "aramidmain-v1.0")
        self.assertEqual(w["genesis_path"], "bin/algod-rust/genesis/aramidmain-genesis.json")
        self.assertEqual(w["consensus_json"], "bin/algod-rust/consensus/aramidmain-consensus.json")
        self.assertEqual(w["relay_discovery"], "srv:_algobootstrap._tcp.aramidmain.a-wallet.net")
        self.assertEqual(w["probe_catchpoint_file"], "true")
        self.assertIn("https://algod.aramidmain.a-wallet.net", w["peer_url"])
        self.assertIn("vars.ARAMIDMAIN_ALGOD_URL", w["peer_url"])
        self.assertEqual(doc["concurrency"]["group"], "aramidmain-node-soak")
        t = triggers(doc)
        self.assertIn("workflow_dispatch", t)
        self.assertNotIn("pull_request", t)
        self.assertNotIn("push", t)
        self.assertEqual(t["schedule"], [{"cron": "20 7 * * *"}])
        # ~3 s blocks: the 5 min no-progress gate is ~100 blocks
        self.assertIn("'5'", w["halt_minutes"])

    def test_schedules_are_staggered(self):
        crons = []
        for _, _, _, doc in callers():
            crons += [s["cron"] for s in triggers(doc)["schedule"]]
        self.assertEqual(len(crons), len(set(crons)))
        # also distinct from every other scheduled workflow in the repo
        others = set()
        for path in glob.glob(os.path.join(WF_DIR, "*.yml")):
            doc, _ = load(path)
            if any(j.get("uses") == REUSABLE_USES for j in (doc.get("jobs") or {}).values()):
                continue
            others |= {s["cron"] for s in (triggers(doc) or {}).get("schedule", [])}
        self.assertEqual(set(crons) & others, set())

    def test_every_caller_matches_the_reusable_interface(self):
        _, text = load(REUSABLE_PATH)
        inputs = triggers(yaml.safe_load(text))["workflow_call"]["inputs"]
        required = {k for k, v in inputs.items() if v.get("required")}
        for fname, job, spec, _doc in callers():
            with_ = spec.get("with") or {}
            self.assertLessEqual(set(with_), set(inputs), f"{fname}:{job} passes unknown inputs")
            self.assertLessEqual(required, set(with_), f"{fname}:{job} misses required inputs")

    def test_every_caller_is_network_consistent(self):
        for fname, job, spec, _doc in callers():
            w = spec["with"]
            net = w["network"]
            self.assertTrue(w["genesis_id"].startswith(net + "-"), f"{fname}: genesis_id {w['genesis_id']}")
            self.assertIn(net, os.path.basename(w["genesis_path"]), f"{fname}: genesis_path")
            self.assertTrue(os.path.exists(os.path.join(ROOT, w["genesis_path"])), f"{fname}: genesis file")
            if w.get("consensus_json"):
                self.assertTrue(os.path.exists(os.path.join(ROOT, w["consensus_json"])), f"{fname}: consensus")
            self.assertRegex(w["relay_discovery"], r"^(peer|srv:\S+)$")

    def test_every_caller_grants_issue_write(self):
        # a called workflow cannot elevate beyond the caller's permissions
        for fname, job, spec, doc in callers():
            perms = spec.get("permissions") or doc.get("permissions") or {}
            self.assertEqual(perms.get("issues"), "write", fname)

    def test_each_network_has_its_own_concurrency_group(self):
        groups = [doc.get("concurrency", {}).get("group") for _, _, _, doc in callers()]
        self.assertTrue(all(groups))
        self.assertEqual(len(groups), len(set(groups)))

    def test_mainnet_caller_keeps_its_historical_parameters(self):
        (_, _, spec, doc), = [c for c in callers() if c[0] == "mainnet-node-soak.yml"]
        w = spec["with"]
        self.assertEqual(w["network"], "mainnet")
        self.assertEqual(w["genesis_id"], "mainnet-v1.0")
        self.assertEqual(w["genesis_path"], "crates/core/algo-ledger/tests/fixtures/mainnet-genesis.json")
        self.assertEqual(w["relay_discovery"], "srv:_algobootstrap._tcp.mainnet.algorand.network")
        self.assertEqual(
            w["catchpoint_index_url"],
            "https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/mainnet/latest.catchpoint",
        )
        self.assertIn("https://mainnet-api.4160.nodely.dev", w["peer_url"])
        self.assertIn("vars.MAINNET_ALGOD_URL", w["peer_url"])
        self.assertEqual(doc["concurrency"]["group"], "mainnet-node-soak")
        self.assertEqual(triggers(doc)["schedule"], [{"cron": "20 4 * * *"}])
        self.assertEqual(
            set(triggers(doc)["workflow_dispatch"]["inputs"]),
            {"duration_minutes", "follow_minutes", "algod_url", "halt_minutes", "dry_run_issues",
             "shadow_execute", "rust_log", "shadow_execute_sample_every"},
        )
        # defaults for scheduled runs (no dispatch inputs) are preserved
        self.assertIn("'240'", w["duration_minutes"])
        self.assertIn("'120'", w["follow_minutes"])
        self.assertIn("'5'", w["halt_minutes"])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
