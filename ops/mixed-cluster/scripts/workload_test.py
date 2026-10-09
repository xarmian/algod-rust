#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for workload.py (issue #1674).  No Docker, no network.

    python3 ops/mixed-cluster/scripts/workload_test.py
"""

import base64
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import workload as wl  # noqa: E402

ADDR = "A" * 58


def txid(n):
    return ("T%051d" % n).replace("0", "A").replace("1", "B").replace("8", "C").replace("9", "D")[:52]


class FakeEnv:
    """Scripted stand-in for Env: every goal command "succeeds" and prints
    what real goal prints; commands whose text contains a key of `fail` exit
    non-zero.  Records every command it saw."""

    def __init__(self, fail=(), post_status=None, rounds=None):
        self.cmds = []
        self.fail = tuple(fail)
        self.n = 0
        self.app = 100
        self.asset = 500
        self.round = 10
        self.post_status = post_status or {"go-node-1": 400, "rust-node-4": 400}
        self.posts = []
        self.accounts = 0
        self.wallet = None

    def _next_tx(self):
        self.n += 1
        return txid(self.n)

    def sh(self, cmd, timeout=180):
        self.cmds.append(cmd)
        for f in self.fail:
            if f in cmd:
                return 1, "goal: boom ({})".format(f)
        t = self._next_tx()
        if "rawsend" in cmd:
            self.round += 1
            return 0, "Raw transaction ID {} issued\nTransaction {} committed in round {}\n".format(t, t, self.round)
        if " -o " in cmd or "-s -o" in cmd:
            return 0, ""
        return 0, ""

    def goal(self, args, timeout=180):
        cmd = "goal {} -d /algod/data".format(args)
        self.cmds.append(cmd)
        for f in self.fail:
            if f in args:
                return 1, "goal: boom ({})".format(f)
        if args.startswith("account new"):
            self.accounts += 1
            return 0, "Created new account with address {}\n".format(("B%057d" % self.accounts).replace("0", "A"))
        if args.startswith("account list"):
            return 0, "[online]\t{}\t{}\t1 microAlgos\n".format(ADDR, ADDR)
        t = self._next_tx()
        self.round += 1
        out = "Attempting\nIssued transaction from account X, txid {} (fee 1000)\nTransaction {} committed in round {}\n".format(
            t, t, self.round)
        if args.startswith("app create"):
            self.app += 1
            out += "Created app with app index {}\n".format(self.app)
        if args.startswith("asset create"):
            self.asset += 1
            out += "Created asset with asset index {}\n".format(self.asset)
        return 0, out

    def rest_json(self, path, node="go-node-1"):
        if "/v2/accounts/" in path:
            return {"amount": 10_000_000, "min-balance": 100000,
                    "created-assets": [{"index": self.asset}], "created-apps": [{"id": self.app}]}
        return {"last-round": self.round}

    def post_txn(self, node, raw):
        self.posts.append((node, raw))
        return self.post_status[node], "{}"

    def fetch_file_b64(self, path):
        return 0, base64.b64encode(b"signed-bytes").decode()

    def put_file(self, local, remote):
        self.cmds.append("put {} {}".format(local, remote))

    def current_round(self):
        return self.round

    def sleep(self, s):
        pass


def make(env=None, seed=1, **kw):
    out = io.StringIO()
    w = wl.Workload(env or FakeEnv(), out, seed, funder=ADDR, **kw)
    return w, out


def records(out):
    return [json.loads(x) for x in out.getvalue().splitlines()]


class HelpersTest(unittest.TestCase):
    def test_app_address_matches_go_algorand(self):
        # Application account reported by `goal app info --app-id 1079` on a
        # go-algorand v5.0.2-stable node.
        self.assertEqual(wl.app_address(1079), "RUCD7ASCU6TFKMIONZURZO5K5CMY6PCH4PM6BWQYG2NYQ7RNQSGZJ6IDXA")

    def test_parse_goal_output(self):
        t = "Q" * 52
        p = wl.parse_goal_output(
            "Issued transaction from account {a}, txid {t} (fee 1000)\nTransaction {t} committed in round 77\n"
            "Created app with app index 42\n".format(a=ADDR, t=t))
        self.assertEqual(p, {"txids": [t], "round": 77, "app_id": 42, "asset_id": None})

    def test_parse_does_not_mistake_address_for_txid(self):
        self.assertEqual(wl.parse_goal_output("to " + ADDR)["txids"], [])

    def test_genesis_funder(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"alloc": [{"addr": "X", "comment": "FeeSink"}, {"addr": "W1", "comment": "Wallet1"}]}, f)
        try:
            self.assertEqual(wl.genesis_funder(f.name), "W1")
        finally:
            os.unlink(f.name)
        self.assertIsNone(wl.genesis_funder("/nonexistent/genesis.json"))


class PlanTest(unittest.TestCase):
    def test_plan_is_deterministic_for_a_seed(self):
        a, _ = make(seed=7)
        b, _ = make(seed=7)
        self.assertEqual(a.plan(200), b.plan(200))

    def test_plan_differs_between_seeds(self):
        a, _ = make(seed=1)
        b, _ = make(seed=2)
        self.assertNotEqual(a.plan(200), b.plan(200))

    def test_first_pass_covers_every_scenario(self):
        a, _ = make(seed=3)
        self.assertEqual(a.plan(len(wl.SCENARIO_ORDER)), list(wl.SCENARIO_ORDER))
        self.assertEqual(set(wl.SCENARIO_ORDER), set(wl.Workload.SCENARIOS))
        self.assertEqual(set(wl.SCENARIO_WEIGHTS), set(wl.Workload.SCENARIOS))

    def test_plan_prefix_is_stable(self):
        a, _ = make(seed=5)
        self.assertEqual(a.plan(40), a.plan(400)[:40])

    def test_only_restricts_the_mix(self):
        a, _ = make(seed=5, only=["pay", "group"])
        self.assertEqual(set(a.plan(60)), {"pay", "group"})


class ScenarioTest(unittest.TestCase):
    def run_scenario(self, name, env=None, seed=1):
        env = env or FakeEnv()
        w, out = make(env, seed)
        w.actors = {k: ("%s" % k) * 58 for k in "ABCD"}
        w.scenario = name
        wl.Workload.SCENARIOS[name](w)
        return w, env, records(out)

    def test_every_scenario_runs_against_a_cooperative_node(self):
        for name in wl.SCENARIO_ORDER:
            env = FakeEnv()
            w, out = make(env)
            w.actors = {k: ("%s" % k) * 58 for k in "ABCD"}
            w.scenario = name
            if name == "group":
                w.box_app = 1
            try:
                wl.Workload.SCENARIOS[name](w)
            except wl.ScenarioAbort as e:  # pragma: no cover - failure detail
                self.fail("{}: {}".format(name, e))
            steps = [r for r in records(out) if r["kind"] == "workload_step"]
            self.assertTrue(steps, name)

    def test_boxes_scenario_exercises_every_box_opcode(self):
        _, env, recs = self.run_scenario("app_boxes")
        ops = [r["op"] for r in recs if r["kind"] == "workload_step"]
        for op in ("box_put", "box_create", "box_get", "box_extract", "box_replace", "box_splice",
                   "box_resize", "box_delete", "app_create", "app_delete"):
            self.assertIn(op, ops)
        joined = "\n".join(env.cmds)
        for arg in ("str:bput", "str:bcreate", "str:bget", "str:bext", "str:brepl", "str:bsplice",
                    "str:bresize", "str:bdel"):
            self.assertIn(arg, joined)

    def test_inner_scenario_exercises_every_inner_txn_kind(self):
        _, env, recs = self.run_scenario("app_inner")
        joined = "\n".join(env.cmds)
        for arg in ("ipay", "iasset", "iopt", "isend", "iaclose", "iappl", "icall", "idel"):
            self.assertIn("str:" + arg, joined)
        self.assertIn("closedel", joined)

    def test_close_delete_scenario_closes_the_app_account(self):
        _, env, recs = self.run_scenario("app_close_delete")
        self.assertTrue(any("app delete" in c and "closedel" in c for c in env.cmds))

    def test_notes_make_every_step_unique(self):
        _, env, _ = self.run_scenario("asset")
        notes = [c.split("--note ")[1].split()[0] for c in env.cmds if "--note " in c]
        self.assertEqual(len(notes), len(set(notes)))

    def test_same_seed_same_command_sequence(self):
        def cmds(seed):
            _, env, _ = self.run_scenario("pay", seed=seed)
            return [c for c in env.cmds if "clerk send" in c]
        self.assertEqual(cmds(9), cmds(9))
        self.assertNotEqual(cmds(9), cmds(10))

    def test_prerequisite_failure_aborts_the_scenario(self):
        env = FakeEnv(fail=("asset create",))
        w, out = make(env)
        w.actors = {k: ("%s" % k) * 58 for k in "ABCD"}
        with self.assertRaises(wl.ScenarioAbort):
            w.sc_asset()
        # the failure is still recorded as a step
        self.assertTrue(any(r.get("outcome") == "rejected" for r in records(out)))


class NegativeTest(unittest.TestCase):
    def neg(self, post_status):
        env = FakeEnv(post_status=post_status)
        w, out = make(env)
        w.negative("close_account_with_assets", "build", "/tmp/w/neg.stxn")
        return w, env, records(out)

    def test_both_reject_is_expected_and_clean(self):
        w, env, recs = self.neg({"go-node-1": 400, "rust-node-4": 400})
        step = [r for r in recs if r["kind"] == "workload_step"][0]
        self.assertEqual((step["outcome"], step["expect"], step["ok"]), ("rejected", "rejected", True))
        self.assertEqual({n for n, _ in env.posts}, {"go-node-1", "rust-node-4"})
        self.assertEqual(w.counters["submit_divergence"], 0)
        self.assertFalse([r for r in recs if r["kind"] == "workload_divergence"])

    def test_rust_admitting_what_go_rejects_is_a_divergence(self):
        w, _, recs = self.neg({"go-node-1": 400, "rust-node-4": 200})
        self.assertEqual(w.counters["submit_divergence"], 1)
        div = [r for r in recs if r["kind"] == "workload_divergence"]
        self.assertEqual(len(div), 1)
        self.assertEqual(div[0]["op"], "close_account_with_assets")

    def test_go_admitting_what_rust_rejects_is_a_divergence(self):
        w, _, recs = self.neg({"go-node-1": 200, "rust-node-4": 400})
        self.assertEqual(w.counters["submit_divergence"], 1)

    def test_both_admit_is_unexpected_but_not_a_divergence(self):
        w, _, recs = self.neg({"go-node-1": 200, "rust-node-4": 200})
        self.assertEqual(w.counters["submit_divergence"], 0)
        self.assertEqual(w.counters["unexpected"], 1)

    def test_unreachable_node_counts_as_divergence(self):
        w, _, _ = self.neg({"go-node-1": 400, "rust-node-4": 0})
        self.assertEqual(w.counters["submit_divergence"], 1)


class DriverTest(unittest.TestCase):
    def test_run_all_stops_on_duration_and_writes_summary(self):
        env = FakeEnv()
        ticks = iter(range(0, 10_000, 40))
        out = io.StringIO()
        w = wl.Workload(env, out, 1, duration_s=300, funder=ADDR, clock=lambda: next(ticks))
        w.run_all = wl.Workload.run_all.__get__(w)
        # setup() copies TEAL files with docker cp; the fake records it instead.
        w.run_all()
        recs = records(out)
        self.assertEqual(recs[0]["kind"], "workload_kmd")
        kinds = [r["kind"] for r in recs]
        self.assertIn("workload_meta", kinds)
        self.assertEqual(kinds[-1], "workload_summary")
        summary = recs[-1]
        self.assertGreater(summary["steps"], 4)
        self.assertEqual(summary["seed"], 1)

    def test_kmd_warmup_retries_then_switches_user(self):
        class FlakyKmd(FakeEnv):
            users = ("root", "algorand")
            user = "root"

            def goal(self, args, timeout=180):
                if args == "wallet list" and self.user == "root":
                    return 1, "Couldn't list wallets: connection refused"
                return super().goal(args, timeout)

        env = FlakyKmd()
        out = io.StringIO()
        w = wl.Workload(env, out, 1, funder=ADDR)
        w.warm_kmd()
        rec = records(out)[0]
        self.assertEqual((rec["kind"], rec["user"]), ("workload_kmd", "algorand"))

    def test_kmd_never_ready_aborts_setup_with_a_record(self):
        class DeadKmd(FakeEnv):
            def goal(self, args, timeout=180):
                return 1, "Couldn't list wallets: connection refused"

        out = io.StringIO()
        w = wl.Workload(DeadKmd(), out, 1, funder=ADDR)
        w.run_all()
        kinds = [r["kind"] for r in records(out)]
        self.assertIn("workload_abort", kinds)
        self.assertEqual(kinds[-1], "workload_summary")

    def test_scenario_abort_is_recorded_and_run_continues(self):
        env = FakeEnv(fail=("asset create",))
        out = io.StringIO()
        ticks = iter(range(0, 100_000, 5))
        w = wl.Workload(env, out, 1, duration_s=2000, funder=ADDR, clock=lambda: next(ticks))
        w.run_all()
        aborts = [r for r in records(out) if r["kind"] == "workload_abort"]
        self.assertTrue(aborts)
        self.assertGreater(len(w.scenario_counts), 1)

    def test_round_budget_stops_mid_scenario_and_still_writes_summary(self):
        class Advancing(FakeEnv):
            def current_round(self):
                self.round += 1  # every poll moves the chain forward
                return self.round

        env = Advancing()
        out = io.StringIO()
        w = wl.Workload(env, out, 1, rounds=wl.STOP_MARGIN_ROUNDS + 12, funder=ADDR)
        w.run_all()
        recs = records(out)
        self.assertEqual(recs[-1]["kind"], "workload_summary")
        # cut short: the first pass of scenarios (9) cannot have completed
        self.assertLess(sum(w.scenario_counts.values()), len(wl.SCENARIO_ORDER))

    def test_stops_when_round_budget_is_spent(self):
        env = FakeEnv()
        out = io.StringIO()
        w = wl.Workload(env, out, 1, rounds=5, funder=ADDR)
        w.start_round = env.round
        env.round += 10
        self.assertTrue(w.should_stop())


if __name__ == "__main__":
    unittest.main()
