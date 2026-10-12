#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Late-joining online account scenario for the mixed cluster (issue #1821).

Exercises the balance-lookback policy of `LookupAgreement` (#1809/#1820) on
the live cluster: a brand-new account is funded with a slice of the supply,
installs a participation key on go-node-1 and goes online.  Its stake counts
for nothing until the balance lookback has passed (2 * SeedRefreshInterval *
SeedLookback rounds, 320 on the default consensus parameters); from the
*activation round* on, Go-produced certificates carry its votes and the Rust
node must resolve its voting key and weight from its own `onlineaccounts`
history.  A Rust node that counted the stake too early (current-state fallback)
or never would reject/mis-weigh those certificates.

This script only drives the scenario and records what the Go nodes saw.  The
decisive check is run afterwards, over the post-activation window, with

    verify-soak.sh --rust-account <NEW> --min-rust-vote-rounds 1 \
                   --from-round <ACTIVATION> --stride 1

which verifies Go certificates carrying the late joiner's votes under the Rust
verifier and the go-algorand verifier (see ops/mixed-cluster/README.md).

Usage (cluster already running from start.sh):
  late_join.py --out late_join.json [--percent 10] [--margin 12]
"""

import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

COMMITTED_RE = re.compile(r"committed in round (\d+)")


def balance_lookback(params):
    """BalanceLookback = 2 * SeedRefreshInterval * SeedLookback."""
    return 2 * int(params["SeedRefreshInterval"]) * int(params["SeedLookback"])


def activation_round(keyreg_round, lookback):
    """First round at which the late joiner's stake counts for agreement."""
    return int(keyreg_round) + int(lookback)


def stake_amount(total_money, percent):
    if not 0 < percent <= 50:
        raise ValueError("percent must be in (0, 50], got {}".format(percent))
    return int(total_money) * int(percent) // 100


def committed_round(goal_output):
    m = COMMITTED_RE.search(goal_output or "")
    return int(m.group(1)) if m else None


def votes_by_round(lines, account):
    """Round -> number of `VoteAccepted` records with Sender == account."""
    out = {}
    for line in lines:
        if "VoteAccepted" not in line or account not in line:
            continue
        try:
            rec = json.loads(line.strip())
        except ValueError:
            continue
        if rec.get("Type") != "VoteAccepted" or rec.get("Sender") != account:
            continue
        rnd = rec.get("ObjectRound", rec.get("Round"))
        out[rnd] = out.get(rnd, 0) + 1
    return out


def split_votes(votes, activation):
    before = sum(n for r, n in votes.items() if r is not None and r < activation)
    after = sum(n for r, n in votes.items() if r is not None and r >= activation)
    return before, after


def consensus_params(netroot, protocol="future"):
    path = os.path.join(netroot, "Node1", "consensus.json")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)[protocol]
    except (OSError, KeyError, ValueError):
        return {"SeedLookback": 2, "SeedRefreshInterval": 80}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--percent", type=int, default=10)
    ap.add_argument("--margin", type=int, default=12, help="rounds to keep running after activation")
    ap.add_argument("--netroot", default=os.path.join(os.path.dirname(HERE), "netroot"))
    a = ap.parse_args(argv)

    import workload as wl

    env = wl.Env()
    rc, out = env.sh("chmod 700 {}/kmd-v0.5; mkdir -p {}".format(wl.DATA_DIR, wl.WORK_DIR))
    if rc != 0:
        raise SystemExit("cannot prepare container: " + out)
    for attempt in range(30):  # cold kmd can refuse the first calls
        rc, out = env.goal("kmd start -t 0")
        rc2, out2 = env.goal("wallet list")
        if rc2 == 0:
            break
        time.sleep(2)
    rc, out = env.goal("account list")
    m = wl.ADDR_RE.search(out)
    if not m:
        raise SystemExit("cannot discover funder: " + out)
    funder = m.group(0)

    rc, out = env.goal("account new")
    mm = wl.NEW_ACCOUNT_RE.search(out) or wl.ADDR_RE.search(out)
    if not mm:
        raise SystemExit("no address in: " + out)
    new = mm.group(1) if mm.re is wl.NEW_ACCOUNT_RE else mm.group(0)

    supply = env.rest_json("/v2/ledger/supply")
    amount = stake_amount(supply["total-money"], a.percent)
    rc, out = env.goal("clerk send -f {} -t {} -a {}".format(funder, new, amount))
    fund_round = committed_round(out)
    if rc != 0 or fund_round is None:
        raise SystemExit("funding failed: " + out[-300:])

    first = env.current_round()
    rc, out = env.goal(
        "account addpartkey -a {} --roundFirstValid {} --roundLastValid {}".format(new, first, first + 100000)
    )
    if rc != 0:
        raise SystemExit("addpartkey failed: " + out[-300:])
    rc, out = env.goal("account changeonlinestatus -a {} -o".format(new))
    keyreg_round = committed_round(out)
    if rc != 0 or keyreg_round is None:
        raise SystemExit("go-online failed: " + out[-300:])

    lookback = balance_lookback(consensus_params(a.netroot))
    activation = activation_round(keyreg_round, lookback)
    summary = {
        "account": new,
        "funder": funder,
        "stake_microalgos": amount,
        "fund_round": fund_round,
        "keyreg_round": keyreg_round,
        "lookback": lookback,
        "activation_round": activation,
    }
    print("late joiner {} online at round {}; stake counts from round {}".format(new, keyreg_round, activation), flush=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(summary, f)

    target = activation + a.margin
    while True:
        cur = env.current_round()
        if cur is not None and cur >= target:
            break
        time.sleep(10)

    # Go-side evidence: VoteAccepted telemetry with the joiner as Sender.
    votes = {}
    for node in ("phase6-go-node-1", "phase6-go-node-2", "phase6-go-node-3"):
        p = subprocess.run(["docker", "logs", node], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        for r, n in votes_by_round(p.stdout.decode("utf-8", "replace").splitlines(), new).items():
            votes[r] = votes.get(r, 0) + n
    before, after = split_votes(votes, activation)
    summary.update({"final_round": env.current_round(), "go_votes_before_activation": before, "go_votes_after_activation": after})
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(summary, f)
    print(json.dumps(summary), flush=True)
    return 0 if after > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
