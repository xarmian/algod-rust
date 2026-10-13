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

After the activation round it records what the Go nodes saw and then runs the
decisive check itself: `verify-soak.sh --cert-latest 1 --rust-account <NEW>
--min-rust-vote-rounds 1`, retried until the newest certificate carries the
joiner's vote and verifies under the Rust verifier AND the go-algorand verifier
(post-hoc verification can only cover the ledger snapshot's newest round, see
ops/mixed-cluster/README.md and issue #1854).

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


def verify_latest(account, tries, runner, outdir, sleep=time.sleep, wait_s=20):
    """Re-verify the NEWEST certificate under the Rust and go-algorand verifiers.

    Post-hoc verification can only cover the snapshot's newest round (the Rust
    ledger keeps online-account history back to ~tip - MaxBalLookback, like go),
    and a given round's cert carries the late joiner's vote only some of the
    time, so retry until one that does verifies.  Returns the attempt number of
    the first success, or None.
    """
    cmd = [
        # LATE_JOIN_BASH selects the bash (on Windows `bash` on PATH can be WSL's,
        # which cannot see C:/ paths; point it at Git Bash). Forward slashes:
        # a path with backslashes loses them in bash.
        os.environ.get("LATE_JOIN_BASH", "bash"), os.path.join(HERE, "verify-soak.sh").replace("\\", "/"),
        "--stride", "1", "--cert-latest", "1",
        "--rust-account", account, "--min-rust-vote-rounds", "1",
        "--out-dir", outdir.replace("\\", "/"),
    ]
    for attempt in range(1, tries + 1):
        if runner(cmd) == 0:
            return attempt
        sleep(wait_s)
    return None


def _run(cmd):
    return subprocess.call(cmd)


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
    ap.add_argument("--percent", type=int, default=18,
                    help="slice of the supply to fund the joiner with; a 10% account is almost never needed to reach the 74% cert threshold, 18% usually is")
    ap.add_argument("--margin", type=int, default=12, help="rounds to keep running after activation")
    ap.add_argument("--verify-tries", type=int, default=12,
                    help="attempts at the final newest-cert verification (0 = skip)")
    ap.add_argument("--verify-outdir", default=os.path.join(os.path.dirname(HERE), "late-join-verify"))
    ap.add_argument("--verify-only", metavar="ACCOUNT",
                    help="skip the scenario; only run the final newest-cert verification for ACCOUNT")
    ap.add_argument("--netroot", default=os.path.join(os.path.dirname(HERE), "netroot"))
    a = ap.parse_args(argv)

    if a.verify_only:
        os.makedirs(a.verify_outdir, exist_ok=True)
        n = verify_latest(a.verify_only, max(a.verify_tries, 1), _run, a.verify_outdir)
        print(json.dumps({"account": a.verify_only, "cert_verify_attempt": n}), flush=True)
        return 0 if n is not None else 3

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
    verified = None
    if a.verify_tries > 0 and after > 0:
        os.makedirs(a.verify_outdir, exist_ok=True)
        verified = verify_latest(new, a.verify_tries, _run, a.verify_outdir)
    summary["cert_verify_attempt"] = verified
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(summary, f)
    print(json.dumps(summary), flush=True)
    if after == 0:
        return 1
    if a.verify_tries > 0 and verified is None:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
