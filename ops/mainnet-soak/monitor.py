#!/usr/bin/env python3

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Issue #1598 -- nightly mainnet node soak: halt detection + verdict.
#
# A single algod-rust `participate --network mainnet` process is started on
# the CI runner, told to fast-catchup (`POST /v2/catchup/{label}`) from a
# real mainnet relay/archival node, and polled on its own `/v2/status`
# alongside the catchup peer's `/v2/status` every ~10s for the run's
# duration. This module turns that stream of samples into a verdict: did
# the node ever go quiet (no observable progress) for `halt_minutes` while
# the peer proved the network was alive and ahead?
#
# Deliberately stdlib-only (no requests/pandas/etc.) and self-tested
# (`monitor.py self-test`, run before any verdict is trusted -- see
# `monitor_test.py` and the analogous `ops/mixed-cluster/scripts/
# analyze_test.py` pattern this mirrors) so the collector and the
# classifier stay in separate, independently-testable pieces: `collect()`/
# `main() --collect` produce the JSONL, `classify()` is a pure function
# over already-collected samples that every unit test exercises directly.
#
# Progress signature, per sample (see `signature()`):
#   - "catchup" phase (node's `/v2/status` `catchpoint` field non-empty):
#     the tuple of catchpoint-acquired-blocks/processed-accounts/
#     processed-kvs/verified-accounts/verified-kvs counters. A frozen
#     tuple means the download/account-import/verify pipeline stopped
#     moving, even though `last-round` isn't expected to advance yet.
#   - "follow" phase (no `catchpoint`): the node's `last-round`.
#
# Verdict, in priority order:
#   1. NODE_FAILURE -- the node process exited or its REST stopped
#      answering. Exit 1 (issue-worthy): the round is the last one
#      observed before the failure.
#   2. SOURCE_OUTAGE -- the node's own signature is frozen for
#      `halt_minutes`, but so is the peer's `last-round` (or the peer was
#      unreachable throughout that window). We cannot tell node staleness
#      from network staleness here, so this is a warning, never an issue.
#      Exit 2.
#   3. STUCK -- the node's signature is frozen for `halt_minutes` while the
#      peer's `last-round` kept advancing (proving the network was alive
#      and the node fell behind). Exit 1 (issue-worthy).
#   4. OK -- no stall observed. Exit 0. Includes a node that is still
#      catching up when the run's time budget runs out, as long as it was
#      making progress the whole time -- "didn't finish in the budget" is
#      not the same claim as "got stuck," and conflating them would turn a
#      slow-but-working run into a false-positive issue.

import argparse
import json
import statistics
import sys
import time
import unittest
from collections import namedtuple

DEFAULT_HALT_MINUTES = 5.0
DEFAULT_POLL_INTERVAL_S = 10.0
# How close the node's last-round must be to the peer's to call the node
# "at the tip" and end the catchup-phase clock. Matches the two-round
# slack `docs/SOAK_METHODOLOGY.md`-style harnesses in this repo already
# use for "caught up" checks under normal round-to-round jitter.
TIP_SLACK_ROUNDS = 2

Verdict = namedtuple(
    "Verdict",
    [
        "status",  # "ok" | "stuck" | "source_outage" | "node_failure"
        "phase",  # "catchup" | "follow" | None (node_failure with no samples)
        "round",  # int | None -- the round to report/dedup on
        "message",  # human-readable one-liner
        "stalled_since_s",  # float | None -- how long the frozen signature has held
    ],
)


def node_signature(sample: dict):
    """The (phase, signature) pair for one node sample. `None` if the
    sample itself reports the node unreachable (handled separately by the
    caller as a potential NODE_FAILURE, not folded into staleness math)."""
    node = sample.get("node") or {}
    if not node.get("ok", False):
        return None
    catchpoint = node.get("catchpoint") or ""
    if catchpoint:
        sig = (
            node.get("catchpoint_acquired_blocks"),
            node.get("catchpoint_processed_accounts"),
            node.get("catchpoint_processed_kvs"),
            node.get("catchpoint_verified_accounts"),
            node.get("catchpoint_verified_kvs"),
        )
        return ("catchup", sig)
    return ("follow", node.get("last_round"))


def peer_advancing_between(samples, start_idx, end_idx):
    """True if the peer's own reported `last_round` increased anywhere in
    samples[start_idx..=end_idx], or the peer was simply unreachable for
    the whole window (unknown, not proven-stalled -- treated as NOT
    advancing, i.e. inconclusive, by the caller)."""
    seen = []
    for s in samples[start_idx : end_idx + 1]:
        peer = s.get("peer") or {}
        if peer.get("ok") and isinstance(peer.get("last_round"), int):
            seen.append(peer["last_round"])
    if len(seen) < 2:
        return False
    return max(seen) > min(seen)


def classify(samples: list, halt_minutes: float = DEFAULT_HALT_MINUTES) -> Verdict:
    """Walk `samples` (ordered by `ts`, ascending) and return the verdict.

    `samples[i]` shape:
        {
          "ts": float (unix seconds),
          "node": {"ok": bool, "error": str|None, "catchpoint": str|None,
                    "catchpoint_acquired_blocks": int|None, ...,
                    "last_round": int|None},
          "peer": {"ok": bool, "error": str|None, "last_round": int|None},
        }
    """
    if not samples:
        return Verdict("ok", None, None, "no samples collected", None)

    halt_s = halt_minutes * 60.0

    # NODE_FAILURE: the *last* sample reports the node unreachable. A
    # transient blip earlier that later recovered is not a failure -- only
    # an unrecovered-at-end-of-stream unreachable node is (a live poller
    # stops the stream itself once this fires; a post-hoc analysis over
    # a completed JSONL sees the same condition at the tail).
    last = samples[-1]
    if not (last.get("node") or {}).get("ok", False):
        # Find the last round we DID observe, if any.
        last_round = None
        for s in reversed(samples):
            node = s.get("node") or {}
            if node.get("ok") and isinstance(node.get("last_round"), int):
                last_round = node["last_round"]
                break
        err = (last.get("node") or {}).get("error") or "unreachable"
        return Verdict(
            "node_failure",
            None,
            last_round,
            f"node became unreachable ({err})",
            None,
        )

    # Walk forward tracking how long the current signature has held.
    last_sig = None
    last_change_idx = 0
    last_change_ts = samples[0]["ts"]
    for i, s in enumerate(samples):
        sig = node_signature(s)
        if sig is None:
            # A mid-stream unreachable sample that later recovered: treat
            # it as "no information" rather than a signature change, so a
            # single flaky poll doesn't reset the stall clock to look
            # healthier than it is.
            continue
        if sig != last_sig:
            last_sig = sig
            last_change_idx = i
            last_change_ts = s["ts"]

    stalled_for = samples[-1]["ts"] - last_change_ts
    if stalled_for < halt_s:
        phase = last_sig[0] if last_sig else None
        return Verdict("ok", phase, None, "no stall observed", None)

    phase, sig = last_sig
    round_ = sig if phase == "follow" else (sig[0] if sig and sig[0] is not None else None)

    if peer_advancing_between(samples, last_change_idx, len(samples) - 1):
        return Verdict(
            "stuck",
            phase,
            round_,
            f"node made no progress for {stalled_for:.0f}s during {phase} "
            f"while the peer kept advancing",
            stalled_for,
        )
    return Verdict(
        "source_outage",
        phase,
        round_,
        f"node made no progress for {stalled_for:.0f}s, but the peer did not "
        f"prove the network was advancing either (unreachable or also stalled)",
        stalled_for,
    )


def verdict_context(samples: list, verdict: Verdict) -> dict:
    """Extra fields describing the moment of the verdict -- the last known
    node/peer round, node's own `time-since-last-round`, and (for a
    catchup-phase halt) the catchpoint label -- for the issue-filing
    template. Never raises; missing data becomes `None`."""
    node_last_round = None
    node_time_since_last_round = None
    peer_last_round = None
    catchpoint_label = None
    for s in reversed(samples):
        node = s.get("node") or {}
        peer = s.get("peer") or {}
        if node_last_round is None and isinstance(node.get("last_round"), int):
            node_last_round = node["last_round"]
        if node_time_since_last_round is None and node.get("time_since_last_round_ns") is not None:
            node_time_since_last_round = node["time_since_last_round_ns"]
        if peer_last_round is None and isinstance(peer.get("last_round"), int):
            peer_last_round = peer["last_round"]
        if catchpoint_label is None and node.get("catchpoint"):
            catchpoint_label = node["catchpoint"]
        if None not in (node_last_round, node_time_since_last_round, peer_last_round, catchpoint_label):
            break
    return {
        "node_last_round": node_last_round,
        "node_time_since_last_round": node_time_since_last_round,
        "peer_last_round": peer_last_round,
        "catchpoint_label": catchpoint_label,
    }


def exit_code_for(verdict: Verdict) -> int:
    return {
        "ok": 0,
        "stuck": 1,
        "node_failure": 1,
        "source_outage": 2,
    }[verdict.status]


# --- Fast-catchup timing + summary (healthy-run reporting) -----------------


def summarize(samples: list) -> dict:
    """Derive the reporting metrics for a (not necessarily stall-free) run:
    fast-catchup total time, a coarse per-counter-group phase breakdown,
    and tip-lag stats once the node reaches the tip. Never raises -- a
    metric that can't be computed from the given samples is `None`."""
    if not samples:
        return {
            "fast_catchup_seconds": None,
            "phase_seconds": {},
            "reached_tip": False,
            "lag_rounds": {"n": 0, "mean": None, "p95": None, "max": None},
        }

    t0 = samples[0]["ts"]
    catchup_end_ts = None
    phase_seconds = {"blocks": 0.0, "accounts": 0.0, "kvs": 0.0}
    lag_samples = []
    reached_tip = False

    prev_ts = t0
    prev_node = {}
    for s in samples:
        node = s.get("node") or {}
        peer = s.get("peer") or {}
        dt = s["ts"] - prev_ts

        if node.get("ok") and (node.get("catchpoint") or ""):
            # Attribute this interval's time to whichever counter group(s)
            # actually moved since the previous sample -- a mechanical,
            # non-domain-modeled phase split (see module doc comment).
            moved = set()
            for group, keys in (
                ("blocks", ("catchpoint_acquired_blocks",)),
                (
                    "accounts",
                    ("catchpoint_processed_accounts", "catchpoint_verified_accounts"),
                ),
                ("kvs", ("catchpoint_processed_kvs", "catchpoint_verified_kvs")),
            ):
                for k in keys:
                    if node.get(k) is not None and node.get(k) != prev_node.get(k):
                        moved.add(group)
            if moved:
                share = dt / len(moved)
                for group in moved:
                    phase_seconds[group] += share
            else:
                # No counter moved yet (e.g. the very first catchup
                # sample) -- still catchup time, just not attributable to
                # a specific sub-phase.
                phase_seconds.setdefault("unattributed", 0.0)
                phase_seconds["unattributed"] += dt
        elif node.get("ok") and catchup_end_ts is None and prev_node.get("catchpoint"):
            # First follow-phase sample right after a catchup phase: the
            # catchup clock stops here.
            catchup_end_ts = s["ts"]

        if node.get("ok") and not (node.get("catchpoint") or ""):
            peer_round = peer.get("last_round") if peer.get("ok") else None
            node_round = node.get("last_round")
            if isinstance(peer_round, int) and isinstance(node_round, int):
                lag = peer_round - node_round
                if lag <= TIP_SLACK_ROUNDS:
                    reached_tip = True
                if reached_tip:
                    lag_samples.append(max(lag, 0))

        prev_ts = s["ts"]
        if node.get("ok"):
            prev_node = node

    fast_catchup_seconds = (catchup_end_ts - t0) if catchup_end_ts is not None else None

    lag_stats = {"n": len(lag_samples), "mean": None, "p95": None, "max": None}
    if lag_samples:
        lag_stats["mean"] = statistics.mean(lag_samples)
        lag_stats["max"] = max(lag_samples)
        sorted_lag = sorted(lag_samples)
        idx = min(len(sorted_lag) - 1, int(round(0.95 * (len(sorted_lag) - 1))))
        lag_stats["p95"] = sorted_lag[idx]

    return {
        "fast_catchup_seconds": fast_catchup_seconds,
        "phase_seconds": {k: round(v, 1) for k, v in phase_seconds.items() if v > 0},
        "reached_tip": reached_tip,
        "lag_rounds": lag_stats,
    }


# --- Live collection ---------------------------------------------------


def fetch_status(base_url: str, token: str, timeout: float = 5.0) -> dict:
    """GET {base_url}/v2/status. Returns {"ok": True, **fields} or
    {"ok": False, "error": str}. stdlib-only (urllib), no requests dep."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        base_url.rstrip("/") + "/v2/status",
        headers={"X-Algo-API-Token": token} if token else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "error": str(e)}
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"invalid JSON: {e}"}
    return {
        "ok": True,
        "error": None,
        "catchpoint": body.get("catchpoint") or None,
        "catchpoint_acquired_blocks": body.get("catchpoint-acquired-blocks"),
        "catchpoint_processed_accounts": body.get("catchpoint-processed-accounts"),
        "catchpoint_processed_kvs": body.get("catchpoint-processed-kvs"),
        "catchpoint_total_accounts": body.get("catchpoint-total-accounts"),
        "catchpoint_total_blocks": body.get("catchpoint-total-blocks"),
        "catchpoint_total_kvs": body.get("catchpoint-total-kvs"),
        "catchpoint_verified_accounts": body.get("catchpoint-verified-accounts"),
        "catchpoint_verified_kvs": body.get("catchpoint-verified-kvs"),
        "last_round": body.get("last-round"),
        "time_since_last_round_ns": body.get("time-since-last-round"),
        "last_catchpoint": body.get("last-catchpoint") or None,
    }


def take_sample(node_url, node_token, peer_url, peer_token) -> dict:
    return {
        "ts": time.time(),
        "node": fetch_status(node_url, node_token),
        "peer": fetch_status(peer_url, peer_token),
    }


def collect(
    node_url,
    node_token,
    peer_url,
    peer_token,
    duration_s,
    halt_minutes,
    poll_interval_s,
    out_path,
    process_alive=lambda: True,
):
    """Poll both endpoints every `poll_interval_s` for up to `duration_s`,
    appending each sample to `out_path` as it's taken (so a killed/timed-out
    job still leaves a partial, analyzable JSONL). Stops early -- before
    the full duration -- the moment `classify()` on the samples-so-far
    would report anything other "ok" (a live halt, not just a slow catchup,
    is worth ending the run for early rather than burning the rest of the
    CI budget waiting it out). `process_alive` lets the caller report a
    known-dead child process immediately as a node_failure sample rather
    than waiting for the next failed poll.

    Returns the final `Verdict`.
    """
    start = time.time()
    samples = []
    with open(out_path, "a", encoding="utf-8") as f:
        while True:
            if not process_alive():
                samples.append(
                    {
                        "ts": time.time(),
                        "node": {"ok": False, "error": "process exited"},
                        "peer": fetch_status(peer_url, peer_token),
                    }
                )
            else:
                samples.append(take_sample(node_url, node_token, peer_url, peer_token))
            f.write(json.dumps(samples[-1]) + "\n")
            f.flush()

            verdict = classify(samples, halt_minutes)
            if verdict.status != "ok":
                return verdict
            if time.time() - start >= duration_s:
                return verdict
            time.sleep(poll_interval_s)


# --- CLI -----------------------------------------------------------------


def _load_jsonl(path: str) -> list:
    samples = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def build_result(samples: list, verdict: Verdict) -> dict:
    """The full JSON result both `analyze` and `collect` emit: the verdict,
    `verdict_context`'s halt-moment fields (consumed by `file_issue.py`'s
    template), and `summarize`'s healthy-run timing/lag metrics."""
    return {
        "status": verdict.status,
        "phase": verdict.phase,
        "round": verdict.round,
        "message": verdict.message,
        "stalled_since_s": verdict.stalled_since_s,
        **verdict_context(samples, verdict),
        **summarize(samples),
    }


def _emit(result: dict, json_out: str | None):
    print(json.dumps(result, indent=2))
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)


def _cmd_analyze(args):
    samples = _load_jsonl(args.jsonl)
    verdict = classify(samples, args.halt_minutes)
    _emit(build_result(samples, verdict), args.json_out)
    return exit_code_for(verdict)


def _cmd_collect(args):
    verdict = collect(
        node_url=args.node_url,
        node_token=args.node_token,
        peer_url=args.peer_url,
        peer_token=args.peer_token,
        duration_s=args.duration_minutes * 60.0,
        halt_minutes=args.halt_minutes,
        poll_interval_s=args.poll_interval_s,
        out_path=args.out,
    )
    samples = _load_jsonl(args.out)
    _emit(build_result(samples, verdict), args.json_out)
    return exit_code_for(verdict)


def _cmd_self_test(args):
    import os as _os

    this_dir = _os.path.dirname(_os.path.abspath(__file__))
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    # Both test modules -- monitor_test.py (classify/summarize/collect) and
    # file_issue_test.py (templating/dedup) -- so one self-test command
    # covers everything a run needs to trust before it goes live.
    suite.addTests(loader.discover(this_dir, pattern="monitor_test.py"))
    suite.addTests(loader.discover(this_dir, pattern="file_issue_test.py"))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 3


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_self_test = sub.add_parser("self-test", help="run monitor_test.py")
    p_self_test.set_defaults(func=_cmd_self_test)

    p_collect = sub.add_parser("collect", help="poll node+peer status, write JSONL, verdict")
    p_collect.add_argument("--node-url", required=True)
    p_collect.add_argument("--node-token", default="")
    p_collect.add_argument("--peer-url", required=True)
    p_collect.add_argument("--peer-token", default="")
    p_collect.add_argument("--duration-minutes", type=float, default=60.0)
    p_collect.add_argument("--halt-minutes", type=float, default=DEFAULT_HALT_MINUTES)
    p_collect.add_argument("--poll-interval-s", type=float, default=DEFAULT_POLL_INTERVAL_S)
    p_collect.add_argument("--out", required=True, help="JSONL output path")
    p_collect.add_argument("--json-out", default=None, help="verdict+summary JSON path")
    p_collect.set_defaults(func=_cmd_collect)

    p_analyze = sub.add_parser("analyze", help="verdict over an existing JSONL (dry runs, tests)")
    p_analyze.add_argument("jsonl")
    p_analyze.add_argument("--halt-minutes", type=float, default=DEFAULT_HALT_MINUTES)
    p_analyze.add_argument("--json-out", default=None)
    p_analyze.set_defaults(func=_cmd_analyze)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
