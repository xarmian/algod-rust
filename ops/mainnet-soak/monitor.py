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
# Verify-phase allowance (issue #1623): algod-rust's `run_verify_ledger`
# (`crates/core/algo-ledger/src/sync/mod.rs`) rebuilds the Merkle trie and
# compares the catchpoint label in one single, non-incremental step -- it
# jumps straight from "importing" to the final verified-accounts/kvs count
# rather than reporting progress mid-trie-build the way go-algorand's own
# `updateVerifiedCounts` does. For a mainnet-sized catchpoint (~22.47M
# accounts) that single step has been observed to legitimately take 900+
# seconds with the catchup counters completely frozen the whole time --
# well past the default 5-minute `halt_minutes` used for genuine stalls.
# `is_verifying_signature()` recognizes this specific, already-visible-in-
# the-existing-fields window (import counters all fully caught up to their
# totals, verify counters not yet) and `classify()` gives it its own,
# longer-but-still-finite `verify_halt_minutes` allowance instead of the
# steady-state one -- so a real deadlock inside the trie rebuild is still
# eventually caught, just not mistaken for a stall at 5 minutes in.
#
# Verdict, in priority order:
#   0. INVALID_BLOCK_STALL (issue #1715) -- the node reports
#      `stalled-on-invalid-block` in `/v2/status` (or, when `/v2/status` does
#      not answer, the gauge `algod_rust_sync_stalled_on_invalid_block` is 1):
#      it is stuck on a block that deterministically fails to apply. Checked
#      before everything else, exit 1 (issue-worthy), round = the stalled
#      block's round, the status payload is kept in the summary.
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
#
# Follow window (`--follow-minutes`): once the node is first seen at the tip,
# `collect()` keeps polling for that many more minutes and then ends "ok";
# `--duration-minutes` stays the hard cap on total poll time, so the run ends
# at min(cap, first_tip + follow). `0` (default) disables it. The stall rules
# above keep applying throughout, so a halt inside the follow window is still
# a halt. Detailed catchup phases and the broken-state scan live in
# `nodelog.py` (`--node-log`, `scan-log`).

import argparse
import json
import statistics
import sys
import time
import unittest
from collections import namedtuple

import nodelog

DEFAULT_HALT_MINUTES = 5.0
# Generous-but-finite allowance for the single-shot, non-incremental
# `VerifyingLedger` window (issue #1623) -- observed real duration on
# mainnet is 900s+ (15min); this leaves wide margin above that while still
# catching a genuine deadlock inside the trie rebuild eventually, rather
# than exempting the phase from stall detection forever.
#
# Widened from 45 to 100 minutes (issue #1640, a real nightly-scheduled
# dispatch's false-positive "stuck" report): a single verify *attempt*
# taking ~15-20 minutes was never the whole story once two other, later
# mechanisms started compounding within the same window --
# (a) issue #1636's own in-process diagnostic (`verify_catchpoint`,
#     merged in #1639/#1641) reruns the *entire* trie rebuild a second
#     time in-process whenever the first pass's computed label mismatches,
#     roughly doubling that attempt's wall-clock cost on its own; and
# (b) issue #1638's defensive retry-on-verify-failure mitigation can then
#     trigger a full second download+import+verify cycle after that.
# A genuinely bad run (mismatch on both the primary and retried attempt,
# which issue #1636 shows is common against a still-not-root-caused real
# mainnet catchpoint) can therefore need import + verify + diagnostic
# rerun + a second full cycle -- comfortably over 60 real minutes -- before
# the node either succeeds or genuinely gives up. 100 minutes clears that
# real-world worst case with margin while remaining safely below this
# workflow's own 90-minute job `timeout-minutes` plus its default 60-minute
# `duration_minutes` collection window combined is not a hard ceiling here
# (a longer manual dispatch, as several of this issue's own live-dispatch
# investigation rounds used, can still exceed 100 minutes and get a real
# stuck verdict if genuinely deadlocked) -- but within the default 60-
# minute budget, this now means "the run legitimately couldn't finish in
# the time available" reads as `reached_tip: false` with no verdict, not a
# misleading `stuck` classification layered on top of an already-known,
# separately-tracked root cause (issue #1636).
DEFAULT_VERIFY_HALT_MINUTES = 100.0
# Post-verify allowance (issue #1663): once import and verify counters are
# both complete, the node still does the lookback block download (~4 min on
# mainnet), the go-catchpoint 320-block window replay (~4 min) and WAL
# checkpointing, none of which advance any `catchpoint-*` counter. The 5
# minute steady-state rule killed healthy nightlies there. This window is
# bounded (not the 100 minute verify one): a wedge here is still caught.
DEFAULT_POST_VERIFY_HALT_MINUTES = 30.0
# Grace window (issue #1623 live dispatch, run 36204923591): the
# non-incremental verify pass has been observed to starve the node's REST
# responder under CI-runner CPU contention badly enough that individual
# `/v2/status` polls time out -- a genuine-but-transient unresponsiveness,
# not a dead process -- so a single failed poll must not immediately be
# treated as NODE_FAILURE by the live collector. A generic transient blip
# (not known to be verify-related) gets this shorter allowance; one whose
# last known-good sample was mid-verify gets the longer
# `verify_halt_minutes` allowance instead (see `collect()`).
DEFAULT_UNREACHABLE_GRACE_MINUTES = 3.0
DEFAULT_POLL_INTERVAL_S = 10.0
# How close the node's last-round must be to the peer's to call the node
# "at the tip" and end the catchup-phase clock. Matches the two-round
# slack `docs/SOAK_METHODOLOGY.md`-style harnesses in this repo already
# use for "caught up" checks under normal round-to-round jitter.
TIP_SLACK_ROUNDS = 2

Verdict = namedtuple(
    "Verdict",
    [
        "status",  # "ok" | "stuck" | "source_outage" | "node_failure" | "invalid_block_stall"
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


def is_verifying_signature(sample: dict) -> bool:
    """True if `sample` shows the node genuinely inside the non-incremental
    `VerifyingLedger` window (issue #1623): every import-phase counter
    (acquired blocks, processed accounts, processed kvs) has fully caught
    up to its known total, but the verify-phase counters (verified
    accounts/kvs) have not yet -- the exact frozen state
    `run_verify_ledger` produces for the whole duration of its single-shot
    Merkle-trie rebuild + label comparison, before it jumps straight to
    the final verified counts. `False` for a node that isn't in a
    catchpoint catchup at all, or is still mid-import (a real stall there
    is not given this longer allowance)."""
    node = sample.get("node") or {}
    if not node.get("ok", False) or not (node.get("catchpoint") or ""):
        return False

    def done(total_key, val_key):
        total = node.get(total_key)
        val = node.get(val_key)
        return isinstance(total, int) and isinstance(val, int) and val >= total

    import_done = (
        done("catchpoint_total_blocks", "catchpoint_acquired_blocks")
        and done("catchpoint_total_accounts", "catchpoint_processed_accounts")
        and done("catchpoint_total_kvs", "catchpoint_processed_kvs")
    )
    verify_done = done("catchpoint_total_accounts", "catchpoint_verified_accounts") and done(
        "catchpoint_total_kvs", "catchpoint_verified_kvs"
    )
    return import_done and not verify_done


def is_post_verify_signature(sample: dict) -> bool:
    """True if `sample` shows a catchpoint catchup whose import AND verify
    counters are all complete (issue #1663): the remaining work (lookback
    download, window replay, WAL checkpoint) does not move any counter."""
    node = sample.get("node") or {}
    if not node.get("ok", False) or not (node.get("catchpoint") or ""):
        return False

    def done(total_key, val_key):
        total = node.get(total_key)
        val = node.get(val_key)
        return isinstance(total, int) and isinstance(val, int) and val >= total

    # total_blocks must be positive so the all-zero download state is not
    # mistaken for "complete".
    blocks = node.get("catchpoint_total_blocks")
    return (
        isinstance(blocks, int)
        and blocks > 0
        and done("catchpoint_total_blocks", "catchpoint_acquired_blocks")
        and done("catchpoint_total_accounts", "catchpoint_processed_accounts")
        and done("catchpoint_total_kvs", "catchpoint_processed_kvs")
        and done("catchpoint_total_accounts", "catchpoint_verified_accounts")
        and done("catchpoint_total_kvs", "catchpoint_verified_kvs")
    )


def is_downloading_signature(sample: dict) -> bool:
    """True if `sample` shows a catchpoint catchup whose every progress
    counter and total is still zero: the catchpoint *file download*, before
    the importer has read the header (issue #1650 live dispatch: a slow relay
    took ~5 minutes to serve the file, tripping the 5-minute stuck rule with
    the node perfectly healthy). Given the same longer allowance as verify."""
    node = sample.get("node") or {}
    if not node.get("ok", False) or not (node.get("catchpoint") or ""):
        return False
    keys = (
        "catchpoint_total_blocks",
        "catchpoint_total_accounts",
        "catchpoint_total_kvs",
        "catchpoint_acquired_blocks",
        "catchpoint_processed_accounts",
        "catchpoint_processed_kvs",
        "catchpoint_verified_accounts",
        "catchpoint_verified_kvs",
    )
    return all(node.get(k) == 0 for k in keys)


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


def _stall_of(sample: dict):
    """The `stalled_on_invalid_block` payload of one sample's node, or None."""
    stall = (sample.get("node") or {}).get("stalled_on_invalid_block")
    return stall if isinstance(stall, dict) and stall else None


def describe_stall(stall: dict) -> str:
    """One-line description (round, error, consecutive failures) of a stall."""
    parts = [f"node stalled on invalid block {stall.get('round')}"]
    if stall.get("error"):
        parts.append(f": {nodelog.sanitize_text(stall['error'])}")
    if stall.get("consecutive_failures") is not None:
        parts.append(f" ({stall['consecutive_failures']} consecutive failures)")
    if stall.get("source") == "gauge":
        parts.append(" [from the /metrics gauge; /v2/status unavailable]")
    return "".join(parts)


def classify(
    samples: list,
    halt_minutes: float = DEFAULT_HALT_MINUTES,
    verify_halt_minutes: float = DEFAULT_VERIFY_HALT_MINUTES,
    post_verify_halt_minutes: float = DEFAULT_POST_VERIFY_HALT_MINUTES,
) -> Verdict:
    """Walk `samples` (ordered by `ts`, ascending) and return the verdict.

    `samples[i]` shape:
        {
          "ts": float (unix seconds),
          "node": {"ok": bool, "error": str|None, "catchpoint": str|None,
                    "catchpoint_acquired_blocks": int|None, ...,
                    "last_round": int|None},
          "peer": {"ok": bool, "error": str|None, "last_round": int|None},
        }

    A frozen signature whose most recent sample looks like the node is
    genuinely inside the non-incremental verify window
    (`is_verifying_signature()`, issue #1623) is judged against
    `verify_halt_minutes` instead of `halt_minutes` -- longer, but still
    finite, so a real deadlock in that phase is still eventually caught.
    """
    if not samples:
        return Verdict("ok", None, None, "no samples collected", None)

    halt_s = halt_minutes * 60.0

    # INVALID_BLOCK_STALL (issue #1715): the node says it cannot apply a
    # block. Only a stall still present in the LAST sample fails the run: one
    # that cleared (a valid block committed, later samples healthy) is only
    # reported as `invalid_block_stall_cleared`, and an unreachable node at the
    # end is a node_failure.
    if _stall_of(samples[-1]):
        stall = _stall_of(samples[-1])
        first = len(samples) - 1
        while first > 0 and _stall_of(samples[first - 1]):
            first -= 1
        phase = None
        for s in reversed(samples):
            sig = node_signature(s)
            if sig is not None:
                phase = sig[0]
                break
        return Verdict(
            "invalid_block_stall",
            phase,
            stall.get("round"),
            describe_stall(stall),
            samples[-1]["ts"] - samples[first]["ts"],
        )

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
    verifying = (
        last_sig is not None
        and last_sig[0] == "catchup"
        and (is_verifying_signature(samples[-1]) or is_downloading_signature(samples[-1]))
    )
    post_verify = (
        not verifying
        and last_sig is not None
        and last_sig[0] == "catchup"
        and is_post_verify_signature(samples[-1])
    )
    if verifying:
        effective_halt_s = verify_halt_minutes * 60.0
    elif post_verify:
        effective_halt_s = max(post_verify_halt_minutes, halt_minutes) * 60.0
    else:
        effective_halt_s = halt_s

    if stalled_for < effective_halt_s:
        phase = last_sig[0] if last_sig else None
        return Verdict("ok", phase, None, "no stall observed", None)

    phase, sig = last_sig
    round_ = sig if phase == "follow" else (sig[0] if sig and sig[0] is not None else None)

    verify_note = " (past the verify-phase allowance)" if verifying else ""
    if post_verify:
        verify_note = " (past the post-verify allowance)"

    if peer_advancing_between(samples, last_change_idx, len(samples) - 1):
        return Verdict(
            "stuck",
            phase,
            round_,
            f"node made no progress for {stalled_for:.0f}s during {phase}"
            f"{verify_note} while the peer kept advancing",
            stalled_for,
        )
    return Verdict(
        "source_outage",
        phase,
        round_,
        f"node made no progress for {stalled_for:.0f}s{verify_note}, but the peer did not "
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
    invalid_block_stall = None
    invalid_block_stall_cleared = None
    stalled = [s for s in samples if _stall_of(s)]
    if stalled and verdict.status == "invalid_block_stall":
        invalid_block_stall = _stall_of(stalled[-1])
    elif stalled:
        last_payload = _stall_of(stalled[-1])
        invalid_block_stall_cleared = {
            "round": last_payload.get("round"),
            "error": last_payload.get("error"),
            "consecutive_failures": last_payload.get("consecutive_failures"),
            "first_ts": stalled[0]["ts"],
            "last_ts": stalled[-1]["ts"],
        }
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
        "invalid_block_stall": invalid_block_stall,
        "invalid_block_stall_cleared": invalid_block_stall_cleared,
    }


def exit_code_for(verdict: Verdict) -> int:
    return {
        "ok": 0,
        "stuck": 1,
        "node_failure": 1,
        "invalid_block_stall": 1,
        "source_outage": 2,
    }[verdict.status]


# --- Fast-catchup timing + summary (healthy-run reporting) -----------------


def _lag_stats(lag_samples: list) -> dict:
    stats = {"n": len(lag_samples), "mean": None, "p50": None, "p95": None, "p99": None, "max": None}
    if lag_samples:
        stats["mean"] = statistics.mean(lag_samples)
        stats["max"] = max(lag_samples)
        sorted_lag = sorted(lag_samples)
        for key, q in (("p50", 0.50), ("p95", 0.95), ("p99", 0.99)):
            idx = min(len(sorted_lag) - 1, int(round(q * (len(sorted_lag) - 1))))
            stats[key] = sorted_lag[idx]
    return stats


HALT_STATUSES = ("stuck", "source_outage", "invalid_block_stall")


def summarize(samples: list, verdict: "Verdict | None" = None) -> dict:
    """Derive the reporting metrics for a (not necessarily stall-free) run:
    fast-catchup total time, a coarse per-counter-group phase breakdown,
    and tip-lag stats once the node reaches the tip. Never raises -- a
    metric that can't be computed from the given samples is `None`.

    Issue #1759: `lag_rounds` covers every sample after the first tip
    sighting (kept for compatibility). Given a halt `verdict`, the trailing
    frozen-node window (`stall_window`: `start_ts` = when the signature
    froze, `seconds`) is excluded from `lag_rounds_before_stall`, so "node is
    slow" is not mixed with "node is stuck"; without a halt both are equal
    and `stall_window` is `None`."""
    if not samples:
        return {
            "fast_catchup_seconds": None,
            "phase_seconds": {},
            "reached_tip": False,
            "lag_rounds": _lag_stats([]),
            "lag_rounds_before_stall": _lag_stats([]),
            "stall_window": None,
            "follow_block_timing": {},
            "first_tip_ts": None,
            "time_to_tip_seconds": None,
            "observed_seconds": 0.0,
        }

    t0 = samples[0]["ts"]
    catchup_end_ts = None
    phase_seconds = {"blocks": 0.0, "accounts": 0.0, "kvs": 0.0}
    lag_samples = []
    reached_tip = False
    first_tip_ts = None

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
                    if first_tip_ts is None:
                        first_tip_ts = s["ts"]
                if reached_tip:
                    lag_samples.append((s["ts"], max(lag, 0)))

        prev_ts = s["ts"]
        if node.get("ok"):
            prev_node = node

    fast_catchup_seconds = (catchup_end_ts - t0) if catchup_end_ts is not None else None

    lag_stats = _lag_stats([lag for _, lag in lag_samples])
    stall_window = None
    lag_before = lag_stats
    if verdict is not None and verdict.status in HALT_STATUSES and verdict.stalled_since_s is not None:
        start_ts = samples[-1]["ts"] - verdict.stalled_since_s
        stall_window = {"start_ts": start_ts, "seconds": verdict.stalled_since_s}
        lag_before = _lag_stats([lag for ts, lag in lag_samples if ts <= start_ts])

    return {
        "fast_catchup_seconds": fast_catchup_seconds,
        "phase_seconds": {k: round(v, 1) for k, v in phase_seconds.items() if v > 0},
        "reached_tip": reached_tip,
        "lag_rounds": lag_stats,
        "lag_rounds_before_stall": lag_before,
        "stall_window": stall_window,
        "follow_block_timing": summarize_follow_timing(samples, first_tip_ts),
        "first_tip_ts": first_tip_ts,
        "time_to_tip_seconds": (first_tip_ts - t0) if first_tip_ts is not None else None,
        "observed_seconds": samples[-1]["ts"] - t0,
    }


# --- Per-block follow-path timing histograms (issue #1678) -------------

FOLLOW_TIMING_PREFIX = "algod_rust_follow_block_"
FOLLOW_TIMING_SUFFIX = "_seconds"
# Success-path series and, since issue #1761, the failed-path ones.
FOLLOW_TIMING_KEYS = (
    "apply",
    "apply_failed",
    "avm",
    "commit",
    "commit_failed",
    "wal_checkpoint",
    "ensure_block",
    "ensure_block_failed",
)
PROCESS_START_KEY = "process_start_time_seconds"
PROCESS_START_METRIC = "algod_rust_process_start_time_seconds"
STALL_GAUGE_METRIC = "algod_rust_sync_stalled_on_invalid_block"
STALL_ROUND_METRIC = "algod_rust_sync_stalled_block_round"


def _metric_value(text: str, name: str):
    """Value of the unlabelled sample `name`, or None."""
    for line in text.splitlines():
        if line.startswith(name + " "):
            try:
                return float(line.rpartition(" ")[2])
            except ValueError:
                return None
    return None


def parse_process_start_time(text: str):
    """`algod_rust_process_start_time_seconds` from an exposition, or None
    (node predates the gauge)."""
    return _metric_value(text, PROCESS_START_METRIC)


def parse_stall_gauge(text: str):
    """{"round": N} when `algod_rust_sync_stalled_on_invalid_block` is 1,
    else None."""
    if _metric_value(text, STALL_GAUGE_METRIC) == 1.0:
        round_ = _metric_value(text, STALL_ROUND_METRIC)
        return {"round": int(round_) if round_ is not None else None}
    return None


def _scrape_metrics_text(base_url: str, timeout: float) -> str:
    """The one `/metrics` GET shared by the timing and gauge readers."""
    import urllib.request

    with urllib.request.urlopen(base_url.rstrip("/") + "/metrics", timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def fetch_stall_gauge(base_url: str, timeout: float = 1.0):
    """GET {base_url}/metrics and return the stall gauge payload; None when
    clear or unreachable (never raises). Only used while `/v2/status` is
    unavailable, at most once per scrape interval (see `take_sample`)."""
    try:
        return parse_stall_gauge(_scrape_metrics_text(base_url, timeout))
    except Exception:  # noqa: BLE001 -- the gauge is a fallback signal only
        return None


def parse_follow_timing(text: str) -> dict:
    """Parse the `algod_rust_follow_block_*_seconds` histograms out of a
    Prometheus text exposition. Returns {key: {"count", "sum", "buckets":
    [[le, cumulative], ...]}} with finite `le` bounds, only for
    keys whose full bucket/sum/count triple is present."""
    raw = {}
    for line in text.splitlines():
        if not line.startswith(FOLLOW_TIMING_PREFIX):
            continue
        series, _, value = line.rpartition(" ")
        try:
            value = float(value)
        except ValueError:
            continue
        name, _, labels = series.partition("{")
        for kind in ("_bucket", "_sum", "_count"):
            if name.endswith(FOLLOW_TIMING_SUFFIX + kind):
                key = name[len(FOLLOW_TIMING_PREFIX) : -len(FOLLOW_TIMING_SUFFIX + kind)]
                entry = raw.setdefault(key, {"buckets": []})
                if kind == "_bucket":
                    le = labels.split('le="', 1)[-1].split('"', 1)[0]
                    if le != "+Inf":  # the +Inf bucket equals `_count`
                        entry["buckets"].append([float(le), value])
                else:
                    entry[kind[1:]] = value
                break
    out = {}
    for key, e in raw.items():
        if e["buckets"] and "sum" in e and "count" in e:
            e["buckets"].sort(key=lambda b: b[0])
            e["count"] = int(e["count"])
            out[key] = e
    return out


# Scrape /metrics at most this often, and give up on a slow node quickly, so
# the poll loop (and with it the stall-detection cadence) is never held up.
FOLLOW_TIMING_SCRAPE_INTERVAL_S = 30.0
FOLLOW_TIMING_SCRAPE_TIMEOUT_S = 1.0
_follow_scrape_state = {
    "last_ts": 0.0,
    "failures": 0,
    "logged": False,
    "tip_scraped": False,
    "gauge_last_ts": 0.0,
}


def fetch_follow_timing(base_url: str, timeout: float = FOLLOW_TIMING_SCRAPE_TIMEOUT_S):
    """GET {base_url}/metrics and parse the follow-path histograms; None if
    unreachable or the node predates the metrics (never raises). A
    persistent failure is logged to stderr once per process, not swallowed
    silently."""
    try:
        text = _scrape_metrics_text(base_url, timeout)
        parsed = parse_follow_timing(text)
        error = None if parsed else "no algod_rust_follow_block_* series in /metrics"
        start = parse_process_start_time(text)
        if parsed and start is not None:
            parsed[PROCESS_START_KEY] = start
    except Exception as e:  # noqa: BLE001 -- reporting must never fail a run
        parsed, error = None, str(e)
    st = _follow_scrape_state
    if error is None:
        st["failures"] = 0
        return parsed
    st["failures"] += 1
    if st["failures"] >= 3 and not st["logged"]:
        st["logged"] = True
        print(
            f"monitor: follow-timing scrape of {base_url}/metrics failed "
            f"{st['failures']} times in a row (last: {error}); "
            "follow_block_timing will be missing from the summary",
            file=sys.stderr,
        )
    return None


def follow_timing_scrape_due(now: float) -> bool:
    """True (and the clock is advanced) if the scrape interval has elapsed."""
    st = _follow_scrape_state
    if now - st["last_ts"] < FOLLOW_TIMING_SCRAPE_INTERVAL_S:
        return False
    st["last_ts"] = now
    return True


def _histogram_quantile(buckets, count, q):
    """Upper bound (seconds) of the finite bucket holding quantile `q`; when
    the quantile falls in the +Inf bucket, the last finite bound ("at
    least")."""
    if count <= 0 or not buckets:
        return None
    target = q * count
    for le, cum in buckets:
        if cum >= target and cum > 0:
            return le
    return buckets[-1][0]


def _histogram_max(buckets, count):
    """Upper bound of the highest populated bucket (+Inf -> last finite)."""
    if count <= 0 or not buckets:
        return None
    if count > buckets[-1][1]:
        return buckets[-1][0]
    prev = 0
    top = None
    for le, cum in buckets:
        if cum > prev:
            top = le
        prev = cum
    return top


def _delta_histogram(last, base):
    """(buckets, count, sum) of `last` minus `base`, or None when the pair
    is not a valid delta: different shapes, a count/sum/bucket that went
    backwards, or non-monotonic cumulative buckets (all mean the node
    restarted between the scrapes)."""
    if len(last["buckets"]) != len(base["buckets"]):
        return None
    buckets = [[le, cum - c0[1]] for (le, cum), c0 in zip(last["buckets"], base["buckets"])]
    count = last["count"] - base["count"]
    total = last["sum"] - base["sum"]
    cums = [c for _, c in buckets]
    if count < 0 or total < 0 or any(c < 0 for c in cums):
        return None
    if any(a > b for a, b in zip(cums, cums[1:])) or (cums and cums[-1] > count):
        return None
    return buckets, count, total


def _restart_between(a: dict, b: dict) -> bool:
    """True if two consecutive scrapes show the node restarted between them
    (different process start time, else a counter that went backwards)."""
    sa, sb = a.get(PROCESS_START_KEY), b.get(PROCESS_START_KEY)
    if sa is not None and sb is not None:
        return sa != sb
    for key in FOLLOW_TIMING_KEYS:
        ha, hb = a.get(key), b.get(key)
        if ha and hb and _delta_histogram(hb, ha) is None:
            return True
    return False


def summarize_follow_timing(samples: list, first_tip_ts=None) -> dict:
    """p50/p95/max (bucket upper bounds, seconds) plus count/mean per
    follow-path histogram. Each entry states its `baseline`: `"delta"` when
    the last scrape minus an earlier scrape taken at/after `first_tip_ts`
    (the follow window) is used, `"absolute"` when there is no earlier
    scrape to subtract (a single scrape, or the only post-tip scrape is the
    last one) or the pair is invalid; `restarted: true` flags the latter
    case (counter went backwards, i.e. the node restarted between the
    scrapes, so the post-restart absolute values are reported). {} when no
    sample carries `follow_timing`."""
    scraped = [s for s in samples if s.get("follow_timing")]
    if not scraped:
        return {}
    last_sample = scraped[-1]
    last = last_sample["follow_timing"]
    base = {}
    base_sample = None
    if first_tip_ts is not None:
        for s in scraped[:-1]:
            if s["ts"] >= first_tip_ts:
                base = s["follow_timing"]
                base_sample = s
                break
    # The first scrape taken after a restart (the last one if no consecutive
    # pair shows it): were catchup-era timings included in the absolute values?
    chain = [base_sample] + [s for s in scraped if s["ts"] > base_sample["ts"]] if base_sample else scraped
    post_restart_sample = last_sample
    for prev, cur in zip(chain, chain[1:]):
        if _restart_between(prev["follow_timing"], cur["follow_timing"]):
            post_restart_sample = cur
            break
    pre_tip = not at_tip(post_restart_sample)
    # Issue #1761: a differing process start time proves a restart even when
    # the restarted node has since outgrown every baseline counter.
    start_last, start_base = last.get(PROCESS_START_KEY), base.get(PROCESS_START_KEY)
    process_restarted = start_last is not None and start_base is not None and start_last != start_base
    out = {}
    for key in FOLLOW_TIMING_KEYS:
        h = last.get(key)
        if not h:
            continue
        buckets = [list(b) for b in h["buckets"]]
        count, total = h["count"], h["sum"]
        baseline, restarted = "absolute", False
        b0 = base.get(key)
        if process_restarted:
            restarted = True
        elif b0:
            d = _delta_histogram(h, b0)
            if d is None:
                restarted = True
            else:
                buckets, count, total = d
                baseline = "delta"
        out[key] = {
            "baseline": baseline,
            "restarted": restarted,
            # True when the post-restart values begin before the node was at
            # the tip, i.e. include catchup-era timings.
            "pre_tip_included": restarted and pre_tip,
            "count": count,
            "mean_s": (total / count) if count > 0 else None,
            "p50_s": _histogram_quantile(buckets, count, 0.50),
            "p95_s": _histogram_quantile(buckets, count, 0.95),
            "max_s": _histogram_max(buckets, count),
        }
    return out


# --- Live collection ---------------------------------------------------


def _status_stall(raw):
    """The `/v2/status` `stalled-on-invalid-block` object, normalised to
    snake_case keys; None when absent (issue #1715)."""
    if not isinstance(raw, dict) or not raw:
        return None
    return {
        "round": raw.get("round"),
        "error": raw.get("error"),
        "consecutive_failures": raw.get("consecutive-failures"),
        "since_unix_secs": raw.get("since-unix-secs"),
    }


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
        "stalled_on_invalid_block": _status_stall(body.get("stalled-on-invalid-block")),
    }


def take_sample(node_url, node_token, peer_url, peer_token) -> dict:
    sample = {
        "ts": time.time(),
        "node": fetch_status(node_url, node_token),
        "peer": fetch_status(peer_url, peer_token),
    }
    # Issue #1678: the cumulative follow-path histograms ride along once the
    # node is out of catchup (the latest scrape survives a killed run).
    node = sample["node"]
    if not node.get("ok"):
        # Issue #1715: /v2/status is unavailable; the stall gauge still hard
        # fails a node that is stuck on an invalid block.
        st = _follow_scrape_state
        if sample["ts"] - st.get("gauge_last_ts", 0.0) >= FOLLOW_TIMING_SCRAPE_INTERVAL_S:
            st["gauge_last_ts"] = sample["ts"]
            gauge = fetch_stall_gauge(node_url)
            if gauge:
                node["stalled_on_invalid_block"] = {**gauge, "source": "gauge"}
    elif not (node.get("catchpoint") or ""):
        st = _follow_scrape_state
        due = follow_timing_scrape_due(sample["ts"])
        on_tip = at_tip(sample)
        # Issue #1761: the delta window must start exactly at the tip
        # transition, not up to a rate-limit interval later.
        if not due and on_tip and not st.get("tip_scraped") and st["failures"] < 3:
            due = True
            st["last_ts"] = sample["ts"]
        if due:
            timing = fetch_follow_timing(node_url)
            if timing:
                sample["follow_timing"] = timing
                if on_tip:
                    st["tip_scraped"] = True
    return sample


def at_tip(sample: dict) -> bool:
    """True if `sample` shows the node in follow mode within
    `TIP_SLACK_ROUNDS` of the peer (same rule `summarize()` uses)."""
    node = sample.get("node") or {}
    peer = sample.get("peer") or {}
    if not node.get("ok") or (node.get("catchpoint") or ""):
        return False
    if not peer.get("ok"):
        return False
    pr, nr = peer.get("last_round"), node.get("last_round")
    return isinstance(pr, int) and isinstance(nr, int) and pr - nr <= TIP_SLACK_ROUNDS


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
    verify_halt_minutes=DEFAULT_VERIFY_HALT_MINUTES,
    unreachable_grace_minutes=DEFAULT_UNREACHABLE_GRACE_MINUTES,
    post_verify_halt_minutes=DEFAULT_POST_VERIFY_HALT_MINUTES,
    follow_s=0.0,
):
    """Poll both endpoints every `poll_interval_s` for up to `duration_s`,
    appending each sample to `out_path` as it's taken (so a killed/timed-out
    job still leaves a partial, analyzable JSONL). Stops early -- before
    the full duration -- the moment `classify()` on the samples-so-far
    would report anything other "ok" (a live halt, not just a slow catchup,
    is worth ending the run for early rather than burning the rest of the
    CI budget waiting it out). `process_alive` lets the caller report a
    known-dead child process immediately as a node_failure sample rather
    than waiting for the next failed poll -- that case is never given the
    unreachable grace window below, since it's a confirmed death, not a
    slow poll.

    Unreachable-poll grace (issue #1623 live dispatch, run 36204923591): a
    single unreachable `/v2/status` poll (the node process itself still
    alive per `process_alive()`) is not immediately treated as
    NODE_FAILURE -- `classify()`'s tail-based check would otherwise fire
    on the very first bad poll of a live, growing stream, with no chance
    to observe a recovery the way post-hoc analysis of a complete log can.
    The node is given `unreachable_grace_minutes` (or the longer
    `verify_halt_minutes`, if the last known-good sample looked like the
    non-incremental verify window -- that pass has been observed to starve
    the REST responder under CI-runner CPU contention badly enough to time
    out polls without the node actually being dead) to become reachable
    again before the failure is treated as real.

    Follow window: when `follow_s > 0`, the run ends (verdict from
    `classify()`, normally "ok") `follow_s` seconds after the node is first
    seen at the tip, or at `duration_s`, whichever comes first -- `duration_s`
    remains the hard cap on total poll time. `follow_s == 0` is the original
    behaviour.

    Returns the final `Verdict`.
    """
    start = time.time()
    follow_end = None
    samples = []
    unreachable_since = None
    last_ok_was_verifying = False
    with open(out_path, "a", encoding="utf-8") as f:
        while True:
            died = not process_alive()
            if died:
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

            now = time.time()
            if follow_s > 0 and follow_end is None and at_tip(samples[-1]):
                follow_end = samples[-1]["ts"] + follow_s
            node = samples[-1].get("node") or {}
            if died:
                # A confirmed-dead process is never given the grace window.
                unreachable_since = None
            elif node.get("ok", False):
                unreachable_since = None
                last_ok_was_verifying = (
                    is_verifying_signature(samples[-1])
                    or is_downloading_signature(samples[-1])
                    or is_post_verify_signature(samples[-1])
                )
            else:
                if unreachable_since is None:
                    unreachable_since = now
                grace_s = (
                    verify_halt_minutes if last_ok_was_verifying else unreachable_grace_minutes
                ) * 60.0
                if now - unreachable_since < grace_s:
                    if now - start >= duration_s:
                        # The run budget ended while still inside an active
                        # grace window -- report "ok" rather than calling
                        # classify() (whose tail-based NODE_FAILURE check
                        # would fire on the still-in-progress transient
                        # blip we're deliberately tolerating), matching the
                        # existing "still catching up at budget end is not
                        # the same claim as stuck" policy for this case.
                        return Verdict(
                            "ok",
                            None,
                            None,
                            "run budget ended within an active unreachable-grace window",
                            None,
                        )
                    time.sleep(poll_interval_s)
                    continue

            verdict = classify(samples, halt_minutes, verify_halt_minutes, post_verify_halt_minutes)
            if verdict.status != "ok":
                return verdict
            if now - start >= duration_s:
                return verdict
            if follow_end is not None and now >= follow_end:
                return verdict
            time.sleep(poll_interval_s)


def render_step_summary_lines(r: dict) -> list:
    """The workflow step-summary markdown (verdict, metrics table, follow
    timing rows with their `baseline`/`restarted` flags, then the nodelog
    sections) for a `summary.json` dict. Lives here, not inline in the
    workflow, so it is unit-tested."""
    lag = r.get("lag_rounds") or {}
    lag_before = r.get("lag_rounds_before_stall") or {}
    phase_s = r.get("phase_seconds") or {}

    def lag_row(label, stats):
        return (
            f"| {label}: mean/p50/p95/p99/max (n) | {stats.get('mean')}/{stats.get('p50')}/"
            f"{stats.get('p95')}/{stats.get('p99')}/{stats.get('max')} (n={stats.get('n')}) |"
        )

    lines = [
        "# Mainnet node soak",
        "",
        f"**Verdict:** `{r.get('status')}` \u2014 {nodelog.sanitize_text(r.get('message') or '', 700)}",
        "",
        "| metric | value |",
        "| --- | --- |",
        f"| Catchpoint label | `{r.get('catchpoint_label') or 'n/a'}` |",
        f"| Fast-catchup time | {r.get('fast_catchup_seconds')} s |",
        f"| Reached tip | {r.get('reached_tip')} |",
        f"| Phase durations (s) | {phase_s} |",
        lag_row("Lag at tip (rounds), whole run", lag),
    ]
    window = r.get("stall_window")
    if window:
        lines.append(lag_row("Lag before stall (rounds)", lag_before))
        lines.append(f"| Stall window | {window.get('seconds')} s from ts {window.get('start_ts')} |")
    stall = r.get("invalid_block_stall")
    if stall:
        lines.append(f"| stalled-on-invalid-block | {nodelog.format_stall(stall, table=True)} |")
    cleared = r.get("invalid_block_stall_cleared")
    if cleared:
        lines.append(
            "| stalled-on-invalid-block cleared (warning, run not failed) | "
            f"{nodelog.format_stall(cleared, table=True)}, "
            f"seen from ts {cleared.get('first_ts')} to {cleared.get('last_ts')} |"
        )
    lines += [
        f"| Node last-round | {r.get('node_last_round')} |",
        f"| Peer last-round | {r.get('peer_last_round')} |",
    ]
    for key, h in (r.get("follow_block_timing") or {}).items():
        lines.append(
            f"| Follow block {key} (s): p50/p95/max (n) | {h.get('p50_s')}/{h.get('p95_s')}/{h.get('max_s')} "
            f"(n={h.get('count')}) baseline={h.get('baseline')} restarted={h.get('restarted')} |"
        )
    lines += nodelog.render_markdown(r).splitlines()
    return lines


# --- CLI -----------------------------------------------------------------


def _load_jsonl(path: str) -> list:
    samples = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(json.loads(line))
    return samples


def build_result(
    samples: list, verdict: Verdict, follow_minutes: float = 0.0, node_log: str | None = None
) -> dict:
    """The full JSON result both `analyze` and `collect` emit: the verdict,
    `verdict_context`'s halt-moment fields (consumed by `file_issue.py`'s
    template), `summarize`'s healthy-run timing/lag metrics, the follow
    window (if requested) and, given `node_log`, the log-derived
    `phase_seconds_detailed`."""
    result = {
        "status": verdict.status,
        "phase": verdict.phase,
        "round": verdict.round,
        "message": verdict.message,
        "stalled_since_s": verdict.stalled_since_s,
        **verdict_context(samples, verdict),
        **summarize(samples, verdict),
    }
    if follow_minutes and follow_minutes > 0:
        first_tip = result.get("first_tip_ts")
        last_ts = samples[-1]["ts"] if samples else None
        observed = (last_ts - first_tip) if first_tip is not None and last_ts is not None else None
        result["follow"] = {
            "requested_s": round(follow_minutes * 60.0, 1),
            "observed_s": None if observed is None else round(observed, 1),
            "time_to_tip_s": None
            if result.get("time_to_tip_seconds") is None
            else round(result["time_to_tip_seconds"], 1),
            "completed": observed is not None
            and observed >= follow_minutes * 60.0 - 2 * DEFAULT_POLL_INTERVAL_S,
        }
    if node_log:
        try:
            detailed = nodelog.parse_phase_file(node_log)
            wall = result.get("fast_catchup_seconds")
            detailed["catchup_wall_s"] = None if wall is None else round(wall, 1)
            total = detailed.get("catchup_log_total_s")
            detailed["unaccounted_s"] = (
                round(wall - total, 1) if wall is not None and total is not None else None
            )
            result["phase_seconds_detailed"] = detailed
        except Exception as e:  # never fail a run over reporting
            result["phase_seconds_detailed"] = {"error": str(e)}
    return result


def _emit(result: dict, json_out: str | None):
    print(json.dumps(result, indent=2))
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)


def _cmd_analyze(args):
    samples = _load_jsonl(args.jsonl)
    verdict = classify(
        samples, args.halt_minutes, args.verify_halt_minutes, args.post_verify_halt_minutes
    )
    _emit(build_result(samples, verdict, 0.0, args.node_log), args.json_out)
    return exit_code_for(verdict)


def _cmd_collect(args):
    verdict = collect(
        node_url=args.node_url,
        node_token=args.node_token,
        peer_url=args.peer_url,
        peer_token=args.peer_token,
        duration_s=args.duration_minutes * 60.0,
        halt_minutes=args.halt_minutes,
        verify_halt_minutes=args.verify_halt_minutes,
        post_verify_halt_minutes=args.post_verify_halt_minutes,
        unreachable_grace_minutes=args.unreachable_grace_minutes,
        poll_interval_s=args.poll_interval_s,
        out_path=args.out,
        follow_s=args.follow_minutes * 60.0,
    )
    samples = _load_jsonl(args.out)
    _emit(build_result(samples, verdict, args.follow_minutes, args.node_log), args.json_out)
    return exit_code_for(verdict)


def _cmd_scan_log(args):
    """Scan node.log for broken-state signatures, merge the result into the
    summary JSON (created if absent) and print the markdown. Exit 1 if any
    hard signature fired, else 0."""
    scan = nodelog.scan_file(args.node_log)
    if args.summary:
        try:
            with open(args.summary, encoding="utf-8") as f:
                summary = json.load(f)
        except (OSError, ValueError):
            summary = {}
        summary["log_scan"] = scan
        with open(args.summary, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
    print(nodelog.render_markdown({"log_scan": scan}))
    return 1 if scan["hard_total"] > 0 else 0


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
    p_collect.add_argument("--verify-halt-minutes", type=float, default=DEFAULT_VERIFY_HALT_MINUTES)
    p_collect.add_argument(
        "--post-verify-halt-minutes", type=float, default=DEFAULT_POST_VERIFY_HALT_MINUTES
    )
    p_collect.add_argument(
        "--unreachable-grace-minutes", type=float, default=DEFAULT_UNREACHABLE_GRACE_MINUTES
    )
    p_collect.add_argument("--poll-interval-s", type=float, default=DEFAULT_POLL_INTERVAL_S)
    p_collect.add_argument(
        "--follow-minutes",
        type=float,
        default=0.0,
        help="keep polling this long after first reaching the tip (0 = off); "
        "--duration-minutes stays the hard cap",
    )
    p_collect.add_argument("--node-log", default=None, help="node.log for phase_seconds_detailed")
    p_collect.add_argument("--out", required=True, help="JSONL output path")
    p_collect.add_argument("--json-out", default=None, help="verdict+summary JSON path")
    p_collect.set_defaults(func=_cmd_collect)

    p_analyze = sub.add_parser("analyze", help="verdict over an existing JSONL (dry runs, tests)")
    p_analyze.add_argument("jsonl")
    p_analyze.add_argument("--halt-minutes", type=float, default=DEFAULT_HALT_MINUTES)
    p_analyze.add_argument("--verify-halt-minutes", type=float, default=DEFAULT_VERIFY_HALT_MINUTES)
    p_analyze.add_argument(
        "--post-verify-halt-minutes", type=float, default=DEFAULT_POST_VERIFY_HALT_MINUTES
    )
    p_analyze.add_argument("--json-out", default=None)
    p_analyze.add_argument("--node-log", default=None, help="node.log for phase_seconds_detailed")
    p_analyze.set_defaults(func=_cmd_analyze)

    p_scan = sub.add_parser("scan-log", help="scan node.log for broken-state signatures")
    p_scan.add_argument("node_log")
    p_scan.add_argument("--summary", default=None, help="summary.json to merge log_scan into")
    p_scan.set_defaults(func=_cmd_scan_log)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
