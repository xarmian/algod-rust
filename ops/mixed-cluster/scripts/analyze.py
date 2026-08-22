#!/usr/bin/env python3
# PLAN-32 / TASK-87 — soak-output analyzer.
#
# Reads exactly ONE JSONL file produced by scripts/metrics.py and emits
# a human-readable summary plus a machine-readable sidecar
# ('<input>.summary.json') containing the same metrics. Multi-file
# input is intentionally unsupported — merging records from separate
# runs confuses the round-keyed lag and block-time aggregates; run
# analyze.py once per file and diff the sidecars to compare.
#
# Metrics computed:
#   - Rounds observed (total, first, last) + back-filled-only count
#   - Block-time distribution: mean / p50 / p95 / p99 of
#     (block_ts[r] - block_ts[r-1]) over consecutive rounds
#   - Commit-latency distribution: for each round, the spread between
#     the earliest and latest node-observed commit_ts (convergence time)
#   - Per-node max round at end-of-run + whether any node fell behind
#     by more than --lag-tolerance (seeded from run_meta so a stuck
#     node is visible even without node_round events)
#   - Proposer histogram (count per proposer address)
#   - Rust container state timeline: any non-"running" observation, any
#     log-round observation (best-effort)
#   - Warning digest: count per unique warning message prefix
#
# Issue #470 (Epic 42c) additions — assertions about the RUST node's own
# consensus participation, all opt-in via CLI flags so the historical
# observer-topology reports keep working unchanged:
#
#   --rust-account ADDR        Assert this address appears as a block
#                              proposer, with a share statistically
#                              consistent with --rust-stake-fraction.
#   --rust-stake-fraction F    Its share of ONLINE stake (default 0.10,
#                              the 30/30/30/10 split in template.json).
#   --proposer-sigma S         Two-sided bound in standard deviations
#                              (default 3.0). See `proposer_share_check`.
#   --rust-log PATH            A `docker logs phase6-rust-node-4` capture.
#                              Asserts the node cast BOTH soft and cert
#                              votes, and reports any period > 0
#                              (next-step / period-advancement) activity.
#   --require-steps a,b        Steps that must appear in --rust-log
#                              (default "soft,cert").
#   --max-mean-block-time S    Cadence gate: fail if the mean inter-block
#                              time exceeds S seconds (0 = disabled).
#   --max-p95-block-time S     Same, on the p95 (0 = disabled).
#
# Issue #473 (Epic 42f) additions — the Rust node now serves
# `GET /v2/participation/status`, and metrics.py records it as
# "participation" / "participation_final" JSONL records. These are always
# summarized when present (older soak files are unaffected) and can be
# gated:
#
#   --require-participation-endpoint   Fail unless the endpoint reported
#                                      real votes at every required step.
#   --max-round-duration-ms MS         With the above: fail if the node's
#                                      p95 round-start-to-commit exceeds MS.
#
# The endpoint supersedes --rust-log as *evidence*: the log says a line was
# printed, the endpoint reports what the agreement state machine counted,
# plus per-round timings the log never carried. --rust-log is still
# supported (and still the only source for equivocation-shaped checks).
#
# Acceptance-criteria hints (printed at the bottom):
#   - Any stall / interrupt / timeout phase in run_meta
#   - Any lag > --lag-tolerance
#   - Any warning records
#   - Any blocks missing block_ts / proposer
#   - (#470) zero Rust proposals, an out-of-bound Rust proposer share,
#     a missing vote step, or a cadence threshold breach
# Exit code is 0 iff every acceptance hint is clean. The full criteria
# from TASK-87 live in docs/SOAK_METHODOLOGY.md.
#
# Usage:
#   scripts/analyze.py <soak.jsonl> [--lag-tolerance N] [--json-out PATH]

import argparse
import json
import math
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime

# ── #470: Rust participation parsing ────────────────────────────────────
#
# `algo_agreement::service` logs one line per Attest action:
#
#   INFO algo_agreement::service: attested to ProposalValue { ... } at (357, 0, cert)
#
# The trailing triple is (round, period, step); `Step`'s Display renders
# 0..3 as propose/soft/cert/next and anything above 3 as "next+N"
# (see crates/core/algo-agreement/src/step.rs).
ATTEST_RE = re.compile(
    r"attested to .* at \((?P<round>\d+), (?P<period>\d+), (?P<step>[a-z]+(?:\+\d+)?)\)"
)

# Same file logs reproposals at the propose step.
REPROPOSE_RE = re.compile(
    r"repropose to .* at \((?P<round>\d+), (?P<period>\d+), (?P<step>[a-z]+(?:\+\d+)?)\)"
)

# `tracing`'s pretty formatter wraps field names in ANSI escapes, which
# survive `docker logs` redirection into a file.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

DEFAULT_REQUIRED_STEPS = ("soft", "cert")


def percentile(values, pct: float):
    if not values:
        return None
    if len(values) == 1:
        return float(values[0])
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    lo = int(math.floor(k))
    hi = int(math.ceil(k))
    if lo == hi:
        return float(s[lo])
    return float(s[lo] + (s[hi] - s[lo]) * (k - lo))


def parse_iso(ts: str):
    if not ts:
        return None
    # Python 3.11+ handles "Z" natively; earlier versions need replacement.
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def load_jsonl(paths):
    for path in paths:
        with open(path) as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    print(
                        f"warning: {path}:{line_no} parse error: {e}",
                        file=sys.stderr,
                    )


def describe(values, unit=""):
    if not values:
        return "n=0"
    return (
        f"n={len(values)} "
        f"mean={statistics.mean(values):.3f}{unit} "
        f"p50={percentile(values, 50):.3f}{unit} "
        f"p95={percentile(values, 95):.3f}{unit} "
        f"p99={percentile(values, 99):.3f}{unit} "
        f"min={min(values):.3f}{unit} max={max(values):.3f}{unit}"
    )


def proposer_share_check(
    proposers: dict,
    account: str,
    stake_fraction: float,
    sigma: float,
):
    """Issue #470 §1 — is `account`'s proposer share consistent with its stake?

    Model
    -----
    Under go-algorand's sortition, block-proposer selection over N
    independent rounds is Binomial(N, p) where p is the account's share
    of ONLINE stake (`stake_fraction`). We accept the run when the
    observed count k lies inside a two-sided normal-approximation
    interval:

        mu    = N * p
        sd    = sqrt(N * p * (1 - p))
        |k - mu| <= `sigma_bound` * sd

    `sigma_bound` defaults to 3.0. Why 3 sigma and not something tighter: the
    real 200-round run recorded on issue #482 saw 13/200 proposals for a
    p = 0.10 account (mu = 20, sd = 4.243, z = -1.65). A 2-sigma gate would
    have been within ~0.35 sigma of failing that perfectly healthy run, so
    2 sigma is too tight for a CI gate at N = 200. 3 sigma accepts k in [7, 32]
    at N = 200 — still far from a genuine regression, which produces
    k = 0 (z = -4.71, rejected on BOTH the sigma test and the explicit
    zero gate below).

    Zero proposals is ALWAYS a failure regardless of the sigma bound:
    a node that never proposes is exactly the #482 regression, and at
    small N the normal interval can otherwise reach down to 0.

    The normal approximation degrades when mu < 10; we still apply it
    (the alternative, an exact binomial tail, needs scipy) but flag it
    in the result as `normal_approx_weak` so a reader knows the interval
    is indicative rather than exact.
    """
    total = sum(proposers.values())
    count = int(proposers.get(account, 0))
    result = {
        "account": account,
        "stake_fraction": stake_fraction,
        "sigma_bound": sigma,
        "blocks_with_proposer": total,
        "rust_proposals": count,
        "observed_fraction": (count / total) if total else None,
        "expected": None,
        "sd": None,
        "z": None,
        "lower_bound": None,
        "upper_bound": None,
        "normal_approx_weak": None,
        "ok": False,
        "failures": [],
    }

    if total <= 0:
        result["failures"].append(
            "no blocks with a proposer were captured — cannot assess "
            "the Rust proposer share"
        )
        return result
    if not 0.0 < stake_fraction < 1.0:
        result["failures"].append(
            f"--rust-stake-fraction must be in (0, 1); got {stake_fraction}"
        )
        return result

    mu = total * stake_fraction
    sd = math.sqrt(total * stake_fraction * (1.0 - stake_fraction))
    result["expected"] = mu
    result["sd"] = sd
    result["normal_approx_weak"] = mu < 10.0
    result["z"] = ((count - mu) / sd) if sd > 0 else None
    result["lower_bound"] = mu - sigma * sd
    result["upper_bound"] = mu + sigma * sd

    if count == 0:
        result["failures"].append(
            f"Rust account {account[:8]}… proposed ZERO of {total} blocks "
            f"(expected ~{mu:.1f}) - the node is following, not proposing"
        )
    elif sd > 0 and abs(count - mu) > sigma * sd:
        result["failures"].append(
            f"Rust proposer share out of bound: {count}/{total} "
            f"(z={result['z']:+.2f}, |z| > {sigma:.1f}); expected "
            f"{mu:.1f} +/- {sigma * sd:.1f}"
        )

    result["ok"] = not result["failures"]
    return result


def parse_rust_participation_log(text: str):
    """Issue #470 §3 — extract vote-step coverage from the Rust node log.

    Returns a dict with per-step attest counts, the set of rounds the
    node attested in, and any period > 0 observations (a period > 0
    attest is exactly the `next`-step / period-advancement case the
    issue asks us to exercise).

    Robust against: ANSI escapes from `tracing`'s pretty formatter,
    interleaved unrelated lines, and truncated/binary junk.
    """
    steps = Counter()
    periods = Counter()
    rounds = set()
    period_advanced_rounds = set()
    repropose_rounds = set()
    lines_scanned = 0

    for raw in text.splitlines():
        lines_scanned += 1
        line = ANSI_RE.sub("", raw)
        m = ATTEST_RE.search(line)
        if m:
            rnd = int(m.group("round"))
            period = int(m.group("period"))
            step = m.group("step")
            steps[step] += 1
            periods[period] += 1
            rounds.add(rnd)
            if period > 0:
                period_advanced_rounds.add(rnd)
            continue
        m = REPROPOSE_RE.search(line)
        if m:
            repropose_rounds.add(int(m.group("round")))
            if int(m.group("period")) > 0:
                period_advanced_rounds.add(int(m.group("round")))

    return {
        "lines_scanned": lines_scanned,
        "attests_total": sum(steps.values()),
        "steps": dict(steps),
        "periods": dict(periods),
        "rounds_attested": len(rounds),
        "first_round": min(rounds) if rounds else None,
        "last_round": max(rounds) if rounds else None,
        "period_advanced_rounds": sorted(period_advanced_rounds),
        "reproposals": len(repropose_rounds),
    }


def summarize_participation_records(records):
    """Issue #473 — fold `participation` / `participation_final` records.

    metrics.py polls the Rust node's `GET /v2/participation/status`, which
    reports counters straight out of the agreement service. That is strictly
    better evidence than the log scrape above: the log tells us a line was
    printed, the endpoint tells us what the node's own state machine counted,
    including timings the log never carried.

    Returns `None` when the run predates #473 (no such records), so older
    soak outputs analyze exactly as before.
    """
    samples = [r for r in records if r.get("kind") == "participation"]
    finals = [r for r in records if r.get("kind") == "participation_final"]
    if not samples and not finals:
        return None

    final = next(
        (r for r in reversed(finals) if r.get("available") and r.get("snapshot")),
        None,
    )
    snapshot = final.get("snapshot") if final else None
    if snapshot is None:
        # Fall back to the last available per-tick summary, which carries the
        # counters but not `recent_rounds`.
        snapshot = next(
            (r for r in reversed(samples) if r.get("available")),
            None,
        )

    unavailable = [r for r in samples if not r.get("available")]
    out = {
        "samples": len(samples),
        "unavailable_samples": len(unavailable),
        "unavailable_reasons": dict(
            Counter(r.get("reason", "unknown") for r in unavailable)
        ),
        "endpoint_ever_available": bool(snapshot),
    }
    if not snapshot:
        return out

    # The per-tick summary uses `*_ms` sub-dicts with short keys; the full
    # snapshot uses the raw field names. Read both shapes.
    def stats(name):
        raw = snapshot.get(name)
        if isinstance(raw, dict) and "last_ms" in raw:
            return {
                "count": raw.get("count"),
                "last": raw.get("last_ms"),
                "min": raw.get("min_ms"),
                "max": raw.get("max_ms"),
                "mean": raw.get("mean_ms"),
            }
        return snapshot.get(name + "_ms")

    out.update({
        "votes_cast_total": snapshot.get("votes_cast_total"),
        "votes_cast_by_step": snapshot.get("votes_cast_by_step") or {},
        "proposals_made": snapshot.get("proposals_made"),
        "proposal_rounds": snapshot.get("proposal_rounds"),
        "proposals_accepted": snapshot.get("proposals_accepted"),
        "proposals_rejected": snapshot.get("proposals_rejected"),
        "reproposals": snapshot.get("reproposals"),
        "blocks_committed": snapshot.get("blocks_committed"),
        "vote_broadcast_failures": snapshot.get("vote_broadcast_failures"),
        "rounds_started": snapshot.get("rounds_started"),
        "last_committed_round": snapshot.get("last_committed_round"),
        "round_duration_ms": stats("round_duration"),
        "round_start_to_first_vote_ms": stats("round_start_to_first_vote"),
        "round_start_to_proposal_ms": stats("round_start_to_proposal"),
    })

    # Per-round timing distribution, available only from the full snapshot.
    recent = snapshot.get("recent_rounds")
    if isinstance(recent, list) and recent:
        commits = [
            s["start_to_commit_ms"] for s in recent
            if isinstance(s, dict) and isinstance(s.get("start_to_commit_ms"), (int, float))
        ]
        votes = [
            s["start_to_first_vote_ms"] for s in recent
            if isinstance(s, dict)
            and isinstance(s.get("start_to_first_vote_ms"), (int, float))
        ]
        out["recent_rounds_count"] = len(recent)
        out["recent_round_duration_ms"] = {
            "n": len(commits),
            "p50": percentile(commits, 50),
            "p95": percentile(commits, 95),
            "max": max(commits) if commits else None,
        }
        out["recent_first_vote_ms"] = {
            "n": len(votes),
            "p50": percentile(votes, 50),
            "p95": percentile(votes, 95),
            "max": max(votes) if votes else None,
        }
    return out


def participation_endpoint_check(part: dict, required_steps, max_round_ms: float = 0.0):
    """Issue #473 — assert the endpoint proves real participation.

    Distinct from `step_coverage_check`, which reads the same facts out of
    the log: this one reads the node's own counters, and additionally gates
    round-progression timing (`--max-round-duration-ms`), which is what makes
    "the Rust node keeps pace with the Go nodes" a measurement rather than an
    inference from block cadence.
    """
    failures = []
    if not part or not part.get("endpoint_ever_available"):
        failures.append(
            "the Rust node's /v2/participation/status never answered — "
            "is it running `participate --rest-listen` (issues #469/#473)?"
        )
        return {"ok": False, "failures": failures, "required_steps": list(required_steps)}

    by_step = part.get("votes_cast_by_step") or {}
    seen = set(by_step)
    normalized = set(seen)
    if any(s.startswith("next+") for s in seen):
        normalized.add("next")
    missing = [s for s in required_steps if s not in normalized]

    if not part.get("votes_cast_total"):
        failures.append(
            "the participation endpoint reports zero votes cast — the node "
            "is running but not voting"
        )
    elif missing:
        failures.append(
            "participation endpoint shows no votes at step(s): "
            + ", ".join(missing)
            + f" (saw: {', '.join(sorted(seen)) or 'none'})"
        )

    duration = part.get("recent_round_duration_ms") or {}
    p95 = duration.get("p95")
    if max_round_ms > 0 and isinstance(p95, (int, float)) and p95 > max_round_ms:
        failures.append(
            f"p95 round duration {p95:.0f}ms > --max-round-duration-ms "
            f"{max_round_ms:.0f} — the Rust node is not keeping pace"
        )

    return {
        "required_steps": list(required_steps),
        "steps_seen": sorted(seen),
        "missing_steps": missing,
        "max_round_duration_ms": max_round_ms,
        "ok": not failures,
        "failures": failures,
    }


def step_coverage_check(parsed: dict, required_steps):
    """Fail when a required vote step never appears in the Rust log."""
    seen = set(parsed.get("steps", {}))
    # "next+N" (period advancement beyond the first next step) satisfies
    # a "next" requirement — Step's Display renders 4, 5, … that way.
    normalized = set(seen)
    if any(s.startswith("next+") for s in seen):
        normalized.add("next")
    missing = [s for s in required_steps if s not in normalized]
    failures = []
    if parsed.get("attests_total", 0) == 0:
        failures.append(
            "the Rust log contains no 'attested to …' lines at all — "
            "the node cast no votes (wrong log file, or no partkeys?)"
        )
    elif missing:
        failures.append(
            "Rust node never cast these vote step(s): "
            + ", ".join(missing)
            + f" (saw: {', '.join(sorted(seen)) or 'none'})"
        )
    return {
        "required_steps": list(required_steps),
        "steps_seen": sorted(seen),
        "missing_steps": missing,
        "period_advancement_observed": bool(parsed.get("period_advanced_rounds")),
        "ok": not failures,
        "failures": failures,
    }


def cadence_check(block_time_summary: dict, max_mean: float, max_p95: float):
    """Fail when block production is slower than the configured bound.

    Both bounds are opt-in (0 disables). `analyze.py` historically only
    *reported* the block-time distribution; issue #470 §4 wants a real
    gate, but the acceptable value depends on the harness (a 4-node
    docker cluster on a laptop is slower than CI), so the caller picks.
    """
    failures = []
    if block_time_summary.get("n"):
        if max_mean > 0 and block_time_summary["mean"] > max_mean:
            failures.append(
                f"mean block time {block_time_summary['mean']:.2f}s > "
                f"{max_mean:.2f}s"
            )
        if max_p95 > 0 and block_time_summary["p95"] > max_p95:
            failures.append(
                f"p95 block time {block_time_summary['p95']:.2f}s > "
                f"{max_p95:.2f}s"
            )
    elif max_mean > 0 or max_p95 > 0:
        failures.append(
            "cadence bound requested but no consecutive block pairs were "
            "captured"
        )
    return {
        "max_mean_block_time_s": max_mean,
        "max_p95_block_time_s": max_p95,
        "ok": not failures,
        "failures": failures,
    }


def summarize(records, lag_tolerance: int):
    run_metas = []
    warnings = []
    # round -> node -> first commit_ts (datetime)
    commit_ts_by_round: dict = defaultdict(dict)
    # rounds seen ONLY through back_fill records (no authoritative
    # commit_ts available). Tracked separately so they don't silently
    # disappear from the report even though they can't contribute to
    # the commit-spread distribution.
    back_filled_rounds: set = set()
    # round -> block record
    block_by_round: dict = {}
    # node -> max round. Seeded from run_meta.baseline + run_meta.end so a
    # REST node that NEVER advances past baseline still shows up in the
    # lag check (otherwise it'd be invisible — no node_round emitted).
    node_max_round: dict = defaultdict(int)
    # Set of REST node names the collector was configured to poll. A node
    # missing from this set was never contacted at all (don't lag-check it).
    configured_rest_nodes: set = set()
    # rust node log samples
    rust_state_samples: list = []

    for rec in records:
        k = rec.get("kind")
        if k == "run_meta":
            run_metas.append(rec)
            # Seed node_max_round / configured_rest_nodes from authoritative
            # collector state so a stuck node is visible in the lag check.
            for key in ("start_round_by_node", "final_last_seen"):
                m = rec.get(key)
                if isinstance(m, dict):
                    for node, r in m.items():
                        try:
                            r_int = int(r)
                        except (TypeError, ValueError):
                            continue
                        node_max_round[node] = max(node_max_round[node], r_int)
                        configured_rest_nodes.add(node)
            nodes_rest = rec.get("nodes_rest")
            if isinstance(nodes_rest, list):
                for n in nodes_rest:
                    if isinstance(n, str):
                        configured_rest_nodes.add(n)
        elif k == "warning":
            warnings.append(rec)
        elif k == "node_round":
            r = rec.get("round")
            node = rec.get("node")
            commit_ts = parse_iso(rec.get("commit_ts_utc"))
            if r is not None and node:
                node_max_round[node] = max(node_max_round[node], int(r))
                if commit_ts is not None and node not in commit_ts_by_round[r]:
                    # Prefer the FIRST commit_ts we saw for this (round,node).
                    commit_ts_by_round[r][node] = commit_ts
                elif rec.get("back_fill"):
                    # Only register as back-filled if we don't already have
                    # a better (commit_ts-bearing) observation for that round.
                    if r not in commit_ts_by_round or not commit_ts_by_round[r]:
                        back_filled_rounds.add(int(r))
        elif k == "block":
            r = rec.get("round")
            if r is not None and r not in block_by_round:
                block_by_round[r] = rec
        elif k == "container":
            rust_state_samples.append(rec)

    # Rounds that at least one commit_ts landed for — authoritative
    # sampled rounds. Back-filled rounds are tracked separately.
    timestamped_rounds = set(commit_ts_by_round.keys())
    # De-dupe back-fills against timestamped rounds.
    back_filled_rounds = back_filled_rounds - timestamped_rounds
    all_observed = timestamped_rounds | back_filled_rounds
    observed_rounds = sorted(timestamped_rounds)
    baseline_record = next(
        (m for m in run_metas if m.get("phase") == "baseline"), None
    )
    start_max = baseline_record.get("start_max_round") if baseline_record else None
    target_max = baseline_record.get("target_max_round") if baseline_record else None

    first_observed = min(all_observed) if all_observed else None
    last_observed = max(all_observed) if all_observed else None

    # Block-time distribution
    sorted_block_rounds = sorted(block_by_round.keys())
    block_times = []
    missing_block_ts = []
    for r in sorted_block_rounds:
        b = block_by_round[r]
        ts = b.get("block_ts_unix")
        if not isinstance(ts, (int, float)):
            missing_block_ts.append(r)
            continue
        if (r - 1) in block_by_round:
            prev = block_by_round[r - 1].get("block_ts_unix")
            if isinstance(prev, (int, float)):
                dt = float(ts) - float(prev)
                if dt >= 0:
                    block_times.append(dt)

    # Commit-latency distribution (max-min commit_ts across nodes, per round)
    commit_spreads_ms = []
    partial_observations = 0
    for r, per_node in commit_ts_by_round.items():
        if len(per_node) < 2:
            partial_observations += 1
            continue
        tss = list(per_node.values())
        spread = (max(tss) - min(tss)).total_seconds() * 1000.0
        commit_spreads_ms.append(spread)

    # Proposer histogram
    proposers = Counter()
    missing_proposer_rounds = []
    for r, b in block_by_round.items():
        p = b.get("proposer")
        if p:
            proposers[p] += 1
        else:
            missing_proposer_rounds.append(r)

    # Lag check (max - min across REST nodes at end-of-run)
    lag_violation = None
    if node_max_round:
        mx = max(node_max_round.values())
        mn = min(node_max_round.values())
        if (mx - mn) > lag_tolerance:
            lag_violation = {"max": mx, "min": mn, "delta": mx - mn}

    # Rust container sampling
    rust_states = Counter()
    rust_log_rounds = []
    for s in rust_state_samples:
        rust_states[s.get("state", "unknown")] += 1
        if isinstance(s.get("log_round"), int):
            rust_log_rounds.append(s["log_round"])
    rust_summary = {
        "samples": len(rust_state_samples),
        "state_counts": dict(rust_states),
        "log_rounds_seen": (min(rust_log_rounds) if rust_log_rounds else None,
                             max(rust_log_rounds) if rust_log_rounds else None),
    }

    # Warning digest: first ~6 chars of each message
    warning_digest = Counter()
    for w in warnings:
        msg = str(w.get("msg", ""))
        prefix = msg.split(":")[0][:48]
        warning_digest[prefix] += 1

    # Find the authoritative "end" run_meta for the final phase
    end_meta = next(
        (m for m in reversed(run_metas)
         if m.get("phase") in {
             "target_reached", "stalled", "overall_timeout", "interrupted"
         }),
        None,
    )

    return {
        "run_meta": {
            "start": run_metas[0] if run_metas else None,
            "baseline": baseline_record,
            "end": end_meta,
            "all_phases": [m.get("phase") for m in run_metas if m.get("phase")],
        },
        "rounds": {
            "observed_count": len(observed_rounds),
            "back_filled_only_count": len(back_filled_rounds),
            "first_observed": first_observed,
            "last_observed": last_observed,
            "start_max": start_max,
            "target_max": target_max,
            "blocks_captured": len(block_by_round),
            "blocks_missing_ts": missing_block_ts,
            "blocks_missing_proposer": missing_proposer_rounds,
            "partial_round_observations": partial_observations,
        },
        "block_time_s": {
            "n": len(block_times),
            "mean": statistics.mean(block_times) if block_times else None,
            "p50": percentile(block_times, 50),
            "p95": percentile(block_times, 95),
            "p99": percentile(block_times, 99),
            "min": min(block_times) if block_times else None,
            "max": max(block_times) if block_times else None,
        },
        "commit_spread_ms": {
            "n": len(commit_spreads_ms),
            "mean": statistics.mean(commit_spreads_ms) if commit_spreads_ms else None,
            "p50": percentile(commit_spreads_ms, 50),
            "p95": percentile(commit_spreads_ms, 95),
            "p99": percentile(commit_spreads_ms, 99),
            "min": min(commit_spreads_ms) if commit_spreads_ms else None,
            "max": max(commit_spreads_ms) if commit_spreads_ms else None,
        },
        "proposers": dict(proposers),
        "node_max_round": dict(node_max_round),
        "lag_violation": lag_violation,
        "lag_tolerance": lag_tolerance,
        "rust_summary": rust_summary,
        # None on pre-#473 soak outputs (no participation records present).
        "rust_participation": summarize_participation_records(records),
        "warnings": {
            "count": len(warnings),
            "digest": dict(warning_digest),
        },
        # Raw block_times / spreads are useful for follow-up plotting;
        # keep them out of the printed report but expose in the JSON.
        "_samples": {
            "block_times_s": block_times,
            "commit_spreads_ms": commit_spreads_ms,
        },
    }


def print_report(summary, source_paths):  # noqa: C901 — one linear report
    end = summary["run_meta"]["end"] or {}
    baseline = summary["run_meta"]["baseline"] or {}
    phase = end.get("phase", "(no end record)")
    elapsed = end.get("total_elapsed_s")

    print("=" * 72)
    print(f"Mixed-cluster soak — analysis ({', '.join(source_paths)})")
    print("=" * 72)
    print(f"End phase: {phase}" + (
        f"   elapsed: {elapsed:.1f}s" if isinstance(elapsed, (int, float)) else ""
    ))
    print(f"Baseline max round: {baseline.get('start_max_round')}")
    print(f"Target  max round: {baseline.get('target_max_round')}")
    print(f"Final   max round: {max(summary['node_max_round'].values()) if summary['node_max_round'] else None}")
    print()

    r = summary["rounds"]
    print(f"Rounds: observed={r['observed_count']} "
          f"back_filled_only={r['back_filled_only_count']} "
          f"first={r['first_observed']} last={r['last_observed']} "
          f"blocks_captured={r['blocks_captured']} "
          f"partial_observations={r['partial_round_observations']}")
    if r["blocks_missing_ts"]:
        print(f"  rounds with missing block_ts: {len(r['blocks_missing_ts'])}")
    if r["blocks_missing_proposer"]:
        print(f"  rounds with missing proposer:  {len(r['blocks_missing_proposer'])}")
    print()

    bt = summary["block_time_s"]
    if bt["n"]:
        print(f"Block time (s): n={bt['n']} mean={bt['mean']:.3f} "
              f"p50={bt['p50']:.3f} p95={bt['p95']:.3f} p99={bt['p99']:.3f} "
              f"min={bt['min']:.3f} max={bt['max']:.3f}")
    else:
        print("Block time: no consecutive block pairs captured.")

    cs = summary["commit_spread_ms"]
    if cs["n"]:
        print(f"Commit spread (ms, max-min across nodes per round): "
              f"n={cs['n']} mean={cs['mean']:.1f} p50={cs['p50']:.1f} "
              f"p95={cs['p95']:.1f} p99={cs['p99']:.1f} "
              f"min={cs['min']:.1f} max={cs['max']:.1f}")
    else:
        print("Commit spread: not enough multi-node observations.")
    print()

    print("Per-node max round at end-of-run:")
    for node, mx in sorted(summary["node_max_round"].items()):
        print(f"  {node}: {mx}")
    lag = summary["lag_violation"]
    if lag:
        print(f"  LAG VIOLATION: {lag['delta']} > {summary['lag_tolerance']} "
              f"(max {lag['max']}, min {lag['min']})")
    else:
        print(f"  lag within tolerance (<={summary['lag_tolerance']})")
    print()

    print("Proposer histogram:")
    if summary["proposers"]:
        total = sum(summary["proposers"].values())
        for addr, count in sorted(summary["proposers"].items(), key=lambda kv: -kv[1]):
            pct = 100.0 * count / total
            short = addr[:8] + "…" if len(addr) > 8 else addr
            print(f"  {short:<10s} count={count:<5d} ({pct:5.1f}%)")
    else:
        print("  no proposer data captured.")
    print()

    # ── #470 §1: Rust proposer share ────────────────────────────────────
    ps = summary.get("rust_proposer_share")
    if ps:
        short = ps["account"][:8] + "…"
        print("Rust proposer share (issue #470 §1):")
        print(
            f"  account={short} proposals={ps['rust_proposals']}"
            f"/{ps['blocks_with_proposer']}"
            + (
                f" ({100.0 * ps['observed_fraction']:.1f}%)"
                if ps["observed_fraction"] is not None
                else ""
            )
        )
        if ps["expected"] is not None:
            print(
                f"  binomial(N={ps['blocks_with_proposer']}, "
                f"p={ps['stake_fraction']:.3f}): expected={ps['expected']:.1f} "
                f"sd={ps['sd']:.2f} z={ps['z']:+.2f} "
                f"accept=[{max(0.0, ps['lower_bound']):.1f}, "
                f"{ps['upper_bound']:.1f}] at {ps['sigma_bound']:.1f} sigma"
            )
        if ps.get("normal_approx_weak"):
            print(
                "  note: expected count < 10 — the normal approximation is "
                "indicative only; the zero-proposal gate still applies."
            )
        print("  " + ("OK" if ps["ok"] else "FAIL"))
        print()

    # ── #470 §3: vote-step coverage ─────────────────────────────────────
    sc = summary.get("rust_step_coverage")
    if sc:
        parsed = summary.get("rust_participation_log", {})
        print("Rust vote-step coverage (issue #470 §3):")
        print(
            f"  attests={parsed.get('attests_total', 0)} "
            f"rounds={parsed.get('rounds_attested', 0)} "
            f"steps={parsed.get('steps', {})}"
        )
        print(
            f"  required={','.join(sc['required_steps'])} "
            f"seen={','.join(sc['steps_seen']) or 'none'}"
        )
        adv = parsed.get("period_advanced_rounds") or []
        if adv:
            print(
                f"  period advancement (next step) observed in "
                f"{len(adv)} round(s): {adv[:10]}"
                + (" …" if len(adv) > 10 else "")
            )
        else:
            print("  period advancement: none observed (period 0 throughout)")
        print("  " + ("OK" if sc["ok"] else "FAIL"))
        print()

    cad = summary.get("cadence")
    if cad and (cad["max_mean_block_time_s"] or cad["max_p95_block_time_s"]):
        print(
            f"Cadence gate: max_mean={cad['max_mean_block_time_s']}s "
            f"max_p95={cad['max_p95_block_time_s']}s — "
            + ("OK" if cad["ok"] else "FAIL")
        )
        print()

    # ── #473: participation endpoint ────────────────────────────────────
    part = summary.get("rust_participation")
    if part:
        print("Rust participation endpoint (issue #473, /v2/participation/status):")
        if not part.get("endpoint_ever_available"):
            print(f"  UNAVAILABLE — samples={part['samples']} "
                  f"reasons={part.get('unavailable_reasons')}")
        else:
            print(
                f"  votes={part.get('votes_cast_total')} "
                f"by_step={part.get('votes_cast_by_step')} "
                f"proposals={part.get('proposals_made')} "
                f"(accepted={part.get('proposals_accepted')}, "
                f"rejected={part.get('proposals_rejected')}) "
                f"reproposals={part.get('reproposals')}"
            )
            print(
                f"  rounds_started={part.get('rounds_started')} "
                f"blocks_committed={part.get('blocks_committed')} "
                f"last_committed_round={part.get('last_committed_round')} "
                f"broadcast_failures={part.get('vote_broadcast_failures')}"
            )
            for label, key in (
                ("round duration", "recent_round_duration_ms"),
                ("round start to first vote", "recent_first_vote_ms"),
            ):
                d = part.get(key)
                if d and d.get("n"):
                    print(
                        f"  {label} (ms, last {d['n']} rounds): "
                        f"p50={d['p50']:.0f} p95={d['p95']:.0f} max={d['max']:.0f}"
                    )
            if part.get("unavailable_samples"):
                print(f"  note: {part['unavailable_samples']} sample(s) could not "
                      f"reach the endpoint: {part.get('unavailable_reasons')}")
        pc = summary.get("rust_participation_check")
        if pc:
            print("  " + ("OK" if pc["ok"] else "FAIL"))
        print()

    rs = summary["rust_summary"]
    print(f"Rust node (phase6-rust-node-4): samples={rs['samples']} "
          f"states={rs['state_counts']} "
          f"log_rounds_seen={rs['log_rounds_seen']}")
    print()

    w = summary["warnings"]
    if w["count"]:
        print(f"Warnings: {w['count']} record(s)")
        for prefix, count in sorted(w["digest"].items(), key=lambda kv: -kv[1]):
            print(f"  [{count}] {prefix}")
    else:
        print("Warnings: none")
    print()

    # Acceptance hints
    hints = []
    if phase != "target_reached":
        hints.append(f"end-phase not 'target_reached' (got {phase!r})")
    if lag:
        hints.append(
            f"node lag {lag['delta']} > tolerance {summary['lag_tolerance']}"
        )
    if w["count"] > 0:
        hints.append(f"{w['count']} warning record(s) — review above")
    if r["blocks_missing_ts"]:
        hints.append(f"{len(r['blocks_missing_ts'])} block(s) missing block_ts")
    if r["blocks_missing_proposer"]:
        hints.append(
            f"{len(r['blocks_missing_proposer'])} block(s) missing proposer"
        )
    for key in (
        "rust_proposer_share",
        "rust_step_coverage",
        "rust_participation_check",
        "cadence",
    ):
        section = summary.get(key)
        if section:
            hints.extend(section.get("failures", []))

    if hints:
        print("Acceptance hints (see docs/SOAK_METHODOLOGY.md §Acceptance):")
        for h in hints:
            print(f"  - {h}")
        return False

    print("Acceptance hints: clean run — all criteria satisfied.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze ONE PLAN-32 / TASK-87 soak JSONL file. "
            "Pass separate files through separate invocations — merging "
            "records across runs silently confuses the lag check and "
            "block-time distribution."
        ),
    )
    parser.add_argument("input", help="A JSONL file from metrics.py.")
    parser.add_argument("--lag-tolerance", type=int, default=5,
                        help="Max allowed per-node round delta at end of run (default 5).")
    parser.add_argument("--json-out", default=None,
                        help="Path to write the full summary JSON (default: <input>.summary.json).")
    # ── issue #470 (Epic 42c) participation assertions ──────────────────
    parser.add_argument("--rust-account", default=None,
                        help="Rust participant address; assert it proposed blocks "
                             "with a share consistent with --rust-stake-fraction.")
    parser.add_argument("--rust-stake-fraction", type=float, default=0.10,
                        help="Rust account's share of ONLINE stake (default 0.10).")
    parser.add_argument("--proposer-sigma", type=float, default=3.0,
                        help="Two-sided binomial bound in sigmas (default 3.0).")
    parser.add_argument("--rust-log", default=None,
                        help="Path to a `docker logs phase6-rust-node-4` capture; "
                             "asserts vote-step coverage.")
    parser.add_argument("--require-steps", default=",".join(DEFAULT_REQUIRED_STEPS),
                        help="Comma-separated vote steps that must appear in "
                             "--rust-log (default: soft,cert).")
    # ── issue #473 (Epic 42f) participation-endpoint assertions ─────────
    parser.add_argument("--require-participation-endpoint", action="store_true",
                        help="Assert the Rust node's /v2/participation/status "
                             "reported real votes (issue #473). Without this "
                             "flag the endpoint data is reported but not gated, "
                             "so pre-#473 soak outputs still analyze cleanly.")
    parser.add_argument("--max-round-duration-ms", type=float, default=0.0,
                        help="With --require-participation-endpoint: fail if the "
                             "Rust node's p95 round-start-to-commit time exceeds "
                             "this many ms (0 = disabled).")
    parser.add_argument("--max-mean-block-time", type=float, default=0.0,
                        help="Fail if mean inter-block time exceeds this many "
                             "seconds (0 = disabled).")
    parser.add_argument("--max-p95-block-time", type=float, default=0.0,
                        help="Fail if p95 inter-block time exceeds this many "
                             "seconds (0 = disabled).")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"error: {args.input} not found", file=sys.stderr)
        return 2

    records = list(load_jsonl([args.input]))
    if not records:
        print(f"error: no records loaded from {args.input}", file=sys.stderr)
        return 2

    summary = summarize(records, args.lag_tolerance)

    # ── issue #470 assertions, layered on top of the base summary ───────
    if args.rust_account:
        summary["rust_proposer_share"] = proposer_share_check(
            summary["proposers"],
            args.rust_account,
            args.rust_stake_fraction,
            args.proposer_sigma,
        )
    if args.rust_log:
        try:
            with open(args.rust_log, encoding="utf-8", errors="replace") as f:
                log_text = f.read()
        except OSError as e:
            print(f"error: cannot read --rust-log {args.rust_log}: {e}",
                  file=sys.stderr)
            return 2
        parsed = parse_rust_participation_log(log_text)
        required = [s.strip() for s in args.require_steps.split(",") if s.strip()]
        summary["rust_participation_log"] = parsed
        summary["rust_step_coverage"] = step_coverage_check(parsed, required)
    if args.require_participation_endpoint:
        required = [s.strip() for s in args.require_steps.split(",") if s.strip()]
        summary["rust_participation_check"] = participation_endpoint_check(
            summary.get("rust_participation"),
            required,
            args.max_round_duration_ms,
        )
    summary["cadence"] = cadence_check(
        summary["block_time_s"],
        args.max_mean_block_time,
        args.max_p95_block_time,
    )

    clean = print_report(summary, [args.input])

    # Strip _samples from the sidecar to keep it compact (and also emit a
    # separate _samples file if the caller wants raw arrays).
    out_path = args.json_out or (args.input + ".summary.json")
    summary["acceptance_ok"] = bool(clean)
    serializable = {k: v for k, v in summary.items() if k != "_samples"}
    with open(out_path, "w") as f:
        json.dump(serializable, f, indent=2, default=str)
    print(f"summary JSON: {out_path}")

    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main())
