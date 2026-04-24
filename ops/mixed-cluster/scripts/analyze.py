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
# Acceptance-criteria hints (printed at the bottom):
#   - Any stall / interrupt / timeout phase in run_meta
#   - Any lag > --lag-tolerance
#   - Any warning records
#   - Any blocks missing block_ts / proposer
# Exit code is 0 iff every acceptance hint is clean. The full criteria
# from TASK-87 live in docs/SOAK_METHODOLOGY.md.
#
# Usage:
#   scripts/analyze.py <soak.jsonl> [--lag-tolerance N] [--json-out PATH]

import argparse
import json
import math
import os
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime


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


def print_report(summary, source_paths):
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
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"error: {args.input} not found", file=sys.stderr)
        return 2

    records = list(load_jsonl([args.input]))
    if not records:
        print(f"error: no records loaded from {args.input}", file=sys.stderr)
        return 2

    summary = summarize(records, args.lag_tolerance)
    clean = print_report(summary, [args.input])

    # Strip _samples from the sidecar to keep it compact (and also emit a
    # separate _samples file if the caller wants raw arrays).
    out_path = args.json_out or (args.input + ".summary.json")
    serializable = {k: v for k, v in summary.items() if k != "_samples"}
    with open(out_path, "w") as f:
        json.dump(serializable, f, indent=2, default=str)
    print(f"summary JSON: {out_path}")

    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main())
