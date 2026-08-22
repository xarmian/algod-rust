#!/usr/bin/env python3
# PLAN-32 / TASK-87 — per-round metric collector for the mixed cluster.
#
# Polls each Go node's /v2/status on a fixed interval, detects round
# transitions, and emits one JSONL record per observation. Once per newly
# observed round we also fetch /v2/blocks/{r} from a healthy Go node to
# capture block-level metadata (proposer, block timestamp, txn count,
# block hash).
#
# Since issue #469 the Rust node (phase6-rust-node-4) runs
# `participate --rest-listen`, and since issue #473 it also serves
# `GET /v2/participation/status` with its own consensus-participation
# counters and per-round timings. We therefore scrape it like any other
# node and additionally poll that endpoint, instead of inferring
# participation from `docker logs`. The `docker inspect` container sample
# is kept as a liveness signal (and as the fallback that still produces a
# record when the endpoint is unreachable).
#
# Output: one JSONL record per event to --out. Records have a 'kind':
#   - "run_meta":      start / baseline / end markers for the run
#   - "node_round":    a REST node observed round r at wall time t
#   - "block":         block r's metadata (proposer, ts, hash, txn_count)
#   - "container":     a state sample for the Rust node's container
#   - "participation": a /v2/participation/status snapshot (#473)
#   - "warning":       a soft issue (stale baseline, parse failure, lag)
#
# Stop conditions (in priority order):
#   1. Target round reached (cluster max >= start_max + --rounds)
#   2. Stall detected (no REST node advanced in --stall-timeout s)
#   3. Overall wall-clock timeout exceeded (--overall-timeout; 0 = off)
#   4. SIGINT / SIGTERM — emits a run_meta{phase=interrupted} and flushes.
#
# Usage:
#   scripts/metrics.py --rounds 200 --out soak.jsonl --interval 0.5
#
# Design notes:
#   - Single-process, single-thread. Sampling is sequential across nodes,
#     which is fine at the 500ms interval we default to.
#   - Only the stdlib is used (urllib, json, subprocess) so there are no
#     extra install steps beyond python3.
#   - commit_ts_utc is derived from (now - time_since_last_round); it is
#     only meaningful for the node's CURRENT last_round (the latest tick).
#     When we back-fill intermediate rounds after a multi-round jump we
#     leave commit_ts_utc as null — the jump itself is a warning sign and
#     analyze.py treats those rounds conservatively.

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

TOKEN = "a" * 64  # matches docker-compose.yml; harness is local-only.

NODES_REST = [
    {"name": "go-node-1", "container": "phase6-go-node-1", "host": "127.0.0.1", "port": 4001},
    {"name": "go-node-2", "container": "phase6-go-node-2", "host": "127.0.0.1", "port": 4002},
    {"name": "go-node-3", "container": "phase6-go-node-3", "host": "127.0.0.1", "port": 4003},
]

NODES_NOREST = [
    {"name": "rust-node-4", "container": "phase6-rust-node-4"},
]

# Nodes exposing `GET /v2/participation/status` (issue #473). Only the Rust
# node implements it — go-algorand has no equivalent endpoint — so this list
# is what makes the Rust node's participation machine-readable instead of
# log-scraped.
NODES_PARTICIPATION = [
    {"name": "rust-node-4", "host": "127.0.0.1", "port": 4004},
]

# Best-effort log regex for the Rust node. The Rust relay today does not
# emit a stable structured "round=N" line, so we look for a handful of
# human-written phrases that appear as blocks are imported. If none
# match, we emit log_round=null and the container state still serves as
# a liveness signal.
RUST_LOG_ROUND_RE = re.compile(
    r"\b(?:imported|committed|applied|round advanced to|at round)\s+(?:block\s+)?(?:to\s+)?(\d+)\b",
    re.IGNORECASE,
)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def http_get_json(url: str, timeout: float = 5.0):
    req = Request(url, headers={"X-Algo-API-Token": TOKEN})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def docker_state(container: str) -> str:
    try:
        out = subprocess.run(
            ["docker", "inspect", "--format={{.State.Status}}", container],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        return out or "notfound"
    except subprocess.CalledProcessError:
        return "notfound"
    except Exception:
        return "unknown"


def rust_latest_round_from_logs(container: str):
    try:
        res = subprocess.run(
            ["docker", "logs", "--tail", "200", container],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return None
    lines = (res.stdout + res.stderr).splitlines()
    for line in reversed(lines):
        m = RUST_LOG_ROUND_RE.search(line)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
    return None


def participation_snapshot(host: str, port: int):
    """Fetch `/v2/participation/status` (issue #473).

    Returns `(snapshot_dict, None)` on success, `(None, reason)` otherwise.
    A 404 is a meaningful, non-error answer: the node is up but is not
    participating in consensus, which is exactly what the endpoint promises
    to distinguish from "participating with zero votes".
    """
    url = f"http://{host}:{port}/v2/participation/status"
    try:
        return http_get_json(url, timeout=3), None
    except HTTPError as e:
        if e.code == 404:
            return None, "not_participating"
        return None, f"http_{e.code}"
    except Exception as e:  # URLError, timeouts, malformed JSON
        return None, f"unreachable: {e!s}"


def summarize_participation(snap: dict) -> dict:
    """Flatten the parts of a participation snapshot we record per sample.

    The full snapshot carries a `recent_rounds` array that would dominate the
    JSONL if written on every tick, so it is summarized here; the terminal
    sample (see `main`) writes the whole document once.
    """
    if not isinstance(snap, dict):
        return {}
    out = {
        "votes_cast_total": snap.get("votes_cast_total"),
        "votes_cast_by_step": snap.get("votes_cast_by_step"),
        "proposals_made": snap.get("proposals_made"),
        "proposal_rounds": snap.get("proposal_rounds"),
        "proposals_accepted": snap.get("proposals_accepted"),
        "proposals_rejected": snap.get("proposals_rejected"),
        "reproposals": snap.get("reproposals"),
        "blocks_committed": snap.get("blocks_committed"),
        "vote_broadcast_failures": snap.get("vote_broadcast_failures"),
        "rounds_started": snap.get("rounds_started"),
        "current_round": snap.get("current_round"),
        "last_committed_round": snap.get("last_committed_round"),
        "uptime_ms": snap.get("uptime_ms"),
    }
    for key, field in (
        ("round_duration", "round_duration"),
        ("round_start_to_first_vote", "round_start_to_first_vote"),
        ("round_start_to_proposal", "round_start_to_proposal"),
    ):
        stats = snap.get(field)
        if isinstance(stats, dict):
            out[key + "_ms"] = {
                "count": stats.get("count"),
                "last": stats.get("last_ms"),
                "min": stats.get("min_ms"),
                "max": stats.get("max_ms"),
                "mean": stats.get("mean_ms"),
            }
    return out


def write_record(fp, record: dict) -> None:
    record.setdefault("wall_ts", now_utc_iso())
    fp.write(json.dumps(record, separators=(",", ":")) + "\n")
    fp.flush()


def extract_proposer(block: dict, cert):
    # v40+ stores the proposer in the block header (`prp`); earlier
    # protocols put it in cert.prop.oprop. Try both.
    if isinstance(block, dict):
        for key in ("prp", "proposer"):
            v = block.get(key)
            if v:
                return v
    if isinstance(cert, dict):
        prop = cert.get("prop")
        if isinstance(prop, dict):
            for key in ("oprop", "original-proposer", "original_proposer"):
                v = prop.get(key)
                if v:
                    return v
    return None


def extract_txn_count(block: dict):
    """Return the count of transactions included in THIS block.

    The v2 block JSON omits the `txns` key entirely when the block has
    no transactions. `tc` is the *cumulative* chain-wide transaction
    counter and is intentionally NOT used here — confusing cumulative
    with per-block counts has burned us before.
    """
    if not isinstance(block, dict):
        return None
    txns = block.get("txns")
    if isinstance(txns, list):
        return len(txns)
    if txns is None:
        return 0
    # Unexpected shape (e.g. dict) — let analysis notice it.
    return None


class Interrupted(Exception):
    pass


def install_signal_handlers():
    def _raise(*_):
        raise Interrupted()

    signal.signal(signal.SIGINT, _raise)
    signal.signal(signal.SIGTERM, _raise)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Soak-run metric collector (PLAN-32 / TASK-87)",
    )
    parser.add_argument(
        "--rounds", type=int, default=200,
        help="Number of NEW rounds to observe beyond the current baseline (default 200).",
    )
    parser.add_argument(
        "--out", required=True,
        help="Output JSONL path. Overwritten if it exists.",
    )
    parser.add_argument(
        "--interval", type=float, default=0.5,
        help="Poll interval in seconds (default 0.5).",
    )
    parser.add_argument(
        "--stall-timeout", type=float, default=60.0,
        help="Abort if no REST node advances for N seconds (default 60).",
    )
    parser.add_argument(
        "--overall-timeout", type=float, default=0.0,
        help="Abort after N wall-clock seconds (0 = no cap).",
    )
    parser.add_argument(
        "--rust-sample-interval", type=float, default=5.0,
        help="Sample the Rust container every N seconds (default 5).",
    )
    args = parser.parse_args()

    if args.rounds <= 0:
        print("--rounds must be > 0", file=sys.stderr)
        return 2
    if args.interval <= 0:
        print("--interval must be > 0", file=sys.stderr)
        return 2

    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    install_signal_handlers()
    start_wall = time.time()
    fp = open(args.out, "w", buffering=1)

    write_record(fp, {
        "kind": "run_meta",
        "phase": "start",
        "target_rounds": args.rounds,
        "interval_s": args.interval,
        "stall_timeout_s": args.stall_timeout,
        "overall_timeout_s": args.overall_timeout,
        "nodes_rest": [n["name"] for n in NODES_REST],
        "nodes_norest": [n["name"] for n in NODES_NOREST],
        "nodes_participation": [n["name"] for n in NODES_PARTICIPATION],
    })

    # Establish a baseline from /v2/status so we only record NEW transitions.
    last_seen: dict = {}
    start_round_by_node: dict = {}
    try:
        for n in NODES_REST:
            st = http_get_json(f"http://{n['host']}:{n['port']}/v2/status", timeout=5)
            r = int(st.get("last-round", 0))
            last_seen[n["name"]] = r
            start_round_by_node[n["name"]] = r
    except Exception as e:
        write_record(fp, {
            "kind": "warning",
            "msg": f"baseline /v2/status failed: {e!s}; cluster may not be up",
        })
        write_record(fp, {"kind": "run_meta", "phase": "end", "reason": "baseline_unavailable"})
        fp.close()
        return 3

    start_max = max(start_round_by_node.values())
    target_max = start_max + args.rounds
    write_record(fp, {
        "kind": "run_meta",
        "phase": "baseline",
        "start_round_by_node": start_round_by_node,
        "start_max_round": start_max,
        "target_max_round": target_max,
    })

    seen_blocks: set = set()
    last_advance_wall = start_wall
    last_rust_sample = 0.0
    # Most recent full participation snapshot per node, written out once at
    # end-of-run (the per-tick records carry only the summary).
    last_participation: dict = {}
    final_phase = "target_reached"
    try:
        while True:
            tick = time.time()
            if args.overall_timeout > 0 and (tick - start_wall) > args.overall_timeout:
                write_record(fp, {
                    "kind": "warning",
                    "msg": f"overall timeout after {tick - start_wall:.0f}s",
                })
                final_phase = "overall_timeout"
                break

            cluster_max = 0
            any_advance = False

            for n in NODES_REST:
                try:
                    st = http_get_json(
                        f"http://{n['host']}:{n['port']}/v2/status", timeout=3
                    )
                except Exception as e:
                    write_record(fp, {
                        "kind": "warning",
                        "msg": f"status fetch {n['name']} failed: {e!s}",
                    })
                    continue
                # Capture the wall time RIGHT AFTER this node's /v2/status
                # returned — used below to derive commit_ts_utc. Using the
                # outer `tick` would backdate every node's commit_ts by
                # however long the earlier polls took (including retries /
                # timeouts), which contaminates commit_spread_ms.
                poll_ts_wall = time.time()

                try:
                    lr = int(st.get("last-round", 0))
                except (TypeError, ValueError):
                    write_record(fp, {
                        "kind": "warning",
                        "msg": f"status parse {n['name']}: unexpected last-round={st.get('last-round')!r}",
                    })
                    continue

                tslr_ns = int(st.get("time-since-last-round", 0) or 0)
                catchup_ns = int(st.get("catchup-time", 0) or 0)
                cluster_max = max(cluster_max, lr)
                prev = last_seen.get(n["name"], lr)

                if lr < prev:
                    # A node reporting a smaller last-round than we last
                    # observed is notable — either a genuine reorg (very
                    # unlikely on a healthy cluster) or a stale response.
                    # Record and keep the prior max so the lag check below
                    # doesn't drop.
                    write_record(fp, {
                        "kind": "warning",
                        "msg": f"regression: {n['name']} last-round went {prev} -> {lr}",
                    })
                elif lr > prev:
                    # Record each step we advanced through. commit_ts_utc is
                    # only meaningful for the current last_round (the value
                    # of time-since-last-round applies to lr, not earlier
                    # rounds in a multi-step jump).
                    for r in range(prev + 1, lr + 1):
                        commit_ts = None
                        tslr_ms = None
                        if r == lr:
                            commit_wall = poll_ts_wall - tslr_ns / 1e9
                            commit_ts = datetime.fromtimestamp(
                                commit_wall, tz=timezone.utc
                            ).isoformat()
                            tslr_ms = tslr_ns / 1e6
                        write_record(fp, {
                            "kind": "node_round",
                            "node": n["name"],
                            "round": r,
                            "commit_ts_utc": commit_ts,
                            "time_since_last_round_ms": tslr_ms,
                            "catchup_time_ns": catchup_ns,
                            "back_fill": r != lr,
                        })
                    last_seen[n["name"]] = lr
                    any_advance = True

            # Fetch block metadata for any newly-observed rounds that fall
            # in the soak window (start_max, target_max].
            for r in range(start_max + 1, cluster_max + 1):
                if r in seen_blocks or r > target_max:
                    continue
                fetched = False
                for n in NODES_REST:
                    try:
                        b = http_get_json(
                            f"http://{n['host']}:{n['port']}/v2/blocks/{r}?format=json",
                            timeout=5,
                        )
                    except (HTTPError, URLError):
                        continue  # try the next node
                    except Exception as e:
                        write_record(fp, {
                            "kind": "warning",
                            "msg": f"block fetch r={r} via {n['name']} failed: {e!s}",
                        })
                        continue
                    blk = b.get("block") if isinstance(b, dict) else None
                    cert = b.get("cert") if isinstance(b, dict) else None
                    proposer = extract_proposer(blk, cert)
                    tx_counter = (blk or {}).get("tc") if isinstance(blk, dict) else None
                    write_record(fp, {
                        "kind": "block",
                        "round": r,
                        "block_ts_unix": (blk or {}).get("ts") if isinstance(blk, dict) else None,
                        "proposer": proposer,
                        "gen_hash": (blk or {}).get("gh") if isinstance(blk, dict) else None,
                        "prev_hash": (blk or {}).get("prev") if isinstance(blk, dict) else None,
                        "txn_count": extract_txn_count(blk) if isinstance(blk, dict) else None,
                        "tx_counter": tx_counter if isinstance(tx_counter, int) else None,
                        "source_node": n["name"],
                    })
                    seen_blocks.add(r)
                    fetched = True
                    break
                if not fetched:
                    # Leave the round un-marked; next tick we'll try again.
                    pass

            # Rust container sample (at a coarser cadence so we don't spam docker)
            if (tick - last_rust_sample) >= args.rust_sample_interval:
                for n in NODES_NOREST:
                    state = docker_state(n["container"])
                    rr = rust_latest_round_from_logs(n["container"])
                    write_record(fp, {
                        "kind": "container",
                        "node": n["name"],
                        "state": state,
                        "log_round": rr,
                    })
                # Participation counters straight from the node (#473) —
                # authoritative where the log scrape above is best-effort.
                for n in NODES_PARTICIPATION:
                    snap, reason = participation_snapshot(n["host"], n["port"])
                    if snap is None:
                        write_record(fp, {
                            "kind": "participation",
                            "node": n["name"],
                            "available": False,
                            "reason": reason,
                        })
                        continue
                    last_participation[n["name"]] = snap
                    record = {
                        "kind": "participation",
                        "node": n["name"],
                        "available": True,
                    }
                    record.update(summarize_participation(snap))
                    write_record(fp, record)
                last_rust_sample = tick

            if any_advance:
                last_advance_wall = tick
            elif (tick - last_advance_wall) > args.stall_timeout:
                write_record(fp, {
                    "kind": "warning",
                    "msg": f"stall: no node advanced in {tick - last_advance_wall:.0f}s",
                    "last_seen": dict(last_seen),
                })
                final_phase = "stalled"
                break

            if cluster_max >= target_max:
                break

            # Sleep the remainder of the tick interval
            slept = time.time() - tick
            remaining = args.interval - slept
            if remaining > 0:
                time.sleep(remaining)
    except Interrupted:
        final_phase = "interrupted"
        write_record(fp, {"kind": "warning", "msg": "interrupted by signal"})

    # Terminal participation sample: take a fresh one (so the run's last few
    # rounds are included) and write the FULL snapshot, `recent_rounds` and
    # all, for analyze.py's timing distribution.
    for n in NODES_PARTICIPATION:
        snap, reason = participation_snapshot(n["host"], n["port"])
        if snap is None:
            snap = last_participation.get(n["name"])
        if snap is None:
            write_record(fp, {
                "kind": "participation_final",
                "node": n["name"],
                "available": False,
                "reason": reason,
            })
            continue
        write_record(fp, {
            "kind": "participation_final",
            "node": n["name"],
            "available": True,
            "snapshot": snap,
        })

    write_record(fp, {
        "kind": "run_meta",
        "phase": final_phase,
        "total_elapsed_s": time.time() - start_wall,
        "final_last_seen": dict(last_seen),
        "final_max_round": max(last_seen.values()) if last_seen else None,
        "blocks_captured": len(seen_blocks),
    })
    fp.close()
    return 0 if final_phase == "target_reached" else 1


if __name__ == "__main__":
    sys.exit(main())
