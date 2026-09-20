#!/usr/bin/env python3

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Issue #496 (Phase 7) — per-round metric collector for the 3 Go + 3 Rust
# mixed cluster.
#
# Copy of ../../mixed-cluster/scripts/metrics.py with the node tables
# pointed at this directory's six-node topology (phase7-* containers,
# ports 4101-4106) and three Rust participation nodes instead of one.
# See that file for the full design-notes header; the polling / stop-
# condition / JSONL-schema logic below is unchanged.

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
    {"name": "go-node-1", "container": "phase7-go-node-1", "host": "127.0.0.1", "port": 4101},
    {"name": "go-node-2", "container": "phase7-go-node-2", "host": "127.0.0.1", "port": 4102},
    {"name": "go-node-3", "container": "phase7-go-node-3", "host": "127.0.0.1", "port": 4103},
]

NODES_NOREST = [
    {"name": "rust-node-4", "container": "phase7-rust-node-4"},
    {"name": "rust-node-5", "container": "phase7-rust-node-5"},
    {"name": "rust-node-6", "container": "phase7-rust-node-6"},
]

# Nodes exposing `GET /v2/participation/status` (issue #473) — all three
# Rust nodes here, unlike the single one in the 4-node harness.
NODES_PARTICIPATION = [
    {"name": "rust-node-4", "host": "127.0.0.1", "port": 4104},
    {"name": "rust-node-5", "host": "127.0.0.1", "port": 4105},
    {"name": "rust-node-6", "host": "127.0.0.1", "port": 4106},
]

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
    url = f"http://{host}:{port}/v2/participation/status"
    try:
        return http_get_json(url, timeout=3), None
    except HTTPError as e:
        if e.code == 404:
            return None, "not_participating"
        return None, f"http_{e.code}"
    except Exception as e:
        return None, f"unreachable: {e!s}"


def summarize_participation(snap: dict) -> dict:
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
    if not isinstance(block, dict):
        return None
    txns = block.get("txns")
    if isinstance(txns, list):
        return len(txns)
    if txns is None:
        return 0
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
        description="Soak-run metric collector (issue #496 / Phase 7, 6-node cluster)",
    )
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--out", required=True)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--stall-timeout", type=float, default=60.0)
    parser.add_argument("--overall-timeout", type=float, default=0.0)
    parser.add_argument("--rust-sample-interval", type=float, default=5.0)
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
                    write_record(fp, {
                        "kind": "warning",
                        "msg": f"regression: {n['name']} last-round went {prev} -> {lr}",
                    })
                elif lr > prev:
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
                        continue
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
                    pass

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

            slept = time.time() - tick
            remaining = args.interval - slept
            if remaining > 0:
                time.sleep(remaining)
    except Interrupted:
        final_phase = "interrupted"
        write_record(fp, {"kind": "warning", "msg": "interrupted by signal"})

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
