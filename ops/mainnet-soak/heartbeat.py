#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""One-line summary of the newest sample in monitor.py's status JSONL.

Used by the mainnet-node-soak workflow's poll step to print a heartbeat line
to the job log every minute, so a job that is later killed/cancelled still
leaves live evidence in the streamed log (artifacts may never upload).
"""
import json
import sys


def summarize_last_line(line: str) -> str:
    try:
        d = json.loads(line)
        n = d["node"]
        p = d["peer"]
    except (ValueError, KeyError, TypeError) as e:
        return f"no sample yet ({e})"
    return (
        f"node_last_round={n.get('last_round')} peer_last_round={p.get('last_round')} "
        f"catchpoint={n.get('catchpoint')} "
        f"accounts={n.get('catchpoint_processed_accounts')}/{n.get('catchpoint_total_accounts')} "
        f"verified={n.get('catchpoint_verified_accounts')} "
        f"blocks={n.get('catchpoint_acquired_blocks')}/{n.get('catchpoint_total_blocks')} "
        f"node_ok={n.get('ok')}"
    )


if __name__ == "__main__":
    print(summarize_last_line(sys.stdin.read().strip()))
