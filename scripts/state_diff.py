#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Diff a round/address between a public node and a local algod-rust (issue #1771).

Divergence hunts keep rebuilding the same ad hoc plumbing: fetch the block
header from a public algod, fetch the account as of that round from a public
indexer, fetch the same from the local node, and compare. This is that tool.

  python3 scripts/state_diff.py --round 65743637 --address ADDR... \
      [--local http://127.0.0.1:8080] [--local-token TOKEN]

* Block: header (everything but `txns`) from the public algod
  /v2/blocks/<round>?format=json vs the local node's.
* Account: the public indexer's /v2/accounts/<addr>?round=<round> vs the local
  /v2/accounts/<addr>. The local node serves the *latest* state only, so the
  account diff is meaningful when the local node's round equals --round; a
  mismatch is reported up front.

Exit status: 0 no differences, 1 differences, 2 usage/fetch error.
Environment: STATE_DIFF_ALGOD / STATE_DIFF_INDEXER override the public hosts.
"""
import argparse
import json
import os
import sys

# Fields present on only one side by construction (indexer bookkeeping, or the
# per-request round stamp), never a state divergence.
IGNORED = {
    "round",
    "deleted",
    "created-at-round",
    "closed-at-round",
    "last-heartbeat",
    "last-proposed",
    "total-created-apps",
    "total-created-assets",
    "total-apps-opted-in",
    "total-assets-opted-in",
    "total-boxes",
    "total-box-bytes",
}
# List fields keyed by an identity field so order does not matter.
LIST_KEYS = {"assets": "asset-id", "apps-local-state": "id", "created-apps": "id", "created-assets": "index"}


def _empty(v):
    return v in (None, 0, False, "", [], {})


def _walk(path, a, b, out, side=("public", "local")):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k in IGNORED and not path:
                continue
            _walk(f"{path}.{k}" if path else k, a.get(k), b.get(k), out, side)
    elif a != b and not (_empty(a) and _empty(b)):
        out.append(f"{path}: {side[0]}={a!r} {side[1]}={b!r}")


def diff_accounts(public, local):
    """Return human-readable differences between two account JSON objects."""
    out = []
    for k in sorted((set(public) | set(local)) - IGNORED - set(LIST_KEYS)):
        _walk(k, public.get(k), local.get(k), out)
    for field, key in LIST_KEYS.items():
        pa = {e.get(key): e for e in public.get(field) or []}
        la = {e.get(key): e for e in local.get(field) or []}
        for ident in sorted(set(pa) | set(la), key=str):
            p, l = pa.get(ident), la.get(ident)
            if p is None:
                out.append(f"{field}[{ident}]: only in local")
            elif l is None:
                out.append(f"{field}[{ident}]: only in public")
            else:
                _walk(f"{field}[{ident}]", p, l, out)
    return out


def block_header(block_json):
    """The block header: the `block` object minus its transactions."""
    b = dict(block_json.get("block", block_json))
    b.pop("txns", None)
    return b


def diff_blocks(public, local):
    out = []
    _walk("", block_header(public), block_header(local), out)
    return out


def _get(url, headers=None):
    import requests

    r = requests.get(url, headers=headers or {}, timeout=60)
    r.raise_for_status()
    return r.json()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--address", action="append", default=[])
    ap.add_argument("--local", default="http://127.0.0.1:8080")
    ap.add_argument("--local-token", default=os.environ.get("ALGOD_TOKEN", ""))
    ap.add_argument("--algod", default=os.environ.get("STATE_DIFF_ALGOD", "https://mainnet-api.algonode.cloud"))
    ap.add_argument("--indexer", default=os.environ.get("STATE_DIFF_INDEXER", "https://mainnet-idx.algonode.cloud"))
    a = ap.parse_args(argv)
    hdr = {"X-Algo-API-Token": a.local_token} if a.local_token else {}
    differences = 0
    try:
        r = a.round
        local_status = _get(f"{a.local}/v2/status", hdr)
        local_round = local_status.get("last-round")
        diffs = diff_blocks(
            _get(f"{a.algod}/v2/blocks/{r}?format=json"),
            _get(f"{a.local}/v2/blocks/{r}?format=json", hdr),
        )
        print(f"block {r}: " + ("identical header" if not diffs else f"{len(diffs)} difference(s)"))
        for d in diffs:
            print("  " + d)
        differences += len(diffs)
        if a.address and local_round != r:
            print(f"note: local node is at round {local_round}, not {r}; account diffs compare different rounds")
        for addr in a.address:
            pub = _get(f"{a.indexer}/v2/accounts/{addr}?round={r}").get("account", {})
            loc = _get(f"{a.local}/v2/accounts/{addr}", hdr)
            diffs = diff_accounts(pub, loc)
            print(f"account {addr}: " + ("identical" if not diffs else f"{len(diffs)} difference(s)"))
            for d in diffs:
                print("  " + d)
            differences += len(diffs)
    except Exception as e:  # network/HTTP failure is a usage error, not a diff
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
