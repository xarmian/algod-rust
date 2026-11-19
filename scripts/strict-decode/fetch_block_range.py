#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Fetch a range of real blocks for the strict-decode sweep (issue #2439).

Writes GET /v2/blocks/{r}?format=msgpack bodies (`{"block", "cert"}`, byte for
byte as served) for r in FIRST..LAST into OUT in the replay corpus record
layout (`ACRPBLK1`, then per round u64 round, u32 length, payload), the file
`crates/core/algo-codec/tests/real_chain_decode_sweep_test.rs` decodes through
algod-rust's strict readers. The serving nodes accepted every one of these
blocks, so any block the sweep rejects is a reader stricter than go.

    fetch_block_range.py --endpoint URL (--first R --last R | --last-n N) --out FILE

`--last-n N` takes the N rounds ending at the endpoint's last round. Public
endpoints that work: https://mainnet-api.algonode.cloud,
https://testnet-api.algonode.cloud, https://mainnet-api.voi.nodely.dev,
https://algod.aramidmain.a-wallet.net. Then:

    ALGOD_RUST_DECODE_SWEEP=FILE [ALGOD_RUST_DECODE_SWEEP_NETWORK=aramidmain] \\
        cargo test -p algo-codec --test real_chain_decode_sweep_test -- --nocapture

(`scripts/strict-decode/decode_sweep.sh` runs both steps for the four networks.)
"""

import argparse
import concurrent.futures
import json
import struct
import sys
import time
import urllib.error
import urllib.request

MAGIC = b"ACRPBLK1"


def get(url, retries):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "algod-rust-decode-sweep"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt + 1 == retries:
                raise RuntimeError(f"{url}: {e}") from e
            time.sleep(1 + attempt * 2)
    raise AssertionError("unreachable")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--first", type=int)
    ap.add_argument("--last", type=int)
    ap.add_argument("--last-n", type=int)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--retries", type=int, default=6)
    a = ap.parse_args(argv)
    ep = a.endpoint.rstrip("/")
    if a.last_n is not None:
        last = json.loads(get(f"{ep}/v2/status", a.retries))["last-round"]
        first = max(0, last - a.last_n + 1)
    elif a.first is not None and a.last is not None:
        first, last = a.first, a.last
    else:
        ap.error("give --first and --last, or --last-n")
    if last < first:
        ap.error("empty range")

    def block(r):
        return get(f"{ep}/v2/blocks/{r}?format=msgpack", a.retries)

    n = 0
    with open(a.out, "wb") as f, concurrent.futures.ThreadPoolExecutor(a.workers) as pool:
        f.write(MAGIC)
        window = max(a.workers * 4, 8)
        pending = {}
        nxt = first
        for r in range(first, last + 1):
            while nxt <= last and nxt < r + window:
                pending[nxt] = pool.submit(block, nxt)
                nxt += 1
            body = pending.pop(r).result()
            f.write(struct.pack(">QI", r, len(body)) + body)
            n += 1
            if n % 1000 == 0:
                print(f"fetch_block_range: {n}/{last - first + 1}", file=sys.stderr, flush=True)
    print(f"fetch_block_range: rounds {first}..{last} ({n} blocks) -> {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
