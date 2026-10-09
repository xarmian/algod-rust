#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Cross-implementation block comparator for the mixed cluster (issue #1674).

For every round it fetches GET /v2/blocks/{round}?format=msgpack from all
four nodes (three go-algorand, one algod-rust) and compares the RAW BYTES of
the `block` value inside the response.  The response also carries a `cert`
whose vote set legitimately differs between nodes, so the comparison slices
the `block` entry out of the top-level map by msgpack structure rather than
comparing whole responses.  Because the block bytes include every
transaction's ApplyData (`dt`), byte equality proves both implementations
agree on block hash, per-round transaction count and ApplyData.

It also fetches GET /v2/blocks/{round}/hash from every node and compares.

Two modes share one engine:
  batch   (default)  compare --from-round..--to-round and exit
  --follow           keep comparing newly produced rounds (no upper bound)
                     until SIGTERM / SIGINT / --stop-file / --to-round.
                     Needed for long soaks: non-archival go nodes prune old
                     blocks, so rounds must be compared while they are fresh.

Output is JSONL: one `block_compare` record per round and a final
`blockcompare_summary`.  Exit codes: 0 all compared rounds identical;
2 at least one mismatch; 3 degraded (no round could be compared, or nodes
unreachable) and no mismatch.

Standard library only.
"""

import argparse
import json
import os
import signal
import struct
import sys
import time
import urllib.error
import urllib.request

TOKEN = os.environ.get("ALGOD_TOKEN", "a" * 64)
NODES = (
    ("go-node-1", 4001),
    ("go-node-2", 4002),
    ("go-node-3", 4003),
    ("rust-node-4", 4004),
)
REFERENCE = "go-node-1"


# ── minimal msgpack (decode + structural skip) ─────────────────────────


class MsgpackError(ValueError):
    pass


def skip(buf: bytes, pos: int) -> int:
    """Return the offset just past the msgpack value starting at pos."""
    if pos >= len(buf):
        raise MsgpackError("truncated at {}".format(pos))
    b = buf[pos]
    pos += 1
    if b <= 0x7F or b >= 0xE0 or b in (0xC0, 0xC2, 0xC3):
        return pos
    if 0x80 <= b <= 0x8F:
        return _skip_n(buf, pos, 2 * (b & 0x0F))
    if 0x90 <= b <= 0x9F:
        return _skip_n(buf, pos, b & 0x0F)
    if 0xA0 <= b <= 0xBF:
        return pos + (b & 0x1F)
    fixed = {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8, 0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8, 0xCA: 4, 0xCB: 8}
    if b in fixed:
        return pos + fixed[b]
    if b in (0xC4, 0xC5, 0xC6):  # bin 8/16/32
        n, pos = _len(buf, pos, {0xC4: 1, 0xC5: 2, 0xC6: 4}[b])
        return pos + n
    if b in (0xD9, 0xDA, 0xDB):  # str 8/16/32
        n, pos = _len(buf, pos, {0xD9: 1, 0xDA: 2, 0xDB: 4}[b])
        return pos + n
    if b in (0xDC, 0xDD):
        n, pos = _len(buf, pos, 2 if b == 0xDC else 4)
        return _skip_n(buf, pos, n)
    if b in (0xDE, 0xDF):
        n, pos = _len(buf, pos, 2 if b == 0xDE else 4)
        return _skip_n(buf, pos, 2 * n)
    if 0xD4 <= b <= 0xD8:  # fixext 1/2/4/8/16
        return pos + 1 + (1 << (b - 0xD4))
    if b in (0xC7, 0xC8, 0xC9):  # ext 8/16/32
        n, pos = _len(buf, pos, {0xC7: 1, 0xC8: 2, 0xC9: 4}[b])
        return pos + 1 + n
    raise MsgpackError("unsupported type byte 0x{:02x} at {}".format(b, pos - 1))


def _len(buf, pos, width):
    if pos + width > len(buf):
        raise MsgpackError("truncated length at {}".format(pos))
    return int.from_bytes(buf[pos:pos + width], "big"), pos + width


def _skip_n(buf, pos, n):
    for _ in range(n):
        pos = skip(buf, pos)
    return pos


def decode(buf: bytes, pos: int = 0):
    """Decode one value; returns (value, next_pos).  Maps become dicts."""
    if pos >= len(buf):
        raise MsgpackError("truncated at {}".format(pos))
    b = buf[pos]
    pos += 1
    if b <= 0x7F:
        return b, pos
    if b >= 0xE0:
        return b - 0x100, pos
    if b == 0xC0:
        return None, pos
    if b == 0xC2:
        return False, pos
    if b == 0xC3:
        return True, pos
    if 0x80 <= b <= 0x8F:
        return _decode_map(buf, pos, b & 0x0F)
    if 0x90 <= b <= 0x9F:
        return _decode_array(buf, pos, b & 0x0F)
    if 0xA0 <= b <= 0xBF:
        n = b & 0x1F
        return buf[pos:pos + n].decode("utf-8", "replace"), pos + n
    ints = {0xCC: ">B", 0xCD: ">H", 0xCE: ">I", 0xCF: ">Q", 0xD0: ">b", 0xD1: ">h", 0xD2: ">i", 0xD3: ">q",
            0xCA: ">f", 0xCB: ">d"}
    if b in ints:
        fmt = ints[b]
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, buf[pos:pos + size])[0], pos + size
    if b in (0xC4, 0xC5, 0xC6):
        n, pos = _len(buf, pos, {0xC4: 1, 0xC5: 2, 0xC6: 4}[b])
        return bytes(buf[pos:pos + n]), pos + n
    if b in (0xD9, 0xDA, 0xDB):
        n, pos = _len(buf, pos, {0xD9: 1, 0xDA: 2, 0xDB: 4}[b])
        return buf[pos:pos + n].decode("utf-8", "replace"), pos + n
    if b in (0xDC, 0xDD):
        n, pos = _len(buf, pos, 2 if b == 0xDC else 4)
        return _decode_array(buf, pos, n)
    if b in (0xDE, 0xDF):
        n, pos = _len(buf, pos, 2 if b == 0xDE else 4)
        return _decode_map(buf, pos, n)
    end = skip(buf, pos - 1)
    return ("ext", bytes(buf[pos:end])), end


def _decode_array(buf, pos, n):
    out = []
    for _ in range(n):
        v, pos = decode(buf, pos)
        out.append(v)
    return out, pos


def _decode_map(buf, pos, n):
    out = {}
    for _ in range(n):
        k, pos = decode(buf, pos)
        v, pos = decode(buf, pos)
        out[k if isinstance(k, (str, int)) else repr(k)] = v
    return out, pos


def map_entry_slice(buf: bytes, key: str):
    """Raw bytes of the value stored under `key` in a top-level msgpack map."""
    b = buf[0]
    pos = 1
    if 0x80 <= b <= 0x8F:
        n = b & 0x0F
    elif b == 0xDE:
        n, pos = _len(buf, pos, 2)
    elif b == 0xDF:
        n, pos = _len(buf, pos, 4)
    else:
        raise MsgpackError("top level is not a map (0x{:02x})".format(b))
    for _ in range(n):
        k, pos = decode(buf, pos)
        end = skip(buf, pos)
        if k == key:
            return bytes(buf[pos:end])
        pos = end
    return None


def diff_paths(a, b, path="$", limit=8):
    """First differing paths between two decoded msgpack values."""
    out = []
    _diff(a, b, path, out, limit)
    return out


def _fmt(v):
    if isinstance(v, bytes):
        return "bytes[{}]:{}".format(len(v), v[:8].hex())
    s = json.dumps(v, default=repr) if not isinstance(v, str) else v
    return s[:60]


def _diff(a, b, path, out, limit):
    if len(out) >= limit:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if k not in a:
                out.append("{}.{}: missing on left (right={})".format(path, k, _fmt(b[k])))
            elif k not in b:
                out.append("{}.{}: missing on right (left={})".format(path, k, _fmt(a[k])))
            else:
                _diff(a[k], b[k], "{}.{}".format(path, k), out, limit)
            if len(out) >= limit:
                return
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append("{}: length {} != {}".format(path, len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            _diff(x, y, "{}[{}]".format(path, i), out, limit)
            if len(out) >= limit:
                return
    elif a != b or type(a) is not type(b):
        out.append("{}: {} != {}".format(path, _fmt(a), _fmt(b)))


# ── block facts ────────────────────────────────────────────────────────


def block_facts(block: dict) -> dict:
    """Txn count, txn types, inner-txn and box-ref evidence of a decoded block."""
    txns = block.get("txns") or []
    types = {}
    inner = 0
    boxes = 0
    for t in txns:
        txn = t.get("txn") or {}
        ty = txn.get("type", "?")
        types[ty] = types.get(ty, 0) + 1
        dt = t.get("dt") or {}
        if dt.get("itx"):
            inner += 1
        if txn.get("apbx"):
            boxes += 1
    return {
        "txn_count": len(txns),
        "types": types,
        "non_payment": any(k != "pay" for k in types),
        "inner_txn_txns": inner,
        "box_ref_txns": boxes,
    }


def summarize_records(records) -> dict:
    """Aggregate block_compare records (shared by the CLI and analyze.py)."""
    s = {
        "rounds_compared": 0,
        "rounds_with_txns": 0,
        "rounds_non_payment": 0,
        "mismatches": [],
        "hash_mismatches": [],
        "degraded_rounds": 0,
        "txn_types": {},
        "inner_txn_txns": 0,
        "box_ref_txns": 0,
        "total_txns": 0,
        "nodes_missing": {},
    }
    for r in records:
        if r.get("kind") != "block_compare":
            continue
        if r.get("degraded"):
            s["degraded_rounds"] += 1
            for n in r.get("missing", []):
                s["nodes_missing"][n] = s["nodes_missing"].get(n, 0) + 1
            continue
        s["rounds_compared"] += 1
        tc = r.get("txn_count", 0)
        s["total_txns"] += tc
        if tc:
            s["rounds_with_txns"] += 1
        if r.get("non_payment"):
            s["rounds_non_payment"] += 1
        for ty, c in (r.get("types") or {}).items():
            s["txn_types"][ty] = s["txn_types"].get(ty, 0) + c
        s["inner_txn_txns"] += r.get("inner_txn_txns", 0)
        s["box_ref_txns"] += r.get("box_ref_txns", 0)
        if not r.get("identical", True):
            s["mismatches"].append({"round": r["round"], "nodes": r.get("mismatch_nodes", []), "diff": r.get("diff", [])})
        if not r.get("hash_match", True):
            s["hash_mismatches"].append({"round": r["round"], "hashes": r.get("hashes", {})})
    return s


# ── fetching ───────────────────────────────────────────────────────────


def http_get(port, path, timeout=10):
    req = urllib.request.Request("http://127.0.0.1:{}{}".format(port, path), headers={"X-Algo-API-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def node_round(port):
    try:
        return int(json.loads(http_get(port, "/v2/status"))["last-round"])
    except Exception:
        return None


def fetch_block(port, rnd):
    return http_get(port, "/v2/blocks/{}?format=msgpack".format(rnd))


def fetch_hash(port, rnd):
    return json.loads(http_get(port, "/v2/blocks/{}/hash".format(rnd))).get("blockHash")


def compare_round(rnd, fetch=fetch_block, fetch_h=fetch_hash, nodes=NODES, reference=REFERENCE):
    """Compare one round across nodes; returns a block_compare record."""
    raw = {}
    errors = {}
    for name, port in nodes:
        try:
            full = fetch(port, rnd)
            blk = map_entry_slice(full, "block")
            if blk is None:
                raise MsgpackError("no `block` entry in response")
            raw[name] = blk
        except Exception as e:  # noqa: BLE001 - recorded, not swallowed
            errors[name] = str(e)[:120]
    rec = {"kind": "block_compare", "round": rnd}
    if reference not in raw or len(raw) < 2:
        rec.update({"degraded": True, "missing": sorted(errors), "errors": errors})
        return rec
    ref = raw[reference]
    ref_val, _ = decode(ref)
    rec.update(block_facts(ref_val))
    mism = sorted(n for n, b in raw.items() if b != ref)
    rec["identical"] = not mism
    rec["nodes_compared"] = sorted(raw)
    rec["bytes"] = len(ref)
    if errors:
        rec["missing"] = sorted(errors)
        rec["errors"] = errors
    if mism:
        rec["mismatch_nodes"] = mism
        other, _ = decode(raw[mism[0]])
        rec["diff"] = diff_paths(ref_val, other)
    hashes = {}
    for name, port in nodes:
        try:
            hashes[name] = fetch_h(port, rnd)
        except Exception:  # noqa: BLE001 - hash endpoint is advisory
            hashes[name] = None
    known = {h for h in hashes.values() if h}
    rec["hashes"] = hashes
    rec["hash_match"] = len(known) <= 1
    return rec


# ── driver ─────────────────────────────────────────────────────────────


class Stop(Exception):
    pass


def run(args, out, now=time.time):
    stop = {"flag": False}

    def _h(*_):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _h)
    signal.signal(signal.SIGINT, _h)

    nxt = args.from_round
    records = []
    t0 = now()
    idle_since = now()
    while not (stop["flag"] or (args.stop_file and os.path.exists(args.stop_file))):
        rounds = [node_round(p) for _, p in NODES]
        tip = None if any(r is None for r in rounds) else min(rounds)
        upper = tip
        if tip is not None and args.to_round:
            upper = min(tip, args.to_round)
        if upper is not None and nxt <= upper:
            idle_since = now()
            while nxt <= upper and not stop["flag"]:
                rec = compare_round(nxt)
                records.append(rec)
                out.write(json.dumps(rec, sort_keys=True) + "\n")
                out.flush()
                nxt += 1
            continue
        # Nothing to compare right now.
        if not args.follow or (args.to_round and nxt > args.to_round):
            break
        if args.max_idle_s and now() - idle_since > args.max_idle_s:
            break
        time.sleep(args.poll_interval)
    summary = summarize_records(records)
    summary.update({
        "kind": "blockcompare_summary",
        "from_round": args.from_round,
        "last_round": nxt - 1,
        "elapsed_s": round(now() - t0, 1),
        "mismatch_count": len(summary["mismatches"]),
        "hash_mismatch_count": len(summary["hash_mismatches"]),
    })
    out.write(json.dumps(summary, sort_keys=True) + "\n")
    out.flush()
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=None, help="Output JSONL (required unless --summarize).")
    ap.add_argument("--summarize", default=None, metavar="JSONL",
                    help="Do not talk to the cluster: re-summarize an existing blockcompare JSONL.")
    ap.add_argument("--from-round", type=int, default=1)
    ap.add_argument("--to-round", type=int, default=0, help="0 = current cluster tip (batch) / unbounded (follow).")
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--stop-file", default=None, help="Stop (after finishing the pending round) when this file exists.")
    ap.add_argument("--poll-interval", type=float, default=1.0)
    ap.add_argument("--max-idle-s", type=float, default=0, help="Follow mode: stop after S s without new rounds.")
    args = ap.parse_args()
    if args.summarize:
        with open(args.summarize, encoding="utf-8") as f:
            recs = [json.loads(x) for x in f if x.strip()]
        s = summarize_records(recs)
        s.update({"last_round": max((r["round"] for r in recs if r.get("kind") == "block_compare"), default=0),
                  "mismatch_count": len(s["mismatches"]), "hash_mismatch_count": len(s["hash_mismatches"])})
    else:
        if not args.out:
            ap.error("--out is required")
        with open(args.out, "w", encoding="utf-8") as out:
            s = run(args, out)
    print(json.dumps({k: s[k] for k in ("rounds_compared", "rounds_non_payment", "mismatch_count",
                                         "hash_mismatch_count", "degraded_rounds", "last_round")}))
    if s["mismatch_count"] or s["hash_mismatch_count"]:
        return 2
    if s["rounds_compared"] == 0:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
