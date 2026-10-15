#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""POST bodies carrying a key go-algorand's SignedTxn structs lack to a Go node
and to the Rust node of the running mixed cluster and require byte-identical
responses (issue #1962).

go decodes `POST /v2/transactions` with `protocol.NewDecoder`
(`ErrorIfNoField`), so each body is a 400 whose text names the stream offset
just after the unknown key. The offsets in `unknown_field_parity_test.py` were
captured from a go-algorand v5.0.3-stable node.

    python3 unknown_field_parity.py [--go go-node-1] [--rust rust-node-4]

Needs the cluster from start.sh. Host ports follow PHASE6_HOST_PORT_BASE
(ports.py). Exit 0: every body answered identically by both nodes.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ports  # noqa: E402

TOKEN = os.environ.get("ALGOD_TOKEN", "a" * 64)


def _s(x):
    b = x.encode()
    assert len(b) < 32
    return bytes([0xA0 + len(b)]) + b


def _bin(b):
    return bytes([0xC4, len(b)]) + b


def _uint(n):
    return bytes([n]) if n < 128 else b"\xcd" + n.to_bytes(2, "big")


def _map(pairs):
    return bytes([0x80 + len(pairs)]) + b"".join(_s(k) + v for k, v in pairs)


def _txn(extra=()):
    return _map([
        ("amt", _uint(1000)), ("fee", _uint(1000)), ("fv", _uint(100)), ("gh", _bin(bytes([3]) * 32)),
        ("lv", _uint(1100)), ("rcv", _bin(bytes([2]) * 32)), ("snd", _bin(bytes([1]) * 32)),
        ("type", _s("pay")), *extra,
    ])


def bodies():
    """name -> (request body, the unknown key go names)."""
    sig = ("sig", _bin(bytes([7]) * 64))
    one = _uint(1)
    ok = _map([("txn", _txn()), sig])
    top = _map([("txn", _txn()), sig, ("zzz", one)])
    txn = _map([("txn", _txn([("zzz", one)])), sig])
    lsig = _map([("txn", _txn()), ("lsig", _map([("l", _bin(b"\x06\x81\x01")), ("zzz", one)]))])
    subsig = bytes([0x91]) + _map([("pk", _bin(bytes([5]) * 32)), ("zzz", one)])
    msig = _map([("txn", _txn()), ("msig", _map([("v", one), ("thr", one), ("subsig", subsig)]))])
    pqsig = _map([("txn", _txn()), ("pqsig", _map([("sch", _bin(b"f1")), ("zzz", one)]))])
    t = ("txn", _txn())
    return {
        "top": (top, "zzz"), "txn": (txn, "zzz"), "lsig": (lsig, "zzz"), "msig": (msig, "zzz"),
        "pqsig": (pqsig, "zzz"),
        "group_ok_top": (ok + top, "zzz"), "group_top_ok": (top + ok, "zzz"), "group_ok_txn": (ok + txn, "zzz"),
        "hgi": (_map([("hgi", b"\xc3"), sig, t]), "hgi"), "hgh": (_map([("hgh", b"\xc3"), sig, t]), "hgh"),
        "ca": (_map([("ca", _uint(5)), sig, t]), "ca"), "apid": (_map([("apid", _uint(5)), sig, t]), "apid"),
        "both": (_map([("hgh", b"\xc3"), ("hgi", b"\xc3"), sig, t]), "hgh"),
    }


def expected_message(pos, key):
    return ("msgpack decode error [pos {}]: no matching struct field found "
            "when decoding stream map with key {}".format(pos, key))


def message_of(text):
    try:
        return json.loads(text)["message"]
    except (ValueError, KeyError, TypeError):
        return text.strip()


def compare(name, go, rust):
    """Differences between the two nodes' (status, body) for one body."""
    problems = []
    if go[0] != rust[0]:
        problems.append("{}: status go={} rust={}".format(name, go[0], rust[0]))
    if message_of(go[1]) != message_of(rust[1]):
        problems.append("{}: message go={!r} rust={!r}".format(name, message_of(go[1]), message_of(rust[1])))
    return problems


def post(node, body):
    req = urllib.request.Request(
        "http://127.0.0.1:{}/v2/transactions".format(ports.node_port(node)), data=body, method="POST",
        headers={"X-Algo-API-Token": TOKEN, "Content-Type": "application/x-binary"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--go", default="go-node-1")
    ap.add_argument("--rust", default="rust-node-4")
    a = ap.parse_args(argv)
    problems = []
    for name, (body, key) in sorted(bodies().items()):
        go, rust = post(a.go, body), post(a.rust, body)
        found = compare(name, go, rust)
        pos = body.index(key.encode()) + len(key)
        if message_of(go[1]) != expected_message(pos, key):
            found.append("{}: go answered {!r}, expected {!r}".format(name, message_of(go[1]), expected_message(pos, key)))
        print("{} {}".format("FAIL" if found else "ok  ", name), "" if not found else "; ".join(found))
        problems += found
    print(json.dumps({"event": "unknown_field_parity", "ok": not problems, "bodies": len(bodies()), "problems": problems}))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
