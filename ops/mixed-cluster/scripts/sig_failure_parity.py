#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""A transaction whose ed25519 signature does not verify, posted to a Go node
and to the Rust node of the running mixed cluster; the answers must match
(issue #1969).

go reports every failed signature of a group through the batch verifier as
`400 {"message":"At least one signature didn't pass verification"}`
(`crypto.ErrBatchHasFailedSigs`), on `POST /v2/transactions` and on
`POST /v2/transactions/simulate` with a msgpack or a JSON body.

    python3 sig_failure_parity.py [--go go-node-1] [--rust rust-node-4]

Needs the cluster from start.sh; host ports follow PHASE6_HOST_PORT_BASE.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ports  # noqa: E402
import unknown_field_parity as ufp  # noqa: E402

TOKEN = os.environ.get("ALGOD_TOKEN", "a" * 64)
# Cases algod-rust cannot pass yet, with the issue that tracks them.
KNOWN_GAPS = {"simulate_json": "#1972: go's JSON form of a SignedTxn is not decodable"}
GO_MESSAGE = "At least one signature didn't pass verification"


def address(key32):
    """The 58-character Algorand address of a 32-byte public key."""
    checksum = hashlib.new("sha512_256", key32).digest()[-4:]
    return base64.b32encode(key32 + checksum).decode().rstrip("=")


def _txn_msgpack():
    """A payment whose validity window [1, 1000] covers the first rounds of a fresh cluster."""
    return ufp._map([
        ("amt", ufp._uint(1000)), ("fee", ufp._uint(1000)), ("fv", ufp._uint(1)), ("gh", ufp._bin(bytes([3]) * 32)),
        ("lv", ufp._uint(1000)), ("rcv", ufp._bin(bytes([2]) * 32)), ("snd", ufp._bin(bytes([1]) * 32)),
        ("type", ufp._s("pay")),
    ])


def _stxn_msgpack():
    return ufp._map([("txn", _txn_msgpack()), ("sig", ufp._bin(bytes([7]) * 64))])


def _stxn_json():
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return {
        "txn": {
            "type": "pay", "snd": address(bytes([1]) * 32), "rcv": address(bytes([2]) * 32),
            "amt": 1000, "fee": 1000, "fv": 1, "lv": 1000, "gh": b64(bytes([3]) * 32),
        },
        "sig": b64(bytes([7]) * 64),
    }


def cases():
    """name -> {path, content_type, body}."""
    mp_request = ufp._map([("txn-groups", bytes([0x91]) + ufp._map([("txns", bytes([0x91]) + _stxn_msgpack())]))])
    return {
        "submit": {"path": "/v2/transactions", "content_type": "application/x-binary", "body": _stxn_msgpack()},
        "simulate_msgpack": {"path": "/v2/transactions/simulate", "content_type": "application/msgpack",
                             "body": mp_request},
        "simulate_json": {"path": "/v2/transactions/simulate", "content_type": "application/json",
                          "body": json.dumps({"txn-groups": [{"txns": [_stxn_json()]}]}).encode()},
    }


def compare(name, go, rust):
    problems = []
    if go[0] != rust[0]:
        problems.append("{}: status go={} rust={}".format(name, go[0], rust[0]))
    if ufp.message_of(go[1]) != ufp.message_of(rust[1]):
        problems.append("{}: message go={!r} rust={!r}".format(name, ufp.message_of(go[1]), ufp.message_of(rust[1])))
    return problems


def post(node, case):
    req = urllib.request.Request(
        "http://127.0.0.1:{}{}".format(ports.node_port(node), case["path"]), data=case["body"], method="POST",
        headers={"X-Algo-API-Token": TOKEN, "Content-Type": case["content_type"]})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--go", default="go-node-1")
    ap.add_argument("--rust", default="rust-node-4")
    ap.add_argument("--include-known-gaps", action="store_true", help="also run the cases listed in KNOWN_GAPS")
    a = ap.parse_args(argv)
    problems = []
    for name, case in sorted(cases().items()):
        if name in KNOWN_GAPS and not a.include_known_gaps:
            print("skip {} (known gap, {})".format(name, KNOWN_GAPS[name]))
            continue
        go, rust = post(a.go, case), post(a.rust, case)
        found = compare(name, go, rust)
        if ufp.message_of(go[1]) != GO_MESSAGE:
            found.append("{}: go answered {!r}, expected {!r}".format(name, ufp.message_of(go[1]), GO_MESSAGE))
        print("{} {}".format("FAIL" if found else "ok  ", name), "; ".join(found))
        problems += found
    print(json.dumps({"event": "sig_failure_parity", "ok": not problems, "cases": len([n for n in cases() if a.include_known_gaps or n not in KNOWN_GAPS]),
                      "skipped": {} if a.include_known_gaps else KNOWN_GAPS, "problems": problems}))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
