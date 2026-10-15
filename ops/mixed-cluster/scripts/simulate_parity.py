#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""POST msgpack `/v2/transactions/simulate` bodies to a Go node and to the
Rust node of the running mixed cluster and require identical answers
(issues #1967, #1968).

* `clean`: a well-formed request whose msgpack carries binary addresses and
  signatures (what every SDK sends). The Rust node used to answer 400 "could
  not decode simulate request"; go decodes it and rejects the bogus signature.
* `request` / `group` / `stxn` / `txn` / `hgi`: an unknown key at that level.
  go's strict msgpack decode fails, its JSON fallback then fails on the msgpack
  map marker, and the answer is one fixed text (captured from a go-algorand
  v5.0.3-stable node).

    python3 simulate_parity.py [--go go-node-1] [--rust rust-node-4]

Needs the cluster from start.sh; host ports follow PHASE6_HOST_PORT_BASE.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ports  # noqa: E402
import unknown_field_parity as ufp  # noqa: E402

TOKEN = os.environ.get("ALGOD_TOKEN", "a" * 64)
GO_REJECTION = ("failed to decode object: json decode error [pos 1]: "
                "only encoded map or array can be decoded into a struct")


def _arr(items):
    return bytes([0x90 + len(items)]) + b"".join(items)


def bodies():
    """name -> msgpack simulate request body."""
    one = ufp._uint(1)
    sig = ("sig", ufp._bin(bytes([7]) * 64))

    def stxn(top=(), txn_extra=()):
        return ufp._map([("txn", ufp._txn(txn_extra)), sig, *top])

    def req(stxns, group=(), top=()):
        return ufp._map([("txn-groups", _arr([ufp._map([("txns", _arr(stxns)), *group])])), *top])

    return {
        "clean": req([stxn()]),
        "request": req([stxn()], top=[("zzz", one)]),
        "group": req([stxn()], group=[("zzz", one)]),
        "stxn": req([stxn(top=[("zzz", one)])]),
        "txn": req([stxn(txn_extra=[("zzz", one)])]),
        "hgi": req([stxn(top=[("hgi", b"\xc3")])]),
    }


def expected(name):
    if name == "clean":
        return 400, "At least one signature didn't pass verification"
    return 400, GO_REJECTION


def compare(name, go, rust):
    problems = []
    if go[0] != rust[0]:
        problems.append("{}: status go={} rust={}".format(name, go[0], rust[0]))
    if ufp.message_of(go[1]) != ufp.message_of(rust[1]):
        problems.append("{}: message go={!r} rust={!r}".format(name, ufp.message_of(go[1]), ufp.message_of(rust[1])))
    return problems


def post(node, body):
    req = urllib.request.Request(
        "http://127.0.0.1:{}/v2/transactions/simulate".format(ports.node_port(node)), data=body, method="POST",
        headers={"X-Algo-API-Token": TOKEN, "Content-Type": "application/msgpack"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--go", default="go-node-1")
    ap.add_argument("--rust", default="rust-node-4")
    a = ap.parse_args(argv)
    problems = []
    for name, body in sorted(bodies().items()):
        go, rust = post(a.go, body), post(a.rust, body)
        found = compare(name, go, rust)
        want = expected(name)
        if (go[0], ufp.message_of(go[1])) != want:
            found.append("{}: go answered {} {!r}, expected {} {!r}".format(name, go[0], ufp.message_of(go[1]), *want))
        print("{} {}".format("FAIL" if found else "ok  ", name), "; ".join(found))
        problems += found
    print(json.dumps({"event": "simulate_parity", "ok": not problems, "bodies": len(bodies()), "problems": problems}))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
