#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""State-proof cross-check for the mixed cluster (Phase 21 / DIV-001, #1948).

The 3 go-algorand + 1 algod-rust cluster is the only place where a
go-algorand node and an algod-rust node validate each other's Falcon-1024
signatures *inside a live consensus protocol*: every online account holds a
Falcon state-proof key, every node signs state-proof messages with it, and
the first committed state-proof transaction (for round 512 on a fresh chain,
`StateProofInterval = 256`) is validated -- reveal signatures and all -- by
every node. This script waits for that proof and asserts:

  1. every node reports `last-round >= --state-proof-round + --margin`;
  2. `GET /v2/stateproofs/{round}` succeeds on every node and returns the
     identical state-proof message and the identical proof bytes;
  3. the block hashes of the rounds around the proof's commitment
     (`--state-proof-round .. +margin`) are identical on all nodes, i.e. no
     node rejected, or forked over, the block that carries the proof;
  4. (informational) the block-header state-proof tracking `n` has advanced
     past the proven round on every node that exposes it.

Output is one JSON object (`stateproof_check`) on stdout; exit codes: 0 all
checks passed, 2 a check failed, 3 timed out / nodes unreachable.

Standard library only. `run_checks` takes its HTTP fetcher as a parameter so
the logic is unit-tested without a cluster (stateproof_check_test.py).
"""

import argparse
import json
import os
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


def http_get_json(host, port, path, timeout=10):
    """GET http://host:port/path -> (status, parsed-json-or-None)."""
    req = urllib.request.Request(
        "http://{}:{}{}".format(host, port, path), headers={"X-Algo-API-Token": TOKEN}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, OSError, ValueError):
        return 0, None


def last_round(fetch, node):
    status, body = fetch(node, "/v2/status")
    if status == 200 and isinstance(body, dict):
        return body.get("last-round")
    return None


def normalized_proof(body):
    """The comparable part of a /v2/stateproofs/{round} response."""
    if not isinstance(body, dict):
        return None
    return json.dumps(
        {"Message": body.get("Message"), "StateProof": body.get("StateProof")},
        sort_keys=True,
    )


def sp_tracking_next(fetch, node, rnd):
    """Header state-proof tracking `n` (next round to prove) at `rnd`, if exposed."""
    status, body = fetch(node, "/v2/blocks/{}".format(rnd))
    if status != 200 or not isinstance(body, dict):
        return None
    spt = (body.get("block") or {}).get("spt")
    if isinstance(spt, dict):
        basic = spt.get("0", spt.get(0))
        if isinstance(basic, dict):
            return basic.get("n")
    return None


def run_checks(fetch, nodes, proof_round, margin):
    """Run checks 2-4 against nodes that have already reached the target round.

    `fetch(node_name, path) -> (status, json)`.
    Returns (checks, details) where checks is a list of {name, ok, detail}.
    """
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    # 2. identical proofs everywhere
    proofs = {}
    for node in nodes:
        status, body = fetch(node, "/v2/stateproofs/{}".format(proof_round))
        proofs[node] = (status, normalized_proof(body))
    missing = [n for n, (st, p) in proofs.items() if st != 200 or p is None]
    add(
        "state_proof_served_by_every_node",
        not missing,
        "missing/failed on: {}".format(missing) if missing else "round {}".format(proof_round),
    )
    distinct = {p for (st, p) in proofs.values() if st == 200 and p is not None}
    add(
        "state_proof_identical_on_every_node",
        len(distinct) == 1 and not missing,
        "{} distinct proof payload(s)".format(len(distinct)),
    )

    # 3. identical block hashes around the commitment
    mismatches = []
    unreadable = []
    for rnd in range(proof_round, proof_round + margin + 1):
        hashes = {}
        for node in nodes:
            status, body = fetch(node, "/v2/blocks/{}/hash".format(rnd))
            if status == 200 and isinstance(body, dict) and body.get("blockHash"):
                hashes[node] = body["blockHash"]
            else:
                unreadable.append((rnd, node))
        if len(set(hashes.values())) > 1:
            mismatches.append((rnd, hashes))
    add(
        "block_hashes_identical_around_proof",
        not mismatches and not unreadable,
        "mismatches: {}; unreadable: {}".format(mismatches[:3], unreadable[:3])
        if (mismatches or unreadable)
        else "rounds {}..{} identical on {} nodes".format(
            proof_round, proof_round + margin, len(nodes)
        ),
    )

    # 4. informational: tracking advanced
    advanced = {}
    for node in nodes:
        n = sp_tracking_next(fetch, node, proof_round + margin)
        if n is not None:
            advanced[node] = n
    if advanced:
        add(
            "state_proof_tracking_advanced",
            all(n > proof_round for n in advanced.values()),
            "header spt.n at round {}: {}".format(proof_round + margin, advanced),
        )
    return checks


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--state-proof-round", type=int, default=512,
                    help="the round whose state proof must be committed (default 512)")
    ap.add_argument("--margin", type=int, default=12,
                    help="rounds past the proof round to wait for / compare (default 12)")
    ap.add_argument("--timeout", type=int, default=3600, help="seconds to wait for the target round")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args(argv[1:])

    ports = dict(NODES)
    names = [n for n, _ in NODES]

    def fetch(node, path):
        return http_get_json(args.host, ports[node], path)

    target = args.state_proof_round + args.margin
    deadline = time.time() + args.timeout
    last_report = 0
    while True:
        rounds = {n: last_round(fetch, n) for n in names}
        if all(r is not None and r >= target for r in rounds.values()):
            break
        if time.time() > deadline:
            print(json.dumps({"event": "stateproof_check", "ok": False,
                              "error": "timeout waiting for round {}".format(target),
                              "rounds": rounds}))
            return 3
        if time.time() - last_report > 60:
            print("waiting for round {}: {}".format(target, rounds), file=sys.stderr)
            last_report = time.time()
        time.sleep(5)

    checks = run_checks(fetch, names, args.state_proof_round, args.margin)
    ok = all(c["ok"] for c in checks if c["name"] != "state_proof_tracking_advanced") and all(
        c["ok"] for c in checks
    )
    print(json.dumps({"event": "stateproof_check", "ok": ok,
                      "state_proof_round": args.state_proof_round, "margin": args.margin,
                      "checks": checks}, indent=2))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
