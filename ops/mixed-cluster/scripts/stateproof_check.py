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

  1. the proof is COMMITTED: the block-header state-proof tracking `n`
     (`block.spt["0"].n`) moves past `--state-proof-round`. go-algorand
     re-broadcasts each account's signature only on rounds where
     `address mod (StateProofInterval/2) == round mod (StateProofInterval/2)`,
     so the proof lands anywhere from a few rounds to ~128 rounds after the
     proven round; the script waits up to `--proof-timeout` seconds for it and
     binary-searches the exact commit round;
  2. every node reports `last-round >= commit round + --margin`;
  3. the commit block, fetched as raw msgpack from every node, carries an
     `stpf` transaction and its `block` bytes are byte-identical on all four
     nodes (the node-specific `cert` is excluded);
  4. the block hashes of EVERY round from the proven round through
     `commit round + margin` are identical on all nodes, i.e. no node
     rejected, or forked over, the block that carries the proof;
  5. the header tracking is identical on every node at that last round;
  6. `GET /v2/stateproofs/{round}` returns the identical state-proof message
     and proof bytes on every node, algod-rust included (issue #1952).

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blockcompare as bc  # noqa: E402  (msgpack slicing/decoding shared with the block comparator)
import ports  # noqa: E402

TOKEN = os.environ.get("ALGOD_TOKEN", "a" * 64)
# host ports from PHASE6_HOST_PORT_BASE (issue #1956), default 4001..4004
NODES = ports.nodes(("go-node-1", "go-node-2", "go-node-3", "rust-node-4"))


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


def http_get_bytes(host, port, path, timeout=30):
    """GET -> (status, raw bytes or None)."""
    req = urllib.request.Request(
        "http://{}:{}{}".format(host, port, path), headers={"X-Algo-API-Token": TOKEN}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, OSError, ValueError):
        return 0, None


def commit_block(fetch_raw, node, rnd):
    """(block-bytes, {txn type -> count}) of `rnd` as served by `node`, or (None, None)."""
    status, raw = fetch_raw(node, "/v2/blocks/{}?format=msgpack".format(rnd))
    if status != 200 or not raw:
        return None, None
    try:
        block_bytes = bc.map_entry_slice(raw, "block")
        if block_bytes is None:
            return None, None
        decoded, _ = bc.decode(block_bytes)
        return block_bytes, bc.block_facts(decoded)["types"]
    except Exception:  # malformed msgpack: treated as "unreadable"
        return None, None


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


def find_commit_round(fetch, node, proof_round, latest):
    """First round whose header tracking `n` is past `proof_round` (binary search).

    The tracking value only ever increases, so the predicate is monotone.
    Returns None if even `latest` has not advanced (proof not yet committed) or
    the node does not expose the field.
    """
    def advanced(rnd):
        n = sp_tracking_next(fetch, node, rnd)
        return n is not None and n > proof_round

    if not advanced(latest):
        return None
    lo, hi = proof_round, latest  # advanced(hi) is true; advanced(proof_round) is false
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if advanced(mid):
            hi = mid
        else:
            lo = mid
    return hi


def run_checks(fetch, nodes, proof_round, margin, commit_round=None, fetch_raw=None, rust_nodes=("rust-node-4",)):
    """Run the cross-node checks once every node has reached commit_round + margin.

    `fetch(node_name, path) -> (status, json)`. `commit_round` is the round of
    the block that carries the proof (default: `proof_round`, i.e. compare
    `proof_round .. proof_round + margin`).
    Returns a list of {name, ok, detail}.
    """
    commit_round = proof_round if commit_round is None else commit_round
    checks = []

    def add(name, ok, detail=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    # 2. the commit block: byte-identical on every node and carrying an `stpf` txn
    if fetch_raw is not None:
        blocks = {}
        types = {}
        for node in nodes:
            blocks[node], types[node] = commit_block(fetch_raw, node, commit_round)
        unreadable = [n for n in nodes if blocks[n] is None]
        add(
            "commit_block_carries_state_proof_txn_on_every_node",
            not unreadable and all(t.get("stpf", 0) >= 1 for t in types.values() if t),
            "unreadable on {}".format(unreadable) if unreadable
            else "txn types per node at round {}: {}".format(commit_round, types),
        )
        distinct_blocks = {b for b in blocks.values() if b is not None}
        add(
            "commit_block_bytes_identical_on_every_node",
            not unreadable and len(distinct_blocks) == 1,
            "{} distinct block encoding(s) at round {}".format(len(distinct_blocks), commit_round),
        )

    # 3. the REST endpoint: required of every node, algod-rust included (issue #1952)
    proofs = {}
    for node in nodes:
        status, body = fetch(node, "/v2/stateproofs/{}".format(proof_round))
        proofs[node] = (status, normalized_proof(body))
    go_nodes = [n for n in nodes if n not in rust_nodes]
    missing = [n for n in go_nodes if proofs[n][0] != 200 or proofs[n][1] is None]
    add(
        "state_proof_served_by_go_nodes",
        not missing,
        "missing/failed on: {}".format(missing) if missing else "round {}".format(proof_round),
    )
    distinct = {proofs[n][1] for n in go_nodes if proofs[n][0] == 200 and proofs[n][1] is not None}
    add(
        "state_proof_identical_on_go_nodes",
        len(distinct) == 1 and not missing,
        "{} distinct proof payload(s) across {} go-algorand nodes".format(len(distinct), len(go_nodes)),
    )
    for node in nodes:
        if node in rust_nodes:
            status, payload = proofs[node]
            same = payload is not None and payload in distinct
            add(
                "rust_state_proof_endpoint_" + node,
                same,
                "HTTP {}; {}".format(status, "identical to the Go nodes'" if same
                                     else "not served or differs from the Go nodes'"),
            )

    # 3. identical block hashes from the proven round through the commit + margin
    last = commit_round + margin
    mismatches = []
    unreadable = []
    for rnd in range(proof_round, last + 1):
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
        else "rounds {}..{} ({} rounds) identical on {} nodes".format(
            proof_round, last, last - proof_round + 1, len(nodes)
        ),
    )

    # 4. header tracking: advanced past the proven round, identically everywhere
    tracking = {}
    for node in nodes:
        n = sp_tracking_next(fetch, node, last)
        if n is not None:
            tracking[node] = n
    if tracking:
        add(
            "state_proof_tracking_advanced_identically",
            len(tracking) == len(nodes)
            and len(set(tracking.values())) == 1
            and all(n > proof_round for n in tracking.values()),
            "header spt.n at round {}: {}".format(last, tracking),
        )
    else:
        add("state_proof_tracking_advanced_identically", False, "no node exposed spt.n")
    return checks


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--state-proof-round", type=int, default=512,
                    help="the round whose state proof must be committed (default 512)")
    ap.add_argument("--margin", type=int, default=8,
                    help="rounds past the commit round to wait for / compare (default 8)")
    ap.add_argument("--timeout", type=int, default=3600,
                    help="seconds to wait for the chain to reach the proven round")
    ap.add_argument("--proof-timeout", type=int, default=1800,
                    help="seconds, after that, to wait for the proof to be committed")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args(argv[1:])

    ports = dict(NODES)
    names = [n for n, _ in NODES]
    reference = names[0]  # a go-algorand node decides when the proof is committed

    def fetch(node, path):
        return http_get_json(args.host, ports[node], path)

    def fail(error, **extra):
        print(json.dumps(dict({"event": "stateproof_check", "ok": False, "error": error}, **extra)))
        return 3

    def rounds():
        return {n: last_round(fetch, n) for n in names}

    last_report = [0.0]

    def progress(msg):
        if time.time() - last_report[0] > 60:
            print(msg, file=sys.stderr)
            last_report[0] = time.time()

    # Phase A: the chain reaches the proven round.
    deadline = time.time() + args.timeout
    while True:
        r = rounds()
        if all(v is not None and v >= args.state_proof_round for v in r.values()):
            break
        if time.time() > deadline:
            return fail("timeout waiting for round {}".format(args.state_proof_round), rounds=r)
        progress("waiting for round {}: {}".format(args.state_proof_round, r))
        time.sleep(5)

    # Phase B: the proof is committed (reference node's header tracking moves on).
    deadline = time.time() + args.proof_timeout
    commit = None
    while True:
        r = rounds()
        latest = last_round(fetch, reference)
        if latest is not None:
            commit = find_commit_round(fetch, reference, args.state_proof_round, latest)
        if commit is not None:
            break
        if time.time() > deadline:
            return fail("state proof for round {} not committed within {}s".format(
                args.state_proof_round, args.proof_timeout), rounds=r)
        progress("waiting for the state proof of round {} to be committed: {}".format(
            args.state_proof_round, r))
        time.sleep(5)
    print("state proof for round {} committed in block {}".format(args.state_proof_round, commit),
          file=sys.stderr)

    # Phase C: every node has caught up past the commit + margin.
    target = commit + args.margin
    deadline = time.time() + 600
    while True:
        r = rounds()
        if all(v is not None and v >= target for v in r.values()):
            break
        if time.time() > deadline:
            return fail("timeout waiting for round {} on every node".format(target),
                        commit_round=commit, rounds=r)
        time.sleep(3)

    def fetch_raw(node, path):
        return http_get_bytes(args.host, ports[node], path)

    checks = run_checks(fetch, names, args.state_proof_round, args.margin, commit, fetch_raw)
    ok = all(c["ok"] for c in checks)
    print(json.dumps({"event": "stateproof_check", "ok": ok,
                      "state_proof_round": args.state_proof_round,
                      "commit_round": commit,
                      "commit_delay_rounds": commit - args.state_proof_round,
                      "margin": args.margin, "checks": checks}, indent=2))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
