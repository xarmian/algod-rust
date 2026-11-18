#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Checker of the issue #2400 `upgradeprop-nonutf8` mixed-cluster case.

go-node-1 runs a test-only go-algorand build (upgradeprop-inject/) that
proposes an upgrade to a NON-UTF-8 byte string. go accepts any such proposal
(data/bookkeeping/block.go applyUpgradeVote: only the length and the wait
range are checked) and carries it as `nextproto` in every header until the
vote deadline `nextbefore`, where the failed proposal is cleared. This module
fetches every round from every node and asserts:

  * every node (Rust included) has every round through the deadline + margin,
    i.e. nobody stalled or forked off at the proposal block (pre-#2397 Rust
    could not decode the header and stopped there);
  * block hashes AND raw block msgpack are identical on all nodes;
  * `upgradeprop` is byte-exactly the injected bytes on the proposal round
    only, and `nextproto`/`nextbefore` are byte-exact on every header of the
    window and cleared from the deadline on.

Subcommands:
  run       poll the live cluster, collect, evaluate, write a JSON summary
  evaluate  re-evaluate a previously collected observations JSON

Pure functions (decode_raw, header_fields, evaluate) are unit-tested in
upgradeprop_check_test.py without a cluster.
"""
import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ports  # noqa: E402

TOKEN = os.environ.get("ALGOD_TOKEN", "a" * 64)
NODE_NAMES = ("go-node-1", "go-node-2", "go-node-3", "rust-node-4")
REFERENCE = "go-node-1"


# ── raw msgpack decode: strings stay bytes, nothing is lossy ──────────


class MsgpackError(ValueError):
    pass


def _uint(buf, pos, width):
    if pos + width > len(buf):
        raise MsgpackError("truncated at {}".format(pos))
    return int.from_bytes(buf[pos:pos + width], "big"), pos + width


def decode_raw(buf, pos=0):
    """Decode one msgpack value at pos -> (value, next_pos).

    str and bin both decode to `bytes` (a Go `string` is a byte string), map
    keys too. Floats/ext are not used by algod block responses."""
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
    if b in (0xC2, 0xC3):
        return b == 0xC3, pos
    if 0xA0 <= b <= 0xBF:
        n = b & 0x1F
        return bytes(buf[pos:pos + n]), pos + n
    if b in (0xD9, 0xDA, 0xDB, 0xC4, 0xC5, 0xC6):
        width = {0xD9: 1, 0xDA: 2, 0xDB: 4, 0xC4: 1, 0xC5: 2, 0xC6: 4}[b]
        n, pos = _uint(buf, pos, width)
        if pos + n > len(buf):
            raise MsgpackError("truncated string at {}".format(pos))
        return bytes(buf[pos:pos + n]), pos + n
    if b in (0xCC, 0xCD, 0xCE, 0xCF):
        return _uint(buf, pos, {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8}[b])
    if b in (0xD0, 0xD1, 0xD2, 0xD3):
        width = {0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8}[b]
        v, pos = _uint(buf, pos, width)
        if v >= 1 << (8 * width - 1):
            v -= 1 << (8 * width)
        return v, pos
    if 0x90 <= b <= 0x9F or b in (0xDC, 0xDD):
        if b <= 0x9F:
            n = b & 0x0F
        else:
            n, pos = _uint(buf, pos, 2 if b == 0xDC else 4)
        out = []
        for _ in range(n):
            v, pos = decode_raw(buf, pos)
            out.append(v)
        return out, pos
    if 0x80 <= b <= 0x8F or b in (0xDE, 0xDF):
        if b <= 0x8F:
            n = b & 0x0F
        else:
            n, pos = _uint(buf, pos, 2 if b == 0xDE else 4)
        out = {}
        for _ in range(n):
            k, pos = decode_raw(buf, pos)
            v, pos = decode_raw(buf, pos)
            out[k] = v
        return out, pos
    raise MsgpackError("unsupported type byte 0x{:02x} at {}".format(b, pos - 1))


def block_span(resp):
    """(start, end) of the `block` value inside a /v2/blocks msgpack response."""
    b = resp[0]
    pos = 1
    if 0x80 <= b <= 0x8F:
        n = b & 0x0F
    elif b in (0xDE, 0xDF):
        n, pos = _uint(resp, pos, 2 if b == 0xDE else 4)
    else:
        raise MsgpackError("block response is not a map")
    for _ in range(n):
        k, pos = decode_raw(resp, pos)
        start = pos
        _, pos = decode_raw(resp, pos)
        if k == b"block":
            return start, pos
    raise MsgpackError("block response has no `block` key")


def header_fields(resp):
    """Upgrade-related header fields of one /v2/blocks?format=msgpack body."""
    start, end = block_span(resp)
    block, _ = decode_raw(resp, start)
    return {
        "rnd": block.get(b"rnd", 0),
        "upgradeprop": block.get(b"upgradeprop", b""),
        "upgradeyes": bool(block.get(b"upgradeyes", False)),
        "nextproto": block.get(b"nextproto", b""),
        "nextbefore": block.get(b"nextbefore", 0),
        "nextswitch": block.get(b"nextswitch", 0),
        "nextyes": block.get(b"nextyes", 0),
        "proposer": block.get(b"prp", b""),
        "block_hex": resp[start:end].hex(),
    }


# ── evaluation (pure) ──────────────────────────────────────────────────


def address_to_pk(addr):
    """Algorand base32 address -> 32-byte public key (checksum not verified)."""
    pad = "=" * (-len(addr) % 8)
    return base64.b32decode(addr + pad)[:32]


def evaluate(obs, inject, vote_rounds, margin, rust_pk=b"", reference=REFERENCE):
    """Evaluate collected observations.

    obs: {node: {round(int): {"hash": str, **header_fields} | None}}
    Returns (checks, facts): checks = [(name, pass|fail|info, detail)]."""
    checks = []
    facts = {}
    ref = obs.get(reference, {})
    proposal_rounds = sorted(r for r, o in ref.items() if o and o["upgradeprop"] == inject)
    if not proposal_rounds:
        checks.append(("proposal-found", "fail",
                       "{} has no block whose upgradeprop is {}".format(reference, inject.hex())))
        return checks, facts
    p = proposal_rounds[0]
    deadline = p + vote_rounds
    end = deadline + margin
    facts.update(proposal_round=p, vote_deadline=deadline, last_round_checked=end)
    checks.append(("proposal-found", "pass",
                   "round {} proposes upgradeprop {} (non-UTF-8: {})".format(
                       p, inject.hex(), not _is_utf8(inject))))

    rounds = range(max(1, p - 2), end + 1)
    missing = ["{}@{}".format(n, r) for n in sorted(obs) for r in rounds if not obs[n].get(r)]
    if missing:
        stalled = {}
        for n in sorted(obs):
            have = [r for r in rounds if obs[n].get(r)]
            stalled[n] = max(have) if have else None
        checks.append(("all-nodes-all-rounds", "fail",
                       "{} missing (node tips inside the window: {})".format(
                           len(missing), ", ".join("{}={}".format(k, v) for k, v in stalled.items()))))
    else:
        checks.append(("all-nodes-all-rounds", "pass",
                       "every node has rounds {}..{}".format(rounds.start, end)))

    forks = []
    for r in rounds:
        got = {n: obs[n][r] for n in obs if obs[n].get(r)}
        if len({o["hash"] for o in got.values()}) > 1 or len({o["block_hex"] for o in got.values()}) > 1:
            forks.append(r)
    if forks:
        checks.append(("identical-blocks", "fail", "hash/raw-block mismatch at rounds {}".format(forks)))
    else:
        checks.append(("identical-blocks", "pass",
                       "block hash and raw block msgpack equal on every node that has the round"))

    bad = []
    for n in sorted(obs):
        for r in rounds:
            o = obs[n].get(r)
            if not o:
                continue
            want_prop = inject if r == p else b""
            in_window = p <= r < deadline
            want_next = inject if in_window else b""
            want_before = deadline if in_window else 0
            if o["upgradeprop"] != want_prop:
                bad.append("{}@{} upgradeprop={}".format(n, r, o["upgradeprop"].hex()))
            if o["nextproto"] != want_next or o["nextbefore"] != want_before:
                bad.append("{}@{} nextproto={} nextbefore={}".format(
                    n, r, o["nextproto"].hex(), o["nextbefore"]))
    if bad:
        checks.append(("upgrade-state-bytes", "fail", "; ".join(bad[:10])))
    else:
        checks.append(("upgrade-state-bytes", "pass",
                       "upgradeprop only at {}, nextproto byte-exact on {}..{} with nextbefore={}, "
                       "cleared from {} on".format(p, p, deadline - 1, deadline, deadline)))

    if rust_pk:
        rust_rounds = [r for r in range(p, deadline + 1) if ref.get(r) and ref[r]["proposer"] == rust_pk]
        facts["rust_proposed_in_window"] = rust_rounds
        checks.append(("rust-proposed-in-window", "info",
                       "rust-node-4 proposed rounds {} of {}..{} (accepted by go)".format(
                           rust_rounds, p, deadline)))
    facts["hashes"] = {r: (ref[r]["hash"] if ref.get(r) else None) for r in rounds}
    return checks, facts


def _is_utf8(b):
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


# ── live collection ────────────────────────────────────────────────────


def http_get(port, path, timeout=10):
    req = urllib.request.Request("http://127.0.0.1:{}{}".format(port, path),
                                 headers={"X-Algo-API-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def node_round(port):
    try:
        return int(json.loads(http_get(port, "/v2/status"))["last-round"])
    except Exception:
        return None


def fetch(port, rnd):
    try:
        f = header_fields(http_get(port, "/v2/blocks/{}?format=msgpack".format(rnd)))
        f["hash"] = json.loads(http_get(port, "/v2/blocks/{}/hash".format(rnd)))["blockHash"]
        return f
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        return None


def find_proposal(port, inject, lo, hi):
    for r in range(lo, hi + 1):
        o = fetch(port, r)
        if o and o["upgradeprop"] == inject:
            return r
    return None


def run(args):
    table = dict(ports.table(NODE_NAMES))
    inject = bytes.fromhex(args.inject_hex)
    ref_port = table[REFERENCE]
    log = lambda m: print("    " + m, flush=True)  # noqa: E731

    # 1. wait for the proposal round on the reference node
    deadline_wall = time.time() + args.timeout
    p, scanned = None, 0
    while time.time() < deadline_wall and p is None:
        tip = node_round(ref_port) or 0
        if tip > scanned:
            p = find_proposal(ref_port, inject, scanned + 1, tip)
            scanned = tip
        if p is None:
            if scanned > args.inject_until + 2:
                break
            time.sleep(2)
    if p is None:
        log("no proposal with upgradeprop {} through round {}".format(inject.hex(), scanned))
    else:
        log("proposal round {} (vote deadline {})".format(p, p + args.vote_rounds))

    # 2. wait for the Go quorum to pass the deadline + margin, then give every
    #    node a grace period to catch up to it
    end = (p or scanned) + args.vote_rounds + args.margin
    while time.time() < deadline_wall:
        tip = node_round(ref_port) or 0
        if tip >= end:
            break
        time.sleep(2)
    grace = time.time() + args.grace
    while time.time() < grace:
        tips = [node_round(table[n]) for n in NODE_NAMES]
        if all(t is not None and t >= end for t in tips):
            break
        time.sleep(2)
    tips = {n: node_round(table[n]) for n in NODE_NAMES}
    log("node tips: {}".format(tips))

    # 3. collect and evaluate
    lo = max(1, (p or 1) - 2)
    obs = {n: {r: fetch(table[n], r) for r in range(lo, end + 1)} for n in NODE_NAMES}
    rust_pk = address_to_pk(args.rust_address) if args.rust_address else b""
    checks, facts = evaluate(obs, inject, args.vote_rounds, args.margin, rust_pk)
    facts["tips"] = tips
    return obs, checks, facts


def _obs_to_json(obs):
    out = {}
    for n, rounds in obs.items():
        out[n] = {}
        for r, o in rounds.items():
            if o is None:
                out[n][str(r)] = None
                continue
            j = dict(o)
            for k in ("upgradeprop", "nextproto", "proposer"):
                j[k] = o[k].hex()
            out[n][str(r)] = j
    return out


def _obs_from_json(j):
    out = {}
    for n, rounds in j.items():
        out[n] = {}
        for r, o in rounds.items():
            if o is not None:
                o = dict(o)
                for k in ("upgradeprop", "nextproto", "proposer"):
                    o[k] = bytes.fromhex(o[k])
            out[n][int(r)] = o
    return out


def emit(checks, facts, out_path, obs):
    failed = [c for c in checks if c[1] == "fail"]
    for name, status, detail in checks:
        print("    [{}] {}: {}".format(status.upper(), name, detail), flush=True)
    summary = {
        "issue": 2400,
        "checks": [dict(name=n, status=s, detail=d) for n, s, d in checks],
        "facts": facts,
        "failed": len(failed),
        "observations": _obs_to_json(obs),
    }
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    return 1 if failed else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--inject-hex", required=True)
    r.add_argument("--inject-until", type=int, required=True)
    r.add_argument("--vote-rounds", type=int, required=True)
    r.add_argument("--margin", type=int, default=10)
    r.add_argument("--timeout", type=int, default=600, help="wall-clock cap, seconds")
    r.add_argument("--grace", type=int, default=90, help="seconds for every node to catch up")
    r.add_argument("--rust-address", default="")
    r.add_argument("--out", required=True)
    e = sub.add_parser("evaluate")
    e.add_argument("--summary", required=True, help="a previous run's summary JSON")
    e.add_argument("--inject-hex", required=True)
    e.add_argument("--vote-rounds", type=int, required=True)
    e.add_argument("--margin", type=int, default=10)
    args = ap.parse_args(argv)
    if args.cmd == "run":
        obs, checks, facts = run(args)
        return emit(checks, facts, args.out, obs)
    with open(args.summary) as f:
        obs = _obs_from_json(json.load(f)["observations"])
    checks, facts = evaluate(obs, bytes.fromhex(args.inject_hex), args.vote_rounds, args.margin)
    for name, status, detail in checks:
        print("[{}] {}: {}".format(status.upper(), name, detail))
    return 1 if any(c[1] == "fail" for c in checks) else 0


if __name__ == "__main__":
    sys.exit(main())
