#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Build the `testnet-head` replay corpus from a public archival testnet
endpoint (issue #2119, epic #2101).

The DevMode corpora (issue #2104) hold degenerate certificates, so the
`replay` tier never exercises certificate authentication. This corpus holds
the first N rounds of the real testnet: every block carries its real
certificate (the votes of the committee), and both harnesses take their
non-DevMode branch (`devmode: false` in corpus.json), authenticating every
certificate (go `cert.Authenticate`, algod-rust
`Certificate::authenticate`).

Layout: the same corpus directory as `generate.py` writes (blocks.bin in the
`ACRPBLK1` record layout, genesis.json, node-config.json, corpus.json,
MANIFEST.sha256). There is no consensus.json: testnet runs the standard
consensus parameters of both implementations.

Where each piece comes from:

  blocks.bin     GET /v2/blocks/{r}?format=msgpack for r in 0..N, the response
                 body verbatim (a msgpack map {"block", "cert"}), the record
                 payload;
  genesis.json   GET /genesis, verbatim; its hash must equal the endpoint's
                 genesis-hash (GET /v2/transactions/params);
  corpus.json    final_state: round, block_hash and txn_counter are attested
                 by the endpoint for round N (GET /v2/blocks/N/hash and
                 GET /v2/blocks/N?header-only=true). total_money,
                 online_money, accounts, accounts_microalgos and
                 accounts_sha256 describe the balances at round N, which no
                 algod endpoint serves for a past round; they are the state
                 go-algorand's own ledger reaches replaying this very stream,
                 committed in the --final-state file (see `finalize`) and
                 cross-checked here against the attested fields.

Cost (N = 20,000): about 20,000 requests and several hundred MB on disk; the
result is cached outside git (benchmarks/corpus/testnet-head, git-ignored)
and pinned by benchmarks/corpus/testnet-head.ref.

Usage:
  fetch_testnet.py fetch    [--ref FILE] [--endpoint URL] [--rounds N]
                            [--final-state FILE] [--dest DIR] [--force]
                            [--name NAME] [--workers K] [--retries K]
  fetch_testnet.py finalize --corpus DIR --replay-result FILE --out FILE
      derive the committed final-state file from a go replay result
      (benchmarks/go-replay `-out` JSON) after checking its round, block
      hash and txn counter against corpus.json's attested ones.

Exit codes: 0 ok, 1 verification/usage error, 3 endpoint not reachable.
"""
import argparse
import concurrent.futures
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)
import corpus_tool  # noqa: E402

MAGIC = b"ACRPBLK1"
DEFAULT_REF = os.path.join(REPO, "benchmarks", "corpus", "testnet-head.ref")
DEFAULT_DEST = os.path.join(REPO, "benchmarks", "corpus", "testnet-head")
STATE_KEYS = ("total_money", "online_money", "accounts", "accounts_microalgos",
              "accounts_sha256")
# A record's length field is 32 bits (corpus.rs / record.go).
MAX_PAYLOAD = 1 << 32
# What a replay needs of the node: archival (the harness reads every block
# back) and certificate verification on (the default; stated so that the
# corpus never silently depends on a changed default).
NODE_CONFIG = {
    "Version": 38,
    "Archival": True,
    "GossipFanout": 0,
    "IncomingConnectionsLimit": 0,
    "DNSBootstrapID": "",
    "EnableDeveloperAPI": True,
    "EnableExperimentalAPI": True,
}


class FetchError(Exception):
    pass


class Unreachable(FetchError):
    pass


def read_ref(path):
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


class Endpoint:
    """A minimal algod REST client (standard library only)."""

    def __init__(self, base, retries=6, timeout=60):
        self.base = base.rstrip("/")
        self.retries = retries
        self.timeout = timeout

    def get(self, path):
        url = self.base + path
        last = None
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(url, timeout=self.timeout) as r:
                    return r.read()
            except urllib.error.HTTPError as e:
                # 4xx other than throttling is final: the endpoint does not
                # serve this (an unarchived round, say).
                if e.code not in (429, 500, 502, 503, 504):
                    raise FetchError(f"GET {url}: HTTP {e.code}")
                last = f"HTTP {e.code}"
            except (urllib.error.URLError, OSError) as e:
                last = str(e)
            time.sleep(min(0.5 * 2 ** attempt, 15))
        raise Unreachable(f"GET {url}: {last}")

    def json(self, path):
        return json.loads(self.get(path))

    def block(self, rnd):
        return self.get(f"/v2/blocks/{rnd}?format=msgpack")


def record(rnd, payload):
    if len(payload) >= MAX_PAYLOAD:
        raise FetchError(f"round {rnd}: payload too large")
    return struct.pack(">QI", rnd, len(payload)) + payload


def attested(ep, rounds):
    """What the endpoint says about the last block: hash and txn counter."""
    bh = ep.json(f"/v2/blocks/{rounds}/hash")["blockHash"]
    hdr = ep.json(f"/v2/blocks/{rounds}?header-only=true")["block"]
    if hdr.get("rnd") != rounds:
        raise FetchError(f"header-only block is round {hdr.get('rnd')}, want {rounds}")
    return {"round": rounds,
            "block_hash": bh if bh.startswith("blk-") else "blk-" + bh,
            "txn_counter": int(hdr.get("tc", 0))}


def write_blocks(ep, rounds, path, workers):
    """Fetch rounds 0..rounds in order into `path`, `workers` at a time."""
    with open(path, "wb") as f:
        f.write(MAGIC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            window = max(workers * 4, 8)
            pending = {}
            nxt = 0
            for r in range(rounds + 1):
                while nxt <= rounds and nxt < r + window:
                    pending[nxt] = pool.submit(ep.block, nxt)
                    nxt += 1
                f.write(record(r, pending.pop(r).result()))
                if r and r % 2000 == 0:
                    print(f"fetch_testnet: round {r}/{rounds}", flush=True)


def build_corpus(ep, rounds, dest, name, final_state, workers=16):
    """Write the corpus directory `dest` (which must not exist)."""
    os.makedirs(dest)
    try:
        gen_raw = ep.get("/genesis")
        params = ep.json("/v2/transactions/params")
        with open(os.path.join(dest, "genesis.json"), "wb") as f:
            f.write(gen_raw.replace(b"\r\n", b"\n"))
        with open(os.path.join(dest, "node-config.json"), "w", encoding="utf-8",
                  newline="\n") as f:
            json.dump(NODE_CONFIG, f, indent="\t")
        write_blocks(ep, rounds, os.path.join(dest, "blocks.bin"), workers)
        att = attested(ep, rounds)
        fs = dict(att)
        if final_state is not None:
            for k in ("round", "block_hash", "txn_counter"):
                if final_state.get(k) != att[k]:
                    raise FetchError(
                        f"final-state file says {k} {final_state.get(k)!r} at round "
                        f"{rounds}, the endpoint attests {att[k]!r}")
            fs.update({k: final_state[k] for k in STATE_KEYS})
        cj = {
            "schema": corpus_tool.SCHEMA,
            "name": name,
            "source": {
                "kind": "testnet-prefix",
                "note": "rounds 0..N of the public testnet, blocks and certificates "
                        "verbatim from an archival algod (GET /v2/blocks/{r}?format=msgpack)",
            },
            "network": {
                "genesis_id": params["genesis-id"],
                "genesis_hash": params["genesis-hash"],
                "devmode": False,
            },
            "files": {"blocks": "blocks.bin", "genesis": "genesis.json",
                      "node_config": "node-config.json"},
            "rounds": {"first": 0, "last": rounds, "count": rounds + 1},
            "final_state": fs,
        }
        with open(os.path.join(dest, "corpus.json"), "w", encoding="utf-8",
                  newline="\n") as f:
            json.dump(cj, f, indent=2)
            f.write("\n")
        corpus_tool.write_manifest(dest)
    except BaseException:
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest


def cmd_fetch(args):
    ref = read_ref(args.ref) if os.path.isfile(args.ref) else {}
    endpoint = args.endpoint or os.environ.get("TESTNET_ENDPOINT") or ref.get("endpoint")
    rounds = args.rounds if args.rounds is not None else int(ref.get("rounds", 0))
    pin = ref.get("manifest_sha256") if args.rounds is None else None
    if pin is not None and (len(pin) != 64 or not set(pin) <= corpus_tool.HEX_DIGITS):
        pin = None  # not pinned yet (the ref of a range being established)
    # An explicit empty --final-state fetches without one (the first fetch of a
    # range, whose state `finalize` derives).
    fs_path = args.final_state if args.final_state is not None else ref.get("final_state")
    if not fs_path:
        pin = None  # a provisional corpus (no final state yet) has no pin either
    if not endpoint:
        raise FetchError(f"no endpoint (set endpoint= in {args.ref}, TESTNET_ENDPOINT or --endpoint)")
    if rounds < 1:
        raise FetchError("no round count (set rounds= in the ref or pass --rounds)")
    final_state = None
    if fs_path:
        p = fs_path if os.path.isabs(fs_path) else os.path.join(REPO, fs_path)
        with open(p, encoding="utf-8") as f:
            final_state = json.load(f)
        if final_state.get("round") != rounds:
            raise FetchError(f"{p} is for round {final_state.get('round')}, not {rounds}")
    if os.path.exists(args.dest):
        if not args.force:
            raise FetchError(f"{args.dest} already exists (pass --force to replace it)")
        import shutil
        shutil.rmtree(args.dest)
    tmp = args.dest + ".partial"
    if os.path.exists(tmp):
        import shutil
        shutil.rmtree(tmp)
    print(f"fetch_testnet: {endpoint}: rounds 0..{rounds} -> {args.dest}", flush=True)
    build_corpus(Endpoint(endpoint, retries=args.retries), rounds, tmp, args.name, final_state,
                 args.workers)
    got = corpus_tool.sha256_file(os.path.join(tmp, corpus_tool.MANIFEST))
    if pin and got != pin:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        raise FetchError(f"MANIFEST.sha256 has sha256 {got}, {args.ref} pins {pin} "
                         "(the endpoint served different bytes)")
    os.replace(tmp, args.dest)
    print(f"fetch_testnet: installed {args.dest} (MANIFEST.sha256 {got}"
          f"{' matches the pin' if pin else ''})")
    return 0


def cmd_finalize(args):
    cj = corpus_tool.load_corpus_json(args.corpus)
    with open(args.replay_result, encoding="utf-8") as f:
        res = json.load(f)
    st = res["final_state"]
    want = cj["final_state"]
    for k in ("round", "block_hash", "txn_counter"):
        if st[k] != want[k]:
            raise FetchError(f"replay {k} {st[k]!r} != the endpoint-attested {want[k]!r}")
    out = {k: st[k] for k in ("round", "block_hash", "txn_counter")}
    out.update(total_money=st["total_money"], online_money=st["online_money"],
               accounts=st["known_accounts"]["count"],
               accounts_microalgos=st["known_accounts"]["microalgos"],
               accounts_sha256=st["known_accounts"]["sha256"])
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print(f"fetch_testnet: wrote {args.out}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--ref", default=DEFAULT_REF)
    f.add_argument("--endpoint")
    f.add_argument("--rounds", type=int)
    f.add_argument("--final-state")
    f.add_argument("--dest", default=DEFAULT_DEST)
    f.add_argument("--name", default="testnet-head")
    f.add_argument("--workers", type=int, default=16)
    f.add_argument("--retries", type=int, default=6)
    f.add_argument("--force", action="store_true")
    z = sub.add_parser("finalize")
    z.add_argument("--corpus", required=True)
    z.add_argument("--replay-result", required=True)
    z.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        return cmd_fetch(args) if args.cmd == "fetch" else cmd_finalize(args)
    except Unreachable as e:
        print(f"fetch_testnet: endpoint not reachable: {e}", file=sys.stderr)
        return 3
    except (FetchError, OSError, KeyError, ValueError) as e:
        print(f"fetch_testnet: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
