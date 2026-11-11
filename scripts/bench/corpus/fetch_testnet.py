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
  genesis.json   GET /genesis, byte for byte as served; its hash (go's
                 Genesis.Hash, computed here) must equal the endpoint's
                 genesis-hash (GET /v2/transactions/params), else nothing is
                 installed;
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
                            (--rounds overrides the ref's range: its final
                            state and pin then apply only if given explicitly)
                            [--final-state FILE] [--dest DIR] [--force]
                            [--name NAME] [--workers K] [--retries K]
  fetch_testnet.py plan-catchpoint [--label LABEL] [--rounds N] [--out FILE]
                            [--endpoint URL] [--channel-url URL]
      the catchpoint-start corpus plan (issue #2146): resolve the catchpoint
      the replay starts from (the channel's latest, or --label), check that
      the endpoint serves the N rounds after it with certificates, and write
      the ref (`catchpoint=`, `rounds=`, `endpoint=`, `genesis_hash=`).
      See docs/BENCH_CATCHPOINT_REPLAY.md.
  fetch_testnet.py fetch-catchpoint [--ref FILE] [--dest DIR] [--rounds N]
                            [--final-state FILE] [--catchpoint-file FILE]
                            [--allow-uncovered] [--force]
      build the catchpoint-start corpus the ref (plan-catchpoint) describes
      (issue #2293): blocks.bin of the lookback before the catchpoint round and
      the rounds after it, the catchpoint file (from `catchpoint_source=`, a
      relay, or --catchpoint-file), a corpus.json with `rounds.first` and
      `start`. Refuses a range without proposer payouts, state proofs and app
      calls. Without a final state the corpus is provisional: replay it with
      go, then `finalize`, commit the final-state file and set `final_state=`
      in the ref.
  fetch_testnet.py finalize --corpus DIR --replay-result FILE --out FILE
      derive the committed final-state file from a go replay result
      (benchmarks/go-replay `-out` JSON) after checking its round, block
      hash and txn counter against corpus.json's attested ones.

Exit codes: 0 ok, 1 verification/usage error, 3 endpoint not reachable.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
import struct
import sys
import time
import shutil
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


# Where algorand publishes the label of each network's latest catchpoint, and
# the rounds between two catchpoints on the public testnet (go
# `config.Local.CatchpointInterval` of a catchpoint-serving node).
CATCHPOINT_CHANNEL = ("https://algorand-catchpoints.s3.us-east-2.amazonaws.com"
                      "/channel/testnet/latest.catchpoint")
CATCHPOINT_INTERVAL = 10000
DEFAULT_CATCHPOINT_REF = os.path.join(REPO, "benchmarks", "corpus", "testnet-catchpoint.ref")
DEFAULT_CATCHPOINT_DEST = os.path.join(REPO, "benchmarks", "corpus", "testnet-catchpoint")
BASE32 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


class FetchError(Exception):
    pass


class Unreachable(FetchError):
    pass


def parse_catchpoint_label(label, interval=CATCHPOINT_INTERVAL):
    """(round, hash) of a catchpoint label `<round>#<52 base32 chars>` (go
    `ledgercore.ParseCatchpointLabel`: a positive round on a catchpoint
    boundary and the base32 of a 32-byte digest); FetchError otherwise."""
    label = label.strip()
    rnd, sep, digest = label.partition("#")
    if not sep or not rnd.isdigit() or int(rnd) == 0:
        raise FetchError(f"not a catchpoint label: {label!r} (want <round>#<hash>)")
    if len(digest) != 52 or not set(digest) <= BASE32:
        raise FetchError(f"catchpoint label {label!r}: the hash is not 52 base32 characters")
    if interval and int(rnd) % interval:
        raise FetchError(f"catchpoint label {label!r}: round {rnd} is not a multiple of "
                         f"{interval}")
    return int(rnd), digest


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
            except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
                # a connection that drops mid-body (IncompleteRead), a reset,
                # a timeout: all retried with the same backoff
                last = f"{type(e).__name__}: {e}"
            if attempt + 1 < self.retries:
                time.sleep(min(0.5 * 2 ** attempt, 15))
        raise Unreachable(f"GET {url}: {last}")

    def json(self, path):
        return json.loads(self.get(path))

    def block(self, rnd):
        """The block response for `rnd`, checked to be a block response for
        that round: a 200 with an HTML error page, an empty body or another
        round's block must never be stored as the corpus."""
        body = self.get(f"/v2/blocks/{rnd}?format=msgpack")
        try:
            got = corpus_tool.block_round(body)
        except ValueError as e:
            raise FetchError(f"round {rnd}: the endpoint's reply is not a block "
                             f"response ({e}; {len(body)} bytes)")
        if got != rnd:
            raise FetchError(f"asked for round {rnd}, the endpoint served block {got}")
        return body


def _mp_str(s):
    b = s.encode("utf-8")
    if len(b) < 32:
        return bytes([0xa0 | len(b)]) + b
    if len(b) < 256:
        return b"\xd9" + bytes([len(b)]) + b
    return b"\xda" + len(b).to_bytes(2, "big") + b


def _mp_bin(b):
    if len(b) < 256:
        return b"\xc4" + bytes([len(b)]) + b
    return b"\xc5" + len(b).to_bytes(2, "big") + b


def _mp_uint(v):
    if v < 0:
        raise FetchError("negative integer in a genesis")
    if v < 128:
        return bytes([v])
    for tag, w in ((0xcc, 1), (0xcd, 2), (0xce, 4), (0xcf, 8)):
        if v < 1 << (8 * w):
            return bytes([tag]) + v.to_bytes(w, "big")
    raise FetchError("integer too large")


def _mp_len(n, fix, tag16, tag32):
    if n < 16:
        return bytes([fix | n])
    if n < 1 << 16:
        return bytes([tag16]) + n.to_bytes(2, "big")
    return bytes([tag32]) + n.to_bytes(4, "big")


def _mp_map(fields):
    """A canonical msgpack map: keys sorted by their bytes."""
    items = sorted(fields.items(), key=lambda kv: kv[0].encode())
    return _mp_len(len(items), 0x80, 0xde, 0xdf) + b"".join(
        _mp_str(k) + v for k, v in items)


def _b64_nonzero(s):
    """The bytes of an optional base64 field, None when absent, empty or all
    zero (go's omitempty on a fixed-size byte array)."""
    if not s:
        return None
    b = base64.b64decode(s)
    return b if any(b) else None


def _alloc_state(st):
    f = {}
    if st.get("algo"):
        f["algo"] = _mp_uint(st["algo"])
    if st.get("onl"):
        f["onl"] = _mp_uint(st["onl"])
    for k in ("sel", "stprf", "vote"):
        b = _b64_nonzero(st.get(k))
        if b is not None:
            f[k] = _mp_bin(b)
    for k in ("voteFst", "voteKD", "voteLst"):
        if st.get(k):
            f[k] = _mp_uint(st[k])
    return _mp_map(f)


def genesis_hash_b64(raw):
    """go's `Genesis.Hash()` of a genesis.json, base64: SHA512/256("GE" ||
    canonical msgpack of the genesis). A port of
    crates/core/algo-ledger/src/genesis.rs `canonical_encode_genesis` (same
    omitempty rules: an allocation always carries addr, comment and state)."""
    g = json.loads(raw)
    f = {}
    alloc = g.get("alloc") or []
    if alloc:
        f["alloc"] = _mp_len(len(alloc), 0x90, 0xdc, 0xdd) + b"".join(
            _mp_map({"addr": _mp_str(a["addr"]), "comment": _mp_str(a.get("comment") or ""),
                     "state": _alloc_state(a.get("state") or {})}) for a in alloc)
    if g.get("comment"):
        f["comment"] = _mp_str(g["comment"])
    if g.get("devmode"):
        f["devmode"] = b"\xc3"
    for k in ("fees", "id", "network", "proto", "rwd"):
        if g.get(k):
            f[k] = _mp_str(g[k])
    if g.get("timestamp"):
        f["timestamp"] = _mp_uint(g["timestamp"])
    try:
        h = hashlib.new("sha512_256", b"GE" + _mp_map(f))
    except ValueError:
        raise FetchError("this Python's hashlib has no sha512_256")
    return base64.b64encode(h.digest()).decode()


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


def build_corpus(ep, rounds, dest, name, final_state, workers=16, expected_genesis_hash=None):
    """Write the corpus directory `dest` (which must not exist)."""
    os.makedirs(dest)
    try:
        gen_raw = ep.get("/genesis")
        params = ep.json("/v2/transactions/params")
        got = genesis_hash_b64(gen_raw)
        if got != params["genesis-hash"]:
            raise FetchError(f"the endpoint's /genesis hashes to {got}, but it reports "
                             f"genesis-hash {params['genesis-hash']}")
        if expected_genesis_hash and got != expected_genesis_hash:
            raise FetchError(f"wrong network: the endpoint's genesis hashes to {got} "
                             f"({params.get('genesis-id')}), the ref pins {expected_genesis_hash}")
        # Verbatim: benchmarks/corpus/** is `-text` (.gitattributes), so no
        # checkout rewrites it, and the hash above is of the parsed JSON.
        with open(os.path.join(dest, "genesis.json"), "wb") as f:
            f.write(gen_raw)
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
    # The ref describes one range. `--rounds` selects another, so the ref's
    # final state and manifest pin (of its range) do not apply to it.
    overridden = args.rounds is not None
    pin = None if overridden else ref.get("manifest_sha256")
    if pin is not None and (len(pin) != 64 or not set(pin) <= corpus_tool.HEX_DIGITS):
        pin = None  # not pinned yet (the ref of a range being established)
    # An explicit empty --final-state fetches without one (the first fetch of a
    # range, whose state `finalize` derives).
    fs_path = args.final_state
    if fs_path is None and not overridden:
        fs_path = ref.get("final_state")
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
    import shutil
    if os.path.exists(args.dest) and not args.force:
        raise FetchError(f"{args.dest} already exists (pass --force to replace it)")
    tmp = args.dest + ".partial"
    if os.path.exists(tmp):
        import shutil
        shutil.rmtree(tmp)
    print(f"fetch_testnet: {endpoint}: rounds 0..{rounds} -> {args.dest}", flush=True)
    build_corpus(Endpoint(endpoint, retries=args.retries), rounds, tmp, args.name, final_state,
                 args.workers, expected_genesis_hash=ref.get("genesis_hash"))
    got = corpus_tool.sha256_file(os.path.join(tmp, corpus_tool.MANIFEST))
    if pin and got != pin:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
        raise FetchError(f"MANIFEST.sha256 has sha256 {got}, {args.ref} pins {pin} "
                         "(the endpoint served different bytes)")
    # Only now, with the new corpus complete and verified, does the old one go
    # (a failed fetch above leaves it untouched): move it aside, install, drop it.
    old = args.dest + ".old"
    had_old = os.path.exists(args.dest)
    if had_old:
        shutil.rmtree(old, ignore_errors=True)
        os.replace(args.dest, old)
    try:
        os.replace(tmp, args.dest)
    except BaseException:
        if had_old:
            os.replace(old, args.dest)
        raise
    if had_old:
        shutil.rmtree(old, ignore_errors=True)
    print(f"fetch_testnet: installed {args.dest} (MANIFEST.sha256 {got}"
          f"{' matches the pin' if pin else ''})")
    return 0


def cmd_plan_catchpoint(args):
    ref = read_ref(args.ref) if os.path.isfile(args.ref) else {}
    endpoint = args.endpoint or os.environ.get("TESTNET_ENDPOINT") or ref.get("endpoint")
    if not endpoint:
        raise FetchError(f"no endpoint (set endpoint= in {args.ref}, TESTNET_ENDPOINT or --endpoint)")
    rounds = args.rounds if args.rounds is not None else int(ref.get("rounds", 200))
    if rounds < 1:
        raise FetchError("--rounds must be at least 1")
    label = args.label
    if not label:
        label = Endpoint(args.channel_url, retries=3).get("").decode("ascii", "replace")
    rnd, digest = parse_catchpoint_label(label)
    label = f"{rnd}#{digest}"
    ep = Endpoint(endpoint, retries=args.retries)
    genesis_hash = ref.get("genesis_hash")
    if genesis_hash:
        got = ep.json("/v2/transactions/params")["genesis-hash"]
        if got != genesis_hash:
            raise FetchError(f"{endpoint} serves genesis {got}, {args.ref} pins {genesis_hash}")
    # The replay reads every block of the range back from an archival node, so
    # the first and the last must be served, with their certificates (block()
    # refuses a reply that is not a block response of that round).
    for r in (rnd + 1, rnd + rounds):
        ep.block(r)
    lines = [
        "# The catchpoint-start replay corpus plan (issue #2146): written by",
        "# scripts/bench/corpus/fetch_testnet.py plan-catchpoint, see",
        "# docs/BENCH_CATCHPOINT_REPLAY.md.",
        f"endpoint={endpoint}",
    ]
    if genesis_hash:
        lines.append(f"genesis_hash={genesis_hash}")
    lines += [f"catchpoint={label}", f"catchpoint_round={rnd}", f"rounds={rounds}"]
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    print(f"fetch_testnet: catchpoint {label}: replay rounds {rnd + 1}..{rnd + rounds} "
          f"(served, with certificates) -> {args.out}")
    return 0


# ---- catchpoint-start corpus (issue #2293) ---------------------------------

# The consensus parameters the catchup lookback depends on (go
# catchup/catchpointService.go processStageBlocksDownload), identical on every
# protocol since the state proofs of v34.
MAX_TXN_LIFE = 1000
DEEPER_BLOCK_HEADER_HISTORY = 1
CATCHPOINT_LOOKBACK = 320
MAX_BAL_LOOKBACK = 320
STATE_PROOF_INTERVAL = 256
STATE_PROOF_VOTERS_LOOKBACK = 16
STATE_PROOF_MAX_RECOVERY_INTERVALS = 10


def catchpoint_lookback(round_, next_state_proof_round):
    """How many blocks before the catchpoint round the replay needs: go's
    lookback (MaxTxnLife + DeeperBlockHeaderHistory + CatchpointLookback, at
    least MaxBalLookback, at least what a pending state proof needs), trimmed
    to round - 1. algod-rust's own lookback (MaxTxnLife, or the state-proof
    one) is never larger."""
    sp = 0  # no state proof tracking (go: StateProofInterval == 0)
    if next_state_proof_round:
        recent = round_ - round_ % STATE_PROOF_INTERVAL
        oldest_recovery = max(0, recent - STATE_PROOF_INTERVAL * STATE_PROOF_MAX_RECOVERY_INTERVALS)
        oldest = (next_state_proof_round if next_state_proof_round > oldest_recovery
                  else oldest_recovery)
        sp = round_ - max(0, max(0, oldest - STATE_PROOF_INTERVAL) - STATE_PROOF_VOTERS_LOOKBACK)
    lookback = max(MAX_TXN_LIFE + DEEPER_BLOCK_HEADER_HISTORY + CATCHPOINT_LOOKBACK,
                   MAX_BAL_LOOKBACK, sp, MAX_TXN_LIFE)
    return min(lookback, round_ - 1)


def block_coverage(payload):
    """(payout, state_proofs, app_calls) of a block response record: whether the
    header names a proposer payout (`prp`), and how many state proof and
    application call transactions the payset holds."""
    top = corpus_tool._mp_map(payload, 0)
    blk = corpus_tool._mp_map(payload, top["block"][0])
    payout = "prp" in blk
    stpf = appl = 0
    if "txns" in blk:
        kind, n, j = corpus_tool._mp_item(payload, blk["txns"][0])
        if kind != "array":
            raise FetchError("block txns is not an array")
        for _ in range(n):
            signed = corpus_tool._mp_map(payload, j)
            txn = corpus_tool._mp_map(payload, signed["txn"][0])
            _, t, _ = corpus_tool._mp_item(payload, txn["type"][0])
            t = t.decode("utf-8", "replace")
            stpf += t == "stpf"
            appl += t == "appl"
            j = corpus_tool._mp_skip(payload, j)
    return payout, stpf, appl


def range_coverage(blocks_path, after_round):
    """What the rounds after `after_round` of blocks.bin exercise."""
    with open(blocks_path, "rb") as f:
        raw = f.read()
    cov = {"proposer_payouts": 0, "state_proofs": 0, "app_calls": 0}
    for rnd, off, n in corpus_tool.parse_records(raw):
        if rnd <= after_round:
            continue
        payout, stpf, appl = block_coverage(raw[off:off + n])
        cov["proposer_payouts"] += payout
        cov["state_proofs"] += stpf
        cov["app_calls"] += appl
    return cov


def coverage_gate(cov):
    """FetchError unless the range exercises what testnet-head cannot."""
    missing = [k for k in ("proposer_payouts", "state_proofs", "app_calls") if not cov[k]]
    if missing:
        raise FetchError("the replayed range has no " + ", no ".join(missing)
                         + f" ({cov}); pick a catchpoint whose following rounds hold them, or "
                           "more rounds (--rounds), or pass --allow-uncovered")


def b36(n):
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = digits[r] + out
    return out or "0"


def download_catchpoint_file(source, genesis_id, round_, label, dest, retries=3):
    """GET {source}/v1/{genesis_id}/ledger/{round in base 36} into `dest`, and
    check that the file's header names `label`. The relays send it chunked, so
    the size is only known at the end."""
    url = f"{source.rstrip('/')}/v1/{genesis_id}/ledger/{b36(round_)}"
    last = None
    for attempt in range(retries):
        tmp = dest + ".partial"
        try:
            with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
                total, mark = 0, time.time()
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
                    total += len(chunk)
                    if time.time() - mark > 30:
                        print(f"fetch_testnet: catchpoint file: {total / 1e6:.0f} MB", flush=True)
                        mark = time.time()
            got = catchpoint_file_label(tmp)
            if got != label:
                os.remove(tmp)
                raise FetchError(f"{url} serves the catchpoint {got!r}, not {label!r}")
            os.replace(tmp, dest)
            print(f"fetch_testnet: catchpoint file {total / 1e6:.0f} MB -> {dest}", flush=True)
            return total
        except FetchError:
            raise
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            last = f"{type(e).__name__}: {e}"
            time.sleep(min(2 ** attempt, 15))
    raise Unreachable(f"GET {url}: {last}")


def catchpoint_file_label(path):
    """The label in the content header (first tar entry) of a catchpoint file."""
    import tarfile
    with tarfile.open(path, "r:*") as tf:
        m = tf.next()
        if m is None or m.name != "content.msgpack":
            raise FetchError(f"{path}: not a catchpoint file (first entry {m and m.name!r})")
        head, _ = corpus_tool.mp_decode(tf.extractfile(m).read(), 0)
    return head.get("catchpoint", "")


def write_blocks_range(ep, first, last, path, workers):
    """Fetch rounds first..last in order into `path`, `workers` at a time."""
    with open(path, "wb") as f:
        f.write(MAGIC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            window = max(workers * 4, 8)
            pending = {}
            nxt = first
            for r in range(first, last + 1):
                while nxt <= last and nxt < r + window:
                    pending[nxt] = pool.submit(ep.block, nxt)
                    nxt += 1
                f.write(record(r, pending.pop(r).result()))
                if (r - first) and (r - first) % 500 == 0:
                    print(f"fetch_testnet: round {r}/{last}", flush=True)


def build_catchpoint_corpus(ep, ref, dest, name, final_state, workers, catchpoint_file=None,
                            allow_uncovered=False):
    """Write the catchpoint-start corpus `dest` (which must not exist)."""
    label = ref["catchpoint"]
    rnd, _ = parse_catchpoint_label(label, interval=0)
    rounds = int(ref["rounds"])
    last = rnd + rounds
    os.makedirs(dest)
    try:
        gen_raw = ep.get("/genesis")
        params = ep.json("/v2/transactions/params")
        got = genesis_hash_b64(gen_raw)
        if got != params["genesis-hash"]:
            raise FetchError(f"the endpoint's /genesis hashes to {got}, but it reports "
                             f"genesis-hash {params['genesis-hash']}")
        if ref.get("genesis_hash") and got != ref["genesis_hash"]:
            raise FetchError(f"wrong network: the endpoint's genesis hashes to {got}, "
                             f"the ref pins {ref['genesis_hash']}")
        with open(os.path.join(dest, "genesis.json"), "wb") as f:
            f.write(gen_raw)
        with open(os.path.join(dest, "node-config.json"), "w", encoding="utf-8",
                  newline="\n") as f:
            json.dump(NODE_CONFIG, f, indent="\t")
        hdr = ep.json(f"/v2/blocks/{rnd}?header-only=true")["block"]
        spt = (hdr.get("spt") or {}).get("0") or {}
        first = rnd - catchpoint_lookback(rnd, int(spt.get("n") or 0))
        print(f"fetch_testnet: lookback {rnd - first} blocks: rounds {first}..{last}", flush=True)
        write_blocks_range(ep, first, last, os.path.join(dest, "blocks.bin"), workers)
        cov = range_coverage(os.path.join(dest, "blocks.bin"), rnd)
        print(f"fetch_testnet: the replayed rounds exercise {cov}", flush=True)
        if not allow_uncovered:
            coverage_gate(cov)
        if catchpoint_file:
            shutil.copyfile(catchpoint_file, os.path.join(dest, "catchpoint.tar"))
            got_label = catchpoint_file_label(os.path.join(dest, "catchpoint.tar"))
            if got_label != label:
                raise FetchError(f"{catchpoint_file} is the catchpoint {got_label!r}, not {label!r}")
        else:
            source = ref.get("catchpoint_source")
            if not source:
                raise FetchError("no catchpoint_source= in the ref (a relay such as "
                                 "http://r-5i.algorand-testnet.network:4161) and no --catchpoint-file")
            download_catchpoint_file(source, params["genesis-id"], rnd, label,
                                     os.path.join(dest, "catchpoint.tar"))
        att = attested(ep, last)
        fs = dict(att)
        if final_state is not None:
            for k in ("round", "block_hash", "txn_counter"):
                if final_state.get(k) != att[k]:
                    raise FetchError(f"final-state file says {k} {final_state.get(k)!r} at round "
                                     f"{last}, the endpoint attests {att[k]!r}")
            fs.update({k: final_state[k] for k in STATE_KEYS})
        cj = {
            "schema": corpus_tool.SCHEMA,
            "name": name,
            "source": {
                "kind": "testnet-catchpoint",
                "note": f"rounds {first}..{last} of the public testnet (blocks and certificates "
                        "verbatim from an archival algod) and the catchpoint of round "
                        f"{rnd} from a relay; the replay starts from the catchpoint",
            },
            "network": {"genesis_id": params["genesis-id"],
                        "genesis_hash": params["genesis-hash"], "devmode": False},
            "files": {"blocks": "blocks.bin", "genesis": "genesis.json",
                      "node_config": "node-config.json", "catchpoint": "catchpoint.tar"},
            "rounds": {"first": first, "last": last, "count": last - first + 1},
            "start": {"catchpoint": label, "file": "catchpoint.tar", "round": rnd,
                      "coverage": cov},
            "final_state": fs,
        }
        with open(os.path.join(dest, "corpus.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(cj, f, indent=2)
            f.write("\n")
        corpus_tool.write_manifest(dest)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest


def cmd_fetch_catchpoint(args):
    ref = read_ref(args.ref) if os.path.isfile(args.ref) else {}
    if args.endpoint:
        ref["endpoint"] = args.endpoint
    if args.rounds is not None:
        ref["rounds"] = str(args.rounds)
    endpoint = os.environ.get("TESTNET_ENDPOINT") or ref.get("endpoint")
    if not endpoint:
        raise FetchError(f"no endpoint (set endpoint= in {args.ref}, TESTNET_ENDPOINT or --endpoint)")
    for k in ("catchpoint", "rounds"):
        if not ref.get(k):
            raise FetchError(f"no {k}= in {args.ref} (run plan-catchpoint)")
    parse_catchpoint_label(ref["catchpoint"], interval=0)
    final_state = None
    fs_path = args.final_state if args.final_state is not None else ref.get("final_state")
    if fs_path:
        p = fs_path if os.path.isabs(fs_path) else os.path.join(REPO, fs_path)
        with open(p, encoding="utf-8") as f:
            final_state = json.load(f)
    if os.path.exists(args.dest) and not args.force:
        raise FetchError(f"{args.dest} already exists (pass --force to replace it)")
    tmp = args.dest + ".partial"
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"fetch_testnet: catchpoint {ref['catchpoint']} + {ref['rounds']} rounds from "
          f"{endpoint} -> {args.dest}", flush=True)
    build_catchpoint_corpus(Endpoint(endpoint, retries=args.retries), ref, tmp, args.name,
                            final_state, args.workers, args.catchpoint_file, args.allow_uncovered)
    old = args.dest + ".old"
    had_old = os.path.exists(args.dest)
    if had_old:
        shutil.rmtree(old, ignore_errors=True)
        os.replace(args.dest, old)
    try:
        os.replace(tmp, args.dest)
    except BaseException:
        if had_old:
            os.replace(old, args.dest)
        raise
    if had_old:
        shutil.rmtree(old, ignore_errors=True)
    print(f"fetch_testnet: installed {args.dest}"
          + ("" if final_state else " (provisional: no final state yet, run `finalize`)"))
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
    fc = sub.add_parser("fetch-catchpoint")
    fc.add_argument("--ref", default=DEFAULT_CATCHPOINT_REF)
    fc.add_argument("--endpoint")
    fc.add_argument("--rounds", type=int)
    fc.add_argument("--final-state")
    fc.add_argument("--dest", default=DEFAULT_CATCHPOINT_DEST)
    fc.add_argument("--name", default="testnet-catchpoint")
    fc.add_argument("--workers", type=int, default=16)
    fc.add_argument("--retries", type=int, default=6)
    fc.add_argument("--catchpoint-file", help="use this catchpoint file instead of downloading it")
    fc.add_argument("--allow-uncovered", action="store_true",
                    help="do not require payouts, state proofs and app calls in the range")
    fc.add_argument("--force", action="store_true")
    c = sub.add_parser("plan-catchpoint")
    c.add_argument("--ref", default=DEFAULT_REF)
    c.add_argument("--label")
    c.add_argument("--rounds", type=int)
    c.add_argument("--out", default=DEFAULT_CATCHPOINT_REF)
    c.add_argument("--endpoint")
    c.add_argument("--channel-url", default=CATCHPOINT_CHANNEL)
    c.add_argument("--retries", type=int, default=6)
    z = sub.add_parser("finalize")
    z.add_argument("--corpus", required=True)
    z.add_argument("--replay-result", required=True)
    z.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        return {"fetch": cmd_fetch, "finalize": cmd_finalize,
                "plan-catchpoint": cmd_plan_catchpoint,
                "fetch-catchpoint": cmd_fetch_catchpoint}[args.cmd](args)
    except Unreachable as e:
        print(f"fetch_testnet: endpoint not reachable: {e}", file=sys.stderr)
        return 3
    except (FetchError, OSError, KeyError, ValueError) as e:
        print(f"fetch_testnet: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
