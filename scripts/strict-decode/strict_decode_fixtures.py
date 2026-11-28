#!/usr/bin/env python3
# Copyright (C) 2019-2026 Algorand Foundation Ltd.
# Modifications Copyright (C) 2026 Algod DAO
# This file is part of algod-rust, a modified work based on go-algorand
# (https://github.com/algorand/go-algorand).
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate the committed strict-unknown-field parity fixtures (issues #2394, #2396).

go-algorand decodes every msgpack message with generated msgp decoders (or
`protocol.CodecHandle`, `ErrorIfNoField = true`): a key the target struct does
not have is `msgp.ErrNoField` and the whole message is dropped. algod-rust's
hand-written readers must accept and reject exactly the same messages. The
oracle is a pair of Go test files (tools/strict-decode-oracle/*.go.txt) copied
into a go-algorand checkout (`agreement` and `rpcs` packages; the gossip
decoders are unexported) and run there, so every expected verdict comes from
go's real decode, never from the Rust code.

    GO_ALGORAND_DIR=/path/to/go-algorand python3 scripts/strict-decode/strict_decode_fixtures.py

writes, under crates/core/algo-agreement/tests/fixtures/strict_decode/:

  seeds.jsonl   {"name","kind","hex"}: valid messages. Real ones are derived
                from the committed block / agreement fixtures and the small
                replay corpus; the `*_rand*` ones are go-encoded, fully
                populated `protocol.RandomizeObject` values (every field of
                every nested struct is set), kept as committed bytes because
                go's randomiser is not reproducible (`--regen-seeds` rewrites
                them).
  cases.jsonl   {"id","seed","kind","map","pos","key","val","sha","go_ok"}: a
                mutation of one seed (insert key/value at position `pos` of the
                `map`-th map, pre-order; map -1 is the unmutated seed), the
                sha256 prefix of the mutant bytes and go's verdict. Replayed by
                the algo-agreement test `strict_unknown_fields_go_parity`.

`--check` regenerates the verdicts in memory and fails when cases.jsonl is
stale. `--fuzz N OUT` writes N more random cases (every map of every seed
eventually) with go's verdicts to OUT for a one-off differential fuzz run:

    STRICT_FUZZ_FILE=OUT cargo test -p algo-agreement --test strict_unknown_fields_go_parity fuzz_file

The go-algorand checkout needs its libsodium built (`make libsodium`).

Fixture sets (`--set`, default: all). `consensus` is the set described above;
the others (issue #2396) cover go's non-consensus msgpack entry points, each
with its own seeds.jsonl / cases.jsonl in the crate whose test replays it:

  consensus  crates/core/algo-agreement/tests/fixtures/strict_decode/
  ledger     crates/core/algo-ledger/tests/fixtures/strict_decode/
             catchpoint file header / balances chunk / SP verification context
             (ledger/catchupaccessor.go), test `strict_unknown_fields_go_parity`
  network    crates/node/algo-network/tests/fixtures/strict_decode/
             identity challenge / response / verification (network/netidentity.go)
             and the tx-sync response (rpcs/httpTxSync.go, protocol.DecodeReflect)
  p2p        crates/node/algo-p2p/tests/fixtures/strict_decode/
             libp2p peer meta headers (network/p2pMetainfo.go)

In the non-consensus sets a transplant only inserts a key the destination map
does not already have. Repeated keys have their own cases (issues #2421,
#2424), after the transplants: a key the map already has, again, with a value
derived from its first one (a map with fewer entries or none, a shorter array
whose elements have fewer entries, a shorter byte string, nil) or another map's
value under the same key. go decodes a repeated key *into* the already decoded
field: a scalar is overwritten, a nested struct and a map are merged, a slice
is re-sliced and decoded element by element into the existing elements when
the old capacity allows it (else it is a fresh slice), a `[N]byte` keeps the
bytes past a shorter value, nil clears. So every accepted case also carries
`go_val`, the sha256 prefix of go's re-encode of the decoded value, and the
ledger / network / p2p replaying tests compare it with algod-rust's decoded
value, re-encoded. Repeated-key cases are generated for a set's
`repeat_kinds`: every kind since issue #2424 (the consensus readers and the
tx-sync reader merge a repeated key like go), and the consensus set's
algo-agreement test compares decoded values too.

Allocation-bound cases (issue #2427) come last: for every msgp `allocbound`
reachable from a consensus message (BOUND_RULES), the field again at exactly
its bound and at bound + 1 elements / bytes, in a set's `bound_kinds`. go
rejects the second with `msgp.ErrOverflow` on the length header; the tx-sync
response (go-codec) checks no allocbound and accepts both.

Struct-from-array cases (issue #2426) come last: go decodes a struct from an
array too (elements are the fields in go's declaration order, embedded structs
flattened, `ErrTooManyArrayFields` on one more, the fields past a shorter array
left alone). A case carries its whole mutant in `hex` (`map` -2): some structs
of a seed turned into arrays, type-directed by the field layout in
crates/core/algo-types/src/go_struct_order.json (dumped from go's types by the
rpcs oracle's `STRICT_SCHEMA_OUT`), for the structs whose algod-rust reader
has the array form (`converted_types`). `--fuzz` writes more of them.

Nil-element cases (issue #2430) come after them: `apaa`, a proof's `pth` and
a LogicSig's `arg` again, as lists mixing `nil`, empty and one-byte elements,
in a set's `nil_kinds`. go keeps a `nil` element nil and re-encodes it as
`nil`, an empty `bin` / `str` as `bin` 0, so `go_val` pins the difference.
"""
import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
ORACLE = os.path.join(ROOT, "tools", "strict-decode-oracle")
# go package -> (oracle template, the oracle test's name suffix)
TEMPLATES = {
    "agreement": ("agreement_oracle_test.go.txt", "Agreement"),
    "rpcs": ("rpcs_oracle_test.go.txt", "Rpcs"),
    "ledger": ("ledger_oracle_test.go.txt", "Ledger"),
    "network": ("network_oracle_test.go.txt", "Network"),
    "cmd/algokey": ("algokey_oracle_test.go.txt", "Algokey"),
}
# kind -> go package whose oracle decodes it
KIND_PKG = {
    **{k: "agreement" for k in ("payload", "vote", "bundle", "cert")},
    **{
        k: "rpcs"
        for k in ("blockcert", "block", "header", "stxn", "stxninblock", "txn", "applydata", "evaldelta", "txsync")
    },
    **{k: "ledger" for k in ("cpheader", "cpchunk", "cpspver")},
    **{k: "network" for k in ("idchal", "idresp", "idverify", "peermeta")},
    "pqkey": "cmd/algokey",
}
DST = "zz_strict_decode_oracle_test.go"


def fixture_dir(*crate):
    return os.path.join(ROOT, "crates", *crate, "tests", "fixtures", "strict_decode")

# ── raw msgpack walking (offsets only: leaves keep their original bytes) ─────


def skip(b, i):
    c = b[i]
    if c <= 0x7F or c >= 0xE0 or c in (0xC0, 0xC2, 0xC3):
        return i + 1
    if 0x80 <= c <= 0x8F:
        return skip_n(b, i + 1, 2 * (c & 0x0F))
    if 0x90 <= c <= 0x9F:
        return skip_n(b, i + 1, c & 0x0F)
    if 0xA0 <= c <= 0xBF:
        return i + 1 + (c & 0x1F)
    fixed = {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8, 0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8, 0xCA: 4, 0xCB: 8}
    if c in fixed:
        return i + 1 + fixed[c]
    if c in (0xC4, 0xD9):
        return i + 2 + b[i + 1]
    if c in (0xC5, 0xDA):
        return i + 3 + int.from_bytes(b[i + 1 : i + 3], "big")
    if c in (0xC6, 0xDB):
        return i + 5 + int.from_bytes(b[i + 1 : i + 5], "big")
    if c in (0xDC, 0xDE):
        n = int.from_bytes(b[i + 1 : i + 3], "big")
        return skip_n(b, i + 3, n if c == 0xDC else 2 * n)
    if c in (0xDD, 0xDF):
        n = int.from_bytes(b[i + 1 : i + 5], "big")
        return skip_n(b, i + 5, n if c == 0xDD else 2 * n)
    raise ValueError(f"unsupported msgpack byte {c:#x} at {i}")


def skip_n(b, i, n):
    for _ in range(n):
        i = skip(b, i)
    return i


def map_header(b, i):
    """(entries, header_len) of the map at i, or None."""
    c = b[i]
    if 0x80 <= c <= 0x8F:
        return c & 0x0F, 1
    if c == 0xDE:
        return int.from_bytes(b[i + 1 : i + 3], "big"), 3
    if c == 0xDF:
        return int.from_bytes(b[i + 1 : i + 5], "big"), 5
    return None


def walk_maps(b, i=0, out=None):
    """Every map in pre-order: (start, header_len, [(key_start, val_start, val_end)], end)."""
    if out is None:
        out = []
    c = b[i]
    mh = map_header(b, i)
    if mh is not None:
        n, hl = mh
        slot = len(out)
        out.append(None)
        entries = []
        j = i + hl
        for _ in range(n):
            ks = j
            vs = skip(b, ks)
            walk_maps(b, ks, out)
            walk_maps(b, vs, out)
            ve = skip(b, vs)
            entries.append((ks, vs, ve))
            j = ve
        out[slot] = (i, hl, entries, j)
        return out
    if 0x90 <= c <= 0x9F or c in (0xDC, 0xDD):
        if c <= 0x9F:
            n, hl = c & 0x0F, 1
        elif c == 0xDC:
            n, hl = int.from_bytes(b[i + 1 : i + 3], "big"), 3
        else:
            n, hl = int.from_bytes(b[i + 1 : i + 5], "big"), 5
        j = i + hl
        for _ in range(n):
            walk_maps(b, j, out)
            j = skip(b, j)
    return out


def encode_map_len(n):
    if n < 16:
        return bytes([0x80 | n])
    if n < 65536:
        return b"\xde" + n.to_bytes(2, "big")
    return b"\xdf" + n.to_bytes(4, "big")


def mutate(b, map_idx, pos, key, val):
    if map_idx < 0:
        return b
    start, hl, entries, end = walk_maps(b)[map_idx]
    pos = min(pos, len(entries))
    body = b""
    for k, (ks, vs, ve) in enumerate(entries):
        if k == pos:
            body += key + val
        body += b[ks:ve]
    if pos == len(entries):
        body += key + val
    return b[:start] + encode_map_len(len(entries) + 1) + body + b[end:]


def str_key(s):
    raw = s.encode()
    assert len(raw) < 32
    return bytes([0xA0 | len(raw)]) + raw


def top_value(b, key):
    """Raw bytes of top-level map `key`'s value."""
    n, hl = map_header(b, 0)
    j = hl
    for _ in range(n):
        ks, vs = j, skip(b, j)
        ve = skip(b, vs)
        if b[ks:vs] == str_key(key):
            return b[vs:ve]
        j = ve
    return None


def drop_keys(b, drop):
    n, hl = map_header(b, 0)
    j, kept = hl, []
    for _ in range(n):
        ks = j
        vs = skip(b, ks)
        ve = skip(b, vs)
        if b[ks:vs] not in {str_key(k) for k in drop}:
            kept.append(b[ks:ve])
        j = ve
    return encode_map_len(len(kept)) + b"".join(kept)


def keep_keys(b, keep):
    n, hl = map_header(b, 0)
    j, kept = hl, []
    for _ in range(n):
        ks = j
        vs = skip(b, ks)
        ve = skip(b, vs)
        if b[ks:vs] in {str_key(k) for k in keep}:
            kept.append(b[ks:ve])
        j = ve
    return encode_map_len(len(kept)) + b"".join(kept)


def array_items(b):
    c = b[0]
    if c <= 0x9F:
        n, i = c & 0x0F, 1
    elif c == 0xDC:
        n, i = int.from_bytes(b[1:3], "big"), 3
    else:
        n, i = int.from_bytes(b[1:5], "big"), 5
    out = []
    for _ in range(n):
        e = skip(b, i)
        out.append(b[i:e])
        i = e
    return out


# ── seeds ─────────────────────────────────────────────────────────────────

BLOCK_ONLY = ["ca", "dt", "rs", "rr", "rc", "aca", "hgi", "hgh", "apid", "caid"]
APPLY_DATA = ["ca", "dt", "rs", "rr", "rc", "aca", "apid", "caid"]


def real_seeds():
    seeds = []

    def add(name, kind, raw):
        seeds.append({"name": name, "kind": kind, "hex": raw.hex()})

    def from_blockcert(prefix, bc):
        add(f"{prefix}_blockcert", "blockcert", bc)
        blk = top_value(bc, "block")
        add(f"{prefix}_block", "block", blk)
        cert = top_value(bc, "cert")
        if cert is not None:
            add(f"{prefix}_cert", "cert", cert)
        txns = top_value(blk, "txns")
        if txns is not None:
            for k, t in enumerate(array_items(txns)[:3]):
                add(f"{prefix}_stxninblock{k}", "stxninblock", t)
                add(f"{prefix}_stxn{k}", "stxn", drop_keys(t, BLOCK_ONLY))
                inner = top_value(t, "txn")
                if inner is not None:
                    add(f"{prefix}_txn{k}", "txn", inner)
                ad = keep_keys(t, APPLY_DATA)
                add(f"{prefix}_applydata{k}", "applydata", ad)
                dt = top_value(t, "dt")
                if dt is not None:
                    add(f"{prefix}_evaldelta{k}", "evaldelta", dt)
        hdr = drop_keys(blk, ["txns"])
        add(f"{prefix}_header", "header", hdr)

    fx = os.path.join(ROOT, "crates", "core", "algo-codec", "tests", "fixtures")
    for n in (1, 2, 6, 8):
        from_blockcert(f"fx_block_{n}", open(os.path.join(fx, f"block_{n}.msgpack"), "rb").read())

    # replay corpus: rounds whose txns carry an eval delta, inner txns, logic sigs...
    blocks = os.path.join(ROOT, "benchmarks", "corpus", "small", "blocks.bin")
    if os.path.exists(blocks):
        raw = open(blocks, "rb").read()
        assert raw[:8] == b"ACRPBLK1"
        i, picked = 8, {"dt": 0, "itx": 0, "lsig": 0, "msig": 0}
        while i < len(raw):
            ln = int.from_bytes(raw[i + 8 : i + 12], "big")
            rec = raw[i + 12 : i + 12 + ln]
            i += 12 + ln
            blk = top_value(rec, "block")
            txns = top_value(blk, "txns") if blk else None
            if not txns:
                continue
            feats = set()
            for t in array_items(txns):
                for key in ("dt", "lsig", "msig"):
                    if top_value(t, key) is not None:
                        feats.add(key)
                dt = top_value(t, "dt")
                if dt is not None and top_value(dt, "itx") is not None:
                    feats.add("itx")
            for f in sorted(feats):
                if picked[f] < 1 and len(rec) < 60000:
                    picked[f] += 1
                    from_blockcert(f"corpus_small_{f}", rec)
                    break

    # agreement wire fixtures captured from go
    wire = os.path.join(ROOT, "crates", "core", "algo-agreement", "tests", "fixtures", "wire")
    for sub, kind, names in (
        ("tpayload", "payload", None),
        ("uvote", "vote", None),
        ("ubundle", "bundle", None),
        ("cert", "cert", None),
    ):
        d = os.path.join(wire, sub)
        files = sorted(f for f in os.listdir(d) if f.endswith(".msgpack"))
        for f in files[:3]:
            add(f"wire_{sub}_{f[:-8]}", kind, open(os.path.join(d, f), "rb").read())
    return seeds


# ── go oracle ─────────────────────────────────────────────────────────────


def run_go(go_algorand, rows, seeds_out=None, seed_tests=None):
    """rows: [{"name","kind","hex"}] -> {name: {"ok","err"}}; seeds_out: list to
    fill with random seeds from the `seed_tests` ({package: go test name})."""
    res = {}
    seed_tests = seed_tests or {}
    pkgs = sorted({KIND_PKG[r["kind"]] for r in rows} | (set(seed_tests) if seeds_out is not None else set()))
    with tempfile.TemporaryDirectory() as tmp:
        for pkg in pkgs:
            template, suffix = TEMPLATES[pkg]
            sub = [r for r in rows if KIND_PKG[r["kind"]] == pkg]
            want_seeds = seeds_out is not None and pkg in seed_tests
            dst = os.path.join(go_algorand, pkg, DST)
            inp, outp, sd = (os.path.join(tmp, f"{pkg.replace(chr(47), chr(95))}.{x}") for x in ("in", "out", "seeds"))
            with open(inp, "w", encoding="utf-8") as f:
                for r in sub:
                    f.write(json.dumps({"name": r["name"], "kind": r["kind"], "hex": r["hex"]}) + "\n")
            shutil.copyfile(os.path.join(ORACLE, template), dst)
            try:
                env = dict(os.environ, STRICT_IN=inp, STRICT_OUT=outp)
                run = f"^TestStrictDecodeOracle{suffix}$"
                if want_seeds:
                    env["STRICT_SEEDS_OUT"] = sd
                    run += f"|^{seed_tests[pkg]}$"
                subprocess.run(["go", "test", "-count=1", "-run", run, "./" + pkg], cwd=go_algorand, env=env, check=True)
            finally:
                os.remove(dst)
            for line in open(outp, encoding="utf-8"):
                r = json.loads(line)
                res[r["name"]] = r
            if want_seeds:
                seeds_out.extend(json.loads(l) for l in open(sd, encoding="utf-8"))
    return res


# ── cases ─────────────────────────────────────────────────────────────────

# No empty array: go decodes a struct from an array (positionally), so `[]` is
# accepted wherever a struct value is expected (the array form has its own cases).
VALUES = [
    bytes([0xC0]),  # nil
    bytes([0x01]),  # uint 1
    bytes([0xA1, 0x78]),  # "x"
    bytes([0x80]),  # {}
    bytes([0xC4, 0x01, 0x00]),  # bin
    bytes([0x81, 0xA1, 0x61, 0x01]),  # {"a":1}
    bytes([0xC3]),  # true
]


# Always-present regression cases (seed, map index, position, key, value): a
# repeated key whose value is an empty map. go's generated decoder decodes the
# empty map INTO the already populated struct (fields it does not mention are
# kept), so a state-proof `Reveal`/`Participant` with a duplicated `p` still has
# its `required` verifier (issue #2397, found by the 100k differential fuzz).
PINNED = [
    ("applydata_rand3", 22, 2, str_key("p"), bytes([0x80])),  # Reveal: second `p` = {}
    ("applydata_rand3", 23, 2, str_key("p"), bytes([0x80])),  # Participant: second `p` = {}
]


def donor_entries(b):
    """Every (key, value) entry of every map of `b`, as raw bytes."""
    out = []
    for start, hl, entries, end in walk_maps(b):
        for ks, vs, ve in entries:
            # An array-valued entry is left out: go decodes a struct from an
            # array, so a dict of structs accepts it under any key.
            if 0xA0 <= b[ks] <= 0xBF and not (0x90 <= b[vs] <= 0x9F or b[vs] in (0xDC, 0xDD)):
                out.append((b[ks:vs], b[vs:ve]))
    return out


def make_cases(seeds, rng, per_map, cap=None, pinned=(), fresh_keys_only=False):
    """Per map of every seed, `per_map` mutants: an unknown key `zz` (any value
    kind), then *transplants*, a real (key, value) entry of another map of the
    same seed. A transplant is well typed, so where the key is valid in the
    destination go accepts it (a repeated key), and where it is not go rejects
    it as an unknown field: no verdict depends on a value's type."""
    cases = []
    for s in seeds:
        b = bytes.fromhex(s["hex"])
        donors = donor_entries(b)
        cases.append((s, -1, 0, b"", b""))
        for m, (start, hl, entries, end) in enumerate(walk_maps(b)):
            present = {b[ks:vs] for ks, vs, ve in entries}
            fresh = [d for d in donors if d[0] not in present] if fresh_keys_only else donors
            for j in range(per_map):
                pos = rng.randint(0, len(entries))
                if j == 0 or not fresh:
                    cases.append((s, m, pos, str_key("zz"), rng.choice(VALUES)))
                else:
                    k, v = rng.choice(fresh)
                    cases.append((s, m, pos, k, v))
    rng.shuffle(cases)
    if cap is not None:
        cases = cases[:cap]
    by_name = {s["name"]: s for s in seeds}
    for seed, m, pos, key, val in pinned:
        if seed in by_name:
            cases.append((by_name[seed], m, pos, key, val))
    return finish_cases(cases)


def repeated_values(b, vs, ve):
    """Values for a second occurrence of the key whose first value is b[vs:ve]."""
    v = b[vs:ve]
    out = [bytes([0xC0])]
    mh = map_header(v, 0)
    if mh is not None:
        n, hl = mh
        out.append(bytes([0x80]))
        if n > 1:
            out.append(encode_map_len(1) + v[hl : skip(v, skip(v, hl))])
    elif 0x90 <= v[0] <= 0x9F or v[0] in (0xDC, 0xDD):
        items = array_items(v)
        out.append(encode_array_len(0))
        # fewer elements, each with only its first entry: decoded into the
        # existing elements, so go keeps their other fields
        shrunk = []
        for it in items[: max(1, len(items) - 1)]:
            ih = map_header(it, 0)
            if ih is not None and ih[0] > 1:
                it = encode_map_len(1) + it[ih[1] : skip(it, skip(it, ih[1]))]
            shrunk.append(it)
        out.append(encode_array_len(len(shrunk)) + b"".join(shrunk))
        out.append(encode_array_len(len(items) + 1) + b"".join(items) + (items[0] if items else b""))
    elif v[0] in (0xC4, 0xC5, 0xC6) or 0xA0 <= v[0] <= 0xBF or v[0] in (0xD9, 0xDA, 0xDB):
        out.append(bytes([0xC4, 0x01, 0x00]))
        out.append(bytes([0xC4, 0x01, 0xFF]))
    return out


def make_repeat_cases(seeds, rng, cap):
    """Per map of every seed, one case: a key the map already has, again (see
    the module docstring). Ids continue after the transplant cases."""
    cases = []
    for s in seeds:
        b = bytes.fromhex(s["hex"])
        same_key = {}
        for start, hl, entries, end in walk_maps(b):
            for ks, vs, ve in entries:
                same_key.setdefault(b[ks:vs], []).append(b[vs:ve])
        for m, (start, hl, entries, end) in enumerate(walk_maps(b)):
            if not entries:
                continue
            ks, vs, ve = rng.choice(entries)
            key = b[ks:vs]
            vals = repeated_values(b, vs, ve) + [x for x in same_key[key] if x != b[vs:ve]]
            cases.append((s, m, rng.randint(0, len(entries)), key, rng.choice(vals)))
    rng.shuffle(cases)
    return cases[:cap]


# ── allocation-bound boundary cases (issue #2427) ─────────────────────────
#
# go's generated msgp decoders read the length header of every field with an
# `allocbound` (`msgp.ReadBytesBytesHeader` / `ReadArrayHeaderBytes` /
# `ReadMapHeaderBytes`) and fail with `msgp.ErrOverflow` when it is larger,
# before reading the value. Each rule below is one such bound reachable from a
# consensus message (the `Transaction` / `BlockHeader` / `Payset` /
# `StateProof` / `LogicSig` / `EvalDelta` / bundle decoders of go v5.1.1-stable;
# the `bounds.*` values are the maxima `config.checkSetAllocBounds` computes
# over every consensus version). Every rule gives two mutants of a map of that
# struct: the field again, at the end of the map (so it is the value go keeps),
# with exactly `bound` and with `bound + 1` elements / bytes. go-codec (the
# tx-sync response) checks no allocbound, so there both are accepted.


def enc_uint(n):
    if n < 128:
        return bytes([n])
    if n < 256:
        return b"\xcc" + bytes([n])
    if n < 65536:
        return b"\xcd" + n.to_bytes(2, "big")
    return b"\xce" + n.to_bytes(4, "big")


def enc_str_n(n):
    raw = b"a" * n
    if n < 32:
        return bytes([0xA0 | n]) + raw
    if n < 256:
        return b"\xd9" + bytes([n]) + raw
    return b"\xda" + n.to_bytes(2, "big") + raw


def enc_bin_n(n):
    raw = b"\x61" * n
    if n < 256:
        return b"\xc4" + bytes([n]) + raw
    if n < 65536:
        return b"\xc5" + n.to_bytes(2, "big") + raw
    return b"\xc6" + n.to_bytes(4, "big") + raw


def enc_array(n, elem):
    if n < 16:
        head = bytes([0x90 | n])
    elif n < 65536:
        head = b"\xdc" + n.to_bytes(2, "big")
    else:
        head = b"\xdd" + n.to_bytes(4, "big")
    return head + elem * n


def enc_map_u64(n, val):
    return encode_map_len(n) + b"".join(enc_uint(k) + val for k in range(n))


def enc_map_str(n, val):
    return encode_map_len(n) + b"".join(str_key(f"k{k:05d}") + val for k in range(n))


S = lambda n: enc_str_n(n)  # noqa: E731  a go `string`
B = lambda n: enc_bin_n(n)  # noqa: E731  a go `[]byte`
A = lambda elem: lambda n: enc_array(n, elem)  # noqa: E731  a slice of n `elem`
MU = lambda val: lambda n: enc_map_u64(n, val)  # noqa: E731  a map[uint64]T
MS = lambda val: lambda n: enc_map_str(n, val)  # noqa: E731  a map[string]T
AE = lambda n: enc_array(1, enc_bin_n(n))  # noqa: E731  one element of n bytes

NIL, EMPTY_MAP, EMPTY_BIN = b"\xc0", b"\x80", b"\xc4\x00"
# the smallest `stateproof.Reveal` go accepts: its required `p` with a non-zero
# verifier (`{"p": {"p": {"lf": 1}}}`)
MIN_REVEAL = b"\x81\xa1p\x81\xa1p\x81\xa2lf\x01"
# the smallest `SignedTxnWithAD` go accepts: its required `txn` with the
# Transaction's required `snd` and `type`
MIN_STXN = b"\x81\xa3txn\x82\xa3snd\xc4\x20" + b"\x01" * 32 + b"\xa4type\xa3pay"

HEADER = {"$block", "block", "$header"}
HEADER_SIB = {"rnd", "prev", "gh", "proto", "ts", "seed", "txn", "gen", "fees", "rwd"}
TXN_SIB = {"snd", "type", "fv", "lv", "fee", "gh", "note"}
# (parents, any sibling key the map must have or None, key, value builder, bound, go's bound)
BOUND_RULES = [
    # bookkeeping.BlockHeader (Block, unauthenticatedProposal, transmittedPayload)
    (HEADER, HEADER_SIB, "gen", S, 128, "bounds.MaxGenesisIDLen"),
    (HEADER, HEADER_SIB, "proto", S, 128, "bounds.MaxConsensusVersionLen"),
    (HEADER, HEADER_SIB, "nextproto", S, 128, "bounds.MaxConsensusVersionLen"),
    (HEADER, HEADER_SIB, "upgradeprop", S, 128, "bounds.MaxConsensusVersionLen"),
    (HEADER, HEADER_SIB, "spt", MU(NIL), 1, "protocol.NumStateProofTypes"),
    (HEADER, HEADER_SIB, "partupdrmv", A(NIL), 32, "bounds.MaxProposedExpiredOnlineAccounts"),
    (HEADER, HEADER_SIB, "partupdabs", A(NIL), 32, "bounds.MaxMarkAbsent"),
    ({"spt"}, {"v", "t", "n"}, "v", B, 64, "crypto.MaxHashDigestSize"),
    # transactions.Payset (100000 valid elements would be 5 MB: at the bound go
    # and algod-rust both reject the first element's missing required `txn`)
    ({"$block", "block"}, HEADER_SIB, "txns", A(EMPTY_MAP), 100000, "Payset 100000"),
    # transactions.Transaction
    ({"txn"}, TXN_SIB, "note", B, 4096, "bounds.MaxTxnNoteBytes"),
    ({"txn"}, TXN_SIB, "gen", S, 128, "bounds.MaxGenesisIDLen"),
    ({"txn"}, TXN_SIB, "type", S, 7, "txTypeMaxLen"),
    ({"txn"}, TXN_SIB, "apaa", A(EMPTY_BIN), 32, "encodedMaxApplicationArgs"),
    ({"txn"}, TXN_SIB, "apat", A(NIL), 32, "encodedMaxAccounts"),
    ({"txn"}, TXN_SIB, "apas", A(b"\x01"), 32, "encodedMaxForeignAssets"),
    ({"txn"}, TXN_SIB, "apfa", A(b"\x01"), 32, "encodedMaxForeignApps"),
    ({"txn"}, TXN_SIB, "al", A(EMPTY_MAP), 16, "bounds.MaxAppAccess"),
    ({"txn"}, TXN_SIB, "apbx", A(EMPTY_MAP), 32, "encodedMaxBoxes"),
    ({"txn"}, TXN_SIB, "apap", B, 16384, "bounds.MaxAvailableAppProgramLen"),
    ({"txn"}, TXN_SIB, "apsu", B, 16384, "bounds.MaxAvailableAppProgramLen"),
    ({"apbx", "b"}, {"i", "n"}, "n", B, 128, "bounds.MaxBytesKeyValueLen"),
    ({"apar"}, {"t", "dc", "un", "an", "au", "m"}, "un", S, 8, "bounds.MaxAssetUnitNameBytes"),
    ({"apar"}, {"t", "dc", "un", "an", "au", "m"}, "an", S, 32, "bounds.MaxAssetNameBytes"),
    ({"apar"}, {"t", "dc", "un", "an", "au", "m"}, "au", S, 96, "bounds.MaxAssetURLBytes"),
    # stateproof.StateProof, merklearray.Proof, merklesignature.Signature
    ({"sp"}, {"c", "w", "S", "P", "r", "pr"}, "c", B, 64, "crypto.MaxHashDigestSize"),
    ({"sp"}, {"c", "w", "S", "P", "r", "pr"}, "r", MU(MIN_REVEAL), 640, "stateproof.MaxReveals"),
    ({"sp"}, {"c", "w", "S", "P", "r", "pr"}, "pr", A(b"\x01"), 640, "stateproof.MaxReveals"),
    ({"S", "P", "prf"}, {"pth", "hsh", "td"}, "pth", A(NIL), 32768, "MaxNumLeavesOnEncodedTree/2"),
    ({"S", "P", "prf"}, {"pth", "hsh", "td"}, "pth", AE, 64, "crypto.MaxHashDigestSize"),
    ({"s"}, {"sig", "idx", "prf", "vkey"}, "sig", B, 1538, "crypto.FalconMaxSignatureSize"),
    ({"spmsg"}, None, "b", B, 32, "crypto.Sha256Size"),
    ({"spmsg"}, None, "v", B, 64, "crypto.SumhashDigestSize"),
    # transactions.LogicSig, crypto.MultisigSig, transactions.PQSig (#2390)
    ({"lsig"}, None, "l", B, 16000, "bounds.MaxLogicSigMaxSize"),
    ({"lsig"}, None, "arg", A(EMPTY_BIN), 255, "EvalMaxArgs"),
    ({"lsig"}, None, "arg", AE, 4096, "MaxLogicSigArgSize"),
    ({"msig", "lmsig"}, {"v", "thr", "subsig"}, "subsig", A(EMPTY_MAP), 255, "maxMultisig"),
    ({"pqsig"}, None, "pk", B, 1793, "crypto.MaxPQPublicKeySize"),
    ({"pqsig"}, None, "sig", B, 1538, "crypto.MaxPQSignatureSize"),
    # transactions.EvalDelta, basics.StateDelta / ValueDelta (#2424)
    ({"dt"}, None, "gd", MS(NIL), 2048, "bounds.MaxStateDeltaKeys"),
    ({"dt"}, None, "ld", MU(NIL), 2048, "bounds.MaxEvalDeltaAccounts"),
    ({"dt"}, None, "sa", A(NIL), 2048, "bounds.MaxEvalDeltaAccounts"),
    ({"dt"}, None, "lg", A(b"\xa0"), 2048, "bounds.MaxLogCalls"),
    ({"dt"}, None, "itx", A(MIN_STXN), 256, "bounds.MaxInnerTransactionsPerDelta"),
    (None, {"at"}, "bs", S, 128, "bounds.MaxAppBytesValueLen"),
    # agreement.unauthenticatedBundle / Certificate
    ({"$bundle", "cert"}, {"rnd", "per", "step", "prop", "vote", "eqv"}, "vote", A(EMPTY_MAP), 7750,
     "bounds.MaxVoteThreshold"),
    ({"$bundle", "cert"}, {"rnd", "per", "step", "prop", "vote", "eqv"}, "eqv", A(EMPTY_MAP), 7750,
     "bounds.MaxVoteThreshold"),
]

# the parent of a seed's top-level map(s)
ROOT_PARENT = {
    "payload": "$block",
    "block": "$block",
    "header": "$header",
    "blockcert": "$blockcert",
    "vote": "$vote",
    "bundle": "$bundle",
    "cert": "$bundle",
    "stxn": "$stxn",
    "stxninblock": "$stxn",
    "applydata": "$stxn",
    "txsync": "$stxn",
    "txn": "txn",
    "evaldelta": "dt",
}


def walk_maps_ctx(b, i, parent, out):
    """walk_maps, also giving each map its parent: the nearest enclosing
    string key (array elements and integer-keyed map values inherit it)."""
    mh = map_header(b, i)
    c = b[i]
    if mh is not None:
        n, hl = mh
        slot = len(out)
        out.append(None)
        keys = set()
        j = i + hl
        for _ in range(n):
            ks = j
            vs = skip(b, ks)
            walk_maps_ctx(b, ks, parent, out)
            is_str = 0xA0 <= b[ks] <= 0xBF
            key = b[ks + 1 : vs].decode("latin-1") if is_str else None
            if key is not None:
                keys.add(key)
            walk_maps_ctx(b, vs, key if key is not None else parent, out)
            j = skip(b, vs)
        out[slot] = (parent, keys, n)
        return out
    if 0x90 <= c <= 0x9F or c in (0xDC, 0xDD):
        if c <= 0x9F:
            n, hl = c & 0x0F, 1
        elif c == 0xDC:
            n, hl = int.from_bytes(b[i + 1 : i + 3], "big"), 3
        else:
            n, hl = int.from_bytes(b[i + 1 : i + 5], "big"), 5
        j = i + hl
        for _ in range(n):
            walk_maps_ctx(b, j, parent, out)
            j = skip(b, j)
    return out


# seed kinds in the order bound cases pick them: the gossip messages first
BOUND_KIND_ORDER = [
    "payload",
    "bundle",
    "vote",
    "stxn",
    "block",
    "blockcert",
    "cert",
    "header",
    "stxninblock",
    "txn",
    "applydata",
    "evaldelta",
    "txsync",
]


def make_bound_cases(seeds, kinds):
    """The boundary mutants of every rule: per (rule, seed kind) the first map
    of a matching struct (real seeds first), at `bound` and `bound + 1`. A
    value over 1 KiB is placed in the first two kinds of BOUND_KIND_ORDER that
    have such a map, one over 8 KiB in the first one (fixture size)."""
    real = [s for s in seeds if "_rand" not in s["name"]] + [s for s in seeds if "_rand" in s["name"]]
    ordered = [s for k in BOUND_KIND_ORDER if k in kinds for s in real if s["kind"] == k]
    walked = {s["name"]: walk_maps_ctx(bytes.fromhex(s["hex"]), 0, ROOT_PARENT[s["kind"]], []) for s in ordered}
    cases = []
    for parents, sib, key, build, bound, _go in BOUND_RULES:
        size = len(build(bound))
        max_kinds = 1 if size > 8192 else 2 if size > 1024 else len(kinds)
        done = []
        for s in ordered:
            if s["kind"] in done or len(done) >= max_kinds:
                continue
            for m, (parent, keys, n) in enumerate(walked[s["name"]]):
                if (parents is None or parent in parents) and (sib is None or keys & sib):
                    for v in (bound, bound + 1):
                        cases.append((s, m, n, str_key(key), build(v)))
                    done.append(s["kind"])
                    break
    return cases


# ── nil elements of `[]byte` lists (issue #2430) ──────────────────────────
#
# go reads every element of a `[][]byte` / `[]crypto.GenericDigest` with
# `msgp.ReadBytesBytes`, which keeps a msgpack `nil` element as a nil slice,
# and `msgp.AppendBytes` re-encodes a nil slice as `nil` (0xc0), a `bin` / `str`
# of length 0 as `bin` 0. So `go_val` tells nil from empty elements. Each rule
# gives the field again at the end of the first matching map per seed kind
# (decoded into the populated field when the seed already has it), as lists of
# nil, `bin` 0, `str` 0 and one-byte elements.
NIL_ELEM_VALUES = [
    enc_array(1, NIL),
    b"\x94" + NIL + EMPTY_BIN + b"\xa0" + b"\xc4\x01a",
    b"\x93" + b"\xc4\x01a" + NIL + NIL,
]
NIL_ELEM_RULES = [
    ({"txn"}, TXN_SIB, "apaa"),  # transactions.ApplicationCallTxnFields.ApplicationArgs
    ({"S", "P", "prf"}, {"pth", "hsh", "td"}, "pth"),  # merklearray.Proof.Path
    ({"lsig"}, None, "arg"),  # transactions.LogicSig.Args
]


def make_nil_elem_cases(seeds, kinds):
    real = [s for s in seeds if "_rand" not in s["name"]] + [s for s in seeds if "_rand" in s["name"]]
    ordered = [s for k in BOUND_KIND_ORDER if k in kinds for s in real if s["kind"] == k]
    walked = {s["name"]: walk_maps_ctx(bytes.fromhex(s["hex"]), 0, ROOT_PARENT[s["kind"]], []) for s in ordered}
    cases = []
    for parents, sib, key in NIL_ELEM_RULES:
        done = set()
        for s in ordered:
            if s["kind"] in done:
                continue
            for m, (parent, keys, n) in enumerate(walked[s["name"]]):
                if parent in parents and (sib is None or keys & sib):
                    for v in NIL_ELEM_VALUES:
                        cases.append((s, m, n, str_key(key), v))
                    done.add(s["kind"])
                    break
    return cases


def finish_cases(cases, first_id=0):
    out = []
    for n, (s, m, pos, key, val) in enumerate(cases):
        mut = mutate(bytes.fromhex(s["hex"]), m, pos, key, val)
        out.append(
            {
                "id": first_id + n,
                "seed": s["name"],
                "kind": s["kind"],
                "map": m,
                "pos": pos,
                "key": key.hex(),
                "val": val.hex(),
                "sha": hashlib.sha256(mut).hexdigest()[:16],
                "_hex": mut.hex(),
            }
        )
    return out


def attach_verdicts(go_algorand, cases):
    rows = [{"name": str(c["id"]), "kind": c["kind"], "hex": c["_hex"]} for c in cases]
    res = run_go(go_algorand, rows)
    for c in cases:
        r = res[str(c["id"])]
        c["go_ok"] = bool(r["ok"])
        if c["go_ok"]:
            # go's decoded value, re-encoded (issue #2421)
            c["go_val"] = hashlib.sha256(bytes.fromhex(r.get("enc", ""))).hexdigest()[:16]
    return cases


def dump(cases):
    return "".join(
        json.dumps({k: v for k, v in c.items() if not k.startswith("_")}, sort_keys=True) + "\n" for c in cases
    )


# ── struct-from-array cases (issue #2426) ─────────────────────────────────
#
# go decodes a struct from an ARRAY too: the elements are the fields in go's
# declaration order (embedded structs flattened), `ErrTooManyArrayFields` on
# an element more, the fields past a shorter array left alone. The cases turn
# the maps of a seed into arrays, type-directed by the msgp field layout that
# the oracle dumps from go's own types (crates/core/algo-types/src/
# go_struct_order.json: `STRICT_SCHEMA_OUT`, checked against the generated
# decoders), so the verdicts and decoded values come from go.

SCHEMA_PATH = os.path.join(ROOT, "crates", "core", "algo-types", "src", "go_struct_order.json")

_CONVERTED = None


def converted_types():
    """The go structs whose algod-rust reader has the array form: the go type
    names (`"pkg.Type"` string literals that are a key of the schema) in the
    sources of the crates whose readers pass them to `rmp_decode::struct_keys` /
    `struct_keys_with` / `Block::decode_as` or name them in `msgp_schema`'s
    validator. A struct outside this set stays a map in the array cases, so a
    case is never about a reader that is not converted yet (issue #2426)."""
    global _CONVERTED
    if _CONVERTED is None:
        import re

        names = set(load_schema())
        found = set()
        for crate_dir in (
            ("core", "algo-types"),
            ("core", "algo-agreement"),
            ("node", "algo-network"),
            ("tools", "algokey-rust"),
        ):
            src = os.path.join(ROOT, "crates", *crate_dir, "src")
            for base, _dirs, files in sorted(os.walk(src)):
                for f in sorted(files):
                    if f.endswith(".rs"):
                        txt = open(os.path.join(base, f), encoding="utf-8").read()
                        found |= {m for m in re.findall(r'"([a-z]+\.[A-Za-z_]+)"', txt) if m in names}
        # structs read by another struct's reader: go's `SingleLeafProof` has
        # `Proof`'s fields, and an `ApplyData` is read as the apply-data half
        # of a `SignedTxnWithAD`
        for alias, reader in (
            ("merklearray.SingleLeafProof", "merklearray.Proof"),
            ("transactions.ApplyData", "transactions.SignedTxnWithAD"),
        ):
            if reader in found:
                found.add(alias)
        _CONVERTED = found
    return _CONVERTED


# the go type each seed kind decodes
ROOT_TYPES = {
    "blockcert": "rpcs.EncodedBlockCert",
    "block": "bookkeeping.Block",
    "header": "bookkeeping.BlockHeader",
    "stxn": "transactions.SignedTxn",
    "stxninblock": "transactions.SignedTxnInBlock",
    "txn": "transactions.Transaction",
    "applydata": "transactions.ApplyData",
    "evaldelta": "transactions.EvalDelta",
    "payload": "agreement.transmittedPayload",
    "vote": "agreement.unauthenticatedVote",
    "bundle": "agreement.unauthenticatedBundle",
    "cert": "agreement.Certificate",
    "idchal": "network.identityChallengeSigned",
    "idresp": "network.identityChallengeResponseSigned",
    "idverify": "network.identityVerificationMessageSigned",
    # the tx-sync response: a list of signed transactions (go-codec)
    "txsync": ("list", "transactions.SignedTxn"),
    "pqkey": "main.saltedSigningMaterial",
    # catchpoint file sections (ledger/catchupaccessor.go, issue #2609)
    "cpheader": "ledger.CatchpointFileHeader",
    "cpchunk": "ledger.CatchpointSnapshotChunkV6",
    "cpspver": "ledger.catchpointStateProofVerificationContext",
}


def root_descriptor(kind):
    t = ROOT_TYPES[kind]
    if isinstance(t, tuple):
        return {"k": "list", "e": {"k": "struct", "t": t[1]}}
    return {"k": "struct", "t": t}

_SCHEMA = None


def load_schema():
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = json.load(open(SCHEMA_PATH, encoding="utf-8"))
    return _SCHEMA


def schema_text(go_algorand):
    """The msgp field layout (go_struct_order.json) as the oracles dump it from go's
    types, the rpcs and agreement packages merged."""
    merged = {}
    with tempfile.TemporaryDirectory() as tmp:
        for pkg, (template, suffix) in sorted(TEMPLATES.items()):
            if pkg not in ("rpcs", "agreement", "network", "cmd/algokey", "ledger"):
                continue
            out = os.path.join(tmp, pkg.replace("/", "_") + ".json")
            dst = os.path.join(go_algorand, pkg, DST)
            shutil.copyfile(os.path.join(ORACLE, template), dst)
            try:
                env = dict(os.environ, STRICT_SCHEMA_OUT=out)
                subprocess.run(
                    ["go", "test", "-count=1", "-run", f"^TestStrictDecodeSchema{suffix}$", "./" + pkg],
                    cwd=go_algorand,
                    env=env,
                    check=True,
                )
            finally:
                os.remove(dst)
            for name, fields in json.load(open(out, encoding="utf-8")).items():
                assert merged.setdefault(name, fields) == fields, f"{name} differs between oracles"
    return json.dumps(merged, indent=1, sort_keys=True) + "\n"


# Structs a set turns into arrays on top of `converted_types()` (see
# `reachable_structs`); the ledger set's readers have no array form since go
# v5.1.1 (issue #2609), so its array cases pin go's rejection of every struct.
_EXTRA_ALLOWED = set()


def reachable_structs(kinds):
    """Every go struct reachable from the root types of `kinds`."""
    schema = load_schema()
    seen = set()

    def walk(t):
        if t["k"] == "struct":
            if t["t"] in seen:
                return
            seen.add(t["t"])
            for f in schema[t["t"]]:
                walk(f["type"])
        elif t["k"] in ("list", "map"):
            walk(t["e"])

    for k in sorted(kinds):
        if k in ROOT_TYPES:
            walk(root_descriptor(k))
    return seen


def array_form_allowed(tname):
    return tname in load_schema() and (tname in converted_types() or tname in _EXTRA_ALLOWED)


def zero_encoding(t):
    """go's zero value of a field of type `t`, as the encoder would write it;
    a struct / list / map is nil."""
    if t["k"] != "leaf":
        return bytes([0xC0])
    name = t.get("t", "")
    if name == "bool":
        return bytes([0xC2])
    if name == "string":
        return bytes([0xA0])
    if name == "bytes":
        return bytes([0xC0])
    if name.startswith("bytes["):
        n = int(name[6:-1])
        return b"\xc4" + bytes([n]) + bytes(n) if n < 256 else b"\xc5" + n.to_bytes(2, "big") + bytes(n)
    return bytes([0x00])  # an integer


def struct_instances(b, i, t, out):
    """Pre-order list of the array-capable struct maps under the value at b[i:]
    of type `t`: [(start, struct type name)]."""
    c = b[i]
    if t["k"] == "struct":
        mh = map_header(b, i)
        if mh is None:
            return
        n, hl = mh
        name = t["t"]
        if array_form_allowed(name):
            out.append((i, name))
        fields = {f["key"]: f["type"] for f in load_schema()[name]}
        j = i + hl
        for _ in range(n):
            ks = j
            vs = skip(b, ks)
            ve = skip(b, vs)
            key = b[ks:vs]
            if 0xA0 <= key[0] <= 0xBF and key[1:].decode("latin-1") in fields:
                struct_instances(b, vs, fields[key[1:].decode("latin-1")], out)
            j = ve
    elif t["k"] == "list":
        if 0x90 <= c <= 0x9F or c in (0xDC, 0xDD):
            for it_start in array_item_starts(b, i):
                struct_instances(b, it_start, t["e"], out)
    elif t["k"] == "map":
        mh = map_header(b, i)
        if mh is not None:
            n, hl = mh
            j = i + hl
            for _ in range(n):
                vs = skip(b, j)
                struct_instances(b, vs, t["e"], out)
                j = skip(b, vs)


def array_item_starts(b, i):
    c = b[i]
    if c <= 0x9F:
        n, j = c & 0x0F, i + 1
    elif c == 0xDC:
        n, j = int.from_bytes(b[i + 1 : i + 3], "big"), i + 3
    else:
        n, j = int.from_bytes(b[i + 1 : i + 5], "big"), i + 5
    out = []
    for _ in range(n):
        out.append(j)
        j = skip(b, j)
    return out


def to_array_form(b, i, t, plan, state):
    """The bytes of the value at b[i:] of type `t`, with the struct maps `plan`
    selects turned into arrays. `plan(index, start, name)` -> None (keep the
    map), or the array's variant ("full", "trim", "extra", or an int to cut to
    that many elements); `state['n']` counts the struct maps seen (the
    `index` of `struct_instances`)."""
    end = skip(b, i)
    c = b[i]
    if t["k"] == "struct":
        mh = map_header(b, i)
        if mh is None:
            return b[i:end]
        n, hl = mh
        name = t["t"]
        idx = None
        if array_form_allowed(name):
            idx = state["n"]
            state["n"] += 1
        fields = load_schema()[name]
        by_key = {f["key"]: f for f in fields}
        entries = []
        j = i + hl
        for _ in range(n):
            ks = j
            vs = skip(b, ks)
            ve = skip(b, vs)
            entries.append((b[ks:vs], vs, ve))
            j = ve
        variant = plan(idx, i, name) if idx is not None else None
        decodable = all(0xA0 <= k[0] <= 0xBF and k[1:].decode("latin-1") in by_key for k, _, _ in entries)
        have = {k[1:].decode("latin-1"): (vs, ve) for k, vs, ve in entries if 0xA0 <= k[0] <= 0xBF}
        if variant is None or not decodable:
            body = b""
            for k, vs, ve in entries:
                f = by_key.get(k[1:].decode("latin-1")) if 0xA0 <= k[0] <= 0xBF else None
                v = to_array_form(b, vs, f["type"], plan, state) if f else b[vs:ve]
                body += k + v
            return encode_map_len(n) + body
        # children in stream order (the numbering of `struct_instances`)
        child = {}
        for k, vs, ve in entries:
            kk = k[1:].decode("latin-1")
            child[kk] = to_array_form(b, vs, by_key[kk]["type"], plan, state)
        elems = [child[f["key"]] if f["key"] in child else zero_encoding(f["type"]) for f in fields]
        last = max((k for k, f in enumerate(fields) if f["key"] in have), default=-1)
        if variant == "trim":
            elems = elems[: last + 1]
        elif variant == "extra":
            elems = elems + [bytes([0xC0])]
        elif isinstance(variant, int):
            elems = elems[: min(variant, len(elems))]
        return encode_array_len(len(elems)) + b"".join(elems)
    if t["k"] == "list" and (0x90 <= c <= 0x9F or c in (0xDC, 0xDD)):
        items = [to_array_form(b, s, t["e"], plan, state) for s in array_item_starts(b, i)]
        return encode_array_len(len(items)) + b"".join(items)
    if t["k"] == "map":
        mh = map_header(b, i)
        if mh is not None:
            n, hl = mh
            out = []
            j = i + hl
            for _ in range(n):
                ks = j
                vs = skip(b, ks)
                ve = skip(b, vs)
                out.append(b[ks:vs] + to_array_form(b, vs, t["e"], plan, state))
                j = ve
            return encode_map_len(n) + b"".join(out)
    return b[i:end]


def make_array_cases(seeds, kinds, rng, per_type=5, cap=None):
    """Array-form mutants of the seeds of `kinds`: per struct type some
    instances turned into arrays (full / trimmed / cut / one element too many,
    descendants kept as maps), and every seed once with every struct an array
    ("all" and trimmed)."""
    cases = []  # (seed, hex of the mutant)
    by_type = {}
    for s in seeds:
        if s["kind"] not in kinds or s["kind"] not in ROOT_TYPES:
            continue
        b = bytes.fromhex(s["hex"])
        root = root_descriptor(s["kind"])
        inst = []
        struct_instances(b, 0, root, inst)
        for k, (start, name) in enumerate(inst):
            by_type.setdefault(name, []).append((s, b, root, k))

        def everywhere(variant):
            return lambda idx, start, name: variant

        for variant in ("full", "trim"):
            m = to_array_form(b, 0, root, everywhere(variant), {"n": 0})
            if m != b:
                cases.append((s, m))
    variants = ["full", "trim", "extra", "cut"]
    for name, items in sorted(by_type.items()):
        picks = items[:]
        rng.shuffle(picks)
        for n, (s, b, root, k) in enumerate(picks[:per_type]):
            variant = variants[n % len(variants)]
            if variant == "cut":
                variant = rng.randint(0, 6)
            m = to_array_form(b, 0, root, lambda idx, start, nm, k=k, v=variant: v if idx == k else None, {"n": 0})
            if m != b:
                cases.append((s, m))
    # a struct whose array is full, plus one element: too many fields
    rng.shuffle(cases)
    if cap is not None:
        cases = cases[:cap]
    return cases


def make_repeat_array_cases(seeds, kinds, rng, cap=None):
    """A key a map already has again, its value a state-proof `Reveal` turned
    into an array (the structs below it as maps, or all as arrays): go-codec
    decodes a repeated entry of a `map[uint64]Reveal` INTO the existing
    (unaddressable) value, a path of its own (issue #2426). Returns
    `finish_cases` tuples (a key inserted into the seed's n-th map)."""
    out = []
    for s in seeds:
        if s["kind"] not in kinds or s["kind"] not in ROOT_TYPES:
            continue
        b = bytes.fromhex(s["hex"])
        inst = []
        struct_instances(b, 0, root_descriptor(s["kind"]), inst)
        maps = walk_maps(b)
        for start, name in inst:
            if name != "stateproof.Reveal":
                continue
            for m, (mstart, hl, entries, mend) in enumerate(maps):
                for e, (ks, vs, ve) in enumerate(entries):
                    if vs != start:
                        continue
                    for deep in (False, True):
                        arr = to_array_form(
                            b,
                            vs,
                            {"k": "struct", "t": name},
                            (lambda idx, st, nm, deep=deep: "full" if (deep or idx == 0) else None),
                            {"n": 0},
                        )
                        out.append((s, m, e + 1, b[ks:vs], arr))
                    # arrays go-codec can decode INTO the unaddressable entry:
                    # empty ones (nothing to set) and integers
                    A = encode_array_len
                    for canned in (
                        A(0),
                        A(1) + A(0),
                        A(1) + A(2) + A(0) + bytes([7]),
                        A(2) + A(0) + A(0),
                        A(2) + A(2) + A(0) + bytes([7]) + A(2) + A(0) + bytes([9]),
                        A(1) + A(1) + A(0),
                    ):
                        out.append((s, m, e + 1, b[ks:vs], canned))
    rng.shuffle(out)
    return out[:cap] if cap is not None else out


def finish_hex_cases(cases, first_id):
    """Cases given as (seed, mutant bytes): `map` -2 marks them for the replay
    (the mutant is the case's own `hex`, not a key inserted into the seed)."""
    out = []
    for n, (s, mut) in enumerate(cases):
        out.append(
            {
                "id": first_id + n,
                "seed": s["name"],
                "kind": s["kind"],
                "map": -2,
                "pos": 0,
                "key": "",
                "val": "",
                "hex": mut.hex(),
                "sha": hashlib.sha256(mut).hexdigest()[:16],
                "_hex": mut.hex(),
            }
        )
    return out


# ── array-valued entries, truncated and deep array forms (issue #2609) ────────
#
# go v5.1.1's generated decoders read a struct from a map only: an array where a
# struct is expected is `ReadMapHeaderBytes`'s TypeError, whatever it holds. The
# sections below come after every older one (so no older row moves) and pin
# that for the shapes the key-insertion cases leave out: a struct-valued key
# again with an array value (empty, nil element, extra elements, array16 /
# array32 headers), array headers cut short, and arrays nested deep.

ARRAY_VALUES = [
    bytes([0x90]),  # []
    bytes([0x91, 0xC0]),  # [nil]
    bytes([0x92, 0x01, 0x02]),  # [1, 2]
    bytes([0x91, 0x90]),  # [[]]
    bytes([0xDC, 0x00, 0x00]),  # array16 []
    bytes([0xDD, 0x00, 0x00, 0x00, 0x00]),  # array32 []
    bytes([0x91, 0x80]),  # [{}]
]


def make_array_value_cases(seeds, kinds, rng, cap=600):
    """`finish_cases` tuples: a key whose value is a map, again, with an array."""
    out = []
    for s in seeds:
        if s["kind"] not in kinds:
            continue
        b = bytes.fromhex(s["hex"])
        for m, (start, hl, entries, end) in enumerate(walk_maps(b)):
            for ks, vs, ve in entries:
                if 0xA0 <= b[ks] <= 0xBF and map_header(b, vs) is not None:
                    out.append((s, m, rng.randint(0, len(entries)), b[ks:vs], rng.choice(ARRAY_VALUES)))
    rng.shuffle(out)
    return out[:cap]


def make_array_shape_cases(seeds, kinds, cap_per_kind=6):
    """(seed, mutant bytes): array headers cut short, arrays nested deep and
    the array form of a seed cut at a few points."""
    out = []
    seen = set()

    def add(s, mut):
        if mut not in seen:
            seen.add(mut)
            out.append((s, mut))

    for kind in sorted(kinds):
        of_kind = [s for s in seeds if s["kind"] == kind]
        if not of_kind:
            continue
        s0 = of_kind[0]
        b0 = bytes.fromhex(s0["hex"])
        for head in ("93", "dc", "dc00", "dc0003", "dd000000", "dd00000003"):
            add(s0, bytes.fromhex(head))
        for depth in (1, 2, 20, 130, 300):
            add(s0, bytes([0x91]) * depth + b0)
            add(s0, bytes([0x91]) * depth + bytes([0xC0]))
        if kind not in ROOT_TYPES:
            continue
        root = root_descriptor(kind)
        for s in of_kind[:cap_per_kind]:
            b = bytes.fromhex(s["hex"])
            m = to_array_form(b, 0, root, lambda idx, start, name: "full", {"n": 0})
            if m == b:
                continue
            for cut in sorted({1, 2, 3, len(m) // 2, len(m) - 1}):
                if 0 < cut < len(m):
                    add(s, m[:cut])
    return out


# ── non-consensus real seeds (issue #2396) ────────────────────────────────


def encode_str(raw):
    if len(raw) < 32:
        return bytes([0xA0 | len(raw)]) + raw
    assert len(raw) < 256
    return b"\xd9" + bytes([len(raw)]) + raw


def encode_array_len(n):
    if n < 16:
        return bytes([0x90 | n])
    return b"\xdc" + n.to_bytes(2, "big")


def truncate_arrays(b, n):
    """A top-level map whose array values keep only their first `n` items."""
    cnt, hl = map_header(b, 0)
    j, out = hl, []
    for _ in range(cnt):
        ks = j
        vs = skip(b, ks)
        ve = skip(b, vs)
        v = b[vs:ve]
        if 0x90 <= v[0] <= 0x9F or v[0] in (0xDC, 0xDD):
            items = array_items(v)[:n]
            v = encode_array_len(len(items)) + b"".join(items)
        out.append(b[ks:vs] + v)
        j = ve
    return encode_map_len(cnt) + b"".join(out)


CATCHPOINT_TARS = [
    os.path.join(ROOT, "benchmarks", "corpus", "small-catchpoint", "catchpoint.tar"),
    os.path.join(ROOT, "benchmarks", "go-replay", "testdata", "small-catchpoint-1000.tar"),
]


def real_seeds_ledger():
    """Sections of the committed go-written small catchpoints (arrays cut to
    their first three records, to keep the fixture small)."""
    import tarfile

    seeds = []
    for t, path in enumerate(CATCHPOINT_TARS):
        with tarfile.open(path) as tar:
            for m in tar.getmembers():
                data = tar.extractfile(m).read()
                tag = f"cp{t}_{m.name.replace('.msgpack', '').replace('.', '_')}"
                if m.name == "content.msgpack":
                    seeds.append({"name": tag, "kind": "cpheader", "hex": data.hex()})
                elif m.name == "stateProofVerificationContext.msgpack":
                    seeds.append({"name": tag, "kind": "cpspver", "hex": truncate_arrays(data, 3).hex()})
                elif m.name.startswith("balances."):
                    seeds.append({"name": tag, "kind": "cpchunk", "hex": truncate_arrays(data, 3).hex()})
    return seeds


def real_seeds_network():
    """tx-sync responses built from the consensus set's signed transactions."""
    cons = [s for s in read_seeds(SETS["consensus"]) if s["kind"] == "stxn" and "_rand" not in s["name"]]
    seeds = []
    for k in range(min(4, len(cons))):
        group = [bytes.fromhex(s["hex"]) for s in cons[k : k + 1 + k % 3]]
        raw = encode_array_len(len(group)) + b"".join(group)
        seeds.append({"name": f"txsync_real{k}", "kind": "txsync", "hex": raw.hex()})
    return seeds


def real_seeds_p2p():
    """Peer meta headers shaped like go's writePeerMetaHeaders output."""

    def headers(pairs):
        out = encode_map_len(len(pairs))
        for k, vs in pairs:
            out += encode_str(k.encode()) + encode_array_len(len(vs))
            out += b"".join(encode_str(v.encode()) for v in vs)
        return out

    full = [
        ("Genesisid", ["testnet-v1.0"]),
        ("X-Algorand-Instancename", ["8c46b5b5ac2b"]),
        ("X-Algorand-Location", [""]),
        ("X-Algorand-Nodefeatures", ["gossip"]),
        ("X-Algorand-Telid", ["7e5e3a4f-5a5a-4f0e-8c7a-2f6b9d0e1a11"]),
        ("X-Algorand-Version", ["2.2"]),
        ("X-Algorand-Versionsupported", ["2.2", "2.1"]),
    ]
    return [
        {"name": "peermeta_real0", "kind": "peermeta", "hex": headers(full).hex()},
        {"name": "peermeta_real1", "kind": "peermeta", "hex": headers([("X-Algorand-Version", ["2.2"])]).hex()},
    ]


# ── fixture sets ──────────────────────────────────────────────────────────

SETS = {
    "consensus": {
        "dir": fixture_dir("core", "algo-agreement"),
        "kinds": {
            "payload",
            "vote",
            "bundle",
            "cert",
            "blockcert",
            "block",
            "header",
            "stxn",
            "stxninblock",
            "txn",
            "applydata",
            "evaldelta",
        },
        "seed_tests": {"agreement": "TestStrictDecodeSeedsAgreement", "rpcs": "TestStrictDecodeSeedsRpcs"},
        "real": real_seeds,
        "rng": 2394,
        "fuzz_xor": 0x2394,
        "pinned": PINNED,
        "fresh": False,
        # issue #2424: the consensus readers merge a repeated key like go
        "repeat_kinds": {
            "payload",
            "vote",
            "bundle",
            "cert",
            "blockcert",
            "block",
            "header",
            "stxn",
            "stxninblock",
            "txn",
            "applydata",
            "evaldelta",
        },
        # issue #2427: go's msgp allocbounds
        "bound_kinds": {
            "payload",
            "vote",
            "bundle",
            "cert",
            "blockcert",
            "block",
            "header",
            "stxn",
            "stxninblock",
            "txn",
            "applydata",
            "evaldelta",
        },
        # issue #2430: nil elements of []byte lists
        "nil_kinds": {"stxn", "block", "payload", "stxninblock", "txn", "applydata", "evaldelta"},
        # issue #2426: structs read from arrays
        "array_kinds": {
            "blockcert",
            "block",
            "header",
            "stxn",
            "stxninblock",
            "txn",
            "applydata",
            "evaldelta",
            "payload",
            "vote",
            "bundle",
            "cert",
        },
    },
    "ledger": {
        "dir": fixture_dir("core", "algo-ledger"),
        "kinds": {"cpheader", "cpchunk", "cpspver"},
        "seed_tests": {"ledger": "TestStrictDecodeSeedsLedger"},
        "real": real_seeds_ledger,
        "rng": 23961,
        "fuzz_xor": 23961,
        "pinned": (),
        "fresh": True,
        "repeat_kinds": {"cpheader", "cpchunk", "cpspver"},
        "bound_kinds": set(),
        "nil_kinds": set(),
        # issue #2609: go v5.1.1 reads these structs from a map only
        "array_kinds": {"cpheader", "cpchunk", "cpspver"},
        "array_all_schema": True,
    },
    "network": {
        "dir": fixture_dir("node", "algo-network"),
        "kinds": {"idchal", "idresp", "idverify", "txsync"},
        "seed_tests": {"network": "TestStrictDecodeSeedsNetwork", "rpcs": "TestStrictDecodeSeedsTxSync"},
        "real": real_seeds_network,
        "rng": 23962,
        "fuzz_xor": 23962,
        "pinned": (),
        "fresh": True,
        "repeat_kinds": {"idchal", "idresp", "idverify", "txsync"},
        # issue #2426: structs read from arrays (go-codec for the tx-sync response)
        "array_kinds": {"idchal", "idresp", "idverify", "txsync"},
        # go-codec: no allocbound is checked, both mutants are accepted
        "bound_kinds": {"txsync"},
        # issue #2430: nil elements of []byte lists (go-codec)
        "nil_kinds": {"txsync"},
    },
    "algokey": {
        "dir": fixture_dir("tools", "algokey-rust"),
        "kinds": {"pqkey"},
        "seed_tests": {"cmd/algokey": "TestStrictDecodeSeedsAlgokey"},
        "real": lambda: [],
        "rng": 25211,
        "fuzz_xor": 25211,
        "pinned": (),
        "fresh": True,
        "repeat_kinds": {"pqkey"},
        "bound_kinds": set(),
        "nil_kinds": set(),
        # issue #2521: a key file is a struct, read from an array too
        "array_kinds": {"pqkey"},
    },
    "p2p": {
        "dir": fixture_dir("node", "algo-p2p"),
        "kinds": {"peermeta"},
        "seed_tests": {"network": "TestStrictDecodeSeedsNetwork"},
        "real": real_seeds_p2p,
        "rng": 23963,
        "fuzz_xor": 23963,
        "pinned": (),
        "fresh": True,
        "repeat_kinds": {"peermeta"},
        "bound_kinds": set(),
        "nil_kinds": set(),
    },
}


def seeds_path(st):
    return os.path.join(st["dir"], "seeds.jsonl")


def cases_path(st):
    return os.path.join(st["dir"], "cases.jsonl")


def read_seeds(st):
    return [json.loads(l) for l in open(seeds_path(st), encoding="utf-8") if l.strip()]


def run_set(name, st, go, a):
    os.makedirs(st["dir"], exist_ok=True)
    if a.regen_seeds or not os.path.exists(seeds_path(st)):
        rand = []
        run_go(go, [], seeds_out=rand, seed_tests=st["seed_tests"])
        rand = [s for s in rand if s["kind"] in st["kinds"]]
        seeds = st["real"]() + rand
        # a seed go itself rejects would only test the baseline: keep go-accepted ones
        v = run_go(go, [{"name": s["name"], "kind": s["kind"], "hex": s["hex"]} for s in seeds])
        seeds = [s for s in seeds if v[s["name"]]["ok"]]
        with open(seeds_path(st), "w", encoding="utf-8", newline="\n") as f:
            for s in seeds:
                f.write(json.dumps(s, sort_keys=True) + "\n")
        print(f"wrote {seeds_path(st)} ({len(seeds)} seeds)")

    seeds = read_seeds(st)
    global _EXTRA_ALLOWED
    _EXTRA_ALLOWED = reachable_structs(st["kinds"]) if st.get("array_all_schema") else set()
    if a.fuzz:
        n = int(a.fuzz[0])
        rng = random.Random(n ^ st["fuzz_xor"])
        cases = make_cases(seeds, rng, per_map=40, cap=n, pinned=st["pinned"], fresh_keys_only=st["fresh"])
        rep = []
        rep_seeds = [s for s in seeds if s["kind"] in st["repeat_kinds"]]
        for _ in range(64 if rep_seeds else 0):
            if len(rep) >= n:
                break
            rep += make_repeat_cases(rep_seeds, rng, n - len(rep))
        cases += finish_cases(rep, first_id=len(cases))
        cases += finish_cases(make_bound_cases(seeds, st["bound_kinds"]), first_id=len(cases))
        cases += finish_cases(make_nil_elem_cases(seeds, st["nil_kinds"]), first_id=len(cases))
        arr = make_array_cases(seeds, st.get("array_kinds", set()), rng, per_type=max(5, n // 400))
        cases += finish_hex_cases(arr, first_id=len(cases))
        rarr = make_repeat_array_cases(seeds, st.get("array_kinds", set()), rng, cap=max(200, n // 400))
        cases += finish_cases(rarr, first_id=len(cases))
        cases += finish_cases(make_array_value_cases(seeds, st["kinds"], rng, cap=max(600, n // 100)), first_id=len(cases))
        cases += finish_hex_cases(make_array_shape_cases(seeds, st["kinds"]), first_id=len(cases))
        cases = attach_verdicts(go, cases)
        out = a.fuzz[1] if name == "consensus" else f"{a.fuzz[1]}.{name}"
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(dump(cases))
        print(f"wrote {out} ({len(cases)} cases, {sum(c['go_ok'] for c in cases)} accepted by go)")
        return

    cases = make_cases(
        seeds, random.Random(st["rng"]), a.per_map, a.cap, pinned=st["pinned"], fresh_keys_only=st["fresh"]
    )
    rep_seeds = [s for s in seeds if s["kind"] in st["repeat_kinds"]]
    rep = make_repeat_cases(rep_seeds, random.Random(st["rng"] ^ 0x2421), a.repeat_cap)
    cases += finish_cases(rep, first_id=len(cases))
    cases += finish_cases(make_bound_cases(seeds, st["bound_kinds"]), first_id=len(cases))
    cases += finish_cases(make_nil_elem_cases(seeds, st["nil_kinds"]), first_id=len(cases))
    arr = make_array_cases(seeds, st.get("array_kinds", set()), random.Random(st["rng"] ^ 0x2426))
    cases += finish_hex_cases(arr, first_id=len(cases))
    rarr = make_repeat_array_cases(seeds, st.get("array_kinds", set()), random.Random(st["rng"] ^ 0x2427), cap=200)
    cases += finish_cases(rarr, first_id=len(cases))
    cases += finish_cases(
        make_array_value_cases(seeds, st["kinds"], random.Random(st["rng"] ^ 0x2609)), first_id=len(cases)
    )
    cases += finish_hex_cases(make_array_shape_cases(seeds, st["kinds"]), first_id=len(cases))
    cases = attach_verdicts(go, cases)
    text = dump(cases)
    path = cases_path(st)
    if a.check:
        cur = open(path, encoding="utf-8", newline="").read()
        if cur != text:
            sys.exit(f"{path} is stale; rerun without --check")
        print(f"{name}: up to date")
        return
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {path} ({len(cases)} cases, {sum(c['go_ok'] for c in cases)} accepted by go)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail when a cases.jsonl is stale")
    ap.add_argument("--regen-seeds", action="store_true", help="rewrite the go-random seeds (not reproducible)")
    ap.add_argument(
        "--fuzz",
        nargs=2,
        metavar=("N", "OUT"),
        help="write N extra random cases per set with go verdicts to OUT (consensus) and OUT.<set>",
    )
    ap.add_argument(
        "--regen-schema",
        action="store_true",
        help="rewrite crates/core/algo-types/src/go_struct_order.json from go's types (--check: fail when stale)",
    )
    ap.add_argument("--set", action="append", choices=sorted(SETS), help="fixture set(s); default: all")
    ap.add_argument("--per-map", type=int, default=2)
    ap.add_argument("--cap", type=int, default=4000)
    ap.add_argument("--repeat-cap", type=int, default=1500, help="repeated-key cases per set (issue #2421)")
    ap.add_argument("--go-algorand", default=os.environ.get("GO_ALGORAND_DIR"))
    a = ap.parse_args()
    if not a.go_algorand:
        sys.exit("set GO_ALGORAND_DIR or pass --go-algorand (a v5.1.1-stable checkout with libsodium built)")
    go = os.path.abspath(a.go_algorand)
    if a.regen_schema:
        text = schema_text(go)
        if a.check:
            if open(SCHEMA_PATH, encoding="utf-8", newline="").read() != text:
                sys.exit(f"{SCHEMA_PATH} is stale; rerun with --regen-schema")
            print("go_struct_order.json: up to date")
        else:
            with open(SCHEMA_PATH, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            print(f"wrote {SCHEMA_PATH}")
        return
    for name in a.set or list(SETS):
        run_set(name, SETS[name], go, a)


if __name__ == "__main__":
    main()
