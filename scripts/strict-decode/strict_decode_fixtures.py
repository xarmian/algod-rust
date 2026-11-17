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
does not already have. Repeated keys have their own cases (issue #2421), after
the transplants: a key the map already has, again, with a value
derived from its first one (a map with fewer entries or none, a shorter array
whose elements have fewer entries, a shorter byte string, nil) or another map's
value under the same key. go decodes a repeated key *into* the already decoded
field: a scalar is overwritten, a nested struct and a map are merged, a slice
is re-sliced and decoded element by element into the existing elements when
the old capacity allows it (else it is a fresh slice), a `[N]byte` keeps the
bytes past a shorter value, nil clears. So every accepted case also carries
`go_val`, the sha256 prefix of go's re-encode of the decoded value, and the
ledger / network / p2p replaying tests compare it with algod-rust's decoded
value, re-encoded. Repeated-key cases are generated only for a set's
`repeat_kinds`: not yet for the consensus kinds and `txsync`, whose
`SignedTxn` / block / vote readers still replace a repeated field (DIV-004,
issue #2424).
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
            inp, outp, sd = (os.path.join(tmp, f"{pkg}.{x}") for x in ("in", "out", "seeds"))
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
# accepted wherever a struct value is expected; algod-rust reads the map form
# only (DIV-004), a documented difference this fixture is not about.
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
            # array (DIV-004), so a dict of structs accepts it under any key.
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
        # the consensus readers do not merge a repeated key yet (DIV-004, #2424)
        "repeat_kinds": set(),
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
        # txsync goes through the consensus SignedTxn reader (DIV-004, #2424)
        "repeat_kinds": {"idchal", "idresp", "idverify"},
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
    ap.add_argument("--set", action="append", choices=sorted(SETS), help="fixture set(s); default: all")
    ap.add_argument("--per-map", type=int, default=2)
    ap.add_argument("--cap", type=int, default=4000)
    ap.add_argument("--repeat-cap", type=int, default=1500, help="repeated-key cases per set (issue #2421)")
    ap.add_argument("--go-algorand", default=os.environ.get("GO_ALGORAND_DIR"))
    a = ap.parse_args()
    if not a.go_algorand:
        sys.exit("set GO_ALGORAND_DIR or pass --go-algorand (a v5.0.5-stable checkout with libsodium built)")
    go = os.path.abspath(a.go_algorand)
    for name in a.set or list(SETS):
        run_set(name, SETS[name], go, a)


if __name__ == "__main__":
    main()
