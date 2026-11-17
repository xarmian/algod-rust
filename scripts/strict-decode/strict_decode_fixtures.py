#!/usr/bin/env python3
# Copyright (C) 2019-2026 Algorand Foundation Ltd.
# Modifications Copyright (C) 2026 Algod DAO
# This file is part of algod-rust, a modified work based on go-algorand
# (https://github.com/algorand/go-algorand).
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate the committed strict-unknown-field parity fixtures (issue #2394).

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
FIX = os.path.join(ROOT, "crates", "core", "algo-agreement", "tests", "fixtures", "strict_decode")
SEEDS = os.path.join(FIX, "seeds.jsonl")
CASES = os.path.join(FIX, "cases.jsonl")
ORACLE = os.path.join(ROOT, "tools", "strict-decode-oracle")
PKGS = {
    "agreement": ("agreement_oracle_test.go.txt", {"payload", "vote", "bundle", "cert"}),
    "rpcs": (
        "rpcs_oracle_test.go.txt",
        {"blockcert", "block", "header", "stxn", "stxninblock", "txn", "applydata", "evaldelta"},
    ),
}
DST = "zz_strict_decode_oracle_test.go"

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


def ascii_strs(b):
    """`b` with every non-ASCII byte of a msgpack `str` value replaced by `x`.

    go's randomiser fills Go strings (transaction type, genesis id, log lines,
    ...) with arbitrary bytes, and go accepts non-UTF-8 `str` values anywhere;
    algod-rust's string readers (`read_string`) refuse them: a separate
    difference, tracked in its own issue, that this fixture is not about, so the
    random seeds keep their strings ASCII and the verdicts isolate unknown keys.
    """
    out = bytearray(b)

    def go(i):
        c = out[i]
        if 0x80 <= c <= 0x8F or 0x90 <= c <= 0x9F or c in (0xDC, 0xDD, 0xDE, 0xDF):
            if c in (0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F):
                n, hl, mul = c & 0x0F, 1, 2
            elif c <= 0x9F:
                n, hl, mul = c & 0x0F, 1, 1
            elif c == 0xDC:
                n, hl, mul = int.from_bytes(out[i + 1 : i + 3], "big"), 3, 1
            elif c == 0xDD:
                n, hl, mul = int.from_bytes(out[i + 1 : i + 5], "big"), 5, 1
            elif c == 0xDE:
                n, hl, mul = int.from_bytes(out[i + 1 : i + 3], "big"), 3, 2
            else:
                n, hl, mul = int.from_bytes(out[i + 1 : i + 5], "big"), 5, 2
            j = i + hl
            for _ in range(n * mul):
                j = go(j)
            return j
        e = skip(bytes(out), i)
        if 0xA0 <= c <= 0xBF:
            hl = 1
        elif c == 0xD9:
            hl = 2
        elif c == 0xDA:
            hl = 3
        elif c == 0xDB:
            hl = 5
        else:
            return e
        for k in range(i + hl, e):
            if out[k] > 0x7F:
                out[k] = 0x78
        return e

    go(0)
    return bytes(out)


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


def run_go(go_algorand, rows, seeds_out=None):
    """rows: [{"name","kind","hex"}] -> {name: {"ok","err"}}; seeds_out: list to fill with random seeds."""
    res = {}
    with tempfile.TemporaryDirectory() as tmp:
        for pkg, (template, kinds) in PKGS.items():
            sub = [r for r in rows if r["kind"] in kinds]
            if not sub and seeds_out is None:
                continue
            dst = os.path.join(go_algorand, pkg, DST)
            inp, outp, sd = (os.path.join(tmp, f"{pkg}.{x}") for x in ("in", "out", "seeds"))
            with open(inp, "w", encoding="utf-8") as f:
                for r in sub:
                    f.write(json.dumps({"name": r["name"], "kind": r["kind"], "hex": r["hex"]}) + "\n")
            shutil.copyfile(os.path.join(ORACLE, template), dst)
            try:
                env = dict(os.environ, STRICT_IN=inp, STRICT_OUT=outp)
                if seeds_out is not None:
                    env["STRICT_SEEDS_OUT"] = sd
                run = "^TestStrictDecodeOracle|^TestStrictDecodeSeeds" if seeds_out is not None else "^TestStrictDecodeOracle"
                subprocess.run(["go", "test", "-count=1", "-run", run, "./" + pkg], cwd=go_algorand, env=env, check=True)
            finally:
                os.remove(dst)
            for line in open(outp, encoding="utf-8"):
                r = json.loads(line)
                res[r["name"]] = r
            if seeds_out is not None:
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


def make_cases(seeds, rng, per_map, cap=None):
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
            for j in range(per_map):
                pos = rng.randint(0, len(entries))
                if j == 0 or not donors:
                    cases.append((s, m, pos, str_key("zz"), rng.choice(VALUES)))
                else:
                    k, v = rng.choice(donors)
                    cases.append((s, m, pos, k, v))
    rng.shuffle(cases)
    if cap is not None:
        cases = cases[:cap]
    out = []
    for n, (s, m, pos, key, val) in enumerate(cases):
        mut = mutate(bytes.fromhex(s["hex"]), m, pos, key, val)
        out.append(
            {
                "id": n,
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
        c["go_ok"] = bool(res[str(c["id"])]["ok"])
    return cases


def dump(cases):
    return "".join(
        json.dumps({k: v for k, v in c.items() if not k.startswith("_")}, sort_keys=True) + "\n" for c in cases
    )


def read_seeds():
    return [json.loads(l) for l in open(SEEDS, encoding="utf-8") if l.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail when cases.jsonl is stale")
    ap.add_argument("--regen-seeds", action="store_true", help="rewrite the go-random seeds (not reproducible)")
    ap.add_argument("--fuzz", nargs=2, metavar=("N", "OUT"), help="write N extra random cases with go verdicts")
    ap.add_argument("--per-map", type=int, default=2)
    ap.add_argument("--cap", type=int, default=4000)
    ap.add_argument("--go-algorand", default=os.environ.get("GO_ALGORAND_DIR"))
    a = ap.parse_args()
    if not a.go_algorand:
        sys.exit("set GO_ALGORAND_DIR or pass --go-algorand (a v5.0.5-stable checkout with libsodium built)")
    go = os.path.abspath(a.go_algorand)
    os.makedirs(FIX, exist_ok=True)

    if a.regen_seeds or not os.path.exists(SEEDS):
        rand = []
        run_go(go, [], seeds_out=rand)
        for r in rand:
            r["hex"] = ascii_strs(bytes.fromhex(r["hex"])).hex()
        seeds = real_seeds() + rand
        # a seed go itself rejects would only test the baseline: keep go-accepted ones
        v = run_go(go, [{"name": s["name"], "kind": s["kind"], "hex": s["hex"]} for s in seeds])
        seeds = [s for s in seeds if v[s["name"]]["ok"]]
        with open(SEEDS, "w", encoding="utf-8", newline="\n") as f:
            for s in seeds:
                f.write(json.dumps(s, sort_keys=True) + "\n")
        print(f"wrote {SEEDS} ({len(seeds)} seeds)")

    seeds = read_seeds()
    if a.fuzz:
        cases = make_cases(seeds, random.Random(int(a.fuzz[0]) ^ 0x2394), per_map=40, cap=int(a.fuzz[0]))
        cases = attach_verdicts(go, cases)
        with open(a.fuzz[1], "w", encoding="utf-8", newline="\n") as f:
            f.write(dump(cases))
        print(f"wrote {a.fuzz[1]} ({len(cases)} cases, {sum(c['go_ok'] for c in cases)} accepted by go)")
        return

    cases = attach_verdicts(go, make_cases(seeds, random.Random(2394), a.per_map, a.cap))
    text = dump(cases)
    if a.check:
        cur = open(CASES, encoding="utf-8", newline="").read()
        if cur != text:
            sys.exit(f"{CASES} is stale; rerun without --check")
        print("up to date")
        return
    with open(CASES, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {CASES} ({len(cases)} cases, {sum(c['go_ok'] for c in cases)} accepted by go)")


if __name__ == "__main__":
    main()
