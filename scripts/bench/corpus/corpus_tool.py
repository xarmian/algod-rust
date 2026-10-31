#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Manifest and corpus.json tooling for the benchmark block corpus.

Issue #2104 (epic #2101). A corpus directory holds blocks.bin, genesis.json,
node-config.json, consensus.json, corpus.json and MANIFEST.sha256 (see the
"Workload corpus" section of docs/BENCHMARK_COMPARISON.md). This tool needs
only the Python standard library; decoding the blocks is left to the two
implementations (benchmarks/go-corpus `corpusgen verify`, and the Rust test
crates/tools/algo-bench/tests/corpus_small.rs).

Usage:
  corpus_tool.py manifest DIR          write DIR/MANIFEST.sha256
  corpus_tool.py verify DIR [--no-coverage]
                                       manifest + corpus.json consistency
                                       (+ every required workload kind present)
  corpus_tool.py compare DIR_A DIR_B   determinism check: identical manifests
                                       and corpus.json, else list what differs
  corpus_tool.py pack DIR OUT.tar.gz   deterministic tarball for a release asset
  corpus_tool.py summary DIR           markdown histogram table
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile

MANIFEST = "MANIFEST.sha256"
SCHEMA = "algod-corpus/v1"

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
# Every workload kind issue #2104 requires in every corpus. The single source
# of truth, also read by crates/tools/algo-bench/tests/corpus_small.rs.
COVERAGE_FILE = os.path.join(REPO, "benchmarks", "corpus", "coverage.json")


def load_coverage(path=COVERAGE_FILE):
    with open(path, encoding="utf-8") as f:
        cov = json.load(f)
    return cov["subtypes"], cov["features"], cov["inner_types"]


REQUIRED_SUBTYPES, REQUIRED_FEATURES, REQUIRED_INNER = load_coverage()
HEX_DIGITS = frozenset("0123456789abcdef")
REQUIRED_FILES = ["blocks", "genesis", "node_config", "consensus"]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def corpus_files(d):
    """Every regular file of a corpus directory except the manifest, sorted."""
    return sorted(n for n in os.listdir(d)
                  if n != MANIFEST and os.path.isfile(os.path.join(d, n)))


def manifest_text(d):
    return "".join(f"{sha256_file(os.path.join(d, n))}  {n}\n" for n in corpus_files(d))


def write_manifest(d):
    path = os.path.join(d, MANIFEST)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(manifest_text(d))
    return path


def parse_manifest(text):
    entries = {}
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        digest, sep, name = line.partition("  ")
        # Same rules as crates/tools/algo-bench/src/corpus.rs parse_manifest
        # (shared vectors: scripts/bench/testdata/corpus/manifest_vectors.json):
        # a lowercase sha256 hex digest, and a plain file name in the corpus
        # directory itself.
        if (not sep or len(digest) != 64 or not set(digest) <= HEX_DIGITS or not name
                or "/" in name or "\\" in name or name in (".", "..", MANIFEST)):
            raise ValueError(f"{MANIFEST} line {i}: malformed: {line!r}")
        if name in entries:
            raise ValueError(f"{MANIFEST} line {i}: duplicate entry {name}")
        entries[name] = digest
    return entries


def verify_manifest(d):
    """Errors (empty list = OK): bad hashes, missing or unlisted files."""
    path = os.path.join(d, MANIFEST)
    if not os.path.isfile(path):
        return [f"{path}: missing"]
    with open(path, "rb") as f:
        raw = f.read()
    if b"\r" in raw:
        return [f"{path}: contains CR bytes (line-ending conversion corrupted the corpus)"]
    try:
        entries = parse_manifest(raw.decode("utf-8"))
    except ValueError as e:
        return [str(e)]
    errors = []
    for name, digest in sorted(entries.items()):
        p = os.path.join(d, name)
        if not os.path.isfile(p):
            errors.append(f"{name}: listed in {MANIFEST} but missing")
        elif sha256_file(p) != digest:
            errors.append(f"{name}: sha256 mismatch")
    for name in corpus_files(d):
        if name not in entries:
            errors.append(f"{name}: present but not listed in {MANIFEST}")
    return errors


def load_corpus_json(d):
    with open(os.path.join(d, "corpus.json"), encoding="utf-8") as f:
        return json.load(f)


def _counts(obj, key, errors):
    v = obj.get(key)
    if not isinstance(v, dict) or not all(isinstance(k, str) and isinstance(n, int) and n >= 0
                                          for k, n in v.items()):
        errors.append(f"histogram.{key}: must be an object of non-negative integers")
        return {}
    return v


def validate_corpus_json(cj, coverage=True):
    """Structural and arithmetic consistency of corpus.json (no block decoding)."""
    errors = []
    if cj.get("schema") != SCHEMA:
        return [f"schema is {cj.get('schema')!r}, expected {SCHEMA!r}"]
    for key in ("name", "generator", "go_algorand", "network", "files", "rounds", "txns",
                "txids_sha256", "histogram", "final_state"):
        if key not in cj:
            errors.append(f"missing key {key!r}")
    if errors:
        return errors
    files = cj["files"]
    for k in REQUIRED_FILES:
        if not isinstance(files.get(k), str) or not files[k]:
            errors.append(f"files.{k}: missing")
    r = cj["rounds"]
    if not (isinstance(r.get("first"), int) and isinstance(r.get("last"), int)
            and r.get("count") == r["last"] - r["first"] + 1 and r["first"] == 0):
        errors.append(f"rounds: inconsistent {r}")
    gen = cj["generator"]
    for k in ("version", "seed"):
        if not gen.get(k):
            errors.append(f"generator.{k}: missing")
    net = cj["network"]
    for k in ("genesis_id", "genesis_hash", "consensus_version"):
        if not net.get(k):
            errors.append(f"network.{k}: missing")
    if len(cj["txids_sha256"]) != 64:
        errors.append("txids_sha256: not a sha256 hex digest")
    h = cj["histogram"]
    types = _counts(h, "types", errors)
    subtypes = _counts(h, "subtypes", errors)
    inner = _counts(h, "inner_types", errors)
    feats = _counts(h, "features", errors)
    if sum(types.values()) != cj["txns"]:
        errors.append(f"histogram.types sums to {sum(types.values())}, txns is {cj['txns']}")
    for t, n in types.items():
        s = sum(v for k, v in subtypes.items() if k.split(".", 1)[0] == t)
        if s != n:
            errors.append(f"subtypes of {t} sum to {s}, types.{t} is {n}")
    for k in subtypes:
        if k.split(".", 1)[0] not in types:
            errors.append(f"subtype {k} has no type count")
    if sum(inner.values()) != feats.get("inner_txns", 0):
        errors.append("inner_types does not sum to features.inner_txns")
    if feats.get("grouped_txns", 0) < 2 * feats.get("groups", 0):
        errors.append("features.grouped_txns < 2 * groups")
    fs = cj["final_state"]
    if fs.get("round") != r.get("last"):
        errors.append(f"final_state.round {fs.get('round')} != rounds.last {r.get('last')}")
    if not str(fs.get("block_hash", "")).startswith("blk-"):
        errors.append("final_state.block_hash: missing")
    if coverage:
        errors += coverage_errors(cj)
    return errors


def coverage_errors(cj):
    h = cj.get("histogram", {})
    errors = [f"no {k} transactions" for k in REQUIRED_SUBTYPES
              if h.get("subtypes", {}).get(k, 0) == 0]
    errors += [f"features.{k} is zero" for k in REQUIRED_FEATURES
               if h.get("features", {}).get(k, 0) == 0]
    errors += [f"no inner {k} transactions" for k in REQUIRED_INNER
               if h.get("inner_types", {}).get(k, 0) == 0]
    return errors


def verify(d, coverage=True):
    errors = verify_manifest(d)
    try:
        cj = load_corpus_json(d)
    except (OSError, ValueError) as e:
        return errors + [f"corpus.json: {e}"]
    errors += validate_corpus_json(cj, coverage=coverage)
    for k, name in cj.get("files", {}).items():
        if isinstance(name, str) and not os.path.isfile(os.path.join(d, name)):
            errors.append(f"files.{k}: {name} missing")
    return errors


def _flatten(prefix, v, out):
    if isinstance(v, dict):
        for k in v:
            _flatten(f"{prefix}.{k}" if prefix else k, v[k], out)
    else:
        out[prefix] = v
    return out


def compare(a, b):
    """Differences between two corpora (empty list = byte-identical)."""
    diffs = []
    ma = {n: sha256_file(os.path.join(a, n)) for n in corpus_files(a)}
    mb = {n: sha256_file(os.path.join(b, n)) for n in corpus_files(b)}
    for n in sorted(set(ma) | set(mb)):
        if ma.get(n) != mb.get(n):
            diffs.append(f"file {n}: {ma.get(n, 'missing')[:16]} vs {mb.get(n, 'missing')[:16]}")
    try:
        fa = _flatten("", load_corpus_json(a), {})
        fb = _flatten("", load_corpus_json(b), {})
    except (OSError, ValueError) as e:
        return diffs + [f"corpus.json: {e}"]
    for k in sorted(set(fa) | set(fb)):
        if fa.get(k) != fb.get(k):
            diffs.append(f"corpus.json {k}: {fa.get(k)!r} vs {fb.get(k)!r}")
    return diffs


def pack(d, out, arcname=None):
    """Deterministic .tar.gz of a corpus directory: sorted entries, zero
    mtimes/uids, gzip mtime 0. Same corpus bytes give the same tarball with
    the same Python/zlib."""
    arcname = arcname or os.path.basename(os.path.normpath(d))
    names = corpus_files(d) + [MANIFEST]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        dir_info = tarfile.TarInfo(arcname)
        dir_info.type, dir_info.mode, dir_info.mtime = tarfile.DIRTYPE, 0o755, 0
        tar.addfile(dir_info)
        for n in sorted(names):
            p = os.path.join(d, n)
            info = tarfile.TarInfo(f"{arcname}/{n}")
            info.size, info.mode, info.mtime = os.path.getsize(p), 0o644, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with open(p, "rb") as f:
                tar.addfile(info, f)
    with open(out, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            gz.write(buf.getvalue())
    return out


def summary(cj):
    h = cj["histogram"]
    lines = [f"Corpus `{cj['name']}`: rounds {cj['rounds']['first']}..{cj['rounds']['last']}, "
             f"{cj['txns']} txns ({h['features'].get('inner_txns', 0)} inner), "
             f"seed `{cj['generator']['seed']}`, generator v{cj['generator']['version']}",
             "", "| kind | count |", "|---|---:|"]
    lines += [f"| {k} | {v} |" for k, v in sorted(h["subtypes"].items())]
    lines += [f"| inner {k} | {v} |" for k, v in sorted(h["inner_types"].items())]
    lines += [f"| {k} | {v} |" for k, v in sorted(h["features"].items())]
    return "\n".join(lines) + "\n"


# ---- msgpack records (block + certificate), standard library only -------------
#
# blocks.bin records hold the /v2/blocks/{r}?format=msgpack response body, a
# map {"block": ..., "cert": ...}. The checks below parse that structure
# instead of scanning bytes, so a corruption or a fetched body is tied to a
# specific field of a specific record (issue #2119).

BLOCKS_MAGIC = b"ACRPBLK1"


def parse_records(blocks):
    """[(round, payload_offset, payload_length)] of a blocks.bin's bytes."""
    if blocks[:8] != BLOCKS_MAGIC:
        raise ValueError("bad blocks.bin magic")
    out, i = [], 8
    while i < len(blocks):
        if i + 12 > len(blocks):
            raise ValueError("truncated record header")
        rnd = int.from_bytes(blocks[i:i + 8], "big")
        n = int.from_bytes(blocks[i + 8:i + 12], "big")
        if i + 12 + n > len(blocks):
            raise ValueError("truncated record payload")
        out.append((rnd, i + 12, n))
        i += 12 + n
    return out


def _mp_item(buf, i):
    """One msgpack item header at `i`: (kind, value, next). kind: int, nil,
    bool, float, str, bin, ext (value is the bytes or the number) or map /
    array (value is the element count, next the first element's offset).
    ValueError when the item (its header or its payload) is not entirely
    inside `buf`."""
    kind, v, nxt = _mp_item_unchecked(buf, i)
    if nxt > len(buf):
        raise ValueError(f"truncated msgpack item at offset {i}")
    return kind, v, nxt


def _mp_item_unchecked(buf, i):
    try:
        b = buf[i]
        if b <= 0x7f:
            return "int", b, i + 1
        if b >= 0xe0:
            return "int", b - 256, i + 1
        if 0x80 <= b <= 0x8f:
            return "map", b & 0xf, i + 1
        if 0x90 <= b <= 0x9f:
            return "array", b & 0xf, i + 1
        if 0xa0 <= b <= 0xbf:
            n = b & 0x1f
            return "str", buf[i + 1:i + 1 + n], i + 1 + n
        if b == 0xc0:
            return "nil", None, i + 1
        if b in (0xc2, 0xc3):
            return "bool", b == 0xc3, i + 1
        sizes = {0xc4: 1, 0xc5: 2, 0xc6: 4, 0xd9: 1, 0xda: 2, 0xdb: 4}
        if b in sizes:
            w = sizes[b]
            n = int.from_bytes(buf[i + 1:i + 1 + w], "big")
            s = i + 1 + w
            return ("bin" if b < 0xd0 else "str"), buf[s:s + n], s + n
        if b in (0xc7, 0xc8, 0xc9):
            w = {0xc7: 1, 0xc8: 2, 0xc9: 4}[b]
            n = int.from_bytes(buf[i + 1:i + 1 + w], "big")
            s = i + 1 + w + 1
            return "ext", buf[s:s + n], s + n
        if 0xd4 <= b <= 0xd8:
            n = 1 << (b - 0xd4)
            return "ext", buf[i + 2:i + 2 + n], i + 2 + n
        if b == 0xca:
            return "float", buf[i + 1:i + 5], i + 5
        if b == 0xcb:
            return "float", buf[i + 1:i + 9], i + 9
        if 0xcc <= b <= 0xcf:
            w = 1 << (b - 0xcc)
            return "int", int.from_bytes(buf[i + 1:i + 1 + w], "big"), i + 1 + w
        if 0xd0 <= b <= 0xd3:
            w = 1 << (b - 0xd0)
            return "int", int.from_bytes(buf[i + 1:i + 1 + w], "big", signed=True), i + 1 + w
        if b in (0xdc, 0xdd):
            w = 2 if b == 0xdc else 4
            return "array", int.from_bytes(buf[i + 1:i + 1 + w], "big"), i + 1 + w
        if b in (0xde, 0xdf):
            w = 2 if b == 0xde else 4
            return "map", int.from_bytes(buf[i + 1:i + 1 + w], "big"), i + 1 + w
    except IndexError:
        pass
    raise ValueError(f"malformed msgpack at offset {i}")


def _mp_skip(buf, i):
    pending = 1
    while pending:
        kind, v, i = _mp_item(buf, i)
        if i > len(buf):
            raise ValueError("truncated msgpack")
        pending -= 1
        if kind == "array":
            pending += v
        elif kind == "map":
            pending += 2 * v
    return i


def _mp_map(buf, i):
    """{key: (value_start, value_end)} of the map at `i` (str keys only)."""
    kind, n, j = _mp_item(buf, i)
    if kind != "map":
        raise ValueError("not a msgpack map")
    out = {}
    for _ in range(n):
        kk, key, j = _mp_item(buf, j)
        if kk != "str":
            raise ValueError("non-string map key")
        end = _mp_skip(buf, j)
        out[key.decode("utf-8", "replace")] = (j, end)
        j = end
    return out


def mp_decode(buf, i=0):
    """The msgpack value at `i` as Python data: maps are dicts keyed by
    str, bin is bytes. Returns (value, next_offset)."""
    kind, v, j = _mp_item(buf, i)
    if kind == "array":
        out = []
        for _ in range(v):
            x, j = mp_decode(buf, j)
            out.append(x)
        return out, j
    if kind == "map":
        out = {}
        for _ in range(v):
            kk, key, j = _mp_item(buf, j)
            if kk != "str":
                raise ValueError("non-string map key")
            x, j = mp_decode(buf, j)
            out[key.decode("utf-8", "replace")] = x
        return out, j
    if kind == "str":
        return v.decode("utf-8", "replace"), j
    return v, j


def block_round(payload):
    """The round of a block response record; ValueError unless the payload is
    a msgpack map holding a "block" map and a "cert". Round 0's header has
    no `rnd` key (it is omitted when zero)."""
    top = _mp_map(payload, 0)
    if "block" not in top or "cert" not in top:
        raise ValueError("not a block response: no block/cert")
    blk = _mp_map(payload, top["block"][0])
    if "rnd" not in blk:
        return 0
    kind, v, _ = _mp_item(payload, blk["rnd"][0])
    if kind != "int":
        raise ValueError("block rnd is not an integer")
    return v


def _cert_vote_offsets(payload):
    top = _mp_map(payload, 0)
    if "cert" not in top:
        raise ValueError("no cert in the record")
    cert = _mp_map(payload, top["cert"][0])
    if "vote" not in cert:
        raise ValueError("the certificate holds no votes")
    kind, n, j = _mp_item(payload, cert["vote"][0])
    if kind != "array" or n == 0:
        raise ValueError("the certificate holds no votes")
    out = []
    for _ in range(n):
        end = _mp_skip(payload, j)
        out.append((j, end))
        j = end
    return out


def cert_votes(payload):
    """The certificate's votes as decoded dicts ([] when it has none)."""
    try:
        offs = _cert_vote_offsets(payload)
    except ValueError:
        return []
    return [mp_decode(payload, s)[0] for s, _ in offs]


def vote_signature_last_byte_offset(payload):
    """Offset in `payload` of the last byte of the certificate's last vote's
    one-time signature `sig.s` (a 64-byte bin). ValueError if the record has
    no such vote."""
    start, _ = _cert_vote_offsets(payload)[-1]
    vote = _mp_map(payload, start)
    if "sig" not in vote:
        raise ValueError("the last vote has no sig")
    sig = _mp_map(payload, vote["sig"][0])
    if "s" not in sig:
        raise ValueError("the last vote's sig has no s")
    kind, data, nxt = _mp_item(payload, sig["s"][0])
    if kind != "bin" or len(data) != 64:
        raise ValueError("sig.s is not a 64-byte bin")
    return nxt - 1


def corrupt_vote(blocks_path, rnd=None):
    """Flip the low bit of the last byte of round `rnd`'s (default: the last
    record's) last vote signature in blocks.bin; returns (round, offset in
    the file)."""
    try:
        with open(blocks_path, "rb") as f:
            b = bytearray(f.read())
    except OSError as e:
        raise ValueError(f"cannot read {blocks_path}: {e}")
    recs = parse_records(bytes(b))
    if not recs:
        raise ValueError("blocks.bin holds no records")
    if rnd is None:
        r, off, n = recs[-1]
    else:
        found = [x for x in recs if x[0] == rnd]
        if not found:
            raise ValueError(f"blocks.bin has no record for round {rnd}")
        r, off, n = found[0]
    pos = off + vote_signature_last_byte_offset(bytes(b[off:off + n]))
    b[pos] ^= 1
    with open(blocks_path, "wb") as f:
        f.write(b)
    return r, pos


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("manifest").add_argument("dir")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    v.add_argument("--no-coverage", action="store_true")
    c = sub.add_parser("compare")
    c.add_argument("a")
    c.add_argument("b")
    p = sub.add_parser("pack")
    p.add_argument("dir")
    p.add_argument("out")
    sub.add_parser("summary").add_argument("dir")
    args = ap.parse_args(argv)
    if args.cmd == "manifest":
        print(write_manifest(args.dir))
        return 0
    if args.cmd == "verify":
        errors = verify(args.dir, coverage=not args.no_coverage)
        for e in errors:
            print(f"corpus: {args.dir}: {e}", file=sys.stderr)
        if not errors:
            cj = load_corpus_json(args.dir)
            print(f"corpus: {args.dir} OK ({cj['txns']} txns, rounds 0..{cj['rounds']['last']})")
        return 1 if errors else 0
    if args.cmd == "compare":
        diffs = compare(args.a, args.b)
        for d in diffs:
            print(f"corpus: differs: {d}", file=sys.stderr)
        if not diffs:
            print(f"corpus: {args.a} and {args.b} are byte-identical")
        return 1 if diffs else 0
    if args.cmd == "pack":
        print(pack(args.dir, args.out))
        print(f"sha256 {sha256_file(args.out)}")
        return 0
    if args.cmd == "summary":
        sys.stdout.write(summary(load_corpus_json(args.dir)))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
