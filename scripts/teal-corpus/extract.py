#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Extract a de-duplicated TEAL program/source corpus from an ARC56Registry
checkout (issue #2365, epic #2364).

  python3 -I scripts/teal-corpus/extract.py [--work-dir D] [--out D] [--clean]

Reads `<registry>/{approval,clear}-programs/<hash[:3]>/<hash>.arc56.json` as
untrusted data (never executed, symlinks never followed) and writes:

  programs/<sha256>.bin     decoded bytecode, de-duplicated across approval/clear
  sources/<sha256>.teal     decoded original TEAL (sha256 of the source bytes)
  manifest.jsonl            one row per program, sorted by sha256
  corpus.json               registry SHA, fetch time, counts, skip reasons

Output is deterministic for a given checkout: sorted walk, sorted keys, LF
newlines, no extraction-time timestamps (`fetched_at` comes from fetch.json).
Malformed entries are counted by reason, never fatal.
"""
import argparse
import base64
import binascii
import hashlib
import json
import os
import shutil
import sys

KINDS = (("approval", "approval-programs-moved"), ("clear", "clear-programs-moved"))
SUFFIX = ".arc56.json"
DEFAULT_WORK = "teal-corpus-work"


def decode_b64(value):
    """Strict base64 -> bytes, or None when not a valid base64 string."""
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def first_varuint(data):
    """First unsigned varint of data (the AVM version), or None if truncated/overlong."""
    v = 0
    for i, b in enumerate(data[:10]):
        v |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return v
    return None


def iter_entries(registry, dirname):
    """Yield (relative posix path, absolute path, unusable) sorted, never following symlinks."""
    root = os.path.join(registry, dirname)
    if not os.path.isdir(root) or os.path.islink(root):
        return
    for sub in sorted(os.listdir(root)):
        sdir = os.path.join(root, sub)
        if os.path.islink(sdir) or not os.path.isdir(sdir):
            continue
        for name in sorted(os.listdir(sdir)):
            if not name.endswith(SUFFIX):
                continue
            path = os.path.join(sdir, name)
            rel = "%s/%s/%s" % (dirname, sub, name)
            yield rel, path, os.path.islink(path) or not os.path.isfile(path)


def has_template_vars(spec, program, source):
    tv = spec.get("templateVariables")
    if isinstance(tv, (dict, list)) and len(tv) > 0:
        return True
    if source is not None and b"TMPL_" in source:
        return True
    return b"TMPL_" in program


def extract(registry, out, registry_sha=None, fetched_at=None):
    skipped = {}
    counts = {"entries": 0, "programs": 0, "sources": 0, "orphan_sources": 0,
              "duplicate_entries": 0, "registry_hash_mismatch": 0,
              "template_var_programs": 0, "unknown_version": 0}

    def skip(reason):
        skipped[reason] = skipped.get(reason, 0) + 1

    programs = {}  # sha -> row
    sources = {}   # sha -> bytes

    for kind, dirname in KINDS:
        for rel, path, bad in iter_entries(registry, dirname):
            counts["entries"] += 1
            if bad:
                skip("not_a_regular_file")
                continue
            try:
                with open(path, "rb") as f:
                    raw = f.read()
                spec = json.loads(raw.decode("utf-8"))
            except (OSError, ValueError, RecursionError):
                skip("invalid_json")
                continue
            if not isinstance(spec, dict):
                skip("not_an_object")
                continue

            src_bytes = None
            src_field = spec.get("source")
            if isinstance(src_field, dict) and src_field.get(kind) not in (None, ""):
                src_bytes = decode_b64(src_field.get(kind))
                if src_bytes is None:
                    skip("source_invalid_base64")
                elif len(src_bytes) == 0:
                    src_bytes = None
            src_sha = None
            if src_bytes is not None:
                src_sha = hashlib.sha256(src_bytes).hexdigest()
                sources[src_sha] = src_bytes

            bc = spec.get("byteCode")
            enc = bc.get(kind) if isinstance(bc, dict) else None
            if enc is None:
                if src_bytes is not None:
                    skip("source_without_bytecode")
                    counts["orphan_sources"] += 1
                else:
                    skip("missing_bytecode")
                continue
            prog = decode_b64(enc)
            if prog is None:
                skip("invalid_base64")
                continue
            if len(prog) == 0:
                skip("empty_program")
                continue

            sha = hashlib.sha256(prog).hexdigest()
            reg_hash = os.path.basename(path)[: -len(SUFFIX)]
            tmpl = has_template_vars(spec, prog, src_bytes)
            row = programs.get(sha)
            if row is None:
                programs[sha] = {
                    "sha256": sha,
                    "kind": kind,
                    "size": len(prog),
                    "version": first_varuint(prog),
                    "registry_path": rel,
                    "registry_hash": reg_hash,
                    "registry_hash_matches": reg_hash == sha,
                    "source_sha256": src_sha,
                    "extra_source_sha256": [],
                    "has_template_vars": tmpl,
                    "_bin": prog,
                }
                continue
            counts["duplicate_entries"] += 1
            if row["kind"] != kind:
                row["kind"] = "both"
            row["has_template_vars"] = row["has_template_vars"] or tmpl
            if src_sha is not None:
                if row["source_sha256"] is None:
                    row["source_sha256"] = src_sha
                elif src_sha != row["source_sha256"] and src_sha not in row["extra_source_sha256"]:
                    row["extra_source_sha256"].append(src_sha)
            if reg_hash == sha and not row["registry_hash_matches"]:
                row["registry_hash"], row["registry_path"] = reg_hash, rel
                row["registry_hash_matches"] = True

    os.makedirs(os.path.join(out, "programs"))
    os.makedirs(os.path.join(out, "sources"))
    for sha in sorted(programs):
        with open(os.path.join(out, "programs", sha + ".bin"), "wb") as f:
            f.write(programs[sha].pop("_bin"))
    for sha in sorted(sources):
        with open(os.path.join(out, "sources", sha + ".teal"), "wb") as f:
            f.write(sources[sha])
    by_kind = {}
    by_version = {}
    with open(os.path.join(out, "manifest.jsonl"), "w", newline="\n") as f:
        for sha in sorted(programs):
            row = programs[sha]
            row["extra_source_sha256"].sort()
            f.write(json.dumps(row, sort_keys=True) + "\n")
            if row["version"] is None:
                counts["unknown_version"] += 1
            if not row["registry_hash_matches"]:
                counts["registry_hash_mismatch"] += 1
            if row["has_template_vars"]:
                counts["template_var_programs"] += 1
            by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
            k = str(row["version"])
            by_version[k] = by_version.get(k, 0) + 1
    counts["programs"] = len(programs)
    counts["sources"] = len(sources)
    counts["programs_with_source"] = sum(1 for r in programs.values() if r["source_sha256"])
    corpus = {
        "registry_sha": registry_sha,
        "fetched_at": fetched_at,
        "counts": counts,
        "programs_by_kind": by_kind,
        "programs_by_version": by_version,
        "skipped": skipped,
    }
    with open(os.path.join(out, "corpus.json"), "w", newline="\n") as f:
        json.dump(corpus, f, indent=2, sort_keys=True)
        f.write("\n")
    return corpus


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--work-dir", default=os.environ.get("TEAL_CORPUS_WORK_DIR", DEFAULT_WORK))
    ap.add_argument("--registry-dir", help="registry checkout (default <work-dir>/registry)")
    ap.add_argument("--fetch-info", help="fetch.json from fetch.py (default <work-dir>/fetch.json)")
    ap.add_argument("--registry-sha", default=os.environ.get("TEAL_CORPUS_REGISTRY_SHA"),
                    help="registry commit SHA to record (overrides fetch.json)")
    ap.add_argument("--out", help="output directory (default <work-dir>/corpus)")
    ap.add_argument("--clean", action="store_true", help="replace a non-empty output directory")
    args = ap.parse_args(argv)

    work = args.work_dir
    registry = args.registry_dir or os.path.join(work, "registry")
    out = args.out or os.path.join(work, "corpus")
    info_path = args.fetch_info or os.path.join(work, "fetch.json")
    sha, fetched_at = args.registry_sha, None
    if os.path.isfile(info_path):
        with open(info_path, encoding="utf-8") as f:
            info = json.load(f)
        fetched_at = info.get("fetched_at")
        sha = sha or info.get("registry_sha")
    if not os.path.isdir(registry):
        raise SystemExit("error: registry checkout %s not found (run fetch.py first)" % registry)
    if os.path.exists(out) and os.listdir(out):
        if not args.clean:
            raise SystemExit("error: %s is not empty; pass --clean to replace it" % out)
        shutil.rmtree(out)
    os.makedirs(out, exist_ok=True)
    corpus = extract(registry, out, sha, fetched_at)
    print(json.dumps(corpus, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
