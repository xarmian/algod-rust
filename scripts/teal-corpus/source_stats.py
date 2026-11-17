#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Original-source parity report (issue #2369, epic #2364).

    source_stats.py CORPUS_DIR OUT_DIR

Reads OUT_DIR/assemble.go.jsonl and OUT_DIR/assemble.rust.jsonl (the `assemble`
operation of both drivers over CORPUS_DIR/sources, source maps included), the
corpus manifest and the registry specs (CORPUS_DIR/../registry/<registry_path>).

Gate (exit 1 on any failure): per source the two rows must be identical in
bytecode, program hash, source map (version, sources, names, mappings), warnings
and, on failure, the ordered error list; no panic and no timeout on either side.
Statistics (informational): how many sources assemble, how many assemble to the
byteCode the spec ships, and the breakdown by `#pragma version` and by the
spec's compilerInfo generator. TMPL_* sources are compared like every other
source (their rows are error rows). Writes OUT_DIR/source.summary.json and
OUT_DIR/source.mismatches.jsonl, prints the summary to stderr.
"""
import base64
import json
import os
import sys

FIELDS = ("bytecode_b64", "hash", "sourcemap", "warnings", "errors", "error", "ok")


def read_rows(path):
    rows = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            v = json.loads(line)
            if "header" in v:
                continue
            rows[v["sha256"]] = v
    return rows


def read_manifest(corpus):
    out = []
    with open(os.path.join(corpus, "manifest.jsonl"), encoding="utf-8") as f:
        for line in f:
            if line.strip():
                out.append(json.loads(line))
    return out


def generator_of(corpus, entry):
    """compilerInfo.compiler of the entry's registry spec, 'unknown' when absent."""
    rel = entry.get("registry_path")
    if rel:
        path = os.path.join(corpus, "..", "registry", rel)
        try:
            with open(path, encoding="utf-8") as f:
                info = json.load(f).get("compilerInfo") or {}
            return info.get("compiler") or "unknown"
        except (OSError, ValueError):
            pass
    return "unknown"


def source_pragma_version(corpus, sha):
    """The value of the source's own `#pragma version`, or "none"."""
    try:
        with open(os.path.join(corpus, "sources", sha + ".teal"), encoding="utf-8", errors="replace") as f:
            for line in f:
                t = line.split("//")[0].split()
                if len(t) >= 3 and t[0] == "#pragma" and t[1] == "version":
                    return t[2]
    except OSError:
        pass
    return "none"


def mismatch_field(g, r):
    for k in FIELDS:
        if g.get(k) != r.get(k):
            return k
    return "row" if g != r else None


def report(corpus, out):
    go = read_rows(os.path.join(out, "assemble.go.jsonl"))
    rs = read_rows(os.path.join(out, "assemble.rust.jsonl"))
    mism, by_field = [], {}
    for sha in sorted(set(go) | set(rs)):
        g, r = go.get(sha), rs.get(sha)
        if g is None or r is None:
            f = "row"
        else:
            f = mismatch_field(g, r)
        if f is not None:
            by_field[f] = by_field.get(f, 0) + 1
            mism.append({"sha256": sha, "field": f, "left": g, "right": r})
    robust = [x for x in list(go.values()) + list(rs.values()) if "panic" in x or x.get("timeout")]
    assembled = [x for x in go.values() if x.get("ok")]

    per_ver, per_gen = {}, {}
    equal = programs = tmpl_programs = tmpl_identical = 0
    seen_equal_sources = set()
    for e in read_manifest(corpus):
        src = e.get("source_sha256")
        if not src or src not in go:
            continue
        programs += 1
        row = go[src]
        shipped = None
        try:
            with open(os.path.join(corpus, "programs", e["sha256"] + ".bin"), "rb") as f:
                shipped = f.read()
        except OSError:
            pass
        ok = bool(row.get("ok"))
        eq = ok and shipped is not None and base64.b64decode(row["bytecode_b64"]) == shipped
        equal += eq
        if eq:
            seen_equal_sources.add(src)
        for table, key in ((per_ver, str(e.get("version"))), (per_gen, generator_of(corpus, e))):
            t = table.setdefault(key, {"programs": 0, "assemble": 0, "equal_shipped": 0})
            t["programs"] += 1
            t["assemble"] += ok
            t["equal_shipped"] += eq
        if e.get("has_template_vars"):
            tmpl_programs += 1
            if src in rs and go[src] == rs[src] and not ok:
                tmpl_identical += 1

    per_pragma = {}
    for sha, row in go.items():
        t = per_pragma.setdefault(source_pragma_version(corpus, sha), {"sources": 0, "assemble": 0})
        t["sources"] += 1
        t["assemble"] += bool(row.get("ok"))

    summary = {
        "sources": len(go),
        "assemble": len(assembled),
        "error": sum(1 for x in go.values() if not x.get("ok") and "panic" not in x and not x.get("timeout")),
        "identical": sum(1 for s, g in go.items() if s in rs and g == rs[s] and g.get("ok")),
        "both_error_identical": sum(1 for s, g in go.items()
                                    if s in rs and g == rs[s] and not g.get("ok") and "panic" not in g and not g.get("timeout")),
        "mismatched": len(mism),
        "mismatched_by_field": dict(sorted(by_field.items())),
        "panics": sum(1 for x in robust if "panic" in x),
        "timeouts": sum(1 for x in robust if x.get("timeout")),
        "programs_with_source": programs,
        "equal_shipped_bytecode": equal,
        "equal_shipped_sources": len(seen_equal_sources),
        "by_program_version": dict(sorted(per_ver.items(), key=lambda kv: (len(kv[0]), kv[0]))),
        "by_source_pragma_version": dict(sorted(per_pragma.items(), key=lambda kv: (len(kv[0]), kv[0]))),
        "by_generator": dict(sorted(per_gen.items())),
        "template_variable_sources": {"programs": tmpl_programs, "both_error_identical": tmpl_identical},
    }
    with open(os.path.join(out, "source.mismatches.jsonl"), "w", encoding="utf-8") as f:
        for m in mism:
            f.write(json.dumps(m, sort_keys=True) + "\n")
    with open(os.path.join(out, "source.summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(summary, indent=2, sort_keys=True), file=sys.stderr)
    return 1 if (mism or robust) else 0


def main():
    a = sys.argv[1:]
    if len(a) == 2:
        return report(a[0], a[1])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
