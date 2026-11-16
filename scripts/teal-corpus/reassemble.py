#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Reassembly stage of the Phase 25 TEAL corpus check (issue #2368, epic #2364).

The stage takes go-algorand's disassembly `T` of every corpus program `P` and
checks that both assemblers turn `T` into the same bytecode, program hash and
(on failure) ordered error list and warnings. It is driven in two halves by
`run_drivers.sh` (stage `reassemble`) around the ordinary `assemble` drivers:

    reassemble.py prepare OUT_DIR           # after the disassemble stage
    reassemble.py report CORPUS_DIR OUT_DIR # after the assemble drivers

`prepare` reads OUT_DIR/disassemble.{go,rust}.jsonl and writes the disassembled
texts as two driver corpora, OUT_DIR/reasm-go/sources/<sha256(T)>.teal (go's
text, the gated input) and OUT_DIR/reasm-rust/sources/ (Rust's own text, for the
cross-check, so the gate does not silently depend on disassembly parity).

`report` reads the three assemble outputs
(OUT_DIR/reassemble.go.jsonl: go.assemble(T_go),
OUT_DIR/reassemble.rust.jsonl: rust.assemble(T_go),
OUT_DIR/reassemble.rust-text.jsonl: rust.assemble(T_rust)) and prints and writes
(OUT_DIR/reassemble.summary.json, OUT_DIR/reassemble.mismatches.jsonl):

* gate: compared / identical bytecode / identical errors / mismatched / panics /
  timeouts for go.assemble(T) vs rust.assemble(T);
* gate: rust.assemble(rust.disassemble(P)) == go.assemble(go.disassemble(P));
* statistics (never a gate): the fixed point assemble(disassemble(P)) == P per
  implementation, whether both implementations leave the same programs off it
  with the same bytes, and sha256(assemble(disassemble(P))) vs the registry hash.

Exit 0 when both gates are clean, 1 on any mismatch/panic/timeout, 2 on a
usage or input error.
"""
import base64
import hashlib
import json
import os
import sys


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def read_rows(path):
    rows, header = {}, {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            v = json.loads(line)
            if "header" in v:
                header = v["header"]
            else:
                rows[v["sha256"]] = v
    return rows, header


def strip_sha(row):
    return {k: v for k, v in row.items() if k != "sha256"}


def is_robustness(row):
    return row.get("panic") is not None or row.get("timeout") is True


def prepare(out):
    for impl in ("go", "rust"):
        rows, _ = read_rows(os.path.join(out, f"disassemble.{impl}.jsonl"))
        d = os.path.join(out, f"reasm-{impl}", "sources")
        os.makedirs(d, exist_ok=True)
        for name in os.listdir(d):
            os.remove(os.path.join(d, name))
        n = 0
        for r in rows.values():
            if r.get("ok") and r.get("text") is not None:
                data = r["text"].encode("utf-8")
                with open(os.path.join(d, sha256_hex(data) + ".teal"), "wb") as f:
                    f.write(data)
                n += 1
        print(f"reassemble prepare: {impl}: {n} disassembled texts", file=sys.stderr)


def text_sha(row):
    if row.get("ok") and row.get("text") is not None:
        return sha256_hex(row["text"].encode("utf-8"))
    return None


def report(corpus, out):
    dgo, _ = read_rows(os.path.join(out, "disassemble.go.jsonl"))
    drs, _ = read_rows(os.path.join(out, "disassemble.rust.jsonl"))
    ago, _ = read_rows(os.path.join(out, "reassemble.go.jsonl"))
    ars, _ = read_rows(os.path.join(out, "reassemble.rust.jsonl"))
    arst, _ = read_rows(os.path.join(out, "reassemble.rust-text.jsonl"))
    manifest = {}
    mpath = os.path.join(corpus, "manifest.jsonl")
    if os.path.exists(mpath):
        with open(mpath, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    m = json.loads(line)
                    manifest[m["sha256"]] = m

    mismatches = []
    # Gate 1: go.assemble(T) vs rust.assemble(T), over the distinct texts.
    g1 = dict(compared=0, identical_ok=0, identical_errors=0, mismatched=0,
              panics=0, timeouts=0, warnings_identical=0)
    for sha in sorted(set(ago) | set(ars)):
        l, r = ago.get(sha), ars.get(sha)
        g1["compared"] += 1
        for side in (l, r):
            if side is not None and side.get("panic") is not None:
                g1["panics"] += 1
            if side is not None and side.get("timeout") is True:
                g1["timeouts"] += 1
        if l is not None and l == r:
            if l.get("ok"):
                g1["identical_ok"] += 1
                if l.get("warnings"):
                    g1["warnings_identical"] += 1
            elif not is_robustness(l):
                g1["identical_errors"] += 1
            continue
        g1["mismatched"] += 1
        keys = sorted(set(l or {}) | set(r or {}))
        field = next((k for k in keys if (l or {}).get(k) != (r or {}).get(k)), "row")
        mismatches.append({"gate": "reassemble", "sha256": sha, "field": field,
                           "left": (l or {}).get(field), "right": (r or {}).get(field)})

    # Gate 2: rust.assemble(rust.disassemble(P)) == go.assemble(go.disassemble(P)).
    g2 = dict(programs=0, identical=0, mismatched=0)
    programs = sorted(set(dgo) | set(drs))
    for p in programs:
        g2["programs"] += 1
        gd, rd = dgo.get(p), drs.get(p)
        gt = text_sha(gd) if gd else None
        rt = text_sha(rd) if rd else None
        if gt is None and rt is None:
            # Both disassemblies failed: equal only when the errors are equal.
            if (gd or {}).get("error") == (rd or {}).get("error"):
                g2["identical"] += 1
            else:
                g2["mismatched"] += 1
                mismatches.append({"gate": "cross-check", "sha256": p, "field": "disassemble.error",
                                   "left": (gd or {}).get("error"), "right": (rd or {}).get("error")})
            continue
        gr = ago.get(gt) if gt else None
        rr = arst.get(rt) if rt else None
        if gr is not None and rr is not None and strip_sha(gr) == strip_sha(rr):
            g2["identical"] += 1
        else:
            g2["mismatched"] += 1
            mismatches.append({"gate": "cross-check", "sha256": p, "field": "assemble(disassemble(P))",
                               "left": strip_sha(gr) if gr else None,
                               "right": strip_sha(rr) if rr else None})

    # Statistics: fixed point and registry hash.
    def fixed_point(dis, asm):
        fixed, off = 0, {}
        for p in programs:
            d = dis.get(p)
            t = text_sha(d) if d else None
            if t is None:
                continue
            a = asm.get(t)
            prog = None
            try:
                with open(os.path.join(corpus, "programs", p + ".bin"), "rb") as f:
                    prog = f.read()
            except OSError:
                pass
            if a is not None and a.get("ok") and prog is not None \
                    and base64.b64decode(a["bytecode_b64"]) == prog:
                fixed += 1
            else:
                off[p] = (a or {}).get("bytecode_b64") if a and a.get("ok") else \
                    "error:" + json.dumps((a or {}).get("errors"), sort_keys=True)
        return fixed, off

    gofix, gooff = fixed_point(dgo, ago)
    rsfix, rsoff = fixed_point(drs, arst)
    same_set = set(gooff) == set(rsoff)
    same_bytes = same_set and all(gooff[p] == rsoff[p] for p in gooff)
    reg_match = reg_total = 0
    for p in programs:
        m = manifest.get(p)
        d = dgo.get(p)
        t = text_sha(d) if d else None
        a = ago.get(t) if t else None
        if m is None or a is None or not a.get("ok"):
            continue
        reg_total += 1
        if sha256_hex(base64.b64decode(a["bytecode_b64"])) == m.get("registry_hash"):
            reg_match += 1

    summary = {
        "gate_reassemble": g1,
        "gate_cross_check": g2,
        "fixed_point": {
            "programs": len([p for p in programs if p in dgo and dgo[p].get("ok")]),
            "go_fixed": gofix, "rust_fixed": rsfix,
            "go_non_round_tripping": len(gooff), "rust_non_round_tripping": len(rsoff),
            "same_set": same_set, "same_bytes": same_bytes,
            "non_round_tripping_programs": sorted(gooff),
        },
        "registry_hash": {"compared": reg_total, "matching": reg_match},
        "mismatches": len(mismatches),
    }
    with open(os.path.join(out, "reassemble.mismatches.jsonl"), "w", encoding="utf-8") as f:
        for m in mismatches:
            f.write(json.dumps(m, sort_keys=True) + "\n")
    with open(os.path.join(out, "reassemble.summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")
    short = dict(summary)
    short["fixed_point"] = {k: v for k, v in summary["fixed_point"].items()
                            if k != "non_round_tripping_programs"}
    print(json.dumps(short, indent=2, sort_keys=True), file=sys.stderr)
    bad = g1["mismatched"] or g1["panics"] or g1["timeouts"] or g2["mismatched"]
    return 1 if bad else 0


def main():
    a = sys.argv[1:]
    if len(a) == 2 and a[0] == "prepare":
        prepare(a[1])
        return 0
    if len(a) == 3 and a[0] == "report":
        return report(a[1], a[2])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
