#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Corpus statistics and history for the Phase 25 TEAL corpus check
(issue #2371, epic #2364).

  stats.py build CORPUS_DIR OUT_DIR [--opcodes FILE] [--commit SHA] [--machine S] [-o FILE]
  stats.py history STATS_JSON HISTORY_CSV [--date YYYY-MM-DD]

`build` aggregates the driver outputs in OUT_DIR (what `run_drivers.sh` wrote:
<op>.{go,rust}.jsonl, reassemble.summary.json), the corpus manifest and
corpus.json into one deterministic `stats.json` (default OUT_DIR/stats.json):
sorted keys, LF newlines, no timestamps, so the same inputs give the same bytes.

stats.json, schema "teal-corpus-stats/v1":

  run        {algod_rust_commit, go_algorand_tag, go_algorand_commit, machine}
             (the first two optional CLI inputs; the go tag/commit come from
             the go driver's output header)
  corpus     {registry_sha, fetched_at, programs, by_kind{approval,clear,shared},
              distinct_sources, total_bytes, size{min,p50,p90,p99,max},
              registry_hash_agreement{matching,total,rate}}
             `shared` = the same bytes used as approval and clear program.
             size percentiles are nearest-rank over program byte lengths.
  avm_versions  {"<version>": programs}
  opcodes    {histogram{name:{occurrences,programs}}, distinct_seen, table_size,
              coverage_rate, never_seen[], not_in_table[]}
             opcodes are the first token of every instruction line of go's
             disassembly of every program it disassembles; the table is
             OPCODES_FILE (`teal-corpus opcodes` of the go driver, i.e.
             logic.OpSpecs of the pinned go-algorand). never_seen = table
             opcodes no corpus program uses.
  stages     {disassemble|reassemble|source|rest_sample: {compared, identical,
              identical_error, mismatched, panics, timeouts,
              identical_panic_mirrored}}
             a stage whose go/rust outputs are absent is absent, never zero.
             Row semantics are `teal-corpus diff`'s: identical = equal rows
             that succeeded; identical_error = equal rows that failed without
             a panic/timeout; identical_panic_mirrored = equal go assembler
             scratch-index panics the port reproduces as a typed condition (#2381);
             panics/timeouts = rows on either side recording one (not mirrored);
             mismatched = rows that differ or exist on one side only.
  fixed_point  {programs, go_fixed, rust_fixed, go_rate, rust_rate,
              registry_hash_matching, registry_hash_compared, registry_hash_rate}
             from reassemble.summary.json (reassemble.py); null when absent.
  error_classes  {stage: {class: count}} over rows both sides reject
             identically; classes mask numbers (`N`, `0xN`), quoted strings and the
             token of a `did not parse:` error (template variable names).

`history` appends the headline numbers of a stats.json as one row of a CSV
series (docs/teal-corpus/history.csv). The row key is (date, registry_sha,
algod_rust_commit): re-running a day replaces that row instead of duplicating it.
Exit 0 on success, 2 on a usage or input error.
"""
import argparse
import csv
import json
import math
import os
import re
import sys

SCHEMA = "teal-corpus-stats/v1"

# (stage name, driver output stem). `reassemble` is the assemble driver over go's
# disassembly texts (run_drivers.sh), `source` over the original sources.
STAGES = (("disassemble", "disassemble"), ("reassemble", "reassemble"),
          ("source", "assemble"), ("rest_sample", "rest_sample"))

SCRATCH_PANIC = re.compile(r"^runtime error: index out of range \[[0-9]+\] with length 256$")
NUM = re.compile(r"0x[0-9a-fA-F]+|[0-9]+")
QUOTED = re.compile(r'"[^"]*"')
UNPARSED = re.compile(r"(did not parse: ).*")
HISTORY_FIELDS = (
    "date", "registry_sha", "algod_rust_commit", "go_algorand_tag", "programs", "approval", "clear", "shared",
    "distinct_sources", "total_bytes", "opcodes_seen", "opcodes_table",
    "disassemble_compared", "disassemble_mismatched", "reassemble_compared", "reassemble_mismatched",
    "source_compared", "source_mismatched", "panics", "timeouts",
    "go_fixed_rate", "rust_fixed_rate", "registry_hash_rate",
)


def read_rows(path):
    """(rows by sha256, header) of a driver JSONL file."""
    rows, header = {}, {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            v = json.loads(line)
            if "header" in v:
                header = v["header"]
            else:
                rows[v["sha256"]] = v
    return rows, header


def read_jsonl(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                out.append(json.loads(line))
    return out


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except OSError:
        return None


def rate(a, b):
    return round(a / b, 6) if b else None


def percentile(sorted_vals, p):
    """Nearest-rank percentile of an ascending list."""
    if not sorted_vals:
        return None
    return sorted_vals[max(0, math.ceil(p / 100 * len(sorted_vals)) - 1)]


def is_robustness(row):
    return row.get("panic") is not None or row.get("timeout") is True


def mirrored_panic(row):
    p = row.get("panic")
    return isinstance(p, str) and SCRATCH_PANIC.match(p) is not None


def error_class(row):
    """A stable, number-masked class of a failed row's first error."""
    msg = row.get("error")
    if msg is None:
        errs = row.get("errors") or []
        msg = errs[0].get("message", "") if errs and isinstance(errs[0], dict) else ""
    msg = UNPARSED.sub(r"\g<1>X", QUOTED.sub('"X"', msg))
    msg = NUM.sub(lambda m: "0xN" if m.group(0).startswith("0x") else "N", msg)
    return msg[:100] or "(empty)"


def stage_stats(go, rs):
    s = dict(compared=0, identical=0, identical_error=0, mismatched=0, panics=0, timeouts=0,
             identical_panic_mirrored=0)
    classes = {}
    for sha in sorted(set(go) | set(rs)):
        g, r = go.get(sha), rs.get(sha)
        s["compared"] += 1
        equal = g is not None and g == r
        mirrored = equal and mirrored_panic(g)
        for side in (g, r):
            if side is None or mirrored:
                continue
            s["panics"] += side.get("panic") is not None
            s["timeouts"] += side.get("timeout") is True
        if not equal:
            s["mismatched"] += 1
        elif mirrored:
            s["identical_panic_mirrored"] += 1
        elif g.get("ok"):
            s["identical"] += 1
        elif not is_robustness(g):
            s["identical_error"] += 1
            c = error_class(g)
            classes[c] = classes.get(c, 0) + 1
    return s, dict(sorted(classes.items(), key=lambda kv: (-kv[1], kv[0])))


def instruction_opcode(line):
    """The opcode of one disassembly line, None for pragmas, labels and comments."""
    t = line.split("//")[0].split()
    if not t or t[0].startswith("#") or t[0].endswith(":"):
        return None
    return t[0]


def opcode_stats(go_dis, table):
    occ, progs = {}, {}
    for row in go_dis.values():
        if not row.get("ok") or row.get("text") is None:
            continue
        seen = set()
        for line in row["text"].split("\n"):
            op = instruction_opcode(line)
            if op is None:
                continue
            occ[op] = occ.get(op, 0) + 1
            seen.add(op)
        for op in seen:
            progs[op] = progs.get(op, 0) + 1
    names = set(table)
    seen_in_table = names & set(occ)
    return {
        "histogram": {k: {"occurrences": occ[k], "programs": progs[k]} for k in sorted(occ)},
        "distinct_seen": len(seen_in_table),
        "table_size": len(names),
        "coverage_rate": rate(len(seen_in_table), len(names)),
        "never_seen": sorted(names - set(occ)),
        "not_in_table": sorted(set(occ) - names),
    }


def corpus_stats(corpus, manifest):
    info = read_json(os.path.join(corpus, "corpus.json")) or {}
    sizes = sorted(m["size"] for m in manifest)
    kinds = {"approval": 0, "clear": 0, "shared": 0}
    sources = set()
    versions = {}
    matching = 0
    for m in manifest:
        k = "shared" if m.get("kind") == "both" else m.get("kind")
        kinds[k] = kinds.get(k, 0) + 1
        if m.get("source_sha256"):
            sources.add(m["source_sha256"])
        sources.update(m.get("extra_source_sha256") or [])
        v = str(m.get("version"))
        versions[v] = versions.get(v, 0) + 1
        matching += bool(m.get("registry_hash_matches"))
    return {
        "registry_sha": info.get("registry_sha"),
        "fetched_at": info.get("fetched_at"),
        "programs": len(manifest),
        "by_kind": dict(sorted(kinds.items())),
        "distinct_sources": len(sources),
        "total_bytes": sum(sizes),
        "size": {"min": sizes[0] if sizes else None, "p50": percentile(sizes, 50),
                 "p90": percentile(sizes, 90), "p99": percentile(sizes, 99),
                 "max": sizes[-1] if sizes else None},
        "registry_hash_agreement": {"matching": matching, "total": len(manifest),
                                    "rate": rate(matching, len(manifest))},
    }, dict(sorted(versions.items(), key=lambda kv: (len(kv[0]), kv[0])))


def fixed_point_stats(out):
    summ = read_json(os.path.join(out, "reassemble.summary.json"))
    if not summ:
        return None
    fp, rh = summ.get("fixed_point") or {}, summ.get("registry_hash") or {}
    n = fp.get("programs", 0)
    return {
        "programs": n, "go_fixed": fp.get("go_fixed", 0), "rust_fixed": fp.get("rust_fixed", 0),
        "go_rate": rate(fp.get("go_fixed", 0), n), "rust_rate": rate(fp.get("rust_fixed", 0), n),
        "registry_hash_matching": rh.get("matching", 0), "registry_hash_compared": rh.get("compared", 0),
        "registry_hash_rate": rate(rh.get("matching", 0), rh.get("compared", 0)),
    }


def build_stats(corpus, out, opcodes_path=None, algod_rust_commit=None, machine=None):
    manifest = read_jsonl(os.path.join(corpus, "manifest.jsonl"))
    corpus_part, versions = corpus_stats(corpus, manifest)
    stages, classes, go_header = {}, {}, {}
    go_dis = {}
    for name, stem in STAGES:
        gp, rp = os.path.join(out, stem + ".go.jsonl"), os.path.join(out, stem + ".rust.jsonl")
        if not (os.path.isfile(gp) and os.path.isfile(rp)):
            continue
        g, gh = read_rows(gp)
        r, _ = read_rows(rp)
        stages[name], classes[name] = stage_stats(g, r)
        go_header = go_header or gh
        if name == "disassemble":
            go_dis = g
    table_doc = read_json(opcodes_path) if opcodes_path else None
    table = (table_doc or {}).get("opcodes") or {}
    run = {"algod_rust_commit": algod_rust_commit, "machine": machine,
           "go_algorand_tag": go_header.get("go_algorand_tag") or (table_doc or {}).get("go_algorand_tag"),
           "go_algorand_commit": go_header.get("go_algorand_commit") or (table_doc or {}).get("go_algorand_commit")}
    return {
        "schema": SCHEMA,
        "run": run,
        "corpus": corpus_part,
        "avm_versions": versions,
        "opcodes": opcode_stats(go_dis, table) if go_dis else None,
        "stages": stages,
        "fixed_point": fixed_point_stats(out),
        "error_classes": classes,
    }


def write_json(path, doc):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")


def history_row(stats, date):
    c, st, fp, op = stats["corpus"], stats["stages"], stats.get("fixed_point") or {}, stats.get("opcodes") or {}

    def stage(name, key):
        return st[name][key] if name in st else ""

    return {
        "date": date, "registry_sha": c["registry_sha"] or "",
        "algod_rust_commit": stats["run"].get("algod_rust_commit") or "",
        "go_algorand_tag": stats["run"].get("go_algorand_tag") or "",
        "programs": c["programs"], "approval": c["by_kind"].get("approval", 0),
        "clear": c["by_kind"].get("clear", 0), "shared": c["by_kind"].get("shared", 0),
        "distinct_sources": c["distinct_sources"], "total_bytes": c["total_bytes"],
        "opcodes_seen": op.get("distinct_seen", ""), "opcodes_table": op.get("table_size", ""),
        "disassemble_compared": stage("disassemble", "compared"),
        "disassemble_mismatched": stage("disassemble", "mismatched"),
        "reassemble_compared": stage("reassemble", "compared"),
        "reassemble_mismatched": stage("reassemble", "mismatched"),
        "source_compared": stage("source", "compared"), "source_mismatched": stage("source", "mismatched"),
        "panics": sum(s["panics"] for s in st.values()), "timeouts": sum(s["timeouts"] for s in st.values()),
        "go_fixed_rate": "" if fp.get("go_rate") is None else fp["go_rate"],
        "rust_fixed_rate": "" if fp.get("rust_rate") is None else fp["rust_rate"],
        "registry_hash_rate": "" if fp.get("registry_hash_rate") is None else fp["registry_hash_rate"],
    }


def append_history(stats_path, csv_path, date):
    with open(stats_path, encoding="utf-8") as f:
        row = history_row(json.load(f), date)
    rows = []
    if os.path.isfile(csv_path):
        with open(csv_path, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
    key = (row["date"], row["registry_sha"], row["algod_rust_commit"])
    rows = [r for r in rows if (r["date"], r["registry_sha"], r["algod_rust_commit"]) != key]
    rows.append({k: str(v) for k, v in row.items()})
    rows.sort(key=lambda r: (r["date"], r["registry_sha"], r["algod_rust_commit"]))
    os.makedirs(os.path.dirname(os.path.abspath(csv_path)), exist_ok=True)
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=HISTORY_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("corpus")
    b.add_argument("out")
    b.add_argument("--opcodes", help="opcode table JSON from `teal-corpus opcodes` (go driver)")
    b.add_argument("--commit", help="algod-rust commit the Rust driver was built from")
    b.add_argument("--machine", help="free-form machine description")
    b.add_argument("-o", dest="dest", help="output file (default OUT_DIR/stats.json)")
    h = sub.add_parser("history")
    h.add_argument("stats")
    h.add_argument("csv")
    h.add_argument("--date", help="UTC date of the run (default today)")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        if a.cmd == "build":
            doc = build_stats(a.corpus, a.out, a.opcodes, a.commit, a.machine)
            write_json(a.dest or os.path.join(a.out, "stats.json"), doc)
        else:
            import datetime
            date = a.date or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
            append_history(a.stats, a.csv, date)
    except (OSError, ValueError, KeyError) as e:
        print(f"stats.py: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
