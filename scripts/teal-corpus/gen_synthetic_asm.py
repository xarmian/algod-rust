#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Generate a synthetic, adversarial assembler corpus (issue #2368, epic #2364).

The registry corpus only holds programs real compilers emitted, whose
disassembly never exercises most of the assembler's static type tracking
(`type_track.rs`, a port of go's `ProgramKnowledge`). This tool writes TEAL
sources that do, in the layout the drivers read (`OUT/sources/<sha256>.teal`),
for `scripts/teal-corpus/run_drivers.sh OUT OUTDIR assemble`:

    gen_synthetic_asm.py OUT_DIR [--seed N] [--random N] [--versions 3,8,14]

* every opcode of `go_op_types.jsonl` (the go dump the tracker's table is
  generated from) at every requested version, preceded by every combination of
  typed pushes (uint64, short/long/32-byte byte strings, typed field reads) for
  its arguments (capped for wide opcodes), with every field name of its group
  and small numeric immediates;
* `--random` programs built from a vocabulary of stack, scratch, frame,
  subroutine and branch instructions (so dead code, label resets, `proto`,
  `frame_dig`/`frame_bury`, `bury`, `cover`, `popn`, `loads`, ... meet every
  state of the tracker).

Deterministic for a given seed.
"""
import argparse
import hashlib
import itertools
import json
import os
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE = ROOT / "crates/core/algo-avm/tests/fixtures/go_op_types.jsonl"

PUSHES = [
    "int 1",
    "int 200",
    "byte 0x01",
    "byte 0x" + "ab" * 32,
    "byte 0x" + "cd" * 70,
    "txn Sender",
    "txn Fee",
    "global GroupSize",
    "byte 0x",
]
SMALL_IMMS = ["0", "1", "2", "7", "255"]

# Skipped: assembler-structural opcodes the combinatorial sweep cannot drive
# meaningfully (their own tests cover them) or that need label operands.
SKIP = {"intcblock", "bytecblock", "pushbytess", "pushints", "switch", "match"}
BRANCHES = {"b", "bz", "bnz", "callsub"}


def load():
    rows = [json.loads(l) for l in FIXTURE.read_text(encoding="utf-8").splitlines() if l.strip()]
    ops = [r for r in rows if r["kind"] == "op"]
    groups = {}
    for r in rows:
        if r["kind"] == "field":
            groups.setdefault(r["group"], []).append(r["field"])
    return ops, groups


def imm_variants(op, groups):
    """Immediate-argument lists to try for `op`: every field of a group in turn
    (other immediates small numbers), capped."""
    imms = op.get("imms", [])
    if not imms:
        return [[]]
    pools = []
    for im in imms:
        if im.get("group"):
            pools.append(groups[im["group"]][:60])
        else:
            pools.append(SMALL_IMMS)
    out = []
    for combo in itertools.islice(itertools.product(*pools), 400):
        out.append(list(combo))
    return out


def op_arity(op, version):
    var = [v for v in op["variants"] if v["from"] <= version]
    return len(var[-1]["args"]) if var else None


def combos(arity, rnd, cap=48):
    if arity == 0:
        return [[]]
    full = list(itertools.product(PUSHES, repeat=arity))
    if len(full) <= cap:
        return [list(c) for c in full]
    return [list(c) for c in rnd.sample(full, cap)]


VOCAB = [
    "int 1", "int 0", "int 3", "byte 0x01", "byte 0xabcd", "byte 0x" + "11" * 32,
    "txn Sender", "txn Fee", "global ZeroAddress", "global GroupSize",
    "pop", "dup", "dup2", "swap", "dig 1", "dig 2", "bury 1", "bury 2", "cover 1",
    "cover 2", "uncover 1", "uncover 2", "popn 1", "popn 2", "dupn 1", "dupn 2",
    "select", "+", "-", "len", "itob", "btoi", "concat", "b+", "b==", "==", "!", "&&",
    "store 0", "store 1", "load 0", "load 1", "loads", "stores",
    "extract 0 2", "extract3", "substring 0 1", "bzero", "sha256", "assert",
    "setbit", "getbit", "frame_dig -1", "frame_dig 0", "frame_bury 0", "frame_bury -1",
    "box_len", "app_global_get", "app_local_get", "app_global_put",
    "return", "err", "retsub",
    "pushints 1 2", "pushbytess 0x01 0x02", "balance",
]
LABELS = ["L0", "L1", "L2"]


def random_program(rnd, version, max_len=14):
    lines = [f"#pragma version {version}"]
    n = rnd.randint(2, max_len)
    open_labels = set()
    for _ in range(n):
        r = rnd.random()
        if r < 0.10:
            lab = rnd.choice(LABELS)
            lines.append(f"{lab}:")
            open_labels.add(lab)
        elif r < 0.17:
            lines.append(rnd.choice(["b", "bz", "bnz", "callsub"]) + " " + rnd.choice(LABELS))
        elif r < 0.21 and version >= 8:
            lines.append(f"proto {rnd.randint(0, 3)} {rnd.randint(0, 2)}")
        else:
            lines.append(rnd.choice(VOCAB))
    for lab in LABELS:  # mostly define every referenced label
        if lab not in open_labels and rnd.random() < 0.9:
            lines.append(f"{lab}:")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--seed", type=int, default=2368)
    ap.add_argument("--random", type=int, default=60000)
    ap.add_argument("--versions", default="3,8,14")
    ap.add_argument("--cap", type=int, default=48)
    ap.add_argument("--max-len", type=int, default=14)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    sdir = os.path.join(a.out, "sources")
    os.makedirs(sdir, exist_ok=True)
    seen = set()

    def emit(text):
        data = text.encode()
        sha = hashlib.sha256(data).hexdigest()
        if sha in seen:
            return
        seen.add(sha)
        with open(os.path.join(sdir, sha + ".teal"), "wb") as f:
            f.write(data)

    ops, groups = load()
    versions = [int(v) for v in a.versions.split(",") if v]
    for version in versions:
        for op in ops:
            name = op["name"]
            if name in SKIP or name in BRANCHES or op["version"] > version:
                continue
            arity = op_arity(op, version)
            if arity is None:
                continue
            for imms in imm_variants(op, groups):
                for pushes in combos(arity, rnd, a.cap):
                    body = "\n".join(pushes + [" ".join([name] + imms)])
                    emit(f"#pragma version {version}\n{body}\n")
    for _ in range(a.random):
        emit(random_program(rnd, rnd.choice(versions), a.max_len))
    print(f"{len(seen)} sources in {sdir}")


if __name__ == "__main__":
    main()
