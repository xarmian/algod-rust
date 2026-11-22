#!/usr/bin/env python3
# Copyright (C) 2019-2026 Algorand Foundation Ltd.
# Modifications Copyright (C) 2026 Algod DAO
# This file is part of algod-rust, a modified work based on go-algorand
# (https://github.com/algorand/go-algorand).
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate the committed pcDetails parity fixture (issue #2375, epic #2364).

go-algorand's `(*EvalContext).pcDetails` (data/transactions/logic/eval.go) is
the `opcodes=` text of the `Details` of a failed application call in simulate:
the disassembly (`disassembleInstrumented`, labels numbered in the order each
branch target is first met) of the instruction at the failing pc and of up to
two instructions before it, newlines turned into "; ". It is unexported, so the
oracle is a test file (tools/teal-corpus/oracle/pcdetails_oracle_test.go.txt)
copied into a go-algorand checkout and run there; the expected text of every
(program, pc) pair comes from that real function, never from the Rust code:

    GO_ALGORAND_DIR=/path/to/go-algorand python3 scripts/teal-corpus/pcdetails_fixtures.py

writes `crates/core/algo-avm/tests/fixtures/pcdetails_go_parity.jsonl`, one
`{"name","class","program_hex","details":[...]}` row per program (`details[pc]`
for every pc in 0..=len+1), replayed by the `algo-avm` test
`pc_details_go_parity`. `--check` regenerates in memory and fails when the
committed file is stale. The go-algorand checkout needs its libsodium built
(`make libsodium`), like every go-algorand build here.

The programs are the disassembly regression cases of disasm_fixtures.py (every
class of label order, back jumps, proto, switch/match, varint branches,
truncation: the error cases pin that pcDetails is empty when the disassembly
fails) plus the cases below, which put the failing pc where labels sit in the
window.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import disasm_fixtures as d  # noqa: E402

OUT = os.path.join(
    HERE, "..", "..", "crates", "core", "algo-avm", "tests", "fixtures", "pcdetails_go_parity.jsonl"
)
TEMPLATE = os.path.join(
    HERE, "..", "..", "tools", "teal-corpus", "oracle", "pcdetails_oracle_test.go.txt"
)
LOGIC_PKG = "data/transactions/logic"
ORACLE_FILE = "zz_pcdetails_oracle_test.go"


def extra_cases():
    prog, varint = d.prog, d.varint
    c = []

    def add(name, klass, program):
        c.append((name, klass, program))

    # 1 pushint 1 | 3 bnz first | 6 err | 7 second: pushint 5 | 9 pushint 0 |
    # 11 assert | 12 first: pushint 1 | 14 bnz second | 17 pushint 1.
    # The first branch met names the HIGHER target label1.
    add(
        "pcd_labels_out_of_order",
        "pcdetails-label-order",
        prog(8, "81 01", "40 0006", "00", "81 05", "81 00", "44", "81 01", "40 fff6", "81 01"),
    )
    # the failing opcode directly after a label: label lines sit inside the window
    add(
        "pcd_labels_in_window",
        "pcdetails-label-order",
        prog(8, "81 01", "40 0002", "00", "00", "81 01", "40 fffa", "81 01"),
    )
    # a loop: back jump (rewind) with a forward label met first, then a second
    # back jump to an earlier label
    add(
        "pcd_back_jump_loop",
        "pcdetails-back-jump",
        prog(
            8, "81 01", "40 0006", "81 00", "44", "81 01", "43", "81 02", "81 01", "09", "49",
            "40 fff9", "48", "42 ffed",
        ),
    )
    # proto: callsub targets and an unreferenced proto (label synthesized)
    add(
        "pcd_proto_labels",
        "pcdetails-proto",
        prog(
            8, "42 0004", "8a0000", "89", "81 03", "88 0006", "88 000c", "81 01", "43",
            "8a0101", "8b ff", "81 01", "08", "89", "8a0100", "8b ff", "81 00", "44", "89",
        ),
    )
    # switch with targets descending
    add(
        "pcd_switch_descending",
        "pcdetails-label-order",
        prog(8, "81 02", "8d03", "0007", "0004", "0001", "00", "81 01", "43", "81 01", "43", "81 00", "44"),
    )
    # v13+: varint branches, forward and back, two labels out of order
    add(
        "pcd_varint_labels",
        "pcdetails-varint",
        prog(
            13, "81 01", "40" + varint(6).hex(), "00", "81 05", "81 00", "44", "81 01",
            "40" + varint(-7).hex(), "81 01",
        ),
    )
    # constant blocks: the intc/bytec comments are part of the text
    add(
        "pcd_constant_comments",
        "pcdetails-constants",
        prog(8, "20 02 07 08", "26 01 02 6869", "22", "28", "23", "44"),
    )
    # go's TestPcDetails (eval_test.go) sources, assembled at the current
    # LogicVersion: `int 1; int 2; -`, `int 1; err`, `int 1; dup; int 2; -; +`
    # and `b end; end:`.
    add("pcd_go_test_sub", "pcdetails-go-test", prog(14, "81 01", "81 02", "09"))
    add("pcd_go_test_err", "pcdetails-go-test", prog(14, "81 01", "00"))
    add("pcd_go_test_dup", "pcdetails-go-test", prog(14, "81 01", "49", "81 02", "09", "08"))
    add("pcd_go_test_branch_to_end", "pcdetails-go-test", prog(14, "42" + varint(0).hex()))
    return c


def all_programs():
    seen, out = set(), []
    for name, klass, program in d.cases() + extra_cases():
        if program in seen:
            continue
        seen.add(program)
        out.append((name, klass, program))
    names = [n for n, _, _ in out]
    if len(set(names)) != len(names):
        sys.exit("duplicate case names")
    return out


def run_go(go_algorand, programs):
    """Run the oracle for [(name, program bytes)] -> {name: row}."""
    pkg = os.path.join(go_algorand, *LOGIC_PKG.split("/"))
    dst = os.path.join(pkg, ORACLE_FILE)
    with tempfile.TemporaryDirectory() as tmp:
        inp, outp = os.path.join(tmp, "in.jsonl"), os.path.join(tmp, "out.jsonl")
        with open(inp, "w", encoding="utf-8") as f:
            for name, p in programs:
                f.write(json.dumps({"name": name, "program_hex": p.hex()}) + "\n")
        shutil.copyfile(TEMPLATE, dst)
        try:
            env = dict(os.environ, PCDETAILS_IN=inp, PCDETAILS_OUT=outp)
            subprocess.run(
                ["go", "test", "-count=1", "-run", "^TestPcDetailsOracle$", "./" + LOGIC_PKG],
                cwd=go_algorand,
                env=env,
                check=True,
            )
        finally:
            os.remove(dst)
        res = {}
        for line in open(outp, encoding="utf-8"):
            r = json.loads(line)
            res[r["name"]] = r
        return res


def build(go_algorand):
    programs = all_programs()
    # A v13+ program whose hash is on-curve is disassembled with a leading
    # `#pragma autosalt false` line, which shifts every text offset. Take the
    # first such candidate go's own Disassemble reports, so pcDetails is pinned
    # across that header too.
    cand = [(f"pcd_autosalt_{n:02x}", d.prog(13, "81 %02x" % n, "81 00", "44")) for n in range(96)]
    found = run_go(go_algorand, cand)
    salted = next(((n, p) for n, p in cand if "autosalt false" in found[n]["text"]), None)
    if salted is None:
        sys.exit("no on-curve v13 candidate found")
    programs.append((salted[0], "pcdetails-autosalt-header", salted[1]))
    res = run_go(go_algorand, [(n, p) for n, _, p in programs])
    lines = []
    for name, klass, p in programs:
        lines.append(
            json.dumps(
                {"name": name, "class": klass, "program_hex": p.hex(), "details": res[name]["details"]},
                sort_keys=True,
                ensure_ascii=False,
            )
        )
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail when the committed file is stale")
    ap.add_argument("--go-algorand", default=os.environ.get("GO_ALGORAND_DIR"))
    a = ap.parse_args()
    if not a.go_algorand:
        sys.exit("set GO_ALGORAND_DIR or pass --go-algorand (a v5.1.1-stable checkout with libsodium built)")
    text = build(os.path.abspath(a.go_algorand))
    if a.check:
        cur = open(OUT, encoding="utf-8", newline="").read()
        if cur != text:
            sys.exit(f"{OUT} is stale; rerun without --check")
        print("up to date")
        return
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {OUT} ({text.count(chr(10))} programs)")


if __name__ == "__main__":
    main()
