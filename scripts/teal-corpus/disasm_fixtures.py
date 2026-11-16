#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Generate the committed disassembly-parity regression fixture (issue #2367).

Every case below is a minimal byte program for one class of mismatch between
go-algorand's `logic.Disassemble` and algod-rust's `disassemble` that the full
ARC56Registry corpus run (epic #2364) surfaced, or that a go-algorand source
read says must be pinned. The expected output of each case is produced by the
GO driver (`tools/teal-corpus`, built against the pinned go-algorand), never
by the Rust implementation:

    GO_DRIVER=/path/to/teal-corpus-go python3 scripts/teal-corpus/disasm_fixtures.py

writes `crates/core/algo-avm/tests/fixtures/disasm_go_parity.jsonl`, one
`{"name","class","program_hex","ok","text"|"error"}` row per case, which the
`algo-avm` test `disassemble_go_parity` replays. `--check` regenerates in memory
and fails when the committed file is stale.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(
    HERE, "..", "..", "crates", "core", "algo-avm", "tests", "fixtures", "disasm_go_parity.jsonl"
)


def prog(version, *parts):
    """A program: the version byte followed by each part (bytes or a hex string)."""
    out = bytearray([version])
    for p in parts:
        out += bytes.fromhex(p) if isinstance(p, str) else bytes(p)
    return bytes(out)


def varint(n):
    """Go's binary.PutVarint (zigzag + uleb128)."""
    u = (n << 1) ^ (n >> 63)
    out = bytearray()
    while u >= 0x80:
        out.append((u & 0x7F) | 0x80)
        u >>= 7
    out.append(u)
    return bytes(out)


def cases():
    c = []

    def add(name, klass, program):
        c.append((name, klass, program))

    # -- label numbering: go numbers labels in the order each target is first
    # encountered while disassembling, not by target address.
    # b L2(+1: skip err); err; L2: b L1... built with explicit offsets.
    # v8: bz +4 ; err ; err ; err ; err ; return  -> single forward label
    add("label_single_forward", "label-order", prog(8, "4100 03", "00 00 00", "43"))
    # switch with descending targets: first-encountered label sits at the highest address.
    # 0x8d switch, count 3, offsets relative to end of the instruction (pc after offsets).
    # layout: switch(1) n(1) 3 offsets(6) = 8 bytes, then 4 x err/return markers.
    add(
        "label_switch_descending",
        "label-order",
        prog(8, "8d03", "0002", "0001", "0000", "00", "00", "00"),
    )
    # two branches whose targets appear in reverse order of the branches.
    # b A ; b B ; B: err ; A: err ; with A beyond B
    add("label_two_branches_reversed", "label-order", prog(8, "42 0003", "42 0000", "00", "00", "00", "00"))
    # match with duplicate targets reuses the label.
    add("label_match_duplicate_targets", "label-order", prog(8, "8e02", "0002", "0002", "00", "00", "43"))
    # backward jump (loop): label is only known after the jump -> rerun pass.
    add("label_backward_loop", "label-order", prog(8, "22", "41 fffc", "43"))
    # a branch into the middle of an instruction: the label is never emitted.
    add("label_into_instruction", "label-order", prog(8, "81 01", "42 0001", "81 02", "43"))
    # a branch to the very end of the program: trailing label.
    add("label_trailing", "label-order", prog(8, "42 0000"))
    # a branch before the start of the program (out of range target, still counts).
    add("label_negative_target", "label-order", prog(8, "42 ff00", "43"))
    # forward and backward mixed with a repeated target.
    add("label_mixed_repeat", "label-order", prog(8, "22", "40 0003", "42 0003", "43", "42 fff8", "43"))
    # proto without a branch target gets a synthesized label (v8+).
    add("label_proto_unreferenced", "label-order", prog(8, "42 0003", "8a0101", "89", "43"))
    # proto numbering interleaves with branch labels in program order.
    add("label_proto_interleaved", "label-order", prog(8, "42 0006", "8a0000", "89", "42 0003", "8a0101", "89", "43"))
    # varint branches (v13+): forward, backward, target numbering.
    add("label_varint_forward", "label-order", prog(13, "42" + varint(1).hex(), "00", "43"))
    add("label_varint_backward", "label-order", prog(13, "22", "42" + varint(-1).hex(), "43"))
    add(
        "label_varint_two_labels_reversed",
        "label-order",
        prog(13, "42" + varint(2).hex(), "42" + varint(0).hex(), "00", "43"),
    )
    add("label_varint_padded_offset", "label-order", prog(13, "42" + "82" + "00", "00", "00", "43"))
    add("label_callsub_varint", "label-order", prog(13, "88" + varint(1).hex(), "43", "8a0000", "89"))
    add("label_switch_v13", "label-order", prog(13, "8d02", "0001", "0000", "00", "43"))
    add("label_v14_forward", "label-order", prog(14, "40" + varint(1).hex(), "00", "43"))

    # -- unsupported / undecodable version header
    add("version_unsupported_15", "version", prog(15, "43"))
    add("version_unsupported_255", "version", prog(255, "01", "43"))
    add("version_unsupported_varuint", "version", bytes([0x81, 0x01, 0x43]))
    add("version_invalid_varint", "version", bytes([0xFF] * 12))
    add("version_empty", "version", b"")
    add("version_only", "version", prog(8))
    add("version_zero_alias", "version", prog(0, "22", "43"))
    add("version_padded_varuint", "version", bytes([0x88, 0x00, 0x22, 0x43]))

    # -- opcodes: unknown / not yet available at the program's version / prefix family
    add("opcode_illegal_byte", "opcode-error", prog(8, "ff"))
    add("opcode_not_yet_in_version", "opcode-error", prog(2, "22", "4b"))  # dig (v3) in a v2 program
    add("opcode_pushint_in_v2", "opcode-error", prog(2, "81 01"))
    add("opcode_prefix_missing_sub", "opcode-error", prog(13, "d4"))
    add("opcode_prefix_bad_sub", "opcode-error", prog(13, "d4ff"))
    add("opcode_prefix_before_v13", "opcode-error", prog(12, "d401"))
    add("opcode_prefix_ok", "opcode-error", prog(13, "d401", "43"))
    add("opcode_after_valid_text", "opcode-error", prog(8, "22", "43", "fe"))

    # -- immediates: field groups, int8, plain byte immediates, truncation
    add("imm_txn_field", "immediate", prog(8, "3100", "43"))
    add("imm_txn_bad_field", "immediate", prog(8, "31ff"))
    add("imm_txn_truncated", "immediate", prog(8, "31"))
    add("imm_global_bad_field", "immediate", prog(8, "32ff"))
    add("imm_gtxn_second_group", "immediate", prog(8, "33 00 01", "43"))
    add("imm_gtxn_truncated_second", "immediate", prog(8, "33 00"))
    add("imm_gtxn_bad_field", "immediate", prog(8, "33 00 ff"))
    add("imm_txna_scalar_field_rejected", "field-group", prog(8, "36 00"))
    add("imm_txna_array_field", "field-group", prog(8, "36 1c 00", "43"))
    add("imm_txna_truncated_index", "field-group", prog(8, "36 1c"))
    add("imm_txn_array_field_rejected", "field-group", prog(8, "31 1c"))
    add("imm_txn_last_field", "field-group", prog(8, "31 44", "43"))
    add("imm_txn_past_last_field", "field-group", prog(8, "31 45"))
    add("imm_txnas_array_field", "field-group", prog(8, "c0 1c", "43"))
    add("imm_txnas_scalar_field_rejected", "field-group", prog(8, "c0 00"))
    add("imm_gtxns_scalar_field", "field-group", prog(8, "38 00", "43"))
    add("imm_gtxnsa_scalar_field_rejected", "field-group", prog(8, "39 00 00"))
    add("imm_itxn_array_field_rejected", "field-group", prog(8, "b4 1c"))
    add("imm_itxn_field_accepts_array_field", "field-group", prog(8, "b2 1c", "43"))
    add("imm_gitxn_accepts_array_field", "field-group", prog(8, "b7 00 1c", "43"))
    add("imm_app_params_set_box_field", "field-group", prog(13, "76 0b", "43"))
    add("imm_app_params_set_low_field_rejected", "field-group", prog(13, "76 00"))
    add("imm_gtxna_three", "immediate", prog(8, "37 00 1c 02", "43"))
    add("imm_gtxna_truncated_third", "immediate", prog(8, "37 00 1c"))
    add("imm_proto_truncated", "immediate", prog(8, "8a 01"))
    add("imm_frame_dig_negative", "immediate", prog(8, "8b ff", "43"))
    add("imm_frame_bury_int8", "immediate", prog(8, "8c 80", "43"))
    add("imm_frame_dig_truncated", "immediate", prog(8, "8b"))
    add("imm_extract_pair", "immediate", prog(8, "80 00", "57 00 02", "43"))
    add("imm_ecdsa_curve_bad", "immediate", prog(8, "05 ff"))
    add("imm_block_field_ok", "immediate", prog(8, "81 01", "d1 00", "43"))
    add("imm_block_field_bad", "immediate", prog(8, "81 01", "d1 ff"))
    add("imm_block_field_v13_branch512", "field-group", prog(13, "81 01", "d1 0a", "43"))
    add("imm_block_field_v13_sha512_256_commitment", "field-group", prog(13, "81 01", "d1 0b", "43"))
    add("imm_block_field_v13_sha256_commitment", "field-group", prog(13, "81 01", "d1 0c", "43"))
    add("imm_block_field_v13_sha512_commitment", "field-group", prog(13, "81 01", "d1 0d", "43"))
    add("imm_block_field_past_last", "field-group", prog(13, "81 01", "d1 0e"))
    add("imm_mimc_bad", "immediate", prog(11, "e6 ff"))
    add("imm_vrf_verify_bad", "immediate", prog(8, "d0 ff"))
    add("imm_base64_decode_bad", "immediate", prog(8, "5e ff"))
    add("imm_asset_params_bad", "immediate", prog(8, "71 ff"))
    add("imm_intc_with_block", "immediate", prog(8, "20 02 07 08", "21 01", "43"))
    add("imm_intc_out_of_block", "immediate", prog(8, "20 01 07", "21 05", "22", "23", "43"))
    add("imm_bytec_with_block", "immediate", prog(8, "26 02 02 6869 01 ff", "27 00", "28", "29", "43"))
    add("imm_second_intcblock_wins", "immediate", prog(8, "20 01 07", "22", "20 01 09", "22", "43"))
    add("imm_second_bytecblock_wins", "immediate", prog(8, "26 01 01 61", "28", "26 01 01 62", "28", "43"))

    # -- constants: formatting of ints/bytes and the guessByteFormat comment
    add("const_intcblock_empty", "constant", prog(8, "20 00", "43"))
    add("const_bytecblock_empty", "constant", prog(8, "26 00", "43"))
    add("const_intcblock_large", "constant", prog(8, "20 02", "ffffffffffffffffff01", "00", "43"))
    add("const_pushint_padded_varuint", "constant", prog(8, "81 80 00", "43"))
    add("const_pushints", "constant", prog(8, "83 02 01 ff01", "43"))
    add("const_pushints_empty", "constant", prog(8, "83 00", "43"))
    add("const_pushbytess", "constant", prog(8, "82 02 02 6869 00", "43"))
    add("const_pushbytess_empty", "constant", prog(8, "82 00", "43"))
    add("const_pushbytes_ascii", "constant", prog(8, "80 02 6869", "43"))
    add("const_pushbytes_empty", "constant", prog(8, "80 00", "43"))
    add("const_pushbytes_quote_backslash", "constant", prog(8, "80 03 225c27", "43"))
    add("const_pushbytes_nonprintable", "constant", prog(8, "80 03 0a0d09", "43"))
    add("const_pushbytes_high_bit", "constant", prog(8, "80 02 c3a9", "43"))
    add("const_pushbytes_del", "constant", prog(8, "80 02 7e7f", "43"))
    add("const_pushbytes_32_address", "constant", prog(8, "80 20", "00" * 32, "43"))
    add("const_pushbytes_32_printable", "constant", prog(8, "80 20", "61" * 32, "43"))

    # -- truncated or malformed constant blocks and branches
    add("trunc_intcblock_no_count", "truncated", prog(8, "20"))
    add("trunc_intcblock_short", "truncated", prog(8, "20 03 01"))
    add("trunc_intcblock_item", "truncated", prog(8, "20 01 80"))
    add("trunc_intcblock_too_many", "truncated", prog(8, "20 ff01 01"))
    add("trunc_intcblock_count_overflow", "truncated", prog(8, "20" + "ff" * 10))
    add("trunc_bytecblock_no_count", "truncated", prog(8, "26"))
    add("trunc_bytecblock_short", "truncated", prog(8, "26 02 01 61"))
    add("trunc_bytecblock_item_len", "truncated", prog(8, "26 01"))
    add("trunc_bytecblock_item_data", "truncated", prog(8, "26 01 05 61"))
    add("trunc_bytecblock_too_many", "truncated", prog(8, "26 ff01 00"))
    add("trunc_bytecblock_trailing_empty", "truncated", prog(8, "26 01 00"))
    add("trunc_bytecblock_trailing_empty_v13", "truncated", prog(13, "26 01 00"))
    add("trunc_pushint_no_value", "truncated", prog(8, "81"))
    add("trunc_pushint_unterminated", "truncated", prog(8, "81 80"))
    add("trunc_pushint_overflow", "truncated", prog(8, "81" + "ff" * 10 + "01"))
    add("trunc_pushbytes_no_len", "truncated", prog(8, "80"))
    add("trunc_pushbytes_short", "truncated", prog(8, "80 05 6162"))
    add("trunc_pushints_short", "truncated", prog(8, "83 02 01"))
    add("trunc_pushbytess_short", "truncated", prog(8, "82 02 01 61"))
    add("trunc_branch_no_offset", "truncated", prog(8, "42"))
    add("trunc_branch_one_byte", "truncated", prog(8, "42 00"))
    add("trunc_branch_varint_none", "truncated", prog(13, "42"))
    add("trunc_branch_varint_unterminated", "truncated", prog(13, "42 80"))
    add("trunc_branch_varint_overflow", "truncated", prog(13, "42" + "ff" * 10 + "01"))
    add("trunc_switch_no_count", "truncated", prog(8, "8d"))
    add("trunc_switch_short", "truncated", prog(8, "8d 02 0000"))
    add("trunc_match_no_count", "truncated", prog(8, "8e"))
    add("trunc_match_short", "truncated", prog(8, "8e 03 0000 0000"))
    add("trunc_error_after_labels", "truncated", prog(8, "42 0000", "81"))

    # -- mixed realistic shape: a subroutine program with loops, proto and a switch
    add(
        "shape_subroutine_loop",
        "shape",
        prog(
            8,
            "20 02 01 02",
            "22",
            "88 0006",
            "43",
            "8a 01 01",
            "8b ff",
            "23",
            "08",
            "49",
            "40 fff9",
            "89",
        ),
    )
    return c


def go_rows(go_driver, programs):
    with tempfile.TemporaryDirectory() as d:
        pdir = os.path.join(d, "programs")
        os.makedirs(pdir)
        by_sha = {}
        for name, _klass, p in programs:
            sha = hashlib.sha256(p).hexdigest()
            by_sha[sha] = name
            with open(os.path.join(pdir, sha + ".bin"), "wb") as f:
                f.write(p)
        out = os.path.join(d, "go.jsonl")
        subprocess.run(
            [go_driver, "disassemble", "--corpus", d, "--out", out, "--jobs", "1"], check=True
        )
        rows = {}
        for line in open(out, encoding="utf-8"):
            row = json.loads(line)
            if "header" in row:
                continue
            rows[row["sha256"]] = row
        return rows


def build(go_driver):
    programs = cases()
    names = [n for n, _, _ in programs]
    if len(set(names)) != len(names):
        sys.exit("duplicate case names")
    rows = go_rows(go_driver, programs)
    lines = []
    seen = set()
    for name, klass, p in programs:
        sha = hashlib.sha256(p).hexdigest()
        if sha in seen:
            sys.exit(f"case {name} duplicates another case's bytes")
        seen.add(sha)
        r = rows[sha]
        out = {"name": name, "class": klass, "program_hex": p.hex(), "ok": r["ok"]}
        if r["ok"]:
            out["text"] = r["text"]
        else:
            out["error"] = r["error"]
        lines.append(json.dumps(out, sort_keys=True, ensure_ascii=False))
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail when the committed file is stale")
    ap.add_argument("--go-driver", default=os.environ.get("GO_DRIVER"))
    a = ap.parse_args()
    if not a.go_driver:
        sys.exit("set GO_DRIVER (tools/teal-corpus/build.sh) or pass --go-driver")
    text = build(a.go_driver)
    if a.check:
        cur = open(OUT, encoding="utf-8", newline="").read()
        if cur != text:
            sys.exit(f"{OUT} is stale; rerun without --check")
        print("up to date")
        return
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"wrote {OUT} ({text.count(chr(10))} cases)")


if __name__ == "__main__":
    main()
