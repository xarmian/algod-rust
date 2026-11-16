#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Generate the committed reassembly-parity regression fixture (issue #2368).

Every case below is a minimal TEAL source for one class of mismatch between
go-algorand's `logic.AssembleString` and algod-rust's `assemble_string` that the
full ARC56Registry reassembly run (epic #2364: go's disassembly of every corpus
program, assembled by both) surfaced, or that a go-algorand source read says
must be pinned. The expected output of each case is produced by the GO driver
(`tools/teal-corpus`, built against the pinned go-algorand), never by the Rust
implementation:

    GO_DRIVER=/path/to/teal-corpus-go python3 scripts/teal-corpus/asm_fixtures.py

writes `crates/core/algo-avm/tests/fixtures/asm_go_parity.jsonl`, one
`{"name","class","source","ok","bytecode_b64"|"errors","warnings"?}` row per case,
which the `algo-avm` test `assemble_go_parity` replays (bytecode, ordered error
list with line and column, warnings). `--check` regenerates in memory and fails
when the committed file is stale.
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
    HERE, "..", "..", "crates", "core", "algo-avm", "tests", "fixtures", "asm_go_parity.jsonl"
)

ADDR32 = "0x" + "11" * 32


def cases():
    c = []

    def add(name, klass, source):
        c.append((name, klass, source))

    def v(version, body):
        return f"#pragma version {version}\n{body}"

    # -- version-only and comment-only programs: go has no "empty program" error
    # beyond empty text; the program is the version header alone, and a program
    # that never settled a version keeps assemblerNoVersion (^uint64(0)).
    add("empty_pragma_only_v8", "empty-program", "#pragma version 8\n")
    add("empty_pragma_only_v3_comment", "empty-program", "#pragma version 3\n// nothing\n")
    add("empty_pragma_only_v1", "empty-program", "#pragma version 1\n")
    add("empty_pragma_zero", "empty-program", "#pragma version 0\n")
    add("empty_comment_only", "empty-program", "// only a comment\n")
    add("empty_label_only", "empty-program", "#pragma version 8\nlabel:\n")
    add("empty_text", "empty-program", "")
    add("empty_whitespace_text", "empty-program", "  \n\t\n")
    add("empty_pragma_v13_autosalt", "empty-program", "#pragma version 13\n")

    # -- error columns: go blames the token, not the line
    big = "00" * 4097
    add("col_bytecblock_too_big", "error-column", v(8, f"bytecblock 0x{big}\n"))
    add("col_bytecblock_second_too_big", "error-column", v(8, f"bytecblock 0x01 0x{big}\n"))
    add("col_bytecblock_bad_arg", "error-column", v(8, "bytecblock 0x01 zzz 0x02\n"))
    add("col_substring_end_before_start", "error-column", v(8, "byte 0x00\nsubstring 2 0\n"))
    add("col_substring_equal_ok", "error-column", v(8, "byte 0x0000\nsubstring 1 1\nlen\nreturn\n"))
    add("col_substring_indented", "error-column", v(8, "byte 0x00\n   substring 2 0\n"))
    add("col_type_error_indented", "error-column", v(8, "int 1\n\tbyte 0x01\n\t+\n"))
    add("col_type_error_after_label", "error-column", v(8, "int 1\nL: byte 0x01\n+\n"))
    add("col_duplicate_label", "error-column", v(8, "L:\n  L:\nint 1\n"))
    add("col_intcblock_following_int", "error-column", v(8, "int 1\nintcblock 1\n"))
    add("col_bytecblock_following_byte", "error-column", v(8, "byte 0x01\n  bytecblock 0x01\n"))

    # -- txn-family / global / params fields give the pushed value the field's type
    add("field_txn_sender_plus", "field-type", v(8, "txn Sender\nint 1\n+\npop\n"))
    add("field_txn_fee_concat", "field-type", v(8, "txn Fee\nbyte 0x1234\nconcat\npop\n"))
    add("field_txn_fee_plus_ok", "field-type", v(8, "txn Fee\nint 1\n+\npop\n"))
    add("field_txna_accounts_plus", "field-type", v(8, "txna Accounts 0\nint 1\n+\npop\n"))
    add("field_txn_array_pseudo", "field-type", v(8, "txn Accounts 0\nint 1\n+\npop\n"))
    add("field_gtxn_sender", "field-type", v(8, "gtxn 0 Sender\nint 1\n+\npop\n"))
    add("field_gtxns_amount", "field-type", v(8, "int 0\ngtxns Amount\nbyte 0x01\nconcat\npop\n"))
    add("field_global_group_size", "field-type", v(8, "global GroupSize\nbyte 0x01\nconcat\npop\n"))
    add("field_global_zero_address", "field-type", v(8, "global ZeroAddress\nint 1\n+\npop\n"))
    add("field_itxn_scalar", "field-type", v(8, "itxn Sender\nint 1\n+\npop\n"))
    add("field_itxna", "field-type", v(8, "itxna Logs 0\nint 1\n+\npop\n"))
    add("field_asset_holding_get", "field-type", v(8, "int 0\nint 1\nasset_holding_get AssetBalance\nbyte 0x01\nconcat\npop\npop\n"))
    add("field_asset_params_get_bytes", "field-type", v(8, "int 1\nasset_params_get AssetName\nint 1\n+\npop\npop\n"))
    add("field_app_params_get_creator", "field-type", v(8, "int 1\napp_params_get AppCreator\nint 1\n+\npop\npop\n"))
    add("field_acct_params_get", "field-type", v(8, "global ZeroAddress\nacct_params_get AcctBalance\nbyte 0x01\nconcat\npop\npop\n"))
    add("field_block_timestamp", "field-type", v(8, "int 1\nblock BlkTimestamp\nbyte 0x01\nconcat\npop\n"))
    add("field_json_ref_untyped", "field-type", v(8, 'byte "{}"\nbyte "k"\njson_ref JSONString\nint 1\n+\npop\n'))

    # -- proto bounds from the opcode table (sized bytes, bigint, stateKey, boxName, bool)
    add("bound_sha256_result_b_plus", "bound", v(8, "byte 0x01\nsha256\nbyte 0x01\nb+\npop\n"))
    add("bound_sha256_result_plus", "bound", v(8, "byte 0x01\nsha256\nint 1\n+\npop\n"))
    add("bound_bzero_too_big", "bound", v(8, "int 5000\nbzero\npop\n"))
    add("bound_bzero_ok", "bound", v(8, "int 4096\nbzero\npop\n"))
    add("bound_bzero_wide_value", "bound", v(8, "txn Fee\nbzero\nlen\nreturn\n"))
    add("bound_b_plus_result_b_plus", "bound", v(8, "byte 0x01\nbyte 0x01\nb+\nbyte 0x01\nb+\npop\n"))
    add("bound_b_mul_result", "bound", v(8, "byte 0x01\nbyte 0x01\nb*\nint 1\n+\npop\n"))
    add("bound_b_plus_too_long_operand", "bound", v(8, "int 65\nbzero\nbyte 0x01\nb+\npop\n"))
    add("bound_bigint_const_uint", "bound", v(8, "int 1\nbyte 0x01\nb+\npop\n"))
    add("bound_app_global_get_int_key", "bound", v(8, "int 0\napp_global_get\npop\n"))
    add("bound_app_global_get_long_key", "bound", v(8, "int 65\nbzero\napp_global_get\npop\n"))
    add("bound_box_len_empty_name", "bound", v(8, 'byte ""\nbox_len\npop\npop\n'))
    add("bound_box_len_ok", "bound", v(8, 'byte "a"\nbox_len\npop\npop\n'))
    add("bound_ed25519verify_sizes", "bound", v(8, "byte 0x01\nbyte 0x01\nbyte 0x01\ned25519verify\npop\n"))
    add("bound_ed25519verify_ok", "bound", v(8, f"byte 0x01\nbyte 0x{'00' * 64}\nbyte {ADDR32}\ned25519verify\npop\n"))
    add("bound_bool_value_in_range", "bound", v(8, "int 1\nint 1\n==\nbyte 0x01\nconcat\npop\n"))
    add("bound_constant_value_overlaps", "bound", v(8, "int 5\nint 1\nassert\nint 2\n+\npop\n"))
    add("bound_extract_uint_wide", "bound", v(8, "byte 0x00\nint 0\nextract_uint64\npop\n"))
    add("bound_len_result", "bound", v(8, "byte 0x01\nlen\nbyte 0x01\nconcat\npop\n"))

    # -- pseudo-ops: the name error messages use, merged protos for a wrong arity
    add("pseudo_extract_no_imms_stack", "pseudo", v(8, "byte 0x01\nextract\npop\n"))
    add("pseudo_extract3_wrong_type", "pseudo", v(8, "int 1\nint 0\nint 1\nextract\npop\n"))
    add("pseudo_extract_two_imms", "pseudo", v(8, "int 1\nextract 0 1\npop\n"))
    add("pseudo_extract_one_imm", "pseudo", v(8, "byte 0x01\nextract 0\npop\n"))
    add("pseudo_replace_no_imm_stack", "pseudo", v(8, "byte 0x00\nbyte 0x12\nreplace\npop\n"))
    add("pseudo_replace_one_imm_type", "pseudo", v(8, "byte 0x00\nint 0\nreplace 0\npop\n"))
    add("pseudo_txn_no_imms", "pseudo", v(8, "txn\npop\n"))
    add("pseudo_txn_three_imms", "pseudo", v(8, "txn Accounts 0 1\npop\n"))
    add("pseudo_gtxn_one_imm", "pseudo", v(8, "gtxn 0\npop\n"))
    add("pseudo_gtxns_no_imms", "pseudo", v(8, "int 0\ngtxns\npop\n"))
    add("pseudo_int_wrong_type_consumer", "pseudo", v(8, "int 1\nbyte 0x01\n+\n"))
    add("pseudo_int_named_constant_not_tracked", "pseudo", v(8, "int pay\nint 1\n+\npop\n"))
    add("pseudo_byte_sized", "pseudo", v(8, "byte 0x0102\nint 1\n+\npop\n"))
    add("pseudo_addr_type", "pseudo", v(8, "addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\nint 1\n+\npop\n"))
    add("pseudo_method_type", "pseudo", v(8, 'method "add(uint64)uint64"\nint 1\n+\npop\n'))

    # -- stack shuffling keeps the exact tracked types
    add("stack_dup_type", "stack", v(8, "byte 0x01\ndup\nint 1\n+\npop\npop\n"))
    add("stack_dup2_type", "stack", v(8, "int 1\nbyte 0x01\ndup2\nint 1\n+\npop\npop\npop\npop\n"))
    add("stack_dig_type", "stack", v(8, "byte 0x01\nint 1\ndig 1\nint 1\n+\npop\npop\npop\n"))
    add("stack_dig_below_known_bottom", "stack", v(8, "int 1\ndig 3\npop\npop\n"))
    add("stack_swap_type", "stack", v(8, "byte 0x01\nint 1\nswap\nint 1\n+\npop\npop\n"))
    add("stack_select_union", "stack", v(8, "int 1\nbyte 0x01\nint 1\nselect\nint 1\n+\npop\n"))
    add("stack_select_same_type", "stack", v(8, "int 1\nint 2\nint 1\nselect\nint 1\n+\npop\n"))
    add("stack_setbit_type", "stack", v(8, "byte 0x01\nint 0\nint 1\nsetbit\nint 1\n+\npop\n"))
    add("stack_cover_type", "stack", v(8, "byte 0x01\nint 1\nint 2\ncover 2\nint 1\n+\npop\npop\npop\n"))
    add("stack_uncover_type", "stack", v(8, "byte 0x01\nint 1\nint 2\nuncover 2\nint 1\n+\npop\npop\npop\n"))
    add("stack_cover_too_deep", "stack", v(8, "int 1\ncover 3\n"))
    add("stack_dupn_type", "stack", v(8, "byte 0x01\ndupn 2\nint 1\n+\npop\npop\npop\n"))
    add("stack_popn_height", "stack", v(8, "int 1\npopn 2\n"))
    add("stack_popn_zero", "stack", v(8, "popn 0\nint 1\n"))
    add("stack_bury_type", "stack", v(8, "byte 0x01\nint 1\nbury 1\nint 1\n+\npop\n"))
    add("stack_bury_zero", "stack", v(8, "int 1\nbury 0\n"))
    add("stack_bury_height", "stack", v(8, "int 1\nbury 2\n"))
    add("stack_equals_mixed", "stack", v(8, "int 1\nbyte 0x01\n==\npop\n"))
    add("stack_equals_ignores_bounds", "stack", v(8, "int 1\nint 2\n==\npop\n"))
    add("stack_pushints_type", "stack", v(8, "pushints 1 2\nbyte 0x01\nconcat\npop\n"))
    add("stack_pushbytess_type", "stack", v(8, "pushbytess 0x01 0x02\nint 1\n+\npop\n"))
    add("stack_pushint_hex_constant", "stack", v(8, "pushint 0x10\nint 1\n+\npop\n"))
    add("stack_height_error_message", "stack", v(8, "+\n"))
    add("stack_height_error_pseudo", "stack", v(8, "int 1\nsubstring 0 1\n"))
    add("stack_match_height", "stack", v(8, "int 1\nint 2\nmatch a b\na:\nb:\nint 1\n"))
    add("stack_switch_type", "stack", v(8, "byte 0x01\nswitch a\na:\nint 1\n"))

    # -- scratch space types
    add("scratch_store_load_type", "scratch", v(8, "byte 0x01\nstore 3\nload 3\nint 1\n+\npop\n"))
    add("scratch_untouched_slot_is_zero", "scratch", v(8, "load 7\nbyte 0x01\nconcat\npop\n"))
    add("scratch_stores_constant_index", "scratch", v(8, "int 4\nbyte 0x01\nstores\nint 4\nloads\nint 1\n+\npop\n"))
    add("scratch_stores_unknown_index", "scratch", v(8, "txn Fee\nbyte 0x01\nstores\nload 0\nint 1\n+\npop\n"))
    add("scratch_loads_uniform", "scratch", v(8, "txn Fee\nloads\nint 1\n+\npop\n"))
    add("scratch_loads_mixed", "scratch", v(8, "byte 0x01\nstore 1\ntxn Fee\nloads\nint 1\n+\npop\n"))
    add("scratch_reset_at_label_after_branch", "scratch", v(8, "byte 0x01\nstore 1\nb done\ndone:\nload 1\nint 1\n+\npop\n"))
    add("scratch_store_in_dead_code", "scratch", v(8, "err\nbyte 0x01\nstore 1\nL:\nload 1\nint 1\n+\npop\n"))

    # -- dead code, labels, typetrack pragma, subroutine frames
    add("dead_code_no_error", "control", v(8, "b end\nint 1\nbyte 0x01\n+\nend:\nint 1\nreturn\n"))
    add("dead_code_after_return", "control", v(8, "int 1\nreturn\nbyte 0x01\nint 1\n+\n"))
    add("dead_code_proto_still_checked", "control", v(8, "int 1\nreturn\nproto 0 0\n"))
    add("label_reopens_with_any_bottom", "control", v(8, "b L\nL:\n+\n"))
    add("label_after_fallthrough_keeps_stack", "control", v(8, "int 1\nL:\nbyte 0x01\n+\npop\n"))
    add("callsub_reopens", "control", v(8, "callsub f\n+\nint 1\nreturn\nf:\nretsub\n"))
    add("typetrack_off_on_resets", "control", v(8, "#pragma typetrack false\nint 1\nbyte 0x01\n+\n#pragma typetrack true\n+\n"))
    add("proto_not_unreachable", "control", v(8, "int 1\nproto 0 0\n"))
    add("proto_at_start", "control", v(8, "proto 0 0\n"))
    add("proto_after_retsub", "control", v(8, "callsub f\nint 1\nreturn\nf:\nproto 0 0\nretsub\n"))
    add("frame_dig_typed", "frame", v(8, "int 1\nbyte 0x01\ncallsub f\nint 1\nreturn\nf:\nproto 2 1\nframe_dig -1\nbyte 0x02\nb==\nswap\npop\nretsub\n"))
    add("frame_dig_args_type", "frame", v(8, "int 1\nbyte 0x01\ncallsub f\nint 1\nreturn\nf:\nproto 2 1\nframe_dig -2\nint 1\n+\nframe_dig -1\nint 1\n+\nretsub\n"))
    add("frame_dig_in_sub_with_args", "frame", v(8, "callsub f\nint 1\nreturn\nf:\nproto 1 1\nframe_dig -2\nretsub\n"))
    add("frame_dig_above_stack", "frame", v(8, "callsub f\nint 1\nreturn\nf:\nproto 1 1\nframe_dig 5\nretsub\n"))
    add("frame_dig_no_fp", "frame", v(8, "frame_dig 0\nint 1\n+\npop\n"))
    add("frame_bury_typed", "frame", v(8, "int 1\nint 2\ncallsub f\nint 1\nreturn\nf:\nproto 2 1\nbyte 0x01\nframe_bury -2\nframe_dig -2\nint 1\n+\nretsub\n"))
    add("frame_bury_above_stack", "frame", v(8, "callsub f\nint 1\nreturn\nf:\nproto 1 1\nframe_bury 3\nretsub\n"))
    add("frame_bury_in_sub_with_args", "frame", v(8, "callsub f\nint 1\nreturn\nf:\nproto 1 1\nint 1\nframe_bury -3\nretsub\n"))
    add("frame_bury_no_fp_wipes_types", "frame", v(8, "int 1\nbyte 0x01\nframe_bury 0\nint 1\n+\npop\n"))

    # -- itxn_field / group fields
    add("itxn_field_sender_int", "field-type", v(8, "itxn_begin\nint 1\nitxn_field Sender\n"))
    add("itxn_field_sender_short_bytes", "field-type", v(8, "itxn_begin\nbyte 0x56127823\nitxn_field Sender\n"))
    add("itxn_field_sender_address", "field-type", v(8, "itxn_begin\nglobal ZeroAddress\nitxn_field Sender\n"))
    add("itxn_field_amount_bytes", "field-type", v(8, "itxn_begin\nbyte 0x87123376\nitxn_field Amount\n"))

    # -- ordering of errors: getSpec complaints before type errors before assembly errors
    add("order_pseudo_count_then_type", "order", v(8, "txn\npop\n+\n"))
    return c


def go_rows(go_driver, sources):
    with tempfile.TemporaryDirectory() as d:
        sdir = os.path.join(d, "sources")
        os.makedirs(sdir)
        for _name, _klass, src in sources:
            sha = hashlib.sha256(src.encode()).hexdigest()
            with open(os.path.join(sdir, sha + ".teal"), "wb") as f:
                f.write(src.encode())
        out = os.path.join(d, "go.jsonl")
        subprocess.run(
            [go_driver, "assemble", "--corpus", d, "--out", out, "--jobs", "1"], check=True
        )
        rows = {}
        for line in open(out, encoding="utf-8"):
            row = json.loads(line)
            if "header" in row:
                continue
            rows[row["sha256"]] = row
        return rows


def build(go_driver):
    cs = cases()
    names = [n for n, _, _ in cs]
    if len(set(names)) != len(names):
        sys.exit("duplicate case names")
    rows = go_rows(go_driver, cs)
    lines = []
    seen = set()
    for name, klass, src in cs:
        sha = hashlib.sha256(src.encode()).hexdigest()
        if sha in seen:
            sys.exit(f"case {name} duplicates another case's source")
        seen.add(sha)
        r = rows[sha]
        out = {"name": name, "class": klass, "source": src, "ok": r["ok"]}
        if r["ok"]:
            out["bytecode_b64"] = r["bytecode_b64"]
            if r.get("warnings"):
                out["warnings"] = r["warnings"]
        else:
            out["errors"] = r["errors"]
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
