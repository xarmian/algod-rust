#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Generate an adversarial assembler *front-end* corpus (issue #2369, epic #2364).

The registry corpus only holds sources that compiled with real tools, so the
assembler's error shaping (message text, line, column, ordered list) is barely
exercised. This tool writes TEAL sources that are wrong in the ways a developer
gets wrong, in the layout the drivers read (`OUT/sources/<sha256>.teal`), for
`scripts/teal-corpus/run_drivers.sh OUT OUTDIR assemble`:

    gen_synthetic_syntax.py OUT_DIR [--seed N] [--count N] [--versions 3,8,13]
                            [--mutate N --mutate-from CORPUS]

* every opcode and pseudo-op with its immediates dropped, extra, malformed or
  out of range (junk numbers, unknown fields, bad encodings, bad escapes);
* directives (`#pragma`, `#define`), labels, comments, string literals,
  `TMPL_*` variables and odd whitespace;
* `--count` random token soup built from the same vocabularies;
* ABI method signatures, addresses, base64/base32/hex/string literals, macro
  names and pragma variants (`extra_programs`);
* `--mutate N`: token-level mutations (delete, duplicate, replace with junk,
  truncate) of the original sources under `--mutate-from CORPUS/sources`;
* sources that are not UTF-8 (`non_utf8_programs`, issue #2388): invalid and
  truncated sequences, overlongs, surrogates and the valid private-use characters
  that the Rust assembler's byte-preserving text form reserves, at every kind of
  position (literal, comment, label, mnemonic, immediate, macro, pragma).

Deterministic for a given seed.
"""
import argparse
import hashlib
import os
import random
from pathlib import Path

JUNK = [
    "zero", "-1", "256", "65536", "18446744073709551616", "0x", "0xzz", "0x1", "1.5", '"', '"abc',
    '"\\q"', "b64(", "b64()", "b64(!!)", "b32(1)", "base64 AA==", "base32 ME======", "base64(AA)",
    "AAAA", "TMPL_X", "x y", "//", "#", ":", "L:", "(", ")", "", "int", "pushint 1 2",
    "-0x1", "0b101", "0o17", "1_000", "1e3", "\u00e9", "\t",
]
PSEUDO = [
    "int", "byte", "addr", "method", "pushint", "pushints", "pushbytes", "pushbytess", "intcblock",
    "bytecblock", "intc", "bytec", "load", "store", "dig", "bury", "cover", "uncover", "popn", "dupn",
    "frame_dig", "frame_bury", "proto", "extract", "substring", "txn", "txna", "txnas", "gtxn", "gtxna",
    "gtxns", "gtxnsa", "itxn_field", "itxn", "itxna", "global", "arg", "args", "asset_holding_get",
    "app_params_get", "acct_params_get", "asset_params_get", "base64_decode", "json_ref", "ecdsa_verify",
    "ec_add", "vrf_verify", "block", "gloadss", "gaids", "box_extract", "switch", "match", "b", "bz",
    "bnz", "callsub", "retsub", "return", "err", "assert", "pop", "dup",
]
GOODARGS = {
    "int": "1", "byte": "0x01", "addr": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
    "method": '"foo(uint64)void"', "pushint": "1", "pushints": "1 2", "pushbytes": "0x01",
    "pushbytess": "0x01 0x02", "intcblock": "1 2", "bytecblock": "0x01 0x02", "txn": "Sender",
    "txna": "Accounts 0", "gtxn": "0 Sender", "gtxna": "0 Accounts 0", "global": "GroupSize",
    "extract": "0 1", "substring": "0 1", "arg": "0", "dig": "1", "proto": "1 1", "itxn_field": "Amount",
    "asset_holding_get": "AssetBalance", "app_params_get": "AppCreator", "block": "BlkTimestamp",
    "json_ref": "JSONString", "ecdsa_verify": "Secp256k1", "ec_add": "BN254g1", "vrf_verify": "VrfAlgorand",
    "load": "0", "store": "0", "intc": "0", "bytec": "0", "frame_dig": "0", "frame_bury": "0",
    "b": "L0", "bz": "L0", "bnz": "L0", "callsub": "L0", "switch": "L0 L1", "match": "L0 L1",
    "base64_decode": "StdEncoding", "itxn": "Fee", "itxna": "Logs 0", "gtxnsa": "Accounts 0",
    "acct_params_get": "AcctBalance", "asset_params_get": "AssetTotal",
}

BODIES = [
    "#define\n", "#define X\nint 1\n", "#define X 1\nX\nX X\n", "#define X X\nX\n",
    "#define X(\n", "#define X(a) a\nX(1)\n", "#define X() int 1\nX()\n", "#define 1 2\n",
    "#define int 1\n", "#define L: 1\n", "#define X int 1 // c\nX\n", "#define X int 1\n#define X int 2\nX\n",
    "#pragma\n", "#pragma version\n", "#pragma version 99\n", "#pragma version 8 9\n",
    "#pragma version 8\n#pragma version 8\n", "#pragma version x\n", "#pragma typetrack\n",
    "#pragma typetrack maybe\n", "#pragma typetrack false\nint 1\nbyte 0x01\n+\n", "#pragma autosalt\n",
    "#pragma autosalt x\n", "#pragma foo\n", "#foo\n", "#include x\n", "#\n", "L:\nL:\n", "L: L:\n",
    ":\n", "a b:\n", "L:int 1\n", "L: int 1\nb L\n", "b M\n", "bz M\nint 1\n", "callsub M\n",
    "int 1 // c\n// d\n", "int 1 //c", 'byte "a//b"\n', 'byte "a\\"b"\n', 'byte "a\\x4"\n',
    'byte "a\\n\\t"\n', 'byte "unterminated\n', 'byte "a" "b"\n', "byte 0x0\n", "byte 0xGG\n",
    "byte b64 AA\n", "byte b64 AA==\n", "byte b64(AA==)\n", "byte b32 ME======\n", "byte base32 ME\n",
    "byte base64 ****\n", "byte base32(ME======)\n", "byte base64\n", "byte b64\n", "byte base32 \n",
    "int 0x10\nint 0b11\nint 0o7\nint 1_0\n", "int 18446744073709551615\nint 18446744073709551616\n",
    "int -1\n", "int +1\n", "int NoOp\nint pay\nint OptIn\nint axfer\nint Foo\n",
    "int TMPL_A\nbyte TMPL_B\naddr TMPL_C\n", "pushint TMPL_A\npushbytes TMPL_B\n",
    "intcblock TMPL_A\nbytecblock TMPL_B\n", 'method "a"\n', 'method "a("\n', "method a\n",
    'method ""\n', 'method "f()void"\nmethod "f(uint64,byte[])"\n', 'method "f(\\""\n',
    "addr AAAA\n", "addr \n", "addr 0x00\n", 'addr "AAAA"\n',
    "switch\n", "switch M\n", "match L0 L0\nL0:\n", "int 1\nswitch L0 L1\nL0:\nL1:\n",
    "txn Foo\n", "txn\n", "txn Sender 0\n", "txna Accounts\n", "txna Sender 0\n", "txna Sender\n",
    "gtxn 0\n", "gtxn zero Sender\n", "gtxn 256 Sender\n", "gtxn -1 Sender\n", "gtxn 0 Foo\n",
    "gtxn 0 Accounts 0\n", "gtxna 0 Accounts\n", "gtxna 0 Sender 0\n", "gtxna 0 Foo 0\n", "gtxna 0 Accounts x\n",
    "gtxna zero Accounts 0\n", "gtxns Foo\n", "gtxnsa Accounts\n", "gtxnsa Foo 0\n", "gtxn 0 Sender x\n",
    "global Foo\n", "global\n", "global GroupSize 1\n", "itxn_field Foo\n", "itxn_field\n",
    "int 1\nitxn_field Amount\n", "arg 256\n", "arg -1\n", "arg x\n", "arg_4\n", "arg_0 1\n",
    "intc_4\n", "intc 256\n", "bytec_0 1\n", "dig 256\n", "dig\n", "load 256\n", "store x\n",
    "extract 0\n", "extract 256 1\n", "extract 0 256\n", "substring 0\n", "substring 256 1\n",
    "frame_dig 128\n", "frame_dig -129\n", "frame_dig x\n", "proto 1\n", "proto 256 0\n", "proto x y\n",
    "popn 256\n", "bury 256\n", "bury 0\n", "cover 256\n", "uncover x\n", "dupn x\n",
    "pushint\n", "pushint x\n", "pushint 18446744073709551616\n", "pushints\n", "pushints 1 x\n",
    "pushbytes\n", "pushbytes x\n", "pushbytes 0x01 0x02\n", "pushbytess\n", "pushbytess 0x01 x\n",
    "intcblock\n", "intcblock x\n", "bytecblock\n", "bytecblock x\n", 'bytecblock 0x01 "a"\n',
    "asset_holding_get\n", "asset_holding_get Foo\n", "asset_holding_get AssetBalance 1\n",
    "app_params_get Foo\n", "acct_params_get Foo\n", "asset_params_get Foo\n", "block Foo\n",
    "json_ref Foo\n", "ecdsa_verify Foo\n", "ec_add Foo\n", "vrf_verify Foo\n", "base64_decode Foo\n",
    "base64_decode\n", "ecdsa_pk_decompress Foo\n", "ecdsa_pk_recover Foo\n", "ec_pairing_check Foo\n",
    "box_create\n", "unknown_opcode\n", "unknown_opcode 1\n", "INT 1\n", "Int 1\n", " \n\n\tint 1\n",
    "int 1\r\nint 2\r\n", "int 1;int 2\n", "int 1,2\n", "int(1)\n", "int 1 // \u00e9\n", "\u00e9\n",
    "int\t1\n", "int  1  \n", "\u00a0int 1\n", "int 1\u00a0\n", "int\u00a01\n",
]


METHODS = [
    "add(uint64,uint64)uint64", "f()void", "f()", "f", "(", ")", "f(", "f)", "(a)void", "f(uint64)void)",
    "f(uint7)void", "f(uint0)void", "f(uint8)void", "f(uint512)void", "f(uint520)void", "f(uint)void",
    "f(uint+8)void", "f(uint08)void", "f(uint65536)void", "f(uint99999999999)void", "f(ufixed8x1)void",
    "f(ufixed8x0)void", "f(ufixed8x161)void", "f(ufixed7x2)void", "f(ufixed)void", "f(ufixed8)void",
    "f(ufixed08x1)void", "f(ufixed8x01)void", "f(ufixed99999x1)void", "f(ufixed8x99999)void",
    "f(byte[])void", "f(byte[3])void", "f(byte[03])void", "f(byte[0])void", "f(byte[65536])void",
    "f(byte[65535])void", "f(byte[-1])void", "f(byte[])[])void", "f([])void", "f(A[3])void", "f(a b)void",
    "f((uint64,bool))void", "f((uint64,bool)[])void", "f((uint64,bool)[2][3])void", "f(())void", "f((()))void",
    "f((,))void", "f((uint64,))void", "f((,uint64))void", "f((uint64,,bool))void", "f((uint64)void", "f(uint64))void",
    "f(uint64,)void", "f(,uint64)void", "f(,)void", "f(uint64,,bool)void", "f((uint64,(bool,address))[])void",
    "f(txn,pay,keyreg,acfg,axfer,afrz,appl,account,asset,application)void", "f(account[])void", "f(txn[])void",
    "f(string,bool,address,byte)string", "f()string[]", "f()(string,bool)", "f()bad", "f()uint7", "f()void[]",
    "f()Void", "f(Uint64)void", "f(bool[])bool[2]", "f(uint64[2][])void", "f(uint64[][])void", "f(uint64[2]2)void",
    "f(uint64[2)void", "f(uint64]2[)void", "f((uint64,bool)[2)void", "f(((uint64)))void", "f(((uint64),bool))void",
    "(uint64)void", "a(b(c)d)e", "a(b)c)", "a(b()c", "\u00e9(uint64)void", "f(\u00e9)void", "f()\u00e9",
    "f(uint64)\tvoid", "f( uint64)void", "f(uint64 )void", "f(uint64, bool)void", "  f()void", "f()void  ",
    "ab(uint64[3],(byte,bool)[],string)(address,uint256)", "x(uint256,uint256)uint256", "f(ufixed64x10)ufixed128x20",
]

ADDRS = [
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKR",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay5hfkq",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFK",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQQ",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ=",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ======",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "A", "AA", "0", "1", "!",
    "7777777777777777777777777777777777777777777777777777777Y5HFKQ", "JDVSF2X5SQTSNYVW7CYY5QEQ6L2YBQDKXAWTPD7EXYATQ2H6UBI3XIBK6U",
    "Y5HFKQ", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5H1KQ", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFK\u00e9",
]

B64S = [
    "AA==", "AA=", "AA", "A", "AAA", "AAAA", "AAAAA", "AAAAAA==", "AAAAAAA=", "AAAAAAAA", "====", "=", "==", "AA===",
    "AA==AA", "A=", "A===", "AA=A", "AAA=A", "AAA==", "AA==\r", "AA\r==", "\rAA==", "A\rA==", "AA=\r=", "A*==", "AA==*",
    "AAAA\r", "AAAA\rAAAA", "+/+/", "-_-_", "A-A=", "\u00e9A==", "AAA\u00e9", "AQID", "AQIDBA==", "AQIDBAU=", "Zm9v", "Zm9vYg==",
    "Zm9vYmE=", "Zm9vYmFy", "Zm9vYmFyZg", "////", "////AAAA////AAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
]

B32S = [
    "ME======", "ME", "M", "MFRGG===", "MFRGG", "MFRGGZ==", "MFRGGZ=", "MFRGGZDF", "MFRGGZDFMY======", "MFRGGZDFMY",
    "me======", "me", "MFRGG====", "MFRGG=", "MFRGG==", "ME=====", "ME=======", "ME=====A", "=", "======", "A=======", "AA======",
    "AAA=====", "AAAA====", "AAAAA===", "AAAAAA==", "AAAAAAA=", "AAAAAAAA", "AAAAAAAAA", "AAAAAAAA=", "AAAAAAAA======",
    "AAAAAAAAAAAAAAAA", "ME\r======", "M\rE======", "ME======\r", "MFRG1===", "MFRGG0==", "8", "1", "AAAAAAAA\u00e9", "\u00e9",
    "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======", "MZXW6YTBOI", "MZXW6Y", "MZXW6YT", "MZXW6YTBO",
]

HEXES = [
    "0x", "0x0", "0x00", "0x0g", "0xg0", "0xGG", "0x01", "0xAb", "0xaB12", "0X01", "0x\u00e9", "0x0\u00e9", "0x 1", "0x-1", "0x+1",
    "0x" + "ab" * 4096, "0x" + "ab" * 4097, "0x" + "ab" * 4097 + "z", "0x1_0", "0x0x1",
]

STRS = [
    '""', '"a"', '"abc def"', '"a\\"b"', '"a\\\\"', '"a\\\\\\"b"', '"\\n\\r\\t"', '"\\q"', '"\\x"', '"\\x4"', '"\\x41"',
    '"\\x4g"', '"\\xg4"', '"\\x41\\x42"', '"\\x\\x41"', '"\\x4\\x1"', '"\\\\x41"', '"\\"', '"\\', '"', '"a', 'a"', '"a"b"',
    '"\u00e9"', '"\\\u00e9"', '"\\x\u00e9\u00e9"', '"\\x4\u00e9"', '"a\\', '"\\xz"', '"\\x4z"', '"a b" c', '"a;b"', '"a//b"', '"a" // c',
    '"\\x00\\xff"', '"\\u0041"', '"\\0"', '"\\a"', "'a'", '"a\tb"', '"' + "a" * 4097 + '"',
]

EXTRA_TOKENS = (
    ADDRS[:8]
    + [f"b64({b})" for b in B64S[:20]] + [f"b32({b})" for b in B32S[:20]]
    + HEXES[:12] + STRS[:30] + ['"' + m + '"' for m in METHODS[:30]]
)

MACRO_NAMES = [
    "X", "x1", "1x", "-x", "+x", "-1", "+1", "-", "+", "_", "a_b", "a-b", "a.b", "a$b", "a@b", "a:b", "a(b", "a)b", "a;b", "a#b",
    "int", "byte", "addr", "method", "txn", "gtxn", "gtxns", "extract", "replace", "b64", "base64", "b32", "base32", "pushint",
    "pushbytes", "add", "+=", "b+", "return", "Sender", "Fee", "GroupIndex", "ApplicationID", "NoOp", "pay", "OptIn", "appl",
    "BN254g1", "StdEncoding", "Secp256k1", "AssetBalance", "AcctBalance", "CurrentApplicationID", "Accounts", "unknown",
    "\u00e9", "\u00e9t\u00e9", "\u0661", "x\u0661", "\u00b2", "x\u00b2", "\u00a0", "x\u00a0y", "\u2028", "\u4e16\u754c", "\u0301",
    "x\u0301", "\U0001f600", "TMPL_X", "label", "L0", "main",
]


def extra_programs(versions):
    out = []
    for version in versions:
        hdr = f"#pragma version {version}\n"
        for m in METHODS:
            out.append(hdr + 'method "' + m + '"\n')
            out.append(hdr + 'method "' + m + '"   // c\n')
        out.append(hdr + 'method "f()void" "g()void"\n')
        out.append(hdr + "method\n")
        out.append(hdr + 'method "f()void\n')
        for a in ADDRS:
            out.append(hdr + f"addr {a}\n")
            out.append(hdr + f"int 1\n  addr {a}  // c\n")
        for a in ADDRS[:4]:
            out.append(hdr + f"addr {a} {a}\n")
        for b in B64S:
            out.append(hdr + f"byte b64 {b}\n")
            out.append(hdr + f"byte base64 {b}\n")
            out.append(hdr + f"byte b64({b})\n")
            out.append(hdr + f"byte base64({b})\n")
            out.append(hdr + f"pushbytes b64({b})\n")
            out.append(hdr + f"bytecblock b64({b}) 0x01\n")
            out.append(hdr + f"bytecblock 0x01 base64 {b}\n")
            out.append(hdr + f"pushbytess 0x01 base64({b})\n")
        for b in B32S:
            out.append(hdr + f"byte b32 {b}\n")
            out.append(hdr + f"byte base32 {b}\n")
            out.append(hdr + f"byte b32({b})\n")
            out.append(hdr + f"byte base32({b})\n")
            out.append(hdr + f"pushbytes base32({b})\n")
            out.append(hdr + f"bytecblock base32({b}) 0x01\n")
            out.append(hdr + f"bytecblock 0x01 b32 {b}\n")
            out.append(hdr + f"pushbytess b32({b}) base32 {b}\n")
            out.append(hdr + f"addr {b}\n")
        for h in HEXES:
            out.append(hdr + f"byte {h}\n")
            out.append(hdr + f"pushbytes {h}\n")
            out.append(hdr + f"bytecblock {h}\n")
            out.append(hdr + f"pushbytess {h} 0x01\n")
        for st in STRS:
            out.append(hdr + f"byte {st}\n")
            out.append(hdr + f"pushbytes {st}\n")
            out.append(hdr + f"bytecblock {st}\n")
            out.append(hdr + f"method {st}\n")
            out.append(hdr + f"int 1\n{st}\n")
            out.append(hdr + f"byte {st} {st}\n")
        for n in MACRO_NAMES:
            out.append(hdr + f"#define {n} int 1\n{n}\n")
            out.append(f"#define {n} int 1\n{hdr}{n}\n")
            out.append(hdr + f"{n}:\n#define {n} int 1\n")
            out.append(hdr + f"#define {n} int 1\n{n}:\n")
            out.append(f"#define {n} int 1\n#pragma version {version}\n")
        out.append(hdr + "#define A B\n#define B A\nA\n")
        out.append(hdr + "#define A B\n#define B C\n#define C A\n")
        out.append(hdr + "#define A int\n#define B 1\nA B\n")
        out.append(hdr + "#define A txn\nA Foo\nA\nA Sender Sender\n")
        out.append(hdr + "#define A txn Foo\nA\n")
        out.append(hdr + "#define A Foo\ntxn A\nA\n")
        out.append(hdr + "#define A ; int 1\nA\nA A\n")
        out.append(hdr + "#define A int 1 ; int 2\nA\n")
        out.append(hdr + "#define A pushint\nint 1\nA\nA 1 2\n")
        out.append(hdr + "#define A byte\nA 0xg\nA\nA b64 !\n")
        out.append(hdr + "#define A +\nint 1\nA\n")
        out.append(hdr + "#define A int 1\nA: A\n")
        out.append(hdr + "#define A int 1\n#define A int 2\nA\n")
        out.append(hdr + "#define A\n")
        out.append(hdr + "#define\n")
        out.append(hdr + "#define A B C D\nA\n")
        out.append(hdr + "#define a txn\n#define b Sender\na b\na\nb\n")
        out.append("#define A txn\n#define B Sender\n" + hdr + "A B\nA\nB\n")
        out.append(hdr + "#pragma version " + str(version) + "\n#pragma version " + str(version + 1) + "\n")
        out.append(hdr + "#pragma version " + str(version) + "\n")
        out.append("L:\n#pragma version " + str(version) + "\n")
        out.append("int 1\n#pragma version " + str(version) + "\n")
        out.append("// c\n#pragma version " + str(version) + "\nint 1\n")
        out.append("#pragma version " + hex(version) + "\nint 1\n")
        out.append("#pragma version 0b1000\nint 1\n")
        out.append("#pragma version 0o10\nint 1\n")
        out.append("#pragma version 1_0\nint 1\n")
        out.append("#pragma version 8\n#pragma version 0x8\nint 1\n")
        out.append("#pragma typetrack false\n#pragma typetrack true\nint 1\nint 1\nbyte 0x01\n+\n")
        out.append("#pragma autosalt true\n#pragma autosalt false\nint 1\n")
        out.append("#pragma autosalt TRUE\nint 1\n")
        out.append("#pragma autosalt t\nint 1\n")
        out.append("#pragma autosalt 2\nint 1\n")
        out.append("#pragma autosalt true x y\nint 1\n")
        out.append("int 1\n#pragma autosalt true\n")
        out.append("int 1\n#pragma typetrack true\n")
        out.append("#pragma    version   " + str(version) + "   \nint 1\n")
        out.append("#pragma\tversion\t" + str(version) + "\nint 1\n")
        out.append("#pragma version " + str(version) + " // c\nint 1\n")
        out.append("#pragma version " + str(version) + "; int 1\n")
        out.append("   #pragma version " + str(version) + "\nint 1\n")
        out.append("#pragma version " + str(version) + "\n   #define A int 1\nA\n")
        out.append("; #pragma version " + str(version) + "\n")
        out.append("\t#\n")
        out.append("# pragma version " + str(version) + "\n")
        out.append("#define A 1\n#define B A\n#pragma version " + str(version) + "\nint B\n")
        out.append("#define pop 1\n#pragma version 4\n")
        out.append("#define pop 1\npop\n#pragma version 4\n")
        out.append("#define pop 1\nint 1\n")
        out.append("#define Sender 1\n#pragma version 4\nint 1\n")
    out.append("int 1\n" * 10 + "#define A 1\n")
    out.append("#pragma version 8\nint 1\n" + "x" * 70000 + "\nint 2\n")
    out.append("#pragma version 8\n" + "x" * 65535 + "\nint 2\n")
    out.append("#pragma version 8\n" + "x" * 65536 + "\nint 2\n")
    out.append("#pragma version 8\n" + "x" * 65534 + "\r\nint 2\n")
    out.append("#pragma version 8\r\nint 1\r\n")
    out.append("#pragma version 8\rint 1\r")
    out.append("#pragma version 8\nint 1\r")
    out.append("#pragma version 8\nint 1\r\r\n")
    out.append("#pragma version 8\nint\r1\n")
    out.append("#pragma version 8\n\ufeffint 1\n")
    out.append("\ufeff#pragma version 8\nint 1\n")
    out.append("#pragma version 8\nint 1\n\x00\n")
    out.append("#pragma version 8\nint\x001\n")
    out.append("#pragma version 8\n\x0bint 1\n")
    out.append("#pragma version 8\nint 1\x0c\n")
    return out


# Byte sequences that are not (all) valid UTF-8, plus valid ones that stress the
# Rust assembler's lossless text form (U+10FF00..U+10FFFF are four-byte characters).
BAD_BYTES = [
    b"\xff", b"\xfe", b"\x80", b"\xc3\x28", b"\xe2\x82", b"\xe2\x82\xac\xe2", b"\xf0\x28\x8c\x28",
    b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xf4\x8f\xbc", b"\xf4",
    b"\xf4\x8f\xbc\x80", b"\xf4\x8f\xbf\xbf", b"\xf4\x8f\xbc\x80\xff", b"\xff\xf4\x8f\xbc\x80",
    b"\xef\xbf\xbd", b"\xc3\xa9\xff",
]
# Templates; `%s` is replaced by a byte sequence.
NON_UTF8_TEMPLATES = [
    b'byte "%s"\nint 1\n', b'byte "a%sb"\n', b'byte "\\%s"\n', b'byte "\\x%s"\n', b'byte "\\x1%s"\n',
    b'int 1 // %s\n', b'// %s\nint 1\n', b'int 1 //%s', b'byte "x" // %s\n', b'byte "a//%s"\n',
    b'%s:\nint 1\n', b'int 1\n%s: int 1\n', b'b %s\n%s:\nint 1\n', b'int 1\nbnz %s\n', b'b L%s\nL:\n',
    b'%s\n', b'%s 1\n', b'%s foo\n', b'int 1\n%s\n', b'foo%s\n', b'int 1; %s; int 2\n', b'int 1;%s\n',
    b'int %s\n', b'int 1%s\n', b'int 1 %s\n', b'int 0x%s\n', b'int 0%s\n',
    b'byte 0x%s\n', b'byte 0x0%s\n', b'byte 0x%s0\n', b'byte b64(%s)\n', b'byte b64(AA%s)\n', b'byte b64 %s\n',
    b'byte base64 AA%s\n', b'byte b32 %s\n', b'byte base32(%s)\n', b'byte b32(MFR%s)\n', b'byte %s\n', b'byte\n%s\n',
    b'addr %s\n', b'addr AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%s\n', b'method "%s"\n',
    b'method "f(%s)void"\n', b'method %s\n', b'pushbytes "%s"\npop\nint 1\n', b'pushbytes %s\n',
    b'pushint %s\n', b'bytecblock "%s"\n', b'bytecblock 0x01 %s\n', b'intcblock %s\n',
    b'txn %s\n', b'txna Accounts %s\n', b'gtxn 0 %s\n', b'global %s\n', b'itxn_field %s\n', b'asset_holding_get %s\n',
    b'#define %s 1\n', b'#define X %s\nX\n', b'#define X int 1 // %s\nX\n', b'#define X%s 1\n',
    b'#define X 1\nX%s\n', b'#define X int 1\nX; %s\n', b'#define -%s 1\n',
    b'#pragma %s\n', b'#pragma version %s\n', b'#pragma typetrack %s\n', b'#pragma autosalt %s\n',
    b'#pragma version 8 %s\n', b'#pragma version 8 // %s\nint 1\n', b'#%s\n',
    b'int 1\n%s%s\n', b'%s%s%s\n', b'int 1\n  %s  \n', b'\t%s\t\n',
]


def non_utf8_programs(versions):
    out = []
    for version in versions:
        hdr = f"#pragma version {version}\n".encode()
        for tmpl in NON_UTF8_TEMPLATES:
            for bad in BAD_BYTES:
                body = tmpl.replace(b"%s", bad)
                out.append(hdr + body)
                if version == versions[0]:
                    out.append(body)
    # Whole programs that are only invalid bytes, and a long line of them.
    out.extend([b"\xff", b"\xff\xfe\xfd", b"\xf4\x8f\xbc\x80", b"\xf4\x8f\xbc", b"\xff" * 70000, b"a" * 100 + b"\xff" * 70000])
    # Columns: valid multi-byte characters, then an error, with and without
    # invalid bytes before it on the same line.
    for lead in [b"\xc3\xa9", b"\xe2\x82\xac", b"\xf0\x9f\x98\x80", b"\xff", b"\xf4\x8f\xbc\x80"]:
        out.append(b"#pragma version 8\n" + lead + b" foo\n")
        out.append(b"#pragma version 8\nint 1; " + lead + b"; bogus\n")
        out.append(b"#pragma version 8\nbyte \"" + lead + b"\" bogus\n")
        out.append(b"#pragma version 8\nbyte \"" + lead + b"\"\nint 1\nbyte " + lead + b"\n")
        out.append(b"#pragma version 8\nint " + lead + b"\nint 1 2\n")
        out.append(b"#pragma version 8\nbytecblock \"" + lead + b"\"\nbytec_0 1\n")
        out.append(b"#pragma version 8\nint 1\nbz " + lead + b"\n")
        out.append(b"#pragma version 8\n" + lead + b"\nint 1\n")
    return out


def syntax_programs(rnd, versions, count):
    out = []
    for version in versions:
        hdr = f"#pragma version {version}\n"
        for op in PSEUDO:
            toks = GOODARGS.get(op, "").split()
            variants = [[], toks[:-1] if toks else [], toks + ["extra"], toks + ["1", "2"]]
            for i in range(len(toks)):
                for j in JUNK:
                    t = list(toks)
                    t[i] = j
                    variants.append(t)
            for j in JUNK:
                variants.append([j])
            for t in variants:
                out.append(hdr + " ".join([op] + t) + "\n")
                out.append(hdr + "int 1\n  " + " ".join([op] + t) + "   // c\n")
        for body in BODIES:
            out.append(hdr + body)
            out.append(body)
    for ver in ["0", "1", "2", "99", "-1", "x", "08", "+8", "8.0", "0x8", "4294967296", "18446744073709551615"]:
        out.append(f"#pragma version {ver}\nint 1\n")
    while len(out) < count:
        lines = []
        for _ in range(rnd.randint(1, 4)):
            args = [rnd.choice(JUNK + list(GOODARGS.values()) + EXTRA_TOKENS) for _ in range(rnd.randint(0, 4))]
            lines.append(" ".join([rnd.choice(PSEUDO)] + args))
        out.append(f"#pragma version {rnd.choice(versions)}\n" + "\n".join(lines) + "\n")
    return out


def mutate_sources(rnd, corpus, count):
    srcs = sorted(Path(corpus, "sources").glob("*.teal"))
    out = []
    for _ in range(count):
        lines = rnd.choice(srcs).read_text(encoding="utf-8", errors="replace").split("\n")
        for _ in range(rnd.randint(1, 3)):
            i = rnd.randrange(len(lines))
            toks = lines[i].split(" ")
            r = rnd.random()
            if r < 0.25:
                del toks[rnd.randrange(len(toks))]
            elif r < 0.45:
                toks.insert(rnd.randrange(len(toks) + 1), rnd.choice(JUNK + EXTRA_TOKENS))
            elif r < 0.65:
                toks[rnd.randrange(len(toks))] = rnd.choice(JUNK + EXTRA_TOKENS)
            elif r < 0.8:
                toks.append(toks[-1])
            elif r < 0.9:
                lines.insert(i, rnd.choice(lines))
            else:
                toks = toks[: rnd.randrange(len(toks) + 1)]
            lines[i] = " ".join(toks)
        out.append("\n".join(lines))
    return out


def mutate_bytes(rnd, corpus, count):
    """Byte-level mutations of the original sources (issue #2388): insert, replace or
    truncate at a random offset with sequences that are not UTF-8, so the invalid
    bytes land in comments, string literals, identifiers and between tokens."""
    srcs = sorted(Path(corpus, "sources").glob("*.teal"))
    out = []
    for _ in range(count):
        data = bytearray(rnd.choice(srcs).read_bytes())
        for _ in range(rnd.randint(1, 3)):
            at = rnd.randrange(len(data) + 1)
            bad = rnd.choice(BAD_BYTES)
            r = rnd.random()
            if r < 0.6:
                data[at:at] = bad
            elif r < 0.9:
                data[at : at + rnd.randint(1, 3)] = bad
            else:
                del data[at:]
        out.append(bytes(data))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--seed", type=int, default=2369)
    ap.add_argument("--count", type=int, default=20000)
    ap.add_argument("--versions", default="3,8,13")
    ap.add_argument("--mutate", type=int, default=0)
    ap.add_argument("--mutate-from")
    ap.add_argument("--mutate-bytes", type=int, default=0, help="byte-level non-UTF-8 mutations of --mutate-from")
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    sdir = os.path.join(a.out, "sources")
    os.makedirs(sdir, exist_ok=True)
    seen = set()
    versions = [int(v) for v in a.versions.split(",") if v]
    texts = syntax_programs(rnd, versions, a.count) + extra_programs(versions)
    if a.mutate:
        texts += mutate_sources(rnd, a.mutate_from, a.mutate)
    texts += non_utf8_programs(versions)
    if a.mutate_bytes:
        texts += mutate_bytes(rnd, a.mutate_from, a.mutate_bytes)
    for text in texts:
        data = text if isinstance(text, bytes) else text.encode()
        sha = hashlib.sha256(data).hexdigest()
        if sha in seen:
            continue
        seen.add(sha)
        with open(os.path.join(sdir, sha + ".teal"), "wb") as f:
            f.write(data)
    print(f"{len(seen)} sources in {sdir}")


if __name__ == "__main__":
    main()
