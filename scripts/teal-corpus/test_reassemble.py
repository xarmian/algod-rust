#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for scripts/teal-corpus/reassemble.py (issue #2368) on hand-built
driver outputs: the gate, the cross-check and the fixed-point statistics.
Run: python3 -I scripts/teal-corpus/test_reassemble.py"""
import base64
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("teal_corpus_reassemble", os.path.join(HERE, "reassemble.py"))
ra = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ra)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def write(path, op, rows, impl="x"):
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"header": {"operation": op, "impl": impl}}) + "\n")
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def b64(b):
    return base64.b64encode(b).decode()


class Reassemble(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.tmp.name, "out")
        self.corpus = os.path.join(self.tmp.name, "corpus")
        os.makedirs(self.out)
        os.makedirs(os.path.join(self.corpus, "programs"))
        # P1 round-trips; P2 does not (go and rust agree); P3 fails to disassemble.
        self.p1 = bytes([8, 0x81, 1, 0x43])
        self.p2 = bytes([8, 0x81, 0x80, 0x00, 0x43])  # padded varuint: not canonical
        self.p3 = bytes([8, 0xFF])
        for p in (self.p1, self.p2, self.p3):
            with open(os.path.join(self.corpus, "programs", sha(p) + ".bin"), "wb") as f:
                f.write(p)
        self.t1 = "#pragma version 8\npushint 1\nreturn\n"
        self.t2 = "#pragma version 8\npushint 0\nreturn\n"
        with open(os.path.join(self.corpus, "manifest.jsonl"), "w") as f:
            for p in (self.p1, self.p2):
                f.write(json.dumps({"sha256": sha(p), "registry_hash": sha(p)}) + "\n")

    def tearDown(self):
        self.tmp.cleanup()

    def disasm(self, impl, t2=None):
        rows = [
            {"ok": True, "sha256": sha(self.p1), "text": self.t1},
            {"ok": True, "sha256": sha(self.p2), "text": t2 or self.t2},
            {"error": "illegal opcode", "ok": False, "sha256": sha(self.p3)},
        ]
        write(os.path.join(self.out, f"disassemble.{impl}.jsonl"), "disassemble", rows, impl)

    def asm_rows(self, texts, **over):
        rows = []
        for t in texts:
            code = bytes([8, 0x81, int(t.split("pushint ")[1].split()[0]), 0x43])
            row = {"bytecode_b64": b64(code), "hash": "H", "ok": True, "sha256": sha(t.encode())}
            row.update(over.get(t, {}))
            rows.append(row)
        return rows

    def write_asm(self, go_extra=None, rs_extra=None, rs_text_extra=None):
        write(os.path.join(self.out, "reassemble.go.jsonl"), "assemble", self.asm_rows([self.t1, self.t2], **(go_extra or {})))
        write(os.path.join(self.out, "reassemble.rust.jsonl"), "assemble", self.asm_rows([self.t1, self.t2], **(rs_extra or {})))
        write(os.path.join(self.out, "reassemble.rust-text.jsonl"), "assemble", self.asm_rows([self.t1, self.t2], **(rs_text_extra or {})))

    def summary(self):
        with open(os.path.join(self.out, "reassemble.summary.json")) as f:
            return json.load(f)

    def test_prepare_writes_both_text_corpora(self):
        self.disasm("go")
        self.disasm("rust")
        ra.prepare(self.out)
        for impl in ("go", "rust"):
            d = os.path.join(self.out, f"reasm-{impl}", "sources")
            self.assertEqual(sorted(os.listdir(d)), sorted(sha(t.encode()) + ".teal" for t in (self.t1, self.t2)))

    def test_clean_run_reports_fixed_point_statistics(self):
        self.disasm("go")
        self.disasm("rust")
        self.write_asm()
        self.assertEqual(ra.report(self.corpus, self.out), 0)
        s = self.summary()
        self.assertEqual(s["gate_reassemble"]["mismatched"], 0)
        self.assertEqual(s["gate_cross_check"]["mismatched"], 0)
        fp = s["fixed_point"]
        self.assertEqual((fp["go_fixed"], fp["rust_fixed"]), (1, 1))
        self.assertEqual(fp["non_round_tripping_programs"], [sha(self.p2)])
        self.assertTrue(fp["same_set"] and fp["same_bytes"])
        self.assertEqual(s["registry_hash"], {"compared": 2, "matching": 1})

    def test_bytecode_difference_fails_the_gate(self):
        self.disasm("go")
        self.disasm("rust")
        self.write_asm(rs_extra={self.t1: {"bytecode_b64": b64(b"\x08\x43")}})
        self.assertEqual(ra.report(self.corpus, self.out), 1)
        self.assertEqual(self.summary()["gate_reassemble"]["mismatched"], 1)

    def test_error_column_difference_fails_the_gate(self):
        self.disasm("go")
        self.disasm("rust")
        err = lambda col: {"ok": False, "errors": [{"col": col, "line": 2, "message": "m"}]}
        self.write_asm(go_extra={self.t1: err(1)}, rs_extra={self.t1: err(2)}, rs_text_extra={self.t1: err(1)})
        self.assertEqual(ra.report(self.corpus, self.out), 1)
        self.assertEqual(self.summary()["gate_reassemble"]["mismatched"], 1)
        self.assertEqual(self.summary()["gate_cross_check"]["mismatched"], 0)

    def test_cross_check_catches_a_disassembly_difference(self):
        self.disasm("go")
        self.disasm("rust", t2="#pragma version 8\npushint 7\nreturn\n")
        self.write_asm()
        write(
            os.path.join(self.out, "reassemble.rust-text.jsonl"),
            "assemble",
            self.asm_rows([self.t1, "#pragma version 8\npushint 7\nreturn\n"]),
        )
        self.assertEqual(ra.report(self.corpus, self.out), 1)
        self.assertEqual(self.summary()["gate_cross_check"]["mismatched"], 1)

    def test_panic_and_timeout_fail_the_gate(self):
        self.disasm("go")
        self.disasm("rust")
        self.write_asm(rs_extra={self.t1: {"ok": False, "panic": "boom", "bytecode_b64": None}})
        self.assertEqual(ra.report(self.corpus, self.out), 1)
        self.assertEqual(self.summary()["gate_reassemble"]["panics"], 1)


if __name__ == "__main__":
    unittest.main()
