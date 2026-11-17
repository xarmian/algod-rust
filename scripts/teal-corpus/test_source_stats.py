#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for scripts/teal-corpus/source_stats.py (issue #2369) on hand-built
driver outputs, manifest and registry specs: the gate, the shipped-bytecode
comparison and the pragma/generator breakdowns.
Run: python3 -I scripts/teal-corpus/test_source_stats.py"""
import base64
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("teal_corpus_source_stats", os.path.join(HERE, "source_stats.py"))
ss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ss)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def b64(b):
    return base64.b64encode(b).decode()


def write(path, op, rows):
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"header": {"operation": op}}) + "\n")
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


class SourceStats(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.work = os.path.join(root, "work")
        self.corpus = os.path.join(self.work, "corpus")
        self.out = os.path.join(root, "out")
        os.makedirs(os.path.join(self.corpus, "programs"))
        os.makedirs(os.path.join(self.corpus, "sources"))
        os.makedirs(os.path.join(self.work, "registry", "approval-programs", "aaa"))
        os.makedirs(self.out)
        # S1 assembles to the shipped program; S2 assembles to something else;
        # S3 is a TMPL_ source both sides reject identically.
        self.prog1 = bytes([8, 0x81, 1])
        self.prog2 = bytes([10, 0x81, 1])
        self.prog3 = bytes([10, 0x81, 2])
        self.s = [b"#pragma version 8\nint 1\n", b"#pragma version 10\nint 2\n", b"#pragma version 10\nint TMPL_X\n"]
        manifest = []
        for src in self.s:
            with open(os.path.join(self.corpus, "sources", sha(src) + ".teal"), "wb") as f:
                f.write(src)
        for i, (p, src, gen) in enumerate(
            [(self.prog1, self.s[0], "puya"), (self.prog2, self.s[1], None), (self.prog3, self.s[2], "algod")]
        ):
            with open(os.path.join(self.corpus, "programs", sha(p) + ".bin"), "wb") as f:
                f.write(p)
            rel = f"approval-programs/aaa/{sha(p)}.arc56.json"
            spec = {"source": {"approval": ""}, "byteCode": {"approval": b64(p)}}
            if gen:
                spec["compilerInfo"] = {"compiler": gen}
            with open(os.path.join(self.work, "registry", rel), "w", encoding="utf-8") as f:
                json.dump(spec, f)
            manifest.append({"sha256": sha(p), "source_sha256": sha(src), "registry_path": rel,
                             "version": 8 if i == 0 else 10, "has_template_vars": i == 2})
        with open(os.path.join(self.corpus, "manifest.jsonl"), "w", encoding="utf-8") as f:
            for m in manifest:
                f.write(json.dumps(m, sort_keys=True) + "\n")
        self.ok1 = {"ok": True, "sha256": sha(self.s[0]), "bytecode_b64": b64(self.prog1), "hash": "h1"}
        self.ok2 = {"ok": True, "sha256": sha(self.s[1]), "bytecode_b64": b64(bytes([10, 0x81, 9])), "hash": "h2"}
        self.err3 = {"ok": False, "sha256": sha(self.s[2]), "errors": [{"col": 4, "line": 2, "message": "m"}]}

    def run_report(self, go, rust):
        write(os.path.join(self.out, "assemble.go.jsonl"), "assemble", go)
        write(os.path.join(self.out, "assemble.rust.jsonl"), "assemble", rust)
        rc = ss.report(self.corpus, self.out)
        with open(os.path.join(self.out, "source.summary.json"), encoding="utf-8") as f:
            return rc, json.load(f)

    def test_statistics_and_clean_gate(self):
        rows = [self.ok1, self.ok2, self.err3]
        rc, s = self.run_report(rows, rows)
        self.assertEqual(rc, 0)
        self.assertEqual(s["sources"], 3)
        self.assertEqual(s["assemble"], 2)
        self.assertEqual(s["error"], 1)
        self.assertEqual(s["mismatched"], 0)
        self.assertEqual(s["equal_shipped_bytecode"], 1)
        self.assertEqual(s["by_program_version"]["8"], {"programs": 1, "assemble": 1, "equal_shipped": 1})
        self.assertEqual(s["by_program_version"]["10"], {"programs": 2, "assemble": 1, "equal_shipped": 0})
        self.assertEqual(s["by_source_pragma_version"]["8"], {"sources": 1, "assemble": 1})
        self.assertEqual(s["by_source_pragma_version"]["10"], {"sources": 2, "assemble": 1})
        self.assertEqual(s["by_generator"]["puya"]["equal_shipped"], 1)
        self.assertEqual(s["by_generator"]["algod"]["assemble"], 0)
        self.assertEqual(s["by_generator"]["unknown"]["assemble"], 1)
        self.assertEqual(s["template_variable_sources"], {"programs": 1, "both_error_identical": 1})

    def test_mismatch_fails_the_gate_per_field(self):
        bad = dict(self.ok1, hash="other")
        bad_err = dict(self.err3, errors=[{"col": 0, "line": 2, "message": "m"}])
        rc, s = self.run_report([self.ok1, self.ok2, self.err3], [bad, self.ok2, bad_err])
        self.assertEqual(rc, 1)
        self.assertEqual(s["mismatched"], 2)
        self.assertEqual(s["mismatched_by_field"], {"errors": 1, "hash": 1})

    def test_panic_and_timeout_fail_the_gate(self):
        rc, s = self.run_report([self.ok1, self.ok2, self.err3],
                                [self.ok1, {"sha256": self.ok2["sha256"], "ok": False, "timeout": True}, self.err3])
        self.assertEqual(rc, 1)
        self.assertEqual(s["timeouts"], 1)


if __name__ == "__main__":
    unittest.main()
