#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for scripts/teal-corpus/extract.py (issue #2365) on a synthetic
registry tree. Run: python3 -I scripts/teal-corpus/test_extract.py"""
import base64
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("teal_corpus_extract", os.path.join(HERE, "extract.py"))
ex = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ex)


def b64(b):
    return base64.b64encode(b).decode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


PROG_A = bytes([9, 0x81, 1, 0x43])           # v9
PROG_B = bytes([10, 0x81, 2, 0x43])          # v10
PROG_T = bytes([8, 0x80, 0x08]) + b"TMPL_X"  # has TMPL_ marker
SRC_A = b"#pragma version 9\nint 1\nreturn\n"
SRC_A2 = b"#pragma version 9\nint 1\nreturn // other\n"


def put(root, kind_dir, name, content):
    h = name[:3]
    d = os.path.join(root, kind_dir, h)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name + ".arc56.json")
    with open(p, "wb") as f:
        f.write(content if isinstance(content, bytes) else json.dumps(content).encode())
    return p


def spec(approval=None, clear=None, src_a=None, src_c=None, **extra):
    s = dict(extra)
    if approval is not None or clear is not None:
        s["byteCode"] = {}
        if approval is not None:
            s["byteCode"]["approval"] = approval
        if clear is not None:
            s["byteCode"]["clear"] = clear
    if src_a is not None or src_c is not None:
        s["source"] = {}
        if src_a is not None:
            s["source"]["approval"] = src_a
        if src_c is not None:
            s["source"]["clear"] = src_c
    return s


def build_registry(root):
    # good approval, hash filed correctly, with source
    put(root, "approval-programs", sha(PROG_A), spec(approval=b64(PROG_A), src_a=b64(SRC_A)))
    # same program again under a wrong hash (dup, different source) in approval,
    put(root, "approval-programs", "aaa" + "0" * 61, spec(approval=b64(PROG_A), src_a=b64(SRC_A2)))
    # and the same bytes as a clear program -> kind both
    put(root, "clear-programs", "bbb" + "0" * 61, spec(clear=b64(PROG_A)))
    # clear-only distinct program with a wrong registry hash
    put(root, "clear-programs", "ccc" + "0" * 61, spec(clear=b64(PROG_B)))
    # template variables via spec field and via TMPL_ marker
    put(root, "approval-programs", "ddd" + "0" * 61, spec(approval=b64(PROG_B), templateVariables={"X": {}}))
    put(root, "approval-programs", "eee" + "0" * 61, spec(approval=b64(PROG_T)))
    # skip reasons
    put(root, "approval-programs", "f00" + "0" * 61, b"{not json")
    put(root, "approval-programs", "f01" + "0" * 61, b"\xff\xfe")
    put(root, "approval-programs", "f02" + "0" * 61, b"[1, 2]")
    put(root, "approval-programs", "f03" + "0" * 61, spec(name="x"))
    put(root, "approval-programs", "f04" + "0" * 61, spec(approval="***not base64***"))
    put(root, "approval-programs", "f05" + "0" * 61, spec(approval=""))
    put(root, "approval-programs", "f06" + "0" * 61, spec(src_a=b64(SRC_A)))
    put(root, "approval-programs", "f07" + "0" * 61, spec(approval=b64(PROG_A), src_a="!!"))
    put(root, "approval-programs", "f08" + "0" * 61, {"byteCode": "nope"})
    # an unrelated file in the directory must be ignored (not counted)
    put_dir = os.path.join(root, "approval-programs", "f00")
    with open(os.path.join(put_dir, "f00.txt"), "w") as f:
        f.write("https://example.invalid\n")


class ExtractTests(unittest.TestCase):
    def run_extract(self, **kw):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        reg = os.path.join(tmp.name, "reg")
        out = os.path.join(tmp.name, "out")
        os.makedirs(reg)
        build_registry(reg)
        corpus = ex.extract(reg, out, "1" * 40, "2026-11-16T00:00:00Z", **kw)
        with open(os.path.join(out, "manifest.jsonl")) as f:
            rows = [json.loads(line) for line in f]
        return tmp.name, out, corpus, rows

    def test_counts_and_skip_reasons(self):
        _, _, c, rows = self.run_extract()
        self.assertEqual(c["skipped"], {
            "invalid_json": 2, "not_an_object": 1, "missing_bytecode": 2,
            "invalid_base64": 1, "empty_program": 1,
            "source_without_bytecode": 1, "source_invalid_base64": 1,
        })
        self.assertEqual(c["counts"]["entries"], 15)
        self.assertEqual(c["counts"]["programs"], 3)
        self.assertEqual(len(rows), c["counts"]["programs"])

    def test_dedup_across_approval_and_clear(self):
        _, out, _, rows = self.run_extract()
        by = {r["sha256"]: r for r in rows}
        self.assertEqual(by[sha(PROG_A)]["kind"], "both")
        self.assertEqual(by[sha(PROG_B)]["kind"], "both")  # clear ccc.. and approval ddd..
        self.assertEqual(by[sha(PROG_T)]["kind"], "approval")
        self.assertTrue(os.path.isfile(os.path.join(out, "programs", sha(PROG_A) + ".bin")))
        with open(os.path.join(out, "programs", sha(PROG_A) + ".bin"), "rb") as f:
            self.assertEqual(f.read(), PROG_A)

    def test_row_fields(self):
        _, out, _, rows = self.run_extract()
        a = {r["sha256"]: r for r in rows}[sha(PROG_A)]
        self.assertEqual(a["size"], len(PROG_A))
        self.assertEqual(a["version"], 9)
        self.assertTrue(a["registry_hash_matches"])  # the correctly filed copy wins
        self.assertEqual(a["registry_hash"], sha(PROG_A))
        self.assertEqual(a["registry_path"], "approval-programs/%s/%s.arc56.json" % (sha(PROG_A)[:3], sha(PROG_A)))
        self.assertEqual(a["source_sha256"], sha(SRC_A))
        self.assertEqual(a["extra_source_sha256"], [sha(SRC_A2)])
        self.assertFalse(a["has_template_vars"])
        for s in (SRC_A, SRC_A2):
            with open(os.path.join(out, "sources", sha(s) + ".teal"), "rb") as f:
                self.assertEqual(f.read(), s)

    def test_hash_mismatch_reported_not_fatal(self):
        _, _, c, rows = self.run_extract()
        b = {r["sha256"]: r for r in rows}[sha(PROG_B)]
        self.assertFalse(b["registry_hash_matches"])
        self.assertIsNone(b["source_sha256"])
        self.assertEqual(c["counts"]["registry_hash_mismatch"], 2)  # B and T

    def test_template_vars(self):
        _, _, c, rows = self.run_extract()
        by = {r["sha256"]: r for r in rows}
        self.assertTrue(by[sha(PROG_B)]["has_template_vars"])
        self.assertTrue(by[sha(PROG_T)]["has_template_vars"])
        self.assertEqual(c["counts"]["template_var_programs"], 2)

    def test_version_varuint(self):
        self.assertEqual(ex.first_varuint(bytes([0x80, 0x01])), 128)
        self.assertEqual(ex.first_varuint(bytes([0x80])), None)
        self.assertEqual(ex.first_varuint(b""), None)

    def test_orphan_source_still_written(self):
        _, out, c, _ = self.run_extract()
        self.assertEqual(c["counts"]["orphan_sources"], 1)
        self.assertTrue(os.path.isfile(os.path.join(out, "sources", sha(SRC_A) + ".teal")))

    def test_corpus_json_records_sha(self):
        _, out, c, _ = self.run_extract()
        with open(os.path.join(out, "corpus.json")) as f:
            disk = json.load(f)
        self.assertEqual(disk, c)
        self.assertEqual(disk["registry_sha"], "1" * 40)
        self.assertEqual(disk["fetched_at"], "2026-11-16T00:00:00Z")

    def test_deterministic(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        reg = os.path.join(tmp.name, "reg")
        os.makedirs(reg)
        build_registry(reg)
        outs = []
        for i in range(2):
            out = os.path.join(tmp.name, "out%d" % i)
            ex.extract(reg, out, "1" * 40, "t")
            outs.append(out)

        def snap(root):
            res = {}
            for d, _, files in os.walk(root):
                for n in files:
                    p = os.path.join(d, n)
                    with open(p, "rb") as f:
                        res[os.path.relpath(p, root)] = f.read()
            return res
        self.assertEqual(snap(outs[0]), snap(outs[1]))
        self.assertNotIn(b"\r", snap(outs[0])["manifest.jsonl"])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_symlinks_not_followed(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        reg = os.path.join(tmp.name, "reg")
        secret = os.path.join(tmp.name, "secret.json")
        with open(secret, "w") as f:
            json.dump(spec(approval=b64(PROG_A)), f)
        d = os.path.join(reg, "approval-programs", "abc")
        os.makedirs(d)
        try:
            os.symlink(secret, os.path.join(d, "abc.arc56.json"))
        except OSError:
            self.skipTest("cannot create symlink")
        c = ex.extract(reg, os.path.join(tmp.name, "out"))
        self.assertEqual(c["counts"]["programs"], 0)
        self.assertEqual(c["skipped"], {"not_a_regular_file": 1})

    def test_missing_directories_ok(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        c = ex.extract(tmp.name, os.path.join(tmp.name, "out"))
        self.assertEqual(c["counts"]["programs"], 0)
        self.assertIsNone(c["registry_sha"])

    def test_cli_requires_clean_for_nonempty_out(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        reg = os.path.join(tmp.name, "reg")
        out = os.path.join(tmp.name, "out")
        os.makedirs(reg)
        os.makedirs(out)
        with open(os.path.join(out, "x"), "w") as f:
            f.write("x")
        with self.assertRaises(SystemExit):
            ex.main(["--registry-dir", reg, "--out", out, "--work-dir", tmp.name])
        sys.stdout = open(os.devnull, "w")
        try:
            self.assertEqual(ex.main(["--registry-dir", reg, "--out", out, "--work-dir", tmp.name, "--clean",
                                      "--registry-sha", "f" * 40]), 0)
        finally:
            sys.stdout.close()
            sys.stdout = sys.__stdout__
        with open(os.path.join(out, "corpus.json")) as f:
            self.assertEqual(json.load(f)["registry_sha"], "f" * 40)


if __name__ == "__main__":
    unittest.main()
