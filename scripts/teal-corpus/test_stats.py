#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for scripts/teal-corpus/stats.py (issue #2371) on hand-built driver
outputs, manifest, corpus.json and opcode table: every stats.json section, the
never-seen opcode list, the error-class histogram, determinism and the history
series.
Run: python3 -I scripts/teal-corpus/test_stats.py"""
import csv
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("teal_corpus_stats", os.path.join(HERE, "stats.py"))
st = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(st)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def write_rows(path, op, rows, impl="x"):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({"header": {"operation": op, "impl": impl, "go_algorand_tag": "v5.0.5-stable"}}) + "\n")
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


SCRATCH_PANIC = "runtime error: index out of range [300] with length 256"


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.tmp.name
        self.corpus = os.path.join(root, "work", "corpus")
        self.out = os.path.join(root, "out")
        os.makedirs(os.path.join(self.corpus, "programs"))
        os.makedirs(self.out)
        # (bytes, kind, version, registry_hash_matches, source)
        self.progs = [
            (b"\x08" + b"a" * 9, "approval", 8, True, b"src-a"),    # 10 bytes
            (b"\x0a" + b"b" * 19, "clear", 10, True, None),          # 20
            (b"\x0a" + b"c" * 29, "both", 10, False, b"src-c"),      # 30
            (b"\x09" + b"d" * 39, "approval", 9, True, None),        # 40: both reject
            (b"\x0a" + b"e" * 99, "approval", 10, True, None),       # 100: texts differ
        ]
        self.sha = [sha(p[0]) for p in self.progs]
        with open(os.path.join(self.corpus, "manifest.jsonl"), "w", encoding="utf-8", newline="\n") as f:
            for (p, kind, ver, rhm, src), s in zip(self.progs, self.sha):
                f.write(json.dumps({"sha256": s, "kind": kind, "size": len(p), "version": ver,
                                    "registry_hash_matches": rhm, "has_template_vars": False,
                                    "source_sha256": sha(src) if src else None,
                                    "extra_source_sha256": [sha(b"src-extra")] if src == b"src-c" else []},
                                   sort_keys=True) + "\n")
        with open(os.path.join(self.corpus, "corpus.json"), "w", encoding="utf-8") as f:
            json.dump({"registry_sha": "abc123", "fetched_at": "2026-11-17T00:00:00Z"}, f)
        self.opcodes = os.path.join(root, "opcodes.json")
        with open(self.opcodes, "w", encoding="utf-8") as f:
            json.dump({"go_algorand_tag": "v5.0.5-stable",
                       "opcodes": {"pushint": 1, "intcblock": 1, "intc_0": 1, "return": 1, "bnz": 1,
                                   "err": 1, "ed25519verify_bare": 7}}, f)
        t1 = "#pragma version 8\nintcblock 1\nintc_0\nreturn\n"
        t2 = "#pragma version 10\npushint 1\nreturn\n"
        t3 = "#pragma version 10\nL:\npushint 1\n// c\nbnz L\npushint 2 // x\nreturn\n"
        t5g, t5r = "#pragma version 10\npushint 1\n", "#pragma version 10\npushint 2\n"
        err4 = "invalid opcode 0xff at pc=39"
        go = [{"sha256": self.sha[0], "ok": True, "text": t1}, {"sha256": self.sha[1], "ok": True, "text": t2},
              {"sha256": self.sha[2], "ok": True, "text": t3}, {"sha256": self.sha[3], "ok": False, "error": err4},
              {"sha256": self.sha[4], "ok": True, "text": t5g}]
        rs = [dict(r) for r in go]
        rs[4] = {"sha256": self.sha[4], "ok": True, "text": t5r}
        write_rows(os.path.join(self.out, "disassemble.go.jsonl"), "disassemble", go, "go-algorand")
        write_rows(os.path.join(self.out, "disassemble.rust.jsonl"), "disassemble", rs, "algod-rust")
        # source stage: 4 sources; s0 ok identical, s1 error identical, s2 mirrored panic, s3 timeout on rust
        ss = [sha(b"s0"), sha(b"s1"), sha(b"s2"), sha(b"s3")]
        gsrc = [{"sha256": ss[0], "ok": True, "bytecode_b64": "AQ=="},
                {"sha256": ss[1], "ok": False, "errors": [{"line": 3, "col": 4, "message": "unknown opcode: foo"}]},
                {"sha256": ss[2], "ok": False, "panic": SCRATCH_PANIC},
                {"sha256": ss[3], "ok": True, "bytecode_b64": "Ag=="}]
        rsrc = [dict(r) for r in gsrc]
        rsrc[3] = {"sha256": ss[3], "timeout": True, "ok": False}
        write_rows(os.path.join(self.out, "assemble.go.jsonl"), "assemble", gsrc, "go-algorand")
        write_rows(os.path.join(self.out, "assemble.rust.jsonl"), "assemble", rsrc, "algod-rust")
        with open(os.path.join(self.out, "reassemble.summary.json"), "w", encoding="utf-8") as f:
            json.dump({"fixed_point": {"programs": 4, "go_fixed": 3, "rust_fixed": 2},
                       "registry_hash": {"compared": 4, "matching": 3}}, f)
        # reassemble stage rows: two texts, identical
        rg = [{"sha256": sha(b"t1"), "ok": True, "bytecode_b64": "AQ=="},
              {"sha256": sha(b"t2"), "ok": False,
               "errors": [{"line": 7, "col": 1, "message": 'label "L9" defined twice'}]}]
        write_rows(os.path.join(self.out, "reassemble.go.jsonl"), "assemble", rg, "go-algorand")
        write_rows(os.path.join(self.out, "reassemble.rust.jsonl"), "assemble", [dict(r) for r in rg], "algod-rust")

    def tearDown(self):
        self.tmp.cleanup()

    def build(self):
        return st.build_stats(self.corpus, self.out, self.opcodes, algod_rust_commit="deadbeef", machine="test-box")


class Stats(Fixture):
    def test_corpus_shape(self):
        c = self.build()["corpus"]
        self.assertEqual(c["registry_sha"], "abc123")
        self.assertEqual(c["programs"], 5)
        self.assertEqual(c["by_kind"], {"approval": 3, "clear": 1, "shared": 1})
        self.assertEqual(c["distinct_sources"], 3)  # src-a, src-c, src-extra
        self.assertEqual(c["total_bytes"], 200)
        self.assertEqual(c["size"], {"min": 10, "p50": 30, "p90": 100, "p99": 100, "max": 100})
        self.assertEqual(c["registry_hash_agreement"], {"matching": 4, "total": 5, "rate": 0.8})

    def test_version_histogram(self):
        self.assertEqual(self.build()["avm_versions"], {"10": 3, "8": 1, "9": 1})

    def test_opcode_histogram_and_never_seen(self):
        o = self.build()["opcodes"]
        self.assertEqual(o["histogram"]["pushint"], {"occurrences": 4, "programs": 3})
        self.assertEqual(o["histogram"]["intc_0"], {"occurrences": 1, "programs": 1})
        self.assertEqual(o["distinct_seen"], 5)
        self.assertEqual(o["table_size"], 7)
        self.assertEqual(o["never_seen"], ["ed25519verify_bare", "err"])
        self.assertEqual(o["not_in_table"], [])
        self.assertEqual(o["coverage_rate"], round(5 / 7, 6))

    def test_opcode_not_in_table_is_reported(self):
        with open(self.opcodes, "w", encoding="utf-8") as f:
            json.dump({"go_algorand_tag": "t", "opcodes": {"pushint": 1}}, f)
        o = self.build()["opcodes"]
        self.assertEqual(o["not_in_table"], ["bnz", "intc_0", "intcblock", "return"])

    def test_stage_counts(self):
        s = self.build()["stages"]
        self.assertEqual(s["disassemble"], {"compared": 5, "identical": 3, "identical_error": 1, "mismatched": 1,
                                            "panics": 0, "timeouts": 0, "identical_panic_mirrored": 0})
        self.assertEqual(s["source"], {"compared": 4, "identical": 1, "identical_error": 1, "mismatched": 1,
                                       "panics": 0, "timeouts": 1, "identical_panic_mirrored": 1})
        self.assertEqual(s["reassemble"]["identical"], 1)
        self.assertEqual(s["reassemble"]["identical_error"], 1)
        self.assertNotIn("rest_sample", s)

    def test_robustness_counts_unmirrored_panics(self):
        rows = [{"sha256": "a" * 64, "ok": False, "panic": "boom"}]
        write_rows(os.path.join(self.out, "assemble.go.jsonl"), "assemble", rows)
        write_rows(os.path.join(self.out, "assemble.rust.jsonl"), "assemble", rows)
        s = self.build()["stages"]["source"]
        self.assertEqual((s["panics"], s["identical_panic_mirrored"], s["mismatched"]), (2, 0, 0))

    def test_fixed_point_rates(self):
        f = self.build()["fixed_point"]
        self.assertEqual(f, {"programs": 4, "go_fixed": 3, "rust_fixed": 2, "go_rate": 0.75, "rust_rate": 0.5,
                             "registry_hash_matching": 3, "registry_hash_compared": 4, "registry_hash_rate": 0.75})

    def test_error_class_histogram(self):
        e = self.build()["error_classes"]
        self.assertEqual(e["disassemble"], {"invalid opcode 0xN at pc=N": 1})
        self.assertEqual(e["source"], {"unknown opcode: foo": 1})
        self.assertEqual(e["reassemble"], {'label "X" defined twice': 1})

    def test_provenance(self):
        r = self.build()["run"]
        self.assertEqual(r["algod_rust_commit"], "deadbeef")
        self.assertEqual(r["go_algorand_tag"], "v5.0.5-stable")
        self.assertEqual(r["machine"], "test-box")
        self.assertEqual(self.build()["schema"], "teal-corpus-stats/v1")

    def test_missing_stage_is_absent_not_zero(self):
        os.remove(os.path.join(self.out, "reassemble.go.jsonl"))
        os.remove(os.path.join(self.out, "reassemble.rust.jsonl"))
        self.assertNotIn("reassemble", self.build()["stages"])

    def test_deterministic_bytes(self):
        a, b = os.path.join(self.out, "a.json"), os.path.join(self.out, "b.json")
        self.assertEqual(st.main(["build", self.corpus, self.out, "--opcodes", self.opcodes, "-o", a]), 0)
        self.assertEqual(st.main(["build", self.corpus, self.out, "--opcodes", self.opcodes, "-o", b]), 0)
        with open(a, "rb") as fa, open(b, "rb") as fb:
            da, db = fa.read(), fb.read()
        self.assertEqual(da, db)
        self.assertNotIn(b"\r", da)
        self.assertEqual(json.loads(da)["stages"]["disassemble"]["compared"], 5)


class History(Fixture):
    def test_append_and_idempotent(self):
        sp = os.path.join(self.out, "stats.json")
        st.main(["build", self.corpus, self.out, "--opcodes", self.opcodes, "-o", sp, "--commit", "deadbeef"])
        h = os.path.join(self.out, "history.csv")
        self.assertEqual(st.main(["history", sp, h, "--date", "2026-11-17"]), 0)
        self.assertEqual(st.main(["history", sp, h, "--date", "2026-11-17"]), 0)  # same key: replaced
        self.assertEqual(st.main(["history", sp, h, "--date", "2026-11-18"]), 0)
        with open(h, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual([r["date"] for r in rows], ["2026-11-17", "2026-11-18"])
        r = rows[0]
        self.assertEqual((r["registry_sha"], r["algod_rust_commit"], r["programs"]), ("abc123", "deadbeef", "5"))
        self.assertEqual((r["opcodes_seen"], r["opcodes_table"]), ("5", "7"))
        self.assertEqual((r["disassemble_compared"], r["disassemble_mismatched"]), ("5", "1"))
        self.assertEqual(r["go_fixed_rate"], "0.75")
        self.assertEqual(r["panics"], "0")
        self.assertEqual(r["timeouts"], "1")


if __name__ == "__main__":
    unittest.main()
