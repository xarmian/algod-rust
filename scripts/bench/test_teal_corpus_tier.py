#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for the `teal-corpus` bench-compare tier (issue #2371): the metric
derivation, the equality gate, the top-N selection and, with fake drivers, the
whole tier: result rows are schema-valid and a failing gate withholds timings."""
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bench_schema  # noqa: E402

_spec = importlib.util.spec_from_file_location("teal_corpus_tier", os.path.join(HERE, "tiers", "teal-corpus.py"))
tier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tier)

FAKE_DRIVER = r'''#!/usr/bin/env python3
import hashlib, json, os, sys
a = sys.argv[1:]
op = a[0]
opt = {a[i]: a[i + 1] for i in range(1, len(a) - 1, 2)}
side = os.environ["FAKE_SIDE"]
d = opt.get("--input-dir") or os.path.join(opt["--corpus"], "programs" if op == "disassemble" else "sources")
rows, per, total = [], {}, 0
for name in sorted(os.listdir(d)):
    b = open(os.path.join(d, name), "rb").read()
    total += len(b)
    s = hashlib.sha256(b).hexdigest()
    per[s] = 1000 * (len(b) + 1) * (1 if side == "go" else 2)
    row = {"sha256": s, "ok": True}
    if op == "disassemble":
        row["text"] = "#pragma version 8\npushint %d\n" % len(b)
    else:
        row["bytecode_b64"] = "AQ=="
        row["hash"] = hashlib.sha256(b).hexdigest()[:8]
    if os.environ.get("FAKE_DIVERGE") == side and op == "assemble":
        row["hash"] = "bad"
    rows.append(row)
rows.sort(key=lambda r: r["sha256"])
with open(opt["--out"], "w") as f:
    f.write(json.dumps({"header": {"operation": op, "impl": side, "go_algorand_tag": "v-fake"}}) + "\n")
    for r in rows:
        f.write(json.dumps(r, sort_keys=True) + "\n")
if "--timings" in opt:
    json.dump({"schema": "teal-corpus-timings/v1", "impl": side, "operation": op, "jobs": 1, "inputs": len(rows),
               "input_bytes": total, "wall_ns": sum(per.values()) + 5000, "per_program_ns": per},
              open(opt["--timings"], "w"))
'''


class Helpers(unittest.TestCase):
    def test_metrics_from_timings(self):
        t = {"wall_ns": 2_000_000_000, "inputs": 4, "input_bytes": 8_000_000,
             "per_program_ns": {"a": 1000, "b": 2000, "c": 3000, "d": 10000}}
        m = tier.metrics_from_timings(t)
        self.assertEqual(m["wall_s"], ("s", "lower", 2.0))
        self.assertEqual(m["programs_per_s"], ("programs/s", "higher", 2.0))
        self.assertEqual(m["MB_per_s"], ("MB/s", "higher", 4.0))
        self.assertEqual(m["p50_us"][2], 2.0)
        self.assertEqual(m["p99_us"][2], 10.0)

    def test_select_largest_is_deterministic_with_ties(self):
        man = [{"sha256": "b", "size": 5}, {"sha256": "a", "size": 5}, {"sha256": "c", "size": 9},
               {"sha256": "d", "size": 1}]
        self.assertEqual(tier.select_largest(man, 3), ["c", "a", "b"])

    def test_gate(self):
        row = lambda s, **kw: json.dumps(dict({"sha256": s, "ok": True}, **kw), sort_keys=True).encode()
        self.assertEqual(tier.gate_errors([row("a")], [row("a")]), [])
        self.assertTrue(tier.gate_errors([row("a")], [row("a", ok=False)]))
        self.assertTrue(tier.gate_errors([row("a")], []))
        self.assertTrue(tier.gate_errors([row("a", timeout=True)], [row("a", timeout=True)]))
        self.assertTrue(tier.gate_errors([row("a", panic="boom")], [row("a", panic="boom")]))
        scratch = row("a", panic="runtime error: index out of range [300] with length 256")
        self.assertEqual(tier.gate_errors([scratch], [scratch]), [])
        self.assertTrue(tier.gate_errors([scratch], [row("a")]))


@unittest.skipIf(os.name == "nt", "the fake drivers are executable scripts")
class WholeTier(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        r = self.tmp.name
        self.corpus = os.path.join(r, "corpus")
        os.makedirs(os.path.join(self.corpus, "programs"))
        os.makedirs(os.path.join(self.corpus, "sources"))
        manifest = []
        for i in range(5):
            prog = bytes([8]) + b"p" * (i * 3 + 1)
            src = b"#pragma version 8\n" + b"int 1\n" * (i + 1)
            ps, ss = hashlib.sha256(prog).hexdigest(), hashlib.sha256(src).hexdigest()
            open(os.path.join(self.corpus, "programs", ps + ".bin"), "wb").write(prog)
            open(os.path.join(self.corpus, "sources", ss + ".teal"), "wb").write(src)
            manifest.append({"sha256": ps, "size": len(prog), "source_sha256": ss})
        with open(os.path.join(self.corpus, "manifest.jsonl"), "w") as f:
            for m in manifest:
                f.write(json.dumps(m) + "\n")
        json.dump({"registry_sha": "feedface"}, open(os.path.join(self.corpus, "corpus.json"), "w"))
        self.drivers = {}
        for side in ("go", "rust"):
            p = os.path.join(r, f"fake-{side}")
            with open(p, "w") as f:
                f.write(FAKE_DRIVER.replace("os.environ[\"FAKE_SIDE\"]", repr(side)))
            os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
            self.drivers[side] = p
        self.out = os.path.join(r, "out")

    def tearDown(self):
        self.tmp.cleanup()

    def run_tier(self, **extra):
        env = dict(os.environ, BENCH_RUNS="2", BENCH_TEAL_WARMUP="1", BENCH_TEAL_TOPN="2",
                   BENCH_OUT=self.out, BENCH_TEAL_CORPUS_DIR=self.corpus,
                   BENCH_TEAL_GO_DRIVER=self.drivers["go"], BENCH_TEAL_RUST_DRIVER=self.drivers["rust"])
        env.update(extra)
        return subprocess.run([sys.executable, os.path.join(HERE, "tiers", "teal-corpus.py")], env=env,
                              capture_output=True, text=True)

    def test_passing_run_writes_schema_valid_paired_rows(self):
        p = self.run_tier()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        res, errs = bench_schema.load_result_file(os.path.join(self.out, "teal-corpus.json"))
        self.assertEqual(errs, [])
        names = {(r["name"], r["impl"]) for r in res}
        for w in ("disassemble/all", "assemble-disassembled/all", "assemble-sources/all",
                  "disassemble/top2", "assemble-sources/top2"):
            for m in ("wall_s", "programs_per_s", "MB_per_s", "p50_us", "p99_us"):
                self.assertIn((f"{w}/{m}", "go"), names)
                self.assertIn((f"{w}/{m}", "rust"), names)
        r = next(x for x in res if x["name"] == "disassemble/all/wall_s" and x["impl"] == "go")
        self.assertEqual(len(r["samples"]), 2)
        self.assertEqual(r["metadata"]["registry_sha"], "feedface")
        self.assertEqual(r["metadata"]["go_algorand_tag"], "v-fake")
        self.assertEqual(r["metadata"]["inputs"], 5)

    def test_divergent_output_withholds_that_workloads_timings_and_fails(self):
        p = self.run_tier(FAKE_DIVERGE="rust")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("equality gate FAILED", p.stdout + p.stderr)
        res, _ = bench_schema.load_result_file(os.path.join(self.out, "teal-corpus.json"))
        names = {r["name"] for r in res}
        self.assertTrue(any(n.startswith("disassemble/all/") for n in names))  # gated fine
        self.assertFalse(any(n.startswith("assemble-sources/") for n in names))  # withheld
        self.assertFalse(any(n.startswith("assemble-disassembled/") for n in names))

    def test_corrupt_negative_test_fails_every_workload(self):
        p = self.run_tier(BENCH_TEAL_CORRUPT="1")
        self.assertEqual(p.returncode, 1)
        self.assertFalse(os.path.exists(os.path.join(self.out, "teal-corpus.json")))

    def test_missing_corpus_is_a_clear_failure(self):
        p = self.run_tier(BENCH_TEAL_CORPUS_DIR=os.path.join(self.tmp.name, "nope"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("make teal-corpus-fetch", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
