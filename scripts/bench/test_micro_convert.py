#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests for micro_convert.py (issue #2103), on outputs captured from
both frameworks: testdata/micro/go-bench.txt is a real `go test -bench
-benchmem -count=2` run of benchmarks/go-micro, testdata/micro/criterion/ a
real CRITERION_HOME of `cargo bench -p algo-bench-pairs` on Windows (hence
the lower-cased `sha512_256-32b` directory)."""
import json
import os
import shutil
import statistics
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bench_schema  # noqa: E402
import micro_convert as mc  # noqa: E402

TESTDATA = os.path.join(HERE, "testdata", "micro")


def _pair(**kw):
    p = {"id": "codec/txid", "unit": "ns/op", "go_package": "example.com/m",
         "go_bench": "BenchmarkCodecTxid", "go_api": "Transaction.ID",
         "rust_bench": "codec/txid", "rust_api": "compute_txn_id",
         "fixture": "stxn-appl.msgpack", "fixture_sha256": "ab" * 32}
    p.update(kw)
    return p


class GoBenchTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(TESTDATA, "go-bench.txt"), encoding="utf-8") as f:
            self.parsed = mc.parse_go_bench(f.read())

    def test_parses_every_benchmark_and_count_repetition(self):
        self.assertEqual(sorted(self.parsed), ["BenchmarkAgreementSortitionSelectF128",
                                               "BenchmarkCodecTxid",
                                               "BenchmarkCryptoSha512_256_32B"])
        txid = self.parsed["BenchmarkCodecTxid"]
        self.assertEqual(txid["ns_op"], [992.1, 980.1])
        self.assertEqual(txid["iterations"], [239557, 240596])
        self.assertEqual(txid["b_op"], [0.0, 0.0])
        self.assertEqual(txid["allocs_op"], [0.0, 0.0])
        self.assertEqual(self.parsed["BenchmarkAgreementSortitionSelectF128"]["b_op"], [96.0, 96.0])

    def test_strips_gomaxprocs_suffix_only(self):
        out = mc.parse_go_bench("BenchmarkFoo_1-8   10   5.5 ns/op\n"
                                "BenchmarkBar      20   1e+03 ns/op\n"
                                "BenchmarkBaz-x-16 30   7 ns/op\n")
        self.assertEqual(out["BenchmarkFoo_1"]["ns_op"], [5.5])
        self.assertEqual(out["BenchmarkBar"]["ns_op"], [1000.0])
        self.assertEqual(out["BenchmarkBaz-x"]["ns_op"], [7.0])
        self.assertEqual(out["BenchmarkBar"]["b_op"], [])

    def test_ignores_non_result_lines(self):
        out = mc.parse_go_bench("goos: linux\nBenchmarkCodecTxid\nPASS\nok x 1s\n"
                                "--- FAIL: BenchmarkX\n")
        self.assertEqual(out, {})

    def test_bench_regex_is_anchored_and_escaped(self):
        r = mc.go_bench_regex(["BenchmarkB", "BenchmarkA"])
        self.assertEqual(r, "^(BenchmarkA|BenchmarkB)$")


class CriterionTest(unittest.TestCase):
    def test_reads_full_ids_and_per_round_mean(self):
        runs = mc.criterion_runs(os.path.join(TESTDATA, "criterion"))
        self.assertEqual(sorted(runs), ["codec/txid", "crypto/sha512_256-32B"])
        sha = runs["crypto/sha512_256-32B"]
        self.assertEqual(sha["source"], "sample.json")
        self.assertEqual(sha["samples"], 100)
        with open(os.path.join(TESTDATA, "criterion", "crypto", "sha512_256-32b", "new",
                               "sample.json"), encoding="utf-8") as f:
            s = json.load(f)
        # A mean over every timed iteration, like go's ns/op (total time / b.N).
        want = sum(s["times"]) / sum(s["iters"])
        self.assertAlmostEqual(sha["value"], want)
        self.assertNotAlmostEqual(
            sha["value"], statistics.median(t / i for t, i in zip(s["times"], s["iters"])),
            places=6)
        self.assertAlmostEqual(sha["median_per_sample"],
                               statistics.median(t / i for t, i in zip(s["times"], s["iters"])))
        self.assertEqual(sha["total_iterations"], int(sum(s["iters"])))

    def test_falls_back_to_estimates_mean_and_says_so(self):
        runs = mc.criterion_runs(os.path.join(TESTDATA, "criterion"))
        txid = runs["codec/txid"]
        self.assertEqual(txid["source"], "estimates.json")
        with open(os.path.join(TESTDATA, "criterion", "codec", "txid", "new",
                               "estimates.json"), encoding="utf-8") as f:
            e = json.load(f)
        self.assertAlmostEqual(txid["value"], e["mean"]["point_estimate"])

    def test_sources_must_not_mix_across_rounds(self):
        self.assertIsNone(mc.mixed_source_error("a/x", ["sample.json"] * 3))
        err = mc.mixed_source_error("a/x", ["sample.json", "estimates.json", "sample.json"])
        self.assertIn("a/x", err)
        self.assertIn("estimates.json", err)

    def test_ignores_base_and_incomplete_dirs(self):
        d = tempfile.mkdtemp()
        try:
            shutil.copytree(os.path.join(TESTDATA, "criterion"), os.path.join(d, "c"))
            os.makedirs(os.path.join(d, "c", "x", "y", "new"))  # no benchmark.json
            os.remove(os.path.join(d, "c", "crypto", "sha512_256-32b", "new", "sample.json"))
            os.remove(os.path.join(d, "c", "crypto", "sha512_256-32b", "new", "estimates.json"))
            runs = mc.criterion_runs(os.path.join(d, "c"))
            # base/ is the previous run: it must not stand in for a missing new/.
            self.assertEqual(sorted(runs), ["codec/txid"])
        finally:
            shutil.rmtree(d)


class RegistryTest(unittest.TestCase):
    def test_fallback_parser_matches_tomllib_on_the_registry(self):
        path = os.path.join(os.path.dirname(os.path.dirname(HERE)), "benchmarks", "pairs.toml")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        mine = mc.parse_registry_toml(text)
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+")
        self.assertEqual(mine, tomllib.loads(text))

    def test_fallback_parser_rejects_what_it_cannot_read(self):
        for bad in ('[pair]\nid = "x"\n', 'x = [1, 2]\n', 'x = "a"\nx = "b"\n', 'garbage\n'):
            with self.assertRaises(ValueError, msg=bad):
                mc.parse_registry_toml(bad)
        reg = mc.parse_registry_toml('schema = 1\n# c\n[[pair]]\nid = "a\\"b"\nok = true\n')
        self.assertEqual(reg, {"schema": 1, "pair": [{"id": 'a"b', "ok": True}]})

    def test_validate_registry(self):
        self.assertEqual(mc.validate_registry({"pair": [_pair()]}), [])
        self.assertEqual(mc.validate_registry({"pair": []}), ["no [[pair]] entries"])
        errs = mc.validate_registry({"pair": [_pair(), _pair(rust_bench="x/y", extra="1")]})
        self.assertTrue(any("duplicate id" in e for e in errs), errs)
        self.assertTrue(any("duplicate go_bench" in e for e in errs), errs)
        self.assertTrue(any("rust_bench must equal id" in e for e in errs), errs)
        self.assertTrue(any("unknown keys" in e for e in errs), errs)
        errs = mc.validate_registry({"pair": [_pair(id="nogroup", rust_bench="nogroup",
                                                    go_bench="TestX", fixture_sha256="zz",
                                                    unit="")]})
        self.assertEqual(len(errs), 4, errs)

    def test_check_fixtures(self):
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "fx"))
            with open(os.path.join(d, "fx", "a.bin"), "wb") as f:
                f.write(b"abc")
            good = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            reg = {"fixture_dir": "fx", "pair": [_pair(fixture="a.bin", fixture_sha256=good)]}
            self.assertEqual(mc.check_fixtures(reg, d), [])
            reg["pair"][0]["fixture_sha256"] = "00" * 32
            self.assertIn("sha256", mc.check_fixtures(reg, d)[0])
            reg["pair"][0]["fixture"] = "missing.bin"
            self.assertIn("not found", mc.check_fixtures(reg, d)[0])
        finally:
            shutil.rmtree(d)


class EquivalenceAndResultTest(unittest.TestCase):
    def test_compare_digests(self):
        ids = ["a/x", "a/y", "a/z", "a/w"]
        go = {"a/x": "hex:01", "a/y": "hex:02", "a/z": "error:boom", "a/w": "valid:true"}
        rust = {"a/x": "hex:01", "a/y": "hex:03", "a/z": "hex:00"}
        errs = mc.compare_digests(ids, go, rust)
        self.assertEqual(len(errs), 3, errs)
        self.assertIn("OUTPUT DIVERGES", errs[0])
        self.assertIn("failed to run", errs[1])
        self.assertIn("missing digest", errs[2])
        self.assertEqual(mc.compare_digests(["a/x"], go, rust), [])

    def test_make_result_is_schema_valid(self):
        r = mc.make_result(_pair(), "go", [980.1, 992.1], {"harness": "go test"})
        self.assertEqual(bench_schema.validate_result(r), [])
        self.assertEqual((r["tier"], r["name"], r["unit"], r["better"]),
                         ("micro", "codec/txid", "ns/op", "lower"))


if __name__ == "__main__":
    unittest.main()
