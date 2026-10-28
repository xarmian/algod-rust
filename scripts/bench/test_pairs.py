#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Registry checks of the micro tier (issue #2103): every benchmarks/pairs.toml
entry must exist on both sides and point at the right bytes.

Static (no Go or Rust toolchain needed; run by `make bench-compare-test` and
the bench-compare-harness CI job):
  * the registry parses and validates;
  * every fixture exists and its sha256 equals the registry's;
  * every `go_bench` is a `func BenchmarkX(b *testing.B)` in
    benchmarks/go-micro/*_test.go and runs its pair id, and every Benchmark
    function there is registered;
  * every pair id is a case of the Go side (micro/cases.go) and of the Rust
    side (algo-bench-pairs IDS + build()), and neither side has extra ones;
  * go-digests.json (the Go-recorded expected outputs) covers exactly the
    registered ids;
  * every file in the fixture directory is accounted for.

Live (BENCH_MICRO_GO_LIST=1, needs Go and a go-algorand checkout with
libsodium; the bench-micro CI job sets it): `go test -list` in the Go module
lists exactly the registered Benchmark functions.
"""
import json
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import micro_convert as mc  # noqa: E402

REGISTRY = os.path.join(REPO, "benchmarks", "pairs.toml")
GO_MODULE = os.path.join(REPO, "benchmarks", "go-micro")
RUST_LIB = os.path.join(REPO, "crates", "tools", "algo-bench-pairs", "src", "lib.rs")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def go_benchmarks():
    """{Benchmark name: pair id it runs} from the Go module's _test.go files."""
    out = {}
    for fn in sorted(os.listdir(GO_MODULE)):
        if not fn.endswith("_test.go"):
            continue
        src = _read(os.path.join(GO_MODULE, fn))
        for m in re.finditer(r'func (Benchmark\w+)\(b \*testing\.B\)\s*\{\s*run\(b, "([^"]+)"\)',
                             src):
            out[m.group(1)] = m.group(2)
        for name in re.findall(r'func (Benchmark\w+)\(', src):
            out.setdefault(name, None)
    return out


def go_case_ids():
    src = _read(os.path.join(GO_MODULE, "micro", "cases.go"))
    block = src[src.index("var builders = map[string]builder{"):]
    block = block[:block.index("\n}\n")]
    return set(re.findall(r'^\s*"([^"]+)":', block, re.M))


def rust_case_ids():
    src = _read(RUST_LIB)
    block = src[src.index("pub const IDS: &[&str] = &["):]
    block = block[:block.index("];")]
    ids = re.findall(r'"([^"]+)"', block)
    built = set(re.findall(r'^\s*"([^"]+)" => ', src, re.M))
    return ids, built


class RegistryStaticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg = mc.load_registry(REGISTRY)
        cls.ids = [p["id"] for p in cls.reg["pair"]]

    def test_registry_has_the_issue_minimum_pair_set(self):
        # #2103 acceptance: codec, crypto, commitments, AVM, agreement.
        groups = {i.split("/")[0] for i in self.ids}
        self.assertEqual(groups, {"codec", "crypto", "commit", "avm", "agreement"})
        for must in ("codec/decode-block-small", "codec/decode-block-large",
                     "codec/encode-block-small", "codec/encode-block-large",
                     "codec/decode-stxn", "codec/encode-stxn", "codec/txid", "codec/block-hash",
                     "crypto/sha512_256-32B", "crypto/sha512_256-1KiB", "crypto/sha512_256-64KiB",
                     "crypto/ed25519-verify", "crypto/ed25519-batch-64",
                     "crypto/ed25519-batch-1024", "crypto/vrf-verify", "crypto/falcon-verify",
                     "commit/txn-merkle-sha512_256", "commit/txn-vc-sha256",
                     "agreement/sortition-select", "agreement/credential-verify",
                     "agreement/decode-cert", "agreement/decode-proposal"):
            self.assertIn(must, self.ids)
        self.assertGreaterEqual(sum(i.startswith("avm/") for i in self.ids), 4)

    def test_fixture_sha256s_match(self):
        self.assertEqual(mc.check_fixtures(self.reg, REPO), [])

    def test_every_fixture_file_is_accounted_for(self):
        fx_dir = os.path.join(REPO, self.reg["fixture_dir"])
        used = {p["fixture"] for p in self.reg["pair"]}
        for fn in sorted(os.listdir(fx_dir)):
            if fn in used or fn == "go-digests.json":
                continue
            if fn.endswith(".teal") and fn[:-len(".teal")] + ".bin" in used:
                continue  # the source of an assembled program
            self.fail(f"{fn} in {fx_dir} is not referenced by {REGISTRY}")

    def test_go_benchmarks_match_registry_both_ways(self):
        benches = go_benchmarks()
        for p in self.reg["pair"]:
            self.assertIn(p["go_bench"], benches, f"{p['id']}: no Go {p['go_bench']}")
            self.assertEqual(benches[p["go_bench"]], p["id"],
                             f"{p['go_bench']} does not run pair {p['id']}")
            self.assertEqual(p["go_package"], "github.com/xarmian/algod-rust/benchmarks/go-micro")
        registered = {p["go_bench"] for p in self.reg["pair"]}
        self.assertEqual(sorted(set(benches) - registered), [],
                         "Go Benchmark functions missing from pairs.toml")

    def test_go_cases_match_registry(self):
        self.assertEqual(go_case_ids(), set(self.ids))

    def test_rust_cases_match_registry(self):
        ids, built = rust_case_ids()
        self.assertEqual(sorted(ids), sorted(self.ids), "algo-bench-pairs IDS")
        self.assertEqual(built, set(self.ids), "algo-bench-pairs build() arms")
        for p in self.reg["pair"]:
            self.assertEqual(p["rust_bench"], p["id"])

    def test_go_digests_cover_the_registry(self):
        path = os.path.join(REPO, self.reg["fixture_dir"], "go-digests.json")
        with open(path, encoding="utf-8") as f:
            digests = json.load(f)
        self.assertEqual(sorted(digests), sorted(self.ids))
        for i, d in digests.items():
            self.assertFalse(d.startswith("error:"), f"{i}: {d}")


@unittest.skipUnless(os.environ.get("BENCH_MICRO_GO_LIST") == "1",
                     "set BENCH_MICRO_GO_LIST=1 (needs Go + a go-algorand checkout with libsodium)")
class RegistryGoListTest(unittest.TestCase):
    def test_go_test_list(self):
        import tempfile
        import micro_equiv
        reg = mc.load_registry(REGISTRY)
        with tempfile.TemporaryDirectory() as work:
            env = micro_equiv.go_env(micro_equiv.default_go_algorand(), work)
            p = subprocess.run(["go", "test", "-list", "^Benchmark", "."], cwd=GO_MODULE,
                               env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = p.stdout
        listed = {line.strip() for line in out.splitlines() if line.startswith("Benchmark")}
        self.assertEqual(listed, {p["go_bench"] for p in reg["pair"]})


if __name__ == "__main__":
    unittest.main()
