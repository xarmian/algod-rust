#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for the workload corpus tooling (issue #2104): MANIFEST.sha256 and
corpus.json checks (scripts/bench/corpus/corpus_tool.py), the deterministic
release tarball, scripts/bench/fetch_corpus.sh, and the committed `small`
corpus. Run by `make bench-compare-test` (the bench-compare-harness CI job).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(HERE, "corpus"))
import corpus_tool as ct  # noqa: E402
import generate as gen  # noqa: E402

SMALL = os.path.join(REPO, "benchmarks", "corpus", "small")
FETCH = os.path.join(HERE, "fetch_corpus.sh")
SMALL_CAP = 5 * 1024 * 1024
COVERAGE = os.path.join(REPO, "benchmarks", "corpus", "coverage.json")
VECTORS = os.path.join(HERE, "testdata", "corpus", "manifest_vectors.json")
RUST_TEST = os.path.join(REPO, "crates", "tools", "algo-bench", "tests", "corpus_small.rs")
HEX64 = "0123456789abcdef" * 4


def vector_text(text):
    """manifest_vectors.json: a line starting with "H " gets a real digest."""
    return "".join(HEX64 + line[1:] if line.startswith("H ") else line
                   for line in text.splitlines(keepends=True))


def sample_corpus_json():
    sub = {k: 1 for k in ct.REQUIRED_SUBTYPES}
    types = {}
    for k in sub:
        t = k.split(".")[0]
        types[t] = types.get(t, 0) + 1
    feats = {k: 1 for k in ct.REQUIRED_FEATURES}
    feats.update(groups=1, grouped_txns=2, inner_txns=3)
    return {
        "schema": ct.SCHEMA, "name": "t",
        "generator": {"name": "g", "version": "1", "seed": "s"},
        "go_algorand": {"tag": "v", "commit": "c"},
        "network": {"genesis_id": "x-v1", "genesis_hash": "aGFzaA==", "consensus_version": "p"},
        "files": {"blocks": "blocks.bin", "genesis": "genesis.json",
                  "node_config": "node-config.json", "consensus": "consensus.json"},
        "rounds": {"first": 0, "last": 9, "count": 10},
        "txns": sum(types.values()),
        "txids_sha256": "0" * 64,
        "histogram": {"types": types, "subtypes": sub,
                      "inner_types": {"pay": 1, "axfer": 1, "appl": 1}, "features": feats},
        "final_state": {"round": 9, "block_hash": "blk-X"},
    }


def make_corpus(d, cj=None):
    os.makedirs(d, exist_ok=True)
    for name, data in [("blocks.bin", b"ACRPBLK1\x00"), ("genesis.json", b"{}\n"),
                       ("node-config.json", b"{}\n"), ("consensus.json", b"{}\n")]:
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)
    with open(os.path.join(d, "corpus.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(cj or sample_corpus_json(), f, indent=2)
    ct.write_manifest(d)
    return d


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.d = make_corpus(os.path.join(self.tmp, "c"))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_round_trip(self):
        self.assertEqual(ct.verify_manifest(self.d), [])
        self.assertEqual(ct.verify(self.d), [])
        with open(os.path.join(self.d, ct.MANIFEST), encoding="utf-8") as f:
            names = [line.split("  ")[1] for line in f.read().splitlines()]
        self.assertEqual(names, sorted(names))
        self.assertNotIn(ct.MANIFEST, names)

    def test_tampered_file(self):
        with open(os.path.join(self.d, "blocks.bin"), "ab") as f:
            f.write(b"x")
        self.assertEqual(ct.verify_manifest(self.d), ["blocks.bin: sha256 mismatch"])

    def test_missing_and_unlisted(self):
        os.remove(os.path.join(self.d, "genesis.json"))
        with open(os.path.join(self.d, "extra.bin"), "wb") as f:
            f.write(b"1")
        errs = ct.verify_manifest(self.d)
        self.assertIn("genesis.json: listed in MANIFEST.sha256 but missing", errs)
        self.assertIn("extra.bin: present but not listed in MANIFEST.sha256", errs)

    def test_crlf_manifest_rejected(self):
        p = os.path.join(self.d, ct.MANIFEST)
        with open(p, "rb") as f:
            raw = f.read()
        with open(p, "wb") as f:
            f.write(raw.replace(b"\n", b"\r\n"))
        self.assertIn("CR bytes", ct.verify_manifest(self.d)[0])

    def test_malformed_manifest(self):
        with self.assertRaises(ValueError):
            ct.parse_manifest("abc blocks.bin\n")
        with self.assertRaises(ValueError):
            ct.parse_manifest(("0" * 64) + "  ../x\n")


class ManifestVectorsTest(unittest.TestCase):
    """The shared parser vectors (the Rust checker runs the same file)."""

    def test_vectors(self):
        with open(VECTORS, encoding="utf-8") as f:
            vectors = json.load(f)["vectors"]
        self.assertGreater(len(vectors), 10)
        for v in vectors:
            with self.subTest(v["name"]):
                text = vector_text(v["text"])
                if v["valid"]:
                    ct.parse_manifest(text)
                else:
                    with self.assertRaises(ValueError):
                        ct.parse_manifest(text)


class CoverageTest(unittest.TestCase):
    """benchmarks/corpus/coverage.json is the only list of required kinds."""

    def test_tool_reads_coverage_json(self):
        with open(COVERAGE, encoding="utf-8") as f:
            cov = json.load(f)
        self.assertEqual(ct.REQUIRED_SUBTYPES, cov["subtypes"])
        self.assertEqual(ct.REQUIRED_FEATURES, cov["features"])
        self.assertEqual(ct.REQUIRED_INNER, cov["inner_types"])

    def test_rust_test_has_no_private_copy(self):
        with open(RUST_TEST, encoding="utf-8") as f:
            src = f.read()
        self.assertIn("coverage.json", src)
        for k in ("keyreg.online", "app_box_ref_txns", "appl.update"):
            self.assertNotIn(f'"{k}"', src, f"{k} hard-coded in corpus_small.rs")


class GenerateSafetyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_force_keeps_existing_corpus_when_setup_fails(self):
        out = make_corpus(os.path.join(self.tmp, "small"))
        before = ct.manifest_text(out)
        rc = gen.main(["--preset", "tiny", "--out", out, "--force",
                       "--algod", os.path.join(self.tmp, "no-such-algod")])
        self.assertEqual(rc, 1)
        self.assertEqual(ct.verify_manifest(out), [])
        self.assertEqual(ct.manifest_text(out), before, "--force touched --out before succeeding")
        self.assertEqual(sorted(os.listdir(self.tmp)), ["small"], "left a temp dir behind")

    def test_install_replaces_atomically(self):
        out = make_corpus(os.path.join(self.tmp, "c"))
        with open(os.path.join(out, "stale.txt"), "w") as f:
            f.write("old")
        new = gen.staging_dir(out)
        make_corpus(new)
        gen.install(new, out)
        self.assertFalse(os.path.exists(os.path.join(out, "stale.txt")))
        self.assertEqual(ct.verify_manifest(out), [])
        self.assertEqual(sorted(os.listdir(self.tmp)), ["c"])

    def test_install_into_absent_out(self):
        out = os.path.join(self.tmp, "fresh")
        new = gen.staging_dir(out)
        make_corpus(new)
        gen.install(new, out)
        self.assertEqual(ct.verify_manifest(out), [])
        self.assertEqual(sorted(os.listdir(self.tmp)), ["fresh"])

    def test_start_node_exec_error_is_setup_error(self):
        node = os.path.join(self.tmp, "node")
        os.makedirs(node)
        log = os.path.join(self.tmp, "algod.out")
        with self.assertRaises(gen.SetupError):
            gen.start_node(os.path.join(self.tmp, "no-such-algod"), node, log)
        os.remove(log)  # the handle was closed (Windows refuses to delete an open file)


class CorpusJsonTest(unittest.TestCase):
    def test_sample_is_valid(self):
        self.assertEqual(ct.validate_corpus_json(sample_corpus_json()), [])

    def test_type_sum_mismatch(self):
        cj = sample_corpus_json()
        cj["txns"] += 1
        self.assertTrue(any("histogram.types sums" in e for e in ct.validate_corpus_json(cj)))

    def test_subtype_sum_mismatch(self):
        cj = sample_corpus_json()
        cj["histogram"]["subtypes"]["pay.payment"] += 1
        self.assertTrue(any("subtypes of pay" in e for e in ct.validate_corpus_json(cj)))

    def test_rounds_inconsistent(self):
        cj = sample_corpus_json()
        cj["rounds"]["count"] = 3
        self.assertTrue(any(e.startswith("rounds:") for e in ct.validate_corpus_json(cj)))

    def test_coverage_missing_kind(self):
        cj = sample_corpus_json()
        del cj["histogram"]["subtypes"]["keyreg.online"]
        cj["histogram"]["types"]["keyreg"] -= 1
        cj["txns"] -= 1
        errs = ct.validate_corpus_json(cj)
        self.assertEqual(errs, ["no keyreg.online transactions"])
        self.assertEqual(ct.validate_corpus_json(cj, coverage=False), [])

    def test_bad_schema(self):
        cj = sample_corpus_json()
        cj["schema"] = "other/v9"
        self.assertEqual(len(ct.validate_corpus_json(cj)), 1)


class CompareAndPackTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_compare(self):
        a = make_corpus(os.path.join(self.tmp, "a"))
        b = make_corpus(os.path.join(self.tmp, "b"))
        self.assertEqual(ct.compare(a, b), [])
        cj = sample_corpus_json()
        cj["txids_sha256"] = "1" * 64
        c = make_corpus(os.path.join(self.tmp, "c"), cj)
        diffs = ct.compare(a, c)
        self.assertTrue(any(d.startswith("file corpus.json") for d in diffs), diffs)
        self.assertTrue(any(d.startswith("corpus.json txids_sha256") for d in diffs), diffs)

    def test_pack_is_deterministic(self):
        a = make_corpus(os.path.join(self.tmp, "corpus-x"))
        p1 = ct.pack(a, os.path.join(self.tmp, "1.tar.gz"))
        os.utime(os.path.join(a, "blocks.bin"), (1, 1))
        p2 = ct.pack(a, os.path.join(self.tmp, "2.tar.gz"))
        self.assertEqual(ct.sha256_file(p1), ct.sha256_file(p2))


@unittest.skipIf(shutil.which("bash") is None or shutil.which("tar") is None
                 or os.name == "nt", "fetch_corpus.sh needs a POSIX shell")
class FetchCorpusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = make_corpus(os.path.join(self.tmp, "corpus-large"))
        self.tar = ct.pack(self.src, os.path.join(self.tmp, "c.tar.gz"))
        self.pin = ct.sha256_file(os.path.join(self.src, ct.MANIFEST))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def ref(self, url, pin):
        p = os.path.join(self.tmp, "large.ref")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(f"# test\nurl={url}\nmanifest_sha256={pin}\n")
        return p

    def fetch(self, *args, env=None):
        return subprocess.run(["bash", FETCH, *args], capture_output=True, text=True,
                              env=dict(os.environ, **(env or {})))

    def test_install_from_tarball(self):
        dest = os.path.join(self.tmp, "out", "large")
        p = self.fetch("--ref", self.ref("unused", self.pin), "--from", self.tar, "--dest", dest)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(ct.verify(dest), [])
        p = self.fetch("--ref", self.ref("unused", self.pin), "--from", self.tar, "--dest", dest)
        self.assertEqual(p.returncode, 1, "existing dest needs --force")

    def test_wrong_pin_rejected(self):
        dest = os.path.join(self.tmp, "large")
        p = self.fetch("--ref", self.ref("unused", "0" * 64), "--from", self.tar, "--dest", dest)
        self.assertEqual(p.returncode, 1)
        self.assertIn("pins", p.stderr)
        self.assertFalse(os.path.exists(dest))

    def test_tampered_file_rejected(self):
        with open(os.path.join(self.src, "blocks.bin"), "ab") as f:
            f.write(b"x")
        tar = ct.pack(self.src, os.path.join(self.tmp, "bad.tar.gz"))
        p = self.fetch("--ref", self.ref("unused", self.pin), "--from", tar,
                       "--dest", os.path.join(self.tmp, "large"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("blocks.bin: sha256 mismatch", p.stderr)

    def test_unlisted_file_with_regex_metachars_rejected(self):
        # "genesis.jso." as a regex matches the listed "genesis.json" line.
        with open(os.path.join(self.src, "genesis.jso."), "wb") as f:
            f.write(b"smuggled")
        tar = ct.pack(self.src, os.path.join(self.tmp, "meta.tar.gz"))
        dest = os.path.join(self.tmp, "large")
        p = self.fetch("--ref", self.ref("unused", self.pin), "--from", tar, "--dest", dest)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("genesis.jso.: present but not listed", p.stderr)
        self.assertFalse(os.path.exists(dest))

    @unittest.skipIf(shutil.which("curl") is None, "needs curl")
    def test_unpublished_asset_fails_cleanly(self):
        url = "file://" + os.path.join(self.tmp, "no-such-asset.tar.gz")
        p = self.fetch("--ref", self.ref(url, self.pin), "--dest", os.path.join(self.tmp, "l"))
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("generate.py --preset large", p.stderr)


class LargeRefTest(unittest.TestCase):
    def test_committed_ref_parses(self):
        with open(os.path.join(REPO, "benchmarks", "corpus", "large.ref"), encoding="utf-8") as f:
            text = f.read()
        self.assertRegex(text, r"(?m)^url=https://github\.com/\S+\.tar\.gz$")
        self.assertRegex(text, r"(?m)^manifest_sha256=[0-9a-f]{64}$")


@unittest.skipUnless(os.path.isdir(SMALL), "benchmarks/corpus/small not present")
class CommittedSmallCorpusTest(unittest.TestCase):
    def test_small_corpus_verifies(self):
        self.assertEqual(ct.verify(SMALL), [])

    def test_small_corpus_size_cap(self):
        size = sum(os.path.getsize(os.path.join(SMALL, n)) for n in os.listdir(SMALL))
        self.assertLessEqual(size, SMALL_CAP, f"small corpus is {size} bytes")

    def test_small_corpus_genesis_matches(self):
        cj = ct.load_corpus_json(SMALL)
        with open(os.path.join(SMALL, cj["files"]["genesis"]), encoding="utf-8") as f:
            g = json.load(f)
        self.assertTrue(g.get("devmode"))
        self.assertEqual(g["proto"], cj["network"]["consensus_version"])
        self.assertEqual(f"{g['network']}-{g['id']}", cj["network"]["genesis_id"])
        self.assertEqual(g["timestamp"], cj["network"]["genesis_timestamp"])
        with open(os.path.join(SMALL, "blocks.bin"), "rb") as f:
            self.assertEqual(f.read(8), b"ACRPBLK1")


if __name__ == "__main__":
    unittest.main()
