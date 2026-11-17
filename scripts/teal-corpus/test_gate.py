#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for scripts/teal-corpus/gate.py (issue #2372): the nightly's pass
condition (zero mismatches/panics/timeouts, every required stage present and
non-empty, no allow-list), the empty/failed-extraction failure, the job summary,
the tracking-issue body, the benchmark table and the reproducer bundles.
Run: python3 -I scripts/teal-corpus/test_gate.py"""
import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("teal_corpus_gate", os.path.join(HERE, "gate.py"))
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def stage(compared=100, **kw):
    s = dict(compared=compared, identical=compared, identical_error=0, mismatched=0, panics=0, timeouts=0,
             identical_panic_mirrored=0)
    s.update(kw)
    return s


def stats(**stage_overrides):
    stages = {"disassemble": stage(), "reassemble": stage(99), "source": stage(98)}
    stages.update(stage_overrides)
    return {
        "schema": "teal-corpus-stats/v1",
        "run": {"algod_rust_commit": "a" * 40, "go_algorand_tag": "v5.0.5-stable",
                "go_algorand_commit": "b" * 40, "machine": "m"},
        "corpus": {"registry_sha": "c" * 40, "programs": 100},
        "stages": {k: v for k, v in stages.items() if v is not None},
    }


class ExtractionGate(unittest.TestCase):
    def write(self, counts, skipped, manifest_lines=None):
        if manifest_lines is None:
            manifest_lines = counts.get("programs", 0)
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "corpus.json"), "w") as f:
            json.dump({"registry_sha": "c" * 40, "counts": counts, "skipped": skipped}, f)
        with open(os.path.join(d, "manifest.jsonl"), "w") as f:
            f.write("{}\n" * manifest_lines)
        return d

    def test_healthy_corpus_passes(self):
        d = self.write({"entries": 1000, "programs": 900}, {"invalid_json": 3})
        self.assertEqual(gate.check_extraction(d, min_programs=100, max_skip_ratio=0.05), [])

    def test_empty_corpus_fails(self):
        d = self.write({"entries": 0, "programs": 0}, {}, manifest_lines=0)
        fails = gate.check_extraction(d, min_programs=100, max_skip_ratio=0.05)
        self.assertTrue(any("programs" in f for f in fails), fails)

    def test_registry_layout_change_fails(self):
        # every entry skipped: the directory layout moved and nothing extracted
        d = self.write({"entries": 500, "programs": 0}, {"missing_bytecode": 500})
        self.assertTrue(gate.check_extraction(d, min_programs=1, max_skip_ratio=0.05))

    def test_skip_ratio_over_threshold_fails(self):
        d = self.write({"entries": 1000, "programs": 800}, {"invalid_json": 200})
        fails = gate.check_extraction(d, min_programs=100, max_skip_ratio=0.05)
        self.assertTrue(any("skipped" in f for f in fails), fails)

    def test_missing_corpus_fails(self):
        self.assertTrue(gate.check_extraction(tempfile.mkdtemp(), min_programs=1, max_skip_ratio=1))

    def test_manifest_programs_disagreeing_with_counts_fails(self):
        d = self.write({"entries": 10, "programs": 10}, {}, manifest_lines=3)
        self.assertTrue(gate.check_extraction(d, min_programs=1, max_skip_ratio=0.05))


class Verdict(unittest.TestCase):
    def test_green(self):
        self.assertEqual(gate.check_stats(stats()), [])

    def test_mismatch_fails(self):
        f = gate.check_stats(stats(source=stage(98, mismatched=1)))
        self.assertEqual(len(f), 1)
        self.assertIn("source", f[0])

    def test_panic_and_timeout_fail(self):
        f = gate.check_stats(stats(disassemble=stage(panics=1), reassemble=stage(timeouts=2)))
        self.assertEqual(len(f), 2)

    def test_mirrored_panic_and_identical_errors_are_not_failures(self):
        self.assertEqual(gate.check_stats(stats(source=stage(98, identical_error=10, identical_panic_mirrored=2))), [])

    def test_missing_stage_fails(self):
        for name in ("disassemble", "reassemble", "source"):
            f = gate.check_stats(stats(**{name: None}))
            self.assertTrue(any(name in x and "missing" in x for x in f), (name, f))

    def test_zero_compared_fails(self):
        self.assertTrue(gate.check_stats(stats(disassemble=stage(0))))

    def test_rest_stage_required_only_when_asked(self):
        self.assertEqual(gate.check_stats(stats()), [])
        self.assertTrue(gate.check_stats(stats(), require_rest=True))
        self.assertEqual(gate.check_stats(stats(rest_sample=stage(300)), require_rest=True), [])
        self.assertTrue(gate.check_stats(stats(rest_sample=stage(300, mismatched=1)), require_rest=True))

    def test_rest_stage_mismatch_fails_even_when_not_required(self):
        self.assertTrue(gate.check_stats(stats(rest_sample=stage(300, mismatched=1))))

    def test_disassemble_must_cover_every_program(self):
        s = stats(disassemble=stage(50))
        self.assertTrue(any("programs" in x for x in gate.check_stats(s)))


class Reports(unittest.TestCase):
    def test_summary_has_provenance_and_counts(self):
        md = gate.summary_markdown(stats(), bench_md="| w | go | rust |\n|---|---|---|", failures=[])
        for needle in ("c" * 40, "v5.0.5-stable", "a" * 40, "disassemble", "reassemble", "source", "| w | go | rust |",
                       "PASS"):
            self.assertIn(needle, md)

    def test_summary_lists_failures(self):
        md = gate.summary_markdown(stats(source=stage(98, mismatched=3)), bench_md=None,
                                   failures=["source: 3 mismatched"])
        self.assertIn("FAIL", md)
        self.assertIn("source: 3 mismatched", md)

    def test_summary_without_stats_still_reports_failures(self):
        md = gate.summary_markdown(None, bench_md=None, failures=["extraction: nothing extracted"])
        self.assertIn("nothing extracted", md)

    def test_issue_body_has_sha_counts_and_run_url(self):
        body = gate.issue_body(stats(source=stage(98, mismatched=3)), ["source: 3 mismatched"],
                               run_url="https://example/run/1", registry_ref="main", go_ref="v5.0.5-stable")
        for needle in ("c" * 40, "https://example/run/1", "source: 3 mismatched", "mismatched", "v5.0.5-stable"):
            self.assertIn(needle, body)


class Bench(unittest.TestCase):
    def test_table_medians_and_ratio(self):
        rows = [{"name": "disassemble/all/wall_s", "impl": "go", "unit": "s", "samples": [3.0, 1.0, 2.0]},
                {"name": "disassemble/all/wall_s", "impl": "rust", "unit": "s", "samples": [1.0]}]
        t = gate.bench_table(rows)
        self.assertIn("| disassemble/all/wall_s | s | 2.0 | 1.0 | 0.50 |", t)


class Bundle(unittest.TestCase):
    def test_bundle_collects_program_source_and_rows(self):
        root = tempfile.mkdtemp()
        corpus, out, dest = (os.path.join(root, n) for n in ("corpus", "out", "dest"))
        sha = "ab" * 32
        for sub in ("programs", "sources"):
            os.makedirs(os.path.join(corpus, sub))
        os.makedirs(out)
        with open(os.path.join(corpus, "programs", sha + ".bin"), "wb") as f:
            f.write(b"\x08\x81\x01")
        with open(os.path.join(corpus, "sources", sha + ".teal"), "wb") as f:
            f.write(b"int 1")
        with open(os.path.join(out, "disassemble.mismatches.jsonl"), "w") as f:
            f.write(json.dumps({"sha256": sha, "field": "text"}) + "\n")
        for impl in ("go", "rust"):
            with open(os.path.join(out, "disassemble." + impl + ".jsonl"), "w") as f:
                f.write('{"header": {}}\n' + json.dumps({"sha256": sha, "ok": True}) + "\n")
                f.write(json.dumps({"sha256": "cd" * 32, "ok": True}) + "\n")
        self.assertEqual(gate.bundle(corpus, out, dest), [sha])
        d = os.path.join(dest, sha)
        self.assertEqual(sorted(os.listdir(d)), ["program.bin", "rows.disassemble.go.jsonl",
                                                 "rows.disassemble.rust.jsonl", "source.teal"])
        with open(os.path.join(d, "rows.disassemble.go.jsonl")) as f:
            self.assertEqual(len(f.readlines()), 1)

    def test_no_mismatches_no_bundles(self):
        root = tempfile.mkdtemp()
        self.assertEqual(gate.bundle(root, root, os.path.join(root, "d")), [])


class Cli(unittest.TestCase):
    def test_verdict_exit_codes(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "stats.json")
        with open(p, "w") as f:
            json.dump(stats(), f)
        self.assertEqual(gate.main(["verdict", p]), 0)
        with open(p, "w") as f:
            json.dump(stats(source=stage(98, mismatched=1)), f)
        self.assertEqual(gate.main(["verdict", p]), 1)
        self.assertEqual(gate.main(["verdict", os.path.join(d, "absent.json")]), 1)

    def test_extraction_exit_codes(self):
        d = tempfile.mkdtemp()
        self.assertEqual(gate.main(["extraction", d]), 1)


if __name__ == "__main__":
    unittest.main()
