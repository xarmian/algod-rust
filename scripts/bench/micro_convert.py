#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Helpers of the bench-compare `micro` tier (issue #2103, epic #2101).

* load_registry(): reads benchmarks/pairs.toml (tomllib on Python 3.11+, a
  small parser for the registry's TOML subset otherwise, so the harness
  keeps working on the 3.8+ it documents).
* parse_go_bench(): `go test -bench -benchmem` text output -> per-benchmark
  ns/op, B/op, allocs/op samples (one per -count repetition).
* criterion_runs(): a criterion output directory ($CRITERION_HOME or
  target/criterion) -> per-benchmark summary of one `cargo bench` run: the
  median of the per-sample times in new/sample.json (time / iterations of
  every sample), falling back to new/estimates.json's median.
* compare_digests(): the per-pair output-equivalence check.
* make_result(): one schema-v1 result object.

Pure functions plus file reading only; scripts/bench/test_micro_convert.py
tests them on captured outputs of both frameworks (scripts/bench/testdata/).
"""
import hashlib
import json
import os
import re
import statistics

PAIR_KEYS = ("id", "unit", "go_package", "go_bench", "go_api", "rust_bench",
             "rust_api", "fixture", "fixture_sha256")

# --- registry ----------------------------------------------------------------

_KEY = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$')
_STR = re.compile(r'^"((?:[^"\\]|\\.)*)"$')


def _toml_value(raw, where):
    m = _STR.match(raw)
    if m:
        return json.loads('"' + m.group(1) + '"')
    if re.match(r'^-?\d+$', raw):
        return int(raw)
    if raw in ("true", "false"):
        return raw == "true"
    raise ValueError(f"{where}: unsupported TOML value {raw!r}")


def parse_registry_toml(text):
    """Parse the TOML subset pairs.toml uses: comments, top-level and
    [[pair]] `key = "string" | integer | bool` lines."""
    top, pairs, cur = {}, [], None
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s == "[[pair]]":
            cur = {}
            pairs.append(cur)
            continue
        if s.startswith("["):
            raise ValueError(f"line {n}: unsupported table {s!r}")
        m = _KEY.match(s)
        if not m:
            raise ValueError(f"line {n}: cannot parse {s!r}")
        target = top if cur is None else cur
        if m.group(1) in target:
            raise ValueError(f"line {n}: duplicate key {m.group(1)!r}")
        target[m.group(1)] = _toml_value(m.group(2), f"line {n}")
    top["pair"] = pairs
    return top


def load_registry(path):
    with open(path, "rb") as f:
        raw = f.read()
    try:
        import tomllib  # Python 3.11+
        reg = tomllib.loads(raw.decode("utf-8"))
    except ImportError:
        reg = parse_registry_toml(raw.decode("utf-8"))
    errors = validate_registry(reg)
    if errors:
        raise ValueError(f"{path}: " + "; ".join(errors))
    return reg


def validate_registry(reg):
    errors = []
    pairs = reg.get("pair")
    if not isinstance(pairs, list) or not pairs:
        return ["no [[pair]] entries"]
    seen = {}
    for i, p in enumerate(pairs):
        where = p.get("id", f"pair #{i + 1}")
        for k in PAIR_KEYS:
            if not isinstance(p.get(k), str) or not p.get(k):
                errors.append(f"{where}: missing or empty {k!r}")
        extra = sorted(set(p) - set(PAIR_KEYS))
        if extra:
            errors.append(f"{where}: unknown keys {extra}")
        if not re.match(r'^[a-z0-9]+/[A-Za-z0-9_.+-]+$', p.get("id", "")):
            errors.append(f"{where}: id must be <group>/<name>")
        if p.get("rust_bench") and p.get("rust_bench") != p.get("id"):
            errors.append(f"{where}: rust_bench must equal id")
        if not re.match(r'^Benchmark[A-Za-z0-9_]+$', p.get("go_bench", "")):
            errors.append(f"{where}: go_bench must be a Benchmark function name")
        if not re.match(r'^[0-9a-f]{64}$', p.get("fixture_sha256", "")):
            errors.append(f"{where}: fixture_sha256 must be 64 hex digits")
        for k in ("id", "go_bench"):
            v = p.get(k)
            if v in seen.get(k, set()):
                errors.append(f"{where}: duplicate {k} {v!r}")
            seen.setdefault(k, set()).add(v)
    return errors


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_fixtures(reg, repo_root):
    """Return one error per pair whose fixture is missing or has the wrong sha256."""
    fx_dir = os.path.join(repo_root, reg.get("fixture_dir", "benchmarks/fixtures/micro"))
    errors = []
    for p in reg["pair"]:
        path = os.path.join(fx_dir, p["fixture"])
        if not os.path.isfile(path):
            errors.append(f"{p['id']}: fixture {p['fixture']} not found in {fx_dir}")
            continue
        got = sha256_file(path)
        if got != p["fixture_sha256"]:
            errors.append(f"{p['id']}: fixture {p['fixture']} sha256 {got} != registry "
                          f"{p['fixture_sha256']}")
    return errors


# --- Go ----------------------------------------------------------------------

_GO_LINE = re.compile(
    r'^(Benchmark[^\s]*?)(?:-\d+)?\s+(\d+)\s+([0-9.]+(?:e[+-]?\d+)?) ns/op'
    r'(?:.*?\s([0-9.]+) B/op)?(?:.*?\s([0-9.]+) allocs/op)?')


def parse_go_bench(text):
    """`go test -bench` output -> {name: {"ns_op": [...], "b_op": [...],
    "allocs_op": [...], "iterations": [...]}}, one entry per result line
    (so -count=N gives N samples), with the GOMAXPROCS `-N` suffix removed."""
    out = {}
    for line in text.splitlines():
        m = _GO_LINE.match(line.strip())
        if not m:
            continue
        d = out.setdefault(m.group(1), {"ns_op": [], "b_op": [], "allocs_op": [],
                                        "iterations": []})
        d["iterations"].append(int(m.group(2)))
        d["ns_op"].append(float(m.group(3)))
        if m.group(4) is not None:
            d["b_op"].append(float(m.group(4)))
        if m.group(5) is not None:
            d["allocs_op"].append(float(m.group(5)))
    return out


def go_bench_regex(names):
    """-bench regex selecting exactly these top-level benchmarks."""
    return "^(" + "|".join(sorted(re.escape(n) for n in names)) + ")$"


# --- criterion ---------------------------------------------------------------

def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def criterion_summary(new_dir):
    """Summarise one criterion run of one benchmark (its `new/` directory)."""
    sample = os.path.join(new_dir, "sample.json")
    if os.path.isfile(sample):
        s = _read_json(sample)
        iters, times = s.get("iters") or [], s.get("times") or []
        per_iter = [t / i for t, i in zip(times, iters) if i]
        if per_iter:
            return {"value": statistics.median(per_iter), "source": "sample.json",
                    "samples": len(per_iter), "sampling_mode": s.get("sampling_mode"),
                    "total_iterations": sum(int(i) for i in iters)}
    est = os.path.join(new_dir, "estimates.json")
    if os.path.isfile(est):
        e = _read_json(est)
        return {"value": float(e["median"]["point_estimate"]), "source": "estimates.json"}
    return None


def criterion_runs(criterion_home):
    """{full benchmark id: summary} for every benchmark under criterion_home.
    Keys come from each new/benchmark.json's `full_id`, so directory-name
    mangling (criterion replaces '/' and lower-cases names on Windows) does
    not matter."""
    out = {}
    for root, dirs, files in os.walk(criterion_home):
        if os.path.basename(root) != "new" or "benchmark.json" not in files:
            continue
        meta = _read_json(os.path.join(root, "benchmark.json"))
        full_id = meta.get("full_id")
        summary = criterion_summary(root)
        if full_id and summary:
            out[full_id] = summary
    return out


# --- equivalence -------------------------------------------------------------

def compare_digests(ids, go, rust):
    """One message per pair whose Go and Rust digests differ or are missing."""
    errors = []
    for i in ids:
        g, r = go.get(i), rust.get(i)
        if g is None or r is None:
            errors.append(f"{i}: missing digest (go={g!r}, rust={r!r})")
        elif g.startswith("error:") or r.startswith("error:"):
            errors.append(f"{i}: failed to run (go={g!r}, rust={r!r})")
        elif g != r:
            errors.append(f"{i}: OUTPUT DIVERGES go={g!r} rust={r!r}")
    return errors


# --- results -----------------------------------------------------------------

def make_result(pair, impl, samples, metadata, tier="micro"):
    return {"schema": "bench-result/v1", "tier": tier, "name": pair["id"], "impl": impl,
            "unit": pair["unit"], "better": "lower", "samples": list(samples),
            "metadata": metadata}
