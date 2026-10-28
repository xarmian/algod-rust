#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Per-pair Go/Rust output-equivalence check of the micro tier (issue #2103).

Runs every benchmarks/pairs.toml pair's operation once on its fixture with
both implementations and compares the canonical output digests:

  Go:   go run ./cmd/equiv            (benchmarks/go-micro, real go-algorand)
  Rust: cargo run -p algo-bench-pairs --bin micro-equiv

A pair whose digests differ means the two sides did not do the same work on
the same bytes (or one of them is wrong), so its timing would be
meaningless: the check exits 1 and the micro tier stops before benchmarking.

The Go side is built against the go-algorand checkout given by
--go-algorand / $BENCH_GO_ALGORAND_DIR / $GO_ALGORAND_DIR (default
../go-algorand) through a generated go.work, so the checkout can live
anywhere. That checkout must sit on the pinned tag
(scripts/bench/go-algorand.pin; BENCH_MICRO_ALLOW_UNPINNED=1 overrides) and
needs go-algorand's vendored libsodium, which is built with `make
libsodium` when missing.

Usage: python3 scripts/bench/micro_equiv.py [--go-algorand DIR]
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import fingerprint  # noqa: E402
import micro_convert as mc  # noqa: E402

REGISTRY = os.path.join(REPO, "benchmarks", "pairs.toml")
GO_MODULE = os.path.join(REPO, "benchmarks", "go-micro")
GO_ALGORAND_MODULE = "github.com/algorand/go-algorand"


class SetupError(Exception):
    pass


def default_go_algorand():
    return os.path.abspath(os.environ.get("BENCH_GO_ALGORAND_DIR")
                           or os.environ.get("GO_ALGORAND_DIR")
                           or os.path.join(os.path.dirname(REPO), "go-algorand"))


def _git(go_dir, *args):
    return subprocess.run(["git", "-C", go_dir, *args], capture_output=True, text=True)


def check_pin(go_dir):
    """go-algorand HEAD must be the pinned tag's commit (same rule as build_both.sh)."""
    tag = os.environ.get("GO_ALGORAND_REV") or fingerprint.read_pin()
    head = _git(go_dir, "rev-parse", "HEAD")
    want = _git(go_dir, "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}")
    if head.returncode != 0:
        raise SetupError(f"{go_dir} is not a go-algorand git checkout")
    if want.returncode != 0 or head.stdout.strip() != want.stdout.strip():
        msg = (f"go-algorand at {go_dir} is at {head.stdout.strip()}, not the pinned "
               f"{tag} commit {want.stdout.strip() or '(tag missing)'} "
               f"(git -C {go_dir} checkout {tag})")
        if os.environ.get("BENCH_MICRO_ALLOW_UNPINNED") == "1":
            print(f"micro: WARNING: {msg}", file=sys.stderr)
        else:
            raise SetupError(msg)
    return tag, head.stdout.strip()


def ensure_libsodium(go_dir):
    goos = subprocess.run(["go", "env", "GOOS"], capture_output=True, text=True).stdout.strip()
    goarch = subprocess.run(["go", "env", "GOARCH"], capture_output=True,
                            text=True).stdout.strip()
    lib = os.path.join(go_dir, "crypto", "libs", goos, goarch, "lib", "libsodium.a")
    if os.path.isfile(lib):
        return
    print(f"micro: {lib} missing, running make libsodium in {go_dir}", flush=True)
    rc = subprocess.run(["make", "-C", go_dir, "libsodium"]).returncode
    if rc != 0 or not os.path.isfile(lib):
        raise SetupError(f"make libsodium failed in {go_dir} (needs autoconf automake "
                         f"libtool build-essential)")


def go_version_line():
    with open(os.path.join(GO_MODULE, "go.mod"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("go "):
                return line.strip()
    raise SetupError("benchmarks/go-micro/go.mod has no go directive")


def go_env(go_dir, work_dir):
    """Environment that builds benchmarks/go-micro against go_dir."""
    work = os.path.join(work_dir, "go.work")
    with open(work, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"{go_version_line()}\n\nuse {GO_MODULE}\n\n"
                f"replace {GO_ALGORAND_MODULE} => {go_dir}\n")
    return dict(os.environ, GOWORK=work, GOFLAGS=os.environ.get("GOFLAGS", "-buildvcs=false"))


def _json_digests(cmd, cwd, env, what):
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    sys.stderr.write(p.stderr[-4000:])
    try:
        out = json.loads(p.stdout)
    except ValueError:
        raise SetupError(f"{what} printed no JSON (exit {p.returncode}): {p.stdout[-2000:]}")
    return out


def go_digests(env, fixture_dir):
    return _json_digests(["go", "run", "./cmd/equiv", "-fixtures", fixture_dir], GO_MODULE,
                         env, "go run ./cmd/equiv")


def rust_digests(fixture_dir):
    return _json_digests(["cargo", "run", "--release", "--locked", "-q", "-p",
                          "algo-bench-pairs", "--bin", "micro-equiv", "--", fixture_dir],
                         REPO, os.environ, "micro-equiv")


def check(ids, go, rust, out=sys.stdout):
    """Print the per-pair table; return the list of mismatch errors."""
    errors = mc.compare_digests(ids, go, rust)
    bad = {e.split(":", 1)[0] for e in errors}
    for i in ids:
        mark = "DIFF" if i in bad else "ok  "
        out.write(f"  {mark} {i:34} {go.get(i, '-')[:72]}\n")
    return errors


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--go-algorand", default=default_go_algorand())
    args = ap.parse_args(argv)
    reg = mc.load_registry(REGISTRY)
    fixture_dir = os.path.join(REPO, reg["fixture_dir"])
    errors = mc.check_fixtures(reg, REPO)
    if errors:
        print("micro-equiv: fixture check failed:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1
    go_dir = os.path.abspath(args.go_algorand)
    try:
        check_pin(go_dir)
        ensure_libsodium(go_dir)
        with tempfile.TemporaryDirectory(prefix="bench-micro-") as work:
            go = go_digests(go_env(go_dir, work), fixture_dir)
        rust = rust_digests(fixture_dir)
    except SetupError as e:
        print(f"micro-equiv: {e}", file=sys.stderr)
        return 1
    ids = [p["id"] for p in reg["pair"]]
    errors = check(ids, go, rust)
    if errors:
        print(f"micro-equiv: {len(errors)} pair(s) differ:\n  " + "\n  ".join(errors),
              file=sys.stderr)
        return 1
    print(f"micro-equiv: all {len(ids)} pairs produce identical output on both sides")
    return 0


if __name__ == "__main__":
    sys.exit(main())
