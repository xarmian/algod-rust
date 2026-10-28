#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Generate a deterministic workload block corpus (issue #2104, epic #2101).

Builds benchmarks/go-corpus (`corpusgen`, linked against the pinned
go-algorand checkout), writes a fixed DevMode genesis + node config, starts the
pinned go-algorand `algod` on it, drives the workload (payments, ASA
create/opt-in/transfer/clawback/freeze/close, app create/call/opt-in/close-out/
clear/update/delete with global, local and box state, atomic groups, inner
pay/axfer/appl, rekeys, keyreg online/offline, account close-outs), records
every block + certificate, stops algod and writes MANIFEST.sha256.

The same seed and parameters give a byte-identical corpus (genesis, every
block, corpus.json): see "Workload corpus" in docs/BENCHMARK_COMPARISON.md.

Needs Linux/macOS with go (go-algorand's go.mod version), a pinned go-algorand
checkout with libsodium built, and its algod binary:
  bash scripts/bench/build_both.sh --skip-rust      # -> target/bench-compare/go/algod

Usage:
  python3 scripts/bench/corpus/generate.py --preset small --out benchmarks/corpus/small
  python3 scripts/bench/corpus/generate.py --preset large --out /data/corpus-large
  python3 scripts/bench/corpus/generate.py --rounds 300 --accounts 32 \\
      --txns-per-round 8 --seed mine --out /tmp/c
"""
import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(BENCH))
sys.path.insert(0, HERE)
sys.path.insert(0, BENCH)
import corpus_tool  # noqa: E402
import fingerprint  # noqa: E402

GO_MODULE = os.path.join(REPO, "benchmarks", "go-corpus")
GO_ALGORAND_MODULE = "github.com/algorand/go-algorand"
DEFAULT_SEED = "algod-rust-bench-corpus"

# name -> (rounds, accounts, txns_per_round)
PRESETS = {
    "tiny": (100, 32, 6),       # CI determinism check
    "small": (2000, 64, 5),     # committed: benchmarks/corpus/small (<= 5 MB)
    "large": (50000, 1000, 20),  # release asset: ~1M txns
}


class SetupError(Exception):
    pass


def default_go_algorand():
    return os.path.abspath(os.environ.get("GO_ALGORAND_DIR")
                           or os.path.join(os.path.dirname(REPO), "go-algorand"))


def git(d, *args):
    p = subprocess.run(["git", "-C", d, *args], capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""


def go_algorand_pin(go_dir, allow_unpinned):
    tag = os.environ.get("GO_ALGORAND_REV") or fingerprint.read_pin()
    head = git(go_dir, "rev-parse", "HEAD")
    want = git(go_dir, "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}")
    if not head:
        raise SetupError(f"{go_dir} is not a go-algorand git checkout")
    if head != want:
        msg = (f"go-algorand at {go_dir} is at {head}, not the pinned {tag} commit "
               f"{want or '(tag missing)'} (git -C {go_dir} checkout {tag})")
        if not allow_unpinned:
            raise SetupError(msg)
        print(f"corpus: WARNING: {msg}", file=sys.stderr)
    return tag, head


def go_version_line():
    with open(os.path.join(GO_MODULE, "go.mod"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("go "):
                return line.strip()
    raise SetupError("benchmarks/go-corpus/go.mod has no go directive")


def build_corpusgen(go_dir, work):
    gowork = os.path.join(work, "go.work")
    with open(gowork, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"{go_version_line()}\n\nuse {GO_MODULE}\n\n"
                f"replace {GO_ALGORAND_MODULE} => {go_dir}\n")
    env = dict(os.environ, GOWORK=gowork, GOFLAGS=os.environ.get("GOFLAGS", "-buildvcs=false"))
    exe = os.path.join(work, "corpusgen")
    print("corpus: building benchmarks/go-corpus", flush=True)
    rc = subprocess.run(["go", "build", "-o", exe, "."], cwd=GO_MODULE, env=env).returncode
    if rc != 0:
        raise SetupError("go build of benchmarks/go-corpus failed (libsodium built? make -C "
                         f"{go_dir} libsodium)")
    return exe


def run(cmd):
    print("corpus: $ " + " ".join(cmd), flush=True)
    if subprocess.run(cmd).returncode != 0:
        raise SetupError(f"{os.path.basename(cmd[0])} {cmd[1]} failed")


def generate(args):
    rounds, accounts, tpr = PRESETS.get(args.preset, (None, None, None))
    rounds = args.rounds or rounds
    accounts = args.accounts or accounts
    tpr = args.txns_per_round or tpr
    if not (rounds and accounts and tpr):
        raise SetupError("give --preset or all of --rounds/--accounts/--txns-per-round")
    name = args.name or args.preset or "custom"
    out = os.path.abspath(args.out)
    if os.path.isdir(out) and os.listdir(out):
        if not args.force:
            raise SetupError(f"{out} is not empty (pass --force to replace it)")
        shutil.rmtree(out)
    algod = os.path.abspath(args.algod)
    if not os.access(algod, os.X_OK):
        raise SetupError(f"no algod at {algod} (bash scripts/bench/build_both.sh --skip-rust, "
                         "or pass --algod)")
    go_dir = os.path.abspath(args.go_algorand)
    tag, commit = go_algorand_pin(go_dir, args.allow_unpinned)
    with tempfile.TemporaryDirectory(prefix="bench-corpus-") as work:
        corpusgen = args.corpusgen or build_corpusgen(go_dir, work)
        node = os.path.join(work, "node")
        run([corpusgen, "genesis", "-seed", args.seed, "-accounts", str(accounts), "-out", node])
        log = open(os.path.join(work, "algod.out"), "wb")
        print(f"corpus: starting {algod} -d {node}", flush=True)
        proc = subprocess.Popen([algod, "-d", node], stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.time() + 60
            while not os.path.exists(os.path.join(node, "algod.net")):
                if proc.poll() is not None or time.time() > deadline:
                    raise SetupError(f"algod did not start (exit {proc.poll()}); see "
                                     f"{os.path.join(node, 'node.log')}")
                time.sleep(0.1)
            t0 = time.time()
            run([corpusgen, "drive", "-data", node, "-seed", args.seed,
                 "-accounts", str(accounts), "-rounds", str(rounds),
                 "-txns-per-round", str(tpr), "-ts-offset", str(args.ts_offset),
                 "-out", out, "-name", name, "-go-tag", tag, "-go-commit", commit])
            print(f"corpus: drive took {time.time() - t0:.1f}s", flush=True)
        except BaseException:
            if args.keep_node:
                shutil.copytree(node, args.keep_node, dirs_exist_ok=True)
            raise
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
            log.close()
        corpus_tool.write_manifest(out)
        run([corpusgen, "verify", "-corpus", out])
    errors = corpus_tool.verify(out, coverage=not args.no_coverage)
    if errors:
        raise SetupError("generated corpus failed verification:\n  " + "\n  ".join(errors))
    size = sum(os.path.getsize(os.path.join(out, n)) for n in os.listdir(out))
    cj = corpus_tool.load_corpus_json(out)
    print(f"corpus: wrote {out}: {cj['txns']} txns, rounds 0..{rounds}, {size} bytes")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--preset", choices=sorted(PRESETS))
    ap.add_argument("--rounds", type=int)
    ap.add_argument("--accounts", type=int)
    ap.add_argument("--txns-per-round", type=int)
    ap.add_argument("--seed", default=DEFAULT_SEED)
    ap.add_argument("--ts-offset", type=int, default=3,
                    help="DevMode block timestamp step in seconds (default 3)")
    ap.add_argument("--name", help="corpus name in corpus.json (default: the preset)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--force", action="store_true", help="replace a non-empty --out")
    ap.add_argument("--algod", default=os.path.join(REPO, "target", "bench-compare", "go", "algod"))
    ap.add_argument("--go-algorand", default=default_go_algorand())
    ap.add_argument("--corpusgen", help="prebuilt corpusgen binary (default: go build it)")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="warn instead of failing when go-algorand is not at the pinned tag")
    ap.add_argument("--no-coverage", action="store_true",
                    help="skip the every-workload-kind-present check (very short runs)")
    ap.add_argument("--keep-node", metavar="DIR", help="on failure, copy the node data dir here")
    args = ap.parse_args(argv)
    try:
        generate(args)
    except SetupError as e:
        print(f"corpus: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
