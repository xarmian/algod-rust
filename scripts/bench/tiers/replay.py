#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
# bench-tier-needs: build
"""bench-compare `replay` tier: offline ledger replay of the workload block
corpus, go-algorand vs algod-rust, with a final-state equality gate (issue
#2105, epic #2101).

Both sides replay the same corpus (benchmarks/corpus/<name>, issue #2104)
from a fresh data directory:

  go   benchmarks/go-replay (`goreplay`): go-algorand's ledger.Ledger, the
       per-block body of catchup/service.go fetchAndWrite;
  rust `algod-rust bench replay-corpus`: algod-rust's production catchup
       path (CatchupService::sync_range -> AgreementLedgerBridge::ensure_block).

Each run emits a `bench-replay-run/v1` document with timings, resource use
and the canonical final state. The gate fails the tier unless every run of
both sides reaches the same final state and that state matches the corpus's
corpus.json (`corpus_match`). A diverging state is a parity bug, not a
benchmark result.

Inputs (environment):
  BENCH_CORPUS / CORPUS     corpus name: `small` (default, committed),
                            `large` (fetched with scripts/bench/fetch_corpus.sh
                            into benchmarks/corpus/large when missing),
                            `testnet-head` (the first rounds of the real
                            testnet, with real certificates, so both sides
                            authenticate every certificate; fetched with
                            scripts/bench/corpus/fetch_testnet.py into
                            benchmarks/corpus/testnet-head when missing, issue
                            #2119) or `testnet-prefix50` (its committed
                            50-round slice)
  BENCH_CORPUS_DIR          an explicit corpus directory (overrides the name)
  BENCH_REPLAY_WARMUP       discarded warm-up runs per side (default 1)
  BENCH_REPLAY_ROUNDS       replay only rounds 1..N (bisecting; no corpus gate)
  BENCH_REPLAY_CORRUPT      negative test: `txn` (flip one byte of a txn note),
                            `vote` (flip one bit of a vote signature in the
                            last certificate; needs a corpus with real
                            certificates) or `expected` (alter corpus.json's
                            expected state), with the manifest re-hashed; the
                            tier must then fail
  plus the tier contract (BENCH_RUNS, BENCH_OUT, BENCH_RUST_BIN_DIR,
  BENCH_GO_ALGORAND_DIR; docs/BENCHMARK_COMPARISON.md).

Results (results/replay/replay.json), per side: `<corpus>/blocks_per_s`,
`txns_per_s` (top-level + inner), `wall_s`, `peak_rss_mb`, `cpu_s`
(user + sys), `db_mb`, and `write_mb` where the kernel reports
/proc/self/io.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(BENCH))
sys.path.insert(0, BENCH)
sys.path.insert(0, os.path.join(BENCH, "corpus"))
import bench_schema  # noqa: E402,F401
import corpus_tool  # noqa: E402

TIER = "replay"
GO_MODULE = os.path.join(REPO, "benchmarks", "go-replay")
GO_ALGORAND_MODULE = "github.com/algorand/go-algorand"
MB = 1024 * 1024


class TierError(Exception):
    pass


class SideFailures(TierError):
    """One or both sides failed a replay; `failed` maps side -> message."""

    def __init__(self, failed):
        self.failed = failed
        super().__init__("; ".join(f"{k}: {v}" for k, v in sorted(failed.items())))


def run_pair(order, run):
    """Run both sides in `order` with `run(side)`. A failing side never
    stops the other one from running, so a corrupted corpus shows that each
    side rejects it on its own. Raises SideFailures naming every failed side."""
    out, failed = {}, {}
    for side in order:
        try:
            out[side] = run(side)
        except TierError as e:
            failed[side] = str(e)
    if failed:
        raise SideFailures(failed)
    return out


# ---- final-state gate --------------------------------------------------------

def state_diff(a, b, path=""):
    """Paths where two JSON values differ (empty list: equal)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            p = f"{path}.{k}" if path else k
            if k not in a or k not in b:
                out.append(f"{p}: only in {'rust' if k not in a else 'go'}")
            else:
                out += state_diff(a[k], b[k], p)
        return out
    if a != b:
        return [f"{path}: go {a!r} != rust {b!r}"]
    return []


def state_sha256(state):
    """sha256 of the canonical (sorted-keys) JSON of a final state."""
    return hashlib.sha256(json.dumps(state, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def gate(runs, full_replay):
    """Check every run's result. `runs` is a list of {"go": result, "rust":
    result}; returns the list of gate errors (empty: pass)."""
    errors = []
    ref = None
    for i, r in enumerate(runs):
        for side in ("go", "rust"):
            res = r[side]
            if full_replay and res.get("corpus_match") is not True:
                mm = "; ".join(res.get("corpus_mismatches") or []) or "no corpus_match"
                errors.append(f"run {i} {side}: final state differs from corpus.json: {mm}")
        d = state_diff(r["go"]["final_state"], r["rust"]["final_state"])
        if d:
            errors.append(f"run {i}: go and rust final states differ: " + "; ".join(d[:20]))
        for side in ("go", "rust"):
            st = r[side]["final_state"]
            if ref is None:
                ref = st
            elif state_diff(ref, st):
                errors.append(f"run {i} {side}: final state differs from run 0's")
    return errors


# ---- negative-test corpora ---------------------------------------------------

NOTE_NEEDLE = bytes([0xa4]) + b"note" + bytes([0xc4, 10])


def corrupt_corpus(src, dst, kind):
    """Copy corpus `src` to `dst` with one deliberate corruption, then
    re-hash the manifest so the corpus still verifies:

      txn       flip the last byte of the first txn note in blocks.bin (the
                block's payset commitment no longer matches its header);
      vote      flip one bit of the last byte of the last vote's signature
                (cert.vote[-1].sig.s, located by parsing the record's msgpack,
                corpus_tool.corrupt_vote) in the last record: that certificate
                no longer authenticates its block;
      expected  change corpus.json's expected `accounts_sha256`.
    """
    shutil.copytree(src, dst)
    if kind == "vote":
        try:
            corpus_tool.corrupt_vote(os.path.join(dst, "blocks.bin"))
        except ValueError as e:
            raise TierError(f"cannot tamper a vote in blocks.bin: {e} "
                            "(a DevMode corpus has no votes)")
    elif kind == "txn":
        p = os.path.join(dst, "blocks.bin")
        with open(p, "rb") as f:
            b = bytearray(f.read())
        i = b.find(NOTE_NEEDLE)
        if i < 0:
            raise TierError("no txn note in blocks.bin")
        b[i + len(NOTE_NEEDLE) + 9] ^= 1
        with open(p, "wb") as f:
            f.write(b)
    elif kind == "expected":
        p = os.path.join(dst, "corpus.json")
        with open(p, encoding="utf-8") as f:
            cj = json.load(f)
        h = cj["final_state"]["accounts_sha256"]
        cj["final_state"]["accounts_sha256"] = ("0" if h[0] != "0" else "1") + h[1:]
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            json.dump(cj, f, indent=2)
            f.write("\n")
    else:
        raise TierError(f"BENCH_REPLAY_CORRUPT={kind!r}: want txn, vote or expected")
    corpus_tool.write_manifest(dst)
    return dst


# ---- corpus and binaries -----------------------------------------------------

def check_cache_pin(d, name):
    """The fetched testnet-head cache must hold the corpus its ref pins: the
    sha256 of its MANIFEST.sha256 (which in turn pins every file; `main`
    verifies those). A foreign or stale cache is refused, not replayed."""
    if name != "testnet-head":
        return
    ref_path = os.path.join(REPO, "benchmarks", "corpus", "testnet-head.ref")
    if not os.path.isfile(ref_path):
        return
    import fetch_testnet
    pin = fetch_testnet.read_ref(ref_path).get("manifest_sha256", "")
    if len(pin) != 64 or not set(pin) <= corpus_tool.HEX_DIGITS:
        return  # not pinned yet
    m = os.path.join(d, corpus_tool.MANIFEST)
    got = corpus_tool.sha256_file(m) if os.path.isfile(m) else "(no manifest)"
    if got != pin:
        raise TierError(f"{d}: MANIFEST.sha256 has sha256 {got}, benchmarks/corpus/testnet-head.ref "
                        f"pins {pin}: not the pinned testnet-head corpus. Delete it to refetch, or "
                        "run scripts/bench/corpus/fetch_testnet.py fetch --force")


def resolve_corpus():
    d = os.environ.get("BENCH_CORPUS_DIR")
    if d:
        return os.path.abspath(d)
    name = os.environ.get("BENCH_CORPUS") or os.environ.get("CORPUS") or "small"
    d = os.path.join(REPO, "benchmarks", "corpus", name)
    if name == "large" and not os.path.isfile(os.path.join(d, "corpus.json")):
        print("replay: fetching the large corpus (scripts/bench/fetch_corpus.sh)", flush=True)
        rc = subprocess.run(["bash", os.path.join(BENCH, "fetch_corpus.sh")]).returncode
        if rc != 0:
            raise TierError(f"fetch_corpus.sh exited {rc}: generate the corpus with "
                            "`make bench-corpus-large` or pass BENCH_CORPUS_DIR")
    if name == "testnet-head" and not os.path.isfile(os.path.join(d, "corpus.json")):
        print("replay: fetching the testnet-head corpus "
              "(scripts/bench/corpus/fetch_testnet.py)", flush=True)
        rc = subprocess.run([sys.executable, os.path.join(BENCH, "corpus", "fetch_testnet.py"),
                             "fetch"]).returncode
        if rc != 0:
            raise TierError(f"fetch_testnet.py exited {rc}: the testnet endpoint must be "
                            "reachable once (docs/BENCHMARK_COMPARISON.md, \"The testnet-head "
                            "corpus\"), or pass BENCH_CORPUS_DIR")
    if not os.path.isfile(os.path.join(d, "corpus.json")):
        raise TierError(f"no corpus at {d}")
    check_cache_pin(d, name)
    return d


def go_version_line():
    with open(os.path.join(GO_MODULE, "go.mod"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("go "):
                return line.strip()
    raise TierError("benchmarks/go-replay/go.mod has no go directive")


def build_goreplay(go_dir, work):
    """Build benchmarks/go-replay against the go-algorand checkout `go_dir`."""
    import micro_equiv as eq
    eq.check_pin(go_dir)
    eq.ensure_libsodium(go_dir)
    gowork = os.path.join(work, "go.work")
    with open(gowork, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"{go_version_line()}\n\nuse {GO_MODULE}\n\n"
                f"replace {GO_ALGORAND_MODULE} => {go_dir}\n")
    exe = os.path.join(work, "goreplay" + (".exe" if os.name == "nt" else ""))
    env = dict(os.environ, GOWORK=gowork,
               GOFLAGS=os.environ.get("GOFLAGS", "-buildvcs=false"))
    rc = subprocess.run(["go", "build", "-o", exe, "."], cwd=GO_MODULE, env=env).returncode
    if rc != 0:
        raise TierError(f"go build of benchmarks/go-replay exited {rc}")
    return exe


def rust_binary():
    d = os.environ.get("BENCH_RUST_BIN_DIR") or os.path.join(REPO, "target", "bench-compare",
                                                             "rust")
    exe = os.path.join(d, "algod-rust" + (".exe" if os.name == "nt" else ""))
    if not os.path.isfile(exe):
        raise TierError(f"{exe} missing (build_both.sh builds it)")
    return exe


# ---- one replay ---------------------------------------------------------------

def run_side(side, exe, corpus, work, tag, rounds):
    data = os.path.join(work, f"{side}-{tag}")
    out = data + ".json"
    if side == "go":
        cmd = [exe, "-corpus", corpus, "-data", data, "-out", out]
        if rounds:
            cmd += ["-rounds", str(rounds)]
    else:
        cmd = [exe, "bench", "replay-corpus", "--corpus", corpus, "--data-dir", data,
               "--output", out]
        if rounds:
            cmd += ["--rounds", str(rounds)]
    print("$ " + " ".join(cmd), flush=True)
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=dict(os.environ, RUST_LOG="warn"))
    tail = "\n".join(p.stderr.strip().splitlines()[-15:])
    if tail:
        print(tail, flush=True)
    # exit 3: replayed, but the state differs from corpus.json (the gate
    # reports it); anything else non-zero is a failed replay.
    if p.returncode not in (0, 3) or not os.path.isfile(out):
        raise TierError(f"{side} replay exited {p.returncode}")
    with open(out, encoding="utf-8") as f:
        res = json.load(f)
    shutil.rmtree(data, ignore_errors=True)
    res["_cmd"] = " ".join(cmd)
    return res


def samples_of(res):
    m = res["metrics"]
    out = {
        "blocks_per_s": ("block/s", "higher", m["blocks_per_s"]),
        "txns_per_s": ("txn/s", "higher", m["txns_per_s"]),
        "wall_s": ("s", "lower", m["wall_s"]),
        "peak_rss_mb": ("MB", "lower", m["peak_rss_bytes"] / MB),
        "cpu_s": ("s", "lower", m["cpu_user_s"] + m["cpu_sys_s"]),
        "db_mb": ("MB", "lower", m["db_bytes"] / MB),
    }
    if m.get("write_bytes") is not None:
        out["write_mb"] = ("MB", "lower", m["write_bytes"] / MB)
    return out


def results(runs, corpus_name, meta):
    rows = []
    for side in ("go", "rust"):
        per = {}
        for r in runs:
            for k, (unit, better, v) in samples_of(r[side]).items():
                per.setdefault(k, (unit, better, []))[2].append(round(v, 6))
        for k, (unit, better, vals) in per.items():
            rows.append({
                "schema": "bench-result/v1", "tier": TIER,
                "name": f"{corpus_name}/{k}", "impl": side, "unit": unit,
                "better": better, "samples": vals,
                "metadata": dict(meta, command=runs[0][side]["_cmd"],
                                 config=runs[0][side].get("config", {})),
            })
    return rows


# Metrics whose Rust/Go ratio CI requires. The others may lack one: go's
# write_mb legitimately reads 0 on runners whose I/O accounting does not
# attribute its writes, and a zero baseline has no ratio (issue #2124).
TIMING_METRICS = ("wall_s", "cpu_s", "blocks_per_s", "txns_per_s")


def ratio_gate(rep):
    """Errors of a report.json for CI: the report must be ok, hold replay
    rows, and give every timing metric a Rust/Go ratio."""
    if not rep.get("ok"):
        return [f"report not ok: {rep.get('errors')}"]
    rows = [r for r in rep.get("rows", []) if r.get("tier") == TIER]
    if not rows:
        return ["no replay rows"]
    errors = []
    names = {r["name"] for r in rows}
    corpora = sorted({n.split("/", 1)[0] for n in names})
    for c in corpora:
        for k in TIMING_METRICS:
            name = f"{c}/{k}"
            row = next((r for r in rows if r["name"] == name), None)
            if row is None or row.get("ratio") is None:
                errors.append(f"{name}: no Rust/Go ratio")
    return errors


def check_report(path):
    with open(path, encoding="utf-8") as f:
        rep = json.load(f)
    errors = ratio_gate(rep)
    for e in errors:
        print(f"replay: {e}", file=sys.stderr)
    if errors:
        return 1
    rows = [r for r in rep["rows"] if r["tier"] == TIER]
    na = [r["name"] for r in rows if r.get("ratio") is None]
    print(f"{len(rows)} replay rows; every timing metric has a Rust/Go ratio"
          + (f"; no ratio (zero or unmeasured baseline): {', '.join(na)}" if na else ""))
    return 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--check-report":
        return check_report(sys.argv[2])
    runs = int(os.environ.get("BENCH_RUNS", "5"))
    warmup = int(os.environ.get("BENCH_REPLAY_WARMUP", "1"))
    rounds = int(os.environ.get("BENCH_REPLAY_ROUNDS", "0") or 0)
    out_dir = os.environ.get("BENCH_OUT") or os.getcwd()
    if runs < 1 or warmup < 0:
        print("replay: BENCH_RUNS must be >= 1 and BENCH_REPLAY_WARMUP >= 0", file=sys.stderr)
        return 2
    os.makedirs(out_dir, exist_ok=True)
    try:
        corpus = resolve_corpus()
        with tempfile.TemporaryDirectory(prefix="bench-replay-") as work:
            corrupt = os.environ.get("BENCH_REPLAY_CORRUPT")
            if corrupt:
                corpus = corrupt_corpus(corpus, os.path.join(work, "corpus"), corrupt)
                print(f"replay: NEGATIVE TEST: corpus corrupted ({corrupt}); the tier "
                      f"must fail", flush=True)
            errs = corpus_tool.verify_manifest(corpus)
            if errs:
                raise TierError("corpus manifest: " + "; ".join(errs))
            cj = corpus_tool.load_corpus_json(corpus)
            corpus_name = cj.get("name") or os.path.basename(corpus)
            full = not rounds or rounds == cj["rounds"]["last"]
            go_exe = build_goreplay(os.path.abspath(
                os.environ.get("BENCH_GO_ALGORAND_DIR")
                or os.path.join(os.path.dirname(REPO), "go-algorand")), work)
            rust_exe = rust_binary()
            sides = {"go": go_exe, "rust": rust_exe}

            measured = []
            for i in range(warmup + runs):
                order = ("go", "rust") if i % 2 == 0 else ("rust", "go")
                r = run_pair(order, lambda s: run_side(s, sides[s], corpus, work, f"{i}",
                                                       rounds))
                kind = "warm-up" if i < warmup else f"run {i - warmup + 1}/{runs}"
                print(f"replay: {kind}: go {r['go']['metrics']['wall_s']:.2f}s, "
                      f"rust {r['rust']['metrics']['wall_s']:.2f}s", flush=True)
                errors = gate([r], full)
                if errors:
                    raise TierError("final-state gate FAILED:\n  " + "\n  ".join(errors))
                if i >= warmup:
                    measured.append(r)
            errors = gate(measured, full)
            if errors:
                raise TierError("final-state gate FAILED:\n  " + "\n  ".join(errors))
            state = measured[0]["go"]["final_state"]
            meta = {
                "corpus": corpus_name,
                "corpus_dir": os.path.relpath(corpus, REPO) if not corrupt else corpus,
                "manifest_sha256": corpus_tool.sha256_file(
                    os.path.join(corpus, corpus_tool.MANIFEST)),
                "rounds": measured[0]["go"]["rounds"],
                "blocks": measured[0]["go"]["metrics"]["blocks"],
                "txns": measured[0]["go"]["metrics"]["txns"],
                "final_state_sha256": state_sha256(state),
                "final_block_hash": state["block_hash"],
                "corpus_match": full,
                "warmup": warmup,
            }
            with open(os.path.join(out_dir, "replay.json"), "w", encoding="utf-8",
                      newline="\n") as f:
                json.dump(results(measured, corpus_name, meta), f, indent=1)
            print(f"replay: final-state gate passed ({len(measured)} runs per side, "
                  f"state {meta['final_state_sha256'][:16]}, {state['block_hash']})")
    except TierError as e:
        print(f"replay: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # micro_equiv.SetupError and the like
        print(f"replay: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
