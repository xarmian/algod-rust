#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
# bench-tier-needs: build
"""bench-compare `rest` tier: REST API throughput of go-algorand's algod and
algod-rust against identical ledger state, behind a response-equality gate
(issue #2107, epic #2101).

  1. Both implementations replay the same workload corpus (the `replay`
     tier's benchmarks/go-replay and `algod-rust bench replay-corpus`) into a
     data directory each, and both must reach the corpus's final state (the
     replay tier's gate), so the two ledgers are the same by construction.
  2. Each data directory is served by its own node in a Docker
     container with identical CPU / memory / swap limits: go `algod` at the
     pinned tag, `algod-rust node start`. The mount is read-write and the
     files world-writable (both nodes write SQLite WAL files next to the
     ledger); nothing here changes ledger state and every run replays into a
     fresh temporary directory (docs/BENCHMARK_COMPARISON.md, "The rest tier").
  3. The fixed request set (rest_lib.request_set: /v2/status, hot and cold
     accounts, account assets, an application, a box, a block as JSON and as
     msgpack, transaction params, a simulate) is sent to both and EVERY
     response must be equal after rest_lib's documented normalisation
     (VOLATILE) and issue-linked allowlist (KNOWN_DIFFERENCES). Any other
     difference fails the tier before a single load step runs, and the gate
     runs again after the load.
  4. One load generator (benchmarks/go-restload, one binary for both nodes)
     drives each endpoint at fixed concurrency; per endpoint, req/s,
     p50/p95/p99 latency, error rate and the container's CPU cores and peak
     RSS (`docker stats`) become schema-v1 rows `<endpoint>/c<N>/<metric>`.
     Go and Rust alternate who goes first in every repeat.

Inputs (environment; docs/BENCHMARK_COMPARISON.md, "The rest tier"):
  BENCH_REST_PROFILE      `full` (default) or `smoke` (CI: one short step)
  BENCH_REST_CONCURRENCY  load levels, e.g. 1,16,64
  BENCH_REST_DURATION     seconds measured per endpoint and level
  BENCH_REST_WARMUP       discarded seconds per endpoint and level
  BENCH_REST_CPUS / _MEM  per-container limits (default 2 / 3g)
  BENCH_REST_PORT_BASE    first published REST port (default 4400)
  BENCH_REST_GO_IMAGE     default algorand/algod:<pinned tag without `v`>
  BENCH_REST_RUST_IMAGE   a prebuilt algod-rust image (default: build
                          docker/Dockerfile's `runtime` target)
  BENCH_REST_CORRUPT      negative test: the named endpoint's Rust response is
                          altered before the gate, which must then fail
  BENCH_CORPUS / BENCH_CORPUS_DIR   as the replay tier (default `small`)
  plus the tier contract (BENCH_RUNS, BENCH_OUT, BENCH_RUST_BIN_DIR,
  BENCH_GO_ALGORAND_DIR; docs/BENCHMARK_COMPARISON.md).
"""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(BENCH))
sys.path.insert(0, BENCH)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(BENCH, "corpus"))
import bench_schema  # noqa: E402,F401
import corpus_tool  # noqa: E402
import localnet  # noqa: E402  (docker helpers, image handling)
import localnet_lib as ll  # noqa: E402
import replay  # noqa: E402  (corpus resolution, go-replay build, final-state gate)
import rest_lib as rl  # noqa: E402

TIER = "rest"
TOKEN = ll.TOKEN
LOAD_MODULE = os.path.join(REPO, "benchmarks", "go-restload")
STARTUP_TIMEOUT = 180


class TierError(Exception):
    pass


def log(msg):
    print(f"rest: {msg}", flush=True)


# ---- configuration -----------------------------------------------------------

def settings(env=None):
    env = os.environ if env is None else env

    def num(name, default, cast):
        v = env.get(name)
        if v in (None, ""):
            return default
        try:
            return cast(v)
        except ValueError:
            raise TierError(f"{name}={v!r} is not a number") from None

    name = env.get("BENCH_REST_PROFILE", "full")
    if name not in rl.PROFILES:
        raise TierError(f"BENCH_REST_PROFILE={name!r}: want {', '.join(rl.PROFILES)}")
    p = dict(rl.PROFILES[name], profile=name)
    try:
        if env.get("BENCH_REST_CONCURRENCY"):
            p["concurrency"] = rl.parse_concurrency(env["BENCH_REST_CONCURRENCY"])
    except ValueError as e:
        raise TierError(f"BENCH_REST_CONCURRENCY: {e}") from None
    p["duration_s"] = num("BENCH_REST_DURATION", p["duration_s"], float)
    p["warmup_s"] = num("BENCH_REST_WARMUP", p["warmup_s"], float)
    p["cpus"] = num("BENCH_REST_CPUS", 2.0, float)
    p["mem"] = env.get("BENCH_REST_MEM") or "3g"
    p["port_base"] = num("BENCH_REST_PORT_BASE", 4400, int)
    p["go_image"] = env.get("BENCH_REST_GO_IMAGE") or "algorand/algod:" + localnet.pinned_tag().lstrip("v")
    p["rust_image"] = env.get("BENCH_REST_RUST_IMAGE") or ""
    p["corrupt"] = env.get("BENCH_REST_CORRUPT") or ""
    if p["duration_s"] < rl.MIN_DURATION_S:
        raise TierError(f"BENCH_REST_DURATION must be >= {rl.MIN_DURATION_S} s, got "
                        f"{p['duration_s']}")
    if p["warmup_s"] != 0 and p["warmup_s"] < rl.MIN_DURATION_S:
        raise TierError(f"BENCH_REST_WARMUP must be 0 or >= {rl.MIN_DURATION_S} s, got "
                        f"{p['warmup_s']}")
    p["max_error_rate"] = num("BENCH_REST_MAX_ERROR_RATE", rl.MAX_ERROR_RATE, float)
    if not 0 <= p["max_error_rate"] <= 1:
        raise TierError("BENCH_REST_MAX_ERROR_RATE must be between 0 and 1")
    if not p["cpus"] > 0:
        raise TierError(f"BENCH_REST_CPUS must be > 0, got {p['cpus']}")
    if not 1024 <= p["port_base"] <= 65530:
        raise TierError(f"BENCH_REST_PORT_BASE must be 1024..65530, got {p['port_base']}")
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)?[bkmgBKMG]?", p["mem"]):
        raise TierError(f"BENCH_REST_MEM={p['mem']!r}: want a Docker size like 3g or 512m")
    return p


# ---- the shared ledger -------------------------------------------------------

def prepare_ledgers(corpus, cj, work):
    """Replay the corpus on both sides into data directories that are kept,
    gate on the replay tier's final-state equality, and make each directory
    servable READ-WRITE (config, genesis, tokens, world-writable for the
    container user: the nodes write WAL files next to the ledger).
    Returns {side: data_dir}, {side: replay result}."""
    go_exe = replay.build_goreplay(os.path.abspath(
        os.environ.get("BENCH_GO_ALGORAND_DIR")
        or os.path.join(os.path.dirname(REPO), "go-algorand")), work)
    rust_exe = replay.rust_binary()
    sides = {"go": go_exe, "rust": rust_exe}
    try:
        res = replay.run_pair(("go", "rust"), lambda s: replay.run_side(
            s, sides[s], corpus, work, "serve", 0, keep=True))
    except replay.SideFailures as e:
        raise TierError(f"replay failed: {e}") from None
    errors = replay.gate([res], True)
    if errors:
        raise TierError("the two ledgers differ after replay (final-state gate):\n  "
                        + "\n  ".join(errors))
    genesis = os.path.join(corpus, cj["files"]["genesis"])
    dirs = {}
    for side in ("go", "rust"):
        d = res[side]["_data_dir"]
        cfg_path = os.path.join(d, "config.json")
        with open(cfg_path, encoding="utf-8") as f:
            cfg = json.load(f)
        cfg["EndpointAddress"] = f"0.0.0.0:{rl.REST_PORT}"
        with open(cfg_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(cfg, f, indent=2)
        shutil.copyfile(genesis, os.path.join(d, "genesis.json"))
        for n in ("algod.token", "algod.admin.token"):
            with open(os.path.join(d, n), "w", encoding="utf-8", newline="") as f:
                f.write(TOKEN)
        make_writable(d)
        dirs[side] = d
    return dirs, res


def make_writable(path):
    """The container user (uid 1001 for go, root or another for rust) must be
    able to write sqlite WAL files next to the replayed ledger."""
    for dirpath, dirs, files in os.walk(path):
        os.chmod(dirpath, 0o777)
        for f in files:
            os.chmod(os.path.join(dirpath, f), 0o666)


# ---- leftovers ---------------------------------------------------------------

def sweep_stale(docker_fn=None):
    """Remove containers of an earlier, killed run: only those carrying this
    tier's label (`rest_lib.LABEL`), so nothing else is ever touched. They
    would hold the fixed REST ports. Returns the removed container ids."""
    docker_fn = docker_fn or localnet.docker
    p = docker_fn("ps", "-aq", "--filter", f"label={rl.LABEL}=1", check=False)
    ids = (p.stdout or "").split()
    if ids:
        log(f"removing {len(ids)} container(s) left by an earlier run: {' '.join(ids)}")
        docker_fn("rm", "-f", *ids, check=False)
    return ids


def purge_tree(path, image, docker_fn=None):
    """Remove a tree the containers wrote into (root- or uid-1001-owned) with
    `find -delete` in a throw-away container of an image that is ALREADY local
    (never pulled here: this runs in a `finally`). No shell is needed. On any
    failure the leaked path is named in a warning and nothing is raised.
    Returns True when the tree is gone."""
    docker_fn = docker_fn or localnet.docker
    if not os.path.isdir(path):
        return True
    have = docker_fn("image", "inspect", image, check=False)
    if have.returncode == 0:
        docker_fn("run", "--rm", "-v", f"{localnet.posix(path)}:/purge", "--entrypoint", "find",
                  image, "/purge", "-mindepth", "1", "-delete", check=False, timeout=120)
    shutil.rmtree(path, ignore_errors=True)
    if os.path.exists(path):
        log(f"WARNING: could not remove {path} (root-owned files; image {image!r} "
            f"{'present' if have.returncode == 0 else 'not present locally, so not pulled'}); "
            "delete it by hand")
        return False
    return True


# ---- nodes -------------------------------------------------------------------

class Node:
    def __init__(self, impl, image, data_dir, port, cfg):
        self.impl, self.port = impl, port
        self.name = f"bench-rest-{impl}-{os.getpid()}"
        self.args = rl.container_args(impl, name=self.name, image=image,
                                      data_dir=localnet.posix(data_dir), port=port,
                                      cpus=cfg["cpus"], mem=cfg["mem"])
        self.base = f"http://127.0.0.1:{port}"

    def start(self):
        localnet.docker(*self.args)

    def logs(self, tail=25):
        p = localnet.docker("logs", "--tail", str(tail), self.name, check=False)
        return ((p.stdout or "") + (p.stderr or "")).strip()

    def running(self):
        p = localnet.docker("inspect", "--format", "{{.State.Running}}", self.name, check=False)
        return p.stdout.strip() == "true"

    def stop(self):
        localnet.docker("rm", "-f", self.name, check=False)


def fetch(base, req, timeout=30):
    """The response to `req`: {status, content_type, body}. An HTTP error
    status is a response, not an exception."""
    headers = {"X-Algo-API-Token": TOKEN}
    if req.get("content_type"):
        headers["Content-Type"] = req["content_type"]
    if req.get("kind") == "msgpack":
        headers["Accept"] = "application/msgpack"
    data = base64.b64decode(req["body_b64"]) if req.get("body_b64") else None
    rq = urllib.request.Request(base + req["path"], data=data, headers=headers,
                                method=req.get("method", "GET"))
    try:
        with urllib.request.urlopen(rq, timeout=timeout) as r:
            return {"status": r.status, "content_type": r.headers.get("Content-Type", ""),
                    "body": r.read()}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "content_type": e.headers.get("Content-Type", ""),
                "body": e.read()}


def get_json(base, path):
    r = fetch(base, {"path": path, "kind": "json"})
    if r["status"] != 200:
        raise TierError(f"GET {path} on {base}: HTTP {r['status']}: {r['body'][:200]!r}")
    return json.loads(r["body"])


def wait_ready(node, last_round):
    """Wait until the node answers /v2/status at the corpus's last round."""
    deadline = time.monotonic() + STARTUP_TIMEOUT
    err = ""
    while time.monotonic() < deadline:
        if not node.running():
            raise TierError(f"{node.impl} node exited during startup:\n{node.logs()}")
        try:
            st = get_json(node.base, "/v2/status")
            if int(st["last-round"]) == last_round:
                return
            err = f"last-round {st['last-round']}, want {last_round}"
        except (TierError, OSError, KeyError, ValueError) as e:
            err = str(e)
        time.sleep(1)
    raise TierError(f"{node.impl} node not ready at round {last_round} after "
                    f"{STARTUP_TIMEOUT}s ({err}):\n{node.logs()}")


def discover(base, cj, genesis_path):
    """The ledger facts the request set needs, read from the reference (go)
    node, deterministically: hot and cold account among the genesis accounts,
    the newest application that holds a box, and a funded sender."""
    with open(genesis_path, encoding="utf-8") as f:
        genesis = json.load(f)
    addrs = sorted({a["addr"] for a in genesis["alloc"]})
    reserved = {genesis.get("rwd"), genesis.get("fees")} - {None}
    accts = {a: get_json(base, f"/v2/accounts/{a}") for a in addrs}
    hot, cold = rl.pick_hot_cold(accts)
    app_ids = sorted({int(x["id"]) for a in accts.values() for x in a.get("created-apps", [])},
                     reverse=True)
    app_id = box = None
    for aid in app_ids:
        boxes = get_json(base, f"/v2/applications/{aid}/boxes").get("boxes", [])
        if boxes:
            app_id, box = aid, boxes[0]["name"]
            break
    if app_id is None:
        raise TierError("no genesis account created an application that holds a box "
                        f"({len(app_ids)} applications examined); pick a corpus with boxes")
    try:
        sender = rl.pick_sender(accts, reserved)
    except ValueError as e:
        raise TierError(str(e)) from None
    return {"hot": hot, "cold": cold, "app_id": app_id, "box_name_b64": box,
            "round": cj["rounds"]["last"], "sender": sender}


# ---- load --------------------------------------------------------------------

def build_restload(work):
    exe = os.path.join(work, "restload" + (".exe" if os.name == "nt" else ""))
    env = dict(os.environ, GOFLAGS=os.environ.get("GOFLAGS", "-buildvcs=false"))
    env.pop("GOWORK", None)
    rc = subprocess.run(["go", "build", "-o", exe, "."], cwd=LOAD_MODULE, env=env).returncode
    if rc != 0:
        raise TierError(f"go build of benchmarks/go-restload exited {rc}")
    return exe


class StatsSampler(threading.Thread):
    """`docker stats` samples of one container while a load step runs.
    Timestamps are wall-clock (time.time), the clock restload reports its
    measured window in. A failing or empty `docker stats` is retried after a
    back-off; after MAX_FAILURES in a row the sampler gives up and records why
    in `failed` (the resource rows are then absent, the run goes on)."""

    MAX_FAILURES = 20

    def __init__(self, name, docker_fn=None, backoff_s=0.5):
        super().__init__(daemon=True)
        self.name_, self.samples, self._stop_evt = name, [], threading.Event()
        self.docker = docker_fn or localnet.docker
        self.backoff_s, self.failed = backoff_s, None

    def run(self):
        failures = 0
        while not self._stop_evt.is_set():
            started = time.time()
            p = self.docker("stats", "--no-stream", "--format", "{{json .}}", self.name_,
                            check=False, timeout=30)
            got = 0
            for line in (p.stdout or "").splitlines():
                try:
                    s = ll.parse_stats_line(line)
                except (ValueError, KeyError):
                    continue
                # `docker stats --no-stream` describes the interval its own call
                # spans, so a sample carries the start and the end of the call.
                self.samples.append({"start": started, "t": time.time(),
                                     "node": self.name_, **s})
                got += 1
            if p.returncode == 0 and got:
                failures = 0
                continue
            failures += 1
            if failures >= self.MAX_FAILURES:
                self.failed = (f"`docker stats {self.name_}` failed {failures} times in a row "
                               f"(exit {p.returncode}: {(p.stderr or '').strip()[-120:]})")
                return
            self._stop_evt.wait(self.backoff_s)

    def stop(self):
        self._stop_evt.set()
        self.join(timeout=35)


def resource_window_summary(samples, start, end):
    """CPU / RSS of the container over the measured window [start, end]. The
    ONLY place the window is applied: samples whose whole `docker stats` call
    is not inside it are dropped (rest_lib.window_samples), and the summary
    then covers what is left."""
    kept = rl.window_samples(samples, start, end)
    return ll.resource_summary(kept, float("-inf"), float("inf"))


def run_load(exe, node, req, conc, cfg, work, tag):
    """One endpoint at one concurrency against one node: restload's result
    plus the container's CPU / RSS over the window."""
    reqs = os.path.join(work, f"req-{tag}.json")
    out = os.path.join(work, f"out-{tag}.json")
    with open(reqs, "w", encoding="utf-8", newline="\n") as f:
        json.dump(rl.loadgen_requests([req]), f)
    cmd = [exe, "-base", node.base, "-token", TOKEN, "-requests", reqs, "-concurrency",
           str(conc), "-duration", rl.format_duration(cfg["duration_s"]), "-warmup",
           rl.format_duration(cfg["warmup_s"]),
           "-out", out]
    sampler = StatsSampler(node.name)
    sampler.start()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
    finally:
        sampler.stop()
    if p.returncode != 0:
        raise TierError(f"restload exited {p.returncode}: {p.stderr.strip()[-300:]}")
    with open(out, encoding="utf-8") as f:
        res = json.load(f)["endpoints"][0]
    if sampler.failed:
        log(f"WARNING: no resource rows for {node.name}: {sampler.failed}")
    # The window is the one restload measured (after its warm-up), not the
    # moment the process exited.
    summary = resource_window_summary(sampler.samples, res["start_unix"], res["end_unix"])
    return res, summary


# ---- the tier ----------------------------------------------------------------

def check_gate(requests, nodes, cfg, label, corpus):
    go = {r["name"]: fetch(nodes["go"].base, r) for r in requests}
    rust = {r["name"]: fetch(nodes["rust"].base, r) for r in requests}
    if cfg["corrupt"]:
        if cfg["corrupt"] not in rust:
            raise TierError(f"BENCH_REST_CORRUPT={cfg['corrupt']!r}: not an endpoint "
                            f"({', '.join(sorted(rust))})")
        req = next(r for r in requests if r["name"] == cfg["corrupt"])
        try:
            rust[cfg["corrupt"]] = rl.corrupt_response(
                req, go[cfg["corrupt"]], rust[cfg["corrupt"]], rl.KNOWN_DIFFERENCES, corpus)
        except ValueError as e:
            raise TierError(f"BENCH_REST_CORRUPT: {e}") from None
        log(f"NEGATIVE TEST: the rust response of {cfg['corrupt']} is altered; the gate must fail")
    errors = rl.gate(requests, go, rust, rl.KNOWN_DIFFERENCES, corpus=corpus)
    if errors:
        raise TierError(f"response-equality gate FAILED ({label}):\n  " + "\n  ".join(errors))
    sizes = ", ".join(f"{r['name']}={len(go[r['name']]['body'])}B" for r in requests)
    log(f"response-equality gate passed ({label}): {len(requests)} requests, bodies {sizes}")
    return go


def run_tier():
    cfg = settings()
    runs = int(os.environ.get("BENCH_RUNS", "5"))
    if cfg["profile"] == "smoke" and "BENCH_RUNS" not in os.environ:
        runs = 1
    out_dir = os.environ.get("BENCH_OUT") or os.getcwd()
    os.makedirs(out_dir, exist_ok=True)
    if runs < 1:
        raise TierError("BENCH_RUNS must be >= 1")
    rl.check_allowlist(rl.KNOWN_DIFFERENCES)
    sweep_stale()
    work = tempfile.mkdtemp(prefix="bench-rest-")
    nodes = {}
    try:
        corpus = replay.resolve_corpus()
        errs = corpus_tool.verify_manifest(corpus)
        if errs:
            raise TierError("corpus manifest: " + "; ".join(errs))
        cj = corpus_tool.load_corpus_json(corpus)
        corpus_name = cj.get("name") or os.path.basename(corpus)
        localnet.ensure_images(cfg, rust_env="BENCH_REST_RUST_IMAGE",
                               rust_tag="algod-rust:bench-rest")
        dirs, replays = prepare_ledgers(corpus, cj, work)
        restload = build_restload(work)
        for i, side in enumerate(("go", "rust")):
            nodes[side] = Node(side, cfg[f"{side}_image"], dirs[side], cfg["port_base"] + i, cfg)
        try:
            rl.require_same_limits(nodes["go"].args, nodes["rust"].args)
        except ValueError as e:
            raise TierError(str(e)) from None
        for n in nodes.values():
            n.start()
        for n in nodes.values():
            wait_ready(n, cj["rounds"]["last"])
        log(f"both nodes serve round {cj['rounds']['last']} of {corpus_name} "
            f"(limits: {cfg['cpus']} cpus, {cfg['mem']} each)")

        state = discover(nodes["go"].base, cj, os.path.join(corpus, cj["files"]["genesis"]))
        params = get_json(nodes["go"].base, "/v2/transactions/params")
        sim = rl.simulate_request(state["sender"], state["cold"], params)
        sim_app = rl.simulate_app_request(state["sender"], params)
        requests = rl.request_set(state, simulate=[sim, sim_app])
        log("request set: " + ", ".join(r["name"] for r in requests))
        gate_go = check_gate(requests, nodes, cfg, "before load", corpus_name)
        problems = rl.check_simulation(gate_go["simulate"])
        if problems:
            raise TierError("the simulate request is not a successful simulation: "
                            + "; ".join(problems))
        try:
            problems = rl.check_simulate_app(gate_go["simulate_app"])
        except ValueError as e:
            raise TierError(str(e)) from None
        if problems:
            raise TierError("the simulate_app request is not a successful app-call "
                            "simulation: " + "; ".join(problems))

        rows = []
        for conc in cfg["concurrency"]:
            per_run, resources = [], {"go": {}, "rust": {}}
            for i in range(runs):
                order = ("go", "rust") if i % 2 == 0 else ("rust", "go")
                one = {"go": {}, "rust": {}}
                for req in requests:
                    for side in order:
                        res, summ = run_load(restload, nodes[side], req, conc, cfg, work,
                                             f"{side}-{req['name']}-c{conc}-{i}")
                        one[side][req["name"]] = res
                        bad = rl.check_error_rate(res, side, req["name"], cfg["max_error_rate"])
                        if bad:
                            raise TierError(bad)
                        slot = resources[side].setdefault(req["name"],
                                                          {"cpu_cores": [], "rss_mb": []})
                        if summ:
                            slot["cpu_cores"].append(summ["cpu_cores"])
                            slot["rss_mb"].append(summ["rss_mb_peak"])
                    log(f"c{conc} run {i + 1}/{runs} {req['name']}: "
                        + ", ".join(f"{s} {one[s][req['name']]['rps']:.0f} req/s "
                                    f"p99 {one[s][req['name']]['p99_ms']:.1f} ms" for s in order))
                per_run.append(one)
            meta = {
                "corpus": corpus_name, "corpus_dir": os.path.relpath(corpus, REPO),
                "manifest_sha256": corpus_tool.sha256_file(
                    os.path.join(corpus, corpus_tool.MANIFEST)),
                "final_block_hash": replays["go"]["final_state"]["block_hash"],
                "round": cj["rounds"]["last"], "hot": state["hot"], "cold": state["cold"],
                "app_id": state["app_id"], "duration_s": cfg["duration_s"],
                "warmup_s": cfg["warmup_s"], "cpus": cfg["cpus"], "mem": cfg["mem"],
                "go_image": cfg["go_image"], "go_image_id": cfg["go_image_id"],
                "rust_image": cfg["rust_image"], "rust_image_id": cfg["rust_image_id"],
                "profile": cfg["profile"], "allowlisted_differences": sum(1 for e in rl.KNOWN_DIFFERENCES if e.get("corpus") in (None, corpus_name)),
                "command": " ".join(nodes["go"].args[:2]) + " (docker run, rest_lib.container_args)",
            }
            rows += rl.result_rows(per_run, conc, resources, meta)
        check_gate(requests, nodes, dict(cfg, corrupt=""), "after load", corpus_name)
        with open(os.path.join(out_dir, "rest.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(rows, f, indent=1)
        log(f"{len(rows)} rows written")
    finally:
        for n in nodes.values():
            try:
                n.stop()
            except Exception:  # noqa: BLE001 - cleanup must not mask the real error
                pass
        # `find` of the go image removes the root-owned files; that image is
        # local whenever a node ever ran (nothing is pulled here).
        for side in ("go", "rust"):
            purge_tree(os.path.join(work, f"{side}-serve"), cfg["go_image"])
        if not purge_tree(work, cfg["go_image"]):
            log(f"WARNING: leaked work directory {work}")


def ratio_gate(rep, expected=None):
    """Errors of a report.json for CI: the report must be ok, hold `rest`
    rows, and give every endpoint a Rust/Go ratio for its req/s at every
    concurrency level present."""
    if not rep.get("ok"):
        return [f"report not ok: {rep.get('errors')}"]
    rows = [r for r in rep.get("rows", []) if r.get("tier") == TIER]
    if not rows:
        return ["no rest rows"]
    errors = []
    names = {r["name"] for r in rows}
    levels = sorted({n.split("/")[1] for n in names})
    endpoints = sorted(expected or {n.split("/")[0] for n in names})
    for ep in endpoints:
        for lv in levels:
            name = f"{ep}/{lv}/rps"
            row = next((r for r in rows if r["name"] == name), None)
            if row is None or row.get("ratio") is None:
                errors.append(f"{name}: no Rust/Go ratio")
    return errors


def check_report(path):
    with open(path, encoding="utf-8") as f:
        rep = json.load(f)
    errors = ratio_gate(rep, [r["name"] for r in EXPECTED_ENDPOINTS])
    for e in errors:
        print(f"rest: {e}", file=sys.stderr)
    if errors:
        return 1
    print("rest: every endpoint has a Rust/Go req/s ratio")
    return 0


# The endpoint names a complete run reports (rest_lib.request_set + simulate).
EXPECTED_ENDPOINTS = rl.request_set(
    {"hot": "h", "cold": "c", "app_id": 1, "box_name_b64": "Yg==", "round": 1},
    simulate=[{"name": "simulate", "path": "/p"}, {"name": "simulate_app", "path": "/p"}])


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--check-report":
        return check_report(sys.argv[2])
    try:
        run_tier()
    except TierError as e:
        print(f"rest: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # micro_equiv.SetupError, localnet.TierError and the like
        print(f"rest: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
