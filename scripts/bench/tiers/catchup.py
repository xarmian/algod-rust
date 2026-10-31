#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""bench-compare `catchup` tier: fast catchup and follow of a PUBLIC network by
go-algorand's algod and algod-rust, side by side (issue #2108, epic #2101).

Per run (BENCH_RUNS repeats, each from empty data directories):

  1. one catchpoint label is resolved ONCE per tier run (the network's
     `latest.catchpoint` index, or BENCH_CATCHUP_LABEL) and given to both nodes;
  2. both nodes start in Docker with identical CPU / memory / swap limits, the
     same genesis.json (the repo's vendored copy of go-algorand's) and the same
     tokens, `POST /v2/catchup/<label>` is sent to both back to back, and both
     are polled once per BENCH_CATCHUP_POLL_S on `/v2/status`;
  3. the stages go-algorand and algod-rust both report (catchup_lib.stage_of:
     ledger download+import, verify, blocks) and the replay up to the head of
     the network (the newest block is within BENCH_CATCHUP_HEAD_SLACK_S of the
     wall clock) are timed; the replay's blocks/s is derived from them;
  4. both nodes then follow the network for BENCH_CATCHUP_FOLLOW_SECS: round
     rate, how far behind the head (block timestamp vs wall clock) and behind
     the other node they were;
  5. GATE: both reported the label they were told to catch up to, and their
     block hashes are IDENTICAL for every round (cap: BENCH_CATCHUP_HASH_CAP,
     evenly spaced beyond it, ends included) from the round after the
     catchpoint to the highest round both have. A mismatch is a parity bug, not
     a result: the tier fails.

A public run is non-deterministic and depends on external relays, so every row
is marked non-deterministic (report.py), and every failure is classified like
docker/scripts/network-image-smoke.sh does (`FAILURE CLASS: external network`
vs `FAILURE CLASS: node`, catchup_lib.classify_failure). CI never touches the
public network: BENCH_CATCHUP_MODE=mock runs this same driver against two
in-process mock nodes and a mock chain (docs/BENCHMARK_COMPARISON.md, "The
catchup tier").

Inputs (environment):
  BENCH_CATCHUP_NETWORK       testnet (default) | mainnet | betanet
  BENCH_CATCHUP_LABEL         an explicit catchpoint label (default: the network's latest)
  BENCH_CATCHUP_LABEL_URL     the index to read the latest label from
  BENCH_CATCHUP_MODE          live (default) | mock
  BENCH_CATCHUP_PROFILE       full (default) | smoke (short follow window)
  BENCH_CATCHUP_FOLLOW_SECS   follow window per run (default 600)
  BENCH_CATCHUP_STAGE_TIMEOUT seconds from the catchup request to the head (default 7200)
  BENCH_CATCHUP_POLL_S        status poll interval (default 1)
  BENCH_CATCHUP_HEAD_SLACK_S  "at the head" = newest block this young (default 30)
  BENCH_CATCHUP_HASH_CAP      most rounds whose hashes the gate compares (default 20000)
  BENCH_CATCHUP_MIN_GATE_ROUNDS  fewest rounds the gate may compare (default 100)
  BENCH_CATCHUP_CPUS, BENCH_CATCHUP_MEM   per-container limits (default 2 / 3g)
  BENCH_CATCHUP_PORT_BASE     first published REST port (default 4500)
  BENCH_CATCHUP_GO_IMAGE      default algorand/algod:<pinned tag without `v`>
  BENCH_CATCHUP_RUST_IMAGE    a prebuilt algod-rust image (default: build
                              docker/Dockerfile's `runtime` target)
  BENCH_CATCHUP_MOCK_FAULT    mock mode only: none | diverge | stall | die | abort
  plus the tier contract (BENCH_RUNS, BENCH_OUT, ...; docs/BENCHMARK_COMPARISON.md).
"""
import hashlib
import base64
import concurrent.futures
import http.client
import http.server
import json
import os
import shutil
import sys
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(BENCH))
sys.path.insert(0, BENCH)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(BENCH, "corpus"))
import bench_schema  # noqa: E402,F401
import catchup_lib as cl  # noqa: E402
import localnet  # noqa: E402  (docker helpers, image handling)
import localnet_lib as ll  # noqa: E402
import rest  # noqa: E402  (StatsSampler, purge_tree, make_writable)
import rest_lib as rl  # noqa: E402

TIER = cl.TIER
TOKEN = ll.TOKEN
LABEL_KEY = "bench-catchup"
OWNER_LABEL = "bench-catchup-owner"   # pid of the run that started the container
STARTUP_TIMEOUT = 180
TRANSIENT = (OSError, ValueError, KeyError, http.client.HTTPException)   # + TierError, below
MEM_LIMIT = {"v": ""}   # the run's container memory limit, named in an OOM failure
SIDES = ("go", "rust")
GATE_MARGIN_ROUNDS = 50   # rounds added to the oldest retained round (the window slides)


class TierError(Exception):
    """A harness problem (bad setup), not a verdict on either node."""


class CatchupFailure(Exception):
    """A classified failure of the run (catchup_lib.classify_failure)."""

    def __init__(self, cls, detail):
        super().__init__(cl.format_failure(cls, detail))
        self.cls, self.detail = cls, detail


def log(msg):
    print(f"catchup: {msg}", flush=True)


# ---- HTTP ------------------------------------------------------------------------

def http_call(base, path, token=TOKEN, method="GET", timeout=10):
    """(status, body bytes); an HTTP error status is a response. OSError on a
    transport failure."""
    rq = urllib.request.Request(base + path, method=method,
                                data=b"" if method == "POST" else None,
                                headers={"X-Algo-API-Token": token})
    try:
        with urllib.request.urlopen(rq, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def get_json(base, path, timeout=10):
    status, body = http_call(base, path, timeout=timeout)
    if status != 200:
        raise TierError(f"GET {path} on {base}: HTTP {status}: {body[:200]!r}")
    return json.loads(body)


def block_hash(base, rnd):
    """The block hash of `rnd`; None only when the node answers 404 (pruned).
    Transport errors and 5xx are retried, then raise catchup_lib.ProbeError."""
    return cl.hash_or_pruned(lambda r: http_call(base, f"/v2/blocks/{r}/hash"), rnd)


def block_ts(base, rnd):
    doc = get_json(base, f"/v2/blocks/{rnd}?header-only=true&format=json")
    return int(doc["block"]["ts"])


# ---- the label ----------------------------------------------------------------------

def resolve_label(cfg):
    """The catchpoint label both nodes are given. CatchupFailure (external
    network) when the index cannot be read."""
    if cfg["label"]:
        return cfg["label"]
    if cfg["mode"] == "mock":
        return MOCK_LABEL
    last = ""
    for attempt in range(3):
        try:
            with urllib.request.urlopen(cfg["label_url"], timeout=30) as r:
                return cl.parse_index_text(r.read().decode("utf-8", "replace"))
        except (OSError, ValueError) as e:
            last = str(e)
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
    raise CatchupFailure(cl.EXTERNAL, f"cannot read the catchpoint label from "
                                      f"{cfg['label_url']}: {last}")


# ---- nodes -----------------------------------------------------------------------------

def container_args(impl, *, name, image, data_dir, port, cpus, mem):
    """`docker run` arguments of one node: the same limits, port and mount for
    both, only the entrypoint differs (go's `algod -d` and algod-rust's go-compatible
    `algod -d` launcher). rest_lib.limits_of / require_same_limits read it."""
    if impl == "go":
        entry, cmd = ["--entrypoint", "algod"], ["-d", "/data", "-o", "-l", f"0.0.0.0:{rl.REST_PORT}"]
    elif impl == "rust":
        entry = ["--entrypoint", "algod-rust"]
        cmd = ["algod", "-d", "/data", "-o", "-l", f"0.0.0.0:{rl.REST_PORT}"]
    else:
        raise ValueError(f"impl must be go or rust, not {impl!r}")
    return ["run", "-d", "--name", name, "--label", f"{LABEL_KEY}=1", "--label", f"{OWNER_LABEL}={os.getpid()}",
            "--cpus", str(float(cpus)),
            "--memory", mem, "--memory-swap", mem, "-p", f"127.0.0.1:{port}:{rl.REST_PORT}",
            "-v", f"{data_dir}:/data", *entry, image, *cmd]


def seed_data_dir(path, genesis_path):
    """An empty node data directory: genesis, config and tokens, nothing else."""
    os.makedirs(path, exist_ok=True)
    shutil.copyfile(genesis_path, os.path.join(path, "genesis.json"))
    with open(os.path.join(path, "config.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"EndpointAddress": f"0.0.0.0:{rl.REST_PORT}"}, f)
    for n in ("algod.token", "algod.admin.token"):
        with open(os.path.join(path, n), "w", encoding="utf-8", newline="") as f:
            f.write(TOKEN)
    rest.make_writable(path)


class DockerNode:
    def __init__(self, impl, image, data_dir, port, cfg):
        self.impl = impl
        self.name = f"bench-catchup-{impl}-{os.getpid()}"
        self.args = container_args(impl, name=self.name, image=image,
                                   data_dir=localnet.posix(data_dir), port=port,
                                   cpus=cfg["cpus"], mem=cfg["mem"])
        self.base = f"http://127.0.0.1:{port}"
        self.data_dir = data_dir
        self.sampler = None

    def start(self):
        localnet.docker(*self.args)
        self.sampler = rest.StatsSampler(self.name)
        self.sampler.start()

    def logs(self, tail=4000):
        p = localnet.docker("logs", "--tail", str(tail), self.name, check=False)
        return ((p.stdout or "") + (p.stderr or "")).strip()

    def running(self):
        p = localnet.docker("inspect", "--format", "{{.State.Running}}", self.name, check=False)
        return p.stdout.strip() == "true"

    def samples(self):
        return self.sampler.samples if self.sampler else []

    def disk_mb(self):
        """`du -sk /data` in MB; None (the metric is skipped, with a warning)
        when it cannot be read: a passed run is never discarded for it."""
        try:
            p = localnet.docker("exec", self.name, "du", "-sk", "/data", check=False, timeout=60)
            return int(p.stdout.split()[0]) / 1024.0
        except (subprocess.SubprocessError, OSError, ValueError, IndexError) as e:
            log(f"WARNING: no disk_mb for {self.impl}: {type(e).__name__}: {e}")
            return None

    def oom_killed(self):
        p = localnet.docker("inspect", "--format", "{{.State.OOMKilled}}", self.name, check=False)
        return p.stdout.strip() == "true"

    def stop(self):
        if self.sampler:
            self.sampler.stop()
        localnet.docker("rm", "-f", self.name, check=False)


def pid_alive(pid):
    """Whether process `pid` exists (never signals it: on Windows signal 0 is
    CTRL_C_EVENT, so `tasklist` is asked there)."""
    if pid <= 0:
        return False
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True,
                             text=True).stdout
        return str(pid) in out.split()
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OverflowError:
        return False
    return True


def sweep_stale(docker_fn=None, pid_alive=pid_alive):
    """Remove the containers of dead runs only: those carrying this tier's label
    whose owner pid (OWNER_LABEL) is gone or missing. A concurrent live run's
    containers are never touched. Returns the removed container ids."""
    docker_fn = docker_fn or localnet.docker
    p = docker_fn("ps", "-a", "--filter", f"label={LABEL_KEY}=1", "--format",
                  '{{.ID}} {{.Label "' + OWNER_LABEL + '"}}', check=False)
    stale = []
    for line in (p.stdout or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        owner = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if owner == os.getpid() or not pid_alive(owner):
            stale.append(parts[0])
    if stale:
        log(f"removing {len(stale)} container(s) left by an earlier run: {' '.join(stale)}")
        docker_fn("rm", "-f", *stale, check=False)
    return stale


# ---- the mock network (BENCH_CATCHUP_MODE=mock) ---------------------------------------------
# Two in-process HTTP servers that answer the endpoints the driver uses and
# behave like a node catching up to a chain that advances at BLOCK_TIME: the
# stages of a catchup, a replay to the head, then following. No Docker, nothing
# external; it exercises the driver, the gates, the failure classes and the rows.

MOCK_LABEL = "40500000#" + "A" * 52
MOCK_ROUND0 = 40500000
MOCK_LEAD = 1200          # rounds the chain is ahead of the catchpoint when the catchup starts
MOCK_BLOCK_TIME = 0.1     # seconds per round of the mock chain
MOCK_STAGE_S = (0.5, 0.4, 0.4)   # ledger, verify, blocks
MOCK_RETENTION = 500      # rounds a mock node serves behind its newest block, like a non-archival node
MOCK_REPLAY_RPS = {"go": 1200.0, "rust": 960.0}


def mock_hash(rnd, fork=False):
    raw = hashlib.sha256(f"{'fork' if fork else 'mock'}:{rnd}".encode()).digest()
    return "blk-" + base64.b32encode(raw).decode().rstrip("=")[:52]


class MockChain:
    def __init__(self):
        self.t0 = time.time()

    def tip(self, now):
        return MOCK_ROUND0 + MOCK_LEAD + int((now - self.t0) / MOCK_BLOCK_TIME)

    def ts(self, rnd):
        return int(self.t0 + (rnd - MOCK_ROUND0 - MOCK_LEAD) * MOCK_BLOCK_TIME)


class MockNode:
    def __init__(self, impl, chain, cfg):
        self.impl, self.chain, self.fault = impl, chain, cfg["mock_fault"]
        self.trigger = None
        self.label = ""
        self.server = None
        self.base = ""
        self.data_dir = None

    # -- state --
    def status(self, now):
        base = {"catchpoint": "", "catchpoint-total-accounts": 0, "catchpoint-processed-accounts": 0,
                "catchpoint-verified-accounts": 0, "catchpoint-total-blocks": 0,
                "catchpoint-acquired-blocks": 0, "last-round": 0,
                "time-since-last-round": 1_000_000_000}
        if self.trigger is None:
            return base
        el = now - self.trigger
        l1, l2, l3 = MOCK_STAGE_S
        if self.fault == "stall":
            return dict(base, catchpoint=self.label)
        if self.fault == "abort":
            # the catchpoint clears with the ledger still at its pre-request sync
            if el < 0.5:
                return dict(base, catchpoint=self.label, **{"last-round": 5})
            return dict(base, **{"last-round": 5})
        total = 1000
        if el < l1:
            return dict(base, catchpoint=self.label,
                        **{"catchpoint-total-accounts": total if el > 0.05 else 0,
                           "catchpoint-processed-accounts": int(total * el / l1)})
        if el < l1 + l2:
            return dict(base, catchpoint=self.label, **{
                "catchpoint-total-accounts": total, "catchpoint-processed-accounts": total,
                "catchpoint-verified-accounts": int(total * (el - l1) / l2)})
        if el < l1 + l2 + l3:
            return dict(base, catchpoint=self.label, **{
                "catchpoint-total-accounts": total, "catchpoint-processed-accounts": total,
                "catchpoint-verified-accounts": total, "catchpoint-total-blocks": 320,
                "catchpoint-acquired-blocks": int(320 * (el - l1 - l2) / l3)})
        t_done = self.trigger + l1 + l2 + l3
        tip = self.chain.tip(now)
        replayed = MOCK_ROUND0 + int((now - t_done) * MOCK_REPLAY_RPS[self.impl])
        rnd = min(tip - (1 if self.impl == "rust" and int(now * 4) % 2 else 0), replayed)
        return dict(base, **{"last-round": max(rnd, MOCK_ROUND0)})

    def start(self):
        node = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, code, doc):
                body = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                if self.path.startswith("/v2/catchup/"):
                    node.label = urllib.parse.unquote(self.path.rsplit("/", 1)[1].split("?")[0])
                    node.trigger = time.time()
                    return self.reply(201, {"catchup-message": node.label})
                self.reply(404, {"message": "no such endpoint"})

            def do_GET(self):
                now = time.time()
                path, _, query = self.path.partition("?")
                if path == "/v2/status":
                    return self.reply(200, node.status(now))
                parts = path.strip("/").split("/")
                if len(parts) >= 3 and parts[:2] == ["v2", "blocks"]:
                    rnd = int(parts[2])
                    st = node.status(now)
                    if rnd > st["last-round"] or rnd <= st["last-round"] - MOCK_RETENTION:
                        return self.reply(404, {"message": "no such block"})
                    if len(parts) == 4 and parts[3] == "hash":
                        fork = node.fault == "diverge" and node.impl == "rust" \
                            and rnd >= MOCK_ROUND0 + MOCK_LEAD + 10
                        return self.reply(200, {"blockHash": mock_hash(rnd, fork)})
                    if "header-only=true" in query:
                        return self.reply(200, {"block": {"rnd": rnd, "ts": node.chain.ts(rnd)}})
                self.reply(404, {"message": "no such endpoint"})

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def running(self):
        # fault `die`: algod-rust crashes 3.4 s after the catchup request
        if self.fault == "die" and self.impl == "rust" and self.trigger is not None:
            return time.time() < self.trigger + 3.4
        return True

    def logs(self, tail=0):
        if self.fault == "die" and self.impl == "rust":
            return "thread 'main' panicked at src/ledger.rs:1:1: mock crash\n"
        if self.fault in ("stall", "abort"):
            return ("WARN catchpoint GET failed: Connection refused (os error 111)\n"
                    "WARN no relay served the catchpoint\n")
        return "INFO mock node: catchpoint import complete\n"

    def samples(self):
        return []

    def disk_mb(self):
        return None


# ---- one run ---------------------------------------------------------------------------------

def trigger(node, label):
    """The time of the first POST /v2/catchup/<label> attempt (catchup_lib.
    trigger_catchup: the POST is not idempotent, an `already in progress` answer
    after a timed-out attempt counts as success)."""
    # the label's `#` must be percent-encoded: left alone it starts a URL fragment
    path = "/v2/catchup/" + urllib.parse.quote(label, safe="")
    try:
        return cl.trigger_catchup(
            lambda: http_call(node.base, path, method="POST", timeout=30), label)
    except cl.TriggerError as e:
        raise CatchupFailure(cl.NODE, f"{node.impl}: POST {path} failed: {e}") from None


def wait_ready(node, mock):
    deadline = time.monotonic() + (10 if mock else STARTUP_TIMEOUT)
    err = ""
    while time.monotonic() < deadline:
        if not node.running():
            raise CatchupFailure(cl.NODE, f"{node.impl} exited during startup:\n{node.logs(25)}")
        try:
            status, _ = http_call(node.base, "/v2/status")
            if status == 200:
                return
            err = f"HTTP {status}"
        except OSError as e:
            err = str(e)
        time.sleep(1)
    raise CatchupFailure(cl.NODE, f"{node.impl} REST API not ready after startup timeout ({err}):\n"
                                  f"{node.logs(25)}")


def side_facts(nodes, trackers):
    out = {}
    for s, n in nodes.items():
        text = n.logs()
        tr = trackers.get(s)
        out[s] = {"progressed": bool(tr and (tr.progressed or tr.t_done is not None)),
                  "panicked": cl.log_has_fatal_panic(text),
                  "exited": not n.running(),
                  "oom": bool(getattr(n, "oom_killed", lambda: False)()),
                  "relay_error": cl.log_has_relay_error(text)}
    return out


def fail(nodes, trackers, kind, msg, label_error=False, mem_limit=""):
    cls, detail = cl.classify_failure(side_facts(nodes, trackers), label_error=label_error,
                                      kind=kind, mem_limit=mem_limit or MEM_LIMIT["v"])
    for s, n in nodes.items():
        tail = "\n".join(n.logs(60).splitlines()[-25:])
        print(f"catchup: --- last {s} log lines\n{tail}", file=sys.stderr)
    raise CatchupFailure(cls, f"{msg} ({detail})")


def poll(node, tracker, cfg):
    """One status sample of one node into its tracker; (round, lag_s) or None
    when the node did not answer. The status is observed FIRST; the lag probe
    (the newest block's timestamp) is optional: when it fails the sample is kept
    and only the lag is a gap. http.client errors (IncompleteRead,
    BadStatusLine) are transient like any transport error."""
    try:
        t = time.time()
        st = get_json(node.base, "/v2/status", timeout=5)
        rnd = int(st.get("last-round") or 0)
        tracker.observe(t, st, None)
    except TRANSIENT + (TierError,):
        return None
    lag = None
    if tracker.t_done is not None and rnd > 0:
        try:
            lag = time.time() - block_ts(node.base, rnd)
        except TRANSIENT + (TierError,):
            return rnd, None
        tracker.observe_lag(t, rnd, lag)
    return rnd, lag


def run_once(cfg, label, idx, nodes, mock):
    label_round, _ = cl.parse_label(label)
    for n in nodes.values():
        n.start()
    for n in nodes.values():
        wait_ready(n, mock)
    trackers = {s: cl.PhaseTracker(time.time(), cfg["head_slack_s"], label_round) for s in SIDES}
    try:
        return drive(cfg, label, idx, nodes, trackers, label_round)
    except CatchupFailure:
        raise
    except Exception as e:  # noqa: BLE001 - every failure after startup is classified, with logs
        fail(nodes, trackers, "other", f"unexpected {type(e).__name__}: {e}")


def drive(cfg, label, idx, nodes, trackers, label_round):
    t0 = {}
    for s in SIDES:
        t0[s] = trigger(nodes[s], label)
        trackers[s].t0 = t0[s]
    log(f"run {idx}: both nodes asked to catch up to {label}")

    deadline = min(t0.values()) + cfg["stage_timeout_s"]
    while not all(tr.at_head() for tr in trackers.values()):
        for s in SIDES:
            poll(nodes[s], trackers[s], cfg)
        for s in SIDES:
            if not nodes[s].running():
                fail(nodes, trackers, "other", f"{s} container exited during the catchup")
        gone = [s for s in SIDES if trackers[s].aborted]
        if gone:
            fail(nodes, trackers, "abort",
                 f"catchup aborted: the catchpoint cleared on {' and '.join(gone)} before the "
                 f"ledger reached the label's round {label_round}")
        if time.time() > deadline:
            fail(nodes, trackers, "timeout",
                 f"not at the head of the network {cfg['stage_timeout_s']:.0f}s after the "
                 f"catchup request (stages seen: "
                 f"{ {s: sorted(trackers[s].enter) for s in SIDES} })")
        time.sleep(cfg["poll_s"])
    t_head = {s: trackers[s].t_head for s in SIDES}
    log(f"run {idx}: at head: " + ", ".join(
        f"{s} {trackers[s].t_head - t0[s]:.1f}s" for s in SIDES))

    follow = {s: [] for s in SIDES}
    t_f0 = time.time()
    while True:
        now = time.time()
        for s in SIDES:
            got = poll(nodes[s], trackers[s], cfg)
            # one entry per iteration: a missed poll is a gap (None), not a shift
            follow[s].append(None if got is None else (now, got[0], got[1]))
        for s in SIDES:
            if not nodes[s].running():
                fail(nodes, trackers, "other", f"{s} container exited during the follow window")
        if now - t_f0 >= cfg["follow_secs"]:
            break
        time.sleep(cfg["poll_s"])
    t_end = time.time()

    # ---- the gate ----
    seen = {s: trackers[s].catchpoint_seen for s in SIDES}
    errs = cl.label_gate(label, seen)
    tips = {}
    for s in SIDES:
        tips[s] = int(get_json(nodes[s].base, "/v2/status")["last-round"])
    agreed = min(tips.values())
    # A non-archival node keeps only its newest blocks (a live testnet run: neither
    # node served the first ~90% of the rounds after the catchpoint), so the gate
    # range starts at the oldest round BOTH still serve.
    first = cl.oldest_available(
        label_round + 1, agreed,
        lambda r: all(block_hash(nodes[s].base, r) is not None for s in SIDES))
    if first is not None:
        # the retained window keeps sliding while the hashes are fetched
        first = min(first + GATE_MARGIN_ROUNDS, agreed)
    if first is None or agreed - first + 1 < cfg["min_gate_rounds"]:
        fail(nodes, trackers, "gate",
             f"block-hash equality gate FAILED: only "
             f"{0 if first is None else agreed - first + 1} round(s) up to the agreed tip "
             f"{agreed} are served by both nodes (need {cfg['min_gate_rounds']}, "
             "BENCH_CATCHUP_MIN_GATE_ROUNDS)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        try:
            hashes, rounds, first, trims = cl.collect_hashes(
                lambda side, r: block_hash(nodes[side].base, r), SIDES, first, agreed,
                cfg["hash_cap"], fetch=pool.map)
        except cl.RangeMoved as e:
            fail(nodes, trackers, "harness", f"block-hash gate could not fetch a stable range: {e}")
    if trims:
        log(f"run {idx}: the retained range moved during the fetch; start trimmed to {first} "
            f"({trims} retries)")
    herrs, compared = cl.hash_gate(hashes["go"], hashes["rust"], rounds)
    errs += herrs
    if errs:
        fail(nodes, trackers, "gate", "block-hash equality gate FAILED: " + "; ".join(errs))
    agreed_hash = hashes["go"][rounds[-1]]
    log(f"run {idx}: gate passed: {compared} rounds compared in "
        f"[{first}, {agreed}], hash at {rounds[-1]} {agreed_hash}")

    behind = cl.rounds_behind_max(
        [x and (x[0], x[1]) for x in follow["go"]], [x and (x[0], x[1]) for x in follow["rust"]])
    metrics = {}
    for s in SIDES:
        m = dict(trackers[s].durations())
        rate = trackers[s].replay_blocks_per_s()
        if rate is not None:
            m["replay_blocks_per_s"] = rate
        m.update(cl.follow_stats(follow[s]))
        if sum(1 for x in follow[s] if x is not None) >= 2:
            m["follow_rounds_behind_max"] = behind[s]
        m["gate_rounds_compared"] = compared
        m.update(cl.resource_metrics(nodes[s].samples(), t0[s], t_head[s], t_f0, t_end))
        disk = nodes[s].disk_mb()
        if disk is not None:
            m["disk_mb"] = disk
        metrics[s] = m
    return metrics, {"agreed_round": agreed, "agreed_block_hash": agreed_hash,
                     "rounds_compared": compared, "gate_range": [first, agreed], "label": label}


# ---- the tier ---------------------------------------------------------------------------------

def settings():
    try:
        cfg = cl.parse_settings(os.environ)
    except cl.CatchupError as e:
        raise TierError(str(e)) from None
    if cfg["mode"] == "live":
        cfg["go_image"] = cfg["go_image"] or "algorand/algod:" + localnet.pinned_tag().lstrip("v")
    return cfg


def run_tier():
    cfg = settings()
    mock = cfg["mode"] == "mock"
    runs = int(os.environ.get("BENCH_RUNS", "3"))
    if runs < 1:
        raise TierError("BENCH_RUNS must be >= 1")
    out_dir = os.environ.get("BENCH_OUT") or os.getcwd()
    os.makedirs(out_dir, exist_ok=True)
    MEM_LIMIT["v"] = cfg["mem"]
    log(f"{cfg['network']} ({cfg['mode']}), {runs} run(s), follow "
        f"{cfg['follow_secs']:.0f}s each, limits {cfg['cpus']} cpus / {cfg['mem']} each")
    work = tempfile.mkdtemp(prefix="bench-catchup-")
    results, details = [], []
    try:
        if not mock:
            sweep_stale()
            localnet.ensure_images(cfg, rust_env="BENCH_CATCHUP_RUST_IMAGE",
                                   rust_tag="algod-rust:bench-catchup")
            genesis = os.path.join(REPO, cl.NETWORKS[cfg["network"]]["genesis_rel"])
        labels = []
        for i in range(1, runs + 1):
            # resolved per repeat: an hour into a multi-run job the catchpoint of the
            # first repeat may have rotated off the relays (a pinned label stays)
            label = resolve_label(cfg)
            labels.append(label)
            nodes = {}
            try:
                if mock:
                    chain = MockChain()
                    nodes = {s: MockNode(s, chain, cfg) for s in SIDES}
                else:
                    for k, s in enumerate(SIDES):
                        d = os.path.join(work, f"run{i}-{s}")
                        seed_data_dir(d, genesis)
                        nodes[s] = DockerNode(s, cfg[f"{s}_image"], d, cfg["port_base"] + k, cfg)
                    try:
                        rl.require_same_limits(nodes["go"].args, nodes["rust"].args)
                    except ValueError as e:
                        raise TierError(str(e)) from None
                metrics, detail = run_once(cfg, label, i, nodes, mock)
                results.append(metrics)
                details.append(detail)
            finally:
                for n in nodes.values():
                    try:
                        n.stop()
                    except Exception:  # noqa: BLE001 - cleanup must not mask the real error
                        pass
                if not mock:
                    for s in SIDES:
                        rest.purge_tree(os.path.join(work, f"run{i}-{s}"), cfg["go_image"])
        meta = {
            "network": cfg["network"], "label": labels[0] if len(set(labels)) == 1 else "varies",
            "labels": labels, "label_round": cl.parse_label(labels[0])[0],
            "mode": cfg["mode"], "profile": cfg["profile"], "follow_secs": cfg["follow_secs"],
            "poll_s": cfg["poll_s"], "head_slack_s": cfg["head_slack_s"],
            "hash_cap": cfg["hash_cap"], "cpus": cfg["cpus"], "mem": cfg["mem"],
            "agreed_block_hash": details[0]["agreed_block_hash"], "runs_detail": details,
            "go_image": cfg["go_image"], "go_image_id": cfg.get("go_image_id", ""),
            "rust_image": cfg["rust_image"], "rust_image_id": cfg.get("rust_image_id", ""),
            "command": "docker run (catchup.container_args) + POST /v2/catchup/<label>",
        }
        rows = cl.result_rows(results, meta)
        with open(os.path.join(out_dir, "catchup.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(rows, f, indent=1)
        log(f"{len(rows)} rows written (non-deterministic: real network, n={runs})")
    finally:
        if not mock and not rest.purge_tree(work, cfg["go_image"]):
            log(f"WARNING: leaked work directory {work}")
        elif mock:
            shutil.rmtree(work, ignore_errors=True)


def main():
    try:
        run_tier()
    except CatchupFailure as e:
        print(f"catchup: {e}", file=sys.stderr)
        return 1
    except TierError as e:
        print(f"catchup: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - localnet.TierError and the like
        print(f"catchup: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
