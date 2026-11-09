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
import concurrent.futures
import http.client
import json
import os
import shutil
import sys
import subprocess
import tempfile
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
        import _catchup_mock  # lazily: only mock mode needs it (issue #2167)

        return _catchup_mock.label()
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
                    import _catchup_mock  # lazily: only mock mode needs it (issue #2167)

                    nodes = _catchup_mock.make_nodes(SIDES, cfg)
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
