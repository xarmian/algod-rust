#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""bench-compare `localnet` tier: homogeneous localnet throughput, an all-Go
cluster against an all-Rust cluster under the same load (issue #2106,
epic #2101).

A mixed cluster (docker/scripts/bench-stress.sh) cannot attribute throughput,
latency or resource use to one implementation, so this tier runs two
separate, identically shaped clusters one after the other on one host:

  go    1 relay + 4 participation nodes, algorand/algod at the pinned tag;
  rust  1 relay + 4 participation nodes, `algod-rust participate`.

Same genesis (one `goal network create`, copied), same stake split (25% x 4),
same node-local config.json, same Docker CPU/memory limits per container, same
network, and ONE load generator (`algod-rust loadgen`, outside both clusters)
driving the same steps:

  fixed   exactly N deterministic payments (--fixed-count): sender, note, fee
          and validity are pure functions of the sequence number, so the two
          clusters are fed byte-identical transactions. The gate then needs
          the SAME txid set committed by both (and the same load-account
          balances, the same genesis hash, a chain holding exactly those N
          txns, every node on one chain, no node restarted);
  ladder  an offered-TPS ladder (rate-limited, random notes);
  max     an unbounded "max sustained TPS" step (profile `full`).

Per step: confirmed TPS (txns committed between two block headers over their
chain time), submit TPS, submit->commit latency p50/p95/p99 (sampled by the
generator), mean round time, rejected groups, and the cluster's CPU cores,
peak RSS and block-device writes (`docker stats`). Results are schema-v1 rows
named `<step>/<metric>`; one sample per run, the report adds the Rust/Go ratio.
A diverging txid set is a parity bug, not a benchmark result: the tier fails.

Every run starts from a FRESH genesis (CLAUDE.md, "Mixed-cluster soaks"):
`goal network create` stamps the genesis with its creation time and both nodes
clamp block timestamps to prev.ts + 25 s, so a resumed network would emit
+25 s header timestamps and make round times meaningless.

Inputs (environment; docs/BENCHMARK_COMPARISON.md, "The localnet tier"):
  BENCH_LOCALNET_PROFILE     `full` (default) or `smoke` (CI: one tiny step)
  BENCH_LOCALNET_LADDER      offered TPS steps, e.g. 100,500,1000,2000
  BENCH_LOCALNET_STEP_SECS   seconds per ladder / max step
  BENCH_LOCALNET_FIXED_COUNT / _FIXED_TPS   the fixed-count step
  BENCH_LOCALNET_MAX_STEP    1/0: the unbounded step
  BENCH_LOCALNET_CPUS / _MEM per-container limits (default 2 / 3g)
  BENCH_LOCALNET_ACCOUNTS    funded load accounts (default 16)
  BENCH_LOCALNET_PORT_BASE   first published REST port (default 4300)
  BENCH_LOCALNET_GO_IMAGE    default algorand/algod:<pinned tag without `v`>
  BENCH_LOCALNET_RUST_IMAGE  a prebuilt algod-rust image (default: build
                             docker/Dockerfile's `runtime` target)
  plus the tier contract (BENCH_RUNS, BENCH_OUT, BENCH_RUN_DIR, ...).
"""
import json
import os
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
import localnet_lib as ll  # noqa: E402

TIER = "localnet"
FIXED_GROUP_SIZE = 1  # the fixed step is passed --group-size explicitly
FUND_MICROALGOS = 1_000_000_000_000
STARTUP_TIMEOUT = 300


class TierError(Exception):
    pass


def log(msg):
    print(f"localnet: {msg}", flush=True)


def docker(*args, check=True, timeout=None, capture=True):
    p = subprocess.run(["docker", *args], capture_output=capture, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    if check and p.returncode != 0:
        tail = "\n".join(((p.stdout or "") + (p.stderr or "")).strip().splitlines()[-15:])
        raise TierError(f"docker {' '.join(args[:3])} exited {p.returncode}\n{tail}")
    return p


def posix(path):
    return os.path.abspath(path).replace("\\", "/")


# ---- configuration -----------------------------------------------------------

def env_int(name, default):
    v = os.environ.get(name)
    return default if v in (None, "") else int(v)


def pinned_tag():
    with open(os.path.join(BENCH, "go-algorand.pin"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                return os.environ.get("GO_ALGORAND_REV") or line
    raise TierError("scripts/bench/go-algorand.pin is empty")


def settings():
    name = os.environ.get("BENCH_LOCALNET_PROFILE", "full")
    if name not in ll.PROFILES:
        raise TierError(f"BENCH_LOCALNET_PROFILE={name!r}: want {', '.join(ll.PROFILES)}")
    p = dict(ll.PROFILES[name])
    if os.environ.get("BENCH_LOCALNET_LADDER") is not None:
        p["ladder"] = ll.parse_ladder(os.environ["BENCH_LOCALNET_LADDER"])
    p["step_secs"] = env_int("BENCH_LOCALNET_STEP_SECS", p["step_secs"])
    p["fixed_count"] = env_int("BENCH_LOCALNET_FIXED_COUNT", p["fixed_count"])
    p["fixed_tps"] = env_int("BENCH_LOCALNET_FIXED_TPS", p["fixed_tps"])
    if os.environ.get("BENCH_LOCALNET_MAX_STEP") not in (None, ""):
        p["max_step"] = os.environ["BENCH_LOCALNET_MAX_STEP"] == "1"
    if p["fixed_count"] < 1 or p["step_secs"] < 1:
        raise TierError("fixed count and step seconds must be >= 1")
    p.update(
        profile=name,
        cpus=float(os.environ.get("BENCH_LOCALNET_CPUS") or 2),
        mem=os.environ.get("BENCH_LOCALNET_MEM") or "3g",
        accounts=env_int("BENCH_LOCALNET_ACCOUNTS", 16),
        port_base=env_int("BENCH_LOCALNET_PORT_BASE", 4300),
        num_rounds=env_int("BENCH_LOCALNET_NUM_ROUNDS", 30000),
        go_image=os.environ.get("BENCH_LOCALNET_GO_IMAGE")
        or "algorand/algod:" + pinned_tag().lstrip("v"),
        rust_image=os.environ.get("BENCH_LOCALNET_RUST_IMAGE") or "",
    )
    return p


def ensure_images(cfg):
    if docker("image", "inspect", cfg["go_image"], check=False).returncode != 0:
        log(f"pulling {cfg['go_image']}")
        docker("pull", cfg["go_image"], timeout=900)
    if not cfg["rust_image"]:
        cfg["rust_image"] = "algod-rust:bench-localnet"
        log(f"building {cfg['rust_image']} (docker/Dockerfile, target runtime)")
        docker("build", "-q", "-f", os.path.join(REPO, "docker", "Dockerfile"),
               "--target", "runtime", "-t", cfg["rust_image"], REPO, timeout=3600)
    elif docker("image", "inspect", cfg["rust_image"], check=False).returncode != 0:
        raise TierError(f"BENCH_LOCALNET_RUST_IMAGE={cfg['rust_image']} is not a local image")
    for k in ("go_image", "rust_image"):
        cfg[k.replace("image", "image_id")] = docker(
            "image", "inspect", "--format", "{{.Id}}", cfg[k]).stdout.strip()


# ---- the shared network tree -------------------------------------------------

def purge(path, image):
    """Remove a tree the containers wrote into (root- or uid-1001-owned)."""
    if os.path.isdir(path):
        docker("run", "--rm", "-v", f"{posix(path)}:/purge", "--entrypoint", "sh", image,
               "-c", "rm -rf /purge/* /purge/.[!.]* 2>/dev/null || true", check=False)
        shutil.rmtree(path, ignore_errors=True)


def make_network(cfg, work):
    """One fresh `goal network create`, the load accounts funded in its
    genesis, the node-local config overlay applied. Returns (netroot,
    genesis_id, partkeys, load-account addresses)."""
    netroot = os.path.join(work, "netroot")
    os.makedirs(netroot)
    tpl = os.path.join(work, "template.json")
    with open(tpl, "w", encoding="utf-8", newline="\n") as f:
        json.dump(ll.template(cfg["num_rounds"]), f, indent=2)
    log("goal network create (fresh genesis)")
    docker("run", "--rm", "-v", f"{posix(netroot)}:/netroot", "-v",
           f"{posix(tpl)}:/template.json:ro", "--entrypoint", "sh", cfg["go_image"], "-c",
           f"goal network create -n {ll.NETWORK_NAME} -r /netroot -t /template.json "
           "&& chmod -R a+rwX /netroot", timeout=900)
    keys_dir = os.path.join(work, "loadgen")
    os.makedirs(keys_dir)
    os.chmod(keys_dir, 0o777)  # the generator container writes its reports here
    docker("run", "--rm", "-v", f"{posix(keys_dir)}:/out", "--entrypoint", "sh",
           cfg["rust_image"], "-c",
           f"algod-rust loadgen gen-accounts --deterministic --count {cfg['accounts']} "
           "--out /out/keys.json >/dev/null && chmod a+rw /out/keys.json")
    with open(os.path.join(keys_dir, "keys.json"), encoding="utf-8") as f:
        addrs = [a["address"] for a in json.load(f)["accounts"]]

    genesis_id = None
    for dirpath, _, files in os.walk(netroot):
        if "genesis.json" in files:
            p = os.path.join(dirpath, "genesis.json")
            with open(p, encoding="utf-8") as f:
                text = f.read()
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(ll.genesis_with_alloc(text, addrs, FUND_MICROALGOS))
            genesis_id = genesis_id or ll.genesis_id_of(text)
    if not genesis_id:
        raise TierError("goal network create produced no genesis.json")
    partkeys = {}
    for svc, d in ll.NODE_DIRS.items():
        cfg_path = os.path.join(netroot, d, "config.json")
        base = ""
        if os.path.isfile(cfg_path):
            with open(cfg_path, encoding="utf-8") as f:
                base = f.read()
        c = json.loads(ll.node_config(base))
        c["NetAddress"] = f"0.0.0.0:{ll.GOSSIP_PORT}" if svc == "relay" else ""
        with open(cfg_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(c, f, indent=2)
        if svc != "relay":
            hits = []
            for dirpath, _, files in os.walk(os.path.join(netroot, d)):
                hits += [os.path.join(dirpath, x) for x in files if x.endswith(".partkey")]
            if len(hits) != 1:
                raise TierError(f"{d}: expected one .partkey, found {len(hits)}")
            partkeys[svc] = os.path.relpath(hits[0], netroot).replace("\\", "/")
    return netroot, genesis_id, partkeys, addrs


# ---- cluster -----------------------------------------------------------------

class Cluster:
    def __init__(self, impl, cfg, work, shared, genesis_id, partkeys):
        self.impl, self.cfg = impl, cfg
        self.project = f"bench-localnet-{impl}-{os.getpid()}"
        self.dir = os.path.join(work, impl)
        self.netroot = os.path.join(self.dir, "netroot")
        self.compose = os.path.join(self.dir, "compose.yaml")
        self.net = ll.network_name(self.project)
        shutil.copytree(shared, self.netroot)
        if impl == "rust":
            for svc in ll.SERVICES:
                d = os.path.join(self.netroot, f"{svc}-data")
                os.makedirs(d)
                for n in ("algod.token", "algod.admin.token"):
                    with open(os.path.join(d, n), "w", encoding="utf-8") as f:
                        f.write(ll.TOKEN)
                    os.chmod(os.path.join(d, n), 0o666)
                # Writable by whatever user the image runs as (the Go tree gets
                # the same treatment from `chmod -R a+rwX` in make_network).
                os.chmod(d, 0o777)
        top = ll.topology(
            impl, project=self.project, go_image=cfg["go_image"], rust_image=cfg["rust_image"],
            cpus=cfg["cpus"], mem=cfg["mem"], port_base=cfg["port_base"],
            netroot=posix(self.netroot), genesis_id=genesis_id, partkeys=partkeys)
        with open(self.compose, "w", encoding="utf-8", newline="\n") as f:
            f.write(ll.render_compose(top))
        self.samples = []
        self._stop = threading.Event()
        self._thread = None

    # -- REST --
    def api(self, svc, path, timeout=8):
        req = urllib.request.Request(
            f"http://127.0.0.1:{ll.host_port(self.cfg['port_base'], svc)}{path}",
            headers={"X-Algo-API-Token": ll.TOKEN})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def round_of(self, svc):
        try:
            return int(self.api(svc, "/v2/status")["last-round"])
        except (urllib.error.URLError, OSError, KeyError, ValueError):
            return None

    def point(self, rnd):
        return ll.block_point(self.api("relay", f"/v2/blocks/{rnd}"))

    # -- lifecycle --
    def up(self):
        log(f"{self.impl}: starting 1 relay + 4 participation nodes")
        docker("compose", "-f", posix(self.compose), "up", "-d", timeout=900)
        deadline = time.time() + STARTUP_TIMEOUT
        while time.time() < deadline:
            rounds = {s: self.round_of(s) for s in ll.SERVICES}
            if all(r is not None and r >= 2 for r in rounds.values()):
                log(f"{self.impl}: all nodes advancing (rounds {rounds})")
                self._start_sampler()
                return
            time.sleep(2)
        raise TierError(f"{self.impl}: the cluster did not reach round 2 on every node "
                        f"within {STARTUP_TIMEOUT}s (rounds {rounds})")

    def _start_sampler(self):
        names = {ll.container_name(self.project, s): s for s in ll.SERVICES}

        def loop():
            while not self._stop.is_set():
                out = docker("stats", "--no-stream", "--format", "{{json .}}", *names,
                             check=False).stdout or ""
                t = time.time()
                for line in out.splitlines():
                    try:
                        row = ll.parse_stats_line(line)
                    except (ValueError, KeyError):
                        continue
                    if row["name"] in names:
                        self.samples.append(dict(row, t=t, node=names[row["name"]]))
                self._stop.wait(0.5)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop_sampler(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=30)

    def restarts(self):
        out = {}
        for s in ll.SERVICES:
            p = docker("inspect", "--format", "{{.RestartCount}},{{.State.OOMKilled}},"
                       "{{.State.Running}}", ll.container_name(self.project, s), check=False)
            parts = p.stdout.strip().split(",")
            out[s] = {"restart_count": int(parts[0]) if parts[0].isdigit() else 0,
                      "oom": parts[1] == "true" if len(parts) > 1 else False,
                      "running": parts[2] == "true" if len(parts) > 2 else False}
        return out

    def save_logs(self, dest):
        os.makedirs(dest, exist_ok=True)
        for s in ll.SERVICES:
            p = docker("logs", "--tail", "3000", ll.container_name(self.project, s),
                       check=False)
            with open(os.path.join(dest, f"{self.impl}-{s}.log"), "w", encoding="utf-8",
                      newline="\n") as f:
                f.write((p.stdout or "") + (p.stderr or ""))

    def down(self):
        self.stop_sampler()
        docker("compose", "-f", posix(self.compose), "down", "-v", "--remove-orphans",
               check=False, timeout=300)

    # -- load --
    def drain(self, timeout=90):
        end = time.time() + timeout
        while time.time() < end:
            try:
                if int(self.api("relay", "/v2/transactions/pending?max=1")
                       .get("total-transactions", 0)) == 0:
                    return
            except (urllib.error.URLError, OSError, ValueError):
                pass
            time.sleep(2)

    def loadgen(self, work, name, extra, timeout):
        """One `algod-rust loadgen run` from a container on the cluster's
        network, outside every node. Returns its parsed report."""
        out_dir = os.path.join(work, "loadgen")
        endpoints = ",".join(f"http://{s}:{ll.REST_PORT}" for s in ll.SERVICES)
        args = ["loadgen", "run", "--algod-urls", endpoints, "--token", ll.TOKEN,
                "--keys", "/out/keys.json", "--output", f"/out/{name}.json", *extra]
        cmd = ["run", "--rm", "--network", self.net, "-v", f"{posix(out_dir)}:/out",
               "--entrypoint", "algod-rust", self.cfg["rust_image"], *args]
        p = docker(*cmd, check=False, timeout=timeout)
        path = os.path.join(out_dir, f"{name}.json")
        if p.returncode != 0 or not os.path.isfile(path):
            tail = "\n".join(((p.stdout or "") + (p.stderr or "")).strip().splitlines()[-10:])
            raise TierError(f"{self.impl}: loadgen {name} exited {p.returncode}\n{tail}")
        with open(path, encoding="utf-8") as f:
            rep = json.load(f)
        rep["_cmd"] = "docker " + " ".join(cmd)
        return rep

    def step(self, work, name, extra, timeout):
        """One measured load step: drain, mark the chain, run the generator,
        mark the chain again, aggregate."""
        self.drain()
        r0 = ll.require_round(self.round_of("relay"), "relay")
        p0 = self.point(r0)
        t0 = time.time()
        rep = self.loadgen(work, name, extra, timeout)
        t1 = time.time()
        # Confirmations were polled across all nodes: the relay (whose chain the
        # window and the balances are read from) may still lag the last one.
        target = (rep.get("fixed") or {}).get("last_confirmed_round")
        r1 = ll.wait_for_round(lambda: self.round_of("relay"), target, 120)
        p1 = self.point(ll.require_round(r1, "relay"))
        window = ll.window_stats(p0, p1)
        res = ll.resource_summary(self.samples, t0, t1)
        return rep, window, res, p0, p1


def final_state(cluster, addrs):
    """The fixed-step evidence a gate needs: balances, genesis hash, chain
    length, restart counters and a same-chain check at the lowest common round."""
    params = cluster.api("relay", "/v2/transactions/params")
    balances = {a: cluster.api("relay", f"/v2/accounts/{a}")["amount"] for a in addrs}
    rounds = [cluster.round_of(s) for s in ll.SERVICES]
    common = min(r for r in rounds if r is not None) if all(r is not None for r in rounds) \
        else None
    hashes = {}
    if common is not None:
        for s in ll.SERVICES:
            try:
                hashes[s] = cluster.api(s, f"/v2/blocks/{common}/hash")["blockHash"]
            except (urllib.error.URLError, OSError, KeyError):
                pass
    return {"genesis_hash": params["genesis-hash"],
            "balances_sha256": ll.balances_digest(balances),
            "consistency": {"round": common, "hashes": hashes}}


def run_cluster(impl, cfg, work, shared, genesis_id, partkeys, addrs, raw_dir, run_no):
    """One impl's whole run: start, fixed step, ladder, max step, teardown.
    Returns {"fixed": gate-input, "steps": {step: metrics}}."""
    cl = Cluster(impl, cfg, work, shared, genesis_id, partkeys)
    failed = True
    try:
        cl.up()
        steps = {}
        fixed_secs = cfg["fixed_count"] / cfg["fixed_tps"]
        rep, window, res, p0, p1 = cl.step(
            work, "fixed",
            ["--fixed-count", str(cfg["fixed_count"]), "--group-size", str(FIXED_GROUP_SIZE),
             "--target-tps", str(cfg["fixed_tps"]),
             "--duration-secs", str(int(fixed_secs * 3 + 120)), "--confirm-sample", "20",
             "--first-valid", "1", "--settle-secs", "180",
             "--concurrency", "8", "--txids-out", "/out/fixed-txids.txt"],
            timeout=int(fixed_secs * 3 + 600))
        last = rep["fixed"].get("last_confirmed_round")
        p_last = cl.point(last) if last is not None else p1
        steps["fixed"] = ll.fixed_metrics(rep, window, res, ll.commit_span(p0, p_last))
        fixed_window, fixed_res = window, res
        side = final_state(cl, addrs)
        # Transactions the chain committed since before the first submission:
        # nothing else ran, so it must be exactly the fixed set.
        side["final_tc"] = window["txns"]
        side["fixed"] = rep["fixed"]
        side["failed_groups"] = rep["submission"]["failed_groups"]
        shutil.copy(os.path.join(work, "loadgen", "fixed-txids.txt"),
                    os.path.join(raw_dir, f"{impl}-run{run_no}-fixed-txids.txt"))
        log(f"{impl}: fixed step: {rep['fixed']['confirmed_txns']}/"
            f"{rep['fixed']['submitted_txns']} txns confirmed, "
            f"{(steps['fixed'].get('confirmed_tps') or (0,0,0))[2]:.0f} txn/s")
        plan = [(f"ladder-{tps}", tps, 8) for tps in cfg["ladder"]]
        if cfg["max_step"]:
            plan.append(("max", 1_000_000, 32))
        for name, tps, conc in plan:
            time.sleep(5)
            rep2, window, res, _, _ = cl.step(
                work, name,
                ["--target-tps", str(tps), "--duration-secs", str(cfg["step_secs"]),
                 "--ramp-secs", "0", "--group-size", "1", "--concurrency", str(conc),
                 "--fee-multiplier", "4", "--confirm-sample", "50"],
                timeout=cfg["step_secs"] + 300)
            m = ll.step_metrics(rep2, window, res)
            if name == "max":
                m.pop("rejected_groups", None)  # an unbounded offer rejects by design
            steps[name] = m
            with open(os.path.join(raw_dir, f"{impl}-run{run_no}-{name}.json"), "w",
                      encoding="utf-8", newline="\n") as f:
                json.dump({"loadgen": rep2, "window": window, "resources": res}, f, indent=1)
            log(f"{impl}: {name}: "
                f"{(m.get('confirmed_tps') or (0,0,0))[2]:.0f} txn/s confirmed")
        side["restarts"] = cl.restarts()
        cl.stop_sampler()
        with open(os.path.join(raw_dir, f"{impl}-run{run_no}-samples.jsonl"), "w",
                  encoding="utf-8", newline="\n") as f:
            for s in cl.samples:
                f.write(json.dumps(s) + "\n")
        with open(os.path.join(raw_dir, f"{impl}-run{run_no}-fixed.json"), "w",
                  encoding="utf-8", newline="\n") as f:
            json.dump({"loadgen": rep, "window": fixed_window, "resources": fixed_res}, f,
                      indent=1)
        failed = False
        return {"side": side, "steps": steps, "loadgen_cmd": rep["_cmd"]}
    finally:
        if failed:
            cl.save_logs(raw_dir)
        cl.down()
        purge(cl.dir, cfg["go_image"])


# ---- report gate -------------------------------------------------------------

def check_report(path, required=("fixed/confirmed_tps",)):
    with open(path, encoding="utf-8") as f:
        rep = json.load(f)
    if not rep.get("ok"):
        return [f"report not ok: {rep.get('errors')}"]
    rows = {r["name"]: r for r in rep.get("rows", []) if r.get("tier") == TIER}
    errs = [f"{n}: no Rust/Go ratio" for n in required
            if n not in rows or rows[n].get("ratio") is None]
    return errs


# ---- main --------------------------------------------------------------------

def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--check-report":
        errs = check_report(sys.argv[2])
        for e in errs:
            print(f"localnet: {e}", file=sys.stderr)
        return 1 if errs else 0
    runs = int(os.environ.get("BENCH_RUNS", "5"))
    out_dir = os.environ.get("BENCH_OUT") or os.getcwd()
    run_dir = os.environ.get("BENCH_RUN_DIR") or out_dir
    if runs < 1:
        print("localnet: BENCH_RUNS must be >= 1", file=sys.stderr)
        return 2
    os.makedirs(out_dir, exist_ok=True)
    raw_dir = os.path.join(run_dir, "logs", "localnet")
    os.makedirs(raw_dir, exist_ok=True)
    try:
        cfg = settings()
        if not shutil.which("docker"):
            raise TierError("docker not found: the localnet tier runs both clusters in Docker")
        ensure_images(cfg)
        measured = []
        meta_extra = {}
        for i in range(runs):
            work = tempfile.mkdtemp(prefix="bench-localnet-")
            try:
                shared, genesis_id, partkeys, addrs = make_network(cfg, work)
                order = ("go", "rust") if i % 2 == 0 else ("rust", "go")
                got = {}
                errors = []
                for impl in order:
                    log(f"run {i + 1}/{runs}: {impl} cluster")
                    got[impl] = run_cluster(impl, cfg, work, shared, genesis_id, partkeys,
                                            addrs, raw_dir, i + 1)
                errors = ll.gate(got["go"]["side"], got["rust"]["side"],
                                   ll.expected_txns(cfg["fixed_count"], FIXED_GROUP_SIZE))
                if errors:
                    raise TierError("txid-set / state gate FAILED:\n  " + "\n  ".join(errors))
                fx = got["go"]["side"]["fixed"]
                meta_extra = {
                    "genesis_hash": got["go"]["side"]["genesis_hash"],
                    "fixed_txid_set_sha256": fx["confirmed_txid_set_sha256"],
                    "loadgen_command_go": got["go"]["loadgen_cmd"],
                    "loadgen_command_rust": got["rust"]["loadgen_cmd"],
                }
                log(f"run {i + 1}/{runs}: gate passed ({fx['confirmed_txns']} txns, "
                    f"txid set {fx['confirmed_txid_set_sha256'][:16]} on both clusters)")
                measured.append({"go": got["go"]["steps"], "rust": got["rust"]["steps"]})
            finally:
                purge(work, cfg["go_image"])
        meta = {
            "profile": cfg["profile"], "topology": "1 relay + 4 participation nodes, 25% stake each",
            "cpus_per_container": cfg["cpus"], "mem_per_container": cfg["mem"],
            "go_image": cfg["go_image"], "go_image_id": cfg["go_image_id"],
            "rust_image": cfg["rust_image"], "rust_image_id": cfg["rust_image_id"],
            "ladder": cfg["ladder"], "step_secs": cfg["step_secs"],
            "fixed_count": cfg["fixed_count"], "fixed_tps": cfg["fixed_tps"],
            "max_step": cfg["max_step"], "load_accounts": cfg["accounts"],
            **meta_extra,
        }
        with open(os.path.join(out_dir, "localnet.json"), "w", encoding="utf-8",
                  newline="\n") as f:
            json.dump(ll.result_rows(measured, TIER, meta), f, indent=1)
        log(f"gate passed on {len(measured)} run(s); both clusters committed the same txid set")
    except TierError as e:
        print(f"localnet: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - report, never traceback into the runner
        print(f"localnet: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
