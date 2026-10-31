# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Pure logic of the bench-compare `localnet` tier (issue #2106, epic #2101).

Everything here is deterministic and free of Docker, network and clock so it
runs in the default unit tests (test_localnet.py); the tier script
(tiers/localnet.py) does the I/O and calls into this module:

  * topology: the Docker Compose project of one homogeneous cluster. The Go
    and the Rust variant have the same shape (services, ports, per-container
    CPU/memory limits, network), so the only difference is the implementation;
  * genesis_with_alloc: the shared genesis, with the deterministic load
    accounts funded in it, so both clusters start from byte-identical state;
  * docker-stats parsing and per-step aggregation (CPU, RSS, block I/O);
  * window_stats: confirmed TPS and round time from two block headers;
  * the gates (same txid set, same balances, same chain, no restart);
  * the result rows (schema bench-result/v1).
"""
import hashlib
import json
import re
import socket
import time
import urllib.error

MIB = 1024 * 1024
TOKEN = "a" * 64
NETWORK_NAME = "benchnet"

# Service name -> directory `goal network create` makes for it (see
# TEMPLATE below). One relay and four participation nodes, 25% stake each.
NODE_DIRS = {"relay": "Relay", "part1": "Part1", "part2": "Part2", "part3": "Part3",
             "part4": "Part4"}
SERVICES = tuple(NODE_DIRS)
PARTICIPATION = tuple(s for s in SERVICES if s != "relay")
GOSSIP_PORT = 4161
REST_PORT = 8080

# The same node-local tuning docker/scripts/stress-bootstrap.sh applies
# (issue #100): bigger pool and queues, a 500 ms proposal assembly window.
# It is written into every node's config.json for BOTH implementations; the
# Rust nodes read the subset algod-rust supports (docs/BENCHMARK_COMPARISON.md).
CONFIG_OVERLAY = {
    "EndpointAddress": "0.0.0.0:8080",
    "DNSBootstrapID": "",
    "ProposalAssemblyTime": 500000000,
    "TxPoolSize": 150000,
    "TxBacklogSize": 52000,
    "AgreementIncomingVotesQueueLength": 40000,
    "AgreementIncomingProposalsQueueLength": 100,
    "EnableDeveloperAPI": True,
}


def template(num_rounds):
    """The `goal network create` template: 1 relay + 4 participation nodes,
    4 online wallets with 25% of the stake each, consensus `future` (as the
    stress topology, so blocks can fill under load)."""
    wallets = [f"Wallet{i}" for i in range(1, 5)]
    return {
        "Genesis": {
            "NetworkName": NETWORK_NAME,
            "FirstPartKeyRound": 0,
            "LastPartKeyRound": num_rounds,
            "ConsensusProtocol": "future",
            "Wallets": [{"Name": w, "Stake": 25, "Online": True} for w in wallets],
        },
        "Nodes": [{"Name": "Relay", "IsRelay": True, "Wallets": []}] + [
            {"Name": f"Part{i}",
             "Wallets": [{"Name": f"Wallet{i}", "ParticipationOnly": False}]}
            for i in range(1, 5)],
    }


# ---- genesis -----------------------------------------------------------------

def genesis_with_alloc(genesis_text, addresses, microalgos):
    """genesis.json text with `addresses` added to `alloc` as NotParticipating
    accounts holding `microalgos` each. NotParticipating accounts never accrue
    rewards, so a balance depends only on the transactions applied, not on how
    many rounds a cluster happened to run. Refuses an address already present
    (a re-patched genesis would silently change nothing)."""
    g = json.loads(genesis_text)
    have = {a["addr"] for a in g.get("alloc", [])}
    dup = sorted(set(addresses) & have)
    if dup:
        raise ValueError(f"genesis already allocates {dup[0]}")
    for i, addr in enumerate(addresses):
        g.setdefault("alloc", []).append({
            "addr": addr, "comment": f"bench-load-{i}",
            "state": {"algo": microalgos, "onl": 2}})
    return json.dumps(g, indent=2) + "\n"


def genesis_id_of(genesis_text):
    """`<network>-<id>` as algod-rust's --genesis-id wants it."""
    g = json.loads(genesis_text)
    return f"{g.get('network', NETWORK_NAME)}-{g.get('id', 'v1')}"


def node_config(config_text):
    """config.json text with CONFIG_OVERLAY applied (other keys kept)."""
    cfg = json.loads(config_text) if config_text.strip() else {}
    cfg.update(CONFIG_OVERLAY)
    return json.dumps(cfg, indent=2) + "\n"


# ---- topology ----------------------------------------------------------------

def container_name(project, service):
    return f"{project}-{service}"


def network_name(project):
    return f"{project}-net"


def host_port(port_base, service):
    return port_base + SERVICES.index(service)


def topology(impl, *, project, go_image, rust_image, cpus, mem, port_base, netroot,
             genesis_id, partkeys):
    """The Compose project (a dict; JSON is valid YAML) of one homogeneous
    cluster. `partkeys` maps a participation service to its .partkey path
    relative to `netroot` (the Rust nodes import it). `netroot` is the
    cluster's private copy of the shared network tree."""
    if impl not in ("go", "rust"):
        raise ValueError(f"impl must be go or rust, not {impl!r}")
    services = {}
    for svc in SERVICES:
        relay = svc == "relay"
        s = {
            "container_name": container_name(project, svc),
            "cpus": cpus,
            "mem_limit": mem,
            "restart": "no",
            "ports": [f"127.0.0.1:{host_port(port_base, svc)}:{REST_PORT}"],
            "networks": [NETWORK_NAME],
        }
        if impl == "go":
            env = {"ALGORAND_DATA": "/algod/data", "ALGOD_PORT": str(REST_PORT),
                   "TOKEN": TOKEN, "ADMIN_TOKEN": TOKEN}
            if relay:
                env["GOSSIP_PORT"] = str(GOSSIP_PORT)
            else:
                env["PEER_ADDRESS"] = f"relay:{GOSSIP_PORT}"
            s["image"] = go_image
            s["environment"] = env
            s["volumes"] = [{"type": "bind", "source": f"{netroot}/{NODE_DIRS[svc]}",
                             "target": "/algod/data"}]
        else:
            cmd = ["algod-rust", "participate",
                   "--ledger-path=/app/ledger",
                   "--partkey-path=/app/partkeys.sqlite"]
            if not relay:
                cmd.append(f"--import-partkey=/netroot/{partkeys[svc]}")
            cmd += ["--genesis-json=/netroot/genesis.json",
                    "--genesis-path=/netroot/genesis.json",
                    f"--genesis-id={genesis_id}",
                    f"--network={NETWORK_NAME}"]
            if relay:
                cmd += [f"--listen-address=0.0.0.0:{GOSSIP_PORT}", "--relay-messages"]
            else:
                cmd.append(f"--peers=relay:{GOSSIP_PORT}")
            cmd += [f"--rest-listen=0.0.0.0:{REST_PORT}", "--data-dir=/data"]
            s["image"] = rust_image
            s["entrypoint"] = cmd
            s["environment"] = {"RUST_LOG": "info,algod_rust=info,algo_network=info,"
                                            "algo_agreement=info"}
            s["volumes"] = [
                {"type": "volume", "target": "/app"},
                {"type": "bind", "source": netroot, "target": "/netroot",
                 "read_only": True},
                {"type": "bind", "source": f"{netroot}/{svc}-data", "target": "/data"},
            ]
        if not relay:
            s["depends_on"] = ["relay"]
        services[svc] = s
    return {"name": project, "services": services,
            "networks": {NETWORK_NAME: {"name": network_name(project)}}}


def render_compose(top):
    return json.dumps(top, indent=2) + "\n"


def shape(top):
    """What two clusters must have in common to be comparable: service names,
    published ports, resource limits, network and dependency graph."""
    return {
        "services": {n: {k: s.get(k) for k in ("cpus", "mem_limit", "restart", "ports",
                                              "networks", "depends_on")}
                     for n, s in sorted(top["services"].items())},
        "networks": sorted(top["networks"]),
    }


# ---- docker stats ------------------------------------------------------------

_UNITS = {"b": 1, "kb": 1000, "kib": 1024, "mb": 1000 ** 2, "mib": MIB, "gb": 1000 ** 3,
          "gib": 1024 ** 3, "tb": 1000 ** 4, "tib": 1024 ** 4}


def parse_size(text):
    """`12.5MiB` -> bytes. ValueError when it is not a size."""
    m = re.fullmatch(r"\s*([0-9]*\.?[0-9]+)\s*([A-Za-z]*)\s*", text or "")
    if not m or (m.group(2).lower() or "b") not in _UNITS:
        raise ValueError(f"not a docker size: {text!r}")
    return int(float(m.group(1)) * _UNITS[m.group(2).lower() or "b"])


def parse_stats_line(line):
    """One `docker stats --no-stream --format '{{json .}}'` line ->
    {name, cpu_pct, mem_bytes, blk_read, blk_write}."""
    d = json.loads(line)
    cpu = d["CPUPerc"].strip().rstrip("%")
    mem = d["MemUsage"].split("/")[0]
    rd, wr = d["BlockIO"].split("/")
    return {"name": d["Name"], "cpu_pct": float(cpu), "mem_bytes": parse_size(mem),
            "blk_read": parse_size(rd), "blk_write": parse_size(wr)}


def resource_summary(samples, t0, t1):
    """Cluster totals over [t0, t1] from samples {t, node, cpu_pct, mem_bytes,
    blk_write}: the CPU cores used (sum over nodes of the mean CPU%/100), the
    sum of every node's peak RSS and the block-device bytes written. Returns
    {} when no node was sampled in the window."""
    nodes = {}
    for s in samples:
        if t0 <= s["t"] <= t1:
            nodes.setdefault(s["node"], []).append(s)
    if not nodes:
        return {}
    cpu = rss = wr = 0.0
    for rows in nodes.values():
        rows.sort(key=lambda r: r["t"])
        cpu += sum(r["cpu_pct"] for r in rows) / len(rows) / 100.0
        rss += max(r["mem_bytes"] for r in rows)
        wr += max(0, rows[-1]["blk_write"] - rows[0]["blk_write"])
    return {"cpu_cores": cpu, "rss_mb_peak": rss / MIB, "blockio_write_mb": wr / MIB,
            "nodes_sampled": len(nodes)}


# ---- chain window ------------------------------------------------------------

def block_point(block_json):
    """(round, ts, tc) of a `GET /v2/blocks/{round}` JSON document."""
    b = block_json["block"]
    return {"round": int(b.get("rnd", 0)), "ts": int(b.get("ts", 0)),
            "tc": int(b.get("tc", 0))}


def window_stats(p0, p1):
    """Throughput between two block headers: txns committed, chain seconds,
    rounds, confirmed TPS and mean round time (None when the headers carry no
    time between them)."""
    txns = p1["tc"] - p0["tc"]
    secs = p1["ts"] - p0["ts"]
    rounds = p1["round"] - p0["round"]
    return {
        "txns": txns, "secs": secs, "rounds": rounds,
        "confirmed_tps": txns / secs if secs > 0 and txns >= 0 else None,
        "round_time_s": secs / rounds if secs > 0 and rounds > 0 else None,
    }


# ---- steps -> metrics --------------------------------------------------------

def step_metrics(loadgen, window, resources):
    """{metric: (unit, better, value)} of one load step. Metrics with no value
    (no latency samples, no chain time) are left out."""
    sub = loadgen["submission"]
    conf = loadgen["confirmation"]
    m = {}

    def put(name, unit, better, value):
        if value is not None:
            m[name] = (unit, better, float(value))

    put("confirmed_tps", "txn/s", "higher", window.get("confirmed_tps"))
    put("submit_tps", "txn/s", "higher", sub.get("achieved_submit_tps"))
    put("round_time_s", "s", "lower", window.get("round_time_s"))
    put("rejected_groups", "groups", "lower",
        sub.get("failed_groups", 0) + sub.get("backpressure_drops_groups", 0))
    if conf.get("samples"):
        for k in ("p50", "p95", "p99"):
            put(f"latency_{k}_ms", "ms", "lower", conf.get(f"{k}_ms"))
    for k, unit in (("cpu_cores", "cores"), ("rss_mb_peak", "MB"),
                    ("blockio_write_mb", "MB")):
        put(k, unit, "lower", resources.get(k))
    return m


def commit_span(p0, p_last):
    """Chain time and rounds from the block before the first submission (`p0`)
    to the block holding the last transaction of the set (`p_last`), both
    block_point()s. This is commit speed measured on the chain, not by polling."""
    return {"secs": p_last["ts"] - p0["ts"], "rounds": p_last["round"] - p0["round"]}


def fixed_metrics(loadgen, window, resources, span):
    """step_metrics of the fixed-count step plus how fast the whole set was
    committed: `commit_rounds`, `commit_time_s` (block-header seconds) and the
    `set_tps` they imply. Block timestamps have one-second resolution."""
    m = step_metrics(loadgen, window, resources)
    if span["rounds"] > 0:
        m["commit_rounds"] = ("rounds", "lower", float(span["rounds"]))
    if span["secs"] > 0:
        m["commit_time_s"] = ("s", "lower", float(span["secs"]))
        m["set_tps"] = ("txn/s", "higher",
                        loadgen["fixed"]["confirmed_txns"] / span["secs"])
    return m


class RoundWaitError(Exception):
    pass


def require_round(value, what):
    """`value` (a node's last round) or RoundWaitError when the node gave none."""
    if value is None:
        raise RoundWaitError(f"{what} gave no round (is it down?)")
    return value


def wait_for_round(get_round, target, timeout, sleep=time.sleep, now=time.monotonic):
    """Poll get_round() until it returns a round >= target (None target: return
    the current round at once). RoundWaitError after `timeout` seconds, saying
    what was last seen."""
    if target is None:
        return require_round(get_round(), "the node")
    end = now() + timeout
    seen = None
    while True:
        r = get_round()
        if r is not None:
            seen = r
            if r >= target:
                return r
        if now() >= end:
            break
        sleep(1)
    got = f"last saw {seen}" if seen is not None else "no answer"
    raise RoundWaitError(f"the node did not reach round {target} within {timeout}s ({got})")


def is_transient(exc):
    """Whether a REST failure is worth retrying: the node being briefly
    unreachable (connection errors, timeouts, 5xx) as opposed to a real answer
    such as a 4xx."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500
    return isinstance(exc, (urllib.error.URLError, socket.timeout, TimeoutError,
                            ConnectionError, OSError))


def with_retry(call, attempts=4, delay=1.0, sleep=time.sleep):
    """call() with a bounded retry (exponential backoff: delay, 2*delay, ...) on
    transient failures only; the last error is raised once the attempts are used
    and a non-transient error is raised at once."""
    for i in range(attempts):
        try:
            return call()
        except Exception as e:  # noqa: BLE001 - classified below
            if not is_transient(e) or i == attempts - 1:
                raise
            sleep(delay * (2 ** i))


def wait_drained(get_pending, timeout, sleep=time.sleep, now=time.monotonic):
    """Poll get_pending() (txns in the pool, None when unknown) until it is 0 or
    `timeout` passes. Returns the pool size last seen: 0 when drained, the
    leftover backlog otherwise, None if it was never readable."""
    end = now() + timeout
    seen = None
    while True:
        n = get_pending()
        if n is not None:
            seen = n
            if n == 0:
                return 0
        if now() >= end:
            return seen
        sleep(2)


def backlog_metrics(pending):
    """The `start_backlog_txns` row of a step: transactions still pooled when it
    started (0 on a clean start). A step that starts dirty is visible in the
    report instead of silently measuring the previous step's tail."""
    if pending is None:
        return {}
    return {"start_backlog_txns": ("txns", "lower", float(pending))}


def submit_window(rep):
    """The interval a load step actually offered transactions, from the
    generator's report: the rounds around it and its wall-clock instants in
    seconds (None where the generator did not report them)."""
    sub = rep.get("submission", {})
    t0, t1 = sub.get("first_submit_unix_ms"), sub.get("last_submit_unix_ms")
    return {"start_round": sub.get("start_round"), "end_round": sub.get("end_round"),
            "t0": t0 / 1000.0 if t0 else None, "t1": t1 / 1000.0 if t1 else None}


def expected_txns(fixed_count, group_size):
    """Transactions a fixed-count run must submit."""
    if fixed_count < 1 or group_size < 1:
        raise ValueError("fixed count and group size must be >= 1")
    return fixed_count * group_size


# ---- gates -------------------------------------------------------------------

def balances_digest(balances):
    """sha256 of `addr:amount` lines sorted by address."""
    h = hashlib.sha256()
    for addr in sorted(balances):
        h.update(f"{addr}:{balances[addr]}\n".encode())
    return h.hexdigest()


def side_errors(side, r, expected_txns):
    """Gate errors of one cluster's fixed-count step result `r`."""
    errs = []
    fx = r["fixed"]
    if fx.get("expected_txns") != expected_txns:
        errs.append(f"{side}: the generator was asked for {fx.get('expected_txns')} txns, "
                    f"the tier expects {expected_txns}")
    if fx["submitted_txns"] != expected_txns:
        errs.append(f"{side}: submitted {fx['submitted_txns']} txns, expected {expected_txns}")
    if fx["confirmed_txns"] != fx["submitted_txns"]:
        errs.append(f"{side}: {fx['unconfirmed_txns']} of {fx['submitted_txns']} submitted "
                    "txns were never confirmed")
    if fx["submitted_txid_set_sha256"] != fx["confirmed_txid_set_sha256"]:
        errs.append(f"{side}: the confirmed txid set differs from the submitted one")
    if r.get("failed_groups"):
        errs.append(f"{side}: {r['failed_groups']} groups were never accepted by a node")
    if r["final_tc"] != expected_txns:
        errs.append(f"{side}: the chain committed {r['final_tc']} txns during the fixed "
                    f"step, expected exactly {expected_txns}")
    for node, st in sorted(r.get("restarts", {}).items()):
        if st.get("restart_count") or st.get("oom"):
            errs.append(f"{side}: node {node} restarted {st.get('restart_count')} time(s)"
                        f"{' (OOM killed)' if st.get('oom') else ''}")
    cons = r.get("consistency") or {}
    if len(set(cons.get("hashes", {}).values())) > 1:
        errs.append(f"{side}: the nodes disagree on block {cons.get('round')}: "
                    f"{cons['hashes']}")
    if not cons.get("hashes") or len(cons["hashes"]) != len(SERVICES):
        errs.append(f"{side}: not every node reported a block hash for the consistency check")
    return errs


def gate(go, rust, expected_txns):
    """All gate errors of one run (empty list: pass). `go` and `rust` are the
    fixed-count results of the two clusters."""
    errs = side_errors("go", go, expected_txns) + side_errors("rust", rust, expected_txns)
    a, b = go["fixed"], rust["fixed"]
    if a["submitted_txid_set_sha256"] != b["submitted_txid_set_sha256"]:
        errs.append("go and rust were fed different transaction sets "
                    f"({a['submitted_txid_set_sha256'][:16]} != "
                    f"{b['submitted_txid_set_sha256'][:16]})")
    if a["confirmed_txid_set_sha256"] != b["confirmed_txid_set_sha256"]:
        errs.append("go and rust committed different txid sets "
                    f"({a['confirmed_txid_set_sha256'][:16]} != "
                    f"{b['confirmed_txid_set_sha256'][:16]})")
    if go["balances_sha256"] != rust["balances_sha256"]:
        errs.append("go and rust ended with different load-account balances "
                    f"({go['balances_sha256'][:16]} != {rust['balances_sha256'][:16]})")
    if go["genesis_hash"] != rust["genesis_hash"]:
        errs.append(f"go and rust started from different genesis hashes "
                    f"({go['genesis_hash']} != {rust['genesis_hash']})")
    return errs


# ---- results -----------------------------------------------------------------

def result_rows(runs, tier, meta):
    """bench-result/v1 rows. `runs` is a list (one per measured run) of
    {"go": {step: {metric: (unit, better, value)}}, "rust": ...}; the rows are
    named `<step>/<metric>`, one sample per run."""
    rows = []
    for impl in ("go", "rust"):
        per = {}
        for r in runs:
            for step, metrics in r[impl].items():
                for k, (unit, better, v) in metrics.items():
                    per.setdefault(f"{step}/{k}", (unit, better, []))[2].append(round(v, 6))
        for name, (unit, better, vals) in sorted(per.items()):
            rows.append({"schema": "bench-result/v1", "tier": tier, "name": name,
                         "impl": impl, "unit": unit, "better": better, "samples": vals,
                         "metadata": dict(meta)})
    return rows


def parse_ladder(text):
    """`100,500,1000` -> [100, 500, 1000]; ValueError on junk or non-positive."""
    out = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit() or int(part) <= 0:
            raise ValueError(f"ladder step {part!r} is not a positive integer")
        out.append(int(part))
    return out


PROFILES = {
    # CI smoke: one tiny ladder step, ~2-3 minutes with warm images.
    "smoke": {"fixed_count": 200, "fixed_tps": 100, "ladder": [50], "step_secs": 10,
              "max_step": False},
    # The published numbers (issue #2106): the offered-TPS ladder plus an
    # unbounded "max sustained" step.
    "full": {"fixed_count": 5000, "fixed_tps": 500, "ladder": [100, 500, 1000, 2000],
             "step_secs": 60, "max_step": True},
}
