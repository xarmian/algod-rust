# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Pure logic of the bench-compare `catchup` tier (issue #2108, epic #2101):
configuration, catchpoint-label handling, catchup stage detection and phase
durations, follow statistics, the block-hash equality gate, the
external-network vs node failure classification, the container resource
summary and the schema-v1 result rows. No Docker and no network: everything
here is unit-tested by test_catchup.py; the tier script
(scripts/bench/tiers/catchup.py) is the I/O around it.

A catchup against a public network is NON-DETERMINISTIC (relay speed, peer
choice, the network's own load), so every row carries
`metadata.nondeterministic = true`, which report.py turns into an explicit
label next to the numbers.
"""
import re

TIER = "catchup"
EXTERNAL = "external network"
NODE = "node"


class CatchupError(Exception):
    pass


# ---- networks and catchpoint labels ------------------------------------------

# Go-compatible public networks only. voimain / aramidmain run custom
# consensus parameters that go-algorand v5.0.4 does not know, so there is no
# Go side to compare against (docs/BENCHMARK_COMPARISON.md, "The catchup tier").
# `genesis_rel` is the repo's vendored copy of go-algorand's
# installer/genesis/<network>/genesis.json, so both sides get the same bytes.
NETWORKS = {
    name: {
        "genesis_rel": f"docker/algod/genesis/{name}/genesis.json",
        # the index go's own `goal node catchup` reads for the latest label
        "index_url": f"https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/{name}/latest.catchpoint",
    }
    for name in ("testnet", "mainnet", "betanet")
}

_LABEL = re.compile(r"([1-9][0-9]*)#([A-Z2-7]{52})")


def parse_label(label):
    """(round, hash) of a catchpoint label `<round>#<base32 hash>`; ValueError
    when it is not one."""
    m = _LABEL.fullmatch(label or "")
    if not m:
        raise ValueError(f"not a catchpoint label (want <round>#<52 base32 chars>): {label!r}")
    return int(m.group(1)), m.group(2)


def parse_index_text(text):
    """The label in the body of a `latest.catchpoint` index (an error page
    from the bucket is rejected, never used as a label)."""
    label = (text or "").strip()
    parse_label(label)
    return label


# ---- configuration -------------------------------------------------------------

PROFILES = {
    "full": {"follow_secs": 600.0},
    "smoke": {"follow_secs": 10.0},
}
MODES = ("live", "mock")
MOCK_FAULTS = ("none", "diverge", "stall")


def parse_settings(env):
    """The tier's settings from an environment mapping. CatchupError names the
    offending variable."""
    def num(name, default, cast=float):
        v = env.get(name)
        if v in (None, ""):
            return default
        try:
            return cast(v)
        except ValueError:
            raise CatchupError(f"{name}={v!r} is not a number") from None

    profile = env.get("BENCH_CATCHUP_PROFILE") or "full"
    if profile not in PROFILES:
        raise CatchupError(f"BENCH_CATCHUP_PROFILE={profile!r}: want {', '.join(PROFILES)}")
    mode = env.get("BENCH_CATCHUP_MODE") or "live"
    if mode not in MODES:
        raise CatchupError(f"BENCH_CATCHUP_MODE={mode!r}: want {', '.join(MODES)}")
    network = env.get("BENCH_CATCHUP_NETWORK") or "testnet"
    if network not in NETWORKS:
        raise CatchupError(
            f"BENCH_CATCHUP_NETWORK={network!r}: want {', '.join(NETWORKS)} (voimain and "
            "aramidmain use custom consensus parameters go-algorand does not run, so there is "
            "no Go side to compare against)")
    label = env.get("BENCH_CATCHUP_LABEL") or ""
    if label:
        try:
            parse_label(label)
        except ValueError as e:
            raise CatchupError(f"BENCH_CATCHUP_LABEL: {e}") from None
    fault = env.get("BENCH_CATCHUP_MOCK_FAULT") or "none"
    if fault != "none" and mode != "mock":
        raise CatchupError("BENCH_CATCHUP_MOCK_FAULT is only valid with BENCH_CATCHUP_MODE=mock")
    if fault not in MOCK_FAULTS:
        raise CatchupError(f"BENCH_CATCHUP_MOCK_FAULT={fault!r}: want {', '.join(MOCK_FAULTS)}")
    s = {
        "profile": profile, "mode": mode, "network": network, "label": label,
        "label_url": env.get("BENCH_CATCHUP_LABEL_URL") or NETWORKS[network]["index_url"],
        "mock_fault": fault,
        "follow_secs": num("BENCH_CATCHUP_FOLLOW_SECS", PROFILES[profile]["follow_secs"]),
        "stage_timeout_s": num("BENCH_CATCHUP_STAGE_TIMEOUT", 7200.0),
        "poll_s": num("BENCH_CATCHUP_POLL_S", 1.0),
        "head_slack_s": num("BENCH_CATCHUP_HEAD_SLACK_S", 30.0),
        "hash_cap": num("BENCH_CATCHUP_HASH_CAP", 20000, int),
        "min_gate_rounds": num("BENCH_CATCHUP_MIN_GATE_ROUNDS", 100, int),
        "cpus": num("BENCH_CATCHUP_CPUS", 2.0),
        "mem": env.get("BENCH_CATCHUP_MEM") or "3g",
        "port_base": num("BENCH_CATCHUP_PORT_BASE", 4500, int),
        "go_image": env.get("BENCH_CATCHUP_GO_IMAGE") or "",
        "rust_image": env.get("BENCH_CATCHUP_RUST_IMAGE") or "",
    }
    for name, key, low in (("BENCH_CATCHUP_FOLLOW_SECS", "follow_secs", 0),
                           ("BENCH_CATCHUP_STAGE_TIMEOUT", "stage_timeout_s", 0),
                           ("BENCH_CATCHUP_POLL_S", "poll_s", 0),
                           ("BENCH_CATCHUP_HEAD_SLACK_S", "head_slack_s", 0),
                           ("BENCH_CATCHUP_CPUS", "cpus", 0)):
        if not s[key] > low:
            raise CatchupError(f"{name} must be > {low}, got {s[key]}")
    if s["hash_cap"] < 1:
        raise CatchupError(f"BENCH_CATCHUP_HASH_CAP must be >= 1, got {s['hash_cap']}")
    if s["min_gate_rounds"] < 1:
        raise CatchupError(f"BENCH_CATCHUP_MIN_GATE_ROUNDS must be >= 1, got {s['min_gate_rounds']}")
    ok_port = (1024 <= s["port_base"] <= 65530) or (mode == "mock" and s["port_base"] == 0)
    if not ok_port:
        raise CatchupError(f"BENCH_CATCHUP_PORT_BASE must be 1024..65530, got {s['port_base']}")
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)?[bkmgBKMG]?", s["mem"]):
        raise CatchupError(f"BENCH_CATCHUP_MEM={s['mem']!r}: want a Docker size like 3g or 512m")
    return s


# ---- catchup stages and phase durations ----------------------------------------

def _int(status, key):
    try:
        return int(status.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def stage_of(status):
    """The catchup stage a `/v2/status` document reports, from the same
    counters `goal node status` prints (go-algorand and algod-rust fill the
    same fields):

      idle    no catchpoint in progress;
      ledger  catchpoint file download and account/KV import (the two are
              interleaved: both nodes import the file while streaming it, so
              no node-independent boundary between them exists);
      verify  verifying the imported accounts;
      blocks  downloading the lookback blocks and switching to the new ledger.
    """
    if not status.get("catchpoint"):
        return "idle"
    total = _int(status, "catchpoint-total-accounts") + _int(status, "catchpoint-total-kvs")
    processed = (_int(status, "catchpoint-processed-accounts")
                 + _int(status, "catchpoint-processed-kvs"))
    verified = (_int(status, "catchpoint-verified-accounts")
                + _int(status, "catchpoint-verified-kvs"))
    if total == 0 or processed < total:
        return "ledger"
    if verified < total:
        return "verify"
    return "blocks"


STAGES = ("ledger", "verify", "blocks", "done")


class PhaseTracker:
    """Feed it one `/v2/status` sample after another (`observe`); it records
    when each stage was first seen and when the node reached the head of the
    network.

    `t0` is the moment the catchup was requested. A stage's duration is the
    time from its first sighting to the next stage's (polling resolution; a
    stage never seen takes zero time, at the next stage's entry). `done` is
    the catchpoint clearing with a ledger in place; the node is `at head`
    when, after that, the block it last committed is no older than the head
    slack (`lag_s` of the sample: wall clock minus the block's timestamp).
    """

    def __init__(self, t0):
        self.t0 = t0
        self.enter = {}
        self.catchpoint_seen = None
        self.progressed = False
        self.t_done = self.round_done = None
        self.t_head = self.round_head = None
        self.head_slack_s = 30.0

    def observe(self, t, status, lag_s=None):
        stage = stage_of(status)
        rnd = _int(status, "last-round")
        if stage != "idle":
            if self.catchpoint_seen is None:
                self.catchpoint_seen = status["catchpoint"]
            self.enter.setdefault(stage, t)
            if stage != "ledger" or _int(status, "catchpoint-processed-accounts") > 0:
                self.progressed = True
        elif self.catchpoint_seen is not None and rnd > 0 and self.t_done is None:
            self.t_done, self.round_done = t, rnd
            self.enter.setdefault("done", t)
            self.progressed = True
        if (self.t_done is not None and self.t_head is None and lag_s is not None
                and lag_s <= self.head_slack_s):
            self.t_head, self.round_head = t, rnd

    def at_head(self):
        return self.t_head is not None

    def _effective_entries(self):
        eff, nxt = {}, None
        for st in reversed(STAGES):
            nxt = self.enter.get(st, nxt)
            eff[st] = nxt
        return eff

    def durations(self):
        eff = self._effective_entries()
        out = {}
        if eff["verify"] is not None:
            out["phase_ledger_s"] = eff["verify"] - self.t0
        if eff["blocks"] is not None:
            out["phase_verify_s"] = eff["blocks"] - eff["verify"]
        if eff["done"] is not None:
            out["phase_blocks_s"] = eff["done"] - eff["blocks"]
        if self.t_head is not None:
            out["phase_replay_s"] = self.t_head - self.t_done
            out["total_to_head_s"] = self.t_head - self.t0
        return {k: round(v, 3) for k, v in out.items()}

    def replay_blocks_per_s(self):
        """Blocks committed per second between the catchpoint switch and the
        head, None when the node was at the head at once (nothing to replay)."""
        if self.t_head is None or self.t_head <= self.t_done:
            return None
        return (self.round_head - self.round_done) / (self.t_head - self.t_done)


# ---- follow ----------------------------------------------------------------------

def follow_stats(samples):
    """Metrics of the follow window from [(t, round, lag_s)] of one node."""
    if len(samples) < 2:
        return {}
    out = {}
    dt = samples[-1][0] - samples[0][0]
    if dt > 0:
        out["follow_rounds_per_s"] = (samples[-1][1] - samples[0][1]) / dt
    lags = [s[2] for s in samples if s[2] is not None]
    if lags:
        out["follow_lag_s_mean"] = sum(lags) / len(lags)
        out["follow_lag_s_max"] = max(lags)
    return out


def rounds_behind_max(go, rust):
    """Largest number of rounds each node was behind the other, from
    [(t, round)] lists sampled in lockstep (paired by index)."""
    out = {"go": 0, "rust": 0}
    for (_, g), (_, r) in zip(go, rust):
        out["go"] = max(out["go"], r - g)
        out["rust"] = max(out["rust"], g - r)
    return out


# ---- gates -------------------------------------------------------------------------

def sample_rounds(lo, hi, cap):
    """The rounds whose block hash the gate compares: every round of
    [lo, hi] when there are at most `cap`, else `cap` evenly spaced rounds that
    include both ends."""
    if hi < lo:
        return []
    n = hi - lo + 1
    if n <= cap:
        return list(range(lo, hi + 1))
    if cap == 1:
        return [hi]
    step = (n - 1) / (cap - 1)
    return sorted({lo + round(i * step) for i in range(cap)})


def oldest_available(lo, hi, available):
    """The smallest round in [lo, hi] for which `available(round)` is true,
    assuming availability is a suffix (a non-archival node keeps only its
    newest blocks); None when even `hi` is unavailable. O(log n) probes."""
    if hi < lo or not available(hi):
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        if available(mid):
            hi = mid
        else:
            lo = mid + 1
    return lo


def hash_gate(go, rust, rounds):
    """(errors, rounds compared). `go` / `rust` map round -> block hash (a
    round the node could not answer is absent: that is an error, never a pass)."""
    errors = []
    mismatched, compared = [], 0
    for side, hashes in (("go", go), ("rust", rust)):
        missing = [r for r in rounds if hashes.get(r) is None]
        if missing:
            errors.append(f"{side} returned no block hash for {len(missing)} of {len(rounds)} "
                          f"sampled round(s) (first: round {missing[0]})")
    for r in rounds:
        g, u = go.get(r), rust.get(r)
        if g is None or u is None:
            continue
        compared += 1
        if g != u:
            mismatched.append(r)
    if mismatched:
        r = mismatched[0]
        errors.append(f"block hash mismatch at round {r}: go {go[r]} != rust {rust[r]} "
                      f"({len(mismatched)} of {compared} compared rounds differ)")
    if not rounds or compared == 0:
        errors.append("no round was compared: the followed range is empty or no hash was returned")
    return errors, compared


def label_gate(label, seen):
    """Errors for every node that did not report the catchpoint label it was
    told to catch up to (`seen`: {side: label the node reported or None})."""
    errors = []
    for side in sorted(seen):
        if seen[side] is None:
            errors.append(f"{side} never reported a catchpoint in /v2/status")
        elif seen[side] != label:
            errors.append(f"{side} caught up to {seen[side]!r}, not the agreed {label!r}")
    return errors


# ---- failure classification ------------------------------------------------------------
# Same idea and the same evidence rules as docker/scripts/network_image_smoke_lib.sh
# (issue #2121): a failure is blamed on the external network only on strong
# evidence (nobody made progress and a transport-level relay failure is in a
# log); anything ambiguous is a node failure.

SMOKE_TRANSPORT_ERROR_RE = (r"connection refused|connection reset|(operation|connection|request) "
                            r"timed out|dns error|failed to lookup address|tls handshake|ssl error|"
                            r"invalid peer certificate|i/o timeout|no such host")
SMOKE_SEND_ERROR_RE = r"error sending request.*(" + SMOKE_TRANSPORT_ERROR_RE + ")"
SMOKE_RELAY_5XX_RE = (r"(^relay [^ ]+: catchpoint file HTTP (000|5[0-9][0-9])$|"
                      r"(REST /v2/blocks failed|/v1 block-service|catchpoint (GET|connect))"
                      r".*(HTTP|status)[ :]+5[0-9][0-9])")
_TRANSPORT = re.compile(SMOKE_TRANSPORT_ERROR_RE + "|" + SMOKE_SEND_ERROR_RE, re.I)
_5XX = re.compile(SMOKE_RELAY_5XX_RE)
_PANIC = re.compile(r"it is being shutdown|thread 'main'.*panicked at|^panic: |"
                    r"goroutine [0-9]+ \[running\]", re.M)


def log_has_relay_error(text):
    for line in (text or "").splitlines():
        if "WS block fetch failed" in line:
            continue  # the routine warning healthy runs log
        if _TRANSPORT.search(line) or _5XX.search(line):
            return True
    return False


def log_has_fatal_panic(text):
    return bool(_PANIC.search(text or ""))


def classify_failure(sides, label_error=False, kind="other"):
    """(class, detail). `sides` maps go / rust to {progressed, panicked,
    exited, relay_error}; `kind` is `timeout` (a stage or the follow did not
    finish in time), `gate` (the nodes disagree) or `other`."""
    if label_error:
        return EXTERNAL, "the catchpoint label could not be fetched from the network's index"
    bad = [s for s in sorted(sides) if sides[s]["panicked"] or sides[s]["exited"]]
    if bad:
        what = ", ".join(f"{s} {'panicked' if sides[s]['panicked'] else 'exited'}" for s in bad)
        return NODE, what
    if kind == "gate":
        return NODE, "the two nodes disagree"
    relay = any(v["relay_error"] for v in sides.values())
    stuck = [s for s in sorted(sides) if not sides[s]["progressed"]]
    if stuck and len(stuck) < len(sides):
        return NODE, (f"{' and '.join(stuck)} made no progress while the other node did "
                      "(the same relays served both)")
    if stuck:
        if relay:
            return EXTERNAL, ("neither node made progress and a transport-level relay failure "
                              "is in the logs")
        return NODE, "neither node made progress and the logs show no relay failure"
    if kind == "timeout" and relay:
        return EXTERNAL, "both nodes progressed too slowly; relay failures are in the logs"
    return NODE, "both nodes progressed, but the run did not finish"


def format_failure(cls, detail):
    return f"FAILURE CLASS: {cls}: {detail}"


# ---- resources ----------------------------------------------------------------------------

MIB = 1024 * 1024


def resources_over(samples, t0, t1):
    """CPU cores (mean CPU% / 100), peak RSS and block-device bytes read /
    written of ONE container over [t0, t1], from `docker stats` samples
    {t, cpu_pct, mem_bytes, blk_read, blk_write}. {} when nothing was sampled."""
    rows = sorted((s for s in samples if t0 <= s["t"] <= t1), key=lambda s: s["t"])
    if not rows:
        return {}
    return {
        "cpu_cores": sum(r["cpu_pct"] for r in rows) / len(rows) / 100.0,
        "rss_mb_peak": max(r["mem_bytes"] for r in rows) / MIB,
        "blockio_read_mb": max(0, rows[-1]["blk_read"] - rows[0]["blk_read"]) / MIB,
        "blockio_write_mb": max(0, rows[-1]["blk_write"] - rows[0]["blk_write"]) / MIB,
    }


# ---- rows -----------------------------------------------------------------------------------

# metric -> (unit, better)
METRICS = {
    "phase_ledger_s": ("s", "lower"),
    "phase_verify_s": ("s", "lower"),
    "phase_blocks_s": ("s", "lower"),
    "phase_replay_s": ("s", "lower"),
    "total_to_head_s": ("s", "lower"),
    "replay_blocks_per_s": ("blocks/s", "higher"),
    "follow_rounds_per_s": ("blocks/s", "higher"),
    "follow_lag_s_mean": ("s", "lower"),
    "follow_lag_s_max": ("s", "lower"),
    "follow_rounds_behind_max": ("rounds", "lower"),
    "cpu_cores_catchup": ("cores", "lower"),
    "cpu_cores_follow": ("cores", "lower"),
    "rss_mb_peak": ("MB", "lower"),
    "blockio_read_mb": ("MB", "lower"),
    "blockio_write_mb": ("MB", "lower"),
    "disk_mb": ("MB", "lower"),
    "gate_rounds_compared": ("rounds", "higher"),
}


def result_rows(runs, meta):
    """Schema-v1 rows. `runs` is a list (one entry per repeat) of
    {impl: {metric: value}}; a metric a run could not produce is left out of
    that run, never padded. Every row is marked non-deterministic."""
    for run in runs:
        for impl in ("go", "rust"):
            unknown = sorted(set(run.get(impl, {})) - set(METRICS))
            if unknown:
                raise CatchupError(f"unknown catchup metric(s) {unknown}")
    rows = []
    for metric, (unit, better) in METRICS.items():
        for impl in ("go", "rust"):
            samples = [run[impl][metric] for run in runs if metric in run.get(impl, {})]
            if not samples:
                continue
            rows.append({
                "schema": "bench-result/v1", "tier": TIER, "name": metric, "impl": impl,
                "unit": unit, "better": better,
                "samples": [round(float(v), 6) for v in samples],
                "metadata": dict(meta, nondeterministic=True, runs=len(runs)),
            })
    return rows
