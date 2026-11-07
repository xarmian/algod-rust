#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Manual native betanet fast-catchup check of one algod-rust binary (issue #2204).

NOT part of CI and not the `catchup` bench tier: it needs the public betanet
(relays, the catchpoint index, a public REST node for the head and the
block-hash gate) and runs the binary directly on the host, no Docker. It is the
procedure behind the live numbers in `docs/DIVERGENCES.md` (DIV-010).

One run: an empty data directory, the betanet `genesis.json`, the node started,
`POST /v2/catchup/<latest label>` (the `#` percent-encoded), `/v2/status` polled
each second. The replay rate is the blocks applied between the catchpoint
clearing and the node being within 12 rounds of the public node's head. Then the
hashes of five recent rounds (a non-archival node keeps only recent blocks) are
compared with the public node's, and, with `--follow-secs N`, the process CPU
time over the next N seconds at the tip is recorded.

To compare two binaries run it once per binary, alternating, at least three
times each (relay speed varies between runs and over the day):

    python3 scripts/bench/catchup_native.py --bin target/release/algod-rust \\
        --genesis docker/algod/genesis/betanet/genesis.json --follow-secs 60

It prints one JSON object (the replay `blocks_per_s`, `gate_ok`, the follow CPU).
`--rustlog warn,algo_rest_client::gossip_block_source=debug --log node.log` keeps
the node's log for profiling.
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

PUBLIC = "https://betanet-api.4160.nodely.dev"
LABEL_URL = "https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/betanet/latest.catchpoint"
TOKEN = "a" * 64
HEAD_SLACK_ROUNDS = 12


def get(url, token=None, timeout=15):
    req = urllib.request.Request(url)
    if token:
        req.add_header("X-Algo-API-Token", token)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def status(port):
    return json.loads(get(f"http://127.0.0.1:{port}/v2/status", TOKEN, 5))


def cpu_seconds(pid):
    """Total CPU time (user + system) of a process, in seconds."""
    if os.name == "nt":
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", f"(Get-Process -Id {pid}).TotalProcessorTime.TotalSeconds"],
            timeout=30,
        )
        return float(out.decode().strip().replace(",", "."))
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    ticks = int(fields[11]) + int(fields[12])  # utime + stime
    return ticks / os.sysconf("SC_CLK_TCK")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", required=True, help="the algod-rust binary")
    ap.add_argument("--genesis", required=True, help="betanet genesis.json")
    ap.add_argument("--port", type=int, default=8186)
    ap.add_argument("--parallel", type=int, default=0, help="CatchupParallelBlocks (default: the node's)")
    ap.add_argument("--label", default="", help="catchpoint label (default: the latest of the index)")
    ap.add_argument("--timeout", type=int, default=1500)
    ap.add_argument("--log", default="")
    ap.add_argument("--tag", default="run")
    ap.add_argument("--follow-secs", type=int, default=0)
    ap.add_argument("--rustlog", default="warn")
    a = ap.parse_args()

    label = a.label or get(LABEL_URL).decode().strip()
    label_round = int(label.split("#")[0])
    d = tempfile.mkdtemp(prefix="catchup_native_")
    shutil.copy(a.genesis, os.path.join(d, "genesis.json"))
    for name in ("algod.token", "algod.admin.token"):
        with open(os.path.join(d, name), "w") as f:
            f.write(TOKEN)
    cfg = {"EndpointAddress": f"127.0.0.1:{a.port}", "NetAddress": "", "DNSBootstrapID": "<network>.algodev.network"}
    if a.parallel:
        cfg["CatchupParallelBlocks"] = a.parallel
    with open(os.path.join(d, "config.json"), "w") as f:
        json.dump(cfg, f)
    env = dict(os.environ)
    env["RUST_LOG"] = a.rustlog
    logf = open(a.log or os.path.join(d, "node.log"), "w")
    proc = subprocess.Popen([a.bin, "algod", "-d", d], stdout=logf, stderr=subprocess.STDOUT, env=env)
    out = {"tag": a.tag, "label": label, "parallel": a.parallel or 16}
    try:
        t0 = time.time()
        while True:
            try:
                status(a.port)
                break
            except Exception:
                if proc.poll() is not None:
                    raise SystemExit("node exited early")
                if time.time() - t0 > 120:
                    raise SystemExit("REST never came up")
                time.sleep(1)
        enc = urllib.parse.quote(label, safe="")
        req = urllib.request.Request(f"http://127.0.0.1:{a.port}/v2/catchup/{enc}", method="POST")
        req.add_header("X-Algo-API-Token", TOKEN)
        urllib.request.urlopen(req, timeout=30).read()
        t_req = time.time()
        clear = end = None
        seen_catchpoint = False
        last_pub = 0
        pub_lr = 0
        while time.time() - t_req < a.timeout:
            time.sleep(1)
            try:
                st = status(a.port)
            except Exception:
                continue
            now = time.time()
            cp = st.get("catchpoint", "")
            lr = st.get("last-round", 0)
            if cp:
                seen_catchpoint = True
            if seen_catchpoint and not cp and clear is None and lr >= label_round:
                clear = (now, lr)
            if clear and now - last_pub > 5:
                try:
                    pub_lr = json.loads(get(f"{PUBLIC}/v2/status"))["last-round"]
                except Exception:
                    pass
                last_pub = now
            if clear and pub_lr and lr >= pub_lr - HEAD_SLACK_ROUNDS:
                end = (now, lr)
                break
        if not clear or not end:
            out["error"] = "no complete run"
        else:
            blocks = end[1] - clear[1]
            secs = end[0] - clear[0]
            out.update(
                replay_blocks=blocks,
                replay_s=round(secs, 1),
                blocks_per_s=round(blocks / secs, 1),
                total_to_head_s=round(end[0] - t_req, 1),
                start_round=clear[1],
                end_round=end[1],
            )
            hi = end[1]
            rounds = sorted({hi, hi - 150, hi - 300, hi - 450, hi - 600})
            bad = []
            for r in rounds:
                try:
                    mine = json.loads(get(f"http://127.0.0.1:{a.port}/v2/blocks/{r}/hash", TOKEN)).get("blockHash")
                except Exception as e:
                    mine = f"ERR {e}"
                try:
                    ref = json.loads(get(f"{PUBLIC}/v2/blocks/{r}/hash")).get("blockHash")
                except Exception as e:
                    ref = f"ERR {e}"
                if mine != ref:
                    bad.append((r, mine, ref))
            out["gate_rounds"] = rounds
            out["gate_ok"] = not bad
            if bad:
                out["gate_bad"] = bad
            if a.follow_secs:
                c0, r0, w0 = cpu_seconds(proc.pid), status(a.port)["last-round"], time.time()
                time.sleep(a.follow_secs)
                c1, r1, w1 = cpu_seconds(proc.pid), status(a.port)["last-round"], time.time()
                out["follow_cpu_s"] = round(c1 - c0, 2)
                out["follow_wall_s"] = round(w1 - w0, 1)
                out["follow_rounds"] = r1 - r0
                out["follow_cpu_pct"] = round(100 * (c1 - c0) / (w1 - w0), 2)
    finally:
        proc.kill()
        try:
            proc.wait(10)
        except Exception:
            pass
        logf.close()
        time.sleep(1)
        shutil.rmtree(d, ignore_errors=True)
    print(json.dumps(out))


if __name__ == "__main__":
    main()
