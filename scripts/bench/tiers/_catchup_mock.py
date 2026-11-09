# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""The hermetic mock network of the `catchup` tier (BENCH_CATCHUP_MODE=mock,
issue #2167).

Kept out of `catchup.py` so the real (Docker) driver does not carry it: the
tier imports this module lazily, only in mock mode. The leading underscore keeps
`run.py discover_tiers` from listing it as a tier.
"""

import base64
import hashlib
import http.server
import json
import threading
import time
import urllib.parse

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
        # algod-rust trails the Go node by a constant round; a real node's newest round
        # never moves backwards (a lag that came and went made a round the gate had just
        # agreed on 404 on the next probe: "0 rounds served by both nodes", at random).
        rnd = min(tip - (1 if self.impl == "rust" else 0), replayed)
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


# ---- entry points for the tier -----------------------------------------------------------------

def label():
    """The catchpoint label both mock nodes are given."""
    return MOCK_LABEL


def make_nodes(sides, cfg):
    """One mock chain and a mock node per side (`go`, `rust`)."""
    chain = MockChain()
    return {side: MockNode(side, chain, cfg) for side in sides}
