#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Transaction-gossip check of the mixed-cluster harness (issue #2154).

Issue #2150 fixed algod-rust participation nodes not subscribing to the `TX`
gossip topic (go `postMessagesOfInterestThread` / `AlgorandFullNode.
IsParticipating`). That was verified on a homogeneous all-Rust cluster; this
checks it on the mixed cluster, in both directions:

  * a set of payments submitted to a Go node (go-node-1) must appear in the
    transaction pool of every OTHER node, the Rust participation node
    included (the Rust node behind Go relays receives TX gossip);
  * a set submitted to the Rust node (rust-node-4) must appear in every Go
    node's pool (Rust-originated transactions reach the Go side).

For each (source, target) pair the transactions are looked for in the target's
pool (the bulk `GET /v2/transactions/pending` list), every target with its own
request in flight from before the first submission on (issue #2429: a Go
node's REST answer can block for seconds behind its ledger's DB commit, which
must not blind the check to the other nodes). A txn never seen in the pool
but confirmed is reported as `confirmed_first` (seen only as part of a block,
not evidence of gossip). A pair passes when no txn is absent, at least one was
seen in its pool and every pool sighting is within the budget (`--within-s`,
about two rounds). Also recorded: the round the set was submitted in and the
rounds it took to commit (the "comparable commit round count" of the issue).

Needs the cluster from start.sh, Docker on PATH and python3 (standard library
only). Exit 0 when every pair passes.

With --topology rust-relay / go-relay (issue #2280, scripts/topology.py) the
cluster has one Go participation node (go-node-3) whose only peer is a Rust
relay / a Go relay (the control): sources are then go-node-3, go-node-1 and
rust-node-4, so a payment submitted to the isolated Go node must reach every
other node and a payment submitted anywhere must reach it, all through that one
relay. `--sources a,b` overrides the topology's choice.

Usage:
  tx_gossip.py --out tx-gossip.json [--count 12] [--within-s 6]
               [--topology default|rust-relay|go-relay] [--sources a,b]
"""
import argparse
import base64
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import topology  # noqa: E402

NODES = ("go-node-1", "go-node-2", "go-node-3", "rust-node-4")
SOURCES = ("go-node-1", "rust-node-4")
WORK_DIR = "/tmp/w"
ADDR_RE = re.compile(r"\b[A-Z2-7]{58}\b")


class CheckError(Exception):
    pass


def parse_txid(body):
    """The `txId` of a POST /v2/transactions response."""
    try:
        txid = json.loads(body).get("txId")
    except (ValueError, AttributeError):
        raise CheckError("submission response is not JSON: {!r}".format(body[:160]))
    if not txid:
        raise CheckError("submission response has no txId: {!r}".format(body[:160]))
    return txid


def pending_state(status, confirmed_round):
    """absent / pool / confirmed for a GET /v2/transactions/pending/{txid}."""
    if status != 200:
        return "absent"
    return "confirmed" if int(confirmed_round or 0) > 0 else "pool"


def _note_text(value):
    """A transaction note as text from the JSON of either implementation: go
    emits base64, algod-rust a list of byte values."""
    try:
        if isinstance(value, str):
            return base64.b64decode(value).decode("utf-8", "replace")
        if isinstance(value, list):
            return bytes(value).decode("utf-8", "replace")
    except (ValueError, TypeError):
        pass
    return None


def notes_of_pending(doc):
    """The notes of the transactions in a GET /v2/transactions/pending document."""
    out = set()
    for entry in (doc or {}).get("top-transactions") or []:
        note = _note_text(((entry or {}).get("txn") or {}).get("note"))
        if note is not None:
            out.add(note)
    return out


def notes_of_block(doc):
    """The notes of the transactions of a GET /v2/blocks/{round}?format=json document."""
    out = set()
    for entry in ((doc or {}).get("block") or {}).get("txns") or []:
        note = _note_text(((entry or {}).get("txn") or {}).get("note"))
        if note is not None:
            out.add(note)
    return out


def run_check(net, *, nodes, sources, count, within_s, build, poll_s=0.1,
              settle_s=10.0, commit_wait_s=90.0, topology="default", commit_node=None):
    """Submit `count` transactions to each source node and watch every other
    node. `net` provides now(), sleep(s), round_of(node), submit_async(node,
    raw) and pool_notes_async(node) (requests in flight: `.done()`, and
    `.result()` -> (answer, when it was answered); the answers are those of
    submit(node, raw) -> (status, body) and pool_notes(node), the notes in the
    node's pool from the bulk list or None when unavailable), note_of(raw),
    committed_rounds(node, notes, from_round, wait_s) and pending(node, txid)
    -> (status, confirmed_round); `build(source, i)` returns the raw signed
    transaction. Returns the result document (see `pass`, `pairs`, `sources`).

    A transaction is "seen" in a target's pool when its note is in the bulk
    pending list. Every target has its own request in flight, from before the
    first submission until the end: a Go node's REST answer (the list, a POST)
    can block for 1.4 to 2.8 s behind its ledger's slow DB commit (#2429), and
    one stalled node must not leave the others unwatched. The per-txid
    GET /v2/transactions/pending/{txid} (0.1 to 2.5 s and stalls on Go, #2301)
    is used only once, after the deadline, for what the list did not show (to
    tell "confirmed first" from "absent"), and as the whole method when the
    list is unavailable. The commit rounds come from the blocks.

    A pair passes when no txn is absent, at least one was seen in the target's
    pool (the gossip path is proven), and every pool sighting is within the
    budget. A txn seen only as committed is reported (`confirmed_first`) but is
    not a failure on its own: it can be gossiped and committed inside a single
    stalled answer of the target."""
    pairs, source_rows = [], []
    for src in sources:
        raws = [build(src, i) for i in range(count)]
        # After the (slow, goal-in-docker) build: commit_rounds counts from the
        # moment the first payment is submitted.
        round_before = net.round_of(src)
        notes = [net.note_of(raw) for raw in raws]
        targets = [n for n in nodes if n != src]
        txid_of = {}    # note -> txid
        answered = {}   # note -> when the node answered its submission
        max_post = 0.0
        seen = {}       # (target, note) -> (state, latency)
        polls = {t: net.pool_notes_async(t) for t in targets}
        max_poll = {t: 0.0 for t in targets}
        poll_started = {t: net.now() for t in targets}
        bulk_ok = {t: True for t in targets}
        queue = list(raws)
        sub, sub_started = None, None
        deadline = None
        while True:
            # The submissions, one at a time and in order, while the targets
            # are watched.
            if sub is not None and sub.done():
                (status, body), at = sub.result()
                if status != 200:
                    raise CheckError("{} rejected a submitted payment ({}): {}".format(
                        src, status, body[:200]))
                note = net.note_of(queue.pop(0))
                txid_of[note] = parse_txid(body)
                answered[note] = at
                max_post = max(max_post, at - sub_started)
                sub = None
            if sub is None and queue:
                sub, sub_started = net.submit_async(src, queue[0]), net.now()
            if not queue and deadline is None:
                # Gossip latency counts from each node's answer: a Go node's
                # POST can itself take seconds while its pool lock is held.
                deadline = max(answered.values()) + within_s + settle_s
            for target in targets:
                if bulk_ok[target]:
                    fut = polls[target]
                    if not fut.done():
                        continue
                    pool, at = fut.result()
                    max_poll[target] = max(max_poll[target], at - poll_started[target])
                    if pool is None:
                        bulk_ok[target] = False
                        continue
                    for note in notes:
                        if (target, note) not in seen and note in pool:
                            seen[(target, note)] = (
                                "pool", max(0.0, at - answered.get(note, at)))
                    polls[target] = net.pool_notes_async(target)
                    poll_started[target] = net.now()
                    continue
                for note, txid in txid_of.items():
                    if (target, note) in seen:
                        continue
                    state = pending_state(*net.pending(target, txid))
                    if state != "absent":
                        seen[(target, note)] = (state, max(0.0, net.now() - answered[note]))
            if deadline is not None and (len(seen) == len(targets) * len(notes)
                                         or net.now() >= deadline):
                break
            net.sleep(poll_s)
        # What the bulk list never showed: one per-txid lookup each, to tell
        # "committed before it was ever seen in the pool" from "never there".
        for target in targets:
            if not bulk_ok[target]:
                continue
            for note in notes:
                if (target, note) not in seen:
                    state = pending_state(*net.pending(target, txid_of[note]))
                    if state != "absent":
                        seen[(target, note)] = (state, max(0.0, net.now() - answered[note]))
        for target in targets:
            states = [seen.get((target, n)) for n in notes]
            absent = sum(1 for s in states if s is None)
            in_pool = sum(1 for s in states if s and s[0] == "pool")
            confirmed_first = sum(1 for s in states if s and s[0] == "confirmed")
            lat = [s[1] for s in states if s and s[0] == "pool"]
            max_latency = max(lat) if lat else None
            ok = (absent == 0 and in_pool >= 1
                  and max_latency is not None and max_latency <= within_s)
            pairs.append({
                "source": src, "target": target, "txns": len(notes), "ok": ok,
                "in_pool_first": in_pool, "confirmed_first": confirmed_first,
                "absent": absent,
                "max_latency_s": None if max_latency is None else round(max_latency, 3),
                "min_latency_s": round(min(lat), 3) if lat else None,
                "max_poll_s": round(max_poll[target], 3),
            })
        # Commit rounds, read from the blocks of the source node.
        found = net.committed_rounds(commit_node or src, set(notes), round_before or 0,
                                     commit_wait_s)
        confirmed_rounds = {n: r for n, r in found.items() if n in notes}
        rounds = sorted(confirmed_rounds.values())
        source_rows.append({
            "source": src, "submitted": len(txid_of), "confirmed": len(rounds),
            "max_post_s": round(max_post, 3),
            "block_scan": getattr(net, "last_scan", None),
            "round_before": round_before,
            "first_round": rounds[0] if rounds else None,
            "last_round": rounds[-1] if rounds else None,
            "commit_rounds": (rounds[-1] - round_before)
            if rounds and round_before is not None else None,
        })
    return {"pass": all(p["ok"] for p in pairs), "topology": topology,
            "within_s": within_s, "count": count, "pairs": pairs, "sources": source_rows}


# ── the real cluster ───────────────────────────────────────────────────

class ClusterNet:
    """The harness cluster: REST on the host ports, transactions built and
    signed with `goal` inside go-node-1 (kmd, Wallet1)."""

    def __init__(self):
        import workload  # noqa: E402 -- needs ports, docker
        self.workload = workload
        self.env = workload.Env()
        self.funder = None
        self.notes = {}  # raw signed payment -> its note
        self._executor = None

    def now(self):
        return time.monotonic()

    def sleep(self, s):
        time.sleep(s)

    def round_of(self, node):
        try:
            return int(self.env.rest_json("/v2/status", node=node)["last-round"])
        except Exception:  # noqa: BLE001 - a round is optional context
            return None

    def submit(self, node, raw):
        return self.env.post_txn(node, raw)

    def _in_flight(self, fn, *args):
        """`fn(*args)` on a worker thread: a future whose result is
        (answer, when it was answered), so a stalled node blocks only itself."""
        if self._executor is None:
            import concurrent.futures
            self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=16)

        def call():
            answer = fn(*args)
            return answer, self.now()
        return self._executor.submit(call)

    def submit_async(self, node, raw):
        return self._in_flight(self.submit, node, raw)

    def pool_notes_async(self, node):
        return self._in_flight(self.pool_notes, node)

    def _get_json(self, node, path, timeout=10):
        import urllib.request
        url = "http://127.0.0.1:{}{}".format(self.workload.NODE_PORTS[node], path)
        req = urllib.request.Request(url, headers={"X-Algo-API-Token": self.workload.TOKEN})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def note_of(self, raw):
        return self.notes[raw]

    def pool_notes(self, node):
        """The notes in `node`'s pool from GET /v2/transactions/pending (the bulk
        list); None when the node cannot serve it."""
        try:
            return notes_of_pending(self._get_json(node, "/v2/transactions/pending?max=0"))
        except Exception:  # noqa: BLE001 - the per-txid path takes over
            return None

    def committed_rounds(self, node, notes, from_round, wait_s):
        """note -> the round whose block (read from `node`) holds it: blocks
        from_round+1.. are read as they appear, until all are found or wait_s ran out."""
        found = {}
        nxt = int(from_round) + 1
        end = time.monotonic() + wait_s
        while len(found) < len(notes) and time.monotonic() < end:
            latest = self.round_of(node)
            if latest is None or nxt > latest:
                time.sleep(0.5)
                continue
            try:
                doc = self._get_json(node, "/v2/blocks/{}?format=json".format(nxt), timeout=15)
            except Exception:  # noqa: BLE001 - retry the same block
                time.sleep(0.5)
                continue
            for note in notes_of_block(doc) & set(notes):
                found.setdefault(note, nxt)
            nxt += 1
        self.last_scan = {"node": node, "from_round": int(from_round) + 1,
                          "next_unread_round": nxt, "found": len(found), "wanted": len(notes)}
        return found

    def pending(self, node, txid):
        import urllib.error
        import urllib.request
        url = "http://127.0.0.1:{}/v2/transactions/pending/{}".format(
            self.workload.NODE_PORTS[node], txid)
        req = urllib.request.Request(url, headers={"X-Algo-API-Token": self.workload.TOKEN})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                info = json.loads(r.read().decode("utf-8"))
                return r.status, info.get("confirmed-round") or 0
        except urllib.error.HTTPError as e:
            return e.code, 0
        except (urllib.error.URLError, OSError, ValueError):
            return 0, 0

    def warm(self):
        """kmd up and a funder address (what workload.py's setup does)."""
        # WORK_DIR is created here as root but written by whichever user the
        # goal commands run as (the image's own user first), so open it up.
        # kmd.pid: `goal kmd start` first kills the pid in it, a stale one from the
        # `goal network create` container that can be this container's own
        # entrypoint or algod (it SIGTERMed go-node-1 in CI).
        rc, out = self.env.sh(
            "rm -f {d}/kmd-v0.5/kmd.pid; chmod 700 {d}/kmd-v0.5; mkdir -p {w} && chmod 777 {w}".format(
                d=self.workload.DATA_DIR, w=WORK_DIR))
        if rc != 0:
            raise CheckError("cannot prepare {} in the container: {}".format(WORK_DIR, out))
        last = ""
        for user in ("root", "algorand"):
            self.env.user = user
            for _ in range(8):
                self.env.goal("kmd start -t 0")
                rc, last = self.env.goal("wallet list")
                if rc == 0:
                    break
                time.sleep(5)
            if rc == 0:
                break
        else:
            raise CheckError("kmd never became ready: " + last[-300:])
        rc, out = self.env.goal("account list")
        m = ADDR_RE.search(out)
        if rc != 0 or not m:
            raise CheckError("cannot discover the funder account: " + out[-300:])
        self.funder = m.group(0)

    def build(self, source, i):
        """A signed zero-amount self-payment of the funder, distinct per (source, i)
        by its note, as raw bytes."""
        note = "gossip-{}-{}-{}".format(source, i, int(time.time()))
        f = self.funder
        rc, out = self.env.sh(
            "cd {w} && goal clerk send -f {f} -t {f} -a 0 --note {n} -s -o tg.stxn -d {d} 2>&1".format(
                w=WORK_DIR, f=f, n=note, d=self.workload.DATA_DIR))
        if rc != 0:
            raise CheckError("goal could not build the payment (rc={}): {}".format(rc, out[-300:]))
        rc, b64 = self.env.fetch_file_b64(WORK_DIR + "/tg.stxn")
        if rc != 0 or not b64:
            raise CheckError("could not read the signed payment")
        raw = base64.b64decode(b64)
        self.notes[raw] = note
        return raw


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, help="result JSON")
    ap.add_argument("--count", type=int, default=12, help="payments per source node")
    ap.add_argument("--within-s", type=float, default=6.0,
                    help="every txn must be in each target within this many seconds (~2 rounds)")
    ap.add_argument("--topology", default="default", choices=topology.TOPOLOGIES,
                    help="the cluster topology start.sh was run with (selects the sources)")
    ap.add_argument("--sources", default="",
                    help="comma-separated source nodes (default: the topology's)")
    return ap.parse_args(argv)


def resolve_sources(args):
    """The nodes payments are submitted to: --sources, else the topology's."""
    if not args.sources:
        return topology.plan(args.topology).sources
    sources = tuple(x for x in args.sources.split(",") if x)
    for x in sources:
        if x not in NODES:
            raise CheckError("--sources: {!r} is not a cluster node ({})".format(
                x, ", ".join(NODES)))
    return sources


def main(argv=None):
    args = parse_args(argv)
    net = ClusterNet()
    try:
        sources = resolve_sources(args)
        net.warm()
        res = run_check(net, nodes=NODES, sources=sources, count=args.count,
                        within_s=args.within_s, build=net.build, topology=args.topology,
                        commit_node="go-node-1")
    except CheckError as e:
        res = {"pass": False, "error": str(e), "topology": args.topology,
               "pairs": [], "sources": []}
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(res, f, indent=1)
        f.write("\n")
    if res.get("error"):
        print("tx-gossip: FAILED: " + res["error"])
        return 1
    for p in res["pairs"]:
        print("tx-gossip: {:>11} -> {:<11} pool={} confirmed_first={} absent={} "
              "latency {}..{}s max_poll {}s {}".format(
                  p["source"], p["target"], p["in_pool_first"], p["confirmed_first"],
                  p["absent"], p["min_latency_s"], p["max_latency_s"], p["max_poll_s"],
                  "ok" if p["ok"] else "FAIL"))
    for s in res["sources"]:
        print("tx-gossip: {} submitted={} confirmed={} rounds {}..{} (commit_rounds={})".format(
            s["source"], s["submitted"], s["confirmed"], s["first_round"], s["last_round"],
            s["commit_rounds"]))
    bad = [p for p in res["pairs"] if not p["ok"]]
    print("tx-gossip: {}".format(
        "all {} pairs ok".format(len(res["pairs"])) if not bad
        else "{} of {} pairs FAILED".format(len(bad), len(res["pairs"]))))
    return 0 if res["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
