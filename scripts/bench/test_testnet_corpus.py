# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests of the testnet replay corpus tooling (scripts/bench/corpus/
fetch_testnet.py, the `vote` negative corpus of tiers/replay.py; issue #2119).

No network: a local HTTP server plays the archival endpoint, serving the
committed 50-round testnet prefix (benchmarks/corpus/testnet-prefix50, whose
blocks are the real testnet's, certificates included). Fetching it back must
reproduce that corpus byte for byte, which is also what pins a re-fetch of
the real endpoint. The replays themselves (certificate authentication on
both sides) are covered by benchmarks/go-replay's go tests and the Rust
bench_replay tests."""
import contextlib
import http.server
import json
import os
import re
import struct
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tiers"))
sys.path.insert(0, os.path.join(HERE, "corpus"))
import bench_schema  # noqa: E402,F401
import corpus_tool as ct  # noqa: E402
import fetch_testnet as ft  # noqa: E402
import replay  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
PREFIX = os.path.join(REPO, "benchmarks", "corpus", "testnet-prefix50")
SMALL = os.path.join(REPO, "benchmarks", "corpus", "small")
REF = os.path.join(REPO, "benchmarks", "corpus", "testnet-head.ref")


def read(path):
    with open(path, "rb") as f:
        return f.read()


def records(path):
    """round -> payload of a blocks.bin."""
    b = read(path)
    assert b[:8] == b"ACRPBLK1"
    out, i = {}, 8
    while i < len(b):
        rnd, n = struct.unpack(">QI", b[i:i + 12])
        out[rnd] = b[i + 12:i + 12 + n]
        i += 12 + n
    return out


@contextlib.contextmanager
def endpoint(corpus, attested_hash=None):
    """An algod REST endpoint serving `corpus`'s blocks, genesis and head."""
    cj = ct.load_corpus_json(corpus)
    blocks = records(os.path.join(corpus, "blocks.bin"))
    genesis = read(os.path.join(corpus, "genesis.json"))
    last = cj["rounds"]["last"]
    fs = cj["final_state"]

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, body, ctype="application/json"):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path
            m = re.fullmatch(r"/v2/blocks/(\d+)\?format=msgpack", path)
            if path == "/genesis":
                return self.reply(genesis)
            if path == "/v2/transactions/params":
                return self.reply(json.dumps({
                    "genesis-id": cj["network"]["genesis_id"],
                    "genesis-hash": cj["network"]["genesis_hash"]}).encode())
            if m and int(m.group(1)) in blocks:
                return self.reply(blocks[int(m.group(1))], "application/msgpack")
            if path == f"/v2/blocks/{last}/hash":
                h = attested_hash or fs["block_hash"]
                return self.reply(json.dumps({"blockHash": h[len("blk-"):]}).encode())
            if path == f"/v2/blocks/{last}?header-only=true":
                return self.reply(json.dumps(
                    {"block": {"rnd": last, "tc": fs["txn_counter"]}}).encode())
            self.send_error(404)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def final_state_file(d, corpus):
    p = os.path.join(d, "final.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(ct.load_corpus_json(corpus)["final_state"], f)
    return p


class FetchTests(unittest.TestCase):
    def test_prefix_fixture_is_a_valid_nondevmode_corpus(self):
        self.assertEqual(ct.verify_manifest(PREFIX), [])
        cj = ct.load_corpus_json(PREFIX)
        self.assertIs(cj["network"]["devmode"], False)
        self.assertEqual(cj["rounds"], {"first": 0, "last": 50, "count": 51})
        self.assertEqual(sorted(records(os.path.join(PREFIX, "blocks.bin"))), list(range(51)))
        for k in ft.STATE_KEYS + ("round", "block_hash", "txn_counter"):
            self.assertIn(k, cj["final_state"])
        # real certificates: vote signatures are present (the DevMode corpora
        # hold none), which is what makes the replay authenticate them.
        self.assertIn(replay.VOTE_SIG_NEEDLE, read(os.path.join(PREFIX, "blocks.bin")))
        self.assertNotIn(replay.VOTE_SIG_NEEDLE, read(os.path.join(SMALL, "blocks.bin")))

    def test_fetch_reproduces_the_committed_corpus_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX) as url:
            dest = os.path.join(t, "c")
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--endpoint", url,
                          "--rounds", "50", "--dest", dest, "--name", "testnet-prefix50",
                          "--final-state", final_state_file(t, PREFIX), "--workers", "4"])
            self.assertEqual(rc, 0)
            self.assertEqual(ct.compare(dest, PREFIX), [])
            self.assertEqual(ct.verify_manifest(dest), [])
            self.assertFalse(os.path.exists(dest + ".partial"))

    def test_manifest_pin_mismatch_installs_nothing(self):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX) as url:
            ref = os.path.join(t, "x.ref")
            with open(ref, "w", encoding="utf-8") as f:
                f.write(f"endpoint={url}\nrounds=50\nmanifest_sha256={'0' * 64}\n")
            dest = os.path.join(t, "c")
            rc = ft.main(["fetch", "--ref", ref, "--dest", dest, "--final-state",
                          final_state_file(t, PREFIX), "--name", "testnet-prefix50",
                          "--workers", "2"])
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(dest))
            self.assertFalse(os.path.exists(dest + ".partial"))

    def test_matching_manifest_pin_installs(self):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX) as url:
            ref = os.path.join(t, "x.ref")
            pin = ct.sha256_file(os.path.join(PREFIX, ct.MANIFEST))
            with open(ref, "w", encoding="utf-8") as f:
                f.write(f"endpoint={url}\nrounds=50\nmanifest_sha256={pin}\n"
                        f"final_state={final_state_file(t, PREFIX)}\n")
            dest = os.path.join(t, "c")
            rc = ft.main(["fetch", "--ref", ref, "--dest", dest, "--name",
                          "testnet-prefix50", "--workers", "2"])
            self.assertEqual(rc, 0)
            self.assertEqual(ct.compare(dest, PREFIX), [])

    def test_final_state_must_agree_with_the_endpoint(self):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX, "blk-" + "A" * 52) as url:
            dest = os.path.join(t, "c")
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--endpoint", url,
                          "--rounds", "50", "--dest", dest, "--workers", "2",
                          "--final-state", final_state_file(t, PREFIX)])
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(dest))

    def test_unreachable_endpoint_exits_3(self):
        with tempfile.TemporaryDirectory() as t:
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--rounds", "5",
                          "--endpoint", "http://127.0.0.1:9", "--dest", os.path.join(t, "c"),
                          "--final-state", "", "--retries", "1", "--workers", "1"])
            self.assertEqual(rc, 3)

    def test_a_provisional_fetch_ignores_the_pin_of_an_unpinned_ref(self):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX) as url:
            ref = os.path.join(t, "x.ref")
            with open(ref, "w", encoding="utf-8") as f:
                f.write(f"endpoint={url}\nrounds=50\nmanifest_sha256=PENDING\n")
            dest = os.path.join(t, "c")
            rc = ft.main(["fetch", "--ref", ref, "--dest", dest, "--final-state", "",
                          "--name", "testnet-prefix50", "--workers", "2"])
            self.assertEqual(rc, 0)
            fs = ct.load_corpus_json(dest)["final_state"]
            self.assertEqual(sorted(fs), ["block_hash", "round", "txn_counter"])

    def test_existing_dest_needs_force(self):
        with tempfile.TemporaryDirectory() as t:
            dest = os.path.join(t, "c")
            os.mkdir(dest)
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--rounds", "5",
                          "--endpoint", "http://127.0.0.1:9", "--dest", dest,
                          "--final-state", ""])
            self.assertEqual(rc, 1)
            self.assertTrue(os.path.isdir(dest))

    def test_finalize_takes_the_state_from_a_go_replay_result(self):
        cj = ct.load_corpus_json(PREFIX)
        fs = cj["final_state"]
        res = {"final_state": {
            "round": fs["round"], "block_hash": fs["block_hash"],
            "txn_counter": fs["txn_counter"], "total_money": fs["total_money"],
            "online_money": fs["online_money"],
            "known_accounts": {"count": fs["accounts"], "microalgos": fs["accounts_microalgos"],
                               "sha256": fs["accounts_sha256"]}}}
        with tempfile.TemporaryDirectory() as t:
            rp, out = os.path.join(t, "r.json"), os.path.join(t, "f.json")
            with open(rp, "w", encoding="utf-8") as f:
                json.dump(res, f)
            self.assertEqual(ft.main(["finalize", "--corpus", PREFIX, "--replay-result", rp,
                                      "--out", out]), 0)
            with open(out, encoding="utf-8") as f:
                self.assertEqual(json.load(f), fs)
            # A replay that reached another block than the endpoint attests.
            res["final_state"]["block_hash"] = "blk-" + "B" * 52
            with open(rp, "w", encoding="utf-8") as f:
                json.dump(res, f)
            self.assertEqual(ft.main(["finalize", "--corpus", PREFIX, "--replay-result", rp,
                                      "--out", out]), 1)


class RefTests(unittest.TestCase):
    def test_ref_pins_a_manifest_and_a_final_state(self):
        ref = ft.read_ref(REF)
        self.assertRegex(ref["manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertGreaterEqual(int(ref["rounds"]), 1000)
        self.assertTrue(ref["endpoint"].startswith("https://"))
        with open(os.path.join(REPO, ref["final_state"]), encoding="utf-8") as f:
            fs = json.load(f)
        self.assertEqual(fs["round"], int(ref["rounds"]))
        self.assertEqual(sorted(fs), sorted(ft.STATE_KEYS + ("round", "block_hash",
                                                             "txn_counter")))


class VoteCorruptionTests(unittest.TestCase):
    def test_vote_corruption_flips_one_signature_bit_and_rehashes(self):
        with tempfile.TemporaryDirectory() as t:
            d = replay.corrupt_corpus(PREFIX, os.path.join(t, "c"), "vote")
            self.assertEqual(ct.verify_manifest(d), [])
            a, b = read(os.path.join(PREFIX, "blocks.bin")), read(os.path.join(d, "blocks.bin"))
            self.assertEqual(len(a), len(b))
            diff = [i for i in range(len(a)) if a[i] != b[i]]
            self.assertEqual(len(diff), 1)
            self.assertEqual(a[diff[0]] ^ b[diff[0]], 1)
            # inside the last record's last vote signature
            i = a.rfind(replay.VOTE_SIG_NEEDLE)
            self.assertEqual(diff[0], i + len(replay.VOTE_SIG_NEEDLE) + 63)

    def test_vote_corruption_needs_a_corpus_with_votes(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(replay.TierError):
                replay.corrupt_corpus(SMALL, os.path.join(t, "c"), "vote")


if __name__ == "__main__":
    unittest.main()
