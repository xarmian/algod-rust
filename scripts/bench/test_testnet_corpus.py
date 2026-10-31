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
import shlex
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock

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
def endpoint(corpus, attested_hash=None, genesis=None, overrides=None):
    """An algod REST endpoint serving `corpus`'s blocks, genesis and head.
    `genesis` replaces the /genesis body, `overrides` maps a round to the
    body served for it (whatever it is)."""
    cj = ct.load_corpus_json(corpus)
    blocks = records(os.path.join(corpus, "blocks.bin"))
    blocks.update(overrides or {})
    if genesis is None:
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
        recs = records(os.path.join(PREFIX, "blocks.bin"))
        self.assertTrue(all(ct.cert_votes(recs[r]) for r in range(1, 51)))
        small = records(os.path.join(SMALL, "blocks.bin"))
        self.assertFalse(any(ct.cert_votes(small[r]) for r in range(1, 20)))

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


class RefOverrideTests(unittest.TestCase):
    """Issue #2119 review: the ref describes one range; a command that
    overrides the range must not inherit its final state or pin."""

    def run_documented(self, t, url):
        text = read(os.path.join(REPO, "docs", "BENCHMARK_COMPARISON.md")).decode("utf-8")
        lines = [m.group(1) for m in re.finditer(
            r"^python3 scripts/bench/corpus/fetch_testnet\.py (fetch .*testnet-prefix50\.ref.*)$",
            text, re.M)]
        self.assertEqual(len(lines), 1, "the docs must show how to rebuild testnet-prefix50")
        argv = shlex.split(lines[0])
        dest = os.path.join(t, "prefix50")
        argv[argv.index("--dest") + 1] = dest
        old_env, old_cwd = os.environ.get("TESTNET_ENDPOINT"), os.getcwd()
        os.environ["TESTNET_ENDPOINT"] = url
        os.chdir(REPO)
        try:
            return ft.main(argv), dest
        finally:
            os.chdir(old_cwd)
            if old_env is None:
                del os.environ["TESTNET_ENDPOINT"]
            else:
                os.environ["TESTNET_ENDPOINT"] = old_env

    def test_documented_prefix_rebuild_command_works(self):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX) as url:
            rc, dest = self.run_documented(t, url)
            self.assertEqual(rc, 0)
            self.assertEqual(ct.compare(dest, PREFIX), [])

    def test_rounds_override_ignores_the_refs_final_state_and_pin(self):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX) as url:
            old = os.environ.get("TESTNET_ENDPOINT")
            os.environ["TESTNET_ENDPOINT"] = url
            try:
                dest = os.path.join(t, "c")
                # the default ref is testnet-head.ref (20000 rounds, its pin)
                rc = ft.main(["fetch", "--rounds", "50", "--name", "testnet-prefix50",
                              "--dest", dest, "--workers", "2"])
            finally:
                if old is None:
                    del os.environ["TESTNET_ENDPOINT"]
                else:
                    os.environ["TESTNET_ENDPOINT"] = old
            self.assertEqual(rc, 0)
            fs = ct.load_corpus_json(dest)["final_state"]
            self.assertEqual(sorted(fs), ["block_hash", "round", "txn_counter"])


class GenesisTests(unittest.TestCase):
    def test_genesis_hash_port_matches_the_real_testnet_hash(self):
        cj = ct.load_corpus_json(PREFIX)
        self.assertEqual(ft.genesis_hash_b64(read(os.path.join(PREFIX, "genesis.json"))),
                         cj["network"]["genesis_hash"])

    def test_a_genesis_that_does_not_hash_to_the_endpoints_is_refused(self):
        g = json.loads(read(os.path.join(PREFIX, "genesis.json")))
        g["alloc"][0]["state"]["algo"] += 1
        with tempfile.TemporaryDirectory() as t, \
                endpoint(PREFIX, genesis=json.dumps(g).encode()) as url:
            dest = os.path.join(t, "c")
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--endpoint", url,
                          "--rounds", "50", "--dest", dest, "--workers", "2",
                          "--final-state", final_state_file(t, PREFIX)])
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(dest))

    def test_genesis_is_stored_exactly_as_served(self):
        crlf = read(os.path.join(PREFIX, "genesis.json")).replace(b"\n", b"\r\n")
        self.assertIn(b"\r\n", crlf)
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX, genesis=crlf) as url:
            dest = os.path.join(t, "c")
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--endpoint", url,
                          "--rounds", "50", "--dest", dest, "--workers", "2",
                          "--final-state", ""])
            self.assertEqual(rc, 0)
            self.assertEqual(read(os.path.join(dest, "genesis.json")), crlf)


class BlockValidationTests(unittest.TestCase):
    def fetch(self, overrides, retries="1"):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX, overrides=overrides) as url:
            dest = os.path.join(t, "c")
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--endpoint", url,
                          "--rounds", "50", "--dest", dest, "--workers", "2",
                          "--retries", retries, "--final-state", ""])
            self.assertFalse(os.path.exists(dest))
            return rc

    def test_an_empty_200_body_is_not_a_block(self):
        self.assertEqual(self.fetch({7: b""}), 1)

    def test_an_html_200_body_is_not_a_block(self):
        self.assertEqual(self.fetch({7: b"<html><body>rate limited</body></html>"}), 1)

    def test_a_block_for_another_round_is_refused(self):
        other = records(os.path.join(PREFIX, "blocks.bin"))[8]
        self.assertEqual(self.fetch({7: other}), 1)

    def test_round_zero_has_no_rnd_key_and_is_accepted(self):
        recs = records(os.path.join(PREFIX, "blocks.bin"))
        self.assertEqual(ct.block_round(recs[0]), 0)
        self.assertEqual(ct.block_round(recs[31]), 31)

    def test_no_sleep_after_the_last_failed_attempt(self):
        sleeps = []
        ep = ft.Endpoint("http://127.0.0.1:9", retries=3, timeout=2)
        with mock.patch.object(ft.time, "sleep", sleeps.append):
            with self.assertRaises(ft.Unreachable):
                ep.get("/x")
        self.assertEqual(len(sleeps), 2)


class AnchoredVoteTests(unittest.TestCase):
    """The vote negative corpus flips a byte of a specific certificate's last
    vote signature, located by parsing the record's msgpack structure."""

    def test_offset_is_the_last_byte_of_the_last_vote_signature(self):
        recs = records(os.path.join(PREFIX, "blocks.bin"))
        payload = recs[50]
        off = ct.vote_signature_last_byte_offset(payload)
        self.assertEqual(ct.cert_votes(payload)[-1]["sig"]["s"][-1], payload[off])
        self.assertEqual(len(ct.cert_votes(payload)[-1]["sig"]["s"]), 64)
        # a certificate with votes, in every round after genesis
        self.assertTrue(all(ct.cert_votes(recs[r]) for r in range(1, 51)))

    def test_corrupt_vote_changes_exactly_that_byte(self):
        with tempfile.TemporaryDirectory() as t:
            d = replay.corrupt_corpus(PREFIX, os.path.join(t, "c"), "vote")
            a = records(os.path.join(PREFIX, "blocks.bin"))
            b = records(os.path.join(d, "blocks.bin"))
            changed = [r for r in a if a[r] != b[r]]
            self.assertEqual(changed, [50])
            diff = [i for i in range(len(a[50])) if a[50][i] != b[50][i]]
            self.assertEqual(diff, [ct.vote_signature_last_byte_offset(a[50])])
            va, vb = ct.cert_votes(a[50]), ct.cert_votes(b[50])
            self.assertEqual(va[:-1], vb[:-1])
            self.assertEqual(va[-1]["sig"]["s"][:-1], vb[-1]["sig"]["s"][:-1])
            self.assertNotEqual(va[-1]["sig"]["s"], vb[-1]["sig"]["s"])

    def test_a_certificate_without_votes_is_refused(self):
        recs = records(os.path.join(SMALL, "blocks.bin"))
        with self.assertRaises(ValueError):
            ct.vote_signature_last_byte_offset(recs[5])


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
    def test_vote_corruption_needs_a_corpus_with_votes(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(replay.TierError):
                replay.corrupt_corpus(SMALL, os.path.join(d, "c"), "vote")


if __name__ == "__main__":
    unittest.main()
