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
import hashlib
import http.server
import io
import json
import os
import re
import shlex
import shutil
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
def endpoint(corpus, attested_hash=None, genesis=None, overrides=None, truncate=None,
             genesis_hash=None):
    """An algod REST endpoint serving `corpus`'s blocks, genesis and head.
    `genesis` replaces the /genesis body, `genesis_hash` the hash reported by
    /v2/transactions/params, `overrides` maps a round to the body served for
    it (whatever it is), `truncate` maps a round to how many times its body
    is cut short mid-transfer (None: always) before it is served whole."""
    truncate = dict(truncate or {})
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

        def reply(self, body, ctype="application/json", cut=False):
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if cut:
                self.wfile.write(body[:len(body) // 2])
                self.wfile.flush()
                self.close_connection = True
                return
            self.wfile.write(body)

        def do_GET(self):
            path = self.path
            m = re.fullmatch(r"/v2/blocks/(\d+)\?format=msgpack", path)
            if path == "/genesis":
                return self.reply(genesis)
            if path == "/v2/transactions/params":
                return self.reply(json.dumps({
                    "genesis-id": cj["network"]["genesis_id"],
                    "genesis-hash": genesis_hash or cj["network"]["genesis_hash"]}).encode())
            if m and int(m.group(1)) in blocks:
                n = int(m.group(1))
                if n in truncate:
                    if truncate[n] is None:
                        return self.reply(blocks[n], "application/msgpack", cut=True)
                    if truncate[n] > 0:
                        truncate[n] -= 1
                        return self.reply(blocks[n], "application/msgpack", cut=True)
                return self.reply(blocks[n], "application/msgpack")
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


class ForceTests(unittest.TestCase):
    """T1: --force must not delete the old corpus before the new one is ready."""

    def make_old(self, t):
        dest = os.path.join(t, "c")
        os.mkdir(dest)
        with open(os.path.join(dest, "marker"), "w", encoding="utf-8") as f:
            f.write("old corpus")
        return dest

    def test_failing_forced_fetch_leaves_the_old_corpus_intact(self):
        with tempfile.TemporaryDirectory() as t, \
                endpoint(PREFIX, overrides={7: b"<html>nope</html>"}) as url:
            dest = self.make_old(t)
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--endpoint", url,
                          "--rounds", "50", "--dest", dest, "--workers", "2", "--force",
                          "--retries", "1", "--final-state", ""])
            self.assertEqual(rc, 1)
            self.assertEqual(os.listdir(dest), ["marker"])
            self.assertFalse(os.path.exists(dest + ".partial"))
            self.assertFalse(os.path.exists(dest + ".old"))

    def test_unreachable_forced_fetch_leaves_the_old_corpus_intact(self):
        with tempfile.TemporaryDirectory() as t:
            dest = self.make_old(t)
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--rounds", "5",
                          "--endpoint", "http://127.0.0.1:9", "--dest", dest, "--force",
                          "--final-state", "", "--retries", "1", "--workers", "1"])
            self.assertEqual(rc, 3)
            self.assertEqual(os.listdir(dest), ["marker"])

    def test_pin_mismatch_of_a_forced_fetch_leaves_the_old_corpus_intact(self):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX) as url:
            dest = self.make_old(t)
            ref = os.path.join(t, "x.ref")
            with open(ref, "w", encoding="utf-8") as f:
                f.write(f"endpoint={url}\nrounds=50\nmanifest_sha256={'0' * 64}\n"
                        f"final_state={final_state_file(t, PREFIX)}\n")
            rc = ft.main(["fetch", "--ref", ref, "--dest", dest, "--force",
                          "--name", "testnet-prefix50", "--workers", "2"])
            self.assertEqual(rc, 1)
            self.assertEqual(os.listdir(dest), ["marker"])

    def test_successful_forced_fetch_replaces_it(self):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX) as url:
            dest = self.make_old(t)
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--endpoint", url,
                          "--rounds", "50", "--dest", dest, "--workers", "2", "--force",
                          "--name", "testnet-prefix50", "--final-state",
                          final_state_file(t, PREFIX)])
            self.assertEqual(rc, 0)
            self.assertEqual(ct.compare(dest, PREFIX), [])
            self.assertFalse(os.path.exists(dest + ".old"))


class DroppedConnectionTests(unittest.TestCase):
    """T2: a body cut short mid-transfer is retried like any network error."""

    def args(self, t, url, retries):
        return ["fetch", "--ref", os.path.join(t, "none"), "--endpoint", url,
                "--rounds", "50", "--dest", os.path.join(t, "c"), "--workers", "2",
                "--retries", retries, "--final-state", ""]

    def test_a_truncated_body_is_retried_and_the_fetch_succeeds(self):
        with tempfile.TemporaryDirectory() as t, \
                endpoint(PREFIX, truncate={7: 1, 20: 2}) as url, \
                mock.patch.object(ft.time, "sleep", lambda s: None):
            self.assertEqual(ft.main(self.args(t, url, "4")), 0)
            self.assertEqual(ct.verify_manifest(os.path.join(t, "c")), [])

    def test_a_body_that_never_completes_exits_3(self):
        with tempfile.TemporaryDirectory() as t, endpoint(PREFIX, truncate={7: None}) as url, \
                mock.patch.object(ft.time, "sleep", lambda s: None):
            self.assertEqual(ft.main(self.args(t, url, "2")), 3)
            self.assertFalse(os.path.exists(os.path.join(t, "c")))

    def test_endpoint_get_retries_incomplete_read_and_connection_errors(self):
        import http.client
        ep = ft.Endpoint("http://x", retries=3, timeout=1)
        calls = []

        class Resp:
            def __init__(self, exc):
                self.exc = exc

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                if self.exc:
                    raise self.exc
                return b"ok"

        excs = [http.client.IncompleteRead(b"ab", 5), ConnectionResetError("reset"), None]

        def fake(url, timeout):
            calls.append(url)
            return Resp(excs[len(calls) - 1])

        with mock.patch.object(ft.urllib.request, "urlopen", fake), \
                mock.patch.object(ft.time, "sleep", lambda s: None):
            self.assertEqual(ep.get("/x"), b"ok")
        self.assertEqual(len(calls), 3)


class TruncatedMsgpackTests(unittest.TestCase):
    """T5: a payload shorter than its own length headers is never a block."""

    def test_truncated_records_are_refused_at_every_cut(self):
        recs = records(os.path.join(PREFIX, "blocks.bin"))
        payload = recs[10]
        self.assertEqual(ct.block_round(payload), 10)
        for cut in (0, 1, 5, 40, len(payload) // 3, len(payload) // 2,
                    len(payload) - 100, len(payload) - 2, len(payload) - 1):
            with self.assertRaises(ValueError, msg=f"cut at {cut}"):
                ct.block_round(payload[:cut])

    def test_a_bin_header_that_overshoots_the_buffer_is_refused(self):
        # map{"block": bin32 claiming 1 MB, 3 bytes present}
        body = b"\x82\xa5block\xc6\x00\x10\x00\x00abc\xa4cert\x80"
        with self.assertRaises(ValueError):
            ct.block_round(body)
        with self.assertRaises(ValueError):
            ct.mp_decode(b"\xc4\x10abc")
        with self.assertRaises(ValueError):
            ct.mp_decode(b"\xd9\x40abc")
        with self.assertRaises(ValueError):
            ct.mp_decode(b"\xd6\x01")  # fixext 4 with 1 byte

    def test_a_truncated_200_body_is_not_stored(self):
        recs = records(os.path.join(PREFIX, "blocks.bin"))
        with tempfile.TemporaryDirectory() as t, \
                endpoint(PREFIX, overrides={7: recs[7][:len(recs[7]) - 30]}) as url:
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--endpoint", url,
                          "--rounds", "50", "--dest", os.path.join(t, "c"), "--workers", "2",
                          "--retries", "1", "--final-state", ""])
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(os.path.join(t, "c")))

    def test_corrupt_vote_reports_value_errors(self):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "blocks.bin")
            with open(p, "wb") as f:
                f.write(ct.BLOCKS_MAGIC)
            with self.assertRaises(ValueError):
                ct.corrupt_vote(p)  # no records
            shutil.copy(os.path.join(PREFIX, "blocks.bin"), p)
            with self.assertRaises(ValueError):
                ct.corrupt_vote(p, rnd=9999)  # no such round
            with self.assertRaises(ValueError):
                ct.corrupt_vote(os.path.join(t, "missing.bin"))

    def test_the_tier_reports_a_tier_error_for_an_unusable_corpus(self):
        with tempfile.TemporaryDirectory() as t:
            d = os.path.join(t, "c")
            os.mkdir(d)
            with open(os.path.join(d, "blocks.bin"), "wb") as f:
                f.write(ct.BLOCKS_MAGIC)
            with self.assertRaises(replay.TierError):
                replay.corrupt_corpus(d, os.path.join(t, "x"), "vote")


class NetworkPinTests(unittest.TestCase):
    """T7: the ref pins the network's genesis hash, so a self-consistent
    endpoint of another network is refused."""

    REAL = ct.load_corpus_json(PREFIX)["network"]["genesis_hash"]

    def other_network(self):
        g = json.loads(read(os.path.join(PREFIX, "genesis.json")))
        g["alloc"][0]["state"]["algo"] += 1
        raw = json.dumps(g).encode()
        return raw, ft.genesis_hash_b64(raw)

    def test_a_self_consistent_endpoint_of_another_network_is_refused(self):
        raw, h = self.other_network()
        with tempfile.TemporaryDirectory() as t, \
                endpoint(PREFIX, genesis=raw, genesis_hash=h) as url:
            ref = os.path.join(t, "x.ref")
            with open(ref, "w", encoding="utf-8") as f:
                f.write(f"endpoint={url}\nrounds=50\ngenesis_hash={self.REAL}\n")
            dest = os.path.join(t, "c")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = ft.main(["fetch", "--ref", ref, "--dest", dest, "--workers", "2",
                              "--final-state", "", "--name", "testnet-prefix50"])
            self.assertEqual(rc, 1)
            self.assertIn("wrong network", err.getvalue())
            self.assertFalse(os.path.exists(dest))

    def test_the_same_endpoint_without_a_pin_would_be_accepted(self):
        raw, h = self.other_network()
        with tempfile.TemporaryDirectory() as t, \
                endpoint(PREFIX, genesis=raw, genesis_hash=h) as url:
            rc = ft.main(["fetch", "--ref", os.path.join(t, "none"), "--endpoint", url,
                          "--rounds", "50", "--dest", os.path.join(t, "c"), "--workers", "2",
                          "--final-state", ""])
            self.assertEqual(rc, 0)

    def test_the_committed_refs_pin_testnets_genesis_hash(self):
        for name in ("testnet-head.ref", "testnet-prefix50.ref"):
            ref = ft.read_ref(os.path.join(REPO, "benchmarks", "corpus", name))
            self.assertEqual(ref.get("genesis_hash"), self.REAL, name)


class CachePinTests(unittest.TestCase):
    """T4: the auto-fetched testnet-head cache must match the ref's pin."""

    def setup_root(self, t, pin, manifest_text):
        root = os.path.join(t, "repo")
        corpus = os.path.join(root, "benchmarks", "corpus")
        os.makedirs(os.path.join(corpus, "testnet-head"))
        with open(os.path.join(corpus, "testnet-head.ref"), "w", encoding="utf-8") as f:
            f.write(f"endpoint=http://x\nrounds=1\nmanifest_sha256={pin}\n")
        with open(os.path.join(corpus, "testnet-head", "corpus.json"), "w") as f:
            f.write("{}")
        with open(os.path.join(corpus, "testnet-head", ct.MANIFEST), "wb") as f:
            f.write(manifest_text.encode())
        return root

    def resolve(self, root):
        env = {"BENCH_CORPUS": "testnet-head"}
        with mock.patch.object(replay, "REPO", root), \
                mock.patch.dict(os.environ, env), \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BENCH_CORPUS_DIR", None)
            os.environ.pop("CORPUS", None)
            return replay.resolve_corpus()

    def test_a_cache_with_the_pinned_manifest_is_accepted(self):
        text = "a" * 64 + "  blocks.bin\n"
        pin = hashlib.sha256(text.encode()).hexdigest()
        with tempfile.TemporaryDirectory() as t:
            root = self.setup_root(t, pin, text)
            self.assertTrue(self.resolve(root).endswith("testnet-head"))

    def test_a_foreign_cache_is_refused_clearly(self):
        text = "a" * 64 + "  blocks.bin\n"
        with tempfile.TemporaryDirectory() as t:
            root = self.setup_root(t, "0" * 64, text)
            with self.assertRaises(replay.TierError) as cm:
                self.resolve(root)
            self.assertIn("pins", str(cm.exception))
            self.assertIn("testnet-head", str(cm.exception))

    def test_an_unpinned_ref_does_not_block_the_cache(self):
        with tempfile.TemporaryDirectory() as t:
            root = self.setup_root(t, "PENDING", "x\n")
            self.assertTrue(self.resolve(root).endswith("testnet-head"))


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


LABEL = "10000#" + "A" * 52


@contextlib.contextmanager
def catchpoint_endpoint(served, genesis_hash="GH", label=LABEL):
    """An algod endpoint serving a block response for every round in `served`,
    the genesis hash and the channel's latest catchpoint label."""
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, body):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            m = re.fullmatch(r"/v2/blocks/(\d+)\?format=msgpack", self.path)
            if self.path == "/v2/transactions/params":
                return self.reply(json.dumps({"genesis-hash": genesis_hash}).encode())
            if self.path == "/channel/latest.catchpoint":
                return self.reply(label.encode() + b"\n")
            if m and int(m.group(1)) in served:
                n = int(m.group(1))
                return self.reply(ft._mp_map({
                    "block": ft._mp_map({"rnd": ft._mp_uint(n)}), "cert": ft._mp_map({})}))
            self.send_error(404)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


class PlanCatchpointTests(unittest.TestCase):
    """The catchpoint-start corpus plan (issue #2146)."""

    def test_label_parsing(self):
        self.assertEqual(ft.parse_catchpoint_label(LABEL + "\n"), (10000, "A" * 52))
        for bad in ("", "10000", "0#" + "A" * 52, "x#" + "A" * 52, "10000#" + "A" * 51,
                    "10000#" + "a" * 52, "10000#" + "1" * 52, "10001#" + "A" * 52):
            with self.assertRaises(ft.FetchError, msg=bad):
                ft.parse_catchpoint_label(bad)

    def test_plan_resolves_the_channel_label_and_checks_the_range(self):
        with tempfile.TemporaryDirectory() as t, \
                catchpoint_endpoint({10001, 10050}) as url:
            ref = os.path.join(t, "in.ref")
            with open(ref, "w", encoding="utf-8") as f:
                f.write("genesis_hash=GH\n")
            out = os.path.join(t, "out.ref")
            rc = ft.main(["plan-catchpoint", "--ref", ref, "--endpoint", url, "--rounds", "50",
                          "--channel-url", url + "/channel/latest.catchpoint",
                          "--out", out, "--retries", "1"])
            self.assertEqual(rc, 0)
            got = ft.read_ref(out)
            self.assertEqual(got["catchpoint"], LABEL)
            self.assertEqual((got["catchpoint_round"], got["rounds"]), ("10000", "50"))
            self.assertEqual((got["endpoint"], got["genesis_hash"]), (url, "GH"))

    def test_plan_refuses_an_endpoint_that_does_not_serve_the_range(self):
        with tempfile.TemporaryDirectory() as t, catchpoint_endpoint({10001}) as url:
            out = os.path.join(t, "out.ref")
            rc = ft.main(["plan-catchpoint", "--ref", os.path.join(t, "none"), "--endpoint", url,
                          "--rounds", "50", "--label", LABEL, "--out", out, "--retries", "1"])
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(out))

    def test_plan_refuses_another_network(self):
        with tempfile.TemporaryDirectory() as t, \
                catchpoint_endpoint({10001, 10050}, genesis_hash="OTHER") as url:
            ref = os.path.join(t, "in.ref")
            with open(ref, "w", encoding="utf-8") as f:
                f.write("genesis_hash=GH\n")
            out = os.path.join(t, "out.ref")
            rc = ft.main(["plan-catchpoint", "--ref", ref, "--endpoint", url, "--rounds", "50",
                          "--label", LABEL, "--out", out, "--retries", "1"])
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(out))

    def test_the_committed_plan_is_well_formed(self):
        ref = ft.read_ref(os.path.join(REPO, "benchmarks", "corpus", "testnet-catchpoint.ref"))
        rnd, _ = ft.parse_catchpoint_label(ref["catchpoint"])
        self.assertEqual(int(ref["catchpoint_round"]), rnd)
        self.assertGreaterEqual(int(ref["rounds"]), 1)
        self.assertEqual(ref["genesis_hash"], ft.read_ref(REF)["genesis_hash"])
        self.assertTrue(os.path.isfile(os.path.join(REPO, "docs", "BENCH_CATCHPOINT_REPLAY.md")))
        # the committed final state (derived from the go replay, identical to
        # the Rust one) is for the last round of the planned range
        with open(os.path.join(REPO, ref["final_state"]), encoding="utf-8") as f:
            fs = json.load(f)
        self.assertEqual(fs["round"], rnd + int(ref["rounds"]))
        self.assertEqual(sorted(fs), sorted(ft.STATE_KEYS + ("round", "block_hash",
                                                             "txn_counter")))
        self.assertTrue(ref["catchpoint_source"].startswith("http"))


SMALL_CP = os.path.join(REPO, "benchmarks", "corpus", "small-catchpoint")
GO_TESTDATA = os.path.join(REPO, "benchmarks", "go-replay", "testdata")
CP_LABEL = read(os.path.join(GO_TESTDATA, "small-catchpoint-1500.label")).decode().strip()
CP_TAR = os.path.join(GO_TESTDATA, "small-catchpoint-1500.tar")


@contextlib.contextmanager
def slice_endpoint(corpus, round_):
    """An algod endpoint serving the rounds of a catchpoint corpus, the header of
    the catchpoint round (no state proof tracking: a DevMode chain) and the
    attested last block."""
    cj = ct.load_corpus_json(corpus)
    blocks = records(os.path.join(corpus, "blocks.bin"))
    last = cj["rounds"]["last"]
    fs = cj["final_state"]
    genesis = read(os.path.join(corpus, "genesis.json"))

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, body):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            m = re.fullmatch(r"/v2/blocks/(\d+)\?format=msgpack", self.path)
            if self.path == "/genesis":
                return self.reply(genesis)
            if self.path == "/v2/transactions/params":
                return self.reply(json.dumps({
                    "genesis-id": cj["network"]["genesis_id"],
                    "genesis-hash": cj["network"]["genesis_hash"]}).encode())
            if m and int(m.group(1)) in blocks:
                return self.reply(blocks[int(m.group(1))])
            if self.path == f"/v2/blocks/{round_}?header-only=true":
                return self.reply(json.dumps({"block": {"rnd": round_}}).encode())
            if self.path == f"/v2/blocks/{last}/hash":
                return self.reply(json.dumps({"blockHash": fs["block_hash"][len("blk-"):]}).encode())
            if self.path == f"/v2/blocks/{last}?header-only=true":
                return self.reply(json.dumps(
                    {"block": {"rnd": last, "tc": fs["txn_counter"]}}).encode())
            self.send_error(404)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


class CatchpointCorpusTests(unittest.TestCase):
    """The catchpoint-start corpus (issue #2293)."""

    def test_the_committed_small_catchpoint_corpus_is_valid(self):
        self.assertEqual(ct.verify(SMALL_CP, coverage=False), [])
        cj = ct.load_corpus_json(SMALL_CP)
        self.assertEqual(cj["start"]["catchpoint"], CP_LABEL)
        self.assertEqual(cj["rounds"], {"first": 179, "last": 2000, "count": 1822})
        self.assertEqual(sorted(records(os.path.join(SMALL_CP, "blocks.bin")))[:2], [179, 180])

    def test_validate_start_refuses_inconsistent_starts(self):
        base = ct.load_corpus_json(SMALL_CP)
        for patch in ({"round": 1499}, {"catchpoint": "1500#short"}, {"file": "other.tar"}):
            cj = json.loads(json.dumps(base))
            cj["start"].update(patch)
            self.assertTrue(ct.validate_corpus_json(cj, coverage=False), patch)
        cj = json.loads(json.dumps(base))
        cj["rounds"]["first"], cj["rounds"]["count"] = 1600, 401
        self.assertTrue(ct.validate_corpus_json(cj, coverage=False))

    def test_derive_reproduces_the_committed_corpus(self):
        with tempfile.TemporaryDirectory() as t:
            dest = os.path.join(t, "d")
            ct.derive_catchpoint_corpus(SMALL, dest, CP_TAR, CP_LABEL, 179)
            for name in ("blocks.bin", "catchpoint.tar", "genesis.json", "consensus.json"):
                self.assertEqual(read(os.path.join(dest, name)),
                                 read(os.path.join(SMALL_CP, name)), name)
            a, b = ct.load_corpus_json(dest), ct.load_corpus_json(SMALL_CP)
            for k in ("rounds", "start", "files", "network"):
                self.assertEqual(a[k], b[k], k)
            # the account digest of a cut corpus is its own (finalize-known)
            self.assertNotEqual(a["final_state"]["accounts_sha256"],
                                b["final_state"]["accounts_sha256"])
        with self.assertRaises(ValueError):
            ct.derive_catchpoint_corpus(SMALL, os.path.join(t, "x"), CP_TAR, CP_LABEL, 0)

    def test_lookback_matches_gos_formula(self):
        # no state proofs pending: go's MaxTxnLife + DeeperBlockHeaderHistory +
        # CatchpointLookback = 1321
        self.assertEqual(ft.catchpoint_lookback(69120000, 69120000), 1321)
        self.assertEqual(ft.catchpoint_lookback(1500, 0), 1321)
        # a state proof ten intervals behind needs more than that
        self.assertEqual(ft.catchpoint_lookback(69120000, 69110000), 2832)
        # trimmed to round - 1 when the chain is shorter
        self.assertEqual(ft.catchpoint_lookback(1000, 0), 999)

    def test_block_coverage_counts_payouts_state_proofs_and_apps(self):
        small = records(os.path.join(SMALL, "blocks.bin"))
        cov = ft.range_coverage(os.path.join(SMALL, "blocks.bin"), 0)
        self.assertEqual((cov["proposer_payouts"], cov["state_proofs"]), (0, 0))
        self.assertGreater(cov["app_calls"], 0)
        self.assertEqual(ft.block_coverage(small[1])[1:], (0, cov["app_calls"] and ft.block_coverage(small[1])[2]))
        with self.assertRaises(ft.FetchError):
            ft.coverage_gate(cov)
        ft.coverage_gate({"proposer_payouts": 1, "state_proofs": 1, "app_calls": 1})

    def _ref(self, t, url):
        ref = os.path.join(t, "cp.ref")
        with open(ref, "w", encoding="utf-8") as f:
            f.write(f"endpoint={url}\ncatchpoint={CP_LABEL}\ncatchpoint_round=1500\nrounds=500\n"
                    f"genesis_hash={ct.load_corpus_json(SMALL_CP)['network']['genesis_hash']}\n")
        return ref

    def test_fetch_catchpoint_builds_the_corpus_the_ref_describes(self):
        cj0 = ct.load_corpus_json(SMALL_CP)
        with tempfile.TemporaryDirectory() as t, slice_endpoint(SMALL_CP, 1500) as url:
            dest = os.path.join(t, "c")
            rc = ft.main(["fetch-catchpoint", "--ref", self._ref(t, url), "--dest", dest,
                          "--catchpoint-file", CP_TAR, "--allow-uncovered",
                          "--final-state", final_state_file(t, SMALL_CP), "--workers", "4",
                          "--name", "small-catchpoint"])
            self.assertEqual(rc, 0)
            self.assertEqual(ct.verify(dest, coverage=False), [])
            for name in ("blocks.bin", "catchpoint.tar", "genesis.json"):
                self.assertEqual(read(os.path.join(dest, name)),
                                 read(os.path.join(SMALL_CP, name)), name)
            cj = ct.load_corpus_json(dest)
            self.assertEqual(cj["rounds"], cj0["rounds"])
            self.assertEqual(cj["start"]["catchpoint"], CP_LABEL)
            self.assertEqual(cj["start"]["coverage"]["state_proofs"], 0)
            self.assertEqual(cj["final_state"], cj0["final_state"])

    def test_fetch_catchpoint_refuses_a_range_without_state_proofs_or_payouts(self):
        with tempfile.TemporaryDirectory() as t, slice_endpoint(SMALL_CP, 1500) as url:
            dest = os.path.join(t, "c")
            rc = ft.main(["fetch-catchpoint", "--ref", self._ref(t, url), "--dest", dest,
                          "--catchpoint-file", CP_TAR, "--workers", "4", "--retries", "1"])
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(dest))
            self.assertFalse(os.path.exists(dest + ".partial"))

    def test_fetch_catchpoint_refuses_a_file_of_another_catchpoint(self):
        with tempfile.TemporaryDirectory() as t, slice_endpoint(SMALL_CP, 1500) as url:
            ref = self._ref(t, url)
            text = read(ref).decode().replace(CP_LABEL, "1000#" + CP_LABEL.split("#")[1])
            with open(ref, "w", encoding="utf-8") as f:
                f.write(text)
            rc = ft.main(["fetch-catchpoint", "--ref", ref, "--dest", os.path.join(t, "c"),
                          "--catchpoint-file", CP_TAR, "--allow-uncovered", "--workers", "2",
                          "--retries", "1"])
            self.assertEqual(rc, 1)

    def test_the_tier_fetches_a_missing_testnet_catchpoint_corpus(self):
        with tempfile.TemporaryDirectory() as t:
            calls = []

            class P:
                returncode = 0

            def fake_run(cmd, *a, **k):
                calls.append(cmd)
                return P()

            with mock.patch.object(replay, "REPO", t), \
                    mock.patch.dict(os.environ, {"BENCH_CORPUS": "testnet-catchpoint"}), \
                    mock.patch.object(replay.subprocess, "run", fake_run):
                os.environ.pop("BENCH_CORPUS_DIR", None)
                with self.assertRaises(replay.TierError):  # the fake fetched nothing
                    replay.resolve_corpus()
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][-1], "fetch-catchpoint")


if __name__ == "__main__":
    unittest.main()
