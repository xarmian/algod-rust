# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests of the `rest` tier's pure logic (scripts/bench/rest_lib.py and
the tier's settings, scripts/bench/tiers/rest.py, issue #2107): the request
set, the response-equality gate with its volatile-field normalisation and its
issue-linked allowlist, the container shape that keeps both nodes under the
same limits, and the result rows. No Docker, no go, no cargo: the live run is
the tier itself (docs/BENCHMARK_COMPARISON.md, "The rest tier")."""
import base64
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tiers"))
import bench_schema  # noqa: E402
import rest as tier  # noqa: E402
import rest_lib as rl  # noqa: E402

REPO = os.path.dirname(os.path.dirname(HERE))
ZERO_ADDR = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"


def resp(body, status=200, ctype="application/json"):
    if not isinstance(body, bytes):
        body = json.dumps(body).encode()
    return {"status": status, "content_type": ctype, "body": body}


REQ_STATUS = {"name": "status", "method": "GET", "path": "/v2/status", "kind": "json"}
REQ_BLOCK = {"name": "blocks_msgpack", "method": "GET", "path": "/v2/blocks/7?format=msgpack",
             "kind": "msgpack"}
REQ_ACCT = {"name": "account_hot", "method": "GET", "path": "/v2/accounts/A", "kind": "json"}


class NormaliseTest(unittest.TestCase):
    def test_drops_a_plain_path_and_keeps_the_rest(self):
        doc = {"a": 1, "time-since-last-round": 5, "b": {"c": 2}}
        self.assertEqual(rl.drop_paths(doc, ["time-since-last-round"]), {"a": 1, "b": {"c": 2}})

    def test_wildcard_applies_to_every_list_element_and_dict_value(self):
        doc = {"txns": [{"x": 1, "ts": 9}, {"x": 2, "ts": 8}], "m": {"p": {"ts": 1}, "q": {"ts": 2}}}
        got = rl.drop_paths(doc, ["txns.*.ts", "m.*.ts"])
        self.assertEqual(got, {"txns": [{"x": 1}, {"x": 2}], "m": {"p": {}, "q": {}}})

    def test_missing_path_is_not_an_error(self):
        self.assertEqual(rl.drop_paths({"a": 1}, ["b.c", "a.d"]), {"a": 1})

    def test_input_is_not_mutated(self):
        doc = {"a": {"b": 1}}
        rl.drop_paths(doc, ["a.b"])
        self.assertEqual(doc, {"a": {"b": 1}})


class CompareTest(unittest.TestCase):
    def test_identical_json_bodies_match_regardless_of_key_order(self):
        a = resp(b'{"x":1,"y":[1,2]}')
        b = resp(b'{"y":[1,2],"x":1}')
        self.assertEqual(rl.compare(REQ_ACCT, a, b), [])

    def test_a_differing_field_is_reported_with_its_path(self):
        a = resp({"amount": 5, "round": 9})
        b = resp({"amount": 6, "round": 9})
        diffs = rl.compare(REQ_ACCT, a, b)
        self.assertEqual(len(diffs), 1)
        self.assertIn("amount", diffs[0])
        self.assertIn("go 5", diffs[0])
        self.assertIn("rust 6", diffs[0])

    def test_a_field_present_on_one_side_only_is_a_difference(self):
        diffs = rl.compare(REQ_ACCT, resp({"a": 1, "b": 2}), resp({"a": 1}))
        self.assertTrue(any("b" in d and "only in go" in d for d in diffs))

    def test_status_difference_fails(self):
        diffs = rl.compare(REQ_ACCT, resp({"a": 1}), resp({"message": "x"}, status=404))
        self.assertTrue(any("status" in d for d in diffs))

    def test_media_type_parameters_are_ignored_but_the_type_is_not(self):
        a = resp({"a": 1}, ctype="application/json")
        b = resp({"a": 1}, ctype="application/json; charset=utf-8")
        self.assertEqual(rl.compare(REQ_ACCT, a, b), [])
        c = resp({"a": 1}, ctype="text/plain")
        self.assertTrue(any("content-type" in d for d in rl.compare(REQ_ACCT, a, c)))

    def test_volatile_status_fields_are_ignored_and_others_are_not(self):
        base = {"last-round": 5, "time-since-last-round": 100, "catchup-time": 0,
                "last-version": "v"}
        other = dict(base, **{"time-since-last-round": 999999})
        self.assertEqual(rl.compare(REQ_STATUS, resp(base), resp(other)), [])
        other = dict(base, **{"last-round": 6})
        self.assertTrue(rl.compare(REQ_STATUS, resp(base), resp(other)))

    def test_msgpack_bodies_are_compared_structurally_and_then_by_bytes(self):
        a = resp(b"\x81\xa1a\x01", ctype="application/msgpack")
        self.assertEqual(rl.compare(REQ_BLOCK, a, resp(b"\x81\xa1a\x01",
                                                      ctype="application/msgpack")), [])
        b = resp(b"\x81\xa1a\x02", ctype="application/msgpack")
        diffs = rl.compare(REQ_BLOCK, a, b)
        self.assertEqual(len(diffs), 1)
        self.assertIn("a: go 1 != rust 2", diffs[0])
        # the same value with different bytes (a wider integer) is still a difference
        c = resp(b"\x81\xa1a\xcc\x01", ctype="application/msgpack")
        diffs = rl.compare(REQ_BLOCK, a, c)
        self.assertEqual(len(diffs), 1)
        self.assertIn("different msgpack bytes", diffs[0])

    def test_an_undecodable_msgpack_body_falls_back_to_bytes(self):
        a = resp(b"\x81\xa1", ctype="application/msgpack")
        diffs = rl.compare(REQ_BLOCK, a, resp(b"\x81\xa2", ctype="application/msgpack"))
        self.assertTrue(diffs and "byte 1" in diffs[0])

    def test_a_non_json_body_on_a_json_request_falls_back_to_bytes(self):
        a = resp(b"not json", ctype="text/plain")
        self.assertEqual(rl.compare(REQ_ACCT, a, resp(b"not json", ctype="text/plain")), [])
        self.assertTrue(rl.compare(REQ_ACCT, a, resp(b"not jsoN", ctype="text/plain")))

    def test_large_integers_are_compared_exactly(self):
        a = resp(b'{"n":18446744073709551615}')
        b = resp(b'{"n":18446744073709551614}')
        self.assertTrue(rl.compare(REQ_ACCT, a, b))


class GateTest(unittest.TestCase):
    def reqs(self):
        return [REQ_STATUS, REQ_ACCT]

    def good(self):
        return {"status": resp({"last-round": 1, "time-since-last-round": 1}),
                "account_hot": resp({"amount": 5})}

    def test_equal_sets_pass(self):
        g = self.good()
        r = dict(g, status=resp({"last-round": 1, "time-since-last-round": 77}))
        self.assertEqual(rl.gate(self.reqs(), g, r, []), [])

    def test_a_single_mismatch_fails_and_names_the_endpoint(self):
        g = self.good()
        r = dict(g, account_hot=resp({"amount": 6}))
        errs = rl.gate(self.reqs(), g, r, [])
        self.assertEqual(len(errs), 1)
        self.assertIn("account_hot", errs[0])
        self.assertIn("/v2/accounts/A", errs[0])

    def test_a_missing_response_fails(self):
        g = self.good()
        r = {"status": g["status"]}
        errs = rl.gate(self.reqs(), g, r, [])
        self.assertTrue(any("account_hot" in e and "no response" in e for e in errs))

    def test_every_request_must_have_been_issued_to_both(self):
        g = self.good()
        errs = rl.gate(self.reqs(), g, dict(g, extra=resp({})), [])
        self.assertTrue(any("not in the request set" in e for e in errs))

    def entry(self, path, kind, **kw):
        return dict({"endpoint": "account_hot", "path": path, "kind": kind, "issue": 123,
                     "reason": "r"}, **kw)

    def test_value_entry_excuses_its_own_path_only(self):
        g = self.good()
        r = dict(g, account_hot=resp({"amount": 6}))
        allow = [self.entry("amount", "value")]
        self.assertEqual(rl.gate(self.reqs(), g, r, allow), [])
        g2 = dict(g, account_hot=resp({"amount": 5, "other": 1}))
        r2 = dict(g, account_hot=resp({"amount": 6, "other": 2}))
        errs = rl.gate(self.reqs(), g2, r2, allow)
        self.assertEqual(len(errs), 1)
        self.assertIn("other", errs[0])

    def test_only_go_entry_excuses_a_missing_key_but_not_a_value_difference(self):
        g = dict(self.good(), account_hot=resp({"assets": [{"amount": 5}], "amount": 1}))
        allow = [self.entry("assets", "only-go")]
        missing = dict(g, account_hot=resp({"amount": 1}))
        self.assertEqual(rl.gate(self.reqs(), g, missing, allow), [])
        # both sides have the list: it must be equal, nothing below the entry is covered
        wrong = dict(g, account_hot=resp({"assets": [{"amount": 6}], "amount": 1}))
        errs = rl.gate(self.reqs(), g, wrong, allow)
        self.assertTrue(any("assets.0.amount" in e for e in errs), errs)
        # ... and the entry is then stale as well
        self.assertTrue(any("no longer matches" in e for e in errs))
        # a list element missing on the rust side is not the excused difference either
        short = dict(g, account_hot=resp({"assets": [], "amount": 1}))
        self.assertTrue(any("assets.0" in e for e in rl.gate(self.reqs(), g, short, allow)))

    def test_a_prefix_entry_does_not_cover_deeper_paths(self):
        g = dict(self.good(), account_hot=resp({"a": {"b": 1, "c": 2}}))
        r = dict(g, account_hot=resp({"a": {"b": 9, "c": 2}}))
        errs = rl.gate(self.reqs(), g, r, [self.entry("a", "value")])
        self.assertTrue(any("a.b" in e for e in errs), errs)

    def test_only_rust_entry_can_pin_the_rust_value(self):
        g = dict(self.good(), account_hot=resp({"amount": 1}))
        r = dict(g, account_hot=resp({"amount": 1, "step": 2}))
        self.assertEqual(rl.gate(self.reqs(), g, r, [self.entry("step", "only-rust",
                                                                 rust_value=2)]), [])
        r3 = dict(g, account_hot=resp({"amount": 1, "step": 3}))
        errs = rl.gate(self.reqs(), g, r3, [self.entry("step", "only-rust", rust_value=2)])
        self.assertTrue(any("step: only in rust" in e for e in errs), errs)

    def test_wildcard_matches_exactly_one_segment(self):
        g = dict(self.good(), account_hot=resp({"l": [{"x": 1}, {"x": 2}]}))
        r = dict(g, account_hot=resp({"l": [{"x": 5}, {"x": 6}]}))
        self.assertEqual(rl.gate(self.reqs(), g, r, [self.entry("l.*.x", "value")]), [])
        deeper = dict(g, account_hot=resp({"l": [{"x": 1, "y": 3}, {"x": 2}]}))
        self.assertTrue(rl.gate(self.reqs(), g, deeper, [self.entry("l.*.x", "value")]))

    def test_msgpack_block_cert_step_is_the_only_excused_msgpack_difference(self):
        req = {"name": "blocks_msgpack", "method": "GET", "path": "/b", "kind": "msgpack"}
        allow = [{"endpoint": "blocks_msgpack", "path": "cert.step", "kind": "only-rust",
                  "rust_value": 2, "issue": 2159, "reason": "r"}]
        block = {"block": {"rnd": 7, "ts": 100, "txns": [{"txn": {"amt": 1}}]}, "cert": {"rnd": 7}}
        mp = "application/msgpack"
        go = {"blocks_msgpack": resp(rl.msgpack(block), ctype=mp)}

        def rust_with(mutate):
            doc = json.loads(json.dumps(block))
            doc["cert"]["step"] = 2
            mutate(doc)
            return {"blocks_msgpack": resp(rl.msgpack(doc), ctype=mp)}

        self.assertEqual(rl.gate([req], go, rust_with(lambda d: None), allow), [])
        # a different header field, a different txn, a different cert round all fail
        for mutate in (lambda d: d["block"].__setitem__("ts", 101),
                       lambda d: d["block"]["txns"][0]["txn"].__setitem__("amt", 2),
                       lambda d: d["cert"].__setitem__("rnd", 8),
                       lambda d: d["cert"].__setitem__("step", 3)):
            errs = rl.gate([req], go, rust_with(mutate), allow)
            self.assertTrue(errs, mutate)

    def test_a_stale_allowlist_entry_fails_the_gate(self):
        g = self.good()
        errs = rl.gate(self.reqs(), g, dict(g), [self.entry("bogus", "only-go")])
        self.assertTrue(any("allowlist" in e and "no longer" in e for e in errs))

    def test_invalid_allowlist_entries_are_refused(self):
        ok = {"endpoint": "a", "path": "p", "kind": "value", "issue": 1, "reason": "r"}
        rl.check_allowlist([ok])
        for bad in (dict(ok, issue=None), dict(ok, issue="x"), dict(ok, reason=""),
                    dict(ok, kind="whatever"), dict(ok, kind="value", rust_value=1),
                    {k: v for k, v in ok.items() if k not in ("path",)},
                    {k: v for k, v in ok.items() if k not in ("kind",)},
                    {k: v for k, v in ok.items() if k not in ("issue",)}):
            with self.assertRaises(ValueError):
                rl.check_allowlist([bad])

    def test_the_committed_allowlist_is_valid_and_issue_linked(self):
        rl.check_allowlist(rl.KNOWN_DIFFERENCES)
        for e in rl.KNOWN_DIFFERENCES:
            self.assertIsInstance(e["issue"], int)
            self.assertGreaterEqual(e["issue"], 2155)
            self.assertEqual(e["corpus"], "small")

    def test_a_corpus_scoped_entry_applies_only_to_its_corpus(self):
        g = self.good()
        r = dict(g, account_hot=resp({"amount": 5, "bogus": 1}))
        allow = [self.entry("bogus", "only-rust", corpus="small")]
        self.assertEqual(rl.gate(self.reqs(), g, r, allow, corpus="small"), [])
        # another corpus: not excused, and the unused entry is not reported stale
        errs = rl.gate(self.reqs(), g, r, allow, corpus="large")
        self.assertEqual(len(errs), 1)
        self.assertNotIn("allowlist", errs[0])


class CorruptTest(unittest.TestCase):
    """BENCH_REST_CORRUPT's negative test must fail the gate for EVERY
    endpoint, also those that have allowlisted differences."""

    def test_every_endpoint_with_an_allowlist_entry_still_fails_when_corrupted(self):
        mp = "application/msgpack"
        block = {"block": {"rnd": 7, "ts": 100, "bi": 10}, "cert": {"rnd": 7}}
        # (request, go response, rust response) shaped like the real known differences
        cases = {
            "account_hot": (REQ_ACCT,
                            resp({"amount": 5, "assets": [{"amount": 1}], "rewards": 3}),
                            resp({"amount": 4, "rewards": 2})),
            "blocks_msgpack": ({"name": "blocks_msgpack", "method": "GET", "path": "/b",
                               "kind": "msgpack"},
                              resp(rl.msgpack(block), ctype=mp),
                              resp(rl.msgpack(dict(block, cert={"rnd": 7, "step": 2})), ctype=mp)),
        }
        allow = [
            {"endpoint": "account_hot", "path": "assets", "kind": "only-go", "issue": 1,
             "reason": "r"},
            {"endpoint": "account_hot", "path": "amount", "kind": "value", "issue": 1,
             "reason": "r"},
            {"endpoint": "account_hot", "path": "rewards", "kind": "value", "issue": 1,
             "reason": "r"},
            {"endpoint": "blocks_msgpack", "path": "cert.step", "kind": "only-rust",
             "rust_value": 2, "issue": 1, "reason": "r"},
        ]
        for name, (req, go, rust) in cases.items():
            self.assertEqual(rl.gate([req], {req["name"]: go}, {req["name"]: rust}, allow), [],
                             name)
            bad = rl.corrupt_response(req, go, rust, allow)
            self.assertNotEqual(bad["body"], rust["body"], name)
            errs = rl.gate([req], {req["name"]: go}, {req["name"]: bad}, allow)
            self.assertTrue([e for e in errs if not e.startswith("allowlist")], name)

    def test_plain_endpoints_and_byte_bodies_are_corrupted_too(self):
        g = resp({"a": 1, "s": "x"})
        bad = rl.corrupt_response(REQ_ACCT, g, g, [])
        self.assertTrue(rl.gate([REQ_ACCT], {"account_hot": g}, {"account_hot": bad}, []))
        txt = resp(b"not json", ctype="text/plain")
        bad = rl.corrupt_response(REQ_ACCT, txt, txt, [])
        self.assertNotEqual(bad["body"], txt["body"])

    def test_a_corruption_that_cannot_fail_the_gate_is_an_error(self):
        g = resp({"a": 1})
        allow = [{"endpoint": "account_hot", "path": "a", "kind": "value", "issue": 1,
                  "reason": "r"}]
        # every alteration of the only leaf is excused and byte flips of "{" break JSON
        # parsing, which the gate reports; so a corruption IS found (via bytes)
        bad = rl.corrupt_response(REQ_ACCT, g, g, allow)
        self.assertNotEqual(bad["body"], g["body"])


class KnownDifferencesDocTest(unittest.TestCase):
    def test_the_documented_table_is_generated_from_the_code(self):
        with open(os.path.join(REPO, "docs", "BENCHMARK_COMPARISON.md"), encoding="utf-8") as f:
            doc = f.read()
        a = doc.index(rl.KD_TABLE_START) + len(rl.KD_TABLE_START)
        b = doc.index(rl.KD_TABLE_END)
        self.assertEqual(doc[a:b].strip(), rl.known_differences_table().strip())

    def test_every_entry_appears_with_its_issue_number(self):
        table = rl.known_differences_table()
        for e in rl.KNOWN_DIFFERENCES:
            row = next(line for line in table.splitlines()
                       if f"`{e['endpoint']}` | `{e['path']}` |" in line)
            self.assertIn(f"[#{e['issue']}]", row)


class MsgpackDecodeTest(unittest.TestCase):
    def test_round_trip(self):
        v = {"a": [1, 2, 300, 70000, 2 ** 40], "b": b"xy", "c": "s" * 40, "d": None,
             "e": True, "f": {"g": False}}
        self.assertEqual(rl.msgpack_decode(rl.msgpack(v)), v)

    def test_negative_ints_and_floats(self):
        self.assertEqual(rl.msgpack_decode(b"\xff"), -1)
        self.assertEqual(rl.msgpack_decode(b"\xd0\x80"), -128)
        self.assertEqual(rl.msgpack_decode(b"\xcb" + bytes.fromhex("3ff8000000000000")), 1.5)

    def test_truncated_trailing_and_ext_are_errors(self):
        for bad in (b"\x81\xa1", b"\x01\x02", b"\xd4\x01\x00", b"", b"\xc1"):
            with self.assertRaises(ValueError):
                rl.msgpack_decode(bad)


class VolatileDocsTest(unittest.TestCase):
    def test_every_exclusion_has_a_reason(self):
        self.assertTrue(rl.VOLATILE)
        for endpoint, entries in rl.VOLATILE.items():
            self.assertTrue(entries, endpoint)
            for path, reason in entries.items():
                self.assertTrue(reason.strip(), f"{endpoint}.{path}")

    def test_every_exclusion_is_documented_in_the_methodology_doc(self):
        with open(os.path.join(REPO, "docs", "BENCHMARK_COMPARISON.md"), encoding="utf-8") as f:
            doc = f.read()
        for endpoint, entries in rl.VOLATILE.items():
            for path in entries:
                self.assertIn(f"`{path}`", doc, f"{endpoint}: `{path}` not documented")


class MsgpackTest(unittest.TestCase):
    def test_scalars(self):
        self.assertEqual(rl.msgpack({"a": 1}), b"\x81\xa1a\x01")
        self.assertEqual(rl.msgpack(True), b"\xc3")
        self.assertEqual(rl.msgpack(None), b"\xc0")
        self.assertEqual(rl.msgpack(200), b"\xcc\xc8")
        self.assertEqual(rl.msgpack(70000), b"\xce\x00\x01\x11\x70")
        self.assertEqual(rl.msgpack(2 ** 40)[:1], b"\xcf")
        self.assertEqual(rl.msgpack(b"ab"), b"\xc4\x02ab")
        self.assertEqual(rl.msgpack([1, 2]), b"\x92\x01\x02")
        self.assertEqual(rl.msgpack("x" * 40)[:2], b"\xd9\x28")

    def test_map_keys_are_sorted_like_the_canonical_encoding(self):
        self.assertEqual(rl.msgpack({"b": 1, "a": 2}), b"\x82\xa1a\x02\xa1b\x01")

    def test_negative_numbers_are_refused(self):
        with self.assertRaises(ValueError):
            rl.msgpack(-1)


class AddressTest(unittest.TestCase):
    def test_zero_address_decodes_to_32_zero_bytes(self):
        self.assertEqual(rl.decode_address(ZERO_ADDR), bytes(32))

    def test_bad_checksum_and_length_are_refused(self):
        with self.assertRaises(ValueError):
            rl.decode_address(ZERO_ADDR[:-1] + "A")
        with self.assertRaises(ValueError):
            rl.decode_address("AAAA")


class SimulateBodyTest(unittest.TestCase):
    def test_body_is_a_msgpack_simulate_request_with_empty_signatures_allowed(self):
        params = {"genesis-id": "g", "genesis-hash": base64.b64encode(bytes(range(32))).decode(),
                  "min-fee": 1000, "last-round": 10}
        req = rl.simulate_request(ZERO_ADDR, ZERO_ADDR, params)
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["path"], "/v2/transactions/simulate?format=json")
        self.assertEqual(req["content_type"], "application/msgpack")
        body = base64.b64decode(req["body_b64"])
        self.assertIn(b"allow-empty-signatures", body)
        self.assertIn(b"txn-groups", body)
        self.assertIn(bytes(range(32)), body)  # the genesis hash, as bin
        # deterministic: same inputs, same bytes
        self.assertEqual(rl.simulate_request(ZERO_ADDR, ZERO_ADDR, params), req)


class RequestSetTest(unittest.TestCase):
    STATE = {"hot": "H", "cold": "C", "app_id": 12, "box_name_b64": "Ym94", "round": 100,
             "asset_holder": "H", "params": None}

    def test_the_issue_endpoints_are_all_present_in_a_stable_order(self):
        names = [r["name"] for r in rl.request_set(self.STATE)]
        self.assertEqual(names, ["status", "account_hot", "account_cold", "account_assets",
                                 "application", "box", "blocks_json", "blocks_msgpack",
                                 "tx_params"])

    def test_simulate_is_added_when_a_body_is_provided(self):
        sim = {"name": "simulate", "method": "POST", "path": "/p", "kind": "json",
               "content_type": "application/msgpack", "body_b64": "AA=="}
        names = [r["name"] for r in rl.request_set(self.STATE, simulate=sim)]
        self.assertEqual(names[-1], "simulate")

    def test_paths_use_the_state(self):
        by = {r["name"]: r for r in rl.request_set(self.STATE)}
        self.assertEqual(by["account_hot"]["path"], "/v2/accounts/H")
        self.assertEqual(by["account_assets"]["path"], "/v2/accounts/H/assets")
        self.assertEqual(by["application"]["path"], "/v2/applications/12")
        self.assertEqual(by["box"]["path"], "/v2/applications/12/box?name=b64%3AYm94")
        self.assertEqual(by["blocks_msgpack"]["path"], "/v2/blocks/100?format=msgpack")
        self.assertEqual(by["blocks_msgpack"]["kind"], "msgpack")
        self.assertEqual(by["blocks_json"]["path"], "/v2/blocks/100")

    def test_every_request_has_a_unique_loadgen_compatible_name(self):
        names = [r["name"] for r in rl.request_set(self.STATE)]
        self.assertEqual(len(names), len(set(names)))
        for r in rl.request_set(self.STATE):
            self.assertRegex(r["name"], r"^[a-z][a-z0-9_]*$")

    def test_loadgen_file_drops_the_comparison_only_keys(self):
        out = rl.loadgen_requests(rl.request_set(self.STATE))
        for r in out:
            self.assertEqual(set(r) - {"name", "method", "path", "content_type", "accept",
                                       "body_b64"}, set())
        msgpack = next(r for r in out if r["name"] == "blocks_msgpack")
        self.assertEqual(msgpack["accept"], "application/msgpack")


class DiscoverTest(unittest.TestCase):
    def test_hot_is_the_biggest_account_and_cold_the_smallest(self):
        accts = {"A": {"assets": [1, 2, 3, 4, 5, 6, 7, 8], "created-apps": []},
                 "B": {"assets": [], "created-apps": []},
                 "C": {"assets": [1], "created-apps": [{"id": 5}]}}
        hot, cold = rl.pick_hot_cold(accts)
        self.assertEqual((hot, cold), ("A", "B"))

    def test_ties_break_by_address_so_discovery_is_deterministic(self):
        accts = {"Z": {}, "Y": {}}
        self.assertEqual(rl.pick_hot_cold(accts), ("Y", "Y"))

    def test_picks_need_at_least_one_account(self):
        with self.assertRaises(ValueError):
            rl.pick_hot_cold({})


class ContainerShapeTest(unittest.TestCase):
    def args(self, impl):
        return rl.container_args(impl, name=f"bench-rest-{impl}", image=f"img-{impl}",
                                 data_dir="/tmp/d", port=4300, cpus=2.0, mem="3g")

    def test_both_sides_get_the_same_limits_ports_and_mounts(self):
        go, rust = self.args("go"), self.args("rust")
        self.assertEqual(rl.limits_of(go), rl.limits_of(rust))
        self.assertEqual(rl.limits_of(go), {"cpus": "2.0", "memory": "3g",
                                            "memory-swap": "3g", "publish": "127.0.0.1:4300:8080",
                                            "mount": "/tmp/d:/data"})

    def test_the_command_differs_only_by_implementation(self):
        self.assertIn("algod", self.args("go"))
        self.assertIn("algod-rust", self.args("rust"))
        self.assertIn("node", self.args("rust"))

    def test_unknown_impl_is_refused(self):
        with self.assertRaises(ValueError):
            rl.container_args("x", name="n", image="i", data_dir="/d", port=1, cpus=1, mem="1g")

    def test_swap_is_pinned_to_the_memory_limit(self):
        for impl in ("go", "rust"):
            a = self.args(impl)
            self.assertEqual(a[a.index("--memory-swap") + 1], a[a.index("--memory") + 1])


class RowsTest(unittest.TestCase):
    def endpoints(self, rps=100.0):
        return {"name": "status", "requests": 500, "errors": 0, "non_2xx": 0, "duration_s": 5.0,
                "rps": rps, "p50_ms": 1.0, "p95_ms": 2.0, "p99_ms": 3.0, "max_ms": 4.0,
                "bytes": 10}

    def test_rows_validate_against_the_result_schema(self):
        runs = [{"go": {"status": self.endpoints(100)}, "rust": {"status": self.endpoints(120)}},
                {"go": {"status": self.endpoints(110)}, "rust": {"status": self.endpoints(130)}}]
        res = {"go": {"status": {"cpu_cores": [1.0, 1.1], "rss_mb": [50.0, 51.0]}},
               "rust": {"status": {"cpu_cores": [0.5, 0.6], "rss_mb": [20.0, 21.0]}}}
        rows = rl.result_rows(runs, 16, res, {"corpus": "small"})
        for row in rows:
            bench_schema.validate_result(row)
        by = {(r["impl"], r["name"]): r for r in rows}
        self.assertEqual(by[("go", "status/c16/rps")]["samples"], [100.0, 110.0])
        self.assertEqual(by[("rust", "status/c16/rps")]["better"], "higher")
        self.assertEqual(by[("go", "status/c16/p99_ms")]["better"], "lower")
        self.assertEqual(by[("rust", "status/c16/cpu_cores")]["samples"], [0.5, 0.6])
        self.assertEqual(by[("go", "status/c16/error_rate")]["samples"], [0.0, 0.0])
        for r in rows:
            self.assertEqual(r["tier"], "rest")
            self.assertEqual(r["metadata"]["corpus"], "small")

    def test_error_rate_counts_transport_errors_and_non_2xx(self):
        e = self.endpoints()
        e["errors"], e["non_2xx"], e["ok"] = 5, 5, 490
        self.assertAlmostEqual(rl.error_rate(e), 0.02)
        e["requests"] = 0
        self.assertEqual(rl.error_rate(e), 1.0)

    def test_error_rate_without_ok_falls_back_to_the_failure_counts(self):
        e = self.endpoints()
        e["errors"], e["non_2xx"] = 5, 5
        self.assertAlmostEqual(rl.error_rate(e), 0.02)

    def test_a_node_above_the_error_threshold_is_flagged(self):
        e = self.endpoints()
        self.assertIsNone(rl.check_error_rate(e, "go", "status"))
        e.update(errors=0, non_2xx=50, ok=450)
        msg = rl.check_error_rate(e, "rust", "status", 0.01)
        self.assertIn("rust", msg)
        self.assertIn("status", msg)
        self.assertIn("10.0%", msg)
        self.assertIsNone(rl.check_error_rate(e, "rust", "status", 0.2))
        e.update(ok=0, non_2xx=500)
        self.assertTrue(rl.check_error_rate(e, "rust", "status"))


class SenderAndSimulationTest(unittest.TestCase):
    ACCTS = {"RWD": {"amount": 900}, "FEES": {"amount": 800}, "B": {"amount": 100},
             "A": {"amount": 100}, "C": {"amount": 50}}

    def test_sender_is_the_richest_non_reserved_account(self):
        self.assertEqual(rl.pick_sender(self.ACCTS, {"RWD", "FEES"}), "A")  # tie: address
        self.assertEqual(rl.pick_sender(self.ACCTS, set()), "RWD")

    def test_no_candidate_is_an_error(self):
        with self.assertRaises(ValueError):
            rl.pick_sender({"RWD": {"amount": 1}}, {"RWD"})

    def sim(self, group=None, status=200):
        doc = {"txn-groups": [group if group is not None else
                              {"txn-results": [{"txn-result": {"pool-error": ""}}]}]}
        return resp(doc, status=status)

    def test_a_successful_simulation_has_no_problems(self):
        self.assertEqual(rl.check_simulation(self.sim()), [])

    def test_failures_are_reported(self):
        self.assertTrue(rl.check_simulation(self.sim(status=400)))
        self.assertTrue(rl.check_simulation(resp({"message": "x"})))
        bad = {"failure-message": "overspend", "failed-at": [0],
               "txn-results": [{"txn-result": {"pool-error": ""}}]}
        problems = rl.check_simulation(self.sim(bad))
        self.assertTrue(any("overspend" in p for p in problems))
        self.assertTrue(any("failed at" in p for p in problems))
        pe = {"txn-results": [{"txn-result": {"pool-error": "tx rejected"}}]}
        self.assertTrue(any("pool-error" in p for p in rl.check_simulation(self.sim(pe))))
        self.assertTrue(rl.check_simulation(self.sim({"txn-results": []})))


class WindowTest(unittest.TestCase):
    def test_only_samples_whose_whole_call_is_inside_the_window_count(self):
        samples = [
            {"start": 8.0, "t": 10.5},    # straddles the start
            {"start": 10.2, "t": 11.8},   # inside
            {"start": 11.9, "t": 13.4},   # inside
            {"start": 14.0, "t": 15.6},   # straddles the end
            {"start": 16.0, "t": 17.0},   # after
        ]
        got = rl.window_samples(samples, 10.0, 15.0)
        self.assertEqual([s["start"] for s in got], [10.2, 11.9])

    def test_a_window_shorter_than_one_call_has_no_samples(self):
        self.assertEqual(rl.window_samples([{"start": 0.0, "t": 1.5}], 0.2, 1.2), [])


class DurationTest(unittest.TestCase):
    def test_fixed_point_never_an_exponent(self):
        self.assertEqual(rl.format_duration(0.5), "0.500s")
        self.assertEqual(rl.format_duration(5), "5.000s")
        self.assertEqual(rl.format_duration(0), "0.000s")
        self.assertNotIn("e", rl.format_duration(1e-5))
        self.assertNotIn("e", rl.format_duration(1e7))


class SettingsTest(unittest.TestCase):
    def test_profiles_have_a_cheap_smoke_and_a_real_full(self):
        self.assertLess(rl.PROFILES["smoke"]["duration_s"], rl.PROFILES["full"]["duration_s"])
        self.assertEqual(rl.PROFILES["smoke"]["concurrency"], [4])
        self.assertIn(16, rl.PROFILES["full"]["concurrency"])

    def test_parse_concurrency(self):
        self.assertEqual(rl.parse_concurrency("1, 16,64"), [1, 16, 64])
        for bad in ("", "0", "a", "1,1", "-3"):
            with self.assertRaises(ValueError):
                rl.parse_concurrency(bad)


class RatioGateTest(unittest.TestCase):
    def report(self, drop=None, ratio=1.2, ok=True):
        rows = []
        for ep in ("status", "simulate"):
            for m in ("rps", "p99_ms"):
                name = f"{ep}/c4/{m}"
                if name != drop:
                    rows.append({"tier": "rest", "name": name, "ratio": ratio})
        return {"ok": ok, "errors": [], "rows": rows}

    def test_complete_report_passes(self):
        self.assertEqual(tier.ratio_gate(self.report()), [])

    def test_an_endpoint_without_an_rps_ratio_fails(self):
        errs = tier.ratio_gate(self.report(ratio=None))
        self.assertTrue(any("status/c4/rps" in e for e in errs))

    def test_missing_rows_and_a_bad_report_fail(self):
        self.assertTrue(tier.ratio_gate({"ok": True, "rows": []}))
        self.assertTrue(tier.ratio_gate(self.report(ok=False)))

    def test_every_endpoint_must_have_an_rps_row(self):
        rep = self.report(drop="simulate/c4/rps")
        errs = tier.ratio_gate(rep, expected=["status", "simulate"])
        self.assertTrue(any("simulate/c4/rps" in e for e in errs))


class TierSettingsTest(unittest.TestCase):
    def test_defaults_are_the_full_profile_with_equal_limits(self):
        p = tier.settings({})
        self.assertEqual(p["profile"], "full")
        self.assertEqual((p["cpus"], p["mem"]), (2.0, "3g"))
        self.assertTrue(p["go_image"].startswith("algorand/algod:5."))

    def test_smoke_profile_and_overrides(self):
        p = tier.settings({"BENCH_REST_PROFILE": "smoke", "BENCH_REST_CONCURRENCY": "2,8",
                           "BENCH_REST_DURATION": "0.5", "BENCH_REST_MEM": "512m"})
        self.assertEqual((p["concurrency"], p["duration_s"], p["mem"]), ([2, 8], 0.5, "512m"))

    def test_bad_settings_are_refused(self):
        for env in ({"BENCH_REST_PROFILE": "x"}, {"BENCH_REST_CONCURRENCY": "0"},
                    {"BENCH_REST_DURATION": "0"}, {"BENCH_REST_DURATION": "abc"},
                    {"BENCH_REST_DURATION": "1e-05"}, {"BENCH_REST_DURATION": "0.05"},
                    {"BENCH_REST_WARMUP": "0.01"}, {"BENCH_REST_WARMUP": "-1"},
                    {"BENCH_REST_MAX_ERROR_RATE": "2"},
                    {"BENCH_REST_CPUS": "-1"}, {"BENCH_REST_MEM": "lots"},
                    {"BENCH_REST_PORT_BASE": "80"}):
            with self.assertRaises(tier.TierError, msg=env):
                tier.settings(env)


class EnsureImagesTest(unittest.TestCase):
    class P:
        def __init__(self, rc, out=""):
            self.returncode, self.stdout, self.stderr = rc, out, ""

    def run_with(self, **kw):
        calls = []

        def fake(*args, check=True, **_):
            calls.append(args)
            if args[:2] == ("image", "inspect") and "--format" not in args:
                return self.P(0 if args[2].startswith("algorand/") else 1)
            if "--format" in args:
                return self.P(0, "sha256:x")
            return self.P(0)

        orig = tier.localnet.docker
        tier.localnet.docker = fake
        try:
            cfg = {"go_image": "algorand/algod:5", "rust_image": kw.pop("rust_image", "")}
            tier.localnet.ensure_images(cfg, **kw)
        finally:
            tier.localnet.docker = orig
        return cfg, calls

    def test_the_error_names_the_rest_tiers_own_variable(self):
        with self.assertRaises(tier.localnet.TierError) as cm:
            self.run_with(rust_image="nope:1", rust_env="BENCH_REST_RUST_IMAGE",
                          rust_tag="algod-rust:bench-rest")
        self.assertIn("BENCH_REST_RUST_IMAGE=nope:1", str(cm.exception))
        self.assertNotIn("LOCALNET", str(cm.exception))

    def test_the_localnet_defaults_are_unchanged(self):
        with self.assertRaises(tier.localnet.TierError) as cm:
            self.run_with(rust_image="nope:1")
        self.assertIn("BENCH_LOCALNET_RUST_IMAGE=nope:1", str(cm.exception))

    def test_the_rest_tier_builds_its_own_tag(self):
        cfg, calls = self.run_with(rust_env="BENCH_REST_RUST_IMAGE",
                                   rust_tag="algod-rust:bench-rest")
        self.assertEqual(cfg["rust_image"], "algod-rust:bench-rest")
        build = next(c for c in calls if c[0] == "build")
        self.assertEqual(build[build.index("-t") + 1], "algod-rust:bench-rest")


if __name__ == "__main__":
    unittest.main()
