#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Unit tests for upgradeprop_check.py (issue #2400).  No cluster needed."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import upgradeprop_check as uc  # noqa: E402

INJECT = bytes.fromhex("7068617365362dfffe2dc328")  # "phase6-" + ff fe "-" c3 28
NODES = ("go-node-1", "go-node-2", "go-node-3", "rust-node-4")
V = 20
MARGIN = 5


def enc(v):
    """Minimal msgpack encoder for the tests (str values as fixstr/str8)."""
    if isinstance(v, bool):
        return b"\xc3" if v else b"\xc2"
    if isinstance(v, int):
        if v < 128:
            return bytes([v])
        if v < 1 << 16:
            return b"\xcd" + v.to_bytes(2, "big")
        return b"\xcf" + v.to_bytes(8, "big")
    if isinstance(v, (bytes, str)):
        b = v.encode() if isinstance(v, str) else v
        return (bytes([0xA0 | len(b)]) if len(b) < 32 else b"\xd9" + bytes([len(b)])) + b
    if isinstance(v, dict):
        out = bytes([0x80 | len(v)])
        for k in sorted(v):
            out += enc(k) + enc(v[k])
        return out
    raise TypeError(v)


def block_resp(rnd, prop=b"", nextproto=b"", nextbefore=0, prp=b"\x01" * 32):
    block = {"rnd": rnd, "prp": prp, "proto": "future"}
    if prop:
        block.update(upgradeprop=prop, upgradeyes=True)
    if nextproto:
        block.update(nextproto=nextproto, nextbefore=nextbefore)
    return enc({"block": block, "cert": {"prop": {"oprop": "x"}}})


def chain(p, end, inject=INJECT):
    """Honest observations: proposal at p, cleared at p+V."""
    obs = {}
    for n in NODES:
        obs[n] = {}
        for r in range(1, end + 1):
            w = p <= r < p + V
            f = uc.header_fields(block_resp(r, inject if r == p else b"",
                                            inject if w else b"", p + V if w else 0))
            f["hash"] = "H{}".format(r)
            obs[n][r] = f
    return obs


def status(checks, name):
    return [s for n, s, _ in checks if n == name][0]


class DecodeTest(unittest.TestCase):
    def test_non_utf8_string_decodes_byte_exact(self):
        f = uc.header_fields(block_resp(9, INJECT, INJECT, 29))
        self.assertEqual(f["upgradeprop"], INJECT)
        self.assertEqual(f["nextproto"], INJECT)
        self.assertEqual(f["nextbefore"], 29)
        self.assertTrue(f["upgradeyes"])

    def test_block_hex_excludes_the_cert(self):
        a = uc.header_fields(block_resp(3))
        resp = block_resp(3)
        self.assertNotIn(b"oprop".hex(), a["block_hex"])
        self.assertIn(a["block_hex"], resp.hex())

    def test_address_to_pk(self):
        # all-zero key: the well-known zero address
        self.assertEqual(uc.address_to_pk("A" * 52 + "Y5HFKQ"), b"\x00" * 32)


class EvaluateTest(unittest.TestCase):
    def test_honest_chain_passes(self):
        obs = chain(8, 8 + V + MARGIN)
        checks, facts = uc.evaluate(obs, INJECT, V, MARGIN)
        self.assertFalse([c for c in checks if c[1] == "fail"], checks)
        self.assertEqual(facts["proposal_round"], 8)
        self.assertEqual(facts["vote_deadline"], 28)

    def test_rust_stalled_at_the_proposal_fails(self):
        # pre-#2397 Rust: cannot decode round 8's header, stops at 7
        obs = chain(8, 8 + V + MARGIN)
        obs["rust-node-4"] = {r: o for r, o in obs["rust-node-4"].items() if r < 8}
        checks, _ = uc.evaluate(obs, INJECT, V, MARGIN)
        self.assertEqual(status(checks, "all-nodes-all-rounds"), "fail")
        self.assertIn("rust-node-4=7", [d for n, _, d in checks if n == "all-nodes-all-rounds"][0])

    def test_fork_fails(self):
        obs = chain(8, 8 + V + MARGIN)
        obs["rust-node-4"][12] = dict(obs["rust-node-4"][12], hash="OTHER")
        checks, _ = uc.evaluate(obs, INJECT, V, MARGIN)
        self.assertEqual(status(checks, "identical-blocks"), "fail")

    def test_lossy_nextproto_fails(self):
        obs = chain(8, 8 + V + MARGIN)
        lossy = INJECT.decode("utf-8", "replace").encode()
        obs["rust-node-4"][15] = dict(obs["rust-node-4"][15], nextproto=lossy)
        checks, _ = uc.evaluate(obs, INJECT, V, MARGIN)
        self.assertEqual(status(checks, "upgrade-state-bytes"), "fail")

    def test_not_cleared_at_deadline_fails(self):
        obs = chain(8, 8 + V + MARGIN)
        for n in NODES:
            obs[n][28] = dict(obs[n][28], nextproto=INJECT, nextbefore=28)
        checks, _ = uc.evaluate(obs, INJECT, V, MARGIN)
        self.assertEqual(status(checks, "upgrade-state-bytes"), "fail")

    def test_no_proposal_fails(self):
        obs = chain(8, 30, inject=b"other")
        checks, _ = uc.evaluate(obs, INJECT, V, MARGIN)
        self.assertEqual(status(checks, "proposal-found"), "fail")

    def test_rust_proposer_reported(self):
        obs = chain(8, 8 + V + MARGIN)
        rust = b"\x07" * 32
        for n in NODES:
            obs[n][10] = dict(obs[n][10], proposer=rust)
        checks, facts = uc.evaluate(obs, INJECT, V, MARGIN, rust_pk=rust)
        self.assertEqual(facts["rust_proposed_in_window"], [10])

    def test_json_round_trip(self):
        obs = chain(8, 12)
        back = uc._obs_from_json(uc._obs_to_json(obs))
        self.assertEqual(back, obs)


if __name__ == "__main__":
    unittest.main()
