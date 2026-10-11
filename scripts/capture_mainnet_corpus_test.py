#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Tests for capture_mainnet_corpus.py network resilience (issue #1769)."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("CORPUS_CACHE", tempfile.mkdtemp(prefix="corpus-test-cache-"))
import msgpack  # noqa: E402

import capture_mainnet_corpus as c  # noqa: E402


class FakeResp:
    def __init__(self, status, content=b""):
        self.status_code = status
        self.content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP {}".format(self.status_code))


class DeltaRetryTest(unittest.TestCase):
    def setUp(self):
        self._http = c.http
        self._sleep = c.time.sleep
        c.time.sleep = lambda s: None
        c._delta_mem.clear()

    def tearDown(self):
        c.http = self._http
        c.time.sleep = self._sleep
        c._delta_mem.clear()

    def test_intermittent_404_from_the_public_node_is_retried(self):
        # algonode load-balances over backends of which some lack a given
        # round: the same /v2/deltas/<r> alternates 200 and 404.
        body = msgpack.packb({"Accts": {}}, use_bin_type=True)
        answers = [FakeResp(404), FakeResp(404), FakeResp(200, body)]
        calls = []

        def fake_http(url, params=None):
            calls.append(url)
            return answers.pop(0)

        c.http = fake_http
        self.assertIn("Accts", c.delta(987654321))
        self.assertEqual(len(calls), 3)

    def test_persistent_404_still_fails_loudly(self):
        c.http = lambda url, params=None: FakeResp(404)
        with self.assertRaises(Exception):
            c.delta(987654322)


class AtomicWriteTest(unittest.TestCase):
    def test_replace_denied_because_another_capture_wrote_the_same_file(self):
        # Two capture processes sharing the cache can race on the same entry;
        # on Windows os.replace then raises PermissionError although the
        # content is already in place (issue #1769).
        d = tempfile.mkdtemp(prefix="atomic-")
        path = os.path.join(d, "delta-1.mp")
        with open(path, "wb") as f:
            f.write(b"payload")
        real = c.os.replace

        def denied(src, dst):
            raise PermissionError(5, "Access is denied")

        c.os.replace = denied
        try:
            c._atomic_write(path, b"payload")
        finally:
            c.os.replace = real
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"payload")
        self.assertEqual(os.listdir(d), ["delta-1.mp"], "temp file cleaned up")


if __name__ == "__main__":
    unittest.main()
