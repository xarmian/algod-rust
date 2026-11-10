# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Wiring test of `.github/workflows/network-node-soak.yml` (issue #2113).

The nightly mainnet soak lost two runs (2026-10-28, 2026-11-05) to
`catchpoint import failed: catchpoint sqlite error`: on a runner image whose
`/tmp` is a RAM-backed tmpfs of about 7.7 GB (other images have no separate
`/tmp`, it sits on the 145 GB root disk), the catchpoint file, the imported
ledger and its WAL (about 8 GB for mainnet) exhausted it and SQLite answered
SQLITE_FULL. The soak's working directories must therefore live on the
runner's disk (`RUNNER_TEMP`), never on `/tmp`, and the job must fail early,
with a clear message, on a volume that is too small or RAM-backed.
"""
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(HERE, "..", "..", ".github", "workflows", "network-node-soak.yml")


def workflow():
    with open(WORKFLOW, encoding="utf-8") as f:
        return f.read()


class SoakWorkingDirectoryTest(unittest.TestCase):
    def test_the_ledger_data_and_partkey_dirs_are_not_under_tmp(self):
        text = workflow()
        offenders = [
            line.strip()
            for line in text.splitlines()
            if re.search(r"/tmp/\$\{NET\}-soak-(ledger|partkeys|data)", line)
        ]
        self.assertEqual(offenders, [], "soak working dirs must not be under /tmp (tmpfs)")

    def test_they_live_under_the_runner_temp_directory(self):
        text = workflow()
        self.assertIn("SOAK_ROOT", text)
        self.assertRegex(text, r'SOAK_ROOT="\$\{RUNNER_TEMP:\?[^}]*\}[^"]*"')
        for name in ("ledger", "partkeys", "data"):
            self.assertIn("${SOAK_ROOT}/${NET}-soak-" + name, text)

    def test_the_job_refuses_a_ram_backed_or_small_volume(self):
        text = workflow()
        self.assertRegex(text, r"stat -f -c %T")
        self.assertIn("tmpfs", text)
        self.assertRegex(text, r"df -")
        self.assertIn("free", text.lower())


if __name__ == "__main__":
    unittest.main()
