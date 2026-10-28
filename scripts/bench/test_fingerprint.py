#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Unit tests for fingerprint.py (issue #2102, epic #2101).

The parsers are fed captured `lscpu`, `/proc/cpuinfo`, `/proc/meminfo` and
`/etc/os-release` text so the tests run identically on any host.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fingerprint as fp  # noqa: E402

LSCPU_X86 = """\
Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          46 bits physical, 48 bits virtual
  Byte Order:             Little Endian
CPU(s):                   16
  On-line CPU(s) list:    0-15
Vendor ID:                GenuineIntel
  Model name:             Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
    CPU family:           6
    Model:                79
    Thread(s) per core:   2
    Core(s) per socket:   4
    Socket(s):            2
    Stepping:             1
    CPU(s) scaling MHz:   64%
    CPU max MHz:          3300.0000
    CPU min MHz:          1200.0000
    BogoMIPS:             4800.00
Virtualization features:
  Hypervisor vendor:      KVM
  Virtualization type:    full
Caches (sum of all):
  L1d:                    256 KiB (8 instances)
"""

# Older util-linux layout (no indentation), no max MHz line, single socket.
LSCPU_OLD = """\
Architecture:          x86_64
CPU(s):                4
Thread(s) per core:    1
Core(s) per socket:    4
Socket(s):             1
Model name:            AMD EPYC 7763 64-Core Processor
CPU MHz:               2445.406
"""

CPUINFO_X86 = """\
processor\t: 0
vendor_id\t: GenuineIntel
model name\t: Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
cpu MHz\t\t: 2100.000
physical id\t: 0
core id\t\t: 0

processor\t: 1
vendor_id\t: GenuineIntel
model name\t: Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
cpu MHz\t\t: 2200.000
physical id\t: 0
core id\t\t: 1

processor\t: 2
vendor_id\t: GenuineIntel
model name\t: Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
cpu MHz\t\t: 1900.000
physical id\t: 0
core id\t\t: 0

processor\t: 3
vendor_id\t: GenuineIntel
model name\t: Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
cpu MHz\t\t: 2000.000
physical id\t: 0
core id\t\t: 1
"""

# aarch64 cpuinfo has no "model name" / "physical id" / "core id".
CPUINFO_ARM = """\
processor\t: 0
BogoMIPS\t: 243.75
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics
CPU implementer\t: 0x41
CPU part\t: 0xd0c

processor\t: 1
BogoMIPS\t: 243.75
CPU implementer\t: 0x41
CPU part\t: 0xd0c
"""

MEMINFO = """\
MemTotal:       32795132 kB
MemFree:        10221880 kB
MemAvailable:   25017724 kB
"""

OS_RELEASE = """\
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
"""


class LscpuTest(unittest.TestCase):
    def test_modern_layout(self):
        c = fp.parse_lscpu(LSCPU_X86)
        self.assertEqual(c["model"], "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz")
        self.assertEqual(c["logical_cpus"], 16)
        self.assertEqual(c["sockets"], 2)
        self.assertEqual(c["physical_cores"], 8)
        self.assertEqual(c["threads_per_core"], 2)
        self.assertEqual(c["max_mhz"], 3300.0)
        self.assertEqual(c["architecture"], "x86_64")
        self.assertEqual(c["hypervisor"], "KVM")

    def test_old_layout_falls_back_to_cpu_mhz(self):
        c = fp.parse_lscpu(LSCPU_OLD)
        self.assertEqual(c["model"], "AMD EPYC 7763 64-Core Processor")
        self.assertEqual(c["physical_cores"], 4)
        self.assertEqual(c["max_mhz"], 2445.406)
        self.assertIsNone(c["hypervisor"])

    def test_empty(self):
        c = fp.parse_lscpu("")
        self.assertIsNone(c["model"])
        self.assertIsNone(c["physical_cores"])


class CpuinfoTest(unittest.TestCase):
    def test_x86_counts_unique_cores(self):
        c = fp.parse_cpuinfo(CPUINFO_X86)
        self.assertEqual(c["model"], "Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz")
        self.assertEqual(c["logical_cpus"], 4)
        self.assertEqual(c["physical_cores"], 2)
        self.assertEqual(c["sockets"], 1)
        self.assertEqual(c["max_mhz"], 2200.0)

    def test_arm_without_model_name(self):
        c = fp.parse_cpuinfo(CPUINFO_ARM)
        self.assertEqual(c["logical_cpus"], 2)
        self.assertIsNone(c["physical_cores"])
        self.assertEqual(c["model"], "CPU part 0xd0c (implementer 0x41)")


class OtherParsersTest(unittest.TestCase):
    def test_meminfo(self):
        self.assertEqual(fp.parse_meminfo(MEMINFO), 32795132 * 1024)
        self.assertIsNone(fp.parse_meminfo("garbage"))

    def test_os_release(self):
        self.assertEqual(fp.parse_os_release(OS_RELEASE), "Ubuntu 24.04.1 LTS")
        self.assertIsNone(fp.parse_os_release(""))

    def test_governors(self):
        self.assertEqual(fp.summarize_governors(["performance"] * 4), "performance")
        self.assertEqual(fp.summarize_governors(["powersave", "performance", "powersave"]),
                         "mixed: performance=1, powersave=2")
        self.assertIsNone(fp.summarize_governors([]))


class CiDetectTest(unittest.TestCase):
    def test_github_actions(self):
        ci = fp.detect_ci({"CI": "true", "GITHUB_ACTIONS": "true",
                           "RUNNER_NAME": "GitHub Actions 12", "RUNNER_ENVIRONMENT": "github-hosted"})
        self.assertTrue(ci["is_ci"])
        self.assertEqual(ci["provider"], "github-actions")
        self.assertEqual(ci["runner"], "GitHub Actions 12")
        self.assertEqual(ci["runner_environment"], "github-hosted")

    def test_generic_ci(self):
        ci = fp.detect_ci({"CI": "1"})
        self.assertTrue(ci["is_ci"])
        self.assertEqual(ci["provider"], "unknown")

    def test_not_ci(self):
        self.assertFalse(fp.detect_ci({})["is_ci"])
        self.assertFalse(fp.detect_ci({"CI": "false"})["is_ci"])


class PinTest(unittest.TestCase):
    def test_exact_tag(self):
        self.assertTrue(fp.pin_ok("v5.0.4-stable", "v5.0.4-stable"))

    def test_commits_past_tag(self):
        self.assertFalse(fp.pin_ok("v5.0.4-stable-3-g1234abcd", "v5.0.4-stable"))

    def test_missing(self):
        self.assertFalse(fp.pin_ok(None, "v5.0.4-stable"))


class WarningsTest(unittest.TestCase):
    def test_warnings_flag_unfair_conditions(self):
        f = {
            "cpu": {"governor": "powersave"},
            "ci": {"is_ci": True, "provider": "github-actions"},
            "commits": {
                "algod_rust": {"dirty": True},
                "go_algorand": {"pin_ok": False, "describe": "v5.0.3-stable",
                                "expected_tag": "v5.0.4-stable"},
            },
        }
        w = " | ".join(fp.fairness_warnings(f))
        self.assertIn("governor", w)
        self.assertIn("CI runner", w)
        self.assertIn("uncommitted", w)
        self.assertIn("v5.0.4-stable", w)

    def test_no_warnings_when_clean(self):
        f = {
            "cpu": {"governor": "performance"},
            "ci": {"is_ci": False},
            "commits": {"algod_rust": {"dirty": False},
                        "go_algorand": {"pin_ok": True, "dirty": False}},
        }
        self.assertEqual(fp.fairness_warnings(f), [])


class CollectSmokeTest(unittest.TestCase):
    def test_collect_on_this_host_has_required_keys(self):
        here = os.path.dirname(os.path.abspath(__file__))
        repo = os.path.dirname(os.path.dirname(here))
        f = fp.collect(repo_root=repo, go_algorand_dir=os.path.join(repo, "does-not-exist"),
                       expected_tag="v5.0.4-stable", env={})
        for key in ("schema", "timestamp_utc", "cpu", "memory", "os", "toolchains",
                    "commits", "ci", "warnings"):
            self.assertIn(key, f)
        self.assertEqual(f["schema"], "bench-fingerprint/v1")
        self.assertFalse(f["commits"]["go_algorand"]["pin_ok"])
        self.assertIsNotNone(f["cpu"]["logical_cpus"])


if __name__ == "__main__":
    unittest.main()
