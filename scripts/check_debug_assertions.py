#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Lint for issue #1787: tests must not silently depend on `debug_assertions`.

PR-level unit tests (`.github/workflows/unit-tests.yml`) run in the debug
profile; the daily Coverage workflow runs `cargo llvm-cov nextest --release`.
Code that branches on `cfg!(debug_assertions)` / `#[cfg(debug_assertions)]`
behaves differently in the two, so a test can pass on every PR and fail only
in the scheduled release run (the three shadow_execute invariant tests,
#1784). A second per-PR release build is too expensive, so instead every
`debug_assertions` cfg in Rust sources must carry a justification:

    // debug-assertions-ok: <why release and debug test runs both pass>

on the same line or in the comment block directly above. (`debug_assert!` macros are not
flagged: they only add checks and compile out, they do not select behaviour.)

Usage: check_debug_assertions.py [ROOT ...]   (default: crates bin tools fuzz)
Exit 0 clean, 1 on any unannotated use.
"""
import os
import re
import sys

PATTERN = re.compile(r"\bdebug_assertions\b")
MARKER = "debug-assertions-ok:"
SKIP_DIRS = {"target", ".git", "node_modules"}


def annotated_above(lines, i):
    """True if the contiguous `//` comment block directly above line `i`
    contains the marker."""
    j = i - 1
    while j >= 0 and lines[j].lstrip().startswith("//"):
        if MARKER in lines[j]:
            return True
        j -= 1
    return False


def scan_file(path):
    """Return [(line_no, text)] of unannotated `debug_assertions` cfgs."""
    bad = []
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    for i, line in enumerate(lines):
        code = line.split("//", 1)[0]
        if not PATTERN.search(code):
            continue
        if MARKER in line or annotated_above(lines, i):
            continue
        bad.append((i + 1, line.strip()))
    return bad


def scan(roots):
    findings = []
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(".rs"):
                    p = os.path.join(dirpath, name)
                    findings += [(p, n, t) for n, t in scan_file(p)]
    return findings


def main(argv):
    roots = argv[1:] or ["crates", "bin", "tools", "fuzz"]
    findings = scan([r for r in roots if os.path.isdir(r)])
    for path, n, text in findings:
        print("{}:{}: unannotated debug_assertions cfg: {}".format(path, n, text))
    if findings:
        print("\nAdd `// {} <reason>` (same line or line above) after checking the "
              "tests pass in both debug and --release (issue #1787).".format(MARKER))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
