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
`debug_assertions` cfg in Rust sources, and every Cargo profile override of
`debug-assertions` / `overflow-checks`, must carry a justification:

    // debug-assertions-ok: <why release and debug test runs both pass>

(`#` in TOML) on the same line or in the comment block directly above the
statement. The reason text is required. (`debug_assert!` macros are not
flagged: they only add checks and compile out, they do not select behaviour.)

Known limits (non-blocking, a lint not a proof): multi-line `/* */` comments,
`cfg!(not(test))`, `cfg_attr(debug_assertions, ..)` and side-effecting
`debug_assert!` arguments are not analysed, and the note's claim is not
verified, only required.

Usage: check_debug_assertions.py [ROOT ...]   (default: the repository root)
Exit 0 clean, 1 on any unannotated use.
"""
import os
import re
import sys

RUST_PATTERN = re.compile(r"\bdebug_assertions\b")
TOML_PATTERN = re.compile(r"^\s*(debug-assertions|overflow-checks)\s*=")
NOTE = re.compile(r"(//|#).*debug-assertions-ok:\s*\S")
BLOCK_COMMENT = re.compile(r"/\*.*?\*/")
STRING = re.compile(r'"(?:\\.|[^"\\])*"')
SKIP_DIRS = {"target", ".git", ".claude", "node_modules"}


def opens_continuation(line):
    """True if `line` ends mid-expression (rustfmt-wrapped attribute/call)."""
    return line.split("//", 1)[0].rstrip().endswith(("(", ",", "["))


def annotated_above(lines, i, comment_prefix):
    """True if the contiguous comment block directly above the statement that
    contains line `i` holds a justified note."""
    while i > 0 and opens_continuation(lines[i - 1]):
        i -= 1
    j = i - 1
    # Single-line attributes (e.g. `#[test]`) may sit between note and cfg.
    while j >= 0 and lines[j].lstrip().startswith("#[") and comment_prefix == "//":
        j -= 1
    while j >= 0 and lines[j].lstrip().startswith(comment_prefix):
        if NOTE.search(lines[j]):
            return True
        j -= 1
    return False


def scan_file(path):
    """Return [(line_no, text)] of unannotated profile-dependent settings."""
    is_toml = path.endswith(".toml")
    pattern = TOML_PATTERN if is_toml else RUST_PATTERN
    prefix = "#" if is_toml else "//"
    bad = []
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    for i, line in enumerate(lines):
        bare = BLOCK_COMMENT.sub("", STRING.sub('""', line))
        if not pattern.search(bare.split(prefix, 1)[0]):
            continue
        if NOTE.search(bare) or annotated_above(lines, i, prefix):
            continue
        bad.append((i + 1, line.strip()))
    return bad


def scan(roots):
    findings = []
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(".rs") or name in ("Cargo.toml", "config.toml"):
                    p = os.path.join(dirpath, name)
                    findings += [(p, n, t) for n, t in scan_file(p)]
    return findings


def main(argv):
    roots = argv[1:] or ["."]
    findings = scan([r for r in roots if os.path.isdir(r)])
    for path, n, text in findings:
        print("{}:{}: unannotated profile-dependent setting: {}".format(path, n, text))
    if findings:
        print("\nAdd `// debug-assertions-ok: <reason>` (`#` in TOML; same line or the "
              "comment block above) after checking the tests pass in both debug and "
              "--release (issue #1787).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
