#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Print the executable path cargo reported for a binary target.

Issue #2102. build_both.sh pipes
`cargo build --message-format=json-render-diagnostics` stdout into this, so
the copied binary is wherever cargo actually wrote it (CARGO_TARGET_DIR,
build.target-dir, --target), never an assumed ./target/release.

Usage: cargo build ... --message-format=json-render-diagnostics \
           | python3 scripts/bench/cargo_artifact.py <bin-name>
Exit 0 and print the path, or exit 1 when no such artifact was reported.
"""
import json
import sys


def find_executable(stream, name):
    found = None
    for line in stream:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("reason") != "compiler-artifact" or not m.get("executable"):
            continue
        t = m.get("target") or {}
        if t.get("name") == name and "bin" in (t.get("kind") or []):
            found = m["executable"]
    return found


def main(argv):
    if len(argv) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    exe = find_executable(sys.stdin, argv[0])
    if exe is None:
        print(f"cargo_artifact: no executable reported for bin {argv[0]!r}", file=sys.stderr)
        return 1
    print(exe)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
