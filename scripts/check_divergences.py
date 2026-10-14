#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Keep docs/DIVERGENCES.md and the `DIVERGENCE DIV-NNN:` source markers in sync.

algod-rust's premise is byte-level parity with go-algorand, so every place
where it *deliberately* behaves or is built differently must be impossible to
mistake for a parity bug. Issue #1927 (epic #1926, the first such divergence:
the pure-Rust Falcon-1024 port) introduced two linked artefacts:

  * docs/DIVERGENCES.md - the register. One summary-table row and one
    `### DIV-NNN` section per divergence, written so that a go-algorand
    maintainer can see exactly what changed and port it if they like.
  * `DIVERGENCE DIV-NNN: <one line>` - a marker comment at every code site
    that embodies the divergence (any comment style: `//`, `///`, `#`, `--`,
    `/* */`), so `grep -rn "DIVERGENCE DIV-"` finds the code from the doc and
    the doc id from the code.

This script asserts the two never drift:

  * every marker id has a table row AND a section in the register;
  * every register id has a table row AND a section;
  * every row whose status is not `reserved` has at least one marker
    (`reserved` = id allocated, implementation not landed yet);
  * ids are DIV-001, DIV-002, ... with no gaps;
  * every marker carries a description after the colon;
  * statuses are one of: reserved, in-progress, landed, retired.

Usage: check_divergences.py [REPO_ROOT]   (default: the repository root)
Exit 0 clean, 1 with one line per problem otherwise.
"""
import os
import re
import sys

MARKER = re.compile(r"DIVERGENCE\s+(DIV-\d{3})\b(:?)\s*(\S?)")
ROW = re.compile(r"^\|\s*(DIV-\d{3})\s*\|(.*)$")
SECTION = re.compile(r"^###\s+(DIV-\d{3})\b")
STATUSES = {"reserved", "in-progress", "landed", "retired"}
SKIP_DIRS = {"target", ".git", "node_modules", "falcon-c", "__pycache__"}
SKIP_FILES = {"check_divergences.py", "check_divergences_test.py"}
TEXT_EXT = (".rs", ".go", ".py", ".sh", ".ps1", ".c", ".h", ".toml", ".yml",
            ".yaml", ".md", ".json", ".txt", ".ts", ".js", ".mk", "Makefile")


def scan_markers(root, register_path):
    """Return ({id: [(relpath, line)]}, [problems]) for every marker under root."""
    found = {}
    problems = []
    register_abs = os.path.abspath(register_path)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name in SKIP_FILES or not name.endswith(TEXT_EXT):
                continue
            path = os.path.join(dirpath, name)
            if os.path.abspath(path) == register_abs:
                continue
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
            except OSError:
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            for i, line in enumerate(lines, 1):
                for m in MARKER.finditer(line):
                    did, colon, rest = m.group(1), m.group(2), m.group(3)
                    found.setdefault(did, []).append((rel, i))
                    if not colon or not rest:
                        problems.append("{}:{}: marker {} has no description after the colon".format(rel, i, did))
    return found, problems


def parse_register(text):
    """Return ({id: status} from the table, {ids with a section}, [problems])."""
    rows, sections, problems = {}, set(), []
    for i, line in enumerate(text.splitlines(), 1):
        m = ROW.match(line)
        if m:
            did = m.group(1)
            cells = [c.strip() for c in m.group(2).split("|")]
            # Columns: Title | Area | Status | Since  (status is the 3rd cell).
            status = cells[2] if len(cells) > 2 else ""
            if status not in STATUSES:
                problems.append("register line {}: {} has unknown status {!r} (want one of {})".format(
                    i, did, status, ", ".join(sorted(STATUSES))))
            if did in rows:
                problems.append("register line {}: duplicate table row for {}".format(i, did))
            rows[did] = status
            continue
        m = SECTION.match(line)
        if m:
            sections.add(m.group(1))
    return rows, sections, problems


def check(root, register_path):
    problems = []
    if not os.path.isfile(register_path):
        return ["{} is missing".format(os.path.relpath(register_path, root).replace(os.sep, "/"))]
    with open(register_path, encoding="utf-8") as f:
        rows, sections, reg_problems = parse_register(f.read())
    problems += reg_problems
    markers, marker_problems = scan_markers(root, register_path)
    problems += marker_problems

    for did in sorted(rows):
        if did not in sections:
            problems.append("{} has a table row but no `### {}` section in the register".format(did, did))
    for did in sorted(sections):
        if did not in rows:
            problems.append("{} has a section but no table row in the register".format(did))
    for did in sorted(markers):
        if did not in rows and did not in sections:
            sites = ", ".join("{}:{}".format(p, n) for p, n in markers[did][:3])
            problems.append("{} is marked in source ({}) but not in the register".format(did, sites))
    for did, status in sorted(rows.items()):
        if status != "reserved" and did not in markers:
            problems.append("{} ({}) has no source marker `DIVERGENCE {}: ...`".format(did, status, did))

    ids = sorted(set(rows) | set(sections))
    expected = ["DIV-{:03d}".format(n) for n in range(1, len(ids) + 1)]
    if ids != expected:
        problems.append("register ids must be sequential from DIV-001: have {}".format(", ".join(ids)))
    return problems


def main(argv):
    root = os.path.abspath(argv[1]) if len(argv) > 1 else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    problems = check(root, os.path.join(root, "docs", "DIVERGENCES.md"))
    for p in problems:
        print(p)
    if problems:
        print("\nEvery intended divergence from go-algorand needs a docs/DIVERGENCES.md row + "
              "section and a `DIVERGENCE DIV-NNN: <why>` marker at each code site (issue #1927).")
        return 1
    print("check_divergences: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
