#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Fail if a tracked, in-scope source file is missing its SPDX license header.

Part of the Phase 15 licensing-compliance epic (#732), implementing issue
#731. Parts A-C (PRs #734-738) added per-file SPDX headers to every source
file in the categories this script checks; this script exists to catch a
newly added file that forgets one, going forward.

Scope (see docs/LICENSING_AUDIT.md for the full classification rationale):
  - *.rs under crates/, bin/, fuzz/
  - *.go under tools/, docker/scripts/canonical-extract/, benchmarks/go-decode/,
    plus the two named top-level generator scripts
  - *.sh / *.py under docker/, ops/, scripts/
  - *.yml under .github/workflows/

Deliberately excluded (per docs/LICENSING_AUDIT.md): data/fixture files
(anything under a `fixtures/` or `tests/fixtures/` path component),
docker/config/*.json (data, not source), docker/localnet-rust/data/*
(generated genesis/config data), and prose Markdown (headers are
deliberately not added to docs per the audit's explicit note).

Usage: python .github/scripts/check-license-headers.py
Exits 1 and prints every offending path if any in-scope file lacks a header;
exits 0 otherwise. Uses `git ls-files` so it only ever looks at tracked
files, and runs in well under a second on this repo.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SPDX_MARKER = "SPDX-License-Identifier:"
HEADER_SCAN_LINES = 20

# Path components that, if present anywhere in a file's path, take it out of
# scope regardless of extension/directory match below.
EXCLUDED_COMPONENTS = {"fixtures"}

# Explicit path prefixes excluded even though they'd otherwise match an
# extension rule below (generated/data, not source).
EXCLUDED_PREFIXES = (
    "docker/localnet-rust/data/",
)


def git_tracked_files(repo_root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def is_excluded(path: str) -> bool:
    parts = set(Path(path).parts)
    if parts & EXCLUDED_COMPONENTS:
        return True
    if any(path.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
        return True
    return False


def matches_scope(path: str) -> bool:
    if is_excluded(path):
        return False

    if path.endswith(".rs"):
        return (
            path.startswith("crates/")
            or path.startswith("bin/")
            or path.startswith("fuzz/")
        )

    if path.endswith(".go"):
        if (
            path.startswith("tools/")
            or path.startswith("docker/scripts/canonical-extract/")
            or path.startswith("benchmarks/go-decode/")
        ):
            return True
        return path in (
            "tests/golden/gen_agreement_vectors.go",
            "scripts/build-phase-b-fixtures.go",
        )

    if path.endswith(".sh") or path.endswith(".py"):
        return (
            path.startswith("docker/")
            or path.startswith("ops/")
            or path.startswith("scripts/")
        )

    if path.endswith(".yml"):
        return path.startswith(".github/workflows/")

    return False


def has_spdx_header(repo_root: Path, path: str) -> bool:
    file_path = repo_root / path
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            for _ in range(HEADER_SCAN_LINES):
                line = f.readline()
                if not line:
                    break
                if SPDX_MARKER in line:
                    return True
    except OSError as exc:
        print(f"warning: could not read {path}: {exc}", file=sys.stderr)
        return True  # don't fail the build over an unreadable file
    return False


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    tracked = git_tracked_files(repo_root)
    in_scope = [p for p in tracked if matches_scope(p)]

    missing = [p for p in in_scope if not has_spdx_header(repo_root, p)]

    print(f"Checked {len(in_scope)} in-scope file(s) for a license header.")

    if missing:
        print(
            f"\nERROR: {len(missing)} file(s) are missing an "
            f"'{SPDX_MARKER}' header in their first {HEADER_SCAN_LINES} lines:\n"
        )
        for p in sorted(missing):
            print(f"  {p}")
        print(
            "\nAdd a header (see docs/LICENSING_AUDIT.md for the "
            "AGPL-3.0-or-later vs MIT classification of this path, and any "
            "existing sibling file for the exact header text/format)."
        )
        return 1

    print("All in-scope files have a license header.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
