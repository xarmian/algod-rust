#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Finds candidate dead code in the algod-rust workspace, in two tiers:
#
#   Tier A (sound):    rustc's own `dead_code`-family warnings from a real
#                       `cargo build --workspace --all-targets`. These are
#                       compiler-verified for non-`pub` items (rustc cannot
#                       see cross-crate `pub` usage, so `pub` items never
#                       trigger this lint even when genuinely unreachable).
#
#   Tier B (heuristic): a workspace-wide identifier-occurrence scan over
#                       every `pub fn`, flagging two buckets:
#                         B1: the function name appears NOWHERE else in the
#                             workspace (not even in a test) -- very likely
#                             orphaned.
#                         B2: the function name appears only inside test
#                             code (`#[cfg(test)]` modules or files under a
#                             `tests/` directory), never from a non-test
#                             call site -- exactly the "this only exists to
#                             make a Phase 17 parity row say `matched-*`,
#                             but nothing in the real binary ever calls it"
#                             shape this script exists to catch.
#
# Tier B is a name-based heuristic, not a call-graph analysis: it cannot see
# through trait dispatch, macro-generated call sites, or reuse of a common
# method name (`new`, `run`, `build`, ...) across unrelated types, which
# both suppresses real positives and creates false ones. Treat its output
# as a *triage list* to read with the surrounding code, not as an
# unconditional deletion list. Tier A has no such caveat -- it's the
# compiler telling you the truth about non-pub code.
#
# Usage:
#   python scripts/find_unused_code.py                 # both tiers
#   python scripts/find_unused_code.py --tier-a-only    # skip the cargo
#                                                        # build + Tier B scan
#   python scripts/find_unused_code.py --tier-b-only    # skip the build
#   python scripts/find_unused_code.py --out report.md  # write instead of
#                                                        # printing to stdout
#
# Tier A requires a working `cargo build --workspace --all-targets` on this
# machine -- see CLAUDE.md's Windows MSVC environment note if that command
# doesn't already work in your shell (this script does NOT wrap vcvarsall
# itself; run it from a shell where `cargo build` already works, or pass
# --tier-b-only to skip Tier A entirely).

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOTS = ["crates", "bin"]
EXCLUDE_DIR_NAMES = {"target", ".git", "fixtures"}

# rustc dead_code-family lint messages we treat as Tier A hits. Each entry
# is (compiled pattern, name_group_index, kind). The pattern's own name
# group always holds the identifier; the kind is fixed per pattern rather
# than parsed out, since the "is never used" wording varies by item type.
DEAD_CODE_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"^warning: function `([^`]+)` is never used"), 1, "function"),
    (re.compile(r"^warning: struct `([^`]+)` is never constructed"), 1, "struct"),
    (re.compile(r"^warning: enum `([^`]+)` is never used"), 1, "enum"),
    (re.compile(r"^warning: trait `([^`]+)` is never used"), 1, "trait"),
    (re.compile(r"^warning: type alias `([^`]+)` is never used"), 1, "type alias"),
    (re.compile(r"^warning: constant `([^`]+)` is never used"), 1, "constant"),
    (re.compile(r"^warning: static `([^`]+)` is never used"), 1, "static"),
    (re.compile(r"^warning: method `([^`]+)` is never used"), 1, "method"),
    (re.compile(r"^warning: associated function `([^`]+)` is never used"), 1, "associated function"),
    (re.compile(r"^warning: fields? `([^`]+)` (?:is|are) never read"), 1, "field"),
    (re.compile(r"^warning: variants? `([^`]+)` (?:is|are) never constructed"), 1, "variant"),
]
NOTE_LOCATION = re.compile(r"^\s*-->\s+(.+):(\d+):(\d+)")

PUB_FN_DEF = re.compile(
    r"^\s*pub(?:\([^)]*\))?\s+(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]"
)
IDENT_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class DeadCodeHit:
    kind: str
    name: str
    location: str = ""


@dataclass
class PubFnDef:
    name: str
    file: Path
    line: int
    in_test_module: bool


def iter_source_files() -> list[Path]:
    files: list[Path] = []
    for root_name in SOURCE_ROOTS:
        root = REPO_ROOT / root_name
        if not root.exists():
            continue
        for path in root.rglob("*.rs"):
            if any(part in EXCLUDE_DIR_NAMES for part in path.parts):
                continue
            files.append(path)
    return files


def is_test_path(path: Path) -> bool:
    parts = path.parts
    return "tests" in parts or path.stem.endswith("_test") or path.stem == "tests"


def run_tier_a() -> list[DeadCodeHit]:
    print("[tier A] running `cargo build --workspace --all-targets`"
          " (this can take a few minutes)...", file=sys.stderr)
    try:
        proc = subprocess.run(
            ["cargo", "build", "--workspace", "--all-targets"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=1800,
        )
    except FileNotFoundError:
        print(
            "[tier A] `cargo` not found on PATH in this shell -- skipping."
            " See CLAUDE.md's Windows MSVC environment note, or re-run"
            " from a shell where `cargo build` already works.",
            file=sys.stderr,
        )
        return []
    except subprocess.TimeoutExpired:
        print("[tier A] cargo build timed out after 30 minutes -- skipping.", file=sys.stderr)
        return []

    lines = proc.stderr.splitlines()
    hits: list[DeadCodeHit] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        matched_name = None
        matched_kind = None
        for pat, group_idx, kind in DEAD_CODE_PATTERNS:
            m = pat.match(line)
            if m:
                matched_name = m.group(group_idx)
                matched_kind = kind
                break
        if matched_name:
            location = ""
            for j in range(i + 1, min(i + 4, len(lines))):
                loc_m = NOTE_LOCATION.match(lines[j])
                if loc_m:
                    location = f"{loc_m.group(1)}:{loc_m.group(2)}"
                    break
            hits.append(DeadCodeHit(kind=matched_kind, name=matched_name, location=location))
        i += 1
    return hits


def collect_pub_fn_defs(files: list[Path]) -> list[PubFnDef]:
    defs: list[PubFnDef] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        depth_at_test_mod: int | None = None
        brace_depth = 0
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if depth_at_test_mod is None and (
                "#[cfg(test)]" in stripped or stripped.startswith("mod tests")
            ):
                # Heuristic: once we see a #[cfg(test)] attribute (typically
                # immediately preceding `mod tests {`), treat everything
                # from here to the matching closing brace as test code.
                if "mod" in stripped or (idx + 1 < len(lines) and "mod" in lines[idx + 1]):
                    depth_at_test_mod = brace_depth

            brace_depth += line.count("{") - line.count("}")
            if depth_at_test_mod is not None and brace_depth <= depth_at_test_mod:
                depth_at_test_mod = None

            m = PUB_FN_DEF.match(line)
            if m:
                defs.append(
                    PubFnDef(
                        name=m.group(1),
                        file=path,
                        line=idx + 1,
                        in_test_module=depth_at_test_mod is not None or is_test_path(path),
                    )
                )
    return defs


def build_identifier_index(files: list[Path]) -> dict[str, dict[str, int]]:
    """identifier -> {"prod": count_outside_tests, "test": count_inside_tests}."""
    index: dict[str, dict[str, int]] = defaultdict(lambda: {"prod": 0, "test": 0})
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        bucket = "test" if is_test_path(path) else "prod"
        for tok in IDENT_TOKEN.findall(text):
            index[tok][bucket] += 1
    return index


def run_tier_b(files: list[Path]) -> tuple[list[PubFnDef], list[PubFnDef]]:
    print(f"[tier B] scanning {len(files)} source files for pub fn definitions and usage...", file=sys.stderr)
    defs = collect_pub_fn_defs(files)
    defs = [d for d in defs if not d.in_test_module]
    print(f"[tier B] found {len(defs)} non-test pub fn definitions; cross-referencing...", file=sys.stderr)

    index = build_identifier_index(files)

    never_referenced: list[PubFnDef] = []
    test_only: list[PubFnDef] = []
    for d in defs:
        counts = index.get(d.name, {"prod": 0, "test": 0})
        # Subtract 1 for the definition's own occurrence, which always
        # lands in the "prod" bucket for a non-test file.
        prod_count = counts["prod"] - 1
        test_count = counts["test"]
        if prod_count <= 0 and test_count == 0:
            never_referenced.append(d)
        elif prod_count <= 0 and test_count > 0:
            test_only.append(d)
    return never_referenced, test_only


def format_report(
    tier_a: list[DeadCodeHit],
    tier_b_never: list[PubFnDef],
    tier_b_test_only: list[PubFnDef],
    ran_a: bool,
    ran_b: bool,
) -> str:
    lines: list[str] = []
    lines.append("# algod-rust unused-code report")
    lines.append("")
    lines.append(
        "Generated by `scripts/find_unused_code.py`. See that script's header comment"
        " for methodology and the heuristic limitations of Tier B."
    )
    lines.append("")

    if ran_a:
        lines.append(f"## Tier A — compiler-verified dead code ({len(tier_a)} hits)")
        lines.append("")
        if not tier_a:
            lines.append("None found. `cargo build --workspace --all-targets` reported no"
                          " dead_code-family warnings.")
        else:
            for hit in tier_a:
                loc = f" ({hit.location})" if hit.location else ""
                lines.append(f"- `{hit.name}`{loc} — {hit.kind}")
        lines.append("")

    if ran_b:
        lines.append(f"## Tier B1 — pub fn referenced nowhere else in the workspace ({len(tier_b_never)} hits)")
        lines.append("")
        lines.append("High-suspicion: not even a test calls these. Verify manually before removing"
                      " (trait-object dispatch, `#[no_mangle]`/FFI, or an external consumer of this"
                      " crate as a library can all suppress this signal).")
        lines.append("")
        for d in sorted(tier_b_never, key=lambda d: (str(d.file), d.line)):
            rel = d.file.relative_to(REPO_ROOT)
            lines.append(f"- `{d.name}` — {rel}:{d.line}")
        lines.append("")

        lines.append(f"## Tier B2 — pub fn referenced only from test code ({len(tier_b_test_only)} hits)")
        lines.append("")
        lines.append("These are called somewhere, but only from a `#[cfg(test)]` module or a"
                      " `tests/` integration test — never from a non-test production call site."
                      " This is exactly the \"exists to make a Phase 17 parity row pass, but"
                      " nothing in the real binary reaches it\" shape. Some of these are"
                      " legitimately test-only helpers (fixture builders, mock constructors);"
                      " others are genuine parity gaps where the feature was ported but never"
                      " wired into `bin/algod-rust`'s actual startup/request-handling paths.")
        lines.append("")
        for d in sorted(tier_b_test_only, key=lambda d: (str(d.file), d.line)):
            rel = d.file.relative_to(REPO_ROOT)
            lines.append(f"- `{d.name}` — {rel}:{d.line}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tier-a-only", action="store_true")
    parser.add_argument("--tier-b-only", action="store_true")
    parser.add_argument("--out", type=str, default=None, help="write report to this file instead of stdout")
    args = parser.parse_args()

    run_a = not args.tier_b_only
    run_b = not args.tier_a_only

    tier_a_hits: list[DeadCodeHit] = []
    if run_a:
        tier_a_hits = run_tier_a()

    tier_b_never: list[PubFnDef] = []
    tier_b_test_only: list[PubFnDef] = []
    if run_b:
        files = iter_source_files()
        tier_b_never, tier_b_test_only = run_tier_b(files)

    report = format_report(tier_a_hits, tier_b_never, tier_b_test_only, run_a, run_b)

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(report, encoding="utf-8")
        print(f"Report written to {out_path}", file=sys.stderr)
    else:
        print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
