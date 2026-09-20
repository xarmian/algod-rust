#!/usr/bin/env python3
#
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Keep the Phase 17 go-algorand <-> algod-rust test-parity map
# (docs/PHASE17_TEST_PARITY.md + docs/phase17/parity_<area>.md) current
# across go-algorand version upgrades.
#
# The parity map is a live record: one row per `func TestXxx` in the pinned
# go-algorand checkout, linked to its exact GitHub blob at the pinned tag.
# When the pin moves from OLD to NEW, three things must happen, in order:
#
#   1. `report`  — diff the Go test inventory between OLD and NEW: tests
#                  added, removed, moved (file rename), and tests whose body
#                  changed (so the matched Rust test may no longer prove the
#                  same behavior). Emits a Markdown report. Run BEFORE
#                  `repin` (it needs the committed OLD go_tests.tsv, or
#                  `--old-tsv` pointing at `git show <sha>:docs/phase17/go_tests.tsv`).
#   2. `repin`   — rewrite every parity-row link from blob/OLD/<file>#L<n>
#                  to blob/NEW/<file>#L<n'> (line numbers looked up in the
#                  NEW inventory, file renames resolved by unique test name),
#                  regenerate docs/phase17/go_tests.tsv and
#                  docs/phase17/batches/go_<area>.tsv from NEW, and append a
#                  placeholder row (status `unclassified`) for every test
#                  NEW added, so nothing can be silently skipped.
#   3. `check`   — the hard gate: every row links the pinned tag, every Go
#                  test in the inventory has a row and vice versa, no row is
#                  `unclassified`, and `not-implemented` / `missing-test` /
#                  `partial` are all zero. Non-zero exit on any failure.
#                  This is what the algod-version-upgrade skill's Stage 7
#                  runs before an upgrade epic may close.
#
# Area assignment (which parity_<area>.md a Go package belongs to) is the
# package-prefix table AREA_RULES below — the same split the original Phase
# 17 sweep used. A Go package that matches no rule is an error, not a
# silent default: extend the table deliberately.
#
# Usage:
#   scripts/phase17_parity_delta.py report --old-tag OLD --new-tag NEW \
#       [--go-algorand ../go-algorand] [--old-tsv PATH] [--new-tsv PATH] [--out FILE]
#   scripts/phase17_parity_delta.py repin  --old-tag OLD --new-tag NEW \
#       [--go-algorand ../go-algorand] [--new-tsv PATH] [--no-placeholders]
#   scripts/phase17_parity_delta.py check  [--tag TAG] [--go-algorand ../go-algorand] \
#       [--allow-partial N]
#
# Python 3.9+, no third-party dependencies. `report`/`repin`/`check`
# regenerate the NEW inventory natively (same rules as
# scripts/list_go_tests.sh, whose output stays byte-identical) unless
# `--new-tsv` is given.

from __future__ import annotations

import argparse
import datetime as _dt
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PHASE17_DIR = REPO_ROOT / "docs" / "phase17"
BATCHES_DIR = PHASE17_DIR / "batches"
GO_TSV = PHASE17_DIR / "go_tests.tsv"
SUMMARY_PATH = REPO_ROOT / "docs" / "PHASE17_TEST_PARITY.md"
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"

BLOB_PREFIX = "https://github.com/algorand/go-algorand/blob/"

# Statuses a row may carry. `unclassified` is the placeholder `repin`
# inserts for tests NEW added; it is never a valid final state.
FINAL_STATUSES = [
    "matched-1:1",
    "matched-1:many",
    "matched-many:1",
    "partial",
    "not-implemented",
    "missing-test",
    "out-of-scope",
]
PLACEHOLDER_STATUS = "unclassified"
ALL_STATUSES = FINAL_STATUSES + [PLACEHOLDER_STATUS]

# Gap statuses that must be zero for the `check` gate to pass. `partial`
# has its own threshold flag (default 0).
HARD_ZERO_STATUSES = ["not-implemented", "missing-test", PLACEHOLDER_STATUS]

# (area stem, [package prefixes]) — first match wins, so more specific
# prefixes must come before their parents. A prefix matches package `p`
# when p == prefix or p startswith prefix + "/".
AREA_RULES: list[tuple[str, list[str]]] = [
    ("txn_logic", ["data/transactions/logic"]),
    ("txn_core", ["data/transactions"]),
    ("ledger_sim", ["ledger/simulation"]),
    ("ledger_core", ["ledger"]),
    ("agreement", ["agreement"]),
    ("e2e", ["test/e2e-go"]),
    ("network", ["network"]),
    ("crypto", ["crypto"]),
    ("daemon_node", ["daemon", "node", "rpcs"]),
    ("data_misc", ["data"]),
    ("config_proto_sp", ["config", "protocol", "stateproof"]),
    ("util", ["util"]),
    ("logging", ["logging"]),
    ("catchup", ["catchup"]),
    (
        "tools_cmd",
        [
            "cmd",
            "tools",
            "gen",
            "heartbeat",
            "libgoal",
            "netdeploy",
            "nodecontrol",
            "shared",
            "test/netperf-go",
        ],
    ),
]
AREA_STEMS = [stem for stem, _ in AREA_RULES]

# A parity row: `| [TestName](<blob url>#L<line>) | <rust tests> | <status> | <notes> |`
ROW_LINK_RE = re.compile(
    r"^\|\s*\[(?P<name>Test[A-Za-z0-9_]+)\]\("
    + re.escape(BLOB_PREFIX)
    + r"(?P<tag>[^/]+)/(?P<file>[^#)]+)#L(?P<line>\d+)\)\s*\|"
)
STATUS_RE = re.compile(
    r"\|\s*(" + "|".join(re.escape(s) for s in ALL_STATUSES) + r")\s*\|"
)
# Any other blob link (inside notes cells, prose paragraphs, etc.)
ANY_BLOB_RE = re.compile(re.escape(BLOB_PREFIX) + r"(?P<tag>[^/]+)/(?P<rest>[^)\s]+)")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<len>\d+))? @@")


# ----------------------------------------------------------------------------
# Inventory (go_tests.tsv) handling
# ----------------------------------------------------------------------------


class GoTest:
    __slots__ = ("package", "name", "file", "line")

    def __init__(self, package: str, name: str, file: str, line: int):
        self.package = package
        self.name = name
        self.file = file
        self.line = line

    @property
    def key(self) -> tuple[str, str]:
        return (self.file, self.name)


def parse_tsv(text: str) -> list[GoTest]:
    tests: list[GoTest] = []
    for i, raw in enumerate(text.splitlines()):
        if i == 0 and raw.startswith("package\t"):
            continue
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) != 4:
            raise SystemExit(f"malformed TSV line {i + 1}: {raw!r}")
        tests.append(GoTest(parts[0], parts[1], parts[2], int(parts[3])))
    return tests


def sort_tests(tests: list[GoTest]) -> list[GoTest]:
    return sorted(tests, key=lambda t: (t.file, t.line, t.name))


def render_tsv(tests: list[GoTest]) -> str:
    lines = ["package\ttest_name\tfile\tline"]
    for t in sort_tests(tests):
        lines.append(f"{t.package}\t{t.name}\t{t.file}\t{t.line}")
    return "\n".join(lines) + "\n"


FUNC_RE = re.compile(r"^func (Test[A-Za-z0-9_]+)\(")


def generate_inventory(go_algorand: Path) -> list[GoTest]:
    """Walk the checkout for `func TestXxx(` in *_test.go files.

    Native re-implementation of scripts/list_go_tests.sh (same filter:
    *_test.go, excluding vendor/ and testdata/), because that bash script
    forks per match and takes minutes on Windows. Output is identical.
    """
    if not go_algorand.is_dir():
        raise SystemExit(f"go-algorand checkout not found at {go_algorand}")
    tests: list[GoTest] = []
    for path in go_algorand.rglob("*_test.go"):
        relp = path.relative_to(go_algorand).as_posix()
        parts = relp.split("/")
        if "vendor" in parts[:-1] or "testdata" in parts[:-1]:
            continue
        pkg = "/".join(parts[:-1]) or "."
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise SystemExit(f"cannot read {path}: {e}")
        for lineno, line in enumerate(text.splitlines(), start=1):
            m = FUNC_RE.match(line)
            if m:
                tests.append(GoTest(pkg, m.group(1), relp, lineno))
    return sort_tests(tests)


def load_inventory(path: Path | None, go_algorand: Path | None, what: str) -> list[GoTest]:
    if path is not None:
        return parse_tsv(path.read_text(encoding="utf-8"))
    if go_algorand is None:
        raise SystemExit(f"need --{what}-tsv or --go-algorand")
    return generate_inventory(go_algorand)


def area_for_package(package: str) -> str:
    for stem, prefixes in AREA_RULES:
        for p in prefixes:
            if package == p or package.startswith(p + "/"):
                return stem
    raise SystemExit(
        f"go package {package!r} matches no AREA_RULES entry in {Path(__file__).name}; "
        "add it to the right area deliberately (this is a new upstream package)"
    )


def checkout_tag(go_algorand: Path) -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", str(go_algorand), "describe", "--tags", "--exact-match"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def pinned_tag_from_claude_md() -> str | None:
    m = re.search(r"pinned to `([^`]+)`", CLAUDE_MD.read_text(encoding="utf-8"))
    return m.group(1) if m else None


# ----------------------------------------------------------------------------
# Parity-row handling
# ----------------------------------------------------------------------------


class Row:
    __slots__ = ("path", "lineno", "name", "tag", "file", "line", "status")

    def __init__(self, path: Path, lineno: int, name: str, tag: str, file: str, line: int, status: str | None):
        self.path = path
        self.lineno = lineno
        self.name = name
        self.tag = tag
        self.file = file
        self.line = line
        self.status = status

    @property
    def key(self) -> tuple[str, str]:
        return (self.file, self.name)


def parity_files() -> list[Path]:
    return [PHASE17_DIR / f"parity_{stem}.md" for stem in AREA_STEMS]


def parse_rows(path: Path) -> list[Row]:
    rows: list[Row] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        m = ROW_LINK_RE.match(line)
        if not m:
            continue
        sm = STATUS_RE.search(line[m.end() - 1 :])
        rows.append(
            Row(
                path,
                lineno,
                m.group("name"),
                m.group("tag"),
                m.group("file"),
                int(m.group("line")),
                sm.group(1) if sm else None,
            )
        )
    return rows


def all_rows() -> list[Row]:
    rows: list[Row] = []
    for p in parity_files():
        if p.exists():
            rows.extend(parse_rows(p))
    return rows


def rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


# ----------------------------------------------------------------------------
# Delta computation
# ----------------------------------------------------------------------------


class Delta:
    def __init__(self, old: list[GoTest], new: list[GoTest]):
        self.old = old
        self.new = new
        old_by_key = {t.key: t for t in old}
        new_by_key = {t.key: t for t in new}
        self.old_by_key = old_by_key
        self.new_by_key = new_by_key

        added_keys = set(new_by_key) - set(old_by_key)
        removed_keys = set(old_by_key) - set(new_by_key)

        # Resolve file renames: a removed test whose name is unique among
        # removed AND unique among added is the same test moved.
        removed_by_name: dict[str, list[GoTest]] = defaultdict(list)
        for k in removed_keys:
            removed_by_name[old_by_key[k].name].append(old_by_key[k])
        added_by_name: dict[str, list[GoTest]] = defaultdict(list)
        for k in added_keys:
            added_by_name[new_by_key[k].name].append(new_by_key[k])

        self.moved: dict[tuple[str, str], GoTest] = {}  # old key -> new test
        for name, olds in removed_by_name.items():
            news = added_by_name.get(name, [])
            if len(olds) == 1 and len(news) == 1:
                self.moved[olds[0].key] = news[0]
                added_keys.discard(news[0].key)
                removed_keys.discard(olds[0].key)

        self.added = sort_tests([new_by_key[k] for k in added_keys])
        self.removed = sort_tests([old_by_key[k] for k in removed_keys])

    def resolve(self, key: tuple[str, str]) -> GoTest | None:
        """Where an OLD (file,name) lives in NEW, or None if it was removed."""
        if key in self.new_by_key:
            return self.new_by_key[key]
        return self.moved.get(key)


def changed_tests(go_algorand: Path, old_tag: str, new_tag: str, new: list[GoTest]) -> set[tuple[str, str]]:
    """Tests whose function body changed between OLD and NEW.

    Uses `git diff -U0` per changed *_test.go file and attributes each hunk
    (by NEW-side line range) to the test function whose span covers it —
    span = [its line, next test's line in the same file). Helpers between
    tests are attributed to the preceding test: a deliberate over-
    approximation (a re-verify flag that turns out to be a no-op is cheap;
    a missed behavior change is not).
    """
    try:
        changed_files = subprocess.run(
            ["git", "-C", str(go_algorand), "diff", "--name-only", old_tag, new_tag, "--", "*_test.go"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"git diff --name-only failed (are both tags fetched?):\n{e.stderr}")

    by_file: dict[str, list[GoTest]] = defaultdict(list)
    for t in new:
        by_file[t.file].append(t)
    for lst in by_file.values():
        lst.sort(key=lambda t: t.line)

    changed: set[tuple[str, str]] = set()
    for f in changed_files:
        tests = by_file.get(f)
        if not tests:
            continue  # file deleted, or has no Test* functions in NEW
        diff = subprocess.run(
            ["git", "-C", str(go_algorand), "diff", "-U0", old_tag, new_tag, "--", f],
            check=True,
            capture_output=True,
            text=True,
            errors="replace",
        ).stdout
        ranges: list[tuple[int, int]] = []
        for line in diff.splitlines():
            m = HUNK_RE.match(line)
            if not m:
                continue
            start = int(m.group("start"))
            length = int(m.group("len")) if m.group("len") is not None else 1
            end = start + max(length, 1)  # pure deletions touch `start`
            ranges.append((start, end))
        for i, t in enumerate(tests):
            span_start = t.line
            span_end = tests[i + 1].line if i + 1 < len(tests) else 10**9
            for a, b in ranges:
                if a < span_end and b > span_start:
                    changed.add(t.key)
                    break
    return changed


# ----------------------------------------------------------------------------
# Subcommand: report
# ----------------------------------------------------------------------------


def cmd_report(args: argparse.Namespace) -> int:
    go_algorand = Path(args.go_algorand).resolve() if args.go_algorand else None
    old = parse_tsv(Path(args.old_tsv).read_text(encoding="utf-8")) if args.old_tsv else parse_tsv(GO_TSV.read_text(encoding="utf-8"))
    new = load_inventory(Path(args.new_tsv) if args.new_tsv else None, go_algorand, "new")
    delta = Delta(old, new)
    rows = all_rows()
    rows_by_key: dict[tuple[str, str], list[Row]] = defaultdict(list)
    for r in rows:
        rows_by_key[r.key].append(r)

    changed: set[tuple[str, str]] = set()
    if go_algorand is not None:
        changed = changed_tests(go_algorand, args.old_tag, args.new_tag, new)
    added_keys = {t.key for t in delta.added}
    reverify = sorted(k for k in changed if k not in added_keys)

    out: list[str] = []
    out.append(f"# Test-parity delta: go-algorand `{args.old_tag}` → `{args.new_tag}`")
    out.append("")
    out.append(f"_Generated {_dt.date.today().isoformat()} by `scripts/phase17_parity_delta.py report`._")
    out.append("")
    out.append("| metric | count |")
    out.append("|---|---:|")
    out.append(f"| Go tests in `{args.old_tag}` | {len(old)} |")
    out.append(f"| Go tests in `{args.new_tag}` | {len(new)} |")
    out.append(f"| added | {len(delta.added)} |")
    out.append(f"| removed | {len(delta.removed)} |")
    out.append(f"| moved (file rename, same name) | {len(delta.moved)} |")
    out.append(f"| body changed (existing rows to re-verify) | {len(reverify)} |")
    out.append("")

    out.append(f"## Added in `{args.new_tag}` ({len(delta.added)})")
    out.append("")
    out.append(
        "Each needs a new row in the listed `parity_<area>.md` with an honest status. "
        "A `missing-test`/`not-implemented`/`partial` classification is a sub-issue of "
        "the upgrade epic, not a resting state."
    )
    out.append("")
    if delta.added:
        out.append("| go-algorand test | package | area file |")
        out.append("|---|---|---|")
        for t in delta.added:
            url = f"{BLOB_PREFIX}{args.new_tag}/{t.file}#L{t.line}"
            out.append(f"| [{t.name}]({url}) | `{t.package}` | `parity_{area_for_package(t.package)}.md` |")
    else:
        out.append("_none_")
    out.append("")

    out.append(f"## Removed in `{args.new_tag}` ({len(delta.removed)})")
    out.append("")
    out.append(
        "Delete each row (the go test no longer exists at the pin). If the matched Rust "
        "test proved behavior go-algorand deliberately dropped, that is an upstream behavior "
        "change — make sure a Stage 2/3 issue covers it."
    )
    out.append("")
    if delta.removed:
        out.append("| go-algorand test (OLD) | row(s) |")
        out.append("|---|---|")
        for t in delta.removed:
            where = ", ".join(f"`{rel(r.path)}:{r.lineno}`" for r in rows_by_key.get(t.key, [])) or "_no row_"
            out.append(f"| `{t.file}` `{t.name}` | {where} |")
    else:
        out.append("_none_")
    out.append("")

    out.append(f"## Moved ({len(delta.moved)})")
    out.append("")
    out.append("`repin` rewrites these links automatically; listed for the record.")
    out.append("")
    if delta.moved:
        out.append("| test | OLD file | NEW file |")
        out.append("|---|---|---|")
        for old_key, nt in sorted(delta.moved.items()):
            out.append(f"| `{nt.name}` | `{old_key[0]}` | `{nt.file}` |")
    else:
        out.append("_none_")
    out.append("")

    out.append(f"## Body changed — re-verify the mapped Rust test(s) ({len(reverify)})")
    out.append("")
    if go_algorand is None:
        out.append("_skipped: pass `--go-algorand` to compute body changes via `git diff`._")
    else:
        out.append(
            "For each: read `git -C ../go-algorand diff OLD NEW -- <file>` around the function. "
            "If go-algorand added/changed an assertion, the mapped Rust test must gain the same "
            "assertion (or the row honestly drops to `partial` and becomes a sub-issue). "
            "Update the row's notes with what was re-checked."
        )
        out.append("")
        if reverify:
            out.append("| go-algorand test | current status | row |")
            out.append("|---|---|---|")
            for key in reverify:
                nt = delta.new_by_key[key]
                url = f"{BLOB_PREFIX}{args.new_tag}/{nt.file}#L{nt.line}"
                rs = rows_by_key.get(key, [])
                status = ", ".join(sorted({r.status or "?" for r in rs})) or "_no row_"
                where = ", ".join(f"`{rel(r.path)}:{r.lineno}`" for r in rs) or "_no row_"
                out.append(f"| [{nt.name}]({url}) | {status} | {where} |")
        else:
            out.append("_none_")
    out.append("")

    text = "\n".join(out) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(text)
    return 0


# ----------------------------------------------------------------------------
# Subcommand: repin
# ----------------------------------------------------------------------------


def cmd_repin(args: argparse.Namespace) -> int:
    go_algorand = Path(args.go_algorand).resolve() if args.go_algorand else None
    old = parse_tsv(GO_TSV.read_text(encoding="utf-8"))
    new = load_inventory(Path(args.new_tsv) if args.new_tsv else None, go_algorand, "new")
    delta = Delta(old, new)

    if go_algorand is not None:
        tag = checkout_tag(go_algorand)
        if tag != args.new_tag:
            print(
                f"warning: {go_algorand} is at {tag or 'a non-tag commit'}, not {args.new_tag}; "
                "the inventory was generated from what is checked out",
                file=sys.stderr,
            )

    rewritten = 0
    stale: list[Row] = []
    note_links: list[str] = []
    seen_keys: set[tuple[str, str]] = set()

    for path in parity_files():
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        changed_file = False
        for i, line in enumerate(lines):
            m = ROW_LINK_RE.match(line)
            if m:
                key = (m.group("file"), m.group("name"))
                seen_keys.add(key)
                target = delta.resolve(key)
                if target is None:
                    stale.append(Row(path, i + 1, key[1], m.group("tag"), key[0], int(m.group("line")), None))
                    continue
                new_link = f"[{target.name}]({BLOB_PREFIX}{args.new_tag}/{target.file}#L{target.line})"
                old_link = line[m.start() : m.end() - 1].lstrip("| ").rstrip()
                # replace only the first (row) link
                start = line.index(old_link)
                rest = line[start + len(old_link) :]
                line = line[:start] + new_link + rest
                rewritten += 1
            # Re-tag every other blob link (notes cells, prose) textually.
            def _retag(mm: re.Match) -> str:
                if mm.group("tag") == args.old_tag:
                    note_links.append(f"{rel(path)}:{i + 1}: {mm.group('rest')}")
                    return f"{BLOB_PREFIX}{args.new_tag}/{mm.group('rest')}"
                return mm.group(0)

            row_link_end = m.end() - 1 if m else 0
            line = line[:row_link_end] + ANY_BLOB_RE.sub(_retag, line[row_link_end:])
            if line != lines[i]:
                lines[i] = line
                changed_file = True

        # Placeholder rows for tests NEW added.
        if not args.no_placeholders:
            stem = path.stem[len("parity_") :]
            new_here = [t for t in delta.added if area_for_package(t.package) == stem and t.key not in seen_keys]
            if new_here:
                block = [
                    "\n",
                    f"### Tests added in go-algorand `{args.new_tag}` (pending classification)\n",
                    "\n",
                    "Inserted by `scripts/phase17_parity_delta.py repin`. Replace each row's status with a real one and fill in the Rust test link(s) and notes; `check` fails while any row is `unclassified`. Move rows into the main table above once classified.\n",
                    "\n",
                    "| go-algorand test | algod-rust test(s) | status | notes |\n",
                    "|---|---|---|---|\n",
                ]
                for t in new_here:
                    block.append(
                        f"| [{t.name}]({BLOB_PREFIX}{args.new_tag}/{t.file}#L{t.line}) | — | {PLACEHOLDER_STATUS} | new in `{args.new_tag}` |\n"
                    )
                if lines and not lines[-1].endswith("\n"):
                    lines[-1] += "\n"
                lines.extend(block)
                changed_file = True
                print(f"{rel(path)}: appended {len(new_here)} placeholder row(s)")

        if changed_file:
            path.write_text("".join(lines), encoding="utf-8")

    # Regenerate inventory + batches from NEW.
    GO_TSV.write_text(render_tsv(new), encoding="utf-8")
    by_area: dict[str, list[GoTest]] = defaultdict(list)
    for t in new:
        by_area[area_for_package(t.package)].append(t)
    BATCHES_DIR.mkdir(parents=True, exist_ok=True)
    for stem in AREA_STEMS:
        (BATCHES_DIR / f"go_{stem}.tsv").write_text(render_tsv(by_area.get(stem, [])), encoding="utf-8")

    # Update the generated-against line in the index.
    if SUMMARY_PATH.exists():
        text = SUMMARY_PATH.read_text(encoding="utf-8")
        new_text = re.sub(
            r"_Generated \d{4}-\d{2}-\d{2} against go-algorand `[^`]+`",
            f"_Generated {_dt.date.today().isoformat()} against go-algorand `{args.new_tag}`",
            text,
            count=1,
        )
        if new_text != text:
            SUMMARY_PATH.write_text(new_text, encoding="utf-8")

    print(f"rewrote {rewritten} row link(s) to {args.new_tag}; regenerated {rel(GO_TSV)} ({len(new)} tests) and {len(AREA_STEMS)} batch files")
    if note_links:
        print(f"re-tagged {len(note_links)} non-row blob link(s) textually - line anchors NOT verified, re-check each:")
        for s in note_links:
            print(f"  {s}")
    if stale:
        print(f"{len(stale)} row(s) reference tests that no longer exist in {args.new_tag} - delete or remap by hand:")
        for r in stale:
            print(f"  {rel(r.path)}:{r.lineno}: {r.file} {r.name}")
    print("next: python3 scripts/update_phase17_summary.py  (after classifying every placeholder)")
    return 0


# ----------------------------------------------------------------------------
# Subcommand: check
# ----------------------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    tag = args.tag or pinned_tag_from_claude_md()
    if not tag:
        raise SystemExit("could not determine the pinned tag; pass --tag")
    failures: list[str] = []

    inventory = parse_tsv(GO_TSV.read_text(encoding="utf-8"))
    inv_keys = {t.key for t in inventory}

    go_algorand = Path(args.go_algorand).resolve() if args.go_algorand else None
    if go_algorand is not None:
        actual = checkout_tag(go_algorand)
        if actual != tag:
            failures.append(f"{go_algorand} is checked out at {actual or 'a non-tag commit'}, expected {tag}")
        fresh = generate_inventory(go_algorand)
        fresh_keys = {t.key for t in fresh}
        if fresh_keys != inv_keys:
            missing = sorted(fresh_keys - inv_keys)
            extra = sorted(inv_keys - fresh_keys)
            failures.append(
                f"{rel(GO_TSV)} is stale vs the checkout: {len(missing)} test(s) not in TSV, {len(extra)} TSV test(s) not in checkout (run `repin`)"
            )
            for k in missing[:20]:
                failures.append(f"    not in TSV: {k[0]} {k[1]}")
            for k in extra[:20]:
                failures.append(f"    not in checkout: {k[0]} {k[1]}")
        else:
            fresh_lines = {t.key: t.line for t in fresh}
            drift = [t for t in inventory if fresh_lines.get(t.key) != t.line]
            if drift:
                failures.append(f"{len(drift)} TSV line number(s) differ from the checkout (run `repin`)")

    rows = all_rows()
    counts: dict[str, int] = defaultdict(int)
    row_keys: set[tuple[str, str]] = set()
    for r in rows:
        row_keys.add(r.key)
        if r.tag != tag:
            failures.append(f"{rel(r.path)}:{r.lineno}: {r.name} links blob/{r.tag}, expected blob/{tag}")
        if r.status is None:
            failures.append(f"{rel(r.path)}:{r.lineno}: {r.name} has no recognizable status cell")
        else:
            counts[r.status] += 1
        if r.key not in inv_keys:
            failures.append(f"{rel(r.path)}:{r.lineno}: {r.name} ({r.file}) is not in {rel(GO_TSV)}")

    for t in inventory:
        if t.key not in row_keys:
            failures.append(f"no parity row for {t.file} {t.name} (area parity_{area_for_package(t.package)}.md)")

    # Stray OLD-tag links anywhere under docs/phase17 (notes/prose) or the index.
    for p in list(PHASE17_DIR.glob("*.md")) + [SUMMARY_PATH]:
        for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
            for m in ANY_BLOB_RE.finditer(line):
                if m.group("tag") != tag:
                    failures.append(f"{rel(p)}:{lineno}: blob link pinned to {m.group('tag')}, expected {tag}")

    for s in HARD_ZERO_STATUSES:
        if counts.get(s, 0):
            failures.append(f"{counts[s]} row(s) are `{s}` - must be 0")
    if counts.get("partial", 0) > args.allow_partial:
        failures.append(f"{counts['partial']} row(s) are `partial` - must be <= {args.allow_partial}")

    print(f"pin: {tag}; rows: {len(rows)}; inventory: {len(inventory)}")
    for s in ALL_STATUSES:
        if counts.get(s, 0):
            print(f"  {s}: {counts[s]}")
    if failures:
        print(f"\nFAIL - {len(failures)} problem(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nOK - parity map is pinned, complete, and gap-free")
    return 0


# ----------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("report", help="diff the Go test inventory OLD→NEW against the parity rows")
    r.add_argument("--old-tag", required=True)
    r.add_argument("--new-tag", required=True)
    r.add_argument("--go-algorand", default="../go-algorand", help="checkout at NEW (used to generate the inventory and diff bodies)")
    r.add_argument("--old-tsv", help="OLD inventory (default: committed docs/phase17/go_tests.tsv)")
    r.add_argument("--new-tsv", help="NEW inventory (default: generate from --go-algorand)")
    r.add_argument("--out", help="write the Markdown report here instead of stdout")
    r.set_defaults(func=cmd_report)

    p = sub.add_parser("repin", help="rewrite row links to NEW, regenerate TSV/batches, add placeholder rows")
    p.add_argument("--old-tag", required=True)
    p.add_argument("--new-tag", required=True)
    p.add_argument("--go-algorand", default="../go-algorand")
    p.add_argument("--new-tsv")
    p.add_argument("--no-placeholders", action="store_true", help="do not append `unclassified` rows for added tests")
    p.set_defaults(func=cmd_repin)

    c = sub.add_parser("check", help="hard gate: pinned, complete, no gap rows")
    c.add_argument("--tag", help="expected pin (default: read from CLAUDE.md)")
    c.add_argument("--go-algorand", help="if given, also verify the checkout is at --tag and the TSV is fresh")
    c.add_argument("--allow-partial", type=int, default=0, help="max `partial` rows tolerated (default 0)")
    c.set_defaults(func=cmd_check)

    args = ap.parse_args(argv)
    # Reports contain non-ASCII (arrows, dashes); never let a legacy console
    # code page (Windows cp1250 etc.) turn that into a crash.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
