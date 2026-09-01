#!/usr/bin/env python3
#
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Regenerate the "Aggregate totals" and "Per-area breakdown" tables in
# docs/PHASE17_TEST_PARITY.md by re-counting the status column of every row
# in docs/phase17/parity_*.md.
#
# Run this after updating any parity_<area>.md row's status (e.g. after a
# Phase 17 issue's fix lands and a go-algorand test that was
# `missing-test`/`not-implemented` now has a matching Rust test) so the
# summary tables never drift from the per-area detail files. Safe to run
# any time; it only rewrites the two generated tables, not the detail files
# themselves.
#
# Usage: python3 scripts/update_phase17_summary.py

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PHASE17_DIR = REPO_ROOT / "docs" / "phase17"
SUMMARY_PATH = REPO_ROOT / "docs" / "PHASE17_TEST_PARITY.md"

STATUSES = [
    "matched-1:1",
    "matched-1:many",
    "matched-many:1",
    "partial",
    "not-implemented",
    "missing-test",
    "out-of-scope",
]

# (area label, file stem, description shown in the "area" column)
AREAS = [
    ("AVM/TEAL opcodes (`data/transactions/logic`)", "txn_logic"),
    ("Transactions core (`data/transactions`)", "txn_core"),
    (
        "Ledger core (`ledger`, `ledger/eval`, `ledger/apply`, `ledger/ledgercore`, `ledger/store`, `ledger/encoded`)",
        "ledger_core",
    ),
    ("Ledger simulation (`ledger/simulation`)", "ledger_sim"),
    ("Agreement protocol (`agreement`)", "agreement"),
    ("e2e integration (`test/e2e-go`)", "e2e"),
    ("Networking (`network`, `network/p2p`, ...)", "network"),
    ("Crypto (`crypto`, `crypto/stateproof`, ...)", "crypto"),
    ("Daemon/node/rpcs (`daemon/algod`, `node`, `rpcs`)", "daemon_node"),
    ("Data structures (`data/basics`, `data/bookkeeping`, ...)", "data_misc"),
    ("Config/stateproof/protocol", "config_proto_sp"),
    ("Util (`util/*`)", "util"),
    ("Tools/CLI (`tools/*`, `cmd/*`, ...)", "tools_cmd"),
    ("Logging (`logging/*`)", "logging"),
    ("Catchup (`catchup`)", "catchup"),
]

ROW_RE = re.compile(
    r"^\|.*\|\s*(matched-1:1|matched-1:many|matched-many:1|partial|not-implemented|missing-test|out-of-scope)\s*\|.*\|\s*$"
)


def count_statuses(path: Path) -> dict:
    counts = {s: 0 for s in STATUSES}
    total = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        m = ROW_RE.match(line)
        if m:
            counts[m.group(1)] += 1
            total += 1
    return counts, total


def main():
    per_area = []
    grand_total = {s: 0 for s in STATUSES}
    grand_total_rows = 0

    for label, stem in AREAS:
        path = PHASE17_DIR / f"parity_{stem}.md"
        counts, total = count_statuses(path)
        per_area.append((label, stem, total, counts))
        for s in STATUSES:
            grand_total[s] += counts[s]
        grand_total_rows += total

    # ---- Aggregate totals table (sorted by count desc, matching original style) ----
    agg_lines = ["| status | count | share |", "|---|---|---|"]
    for s, count in sorted(grand_total.items(), key=lambda kv: -kv[1]):
        share = round(100 * count / grand_total_rows) if grand_total_rows else 0
        agg_lines.append(f"| `{s}` | {count:,} | {share}% |")
    agg_table = "\n".join(agg_lines)

    real_gaps = grand_total["not-implemented"] + grand_total["missing-test"]
    real_gaps_pct = round(100 * real_gaps / grand_total_rows) if grand_total_rows else 0
    partial_pct = (
        round(100 * grand_total["partial"] / grand_total_rows) if grand_total_rows else 0
    )

    # ---- Per-area breakdown table ----
    per_area_lines = [
        "| area | file | total | 1:1 | 1:many | many:1 | partial | not-impl | missing-test | out-of-scope |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for label, stem, total, counts in per_area:
        per_area_lines.append(
            f"| {label} | [parity_{stem}.md](phase17/parity_{stem}.md) | {total} | "
            f"{counts['matched-1:1']} | {counts['matched-1:many']} | {counts['matched-many:1']} | "
            f"{counts['partial']} | {counts['not-implemented']} | {counts['missing-test']} | "
            f"{counts['out-of-scope']} |"
        )
    per_area_lines.append(
        f"| **Total** | | **{grand_total_rows:,}** | **{grand_total['matched-1:1']}** | "
        f"**{grand_total['matched-1:many']}** | **{grand_total['matched-many:1']}** | "
        f"**{grand_total['partial']}** | **{grand_total['not-implemented']}** | "
        f"**{grand_total['missing-test']}** | **{grand_total['out-of-scope']}** |"
    )
    per_area_table = "\n".join(per_area_lines)

    text = SUMMARY_PATH.read_text(encoding="utf-8")

    # Replace the "## Aggregate totals ..." table (from the header line's
    # table start through the paragraph that follows it, up to the next
    # "## " heading).
    agg_section_re = re.compile(
        r"(## Aggregate totals \([\d,]+ go-algorand tests\)\n\n)"
        r"\| status \| count \| share \|\n\|---\|---\|---\|\n(?:\|.*\n)+"
        r"\n\*\*[\d,]+ rows.*?(?=\n## )",
        re.DOTALL,
    )
    new_agg_section = (
        f"## Aggregate totals ({grand_total_rows:,} go-algorand tests)\n\n"
        f"{agg_table}\n\n"
        f"**{real_gaps:,} rows (`not-implemented` + `missing-test`, {real_gaps_pct}%) are real, actionable\n"
        f"gaps** — either a behavior algod-rust doesn't implement yet, or one it\n"
        f"implements but never tests. `partial` ({grand_total['partial']:,}, {partial_pct}%) is coverage that exists\n"
        f"but is weaker than go-algorand's; some of these are worth strengthening,\n"
        f"most are diminishing-returns edge cases. See\n"
        f"[`docs/PHASE17_PROPOSAL.md`](PHASE17_PROPOSAL.md) for how the real gaps\n"
        f"were triaged into tracked issues.\n"
    )
    if not agg_section_re.search(text):
        raise SystemExit("could not locate Aggregate totals section to replace")
    text = agg_section_re.sub(new_agg_section, text, count=1)

    per_area_section_re = re.compile(
        r"(## Per-area breakdown\n\n)"
        r"\| area \| file \| total \|.*\n\|---\|---\|---:\|.*\n(?:\|.*\n)+",
        re.DOTALL,
    )
    new_per_area_section = f"## Per-area breakdown\n\n{per_area_table}\n\n"
    if not per_area_section_re.search(text):
        raise SystemExit("could not locate Per-area breakdown section to replace")
    text = per_area_section_re.sub(new_per_area_section, text, count=1)

    SUMMARY_PATH.write_text(text, encoding="utf-8")
    print(f"Updated {SUMMARY_PATH} ({grand_total_rows} rows across {len(AREAS)} areas)")


if __name__ == "__main__":
    main()
