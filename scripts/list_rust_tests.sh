#!/usr/bin/env bash
#
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# List every Rust test function in this workspace, as a TSV:
#   crate<TAB>test_name<TAB>file<TAB>line
#
# Usage: scripts/list_rust_tests.sh > docs/phase17/rust_tests.tsv
#
# Used by Phase 17 (docs/PHASE17_PROPOSAL.md) to build the go-algorand <->
# algod-rust test parity table. Re-run any time to regenerate it from
# scratch. Excludes target/, .claude/worktrees/ (stale agent worktrees), and
# vendored/third-party sources.
set -euo pipefail

cd "$(dirname "$0")/.."

printf 'crate\ttest_name\tfile\tline\n'

# Find files containing #[test]/#[tokio::test] attributes, then within each
# file pair the attribute with the following `fn` line.
# then within each file pair the attribute with the following `fn` line.
find crates bin tests tools -name '*.rs' -type f 2>/dev/null \
  | grep -v '/target/' \
  | while read -r file; do
      crate=$(printf '%s' "$file" | sed -E 's#^(crates/[^/]+/[^/]+|bin/[^/]+|tests|tools/[^/]+)/.*#\1#')
      awk -v file="$file" -v crate="$crate" '
        /#\[(test|tokio::test|async_std::test)\]/ { pending=1; next }
        pending && /^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z0-9_]+/ {
          line=$0
          match(line, /fn[[:space:]]+[A-Za-z0-9_]+/)
          name=substr(line, RSTART+3, RLENGTH-3)
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
          printf "%s\t%s\t%s\t%d\n", crate, name, file, FNR
          pending=0
          next
        }
        /^[[:space:]]*#\[/ { next } # allow stacked attributes between #[test] and fn
        { pending=0 }
      ' "$file"
    done
