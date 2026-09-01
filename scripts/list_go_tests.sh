#!/usr/bin/env bash
# List every Go test function in the pinned go-algorand reference checkout
# (../go-algorand relative to this repo), as a TSV:
#   package<TAB>test_name<TAB>file<TAB>line
#
# Usage: scripts/list_go_tests.sh [path-to-go-algorand] > docs/phase17/go_tests.tsv
#
# Used by Phase 17 (docs/PHASE17_PROPOSAL.md) to build the go-algorand <->
# algod-rust test parity table. Re-run whenever the go-algorand pin moves,
# or to regenerate the parity table from scratch.
set -euo pipefail

GO_ALGORAND_DIR="${1:-../go-algorand}"

if [ ! -d "$GO_ALGORAND_DIR" ]; then
  echo "error: go-algorand checkout not found at $GO_ALGORAND_DIR" >&2
  exit 1
fi

cd "$GO_ALGORAND_DIR"

printf 'package\ttest_name\tfile\tline\n'

# Match top-level `func TestXxx(t *testing.T)` / `func TestXxx(t *testing.T, ...)`
# style functions across all _test.go files, excluding vendor/testdata.
grep -rnE '^func Test[A-Za-z0-9_]+\(' --include='*_test.go' . \
  | grep -v '/vendor/' | grep -v '/testdata/' \
  | while IFS=: read -r file line rest; do
      test_name=$(printf '%s' "$rest" | sed -E 's/^func (Test[A-Za-z0-9_]+)\(.*/\1/')
      pkg_dir=$(dirname "$file")
      pkg_dir="${pkg_dir#./}"
      printf '%s\t%s\t%s\t%s\n' "$pkg_dir" "$test_name" "${file#./}" "$line"
    done
