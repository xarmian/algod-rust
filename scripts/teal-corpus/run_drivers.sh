#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Run the Go and Rust TEAL corpus drivers (issue #2366, epic #2364) over a corpus
# from scripts/teal-corpus/extract.py and diff their outputs.
#
#   run_drivers.sh CORPUS_DIR OUT_DIR [disassemble|assemble|reassemble ...]
#
# Needs GO_DRIVER (built by tools/teal-corpus/build.sh) and RUST_DRIVER (the
# `teal-corpus` binary from `cargo build -p teal-corpus --release`) in the
# environment. Writes <op>.go.jsonl, <op>.rust.jsonl and <op>.mismatches.jsonl
# per operation into OUT_DIR. The `reassemble` stage (issue #2368) assembles go's
# disassembly of every program with both drivers, gates on equality, cross-checks
# rust.assemble(rust.disassemble(P)) and prints the fixed-point statistics
# (scripts/teal-corpus/reassemble.py; it runs the disassemble stage first when
# OUT_DIR has no disassemble outputs). Exit 0 when every operation matches, 1 on any
# mismatch, 2 on a usage or driver failure.
set -uo pipefail
CORPUS="${1:?usage: run_drivers.sh CORPUS_DIR OUT_DIR [op...]}"
OUT="${2:?usage: run_drivers.sh CORPUS_DIR OUT_DIR [op...]}"
shift 2
OPS=("$@")
[ ${#OPS[@]} -gt 0 ] || OPS=(disassemble assemble)
: "${GO_DRIVER:?set GO_DRIVER to the built tools/teal-corpus binary}"
: "${RUST_DRIVER:?set RUST_DRIVER to the built teal-corpus binary}"
mkdir -p "$OUT"
status=0
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

# reassemble_stage: issue #2368. Needs the disassemble outputs of both drivers.
reassemble_stage() {
  local rc
  if [ ! -f "$OUT/disassemble.go.jsonl" ] || [ ! -f "$OUT/disassemble.rust.jsonl" ]; then
    bash "${BASH_SOURCE[0]}" "$CORPUS" "$OUT" disassemble || true
  fi
  "$PY" -I "$HERE/reassemble.py" prepare "$OUT" || return 2
  "$GO_DRIVER" assemble --corpus "$CORPUS" --input-dir "$OUT/reasm-go/sources" --out "$OUT/reassemble.go.jsonl"
  rc=$?; [ $rc -eq 0 ] || { echo "go reassemble driver exited $rc" >&2; return 2; }
  "$RUST_DRIVER" assemble --corpus "$CORPUS" --input-dir "$OUT/reasm-go/sources" --out "$OUT/reassemble.rust.jsonl"
  rc=$?; [ $rc -eq 0 ] || { echo "rust reassemble driver exited $rc" >&2; return 2; }
  "$RUST_DRIVER" assemble --corpus "$CORPUS" --input-dir "$OUT/reasm-rust/sources" --out "$OUT/reassemble.rust-text.jsonl"
  rc=$?; [ $rc -eq 0 ] || { echo "rust reassemble (rust text) driver exited $rc" >&2; return 2; }
  "$PY" -I "$HERE/reassemble.py" report "$CORPUS" "$OUT"
}

for op in "${OPS[@]}"; do
  if [ "$op" = reassemble ]; then
    reassemble_stage
    rc=$?
    if [ $rc -eq 1 ]; then [ $status -eq 2 ] || status=1
    elif [ $rc -ne 0 ]; then status=2; fi
    continue
  fi
  "$GO_DRIVER" "$op" --corpus "$CORPUS" --out "$OUT/$op.go.jsonl"
  rc=$?; [ $rc -eq 0 ] || { echo "go $op driver exited $rc" >&2; status=2; }
  "$RUST_DRIVER" "$op" --corpus "$CORPUS" --out "$OUT/$op.rust.jsonl"
  rc=$?; [ $rc -eq 0 ] || { echo "rust $op driver exited $rc" >&2; status=2; }
  "$RUST_DRIVER" diff "$OUT/$op.go.jsonl" "$OUT/$op.rust.jsonl" --out "$OUT/$op.mismatches.jsonl"
  rc=$?
  if [ $rc -eq 1 ]; then [ $status -eq 2 ] || status=1
  elif [ $rc -ne 0 ]; then status=2; fi
done
exit $status
