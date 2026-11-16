#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Run the Go and Rust TEAL corpus drivers (issue #2366, epic #2364) over a corpus
# from scripts/teal-corpus/extract.py and diff their outputs.
#
#   run_drivers.sh CORPUS_DIR OUT_DIR [disassemble|assemble ...]
#
# Needs GO_DRIVER (built by tools/teal-corpus/build.sh) and RUST_DRIVER (the
# `teal-corpus` binary from `cargo build -p teal-corpus --release`) in the
# environment. Writes <op>.go.jsonl, <op>.rust.jsonl and <op>.mismatches.jsonl
# per operation into OUT_DIR. Exit 0 when every operation matches, 1 on any
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
for op in "${OPS[@]}"; do
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
