#!/usr/bin/env bash
#
# Capture PQSig (Falcon-1024) msgpack fixtures from a real go-algorand
# `algokey pq` run, for the byte-exact conformance tests in
# `crates/core/algo-codec/tests/pqsig_canonical_test.rs` (issue #707).
#
# Requires go-algorand pinned to v5.0.0-stable (this repo's pin) at
# ../go-algorand, plus a C toolchain to build its vendored libsodium fork
# (`make libsodium` — see CLAUDE.md's CI-workflows note). On a plain
# Windows dev box without a working cgo toolchain, build inside a Linux
# container instead (this is what was actually used to capture the
# committed fixtures — see below); this script assumes ALGOKEY already
# points at a working `algokey` binary built from that checkout.
#
# Usage:
#   ALGOKEY=/path/to/algokey bash scripts/capture-pqsig-fixtures.sh
#
# Docker recipe used to produce the committed fixtures (Windows host,
# no local cgo toolchain):
#
#   export MSYS_NO_PATHCONV=1   # git-bash: stop it from mangling /src
#   docker run --rm -v "$(cd ../go-algorand && pwd -W 2>/dev/null || pwd):/src" \
#     -w /src golang:1.25-bookworm bash -c '
#       set -e
#       apt-get update -qq && apt-get install -y -qq \
#         autoconf automake libtool build-essential dos2unix >/dev/null
#       # The reference checkout'"'"'s libsodium-fork submodule and
#       # scripts/*.sh carry CRLF line endings on a Windows checkout;
#       # autoconf/configure/make need LF. Fix only the build-time
#       # scripts, in the container, not the on-disk checkout.
#       find crypto/libsodium-fork -type f -exec sh -c \
#         '"'"'head -c2 "$1" | grep -q "#!" && dos2unix -q "$1"'"'"' _ {} \; || true
#       make OS_TYPE=linux ARCH=amd64 libsodium
#       CGO_ENABLED=1 go build -o /src/algokey-linux ./cmd/algokey
#     '
#
# Then run this script with ALGOKEY=../go-algorand/algokey-linux (via the
# same container, or any Linux host — the binary only needs to run, not
# to match the dev box's OS).
#
# Fixture key material: derived deterministically via
# `algokey pq import -m "<mnemonic>"` from the well-known all-zero test
# mnemonic (`abandon abandon abandon ... invest`, seed
# `00000000...0000`) already used by
# `crates/core/algo-consensus-crypto/tests/passphrase_parity.rs` — so
# re-running this script reproduces bit-identical fixtures from a clean
# go-algorand checkout, no secret material is at stake, and the capture
# is fully deterministic (no `algokey pq generate`, which draws from
# `crypto/rand`).

set -euo pipefail

ALGOKEY="${ALGOKEY:-algokey}"
if ! command -v "$ALGOKEY" >/dev/null 2>&1; then
    echo "error: ALGOKEY=$ALGOKEY not found" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX_DIR="$REPO_ROOT/crates/core/algo-codec/tests/fixtures/pqsig"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$FIX_DIR"

MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest"

# 1. Deterministic PQ (Falcon-1024) key from the well-known test mnemonic.
"$ALGOKEY" pq import -m "$MNEMONIC" -k "$TMP/pqkey" >"$TMP/pq_import.stdout"

# 2. An *unsigned* SignedTxn (a plain "pay" transaction) to hand to
# `algokey pq sign`. There's no `algokey`/`goal` one-liner to emit a raw
# unsigned SignedTxn to a file, so this small ad hoc harness (deleted
# after use, never committed to ../go-algorand) builds one directly
# against go-algorand's own `data/transactions` package — see the issue
# body's "small ad hoc harness under ../go-algorand" scoping note.
GO_ALGORAND="$(cd "$REPO_ROOT/../go-algorand" && pwd)"
HARNESS_DIR="$GO_ALGORAND/cmd/pqfixture"
mkdir -p "$HARNESS_DIR"
cat >"$HARNESS_DIR/main.go" <<'GOEOF'
// Temporary ad hoc harness for algod-rust issue #707 (not part of
// go-algorand's own tool set). Produces an *unsigned* SignedTxn msgpack
// file so that `algokey pq sign` can attach a real PQSig to it. Deleted
// after fixture capture; never intended to be committed to this repo.
package main

import (
	"fmt"
	"os"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pqfixture <outfile>")
		os.Exit(1)
	}

	var sender basics.Address
	for i := range sender {
		sender[i] = 9
	}
	var genesisHash [32]byte
	for i := range genesisHash {
		genesisHash[i] = byte(0x10 + i)
	}

	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: 1000},
			FirstValid:  basics.Round(1),
			LastValid:   basics.Round(1000),
			Note:        []byte("pqsig fixture #707"),
			GenesisID:   "algod-rust-pqsig-fixture-v1",
			GenesisHash: genesisHash,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: sender,
			Amount:   basics.MicroAlgos{Raw: 5000},
		},
	}

	stxn := transactions.SignedTxn{Txn: txn}
	if err := os.WriteFile(os.Args[1], protocol.Encode(&stxn), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
GOEOF

(cd "$GO_ALGORAND" && go run ./cmd/pqfixture "$TMP/unsigned_txn.msgp")
rm -rf "$HARNESS_DIR"

# 3. Sign the txn -> SignedTxn.PQsig (+ AuthAddr, since Sender != PQ addr).
"$ALGOKEY" pq sign -k "$TMP/pqkey" -t "$TMP/unsigned_txn.msgp" -o "$TMP/signed_txn_pqsig.msgp"

# 4. Sign a program -> LogicSig.PQsig. Bytes are a trivial "int 1"
# compiled program (version byte 0x06 + pushint opcode 0x81 + value 0x01);
# not valid printable-ASCII TEAL *source*, so `algokey` treats it as
# compiled bytecode as required.
printf '\x06\x81\x01' >"$TMP/program.bin"
"$ALGOKEY" pq sign-program -k "$TMP/pqkey" -p "$TMP/program.bin" -o "$TMP/logicsig_pqsig.msgp"

# 5. Hex-encode into the committed fixture files.
xxd -p "$TMP/signed_txn_pqsig.msgp" | tr -d '\n' >"$FIX_DIR/signed_txn_with_pqsig.canonical.hex"
echo >>"$FIX_DIR/signed_txn_with_pqsig.canonical.hex"
xxd -p "$TMP/logicsig_pqsig.msgp" | tr -d '\n' >"$FIX_DIR/logicsig_with_pqsig.canonical.hex"
echo >>"$FIX_DIR/logicsig_with_pqsig.canonical.hex"

echo "Captured PQSig fixtures under $FIX_DIR"
echo "Verify with: git diff $FIX_DIR  # should be empty on a re-capture"
