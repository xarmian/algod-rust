# Developer Workflow Guide

> **Phase 4 is complete.** See [PHASE4_VALIDATION.md](PHASE4_VALIDATION.md) for the validation report.
>
> **Phase 3 is complete.** See [PHASE3_VALIDATION.md](PHASE3_VALIDATION.md) for the validation report.
>
> **Phase 2 is complete.** See [PHASE2_VALIDATION.md](PHASE2_VALIDATION.md) for the validation report.
>
> **Phase 1 is complete.** See [PHASE1_VALIDATION.md](PHASE1_VALIDATION.md) for the validation report.
>
> **Phase 0 is complete.** See [PHASE0_VALIDATION.md](PHASE0_VALIDATION.md) for the validation report
> and [PHASE1_PROPOSAL.md](PHASE1_PROPOSAL.md) for the Phase 1 roadmap (now completed).

## Quick Reference

```
make help               # Show all available targets
make localnet-up        # Start devnet (algod-go + txn-generator)
make localnet-down      # Stop devnet, remove volumes
make localnet-status    # Query current node status
make generate-txns N=6  # Send N test transactions
make fixtures           # Full fixture regeneration pipeline
make test               # Run all tests
make validate           # Runtime conformance check
```

## Generating Diverse Transaction Fixtures

To generate fixtures covering all supported transaction types (not just payments):

```bash
make fixtures-diverse
```

This does:
1. Starts the localnet (`make localnet-up`)
2. Runs `generate-diverse-txns.sh` which creates:
   - **pay** -- Payment transaction
   - **acfg** -- ASA create (with freeze/clawback addresses)
   - **axfer** -- ASA opt-in and transfer
   - **afrz** -- ASA freeze
   - **appl** -- Application create and call
   - **keyreg** -- Participation key generation + register online
3. Sends one extra transaction so the final block digest can be extracted
4. Captures blocks as msgpack fixtures
5. Runs the Go canonical-extract tool to generate reference hex files

You can also run the diverse transaction generator standalone against a running localnet:

```bash
make localnet-up
make generate-diverse-txns
```

The `DIVERSE_FIXTURE_BLOCKS` variable controls how many blocks are captured (default 12).

## Starting the Localnet

```bash
make localnet-up
```

This starts:
- **algod-go**: Algorand node in DEV_MODE (port 4001)
- **txn-generator**: Sidecar that sends payment transactions every 5s

DEV_MODE only produces blocks when transactions are submitted. The txn-generator
sidecar handles this automatically, but you can also send transactions manually.

## Sending Transactions Manually

```bash
# Send 6 transactions
make generate-txns N=6

# Or directly via docker:
docker exec algod-go goal clerk send -a 1000 \
    -f $(docker exec algod-go goal account list -d /algod/data | head -1 | awk '{print $2}') \
    -t $(docker exec algod-go goal account list -d /algod/data | tail -1 | awk '{print $2}') \
    -d /algod/data -n "my-txn"
```

Key flags for `goal clerk send`:
- `-a`: Amount in microAlgos
- `-f`: From address
- `-t`: To address
- `-d`: Data directory (always `/algod/data` inside container)
- `-n`: Note field (arbitrary string)
- Use lowercase `-n` for note (not `-N`)

## Account Discovery

```bash
# List accounts in the devnet wallet
docker exec algod-go goal account list -d /algod/data

# First account (typically the genesis account with all funds)
docker exec algod-go goal account list -d /algod/data | head -1 | awk '{print $2}'
```

## Regenerating Test Fixtures

The easiest way is the all-in-one pipeline:

```bash
make fixtures
```

This does:
1. Starts the localnet (`make localnet-up`)
2. Generates 6 transactions (5 blocks + 1 extra for block 5's digest)
3. Captures blocks 1-5 as msgpack fixtures
4. Copies them to the test directory
5. Runs the Go canonical-extract tool to generate reference hex files

### Why N+1 Transactions?

Block digests are extracted from the *next* block's `prev` field. To get block 5's
digest, block 6 must exist, which requires a 6th transaction. The `make fixtures`
target handles this automatically.

### Manual Steps (if needed)

```bash
# 1. Start localnet
make localnet-up

# 2. Generate transactions (6 = 5 blocks + 1 for digest extraction)
make generate-txns N=6

# 3. Capture blocks
make capture

# 4. Copy to test fixtures directory
cp fixtures/block_{1,2,3,4,5}.msgpack crates/core/algo-codec/tests/fixtures/

# 5. Generate Go canonical reference bytes
make canonical-extract
```

## Running Tests

```bash
# All tests (requires fixtures to be present)
make test

# Tests skip gracefully if fixtures are missing, printing SKIPPED messages.
# To generate fixtures first:
make fixtures && make test
```

## Conformance Validation

```bash
# Against running localnet
make localnet-up
make validate
```

The validate command compares Rust block decoding against live Go blocks and
writes a report to `./reports/conformance.json`.

## go-algorand Reference Source

The go-algorand source is available at `../go-algorand`, pinned to `v4.5.1-stable`:

```bash
cd ../go-algorand
git log --oneline -1   # should show v4.5.1-stable tag
```

Use this as the authoritative reference when implementing AVM opcodes, consensus
params, field indices, and protocol semantics. Key files:

| File | Contents |
|------|----------|
| `data/transactions/logic/opcodes.go` | Opcode table, version gating, OpSpec |
| `data/transactions/logic/eval.go` | Opcode implementations (opTxn, opGlobal, etc.) |
| `data/transactions/logic/resources.go` | Reference resolution, resource tracking |
| `data/transactions/logic/fields.go` | TxnField, GlobalField, AssetHoldingField enums |
| `config/consensus.go` | Consensus params per protocol version |
| `protocol/consensus.go` | Version constants (`ConsensusCurrentVersion = V41`) |

go-algorand 4.5.1 consensus versions → AVM versions:
- V39 → AVM 10
- V40 → AVM 11 (mimc opcode, consensus incentives)
- V41 → AVM 12 (falcon_verify, app versioning) — **this is ConsensusCurrentVersion**

## Docker Image

- Image: `algorand/algod:4.5.1-stable` (no `v` prefix)
- Token: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (64 `a`s, devnet convention)
- Port: 4001 (host) -> 8080 (container)

## Go Canonical-Extract Tool

Located at `docker/scripts/canonical-extract/`. Requires Go 1.21+ and a running localnet.

```bash
# Run standalone
cd docker/scripts/canonical-extract
go run . -algod-url http://localhost:4001 \
    -algod-token aaaa...aa \
    -rounds 1-5 \
    -output-dir ../../../crates/core/algo-codec/tests/fixtures/canonical
```

Output files per block:
- `block_N_txn_I.canonical.hex` — Canonical encoded transaction
- `block_N_txn_I.txid.hex` — Transaction ID (SHA512/256)
- `block_N_stxn_I.canonical.hex` — Canonical encoded signed transaction
- `block_N.digest.hex` — Block digest (from block N+1's `prev` field)

## V13 Opcode Vector Regeneration

TEAL v13 opcodes (`sumhash512` 0x86, `sha512` 0x87) are tested against fixture
files produced directly by go-algorand's underlying primitives. The fixtures
live at:

- `crates/core/algo-avm/tests/fixtures/v13/sha512/vectors.json`
- `crates/core/algo-avm/tests/fixtures/v13/sumhash512/vectors.json`

Each file is a JSON array of `{name, input_hex, output_hex}` entries.

### Regenerating

The capture tool is a standalone Go module at `tools/v13-vector-capture/`.
It depends on the same `github.com/algorand/go-sumhash v0.1.0` package used by
go-algorand's `data/transactions/logic/crypto.go`.

```bash
cd tools/v13-vector-capture
go run . -out=../../crates/core/algo-avm/tests/fixtures/v13
```

Output is deterministic (seeded `math/rand`), so regeneration against the same
module versions produces byte-identical fixture files. Regenerate only when
advancing `go-algorand` to a consensus version that changes `sumhash512`
semantics — otherwise treat the committed fixtures as golden.

### References

- go-algorand `data/transactions/logic/crypto.go:120` — `opSumhash512`
- go-algorand `data/transactions/logic/crypto.go:128` — `opSHA512`
- go-algorand `data/transactions/logic/opcodes.go:657-658` — opcode specs

## VRF Vector Regeneration

Byte-exact VRF parity is the foundation of Phase 6 — Rust's pure-Rust ECVRF
implementation must agree with go-algorand's `crypto/vrf.go` (which delegates
to the Algorand libsodium-fork) on every proof and output. Ground-truth
vectors are produced by a standalone Go tool and consumed by the Rust parity
harness (TASK-52, a follow-up task).

### Fixture location

- `crates/core/algo-consensus-crypto/tests/fixtures/vrf/vectors.jsonl`
  — JSONL corpus (≥10,000 entries; see the directory's README for the schema).

### One-time prerequisites

The capture tool imports `github.com/algorand/go-algorand/crypto`, which is a
CGo wrapper over the `libsodium-fork` vendored under `../go-algorand/crypto/
libsodium-fork/`. Before the tool can link on Linux, build the fork's static
library:

```bash
# Debian/Ubuntu prerequisites
sudo apt install -y autoconf automake libtool
cd ../go-algorand && make libsodium
```

This produces `../go-algorand/crypto/libs/linux/amd64/lib/libsodium.a` plus
the fork's headers under `crypto/libs/linux/amd64/include/sodium/`. The CGo
directives in `go-algorand/crypto/vrf.go` (`#cgo linux,amd64 CFLAGS:
-I${SRCDIR}/libs/linux/amd64/include`) then resolve automatically when the
capture tool is built with a `replace` directive pointing at the local
checkout.

### Regenerating

```bash
cd tools/vrf-vector-capture
go run .
```

Runtime: ~5 seconds for the default 10,000-vector corpus on a modern x86_64
laptop. Output is deterministic (fixed RNG seed + stable iteration order);
two runs against the same go-algorand pin produce byte-identical fixtures.

The tool refuses to run unless `../go-algorand` is checked out at exactly
the tag tracked in `CLAUDE.md` (currently `v4.5.1-stable`) with a clean
`crypto/` and `protocol/` tree. This prevents a developer's local branch
state from silently changing the golden corpus. If you are intentionally
regenerating against a different pin (e.g. preparing a go-algorand bump),
pass `--allow-unpinned` — but then the resulting fixture is out-of-sync
with the rest of the workspace and must not be committed until the pin
update lands.

### When to regenerate

- Bumping the go-algorand pin to a release that touches `crypto/vrf.go` or
  `crypto/libsodium-fork` (extremely rare inside a v4.x minor series).
- Extending the fixed edge-case matrix in `tools/vrf-vector-capture/main.go`.
  Append only — do not rename or reorder existing fixed entries, because
  downstream tests reference them by the `name` field.

If the regenerated file disagrees with the committed one on any TV1/TV2 line,
stop: the IETF draft-03 constants are external anchors and divergence means
the capture environment is broken, not the corpus.

### References

- go-algorand `crypto/vrf.go:82` — `VrfKeygenFromSeed`
- go-algorand `crypto/vrf.go:99` — `proveBytes` / `C.crypto_vrf_prove`
- go-algorand `crypto/vrf.go:117` — `VrfProof.Hash` / `C.crypto_vrf_proof_to_hash`
- go-algorand `crypto/util.go:38` — `HashRep[H Hashable]` (empty HashID ⇒ identity,
  used to feed raw alpha through `sk.Prove` in the capture tool)
- IETF draft-irtf-cfrg-vrf-03 §A.4 — TV1 / TV2 anchor vectors

## Sortition Vector Regeneration

Rust's `algo_consensus_crypto::sortition::select` must agree with Go's
`github.com/algorand/sortition v1.0.0` on every committee-weight decision —
disagreement at precision-boundary money values (stakes in the `2^59..2^62`
microalgo range) would cause committee-selection disagreement and fork the
network. Parity is captured from a standalone Go tool and checked against
Rust via an integration test.

### Fixture location

- `crates/core/algo-consensus-crypto/tests/fixtures/sortition/vectors.jsonl`
  — JSONL corpus (≥5,000 entries; ~200 in the precision-stress band).

### One-time prerequisites

The capture tool depends on `github.com/algorand/sortition v1.0.0`, which
is a CGo wrapper around Boost 1.65.1's binomial CDF (`sortition.cpp`).
Boost 1.65.1 headers are vendored under the module directory, so no system
Boost is required, but a working C++ toolchain is. On Debian/Ubuntu that
means `g++` (installed by default with `build-essential`); the stock
toolchain worked locally with no extra setup.

### Regenerating

```bash
cd tools/sortition-vector-capture
go run .
```

Runtime: ~4 seconds for the default 5,189-vector corpus. Output is
deterministic (fixed RNG seed + stable iteration order); two runs produce
byte-identical `vectors.jsonl`. Module pinning is enforced through
`go.sum` — a mismatched `github.com/algorand/sortition` version breaks
module resolution at build time, so there's no runtime pin check needed
(unlike the VRF tool, which links a locally-replaced go-algorand).

### Known parity gap — ratio == 1.0 edge cases

The parity harness at `crates/core/algo-consensus-crypto/tests/sortition_parity.rs`
allowlists **13 `digest_max` fixture divergences**. These are ratio=1.0
exactly (VRF output = 0xff…ff), where Rust's numerically-stable log-PMF
recurrence saturates the CDF one f64 ulp below 1.0 while Boost's
regularized-incomplete-beta evaluation rounds up to exactly 1.0 at a
specific j. Production impact is nil: a 256-bit uniform VRF output
producing exactly 0xff…ff is cryptographically unreachable (~2^-256 per
query). Follow-up work is tracked separately — see `is_known_boost_saturation_divergence`
in the parity test for the exhaustive list; any divergence outside that
list hard-fails the test.

### When to regenerate

- Bumping `github.com/algorand/sortition` in `tools/sortition-vector-capture/go.sum`
  (effectively never — v1.0.0 is stable).
- Extending the fixed parameter or digest matrix in `main.go`. Append
  only, never renumber — downstream harness allowlists reference fixtures
  by the `name` field.

### References

- go-algorand `data/committee/credential.go:106` — `sortition.Select` production call site
- sortition@v1.0.0 `sortition.go:44` — Go `Select` signature
- sortition@v1.0.0 `sortition.cpp:10` — Boost-backed CDF walk
- Rust `crates/core/algo-consensus-crypto/src/sortition.rs:92` — `select` under test
