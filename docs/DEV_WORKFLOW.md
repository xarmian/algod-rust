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
