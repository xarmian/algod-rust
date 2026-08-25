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

## Rust Localnet (Docker)

A drop-in alternative to the `algod-go` localnet that runs the **Rust** node
(`algod-rust node start --dev`) in docker. Genesis (`devmode: true`) and config
are baked into the image; dev mode produces one block per submitted transaction
group, so a fresh `up` is immediately ready for `goal clerk send`.

```bash
make localnet-rust-up      # Build the image + start the Rust dev node (port 4001)
make localnet-rust-status  # Query /v2/status
make localnet-rust-logs    # Tail the node logs
make localnet-rust-down    # Stop and remove volumes
```

The node serves the algod v2 REST API on `http://localhost:4001` with the same
fixed token as the Go localnet
(`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`), so existing
tooling and scripts point at it unchanged. The first `make localnet-rust-up`
build compiles the Rust workspace in release mode and can take 10–20 minutes;
subsequent builds reuse the docker layer cache.

### Driving it with `goal` / `goal-rust`

The image ships only the `algod-rust` daemon — there is no `goal` / `goal-rust`
client inside the container. Drive it from the host against the published REST
endpoint (`http://localhost:4001`, fixed `aaaa…` token):

```bash
# Raw REST:
curl -s -H "X-Algo-API-Token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    http://localhost:4001/v2/status

# Or with a host-installed goal-rust / goal pointed at the endpoint.
```

`goal` / `goal-rust` normally read `algod.net` + `algod.token` from a data dir.
The container's data dir is `/algod/data`, but the node writes `algod.net` with
its *container* bind address (`0.0.0.0:8080`), so a copied-out data dir would
dial the wrong endpoint — point your client at `127.0.0.1:4001` instead (e.g.
rewrite `algod.net`, or use whatever endpoint flag your client exposes). The
token is the fixed `aaaa…` value above.

The staged `config.json` in the data dir is a go-algorand-format placeholder for
operator familiarity; the Rust `node start` command does not consume it (it
takes its listen address from `-l` and tokens from `algod.token`).

### The funded dev account

The baked genesis funds a single dev account so you can sign and submit
transactions immediately:

- **Address:** `E4A7NFAARAKFG4ZK7KQ7VZBO5XEQIUKBK2U3KNLAFTX6R3HTJBFG75MQZE`
- **Mnemonic (25 words):**
  `under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic`

Import it to sign transactions:

```bash
goal-rust account import -m "under this above produce during card issue fire gloom reopen topple rough cat smooth salad put broken decade vocal loud pulp gauge hurdle absorb olympic"
# or with the Go toolchain:
algokey import -m "under this above produce …" -f dev.key
```

This account is for **local development only** — never fund it on a public
network. The staged data dir lives at `docker/localnet-rust/data/` and the
image is built from the `localnet` target in `docker/Dockerfile`.

The staged `genesis.json` is generated from `genesis.json.in` by
`docker/scripts/gen-localnet-genesis.sh`, which derives the `proto` spec-URL
from the shared `CONSENSUS_CURRENT_VERSION` constant
(`crates/core/algo-types/src/consensus.rs`) instead of hardcoding it. `make
localnet-rust-up` regenerates it automatically; after bumping
`CONSENSUS_CURRENT_VERSION`, run `make localnet-rust-genesis` (or `localnet-rust-up`)
to refresh the committed file.

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

The go-algorand source is available at `../go-algorand`, pinned to `v4.7.0-stable`:

```bash
cd ../go-algorand
git log --oneline -1   # should show v4.7.0-stable tag
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

go-algorand 4.6.0 consensus versions → AVM versions:
- V39 → AVM 10
- V40 → AVM 11 (mimc opcode, consensus incentives)
- V41 → AVM 12 (falcon_verify, app versioning) — **this is ConsensusCurrentVersion**

## Docker Image

- Image: `algorand/algod:4.7.0-stable` (no `v` prefix)
- Token: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (64 `a`s, devnet convention)
- Port: 4001 (host) -> 8080 (container)

## Go Canonical-Extract Tool

Located at `docker/scripts/canonical-extract/`. Requires Go 1.25+ and a running localnet. (The 1.25 floor comes from the pure-Go SQLite driver `modernc.org/sqlite` used by `-mode trackerdb-blobs` — `-mode blocks` itself only needs 1.21+, but the module is shared.)

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

### Trackerdb BLOB fixtures (PLAN-36 G8 / TASK-119)

The same tool, under `-mode trackerdb-blobs`, opens a Go-produced
`<prefix>.tracker.sqlite` directly and dumps every BLOB column as a hex
fixture — the byte corpus for the G8 canonical-encoder tasks
(`BaseAccountData`, `BaseOnlineAccountData`, `ResourcesData`,
`OnlineRoundParamsData`, `TxTailRound`, `StateProofVerificationContext`).

Run the full pipeline against a running localnet:

```bash
# Bring up localnet + push enough txns to populate the trackerdb tables.
make fixtures-diverse

# Copy the Go-produced tracker DB out of the algod-go container, then
# dump every BLOB row to <repo>/crates/core/algo-codec/tests/fixtures/trackerdb/.
make extract-trackerdb-fixtures
```

Output layout (one subdirectory per BLOB type, each containing one
`.canonical.hex` per row plus a `_meta.json` recording the source
go-algorand version, source data-dir prefix, capture timestamp, and
highest round seen):

- `trackerdb/baseaccountdata/<addrhex>.canonical.hex` (from `accountbase.data`)
- `trackerdb/baseonlineaccountdata/<addrhex>_<updround>.canonical.hex` (from `onlineaccounts.data`)
- `trackerdb/resourcesdata/<addrhex>_<aidx>_<ctype>.canonical.hex` (from `resources.data` joined with `accountbase.address`)
- `trackerdb/onlineroundparams/<round>.canonical.hex` (from `onlineroundparamstail.data`)
- `trackerdb/txtailround/<round>.canonical.hex` (from `txtail.data`)
- `trackerdb/stateproof/<round>.canonical.hex` (from `stateproofverification.verificationcontext`)

**Caveat:** `stateproof/` is typically empty on a fresh localnet — state-proof rows only land after enough rounds with `EnableStateProof=true`. The
`_meta.json` records `row_count: 0` in that case so a downstream encoder
test can skip gracefully. Run the localnet longer (≥256 rounds with
state-proof participation enabled) or capture from a long-running testnet
node to get coverage for that type.

The Make recipe `docker cp`s the tracker `.sqlite` file **plus** its
`-wal` and `-shm` sidecars out of the container — go-algorand opens
the tracker DB in WAL mode, so the latest rows can live in the WAL
until the next checkpoint. The Go tool opens the captured DB with
`mode=ro` (no `immutable=1`) so SQLite replays the captured WAL on
read and produces a consistent view.

Overrides for the Make target:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TRACKERDB_CONTAINER` | `algod-go` | docker-compose service name shipping the DB |
| `TRACKERDB_CONTAINER_PATH` | _(autodiscovered)_ | in-container path. When unset, the recipe runs `find /algod/data -maxdepth 4 -name ledger.tracker.sqlite` inside the container. Pin manually when the container hosts >1 network. |
| `TRACKERDB_LOCAL_DIR` | `/tmp/algod-rust-extract` | host-side scratch directory for the three captured files |
| `TRACKERDB_LOCAL_COPY` | `$(TRACKERDB_LOCAL_DIR)/ledger.tracker.sqlite` | host-side main DB file (WAL/SHM sit beside it) |

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

## AVM Opcode Vector Regeneration

Opcode-level conformance vectors for the AVM/TEAL interpreter (TASK-301).
These exist because the byte-level conformance harness was block-decode /
state-compare oriented and had **zero** opcode coverage — which is exactly why
the consensus-critical `ed25519verify` divergence **BT-294** (the Rust op
SHA-512/256-prehashed the `"ProgData"||H(Program)||data` payload that go does
not prehash) shipped undetected.

Each vector is a TEAL program + LogicSig args evaluated by go-algorand's
authoritative `logic.EvalSignatureFull` (the path a node takes to validate a
LogicSig txn). The Rust replay
(`crates/tools/algo-conformance/tests/avm_opcode_conformance.rs`) runs the same
program + args through the Rust AVM and asserts the (errored, pass, final
stack) result matches go.

### Fixture location

- `crates/tools/algo-conformance/tests/fixtures/avm/vectors.jsonl` — one JSON
  object per line. Schema + coverage are documented in the sibling
  `fixtures/avm/README.md`.

Coverage centres on the **crypto-verify** opcodes (where BT-294 lived):
`ed25519verify`, `ed25519verify_bare`, `ecdsa_verify` (Secp256k1 + Secp256r1),
`vrf_verify` — each with both a passing and a failing case. The
`ed25519verify/valid` vector is the BT-294 guard: a go-produced signature over
the raw `"ProgData"||H||data` payload that the pre-fix Rust op would have
rejected (verified by temporarily reintroducing the prehash and observing the
replay fail).

### Regenerating

The capture tool is a standalone Go module at `tools/avm-opcode-capture/`. It
imports go-algorand's `data/transactions/logic` and `crypto` packages directly
and generates all signature/key material with a fixed RNG seed, so output is
deterministic.

```bash
cd tools/avm-opcode-capture
go run .
```

The tool enforces the go-algorand pin (`v4.7.0-stable`) at runtime; override
with `--allow-unpinned` only for an intentional capture against a different
checkout. Do not edit `vectors.jsonl` by hand — it is a build artifact.

### Running the replay

```bash
cargo test -p algo-conformance --test avm_opcode_conformance
```

### When to regenerate

- go-algorand pin bump touching `data/transactions/logic/crypto.go`,
  `eval.go`, or `crypto/`.
- Adding new vectors in `tools/avm-opcode-capture/main.go` — append, don't
  renumber, so existing `name` identifiers stay stable.

### References

- go-algorand `data/transactions/logic/eval.go:1228` — `EvalSignatureFull`
- go-algorand `data/transactions/logic/crypto.go:175` — `opEd25519Verify` (BT-294 site)
- go-algorand `data/transactions/logic/crypto.go:162` — `Msg.ToBeHashed` (`"ProgData"||H||data`)
- go-algorand `data/transactions/logic/crypto.go:237` — `opEcdsaVerify`
- go-algorand `data/transactions/logic/crypto.go:401` — `opVrfVerify`

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
the tag tracked in `CLAUDE.md` (currently `v4.7.0-stable`) with a clean
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

### Ratio == 1.0 saturation boundary (TASK-59)

`digest_max` fixtures (VRF output = 0xff…ff ⇒ ratio = 1.0 exactly)
exercise the CDF's f64 saturation-to-1.0 rounding boundary — the
point where Boost's `ibetac(j+1, n-j, p) = 1 - ibeta(..)` rounds up
to exactly `1.0`. Rust's walker matches this byte-for-byte via a
dedicated tail-bound check in `binomial_cdf_walk`, keyed on the
`y ≤ 2^-54` threshold under which `1.0 - y == 1.0` holds in f64
round-to-nearest-even. Every `digest_max` corpus fixture now matches
Go — no allowlist. The parity test also asserts a minimum of 13
`digest_max` fixtures so this coverage can't silently erode (see
`sortition_parity_vs_go_algorand`).

Production impact of the fix: still nil — a 256-bit uniform VRF
output producing exactly 0xff…ff remains cryptographically
unreachable (~2^-256 per query). The fix exists so the conformance
corpus can run byte-exact end-to-end without a maintenance-prone
allowlist.

### When to regenerate

- Bumping `github.com/algorand/sortition` in `tools/sortition-vector-capture/go.sum`
  (effectively never — v1.0.0 is stable).
- Extending the fixed parameter or digest matrix in `main.go`. Append
  only, never renumber — downstream harness state (e.g. the corpus
  size floors in `sortition_parity.rs`) references fixtures by the
  `name` field and by fixture count.

### References

- go-algorand `data/committee/credential.go:106` — `sortition.Select` production call site
- sortition@v1.0.0 `sortition.go:44` — Go `Select` signature
- sortition@v1.0.0 `sortition.cpp:10` — Boost-backed CDF walk
- Rust `crates/core/algo-consensus-crypto/src/sortition.rs:92` — `select` under test

## Agreement Wire Vector Regeneration

Rust's hand-coded `algo-agreement` codec must round-trip every msgpack
wire representation go-algorand's `agreement/msgp_gen.go` produces —
Vote / UnauthenticatedVote / Bundle / Certificate / Proposal /
UnauthenticatedProposal, plus the inner `rawVote`, `proposalValue`,
`voteAuthenticator`, `equivocationVoteAuthenticator`, and
`transmittedPayload` types. Divergence in canonical field ordering,
`omitempty` handling, or integer-width encoding would silently change
vote / cert / proposal hashes and break consensus.

### Fixture location

- `crates/core/algo-agreement/tests/fixtures/wire/` — one subdirectory
  per wire type (`rawvote/`, `uvote/`, `vote/`, `ubundle/`, `cert/`,
  `bundle/`, `uproposal/`, `proposal/`, `tpayload/`, `proposalvalue/`).
  Each fixture is a `<name>.msgpack` blob plus a `<name>.json` metadata
  sidecar. See that directory's `README.md` for the schema, variation
  rationale, and per-subdir counts.

### Why this tool is structurally different from v13 / VRF / sortition captures

Every interesting type in the `agreement` package (`rawVote`,
`unauthenticatedVote`, `vote`, `unauthenticatedBundle`, `bundle`,
`voteAuthenticator`, `equivocationVoteAuthenticator`,
`unauthenticatedProposal`, `transmittedPayload`) is **package-private**,
so an external Go program cannot construct or encode them. The capture
therefore runs as a real Go test *inside* go-algorand's `agreement`
package. Because we never modify the pinned go-algorand checkout, the
tool stages the test file into `../go-algorand/agreement/` at runtime
and removes it afterwards.

The staged file's name — `algod_rust_wire_fixtures_test.go` — is
distinctive enough that a stray copy left by an aborted run is
obviously ours. The wrapper's pin-check skips it in the
dirty-tree scan so a mid-flight cleanup failure doesn't permanently
block future regenerations.

### Regenerating

```bash
cd tools/agreement-wire-capture
go run .
```

Runtime: ~40 s end-to-end on a modern laptop. The regeneration
enforces the same `v4.7.0-stable` pin + clean `agreement/` tree the
VRF tool does. Pass `--allow-unpinned` for intentional
regeneration against a different go-algorand tag (the output will
then be out-of-sync with the rest of the workspace until the pin
update lands). `--keep-staged` leaves the staged test file in
place for debugging.

The test asserts each of the 9 guarded subdirectories has ≥20
fixtures (40 files: .msgpack + .json each); a corpus narrower than
that fails regeneration.

### When to regenerate

- Bumping the go-algorand pin to a release that touches
  `agreement/` (new codec fields, renamed codec tags, etc.).
- Extending the fixture matrix in
  `tools/agreement-wire-capture/fixtures_test.go.tmpl`. Append only —
  stable `name` identifiers keep downstream consumers (TASK-55
  roundtrip harness, TASK-56 fuzz seed corpus) from breaking.

### References

- `agreement/vote.go:30`, `vote.go:42` — `rawVote`, `unauthenticatedVote`
- `agreement/vote.go:50` — `vote` (authenticated)
- `agreement/bundle.go:31`, `bundle.go:46` — `unauthenticatedBundle`, `bundle`
- `agreement/bundle.go:57`, `bundle.go:65` — vote / equivocation authenticators
- `agreement/certificate.go:32` — `type Certificate unauthenticatedBundle`
- `agreement/proposal.go:55`, `proposal.go:89` — `unauthenticatedProposal`, `proposal`
- `agreement/proposal.go:49` — `transmittedPayload`
- `agreement/msgp_gen.go` — canonical msgpack encoders (13K LOC, generated)
- `agreement/golden_vectors_test.go` — starter Go-side anchor (pre-existing,
  untracked in go-algorand)

## Lookback Vector Regeneration

Rust's `algo_agreement::lookback` primitives (`params_round`,
`balance_round`, `seed_round`) are called on every vote verification
and their output depends on the per-version `SeedLookback` /
`SeedRefreshInterval` values in `ConsensusParams`. A silent drift
between Rust's and Go's math — or between Rust's per-version params
table and Go's — causes committee-selection divergence during a
protocol upgrade. The fixture anchors every supported version + a
round matrix at the saturation, seed-lookback, balance-lookback, and
large-round boundaries against Go's actual output.

### Fixture location

- `crates/core/algo-agreement/tests/fixtures/lookback/lookback_boundaries.json`
  — a single pretty-printed JSON envelope with 280 vectors across 35
  consensus versions (V7..V41). Consumed by
  `tests/lookback_boundary.rs`.

### Regenerating

```bash
cd tools/lookback-vector-capture
go run .
```

Runtime: a few seconds (pure call-graph through go-algorand's
`agreement.ParamsRound` / `agreement.BalanceRound` + the replicated
`seedRound` formula; no I/O or crypto). The tool enforces the same
`v4.7.0-stable` pin + clean tree the other captures do, filtering
`_test.go` files out of the dirty-tree scan so pre-existing
untracked anchors (`agreement/golden_vectors_test.go`) don't block
regeneration. Pass `--allow-unpinned` for an intentional capture
against a different go-algorand tag.

### When to regenerate

- Bumping the go-algorand pin to a release that touches
  `agreement/selector.go`, `agreement/params.go`, or per-version
  `SeedLookback` / `SeedRefreshInterval` values in
  `config/consensus.go`.
- Adding a new consensus version to
  `tools/lookback-vector-capture/main.go :: allVersions()` (e.g. V42
  when it lands).

### References

- `agreement/params.go:25`   — `ParamsRound(r)` (exported)
- `agreement/selector.go:53` — `BalanceRound(r, cparams)` (exported)
- `agreement/selector.go:59` — `BalanceLookback(cparams)` = 2·SeedRefreshInterval·SeedLookback
- `agreement/selector.go:63` — `seedRound(r, cparams)` (package-private; replicated in the capture tool)
- `data/basics/units.go:150` — `Round.SubSaturate`
- `config/consensus.go:870`  — v8 overrides `SeedRefreshInterval = 80`
  (v7 default was 100) — the only historical lookback-shifting
  protocol change, explicitly anchored by
  `tests/lookback_boundary.rs :: v7_to_v8_transition_shifts_balance_round_by_160`

## Agreement Codec Tests

Two complementary test harnesses guard the `algo-agreement::codec` wire
roundtrip invariant (`encode(decode(b)) == b` against Go-produced
bytes):

### Fixed-corpus replay — `codec_roundtrip.rs`

Decodes every committed `tests/fixtures/wire/<type>/*.msgpack` fixture
from TASK-54 through Rust's codec, re-encodes it, and asserts
byte-identical equality against the Go-produced input. Covers all 10
fixture subdirectories (`uvote`, `vote`, `ubundle`, `bundle`, `cert`,
`rawvote`, `proposalvalue`, `uproposal`, `proposal`, `tpayload`) —
~205 fixtures total, 17 tests in ≈0.01 s.

```bash
cargo test -p algo-agreement --test codec_roundtrip
```

This is the authoritative conformance check vs `go-algorand/agreement/msgp_gen.go`.
Any roundtrip failure indicates field-ordering, `omitempty`, or
integer-width drift and must be investigated before landing the change.

### Property-based canonical-encoding fuzz — `codec_proptest.rs`

Complements the fixed corpus by feeding the codec structured random
values via `proptest` and asserting the canonical-encoding invariant

```text
encode(decode(encode(v))) == encode(v)
```

Covers the wire types whose codec doesn't require a full
`bookkeeping.Block`: `ProposalValue`, `RawVote`, `UnauthenticatedVote`,
`Vote` (authenticated), `UnauthenticatedBundle`, `AuthenticatedBundle`.
`UnauthenticatedProposal` and `TransmittedPayload` are intentionally
anchored by the fixed corpus only (generating arbitrary valid `Block`
values is out of scope).

```bash
# Default: 256 cases per test, 6 tests — ≈0.6 s
cargo test -p algo-agreement --test codec_proptest

# Extended local run: override the case count via env var
PROPTEST_CASES=100000 cargo test -p algo-agreement --test codec_proptest --release
```

Because the test uses byte-identity (not struct equality), a divergence
manifests as a `prop_assert_eq!` byte-vector mismatch and shrinks down
to the minimal input that exhibits the bug. The `proptest-regressions/`
file committed next to the test is how proptest persists minimized
failure seeds between runs — keep it in git so CI and developers
replay the exact same regression inputs.

## Conformance Fixture Refresh

All PLAN-30 conformance parity dimensions (VRF, sortition, agreement
wire, lookback round math, v13 opcodes) are anchored by **committed
golden fixtures produced by go-algorand**. CI (`.github/workflows/
conformance-parity.yml`) replays those fixtures on every PR and blocks
merge on any byte-level divergence. This section is the playbook for
refreshing the fixtures when go-algorand changes underneath us.

### When to refresh

Refresh the full corpus only when one of the following is true. Do
**not** refresh casually — a stale-but-consistent fixture beats a
fresh-but-drifted one.

1. **go-algorand pin bump** — `CLAUDE.md` is updated to a new
   `v4.x.y-stable` tag. Refresh all fixtures whose upstream source
   touched the new release (typically: all of them, unless the release
   notes prove otherwise).
2. **Schema extension in a capture tool** — e.g. a new fixed edge case
   appended to `tools/vrf-vector-capture/main.go`, or a new
   consensus version added to
   `tools/lookback-vector-capture/main.go :: allVersions()`. Append
   only; never rename or reorder existing fixtures, because downstream
   tests reference them by `name`.
3. **Consensus version added** — e.g. V42 ships. Refresh
   `lookback/lookback_boundaries.json` and the VRF / sortition corpora
   (if their stake sampling depends on the per-version params).
4. **Codec tag rename or field addition in `agreement/`** — regenerate
   the wire fixture corpus.

If a capture tool's output disagrees with the committed file on any
pre-existing line, **stop**. That means the capture environment is
broken (wrong go-algorand tag, dirty working tree, toolchain mismatch)
— don't commit the regenerated file.

### Per-fixture regeneration commands

Each fixture has a dedicated capture tool under `tools/`. Run them
individually; they are idempotent and deterministic given the same
go-algorand pin + toolchain.

| Dimension | Fixture | Regen command |
|-----------|---------|---------------|
| **VRF (β)** | `crates/core/algo-consensus-crypto/tests/fixtures/vrf/vectors.jsonl` | `cd tools/vrf-vector-capture && go run .` |
| **Sortition (γ)** | `crates/core/algo-consensus-crypto/tests/fixtures/sortition/vectors.jsonl` | `cd tools/sortition-vector-capture && go run .` |
| **Agreement wire (ε)** | `crates/core/algo-agreement/tests/fixtures/wire/**` | `cd tools/agreement-wire-capture && go run .` |
| **Lookback (η)** | `crates/core/algo-agreement/tests/fixtures/lookback/lookback_boundaries.json` | `cd tools/lookback-vector-capture && go run .` |
| **v13 opcodes** | `crates/core/algo-avm/tests/fixtures/v13/**` | `cd tools/v13-vector-capture && go run . -out=../../crates/core/algo-avm/tests/fixtures/v13` |

All Go tools enforce the `CLAUDE.md`-tracked go-algorand pin and refuse
to run against a dirty `../go-algorand` tree. Pass `--allow-unpinned`
only when you are deliberately preparing a pin bump — the resulting
fixture is out of sync with the rest of the workspace until the bump
lands.

The per-dimension deep dives above (VRF Vector Regeneration, Sortition
Vector Regeneration, Agreement Wire Vector Regeneration, Lookback
Vector Regeneration, V13 Opcode Vector Regeneration) describe
prerequisites (libsodium build for VRF, Boost pinning for sortition,
etc.). Read them before your first refresh on a new machine.

### Validating a refresh locally

After regenerating one or more fixtures, re-run the parity harnesses
in the same order CI does — this is the fastest way to confirm the
fresh corpus still agrees with the Rust implementation:

```bash
# β  VRF parity
cargo test --release -p algo-consensus-crypto --test vrf_parity

# γ  Sortition parity
cargo test --release -p algo-consensus-crypto --test sortition_parity

# ε  Agreement codec roundtrip (replays the wire fixture corpus)
cargo test --release -p algo-agreement --test codec_roundtrip

# ζ  Canonical-encoding proptest — does not consume fixtures, but
#    catches codec regressions a refresh might silently introduce.
cargo test --release -p algo-agreement --test codec_proptest

# η  Lookback boundary parity
cargo test --release -p algo-agreement --test lookback_boundary

# Or all five at once:
cargo test --release --workspace
```

If any of β / γ / ε / η fail after a refresh, do **not** adjust the
Rust implementation to match the new fixtures — that direction
silently rubber-stamps upstream drift. Instead:

1. Diff the new fixture file against the committed one.
2. Map the diff to the go-algorand commit range that produced it.
3. Port the behavior change to the Rust side, then re-run the harness.

Commit the regenerated fixture **and** the matching Rust change in the
same PR; splitting them leaves `main` red for a window.

### Refreshing during a go-algorand pin bump

The ordered playbook for a pin bump (e.g. `v4.5.1-stable` →
`v4.7.0-stable`):

1. Bump the tag in `CLAUDE.md`.
2. In `../go-algorand`, `git fetch && git checkout <new-tag>` and
   rebuild libsodium (`make libsodium`) if the fork changed.
3. Regenerate every fixture table row above (`--allow-unpinned` is
   not required — the tools will auto-detect the new `CLAUDE.md` tag).
4. Run the five parity tests locally. Fix any divergences on the Rust
   side. Re-run until green.
5. Open a single PR containing `CLAUDE.md` + every refreshed fixture
   + every Rust-side port. CI's `conformance-parity` job replays the
   fresh corpus end-to-end.

## Phase A acceptance fixture capture

PLAN-35 (DB Interchange — Phase A: Reader Side) ships an acceptance
test at `crates/core/algo-ledger/tests/phase_a_acceptance.rs` that
covers the synthesizable half of the gate: a DB built via the
production `--ledger-prefix` path is opened, every cross-task
invariant (G1, G3, G5, G6 parts 1-3, G7, G12, G13) is asserted, and
the chain-meta derivation pipeline round-trips.

The remaining half — **bit-identical `/v2/blocks/{r}` comparison
against a real Go-generated DB** — is fixture-based and lives
outside CI. To capture and check in fixtures for that:

Pin the algod-rust repo root in a shell variable up front — every
step below writes fixtures back into this tree, so don't lose the
path when you `cd ../go-algorand`:

```bash
RUST_REPO="$(pwd)"            # run this from the algod-rust root
FIXDIR="$RUST_REPO/crates/core/algo-ledger/tests/fixtures/phase_a"
mkdir -p "$FIXDIR"
```

1. **Generate a Go data directory** at a known round:
   ```bash
   cd ../go-algorand
   ./scripts/local_install.sh
   goal network create -n acceptance \
       -r tests/testdata/nettemplates/TwoNodes50EachFuture.json \
       -d /tmp/acceptance
   goal network start -d /tmp/acceptance
   # Wait a few rounds (the curl in step 2 needs the network up).
   sleep 30
   ```
   The data directory at `/tmp/acceptance/Node1/<genesisID>/` will
   hold `ledger.tracker.sqlite` + `ledger.block.sqlite` once you
   stop the network in step 3.

2. **Capture the Go `/v2/blocks/{r}` reference response** while the
   network is still running (do NOT stop it before this step):
   ```bash
   ALGOD_PORT=$(cat /tmp/acceptance/Node1/algod.net | cut -d: -f2)
   ALGOD_TOK=$(cat /tmp/acceptance/Node1/algod.token)
   curl -s -H "X-Algo-API-Token: $ALGOD_TOK" \
        "http://localhost:$ALGOD_PORT/v2/blocks/3?format=msgpack" \
        -o "$FIXDIR/block_3.msgp"
   ```

3. **Stop the network and check in** the captured artifacts:
   ```bash
   goal network stop -d /tmp/acceptance
   # Copy the on-disk DB pair alongside the response.
   cp /tmp/acceptance/Node1/*/ledger.tracker.sqlite "$FIXDIR/"
   cp /tmp/acceptance/Node1/*/ledger.block.sqlite   "$FIXDIR/"
   ```
   Keep the genesis round small so the artifacts stay under a few
   hundred KiB.

4. **Add the bit-identical assertion** to a NEW test (don't extend
   `phase_a_acceptance.rs` — that file is meant to run with no
   external dependencies). The new test opens the captured pair,
   stands up the REST API via the `algod-rest-api` crate, requests
   `/v2/blocks/{r}`, and `assert_eq`'s against `block_3.msgp` byte
   for byte.

5. **Re-capture on pin bump.** Every go-algorand pin bump rebuilds
   the fixture pair using the new binary. The bit-identical check
   then proves the Rust REST layer's encoder agrees with the new
   Go release on the same on-disk DB.

## algokey-rust End-to-End Suite

The `algokey-rust` tool ships with an end-to-end test suite that drives
a live `algod-go` localnet and cross-checks every artifact against the
pinned `go-algorand@v4.7.0-stable` `algokey` binary.

```bash
# One-command run (brings up localnet, runs all e2e binaries, tears down):
make algokey-e2e
```

See [`crates/tools/algokey-rust/README.md`](../crates/tools/algokey-rust/README.md)
for the full workflow — prerequisites, individual test invocations, the
JUnit XML output, and CI path-filter details.

The suite is also wired into CI as
[`.github/workflows/algokey-e2e.yml`](../.github/workflows/algokey-e2e.yml),
triggered automatically on PRs touching `algokey-rust` or its
dependencies. Unrelated commits skip it.

## kmd-rust MIXED_CLUSTER Interop Test

`crates/node/algo-kmd/tests/interop_test.rs` covers bidirectional
schema-level interop between `algo-kmd` and go-algorand's actual kmd
driver. The test is **gated** — it runs only when `MIXED_CLUSTER=1` is
set, because it needs the `go` toolchain and the `../go-algorand`
source tree pinned to `v4.7.0-stable`.

```bash
# Default run: gated tests skip cleanly, no `go` needed.
cargo test -p algo-kmd

# Full bidirectional interop:
MIXED_CLUSTER=1 cargo test -p algo-kmd --test interop_test
```

The gated tests cover both write-read directions, each asserting MDK +
every key SK + every multisig preimage:

| Test | Writes | Reads | Asserts |
|---|---|---|---|
| `go_writes_rust_reads` | Go's `driver.SQLiteWalletDriver` (`CreateWallet` + `GenerateKey` + `ImportKey` + `ImportMultisigAddr`) | `algo-kmd::WalletDriver` | MDK + every key SK + every multisig preimage |
| `rust_writes_go_reads` | `algo-kmd::WalletDriver` with the same workload | Go's driver via `tools/kmd-wallet-interop verify` | Same — Go side asserts and exits non-zero on mismatch |

The shared Go driver lives at [`tools/kmd-wallet-interop/`](../tools/kmd-wallet-interop/)
and exposes two subcommands (`write`, `verify`). Workload constants
(`numDerived`, `numImported`, MDK bytes, multisig inputs) are mirrored
between `tools/kmd-wallet-interop/main.go` and `interop_test.rs` — see
the latter's `WALLET_NAME`, `NUM_DERIVED`, `SCRYPT_N`, etc., plus the
`fixed_mdk()` / `imported_seeds()` / `msig_inputs()` helpers. They
must stay in sync — any drift breaks the `rust_writes_go_reads`
direction.

### REST interop (TASK-218 / B10)

`crates/node/algo-kmd/tests/rest_interop_test.rs` covers the
end-to-end REST surface: it spawns the `kmd-rust serve` binary
against a fresh data dir, then drives the full v1 workflow through
go-algorand's official `KMDClient` and verifies every signed payload
under go-algorand's crypto layer. Like the schema-level tests above
it's gated by `MIXED_CLUSTER=1`:

```bash
# Default run: gated, skips with a friendly note.
cargo test -p algo-kmd --test rest_interop_test

# Full REST interop:
MIXED_CLUSTER=1 cargo test -p algo-kmd --test rest_interop_test
```

The driver lives at [`tools/kmd-rest-interop/`](../tools/kmd-rest-interop/)
and exercises (in order):

1. `/versions` (no auth)
2. `/v1/wallets` (empty list)
3. `/v1/wallet` (create) → `/v1/wallet/init` (handle)
4. `/v1/key` (×2 derived keys)
5. `/v1/transaction/sign` → verify Ed25519 sig over `crypto.HashRep(txn)`
6. `/v1/multisig/import` (1-of-1) → `/v1/multisig/sign` → `crypto.MultisigVerify`
7. `/v1/program/sign` → verify Ed25519 sig over `"Program" || data`
8. `/v1/wallet/release` → `/v1/wallet/renew` (must 401)

Any wire-shape, signing-message, or status-code drift between the
two implementations trips the test immediately. The Rust harness
graceful-shutdowns kmd-rust between runs and verifies `kmd.net` /
`kmd.pid` are cleaned up.

## goal-rust ↔ Go-algod MIXED_CLUSTER Interop Test

[`crates/tools/goal-rust/tests/algod_interop_test.rs`](../crates/tools/goal-rust/tests/algod_interop_test.rs)
is the cross-impl gate for the `goal-rust` operator CLI. It proves
that `goal-rust` is wire-compatible with **Go's** `algod` binary —
not just our in-tree algod-rust port. Gated by `MIXED_CLUSTER=1`
like every other cross-impl test:

```bash
# Default run: gated, skips with a friendly note.
cargo test -p goal-rust --test algod_interop_test

# Full cross-impl interop:
MIXED_CLUSTER=1 cargo test -p goal-rust --test algod_interop_test
```

Sequence:

1. `go build -o target/algod-interop/algod ../go-algorand/cmd/algod`
   (cached between runs).
2. Stage a fresh data dir with the devnet genesis from
   `../go-algorand/installer/genesis/devnet/genesis.json` plus a
   minimal `config.json` (DNS bootstrap off, endpoint
   `127.0.0.1:0` so the OS picks a free port).
3. Spawn the Go `algod` against the data dir; poll for the
   daemon-written `algod.net` + `algod.token` (60s timeout).
4. Run `goal-rust node status -d <dir>` — assert exit 0 and
   stdout starts with `Last committed block: ` + carries a
   `Genesis hash: ` line.
5. Run `goal-rust node lastround -d <dir>` — assert exit 0 and
   stdout is `<round>\n`.
6. SIGTERM algod, wait for clean exit.

Wire-shape drift on `/v2/status` or `/v2/versions` between the two
implementations trips the test immediately.

## goal-rust account ↔ Go-algod+kmd MIXED_CLUSTER Interop Test

[`crates/tools/goal-rust/tests/algod_account_interop_test.rs`](../crates/tools/goal-rust/tests/algod_account_interop_test.rs)
extends the cross-impl gate to the **`account` group**, driving it
against **both** Go's `algod` and Go's `kmd` — proving wire-compat for
the wallet/account lifecycle, not just the read-only node endpoints.
Gated by `MIXED_CLUSTER=1` like the others:

```bash
# Default run: gated, skips with a friendly note.
cargo test -p goal-rust --test algod_account_interop_test

# Full cross-impl interop:
MIXED_CLUSTER=1 cargo test -p goal-rust --test algod_account_interop_test
```

Sequence:

1. `go build` both `../go-algorand/cmd/algod` and `.../cmd/kmd`
   into `target/algod-interop/` (cached between runs).
2. Spawn Go `algod` (devnet genesis, `127.0.0.1:0`) and Go `kmd`
   (under `<datadir>/kmd-v0.5`, insecure scrypt for speed); poll each
   for its `*.net` + `*.token` readiness markers.
3. Drive `goal-rust account` against the pair:
   - `wallet new` + `account new` (Go kmd) → capture the new address.
   - `account list --password …` (Go kmd open-handle) → new address
     rendered.
   - `account info` + `account balance` on a genesis-funded `WalletN`
     address (Go algod read paths; assertions cross-check the
     genesis-allocated amount, not just "is a number").
   - `addpartkey` + `listpartkeys` + `deletepartkey` against Go algod's
     admin-token-gated `/v2/participation*` (goal-rust sends the admin
     token — see below).
4. SIGTERM both daemons, reap.

goal-rust resolves the algod token like go-algorand's libgoal: the
**admin token** (`algod.admin.token`) is preferred and falls back to
the regular `algod.token`. The admin token is accepted on every
endpoint and is *required* for the participation handlers, so the
partkey-management steps above work against a real Go algod.

**Deliberate omission** (documented in the test header):
`changeonlinestatus`/`marknonparticipating` need a *funded, signable*
account (devnet genesis ships funded addresses without spending keys),
covered against in-tree algod-rust in `account_changeonlinestatus_e2e.rs`.

## Localnet e2e: drive goal-rust AND Go goal against the Rust node

[`crates/tools/goal-rust/tests/localnet_node_e2e.rs`](../crates/tools/goal-rust/tests/localnet_node_e2e.rs)
is the inverse of the interop test above: the **daemon under test is
the in-tree Rust node** (`algod-rust node start --dev`), and both
`goal-rust` and Go's `goal` are pointed at it to prove the localnet
REST/submit surface is usable like go-algorand for the dev-account
lifecycle (TASK-269 / Phase D2). Gated by `MIXED_CLUSTER=1`:

```bash
# Default run: gated, skips with a friendly note.
cargo test -p goal-rust --test localnet_node_e2e

# Full localnet e2e against the Rust node:
MIXED_CLUSTER=1 cargo test -p goal-rust --test localnet_node_e2e
```

Sequence:

1. Stage a data dir from the localnet-rust dev genesis
   ([`docker/localnet-rust/data/genesis.json`](../docker/localnet-rust/data/genesis.json)),
   which funds the published dev account, then spawn `algod-rust node
   start --dev` (bound to `127.0.0.1:0`) and `kmd-rust serve` (under
   `<datadir>/kmd-v0.5`), each polled for its `*.net`/`*.token`
   readiness markers. Both daemons' stdout+stderr are redirected to
   `node.log`/`kmd.log`, surfaced in the panic message on any failure
   (the A11 lesson).
2. **goal-rust direction** (always under the gate): `wallet new` +
   `account import -m <dev mnemonic>`; `account list` (renders
   `[online]`); `account info` (assets/apps + nonzero Minimum Balance,
   Phase C2); `account balance`; `changeonlinestatus --offline` →
   keyreg submit + dev-mode block + status flips to `[offline]` (Phase
   C1, needs the funded signer); **`clerk send` → a real payment signed
   via `kmd-rust`, submitted to the Rust dev node, and confirmed within
   one dev-mode round (recipient balance grows by the sent amount;
   TASK-287)**; `addpartkey` then `changeonlinestatus --online` →
   status flips back to `[online]`.
3. **Go-goal direction** (only when `../go-algorand` builds): Go `goal
   account info` read path against the Rust node's `/v2/accounts`
   endpoint. If `../go-algorand` is absent or `go build ./cmd/goal`
   fails, this section skips with a note and the goal-rust lifecycle
   above still runs.

**Notes:**

- The **payment submit/confirm path is now driven by `goal-rust clerk
  send`** (TASK-287). Before TASK-287 the whole `clerk` group was a stub
  and the leg ran via Go `goal clerk send`; it has been migrated to the
  Rust CLI. The rest of the `clerk` group (rawsend / sign / group /
  split / compile / dryrun* / simulate / inspect / multisig / tealsign)
  remains stubbed.
