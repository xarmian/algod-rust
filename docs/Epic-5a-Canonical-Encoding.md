We are building algod-rust — a Rust reimplementation of go-algorand. Epics 0-4
are complete (2 commits on main). The codebase has 7 crates in a Cargo workspace,
a working Docker localnet, 12 passing tests, retry/backoff on the REST client,
and field-level conformance comparison across 13 header fields and 9 per-txn fields.

## Epic 5a — Canonical Msgpack Encoding

This epic implements Algorand's canonical msgpack encoding and validates
byte-identical output against Go. NO hashing in this epic — just prove the
canonical bytes match.

### Background

Algorand's canonical encoding (go-algorand `codec/` package) has specific rules:
- Map keys are sorted lexicographically by raw bytes
- Zero-value fields are omitted (Go `omitempty` semantics): zero integers,
  false booleans, empty strings, empty byte arrays, nil/None values
- Uses compact msgpack format (shortest integer representation)
- Deterministic — identical inputs always produce identical bytes
- Encodes structs as msgpack MAPS with string keys (the short field names
  like "snd", "rcv", "amt"), NOT as arrays

The current `encode_block()` in `algo-codec` uses `rmp_serde::to_vec_named()`
which does NOT sort keys and may not pack integers minimally. The canonical
encoding rules are documented in `crates/core/algo-codec/src/canonical.rs`
(currently just a roadmap comment).

### Deliverables

1. **Research go-algorand's `codec/` package**
   - Study `codec/codec.go` and `codec/msgp_encode.go` in go-algorand
   - Document exact rules: key sort order, integer packing, omitempty behavior,
     nested struct handling, how byte arrays vs strings are distinguished
   - Pay attention to how Go handles Address (32-byte array) — is it encoded
     as msgpack Binary or as a fixed-length raw bytes?

2. **Implement canonical encoder** in `crates/core/algo-codec/src/canonical.rs`
   - Replace the roadmap comment with a working implementation
   - Two approaches to consider:
     a) Manual encoding using `rmp::encode` primitives (write map header,
        sort keys, write each field) — more control, more verbose
     b) Encode via rmp-serde then post-process to sort keys — simpler but
        may miss integer packing issues
   - Recommend approach (a) for transactions (critical for txn ID) and
     approach (b) as a fallback/comparison tool
   - Must handle nested structs (Transaction inside SignedTransaction,
     SignedTransaction inside Block payset)
   - Public API: `canonical_encode_transaction(&Transaction) -> Vec<u8>`
     and `canonical_encode_block_header(&Block) -> Vec<u8>` (block header
     is the block with payset excluded)

3. **Capture reference canonical bytes from Go**
   - Extend the fixture capture tooling or add a script that extracts
     canonical bytes from the Go node for comparison
   - Alternatively: use `goal clerk inspect` or write a small Go program
     in `docker/scripts/` that encodes a transaction canonically and outputs
     the raw bytes, so we can compare Rust output byte-for-byte
   - At minimum, capture reference bytes for the 5 existing fixture blocks'
     transactions

4. **Byte-level comparison tests**
   - For each captured fixture transaction: canonical_encode in Rust,
     compare against Go reference bytes
   - Test that omitempty works: encode a struct with zero fields, verify
     those keys are absent from the output
   - Test key ordering: verify keys appear in sorted order in the output
   - Test integer packing: small values use compact msgpack format

### Key context
- Block fields defined in `crates/core/algo-types/src/block.rs` (flat struct,
  NO #[serde(flatten)])
- Transaction fields in `crates/core/algo-types/src/transaction.rs`
- All binary fields use `serde_bytes::ByteBuf`, addresses are `Address([u8; 32])`
- Field rename attributes show the canonical key names (e.g., `#[serde(rename = "snd")]`)
- Docker image: algorand/algod:4.5.1-stable, DEV_MODE=1, port 4001
- `rmp` crate (low-level msgpack) is available — add to workspace deps if needed
- Rust 1.93.1 stable, PATH needs $HOME/.cargo/bin
- Silently ignored block fields: bi, fc, prev512, txn256, txn512, spt

### What success looks like
- `canonical_encode_transaction()` produces bytes that are identical to
  Go's `codec.Encode()` output for the same transaction
- `canonical_encode_block_header()` produces bytes identical to Go for
  the same block header
- All existing tests still pass
- New tests validate byte-level equivalence against Go reference data

Read the docs/ directory for architecture and conformance strategy.
Start by researching go-algorand's canonical encoding implementation,
then plan and implement.
