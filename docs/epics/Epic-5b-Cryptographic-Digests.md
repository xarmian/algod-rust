We are building algod-rust — a Rust reimplementation of go-algorand. Epics 0-4
and Epic 5a (canonical msgpack encoding) are complete. We now have byte-identical
canonical encoding that matches Go's codec.Encode() output.

## Epic 5b — Cryptographic Digests (Transaction IDs + Block Hash)

This epic layers SHA512/256 hashing on top of the canonical encoder to compute
transaction IDs and block digests, then validates they match Go reference values.

### Background

Algorand uses SHA512/256 (SHA-512 truncated to 256 bits) with domain separation
prefixes for all cryptographic digests:
- Transaction ID: `SHA512/256("TX" || canonical_encode(txn))`
- Block digest:   `SHA512/256("BH" || canonical_encode(block_header))`

The domain separator is literal ASCII bytes prepended to the canonical encoding
before hashing. The result is a 32-byte digest.

Transaction IDs are displayed as base32 (RFC 4648, no padding) in the Go REST
API, but stored/compared as raw 32-byte arrays.

### Deliverables

1. **Hash computation functions**
   - Add to `algo-codec` or create a new `crates/core/algo-crypto` crate
   - `compute_txn_id(&Transaction) -> [u8; 32]` — canonical encode + hash
   - `compute_block_digest(&Block) -> [u8; 32]` — canonical encode header + hash
   - Use `sha2::Sha512_256` (already in workspace deps)

2. **Extract reference values from Go node**
   - Transaction IDs: available from `GET /v2/blocks/{round}` JSON response
     (look for txn ID fields) or from `GET /v2/transactions/{txid}`
   - Block digest: may be in the `cert` field of the block response, or
     available via a separate API endpoint — research needed
   - Capture reference txn IDs and block digests for all 5 fixture blocks
   - Store as test fixtures (e.g., JSON file mapping round → expected hashes)

3. **Extend conformance comparison**
   - Add txn ID comparison to `compare_block()` in algo-conformance
   - Add block digest comparison to `compare_block()`
   - New `Mismatch` variants or use `FieldMismatch` with paths like
     "txns[0].computed_txid" and "header.computed_digest"

4. **Tests**
   - Unit tests: compute txn ID for fixture transactions, compare against
     Go reference values
   - Unit tests: compute block digest for fixture blocks, compare against
     Go reference values
   - Corruption test: mutate a transaction, verify txn ID changes
   - Integration: `make validate` should now check hashes in addition to
     structural fields

### Key context
- `canonical_encode_transaction()` and `canonical_encode_block_header()`
  are available from Epic 5a in `algo-codec`
- sha2 crate already in workspace Cargo.toml
- Transaction fields: type="pay", sender, receiver, amount, fee, first_valid,
  last_valid, note, genesis_id, genesis_hash, etc.
- Block header = Block struct minus the `txns`/payset field
- The `cert` field in BlockResponse is currently `Option<rmpv::Value>` (opaque)
- Docker localnet: algorand/algod:4.5.1-stable, port 4001, DEV_MODE=1
- Base32 encoding: add `data-encoding` or `base32` crate if needed for
  displaying txn IDs
- Rust 1.93.1 stable, PATH needs $HOME/.cargo/bin

### What success looks like
- Rust-computed txn IDs match Go txn IDs for all fixture transactions
- Rust-computed block digests match Go block digests for all fixture blocks
- `compare_block()` reports hash mismatches when they occur
- `make validate` passes with hash checks enabled
- All existing tests still pass, new hash tests added

Read docs/ for architecture and conformance strategy.
Start by determining how to extract reference txn IDs and block digests
from the Go node, then implement the hash functions and validation.
