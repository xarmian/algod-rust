We are building algod-rust — a Rust reimplementation of go-algorand. Phase 1
is complete. Epics 13-17a implement ledger state transitions with persistent
storage and balance-comparison conformance.

## Epic 17b — Merkle Trie State Root (Stretch Goal)

This epic implements Algorand's account Merkle trie to compute state roots that
match go-algorand byte-for-byte. This is a **stretch goal** for Phase 2 — if the
trie proves too complex, it may be deferred to Phase 2.5 or Phase 3.

### Background

go-algorand maintains a Merkle trie over all account state to produce a 32-byte
state root that is included in block certificates. The trie implementation lives
in `crypto/merkletrie/` and is:

- **Page-based**: nodes are stored in pages for efficient disk access
- **Compressed**: path compression reduces trie depth
- **Domain-separated**: different hashing for leaves vs internal nodes
- **Sorted by address**: accounts are keyed by their 32-byte address
- **Incremental**: only modified accounts trigger trie updates per block

The state root is used for:
- Catchpoint verification (Phase 4)
- State proof generation (not in scope for Phase 2)
- Light client verification (future)

### Deliverables

1. **Research go-algorand's Merkle trie**
   - Study `crypto/merkletrie/trie.go`, `crypto/merkletrie/node.go`,
     `crypto/merkletrie/committer.go`
   - Document exact hashing algorithm: leaf hash, internal node hash, domain prefixes
   - Document path compression scheme
   - Document how account data is serialized for leaf values

2. **Merkle trie implementation** in `algo-ledger/src/merkle_trie.rs`
   - Trie node types: leaf (address + account hash), internal (left/right child hashes)
   - Path compression: shared prefix elimination
   - Insert, update, delete operations
   - Root hash computation: `compute_root() -> [u8; 32]`
   - Incremental updates: only recompute affected path on account changes

3. **Account serialization for trie**
   - Determine how go-algorand serializes account data for trie leaf values
   - This may be canonical msgpack of AccountData or a custom format
   - Must match exactly for root hash to match

4. **Integration with apply_block**
   - After each block is applied, update trie with modified accounts
   - Compute new state root
   - Compare against Go node's state root (if available via API)

5. **Conformance validation**
   - Compare computed state root against Go reference after each block
   - State root may be available via state delta API or block certificates
   - If no direct API access, compare against Go node's catchpoint data

### Risks

This is the highest-risk epic in Phase 2:
- go-algorand's trie is ~2000 lines of Go with page-based disk storage
- Path compression adds significant complexity
- Account serialization format must match exactly
- Performance requirements for incremental updates
- If the trie proves intractable, per-account balance comparison (Epic 17a)
  still provides strong conformance guarantees

### What success looks like
- Merkle trie produces state roots matching go-algorand after each block
- Incremental updates are efficient (sub-millisecond per block)
- Trie state persists to SQLite alongside account data
- OR: epic is explicitly deferred with a clear assessment of remaining work

Read docs/ for architecture and conformance strategy.
Start by deeply studying go-algorand's crypto/merkletrie/ package before
writing any code. Understanding the exact algorithm is critical.
