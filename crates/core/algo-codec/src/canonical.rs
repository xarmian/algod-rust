// Algorand Canonical Encoding
//
// Algorand's canonical msgpack encoding has specific rules:
//
// 1. Map keys are sorted lexicographically by their raw bytes.
// 2. Zero-value fields are omitted entirely (Go's `omitempty` semantics).
// 3. Empty strings, empty byte arrays, zero integers, and false booleans are omitted.
// 4. The encoding must be deterministic — identical inputs always produce identical bytes.
//
// This is critical for:
// - Transaction ID computation: txID = SHA512/256("TX" || canonical_encode(txn))
// - Block digest computation: similar canonical encoding of block header
// - Any hash that must match between Go and Rust implementations.
//
// Phase 0 uses rmp-serde with #[serde(skip_serializing_if)] annotations as an
// approximation. This is sufficient for *decoding* and structural comparison,
// but will NOT produce byte-identical output when re-encoding.
//
// TODO(epic-3): Implement a custom canonical msgpack serializer that:
// - Sorts map keys by raw bytes before encoding
// - Omits all zero-value / empty fields
// - Produces byte-identical output to go-algorand's codec.Encode()
