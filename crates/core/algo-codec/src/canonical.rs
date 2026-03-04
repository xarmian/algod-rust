// Algorand Canonical Msgpack Encoding
//
// Implements go-algorand's canonical encoding rules:
// 1. Structs encoded as msgpack MAPs with string keys (codec tag names)
// 2. Map keys sorted lexicographically by raw bytes
// 3. Zero-value fields omitted (omitempty semantics)
// 4. Integers use shortest msgpack representation, positive values as unsigned
// 5. Byte arrays use msgpack Binary format (bin8/bin16/bin32)
// 6. Strings use msgpack String format (fixstr/str8/str16)
// 7. Deterministic — identical inputs always produce identical bytes

use algo_types::{Address, Block, BlockHeader, SignedTransaction, Transaction};

/// A builder for canonical msgpack maps.
///
/// Collects non-zero fields as (key, encoded_value) pairs,
/// sorts by key, and writes a msgpack map.
struct CanonicalMap {
    fields: Vec<(&'static str, Vec<u8>)>,
}

impl CanonicalMap {
    fn new() -> Self {
        Self { fields: Vec::new() }
    }

    fn add_u64(&mut self, key: &'static str, val: u64) {
        if val != 0 {
            let mut buf = Vec::new();
            write_uint(&mut buf, val);
            self.fields.push((key, buf));
        }
    }

    fn add_i64(&mut self, key: &'static str, val: i64) {
        if val != 0 {
            let mut buf = Vec::new();
            write_int(&mut buf, val);
            self.fields.push((key, buf));
        }
    }

    fn add_bool(&mut self, key: &'static str, val: bool) {
        if val {
            let mut buf = Vec::new();
            rmp::encode::write_bool(&mut buf, true).unwrap();
            self.fields.push((key, buf));
        }
    }

    fn add_string(&mut self, key: &'static str, val: &str) {
        if !val.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_str(&mut buf, val).unwrap();
            self.fields.push((key, buf));
        }
    }

    fn add_bytes(&mut self, key: &'static str, val: &[u8]) {
        // Go's omitempty for []byte: omit when len == 0 (nil or empty).
        // Note: [32]byte digests (gh, seed, prev) use Address type or come
        // through as empty ByteBuf when absent — never as 32 zero bytes.
        if !val.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_bin(&mut buf, val).unwrap();
            self.fields.push((key, buf));
        }
    }

    fn add_address(&mut self, key: &'static str, val: &Address) {
        if !val.is_zero() {
            let mut buf = Vec::new();
            rmp::encode::write_bin(&mut buf, &val.0).unwrap();
            self.fields.push((key, buf));
        }
    }

    fn add_map(&mut self, key: &'static str, val: Vec<u8>) {
        // Skip empty maps. Our encoder always produces fixmap(0) = 0x80 for
        // zero-entry maps, but we also handle map16/map32 representations.
        let is_empty = matches!(val.as_slice(),
            [0x80] | [0xDE, 0x00, 0x00] | [0xDF, 0x00, 0x00, 0x00, 0x00]
        );
        if !is_empty {
            self.fields.push((key, val));
        }
    }

    #[allow(dead_code)] // Will be used for payset encoding in Epic 5b
    fn add_array_of_maps(&mut self, key: &'static str, maps: &[Vec<u8>]) {
        if !maps.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, maps.len() as u32).unwrap();
            for m in maps {
                buf.extend_from_slice(m);
            }
            self.fields.push((key, buf));
        }
    }

    fn add_option_address(&mut self, key: &'static str, val: &Option<Address>) {
        if let Some(addr) = val {
            if !addr.is_zero() {
                self.add_address(key, addr);
            }
        }
    }

    /// WARNING: This passes through raw rmpv bytes WITHOUT recursive canonical
    /// sorting. It is only safe when the input was deserialized from Go output
    /// (which is already canonical). When msig/lsig are promoted to typed Rust
    /// structs, this method must be replaced with canonical_encode_* functions
    /// for those types — and this method should be deleted entirely.
    /// Tracking: the type change from Option<rmpv::Value> to a typed struct
    /// will cause a compile error here, forcing the update.
    fn add_option_rmpv(&mut self, key: &'static str, val: &Option<rmpv::Value>) {
        if let Some(v) = val {
            if !is_rmpv_empty(v) {
                let mut buf = Vec::new();
                rmpv::encode::write_value(&mut buf, v).unwrap();
                self.fields.push((key, buf));
            }
        }
    }

    /// Sort fields by key and encode as a msgpack map.
    fn encode(mut self) -> Vec<u8> {
        self.fields.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        let mut buf = Vec::new();
        rmp::encode::write_map_len(&mut buf, self.fields.len() as u32).unwrap();

        for (key, value) in &self.fields {
            rmp::encode::write_str(&mut buf, key).unwrap();
            buf.extend_from_slice(value);
        }

        buf
    }
}

/// Write an unsigned integer in the most compact msgpack representation.
/// Algorand uses PositiveIntUnsigned=true, so positive values (even from
/// signed Go types) are encoded as unsigned msgpack integers.
fn write_uint(buf: &mut Vec<u8>, val: u64) {
    if val <= 127 {
        // positive fixint: single byte 0x00-0x7f
        rmp::encode::write_pfix(buf, val as u8).unwrap();
    } else if val <= 0xFF {
        rmp::encode::write_u8(buf, val as u8).unwrap();
    } else if val <= 0xFFFF {
        rmp::encode::write_u16(buf, val as u16).unwrap();
    } else if val <= 0xFFFF_FFFF {
        rmp::encode::write_u32(buf, val as u32).unwrap();
    } else {
        rmp::encode::write_u64(buf, val).unwrap();
    }
}

/// Write a signed integer in compact msgpack representation.
/// Positive values are written as unsigned (PositiveIntUnsigned=true).
/// Negative values use the most compact signed representation.
fn write_int(buf: &mut Vec<u8>, val: i64) {
    if val >= 0 {
        write_uint(buf, val as u64);
    } else if val >= -32 {
        // negative fixint: single byte 0xe0-0xff
        rmp::encode::write_nfix(buf, val as i8).unwrap();
    } else if val >= i8::MIN as i64 {
        rmp::encode::write_i8(buf, val as i8).unwrap();
    } else if val >= i16::MIN as i64 {
        rmp::encode::write_i16(buf, val as i16).unwrap();
    } else if val >= i32::MIN as i64 {
        rmp::encode::write_i32(buf, val as i32).unwrap();
    } else {
        rmp::encode::write_i64(buf, val).unwrap();
    }
}

/// Check if an rmpv::Value is "empty" (nil, empty map, empty array, etc.)
fn is_rmpv_empty(v: &rmpv::Value) -> bool {
    match v {
        rmpv::Value::Nil => true,
        rmpv::Value::Map(m) => m.is_empty(),
        rmpv::Value::Array(a) => a.is_empty(),
        rmpv::Value::Binary(b) => b.is_empty(),
        rmpv::Value::String(s) => s.as_str().map_or(true, |s| s.is_empty()),
        _ => false,
    }
}

// ── Public API ──────────────────────────────────────────────────

/// Canonically encode a Transaction (the inner txn body, not signed).
///
/// This produces bytes identical to go-algorand's `protocol.Encode(&tx)`
/// for payment transactions. The encoding uses sorted keys, omitempty,
/// and compact integer representation.
pub fn canonical_encode_transaction(tx: &Transaction) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // Payment fields
    m.add_u64("amt", tx.amount);
    m.add_address("close", &tx.close_remainder_to);

    // Header fields
    m.add_u64("fee", tx.fee);
    m.add_u64("fv", tx.first_valid.0);
    m.add_string("gen", &tx.genesis_id);
    m.add_bytes("gh", &tx.genesis_hash);
    m.add_bytes("grp", &tx.group);
    m.add_u64("lv", tx.last_valid.0);
    m.add_bytes("lx", &tx.lease);
    m.add_bytes("note", &tx.note);
    m.add_address("rcv", &tx.receiver);
    m.add_option_address("rekey", &tx.rekey_to);
    m.add_address("snd", &tx.sender);
    m.add_string("type", &tx.txn_type);

    m.encode()
}

/// Canonically encode a SignedTransaction (the core signed txn, excluding
/// block-level wrapper fields like hgi/hgh which belong to SignedTxnInBlock).
pub fn canonical_encode_signed_transaction(stx: &SignedTransaction) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // Note: hgi and hgh are NOT part of SignedTxn in go-algorand.
    // They belong to SignedTxnInBlock (the block payset wrapper).
    m.add_option_rmpv("lsig", &stx.lsig);
    m.add_option_rmpv("msig", &stx.msig);
    m.add_bytes("sig", &stx.sig);
    m.add_option_address("sgnr", &stx.auth_addr);
    m.add_map("txn", canonical_encode_transaction(&stx.txn));

    m.encode()
}

/// Canonically encode a SignedTxnInBlock (includes hgi/hgh wrapper fields).
/// This is the encoding used in block payset arrays.
pub fn canonical_encode_signed_txn_in_block(stx: &SignedTransaction) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_bool("hgh", stx.has_genesis_hash);
    m.add_bool("hgi", stx.has_genesis_id);
    m.add_option_rmpv("lsig", &stx.lsig);
    m.add_option_rmpv("msig", &stx.msig);
    m.add_bytes("sig", &stx.sig);
    m.add_option_address("sgnr", &stx.auth_addr);
    m.add_map("txn", canonical_encode_transaction(&stx.txn));

    m.encode()
}

/// Canonically encode a BlockHeader (from a Block, excluding payset).
///
/// Note: This encoding may not match Go byte-for-byte if the Go block
/// contains fields we don't model (bi, fc, prev512, txn256, txn512, spt).
/// For blocks where those fields are zero/absent, it will match.
pub fn canonical_encode_block_header_from_block(block: &Block) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_u64("earn", block.rewards_level);
    m.add_address("fees", &block.fee_sink);
    m.add_u64("frac", block.rewards_residue);
    m.add_string("gen", &block.genesis_id);
    m.add_bytes("gh", &block.genesis_hash);
    m.add_u64("nextbefore", block.next_protocol_vote_before.0);
    m.add_string("nextproto", &block.next_protocol);
    m.add_u64("nextswitch", block.next_protocol_switch_on.0);
    m.add_u64("nextyes", block.next_protocol_approvals);
    m.add_bytes("prev", &block.branch);
    m.add_string("proto", &block.current_protocol);
    m.add_address("prp", &block.proposer);
    m.add_u64("rate", block.rewards_rate);
    m.add_u64("rnd", block.round.0);
    m.add_address("rwd", &block.rewards_pool);
    m.add_u64("rwcalr", block.rewards_recalculation_round.0);
    m.add_bytes("seed", &block.seed);
    m.add_u64("tc", block.txn_counter);
    m.add_i64("ts", block.timestamp);
    m.add_bytes("txn", &block.txn_commitment);

    m.encode()
}

/// Canonically encode a BlockHeader struct.
pub fn canonical_encode_block_header(header: &BlockHeader) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_u64("earn", header.rewards_level);
    m.add_address("fees", &header.fee_sink);
    m.add_u64("frac", header.rewards_residue);
    m.add_string("gen", &header.genesis_id);
    m.add_bytes("gh", &header.genesis_hash);
    m.add_u64("nextbefore", header.next_protocol_vote_before.0);
    m.add_string("nextproto", &header.next_protocol);
    m.add_u64("nextswitch", header.next_protocol_switch_on.0);
    m.add_u64("nextyes", header.next_protocol_approvals);
    m.add_bytes("prev", &header.branch);
    m.add_string("proto", &header.current_protocol);
    m.add_address("prp", &header.proposer);
    m.add_u64("rate", header.rewards_rate);
    m.add_u64("rnd", header.round.0);
    m.add_address("rwd", &header.rewards_pool);
    m.add_u64("rwcalr", header.rewards_recalculation_round.0);
    m.add_bytes("seed", &header.seed);
    m.add_u64("tc", header.txn_counter);
    m.add_i64("ts", header.timestamp);
    m.add_bytes("txn", &header.txn_commitment);

    m.encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::Round;
    use serde_bytes::ByteBuf;

    #[test]
    fn test_empty_transaction_produces_minimal_map() {
        let tx = Transaction {
            txn_type: String::new(),
            sender: Address::ZERO,
            fee: 0,
            first_valid: Round(0),
            last_valid: Round(0),
            note: ByteBuf::new(),
            genesis_id: String::new(),
            genesis_hash: ByteBuf::new(),
            group: ByteBuf::new(),
            lease: ByteBuf::new(),
            rekey_to: None,
            amount: 0,
            receiver: Address::ZERO,
            close_remainder_to: Address::ZERO,
        };

        let encoded = canonical_encode_transaction(&tx);
        // All fields are zero/empty → empty map
        assert_eq!(encoded, vec![0x80]); // fixmap(0)
    }

    #[test]
    fn test_keys_are_sorted() {
        let tx = Transaction {
            txn_type: "pay".into(),
            sender: Address([1u8; 32]),
            fee: 1000,
            first_valid: Round(100),
            last_valid: Round(200),
            note: ByteBuf::new(),
            genesis_id: String::new(),
            genesis_hash: ByteBuf::new(),
            group: ByteBuf::new(),
            lease: ByteBuf::new(),
            rekey_to: None,
            amount: 5000,
            receiver: Address([2u8; 32]),
            close_remainder_to: Address::ZERO,
        };

        let encoded = canonical_encode_transaction(&tx);

        // Parse back with rmpv to verify key order
        let val = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = val {
            let keys: Vec<String> = pairs
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();

            // Verify keys are in sorted order
            let mut sorted = keys.clone();
            sorted.sort();
            assert_eq!(keys, sorted, "keys must be in lexicographic order");

            // Expected keys for this transaction (non-zero fields)
            assert_eq!(
                keys,
                vec!["amt", "fee", "fv", "lv", "rcv", "snd", "type"]
            );
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn test_integer_packing_compact() {
        // Small value (< 128) should be positive fixint (1 byte)
        let mut buf = Vec::new();
        write_uint(&mut buf, 42);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 42); // positive fixint

        // Value 128-255 should be uint8 (2 bytes)
        buf.clear();
        write_uint(&mut buf, 200);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], 0xCC); // uint8 marker

        // Value 256-65535 should be uint16 (3 bytes)
        buf.clear();
        write_uint(&mut buf, 1000);
        assert_eq!(buf.len(), 3);
        assert_eq!(buf[0], 0xCD); // uint16 marker

        // Value > 65535 should be uint32 (5 bytes)
        buf.clear();
        write_uint(&mut buf, 100_000);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf[0], 0xCE); // uint32 marker
    }

    #[test]
    fn test_signed_integer_packing() {
        // Positive i64 encoded as unsigned
        let mut buf = Vec::new();
        write_int(&mut buf, 42);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 42);

        // Negative fixint (-1 to -32)
        buf.clear();
        write_int(&mut buf, -1);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 0xFF); // -1 as negative fixint

        // Negative i8
        buf.clear();
        write_int(&mut buf, -100);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0], 0xD0); // int8 marker
    }

    #[test]
    fn test_omitempty_skips_zero_fields() {
        let tx = Transaction {
            txn_type: "pay".into(),
            sender: Address([1u8; 32]),
            fee: 1000,
            first_valid: Round(0), // zero — should be omitted
            last_valid: Round(200),
            note: ByteBuf::new(), // empty — should be omitted
            genesis_id: String::new(), // empty — should be omitted
            genesis_hash: ByteBuf::new(),
            group: ByteBuf::new(),
            lease: ByteBuf::new(),
            rekey_to: None,
            amount: 0, // zero — should be omitted
            receiver: Address::ZERO, // zero — should be omitted
            close_remainder_to: Address::ZERO,
        };

        let encoded = canonical_encode_transaction(&tx);
        let val = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = val {
            let keys: Vec<String> = pairs
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();

            // Only non-zero fields should be present
            assert_eq!(keys, vec!["fee", "lv", "snd", "type"]);
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn test_address_encoded_as_binary_32_bytes() {
        let addr = Address([0xAB; 32]);
        let tx = Transaction {
            txn_type: "pay".into(),
            sender: addr,
            fee: 0,
            first_valid: Round(0),
            last_valid: Round(0),
            note: ByteBuf::new(),
            genesis_id: String::new(),
            genesis_hash: ByteBuf::new(),
            group: ByteBuf::new(),
            lease: ByteBuf::new(),
            rekey_to: None,
            amount: 0,
            receiver: Address::ZERO,
            close_remainder_to: Address::ZERO,
        };

        let encoded = canonical_encode_transaction(&tx);
        let val = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = val {
            // Find the "snd" field
            let snd = pairs.iter().find(|(k, _)| k.as_str() == Some("snd")).unwrap();
            // Should be binary, 32 bytes
            if let rmpv::Value::Binary(b) = &snd.1 {
                assert_eq!(b.len(), 32);
                assert_eq!(b[0], 0xAB);
            } else {
                panic!("address should be encoded as binary, got {:?}", snd.1);
            }
        }
    }

    #[test]
    fn test_signed_transaction_nests_txn() {
        let stx = SignedTransaction {
            txn: Transaction {
                txn_type: "pay".into(),
                sender: Address([1u8; 32]),
                fee: 1000,
                first_valid: Round(1),
                last_valid: Round(100),
                note: ByteBuf::new(),
                genesis_id: String::new(),
                genesis_hash: ByteBuf::new(),
                group: ByteBuf::new(),
                lease: ByteBuf::new(),
                rekey_to: None,
                amount: 5000,
                receiver: Address([2u8; 32]),
                close_remainder_to: Address::ZERO,
            },
            sig: ByteBuf::from(vec![0xDE; 64]),
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: true,
            has_genesis_hash: false,
        };

        let encoded = canonical_encode_signed_transaction(&stx);
        let val = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = val {
            let keys: Vec<String> = pairs
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();
            // sig=non-empty, txn=nested map (hgi/hgh are NOT in SignedTxn)
            assert_eq!(keys, vec!["sig", "txn"]);

            // Verify txn is a nested map
            let txn = pairs.iter().find(|(k, _)| k.as_str() == Some("txn")).unwrap();
            assert!(matches!(txn.1, rmpv::Value::Map(_)));
        }
    }

    #[test]
    fn test_signed_txn_in_block_includes_hgi_hgh() {
        let stx = SignedTransaction {
            txn: Transaction {
                txn_type: "pay".into(),
                sender: Address([1u8; 32]),
                fee: 1000,
                first_valid: Round(1),
                last_valid: Round(100),
                note: ByteBuf::new(),
                genesis_id: String::new(),
                genesis_hash: ByteBuf::new(),
                group: ByteBuf::new(),
                lease: ByteBuf::new(),
                rekey_to: None,
                amount: 5000,
                receiver: Address([2u8; 32]),
                close_remainder_to: Address::ZERO,
            },
            sig: ByteBuf::from(vec![0xDE; 64]),
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: true,
            has_genesis_hash: false,
        };

        let encoded = canonical_encode_signed_txn_in_block(&stx);
        let val = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = val {
            let keys: Vec<String> = pairs
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();
            // hgi=true included, hgh=false omitted
            assert_eq!(keys, vec!["hgi", "sig", "txn"]);
        }
    }
}
