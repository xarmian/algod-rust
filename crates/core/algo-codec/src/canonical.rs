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

use algo_types::{
    Address, AssetParams, Block, BlockHeader, BoxRef, Digest, LogicSig, MultisigSig,
    MultisigSubsig, SignedTransaction, StateSchema, Transaction,
};
use serde_bytes::ByteBuf;

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
        let is_empty = matches!(
            val.as_slice(),
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

    fn add_option_bytes(&mut self, key: &'static str, val: &Option<ByteBuf>) {
        if let Some(b) = val {
            self.add_bytes(key, b);
        }
    }

    fn add_option_map(&mut self, key: &'static str, val: Option<Vec<u8>>) {
        if let Some(encoded) = val {
            self.add_map(key, encoded);
        }
    }

    fn add_option_vec_bytes(&mut self, key: &'static str, val: &Option<Vec<ByteBuf>>) {
        if let Some(items) = val {
            if !items.is_empty() {
                let mut buf = Vec::new();
                rmp::encode::write_array_len(&mut buf, items.len() as u32).unwrap();
                for item in items {
                    rmp::encode::write_bin(&mut buf, item).unwrap();
                }
                self.fields.push((key, buf));
            }
        }
    }

    fn add_option_vec_address(&mut self, key: &'static str, val: &Option<Vec<Address>>) {
        if let Some(addrs) = val {
            if !addrs.is_empty() {
                let mut buf = Vec::new();
                rmp::encode::write_array_len(&mut buf, addrs.len() as u32).unwrap();
                for addr in addrs {
                    rmp::encode::write_bin(&mut buf, &addr.0).unwrap();
                }
                self.fields.push((key, buf));
            }
        }
    }

    fn add_option_vec_u64(&mut self, key: &'static str, val: &Option<Vec<u64>>) {
        if let Some(vals) = val {
            if !vals.is_empty() {
                let mut buf = Vec::new();
                rmp::encode::write_array_len(&mut buf, vals.len() as u32).unwrap();
                for &v in vals {
                    write_uint(&mut buf, v);
                }
                self.fields.push((key, buf));
            }
        }
    }

    fn add_option_vec_box_refs(&mut self, key: &'static str, val: &Option<Vec<BoxRef>>) {
        if let Some(refs) = val {
            if !refs.is_empty() {
                let maps: Vec<Vec<u8>> = refs.iter().map(canonical_encode_box_ref).collect();
                let mut buf = Vec::new();
                rmp::encode::write_array_len(&mut buf, maps.len() as u32).unwrap();
                for m in &maps {
                    buf.extend_from_slice(m);
                }
                self.fields.push((key, buf));
            }
        }
    }

    /// Sort fields by key in lexicographic order (raw UTF-8 bytes).
    ///
    /// Go's go-codec sorts struct field codec tags alphabetically.
    fn encode(mut self) -> Vec<u8> {
        self.fields
            .sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

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

    // All fields go into the SAME map so they sort correctly in a single
    // namespace (Go behavior). The keys are the serde rename values.

    // Asset transfer (axfer)
    m.add_u64("aamt", tx.asset_amount);
    m.add_option_address("aclose", &tx.asset_close_to);

    // Asset freeze (afrz)
    m.add_bool("afrz", tx.asset_frozen);

    // Payment
    m.add_u64("amt", tx.amount);

    // Application call (appl)
    m.add_option_vec_bytes("apaa", &tx.app_arguments);
    m.add_u64("apan", tx.on_completion);
    m.add_option_bytes("apap", &tx.approval_program);
    m.add_option_vec_u64("apas", &tx.foreign_assets);
    m.add_option_vec_address("apat", &tx.accounts);
    m.add_option_vec_box_refs("apbx", &tx.boxes);
    m.add_u64("apep", tx.extra_program_pages);
    m.add_option_vec_u64("apfa", &tx.foreign_apps);
    m.add_option_map(
        "apgs",
        tx.global_state_schema
            .as_ref()
            .map(canonical_encode_state_schema),
    );
    m.add_u64("apid", tx.application_id);
    m.add_option_map(
        "apls",
        tx.local_state_schema
            .as_ref()
            .map(canonical_encode_state_schema),
    );
    m.add_option_bytes("apsu", &tx.clear_state_program);

    // Asset config (acfg)
    m.add_option_map(
        "apar",
        tx.asset_params.as_ref().map(canonical_encode_asset_params),
    );

    // Asset transfer (axfer)
    m.add_option_address("arcv", &tx.asset_receiver);
    m.add_option_address("asnd", &tx.asset_sender);

    // Asset config (acfg)
    m.add_u64("caid", tx.config_asset);

    // Payment
    m.add_address("close", &tx.close_remainder_to);

    // Asset freeze (afrz)
    m.add_option_address("fadd", &tx.freeze_account);
    m.add_u64("faid", tx.freeze_asset);

    // Header fields
    m.add_u64("fee", tx.fee);
    m.add_u64("fv", tx.first_valid.0);
    m.add_string("gen", &tx.genesis_id);
    m.add_bytes("gh", &tx.genesis_hash);
    m.add_bytes("grp", &tx.group);
    m.add_u64("lv", tx.last_valid.0);
    m.add_bytes("lx", &tx.lease);

    // Key registration (keyreg)
    m.add_bool("nonpart", tx.non_participation);

    m.add_bytes("note", &tx.note);
    m.add_address("rcv", &tx.receiver);
    m.add_option_address("rekey", &tx.rekey_to);

    // Key registration (keyreg)
    m.add_option_bytes("selkey", &tx.selection_pk);

    m.add_address("snd", &tx.sender);

    // State proof (stpf)
    m.add_option_rmpv("sp", &tx.state_proof);
    m.add_u64("sptype", tx.state_proof_type);
    m.add_option_bytes("sprfkey", &tx.state_proof_pk);

    m.add_string("type", &tx.txn_type);

    // Key registration (keyreg)
    m.add_u64("votefst", tx.vote_first);
    m.add_option_bytes("votekey", &tx.vote_pk);
    m.add_u64("votekd", tx.vote_key_dilution);
    m.add_u64("votelst", tx.vote_last);

    // Asset transfer (axfer)
    m.add_u64("xaid", tx.xaid);

    m.encode()
}

/// Canonically encode a SignedTransaction (the core signed txn, excluding
/// block-level wrapper fields like hgi/hgh which belong to SignedTxnInBlock).
pub fn canonical_encode_signed_transaction(stx: &SignedTransaction) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // Note: hgi and hgh are NOT part of SignedTxn in go-algorand.
    // They belong to SignedTxnInBlock (the block payset wrapper).
    if let Some(ref lsig) = stx.lsig {
        m.fields.push(("lsig", canonical_encode_logicsig(lsig)));
    }
    if let Some(ref msig) = stx.msig {
        m.fields.push(("msig", canonical_encode_multisig(msig)));
    }
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
    if let Some(ref lsig) = stx.lsig {
        m.fields.push(("lsig", canonical_encode_logicsig(lsig)));
    }
    if let Some(ref msig) = stx.msig {
        m.fields.push(("msig", canonical_encode_multisig(msig)));
    }
    m.add_bytes("sig", &stx.sig);
    m.add_option_address("sgnr", &stx.auth_addr);
    m.add_map("txn", canonical_encode_transaction(&stx.txn));

    m.encode()
}

/// Canonically encode a BlockHeader (from a Block, excluding payset).
pub fn canonical_encode_block_header_from_block(block: &Block) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_u64("bi", block.bonus);
    m.add_u64("earn", block.rewards_level);
    m.add_u64("fc", block.fees_collected);
    m.add_address("fees", &block.fee_sink);
    m.add_u64("frac", block.rewards_residue);
    m.add_string("gen", &block.genesis_id);
    m.add_bytes("gh", &block.genesis_hash);
    m.add_u64("nextbefore", block.next_protocol_vote_before.0);
    m.add_string("nextproto", &block.next_protocol);
    m.add_u64("nextswitch", block.next_protocol_switch_on.0);
    m.add_u64("nextyes", block.next_protocol_approvals);
    m.add_u64("pp", block.proposer_payout);
    m.add_bytes("prev", &block.branch);
    m.add_bytes("prev512", &block.prev512);
    m.add_string("proto", &block.current_protocol);
    m.add_address("prp", &block.proposer);
    m.add_u64("rate", block.rewards_rate);
    m.add_u64("rnd", block.round.0);
    m.add_address("rwd", &block.rewards_pool);
    m.add_u64("rwcalr", block.rewards_recalculation_round.0);
    m.add_bytes("seed", &block.seed);
    m.add_option_rmpv("spt", &block.state_proof_tracking);
    m.add_u64("tc", block.txn_counter);
    m.add_i64("ts", block.timestamp);
    m.add_bytes("txn", &block.txn_commitment);
    m.add_bytes("txn256", &block.txn256);
    m.add_bytes("txn512", &block.txn512);

    m.encode()
}

/// Canonically encode a BlockHeader struct.
pub fn canonical_encode_block_header(header: &BlockHeader) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_u64("bi", header.bonus);
    m.add_u64("earn", header.rewards_level);
    m.add_u64("fc", header.fees_collected);
    m.add_address("fees", &header.fee_sink);
    m.add_u64("frac", header.rewards_residue);
    m.add_string("gen", &header.genesis_id);
    m.add_bytes("gh", &header.genesis_hash);
    m.add_u64("nextbefore", header.next_protocol_vote_before.0);
    m.add_string("nextproto", &header.next_protocol);
    m.add_u64("nextswitch", header.next_protocol_switch_on.0);
    m.add_u64("nextyes", header.next_protocol_approvals);
    m.add_u64("pp", header.proposer_payout);
    m.add_bytes("prev", &header.branch);
    m.add_bytes("prev512", &header.prev512);
    m.add_string("proto", &header.current_protocol);
    m.add_address("prp", &header.proposer);
    m.add_u64("rate", header.rewards_rate);
    m.add_u64("rnd", header.round.0);
    m.add_address("rwd", &header.rewards_pool);
    m.add_u64("rwcalr", header.rewards_recalculation_round.0);
    m.add_bytes("seed", &header.seed);
    m.add_option_rmpv("spt", &header.state_proof_tracking);
    m.add_u64("tc", header.txn_counter);
    m.add_i64("ts", header.timestamp);
    m.add_bytes("txn", &header.txn_commitment);
    m.add_bytes("txn256", &header.txn256);
    m.add_bytes("txn512", &header.txn512);

    m.encode()
}

/// Canonically encode AssetParams as a nested msgpack map.
pub fn canonical_encode_asset_params(apar: &AssetParams) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_option_bytes("am", &apar.metadata_hash);
    m.add_string("an", &apar.asset_name);
    m.add_string("au", &apar.url);
    m.add_option_address("c", &apar.clawback);
    m.add_u64("dc", apar.decimals);
    m.add_bool("df", apar.default_frozen);
    m.add_option_address("f", &apar.freeze);
    m.add_option_address("m", &apar.manager);
    m.add_option_address("r", &apar.reserve);
    m.add_u64("t", apar.total);
    m.add_string("un", &apar.unit_name);

    m.encode()
}

/// Canonically encode StateSchema as a nested msgpack map.
pub fn canonical_encode_state_schema(schema: &StateSchema) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_u64("nbs", schema.num_byte_slice);
    m.add_u64("nui", schema.num_uint);

    m.encode()
}

/// Canonically encode BoxRef as a nested msgpack map.
pub fn canonical_encode_box_ref(bref: &BoxRef) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_u64("i", bref.index);
    m.add_option_bytes("n", &bref.name);

    m.encode()
}

/// Canonically encode a MultisigSubsig as a nested msgpack map.
/// Sorted fields: "pk", "s" (alphabetical). "s" omitted if empty.
pub fn canonical_encode_multisig_subsig(subsig: &MultisigSubsig) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_bytes("pk", &subsig.public_key);
    m.add_bytes("s", &subsig.signature);

    m.encode()
}

/// Canonically encode a MultisigSig as a nested msgpack map.
/// Sorted fields: "subsig", "thr", "v" (alphabetical).
pub fn canonical_encode_multisig(msig: &MultisigSig) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // "subsig" — array of encoded subsigs
    if !msig.subsigs.is_empty() {
        let maps: Vec<Vec<u8>> = msig
            .subsigs
            .iter()
            .map(canonical_encode_multisig_subsig)
            .collect();
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, maps.len() as u32).unwrap();
        for map in &maps {
            buf.extend_from_slice(map);
        }
        m.fields.push(("subsig", buf));
    }

    m.add_u64("thr", msig.threshold as u64);
    m.add_u64("v", msig.version as u64);

    m.encode()
}

/// Canonically encode a TxGroup struct (for group ID computation).
///
/// Encodes a msgpack map with a single key `"txlist"` containing an array of
/// 32-byte binary digests (the transaction hashes). The group ID is then:
/// `SHA512/256("TG" || canonical_encode_tx_group(hashes))`
pub fn canonical_encode_tx_group(hashes: &[Digest]) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    if !hashes.is_empty() {
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, hashes.len() as u32).unwrap();
        for h in hashes {
            rmp::encode::write_bin(&mut buf, h.as_bytes()).unwrap();
        }
        m.fields.push(("txlist", buf));
    }

    m.encode()
}

/// Canonically encode a LogicSig as a nested msgpack map.
/// Sorted fields: "arg", "l", "msig", "sig" (alphabetical).
/// Only includes non-empty/non-None fields.
pub fn canonical_encode_logicsig(lsig: &LogicSig) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // "arg" — optional array of byte arrays
    if let Some(ref args) = lsig.args {
        if !args.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, args.len() as u32).unwrap();
            for arg in args {
                rmp::encode::write_bin(&mut buf, arg).unwrap();
            }
            m.fields.push(("arg", buf));
        }
    }

    m.add_bytes("l", &lsig.logic);

    if let Some(ref msig) = lsig.msig {
        m.fields.push(("msig", canonical_encode_multisig(msig)));
    }

    m.add_bytes("sig", &lsig.sig);

    m.encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::Round;
    use serde_bytes::ByteBuf;

    #[test]
    fn test_empty_transaction_produces_minimal_map() {
        let tx = Transaction::default();

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
            amount: 5000,
            receiver: Address([2u8; 32]),
            ..Default::default()
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
            assert_eq!(keys, vec!["amt", "fee", "fv", "lv", "rcv", "snd", "type"]);
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
            last_valid: Round(200),
            ..Default::default()
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
            ..Default::default()
        };

        let encoded = canonical_encode_transaction(&tx);
        let val = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = val {
            // Find the "snd" field
            let snd = pairs
                .iter()
                .find(|(k, _)| k.as_str() == Some("snd"))
                .unwrap();
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
                amount: 5000,
                receiver: Address([2u8; 32]),
                ..Default::default()
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
            let txn = pairs
                .iter()
                .find(|(k, _)| k.as_str() == Some("txn"))
                .unwrap();
            assert!(matches!(txn.1, rmpv::Value::Map(_)));
        }
    }

    #[test]
    fn test_tx_group_encoding() {
        use algo_types::Digest;

        let h1 = Digest([0xAA; 32]);
        let h2 = Digest([0xBB; 32]);
        let encoded = canonical_encode_tx_group(&[h1, h2]);

        // Parse back to verify structure
        let val = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = val {
            assert_eq!(pairs.len(), 1, "TxGroup map should have exactly 1 key");
            let (key, value) = &pairs[0];
            assert_eq!(key.as_str().unwrap(), "txlist");

            if let rmpv::Value::Array(arr) = value {
                assert_eq!(arr.len(), 2);
                assert_eq!(arr[0].as_slice().unwrap(), &[0xAA; 32]);
                assert_eq!(arr[1].as_slice().unwrap(), &[0xBB; 32]);
            } else {
                panic!("expected array for txlist value");
            }
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn test_tx_group_single_hash() {
        use algo_types::Digest;

        let h = Digest([0x42; 32]);
        let encoded = canonical_encode_tx_group(&[h]);

        let val = rmpv::decode::read_value(&mut &encoded[..]).unwrap();
        if let rmpv::Value::Map(pairs) = val {
            assert_eq!(pairs.len(), 1);
            let (_, value) = &pairs[0];
            if let rmpv::Value::Array(arr) = value {
                assert_eq!(arr.len(), 1);
                assert_eq!(arr[0].as_slice().unwrap(), &[0x42; 32]);
            } else {
                panic!("expected array");
            }
        } else {
            panic!("expected map");
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
                amount: 5000,
                receiver: Address([2u8; 32]),
                ..Default::default()
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
