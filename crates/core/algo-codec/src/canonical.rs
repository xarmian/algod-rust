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
    Address, AssetParams, Block, BlockHeader, BoxRef, Digest, FalconVerifier, HashFactory,
    HeartbeatProof, HeartbeatTxnFields, HoldingRef, LocalsRef, LogicSig, MerkleProof,
    MerkleSignature, MerkleSignatureVerifier, MultisigSig, MultisigSubsig, Participant,
    ResourceRef, Reveal, SigSlotCommit, SignedTransaction, StateProofBody, StateProofMessage,
    StateSchema, Transaction, TxTailRound, TxTailRoundLease,
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
        // Go's omitempty for []byte: omit when len == 0 (nil or empty) OR
        // when all bytes are zero (for fixed-size [N]byte fields like digests).
        if !val.is_empty() && val.iter().any(|&b| b != 0) {
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

    fn add_option_fixed_bytes<const N: usize>(&mut self, key: &'static str, val: &Option<[u8; N]>) {
        if let Some(b) = val {
            if b.iter().any(|&x| x != 0) {
                self.add_bytes(key, b);
            }
        }
    }

    fn add_option_map(&mut self, key: &'static str, val: Option<Vec<u8>>) {
        if let Some(encoded) = val {
            self.add_map(key, encoded);
        }
    }

    fn add_option_vec_bytes(&mut self, key: &'static str, val: &Option<Vec<Option<ByteBuf>>>) {
        if let Some(items) = val {
            if !items.is_empty() {
                let mut buf = Vec::new();
                rmp::encode::write_array_len(&mut buf, items.len() as u32).unwrap();
                for item in items {
                    match item {
                        Some(bytes) => rmp::encode::write_bin(&mut buf, bytes).unwrap(),
                        None => rmp::encode::write_nil(&mut buf).unwrap(),
                    }
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

    // Access list (V41+)
    if let Some(ref access) = tx.access {
        if !access.is_empty() {
            let maps: Vec<Vec<u8>> = access.iter().map(canonical_encode_resource_ref).collect();
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, maps.len() as u32).unwrap();
            for map in &maps {
                buf.extend_from_slice(map);
            }
            m.fields.push(("al", buf));
        }
    }
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
    m.add_u64("apep", tx.extra_program_pages as u64);
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
    m.add_u64("aprv", tx.reject_version);
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
    if let Some(ref hb) = tx.heartbeat {
        m.add_map("hb", canonical_encode_heartbeat(hb));
    }
    m.add_u64("lv", tx.last_valid.0);
    m.add_bytes("lx", &tx.lease);

    // Key registration (keyreg)
    m.add_bool("nonpart", tx.non_participation);

    m.add_bytes("note", &tx.note);
    m.add_address("rcv", &tx.receiver);
    m.add_option_address("rekey", &tx.rekey_to);

    // Key registration (keyreg)
    m.add_option_fixed_bytes("selkey", &tx.selection_pk);

    m.add_address("snd", &tx.sender);

    // State proof (stpf)
    if let Some(ref sp) = tx.state_proof {
        m.add_map("sp", canonical_encode_state_proof_body(sp));
    }
    if let Some(ref msg) = tx.state_proof_message {
        m.add_map("spmsg", canonical_encode_state_proof_message(msg));
    }
    m.add_u64("sptype", tx.state_proof_type);
    m.add_option_fixed_bytes("sprfkey", &tx.state_proof_pk);

    m.add_string("type", tx.txn_type.as_str());

    // Key registration (keyreg)
    m.add_u64("votefst", tx.vote_first);
    m.add_option_fixed_bytes("votekey", &tx.vote_pk);
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

/// Canonically encode a SignedTxnInBlock (includes hgi/hgh wrapper fields
/// and ApplyData fields).
/// This is the encoding used in block payset arrays and for STIB hash computation.
pub fn canonical_encode_signed_txn_in_block(stx: &SignedTransaction) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // ApplyData fields (flattened from SignedTxnWithAD → ApplyData)
    m.add_u64("aca", stx.asset_closing_amount);
    m.add_u64("apid", stx.apply_data_application_id);
    m.add_u64("ca", stx.closing_amount);
    m.add_u64("caid", stx.apply_data_config_asset);
    m.add_option_rmpv("dt", &stx.eval_delta);

    // SignedTxnInBlock wrapper fields
    m.add_bool("hgh", stx.has_genesis_hash);
    m.add_bool("hgi", stx.has_genesis_id);

    // SignedTxn fields
    if let Some(ref lsig) = stx.lsig {
        m.fields.push(("lsig", canonical_encode_logicsig(lsig)));
    }
    if let Some(ref msig) = stx.msig {
        m.fields.push(("msig", canonical_encode_multisig(msig)));
    }

    // ApplyData rewards fields
    m.add_u64("rc", stx.close_rewards);
    m.add_u64("rr", stx.receiver_rewards);
    m.add_u64("rs", stx.sender_rewards);

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
    m.add_option_vec_address("partupdabs", &block.absent_participation_accounts);
    m.add_option_vec_address("partupdrmv", &block.expired_participation_accounts);
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
    m.add_u64("upgradedelay", block.upgrade_delay);
    m.add_string("upgradeprop", &block.upgrade_propose);
    m.add_bool("upgradeyes", block.upgrade_approve);

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
    m.add_option_vec_address("partupdabs", &header.absent_participation_accounts);
    m.add_option_vec_address("partupdrmv", &header.expired_participation_accounts);
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
    m.add_u64("upgradedelay", header.upgrade_delay);
    m.add_string("upgradeprop", &header.upgrade_propose);
    m.add_bool("upgradeyes", header.upgrade_approve);

    m.encode()
}

/// Canonically encode AssetParams as a nested msgpack map.
pub fn canonical_encode_asset_params(apar: &AssetParams) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    m.add_option_fixed_bytes("am", &apar.metadata_hash);
    m.add_string("an", &apar.asset_name);
    m.add_string("au", &apar.url);
    m.add_option_address("c", &apar.clawback);
    m.add_u64("dc", apar.decimals as u64);
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

    if let Some(ref lmsig) = lsig.lmsig {
        m.fields.push(("lmsig", canonical_encode_multisig(lmsig)));
    }

    if let Some(ref msig) = lsig.msig {
        m.fields.push(("msig", canonical_encode_multisig(msig)));
    }

    m.add_bytes("sig", &lsig.sig);

    m.encode()
}

/// Canonically encode a HeartbeatProof.
pub fn canonical_encode_heartbeat_proof(proof: &HeartbeatProof) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_bytes("p", &proof.pk);
    m.add_bytes("p1s", &proof.pk1_sig);
    m.add_bytes("p2", &proof.pk2);
    m.add_bytes("p2s", &proof.pk2_sig);
    m.add_bytes("s", &proof.sig);
    m.encode()
}

/// Canonically encode HeartbeatTxnFields.
pub fn canonical_encode_heartbeat(hb: &HeartbeatTxnFields) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_address("a", &hb.address);
    m.add_u64("kd", hb.key_dilution);
    if let Some(ref proof) = hb.proof {
        m.add_map("prf", canonical_encode_heartbeat_proof(proof));
    }
    m.add_bytes("sd", &hb.seed);
    m.add_bytes("vid", &hb.vote_id);
    m.encode()
}

/// Canonically encode a HashFactory.
pub fn canonical_encode_hash_factory(hf: &HashFactory) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("t", hf.hash_type as u64);
    m.encode()
}

/// Canonically encode a MerkleProof.
pub fn canonical_encode_merkle_proof(proof: &MerkleProof) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    if let Some(ref hf) = proof.hash_factory {
        m.add_map("hsh", canonical_encode_hash_factory(hf));
    }
    if let Some(ref path) = proof.path {
        if !path.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, path.len() as u32).unwrap();
            for item in path {
                match item {
                    Some(b) => rmp::encode::write_bin(&mut buf, b).unwrap(),
                    None => rmp::encode::write_nil(&mut buf).unwrap(),
                }
            }
            m.fields.push(("pth", buf));
        }
    }
    m.add_u64("td", proof.tree_depth as u64);
    m.encode()
}

/// Canonically encode a FalconVerifier.
pub fn canonical_encode_falcon_verifier(fv: &FalconVerifier) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_bytes("k", &fv.public_key);
    m.encode()
}

/// Canonically encode a MerkleSignature.
pub fn canonical_encode_merkle_signature(sig: &MerkleSignature) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("idx", sig.vector_commitment_index);
    if let Some(ref proof) = sig.proof {
        m.add_map("prf", canonical_encode_merkle_proof(proof));
    }
    m.add_bytes("sig", &sig.signature);
    if let Some(ref vkey) = sig.verifying_key {
        m.add_map("vkey", canonical_encode_falcon_verifier(vkey));
    }
    m.encode()
}

/// Canonically encode a SigSlotCommit.
pub fn canonical_encode_sig_slot_commit(slot: &SigSlotCommit) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("l", slot.l);
    if let Some(ref sig) = slot.sig {
        m.add_map("s", canonical_encode_merkle_signature(sig));
    }
    m.encode()
}

/// Canonically encode a MerkleSignatureVerifier.
pub fn canonical_encode_merkle_sig_verifier(v: &MerkleSignatureVerifier) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_bytes("cmt", &v.commitment);
    m.add_u64("lf", v.key_lifetime);
    m.encode()
}

/// Canonically encode a Participant.
pub fn canonical_encode_participant(p: &Participant) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    if let Some(ref pk) = p.pk {
        m.add_map("p", canonical_encode_merkle_sig_verifier(pk));
    }
    m.add_u64("w", p.weight);
    m.encode()
}

/// Canonically encode a Reveal.
pub fn canonical_encode_reveal(r: &Reveal) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    if let Some(ref part) = r.part {
        m.add_map("p", canonical_encode_participant(part));
    }
    if let Some(ref sig_slot) = r.sig_slot {
        m.add_map("s", canonical_encode_sig_slot_commit(sig_slot));
    }
    m.encode()
}

/// Canonically encode a StateProofBody.
pub fn canonical_encode_state_proof_body(sp: &StateProofBody) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    if let Some(ref pp) = sp.part_proofs {
        m.add_map("P", canonical_encode_merkle_proof(pp));
    }
    if let Some(ref sp_proofs) = sp.sig_proofs {
        m.add_map("S", canonical_encode_merkle_proof(sp_proofs));
    }
    m.add_bytes("c", &sp.sig_commit);
    if let Some(ref positions) = sp.positions_to_reveal {
        if !positions.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_array_len(&mut buf, positions.len() as u32).unwrap();
            for pos in positions {
                write_uint(&mut buf, *pos);
            }
            m.fields.push(("pr", buf));
        }
    }
    if let Some(ref reveals) = sp.reveals {
        if !reveals.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_map_len(&mut buf, reveals.len() as u32).unwrap();
            for (key, reveal) in reveals {
                write_uint(&mut buf, *key);
                let encoded = canonical_encode_reveal(reveal);
                buf.extend_from_slice(&encoded);
            }
            m.fields.push(("r", buf));
        }
    }
    m.add_u64("v", sp.merkle_signature_salt_version as u64);
    m.add_u64("w", sp.signed_weight);
    m.encode()
}

/// Canonically encode a StateProofMessage.
pub fn canonical_encode_state_proof_message(msg: &StateProofMessage) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("P", msg.ln_proven_weight);
    m.add_bytes("b", &msg.block_headers_commitment);
    m.add_u64("f", msg.first_attested_round);
    m.add_u64("l", msg.last_attested_round);
    m.add_bytes("v", &msg.voters_commitment);
    m.encode()
}

/// Canonically encode a HoldingRef.
pub fn canonical_encode_holding_ref(hr: &HoldingRef) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("d", hr.address);
    m.add_u64("s", hr.asset);
    m.encode()
}

/// Canonically encode a LocalsRef.
pub fn canonical_encode_locals_ref(lr: &LocalsRef) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("d", lr.address);
    m.add_u64("p", lr.app);
    m.encode()
}

/// Canonically encode a ResourceRef.
pub fn canonical_encode_resource_ref(rr: &ResourceRef) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    if let Some(ref br) = rr.box_ref {
        m.add_map("b", canonical_encode_box_ref(br));
    }
    m.add_address("d", &rr.address);
    if let Some(ref hr) = rr.holding {
        m.add_map("h", canonical_encode_holding_ref(hr));
    }
    if let Some(ref lr) = rr.locals {
        m.add_map("l", canonical_encode_locals_ref(lr));
    }
    m.add_u64("p", rr.app);
    m.add_u64("s", rr.asset);
    m.encode()
}

/// Canonically encode a TxTailRoundLease.
/// Fields: `"TxnIdx"` (u64), `"l"` (lease bytes), `"s"` (sender address).
/// Sorted alphabetically: `T` < `l` < `s`. Non-default fields only (omitempty).
pub fn canonical_encode_txtail_round_lease(lease: &TxTailRoundLease) -> Vec<u8> {
    let mut m = CanonicalMap::new();
    m.add_u64("TxnIdx", lease.txn_idx);
    m.add_bytes("l", &lease.lease);
    m.add_address("s", &lease.sender);
    m.encode()
}

/// Canonically encode a TxTailRound.
/// Fields: `"h"` (BlockHeader), `"i"` (txn IDs), `"l"` (leases), `"v"` (last_valid rounds).
/// Sorted: `h` < `i` < `l` < `v`. Non-empty fields only (omitempty).
pub fn canonical_encode_txtail_round(tail: &TxTailRound) -> Vec<u8> {
    let mut m = CanonicalMap::new();

    // "h" — block header (always present, but omit if empty map)
    m.add_map("h", canonical_encode_block_header(&tail.hdr));

    // "i" — txn IDs (array of binary digests)
    if !tail.txn_ids.is_empty() {
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, tail.txn_ids.len() as u32).unwrap();
        for id in &tail.txn_ids {
            rmp::encode::write_bin(&mut buf, id).unwrap();
        }
        m.fields.push(("i", buf));
    }

    // "l" — leases (array of encoded TxTailRoundLease maps)
    if !tail.leases.is_empty() {
        let maps: Vec<Vec<u8>> = tail
            .leases
            .iter()
            .map(canonical_encode_txtail_round_lease)
            .collect();
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, maps.len() as u32).unwrap();
        for map in &maps {
            buf.extend_from_slice(map);
        }
        m.fields.push(("l", buf));
    }

    // "v" — last-valid rounds (array of u64)
    if !tail.last_valid.is_empty() {
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, tail.last_valid.len() as u32).unwrap();
        for &v in &tail.last_valid {
            write_uint(&mut buf, v);
        }
        m.fields.push(("v", buf));
    }

    m.encode()
}

/// Build a `TxTailRound` from a `Block`, mirroring go-algorand's `TxTailRoundFromBlock`.
///
/// Iterates the block's payset to collect transaction IDs, last-valid rounds,
/// and lease entries. The block header is copied into the result.
pub fn build_txtail_from_block(block: &Block) -> TxTailRound {
    use crate::compute_txn_id;

    let hdr = BlockHeader {
        round: block.round,
        branch: block.branch,
        seed: block.seed,
        txn_commitment: block.txn_commitment,
        timestamp: block.timestamp,
        genesis_id: block.genesis_id.clone(),
        genesis_hash: block.genesis_hash,
        proposer: block.proposer,
        fee_sink: block.fee_sink,
        rewards_pool: block.rewards_pool,
        rewards_level: block.rewards_level,
        rewards_rate: block.rewards_rate,
        rewards_residue: block.rewards_residue,
        rewards_recalculation_round: block.rewards_recalculation_round,
        current_protocol: block.current_protocol.clone(),
        next_protocol: block.next_protocol.clone(),
        next_protocol_approvals: block.next_protocol_approvals,
        next_protocol_switch_on: block.next_protocol_switch_on,
        next_protocol_vote_before: block.next_protocol_vote_before,
        txn_counter: block.txn_counter,
        fees_collected: block.fees_collected,
        bonus: block.bonus,
        proposer_payout: block.proposer_payout,
        prev512: block.prev512,
        txn256: block.txn256,
        txn512: block.txn512,
        state_proof_tracking: block.state_proof_tracking.clone(),
        upgrade_propose: block.upgrade_propose.clone(),
        upgrade_delay: block.upgrade_delay,
        upgrade_approve: block.upgrade_approve,
        expired_participation_accounts: block.expired_participation_accounts.clone(),
        absent_participation_accounts: block.absent_participation_accounts.clone(),
    };

    let mut txn_ids = Vec::with_capacity(block.payset.len());
    let mut last_valid = Vec::with_capacity(block.payset.len());
    let mut leases = Vec::new();

    for (idx, stx) in block.payset.iter().enumerate() {
        let txid = compute_txn_id(&stx.txn);
        txn_ids.push(ByteBuf::from(txid.0.to_vec()));
        last_valid.push(stx.txn.last_valid.0);

        // Check for non-zero lease (32-byte field)
        if stx.txn.lease.iter().any(|&b| b != 0) {
            leases.push(TxTailRoundLease {
                sender: stx.txn.sender,
                lease: ByteBuf::from(stx.txn.lease.to_vec()),
                txn_idx: idx as u64,
            });
        }
    }

    TxTailRound {
        hdr,
        txn_ids,
        last_valid,
        leases,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::Round;

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
            sig: [0xDE; 64],
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: true,
            has_genesis_hash: false,
            ..Default::default()
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
            sig: [0xDE; 64],
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: true,
            has_genesis_hash: false,
            ..Default::default()
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

    /// Create a minimal Block for testing. Block doesn't derive Default, so
    /// this helper fills every field with a zero/empty value.
    fn minimal_block(round: Round, payset: Vec<SignedTransaction>) -> algo_types::Block {
        algo_types::Block {
            round,
            branch: [0u8; 32],
            seed: [0u8; 32],
            txn_commitment: [0u8; 32],
            timestamp: 0,
            genesis_id: String::new(),
            genesis_hash: [0u8; 32],
            proposer: Address::ZERO,
            fee_sink: Address::ZERO,
            rewards_pool: Address::ZERO,
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: Round(0),
            current_protocol: String::new(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_switch_on: Round(0),
            next_protocol_vote_before: Round(0),
            txn_counter: 0,
            fees_collected: 0,
            bonus: 0,
            proposer_payout: 0,
            prev512: [0u8; 64],
            txn256: [0u8; 32],
            txn512: [0u8; 64],
            state_proof_tracking: None,
            upgrade_propose: String::new(),
            upgrade_delay: 0,
            upgrade_approve: false,
            expired_participation_accounts: None,
            absent_participation_accounts: None,
            payset,
        }
    }

    #[test]
    fn test_build_txtail_from_block_empty_payset() {
        let block = minimal_block(Round(42), vec![]);

        let tail = build_txtail_from_block(&block);
        assert!(tail.txn_ids.is_empty());
        assert!(tail.last_valid.is_empty());
        assert!(tail.leases.is_empty());
        assert_eq!(tail.hdr.round, Round(42));
    }

    #[test]
    fn test_build_txtail_from_block_with_lease() {
        let lease_bytes = [0xABu8; 32];
        let sender = Address([0x01u8; 32]);

        let stx = SignedTransaction {
            txn: Transaction {
                txn_type: "pay".into(),
                sender,
                fee: 1000,
                first_valid: Round(10),
                last_valid: Round(20),
                lease: lease_bytes,
                amount: 100,
                receiver: Address([0x02u8; 32]),
                ..Default::default()
            },
            ..Default::default()
        };

        let block = minimal_block(Round(5), vec![stx]);

        let tail = build_txtail_from_block(&block);
        assert_eq!(tail.txn_ids.len(), 1);
        assert_eq!(tail.last_valid, vec![20]);
        assert_eq!(tail.leases.len(), 1);
        assert_eq!(tail.leases[0].sender, sender);
        assert_eq!(tail.leases[0].lease.as_ref(), &lease_bytes);
        assert_eq!(tail.leases[0].txn_idx, 0);
    }
}
