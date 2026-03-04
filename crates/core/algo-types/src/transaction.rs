use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{Address, Round};

/// A signed transaction as it appears in a block's payset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The transaction body.
    #[serde(rename = "txn")]
    pub txn: Transaction,

    /// Ed25519 signature.
    #[serde(rename = "sig", default, skip_serializing_if = "is_empty_bytes")]
    pub sig: ByteBuf,

    /// Multisig metadata (captured as opaque value for Phase 0).
    /// IMPORTANT: When promoting to a typed struct, also add a corresponding
    /// canonical_encode_multisig() function in algo-codec/canonical.rs and
    /// remove the add_option_rmpv call. See P1 note there.
    #[serde(rename = "msig", default, skip_serializing_if = "Option::is_none")]
    pub msig: Option<rmpv::Value>,

    /// Logic signature (captured as opaque value for Phase 0).
    /// IMPORTANT: When promoting to a typed struct, also add a corresponding
    /// canonical_encode_logicsig() function in algo-codec/canonical.rs and
    /// remove the add_option_rmpv call. See P1 note there.
    #[serde(rename = "lsig", default, skip_serializing_if = "Option::is_none")]
    pub lsig: Option<rmpv::Value>,

    /// Auth address for rekeyed accounts.
    #[serde(rename = "sgnr", default, skip_serializing_if = "Option::is_none")]
    pub auth_addr: Option<Address>,

    /// Has genesis ID flag.
    #[serde(rename = "hgi", default, skip_serializing_if = "is_false")]
    pub has_genesis_id: bool,

    /// Has genesis hash flag.
    #[serde(rename = "hgh", default, skip_serializing_if = "is_false")]
    pub has_genesis_hash: bool,
}

/// Core transaction fields.
///
/// Phase 0 models the common fields explicitly. Type-specific fields
/// (payment amount, receiver, asset ID, app args, etc.) are modeled
/// as individual optional fields rather than using `#[serde(flatten)]`
/// due to rmp-serde compatibility issues with flatten + binary types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction type string ("pay", "axfer", "acfg", "afrz", "appl", "keyreg", "stpf").
    #[serde(rename = "type")]
    pub txn_type: String,

    /// Sender address.
    #[serde(rename = "snd")]
    pub sender: Address,

    /// Fee (in microAlgos).
    #[serde(rename = "fee", default)]
    pub fee: u64,

    /// First valid round.
    #[serde(rename = "fv", default)]
    pub first_valid: Round,

    /// Last valid round.
    #[serde(rename = "lv", default)]
    pub last_valid: Round,

    /// Note field.
    #[serde(rename = "note", default, skip_serializing_if = "is_empty_bytes")]
    pub note: ByteBuf,

    /// Genesis ID.
    #[serde(rename = "gen", default, skip_serializing_if = "String::is_empty")]
    pub genesis_id: String,

    /// Genesis hash.
    #[serde(rename = "gh", default, skip_serializing_if = "is_empty_bytes")]
    pub genesis_hash: ByteBuf,

    /// Group ID.
    #[serde(rename = "grp", default, skip_serializing_if = "is_empty_bytes")]
    pub group: ByteBuf,

    /// Lease.
    #[serde(rename = "lx", default, skip_serializing_if = "is_empty_bytes")]
    pub lease: ByteBuf,

    /// Rekey-to address.
    #[serde(rename = "rekey", default, skip_serializing_if = "Option::is_none")]
    pub rekey_to: Option<Address>,

    // ── Payment transaction fields ─────────────────────────────
    /// Payment amount (microAlgos).
    #[serde(rename = "amt", default, skip_serializing_if = "is_zero_u64")]
    pub amount: u64,

    /// Payment receiver.
    #[serde(rename = "rcv", default, skip_serializing_if = "Address::is_zero")]
    pub receiver: Address,

    /// Close remainder to address.
    #[serde(rename = "close", default, skip_serializing_if = "Address::is_zero")]
    pub close_remainder_to: Address,
}

fn is_empty_bytes(v: &ByteBuf) -> bool {
    v.is_empty()
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !v
}
