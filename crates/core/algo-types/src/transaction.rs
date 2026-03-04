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

    /// Multisig signature.
    #[serde(rename = "msig", default, skip_serializing_if = "Option::is_none")]
    pub msig: Option<MultisigSig>,

    /// Logic signature.
    #[serde(rename = "lsig", default, skip_serializing_if = "Option::is_none")]
    pub lsig: Option<LogicSig>,

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
///
/// # Address field conventions
///
/// Some address fields use bare `Address` (e.g. `receiver`, `close_remainder_to`)
/// while others use `Option<Address>` (e.g. `asset_receiver`, `freeze_account`).
/// The bare `Address` fields correspond to payment transaction fields that exist
/// in Go's `PaymentTxnFields` struct, where the zero address is the canonical
/// "absent" representation and `skip_serializing_if = "Address::is_zero"` omits
/// them. The `Option<Address>` fields correspond to newer transaction types
/// (axfer, afrz, appl) where `None` is semantically meaningful and distinct
/// from the zero address.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
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

    // ── Asset Transfer (axfer) fields ─────────────────────────
    /// Asset ID.
    #[serde(rename = "xaid", default, skip_serializing_if = "is_zero_u64")]
    pub xaid: u64,

    /// Asset amount.
    #[serde(rename = "aamt", default, skip_serializing_if = "is_zero_u64")]
    pub asset_amount: u64,

    /// Asset sender (clawback).
    #[serde(rename = "asnd", default, skip_serializing_if = "Option::is_none")]
    pub asset_sender: Option<Address>,

    /// Asset receiver.
    #[serde(rename = "arcv", default, skip_serializing_if = "Option::is_none")]
    pub asset_receiver: Option<Address>,

    /// Asset close-to address.
    #[serde(rename = "aclose", default, skip_serializing_if = "Option::is_none")]
    pub asset_close_to: Option<Address>,

    // ── Asset Config (acfg) fields ────────────────────────────
    /// Config asset ID (0 for create).
    #[serde(rename = "caid", default, skip_serializing_if = "is_zero_u64")]
    pub config_asset: u64,

    /// Asset parameters.
    #[serde(rename = "apar", default, skip_serializing_if = "Option::is_none")]
    pub asset_params: Option<AssetParams>,

    // ── Asset Freeze (afrz) fields ────────────────────────────
    /// Freeze asset ID.
    #[serde(rename = "faid", default, skip_serializing_if = "is_zero_u64")]
    pub freeze_asset: u64,

    /// Freeze account address.
    #[serde(rename = "fadd", default, skip_serializing_if = "Option::is_none")]
    pub freeze_account: Option<Address>,

    /// Freeze flag.
    #[serde(rename = "afrz", default, skip_serializing_if = "is_false")]
    pub asset_frozen: bool,

    // ── Application Call (appl) fields ────────────────────────
    /// Application ID.
    #[serde(rename = "apid", default, skip_serializing_if = "is_zero_u64")]
    pub application_id: u64,

    /// On-completion action.
    #[serde(rename = "apan", default, skip_serializing_if = "is_zero_u64")]
    pub on_completion: u64,

    /// Approval program.
    #[serde(rename = "apap", default, skip_serializing_if = "Option::is_none")]
    pub approval_program: Option<ByteBuf>,

    /// Clear state program.
    #[serde(rename = "apsu", default, skip_serializing_if = "Option::is_none")]
    pub clear_state_program: Option<ByteBuf>,

    /// Application arguments.
    #[serde(rename = "apaa", default, skip_serializing_if = "Option::is_none")]
    pub app_arguments: Option<Vec<ByteBuf>>,

    /// Accounts referenced by the application call.
    #[serde(rename = "apat", default, skip_serializing_if = "Option::is_none")]
    pub accounts: Option<Vec<Address>>,

    /// Foreign apps.
    #[serde(rename = "apfa", default, skip_serializing_if = "Option::is_none")]
    pub foreign_apps: Option<Vec<u64>>,

    /// Foreign assets.
    #[serde(rename = "apas", default, skip_serializing_if = "Option::is_none")]
    pub foreign_assets: Option<Vec<u64>>,

    /// Box references.
    #[serde(rename = "apbx", default, skip_serializing_if = "Option::is_none")]
    pub boxes: Option<Vec<BoxRef>>,

    /// Global state schema.
    #[serde(rename = "apgs", default, skip_serializing_if = "Option::is_none")]
    pub global_state_schema: Option<StateSchema>,

    /// Local state schema.
    #[serde(rename = "apls", default, skip_serializing_if = "Option::is_none")]
    pub local_state_schema: Option<StateSchema>,

    /// Extra program pages.
    #[serde(rename = "apep", default, skip_serializing_if = "is_zero_u64")]
    pub extra_program_pages: u64,

    // ── Key Registration (keyreg) fields ──────────────────────
    /// Vote public key.
    #[serde(rename = "votekey", default, skip_serializing_if = "Option::is_none")]
    pub vote_pk: Option<ByteBuf>,

    /// Selection public key.
    #[serde(rename = "selkey", default, skip_serializing_if = "Option::is_none")]
    pub selection_pk: Option<ByteBuf>,

    /// State proof key.
    #[serde(rename = "sprfkey", default, skip_serializing_if = "Option::is_none")]
    pub state_proof_pk: Option<ByteBuf>,

    /// Vote first valid round.
    #[serde(rename = "votefst", default, skip_serializing_if = "is_zero_u64")]
    pub vote_first: u64,

    /// Vote last valid round.
    #[serde(rename = "votelst", default, skip_serializing_if = "is_zero_u64")]
    pub vote_last: u64,

    /// Vote key dilution.
    #[serde(rename = "votekd", default, skip_serializing_if = "is_zero_u64")]
    pub vote_key_dilution: u64,

    /// Non-participation flag.
    #[serde(rename = "nonpart", default, skip_serializing_if = "is_false")]
    pub non_participation: bool,

    // ── State Proof (stpf) fields ─────────────────────────────
    /// State proof type.
    #[serde(rename = "sptype", default, skip_serializing_if = "is_zero_u64")]
    pub state_proof_type: u64,

    /// State proof body (opaque, passthrough encoding).
    #[serde(rename = "sp", default, skip_serializing_if = "Option::is_none")]
    pub state_proof: Option<rmpv::Value>,
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

/// Multisig subsignature.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MultisigSubsig {
    /// Public key.
    #[serde(rename = "pk")]
    pub public_key: ByteBuf,

    /// Signature (empty if this subsigner hasn't signed).
    #[serde(rename = "s", default, skip_serializing_if = "is_empty_bytes")]
    pub signature: ByteBuf,
}

/// Multisig signature.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MultisigSig {
    /// Version.
    #[serde(rename = "v")]
    pub version: u8,

    /// Threshold.
    #[serde(rename = "thr")]
    pub threshold: u8,

    /// Subsignatures.
    #[serde(rename = "subsig")]
    pub subsigs: Vec<MultisigSubsig>,
}

/// Logic signature.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LogicSig {
    /// TEAL program bytes.
    #[serde(rename = "l")]
    pub logic: ByteBuf,

    /// Delegated signature (optional).
    #[serde(rename = "sig", default, skip_serializing_if = "is_empty_bytes")]
    pub sig: ByteBuf,

    /// Delegated multisig (optional).
    #[serde(rename = "msig", default, skip_serializing_if = "Option::is_none")]
    pub msig: Option<MultisigSig>,

    /// Arguments (optional).
    #[serde(rename = "arg", default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<ByteBuf>>,
}

/// Asset parameters for asset config transactions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetParams {
    /// Total number of units.
    #[serde(rename = "t", default, skip_serializing_if = "is_zero_u64")]
    pub total: u64,

    /// Number of decimals.
    #[serde(rename = "dc", default, skip_serializing_if = "is_zero_u64")]
    pub decimals: u64,

    /// Default frozen.
    #[serde(rename = "df", default, skip_serializing_if = "is_false")]
    pub default_frozen: bool,

    /// Unit name.
    #[serde(rename = "un", default, skip_serializing_if = "String::is_empty")]
    pub unit_name: String,

    /// Asset name.
    #[serde(rename = "an", default, skip_serializing_if = "String::is_empty")]
    pub asset_name: String,

    /// URL.
    #[serde(rename = "au", default, skip_serializing_if = "String::is_empty")]
    pub url: String,

    /// Metadata hash.
    #[serde(rename = "am", default, skip_serializing_if = "Option::is_none")]
    pub metadata_hash: Option<ByteBuf>,

    /// Manager address.
    #[serde(rename = "m", default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<Address>,

    /// Reserve address.
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub reserve: Option<Address>,

    /// Freeze address.
    #[serde(rename = "f", default, skip_serializing_if = "Option::is_none")]
    pub freeze: Option<Address>,

    /// Clawback address.
    #[serde(rename = "c", default, skip_serializing_if = "Option::is_none")]
    pub clawback: Option<Address>,
}

/// State schema for application calls.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StateSchema {
    /// Number of uint values.
    #[serde(rename = "nui", default, skip_serializing_if = "is_zero_u64")]
    pub num_uint: u64,

    /// Number of byte slice values.
    #[serde(rename = "nbs", default, skip_serializing_if = "is_zero_u64")]
    pub num_byte_slice: u64,
}

/// Box reference for application calls.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BoxRef {
    /// Foreign app index.
    #[serde(rename = "i", default, skip_serializing_if = "is_zero_u64")]
    pub index: u64,

    /// Box name.
    #[serde(rename = "n", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<ByteBuf>,
}
