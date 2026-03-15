use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::fmt;

use crate::serde_bytes_array::{
    is_none_or_zero_32, is_none_or_zero_64, is_zero_32, is_zero_64, serde_bytes_32,
    serde_bytes_32_opt, serde_bytes_64, serde_bytes_64_opt, zeros_64,
};
use crate::{Address, Round};

/// Algorand transaction type as a zero-allocation enum.
///
/// Maps 1-to-1 with the short protocol strings ("pay", "axfer", etc.).
/// The `Unknown(String)` variant preserves forward compatibility for new
/// transaction types that this codebase does not yet recognise.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TxnType {
    Pay,
    Axfer,
    Acfg,
    Afrz,
    Appl,
    Keyreg,
    Stpf,
    Hb,
    Unknown(String),
}

impl TxnType {
    /// Return the canonical protocol-level short string.
    pub fn as_str(&self) -> &str {
        match self {
            TxnType::Pay => "pay",
            TxnType::Axfer => "axfer",
            TxnType::Acfg => "acfg",
            TxnType::Afrz => "afrz",
            TxnType::Appl => "appl",
            TxnType::Keyreg => "keyreg",
            TxnType::Stpf => "stpf",
            TxnType::Hb => "hb",
            TxnType::Unknown(s) => s.as_str(),
        }
    }

    /// Return `true` if this is the empty/default type.
    pub fn is_empty(&self) -> bool {
        matches!(self, TxnType::Unknown(s) if s.is_empty())
    }
}

impl Default for TxnType {
    fn default() -> Self {
        TxnType::Unknown(String::new())
    }
}

impl fmt::Display for TxnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for TxnType {
    fn from(s: &str) -> Self {
        match s {
            "pay" => TxnType::Pay,
            "axfer" => TxnType::Axfer,
            "acfg" => TxnType::Acfg,
            "afrz" => TxnType::Afrz,
            "appl" => TxnType::Appl,
            "keyreg" => TxnType::Keyreg,
            "stpf" => TxnType::Stpf,
            "hb" => TxnType::Hb,
            other => TxnType::Unknown(other.to_string()),
        }
    }
}

impl From<String> for TxnType {
    fn from(s: String) -> Self {
        match s.as_str() {
            "pay" => TxnType::Pay,
            "axfer" => TxnType::Axfer,
            "acfg" => TxnType::Acfg,
            "afrz" => TxnType::Afrz,
            "appl" => TxnType::Appl,
            "keyreg" => TxnType::Keyreg,
            "stpf" => TxnType::Stpf,
            "hb" => TxnType::Hb,
            _ => TxnType::Unknown(s),
        }
    }
}

/// Allow `TxnType == "pay"` comparisons for ergonomics.
impl PartialEq<&str> for TxnType {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Allow `"pay" == TxnType` comparisons.
impl PartialEq<TxnType> for &str {
    fn eq(&self, other: &TxnType) -> bool {
        *self == other.as_str()
    }
}

impl Serialize for TxnType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TxnType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(TxnType::from(s))
    }
}

/// A signed transaction as it appears in a block's payset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The transaction body.
    #[serde(rename = "txn")]
    pub txn: Transaction,

    /// Ed25519 signature (ed25519Signature = [64]byte in Go).
    #[serde(
        rename = "sig",
        default = "zeros_64",
        skip_serializing_if = "is_zero_64",
        with = "serde_bytes_64"
    )]
    pub sig: [u8; 64],

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

    // ── ApplyData fields (from SignedTxnWithAD in go-algorand) ─────
    // These are part of SignedTxnInBlock's embedded ApplyData struct.
    // They record the results of transaction execution (closing amounts,
    // rewards, created asset/app IDs). Needed for STIB hash computation.
    /// Closing amount for payment transactions (ApplyData.ca).
    #[serde(rename = "ca", default, skip_serializing_if = "is_zero_u64")]
    pub closing_amount: u64,

    /// Closing amount for asset transfer transactions (ApplyData.aca).
    #[serde(rename = "aca", default, skip_serializing_if = "is_zero_u64")]
    pub asset_closing_amount: u64,

    /// Sender rewards (ApplyData.rs).
    #[serde(rename = "rs", default, skip_serializing_if = "is_zero_u64")]
    pub sender_rewards: u64,

    /// Receiver rewards (ApplyData.rr).
    #[serde(rename = "rr", default, skip_serializing_if = "is_zero_u64")]
    pub receiver_rewards: u64,

    /// Close rewards (ApplyData.rc).
    #[serde(rename = "rc", default, skip_serializing_if = "is_zero_u64")]
    pub close_rewards: u64,

    /// Eval delta -- application state changes (ApplyData.dt).
    /// Opaque passthrough; uses rmpv::Value since EvalDelta contains
    /// recursive inner transactions and complex state deltas.
    #[serde(rename = "dt", default, skip_serializing_if = "Option::is_none")]
    pub eval_delta: Option<rmpv::Value>,

    /// Created/configured asset ID from ApplyData (ApplyData.caid).
    /// Set when an acfg create transaction is executed.
    /// Note: this is DISTINCT from Transaction.config_asset (txn.caid) --
    /// this field is at the SignedTxnInBlock level, not inside the "txn" map.
    #[serde(rename = "caid", default, skip_serializing_if = "is_zero_u64")]
    pub apply_data_config_asset: u64,

    /// Created application ID from ApplyData (ApplyData.apid).
    /// Set when an appl create transaction is executed.
    /// Note: this is DISTINCT from Transaction.application_id (txn.apid).
    #[serde(rename = "apid", default, skip_serializing_if = "is_zero_u64")]
    pub apply_data_application_id: u64,
}

impl Default for SignedTransaction {
    fn default() -> Self {
        Self {
            txn: Transaction::default(),
            sig: [0u8; 64],
            msig: None,
            lsig: None,
            auth_addr: None,
            has_genesis_id: false,
            has_genesis_hash: false,
            closing_amount: 0,
            asset_closing_amount: 0,
            sender_rewards: 0,
            receiver_rewards: 0,
            close_rewards: 0,
            eval_delta: None,
            apply_data_config_asset: 0,
            apply_data_application_id: 0,
        }
    }
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
    /// Transaction type ("pay", "axfer", "acfg", "afrz", "appl", "keyreg", "stpf", "hb").
    #[serde(rename = "type")]
    pub txn_type: TxnType,

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

    /// Note field (variable length).
    #[serde(rename = "note", default, skip_serializing_if = "is_empty_bytes")]
    pub note: ByteBuf,

    /// Genesis ID.
    #[serde(rename = "gen", default, skip_serializing_if = "String::is_empty")]
    pub genesis_id: String,

    /// Genesis hash (crypto.Digest = [32]byte in Go).
    #[serde(
        rename = "gh",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub genesis_hash: [u8; 32],

    /// Group ID (crypto.Digest = [32]byte in Go).
    #[serde(
        rename = "grp",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub group: [u8; 32],

    /// Lease ([32]byte in Go).
    #[serde(
        rename = "lx",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub lease: [u8; 32],

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

    /// Approval program (variable length).
    #[serde(rename = "apap", default, skip_serializing_if = "Option::is_none")]
    pub approval_program: Option<ByteBuf>,

    /// Clear state program (variable length).
    #[serde(rename = "apsu", default, skip_serializing_if = "Option::is_none")]
    pub clear_state_program: Option<ByteBuf>,

    /// Application arguments (variable length).
    #[serde(rename = "apaa", default, skip_serializing_if = "Option::is_none")]
    pub app_arguments: Option<Vec<Option<ByteBuf>>>,

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

    /// Extra program pages (uint32 in Go).
    #[serde(rename = "apep", default, skip_serializing_if = "is_zero_u32")]
    pub extra_program_pages: u32,

    // ── Key Registration (keyreg) fields ──────────────────────
    /// Vote public key (OneTimeSignatureVerifier = [32]byte in Go).
    #[serde(
        rename = "votekey",
        default,
        skip_serializing_if = "is_none_or_zero_32",
        with = "serde_bytes_32_opt"
    )]
    pub vote_pk: Option<[u8; 32]>,

    /// Selection public key (VRFVerifier = [32]byte in Go).
    #[serde(
        rename = "selkey",
        default,
        skip_serializing_if = "is_none_or_zero_32",
        with = "serde_bytes_32_opt"
    )]
    pub selection_pk: Option<[u8; 32]>,

    /// State proof key (merklesignature.Commitment = [64]byte in Go).
    #[serde(
        rename = "sprfkey",
        default,
        skip_serializing_if = "is_none_or_zero_64",
        with = "serde_bytes_64_opt"
    )]
    pub state_proof_pk: Option<[u8; 64]>,

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

    /// State proof body.
    #[serde(rename = "sp", default, skip_serializing_if = "Option::is_none")]
    pub state_proof: Option<StateProofBody>,

    /// State proof message.
    #[serde(rename = "spmsg", default, skip_serializing_if = "Option::is_none")]
    pub state_proof_message: Option<StateProofMessage>,

    // ── Heartbeat (hb) fields ───────────────────────────────────
    /// Heartbeat fields.
    #[serde(rename = "hb", default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<HeartbeatTxnFields>,

    // ── Application Call extended fields ────────────────────────
    /// Access list (V41+ unified resource references).
    #[serde(rename = "al", default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Vec<ResourceRef>>,

    /// Reject version for application calls.
    #[serde(rename = "aprv", default, skip_serializing_if = "is_zero_u64")]
    pub reject_version: u64,
}

fn is_empty_bytes(v: &ByteBuf) -> bool {
    v.is_empty()
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}

fn is_false(v: &bool) -> bool {
    !v
}

/// Multisig subsignature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultisigSubsig {
    /// Public key (ed25519PublicKey = [32]byte in Go).
    #[serde(rename = "pk", with = "serde_bytes_32")]
    pub public_key: [u8; 32],

    /// Signature (ed25519Signature = [64]byte in Go; empty if this subsigner hasn't signed).
    #[serde(
        rename = "s",
        default = "zeros_64",
        skip_serializing_if = "is_zero_64",
        with = "serde_bytes_64"
    )]
    pub signature: [u8; 64],
}

impl Default for MultisigSubsig {
    fn default() -> Self {
        Self {
            public_key: [0u8; 32],
            signature: [0u8; 64],
        }
    }
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogicSig {
    /// TEAL program bytes (variable length).
    #[serde(rename = "l")]
    pub logic: ByteBuf,

    /// Delegated signature (ed25519Signature = [64]byte in Go).
    #[serde(
        rename = "sig",
        default = "zeros_64",
        skip_serializing_if = "is_zero_64",
        with = "serde_bytes_64"
    )]
    pub sig: [u8; 64],

    /// Delegated multisig (optional).
    #[serde(rename = "msig", default, skip_serializing_if = "Option::is_none")]
    pub msig: Option<MultisigSig>,

    /// Arguments (optional, variable length).
    #[serde(rename = "arg", default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<ByteBuf>>,

    /// Delegated logic multisig (optional).
    #[serde(rename = "lmsig", default, skip_serializing_if = "Option::is_none")]
    pub lmsig: Option<MultisigSig>,
}

impl Default for LogicSig {
    fn default() -> Self {
        Self {
            logic: ByteBuf::new(),
            sig: [0u8; 64],
            msig: None,
            args: None,
            lmsig: None,
        }
    }
}

/// Asset parameters for asset config transactions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AssetParams {
    /// Total number of units.
    #[serde(rename = "t", default, skip_serializing_if = "is_zero_u64")]
    pub total: u64,

    /// Number of decimals (uint32 in Go).
    #[serde(rename = "dc", default, skip_serializing_if = "is_zero_u32")]
    pub decimals: u32,

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

    /// Metadata hash ([32]byte in Go).
    #[serde(
        rename = "am",
        default,
        skip_serializing_if = "is_none_or_zero_32",
        with = "serde_bytes_32_opt"
    )]
    pub metadata_hash: Option<[u8; 32]>,

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
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
pub struct StateSchema {
    /// Number of uint values.
    #[serde(rename = "nui", default, skip_serializing_if = "is_zero_u64")]
    pub num_uint: u64,

    /// Number of byte slice values.
    #[serde(rename = "nbs", default, skip_serializing_if = "is_zero_u64")]
    pub num_byte_slice: u64,
}

impl StateSchema {
    /// Add two StateSchemas together (saturating).
    pub fn add_schema(&self, other: &StateSchema) -> StateSchema {
        StateSchema {
            num_uint: self.num_uint.saturating_add(other.num_uint),
            num_byte_slice: self.num_byte_slice.saturating_add(other.num_byte_slice),
        }
    }

    /// Subtract one StateSchema from another (saturating).
    pub fn sub_schema(&self, other: &StateSchema) -> StateSchema {
        StateSchema {
            num_uint: self.num_uint.saturating_sub(other.num_uint),
            num_byte_slice: self.num_byte_slice.saturating_sub(other.num_byte_slice),
        }
    }
}

/// Box reference for application calls.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BoxRef {
    /// Foreign app index.
    #[serde(rename = "i", default, skip_serializing_if = "is_zero_u64")]
    pub index: u64,

    /// Box name (variable length).
    #[serde(rename = "n", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<ByteBuf>,
}

// ── Heartbeat types ────────────────────────────────────────────

/// Heartbeat proof (crypto.HeartbeatProof in Go).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatProof {
    /// Ed25519 signature ([64]byte).
    #[serde(
        rename = "s",
        default = "zeros_64",
        skip_serializing_if = "is_zero_64",
        with = "serde_bytes_64"
    )]
    pub sig: [u8; 64],

    /// Ephemeral public key ([32]byte).
    #[serde(
        rename = "p",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub pk: [u8; 32],

    /// Second ephemeral public key ([32]byte).
    #[serde(
        rename = "p2",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub pk2: [u8; 32],

    /// PK1 signature ([64]byte).
    #[serde(
        rename = "p1s",
        default = "zeros_64",
        skip_serializing_if = "is_zero_64",
        with = "serde_bytes_64"
    )]
    pub pk1_sig: [u8; 64],

    /// PK2 signature ([64]byte).
    #[serde(
        rename = "p2s",
        default = "zeros_64",
        skip_serializing_if = "is_zero_64",
        with = "serde_bytes_64"
    )]
    pub pk2_sig: [u8; 64],
}

impl Default for HeartbeatProof {
    fn default() -> Self {
        Self {
            sig: [0u8; 64],
            pk: [0u8; 32],
            pk2: [0u8; 32],
            pk1_sig: [0u8; 64],
            pk2_sig: [0u8; 64],
        }
    }
}

/// Heartbeat transaction fields.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HeartbeatTxnFields {
    /// Heartbeat address ([32]byte).
    #[serde(rename = "a", default, skip_serializing_if = "Address::is_zero")]
    pub address: Address,

    /// Heartbeat proof.
    #[serde(rename = "prf", default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<HeartbeatProof>,

    /// Seed ([32]byte).
    #[serde(
        rename = "sd",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub seed: [u8; 32],

    /// Vote ID ([32]byte).
    #[serde(
        rename = "vid",
        default,
        skip_serializing_if = "is_zero_32",
        with = "serde_bytes_32"
    )]
    pub vote_id: [u8; 32],

    /// Key dilution.
    #[serde(rename = "kd", default, skip_serializing_if = "is_zero_u64")]
    pub key_dilution: u64,
}

// ── State Proof types ──────────────────────────────────────────

/// Hash factory (crypto.HashFactory in Go).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HashFactory {
    /// Hash type (uint16 in Go).
    #[serde(rename = "t", default, skip_serializing_if = "is_zero_u16")]
    pub hash_type: u16,
}

/// Merkle array proof (merklearray.Proof in Go).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Proof path -- array of generic digests ([]byte each, variable length).
    #[serde(rename = "pth", default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<Option<ByteBuf>>>,

    /// Hash factory.
    #[serde(rename = "hsh", default, skip_serializing_if = "Option::is_none")]
    pub hash_factory: Option<HashFactory>,

    /// Tree depth.
    #[serde(rename = "td", default, skip_serializing_if = "is_zero_u8")]
    pub tree_depth: u8,
}

/// Falcon verifier (crypto.FalconVerifier in Go).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FalconVerifier {
    /// Falcon public key ([1793]byte in Go, kept as variable-length bytes).
    #[serde(rename = "k", default, skip_serializing_if = "is_empty_bytes")]
    pub public_key: ByteBuf,
}

/// Merkle signature (merklesignature.Signature in Go).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MerkleSignature {
    /// Falcon signature (variable length).
    #[serde(rename = "sig", default, skip_serializing_if = "is_empty_bytes")]
    pub signature: ByteBuf,

    /// Vector commitment index.
    #[serde(rename = "idx", default, skip_serializing_if = "is_zero_u64")]
    pub vector_commitment_index: u64,

    /// Single leaf proof.
    #[serde(rename = "prf", default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<MerkleProof>,

    /// Falcon verifying key.
    #[serde(rename = "vkey", default, skip_serializing_if = "Option::is_none")]
    pub verifying_key: Option<FalconVerifier>,
}

/// Signature slot commit (stateproof.sigslotCommit in Go).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SigSlotCommit {
    /// Merkle signature.
    #[serde(rename = "s", default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<MerkleSignature>,

    /// L value.
    #[serde(rename = "l", default, skip_serializing_if = "is_zero_u64")]
    pub l: u64,
}

/// Merkle signature verifier (merklesignature.Verifier in Go).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MerkleSignatureVerifier {
    /// Commitment (merklesignature.Commitment = [64]byte in Go).
    #[serde(
        rename = "cmt",
        default = "zeros_64",
        skip_serializing_if = "is_zero_64",
        with = "serde_bytes_64"
    )]
    pub commitment: [u8; 64],

    /// Key lifetime.
    #[serde(rename = "lf", default, skip_serializing_if = "is_zero_u64")]
    pub key_lifetime: u64,
}

impl Default for MerkleSignatureVerifier {
    fn default() -> Self {
        Self {
            commitment: [0u8; 64],
            key_lifetime: 0,
        }
    }
}

/// State proof participant (basics.Participant in Go).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Participant {
    /// Verifier.
    #[serde(rename = "p", default, skip_serializing_if = "Option::is_none")]
    pub pk: Option<MerkleSignatureVerifier>,

    /// Weight.
    #[serde(rename = "w", default, skip_serializing_if = "is_zero_u64")]
    pub weight: u64,
}

/// State proof reveal (stateproof.Reveal in Go).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Reveal {
    /// Signature slot.
    #[serde(rename = "s", default, skip_serializing_if = "Option::is_none")]
    pub sig_slot: Option<SigSlotCommit>,

    /// Participant.
    #[serde(rename = "p", default, skip_serializing_if = "Option::is_none")]
    pub part: Option<Participant>,
}

/// State proof body (stateproof.StateProof in Go).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StateProofBody {
    /// Signature commitment (GenericDigest = []byte, variable length).
    #[serde(rename = "c", default, skip_serializing_if = "is_empty_bytes")]
    pub sig_commit: ByteBuf,

    /// Signed weight.
    #[serde(rename = "w", default, skip_serializing_if = "is_zero_u64")]
    pub signed_weight: u64,

    /// Signature proofs.
    #[serde(rename = "S", default, skip_serializing_if = "Option::is_none")]
    pub sig_proofs: Option<MerkleProof>,

    /// Participant proofs.
    #[serde(rename = "P", default, skip_serializing_if = "Option::is_none")]
    pub part_proofs: Option<MerkleProof>,

    /// Merkle signature salt version.
    #[serde(rename = "v", default, skip_serializing_if = "is_zero_u8")]
    pub merkle_signature_salt_version: u8,

    /// Reveals (map from uint64 position to Reveal).
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub reveals: Option<std::collections::BTreeMap<u64, Reveal>>,

    /// Positions to reveal.
    #[serde(rename = "pr", default, skip_serializing_if = "Option::is_none")]
    pub positions_to_reveal: Option<Vec<u64>>,
}

/// State proof message (stateproofmsg.Message in Go).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StateProofMessage {
    /// Block headers commitment (GenericDigest = []byte, variable length).
    #[serde(rename = "b", default, skip_serializing_if = "is_empty_bytes")]
    pub block_headers_commitment: ByteBuf,

    /// Voters commitment (GenericDigest = []byte, variable length).
    #[serde(rename = "v", default, skip_serializing_if = "is_empty_bytes")]
    pub voters_commitment: ByteBuf,

    /// Ln proven weight.
    #[serde(rename = "P", default, skip_serializing_if = "is_zero_u64")]
    pub ln_proven_weight: u64,

    /// First attested round.
    #[serde(rename = "f", default, skip_serializing_if = "is_zero_u64")]
    pub first_attested_round: u64,

    /// Last attested round.
    #[serde(rename = "l", default, skip_serializing_if = "is_zero_u64")]
    pub last_attested_round: u64,
}

// ── Access / Resource Reference types (V41+) ───────────────────

/// Holding reference (index-based, within Access list).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HoldingRef {
    /// Address index (0=Sender, n-1=1-based index into Access list).
    #[serde(rename = "d", default, skip_serializing_if = "is_zero_u64")]
    pub address: u64,

    /// Asset index (n-1=1-based index into Access list).
    #[serde(rename = "s", default, skip_serializing_if = "is_zero_u64")]
    pub asset: u64,
}

/// Locals reference (index-based, within Access list).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LocalsRef {
    /// Address index (0=Sender, n-1=1-based index into Access list).
    #[serde(rename = "d", default, skip_serializing_if = "is_zero_u64")]
    pub address: u64,

    /// App index (0=ApplicationID, n-1=1-based index into Access list).
    #[serde(rename = "p", default, skip_serializing_if = "is_zero_u64")]
    pub app: u64,
}

/// Unified resource reference (V41+ Access list entry).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceRef {
    /// Direct address reference.
    #[serde(rename = "d", default, skip_serializing_if = "Address::is_zero")]
    pub address: Address,

    /// Direct asset reference.
    #[serde(rename = "s", default, skip_serializing_if = "is_zero_u64")]
    pub asset: u64,

    /// Direct app reference.
    #[serde(rename = "p", default, skip_serializing_if = "is_zero_u64")]
    pub app: u64,

    /// Holding reference.
    #[serde(rename = "h", default, skip_serializing_if = "Option::is_none")]
    pub holding: Option<HoldingRef>,

    /// Locals reference.
    #[serde(rename = "l", default, skip_serializing_if = "Option::is_none")]
    pub locals: Option<LocalsRef>,

    /// Box reference.
    #[serde(rename = "b", default, skip_serializing_if = "Option::is_none")]
    pub box_ref: Option<BoxRef>,
}
