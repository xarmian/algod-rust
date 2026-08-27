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

// ════════════════════════════════════════════════════════════════
// Standalone msgpack decoders (rmp-based, no serde overhead)
// ════════════════════════════════════════════════════════════════

use crate::rmp_decode;

/// Type alias for decoder methods to avoid shadowing serde's Result usage.
type DecodeResult<T> = algo_error::Result<T>;

impl StateSchema {
    /// Decode from a msgpack map using raw rmp.
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"nui" => s.num_uint = rmp_decode::read_u64(rd)?,
                b"nbs" => s.num_byte_slice = rmp_decode::read_u64(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    /// Decode from msgpack bytes.
    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl BoxRef {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"i" => s.index = rmp_decode::read_u64(rd)?,
                b"n" => s.name = rmp_decode::read_optional(rd, rmp_decode::read_bytes_as_bytebuf)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl AssetParams {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"t" => s.total = rmp_decode::read_u64(rd)?,
                b"dc" => s.decimals = rmp_decode::read_u32(rd)?,
                b"df" => s.default_frozen = rmp_decode::read_bool(rd)?,
                b"un" => s.unit_name = rmp_decode::read_string(rd)?,
                b"an" => s.asset_name = rmp_decode::read_string(rd)?,
                b"au" => s.url = rmp_decode::read_string(rd)?,
                b"am" => {
                    s.metadata_hash =
                        rmp_decode::read_optional(rd, rmp_decode::read_fixed_bytes::<32>)?
                }
                b"m" => s.manager = rmp_decode::read_optional(rd, rmp_decode::read_address)?,
                b"r" => s.reserve = rmp_decode::read_optional(rd, rmp_decode::read_address)?,
                b"f" => s.freeze = rmp_decode::read_optional(rd, rmp_decode::read_address)?,
                b"c" => s.clawback = rmp_decode::read_optional(rd, rmp_decode::read_address)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl MultisigSubsig {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"pk" => s.public_key = rmp_decode::read_fixed_bytes::<32>(rd)?,
                b"s" => s.signature = rmp_decode::read_fixed_bytes::<64>(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl MultisigSig {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"v" => s.version = rmp_decode::read_u8_val(rd)?,
                b"thr" => s.threshold = rmp_decode::read_u8_val(rd)?,
                b"subsig" => {
                    s.subsigs = rmp_decode::read_vec(rd, MultisigSubsig::decode_from_reader)?
                }
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        // go-algorand v4.7.2-stable marks Version/Threshold/Subsigs `codec:",required"`:
        // the generated decoder rejects the field's zero value regardless of key presence
        // on the wire, so check the decoded value rather than an on-key-seen flag.
        if s.version == 0 {
            return Err(algo_error::AlgoError::Codec {
                source: "missing required field 'v'".into(),
                context: "rmp_decode".into(),
            });
        }
        if s.threshold == 0 {
            return Err(algo_error::AlgoError::Codec {
                source: "missing required field 'thr'".into(),
                context: "rmp_decode".into(),
            });
        }
        if s.subsigs.is_empty() {
            return Err(algo_error::AlgoError::Codec {
                source: "missing required field 'subsig'".into(),
                context: "rmp_decode".into(),
            });
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl LogicSig {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        let mut has_logic = false;
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"l" => {
                    s.logic = rmp_decode::read_bytes_as_bytebuf(rd)?;
                    has_logic = true;
                }
                b"sig" => s.sig = rmp_decode::read_fixed_bytes::<64>(rd)?,
                b"msig" => s.msig = rmp_decode::read_optional(rd, MultisigSig::decode_from_reader)?,
                b"arg" => {
                    s.args = rmp_decode::read_optional_vec(rd, rmp_decode::read_bytes_as_bytebuf)?
                }
                b"lmsig" => {
                    s.lmsig = rmp_decode::read_optional(rd, MultisigSig::decode_from_reader)?
                }
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        if !has_logic {
            return Err(algo_error::AlgoError::Codec {
                source: "missing required field 'l'".into(),
                context: "rmp_decode".into(),
            });
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl HeartbeatProof {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"s" => s.sig = rmp_decode::read_fixed_bytes::<64>(rd)?,
                b"p" => s.pk = rmp_decode::read_fixed_bytes::<32>(rd)?,
                b"p2" => s.pk2 = rmp_decode::read_fixed_bytes::<32>(rd)?,
                b"p1s" => s.pk1_sig = rmp_decode::read_fixed_bytes::<64>(rd)?,
                b"p2s" => s.pk2_sig = rmp_decode::read_fixed_bytes::<64>(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl HeartbeatTxnFields {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"a" => s.address = rmp_decode::read_address(rd)?,
                b"prf" => {
                    s.proof = rmp_decode::read_optional(rd, HeartbeatProof::decode_from_reader)?
                }
                b"sd" => s.seed = rmp_decode::read_fixed_bytes::<32>(rd)?,
                b"vid" => s.vote_id = rmp_decode::read_fixed_bytes::<32>(rd)?,
                b"kd" => s.key_dilution = rmp_decode::read_u64(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl HashFactory {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"t" => s.hash_type = rmp_decode::read_u16(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

/// Helper to read an optional ByteBuf that may be nil.
fn read_optional_bytebuf(rd: &mut &[u8]) -> DecodeResult<Option<ByteBuf>> {
    rmp_decode::read_optional(rd, rmp_decode::read_bytes_as_bytebuf)
}

impl MerkleProof {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"pth" => s.path = rmp_decode::read_optional_vec(rd, read_optional_bytebuf)?,
                b"hsh" => {
                    s.hash_factory = rmp_decode::read_optional(rd, HashFactory::decode_from_reader)?
                }
                b"td" => s.tree_depth = rmp_decode::read_u8_val(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl FalconVerifier {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"k" => s.public_key = rmp_decode::read_bytes_as_bytebuf(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl MerkleSignature {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"sig" => s.signature = rmp_decode::read_bytes_as_bytebuf(rd)?,
                b"idx" => s.vector_commitment_index = rmp_decode::read_u64(rd)?,
                b"prf" => s.proof = rmp_decode::read_optional(rd, MerkleProof::decode_from_reader)?,
                b"vkey" => {
                    s.verifying_key =
                        rmp_decode::read_optional(rd, FalconVerifier::decode_from_reader)?
                }
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl SigSlotCommit {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"s" => s.sig = rmp_decode::read_optional(rd, MerkleSignature::decode_from_reader)?,
                b"l" => s.l = rmp_decode::read_u64(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl MerkleSignatureVerifier {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"cmt" => s.commitment = rmp_decode::read_fixed_bytes::<64>(rd)?,
                b"lf" => s.key_lifetime = rmp_decode::read_u64(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl Participant {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"p" => {
                    s.pk =
                        rmp_decode::read_optional(rd, MerkleSignatureVerifier::decode_from_reader)?
                }
                b"w" => s.weight = rmp_decode::read_u64(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        // go-algorand v4.7.2-stable marks `basics.Participant.PK` `codec:",required"`: the
        // generated decoder rejects `PK.MsgIsZero()` regardless of key presence on the wire,
        // so also reject an explicit-but-all-zero verifier, not just an absent "p" key.
        if s.pk
            .as_ref()
            .map_or(true, |pk| *pk == MerkleSignatureVerifier::default())
        {
            return Err(algo_error::AlgoError::Codec {
                source: "missing required field 'p'".into(),
                context: "rmp_decode".into(),
            });
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl Reveal {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"s" => {
                    s.sig_slot = rmp_decode::read_optional(rd, SigSlotCommit::decode_from_reader)?
                }
                b"p" => s.part = rmp_decode::read_optional(rd, Participant::decode_from_reader)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        // go-algorand v4.7.2-stable marks `stateproof.Reveal.Part` `codec:",required"`. The
        // "PK present but zero" sub-case is already caught above by Participant's own
        // required-PK check, propagated through the `?` on the `read_optional` call.
        if s.part.is_none() {
            return Err(algo_error::AlgoError::Codec {
                source: "missing required field 'p'".into(),
                context: "rmp_decode".into(),
            });
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl StateProofBody {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"c" => s.sig_commit = rmp_decode::read_bytes_as_bytebuf(rd)?,
                b"w" => s.signed_weight = rmp_decode::read_u64(rd)?,
                b"S" => {
                    s.sig_proofs = rmp_decode::read_optional(rd, MerkleProof::decode_from_reader)?
                }
                b"P" => {
                    s.part_proofs = rmp_decode::read_optional(rd, MerkleProof::decode_from_reader)?
                }
                b"v" => s.merkle_signature_salt_version = rmp_decode::read_u8_val(rd)?,
                b"r" => {
                    if rmp_decode::try_read_nil(rd) {
                        s.reveals = None;
                    } else {
                        s.reveals = Some(rmp_decode::read_u64_map(rd, Reveal::decode_from_reader)?);
                    }
                }
                b"pr" => {
                    s.positions_to_reveal = rmp_decode::read_optional_vec(rd, rmp_decode::read_u64)?
                }
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl StateProofMessage {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"b" => s.block_headers_commitment = rmp_decode::read_bytes_as_bytebuf(rd)?,
                b"v" => s.voters_commitment = rmp_decode::read_bytes_as_bytebuf(rd)?,
                b"P" => s.ln_proven_weight = rmp_decode::read_u64(rd)?,
                b"f" => s.first_attested_round = rmp_decode::read_u64(rd)?,
                b"l" => s.last_attested_round = rmp_decode::read_u64(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl HoldingRef {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"d" => s.address = rmp_decode::read_u64(rd)?,
                b"s" => s.asset = rmp_decode::read_u64(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl LocalsRef {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"d" => s.address = rmp_decode::read_u64(rd)?,
                b"p" => s.app = rmp_decode::read_u64(rd)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

impl ResourceRef {
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        for _ in 0..len {
            match rmp_decode::read_key_bytes(rd)? {
                b"d" => s.address = rmp_decode::read_address(rd)?,
                b"s" => s.asset = rmp_decode::read_u64(rd)?,
                b"p" => s.app = rmp_decode::read_u64(rd)?,
                b"h" => s.holding = rmp_decode::read_optional(rd, HoldingRef::decode_from_reader)?,
                b"l" => s.locals = rmp_decode::read_optional(rd, LocalsRef::decode_from_reader)?,
                b"b" => s.box_ref = rmp_decode::read_optional(rd, BoxRef::decode_from_reader)?,
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        Ok(s)
    }

    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

// ── Transaction address matching ────────────────────────────────

impl Transaction {
    /// Return `true` when `addr` is involved in this transaction.
    ///
    /// Mirrors go-algorand's `Transaction.MatchAddress` — checks sender
    /// and, depending on the transaction type, receiver / close-to /
    /// asset-receiver / asset-close-to / asset-sender / heartbeat address.
    ///
    /// NOTE: go-algorand does *not* check `freeze_account` and neither
    /// do we.
    pub fn match_address(&self, addr: &Address) -> bool {
        // Sender always matches.
        if *addr == self.sender {
            return true;
        }

        match self.txn_type {
            TxnType::Pay => {
                if *addr == self.receiver {
                    return true;
                }
                if !self.close_remainder_to.is_zero() && *addr == self.close_remainder_to {
                    return true;
                }
            }
            TxnType::Axfer => {
                if let Some(ref a) = self.asset_receiver {
                    if a == addr {
                        return true;
                    }
                }
                if let Some(ref a) = self.asset_close_to {
                    if !a.is_zero() && a == addr {
                        return true;
                    }
                }
                if let Some(ref a) = self.asset_sender {
                    if !a.is_zero() && a == addr {
                        return true;
                    }
                }
            }
            TxnType::Hb => {
                if let Some(ref hb) = self.heartbeat {
                    if *addr == hb.address {
                        return true;
                    }
                }
            }
            _ => {}
        }

        false
    }
}

// ── Transaction decoder ────────────────────────────────────────

impl Transaction {
    /// Decode a Transaction from a msgpack map using raw rmp.
    ///
    /// Uses two-level key dispatch: (key_len, first_byte) for O(1) routing
    /// instead of linear byte-slice comparison across all 49 fields.
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut t = Self::default();
        for _ in 0..len {
            let key = rmp_decode::read_key_bytes(rd)?;
            match (key.len(), key.first().copied().unwrap_or(0)) {
                // ── 2-byte keys ──────────────────────────────────
                (2, b'a') if key == b"al" => {
                    t.access = rmp_decode::read_optional_vec(rd, ResourceRef::decode_from_reader)?
                }
                (2, b'f') if key == b"fv" => t.first_valid = Round(rmp_decode::read_u64(rd)?),
                (2, b'g') if key == b"gh" => {
                    t.genesis_hash = rmp_decode::read_fixed_bytes::<32>(rd)?
                }
                (2, b'h') if key == b"hb" => {
                    t.heartbeat =
                        rmp_decode::read_optional(rd, HeartbeatTxnFields::decode_from_reader)?
                }
                (2, b'l') if key == b"lv" => t.last_valid = Round(rmp_decode::read_u64(rd)?),
                (2, b'l') if key == b"lx" => t.lease = rmp_decode::read_fixed_bytes::<32>(rd)?,
                (2, b's') if key == b"sp" => {
                    t.state_proof =
                        rmp_decode::read_optional(rd, StateProofBody::decode_from_reader)?
                }
                // ── 3-byte keys ──────────────────────────────────
                (3, b'a') if key == b"amt" => t.amount = rmp_decode::read_u64(rd)?,
                (3, b'f') if key == b"fee" => t.fee = rmp_decode::read_u64(rd)?,
                (3, b'g') if key == b"gen" => t.genesis_id = rmp_decode::read_string(rd)?,
                (3, b'g') if key == b"grp" => t.group = rmp_decode::read_fixed_bytes::<32>(rd)?,
                (3, b'r') if key == b"rcv" => t.receiver = rmp_decode::read_address(rd)?,
                (3, b's') if key == b"snd" => t.sender = rmp_decode::read_address(rd)?,
                // ── 4-byte keys ──────────────────────────────────
                (4, b'a') => match key {
                    b"aamt" => t.asset_amount = rmp_decode::read_u64(rd)?,
                    b"afrz" => t.asset_frozen = rmp_decode::read_bool(rd)?,
                    b"apaa" => {
                        t.app_arguments = rmp_decode::read_optional_vec(rd, read_optional_bytebuf)?
                    }
                    b"apan" => t.on_completion = rmp_decode::read_u64(rd)?,
                    b"apap" => {
                        t.approval_program =
                            rmp_decode::read_optional(rd, rmp_decode::read_bytes_as_bytebuf)?
                    }
                    b"apar" => {
                        t.asset_params =
                            rmp_decode::read_optional(rd, AssetParams::decode_from_reader)?
                    }
                    b"apas" => {
                        t.foreign_assets = rmp_decode::read_optional_vec(rd, rmp_decode::read_u64)?
                    }
                    b"apat" => {
                        t.accounts = rmp_decode::read_optional_vec(rd, rmp_decode::read_address)?
                    }
                    b"apbx" => {
                        t.boxes = rmp_decode::read_optional_vec(rd, BoxRef::decode_from_reader)?
                    }
                    b"apep" => t.extra_program_pages = rmp_decode::read_u32(rd)?,
                    b"apfa" => {
                        t.foreign_apps = rmp_decode::read_optional_vec(rd, rmp_decode::read_u64)?
                    }
                    b"apgs" => {
                        t.global_state_schema =
                            rmp_decode::read_optional(rd, StateSchema::decode_from_reader)?
                    }
                    b"apid" => t.application_id = rmp_decode::read_u64(rd)?,
                    b"apls" => {
                        t.local_state_schema =
                            rmp_decode::read_optional(rd, StateSchema::decode_from_reader)?
                    }
                    b"aprv" => t.reject_version = rmp_decode::read_u64(rd)?,
                    b"apsu" => {
                        t.clear_state_program =
                            rmp_decode::read_optional(rd, rmp_decode::read_bytes_as_bytebuf)?
                    }
                    b"arcv" => {
                        t.asset_receiver = rmp_decode::read_optional(rd, rmp_decode::read_address)?
                    }
                    b"asnd" => {
                        t.asset_sender = rmp_decode::read_optional(rd, rmp_decode::read_address)?
                    }
                    _ => rmp_decode::skip_value(rd)?,
                },
                (4, b'c') if key == b"caid" => t.config_asset = rmp_decode::read_u64(rd)?,
                (4, b'f') if key == b"fadd" => {
                    t.freeze_account = rmp_decode::read_optional(rd, rmp_decode::read_address)?
                }
                (4, b'f') if key == b"faid" => t.freeze_asset = rmp_decode::read_u64(rd)?,
                (4, b'n') if key == b"note" => t.note = rmp_decode::read_bytes_as_bytebuf(rd)?,
                (4, b't') if key == b"type" => {
                    t.txn_type = TxnType::from(rmp_decode::read_string(rd)?)
                }
                (4, b'x') if key == b"xaid" => t.xaid = rmp_decode::read_u64(rd)?,
                // ── 5-byte keys ──────────────────────────────────
                (5, b'c') if key == b"close" => {
                    t.close_remainder_to = rmp_decode::read_address(rd)?
                }
                (5, b'r') if key == b"rekey" => {
                    t.rekey_to = rmp_decode::read_optional(rd, rmp_decode::read_address)?
                }
                (5, b's') if key == b"spmsg" => {
                    t.state_proof_message =
                        rmp_decode::read_optional(rd, StateProofMessage::decode_from_reader)?
                }
                // ── 6-byte keys ──────────────────────────────────
                (6, b'a') if key == b"aclose" => {
                    t.asset_close_to = rmp_decode::read_optional(rd, rmp_decode::read_address)?
                }
                (6, b's') if key == b"selkey" => {
                    t.selection_pk =
                        rmp_decode::read_optional(rd, rmp_decode::read_fixed_bytes::<32>)?
                }
                (6, b's') if key == b"sptype" => t.state_proof_type = rmp_decode::read_u64(rd)?,
                (6, b'v') if key == b"votekd" => t.vote_key_dilution = rmp_decode::read_u64(rd)?,
                // ── 7-byte keys ──────────────────────────────────
                (7, b'n') if key == b"nonpart" => t.non_participation = rmp_decode::read_bool(rd)?,
                (7, b's') if key == b"sprfkey" => {
                    t.state_proof_pk =
                        rmp_decode::read_optional(rd, rmp_decode::read_fixed_bytes::<64>)?
                }
                (7, b'v') => match key {
                    b"votefst" => t.vote_first = rmp_decode::read_u64(rd)?,
                    b"votekey" => {
                        t.vote_pk =
                            rmp_decode::read_optional(rd, rmp_decode::read_fixed_bytes::<32>)?
                    }
                    b"votelst" => t.vote_last = rmp_decode::read_u64(rd)?,
                    _ => rmp_decode::skip_value(rd)?,
                },
                // Unknown fields are skipped
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        // go-algorand v4.7.2-stable marks `type`/`snd` `codec:",required"`: the generated
        // decoder rejects the field's zero value regardless of whether the key was present
        // on the wire (`Type.MsgIsZero()` / `Sender.MsgIsZero()`), not merely its absence.
        // A value check (rather than an on-key-seen presence flag) catches an explicit
        // zero-valued "type"/"snd" too, not just an omitted key.
        if t.txn_type.is_empty() {
            return Err(algo_error::AlgoError::Codec {
                source: "missing required field 'type'".into(),
                context: "rmp_decode".into(),
            });
        }
        if t.sender.is_zero() {
            return Err(algo_error::AlgoError::Codec {
                source: "missing required field 'snd'".into(),
                context: "rmp_decode".into(),
            });
        }
        Ok(t)
    }

    /// Decode a Transaction from msgpack bytes.
    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

// ── SignedTransaction decoder ──────────────────────────────────

impl SignedTransaction {
    /// Decode a SignedTransaction (SignedTxnInBlock) from a msgpack map using raw rmp.
    ///
    /// Uses two-level key dispatch: (key_len, first_byte) for fast routing.
    pub fn decode_from_reader(rd: &mut &[u8]) -> DecodeResult<Self> {
        let len = rmp_decode::read_map_len(rd)?;
        let mut s = Self::default();
        let mut has_txn = false;
        for _ in 0..len {
            let key = rmp_decode::read_key_bytes(rd)?;
            match (key.len(), key.first().copied().unwrap_or(0)) {
                (2, b'c') if key == b"ca" => s.closing_amount = rmp_decode::read_u64(rd)?,
                (2, b'd') if key == b"dt" => s.eval_delta = rmp_decode::read_optional_rmpv(rd)?,
                (2, b'r') => match key {
                    b"rs" => s.sender_rewards = rmp_decode::read_u64(rd)?,
                    b"rr" => s.receiver_rewards = rmp_decode::read_u64(rd)?,
                    b"rc" => s.close_rewards = rmp_decode::read_u64(rd)?,
                    _ => rmp_decode::skip_value(rd)?,
                },
                (3, b'a') if key == b"aca" => s.asset_closing_amount = rmp_decode::read_u64(rd)?,
                (3, b'h') => match key {
                    b"hgi" => s.has_genesis_id = rmp_decode::read_bool(rd)?,
                    b"hgh" => s.has_genesis_hash = rmp_decode::read_bool(rd)?,
                    _ => rmp_decode::skip_value(rd)?,
                },
                (3, b's') if key == b"sig" => s.sig = rmp_decode::read_fixed_bytes::<64>(rd)?,
                (3, b't') if key == b"txn" => {
                    s.txn = Transaction::decode_from_reader(rd)?;
                    has_txn = true;
                }
                (4, b'a') if key == b"apid" => {
                    s.apply_data_application_id = rmp_decode::read_u64(rd)?
                }
                (4, b'c') if key == b"caid" => {
                    s.apply_data_config_asset = rmp_decode::read_u64(rd)?
                }
                (4, b'l') if key == b"lsig" => {
                    s.lsig = rmp_decode::read_optional(rd, LogicSig::decode_from_reader)?
                }
                (4, b'm') if key == b"msig" => {
                    s.msig = rmp_decode::read_optional(rd, MultisigSig::decode_from_reader)?
                }
                (4, b's') if key == b"sgnr" => {
                    s.auth_addr = rmp_decode::read_optional(rd, rmp_decode::read_address)?
                }
                _ => rmp_decode::skip_value(rd)?,
            }
        }
        // The serde path requires `txn` (no #[serde(default)]), so validate here.
        if !has_txn {
            return Err(algo_error::AlgoError::Codec {
                source: "SignedTransaction: missing required 'txn' field".into(),
                context: "rmp_decode".into(),
            });
        }
        Ok(s)
    }

    /// Decode a SignedTransaction from msgpack bytes.
    pub fn decode_from_bytes(data: &[u8]) -> DecodeResult<Self> {
        let mut rd = data;
        Self::decode_from_reader(&mut rd)
    }
}

// ── go-algorand v4.7.2-stable required-field decode-rejection tests ────
//
// go-algorand's `codec:",required"` struct tags reject a decode when the
// field's *decoded value* is zero, regardless of whether the msgpack key
// was present on the wire (the generated code checks `Field.MsgIsZero()`
// unconditionally after the decode loop). These tests build minimal
// hand-rolled msgpack maps — both with the required key omitted and with
// it explicitly present-but-zero-valued — covering both of the two ways
// go-algorand's real decoder rejects a malformed encoding.
#[cfg(test)]
mod required_field_decode_tests {
    use super::*;

    fn write_map_len(buf: &mut Vec<u8>, len: u32) {
        rmp::encode::write_map_len(buf, len).unwrap();
    }

    fn write_str_kv(buf: &mut Vec<u8>, key: &str, val: &str) {
        rmp::encode::write_str(buf, key).unwrap();
        rmp::encode::write_str(buf, val).unwrap();
    }

    fn write_bin_kv(buf: &mut Vec<u8>, key: &str, val: &[u8]) {
        rmp::encode::write_str(buf, key).unwrap();
        rmp::encode::write_bin(buf, val).unwrap();
    }

    fn write_uint_kv(buf: &mut Vec<u8>, key: &str, val: u64) {
        rmp::encode::write_str(buf, key).unwrap();
        rmp::encode::write_uint(buf, val).unwrap();
    }

    /// `AlgoError::Codec`'s `Display` only renders `context` ("rmp_decode");
    /// the descriptive "missing required field '...'" text lives in `source`.
    fn err_message(err: &algo_error::AlgoError) -> String {
        std::error::Error::source(err)
            .map(|s| s.to_string())
            .unwrap_or_default()
    }

    // ── Transaction.Type / Header.Sender (Transaction::decode_from_reader) ──

    #[test]
    fn transaction_type_omitted_is_rejected() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 1);
        write_bin_kv(&mut buf, "snd", &[7u8; 32]);
        let mut rd: &[u8] = &buf;
        let err = Transaction::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("type"), "got: {err}");
    }

    #[test]
    fn transaction_type_explicit_empty_string_is_rejected() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 2);
        write_str_kv(&mut buf, "type", "");
        write_bin_kv(&mut buf, "snd", &[7u8; 32]);
        let mut rd: &[u8] = &buf;
        let err = Transaction::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("type"), "got: {err}");
    }

    #[test]
    fn transaction_sender_omitted_is_rejected() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 1);
        write_str_kv(&mut buf, "type", "pay");
        let mut rd: &[u8] = &buf;
        let err = Transaction::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("snd"), "got: {err}");
    }

    #[test]
    fn transaction_sender_explicit_zero_is_rejected() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 2);
        write_str_kv(&mut buf, "type", "pay");
        write_bin_kv(&mut buf, "snd", &[0u8; 32]);
        let mut rd: &[u8] = &buf;
        let err = Transaction::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("snd"), "got: {err}");
    }

    #[test]
    fn transaction_with_type_and_sender_present_decodes_successfully() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 2);
        write_str_kv(&mut buf, "type", "pay");
        write_bin_kv(&mut buf, "snd", &[7u8; 32]);
        let mut rd: &[u8] = &buf;
        let t = Transaction::decode_from_reader(&mut rd).unwrap();
        assert_eq!(t.txn_type, TxnType::Pay);
        assert_eq!(t.sender, Address([7u8; 32]));
    }

    // ── MultisigSig.{Version,Threshold,Subsigs} (MultisigSig::decode_from_reader) ──

    fn encode_multisig(version: Option<u8>, threshold: Option<u8>, with_subsig: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        let n = version.is_some() as u32 + threshold.is_some() as u32 + with_subsig as u32;
        write_map_len(&mut buf, n);
        if let Some(v) = version {
            write_uint_kv(&mut buf, "v", v as u64);
        }
        if let Some(t) = threshold {
            write_uint_kv(&mut buf, "thr", t as u64);
        }
        if with_subsig {
            rmp::encode::write_str(&mut buf, "subsig").unwrap();
            rmp::encode::write_array_len(&mut buf, 1).unwrap();
            // One MultisigSubsig: {"pk": <32 bytes>}.
            write_map_len(&mut buf, 1);
            write_bin_kv(&mut buf, "pk", &[9u8; 32]);
        }
        buf
    }

    #[test]
    fn multisig_version_omitted_is_rejected() {
        let buf = encode_multisig(None, Some(1), true);
        let mut rd: &[u8] = &buf;
        let err = MultisigSig::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("'v'"), "got: {err}");
    }

    #[test]
    fn multisig_version_explicit_zero_is_rejected() {
        let buf = encode_multisig(Some(0), Some(1), true);
        let mut rd: &[u8] = &buf;
        let err = MultisigSig::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("'v'"), "got: {err}");
    }

    #[test]
    fn multisig_threshold_omitted_is_rejected() {
        let buf = encode_multisig(Some(1), None, true);
        let mut rd: &[u8] = &buf;
        let err = MultisigSig::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("'thr'"), "got: {err}");
    }

    #[test]
    fn multisig_subsig_omitted_is_rejected() {
        let buf = encode_multisig(Some(1), Some(1), false);
        let mut rd: &[u8] = &buf;
        let err = MultisigSig::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("'subsig'"), "got: {err}");
    }

    #[test]
    fn multisig_with_all_required_fields_decodes_successfully() {
        let buf = encode_multisig(Some(1), Some(1), true);
        let mut rd: &[u8] = &buf;
        let s = MultisigSig::decode_from_reader(&mut rd).unwrap();
        assert_eq!(s.version, 1);
        assert_eq!(s.threshold, 1);
        assert_eq!(s.subsigs.len(), 1);
    }

    // ── stateproof.Reveal.Part / basics.Participant.PK ──

    fn encode_verifier() -> Vec<u8> {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 1);
        write_bin_kv(&mut buf, "cmt", &[3u8; 64]);
        buf
    }

    #[test]
    fn participant_pk_omitted_is_rejected() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 1);
        write_uint_kv(&mut buf, "w", 5);
        let mut rd: &[u8] = &buf;
        let err = Participant::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("'p'"), "got: {err}");
    }

    #[test]
    fn participant_pk_explicit_zero_verifier_is_rejected() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 1);
        rmp::encode::write_str(&mut buf, "p").unwrap();
        write_map_len(&mut buf, 0); // empty verifier map -> all-zero Verifier
        let mut rd: &[u8] = &buf;
        let err = Participant::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("'p'"), "got: {err}");
    }

    #[test]
    fn participant_with_pk_decodes_successfully() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 1);
        rmp::encode::write_str(&mut buf, "p").unwrap();
        buf.extend(encode_verifier());
        let mut rd: &[u8] = &buf;
        let p = Participant::decode_from_reader(&mut rd).unwrap();
        assert!(p.pk.is_some());
    }

    #[test]
    fn reveal_part_omitted_is_rejected() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 0);
        let mut rd: &[u8] = &buf;
        let err = Reveal::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("'p'"), "got: {err}");
    }

    #[test]
    fn reveal_part_with_zero_pk_is_rejected() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 1);
        rmp::encode::write_str(&mut buf, "p").unwrap();
        // Participant map with pk omitted -> Participant::decode_from_reader itself errors.
        write_map_len(&mut buf, 1);
        write_uint_kv(&mut buf, "w", 1);
        let mut rd: &[u8] = &buf;
        let err = Reveal::decode_from_reader(&mut rd).unwrap_err();
        assert!(err_message(&err).contains("'p'"), "got: {err}");
    }

    #[test]
    fn reveal_with_part_decodes_successfully() {
        let mut buf = Vec::new();
        write_map_len(&mut buf, 1);
        rmp::encode::write_str(&mut buf, "p").unwrap();
        write_map_len(&mut buf, 1);
        rmp::encode::write_str(&mut buf, "p").unwrap();
        buf.extend(encode_verifier());
        let mut rd: &[u8] = &buf;
        let r = Reveal::decode_from_reader(&mut rd).unwrap();
        assert!(r.part.is_some());
    }
}
