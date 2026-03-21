//! Field enums for AVM opcodes that use an immediate byte to select a field.
//!
//! Each enum maps the immediate byte index to a named field, matching
//! go-algorand's field numbering exactly.

use algo_error::AlgoError;

// ---------------------------------------------------------------------------
// Helper macro to reduce boilerplate for `from_u8` implementations.
// ---------------------------------------------------------------------------

macro_rules! field_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $Name:ident {
            $( $(#[$vmeta:meta])* $Variant:ident = $val:expr ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis enum $Name {
            $( $(#[$vmeta])* $Variant = $val ),+
        }

        impl $Name {
            /// Decode the immediate byte into this field enum.
            pub fn from_u8(v: u8) -> Result<Self, AlgoError> {
                match v {
                    $( $val => Ok(Self::$Variant), )+
                    _ => Err(AlgoError::Avm {
                        message: format!(
                            "invalid {} field index: {}",
                            stringify!($Name),
                            v,
                        ),
                    }),
                }
            }
        }
    };
}

// ---------------------------------------------------------------------------
// GlobalField — `global` opcode (0x32)
// ---------------------------------------------------------------------------

field_enum! {
    /// Fields available via the `global` opcode.
    pub enum GlobalField {
        MinTxnFee = 0,
        MinBalance = 1,
        MaxTxnLife = 2,
        ZeroAddress = 3,
        GroupSize = 4,
        LogicSigVersion = 5,
        Round = 6,
        LatestTimestamp = 7,
        CurrentApplicationID = 8,
        CreatorAddress = 9,
        CurrentApplicationAddress = 10,
        GroupID = 11,
        OpcodeBudget = 12,
        CallerApplicationID = 13,
        CallerApplicationAddress = 14,
        AssetCreateMinBalance = 15,
        AssetOptInMinBalance = 16,
        GenesisHash = 17,
        PayoutsEnabled = 18,
        PayoutsGoOnlineFee = 19,
        PayoutsPercent = 20,
        PayoutsMinBalance = 21,
        PayoutsMaxBalance = 22,
    }
}

// ---------------------------------------------------------------------------
// TxnField — `txn`/`gtxn`/`txna`/`gtxna`/`gtxns`/`gtxnsa`/`itxn`/`itxn_field`
//             opcodes (0x31, 0x33, 0x36, 0x37, 0x38, 0x39, 0xb2, 0xb4, etc.)
// ---------------------------------------------------------------------------

field_enum! {
    /// Fields available via transaction access opcodes (`txn`, `gtxn`, `itxn`, etc.).
    ///
    /// Inner transaction fields (`itxn`, `itxn_field`, `gitxn`) reuse the same
    /// indices, so there is no separate `ItxnField` enum.
    pub enum TxnField {
        Sender = 0,
        Fee = 1,
        FirstValid = 2,
        /// Timestamp of block(FirstValid-1). AVM v7+.
        FirstValidTime = 3,
        LastValid = 4,
        Note = 5,
        Lease = 6,
        Receiver = 7,
        Amount = 8,
        CloseRemainderTo = 9,
        VotePK = 10,
        SelectionPK = 11,
        VoteFirst = 12,
        VoteLast = 13,
        VoteKeyDilution = 14,
        Type = 15,
        TypeEnum = 16,
        XferAsset = 17,
        AssetAmount = 18,
        AssetSender = 19,
        AssetReceiver = 20,
        AssetCloseTo = 21,
        GroupIndex = 22,
        TxID = 23,
        ApplicationID = 24,
        OnCompletion = 25,
        ApplicationArgs = 26,
        NumAppArgs = 27,
        Accounts = 28,
        NumAccounts = 29,
        ApprovalProgram = 30,
        ClearStateProgram = 31,
        RekeyTo = 32,
        ConfigAsset = 33,
        ConfigAssetTotal = 34,
        ConfigAssetDecimals = 35,
        ConfigAssetDefaultFrozen = 36,
        ConfigAssetUnitName = 37,
        ConfigAssetName = 38,
        ConfigAssetURL = 39,
        ConfigAssetMetadataHash = 40,
        ConfigAssetManager = 41,
        ConfigAssetReserve = 42,
        ConfigAssetFreeze = 43,
        ConfigAssetClawback = 44,
        FreezeAsset = 45,
        FreezeAssetAccount = 46,
        FreezeAssetFrozen = 47,
        Assets = 48,
        NumAssets = 49,
        Applications = 50,
        NumApplications = 51,
        GlobalNumUint = 52,
        GlobalNumByteSlice = 53,
        LocalNumUint = 54,
        LocalNumByteSlice = 55,
        ExtraProgramPages = 56,
        Nonparticipation = 57,
        Logs = 58,
        NumLogs = 59,
        CreatedAssetID = 60,
        CreatedApplicationID = 61,
        LastLog = 62,
        StateProofPK = 63,
        ApprovalProgramPages = 64,
        NumApprovalProgramPages = 65,
        ClearStateProgramPages = 66,
        NumClearStateProgramPages = 67,
        /// Application version for which the txn must reject. AVM v12+.
        RejectVersion = 68,
    }
}

// ---------------------------------------------------------------------------
// AssetHoldingField — `asset_holding_get` opcode (0x70)
// ---------------------------------------------------------------------------

field_enum! {
    /// Fields available via the `asset_holding_get` opcode.
    pub enum AssetHoldingField {
        AssetBalance = 0,
        AssetFrozen = 1,
    }
}

// ---------------------------------------------------------------------------
// AssetParamsField — `asset_params_get` opcode (0x71)
// ---------------------------------------------------------------------------

field_enum! {
    /// Fields available via the `asset_params_get` opcode.
    pub enum AssetParamsField {
        AssetTotal = 0,
        AssetDecimals = 1,
        AssetDefaultFrozen = 2,
        AssetUnitName = 3,
        AssetName = 4,
        AssetURL = 5,
        AssetMetadataHash = 6,
        AssetManager = 7,
        AssetReserve = 8,
        AssetFreeze = 9,
        AssetClawback = 10,
        AssetCreator = 11,
    }
}

// ---------------------------------------------------------------------------
// AppParamsField — `app_params_get` opcode (0x72)
// ---------------------------------------------------------------------------

field_enum! {
    /// Fields available via the `app_params_get` opcode.
    pub enum AppParamsField {
        AppApprovalProgram = 0,
        AppClearStateProgram = 1,
        AppGlobalNumUint = 2,
        AppGlobalNumByteSlice = 3,
        AppLocalNumUint = 4,
        AppLocalNumByteSlice = 5,
        AppExtraProgramPages = 6,
        AppCreator = 7,
        AppAddress = 8,
    }
}

// ---------------------------------------------------------------------------
// AcctParamsField — `acct_params_get` opcode (0x73)
// ---------------------------------------------------------------------------

field_enum! {
    /// Fields available via the `acct_params_get` opcode.
    pub enum AcctParamsField {
        AcctBalance = 0,
        AcctMinBalance = 1,
        AcctAuthAddr = 2,
        AcctTotalNumUint = 3,
        AcctTotalNumByteSlice = 4,
        AcctTotalExtraAppPages = 5,
        AcctTotalAppsCreated = 6,
        AcctTotalAppsOptedIn = 7,
        AcctTotalAssetsCreated = 8,
        AcctTotalAssets = 9,
        AcctTotalBoxes = 10,
        AcctTotalBoxBytes = 11,
        AcctIncentiveEligible = 12,
        AcctLastProposed = 13,
        AcctLastHeartbeat = 14,
    }
}

// ---------------------------------------------------------------------------
// TxnField — Display and itx_version helpers (matching go-algorand exactly)
// ---------------------------------------------------------------------------

impl std::fmt::Display for TxnField {
    /// Returns the go-algorand field name string for known fields,
    /// or `"TxnField(N)"` for unknown indices (matching Go's stringer output).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Sender => "Sender",
            Self::Fee => "Fee",
            Self::FirstValid => "FirstValid",
            Self::FirstValidTime => "FirstValidTime",
            Self::LastValid => "LastValid",
            Self::Note => "Note",
            Self::Lease => "Lease",
            Self::Receiver => "Receiver",
            Self::Amount => "Amount",
            Self::CloseRemainderTo => "CloseRemainderTo",
            Self::VotePK => "VotePK",
            Self::SelectionPK => "SelectionPK",
            Self::VoteFirst => "VoteFirst",
            Self::VoteLast => "VoteLast",
            Self::VoteKeyDilution => "VoteKeyDilution",
            Self::Type => "Type",
            Self::TypeEnum => "TypeEnum",
            Self::XferAsset => "XferAsset",
            Self::AssetAmount => "AssetAmount",
            Self::AssetSender => "AssetSender",
            Self::AssetReceiver => "AssetReceiver",
            Self::AssetCloseTo => "AssetCloseTo",
            Self::GroupIndex => "GroupIndex",
            Self::TxID => "TxID",
            Self::ApplicationID => "ApplicationID",
            Self::OnCompletion => "OnCompletion",
            Self::ApplicationArgs => "ApplicationArgs",
            Self::NumAppArgs => "NumAppArgs",
            Self::Accounts => "Accounts",
            Self::NumAccounts => "NumAccounts",
            Self::ApprovalProgram => "ApprovalProgram",
            Self::ClearStateProgram => "ClearStateProgram",
            Self::RekeyTo => "RekeyTo",
            Self::ConfigAsset => "ConfigAsset",
            Self::ConfigAssetTotal => "ConfigAssetTotal",
            Self::ConfigAssetDecimals => "ConfigAssetDecimals",
            Self::ConfigAssetDefaultFrozen => "ConfigAssetDefaultFrozen",
            Self::ConfigAssetUnitName => "ConfigAssetUnitName",
            Self::ConfigAssetName => "ConfigAssetName",
            Self::ConfigAssetURL => "ConfigAssetURL",
            Self::ConfigAssetMetadataHash => "ConfigAssetMetadataHash",
            Self::ConfigAssetManager => "ConfigAssetManager",
            Self::ConfigAssetReserve => "ConfigAssetReserve",
            Self::ConfigAssetFreeze => "ConfigAssetFreeze",
            Self::ConfigAssetClawback => "ConfigAssetClawback",
            Self::FreezeAsset => "FreezeAsset",
            Self::FreezeAssetAccount => "FreezeAssetAccount",
            Self::FreezeAssetFrozen => "FreezeAssetFrozen",
            Self::Assets => "Assets",
            Self::NumAssets => "NumAssets",
            Self::Applications => "Applications",
            Self::NumApplications => "NumApplications",
            Self::GlobalNumUint => "GlobalNumUint",
            Self::GlobalNumByteSlice => "GlobalNumByteSlice",
            Self::LocalNumUint => "LocalNumUint",
            Self::LocalNumByteSlice => "LocalNumByteSlice",
            Self::ExtraProgramPages => "ExtraProgramPages",
            Self::Nonparticipation => "Nonparticipation",
            Self::Logs => "Logs",
            Self::NumLogs => "NumLogs",
            Self::CreatedAssetID => "CreatedAssetID",
            Self::CreatedApplicationID => "CreatedApplicationID",
            Self::LastLog => "LastLog",
            Self::StateProofPK => "StateProofPK",
            Self::ApprovalProgramPages => "ApprovalProgramPages",
            Self::NumApprovalProgramPages => "NumApprovalProgramPages",
            Self::ClearStateProgramPages => "ClearStateProgramPages",
            Self::NumClearStateProgramPages => "NumClearStateProgramPages",
            Self::RejectVersion => "RejectVersion",
        };
        write!(f, "{}", name)
    }
}

impl TxnField {
    /// Returns the AVM version in which this field became settable via
    /// `itxn_field`. Returns 0 if the field can never be set in an inner
    /// transaction. Values match go-algorand's `txnFieldSpecs[].itxVersion`.
    pub fn itx_version(&self) -> u8 {
        match self {
            // itxVersion from go-algorand txnFieldSpecs (fields.go)
            Self::Sender => 5,
            Self::Fee => 5,
            Self::FirstValid => 0,     // not settable
            Self::FirstValidTime => 0, // not settable
            Self::LastValid => 0,      // not settable
            Self::Note => 6,
            Self::Lease => 0, // not settable
            Self::Receiver => 5,
            Self::Amount => 5,
            Self::CloseRemainderTo => 5,
            Self::VotePK => 6,
            Self::SelectionPK => 6,
            Self::VoteFirst => 6,
            Self::VoteLast => 6,
            Self::VoteKeyDilution => 6,
            Self::Type => 5,
            Self::TypeEnum => 5,
            Self::XferAsset => 5,
            Self::AssetAmount => 5,
            Self::AssetSender => 5,
            Self::AssetReceiver => 5,
            Self::AssetCloseTo => 5,
            Self::GroupIndex => 0, // not settable
            Self::TxID => 0,       // not settable
            Self::ApplicationID => 6,
            Self::OnCompletion => 6,
            Self::ApplicationArgs => 6,
            Self::NumAppArgs => 0, // not settable (read-only)
            Self::Accounts => 6,
            Self::NumAccounts => 0, // not settable (read-only)
            Self::ApprovalProgram => 6,
            Self::ClearStateProgram => 6,
            Self::RekeyTo => 6,
            Self::ConfigAsset => 5,
            Self::ConfigAssetTotal => 5,
            Self::ConfigAssetDecimals => 5,
            Self::ConfigAssetDefaultFrozen => 5,
            Self::ConfigAssetUnitName => 5,
            Self::ConfigAssetName => 5,
            Self::ConfigAssetURL => 5,
            Self::ConfigAssetMetadataHash => 5,
            Self::ConfigAssetManager => 5,
            Self::ConfigAssetReserve => 5,
            Self::ConfigAssetFreeze => 5,
            Self::ConfigAssetClawback => 5,
            Self::FreezeAsset => 5,
            Self::FreezeAssetAccount => 5,
            Self::FreezeAssetFrozen => 5,
            Self::Assets => 6,
            Self::NumAssets => 0, // not settable (read-only)
            Self::Applications => 6,
            Self::NumApplications => 0, // not settable (read-only)
            Self::GlobalNumUint => 6,
            Self::GlobalNumByteSlice => 6,
            Self::LocalNumUint => 6,
            Self::LocalNumByteSlice => 6,
            Self::ExtraProgramPages => 6,
            Self::Nonparticipation => 6,
            // Effects — not settable
            Self::Logs => 0,
            Self::NumLogs => 0,
            Self::CreatedAssetID => 0,
            Self::CreatedApplicationID => 0,
            Self::LastLog => 0,
            // Non-effect, but settable
            Self::StateProofPK => 6,
            // Pages — settable from v7
            Self::ApprovalProgramPages => 7,
            Self::NumApprovalProgramPages => 0, // read-only
            Self::ClearStateProgramPages => 7,
            Self::NumClearStateProgramPages => 0, // read-only
            Self::RejectVersion => 12,
        }
    }

    /// Format an unknown field index the same way Go's stringer does:
    /// `"TxnField(N)"`.
    pub fn unknown_display(index: u8) -> String {
        format!("TxnField({})", index)
    }
}

/// Inner transaction fields use the same field indices as regular transaction
/// fields. Use [`TxnField`] for `itxn`, `itxn_field`, `gitxn`, etc.
pub type ItxnField = TxnField;

// ---------------------------------------------------------------------------
// EcdsaCurve — `ecdsa_verify`, `ecdsa_pk_decompress`, `ecdsa_pk_recover`
// ---------------------------------------------------------------------------

field_enum! {
    /// Curves available for the `ecdsa_*` opcodes.
    pub enum EcdsaCurve {
        /// secp256k1 curve, used in Bitcoin.
        Secp256k1 = 0,
        /// secp256r1 curve, NIST standard (FIDO).
        Secp256r1 = 1,
    }
}

// ---------------------------------------------------------------------------
// EcGroup — `ec_add`, `ec_scalar_mul`, `ec_pairing_check`, etc.
// ---------------------------------------------------------------------------

field_enum! {
    /// Elliptic curve groups for the `ec_*` opcodes.
    pub enum EcGroup {
        /// G1 of the BN254 curve.
        BN254g1 = 0,
        /// G2 of the BN254 curve.
        BN254g2 = 1,
        /// G1 of the BLS 12-381 curve.
        BLS12_381g1 = 2,
        /// G2 of the BLS 12-381 curve.
        BLS12_381g2 = 3,
    }
}

// ---------------------------------------------------------------------------
// MimcConfig — `mimc` opcode (0xe6)
// ---------------------------------------------------------------------------

field_enum! {
    /// MiMC hash configuration for the `mimc` opcode.
    pub enum MimcConfig {
        /// MiMC configuration for BN254, Miyaguchi-Preneel mode, 110 rounds.
        BN254Mp110 = 0,
        /// MiMC configuration for BLS12-381, Miyaguchi-Preneel mode, 111 rounds.
        BLS12_381Mp111 = 1,
    }
}

// ---------------------------------------------------------------------------
// Base64Encoding — `base64_decode` opcode (0x5e)
// ---------------------------------------------------------------------------

field_enum! {
    /// Encoding variants for the `base64_decode` opcode.
    pub enum Base64Encoding {
        /// base64url encoding (RFC 4648).
        URLEncoding = 0,
        /// Standard base64 encoding (RFC 4648).
        StdEncoding = 1,
    }
}

// ---------------------------------------------------------------------------
// JSONRefType — `json_ref` opcode (0x5f)
// ---------------------------------------------------------------------------

field_enum! {
    /// JSON reference types for the `json_ref` opcode.
    pub enum JSONRefType {
        /// JSON string value.
        JSONString = 0,
        /// JSON uint64 value.
        JSONUint64 = 1,
        /// JSON object value.
        JSONObject = 2,
    }
}

// ---------------------------------------------------------------------------
// VrfStandard — `vrf_verify` opcode (0xd0)
// ---------------------------------------------------------------------------

field_enum! {
    /// VRF standards for the `vrf_verify` opcode.
    pub enum VrfStandard {
        /// Algorand's built-in VRF standard.
        VrfAlgorand = 0,
    }
}

// ---------------------------------------------------------------------------
// BlockField — `block` opcode (0xd1)
// ---------------------------------------------------------------------------

field_enum! {
    /// Fields available via the `block` opcode.
    pub enum BlockField {
        /// The block's VRF seed.
        BlkSeed = 0,
        /// The block's timestamp (seconds from epoch).
        BlkTimestamp = 1,
        /// The block's proposer address (or ZeroAddress pre-Payouts).
        BlkProposer = 2,
        /// Sum of fees for the block (or 0 pre-Payouts).
        BlkFeesCollected = 3,
        /// Extra amount to be paid for the given block.
        BlkBonus = 4,
        /// Hash of the previous block.
        BlkBranch = 5,
        /// Fee sink address for the given round.
        BlkFeeSink = 6,
        /// ConsensusVersion of the block.
        BlkProtocol = 7,
        /// Number of the next transaction after the block.
        BlkTxnCounter = 8,
        /// Actual amount moved from fee sink to proposer.
        BlkProposerPayout = 9,
    }
}

// ---------------------------------------------------------------------------
// VoterParamsField — `voter_params_get` opcode (0x74)
// ---------------------------------------------------------------------------

field_enum! {
    /// Fields available via the `voter_params_get` opcode.
    pub enum VoterParamsField {
        /// Online stake in microalgos (from the balance round).
        VoterBalance = 0,
        /// Whether the account opted into block payouts via keyreg.
        VoterIncentiveEligible = 1,
    }
}

// ---------------------------------------------------------------------------
// Name-to-index lookup functions for assembler/disassembler
// ---------------------------------------------------------------------------

/// Look up a GlobalField by its string name. Returns the field index as u8.
pub fn global_field_by_name(name: &str) -> Option<u8> {
    match name {
        "MinTxnFee" => Some(0),
        "MinBalance" => Some(1),
        "MaxTxnLife" => Some(2),
        "ZeroAddress" => Some(3),
        "GroupSize" => Some(4),
        "LogicSigVersion" => Some(5),
        "Round" => Some(6),
        "LatestTimestamp" => Some(7),
        "CurrentApplicationID" => Some(8),
        "CreatorAddress" => Some(9),
        "CurrentApplicationAddress" => Some(10),
        "GroupID" => Some(11),
        "OpcodeBudget" => Some(12),
        "CallerApplicationID" => Some(13),
        "CallerApplicationAddress" => Some(14),
        "AssetCreateMinBalance" => Some(15),
        "AssetOptInMinBalance" => Some(16),
        "GenesisHash" => Some(17),
        "PayoutsEnabled" => Some(18),
        "PayoutsGoOnlineFee" => Some(19),
        "PayoutsPercent" => Some(20),
        "PayoutsMinBalance" => Some(21),
        "PayoutsMaxBalance" => Some(22),
        _ => None,
    }
}

/// Look up a GlobalField name by its index.
pub fn global_field_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("MinTxnFee"),
        1 => Some("MinBalance"),
        2 => Some("MaxTxnLife"),
        3 => Some("ZeroAddress"),
        4 => Some("GroupSize"),
        5 => Some("LogicSigVersion"),
        6 => Some("Round"),
        7 => Some("LatestTimestamp"),
        8 => Some("CurrentApplicationID"),
        9 => Some("CreatorAddress"),
        10 => Some("CurrentApplicationAddress"),
        11 => Some("GroupID"),
        12 => Some("OpcodeBudget"),
        13 => Some("CallerApplicationID"),
        14 => Some("CallerApplicationAddress"),
        15 => Some("AssetCreateMinBalance"),
        16 => Some("AssetOptInMinBalance"),
        17 => Some("GenesisHash"),
        18 => Some("PayoutsEnabled"),
        19 => Some("PayoutsGoOnlineFee"),
        20 => Some("PayoutsPercent"),
        21 => Some("PayoutsMinBalance"),
        22 => Some("PayoutsMaxBalance"),
        _ => None,
    }
}

/// Look up a TxnField by its string name. Returns the field index as u8.
pub fn txn_field_by_name(name: &str) -> Option<u8> {
    match name {
        "Sender" => Some(0),
        "Fee" => Some(1),
        "FirstValid" => Some(2),
        "FirstValidTime" => Some(3),
        "LastValid" => Some(4),
        "Note" => Some(5),
        "Lease" => Some(6),
        "Receiver" => Some(7),
        "Amount" => Some(8),
        "CloseRemainderTo" => Some(9),
        "VotePK" => Some(10),
        "SelectionPK" => Some(11),
        "VoteFirst" => Some(12),
        "VoteLast" => Some(13),
        "VoteKeyDilution" => Some(14),
        "Type" => Some(15),
        "TypeEnum" => Some(16),
        "XferAsset" => Some(17),
        "AssetAmount" => Some(18),
        "AssetSender" => Some(19),
        "AssetReceiver" => Some(20),
        "AssetCloseTo" => Some(21),
        "GroupIndex" => Some(22),
        "TxID" => Some(23),
        "ApplicationID" => Some(24),
        "OnCompletion" => Some(25),
        "ApplicationArgs" => Some(26),
        "NumAppArgs" => Some(27),
        "Accounts" => Some(28),
        "NumAccounts" => Some(29),
        "ApprovalProgram" => Some(30),
        "ClearStateProgram" => Some(31),
        "RekeyTo" => Some(32),
        "ConfigAsset" => Some(33),
        "ConfigAssetTotal" => Some(34),
        "ConfigAssetDecimals" => Some(35),
        "ConfigAssetDefaultFrozen" => Some(36),
        "ConfigAssetUnitName" => Some(37),
        "ConfigAssetName" => Some(38),
        "ConfigAssetURL" => Some(39),
        "ConfigAssetMetadataHash" => Some(40),
        "ConfigAssetManager" => Some(41),
        "ConfigAssetReserve" => Some(42),
        "ConfigAssetFreeze" => Some(43),
        "ConfigAssetClawback" => Some(44),
        "FreezeAsset" => Some(45),
        "FreezeAssetAccount" => Some(46),
        "FreezeAssetFrozen" => Some(47),
        "Assets" => Some(48),
        "NumAssets" => Some(49),
        "Applications" => Some(50),
        "NumApplications" => Some(51),
        "GlobalNumUint" => Some(52),
        "GlobalNumByteSlice" => Some(53),
        "LocalNumUint" => Some(54),
        "LocalNumByteSlice" => Some(55),
        "ExtraProgramPages" => Some(56),
        "Nonparticipation" => Some(57),
        "Logs" => Some(58),
        "NumLogs" => Some(59),
        "CreatedAssetID" => Some(60),
        "CreatedApplicationID" => Some(61),
        "LastLog" => Some(62),
        "StateProofPK" => Some(63),
        "ApprovalProgramPages" => Some(64),
        "NumApprovalProgramPages" => Some(65),
        "ClearStateProgramPages" => Some(66),
        "NumClearStateProgramPages" => Some(67),
        "RejectVersion" => Some(68),
        _ => None,
    }
}

/// Look up a TxnField name by its index.
pub fn txn_field_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("Sender"),
        1 => Some("Fee"),
        2 => Some("FirstValid"),
        3 => Some("FirstValidTime"),
        4 => Some("LastValid"),
        5 => Some("Note"),
        6 => Some("Lease"),
        7 => Some("Receiver"),
        8 => Some("Amount"),
        9 => Some("CloseRemainderTo"),
        10 => Some("VotePK"),
        11 => Some("SelectionPK"),
        12 => Some("VoteFirst"),
        13 => Some("VoteLast"),
        14 => Some("VoteKeyDilution"),
        15 => Some("Type"),
        16 => Some("TypeEnum"),
        17 => Some("XferAsset"),
        18 => Some("AssetAmount"),
        19 => Some("AssetSender"),
        20 => Some("AssetReceiver"),
        21 => Some("AssetCloseTo"),
        22 => Some("GroupIndex"),
        23 => Some("TxID"),
        24 => Some("ApplicationID"),
        25 => Some("OnCompletion"),
        26 => Some("ApplicationArgs"),
        27 => Some("NumAppArgs"),
        28 => Some("Accounts"),
        29 => Some("NumAccounts"),
        30 => Some("ApprovalProgram"),
        31 => Some("ClearStateProgram"),
        32 => Some("RekeyTo"),
        33 => Some("ConfigAsset"),
        34 => Some("ConfigAssetTotal"),
        35 => Some("ConfigAssetDecimals"),
        36 => Some("ConfigAssetDefaultFrozen"),
        37 => Some("ConfigAssetUnitName"),
        38 => Some("ConfigAssetName"),
        39 => Some("ConfigAssetURL"),
        40 => Some("ConfigAssetMetadataHash"),
        41 => Some("ConfigAssetManager"),
        42 => Some("ConfigAssetReserve"),
        43 => Some("ConfigAssetFreeze"),
        44 => Some("ConfigAssetClawback"),
        45 => Some("FreezeAsset"),
        46 => Some("FreezeAssetAccount"),
        47 => Some("FreezeAssetFrozen"),
        48 => Some("Assets"),
        49 => Some("NumAssets"),
        50 => Some("Applications"),
        51 => Some("NumApplications"),
        52 => Some("GlobalNumUint"),
        53 => Some("GlobalNumByteSlice"),
        54 => Some("LocalNumUint"),
        55 => Some("LocalNumByteSlice"),
        56 => Some("ExtraProgramPages"),
        57 => Some("Nonparticipation"),
        58 => Some("Logs"),
        59 => Some("NumLogs"),
        60 => Some("CreatedAssetID"),
        61 => Some("CreatedApplicationID"),
        62 => Some("LastLog"),
        63 => Some("StateProofPK"),
        64 => Some("ApprovalProgramPages"),
        65 => Some("NumApprovalProgramPages"),
        66 => Some("ClearStateProgramPages"),
        67 => Some("NumClearStateProgramPages"),
        68 => Some("RejectVersion"),
        _ => None,
    }
}

/// Look up an AssetHoldingField by name.
pub fn asset_holding_field_by_name(name: &str) -> Option<u8> {
    match name {
        "AssetBalance" => Some(0),
        "AssetFrozen" => Some(1),
        _ => None,
    }
}

pub fn asset_holding_field_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("AssetBalance"),
        1 => Some("AssetFrozen"),
        _ => None,
    }
}

/// Look up an AssetParamsField by name.
pub fn asset_params_field_by_name(name: &str) -> Option<u8> {
    match name {
        "AssetTotal" => Some(0),
        "AssetDecimals" => Some(1),
        "AssetDefaultFrozen" => Some(2),
        "AssetUnitName" => Some(3),
        "AssetName" => Some(4),
        "AssetURL" => Some(5),
        "AssetMetadataHash" => Some(6),
        "AssetManager" => Some(7),
        "AssetReserve" => Some(8),
        "AssetFreeze" => Some(9),
        "AssetClawback" => Some(10),
        "AssetCreator" => Some(11),
        _ => None,
    }
}

pub fn asset_params_field_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("AssetTotal"),
        1 => Some("AssetDecimals"),
        2 => Some("AssetDefaultFrozen"),
        3 => Some("AssetUnitName"),
        4 => Some("AssetName"),
        5 => Some("AssetURL"),
        6 => Some("AssetMetadataHash"),
        7 => Some("AssetManager"),
        8 => Some("AssetReserve"),
        9 => Some("AssetFreeze"),
        10 => Some("AssetClawback"),
        11 => Some("AssetCreator"),
        _ => None,
    }
}

/// Look up an AppParamsField by name.
pub fn app_params_field_by_name(name: &str) -> Option<u8> {
    match name {
        "AppApprovalProgram" => Some(0),
        "AppClearStateProgram" => Some(1),
        "AppGlobalNumUint" => Some(2),
        "AppGlobalNumByteSlice" => Some(3),
        "AppLocalNumUint" => Some(4),
        "AppLocalNumByteSlice" => Some(5),
        "AppExtraProgramPages" => Some(6),
        "AppCreator" => Some(7),
        "AppAddress" => Some(8),
        _ => None,
    }
}

pub fn app_params_field_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("AppApprovalProgram"),
        1 => Some("AppClearStateProgram"),
        2 => Some("AppGlobalNumUint"),
        3 => Some("AppGlobalNumByteSlice"),
        4 => Some("AppLocalNumUint"),
        5 => Some("AppLocalNumByteSlice"),
        6 => Some("AppExtraProgramPages"),
        7 => Some("AppCreator"),
        8 => Some("AppAddress"),
        _ => None,
    }
}

/// Look up an AcctParamsField by name.
pub fn acct_params_field_by_name(name: &str) -> Option<u8> {
    match name {
        "AcctBalance" => Some(0),
        "AcctMinBalance" => Some(1),
        "AcctAuthAddr" => Some(2),
        "AcctTotalNumUint" => Some(3),
        "AcctTotalNumByteSlice" => Some(4),
        "AcctTotalExtraAppPages" => Some(5),
        "AcctTotalAppsCreated" => Some(6),
        "AcctTotalAppsOptedIn" => Some(7),
        "AcctTotalAssetsCreated" => Some(8),
        "AcctTotalAssets" => Some(9),
        "AcctTotalBoxes" => Some(10),
        "AcctTotalBoxBytes" => Some(11),
        "AcctIncentiveEligible" => Some(12),
        "AcctLastProposed" => Some(13),
        "AcctLastHeartbeat" => Some(14),
        _ => None,
    }
}

pub fn acct_params_field_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("AcctBalance"),
        1 => Some("AcctMinBalance"),
        2 => Some("AcctAuthAddr"),
        3 => Some("AcctTotalNumUint"),
        4 => Some("AcctTotalNumByteSlice"),
        5 => Some("AcctTotalExtraAppPages"),
        6 => Some("AcctTotalAppsCreated"),
        7 => Some("AcctTotalAppsOptedIn"),
        8 => Some("AcctTotalAssetsCreated"),
        9 => Some("AcctTotalAssets"),
        10 => Some("AcctTotalBoxes"),
        11 => Some("AcctTotalBoxBytes"),
        12 => Some("AcctIncentiveEligible"),
        13 => Some("AcctLastProposed"),
        14 => Some("AcctLastHeartbeat"),
        _ => None,
    }
}

/// Look up a VoterParamsField by name.
pub fn voter_params_field_by_name(name: &str) -> Option<u8> {
    match name {
        "VoterBalance" => Some(0),
        "VoterIncentiveEligible" => Some(1),
        _ => None,
    }
}

pub fn voter_params_field_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("VoterBalance"),
        1 => Some("VoterIncentiveEligible"),
        _ => None,
    }
}

/// Look up an EcdsaCurve by name.
pub fn ecdsa_curve_by_name(name: &str) -> Option<u8> {
    match name {
        "Secp256k1" => Some(0),
        "Secp256r1" => Some(1),
        _ => None,
    }
}

pub fn ecdsa_curve_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("Secp256k1"),
        1 => Some("Secp256r1"),
        _ => None,
    }
}

/// Look up an EcGroup by name.
pub fn ec_group_by_name(name: &str) -> Option<u8> {
    match name {
        "BN254g1" => Some(0),
        "BN254g2" => Some(1),
        "BLS12_381g1" => Some(2),
        "BLS12_381g2" => Some(3),
        _ => None,
    }
}

pub fn ec_group_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("BN254g1"),
        1 => Some("BN254g2"),
        2 => Some("BLS12_381g1"),
        3 => Some("BLS12_381g2"),
        _ => None,
    }
}

/// Look up a Base64Encoding by name.
pub fn base64_encoding_by_name(name: &str) -> Option<u8> {
    match name {
        "URLEncoding" => Some(0),
        "StdEncoding" => Some(1),
        _ => None,
    }
}

pub fn base64_encoding_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("URLEncoding"),
        1 => Some("StdEncoding"),
        _ => None,
    }
}

/// Look up a JSONRefType by name.
pub fn json_ref_type_by_name(name: &str) -> Option<u8> {
    match name {
        "JSONString" => Some(0),
        "JSONUint64" => Some(1),
        "JSONObject" => Some(2),
        _ => None,
    }
}

pub fn json_ref_type_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("JSONString"),
        1 => Some("JSONUint64"),
        2 => Some("JSONObject"),
        _ => None,
    }
}

/// Look up a VrfStandard by name.
pub fn vrf_standard_by_name(name: &str) -> Option<u8> {
    match name {
        "VrfAlgorand" => Some(0),
        _ => None,
    }
}

pub fn vrf_standard_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("VrfAlgorand"),
        _ => None,
    }
}

/// Look up a BlockField by name.
pub fn block_field_by_name(name: &str) -> Option<u8> {
    match name {
        "BlkSeed" => Some(0),
        "BlkTimestamp" => Some(1),
        "BlkProposer" => Some(2),
        "BlkFeesCollected" => Some(3),
        "BlkBonus" => Some(4),
        "BlkBranch" => Some(5),
        "BlkFeeSink" => Some(6),
        "BlkProtocol" => Some(7),
        "BlkTxnCounter" => Some(8),
        "BlkProposerPayout" => Some(9),
        _ => None,
    }
}

pub fn block_field_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("BlkSeed"),
        1 => Some("BlkTimestamp"),
        2 => Some("BlkProposer"),
        3 => Some("BlkFeesCollected"),
        4 => Some("BlkBonus"),
        5 => Some("BlkBranch"),
        6 => Some("BlkFeeSink"),
        7 => Some("BlkProtocol"),
        8 => Some("BlkTxnCounter"),
        9 => Some("BlkProposerPayout"),
        _ => None,
    }
}

/// Look up a MimcConfig by name.
pub fn mimc_config_by_name(name: &str) -> Option<u8> {
    match name {
        "BN254Mp110" => Some(0),
        "BLS12_381Mp111" => Some(1),
        _ => None,
    }
}

pub fn mimc_config_name(index: u8) -> Option<&'static str> {
    match index {
        0 => Some("BN254Mp110"),
        1 => Some("BLS12_381Mp111"),
        _ => None,
    }
}

/// Given an opcode name and an immediate index, resolve the field name for a byte value.
/// Returns the field name string if applicable, or None if the opcode doesn't use named fields.
pub fn field_name_for_opcode(mnemonic: &str, imm_index: usize, value: u8) -> Option<&'static str> {
    match (mnemonic, imm_index) {
        ("txn", 0)
        | ("txna", 0)
        | ("txnas", 0)
        | ("itxn", 0)
        | ("itxna", 0)
        | ("itxnas", 0)
        | ("itxn_field", 0) => txn_field_name(value),

        ("gtxn", 1)
        | ("gtxna", 1)
        | ("gtxns", 0)
        | ("gtxnsa", 0)
        | ("gtxnas", 1)
        | ("gtxnsas", 0)
        | ("gitxn", 1)
        | ("gitxna", 1)
        | ("gitxnas", 1) => txn_field_name(value),

        ("global", 0) => global_field_name(value),

        ("asset_holding_get", 0) => asset_holding_field_name(value),
        ("asset_params_get", 0) => asset_params_field_name(value),
        ("app_params_get", 0) => app_params_field_name(value),
        ("acct_params_get", 0) => acct_params_field_name(value),
        ("voter_params_get", 0) => voter_params_field_name(value),

        ("ecdsa_verify", 0) | ("ecdsa_pk_decompress", 0) | ("ecdsa_pk_recover", 0) => {
            ecdsa_curve_name(value)
        }

        ("ec_add", 0)
        | ("ec_scalar_mul", 0)
        | ("ec_pairing_check", 0)
        | ("ec_multi_scalar_mul", 0)
        | ("ec_subgroup_check", 0)
        | ("ec_map_to", 0) => ec_group_name(value),

        ("base64_decode", 0) => base64_encoding_name(value),
        ("json_ref", 0) => json_ref_type_name(value),
        ("vrf_verify", 0) => vrf_standard_name(value),
        ("block", 0) => block_field_name(value),
        ("mimc", 0) => mimc_config_name(value),

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_field_round_trip() {
        assert_eq!(GlobalField::from_u8(0).unwrap(), GlobalField::MinTxnFee);
        assert_eq!(
            GlobalField::from_u8(8).unwrap(),
            GlobalField::CurrentApplicationID,
        );
        assert_eq!(
            GlobalField::from_u8(22).unwrap(),
            GlobalField::PayoutsMaxBalance,
        );
        assert!(GlobalField::from_u8(23).is_err());
        assert!(GlobalField::from_u8(255).is_err());
    }

    #[test]
    fn txn_field_round_trip() {
        assert_eq!(TxnField::from_u8(0).unwrap(), TxnField::Sender);
        assert_eq!(TxnField::from_u8(3).unwrap(), TxnField::FirstValidTime);
        assert_eq!(TxnField::from_u8(16).unwrap(), TxnField::TypeEnum);
        assert_eq!(TxnField::from_u8(23).unwrap(), TxnField::TxID);
        assert_eq!(TxnField::from_u8(48).unwrap(), TxnField::Assets);
        assert_eq!(
            TxnField::from_u8(67).unwrap(),
            TxnField::NumClearStateProgramPages,
        );
        assert_eq!(TxnField::from_u8(68).unwrap(), TxnField::RejectVersion);
        assert!(TxnField::from_u8(69).is_err());
    }

    #[test]
    fn asset_holding_field_round_trip() {
        assert_eq!(
            AssetHoldingField::from_u8(0).unwrap(),
            AssetHoldingField::AssetBalance,
        );
        assert_eq!(
            AssetHoldingField::from_u8(1).unwrap(),
            AssetHoldingField::AssetFrozen,
        );
        assert!(AssetHoldingField::from_u8(2).is_err());
    }

    #[test]
    fn asset_params_field_round_trip() {
        assert_eq!(
            AssetParamsField::from_u8(0).unwrap(),
            AssetParamsField::AssetTotal,
        );
        assert_eq!(
            AssetParamsField::from_u8(11).unwrap(),
            AssetParamsField::AssetCreator,
        );
        assert!(AssetParamsField::from_u8(12).is_err());
    }

    #[test]
    fn app_params_field_round_trip() {
        assert_eq!(
            AppParamsField::from_u8(0).unwrap(),
            AppParamsField::AppApprovalProgram,
        );
        assert_eq!(
            AppParamsField::from_u8(8).unwrap(),
            AppParamsField::AppAddress,
        );
        assert!(AppParamsField::from_u8(9).is_err());
    }

    #[test]
    fn acct_params_field_round_trip() {
        assert_eq!(
            AcctParamsField::from_u8(0).unwrap(),
            AcctParamsField::AcctBalance,
        );
        assert_eq!(
            AcctParamsField::from_u8(14).unwrap(),
            AcctParamsField::AcctLastHeartbeat,
        );
        assert!(AcctParamsField::from_u8(15).is_err());
    }

    #[test]
    fn itxn_field_is_txn_field() {
        // ItxnField is a type alias for TxnField.
        let f: ItxnField = TxnField::Sender;
        assert_eq!(f, TxnField::Sender);
    }

    #[test]
    fn error_message_contains_field_name() {
        let err = GlobalField::from_u8(99).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("GlobalField"),
            "error should name the enum: {msg}"
        );
        assert!(
            msg.contains("99"),
            "error should include the bad index: {msg}"
        );
    }

    #[test]
    fn ecdsa_curve_round_trip() {
        assert_eq!(EcdsaCurve::from_u8(0).unwrap(), EcdsaCurve::Secp256k1);
        assert_eq!(EcdsaCurve::from_u8(1).unwrap(), EcdsaCurve::Secp256r1);
        assert!(EcdsaCurve::from_u8(2).is_err());
    }

    #[test]
    fn ec_group_round_trip() {
        assert_eq!(EcGroup::from_u8(0).unwrap(), EcGroup::BN254g1);
        assert_eq!(EcGroup::from_u8(1).unwrap(), EcGroup::BN254g2);
        assert_eq!(EcGroup::from_u8(2).unwrap(), EcGroup::BLS12_381g1);
        assert_eq!(EcGroup::from_u8(3).unwrap(), EcGroup::BLS12_381g2);
        assert!(EcGroup::from_u8(4).is_err());
    }

    #[test]
    fn mimc_config_round_trip() {
        assert_eq!(MimcConfig::from_u8(0).unwrap(), MimcConfig::BN254Mp110);
        assert_eq!(MimcConfig::from_u8(1).unwrap(), MimcConfig::BLS12_381Mp111,);
        assert!(MimcConfig::from_u8(2).is_err());
    }

    #[test]
    fn base64_encoding_round_trip() {
        assert_eq!(
            Base64Encoding::from_u8(0).unwrap(),
            Base64Encoding::URLEncoding,
        );
        assert_eq!(
            Base64Encoding::from_u8(1).unwrap(),
            Base64Encoding::StdEncoding,
        );
        assert!(Base64Encoding::from_u8(2).is_err());
    }

    #[test]
    fn json_ref_type_round_trip() {
        assert_eq!(JSONRefType::from_u8(0).unwrap(), JSONRefType::JSONString,);
        assert_eq!(JSONRefType::from_u8(1).unwrap(), JSONRefType::JSONUint64,);
        assert_eq!(JSONRefType::from_u8(2).unwrap(), JSONRefType::JSONObject,);
        assert!(JSONRefType::from_u8(3).is_err());
    }

    #[test]
    fn vrf_standard_round_trip() {
        assert_eq!(VrfStandard::from_u8(0).unwrap(), VrfStandard::VrfAlgorand,);
        assert!(VrfStandard::from_u8(1).is_err());
    }

    #[test]
    fn block_field_round_trip() {
        assert_eq!(BlockField::from_u8(0).unwrap(), BlockField::BlkSeed);
        assert_eq!(BlockField::from_u8(1).unwrap(), BlockField::BlkTimestamp);
        assert_eq!(BlockField::from_u8(2).unwrap(), BlockField::BlkProposer);
        assert_eq!(
            BlockField::from_u8(9).unwrap(),
            BlockField::BlkProposerPayout,
        );
        assert!(BlockField::from_u8(10).is_err());
    }

    #[test]
    fn voter_params_field_round_trip() {
        assert_eq!(
            VoterParamsField::from_u8(0).unwrap(),
            VoterParamsField::VoterBalance,
        );
        assert_eq!(
            VoterParamsField::from_u8(1).unwrap(),
            VoterParamsField::VoterIncentiveEligible,
        );
        assert!(VoterParamsField::from_u8(2).is_err());
    }
}
