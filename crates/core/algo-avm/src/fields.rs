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
