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
        LastValid = 3,
        Note = 4,
        Lease = 5,
        Receiver = 6,
        Amount = 7,
        CloseRemainderTo = 8,
        VotePK = 9,
        SelectionPK = 10,
        VoteFirst = 11,
        VoteLast = 12,
        VoteKeyDilution = 13,
        Type = 14,
        TypeEnum = 15,
        XferAsset = 16,
        AssetAmount = 17,
        AssetSender = 18,
        AssetReceiver = 19,
        AssetCloseTo = 20,
        GroupIndex = 21,
        TxID = 22,
        ApplicationID = 23,
        OnCompletion = 24,
        ApplicationArgs = 25,
        NumAppArgs = 26,
        Accounts = 27,
        NumAccounts = 28,
        ApprovalProgram = 29,
        ClearStateProgram = 30,
        RekeyTo = 31,
        ConfigAsset = 32,
        ConfigAssetTotal = 33,
        ConfigAssetDecimals = 34,
        ConfigAssetDefaultFrozen = 35,
        ConfigAssetUnitName = 36,
        ConfigAssetName = 37,
        ConfigAssetURL = 38,
        ConfigAssetMetadataHash = 39,
        ConfigAssetManager = 40,
        ConfigAssetReserve = 41,
        ConfigAssetFreeze = 42,
        ConfigAssetClawback = 43,
        FreezeAsset = 44,
        FreezeAssetAccount = 45,
        FreezeAssetFrozen = 46,
        Assets = 47,
        NumAssets = 48,
        Applications = 49,
        NumApplications = 50,
        GlobalNumUint = 51,
        GlobalNumByteSlice = 52,
        LocalNumUint = 53,
        LocalNumByteSlice = 54,
        ExtraProgramPages = 55,
        Nonparticipation = 56,
        Logs = 57,
        NumLogs = 58,
        CreatedAssetID = 59,
        CreatedApplicationID = 60,
        LastLog = 61,
        StateProofPK = 62,
        ApprovalProgramPages = 63,
        NumApprovalProgramPages = 64,
        ClearStateProgramPages = 65,
        NumClearStateProgramPages = 66,
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

/// Inner transaction fields use the same field indices as regular transaction
/// fields. Use [`TxnField`] for `itxn`, `itxn_field`, `gitxn`, etc.
pub type ItxnField = TxnField;

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
        assert_eq!(TxnField::from_u8(15).unwrap(), TxnField::TypeEnum);
        assert_eq!(TxnField::from_u8(22).unwrap(), TxnField::TxID);
        assert_eq!(TxnField::from_u8(47).unwrap(), TxnField::Assets);
        assert_eq!(
            TxnField::from_u8(66).unwrap(),
            TxnField::NumClearStateProgramPages,
        );
        assert!(TxnField::from_u8(67).is_err());
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
}
