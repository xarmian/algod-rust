use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{Address, BlockHeader};

/// Per-round transaction tail data, matching go-algorand's `TxTailRound`
/// in `ledger/store/trackerdb/data.go`.
///
/// Stores the transaction IDs, last-valid rounds, and lease information
/// for duplicate detection and lease enforcement across rounds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxTailRound {
    /// Transaction IDs (each a 32-byte digest).
    #[serde(rename = "i", default, skip_serializing_if = "Vec::is_empty")]
    pub txn_ids: Vec<ByteBuf>,

    /// Last-valid round for each transaction (parallel to `txn_ids`).
    #[serde(rename = "v", default, skip_serializing_if = "Vec::is_empty")]
    pub last_valid: Vec<u64>,

    /// Lease entries (only for transactions that have a non-zero lease).
    #[serde(rename = "l", default, skip_serializing_if = "Vec::is_empty")]
    pub leases: Vec<TxTailRoundLease>,

    /// Block header for this round.
    #[serde(rename = "h")]
    pub hdr: BlockHeader,
}

/// A single lease entry within a `TxTailRound`, matching go-algorand's
/// `TxTailRoundLease`.
///
/// Note: In go-algorand, the `TxnIdx` field has a typo in its struct tag
/// (`code:"i"` instead of `codec:"i"`), so the msgp code generator falls
/// back to using the field name `"TxnIdx"` as the serialization key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxTailRoundLease {
    /// Sender address.
    #[serde(rename = "s", default, skip_serializing_if = "Address::is_zero")]
    pub sender: Address,

    /// Lease value (32 bytes).
    #[serde(rename = "l", default, skip_serializing_if = "is_empty_bytes")]
    pub lease: ByteBuf,

    /// Index into the parent `TxTailRound`'s `txn_ids` / `last_valid` arrays.
    ///
    /// Serialized as `"TxnIdx"` to match go-algorand's msgp output (the Go
    /// source has a typo `code:"i"` instead of `codec:"i"`, causing the code
    /// generator to use the field name as-is).
    #[serde(rename = "TxnIdx", default, skip_serializing_if = "is_zero_u64")]
    pub txn_idx: u64,
}

fn is_empty_bytes(v: &ByteBuf) -> bool {
    v.is_empty()
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
