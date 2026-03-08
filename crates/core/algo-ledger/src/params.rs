use algo_types::AccountData;

// Protocol parameters for minimum balance computation.
// Values from go-algorand consensus parameters (v4.5.1).

pub const MIN_BALANCE: u64 = 100_000;
pub const ASSET_OPT_IN_MIN_BALANCE: u64 = 100_000;
pub const APP_FLAT_PARAMS_MIN_BALANCE: u64 = 100_000;
pub const APP_FLAT_OPT_IN_MIN_BALANCE: u64 = 100_000;
// Three-tier schema costing from go-algorand:
// Total per uint = SCHEMA_MIN_BALANCE_PER_ENTRY + SCHEMA_UINT_MIN_BALANCE = 28,500
// Total per byte-slice = SCHEMA_MIN_BALANCE_PER_ENTRY + SCHEMA_BYTES_MIN_BALANCE = 50,000
pub const SCHEMA_MIN_BALANCE_PER_ENTRY: u64 = 25_000;
pub const SCHEMA_UINT_MIN_BALANCE: u64 = 3_500;
pub const SCHEMA_BYTES_MIN_BALANCE: u64 = 25_000;
pub const BOX_FLAT_MIN_BALANCE: u64 = 2_500;
pub const BOX_BYTE_MIN_BALANCE: u64 = 400;
pub const REWARDS_RATE_REFRESH_INTERVAL: u64 = 500_000;

// Inner transaction consensus parameters (go-algorand v4.5.1).

/// Maximum inner transactions per app call (before pooling, v30+).
/// With `EnableInnerTransactionPooling` (v31+), this is pooled across the
/// group: effective limit = `MAX_INNER_TRANSACTIONS * MAX_TX_GROUP_SIZE`.
pub const MAX_INNER_TRANSACTIONS: usize = 16;

/// Maximum atomic transaction group size.
pub const MAX_TX_GROUP_SIZE: usize = 16;

/// Maximum inner app-call depth (go-algorand `maxAppCallDepth = 8`).
/// A value of 0 prevents inner app calls; 8 means top-level + 8 levels deep.
pub const MAX_APP_CALL_DEPTH: usize = 8;

/// Minimum AVM version for programs called via inner transactions (v34+).
pub const MIN_INNER_APPL_VERSION: u64 = 4;

/// Default per-app opcode budget (go-algorand `MaxAppProgramCost = 700`).
pub const INNER_APP_BUDGET: i64 = 700;

/// Minimum transaction fee in microAlgos.
pub const MIN_TXN_FEE: u64 = 1000;

/// Compute minimum balance for an account based on its opted-in assets,
/// created assets, created apps, opted-in apps, extra app pages, boxes,
/// and aggregate app schema.
///
/// Schema cost matches Go's three-tier formula:
///   SCHEMA_MIN_BALANCE_PER_ENTRY * (num_uint + num_byte_slice)
///   + SCHEMA_UINT_MIN_BALANCE * num_uint
///   + SCHEMA_BYTES_MIN_BALANCE * num_byte_slice
pub fn min_balance(account: &AccountData) -> u64 {
    // NOTE: total_assets_opted_in already includes creator holdings (incremented
    // on asset create), matching Go's single `TotalAssets` counter. Do NOT add
    // total_created_assets separately — that would double-count.
    let schema = &account.total_app_schema;
    let num_entries = schema.num_uint + schema.num_byte_slice;
    let schema_cost = SCHEMA_MIN_BALANCE_PER_ENTRY * num_entries
        + SCHEMA_UINT_MIN_BALANCE * schema.num_uint
        + SCHEMA_BYTES_MIN_BALANCE * schema.num_byte_slice;

    MIN_BALANCE
        + account.total_assets_opted_in * ASSET_OPT_IN_MIN_BALANCE
        + account.total_created_apps * APP_FLAT_PARAMS_MIN_BALANCE
        + account.total_apps_opted_in * APP_FLAT_OPT_IN_MIN_BALANCE
        + account.total_extra_app_pages as u64 * APP_FLAT_PARAMS_MIN_BALANCE
        + account.total_boxes * BOX_FLAT_MIN_BALANCE
        + account.total_box_bytes * BOX_BYTE_MIN_BALANCE
        + schema_cost
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_balance_default_account() {
        let account = AccountData::default();
        assert_eq!(min_balance(&account), MIN_BALANCE);
    }

    #[test]
    fn test_min_balance_with_assets() {
        let account = AccountData {
            total_assets_opted_in: 3,
            ..Default::default()
        };
        assert_eq!(min_balance(&account), 100_000 + 3 * 100_000);
    }

    #[test]
    fn test_min_balance_with_apps_and_boxes() {
        let account = AccountData {
            total_created_apps: 1,
            total_apps_opted_in: 2,
            total_extra_app_pages: 1,
            total_boxes: 5,
            total_box_bytes: 1000,
            ..Default::default()
        };
        // 100k + 1*100k + 2*100k + 1*100k + 5*2500 + 1000*400
        assert_eq!(
            min_balance(&account),
            100_000 + 100_000 + 200_000 + 100_000 + 12_500 + 400_000
        );
    }
}
