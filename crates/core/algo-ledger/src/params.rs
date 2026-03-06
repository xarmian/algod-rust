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

/// Compute minimum balance for an account based on its opted-in assets,
/// created assets, created apps, opted-in apps, extra app pages, and boxes.
///
/// TODO: Schema-based min balance (SCHEMA_UINT_MIN_BALANCE, SCHEMA_BYTES_MIN_BALANCE)
/// requires knowing the actual local/global schemas for each opted-in/created app.
/// AccountData only tracks aggregate counts, not per-app schemas. Add schema-based
/// min balance when per-app state tracking is available.
pub fn min_balance(account: &AccountData) -> u64 {
    MIN_BALANCE
        + account.total_assets_opted_in * ASSET_OPT_IN_MIN_BALANCE
        + account.total_created_assets * ASSET_OPT_IN_MIN_BALANCE
        + account.total_created_apps * APP_FLAT_PARAMS_MIN_BALANCE
        + account.total_apps_opted_in * APP_FLAT_OPT_IN_MIN_BALANCE
        + account.total_extra_app_pages as u64 * APP_FLAT_PARAMS_MIN_BALANCE
        + account.total_boxes * BOX_FLAT_MIN_BALANCE
        + account.total_box_bytes * BOX_BYTE_MIN_BALANCE
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
