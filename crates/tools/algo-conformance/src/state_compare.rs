use algo_rest_client::AlgodClient;
use algo_types::{AccountStatus, Address};
use tracing::warn;

/// A mismatch between Rust ledger state and Go node state.
#[derive(Debug)]
pub struct BalanceMismatch {
    pub round: u64,
    pub address: Address,
    pub field: String,
    pub expected: String, // from Go node
    pub actual: String,   // from Rust ledger
}

/// Compare accounts touched in a block against a Go node.
///
/// For each address, queries the Go node for account state at the given round
/// and compares with the Rust ledger state.
pub async fn compare_accounts(
    touched: &[Address],
    store: &impl algo_ledger::store_trait::LedgerStore,
    client: &AlgodClient,
    round: u64,
    sample_rate: u64,
) -> Vec<BalanceMismatch> {
    if sample_rate > 0 && round % sample_rate != 0 {
        return Vec::new();
    }

    let mut mismatches = Vec::new();

    for addr in touched {
        let go_info = match client.get_account_at_round(addr, round).await {
            Ok(info) => info,
            Err(e) => {
                warn!(
                    round,
                    addr = %addr.to_algorand_string(),
                    error = %e,
                    "failed to fetch Go account state for comparison"
                );
                continue;
            }
        };

        let rust_acct = store.get_or_default_account(addr);

        // Compare amount_without_pending_rewards vs micro_algos
        if go_info.amount_without_pending_rewards != rust_acct.micro_algos {
            mismatches.push(BalanceMismatch {
                round,
                address: *addr,
                field: "amount_without_pending_rewards".to_string(),
                expected: go_info.amount_without_pending_rewards.to_string(),
                actual: rust_acct.micro_algos.to_string(),
            });
        }

        // Compare status
        let go_status = go_info.status.as_str();
        let rust_status = match rust_acct.status {
            AccountStatus::Offline => "Offline",
            AccountStatus::Online => "Online",
            AccountStatus::NotParticipating => "NotParticipating",
        };
        if go_status != rust_status {
            mismatches.push(BalanceMismatch {
                round,
                address: *addr,
                field: "status".to_string(),
                expected: go_status.to_string(),
                actual: rust_status.to_string(),
            });
        }

        // Compare total_assets_opted_in
        if go_info.total_assets_opted_in != rust_acct.total_assets_opted_in {
            mismatches.push(BalanceMismatch {
                round,
                address: *addr,
                field: "total_assets_opted_in".to_string(),
                expected: go_info.total_assets_opted_in.to_string(),
                actual: rust_acct.total_assets_opted_in.to_string(),
            });
        }

        // Compare total_created_assets
        if go_info.total_created_assets != rust_acct.total_created_assets {
            mismatches.push(BalanceMismatch {
                round,
                address: *addr,
                field: "total_created_assets".to_string(),
                expected: go_info.total_created_assets.to_string(),
                actual: rust_acct.total_created_assets.to_string(),
            });
        }

        // Compare total_apps_opted_in
        if go_info.total_apps_opted_in != rust_acct.total_apps_opted_in {
            mismatches.push(BalanceMismatch {
                round,
                address: *addr,
                field: "total_apps_opted_in".to_string(),
                expected: go_info.total_apps_opted_in.to_string(),
                actual: rust_acct.total_apps_opted_in.to_string(),
            });
        }

        // Compare total_created_apps
        if go_info.total_created_apps != rust_acct.total_created_apps {
            mismatches.push(BalanceMismatch {
                round,
                address: *addr,
                field: "total_created_apps".to_string(),
                expected: go_info.total_created_apps.to_string(),
                actual: rust_acct.total_created_apps.to_string(),
            });
        }
    }

    mismatches
}
