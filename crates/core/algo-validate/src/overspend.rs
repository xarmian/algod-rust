// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! go-algorand's `ledgercore.OverspendError` text (issue #1979).
//!
//! When a transaction's fee or payment amount exceeds its sender's balance,
//! go's pool answers
//!
//! ```text
//! TransactionPool.Remember: transaction <txid>: overspend (account <addr>, data {AccountBaseData:{...} VotingData:{...}}, tried to spend <A>)
//! ```
//!
//! where `data` is Go's `%+v` rendering of `ledgercore.AccountData`
//! (`ledger/ledgercore/accountdata.go`, `ledger/ledgercore/error.go:62`) and
//! the amounts are `basics.MicroAlgos.String()`. The account shown is the
//! sender as `cow.lookup` returns it **before** the move that overspends
//! (`eval.go` `Move`: `Data: fromBal`): for the fee move that is the stored
//! account, for the amount move it is the state after the fee move
//! (pending rewards applied, fee debited). The field order, names and
//! formats below were captured from a go-algorand v5.0.3-stable node.

use algo_types::{AccountData, AccountStatus, Address};

use crate::fee::format_micro_algos;

/// Go's `basics.Status.String()`.
fn status_name(status: AccountStatus) -> &'static str {
    match status {
        AccountStatus::Offline => "Offline",
        AccountStatus::Online => "Online",
        AccountStatus::NotParticipating => "Not Participating",
    }
}

/// Go's `%v` of a byte array: `[1 2 3]`.
fn byte_array(bytes: &[u8]) -> String {
    let items: Vec<String> = bytes.iter().map(u8::to_string).collect();
    format!("[{}]", items.join(" "))
}

/// Go's `%+v` of `ledgercore.AccountData`.
pub fn format_account_data(data: &AccountData) -> String {
    let auth = data.auth_addr.unwrap_or_default();
    format!(
        "{{AccountBaseData:{{Status:{status} MicroAlgos:{algos} RewardsBase:{rb} RewardedMicroAlgos:{rewarded} \
AuthAddr:{auth} IncentiveEligible:{ie} TotalAppSchema:{{NumUint:{nu} NumByteSlice:{nbs}}} \
TotalExtraAppPages:{pages} TotalAppParams:{app_params} TotalAppLocalStates:{app_local} \
TotalAssetParams:{asset_params} TotalAssets:{assets} TotalBoxes:{boxes} TotalBoxBytes:{box_bytes} \
LastProposed:{proposed} LastHeartbeat:{heartbeat}}} \
VotingData:{{VoteID:{vote_id} SelectionID:{sel_id} StateProofID:{sp_id} VoteFirstValid:{vfv} \
VoteLastValid:{vlv} VoteKeyDilution:{vkd}}}}}",
        status = status_name(data.status),
        algos = format_micro_algos(data.micro_algos),
        rb = data.rewards_base,
        rewarded = format_micro_algos(data.rewarded_micro_algos),
        auth = auth.to_algorand_string(),
        ie = data.incentive_eligible,
        nu = data.total_app_schema.num_uint,
        nbs = data.total_app_schema.num_byte_slice,
        pages = data.total_extra_app_pages,
        app_params = data.total_created_apps,
        app_local = data.total_apps_opted_in,
        asset_params = data.total_created_assets,
        assets = data.total_assets_opted_in,
        boxes = data.total_boxes,
        box_bytes = data.total_box_bytes,
        proposed = data.last_proposed,
        heartbeat = data.last_heartbeat,
        vote_id = byte_array(&data.vote_id.unwrap_or([0u8; 32])),
        sel_id = byte_array(&data.selection_id.unwrap_or([0u8; 32])),
        sp_id = byte_array(&data.state_proof_id.unwrap_or([0u8; 64])),
        vfv = data.vote_first_valid,
        vlv = data.vote_last_valid,
        vkd = data.vote_key_dilution,
    )
}

/// go's `eval` wrapping of `ledgercore.OverspendError` for a transaction:
/// `transaction <txid>: overspend (account <addr>, data {...}, tried to spend <A>)`.
pub fn overspend_message(txid: &str, account: &Address, data: &AccountData, tried: u64) -> String {
    format!(
        "transaction {txid}: overspend (account {}, data {}, tried to spend {})",
        account.to_algorand_string(),
        format_account_data(data),
        format_micro_algos(tried),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// The account of the live capture below: offline, 1.499 Algo, nothing else.
    fn captured_account() -> (Address, AccountData) {
        let addr =
            Address::from_str("E3EC3FBAHHXDCRGWFGPKDEXVJ2J4N25J7BUU4D6IAW7HNRSDOBSSJSJ4OA").unwrap();
        let data = AccountData {
            micro_algos: 1_499_000,
            ..AccountData::default()
        };
        (addr, data)
    }

    /// Captured from go-algorand v5.0.3-stable (private network, validly
    /// signed payment of 5 Algo from an account holding 1.5 Algo, fee 1000):
    const CAPTURED_5A: &str = "transaction OEAWIVYPTO2XPMB32G6LKW43P47HYQJZ2PLWZU3N2RACI254YUPQ: overspend (account E3EC3FBAHHXDCRGWFGPKDEXVJ2J4N25J7BUU4D6IAW7HNRSDOBSSJSJ4OA, data {AccountBaseData:{Status:Offline MicroAlgos:1.499000A RewardsBase:0 RewardedMicroAlgos:0.0A AuthAddr:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ IncentiveEligible:false TotalAppSchema:{NumUint:0 NumByteSlice:0} TotalExtraAppPages:0 TotalAppParams:0 TotalAppLocalStates:0 TotalAssetParams:0 TotalAssets:0 TotalBoxes:0 TotalBoxBytes:0 LastProposed:0 LastHeartbeat:0} VotingData:{VoteID:[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] SelectionID:[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] StateProofID:[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] VoteFirstValid:0 VoteLastValid:0 VoteKeyDilution:0}}, tried to spend 5A)";

    #[test]
    fn the_message_is_byte_identical_to_a_live_go_capture() {
        let (addr, data) = captured_account();
        let got = overspend_message(
            "OEAWIVYPTO2XPMB32G6LKW43P47HYQJZ2PLWZU3N2RACI254YUPQ",
            &addr,
            &data,
            5_000_000,
        );
        assert_eq!(got, CAPTURED_5A);
    }

    /// Same account, a payment of 1.4995 Algo (second live capture).
    #[test]
    fn a_fractional_amount_reads_like_go() {
        let (addr, data) = captured_account();
        let got = overspend_message("E7REUMLE4CVRJ2SQN3QMNK2RHHVK365XKOIALY4LR6N2IAAC47YQ", &addr, &data, 1_499_500);
        assert!(got.ends_with(", tried to spend 1.499500A)"), "{got}");
    }

    #[test]
    fn an_unfunded_account_shows_zero_algos_and_the_fee_that_was_tried() {
        let addr =
            Address::from_str("DF7WWI7BNSCTFRVLZA4PVTK6U6E34DDWWKJAGNADTP5IWPJWRVQZRC323I").unwrap();
        let got = overspend_message("T", &addr, &AccountData::default(), 1);
        assert!(got.contains("MicroAlgos:0.0A RewardsBase:0 RewardedMicroAlgos:0.0A"), "{got}");
        assert!(got.ends_with(", tried to spend 1uA)"), "{got}");
    }

    /// Status names follow `basics.Status.String()` (note the space), and the
    /// voting data prints its key bytes.
    #[test]
    fn status_voting_keys_and_auth_addr_are_rendered_like_gos_percent_plus_v() {
        let data = AccountData {
            status: AccountStatus::NotParticipating,
            vote_id: Some([7u8; 32]),
            selection_id: None,
            state_proof_id: Some([1u8; 64]),
            vote_first_valid: 10,
            vote_last_valid: 20,
            vote_key_dilution: 100,
            auth_addr: Some(Address([9u8; 32])),
            incentive_eligible: true,
            total_assets_opted_in: 3,
            total_created_apps: 2,
            total_apps_opted_in: 4,
            total_created_assets: 5,
            total_boxes: 6,
            total_box_bytes: 700,
            total_extra_app_pages: 1,
            last_proposed: 11,
            last_heartbeat: 12,
            ..AccountData::default()
        };
        let text = format_account_data(&data);
        assert!(text.starts_with("{AccountBaseData:{Status:Not Participating MicroAlgos:0.0A"), "{text}");
        assert!(text.contains(&format!("AuthAddr:{}", Address([9u8; 32]).to_algorand_string())), "{text}");
        assert!(text.contains("IncentiveEligible:true"), "{text}");
        assert!(text.contains("TotalExtraAppPages:1 TotalAppParams:2 TotalAppLocalStates:4 TotalAssetParams:5 TotalAssets:3 TotalBoxes:6 TotalBoxBytes:700 LastProposed:11 LastHeartbeat:12}"), "{text}");
        assert!(text.contains(&format!("VoteID:{}", byte_array(&[7u8; 32]))), "{text}");
        assert!(text.contains("SelectionID:[0 0"), "{text}");
        assert!(text.contains("VoteFirstValid:10 VoteLastValid:20 VoteKeyDilution:100}}"), "{text}");
        assert!(text.contains("StateProofID:[1 1"), "{text}");
    }
}
