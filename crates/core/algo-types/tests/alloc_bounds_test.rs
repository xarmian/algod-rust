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

//! go's `config.checkSetAllocBounds` (issue #2439). The values are go
//! v5.0.5-stable's `bounds.*`, printed by a go program after `config.init`
//! (built-in table) and after `config.LoadConfigurableConsensusProtocols`
//! with the vendored aramidmain `consensus.json` as it is: it leaves the v5
//! `MaxAbsolute*` fields out, go reads them as 0 and `MaxTxnNoteBytes` stays
//! at 4096 (issue #2441; go: `bounds MaxTxnNoteBytes 4096 MaxAppTotalArgLen
//! 16384 MaxExtraAppProgramLen 7 MaxLogicSigMaxSize 16000`). The bounds are
//! process-global and only grow, so this binary holds one test that runs the
//! steps in order.

use algo_types::consensus::{
    built_in_consensus_protocols, check_set_alloc_bounds, consensus_params_for_version,
    preload_consensus_protocols_with_bundle,
};
use algo_types::go_msgp::bounds;

const BUNDLE: &str = include_str!("../../../../bin/algod-rust/consensus/aramidmain-consensus.json");

/// go: `builtin MaxVoteThreshold=7750 MaxStateDeltaKeys=2048 ...`.
const GO_BUILT_IN: &[(&str, usize)] = &[
    ("MaxVoteThreshold", 7750),
    ("MaxStateDeltaKeys", 2048),
    ("MaxEvalDeltaAccounts", 2048),
    ("MaxAppProgramLen", 2048),
    ("MaxLogicSigMaxSize", 16000),
    ("MaxTxnNoteBytes", 4096),
    ("MaxBytesKeyValueLen", 128),
    ("MaxExtraAppProgramLen", 7),
    ("MaxAvailableAppProgramLen", 16384),
    ("MaxLogCalls", 2048),
    ("MaxInnerTransactionsPerDelta", 256),
    ("MaxProposedExpiredOnlineAccounts", 32),
    ("MaxMarkAbsent", 32),
    ("MaxAssetNameBytes", 32),
    ("MaxAssetUnitNameBytes", 8),
    ("MaxAssetURLBytes", 96),
    ("MaxAppBytesValueLen", 128),
    ("MaxAppAccess", 16),
];

fn expect(over: &[(&str, usize)]) -> Vec<(&'static str, usize)> {
    GO_BUILT_IN
        .iter()
        .map(|&(name, v)| {
            (
                name,
                over.iter().find(|(n, _)| *n == name).map_or(v, |o| o.1),
            )
        })
        .collect()
}

#[test]
fn alloc_bounds_follow_every_loaded_protocol_like_go() {
    // The initial values are go's built-in maxima, and re-running the port of
    // checkSetAllocBounds over the built-in table changes none of them.
    assert_eq!(bounds::snapshot(), expect(&[]));
    for p in built_in_consensus_protocols().values() {
        check_set_alloc_bounds(p);
    }
    assert_eq!(bounds::snapshot(), expect(&[]));

    // The aramidmain protocols raise nothing: their `MaxAbsoluteTxnNoteBytes`
    // is 0 and go does not fall back to `MaxTxnNoteBytes` (131072).
    let merged =
        preload_consensus_protocols_with_bundle(None, built_in_consensus_protocols(), Some(BUNDLE))
            .unwrap();
    for p in merged.values() {
        check_set_alloc_bounds(p);
    }
    assert_eq!(bounds::snapshot(), expect(&[]));

    // A protocol above every bound raises each one; the available program
    // length is recomputed from the two maxima it is made of.
    let mut big = consensus_params_for_version("future").unwrap();
    big.soft_committee_threshold = 9000;
    big.max_app_program_len = 4096;
    big.logic_sig_max_size = 2000;
    big.max_absolute_logic_sig_program_size = 1000;
    big.max_absolute_txn_note_bytes = 200_000;
    big.max_app_key_len = 200;
    big.max_app_bytes_value_len = 300;
    big.max_absolute_extra_program_pages = 9;
    big.max_inner_transactions = 20;
    big.max_proposed_expired_online_accounts = 40;
    big.payouts_max_mark_absent = 50;
    big.max_asset_name_bytes = 33;
    big.max_asset_unit_name_bytes = 9;
    big.max_asset_url_bytes = 97;
    big.max_app_access = 17;
    check_set_alloc_bounds(&big);
    let group = big.max_tx_group_size;
    assert_eq!(
        bounds::snapshot(),
        expect(&[
            ("MaxVoteThreshold", 9000),
            ("MaxStateDeltaKeys", 4096),
            ("MaxEvalDeltaAccounts", 4096),
            ("MaxAppProgramLen", 4096),
            ("MaxLogicSigMaxSize", 2000 * group),
            ("MaxTxnNoteBytes", 200_000),
            ("MaxBytesKeyValueLen", 300),
            ("MaxExtraAppProgramLen", 9),
            ("MaxAvailableAppProgramLen", 4096 * 10),
            ("MaxLogCalls", 4096),
            ("MaxInnerTransactionsPerDelta", 20 * group),
            ("MaxProposedExpiredOnlineAccounts", 40),
            ("MaxMarkAbsent", 50),
            ("MaxAssetNameBytes", 33),
            ("MaxAssetUnitNameBytes", 9),
            ("MaxAssetURLBytes", 97),
            ("MaxAppBytesValueLen", 300),
            ("MaxAppAccess", 17),
        ])
    );

    // Bounds never shrink (go's checkSetMax).
    for p in built_in_consensus_protocols().values() {
        check_set_alloc_bounds(p);
    }
    assert_eq!(bounds::MAX_TXN_NOTE_BYTES.get(), 200_000);
}
