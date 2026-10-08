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

//! Issue #1707: the txtail must record the txids of the FULL (genesis-field
//! restored) transactions, exactly like go's `TxTailRoundFromBlock`
//! (`ledger/txtail.go`), which iterates the payset decoded through
//! `BlockHeader.DecodeSignedTxn` (`data/bookkeeping/block.go:983-1020`).
//! The Replay path (`apply_block_executing_app_calls` on a pay-only block)
//! hands the STRIPPED block to the txtail builder, so before the fix the
//! recorded ids never matched a real txid lookup.

use algo_ledger::apply::{apply_block_executing_app_calls, apply_block_with_mode, ApplyMode};
use algo_ledger::txtail_cache::TxTailDupCache;
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::consensus::{CONSENSUS_V15, CONSENSUS_V41};
use algo_types::{Address, Block, Digest, Round, SignedTransaction, Transaction};

const GENESIS_ID: &str = "test-net-v1";
const GENESIS_HASH: [u8; 32] = [7u8; 32];

fn block(proto: &str, hgh: bool) -> Block {
    let sender = Address([1u8; 32]);
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "pay".into();
    stx.txn.sender = sender;
    stx.txn.receiver = Address([2u8; 32]);
    stx.txn.amount = 1_000_000;
    stx.txn.fee = 1000;
    stx.txn.first_valid = Round(1);
    stx.txn.last_valid = Round(1000);
    stx.has_genesis_id = true;
    stx.has_genesis_hash = hgh;
    Block {
        round: Round(1),
        genesis_id: GENESIS_ID.to_string(),
        genesis_hash: GENESIS_HASH,
        fee_sink: Address([0xFE; 32]),
        current_protocol: proto.to_string(),
        txn_counter: 1001,
        payset: vec![stx],
        ..Block::default()
    }
}

fn state() -> LedgerState {
    let mut s = LedgerState::new();
    s.fee_sink = Address([0xFE; 32]);
    s.get_or_default_account_mut(&Address([1u8; 32]))
        .micro_algos = 100_000_000;
    s
}

fn txid(txn: &Transaction) -> Digest {
    algo_codec::compute_txn_id(txn)
}

fn dup_cache(s: &LedgerState) -> TxTailDupCache {
    let mut c = TxTailDupCache::new();
    c.sync(1, |r| s.get_txtail(r).unwrap());
    c
}

#[test]
fn replay_pay_block_records_full_txid_on_hash_requiring_protocol() {
    let b = block(CONSENSUS_V41, false);
    let stripped_id = txid(&b.payset[0].txn);
    let mut full = b.payset[0].txn.clone();
    full.genesis_id = GENESIS_ID.to_string();
    full.genesis_hash = GENESIS_HASH;
    let full_id = txid(&full);
    assert_ne!(stripped_id, full_id);

    let mut s = state();
    apply_block_executing_app_calls(&mut s, &b).unwrap();
    let cache = dup_cache(&s);
    assert!(cache.contains(&full_id), "full txid must be in the txtail");
    assert!(
        !cache.contains(&stripped_id),
        "stripped-form id must not be"
    );
}

#[test]
fn hash_optional_protocol_without_hgh_keeps_gh_omitted_in_txid() {
    let b = block(CONSENSUS_V15, false);
    let mut full = b.payset[0].txn.clone();
    full.genesis_id = GENESIS_ID.to_string(); // hgi set; gh stays omitted
    let mut s = state();
    apply_block_executing_app_calls(&mut s, &b).unwrap();
    let cache = dup_cache(&s);
    assert!(cache.contains(&txid(&full)));
}

#[test]
fn hash_optional_protocol_with_hgh_restores_gh_in_txid() {
    let b = block(CONSENSUS_V15, true);
    let mut full = b.payset[0].txn.clone();
    full.genesis_id = GENESIS_ID.to_string();
    full.genesis_hash = GENESIS_HASH;
    let mut s = state();
    apply_block_executing_app_calls(&mut s, &b).unwrap();
    assert!(dup_cache(&s).contains(&txid(&full)));
}

#[test]
fn replay_and_execute_record_identical_txtail() {
    let b = block(CONSENSUS_V41, false);
    let mut replay = state();
    apply_block_with_mode(&mut replay, &b, ApplyMode::Replay).unwrap();
    let mut exec = state();
    apply_block_with_mode(&mut exec, &b, ApplyMode::Execute).unwrap();
    let r = replay.get_txtail(1).unwrap().expect("replay txtail");
    let e = exec.get_txtail(1).unwrap().expect("execute txtail");
    assert_eq!(r, e, "Replay and Execute must record identical txtail rows");
}

/// Issue #1728: a hash-optional protocol applied end to end in EXECUTE mode
/// (payment-only: apps predate V16 hash-optional blocks). The payment must
/// execute, and the txtail must hold the id of the txn as signed (gh
/// omitted) -- the same id the payset merkle leaf is built over.
#[test]
fn hash_optional_execute_apply_records_gh_less_txid_and_moves_funds() {
    let b = block(CONSENSUS_V15, false);
    let mut full = b.payset[0].txn.clone();
    full.genesis_id = GENESIS_ID.to_string();
    let mut s = state();
    apply_block_with_mode(&mut s, &b, ApplyMode::Execute).unwrap();
    assert!(dup_cache(&s).contains(&txid(&full)));
    assert_eq!(
        s.get_or_default_account_mut(&Address([2u8; 32]))
            .micro_algos,
        1_000_000,
        "the payment executed"
    );
    // The stored block stays stripped (no gen/gh leaks into storage).
    assert_eq!(b.payset[0].txn.genesis_id, "");
}

/// Issue #1728: go fails the decode with `consensus protocol %s not found`;
/// apply reports exactly that for an unknown protocol (every apply mode).
#[test]
fn apply_rejects_unknown_protocol_with_go_message() {
    let b = block("no-such-protocol", false);
    for mode in [ApplyMode::Replay, ApplyMode::Execute] {
        let mut s = state();
        let err = apply_block_with_mode(&mut s, &b, mode).unwrap_err();
        assert!(
            err.to_string()
                .contains("consensus protocol no-such-protocol not found"),
            "{mode:?}: {err}"
        );
    }
}
