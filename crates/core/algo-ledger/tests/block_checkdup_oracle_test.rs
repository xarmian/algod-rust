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

//! go-algorand oracle parity for `checkDup` in block validation (issue
//! #2127).
//!
//! go evaluates a block with `Validate: true` when it validates a proposal
//! (`Ledger.Validate`), and with `Validate: false` when it adds a certified
//! block (`Ledger.AddBlock`, catchup). Only the validating evaluation runs
//! `BlockEvaluator.transaction`'s `checkDup`. So a block that replays a
//! committed transaction, repeats one, or reuses a live lease is rejected by
//! `Validate` and accepted by `AddBlock`.
//!
//! `tests/fixtures/block_checkdup/oracle.json` is the real go output
//! (`tools/simulate-rewards-oracle`, `blockdup.go`): the genesis, go's block
//! 1, and per scenario a round-2 block with go's `Validate` error and its
//! `eval.Eval(validate=false)` result. This test checks the same blocks
//! against validate-mode apply, the agreement proposal validator and the
//! replay apply.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use algo_agreement::{AgreementError, BlockValidator, StubBlockValidator};
use algo_ledger::proposal_validator::PayoutCheckingValidator;
use algo_ledger::sqlite::SqliteLedger;
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::{AccountData, AccountStatus, Address, Block};
use base64::Engine as _;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OracleAccount {
    addr: String,
    status: String,
    micro_algos: u64,
}

#[derive(Debug, Deserialize)]
struct OracleScenario {
    name: String,
    block: String,
    validate_error: String,
    replay_error: String,
}

#[derive(Debug, Deserialize)]
struct Oracle {
    protocol: String,
    genesis_id: String,
    genesis_hash: String,
    fee_sink: String,
    rewards_pool: String,
    genesis_accounts: Vec<OracleAccount>,
    block1: String,
    scenarios: Vec<OracleScenario>,
}

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("fixture base64")
}

fn addr(s: &str) -> Address {
    Address(b64(s).try_into().expect("32-byte address"))
}

fn load_oracle() -> Oracle {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/block_checkdup/oracle.json");
    let raw = std::fs::read_to_string(&path).expect("read oracle fixture");
    serde_json::from_str(&raw).expect("parse oracle fixture")
}

fn block(s: &str) -> Block {
    algo_codec::decode_block(&b64(s)).expect("decode go block")
}

/// The go genesis and go's block 1, applied through the replay path.
fn seed<L: LedgerStore>(store: &mut L, o: &Oracle, apply: impl FnOnce(&mut L, &Block)) {
    store.set_protocol(o.protocol.clone());
    store.set_genesis_id(o.genesis_id.clone());
    store.set_genesis_hash(b64(&o.genesis_hash).try_into().expect("genesis hash"));
    store.set_fee_sink(addr(&o.fee_sink));
    store.set_rewards_pool(addr(&o.rewards_pool));
    for a in &o.genesis_accounts {
        let status = match a.status.as_str() {
            "Offline" => AccountStatus::Offline,
            "Not Participating" => AccountStatus::NotParticipating,
            other => panic!("unknown status {other}"),
        };
        store.set_account(
            &addr(&a.addr),
            AccountData {
                status,
                micro_algos: a.micro_algos,
                ..Default::default()
            },
        );
    }
    apply(store, &block(&o.block1));
    assert_eq!(store.current_round().0, 1);
}

fn state(o: &Oracle) -> LedgerState {
    let mut s = LedgerState::new();
    seed(&mut s, o, |s, b| {
        algo_ledger::apply::apply_block(s, b).expect("apply go block 1")
    });
    s
}

fn sqlite(o: &Oracle) -> SqliteLedger {
    let mut l = SqliteLedger::open_in_memory().expect("in-memory ledger");
    seed(&mut l, o, |l, b| {
        l.begin_block().expect("begin block");
        algo_ledger::apply::apply_block(l, b).expect("apply go block 1");
        l.commit_block().expect("commit block");
    });
    l
}

/// The oracle scenarios all fail go's `Validate` and pass its replay.
#[test]
fn oracle_scenarios_are_validate_failures_that_replay_accepts() {
    let o = load_oracle();
    assert_eq!(o.scenarios.len(), 4);
    for sc in &o.scenarios {
        assert!(!sc.validate_error.is_empty(), "{}", sc.name);
        assert!(
            sc.replay_error.is_empty(),
            "{}: {}",
            sc.name,
            sc.replay_error
        );
    }
}

/// Validate-mode block apply (go `eval.Eval(..., validate=true, ...)`)
/// rejects each block with go's exact error.
#[test]
fn validating_apply_rejects_like_go_validate() {
    let o = load_oracle();
    for sc in &o.scenarios {
        let mut s = state(&o);
        let err = algo_ledger::apply_block_validating(&mut s, &block(&sc.block))
            .expect_err(&format!("{}: validating apply must reject", sc.name));
        assert_eq!(err.to_string(), sc.validate_error, "{}", sc.name);
        assert_eq!(s.current_round().0, 1, "{}: nothing committed", sc.name);
    }
}

/// The replay apply (go `Ledger.AddBlock`, `validate=false`) accepts each
/// block, as go does.
#[test]
fn replay_apply_accepts_like_go_add_block() {
    let o = load_oracle();
    for sc in &o.scenarios {
        let mut s = state(&o);
        algo_ledger::apply::apply_block(&mut s, &block(&sc.block))
            .unwrap_or_else(|e| panic!("{}: replay must accept: {e}", sc.name));
        assert_eq!(s.current_round().0, 2, "{}", sc.name);
    }
}

/// The agreement proposal validator (go `Ledger.Validate` on a proposal)
/// rejects each block with go's error, against the `SqliteLedger`'s
/// txtail cache.
#[test]
fn proposal_validator_rejects_like_go_validate() {
    let o = load_oracle();
    let ledger = Arc::new(Mutex::new(sqlite(&o)));
    let validator = PayoutCheckingValidator::new(StubBlockValidator::accepting(), ledger.clone());
    for sc in &o.scenarios {
        let err = validator
            .validate(&block(&sc.block))
            .map(|_| ())
            .expect_err(&format!("{}: the proposal must be rejected", sc.name));
        match err {
            AgreementError::ValidationFailed(message) => {
                assert_eq!(message, sc.validate_error, "{}", sc.name)
            }
            other => panic!("{}: unexpected error {other:?}", sc.name),
        }
        assert_eq!(ledger.lock().unwrap().current_round().0, 1, "{}", sc.name);
    }
}

/// The validator exactly as `participate.rs` wires it for agreement:
/// `PayoutCheckingValidator<BlockValidatorBridge>`. The go-signed blocks
/// pass the stateless checks, then go's `checkDup` rejects them.
#[test]
fn agreement_validator_wiring_rejects_like_go_validate() {
    let o = load_oracle();
    let block1 = block(&o.block1);
    let ledger = Arc::new(Mutex::new(sqlite(&o)));
    let validator = PayoutCheckingValidator::new(
        algo_agreement::BlockValidatorBridge::new(
            o.genesis_id.clone(),
            b64(&o.genesis_hash).try_into().expect("genesis hash"),
            Some(block1.timestamp),
        ),
        ledger,
    );
    for sc in &o.scenarios {
        match validator.validate(&block(&sc.block)).map(|_| ()) {
            Err(AgreementError::ValidationFailed(message)) => {
                assert_eq!(message, sc.validate_error, "{}", sc.name)
            }
            other => panic!("{}: expected go's rejection, got {other:?}", sc.name),
        }
    }
}
