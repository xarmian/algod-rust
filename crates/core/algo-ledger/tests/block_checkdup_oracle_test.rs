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

fn scenario<'a>(o: &'a Oracle, name: &str) -> &'a OracleScenario {
    o.scenarios
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("scenario {name}"))
}

/// go generates blocks with `StartEvaluator(..., Generate + Validate)`, so
/// its block assembly runs `checkDup` against the live ledger, not against
/// whatever the pool admitted. The proposer's final scratch apply
/// (`scratch_execute_payset`), the overlay payset evaluation
/// (`evaluate_payset`) and the pool's per-group evaluation
/// (`evaluate_group`, behind `exec_group`) all reject a transaction reusing
/// a lease the committed ledger holds (issue #2127).
#[test]
fn block_generation_rejects_a_live_lease_like_go() {
    use algo_ledger::locked_base::LockedBase;
    use algo_ledger::pending_overlay::PendingOverlay;
    use algo_ledger::proposal_eval::{evaluate_group, evaluate_payset, GroupEvalError};
    use algo_ledger::shadow_execute::{scratch_execute_payset, ScratchFailure};
    use algo_types::Round;

    let o = load_oracle();
    let sc = scenario(&o, "cross_block_lease_conflict");
    let candidate = block(&sc.block);

    let expect_lease = |error: &algo_error::AlgoError, path: &str| {
        assert_eq!(error.to_string(), sc.validate_error, "{path}");
    };

    // The proposer's final scratch apply on the locked ledger.
    let mut l = sqlite(&o);
    match scratch_execute_payset(&mut l, &candidate, None) {
        Err(ScratchFailure::Txn { index: 0, error }) => expect_lease(&error, "scratch"),
        other => panic!("scratch_execute_payset: {other:?}"),
    }
    assert_eq!(l.current_round().0, 1);

    // The overlay evaluations, through the same LockedBase the node uses.
    let shared = Arc::new(Mutex::new(l));
    let base = LockedBase::new(&shared, Round(1));
    match evaluate_payset(&base, &candidate, None) {
        Err(ScratchFailure::Txn { index: 0, error }) => expect_lease(&error, "evaluate_payset"),
        other => panic!("evaluate_payset: {other:?}"),
    }
    let mut template = candidate.clone();
    template.payset.clear();
    let mut overlay = PendingOverlay::new(&base);
    match evaluate_group(&base, &mut overlay, &template, &candidate.payset) {
        Err(GroupEvalError::Txn { index: 0, error }) => expect_lease(&error, "evaluate_group"),
        other => panic!("evaluate_group: {other:?}"),
    }
}

/// The dev-mode producer commits through
/// `apply_block_capturing_apply_data_with_delta`; go's dev block comes from
/// a Generate + Validate evaluator, so a live-lease conflict is rejected and
/// the open block rolls back (issue #2127).
#[test]
fn dev_mode_commit_rejects_a_live_lease_and_rolls_back() {
    let o = load_oracle();
    let sc = scenario(&o, "cross_block_lease_conflict");
    let mut l = sqlite(&o);
    l.begin_block().expect("begin block");
    let err = algo_ledger::apply::apply_block_capturing_apply_data_with_delta(
        &mut l,
        &block(&sc.block),
        algo_ledger::ApplyMode::Execute,
    )
    .map(|_| ())
    .expect_err("the dev-mode commit must reject the lease conflict");
    assert_eq!(err.to_string(), sc.validate_error);
    l.rollback_block().expect("rollback block");
    assert_eq!(l.current_round().0, 1, "nothing committed");
}

/// The agreement proposal check runs go's `Alive` before `checkDup`, on its
/// own (the inner validator here accepts everything): a dead transaction is
/// rejected with go's `Alive` text, not the txtail low-water-mark error a
/// bare `checkDup` would give (issue #2127).
#[test]
fn proposal_check_rejects_a_dead_transaction_with_go_alive_text() {
    let o = load_oracle();
    let mut candidate = block(&scenario(&o, "committed_txid").block);
    candidate.payset[0].txn.last_valid = algo_types::Round(1);
    let consensus =
        algo_types::consensus::consensus_params_for_version(&o.protocol).expect("protocol");
    let expected = algo_validate::block_alive(
        candidate.round.0,
        &candidate.genesis_id,
        &candidate.genesis_hash,
        &consensus,
        &candidate.payset[0].txn,
    )
    .expect_err("the transaction is dead in round 2");
    assert!(expected.contains("dead"), "{expected}");

    let ledger = Arc::new(Mutex::new(sqlite(&o)));
    let validator = PayoutCheckingValidator::new(StubBlockValidator::accepting(), ledger);
    match validator.validate(&candidate).map(|_| ()) {
        Err(AgreementError::ValidationFailed(message)) => assert_eq!(message, expected),
        other => panic!("expected go's Alive verdict, got {other:?}"),
    }
}
