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
    control_distinct_leases: OracleScenario,
    pool: Vec<OraclePool>,
}

/// go's pool-admission stage for one group (issue #2129): the evaluator's
/// `TestTransactionGroup`, then `TransactionGroup`.
#[derive(Debug, Deserialize)]
struct OraclePool {
    name: String,
    test_error: String,
    add_error: String,
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
    assert_eq!(o.scenarios.len(), 5);
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

/// The validator exactly as `participate.rs` wires it for agreement
/// (`algo_ledger::agreement_block_validator`, a `PayoutCheckingValidator`
/// around the `BlockValidatorBridge`). It includes the in-group lease conflict
/// (#2129), which no stateless check rejects. The go-signed blocks
/// pass the stateless checks, then go's `checkDup` rejects them.
#[test]
fn agreement_validator_wiring_rejects_like_go_validate() {
    let o = load_oracle();
    let block1 = block(&o.block1);
    let ledger = Arc::new(Mutex::new(sqlite(&o)));
    // The function the node's `participate` command assembles.
    let validator = algo_ledger::agreement_block_validator(
        o.genesis_id.clone(),
        b64(&o.genesis_hash).try_into().expect("genesis hash"),
        Some(block1.timestamp),
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
/// `apply_generated_block_capturing_apply_data_with_delta`; go's dev block comes from
/// a Generate + Validate evaluator, so a live-lease conflict is rejected and
/// the open block rolls back (issue #2127).
#[test]
fn dev_mode_commit_rejects_a_live_lease_and_rolls_back() {
    let o = load_oracle();
    let sc = scenario(&o, "cross_block_lease_conflict");
    let mut l = sqlite(&o);
    l.begin_block().expect("begin block");
    let err = algo_ledger::apply::apply_generated_block_capturing_apply_data_with_delta(
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

/// Every path that runs go's `checkDup` runs the same `Alive` before it
/// (`txn_prologue`, `algo_validate::block_alive` with go's text and the
/// genesis checks): the validating apply and block generation reject a
/// dead transaction with exactly the proposal check's message (#2127).
#[test]
fn validating_apply_and_generation_share_go_alive_text() {
    use algo_ledger::locked_base::LockedBase;
    use algo_ledger::pending_overlay::PendingOverlay;
    use algo_ledger::proposal_eval::{evaluate_group, GroupEvalError};
    use algo_types::Round;

    let o = load_oracle();
    let mut candidate = block(&scenario(&o, "committed_txid").block);
    candidate.payset[0].txn.last_valid = Round(1);
    let consensus =
        algo_types::consensus::consensus_params_for_version(&o.protocol).expect("protocol");
    let expected = algo_validate::block_alive(
        candidate.round.0,
        &candidate.genesis_id,
        &candidate.genesis_hash,
        &consensus,
        &candidate.payset[0].txn,
    )
    .expect_err("dead in round 2");

    let mut s = state(&o);
    let err = algo_ledger::apply_block_validating(&mut s, &candidate).expect_err("dead");
    assert_eq!(err.to_string(), expected, "validating apply");

    let shared = Arc::new(Mutex::new(sqlite(&o)));
    let base = LockedBase::new(&shared, Round(1));
    let mut template = candidate.clone();
    template.payset.clear();
    let mut overlay = PendingOverlay::new(&base);
    match evaluate_group(&base, &mut overlay, &template, &candidate.payset) {
        Err(GroupEvalError::Txn { index: 0, error }) => {
            assert_eq!(error.to_string(), expected, "generation")
        }
        other => panic!("evaluate_group: {other:?}"),
    }
}

/// go's validating evaluator runs the authorizer check after `checkDup` on
/// every path it validates, so the proposal check and block generation
/// reject a payment signed by the sender's old key after a rekey: "should
/// have been authorized by <new key>" (issue #2127).
#[test]
fn proposal_check_and_generation_run_the_authorizer_like_go() {
    use algo_ledger::locked_base::LockedBase;
    use algo_ledger::pending_overlay::PendingOverlay;
    use algo_ledger::proposal_eval::{evaluate_group, GroupEvalError};
    use algo_types::Round;

    let o = load_oracle();
    // A fresh payment from the funded sender (not a replay of block 1).
    let mut candidate = block(&scenario(&o, "committed_txid").block);
    candidate.payset[0].txn.note = serde_bytes::ByteBuf::from(b"after-rekey".to_vec());
    let sender = candidate.payset[0].txn.sender;
    let new_key = Address([0x4B; 32]);
    let txid = algo_codec::block_txids_with_rule(
        &candidate,
        &algo_types::genesis_restore::GenesisRestoreRule::for_block(&candidate),
    )[0];
    let expected = format!(
        "transaction {txid}: should have been authorized by {new_key} but was actually authorized by {sender}"
    );

    // The sender is rekeyed to `new_key` in the committed ledger.
    let mut l = sqlite(&o);
    let mut acct = l.get_account(&sender).expect("sender");
    acct.auth_addr = Some(new_key);
    l.set_account(&sender, acct);
    let ledger = Arc::new(Mutex::new(l));

    let validator = PayoutCheckingValidator::new(StubBlockValidator::accepting(), ledger.clone());
    match validator.validate(&candidate).map(|_| ()) {
        Err(AgreementError::ValidationFailed(message)) => assert_eq!(message, expected),
        other => panic!("proposal check: expected go's authorizer verdict, got {other:?}"),
    }

    let base = LockedBase::new(&ledger, Round(1));
    let mut template = candidate.clone();
    template.payset.clear();
    let mut overlay = PendingOverlay::new(&base);
    match evaluate_group(&base, &mut overlay, &template, &candidate.payset) {
        Err(GroupEvalError::Txn { index: 0, error }) => assert_eq!(error.to_string(), expected),
        other => panic!("generation: {other:?}"),
    }
}

/// A lease an earlier group of the same pending block holds is an in-block
/// conflict (go's block cow: `InBlockEvaluator`, pool tag `lease_eval`),
/// not a committed one (issue #2127).
#[test]
fn pending_block_lease_is_an_in_block_conflict() {
    use algo_ledger::locked_base::LockedBase;
    use algo_ledger::pending_overlay::PendingOverlay;
    use algo_ledger::proposal_eval::{evaluate_group, GroupEvalError};
    use algo_types::Round;

    let o = load_oracle();
    let sc = scenario(&o, "in_block_lease_conflict");
    let candidate = block(&sc.block);
    let shared = Arc::new(Mutex::new(sqlite(&o)));
    let base = LockedBase::new(&shared, Round(1));
    let mut template = candidate.clone();
    template.payset.clear();
    let mut overlay = PendingOverlay::new(&base);
    evaluate_group(&base, &mut overlay, &template, &candidate.payset[..1]).expect("first group");
    match evaluate_group(&base, &mut overlay, &template, &candidate.payset[1..]) {
        Err(GroupEvalError::Txn { index: 0, error }) => {
            assert_eq!(error.to_string(), sc.validate_error);
            assert!(
                matches!(
                    error,
                    algo_error::AlgoError::Rejected {
                        class: algo_error::RejectClass::LeaseInLedger { in_block: true },
                        ..
                    }
                ),
                "{error:?}"
            );
        }
        other => panic!("second group: {other:?}"),
    }
}

/// Pool re-evaluation hands its txids over (`evaluate_group_with_txids`):
/// `checkDup` still looks them up in the txtail, so a pending transaction
/// committed meanwhile is rejected with go's text (issue #2127).
#[test]
fn pool_supplied_txids_are_still_checked_against_the_txtail() {
    use algo_ledger::locked_base::LockedBase;
    use algo_ledger::pending_overlay::PendingOverlay;
    use algo_ledger::proposal_eval::{evaluate_group_with_txids, GroupEvalError};
    use algo_types::Round;

    let o = load_oracle();
    let sc = scenario(&o, "committed_txid");
    let candidate = block(&sc.block);
    let txids = algo_codec::block_txids_with_rule(
        &candidate,
        &algo_types::genesis_restore::GenesisRestoreRule::for_block(&candidate),
    );
    let shared = Arc::new(Mutex::new(sqlite(&o)));
    let base = LockedBase::new(&shared, Round(1));
    let mut template = candidate.clone();
    template.payset.clear();
    let mut overlay = PendingOverlay::new(&base);
    match evaluate_group_with_txids(
        &base,
        &mut overlay,
        &template,
        &candidate.payset,
        Some(txids),
    ) {
        Err(GroupEvalError::Txn { index: 0, error }) => {
            assert_eq!(error.to_string(), sc.validate_error)
        }
        other => panic!("{other:?}"),
    }
}

/// Inside a `begin_block` span that has applied rounds, the txid lookup
/// still sees the txids those rounds committed (the shared cache stops at
/// the span's starting round; the span's rows are read directly), and the
/// shared cache never moves backwards (issue #2127).
#[test]
fn sqlite_txid_lookup_sees_rounds_applied_in_the_open_span() {
    let o = load_oracle();
    let block1 = block(&o.block1);
    let committed = algo_codec::block_txids_with_rule(
        &block1,
        &algo_types::genesis_restore::GenesisRestoreRule::for_block(&block1),
    );
    let mut l = SqliteLedger::open_in_memory().expect("in-memory ledger");
    seed(&mut l, &o, |l, b| {
        l.begin_block().expect("begin span");
        // Warm the shared cache at the span's starting round.
        assert!(l.txtail_confirmed_txids(&committed, 1000).is_empty());
        algo_ledger::apply::apply_block(l, b).expect("apply round 1 in the span");
        // Still inside the span, after round 1.
        let found = l.txtail_confirmed_txids(&committed, 1000);
        assert_eq!(
            found.len(),
            committed.len(),
            "round 1's txids seen in the span"
        );
        assert!(l.txtail_contains_txid(&committed[0], 1000));
        l.commit_block().expect("commit span");
    });
    assert_eq!(
        l.txtail_confirmed_txids(&committed, 1000).len(),
        committed.len(),
        "and after the commit"
    );
}

/// A span opened on a ledger rewound below rounds the shared txid cache
/// already loaded does not see those discarded rounds' txids (issue #2127).
#[test]
fn sqlite_span_behind_the_shared_cache_ignores_discarded_rounds() {
    let o = load_oracle();
    let round2 = block(&scenario(&o, "cross_block_lease_conflict").block);
    let txids = algo_codec::block_txids_with_rule(
        &round2,
        &algo_types::genesis_restore::GenesisRestoreRule::for_block(&round2),
    );
    let mut l = sqlite(&o);
    l.begin_block().expect("begin block");
    algo_ledger::apply::apply_block(&mut l, &round2).expect("replay round 2");
    l.commit_block().expect("commit block");
    // The shared cache is synced to round 2.
    assert_eq!(l.txtail_confirmed_txids(&txids, 1000).len(), txids.len());

    // Rewind to round 1 and open a span there.
    l.set_current_round(algo_types::Round(1));
    l.begin_block().expect("begin span at round 1");
    assert!(
        l.txtail_confirmed_txids(&txids, 1000).is_empty(),
        "round 2 is not part of this chain"
    );
    assert!(!l.txtail_contains_txid(&txids[0], 1000));
    l.rollback_block().expect("rollback span");
}

/// go's `Alive` / `checkDup` judge the whole payset whatever the execution
/// does: a proposal whose first transaction cannot be evaluated here (an
/// overspend, a no-verdict) and whose second replays a committed txid is
/// still rejected with go's `checkDup` text, on the overlay check and on the
/// locked scratch check; a ledger busy past the budget never stalls the
/// validator (issue #2127).
#[test]
fn checkdup_verdict_survives_an_unevaluable_earlier_transaction() {
    use algo_ledger::shadow_execute::{scratch_proposal_check, ProposalCheck, ViolationKind};
    use std::time::Duration;

    let o = load_oracle();
    let sc = scenario(&o, "committed_txid");
    let mut candidate = block(&sc.block);
    let mut overspend = candidate.payset[0].clone();
    overspend.txn.note = serde_bytes::ByteBuf::from(b"overspend".to_vec());
    overspend.txn.amount = u64::MAX / 2;
    candidate.payset.insert(0, overspend);

    // The overspend alone is only a no-verdict: the payset cannot run here.
    let mut alone = candidate.clone();
    alone.payset.truncate(1);
    let mut l = sqlite(&o);
    assert!(
        matches!(
            scratch_proposal_check(&mut l, &alone),
            ProposalCheck::NoVerdict { .. }
        ),
        "the overspend is not a prologue verdict"
    );

    // Locked scratch check.
    assert_eq!(
        scratch_proposal_check(&mut l, &candidate),
        ProposalCheck::Violation {
            kind: ViolationKind::Transaction,
            message: sc.validate_error.clone(),
        }
    );
    assert_eq!(l.current_round().0, 1);

    // Overlay check, through the validator.
    let ledger = Arc::new(Mutex::new(l));
    let validator = PayoutCheckingValidator::new(StubBlockValidator::accepting(), ledger.clone());
    match validator.validate(&candidate).map(|_| ()) {
        Err(AgreementError::ValidationFailed(message)) => assert_eq!(message, sc.validate_error),
        other => panic!("overlay check: expected go's checkDup verdict, got {other:?}"),
    }

    // A ledger busy for the whole budget: the fallback pre-pass never waits
    // for the mutex (agreement must not stall), so the validator returns
    // within the budget on the stateless verdict.
    let budget = Duration::from_millis(30);
    let validator = PayoutCheckingValidator::with_budget(
        StubBlockValidator::accepting(),
        ledger.clone(),
        budget,
    );
    let hold = Duration::from_millis(1500);
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let holder = {
        let ledger = ledger.clone();
        std::thread::spawn(move || {
            let _guard = ledger.lock().unwrap();
            held_tx.send(()).unwrap();
            std::thread::sleep(hold);
        })
    };
    held_rx.recv().unwrap();
    let started = std::time::Instant::now();
    validator
        .validate(&candidate)
        .map(|_| ())
        .expect("busy ledger: no verdict, the stateless verdict stands");
    let took = started.elapsed();
    assert!(
        took < hold / 2,
        "the validator waited for the busy ledger ({took:?})"
    );
    holder.join().unwrap();

    // Free again: the proposal is judged and rejected.
    let validator =
        PayoutCheckingValidator::with_budget(StubBlockValidator::accepting(), ledger, budget);
    match validator.validate(&candidate).map(|_| ()) {
        Err(AgreementError::ValidationFailed(message)) => assert_eq!(message, sc.validate_error),
        other => panic!("free ledger: expected go's checkDup verdict, got {other:?}"),
    }
}

/// Issue #2129: go has no stateless group-lease rule. `validate_block` (the
/// stateless validator behind the offline `replay`/`bench` commands, which
/// stand in for go's `AddBlock` that never runs `checkDup`) accepts the block
/// whose group holds two (sender, lease) twins, exactly as go's replay does;
/// the lease conflict is `checkDup`'s, in the validating paths only.
#[test]
fn stateless_validation_accepts_an_in_group_lease_conflict_like_go_replay() {
    let o = load_oracle();
    let block1 = block(&o.block1);
    let sc = scenario(&o, "in_group_lease_conflict");
    assert!(sc.replay_error.is_empty() && !sc.validate_error.is_empty());
    let candidate = block(&sc.block);
    let grp = candidate.payset[0].txn.group;
    assert!(
        grp != [0u8; 32] && grp == candidate.payset[1].txn.group,
        "the oracle block holds one two-member group"
    );
    assert_eq!(candidate.payset[0].txn.lease, candidate.payset[1].txn.lease);
    let result = algo_validate::validate_block(
        &candidate,
        Some(block1.timestamp),
        &o.genesis_id,
        &b64(&o.genesis_hash).try_into().expect("genesis hash"),
        None,
    );
    assert!(result.is_valid, "stateless verdict: {:?}", result.errors);
}

/// Issue #2129: a group with distinct leases is accepted everywhere, by go
/// and here (control for the in-group conflict scenario).
#[test]
fn in_group_distinct_leases_are_accepted_on_every_path_like_go() {
    let o = load_oracle();
    let sc = &o.control_distinct_leases;
    assert!(sc.validate_error.is_empty() && sc.replay_error.is_empty());
    let candidate = block(&sc.block);
    let mut s = state(&o);
    algo_ledger::apply_block_validating(&mut s, &candidate).expect("validating apply accepts");
    assert_eq!(s.current_round().0, 2);

    let block1 = block(&o.block1);
    let result = algo_validate::validate_block(
        &candidate,
        Some(block1.timestamp),
        &o.genesis_id,
        &b64(&o.genesis_hash).try_into().expect("genesis hash"),
        None,
    );
    assert!(result.is_valid, "{:?}", result.errors);
}

/// Issue #2129: go's pool admission (a Generate+Validate evaluator):
/// `TestTransactionGroup` checks each member against the unmodified state, so
/// it cannot see a sibling's lease; `TransactionGroup` applies the members in
/// order and rejects the second with `LeaseInLedgerError`. The group
/// evaluation behind the pool (`evaluate_group`) must give go's `add_error`.
///
/// The Rust pool's per-transaction test stage is stateless and has no
/// ledger-backed `checkDup` of its own yet (#2130's subject), so this test
/// asserts go's recorded test-stage verdict (accepted) here, and the bin
/// crate's `in_group_lease_conflict_passes_the_test_stage_and_fails_the_apply_stage`
/// (`participate_exec_tests.rs`) runs the Rust evaluator's `test_transaction_group`
/// and `transaction_group` on the same shape of group.
#[test]
fn group_evaluation_matches_go_pool_admission() {
    use algo_ledger::locked_base::LockedBase;
    use algo_ledger::pending_overlay::PendingOverlay;
    use algo_ledger::proposal_eval::{evaluate_group, GroupEvalError};
    use algo_types::Round;

    let o = load_oracle();
    for (name, candidate) in [
        (
            "in_group_lease_conflict",
            block(&scenario(&o, "in_group_lease_conflict").block),
        ),
        (
            "in_group_distinct_leases",
            block(&o.control_distinct_leases.block),
        ),
    ] {
        let go = o.pool.iter().find(|p| p.name == name).expect("pool row");
        assert!(go.test_error.is_empty(), "{name}: go's Test passes");
        let shared = Arc::new(Mutex::new(sqlite(&o)));
        let base = LockedBase::new(&shared, Round(1));
        let mut template = candidate.clone();
        template.payset.clear();
        let mut overlay = PendingOverlay::new(&base);
        let got = evaluate_group(&base, &mut overlay, &template, &candidate.payset);
        if go.add_error.is_empty() {
            got.unwrap_or_else(|e| panic!("{name}: {e:?}"));
        } else {
            match got {
                Err(GroupEvalError::Txn { index: 1, error }) => {
                    assert_eq!(error.to_string(), go.add_error, "{name}")
                }
                other => panic!("{name}: expected go's rejection of member 1, got {other:?}"),
            }
        }
    }
}

/// The scenarios whose conflict lies inside the block itself: in one group
/// (issue #2129) and across two groups.
const IN_BLOCK_CONFLICTS: [&str; 2] = ["in_group_lease_conflict", "in_block_lease_conflict"];

fn expect_go_rejection<V: BlockValidator>(validator: &V, o: &Oracle, candidate: &Block, why: &str) {
    for name in IN_BLOCK_CONFLICTS {
        let sc = scenario(o, name);
        let mut candidate = candidate.clone();
        candidate.payset = block(&sc.block).payset;
        match validator.validate(&candidate).map(|_| ()) {
            Err(AgreementError::ValidationFailed(message)) => {
                assert_eq!(message, sc.validate_error, "{why}: {name}")
            }
            other => panic!("{why}: {name}: expected go's checkDup verdict, got {other:?}"),
        }
    }
}

/// Issue #2129: with the stateless group-lease rule gone, an in-block
/// lease conflict (in a group or across groups) must still be rejected before
/// the vote in EVERY case where the stateful proposal check reaches no
/// verdict. The block's own duplicates need no ledger, so the last-resort
/// pre-pass judges them with go's text. Cases: the ledger busy for the whole
/// budget, behind the proposal, poisoned, the scratch evaluation
/// unavailable, and a payset member not evaluable here.
#[test]
fn in_block_lease_conflict_is_rejected_when_the_proposal_check_has_no_verdict() {
    use algo_ledger::shadow_execute::test_hooks;
    use std::time::Duration;

    let o = load_oracle();
    let base = block(&scenario(&o, "in_group_lease_conflict").block);
    let budget = Duration::from_millis(30);
    let make = |ledger: &Arc<Mutex<SqliteLedger>>| {
        PayoutCheckingValidator::with_budget(
            StubBlockValidator::accepting(),
            ledger.clone(),
            budget,
        )
    };

    // Control: with a free ledger the full check judges it.
    let ledger = Arc::new(Mutex::new(sqlite(&o)));
    expect_go_rejection(&make(&ledger), &o, &base, "free ledger");

    // Busy for the whole budget (and the pre-pass's try_lock): no ledger.
    let hold = Duration::from_millis(1500);
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let holder = {
        let ledger = ledger.clone();
        std::thread::spawn(move || {
            let _guard = ledger.lock().unwrap();
            held_tx.send(()).unwrap();
            std::thread::sleep(hold);
        })
    };
    held_rx.recv().unwrap();
    let started = std::time::Instant::now();
    expect_go_rejection(&make(&ledger), &o, &base, "busy ledger");
    assert!(
        started.elapsed() < hold / 2,
        "never waits for a busy ledger"
    );
    holder.join().unwrap();

    // Behind the proposal: the ledger is at round 1, the proposal is for 5.
    let mut stale = base.clone();
    stale.round = algo_types::Round(5);
    expect_go_rejection(&make(&ledger), &o, &stale, "stale ledger");

    // Poisoned ledger lock.
    let poisoned = Arc::new(Mutex::new(sqlite(&o)));
    {
        let l = poisoned.clone();
        let _ = std::thread::spawn(move || {
            let _guard = l.lock().unwrap();
            panic!("poison the ledger lock");
        })
        .join();
    }
    assert!(poisoned.is_poisoned());
    expect_go_rejection(&make(&poisoned), &o, &base, "poisoned ledger");

    // Scratch evaluation unavailable (transient failure on every attempt).
    test_hooks::inject_failure_over_payset_len(Some(0));
    let ledger = Arc::new(Mutex::new(sqlite(&o)));
    expect_go_rejection(&make(&ledger), &o, &base, "scratch unavailable");
    test_hooks::inject_failure_over_payset_len(None);

    // A payset member that cannot be evaluated here comes first.
    let mut overspend = base.payset[0].clone();
    overspend.txn.note = serde_bytes::ByteBuf::from(b"overspend".to_vec());
    overspend.txn.amount = u64::MAX / 2;
    overspend.txn.group = [0u8; 32];
    overspend.txn.lease = [0u8; 32];
    let mut unevaluable = base.clone();
    unevaluable.payset.insert(0, overspend.clone());
    let ledger = Arc::new(Mutex::new(sqlite(&o)));
    for name in IN_BLOCK_CONFLICTS {
        let sc = scenario(&o, name);
        let mut c = unevaluable.clone();
        c.payset.truncate(1);
        c.payset.extend(block(&sc.block).payset);
        match make(&ledger).validate(&c).map(|_| ()) {
            Err(AgreementError::ValidationFailed(m)) => assert_eq!(m, sc.validate_error, "{name}"),
            other => panic!("unevaluable member: {name}: {other:?}"),
        }
        // ...also with the ledger busy.
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let holder = {
            let ledger = ledger.clone();
            std::thread::spawn(move || {
                let _guard = ledger.lock().unwrap();
                held_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(300));
            })
        };
        held_rx.recv().unwrap();
        match make(&ledger).validate(&c).map(|_| ()) {
            Err(AgreementError::ValidationFailed(m)) => assert_eq!(m, sc.validate_error, "{name}"),
            other => panic!("unevaluable member, busy ledger: {name}: {other:?}"),
        }
        holder.join().unwrap();
    }
}

/// Residual window of the no-verdict fallback, as before #2129: a conflict
/// with the COMMITTED ledger (a replayed txid, a live lease) needs the
/// ledger, so with the ledger unavailable the proposal is accepted on the
/// stateless verdict. The block's own duplicates do not (test above), and the
/// distinct-lease control is not rejected by the block-only pre-pass.
#[test]
fn block_dups_prepass_judges_only_the_blocks_own_duplicates() {
    use algo_ledger::check_dup::{block_dups_prepass, Prepass};

    let o = load_oracle();
    for name in IN_BLOCK_CONFLICTS {
        let sc = scenario(&o, name);
        assert_eq!(
            block_dups_prepass(&block(&sc.block)),
            Prepass::Violation(sc.validate_error.clone()),
            "{name}"
        );
    }
    for name in ["committed_txid", "cross_block_lease_conflict"] {
        assert_eq!(
            block_dups_prepass(&block(&scenario(&o, name).block)),
            Prepass::Clean,
            "{name}: needs the committed ledger"
        );
    }
    assert_eq!(
        block_dups_prepass(&block(&o.control_distinct_leases.block)),
        Prepass::Clean
    );
}

/// "Could not run" is told apart from "checked and clean" (issue #2129), for
/// both pre-passes: an unknown protocol and a payset that is not in
/// stripped form say nothing about the block.
#[test]
fn prepasses_report_could_not_run_instead_of_clean() {
    use algo_ledger::check_dup::{block_dups_prepass, prologue_prepass, Prepass};

    let o = load_oracle();
    let ledger = sqlite(&o);
    let good = block(&scenario(&o, "in_group_lease_conflict").block);

    let mut unknown = good.clone();
    unknown.current_protocol = "no-such-protocol".into();
    for (name, verdict) in [
        ("block-only", block_dups_prepass(&unknown)),
        ("ledger-backed", prologue_prepass(&ledger, &unknown)),
    ] {
        match verdict {
            Prepass::CouldNotRun(reason) => {
                assert!(reason.contains("unknown protocol"), "{name}: {reason}")
            }
            other => panic!("{name}: {other:?}"),
        }
    }

    // A payset member still carrying its genesis id/hash is not in the
    // block's stripped form.
    let mut unstripped = good.clone();
    unstripped.payset[0].txn.genesis_id = o.genesis_id.clone();
    unstripped.payset[0].txn.genesis_hash = b64(&o.genesis_hash).try_into().expect("hash");
    for (name, verdict) in [
        ("block-only", block_dups_prepass(&unstripped)),
        ("ledger-backed", prologue_prepass(&ledger, &unstripped)),
    ] {
        assert!(
            matches!(verdict, Prepass::CouldNotRun(_)),
            "{name}: {verdict:?}"
        );
    }

    // The ledger-backed pre-pass judges the same conflict, with the same text.
    assert_eq!(
        prologue_prepass(&ledger, &good),
        Prepass::Violation(
            scenario(&o, "in_group_lease_conflict")
                .validate_error
                .clone()
        )
    );
}
