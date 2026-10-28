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

//! Port of go-algorand's `TestCloseMinBalancePolicy` (`ledger/close_test.go`,
//! v5.0.4-stable, issue #2023).
//!
//! While *generating* (pool admission, block assembly -- here
//! [`evaluate_group`], the pool's path), a close-out of an account whose
//! minimum balance is still above the base amount is refused by
//! `check_close_min_balance`, whatever the protocol. *Validation* (applying a
//! block) accepts such a close before `CloseRequiresBaseMinBalance` (v43) and
//! rejects it from v43 on -- so the policy never changes how a node votes.

use algo_ledger::pending_overlay::PendingOverlay;
use algo_ledger::proposal_eval::{evaluate_group, GroupEvalError};
use algo_ledger::{apply_block_capturing_apply_data, ApplyMode, LedgerStore, SqliteLedger};
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V42, CONSENSUS_V43};
use algo_types::{AccountData, Address, Block, Round, SignedTransaction, StateSchema};

const FEE: u64 = 1_000;
const SPONSOR_FUNDS: u64 = 400_000;

fn addr(b: u8) -> Address {
    Address([b; 32])
}

fn assemble(source: &str) -> Vec<u8> {
    algo_avm::assembler::assemble_string(source)
        .unwrap_or_else(|e| panic!("assembly failed: {e:?}\nsource:\n{source}"))
        .program
}

fn pay(sender: Address, receiver: Address, amount: u64) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "pay".into();
    stx.txn.sender = sender;
    stx.txn.receiver = receiver;
    stx.txn.amount = amount;
    stx.txn.fee = FEE;
    stx
}

fn appl_create(
    sender: Address,
    app_id: u64,
    approval_src: &str,
    global_schema: Option<StateSchema>,
) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "appl".into();
    stx.txn.sender = sender;
    stx.txn.fee = FEE;
    stx.txn.approval_program = Some(serde_bytes::ByteBuf::from(assemble(approval_src)));
    stx.txn.clear_state_program = Some(serde_bytes::ByteBuf::from(assemble(APPROVE_SRC)));
    stx.txn.global_state_schema = global_schema;
    stx.apply_data_application_id = app_id;
    stx
}

fn appl_call(sender: Address, app_id: u64, on_completion: u64) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "appl".into();
    stx.txn.sender = sender;
    stx.txn.fee = FEE;
    stx.txn.application_id = app_id;
    stx.txn.on_completion = on_completion;
    stx
}

const APPROVE_SRC: &str = "#pragma version 8\nint 1\n";

/// go's `closer` app: `"update"` sponsors `Applications 1` through an inner
/// resize; `"close"` closes the app's own account to `Accounts 1` through an
/// inner payment.
const CLOSER_SRC: &str = "\
#pragma version 8
txn ApplicationID
bz end
txn ApplicationArgs 0
byte \"close\"
==
bnz close
itxn_begin
int appl
itxn_field TypeEnum
txn Applications 1
itxn_field ApplicationID
int UpdateApplication
itxn_field OnCompletion
txn Applications 1
app_params_get AppApprovalProgram
assert
itxn_field ApprovalProgram
txn Applications 1
app_params_get AppClearStateProgram
assert
itxn_field ClearStateProgram
int 1
itxn_field ExtraProgramPages
itxn_submit
b end
close:
itxn_begin
int pay
itxn_field TypeEnum
txn Accounts 1
itxn_field Receiver
txn Accounts 1
itxn_field CloseRemainderTo
itxn_submit
end:
int 1
";

const ON_COMPLETION_UPDATE: u64 = 4;
const ON_COMPLETION_DELETE: u64 = 5;

/// go's `DoubleLedger` in miniature: one ledger, with the generating path
/// (`evaluate_group` on a pending overlay, as the pool admits a group) and
/// the validating path (applying a block) exposed separately.
struct Harness {
    l: SqliteLedger,
    proto: &'static str,
    fee_sink: Address,
    rewards_pool: Address,
}

impl Harness {
    fn new(proto: &'static str, funded: &[(Address, u64)]) -> Self {
        let mut l = SqliteLedger::open_in_memory().unwrap();
        let fee_sink = addr(0xF1);
        let rewards_pool = addr(0xF2);
        l.set_fee_sink(fee_sink);
        l.set_rewards_pool(rewards_pool);
        // Issue #2116: the block-start withdrawal needs a pool at MinBalance.
        fund_rewards_pool(&mut l);
        l.set_protocol(proto.to_string());
        for (a, amount) in funded {
            l.set_account(
                a,
                AccountData {
                    micro_algos: *amount,
                    ..Default::default()
                },
            );
        }
        Self {
            l,
            proto,
            fee_sink,
            rewards_pool,
        }
    }

    fn template(&self) -> Block {
        Block {
            round: Round(self.l.current_round().0 + 1),
            current_protocol: self.proto.to_string(),
            fee_sink: self.fee_sink,
            rewards_pool: self.rewards_pool,
            ..Block::default()
        }
    }

    /// Validation only (go `SetGenerateForTesting(false)`): apply `txns` as the
    /// next block.
    fn validate(&mut self, txns: Vec<SignedTransaction>) -> Result<(), String> {
        let mut block = self.template();
        block.payset = txns;
        apply_block_capturing_apply_data(&mut self.l, &block, ApplyMode::Execute)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// go `dl.txn`: admit `txn` as the pool would (generating), then commit
    /// it as a block (validating). Returns the generating verdict.
    fn generate(&mut self, txn: SignedTransaction) -> Result<(), String> {
        let template = self.template();
        let mut overlay = PendingOverlay::new(&self.l);
        match evaluate_group(&self.l, &mut overlay, &template, std::slice::from_ref(&txn)) {
            Ok(_) => {}
            Err(GroupEvalError::Txn { error, .. }) => return Err(error.to_string()),
            Err(other) => panic!("group evaluation did not reach a verdict: {other:?}"),
        }
        drop(overlay);
        self.validate(vec![txn])
            .expect("a group the pool admitted must also validate as a block");
        Ok(())
    }

    fn account(&self, a: Address) -> AccountData {
        self.l.get_account(&a).unwrap_or_default()
    }

    fn size_sponsor(&self, app_id: u64) -> Address {
        self.l
            .get_app_params(app_id)
            .expect("app exists")
            .size_sponsor
    }
}

fn close_min_balance_policy(proto: &'static str) {
    let consensus = consensus_params_for_version(proto).unwrap();
    let creator = addr(0x10);
    let sponsor = addr(0x01);
    let sink = addr(0x04);
    let plain = addr(0x02);
    let plain_to = addr(0x03);
    let app_id = 900u64;
    let closer_id = 901u64;
    let closer_addr = Address(algo_ledger::avm_context::app_address(closer_id));

    let mut h = Harness::new(
        proto,
        &[
            (creator, 50_000_000),
            (sponsor, SPONSOR_FUNDS),
            (sink, 200_000),
            (plain, 1_000_000),
            (plain_to, 1_000_000),
            (closer_addr, 3_000_000),
        ],
    );

    h.generate(appl_create(
        creator,
        app_id,
        APPROVE_SRC,
        Some(StateSchema {
            num_uint: 1,
            num_byte_slice: 0,
        }),
    ))
    .expect("create app");

    // A third party takes over responsibility for the app's size.
    let mut sponsor_update = appl_call(sponsor, app_id, ON_COMPLETION_UPDATE);
    sponsor_update.txn.approval_program = Some(serde_bytes::ByteBuf::from(assemble(APPROVE_SRC)));
    sponsor_update.txn.clear_state_program =
        Some(serde_bytes::ByteBuf::from(assemble(APPROVE_SRC)));
    sponsor_update.txn.extra_program_pages = 1;
    sponsor_update.txn.global_state_schema = Some(StateSchema {
        num_uint: 1,
        num_byte_slice: 0,
    });
    h.generate(sponsor_update).expect("sponsor resize");
    assert_eq!(h.size_sponsor(app_id), sponsor);
    let rec = h.account(sponsor);
    assert!(algo_ledger::params::min_balance(&rec) > consensus.min_balance);
    assert_eq!(rec.micro_algos, SPONSOR_FUNDS - FEE);

    // Leaves ClosingAmount at zero.
    let mut close = pay(sponsor, sink, SPONSOR_FUNDS - 2 * FEE);
    close.txn.close_remainder_to = sink;

    // Generating: refused, whatever the protocol.
    let err = h.generate(close.clone()).unwrap_err();
    assert!(err.contains("cannot close"), "{err}");
    if consensus.close_requires_base_min_balance {
        assert!(err.contains("cannot close: min balance"), "{err}");
    } else {
        assert!(
            err.contains(&format!(
                "cannot close: account {sponsor} requires a minimum balance of"
            )),
            "{err}"
        );
    }
    assert_eq!(
        h.account(sponsor),
        rec,
        "a refused group leaves nothing behind"
    );

    // An ordinary account with only the base minimum balance still closes.
    let mut plain_close = pay(plain, plain_to, 0);
    plain_close.txn.close_remainder_to = plain_to;
    h.generate(plain_close).expect("base-MBR account closes");
    assert_eq!(h.account(plain), AccountData::default());

    // Validation only: older protocols accept the close;
    // CloseRequiresBaseMinBalance rejects it even during validation.
    if consensus.close_requires_base_min_balance {
        let err = h.validate(vec![close.clone()]).unwrap_err();
        assert!(err.contains("cannot close: min balance"), "{err}");
        let acct = h.account(sponsor);
        assert_eq!(acct.micro_algos, rec.micro_algos);
        assert_eq!(acct.total_app_schema, rec.total_app_schema);
        assert_eq!(acct.total_extra_app_pages, rec.total_extra_app_pages);
    } else {
        h.validate(vec![close.clone()])
            .expect("pre-v43 validation accepts the close");
        assert_eq!(h.account(sponsor), AccountData::default());
    }
    let params = h.l.get_app_params(app_id).unwrap();
    assert_eq!(params.global_state_schema.num_uint, 1);
    assert_eq!(params.size_sponsor, sponsor);

    // Inner transactions reach the apply through the AVM context rather than
    // the top-level dispatch, so the policy must hold there too: the closer
    // app sponsors `app_id` with an inner update, then tries to close itself
    // with an inner payment.
    h.generate(appl_create(creator, closer_id, CLOSER_SRC, None))
        .expect("create closer");
    let call_closer = |arg: &str| {
        let mut call = appl_call(creator, closer_id, 0);
        call.txn.app_arguments = Some(vec![Some(serde_bytes::ByteBuf::from(arg.as_bytes()))]);
        call.txn.foreign_apps = Some(vec![app_id]);
        call.txn.accounts = Some(vec![sink]);
        call
    };
    h.generate(call_closer("update")).expect("inner resize");
    assert_eq!(h.size_sponsor(app_id), closer_addr);
    let err = h.generate(call_closer("close")).unwrap_err();
    assert!(err.contains("cannot close"), "{err}");
    if !consensus.close_requires_base_min_balance {
        assert!(err.contains("cannot close: account"), "{err}");
    }
    assert_ne!(h.account(closer_addr).micro_algos, 0);

    // Once the sponsored app is gone, the inner close goes through.
    h.generate(appl_call(creator, app_id, ON_COMPLETION_DELETE))
        .expect("delete sponsored app");
    h.generate(call_closer("close"))
        .expect("inner close after delete");
    assert_eq!(h.account(closer_addr), AccountData::default());
}

#[test]
fn close_min_balance_policy_v42() {
    close_min_balance_policy(CONSENSUS_V42);
}

#[test]
fn close_min_balance_policy_v43() {
    close_min_balance_policy(CONSENSUS_V43);
}

/// Issue #2116: go `StartEvaluator` rejects a block whose rewards pool holds
/// less than `MinBalance` after the block-start withdrawal, so test ledgers
/// fund their (zero-address) pool as every real genesis does.
#[allow(dead_code)]
fn funded_sqlite_ledger() -> algo_ledger::SqliteLedger {
    let mut l = algo_ledger::SqliteLedger::open_in_memory().expect("in-memory ledger");
    fund_rewards_pool(&mut l);
    l
}

#[allow(dead_code)]
fn funded_ledger_state() -> algo_ledger::LedgerState {
    let mut s = algo_ledger::LedgerState::new();
    fund_rewards_pool(&mut s);
    s
}

#[allow(dead_code)]
fn fund_rewards_pool<L: algo_ledger::LedgerStore>(store: &mut L) {
    let pool = store.rewards_pool();
    if store.get_account(&pool).is_none() {
        store.set_account(
            &pool,
            algo_types::AccountData {
                micro_algos: 100_000,
                status: algo_types::AccountStatus::NotParticipating,
                ..algo_types::AccountData::default()
            },
        );
    }
}
