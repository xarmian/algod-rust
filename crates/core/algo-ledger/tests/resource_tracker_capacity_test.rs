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

//! Simulation `ResourceTracker` capacity/cross-product/empty-box-ref
//! reporting (issue #970).
//!
//! Ports the reporting-focused subset of go-algorand's `ledger/simulation`
//! `ResourceTracker` (`ledger/simulation/resources.go`, `1088a2aad7e` /
//! `v3.18.0-beta`): the `Max*`/`MaxCrossProductReferences` capacity
//! computation (`makeGlobalResourceTracker`), capacity-gated recording of
//! unnamed accesses (`add*`), and the `NumEmptyBoxRefs`/`extra-box-refs`
//! anonymous-empty-ref count (`Simplify`) -- distinct from `boxes`, which
//! suggests concrete `(app_id, name)` refs.
//!
//! Scope note: this engine (unlike go-algorand's `ResourceTracker.add*`)
//! does not reject the underlying AVM access once a category's capacity is
//! exhausted -- it only stops adding to the *reported* access sets. Full
//! opcode-failure enforcement matching go's `TestUnnamedResourcesLimits`/
//! `TestUnnamedResourcesCrossProductLimits` (an "unavailable Account ..."/
//! "invalid Box reference ..." error once capacity truly runs out) is a
//! distinct, larger follow-up -- see the issue's tracking comment.

use std::collections::BTreeMap;

use algo_codec::canonical_encode_transaction;
use algo_ledger::simulation::{SimulationRequest, SimulationResult, Simulator, SimulatorError};
use algo_ledger::{
    apply_transaction, avm_context::app_address, ApplyContext, ApplyMode, LedgerStore,
};
use algo_types::{AccountData, Address, AppParams, SignedTransaction, StateSchema, Transaction};
use ed25519_dalek::{Signer, SigningKey};

const FEE_SINK: Address = Address([0xFE; 32]);

fn assemble(source: &str) -> Vec<u8> {
    algo_avm::assembler::assemble_string(source)
        .unwrap_or_else(|e| panic!("assembly failed: {e:?}\nsource:\n{source}"))
        .program
}

const TX_PREFIX: &[u8] = b"TX";

fn tx_sign_message(txn: &Transaction) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(TX_PREFIX);
    msg.extend_from_slice(&canonical_encode_transaction(txn));
    msg
}

#[allow(dead_code)]
fn sign(txn: Transaction, key: &SigningKey) -> SignedTransaction {
    let sig = key.sign(&tx_sign_message(&txn));
    SignedTransaction {
        txn,
        sig: sig.to_bytes(),
        ..Default::default()
    }
}

fn base_state() -> algo_ledger::LedgerState {
    let mut state = algo_ledger::LedgerState::new();
    state.fee_sink = FEE_SINK;
    state.protocol = algo_types::consensus::CONSENSUS_V41.to_string();
    state.set_account(
        &FEE_SINK,
        AccountData {
            micro_algos: 0,
            ..Default::default()
        },
    );
    state
}

fn fund(state: &mut algo_ledger::LedgerState, addr: Address, micro_algos: u64) {
    let mut acct = state.get_account(&addr).cloned().unwrap_or_default();
    acct.micro_algos = micro_algos;
    state.set_account(&addr, acct);
}

fn register_app(
    state: &mut algo_ledger::LedgerState,
    creator: Address,
    app_id: u64,
    approval: Vec<u8>,
    clear: Vec<u8>,
) {
    let app_params = AppParams {
        creator,
        approval_program: approval,
        clear_state_program: clear,
        global_state: BTreeMap::new(),
        local_state_schema: StateSchema::default(),
        global_state_schema: StateSchema::default(),
        extra_program_pages: 0,
        ..Default::default()
    };
    state.set_app_params(app_id, app_params);
    let mut acct = state.get_account(&creator).cloned().unwrap_or_default();
    acct.total_created_apps += 1;
    state.set_account(&creator, acct);
}

fn appl_txn(sender: Address, app_id: u64, on_completion: u64) -> Transaction {
    Transaction {
        txn_type: "appl".into(),
        sender,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        application_id: app_id,
        on_completion,
        ..Default::default()
    }
}

fn simulate(
    state: &mut algo_ledger::LedgerState,
    request: SimulationRequest,
) -> Result<SimulationResult, SimulatorError> {
    let mut simulator = Simulator::new_with_developer_api(state);
    simulator.simulate(request)
}

#[allow(dead_code)]
fn apply_real(state: &mut algo_ledger::LedgerState, stx: &SignedTransaction) {
    let ctx = {
        let mut c = ApplyContext::new_replay(0, FEE_SINK, 0);
        c.mode = ApplyMode::Execute;
        c
    };
    apply_transaction(state, stx, &ctx, 0).unwrap_or_else(|e| panic!("prepare txn failed: {e}"));
}

/// A box owned by an app *created earlier in this same simulation* has no
/// stable, resubmittable ID -- it can't be suggested back to the caller as
/// a concrete `(app_id, name)` box ref the way an existing app's box can.
/// go-algorand's `ResourceTracker.Simplify` (`ledger/simulation/
/// resources.go`) handles this by moving such boxes out of `Boxes` and into
/// an anonymous `NumEmptyBoxRefs` count instead.
///
/// Scenario: app A (pre-existing) itxn-creates app B, then itxn-calls B a
/// second time in the same top-level transaction. B's second call reads its
/// own box "bk" via `box_get` with no box ref supplied anywhere in the
/// group -- relying entirely on unnamed-resource tracking. Because B was
/// created earlier in this same simulation (`self.created_apps` inherited
/// from A's context, updated after B's creation itxn returned), this must
/// be reported as `extra-box-refs`/`num_empty_box_refs`, not as a
/// `(app_id, name)` suggestion in `boxes`.
#[test]
fn unnamed_resources_box_on_group_created_app_reported_as_empty_ref() {
    let sender = Address([0xAA; 32]);
    let app_a = 1001u64;
    let mut state = base_state();
    fund(&mut state, sender, 20_000_000);
    fund(&mut state, Address(app_address(app_a)), 10_000_000);

    // B's program: on create (ApplicationID == 0), just approve. On any
    // later call, read its own "bk" box.
    let b_src = "#pragma version 9
txn ApplicationID
!
bnz done
byte \"bk\"
box_get
pop
pop
done:
int 1
";
    let b_approval = assemble(b_src);
    let b_clear = assemble("#pragma version 9\nint 1\n");

    let a_src = format!(
        "#pragma version 9
itxn_begin
int appl
itxn_field TypeEnum
byte 0x{}
itxn_field ApprovalProgram
byte 0x{}
itxn_field ClearStateProgram
itxn_submit
itxn CreatedApplicationID
store 0

itxn_begin
int appl
itxn_field TypeEnum
load 0
itxn_field ApplicationID
itxn_submit

int 1
",
        hex::encode(&b_approval),
        hex::encode(&b_clear),
    );
    let a_approval = assemble(&a_src);
    let a_clear = assemble("#pragma version 9\nint 1\n");
    register_app(&mut state, sender, app_a, a_approval, a_clear);

    let mut txn = appl_txn(sender, app_a, 0);
    // Covers the pooled fees for A's two itxns (create + call) plus A itself.
    txn.fee = 4000;

    let request = SimulationRequest {
        txn_groups: vec![vec![SignedTransaction {
            txn,
            ..Default::default()
        }]],
        allow_empty_signatures: true,
        allow_unnamed_resources: true,
        ..Default::default()
    };
    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "box access on a group-created app must succeed under allow_unnamed_resources: {:?}",
        group.failure_message
    );
    let unnamed = group
        .unnamed_resources_accessed
        .as_ref()
        .expect("unnamed resources must be reported");
    assert_eq!(
        unnamed.num_empty_box_refs, 1,
        "box owned by a group-created app must be reported as an anonymous \
         empty ref, not a concrete suggestion: {unnamed:?}"
    );
    assert!(
        unnamed.boxes.is_empty(),
        "must NOT be reported as a concrete (app_id, name) suggestion \
         since the app has no stable, resubmittable ID: {unnamed:?}"
    );
}
