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

//! Issue #2545: go v5.1.1 `TestFamilyBoxReentrancy` and
//! `TestFamilyBoxReentrancyToggling` (`ledger/boxtxn_test.go`) end to end,
//! with the same TEAL programs, call shapes and expected outcomes.
//!
//! `FamilyBoxAccess` is read at each box access, so toggling it during a group
//! moves boxes in and out of the family reentrancy guard: an owner that opts out
//! just before writing its own box skips it, and a frame that touched a box
//! before the owner opted in is never marked as relying on it. go v5.1.1 pins
//! that both writes are permitted (tightening it would need a new consensus
//! version), with a control for each case showing the chain really reaches the
//! write.

use algo_ledger::avm_context::app_address;
use algo_ledger::{apply_transaction_with_budget, ApplyContext, ApplyMode, LedgerState};
use algo_types::{Address, AppParams, BoxRef, SignedTransaction};

/// go `main(...)`: do nothing at create time, otherwise run the source, then
/// approve. (`;` stands for a newline in go's sources.)
fn main_program(src: &str) -> Vec<u8> {
    let body = src.replace(';', "\n");
    let source = format!("#pragma version 13\ntxn ApplicationID\nbz end\n{body}\nend:\nint 1\n");
    algo_avm::assembler::assemble_string(&source)
        .unwrap_or_else(|e| panic!("assembly failed: {e:?}\n{source}"))
        .program
}

const FAMILY_INITIATOR: &str = r#"
  txn ApplicationArgs 0; byte "optin"; ==; bz notoptin
    int 1; app_params_set AppFamilyBoxAccess
    byte "b"; int 4; box_create; assert
    b done
  notoptin:

  txn ApplicationArgs 0; byte "optout"; ==; bz nosetup
    int 0; app_params_set AppFamilyBoxAccess
    int 0; app_params_set AppForeignBoxReads
    b done
  nosetup:

  txn ApplicationArgs 0; byte "write"; ==; bz nowrite
    byte "b"; int 0; byte "AA"; box_replace
  nowrite:

  txn ApplicationArgs 0; byte "read"; ==; bz noread
    byte "b"; box_get; assert; pop
  noread:

  txn ApplicationArgs 0; byte "sharelate"; ==; bz nosharelate
    byte "b"; int 0; byte "AA"; box_replace
    int 1; app_params_set AppFamilyBoxAccess
  nosharelate:

  txn ApplicationArgs 1; byte "viaX"; ==; bz trydirect
    itxn_begin
    int appl; itxn_field TypeEnum
    txn Applications 1; itxn_field ApplicationID
    txn Applications 2; itxn_field Applications
    txn Applications 3; itxn_field Applications
    itxn_submit
    b done
  trydirect:
  txn ApplicationArgs 1; byte "direct"; ==; bz trydelegate
    itxn_begin
    int appl; itxn_field TypeEnum
    txn Applications 2; itxn_field ApplicationID
    txn Applications 3; itxn_field Applications
    itxn_submit
    b done
  trydelegate:
  txn ApplicationArgs 1; byte "delegate"; ==; bz done
    itxn_begin
    int appl; itxn_field TypeEnum
    txn Applications 2; itxn_field ApplicationID
    txn Applications 3; itxn_field Applications
    itxn_submit
    itxn_begin
    int appl; itxn_field TypeEnum
    txn Applications 1; itxn_field ApplicationID
    txn Applications 2; itxn_field Applications
    txn Applications 3; itxn_field Applications
    itxn_submit
  done:
"#;

const FAMILY_FOREIGN: &str = r#"
  itxn_begin
  int appl; itxn_field TypeEnum
  txn Applications 1; itxn_field ApplicationID
  txn Applications 2; itxn_field Applications
  itxn_submit
"#;

const CROSS_WRITER: &str = r#"txn Applications 1; byte "b"; int 0; byte "CC"; app_box_replace"#;
const CROSS_READER: &str = r#"txn Applications 1; byte "b"; app_box_get; assert; pop"#;

const FAMILY_OPT_OUT_INITIATOR: &str = r#"
  txn Applications 2; byte "b"; app_box_get; assert; pop
  itxn_begin
  int appl; itxn_field TypeEnum
  txn Applications 1; itxn_field ApplicationID
  txn Applications 2; itxn_field Applications
  txn Applications 3; itxn_field Applications
  itxn_submit
"#;

const FAMILY_OPT_OUT_OWNER: &str = r#"
  txn NumAppArgs; bz callback
    int 1; app_params_set AppFamilyBoxAccess
    byte "b"; int 4; box_create; assert
    b done
  callback:
    int 0; app_params_set AppFamilyBoxAccess
    byte "b"; int 0; byte "BB"; box_replace
  done:
"#;

const FAMILY_STAY_OWNER: &str = r#"
  txn NumAppArgs; bz callback
    int 1; app_params_set AppFamilyBoxAccess
    byte "b"; int 4; box_create; assert
    b done
  callback:
    byte "b"; int 0; byte "BB"; box_replace
  done:
"#;

struct World {
    state: LedgerState,
    ctx: ApplyContext,
    sender: Address,
}

impl World {
    fn new() -> Self {
        let fee_sink = Address([0xF1; 32]);
        let mut state = algo_ledger::apply::pool_fixtures::funded_ledger_state();
        state.fee_sink = fee_sink;
        let sender = Address([1u8; 32]);
        state.get_or_default_account_mut(&sender).micro_algos = 50_000_000_000;
        let mut ctx = ApplyContext::new_replay(0, fee_sink, 1);
        ctx.mode = ApplyMode::Execute;
        World { state, ctx, sender }
    }

    /// A funded app of `creator` (go `fundedApp`).
    fn app(&mut self, id: u64, creator: Address, src: &str) -> u64 {
        self.state.app_params.insert(
            id,
            AppParams {
                creator,
                approval_program: main_program(src),
                clear_state_program: main_program(""),
                ..Default::default()
            },
        );
        self.state
            .get_or_default_account_mut(&Address(app_address(id)))
            .micro_algos = 1_000_000_000;
        id
    }

    fn call(
        &mut self,
        app: u64,
        foreign_apps: Vec<u64>,
        box_index: Option<u64>,
        args: &[&str],
    ) -> Result<(), String> {
        let mut stx = SignedTransaction::default();
        stx.txn.txn_type = "appl".into();
        stx.txn.sender = self.sender;
        stx.txn.fee = 10_000;
        stx.txn.application_id = app;
        if !foreign_apps.is_empty() {
            stx.txn.foreign_apps = Some(foreign_apps);
        }
        if let Some(index) = box_index {
            stx.txn.boxes = Some(vec![BoxRef {
                index,
                name: Some(serde_bytes::ByteBuf::from(b"b".to_vec())),
            }]);
        }
        if !args.is_empty() {
            stx.txn.app_arguments = Some(
                args.iter()
                    .map(|a| Some(serde_bytes::ByteBuf::from(a.as_bytes().to_vec())))
                    .collect(),
            );
        }
        apply_transaction_with_budget(&mut self.state, &stx, &self.ctx, 0, None, None, None, None)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn ok(&mut self, app: u64, foreign_apps: Vec<u64>, box_index: Option<u64>, args: &[&str]) {
        self.call(app, foreign_apps, box_index, args)
            .unwrap_or_else(|e| panic!("call to app {app} {args:?} must succeed: {e}"));
    }

    fn refused(
        &mut self,
        app: u64,
        foreign_apps: Vec<u64>,
        box_index: Option<u64>,
        args: &[&str],
        problem: &str,
    ) {
        let err = self
            .call(app, foreign_apps, box_index, args)
            .expect_err("must be refused");
        assert!(err.contains(problem), "want {problem:?}, got: {err}");
    }
}

#[test]
fn family_box_reentrancy_guard_end_to_end() {
    let mut w = World::new();
    let family = w.sender;
    let other = Address([2u8; 32]);
    let a = w.app(1001, family, FAMILY_INITIATOR);
    let x = w.app(1002, other, FAMILY_FOREIGN);
    let cw = w.app(1003, family, CROSS_WRITER);
    let cr = w.app(1004, family, CROSS_READER);
    w.ok(a, vec![], Some(0), &["optin"]);

    const REENTRY: &str = "may not write family-shared box";
    let call = |w: &mut World, touch: &str, route: &str, c: u64| {
        w.call(a, vec![x, c, a], Some(0), &[touch, route])
    };
    let blocked = |w: &mut World, touch: &str, route: &str, c: u64| {
        let err = call(w, touch, route, c).expect_err("blocked");
        assert!(err.contains(REENTRY), "{touch}/{route}: {err}");
    };
    // write then write across a foreign app
    blocked(&mut w, "write", "viaX", cw);
    // read then write across a foreign app
    blocked(&mut w, "read", "viaX", cw);
    // no prior touch: allowed
    call(&mut w, "none", "viaX", cw).expect("no prior touch");
    // write then read across a foreign app: reads never trigger the guard
    call(&mut w, "write", "viaX", cr).expect("reads are exempt");
    // intra-family, no foreign frame: allowed
    call(&mut w, "write", "direct", cw).expect("family trusts itself");
    // delegated touch, then write across a foreign app: the mark must survive
    blocked(&mut w, "none", "delegate", cw);
}

#[test]
fn family_box_reentrancy_toggling_end_to_end() {
    let mut w = World::new();
    let family = w.sender;
    let other = Address([2u8; 32]);
    let a = w.app(1001, family, FAMILY_INITIATOR);
    let x = w.app(1002, other, FAMILY_FOREIGN);
    let cw = w.app(1003, family, CROSS_WRITER);
    let oi = w.app(1004, family, FAMILY_OPT_OUT_INITIATOR);
    let ob = w.app(1005, family, FAMILY_OPT_OUT_OWNER);
    let sb = w.app(1006, family, FAMILY_STAY_OWNER);

    // Enable after the touch. A creates box "b" and turns sharing back off,
    // leaving the box in place and unshared.
    w.ok(a, vec![], Some(0), &["optin"]);
    w.ok(a, vec![], None, &["optout"]);

    // Control: with sharing off C is refused outright, so the route reaches it.
    w.refused(
        a,
        vec![x, cw, a],
        Some(0),
        &["write", "viaX"],
        "may not write box",
    );

    // A writes its box unshared, so A is never marked, then enables sharing and
    // re-enters through X. C's write is allowed and A resumes on a stale box.
    w.ok(a, vec![x, cw, a], Some(0), &["sharelate", "viaX"]);

    // Disable before the write. Both owners opt in and create their box.
    w.ok(ob, vec![], Some(0), &["setup"]);

    // Control: the same chain against an owner that keeps sharing on is blocked,
    // so the chain shape is right and the opt-out is the only difference.
    w.ok(sb, vec![], Some(0), &["setup"]);
    w.refused(
        oi,
        vec![x, sb, oi],
        Some(2),
        &[],
        "may not write family-shared box",
    );

    // B clears its flag before writing its own box, so that write is no longer
    // family-shared and the guard never runs, though A relies on what it read.
    w.ok(oi, vec![x, ob, oi], Some(2), &[]);
}
