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

//! Simulation of placeholder salted-key signatures for every signing scheme
//! (`f1`, `f5`, `ed`) and of a delegated `ls`-scheme LogicSig that is not a
//! placeholder: ports of go v5.1.1's `TestPlaceholderSaltedKeySignatures`
//! and `TestDelegatedLogicSigSaltedKeySigNotPlaceholder`
//! (`ledger/simulation/simulation_eval_test.go`; issues #2546, #2547).
//! `simulation_pq_placeholder_test.rs` has the Falcon-1024 cases at v42.

use algo_ledger::apply::pool_fixtures::{funded_simulation_state, TEST_GENESIS_HASH};
use algo_ledger::simulation::{SimulationRequest, Simulator};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_FUTURE};
use algo_types::{
    canonical_address_salt, AccountData, Address, AddressSalt, LogicSig, SaltedKeySig,
    SignedTransaction, Transaction, SIG_SCHEME_ED25519, SIG_SCHEME_FALCON1024,
    SIG_SCHEME_FALCON512, SIG_SCHEME_LOGIC_SIG,
};
use algo_validate::fee::{required_fee_for_usage, summarize_fees};
use serde_bytes::ByteBuf;

const FEE_SINK: Address = Address([0xFE; 32]);

fn setup_state(sender: Address) -> LedgerState {
    let mut state = funded_simulation_state();
    state.fee_sink = FEE_SINK;
    state.protocol = CONSENSUS_FUTURE.to_string();
    for (addr, micro) in [(sender, 10_000_000), (FEE_SINK, 0)] {
        state.set_account(
            &addr,
            AccountData {
                micro_algos: micro,
                ..Default::default()
            },
        );
    }
    state
}

/// go's `makePlaceholderSaltedKeySigForSimulation`: a correctly sized but
/// otherwise dummy public key, its canonical salt and address.
fn placeholder(scheme: [u8; 2], fill: u8) -> (Address, SaltedKeySig) {
    let size = match &scheme {
        b"f1" => 1793,
        b"f5" => 897,
        b"ed" => 32,
        other => panic!("{other:?}"),
    };
    let public_key = vec![fill; size];
    let (salt, address) = canonical_address_salt(scheme, &public_key).expect("salt");
    (
        address,
        SaltedKeySig {
            scheme,
            salt,
            public_key: ByteBuf::from(public_key),
            signature: ByteBuf::new(),
        },
    )
}

fn pay(sender: Address, receiver: Address, fee: u64) -> Transaction {
    Transaction {
        txn_type: "pay".into(),
        sender,
        receiver,
        fee,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        genesis_hash: TEST_GENESIS_HASH,
        ..Default::default()
    }
}

/// The fee a payment authorized by `sksig` (top-level) must pay: its fee factor
/// including the scheme's surcharge.
fn scheme_fee(sksig: &SaltedKeySig) -> u64 {
    let params = consensus_params_for_version(CONSENSUS_FUTURE).expect("future");
    let probe = SignedTransaction {
        txn: pay(Address([1; 32]), Address([2; 32]), 0),
        pqsig: Some(sksig.clone()),
        ..Default::default()
    };
    let (usage, _) = summarize_fees(&[&probe], &params);
    let (fee, overflow) = required_fee_for_usage(usage, &params);
    assert!(!overflow);
    fee
}

fn simulate(
    state: &mut LedgerState,
    stx: SignedTransaction,
) -> algo_ledger::simulation::SimulationResult {
    let request = SimulationRequest {
        txn_groups: vec![vec![stx]],
        allow_empty_signatures: true,
        ..Default::default()
    };
    Simulator::new(state)
        .simulate(request)
        .expect("a signature failure is the group's, not a request error")
}

#[test]
fn placeholder_salted_key_signatures_for_every_signing_scheme() {
    for scheme in [
        SIG_SCHEME_FALCON1024,
        SIG_SCHEME_FALCON512,
        SIG_SCHEME_ED25519,
    ] {
        let name = String::from_utf8_lossy(&scheme).to_string();
        let receiver = Address([0xBB; 32]);

        // scheme-only placeholder: only the fee surcharge and budget matter
        let (addr, full) = placeholder(scheme, 0x11);
        let fee = scheme_fee(&full);
        let mut state = setup_state(addr);
        let scheme_only = SaltedKeySig {
            scheme,
            ..Default::default()
        };
        let r = simulate(
            &mut state,
            SignedTransaction {
                txn: pay(addr, receiver, fee),
                pqsig: Some(scheme_only),
                ..Default::default()
            },
        );
        assert!(
            r.txn_groups[0].failure_message.is_none(),
            "{name} scheme only: {:?}",
            r.txn_groups[0].failure_message
        );

        // full placeholder whose key derives the sender: accepted
        let mut state = setup_state(addr);
        let r = simulate(
            &mut state,
            SignedTransaction {
                txn: pay(addr, receiver, fee),
                pqsig: Some(full.clone()),
                ..Default::default()
            },
        );
        assert!(
            r.txn_groups[0].failure_message.is_none(),
            "{name} full: {:?}",
            r.txn_groups[0].failure_message
        );

        // wrong salt: the key no longer derives the sender
        let mut wrong_salt = full.clone();
        wrong_salt.salt = AddressSalt(wrong_salt.salt.0 ^ 1);
        let mut state = setup_state(addr);
        let r = simulate(
            &mut state,
            SignedTransaction {
                txn: pay(addr, receiver, fee),
                pqsig: Some(wrong_salt),
                ..Default::default()
            },
        );
        let g = &r.txn_groups[0];
        assert_eq!(g.failed_at, Some(vec![0]), "{name} wrong salt");
        let m = g.failure_message.as_deref().unwrap_or_default();
        assert!(
            m.contains("salted-key signature authorizer mismatch"),
            "{name} wrong salt: {m}"
        );

        // a public key one byte short (the sender follows its own address): the
        // placeholder is not accepted and the sender is overspent / fails
        let mut short = full.clone();
        let l = short.public_key.len();
        short.public_key = ByteBuf::from(short.public_key[..l - 1].to_vec());
        let short_addr = short.address();
        // (not funded: go expects `overspend`)
        let mut state = setup_state(Address([0xCD; 32]));
        let r = simulate(
            &mut state,
            SignedTransaction {
                txn: pay(short_addr, short_addr, fee),
                pqsig: Some(short),
                ..Default::default()
            },
        );
        let g = &r.txn_groups[0];
        assert_eq!(g.failed_at, Some(vec![0]), "{name} invalid public key");
        // The text go reports is `overspend (account ...)`: see
        // `unfunded_placeholder_sender_reports_overspend` (issue #2587).
        assert!(g.failure_message.is_some(), "{name} invalid public key");
    }
}

// go's `TestDelegatedLogicSigSaltedKeySigNotPlaceholder`: an `ls`-scheme
// SaltedKeySig delegating a LogicSig is never taken for a placeholder: even
// with AllowEmptySignatures it fails as a delegation.
#[test]
fn a_delegated_logic_sig_salted_key_sig_is_not_a_placeholder() {
    let params = consensus_params_for_version(CONSENSUS_FUTURE).expect("future");
    assert!(params.enable_sig_scheme_logic_sig);
    let sender = Address([0xAA; 32]);
    let program = algo_avm::assemble_string("#pragma version 2\nint 1")
        .expect("assembles")
        .program;
    let (salt, ls_addr) = canonical_address_salt(SIG_SCHEME_LOGIC_SIG, &program).expect("salt");
    for (name, sksig) in [
        (
            "scheme only",
            SaltedKeySig {
                scheme: SIG_SCHEME_LOGIC_SIG,
                ..Default::default()
            },
        ),
        (
            "full",
            SaltedKeySig {
                scheme: SIG_SCHEME_LOGIC_SIG,
                salt,
                public_key: ByteBuf::from(program.clone()),
                ..Default::default()
            },
        ),
    ] {
        let mut state = setup_state(sender);
        let r = simulate(
            &mut state,
            SignedTransaction {
                txn: pay(sender, sender, 1000),
                auth_addr: Some(ls_addr),
                lsig: Some(LogicSig {
                    logic: ByteBuf::from(program.clone()),
                    pqsig: Some(sksig),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let g = &r.txn_groups[0];
        let m = g.failure_message.as_deref().unwrap_or_default();
        assert!(
            m.contains("salted-key signature delegation validation failed"),
            "{name}: {m}"
        );
        assert_eq!(g.failed_at, Some(vec![0]), "{name}");
    }
}

// go's rule that an ls-scheme SaltedKeySig is never a placeholder, top-level:
// empty signature bytes are a program taking no arguments, so the program is
// evaluated (a rejecting one stays rejected; an approving one is authorized).
#[test]
fn a_top_level_logic_sig_salted_key_sig_is_evaluated_not_replaced() {
    let receiver = Address([0xBB; 32]);
    for (source, approves) in [
        (
            "#pragma version 6
int 1",
            true,
        ),
        (
            "#pragma version 6
int 0",
            false,
        ),
    ] {
        let program = algo_avm::assemble_string(source)
            .expect("assembles")
            .program;
        let (salt, addr) = canonical_address_salt(SIG_SCHEME_LOGIC_SIG, &program).expect("salt");
        let sksig = SaltedKeySig {
            scheme: SIG_SCHEME_LOGIC_SIG,
            salt,
            public_key: ByteBuf::from(program),
            signature: ByteBuf::new(),
        };
        let fee = scheme_fee_ls(&sksig);
        let mut state = setup_state(addr);
        let r = simulate(
            &mut state,
            SignedTransaction {
                txn: pay(addr, receiver, fee),
                pqsig: Some(sksig),
                ..Default::default()
            },
        );
        let g = &r.txn_groups[0];
        if approves {
            assert!(g.failure_message.is_none(), "{:?}", g.failure_message);
        } else {
            let m = g.failure_message.as_deref().unwrap_or_default();
            assert!(m.contains("rejected by logic"), "{m}");
        }
    }
}

fn scheme_fee_ls(sksig: &SaltedKeySig) -> u64 {
    scheme_fee(sksig)
}

/// go's `TestPlaceholderSaltedKeySignatures` "invalid public key" subtest expects
/// the failure text `overspend`: go's framed `ledgercore.OverspendError`
/// (issue #2587).
#[test]
fn unfunded_placeholder_sender_reports_overspend() {
    let scheme = SIG_SCHEME_ED25519;
    let (_, full) = placeholder(scheme, 0x11);
    let fee = scheme_fee(&full);
    let mut short = full.clone();
    let l = short.public_key.len();
    short.public_key = ByteBuf::from(short.public_key[..l - 1].to_vec());
    let addr = short.address();
    let mut state = setup_state(Address([0xCD; 32]));
    let r = simulate(
        &mut state,
        SignedTransaction {
            txn: pay(addr, addr, fee),
            pqsig: Some(short),
            ..Default::default()
        },
    );
    let m = r.txn_groups[0]
        .failure_message
        .as_deref()
        .unwrap_or_default()
        .to_string();
    assert!(m.contains("overspend"), "{m}");
    // go: `transaction <txid>: overspend (account <addr>, data {...}, tried to spend <A>)`
    assert!(m.starts_with("transaction "), "{m}");
    assert!(
        m.contains(&format!(": overspend (account {}, data ", addr.to_algorand_string())),
        "{m}"
    );
    assert!(m.contains(", tried to spend "), "{m}");
}
