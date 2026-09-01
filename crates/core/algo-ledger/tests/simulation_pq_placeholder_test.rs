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

//! Integration tests for simulation's placeholder-PQ-signature handling
//! (issue #835): `allow_empty_signatures` accepting a transaction/LogicSig
//! carrying a real PQ public key but an empty (placeholder) signature, for
//! fee/budget-estimation without a real Falcon-1024 signature, matching
//! go-algorand's `isPlaceholderPQSig`/`isPlaceholderDelegatedPQSig`/
//! `validatePlaceholderPQSig` (`ledger/simulation/simulator.go`).

use serde_bytes::ByteBuf;

use algo_ledger::simulation::{SimulationRequest, Simulator, SimulatorError};
use algo_ledger::{LedgerState, LedgerStore};
use algo_types::consensus::CONSENSUS_V42;
use algo_types::{
    canonical_pq_address_salt, AccountData, Address, LogicSig, PQAddressSalt, PQSig,
    SignedTransaction, Transaction, PQ_SCHEME_FALCON1024,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FEE_SINK: Address = Address([0xFE; 32]);

/// Falcon-1024's public key size (`algo_falcon::FALCON_DET1024_PUBKEY_SIZE`).
/// Hardcoded here rather than pulling in the `algo-falcon` crate: placeholder
/// envelope validation only hashes the public key bytes for address
/// derivation (`PQSig::address`) and never verifies a signature over them, so
/// these tests need a correctly-*sized* key, not a real Falcon-1024 keypair.
const FALCON_DET1024_PUBKEY_SIZE: usize = 1793;

fn setup_state(sender: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = FEE_SINK;
    // PQ signatures are only enabled from v42 (issue #835 test setup).
    state.protocol = CONSENSUS_V42.to_string();

    state.set_account(
        &sender,
        AccountData {
            micro_algos: 10_000_000,
            ..Default::default()
        },
    );
    state.set_account(
        &FEE_SINK,
        AccountData {
            micro_algos: 0,
            ..Default::default()
        },
    );
    state
}

/// A dummy but correctly-sized "public key" and its canonical PQ address.
fn dummy_pq_identity(fill_byte: u8) -> (Vec<u8>, PQAddressSalt, Address) {
    let pk = vec![fill_byte; FALCON_DET1024_PUBKEY_SIZE];
    let (salt, addr) =
        canonical_pq_address_salt(PQ_SCHEME_FALCON1024, &pk).expect("a canonical salt exists");
    (pk, salt, addr)
}

fn make_pay_txn(sender: Address, receiver: Address) -> Transaction {
    Transaction {
        txn_type: "pay".into(),
        sender,
        receiver,
        fee: 1000,
        first_valid: 0.into(),
        last_valid: 1000.into(),
        ..Default::default()
    }
}

fn simulate(
    state: &mut LedgerState,
    request: SimulationRequest,
) -> Result<algo_ledger::simulation::SimulationResult, SimulatorError> {
    let mut simulator = Simulator::new(state);
    simulator.simulate(request)
}

// ---------------------------------------------------------------------------
// Top-level placeholder PQSig
// ---------------------------------------------------------------------------

#[test]
fn scheme_only_placeholder_pqsig_accepted() {
    // Scheme-only placeholder: Scheme set, PublicKey/Signature empty. Used
    // purely for fee-surcharge/budget estimation -- no authorizer check.
    let sender = Address([0xAA; 32]);
    let receiver = Address([0xBB; 32]);
    let mut state = setup_state(sender);

    let stx = SignedTransaction {
        txn: make_pay_txn(sender, receiver),
        pqsig: Some(PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt: PQAddressSalt(0),
            public_key: ByteBuf::new(),
            signature: ByteBuf::new(),
        }),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![stx]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
}

#[test]
fn full_placeholder_pqsig_matching_authorizer_accepted() {
    // Full placeholder: Scheme, Salt, PublicKey set, Signature empty. The
    // public key must derive the sender's address, but no real Falcon
    // signature is required.
    let (pk, salt, addr) = dummy_pq_identity(0x11);
    let receiver = Address([0xBB; 32]);
    let mut state = setup_state(addr);

    let stx = SignedTransaction {
        txn: make_pay_txn(addr, receiver),
        pqsig: Some(PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::new(),
        }),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![stx]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
}

#[test]
fn full_placeholder_pqsig_mismatched_authorizer_rejected() {
    // The public key derives a *different* address than the sender: the
    // placeholder envelope must fail validation (real verification is then
    // attempted against the untouched placeholder and fails too).
    let (pk, salt, _addr) = dummy_pq_identity(0x22);
    let sender = Address([0xCC; 32]); // does NOT match the derived PQ address
    let receiver = Address([0xBB; 32]);
    let mut state = setup_state(sender);

    let stx = SignedTransaction {
        txn: make_pay_txn(sender, receiver),
        pqsig: Some(PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::new(),
        }),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![stx]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    // The placeholder fails envelope validation, so `check()` leaves the
    // transaction untouched; real group verification then rejects it as an
    // invalid request (not a soft per-txn failure), matching go's
    // `verify.TxnGroupWithTracer` behavior on an unresolved placeholder.
    let result = simulate(&mut state, request);
    assert!(result.is_err(), "mismatched placeholder must be rejected");
}

// ---------------------------------------------------------------------------
// Delegated (LogicSig-nested) placeholder PQSig
// ---------------------------------------------------------------------------

#[test]
fn delegated_placeholder_pqsig_matching_authorizer_accepted() {
    // A LogicSig whose delegation is a placeholder PQSig: the escrow
    // fallback authorizes via the program hash once the placeholder
    // validates, without needing a real Falcon signature over the program.
    let (pk, salt, addr) = dummy_pq_identity(0x33);
    let receiver = Address([0xBB; 32]);
    let mut state = setup_state(addr);

    // v6: pushint 1; return -- a trivially-approving LogicSig program.
    let program = vec![0x06, 0x81, 0x01, 0x43];

    let stx = SignedTransaction {
        txn: make_pay_txn(addr, receiver),
        lsig: Some(LogicSig {
            logic: ByteBuf::from(program),
            pqsig: Some(PQSig {
                scheme: PQ_SCHEME_FALCON1024,
                salt,
                public_key: ByteBuf::from(pk),
                signature: ByteBuf::new(),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![stx]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request).expect("simulation should succeed");
    let group = &result.txn_groups[0];
    assert!(
        group.failure_message.is_none(),
        "group must succeed: {:?}",
        group.failure_message
    );
}

#[test]
fn delegated_placeholder_pqsig_mismatched_authorizer_rejected() {
    let (pk, salt, _addr) = dummy_pq_identity(0x44);
    let sender = Address([0xDD; 32]); // does NOT match the derived PQ address
    let receiver = Address([0xBB; 32]);
    let mut state = setup_state(sender);

    let program = vec![0x06, 0x81, 0x01, 0x43];

    let stx = SignedTransaction {
        txn: make_pay_txn(sender, receiver),
        lsig: Some(LogicSig {
            logic: ByteBuf::from(program),
            pqsig: Some(PQSig {
                scheme: PQ_SCHEME_FALCON1024,
                salt,
                public_key: ByteBuf::from(pk),
                signature: ByteBuf::new(),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![stx]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request);
    assert!(result.is_err(), "mismatched placeholder must be rejected");
}

// ---------------------------------------------------------------------------
// A real (non-placeholder) PQSig must not be clobbered by proxy-signing
// ---------------------------------------------------------------------------

#[test]
fn non_placeholder_pqsig_with_wrong_authorizer_is_not_silently_proxy_signed() {
    // Regression guard: before issue #835, `check()`'s "no signature at
    // all" branch didn't check for a present `pqsig` field, so a
    // transaction carrying *any* pqsig (blank signature or not) with no
    // sig/msig/lsig would be silently proxy-signed over, discarding real PQ
    // authorization intent. A pqsig with a non-empty (bogus) signature must
    // now be left alone and fail real verification instead of succeeding
    // via proxy-signing.
    let (pk, salt, _addr) = dummy_pq_identity(0x55);
    let sender = Address([0xEE; 32]);
    let receiver = Address([0xBB; 32]);
    let mut state = setup_state(sender);

    let stx = SignedTransaction {
        txn: make_pay_txn(sender, receiver),
        pqsig: Some(PQSig {
            scheme: PQ_SCHEME_FALCON1024,
            salt,
            public_key: ByteBuf::from(pk),
            signature: ByteBuf::from(vec![0u8; 10]), // non-empty, but bogus
        }),
        ..Default::default()
    };

    let request = SimulationRequest {
        txn_groups: vec![vec![stx]],
        allow_empty_signatures: true,
        ..Default::default()
    };

    let result = simulate(&mut state, request);
    assert!(
        result.is_err(),
        "a non-placeholder (non-empty-signature) pqsig must not be silently proxy-signed"
    );
}
