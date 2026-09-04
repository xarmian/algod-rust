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

//! Full ledger-apply, real-cryptography end-to-end tests for the
//! post-quantum (Falcon-1024) account authorization path — issue #968, a
//! follow-up to issue #824's `TestPQRekeyedAddressAuthorization`/
//! `TestPQChallengedAccountCanHeartbeatForZeroFee` port
//! (`ledger/eval_simple_test.go`, v5.0.0-stable).
//!
//! #824/PR #850 proved the authorizer-vs-`AuthAddr` ledger-apply check in
//! isolation (`apply.rs`'s `check_authorizer_*` unit tests), using
//! synthetic addresses and no real signatures. What was still missing is
//! the *composite* path go's tests actually exercise: a real ed25519 key
//! rekeying an account to a real Falcon-1024-derived address, a real
//! Falcon signature authorizing a spend from it, and a real Falcon-derived
//! address heartbeating for a zero fee discount — all driven through the
//! same two stages a submitted block actually goes through:
//! `algo_validate::block::validate_block` (real signature/proof/fee
//! verification) followed by `algo_ledger::apply_block_validating` (real
//! ledger state application, including the authorizer check).

use algo_codec::canonical_encode_transaction;
use algo_consensus_crypto::{one_time_id_for_round, OneTimeSignatureSecrets};
use algo_ledger::{
    apply_block_validating, build_heartbeat_transaction, HeartbeatParams, LedgerState, LedgerStore,
};
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V42};
use algo_types::{
    canonical_pq_address_salt, AccountStatus, Address, Block, PQSig, Round, SignedTransaction,
    PQ_SCHEME_FALCON1024,
};
use algo_validate::block::validate_block;
use algo_validate::fee::{required_fee_for_txn, required_fee_for_usage, summarize_fees};
use ed25519_dalek::{Signer, SigningKey};
use serde_bytes::ByteBuf;

/// Domain-separation prefix for the top-level transaction signing message
/// (`"TX" || canonical_encode(txn)`) — the same message ed25519 single-sig,
/// multisig, and top-level `PQSig` all authenticate. Mirrors go-algorand's
/// `protocol.Transaction` `HashID` and duplicates the private
/// `algo_validate::signature::TX_PREFIX` constant, the same way
/// `algo_ledger::heartbeat_builder` already duplicates the heartbeat-proof
/// seed prefix for the same reason (no public re-export of an
/// implementation-internal domain tag).
const TX_PREFIX: &[u8] = b"TX";

fn tx_sign_message(txn: &algo_types::Transaction) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(TX_PREFIX);
    msg.extend_from_slice(&canonical_encode_transaction(txn));
    msg
}

fn minimal_block(genesis_hash: [u8; 32], fee_sink: Address, round: u64) -> Block {
    Block {
        round: Round(round),
        branch: [0u8; 32],
        seed: [0u8; 32],
        txn_commitment: [0u8; 32],
        timestamp: 0,
        genesis_id: String::new(),
        genesis_hash,
        proposer: Address::ZERO,
        fee_sink,
        rewards_pool: Address::ZERO,
        rewards_level: 0,
        rewards_rate: 0,
        rewards_residue: 0,
        rewards_recalculation_round: Round(0),
        current_protocol: CONSENSUS_V42.to_string(),
        next_protocol: String::new(),
        next_protocol_approvals: 0,
        next_protocol_switch_on: Round(0),
        next_protocol_vote_before: Round(0),
        txn_counter: 0,
        fees_collected: 0,
        bonus: 0,
        proposer_payout: 0,
        prev512: [0u8; 64],
        txn256: [0u8; 32],
        txn512: [0u8; 64],
        state_proof_tracking: None,
        upgrade_propose: String::new(),
        upgrade_delay: 0,
        upgrade_approve: false,
        expired_participation_accounts: None,
        absent_participation_accounts: None,
        load: 0,
        congestion_tax: 0,
        payset: vec![],
    }
}

/// Assert a block validates cleanly (real signature/fee/proof checks) and
/// panic with the collected errors otherwise — every scenario below wants
/// crypto-clean blocks except the one that specifically expects
/// `apply_block_validating` (ledger-state authorizer check) to reject.
fn assert_block_validates(block: &Block, genesis_hash: &[u8; 32]) {
    let result = validate_block(block, None, "", genesis_hash, None);
    assert!(
        result.is_valid,
        "block failed real signature/fee/wellformedness validation: {:?}",
        result.errors
    );
}

// ---------------------------------------------------------------------------
// TestPQRekeyedAddressAuthorization port (go: ledger/eval_simple_test.go)
// ---------------------------------------------------------------------------

/// Port of go's `TestPQRekeyedAddressAuthorization`'s success path: an
/// ed25519-keyed account rekeys itself to a real Falcon-1024-derived
/// address (real ed25519 signature, real ledger apply), then a spend from
/// that account -- signed with the real Falcon private key and correctly
/// declaring the post-rekey `AuthAddr` -- is validated (real Falcon
/// signature check) and applied (real `check_authorizer` ledger check)
/// successfully.
#[test]
fn pq_rekeyed_address_authorization_full_e2e_succeeds() {
    let params = consensus_params_for_version(CONSENSUS_V42).expect("V42 params");
    assert!(params.enable_pq_scheme_falcon1024);

    let genesis_hash = [0x99u8; 32];
    let fee_sink = Address([0xFEu8; 32]);
    let receiver = Address([0xB2u8; 32]);

    // Real ed25519 identity for the rekeying account: the address IS the
    // ed25519 public key, matching `verify_single_sig`'s convention.
    let ed_key = SigningKey::from_bytes(&[0xA1u8; 32]);
    let ed_addr = Address(ed_key.verifying_key().to_bytes());

    // Real Falcon-1024 identity to rekey to.
    let seed = [0x07u8; algo_falcon::FALCON_SEED_SIZE];
    let (falcon_pk, falcon_sk) = algo_falcon::falcon_keygen(&seed).expect("falcon keygen");
    let (falcon_salt, falcon_addr) = canonical_pq_address_salt(PQ_SCHEME_FALCON1024, &falcon_pk)
        .expect("a canonical PQ salt must exist");

    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    state.get_or_default_account_mut(&ed_addr).micro_algos = 10_000_000;
    state.get_or_default_account_mut(&receiver).micro_algos = 100_000;
    state.get_or_default_account_mut(&fee_sink).micro_algos = 0;

    // ── Block 1: ed25519-signed self-payment that rekeys ed_addr to the
    // Falcon address. ──────────────────────────────────────────────────
    let mut rekey_txn = algo_types::Transaction {
        txn_type: "pay".into(),
        sender: ed_addr,
        receiver: ed_addr,
        amount: 0,
        first_valid: Round(1),
        last_valid: Round(1000),
        genesis_hash,
        rekey_to: Some(falcon_addr),
        ..Default::default()
    };
    let (fee1, overflow1) = required_fee_for_txn(&rekey_txn, &params);
    assert!(!overflow1);
    rekey_txn.fee = fee1;
    let sig1 = ed_key.sign(&tx_sign_message(&rekey_txn));

    let rekey_stx = SignedTransaction {
        txn: rekey_txn,
        sig: sig1.to_bytes(),
        ..Default::default()
    };

    let mut block1 = minimal_block(genesis_hash, fee_sink, 1);
    block1.payset = vec![rekey_stx];
    assert_block_validates(&block1, &genesis_hash);
    apply_block_validating(&mut state, &block1).expect("rekey block must apply");
    assert_eq!(
        state.get_account(&ed_addr).unwrap().auth_addr,
        Some(falcon_addr),
        "account must be rekeyed to the Falcon address"
    );

    // ── Block 2: Falcon-signed spend from ed_addr, correctly declaring
    // AuthAddr = falcon_addr. ─────────────────────────────────────────
    let mut spend_txn = algo_types::Transaction {
        txn_type: "pay".into(),
        sender: ed_addr,
        receiver,
        amount: 1_000,
        first_valid: Round(1),
        last_valid: Round(1000),
        genesis_hash,
        ..Default::default()
    };
    let placeholder_pqsig = PQSig {
        scheme: PQ_SCHEME_FALCON1024,
        salt: falcon_salt,
        public_key: ByteBuf::from(falcon_pk.clone()),
        signature: ByteBuf::new(),
    };
    let probe_stx = SignedTransaction {
        txn: spend_txn.clone(),
        pqsig: Some(placeholder_pqsig.clone()),
        auth_addr: Some(falcon_addr),
        ..Default::default()
    };
    let (usage, _paid) = summarize_fees(&[&probe_stx], &params);
    let (fee2, overflow2) = required_fee_for_usage(usage, &params);
    assert!(!overflow2);
    spend_txn.fee = fee2;

    let falcon_sig =
        algo_falcon::falcon_sign(&falcon_sk, &tx_sign_message(&spend_txn)).expect("falcon sign");
    let spend_stx = SignedTransaction {
        txn: spend_txn,
        auth_addr: Some(falcon_addr),
        pqsig: Some(PQSig {
            signature: ByteBuf::from(falcon_sig),
            ..placeholder_pqsig
        }),
        ..Default::default()
    };

    let mut block2 = minimal_block(genesis_hash, fee_sink, 2);
    block2.payset = vec![spend_stx];
    assert_block_validates(&block2, &genesis_hash);
    apply_block_validating(&mut state, &block2).expect("Falcon-authorized spend must apply");

    assert_eq!(
        state.get_account(&receiver).unwrap().micro_algos,
        100_000 + 1_000,
        "receiver must have been paid by the correctly Falcon-authorized spend"
    );
}

/// Port of go's `TestPQRekeyedAddressAuthorization`'s failure path: after
/// the same real ed25519-to-Falcon rekey, a spend signed with the
/// account's now-*stale* ed25519 key (not declaring the post-rekey
/// `AuthAddr`) passes real signature verification (the ed25519 signature
/// genuinely is valid for its declared authorizer, the sender itself) but
/// must be rejected at ledger-apply time by `check_authorizer`, matching
/// go's `"should have been authorized by"` error and PR #850's fix.
#[test]
fn pq_rekeyed_address_stale_ed25519_authorizer_rejected_full_e2e() {
    let params = consensus_params_for_version(CONSENSUS_V42).expect("V42 params");

    let genesis_hash = [0x99u8; 32];
    let fee_sink = Address([0xFEu8; 32]);
    let receiver = Address([0xB2u8; 32]);

    let ed_key = SigningKey::from_bytes(&[0xA1u8; 32]);
    let ed_addr = Address(ed_key.verifying_key().to_bytes());

    let seed = [0x07u8; algo_falcon::FALCON_SEED_SIZE];
    let (falcon_pk, _falcon_sk) = algo_falcon::falcon_keygen(&seed).expect("falcon keygen");
    let (_falcon_salt, falcon_addr) = canonical_pq_address_salt(PQ_SCHEME_FALCON1024, &falcon_pk)
        .expect("a canonical PQ salt must exist");

    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    state.get_or_default_account_mut(&ed_addr).micro_algos = 10_000_000;
    state.get_or_default_account_mut(&receiver).micro_algos = 100_000;
    state.get_or_default_account_mut(&fee_sink).micro_algos = 0;

    // Block 1: rekey to the Falcon address, exactly as in the success test.
    let mut rekey_txn = algo_types::Transaction {
        txn_type: "pay".into(),
        sender: ed_addr,
        receiver: ed_addr,
        amount: 0,
        first_valid: Round(1),
        last_valid: Round(1000),
        genesis_hash,
        rekey_to: Some(falcon_addr),
        ..Default::default()
    };
    let (fee1, _) = required_fee_for_txn(&rekey_txn, &params);
    rekey_txn.fee = fee1;
    let sig1 = ed_key.sign(&tx_sign_message(&rekey_txn));
    let rekey_stx = SignedTransaction {
        txn: rekey_txn,
        sig: sig1.to_bytes(),
        ..Default::default()
    };
    let mut block1 = minimal_block(genesis_hash, fee_sink, 1);
    block1.payset = vec![rekey_stx];
    assert_block_validates(&block1, &genesis_hash);
    apply_block_validating(&mut state, &block1).expect("rekey block must apply");

    // Block 2: a spend signed by the STALE ed25519 key, not declaring
    // AuthAddr (so its declared authorizer is the sender itself, still a
    // genuinely valid ed25519 signature -- signature verification alone
    // cannot see that the account was rekeyed).
    let mut stale_spend_txn = algo_types::Transaction {
        txn_type: "pay".into(),
        sender: ed_addr,
        receiver,
        amount: 1_000,
        first_valid: Round(1),
        last_valid: Round(1000),
        genesis_hash,
        ..Default::default()
    };
    let (fee2, _) = required_fee_for_txn(&stale_spend_txn, &params);
    stale_spend_txn.fee = fee2;
    let sig2 = ed_key.sign(&tx_sign_message(&stale_spend_txn));
    let stale_spend_stx = SignedTransaction {
        txn: stale_spend_txn,
        sig: sig2.to_bytes(),
        ..Default::default()
    };

    let mut block2 = minimal_block(genesis_hash, fee_sink, 2);
    block2.payset = vec![stale_spend_stx];
    // Real ed25519 signature verification must PASS here -- the signature
    // is genuinely valid for its declared authorizer (the sender itself,
    // since no auth_addr is set). This is exactly the gap PR #850 closed:
    // signature validity alone does not prove authorization correctness.
    assert_block_validates(&block2, &genesis_hash);

    let err = apply_block_validating(&mut state, &block2)
        .expect_err("a stale-key spend after rekey must be rejected at ledger-apply time");
    assert!(
        err.to_string().contains("should have been authorized by"),
        "unexpected error: {err}"
    );
    assert_eq!(
        state.get_account(&receiver).unwrap().micro_algos,
        100_000,
        "rejected spend must not move funds"
    );
}

// ---------------------------------------------------------------------------
// TestPQChallengedAccountCanHeartbeatForZeroFee port
// (go: ledger/eval_simple_test.go:1558)
// ---------------------------------------------------------------------------

/// Port of go's `TestPQChallengedAccountCanHeartbeatForZeroFee`: a
/// genuinely Falcon-1024-derived, online, incentive-eligible, currently
/// challenged account is heartbeated for zero fee by the ordinary
/// accepting LogicSig sender everyone uses (never the Falcon key itself --
/// a heartbeat proves liveness via the participation key's one-time
/// signature, not via the account's spending authorization scheme). The
/// account's address being PQ-shaped must not add any signature-type fee
/// surcharge to the heartbeat, since `signature_fee_contribution` only
/// inspects the *heartbeat transaction's own* signature (the accepting
/// LogicSig, never a `PQsig`), not the challenged `HbAddress`.
#[test]
fn pq_challenged_falcon_address_can_heartbeat_for_zero_fee_full_e2e() {
    let params = consensus_params_for_version(CONSENSUS_V42).expect("V42 params");
    assert!(params.txn_size_pricing_enabled());
    assert!(params.payouts_challenge_interval > 0);
    assert!(params.payouts_challenge_grace_period > 0);

    let genesis_hash = [0x99u8; 32];
    let fee_sink = Address([0xFEu8; 32]);

    // Real Falcon-1024 identity for the challenged/heartbeated account.
    let seed = [0x0Au8; algo_falcon::FALCON_SEED_SIZE];
    let (falcon_pk, _falcon_sk) = algo_falcon::falcon_keygen(&seed).expect("falcon keygen");
    let (_falcon_salt, pq_target) = canonical_pq_address_salt(PQ_SCHEME_FALCON1024, &falcon_pk)
        .expect("a canonical PQ salt must exist");

    let key_dilution = 10u64;
    let first_id = one_time_id_for_round(0, key_dilution);
    let last_id = one_time_id_for_round(3000, key_dilution);
    let num_batches = last_id.batch - first_id.batch + 1;
    let voting = OneTimeSignatureSecrets::generate(first_id.batch, num_batches);
    let vote_id = voting.verifier();

    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    {
        let acct = state.get_or_default_account_mut(&pq_target);
        acct.micro_algos = 5_000_000;
        acct.status = AccountStatus::Online;
        acct.vote_id = Some(vote_id);
        acct.vote_key_dilution = key_dilution;
        acct.incentive_eligible = true;
        acct.last_heartbeat = 0;
        acct.last_proposed = 0;
    }
    // The accepting LogicSig sender needs no funds (fee-exempt heartbeat).
    state.get_or_default_account_mut(&fee_sink).micro_algos = 0;

    // A challenge issued at round `interval` whose seed matches pq_target's
    // address bits trivially (seed == address bytes) so the challenge
    // targets this account regardless of `bits`.
    let challenge_round = params.payouts_challenge_interval;
    let challenge_seed = pq_target.0;
    store_header(&mut state, challenge_round, &challenge_seed, genesis_hash);

    // The heartbeat's own FirstValid round header (separate from the
    // challenge round), carrying the seed the OTS proof signs over.
    let hb_header_round = 1u64;
    let hb_seed = [0x11u8; 32];
    store_header(&mut state, hb_header_round, &hb_seed, genesis_hash);

    // Land inside the risky challenge window: (challenge+grace/2, challenge+grace].
    let apply_round = challenge_round + params.payouts_challenge_grace_period / 2 + 1;
    assert!(apply_round > challenge_round);

    // `apply_block_validating` enforces round monotonicity against the
    // store's own `current_round` tracker (`expected = current_round + 1`).
    // `store_header` above only injects raw header/block bytes for lookup
    // purposes (mirroring go's `hdrProvider`/hb-seed checks), it does not
    // advance the chain -- so fast-forward the tracker directly rather than
    // replaying 1100 empty blocks just to reach a realistic challenge round.
    state.current_round = Round(apply_round - 1);

    let mut stx = build_heartbeat_transaction(HeartbeatParams {
        hb_address: pq_target,
        voting: &voting,
        vote_id,
        key_dilution,
        genesis_hash,
        latest_round: Round(hb_header_round),
        latest_seed: hb_seed,
        challenge_discount: true,
    });
    stx.txn.fee = 0;

    // Prove the discount computation itself is scheme-agnostic: an
    // ordinary accepting-LogicSig-signed heartbeat requires exactly zero
    // fee, independent of HbAddress being PQ-shaped.
    let (usage, _paid) = summarize_fees(&[&stx], &params);
    let (required_fee, overflow) = required_fee_for_usage(usage, &params);
    assert!(!overflow);
    assert_eq!(
        required_fee, 0,
        "a discounted heartbeat for a PQ-shaped HbAddress must still require zero fee"
    );

    let mut block = minimal_block(genesis_hash, fee_sink, apply_round);
    block.payset = vec![stx];
    assert_block_validates(&block, &genesis_hash);
    apply_block_validating(&mut state, &block).expect(
        "zero-fee discounted heartbeat for a challenged Falcon-addressed account must apply",
    );

    assert_eq!(
        state.get_account(&pq_target).unwrap().last_heartbeat,
        apply_round,
        "heartbeat must have updated the challenged account's LastHeartbeat"
    );
}

/// Writes a minimal block header (round, protocol, seed) into the store at
/// `round`, mirroring `apply.rs`'s private `store_block_header_with_seed`
/// test helper (duplicated here because that helper isn't exported --
/// integration tests only see `algo-ledger`'s public API).
fn store_header(state: &mut LedgerState, round: u64, seed: &[u8; 32], genesis_hash: [u8; 32]) {
    let mut block = minimal_block(genesis_hash, Address::ZERO, round);
    block.seed = *seed;
    let hdrdata = algo_codec::canonical_encode_block_header_from_block(&block);
    let blkdata = algo_codec::encode_block(&block).expect("encode block");
    state
        .put_block(round, CONSENSUS_V42, &hdrdata, &blkdata)
        .expect("put_block");
}
