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

//! Salted-key (`SaltedKeySig`) account authorization through real ledger
//! apply, for every scheme go v5.1 can authorize with: `f1` and `f5` (Falcon),
//! `ed` (Ed25519 under a salted, off-curve address) and `ls` (a LogicSig
//! program the address commits to). Ports go's
//! `TestSaltedRekeyedAddressAuthorization`,
//! `TestSaltedLogicSigRekeyedAddressAuthorization` and
//! `TestSaltedChallengedAccountCanHeartbeatForZeroFee`
//! (`ledger/eval_simple_test.go`, v5.1.1-stable; issues #2544, #2546, #2547),
//! driven through the same two stages a submitted block goes through:
//! `validate_block` (real signature/program/fee verification) then
//! `apply_block_validating` (ledger state and the authorizer check), under the
//! `future` consensus protocol where the new schemes are enabled.

use algo_codec::canonical_encode_transaction;
use algo_consensus_crypto::{one_time_id_for_round, OneTimeSignatureSecrets};
use algo_ledger::{
    apply_block_validating, build_heartbeat_transaction, HeartbeatParams, LedgerState, LedgerStore,
};
use algo_types::consensus::{consensus_params_for_version, ConsensusParams, CONSENSUS_FUTURE};
use algo_types::{
    canonical_address_salt, AccountStatus, Address, AddressSalt, Block, Round, SaltedKeySig,
    SignedTransaction, SIG_SCHEME_ED25519, SIG_SCHEME_FALCON1024, SIG_SCHEME_FALCON512,
    SIG_SCHEME_LOGIC_SIG,
};
use algo_validate::block::validate_block;
use algo_validate::fee::{required_fee_for_txn, required_fee_for_usage, summarize_fees};
use ed25519_dalek::{Signer, SigningKey};
use serde_bytes::ByteBuf;

const PROTO: &str = CONSENSUS_FUTURE;

/// Domain-separation prefix for the top-level transaction signing message
/// (`"TX" || canonical_encode(txn)`) — the same message ed25519 single-sig,
/// multisig, and top-level `SaltedKeySig` all authenticate. Mirrors go-algorand's
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
        // go's validateForPayouts requires a proposer on a validated block.
        proposer: Address([0x55; 32]),
        fee_sink,
        rewards_pool: Address::ZERO,
        rewards_level: 0,
        rewards_rate: 0,
        rewards_residue: 0,
        rewards_recalculation_round: Round(0),
        current_protocol: PROTO.to_string(),
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

/// Install `txns` as the block's payset in the stored in-block form (go
/// `EncodeSignedTxn`): gen/gh stripped, the header supplies them back. go's
/// `DecodeSignedTxn` rejects a txn still carrying them (issue #1727).
fn set_payset(block: &mut Block, mut txns: Vec<algo_types::SignedTransaction>) {
    algo_types::genesis_restore::GenesisRestoreRule::for_block(block).strip_payset(&mut txns);
    block.payset = txns;
    // ...and `FeesCollected` must equal what the payset paid.
    block.fees_collected =
        algo_ledger::block_header::payset_fees_collected(&block.payset, &block.fee_sink);
}

/// Assert a block validates cleanly (real signature/fee/proof checks) and
/// panic with the collected errors otherwise — every scenario below wants
/// crypto-clean blocks except the one that specifically expects
/// `apply_block_validating` (ledger-state authorizer check) to reject.
///
/// Recomputes `block.load` first (V42's `LoadTracking`/"bad load" check —
/// see `algo_validate::block`'s own `set_expected_load` test helper): this
/// file's blocks are built directly via `make_next_block_header`, which
/// deliberately leaves `load: 0` and defers the real computation to
/// production code (`participate.rs`), so a non-empty payset here would
/// otherwise fail validation on the unrelated Load field rather than the
/// signature/fee/wellformedness behavior each scenario actually exercises.
fn assert_block_validates(block: &mut Block, genesis_hash: &[u8; 32]) {
    let total_bytes: usize = block
        .payset
        .iter()
        .map(|stx| algo_codec::canonical_encode_signed_txn_in_block(stx).len())
        .sum();
    if let Ok(max_bytes) = algo_validate::rules::max_txn_bytes_per_block(&block.current_protocol) {
        block.load = algo_validate::rules::compute_expected_load(total_bytes, max_bytes);
    }

    let result = validate_block(block, None, "", genesis_hash, None);
    assert!(
        result.is_valid,
        "block failed real signature/fee/wellformedness validation: {:?}",
        result.errors
    );
}

/// A salted-key account of one scheme: its address, and how it authorizes.
struct SaltedAccount {
    scheme: [u8; 2],
    salt: AddressSalt,
    public_key: Vec<u8>,
    address: Address,
    signer: KeyKind,
}

enum KeyKind {
    Falcon1024(Vec<u8>),
    Falcon512(Vec<u8>),
    Ed25519(SigningKey),
    /// the program's arguments
    LogicSig(Vec<Vec<u8>>),
}

/// go's `#pragma version 14; pushbytes "open sesame"; arg_0; ==`.
fn open_sesame() -> Vec<u8> {
    let mut p = vec![0x0e, 0x80, 0x0b];
    p.extend_from_slice(b"open sesame");
    p.extend_from_slice(&[0x2d, 0x12]);
    p
}

fn salted_account(scheme: [u8; 2], seed_byte: u8) -> SaltedAccount {
    let seed = [seed_byte; algo_falcon::FALCON_SEED_SIZE];
    let (public_key, signer) = match &scheme {
        b"f1" => {
            let (pk, sk) = algo_falcon::falcon_keygen(&seed).expect("keygen f1");
            (pk, KeyKind::Falcon1024(sk))
        }
        b"f5" => {
            let (pk, sk) = algo_falcon::falcon512_keygen(&seed).expect("keygen f5");
            (pk, KeyKind::Falcon512(sk))
        }
        b"ed" => {
            let sk = SigningKey::from_bytes(&seed);
            (sk.verifying_key().to_bytes().to_vec(), KeyKind::Ed25519(sk))
        }
        b"ls" => (
            open_sesame(),
            KeyKind::LogicSig(vec![b"open sesame".to_vec()]),
        ),
        other => panic!("{other:?}"),
    };
    let (salt, address) = canonical_address_salt(scheme, &public_key).expect("canonical salt");
    SaltedAccount {
        scheme,
        salt,
        public_key,
        address,
        signer,
    }
}

impl SaltedAccount {
    /// The proof for `txn`, or a signature-less placeholder when `txn` is `None`
    /// (to size the fee before signing).
    fn proof(&self, txn: Option<&algo_types::Transaction>) -> SaltedKeySig {
        let signature = match (&self.signer, txn) {
            (_, None) => Vec::new(),
            (KeyKind::Falcon1024(sk), Some(t)) => {
                algo_falcon::falcon_sign(sk, &tx_sign_message(t)).expect("sign f1")
            }
            (KeyKind::Falcon512(sk), Some(t)) => {
                algo_falcon::falcon512_sign(sk, &tx_sign_message(t)).expect("sign f5")
            }
            (KeyKind::Ed25519(sk), Some(t)) => sk.sign(&tx_sign_message(t)).to_bytes().to_vec(),
            (KeyKind::LogicSig(args), Some(_)) => {
                let a: Vec<Option<Vec<u8>>> = args.iter().cloned().map(Some).collect();
                algo_codec::encode_logic_sig_args(&a)
            }
        };
        SaltedKeySig {
            scheme: self.scheme,
            salt: self.salt,
            public_key: ByteBuf::from(self.public_key.clone()),
            signature: ByteBuf::from(signature),
        }
    }
}

fn params() -> ConsensusParams {
    consensus_params_for_version(PROTO).expect("future params")
}

fn pay(
    sender: Address,
    receiver: Address,
    amount: u64,
    rekey_to: Option<Address>,
    uniq: u8,
    genesis_hash: [u8; 32],
) -> algo_types::Transaction {
    algo_types::Transaction {
        txn_type: "pay".into(),
        sender,
        receiver,
        amount,
        first_valid: Round(1),
        last_valid: Round(1000),
        genesis_hash,
        rekey_to,
        note: ByteBuf::from(vec![uniq]),
        ..Default::default()
    }
}

/// Fund and sign `txn` with the salted account `acct` (declaring `auth_addr`).
fn sign_salted(
    acct: &SaltedAccount,
    mut txn: algo_types::Transaction,
    auth_addr: Option<Address>,
) -> SignedTransaction {
    let probe = SignedTransaction {
        txn: txn.clone(),
        pqsig: Some(acct.proof(None)),
        auth_addr,
        ..Default::default()
    };
    let (usage, _) = summarize_fees(&[&probe], &params());
    let (fee, overflow) = required_fee_for_usage(usage, &params());
    assert!(!overflow);
    txn.fee = fee;
    SignedTransaction {
        pqsig: Some(acct.proof(Some(&txn))),
        txn,
        auth_addr,
        ..Default::default()
    }
}

fn sign_ed(
    key: &SigningKey,
    mut txn: algo_types::Transaction,
    auth_addr: Option<Address>,
) -> SignedTransaction {
    let (fee, _) = required_fee_for_txn(&txn, &params());
    txn.fee = fee;
    SignedTransaction {
        sig: key.sign(&tx_sign_message(&txn)).to_bytes(),
        txn,
        auth_addr,
        ..Default::default()
    }
}

/// Apply `txns` as the block at `round`: validated, then applied.
fn apply(
    state: &mut LedgerState,
    genesis_hash: [u8; 32],
    fee_sink: Address,
    round: u64,
    txns: Vec<SignedTransaction>,
) -> Result<(), String> {
    let mut block = minimal_block(genesis_hash, fee_sink, round);
    set_payset(&mut block, txns);
    assert_block_validates(&mut block, &genesis_hash);
    apply_block_validating(state, &block)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn fresh_state(fee_sink: Address, accounts: &[(Address, u64)]) -> LedgerState {
    let mut state = algo_ledger::apply::pool_fixtures::funded_ledger_state();
    state.fee_sink = fee_sink;
    for (addr, micro) in accounts {
        state.get_or_default_account_mut(addr).micro_algos = *micro;
    }
    state.get_or_default_account_mut(&fee_sink).micro_algos = 0;
    state
}

const SCHEMES: [[u8; 2]; 4] = [
    SIG_SCHEME_FALCON1024,
    SIG_SCHEME_FALCON512,
    SIG_SCHEME_ED25519,
    SIG_SCHEME_LOGIC_SIG,
];

/// go's `TestSaltedRekeyedAddressAuthorization` (and its ls twin): an ed25519
/// account rekeys to the salted address and is spent from by the salted
/// proof; the stale key can no longer spend; and the reverse, a salted account
/// rekeyed to an ed25519 key, spent from by that key, its own proof now stale.
fn rekeyed_authorization(scheme: [u8; 2]) {
    let p = params();
    assert!(p.sig_scheme_enabled(scheme));
    let gh = [0x99u8; 32];
    let fee_sink = Address([0xFEu8; 32]);
    let receiver = Address([0xB2u8; 32]);
    let ed_key = SigningKey::from_bytes(&[0xA1u8; 32]);
    let ed_addr = Address(ed_key.verifying_key().to_bytes());
    let ed2_key = SigningKey::from_bytes(&[0xA2u8; 32]);
    let ed2_addr = Address(ed2_key.verifying_key().to_bytes());
    let salted = salted_account(scheme, 7);

    // 1. ed -> salted: rekey, then the salted proof spends from the ed account
    let mut state = fresh_state(
        fee_sink,
        &[
            (ed_addr, 10_000_000),
            (receiver, 100_000),
            (salted.address, 10_000_000),
        ],
    );
    let rekey = sign_ed(
        &ed_key,
        pay(ed_addr, ed_addr, 0, Some(salted.address), 1, gh),
        None,
    );
    apply(&mut state, gh, fee_sink, 1, vec![rekey]).expect("rekey block");
    assert_eq!(
        state.get_account(&ed_addr).unwrap().auth_addr,
        Some(salted.address)
    );
    let spend = sign_salted(
        &salted,
        pay(ed_addr, receiver, 1_000, None, 2, gh),
        Some(salted.address),
    );
    apply(&mut state, gh, fee_sink, 2, vec![spend])
        .expect("salted-key spend from the rekeyed account");
    assert_eq!(state.get_account(&receiver).unwrap().micro_algos, 101_000);

    // the stale ed25519 key can no longer spend it
    let stale = sign_ed(&ed_key, pay(ed_addr, receiver, 1_000, None, 3, gh), None);
    let e = apply(&mut state, gh, fee_sink, 3, vec![stale]).expect_err("stale key");
    assert!(
        e.contains("should have been authorized by"),
        "{scheme:?}: {e}"
    );

    // 2. salted -> ed2: the salted proof rekeys, ed2 spends, the proof is stale
    let mut state = fresh_state(
        fee_sink,
        &[
            (salted.address, 10_000_000),
            (receiver, 100_000),
            (ed2_addr, 1_000_000),
        ],
    );
    let rekey = sign_salted(
        &salted,
        pay(salted.address, receiver, 1, Some(ed2_addr), 4, gh),
        None,
    );
    apply(&mut state, gh, fee_sink, 1, vec![rekey]).expect("salted account rekeys itself to ed");
    assert_eq!(
        state.get_account(&salted.address).unwrap().auth_addr,
        Some(ed2_addr)
    );
    let spend = sign_ed(
        &ed2_key,
        pay(salted.address, receiver, 1_000, None, 5, gh),
        Some(ed2_addr),
    );
    apply(&mut state, gh, fee_sink, 2, vec![spend]).expect("the new ed key spends");
    let stale = sign_salted(
        &salted,
        pay(salted.address, receiver, 1_000, None, 6, gh),
        None,
    );
    let e = apply(&mut state, gh, fee_sink, 3, vec![stale]).expect_err("stale salted proof");
    assert!(
        e.contains("should have been authorized by"),
        "{scheme:?}: {e}"
    );
}

#[test]
fn salted_rekeyed_address_authorization_falcon1024() {
    rekeyed_authorization(SIG_SCHEME_FALCON1024);
}

#[test]
fn salted_rekeyed_address_authorization_falcon512() {
    rekeyed_authorization(SIG_SCHEME_FALCON512);
}

#[test]
fn salted_rekeyed_address_authorization_ed25519() {
    rekeyed_authorization(SIG_SCHEME_ED25519);
}

#[test]
fn salted_rekeyed_address_authorization_logic_sig() {
    rekeyed_authorization(SIG_SCHEME_LOGIC_SIG);
}

/// go's `TestSaltedChallengedAccountCanHeartbeatForZeroFee`: a challenged,
/// online, eligible account at a salted address is heartbeated for zero fee by
/// the ordinary accepting LogicSig sender, whatever its scheme.
fn challenged_heartbeat(scheme: [u8; 2]) {
    let p = params();
    assert!(p.txn_size_pricing_enabled());
    let gh = [0x99u8; 32];
    let fee_sink = Address([0xFEu8; 32]);
    let target = salted_account(scheme, 0x0A).address;

    let key_dilution = 10u64;
    let first_id = one_time_id_for_round(0, key_dilution);
    let last_id = one_time_id_for_round(3000, key_dilution);
    let voting =
        OneTimeSignatureSecrets::generate(first_id.batch, last_id.batch - first_id.batch + 1);
    let vote_id = voting.verifier();

    let mut state = algo_ledger::apply::pool_fixtures::funded_ledger_state();
    state.fee_sink = fee_sink;
    {
        let acct = state.get_or_default_account_mut(&target);
        acct.micro_algos = 5_000_000;
        acct.status = AccountStatus::Online;
        acct.vote_id = Some(vote_id);
        acct.vote_key_dilution = key_dilution;
        acct.incentive_eligible = true;
        acct.last_heartbeat = 0;
        acct.last_proposed = 0;
    }
    state.get_or_default_account_mut(&fee_sink).micro_algos = 0;

    let challenge_round = p.payouts_challenge_interval;
    store_header(&mut state, challenge_round, &target.0, gh);
    let apply_round = challenge_round + p.payouts_challenge_grace_period / 2 + 1;
    let hb_header_round = apply_round - 1;
    let hb_seed = [0x11u8; 32];
    store_header(&mut state, hb_header_round, &hb_seed, gh);
    state.current_round = Round(apply_round - 1);

    let mut stx = build_heartbeat_transaction(HeartbeatParams {
        hb_address: target,
        voting: &voting,
        vote_id,
        key_dilution,
        genesis_hash: gh,
        latest_round: Round(hb_header_round),
        latest_seed: hb_seed,
        challenge_discount: true,
    });
    stx.txn.fee = 0;
    let (usage, _) = summarize_fees(&[&stx], &p);
    let (required, overflow) = required_fee_for_usage(usage, &p);
    assert!(!overflow);
    assert_eq!(
        required, 0,
        "{scheme:?}: a discounted heartbeat must require zero fee"
    );

    let mut block = minimal_block(gh, fee_sink, apply_round);
    set_payset(&mut block, vec![stx]);
    assert_block_validates(&mut block, &gh);
    apply_block_validating(&mut state, &block).expect("zero-fee discounted heartbeat applies");
    assert_eq!(
        state.get_account(&target).unwrap().last_heartbeat,
        apply_round
    );
}

#[test]
fn salted_challenged_account_can_heartbeat_for_zero_fee_every_scheme() {
    for scheme in SCHEMES {
        challenged_heartbeat(scheme);
    }
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
        .put_block(round, PROTO, &hdrdata, &blkdata)
        .expect("put_block");
}
