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

//! Heartbeat transaction construction — the pieces of go-algorand's
//! `heartbeat/service.go` that build a signed `hb` transaction from a
//! locally-held participation key.
//!
//! Split out from [`crate::heartbeat`] (which holds the *decision* logic --
//! `find_challenge`/`Challenge::failed`/`needs_heartbeat` -- ported from
//! `ledger/apply/challenge.go`) because this module additionally needs
//! `OneTimeSignatureSecrets::sign` (`algo_consensus_crypto`) and TEAL
//! assembly (`algo_avm`) to actually produce a transaction, rather than
//! just deciding whether one is needed.

use std::sync::OnceLock;

use algo_avm::assembler::assemble_string;
use algo_consensus_crypto::OneTimeSignatureSecrets;
use algo_types::{
    Address, HeartbeatProof, HeartbeatTxnFields, LogicSig, Round, SignedTransaction, Transaction,
    TxnType,
};

/// go-algorand's "accepting" LogicSig program (`heartbeat/service.go`):
///
/// ```teal
/// #pragma version 11
/// txn RekeyTo; global ZeroAddress; ==; intcblock 2;
/// ```
///
/// Approves anything except a rekey; the trailing `intcblock 2` is
/// unreachable code whose only purpose (per Go's comment) is to make the
/// program's hash decompress to an invalid Ed25519 point, so the resulting
/// contract-account address can never coincide with a real spending key --
/// nobody can ever produce a delegated signature for it, only the LogicSig
/// itself can authorize spends from it, and the program is deliberately
/// never given amount/receiver fields that would let it spend anything.
const ACCEPTING_TEAL_SOURCE: &str =
    "#pragma version 11\ntxn RekeyTo; global ZeroAddress; ==; intcblock 2;\n";

/// How many rounds a heartbeat transaction is valid for.
///
/// Mirrors Go's `hbLifetime` (`heartbeat/service.go`): "somewhat short...
/// better to try several times during the grace period than to try a single
/// time with a longer lifetime."
pub const HB_LIFETIME: u64 = 10;

/// Domain-separation prefix for the third (leaf) level of a heartbeat proof:
/// the ephemeral key signs `"SD" || seed`. Mirrors go-algorand's
/// `protocol.Seed` `HashID` (`protocol/hash.go`) and duplicates
/// `algo_validate::signature`'s private `SEED_PREFIX` constant (that
/// module's own `verify_heartbeat_proof` is the byte-for-byte match this
/// constant must keep producing signable messages for).
const HB_SEED_PREFIX: &[u8] = b"SD";

fn accepting_program() -> &'static [u8] {
    static PROGRAM: OnceLock<Vec<u8>> = OnceLock::new();
    PROGRAM
        .get_or_init(|| {
            assemble_string(ACCEPTING_TEAL_SOURCE)
                .unwrap_or_else(|errs| {
                    panic!("BUG: accepting heartbeat LogicSig program failed to assemble: {errs:?}")
                })
                .program
        })
        .as_slice()
}

/// The contract-account address of the accepting LogicSig program: the
/// `Sender` every locally-generated heartbeat transaction uses.
///
/// Mirrors Go's `acceptingSender = basics.Address(logic.HashProgram(acceptingByteCode))`.
pub fn accepting_sender() -> Address {
    algo_validate::signature::hash_program(accepting_program())
}

/// Sign a heartbeat proof over `seed` using a participation key's one-time
/// signature secrets, for a heartbeat transaction whose `LastValid` is
/// `last_valid`.
///
/// Mirrors Go's:
/// ```go
/// id := basics.OneTimeIDForRound(stxn.Txn.LastValid, pr.KeyDilution)
/// pr.Voting.Sign(id, latest.Seed).ToHeartbeatProof()
/// ```
/// `OneTimeSignatureSecrets::sign` derives the same `(batch, offset)` pair
/// from `(last_valid, key_dilution)` internally that
/// `basics.OneTimeIDForRound` computes explicitly in Go, so passing
/// `last_valid` through directly is equivalent. The signed message is `"SD"
/// || seed`, matching `algo_validate::signature::verify_heartbeat_proof`'s
/// leaf-level check (`Seed` implements `Hashable` in Go with `ToBeHashed()
/// -> (protocol.Seed, seed[:])`, i.e. the same raw prefix-concatenation).
pub fn sign_heartbeat_proof(
    voting: &OneTimeSignatureSecrets,
    last_valid: u64,
    key_dilution: u64,
    seed: &[u8; 32],
) -> HeartbeatProof {
    let mut msg = Vec::with_capacity(HB_SEED_PREFIX.len() + seed.len());
    msg.extend_from_slice(HB_SEED_PREFIX);
    msg.extend_from_slice(seed);

    let ots = voting.sign(&msg, last_valid, key_dilution);
    HeartbeatProof {
        sig: ots.sig,
        pk: ots.pk,
        pk2: ots.pk2,
        pk1_sig: ots.pk1_sig,
        pk2_sig: ots.pk2_sig,
    }
}

/// Everything needed to build a signed heartbeat transaction for one
/// challenged account.
pub struct HeartbeatParams<'a> {
    /// The account being heartbeat for (`HbAddress`) -- NOT the transaction
    /// `Sender`, which is always [`accepting_sender`].
    pub hb_address: Address,
    /// The account's one-time-signature secrets (from the locally-held
    /// participation key).
    pub voting: &'a OneTimeSignatureSecrets,
    /// The account's registered `OneTimeSignatureVerifier` (`HbVoteID`).
    pub vote_id: [u8; 32],
    /// The account's registered key dilution (`HbKeyDilution`).
    pub key_dilution: u64,
    /// Genesis hash for the transaction header.
    pub genesis_hash: [u8; 32],
    /// The latest committed round; the heartbeat's `FirstValid` and the
    /// block seed (`HbSeed`) it proves over both come from this round's
    /// header, matching `apply_heartbeat`'s check that `HbSeed` equals the
    /// header seed at `FirstValid` exactly (not `FirstValid - 1`).
    pub latest_round: Round,
    /// The block seed at `latest_round` (`HbSeed`).
    pub latest_seed: [u8; 32],
    /// Whether to claim the post-v42 explicit challenge-fee discount
    /// (`HbChallengeDiscount`); set this to
    /// `ConsensusParams::txn_size_pricing_enabled()` at `latest_round`'s
    /// protocol. Before that gate gets Assembly, the zero fee alone signals
    /// the claim and this must stay `false` (`WellFormed` rejects it set
    /// otherwise).
    pub challenge_discount: bool,
}

/// Build (and "sign", via the accepting LogicSig) a heartbeat transaction
/// for one challenged account.
///
/// Mirrors Go's `Service.prepareHeartbeat` (`heartbeat/service.go`). The
/// transaction is fee-exempt (`Fee` left at zero) -- the accepting LogicSig
/// sender never needs a funded account, matching the "Free Heartbeats"
/// design (`heartbeat/README.md`): any account, even an unfunded logicsig,
/// can send heartbeats for a challenged account.
pub fn build_heartbeat_transaction(params: HeartbeatParams<'_>) -> SignedTransaction {
    let first_valid = params.latest_round;
    let last_valid = Round(params.latest_round.0 + HB_LIFETIME);

    let proof = sign_heartbeat_proof(
        params.voting,
        last_valid.0,
        params.key_dilution,
        &params.latest_seed,
    );

    let txn = Transaction {
        txn_type: TxnType::Hb,
        sender: accepting_sender(),
        fee: 0,
        first_valid,
        last_valid,
        genesis_hash: params.genesis_hash,
        heartbeat: Some(HeartbeatTxnFields {
            address: params.hb_address,
            proof: Some(proof),
            seed: params.latest_seed,
            vote_id: params.vote_id,
            key_dilution: params.key_dilution,
            hb_challenge_discount: params.challenge_discount,
        }),
        ..Transaction::default()
    };

    SignedTransaction {
        txn,
        lsig: Some(LogicSig {
            logic: serde_bytes::ByteBuf::from(accepting_program().to_vec()),
            ..LogicSig::default()
        }),
        ..SignedTransaction::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_consensus_crypto::one_time_id_for_round;

    #[test]
    fn accepting_program_assembles_and_is_stable() {
        // Same bytes every call (cached via OnceLock), and non-empty.
        let a = accepting_program();
        let b = accepting_program();
        assert!(!a.is_empty());
        assert_eq!(a, b);
    }

    #[test]
    fn accepting_sender_is_stable_and_not_all_zero() {
        let addr1 = accepting_sender();
        let addr2 = accepting_sender();
        assert_eq!(addr1, addr2);
        assert_ne!(addr1.0, [0u8; 32]);
    }

    /// Port of go-algorand's `TestHeartbeatAcceptingSenderIsPQCompliant`
    /// (`heartbeat/service_test.go`): the accepting LogicSig's contract
    /// account address must not decompress to a valid Edwards25519 point,
    /// so it can never coincide with a real (or PQ) spending key -- this is
    /// the whole reason the program ends in an unreachable `intcblock 2`
    /// (see `ACCEPTING_TEAL_SOURCE`'s doc comment).
    #[test]
    fn accepting_sender_is_pq_compliant() {
        assert!(
            accepting_sender().is_pq_compliant(),
            "heartbeat accepting LogicSig sender must be PQ compliant"
        );
    }

    #[test]
    fn sign_heartbeat_proof_verifies_under_the_real_verifier() {
        let first_id = one_time_id_for_round(0, 10);
        let last_id = one_time_id_for_round(2000, 10);
        let num_batches = last_id.batch - first_id.batch + 1;
        let voting = OneTimeSignatureSecrets::generate(first_id.batch, num_batches);
        let vote_id = voting.verifier();
        let seed = [0x77u8; 32];
        let last_valid = 1500u64;
        let key_dilution = 10u64;

        let proof = sign_heartbeat_proof(&voting, last_valid, key_dilution, &seed);

        algo_validate::signature::verify_heartbeat_proof(
            &proof,
            &vote_id,
            last_valid,
            key_dilution,
            &seed,
        )
        .expect("proof produced by sign_heartbeat_proof must verify");
    }

    #[test]
    fn sign_heartbeat_proof_rejects_under_wrong_seed() {
        let first_id = one_time_id_for_round(0, 10);
        let last_id = one_time_id_for_round(2000, 10);
        let num_batches = last_id.batch - first_id.batch + 1;
        let voting = OneTimeSignatureSecrets::generate(first_id.batch, num_batches);
        let vote_id = voting.verifier();
        let seed = [0x77u8; 32];
        let wrong_seed = [0x88u8; 32];
        let last_valid = 1500u64;
        let key_dilution = 10u64;

        let proof = sign_heartbeat_proof(&voting, last_valid, key_dilution, &seed);

        assert!(algo_validate::signature::verify_heartbeat_proof(
            &proof,
            &vote_id,
            last_valid,
            key_dilution,
            &wrong_seed,
        )
        .is_err());
    }

    #[test]
    fn build_heartbeat_transaction_produces_verifiable_proof_and_expected_fields() {
        let first_id = one_time_id_for_round(0, 10);
        let last_id = one_time_id_for_round(2000, 10);
        let num_batches = last_id.batch - first_id.batch + 1;
        let voting = OneTimeSignatureSecrets::generate(first_id.batch, num_batches);
        let vote_id = voting.verifier();
        let hb_address = Address([9u8; 32]);
        let seed = [0x11u8; 32];
        let genesis_hash = [0x22u8; 32];

        let stx = build_heartbeat_transaction(HeartbeatParams {
            hb_address,
            voting: &voting,
            vote_id,
            key_dilution: 10,
            genesis_hash,
            latest_round: Round(1000),
            latest_seed: seed,
            challenge_discount: true,
        });

        assert_eq!(stx.txn.txn_type, TxnType::Hb);
        assert_eq!(stx.txn.sender, accepting_sender());
        assert_eq!(stx.txn.fee, 0);
        assert_eq!(stx.txn.first_valid, Round(1000));
        assert_eq!(stx.txn.last_valid, Round(1000 + HB_LIFETIME));
        assert_eq!(stx.txn.genesis_hash, genesis_hash);
        assert_eq!(
            stx.txn.group, [0u8; 32],
            "must be a singleton, ungrouped txn"
        );
        assert!(stx.txn.note.is_empty());
        assert_eq!(stx.txn.lease, [0u8; 32]);
        assert!(stx.txn.rekey_to.is_none());

        let hb = stx.txn.heartbeat.expect("heartbeat fields must be set");
        assert_eq!(hb.address, hb_address);
        assert_eq!(hb.seed, seed);
        assert_eq!(hb.vote_id, vote_id);
        assert_eq!(hb.key_dilution, 10);
        assert!(hb.hb_challenge_discount);

        let proof = hb.proof.expect("proof must be set");
        algo_validate::signature::verify_heartbeat_proof(
            &proof,
            &vote_id,
            stx.txn.last_valid.0,
            10,
            &seed,
        )
        .expect("built transaction's proof must verify");

        let lsig = stx.lsig.expect("must carry the accepting LogicSig");
        assert_eq!(lsig.logic.as_slice(), accepting_program());
    }
}
