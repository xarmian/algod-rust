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

//! State-proof signing/proving worker — the core algorithm behind
//! go-algorand's `stateproof` package (`stateproof/worker.go`,
//! `stateproof/signer.go`, `stateproof/builder.go`, `stateproof/db.go`).
//!
//! algod-rust already *verifies*/*applies* a state-proof transaction that
//! already exists in a block (`crate::apply_stateproof`) and tracks the
//! voters snapshot each proof round needs (`crate::voters_tracker`). This
//! module is the missing piece for a node that actually *participates* in
//! producing state proofs: given its own state-proof participation keys, it
//! signs eligible rounds, gathers/persists signatures (its own and peers'),
//! and builds the final `StateProof` once enough weight has signed —
//! wrapping the cryptographic core (`algo_consensus_crypto::stateproof::
//! Prover`, issue #814's crypto-side counterpart to the pre-existing
//! `Verifier`) with the round-eligibility, persistence, and gathering logic
//! go's `Worker` type provides.
//!
//! # Scope (see issue #814)
//!
//! This module implements the algorithmic core as a well-tested, standalone
//! set of types and pure functions:
//!
//! - **Round eligibility** ([`next_state_proof_round`],
//!   [`is_eligible_signing_round`], [`online_provers_threshold`],
//!   [`meets_broadcast_policy`]) — mirrors `signer.go`/`builder.go`'s
//!   round-arithmetic gates.
//! - **Per-account signing** ([`sign_state_proof_message`]) — mirrors
//!   `signer.go`'s `signStateProofMessage`, reusing the existing
//!   `merklesig::Secrets`/`Signer` Falcon-backed signing primitives.
//! - **Signature gathering** ([`SigCollector`]) — mirrors `builder.go`'s
//!   `spProver.insertSig`, wrapping `Prover` with the `AddrToPos` map real
//!   voters snapshots provide.
//! - **Persistence** (the `db` submodule) — mirrors `db.go`'s `sigs` table
//!   schema and queries exactly, via `rusqlite`.
//!
//! It deliberately does **not** wire these pieces into a live background
//! service inside `bin/algod-rust` that runs automatically, listens on the
//! gossip network for `StateProofSig` messages, or autonomously broadcasts
//! `StateProofTx` transactions — go's `Worker::Start`/`Stop`, its two
//! goroutines (`signer`, `builder`), and its network/transaction-sender
//! integration (`stateproof.Network`, `stateproof.TransactionSender`). That
//! needs live multi-node interop testing this pass cannot perform; wiring
//! it in without that verification risks a node that signs/broadcasts
//! incorrectly on live consensus. See the PR description for the
//! follow-up this defers to.

use std::collections::BTreeMap;

use algo_consensus_crypto::merklesig;
use algo_consensus_crypto::stateproof::{MessageHash, Prover, StateProofError};
use algo_types::Address;

// ── Round eligibility (stateproof/signer.go, stateproof/builder.go) ────

/// The round the signer should resume signing from, given the latest
/// block's tracked `StateProofNextRound` and the latest round itself.
///
/// Matches go's `Worker.nextStateProofRound` (`signer.go:60`): if state
/// proofs aren't enabled yet (`StateProofNextRound == 0`), start watching
/// from the round *after* the latest one; otherwise resume exactly where
/// the ledger's tracker says the chain still needs a proof.
pub fn next_state_proof_round(state_proof_next_round: u64, latest: u64) -> u64 {
    if state_proof_next_round == 0 {
        latest + 1
    } else {
        state_proof_next_round
    }
}

/// Whether `round` is one this node should sign (a nonzero multiple of the
/// consensus `StateProofInterval`).
///
/// Matches go's `Worker.signStateProof`'s round-eligibility gate
/// (`signer.go:90-97`): `proto.StateProofInterval == 0` (disabled) or
/// `round % interval != 0` both skip signing.
pub fn is_eligible_signing_round(round: u64, interval: u64) -> bool {
    interval != 0 && round % interval == 0
}

/// Soft limit on how many provers are kept in memory at once — the rest are
/// fetched from the database. Matches go's `proversCacheLength`
/// (`builder.go:40`): at least 2 to function (earliest + latest state
/// proof).
pub const PROVERS_CACHE_LENGTH: u64 = 5;

/// The highest round for which a prover should be kept in the in-memory
/// cache (and the boundary used to limit which pending signatures get
/// re-broadcast over the network).
///
/// Matches go's `onlineProversThreshold` (`builder.go:605`):
/// `stateProofNextRound + (proversCacheLength - 2) * interval` — reserving
/// slot `proversCacheLength - 1` for the *latest* round's prover, which may
/// be far ahead of `stateProofNextRound` if the state-proof chain is
/// stalled.
pub fn online_provers_threshold(state_proof_next_round: u64, interval: u64) -> u64 {
    state_proof_next_round + (PROVERS_CACHE_LENGTH - 2) * interval
}

/// Whether an externally-received signature for `sig_round` is worth
/// accepting, given the state-proof chain isn't stalled beyond reason.
///
/// Matches go's `Worker.meetsBroadcastPolicy` (`builder.go:331`): a
/// signature is accepted either when its round is within the online-prover
/// cache window, or when it's for the *current* latest state-proof round
/// (relevant precisely when the chain has stalled and `sig_round` is ahead
/// of `state_proof_next_round + cache window`).
pub fn meets_broadcast_policy(
    sig_round: u64,
    latest_round: u64,
    interval: u64,
    state_proof_next_round: u64,
) -> bool {
    if interval == 0 {
        return false;
    }
    if sig_round <= online_provers_threshold(state_proof_next_round, interval) {
        return true;
    }
    let latest_state_proof_round = latest_round - (latest_round % interval);
    sig_round == latest_state_proof_round
}

// ── Per-account signing (stateproof/signer.go's signStateProofMessage) ──

/// A signature on a state-proof message hash, ready to be gathered into a
/// [`Prover`] or broadcast to peers.
///
/// Matches go's `sigFromAddr` (`signer.go:36`).
#[derive(Debug, Clone)]
pub struct SigFromAddr {
    pub signer_address: Address,
    pub round: u64,
    pub sig: merklesig::Signature,
}

/// One participation account's state-proof signing key material for a
/// range of rounds, mirroring go's `account.StateProofSecretsForRound`
/// (the type `Accounts.StateProofKeys(round)` returns in go's `Worker`).
pub struct StateProofSigningKey<'a> {
    pub account: Address,
    pub first_valid: u64,
    pub last_valid: u64,
    pub secrets: &'a merklesig::Secrets,
}

/// Sign `message_hash` (the state-proof message for `round`) with every key
/// in `keys` that is eligible for `round` and hasn't already signed.
///
/// Matches go's `Worker.signStateProofMessage` (`signer.go:146`): for each
/// key, skip it if `round` falls outside `[FirstValid, LastValid]`, skip it
/// if `already_signed` reports a signature already exists (go checks this
/// against its local sig database — callers here supply that check via the
/// closure so this function stays storage-agnostic), then sign via the
/// key's `merklesig::Secrets` (go: `key.StateProofSecrets.SignBytes`) and
/// collect the resulting [`SigFromAddr`]. A key whose `sign_bytes` call
/// itself fails (go logs a warning and `continue`s) is silently skipped —
/// callers that want that visibility should log around this call.
pub fn sign_state_proof_message(
    message_hash: MessageHash,
    round: u64,
    keys: &[StateProofSigningKey<'_>],
    already_signed: impl Fn(Address) -> bool,
) -> Vec<SigFromAddr> {
    let mut sigs = Vec::with_capacity(keys.len());
    for key in keys {
        if key.first_valid > round || round > key.last_valid {
            continue;
        }
        if already_signed(key.account) {
            continue;
        }
        let signer = key.secrets.get_signer(round);
        let Ok(sig) = signer.sign_bytes(&message_hash) else {
            continue;
        };
        sigs.push(SigFromAddr {
            signer_address: key.account,
            round,
            sig,
        });
    }
    sigs
}

// ── Signature gathering (stateproof/builder.go's spProver.insertSig) ────

/// Errors from [`SigCollector::insert_sig`].
///
/// Matches go's sentinel errors in `builder.go` (`errAddressNotInVoters`,
/// `errFailedToAddSigAtPos`, `errSigAlreadyPresentAtPos`,
/// `errSignatureVerification`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InsertSigError {
    /// The signer's address is not among the selected voters for this
    /// round (go: `errAddressNotInVoters`).
    #[error("address not in participants for this round")]
    AddressNotInVoters,
    /// A signature is already present at this position (go:
    /// `errSigAlreadyPresentAtPos`).
    #[error("signature already present at this position")]
    AlreadyPresent,
    /// The signature failed cryptographic verification (go:
    /// `errSignatureVerification`).
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),
    /// Adding the signature to the underlying prover failed for a reason
    /// other than the above (go: `errFailedToAddSigAtPos`, plus the
    /// fallback "unknown error" arm of go's `handleSig`).
    #[error("could not add signature to prover: {0}")]
    FailedToAdd(String),
}

/// Wraps a [`Prover`] with the `Address -> position` map real voters
/// snapshots provide, gathering per-account signatures into it.
///
/// Matches go's `spProver` (`builder.go:45`), minus the `VotersHdr`/
/// `Message` fields that don't participate in signature gathering itself
/// (callers that need them — e.g. to decide whether/when to try building —
/// track them alongside a `SigCollector`, exactly as go's `spProver` embeds
/// them for the worker's own bookkeeping).
pub struct SigCollector {
    pub prover: Prover,
    pub addr_to_pos: BTreeMap<Address, u64>,
}

impl SigCollector {
    /// Construct a collector from a fresh [`Prover`] and the selected
    /// voters' address-to-position map (go: `voters.AddrToPos`, populated
    /// by the ledger's voters snapshot alongside the participant array
    /// itself).
    pub fn new(prover: Prover, addr_to_pos: BTreeMap<Address, u64>) -> Self {
        Self {
            prover,
            addr_to_pos,
        }
    }

    /// Insert one participant's signature. `verify` should be `false` only
    /// when the signature was already verified once (e.g. reloaded from a
    /// local database) — matches go's `spProver.insertSig` (`builder.go:287`)
    /// exactly, including its evaluation order: address lookup, then
    /// already-present check, then (optional) cryptographic verification,
    /// then insertion.
    pub fn insert_sig(
        &mut self,
        addr: Address,
        sig: merklesig::Signature,
        verify: bool,
    ) -> Result<(), InsertSigError> {
        let pos = *self
            .addr_to_pos
            .get(&addr)
            .ok_or(InsertSigError::AddressNotInVoters)?;

        let is_present = self
            .prover
            .present(pos)
            .map_err(|e| InsertSigError::FailedToAdd(e.to_string()))?;
        if is_present {
            return Err(InsertSigError::AlreadyPresent);
        }

        self.prover
            .is_valid(pos, &sig, verify)
            .map_err(|e| match e {
                StateProofError::SignatureVerificationFailed { .. }
                | StateProofError::SaltVersionMismatch => {
                    InsertSigError::VerificationFailed(e.to_string())
                }
                other => InsertSigError::FailedToAdd(other.to_string()),
            })?;

        self.prover
            .add(pos, sig)
            .map_err(|e| InsertSigError::FailedToAdd(e.to_string()))?;

        Ok(())
    }
}

// ── Persistence (stateproof/db.go) ───────────────────────────────────────

/// Local database persistence for pending signatures, mirroring go's
/// `sigs` table (`db.go`) via `rusqlite`. Kept as free functions over
/// `&rusqlite::Connection`/`&rusqlite::Transaction` (which derefs to
/// `Connection`) rather than a struct, matching this crate's existing
/// persistence-module style (e.g. `participation::stateproof_persist`).
pub mod db {
    use super::*;
    use rusqlite::{params, Connection, OptionalExtension};

    /// Matches go's `createSigsTable` (`db.go:41`): at most one signature
    /// per `(sprnd, signer)` pair (`UNIQUE (sprnd, signer)`).
    const CREATE_SIGS_TABLE: &str = "CREATE TABLE IF NOT EXISTS sigs (
        sprnd INTEGER,
        signer BLOB,
        sig BLOB,
        from_this_node INTEGER,
        UNIQUE (sprnd, signer)
    )";

    /// Matches go's `createSigsIdx` (`db.go:48`).
    const CREATE_SIGS_IDX: &str =
        "CREATE INDEX IF NOT EXISTS sigs_from_this_node ON sigs (from_this_node)";

    /// Install the `sigs` table (idempotent). Matches go's
    /// `dbSchemaUpgrade0` (`db.go:64`).
    pub fn install_sigs_table(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch(&format!("{CREATE_SIGS_TABLE}; {CREATE_SIGS_IDX};"))
    }

    /// A signature pending inclusion in a state proof, as stored on disk.
    ///
    /// Matches go's `pendingSig` (`db.go:97`).
    #[derive(Debug, Clone)]
    pub struct PendingSig {
        pub signer: Address,
        pub sig: merklesig::Signature,
        pub from_this_node: bool,
    }

    /// Matches go's `addPendingSig` (`db.go:103`).
    pub fn add_pending_sig(
        conn: &Connection,
        round: u64,
        psig: &PendingSig,
    ) -> rusqlite::Result<()> {
        conn.execute(
            "INSERT INTO sigs (sprnd, signer, sig, from_this_node) VALUES (?1, ?2, ?3, ?4)",
            params![
                round,
                psig.signer.0.as_slice(),
                psig.sig.to_msgpack(),
                psig.from_this_node,
            ],
        )?;
        Ok(())
    }

    /// Matches go's `deletePendingSigsBeforeRound` (`db.go:112`).
    pub fn delete_pending_sigs_before_round(conn: &Connection, round: u64) -> rusqlite::Result<()> {
        conn.execute("DELETE FROM sigs WHERE sprnd < ?1", params![round])?;
        Ok(())
    }

    /// Matches go's `sigExistsInDB` (`db.go:147`).
    pub fn sig_exists_in_db(conn: &Connection, round: u64, account: Address) -> rusqlite::Result<bool> {
        let exists: i64 = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sigs WHERE signer = ?1 AND sprnd = ?2)",
            params![account.0.as_slice(), round],
            |row| row.get(0),
        )?;
        Ok(exists != 0)
    }

    fn decode_row(
        signer: Vec<u8>,
        sigbuf: Vec<u8>,
        from_this_node: bool,
    ) -> rusqlite::Result<PendingSig> {
        let mut addr = [0u8; 32];
        let n = signer.len().min(32);
        addr[..n].copy_from_slice(&signer[..n]);
        let (sig, _) = merklesig::Signature::from_msgpack(&sigbuf).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                sigbuf.len(),
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            )
        })?;
        Ok(PendingSig {
            signer: Address(addr),
            sig,
            from_this_node,
        })
    }

    /// Pending sigs up to (and including) `threshold`, plus any sigs
    /// exactly at `max_round` (which may be higher than `threshold`) —
    /// grouped by round. Matches go's `getPendingSigs` (`db.go:119`).
    pub fn get_pending_sigs(
        conn: &Connection,
        threshold: u64,
        max_round: u64,
        only_from_this_node: bool,
    ) -> rusqlite::Result<BTreeMap<u64, Vec<PendingSig>>> {
        let mut query = String::from(
            "SELECT sprnd, signer, sig, from_this_node FROM sigs WHERE (sprnd <= ?1 OR sprnd = ?2)",
        );
        if only_from_this_node {
            query.push_str(" AND from_this_node = 1");
        }
        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map(params![threshold, max_round], |row| {
            let rnd: u64 = row.get(0)?;
            let signer: Vec<u8> = row.get(1)?;
            let sigbuf: Vec<u8> = row.get(2)?;
            let from_this_node: bool = row.get(3)?;
            Ok((rnd, signer, sigbuf, from_this_node))
        })?;

        let mut out: BTreeMap<u64, Vec<PendingSig>> = BTreeMap::new();
        for row in rows {
            let (rnd, signer, sigbuf, from_this_node) = row?;
            let psig = decode_row(signer, sigbuf, from_this_node)?;
            out.entry(rnd).or_default().push(psig);
        }
        Ok(out)
    }

    /// Pending sigs for exactly one round. Matches go's
    /// `getPendingSigsForRound` (`db.go:134`).
    pub fn get_pending_sigs_for_round(conn: &Connection, round: u64) -> rusqlite::Result<Vec<PendingSig>> {
        let mut stmt =
            conn.prepare("SELECT signer, sig, from_this_node FROM sigs WHERE sprnd = ?1")?;
        let rows = stmt.query_map(params![round], |row| {
            let signer: Vec<u8> = row.get(0)?;
            let sigbuf: Vec<u8> = row.get(1)?;
            let from_this_node: bool = row.get(2)?;
            Ok((signer, sigbuf, from_this_node))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (signer, sigbuf, from_this_node) = row?;
            out.push(decode_row(signer, sigbuf, from_this_node)?);
        }
        Ok(out)
    }

    /// Distinct rounds with pending sigs, up to `threshold` (plus
    /// `max_round`). Matches go's `getSignatureRounds` (`db.go:250`).
    pub fn get_signature_rounds(
        conn: &Connection,
        threshold: u64,
        max_round: u64,
    ) -> rusqlite::Result<Vec<u64>> {
        let mut stmt =
            conn.prepare("SELECT DISTINCT sprnd FROM sigs WHERE (sprnd <= ?1 OR sprnd = ?2)")?;
        let rows = stmt.query_map(params![threshold, max_round], |row| row.get::<_, u64>(0))?;
        rows.collect()
    }

    /// Whether a signature already exists for `(round, account)` — a thin,
    /// `Option`-returning convenience some callers prefer over
    /// [`sig_exists_in_db`]'s bool. Not present in go (go always uses the
    /// bool form) — provided for ergonomics only.
    #[allow(dead_code)]
    fn signer_of(conn: &Connection, round: u64, account: Address) -> rusqlite::Result<Option<Address>> {
        conn.query_row(
            "SELECT signer FROM sigs WHERE sprnd = ?1 AND signer = ?2",
            params![round, account.0.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map(|opt| {
            opt.map(|bytes| {
                let mut addr = [0u8; 32];
                let n = bytes.len().min(32);
                addr[..n].copy_from_slice(&bytes[..n]);
                Address(addr)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_consensus_crypto::merklearray;
    use algo_consensus_crypto::stateproof::{self, Participant};
    use rusqlite::Connection;

    // ── Round eligibility ────────────────────────────────────────────

    #[test]
    fn next_state_proof_round_starts_after_latest_when_disabled() {
        assert_eq!(next_state_proof_round(0, 100), 101);
    }

    #[test]
    fn next_state_proof_round_resumes_from_tracker() {
        assert_eq!(next_state_proof_round(512, 900), 512);
    }

    #[test]
    fn is_eligible_signing_round_requires_interval_multiple() {
        assert!(is_eligible_signing_round(256, 256));
        assert!(is_eligible_signing_round(512, 256));
        assert!(!is_eligible_signing_round(300, 256));
        assert!(!is_eligible_signing_round(256, 0), "disabled");
        // go's signStateProof has no round-0 special case: 0 % interval == 0
        // passes the modulo gate like any other multiple (in practice
        // nextStateProofRound never actually offers round 0 as a candidate,
        // since it starts from `latest + 1` at minimum -- see
        // next_state_proof_round -- but the gate itself doesn't exclude it).
        assert!(is_eligible_signing_round(0, 256));
    }

    #[test]
    fn online_provers_threshold_matches_go_formula() {
        // proversCacheLength=5: threshold = next + 3*interval.
        assert_eq!(online_provers_threshold(1024, 256), 1024 + 3 * 256);
        assert_eq!(online_provers_threshold(0, 256), 3 * 256);
    }

    #[test]
    fn meets_broadcast_policy_accepts_within_threshold_or_at_latest() {
        let interval = 256u64;
        let next = 1024u64;
        // Within threshold (1024 + 3*256 = 1792): accepted regardless of
        // latest round.
        assert!(meets_broadcast_policy(1792, 5000, interval, next));
        assert!(meets_broadcast_policy(256, 5000, interval, next));
        // Beyond threshold but exactly the current latest state-proof
        // round: still accepted (stalled-chain recovery path).
        let latest = 5000u64;
        let latest_sp_round = latest - (latest % interval);
        assert!(meets_broadcast_policy(latest_sp_round, latest, interval, next));
        // Beyond threshold and not the latest state-proof round: rejected.
        assert!(!meets_broadcast_policy(2048, latest, interval, next));
        // Disabled: always rejected.
        assert!(!meets_broadcast_policy(256, latest, 0, next));
    }

    // ── Per-account signing ──────────────────────────────────────────

    #[test]
    fn sign_state_proof_message_filters_by_validity_window_and_skips_signed() {
        let round = 500u64;
        let msg: MessageHash = [3u8; 32];

        let secrets_a = merklesig::Secrets::new(round, round, 1).unwrap();
        let secrets_b = merklesig::Secrets::new(round, round, 1).unwrap();
        let secrets_c = merklesig::Secrets::new(round, round, 1).unwrap();

        let addr_a = Address([1u8; 32]);
        let addr_b = Address([2u8; 32]);
        let addr_c = Address([3u8; 32]);

        let keys = vec![
            StateProofSigningKey {
                account: addr_a,
                first_valid: 0,
                last_valid: 1000,
                secrets: &secrets_a,
            },
            StateProofSigningKey {
                account: addr_b,
                // Not yet valid at `round`.
                first_valid: 501,
                last_valid: 1000,
                secrets: &secrets_b,
            },
            StateProofSigningKey {
                account: addr_c,
                first_valid: 0,
                last_valid: 1000,
                secrets: &secrets_c,
            },
        ];

        // addr_c already signed (per the predicate) -- should be skipped.
        let sigs = sign_state_proof_message(msg, round, &keys, |a| a == addr_c);

        assert_eq!(sigs.len(), 1, "only addr_a is eligible and unsigned");
        assert_eq!(sigs[0].signer_address, addr_a);
        assert_eq!(sigs[0].round, round);

        // The produced signature genuinely verifies against addr_a's key.
        let verifier = secrets_a.get_verifier();
        verifier.verify_bytes(round, &msg, &sigs[0].sig).expect("must verify");
    }

    #[test]
    fn sign_state_proof_message_empty_when_no_keys_eligible() {
        let round = 10u64;
        let msg: MessageHash = [0u8; 32];
        let secrets = merklesig::Secrets::new(100, 200, 1).unwrap();
        let keys = vec![StateProofSigningKey {
            account: Address([9u8; 32]),
            first_valid: 100,
            last_valid: 200,
            secrets: &secrets,
        }];
        let sigs = sign_state_proof_message(msg, round, &keys, |_| false);
        assert!(sigs.is_empty());
    }

    // ── SigCollector (signature gathering) ───────────────────────────

    fn build_collector(round: u64, msg: MessageHash, n: usize, weight: u64) -> (SigCollector, Vec<merklesig::Secrets>) {
        let mut secrets_list = Vec::with_capacity(n);
        let mut participants = Vec::with_capacity(n);
        let mut addr_to_pos = BTreeMap::new();
        for i in 0..n {
            let secrets = merklesig::Secrets::new(round, round, 1).unwrap();
            participants.push(Participant {
                pk: secrets.get_verifier(),
                weight,
            });
            let addr = Address([(i as u8) + 1; 32]);
            addr_to_pos.insert(addr, i as u64);
            secrets_list.push(secrets);
        }
        let factory = merklearray::HashFactory::new(merklearray::HashType::Sumhash);
        struct PartArray(Vec<Participant>);
        impl merklearray::Array for PartArray {
            fn length(&self) -> u64 {
                self.0.len() as u64
            }
            fn marshal(&self, pos: u64) -> Result<Box<dyn merklearray::Hashable>, merklearray::MerkleError> {
                Ok(Box::new(self.0[pos as usize].clone()))
            }
        }
        let part_tree =
            merklearray::build_vector_commitment_tree(&PartArray(participants.clone()), factory)
                .unwrap();
        let prover = Prover::make_prover(msg, round, weight, participants, part_tree, 0).unwrap();
        (SigCollector::new(prover, addr_to_pos), secrets_list)
    }

    #[test]
    fn sig_collector_inserts_valid_signature_and_advances_signed_weight() {
        let round = 20u64;
        let msg: MessageHash = [4u8; 32];
        let (mut collector, secrets_list) = build_collector(round, msg, 3, 100);

        let addr0 = Address([1u8; 32]);
        let sig = secrets_list[0].get_signer(round).sign_bytes(&msg).unwrap();
        collector.insert_sig(addr0, sig, true).expect("valid signature must insert");
        assert_eq!(collector.prover.signed_weight(), 100);
    }

    #[test]
    fn sig_collector_rejects_unknown_address() {
        let round = 20u64;
        let msg: MessageHash = [5u8; 32];
        let (mut collector, _secrets_list) = build_collector(round, msg, 2, 100);
        let stranger_secrets = merklesig::Secrets::new(round, round, 1).unwrap();
        let sig = stranger_secrets.get_signer(round).sign_bytes(&msg).unwrap();
        let err = collector
            .insert_sig(Address([99u8; 32]), sig, true)
            .expect_err("address not among voters");
        assert_eq!(err, InsertSigError::AddressNotInVoters);
    }

    #[test]
    fn sig_collector_rejects_duplicate_signature() {
        let round = 20u64;
        let msg: MessageHash = [6u8; 32];
        let (mut collector, secrets_list) = build_collector(round, msg, 2, 100);
        let addr0 = Address([1u8; 32]);
        let sig = secrets_list[0].get_signer(round).sign_bytes(&msg).unwrap();
        collector.insert_sig(addr0, sig.clone(), true).unwrap();
        let err = collector
            .insert_sig(addr0, sig, true)
            .expect_err("second insert at same address must fail");
        assert_eq!(err, InsertSigError::AlreadyPresent);
    }

    #[test]
    fn sig_collector_rejects_forged_signature_when_verifying() {
        let round = 20u64;
        let msg: MessageHash = [7u8; 32];
        let (mut collector, secrets_list) = build_collector(round, msg, 2, 100);
        let addr0 = Address([1u8; 32]);
        // Sign a different message than the prover's `data`.
        let wrong_sig = secrets_list[0]
            .get_signer(round)
            .sign_bytes(&[0xAAu8; 32])
            .unwrap();
        let err = collector
            .insert_sig(addr0, wrong_sig, true)
            .expect_err("forged signature must fail verification");
        assert!(matches!(err, InsertSigError::VerificationFailed(_)));
    }

    #[test]
    fn sig_collector_end_to_end_builds_a_verifiable_proof() {
        let round = 30u64;
        let msg: MessageHash = [8u8; 32];
        let (mut collector, secrets_list) = build_collector(round, msg, 5, 1000);
        let part_commit = collector.prover.part_tree.root();

        for i in [0usize, 1, 3] {
            let addr = Address([(i as u8) + 1; 32]);
            let sig = secrets_list[i].get_signer(round).sign_bytes(&msg).unwrap();
            collector.insert_sig(addr, sig, true).unwrap();
        }
        assert_eq!(collector.prover.signed_weight(), 3000);
        assert!(collector.prover.ready());

        let proof = collector.prover.create_proof().expect("create_proof");
        let verifier = stateproof::Verifier::new(part_commit, 1000, 0).unwrap();
        verifier.verify(round, msg, &proof).expect("must verify");
    }

    // ── DB persistence ───────────────────────────────────────────────

    fn fresh_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        db::install_sigs_table(&conn).unwrap();
        conn
    }

    fn dummy_sig() -> merklesig::Signature {
        let round = 1u64;
        let secrets = merklesig::Secrets::new(round, round, 1).unwrap();
        secrets.get_signer(round).sign_bytes(&[1u8; 32]).unwrap()
    }

    #[test]
    fn db_add_and_sig_exists_roundtrip() {
        let conn = fresh_db();
        let addr = Address([1u8; 32]);
        assert!(!db::sig_exists_in_db(&conn, 256, addr).unwrap());

        let psig = db::PendingSig {
            signer: addr,
            sig: dummy_sig(),
            from_this_node: true,
        };
        db::add_pending_sig(&conn, 256, &psig).unwrap();
        assert!(db::sig_exists_in_db(&conn, 256, addr).unwrap());
        assert!(!db::sig_exists_in_db(&conn, 512, addr).unwrap(), "different round");
    }

    #[test]
    fn db_unique_constraint_rejects_duplicate_signer_round() {
        let conn = fresh_db();
        let addr = Address([2u8; 32]);
        let psig = db::PendingSig {
            signer: addr,
            sig: dummy_sig(),
            from_this_node: false,
        };
        db::add_pending_sig(&conn, 256, &psig).unwrap();
        let err = db::add_pending_sig(&conn, 256, &psig).unwrap_err();
        // sqlite constraint violation, not a panic.
        assert!(matches!(err, rusqlite::Error::SqliteFailure(_, _)));
    }

    #[test]
    fn db_get_pending_sigs_for_round_returns_only_that_round() {
        let conn = fresh_db();
        let addr1 = Address([1u8; 32]);
        let addr2 = Address([2u8; 32]);
        db::add_pending_sig(
            &conn,
            256,
            &db::PendingSig {
                signer: addr1,
                sig: dummy_sig(),
                from_this_node: true,
            },
        )
        .unwrap();
        db::add_pending_sig(
            &conn,
            512,
            &db::PendingSig {
                signer: addr2,
                sig: dummy_sig(),
                from_this_node: false,
            },
        )
        .unwrap();

        let sigs_256 = db::get_pending_sigs_for_round(&conn, 256).unwrap();
        assert_eq!(sigs_256.len(), 1);
        assert_eq!(sigs_256[0].signer, addr1);
        assert!(sigs_256[0].from_this_node);

        let sigs_512 = db::get_pending_sigs_for_round(&conn, 512).unwrap();
        assert_eq!(sigs_512.len(), 1);
        assert_eq!(sigs_512[0].signer, addr2);
        assert!(!sigs_512[0].from_this_node);
    }

    #[test]
    fn db_get_pending_sigs_respects_threshold_and_max_round() {
        let conn = fresh_db();
        for (round, tag) in [(100u64, 1u8), (200, 2), (300, 3), (900, 9)] {
            db::add_pending_sig(
                &conn,
                round,
                &db::PendingSig {
                    signer: Address([tag; 32]),
                    sig: dummy_sig(),
                    from_this_node: true,
                },
            )
            .unwrap();
        }

        // threshold=250 admits rounds <=250, plus round 900 because it
        // equals max_round exactly (simulating "the current latest state
        // proof round", which is always included even beyond threshold).
        let grouped = db::get_pending_sigs(&conn, 250, 900, false).unwrap();
        let mut rounds: Vec<u64> = grouped.keys().copied().collect();
        rounds.sort_unstable();
        assert_eq!(rounds, vec![100, 200, 900]);
    }

    #[test]
    fn db_get_pending_sigs_only_from_this_node_filters() {
        let conn = fresh_db();
        db::add_pending_sig(
            &conn,
            100,
            &db::PendingSig {
                signer: Address([1u8; 32]),
                sig: dummy_sig(),
                from_this_node: true,
            },
        )
        .unwrap();
        db::add_pending_sig(
            &conn,
            100,
            &db::PendingSig {
                signer: Address([2u8; 32]),
                sig: dummy_sig(),
                from_this_node: false,
            },
        )
        .unwrap();

        let all = db::get_pending_sigs(&conn, 200, 200, false).unwrap();
        assert_eq!(all.get(&100).map(|v| v.len()), Some(2));

        let mine = db::get_pending_sigs(&conn, 200, 200, true).unwrap();
        assert_eq!(mine.get(&100).map(|v| v.len()), Some(1));
        assert!(mine[&100][0].from_this_node);
    }

    #[test]
    fn db_delete_pending_sigs_before_round() {
        let conn = fresh_db();
        for round in [100u64, 200, 300] {
            db::add_pending_sig(
                &conn,
                round,
                &db::PendingSig {
                    signer: Address([round as u8; 32]),
                    sig: dummy_sig(),
                    from_this_node: true,
                },
            )
            .unwrap();
        }
        db::delete_pending_sigs_before_round(&conn, 300).unwrap();
        let remaining = db::get_signature_rounds(&conn, 1000, 1000).unwrap();
        assert_eq!(remaining, vec![300]);
    }

    #[test]
    fn db_get_signature_rounds_is_distinct() {
        let conn = fresh_db();
        db::add_pending_sig(
            &conn,
            256,
            &db::PendingSig {
                signer: Address([1u8; 32]),
                sig: dummy_sig(),
                from_this_node: true,
            },
        )
        .unwrap();
        db::add_pending_sig(
            &conn,
            256,
            &db::PendingSig {
                signer: Address([2u8; 32]),
                sig: dummy_sig(),
                from_this_node: true,
            },
        )
        .unwrap();
        let rounds = db::get_signature_rounds(&conn, 1000, 1000).unwrap();
        assert_eq!(rounds, vec![256]);
    }

    #[test]
    fn db_sig_roundtrips_through_msgpack() {
        let conn = fresh_db();
        let addr = Address([7u8; 32]);
        let sig = dummy_sig();
        db::add_pending_sig(
            &conn,
            256,
            &db::PendingSig {
                signer: addr,
                sig: sig.clone(),
                from_this_node: true,
            },
        )
        .unwrap();
        let got = db::get_pending_sigs_for_round(&conn, 256).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].sig.signature, sig.signature);
        assert_eq!(
            got[0].sig.vector_commitment_index,
            sig.vector_commitment_index
        );
    }
}
