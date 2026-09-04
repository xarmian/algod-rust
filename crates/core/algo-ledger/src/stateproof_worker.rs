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

use algo_consensus_crypto::merklearray;
use algo_consensus_crypto::merklesig;
use algo_consensus_crypto::stateproof::{self as crypto_sp, MessageHash, Prover, StateProofError};
use algo_error::AlgoError;
use algo_types::consensus::consensus_params_for_version;
use algo_types::{Address, StateProofBody, StateProofMessage};
use serde_bytes::ByteBuf;

use crate::store_trait::LedgerStore;

fn ledger_err(message: impl Into<String>) -> AlgoError {
    AlgoError::Ledger {
        message: message.into(),
    }
}

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

impl SigFromAddr {
    /// Canonical msgpack encoding for gossip transmission over
    /// `Tag::StateProofSig` -- matches go's `sigFromAddr` codec tags
    /// exactly: `"a"` (SignerAddress), `"r"` (Round), `"s"` (Sig),
    /// omitempty, sorted lexicographically ("a" < "r" < "s").
    pub fn to_msgpack(&self) -> Vec<u8> {
        let addr_zero = self.signer_address.is_zero();
        let sig_bytes = self.sig.to_msgpack();
        let sig_empty = sig_bytes == [0x80];

        let mut field_count: u8 = 0;
        if !addr_zero {
            field_count += 1;
        }
        if self.round != 0 {
            field_count += 1;
        }
        if !sig_empty {
            field_count += 1;
        }

        let mut buf = Vec::with_capacity(8 + sig_bytes.len());
        buf.push(0x80 | field_count);
        if !addr_zero {
            write_fixstr(&mut buf, "a");
            rmp::encode::write_bin(&mut buf, &self.signer_address.0).unwrap();
        }
        if self.round != 0 {
            write_fixstr(&mut buf, "r");
            rmp::encode::write_uint(&mut buf, self.round).unwrap();
        }
        if !sig_empty {
            write_fixstr(&mut buf, "s");
            buf.extend_from_slice(&sig_bytes);
        }
        buf
    }

    /// Decode a [`SigFromAddr`] previously produced by [`Self::to_msgpack`]
    /// (or by a real go peer, whose canonical encoder produces the
    /// identical field set/ordering). Unknown map keys are ignored,
    /// matching this crate's other forward-compatible msgpack readers.
    pub fn from_msgpack(data: &[u8]) -> Result<Self, String> {
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(data))
            .map_err(|e| format!("SigFromAddr: decode: {e}"))?;
        let rmpv::Value::Map(fields) = value else {
            return Err("SigFromAddr: expected a msgpack map".to_string());
        };

        let mut signer_address = Address::default();
        let mut round = 0u64;
        let mut sig = merklesig::Signature::default();

        for (key, val) in fields {
            match key.as_str() {
                Some("a") => {
                    if let Some(bytes) = val.as_slice() {
                        let mut addr = [0u8; 32];
                        let n = bytes.len().min(32);
                        addr[..n].copy_from_slice(&bytes[..n]);
                        signer_address = Address(addr);
                    }
                }
                Some("r") => round = val.as_u64().unwrap_or(0),
                Some("s") => {
                    let mut sig_buf = Vec::new();
                    rmpv::encode::write_value(&mut sig_buf, &val)
                        .map_err(|e| format!("SigFromAddr: re-encode sig: {e}"))?;
                    let (decoded, _) = merklesig::Signature::from_msgpack(&sig_buf)
                        .map_err(|e| format!("SigFromAddr: sig: {e}"))?;
                    sig = decoded;
                }
                _ => {}
            }
        }

        Ok(SigFromAddr {
            signer_address,
            round,
            sig,
        })
    }
}

fn write_fixstr(buf: &mut Vec<u8>, s: &str) {
    debug_assert!(s.len() <= 31, "fixstr supports up to 31 bytes");
    buf.push(0xa0 | s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
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

// ── Autonomous daemon runtime (issue #814's live-daemon-wiring scope) ──
//
// The pieces above (round eligibility, per-account signing, [`SigCollector`],
// the `db` persistence module) are the algorithmic core PR #898 landed.
// What follows wraps them into the per-round orchestration a live
// `bin/algod-rust` background service needs: lazily building/caching a
// [`SigCollector`] per state-proof round from the ledger's persisted
// voters snapshot ([`crate::voters_tracker::voters_participants_and_tree`]/
// [`crate::voters_tracker::voters_addr_to_pos`], issue #912 extended by
// #814 to carry addresses), gathering signatures into it (mirroring go's
// `Worker.handleSig`, `builder.go:343`), and building the final
// `StateProof` once ready (mirroring `tryBroadcast`, `builder.go:641`).
//
// Deliberately simplified relative to go's `Worker`:
// - No disk-persisted `provers` table (go's `stateproof/db.go`'s `provers`
//   table, `persistProver`/`getProver`) -- [`StateProofRuntime`] is
//   in-memory only, rebuilt from the `sigs` table (this module's `db`
//   submodule) and the ledger's own voters-snapshot persistence on daemon
//   restart. A restart therefore re-verifies every already-gathered
//   signature once (cheap) rather than trusting a cached prover object.
// - [`StateProofRuntime::try_build`] always targets the *final*,
//   full-`ProvenWeight` proof rather than go's `AcceptableStateProofWeight`
//   incremental schedule (`stateproof/verify/stateproof.go`), which lets a
//   real node accept smaller (cheaper-to-verify) proofs early in a round's
//   signing window and only fall back to the full threshold once enough
//   time has passed. Skipping that schedule is strictly safe (a proof this
//   runtime submits always meets the *full* proven-weight bar, a strict
//   superset of what any smaller acceptable-weight proof would need) --
//   just potentially slower to produce the very first proof of a round.

use crate::apply_stateproof::state_proof_message_hash;
use crate::stateproof_message::generate_state_proof_message;
use crate::voters_tracker::{voters_addr_to_pos, voters_participants_and_tree};

/// `a*b/d`, matching go's `basics.Muldiv` usage for `provenWeight = total *
/// WeightThreshold / (1<<32)`. Returns `None` on overflow.
fn muldiv_u64_u32(a: u64, b: u32, d: u64) -> Option<u64> {
    let product = (a as u128) * (b as u128);
    u64::try_from(product / (d as u128)).ok()
}

/// One state-proof round's in-memory prover state plus the message it was
/// built to sign, mirroring go's `spProver` (`builder.go:45`) minus the
/// `VotersHdr` field (not needed by this simplified implementation's
/// `try_build`, which skips go's `AcceptableStateProofWeight` schedule --
/// see this section's doc comment) and disk persistence.
pub struct ProverEntry {
    pub collector: SigCollector,
    pub message: StateProofMessage,
}

/// Build a fresh [`ProverEntry`] for `round`, mirroring go's `createProver`
/// (`builder.go:181`): resolve the voters round/lookback, retrieve the
/// persisted participant array + address map for it, resolve the proven
/// weight from the voters header's online total weight, build the message,
/// and construct the [`Prover`]/[`SigCollector`] pair.
fn create_prover_entry<L: LedgerStore>(store: &L, round: u64) -> Result<ProverEntry, AlgoError> {
    let hdr = store.get_block_header(round)?.ok_or_else(|| {
        ledger_err(format!("create_prover_entry: no block header for round {round}"))
    })?;
    let params = consensus_params_for_version(&hdr.current_protocol).ok_or_else(|| {
        ledger_err(format!(
            "create_prover_entry: unknown consensus protocol '{}'",
            hdr.current_protocol
        ))
    })?;
    if params.state_proof_interval == 0 {
        return Err(ledger_err(
            "create_prover_entry: state proofs are not enabled for this protocol",
        ));
    }

    let voters_round = round.saturating_sub(params.state_proof_interval);
    let lookback = voters_round.saturating_sub(params.state_proof_voters_lookback);

    let (participants, tree) = voters_participants_and_tree(store, lookback)?.ok_or_else(|| {
        ledger_err(format!(
            "create_prover_entry: no voters snapshot recorded for lookback round {lookback} \
             (round {round}'s state proof cannot be built yet)"
        ))
    })?;
    let addr_to_pos = voters_addr_to_pos(store, lookback)?.ok_or_else(|| {
        ledger_err(format!(
            "create_prover_entry: no address map recorded for lookback round {lookback}"
        ))
    })?;

    let voters_hdr = store.get_block_header(voters_round)?.ok_or_else(|| {
        ledger_err(format!(
            "create_prover_entry: no block header for voters round {voters_round}"
        ))
    })?;
    let online_total_weight =
        crate::block_header::state_proof_online_total_weight(&voters_hdr.state_proof_tracking);
    let proven_weight = muldiv_u64_u32(
        online_total_weight,
        params.state_proof_weight_threshold,
        1u64 << 32,
    )
    .ok_or_else(|| ledger_err("create_prover_entry: overflow computing provenWeight"))?;

    let message = generate_state_proof_message(store, round)?;
    let msg_hash = state_proof_message_hash(&message);

    let prover = Prover::make_prover(
        msg_hash,
        round,
        proven_weight,
        participants,
        tree,
        params.state_proof_strength_target,
    )
    .map_err(|e| ledger_err(format!("create_prover_entry: {e}")))?;

    Ok(ProverEntry {
        collector: SigCollector::new(prover, addr_to_pos),
        message,
    })
}

/// Outcome of [`StateProofRuntime::handle_sig`], mirroring the two
/// dispositions of go's `network.ForwardingPolicy` this daemon actually
/// needs (`Worker.handleSig`, `builder.go:343`): a genuinely new, valid
/// signature should be gossiped onward; anything already known is safe to
/// silently drop. (Go's third disposition, `Disconnect`, is left to the
/// caller: the gossip-handling layer decides what to do with a
/// cryptographically invalid or off-voters-list signature, since that's a
/// network-policy decision, not an algorithmic one.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigOutcome {
    Broadcast,
    Ignore,
}

/// Errors from [`StateProofRuntime::handle_sig`].
#[derive(Debug, thiserror::Error)]
pub enum HandleSigError {
    #[error("ledger: {0}")]
    Ledger(#[from] AlgoError),
    #[error(transparent)]
    InsertSig(#[from] InsertSigError),
}

/// Lazily-populated per-round prover cache plus submitted-round bookkeeping
/// for the autonomous signing/proving daemon. Pure/synchronous and
/// independent of any network/thread machinery, so it is unit-testable
/// directly -- mirrors go's `Worker.provers` map plus the "already built
/// and submitted" half of `tryBroadcast`'s loop-break behavior.
#[derive(Default)]
pub struct StateProofRuntime {
    provers: BTreeMap<u64, ProverEntry>,
    submitted: std::collections::BTreeSet<u64>,
}

impl StateProofRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get (creating if needed) the prover entry for `round`.
    fn ensure_prover<L: LedgerStore>(&mut self, store: &L, round: u64) -> Result<(), AlgoError> {
        match self.provers.entry(round) {
            std::collections::btree_map::Entry::Occupied(_) => {}
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(create_prover_entry(store, round)?);
            }
        }
        Ok(())
    }

    /// The message a round's prover is signing over, if a prover has been
    /// built for it yet.
    pub fn message_for(&self, round: u64) -> Option<&StateProofMessage> {
        self.provers.get(&round).map(|e| &e.message)
    }

    pub fn has_prover(&self, round: u64) -> bool {
        self.provers.contains_key(&round)
    }

    pub fn signed_weight(&self, round: u64) -> Option<u64> {
        self.provers.get(&round).map(|e| e.collector.prover.signed_weight())
    }

    pub fn is_submitted(&self, round: u64) -> bool {
        self.submitted.contains(&round)
    }

    pub fn mark_submitted(&mut self, round: u64) {
        self.submitted.insert(round);
    }

    /// Insert one signature into `sfa.round`'s prover, lazily creating the
    /// prover entry first if needed. Mirrors the insertion half of go's
    /// `Worker.handleSig` (`builder.go:343`): an already-present signature
    /// is a harmless [`SigOutcome::Ignore`], not an error.
    pub fn handle_sig<L: LedgerStore>(
        &mut self,
        store: &L,
        sfa: &SigFromAddr,
    ) -> Result<SigOutcome, HandleSigError> {
        self.ensure_prover(store, sfa.round)?;
        let entry = self
            .provers
            .get_mut(&sfa.round)
            .expect("ensure_prover just inserted this round's entry");
        match entry
            .collector
            .insert_sig(sfa.signer_address, sfa.sig.clone(), true)
        {
            Ok(()) => Ok(SigOutcome::Broadcast),
            Err(InsertSigError::AlreadyPresent) => Ok(SigOutcome::Ignore),
            Err(e) => Err(HandleSigError::InsertSig(e)),
        }
    }

    /// For every not-yet-submitted round (in ascending order) whose prover
    /// has gathered enough signed weight, build the `StateProof` and
    /// return it alongside the message it attests to -- the caller
    /// constructs and broadcasts the `StateProofTx`, then calls
    /// [`Self::mark_submitted`]. Mirrors go's `tryBroadcast`
    /// (`builder.go:641`): stops at the first round that isn't ready yet,
    /// since `StateProofNext` only ever advances sequentially -- a later
    /// round's proof can't be submitted before an earlier one is.
    pub fn try_build(&mut self) -> Vec<(u64, crypto_sp::StateProof, StateProofMessage)> {
        let mut out = Vec::new();
        let rounds: Vec<u64> = self.provers.keys().copied().collect();
        for round in rounds {
            if self.submitted.contains(&round) {
                continue;
            }
            let entry = self.provers.get_mut(&round).expect("round from provers keys");
            if !entry.collector.prover.ready() {
                tracing::debug!(
                    round,
                    signed_weight = entry.collector.prover.signed_weight(),
                    proven_weight = entry.collector.prover.proven_weight,
                    "stateproof: try_build: round not ready yet, stopping ascending scan"
                );
                break;
            }
            match entry.collector.prover.create_proof() {
                Ok(proof) => out.push((round, proof, entry.message.clone())),
                Err(e) => {
                    tracing::warn!(
                        round,
                        error = %e,
                        signed_weight = entry.collector.prover.signed_weight(),
                        proven_weight = entry.collector.prover.proven_weight,
                        "stateproof: try_build: create_proof failed, stopping ascending scan"
                    );
                    break;
                }
            }
        }
        out
    }

    /// Discard cached provers/submitted-markers below `retain_round` --
    /// mirrors go's `trimProversCache`/`deleteStaleProver` retention
    /// (simplified: no special-cased "keep the latest round too" slot,
    /// since this runtime has no historical-replay path that would need
    /// it).
    pub fn prune(&mut self, retain_round: u64) {
        self.provers.retain(|&r, _| r >= retain_round);
        self.submitted.retain(|&r| r >= retain_round);
    }
}

// ── Wire conversion: crypto StateProof -> StateProofBody (issue #814) ──
//
// The inverse of `apply_stateproof.rs`'s private `convert_state_proof`
// (wire -> crypto, used to verify an already-built proof). This direction
// is needed once, here, to embed a freshly-*built* proof into the
// `StateProofTx` this daemon submits.
//
// Every substructure is wrapped in `Some(..)` unconditionally rather than
// hand-replicating go's per-field omitempty detection: `algo_codec`'s
// `canonical_encode_state_proof_body`/`canonical_encode_merkle_proof`/etc.
// already omit a zero-valued field (or an entirely empty nested map, via
// `CanonicalMap::add_map`'s empty-map check) regardless of whether the
// intermediate Rust value was wrapped in `Some` or left as `None` -- so a
// `Some(zero-value)` here still round-trips to the same canonical bytes a
// hand-tuned `None` would have produced.

fn wire_hash_factory(hf: &merklearray::HashFactory) -> Option<algo_types::HashFactory> {
    Some(algo_types::HashFactory {
        hash_type: hf.hash_type as u16,
    })
}

fn wire_merkle_proof(p: &merklearray::Proof) -> Option<algo_types::MerkleProof> {
    let path = if p.path.is_empty() {
        None
    } else {
        Some(
            p.path
                .iter()
                .map(|d| {
                    if d.is_empty() {
                        None
                    } else {
                        Some(ByteBuf::from(d.clone()))
                    }
                })
                .collect(),
        )
    };
    Some(algo_types::MerkleProof {
        path,
        hash_factory: wire_hash_factory(&p.hash_factory),
        tree_depth: p.tree_depth,
    })
}

fn wire_falcon_verifier(fv: &merklesig::FalconVerifier) -> Option<algo_types::FalconVerifier> {
    Some(algo_types::FalconVerifier {
        public_key: ByteBuf::from(fv.k.to_vec()),
    })
}

fn wire_merkle_signature(sig: &merklesig::Signature) -> Option<algo_types::MerkleSignature> {
    Some(algo_types::MerkleSignature {
        signature: ByteBuf::from(sig.signature.clone()),
        vector_commitment_index: sig.vector_commitment_index,
        proof: wire_merkle_proof(&sig.proof.proof),
        verifying_key: wire_falcon_verifier(&sig.verifying_key),
    })
}

fn wire_sig_slot(slot: &crypto_sp::SigSlotCommit) -> Option<algo_types::SigSlotCommit> {
    Some(algo_types::SigSlotCommit {
        sig: wire_merkle_signature(&slot.sig),
        l: slot.l,
    })
}

fn wire_participant(p: &crypto_sp::Participant) -> Option<algo_types::Participant> {
    Some(algo_types::Participant {
        pk: Some(algo_types::MerkleSignatureVerifier {
            commitment: p.pk.commitment,
            key_lifetime: p.pk.key_lifetime,
        }),
        weight: p.weight,
    })
}

fn wire_reveal(r: &crypto_sp::Reveal) -> algo_types::Reveal {
    algo_types::Reveal {
        sig_slot: wire_sig_slot(&r.sig_slot),
        part: wire_participant(&r.part),
    }
}

/// Convert a freshly-built `crypto_sp::StateProof` into the wire
/// `StateProofBody` a `StateProofTx` embeds.
pub fn state_proof_body_from_crypto(sp: &crypto_sp::StateProof) -> StateProofBody {
    let reveals = if sp.reveals.is_empty() {
        None
    } else {
        Some(
            sp.reveals
                .iter()
                .map(|(pos, r)| (*pos, wire_reveal(r)))
                .collect(),
        )
    };
    let positions_to_reveal = if sp.positions_to_reveal.is_empty() {
        None
    } else {
        Some(sp.positions_to_reveal.clone())
    };
    StateProofBody {
        sig_commit: ByteBuf::from(sp.sig_commit.clone()),
        signed_weight: sp.signed_weight,
        sig_proofs: wire_merkle_proof(&sp.sig_proofs),
        part_proofs: wire_merkle_proof(&sp.part_proofs),
        merkle_signature_salt_version: sp.merkle_signature_salt_version,
        reveals,
        positions_to_reveal,
    }
}

/// Build the (unsigned -- `STATE_PROOF_SENDER` needs no signature)
/// `StateProofTx` `SignedTransaction` for a just-built proof, ready for
/// `LocalTxBroadcaster::submit_group`.
///
/// Matches go's `Worker.tryBroadcast` transaction construction
/// (`builder.go:676-684`): `FirstValid` is the *current* ledger tip at
/// submission time (not the state-proof round itself), `LastValid =
/// FirstValid + MaxTxnLife`, zero fee (the sender's zero-signature-category
/// bypass exempts it from the fee floor -- see `algo_pool::fee`), and no
/// `lsig`/`sig`/`msig` at all (go's `stxn.Txn` has no signature fields set
/// either -- `verify/txn.go:344`'s zero-signature-category check is what
/// allows this).
pub fn build_state_proof_transaction(
    latest_round: u64,
    max_txn_life: u64,
    genesis_hash: [u8; 32],
    proof: &crypto_sp::StateProof,
    message: &StateProofMessage,
) -> algo_types::SignedTransaction {
    let txn = algo_types::Transaction {
        txn_type: algo_types::TxnType::Stpf,
        sender: Address::STATE_PROOF_SENDER,
        fee: 0,
        first_valid: algo_types::Round(latest_round),
        last_valid: algo_types::Round(latest_round + max_txn_life),
        genesis_hash,
        state_proof_type: 0,
        state_proof: Some(state_proof_body_from_crypto(proof)),
        state_proof_message: Some(message.clone()),
        ..algo_types::Transaction::default()
    };
    algo_types::SignedTransaction {
        txn,
        ..algo_types::SignedTransaction::default()
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

    // ── StateProofRuntime: try_build's ascending-scan + prune interaction
    //    (issue #814 live mixed-cluster verification) ──────────────────

    /// `try_build` scans `provers` in ascending round order and stops at the
    /// first not-ready round, mirroring go's `tryBroadcast` -- correct when
    /// state proofs genuinely can't skip an interval. But it doesn't handle
    /// a real multi-node race: some OTHER online signer can independently
    /// gather enough weight and commit the earlier round's `StateProofTx`
    /// first, and this node's own local prover for that round then never
    /// gathers more signatures (peers stop broadcasting for an
    /// already-superseded round) -- so without pruning, `try_build` stays
    /// wedged on the stale round forever, even once a LATER round's prover
    /// has gathered full weight. `prune(retain_round)` (fed by the ledger's
    /// own `StateProofNextRound`, exactly like go's
    /// `OnPrepareVoterCommit`/`trimProversCache`) is what breaks the wedge.
    #[test]
    fn try_build_is_wedged_by_a_stale_round_until_pruned() {
        let mut rt = StateProofRuntime::new();

        // Round 16: only 1 of 3 participants signed (not ready) -- stands in
        // for "this node lost the race; the network already committed round
        // 16's real proof via another signer, so no more round-16 sigs will
        // ever arrive here".
        let (mut early_collector, early_secrets) = build_collector(16, [1u8; 32], 3, 100);
        early_collector
            .insert_sig(
                Address([1u8; 32]),
                early_secrets[0].get_signer(16).sign_bytes(&[1u8; 32]).unwrap(),
                true,
            )
            .unwrap();
        assert!(!early_collector.prover.ready(), "only 1/3 weight signed");
        rt.provers.insert(
            16,
            ProverEntry {
                collector: early_collector,
                message: StateProofMessage::default(),
            },
        );

        // Round 32: all 3 participants signed -- genuinely ready to build.
        let (mut late_collector, late_secrets) = build_collector(32, [2u8; 32], 3, 100);
        for (i, secrets) in late_secrets.iter().enumerate() {
            late_collector
                .insert_sig(
                    Address([(i as u8) + 1; 32]),
                    secrets.get_signer(32).sign_bytes(&[2u8; 32]).unwrap(),
                    true,
                )
                .unwrap();
        }
        assert!(late_collector.prover.ready(), "3/3 weight signed");
        rt.provers.insert(
            32,
            ProverEntry {
                collector: late_collector,
                message: StateProofMessage::default(),
            },
        );

        // Before pruning: the ascending scan hits round 16 first, finds it
        // not ready, and stops -- round 32 is never even attempted, despite
        // being fully ready.
        assert!(
            rt.try_build().is_empty(),
            "must not build anything while the stale round-16 entry blocks the scan"
        );

        // The ledger reports round 32 as the next one still needed (i.e.
        // round 16's real proof already landed on-chain via another
        // signer) -- prune discards the now-moot round-16 entry.
        rt.prune(32);
        assert!(!rt.provers.contains_key(&16), "stale round must be pruned");
        assert!(rt.provers.contains_key(&32), "still-needed round must survive");

        // Now the ascending scan reaches round 32 immediately and builds it.
        let built = rt.try_build();
        assert_eq!(built.len(), 1, "round 32 must now build");
        assert_eq!(built[0].0, 32);
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

    // ── SigFromAddr wire encoding ────────────────────────────────────

    #[test]
    fn sig_from_addr_round_trips_through_msgpack() {
        let sig = dummy_sig();
        let sfa = SigFromAddr {
            signer_address: Address([9u8; 32]),
            round: 512,
            sig: sig.clone(),
        };
        let wire = sfa.to_msgpack();
        let decoded = SigFromAddr::from_msgpack(&wire).unwrap();
        assert_eq!(decoded.signer_address, sfa.signer_address);
        assert_eq!(decoded.round, sfa.round);
        assert_eq!(decoded.sig.signature, sig.signature);
        assert_eq!(
            decoded.sig.vector_commitment_index,
            sig.vector_commitment_index
        );
    }

    #[test]
    fn sig_from_addr_rejects_garbage() {
        assert!(SigFromAddr::from_msgpack(&[0xFF, 0xFF]).is_err());
    }

    // ── build_state_proof_transaction ────────────────────────────────

    #[test]
    fn build_state_proof_transaction_is_fee_exempt_and_unsigned() {
        let sp = crypto_sp::StateProof {
            sig_commit: vec![1, 2, 3],
            signed_weight: 100,
            sig_proofs: merklearray::Proof::default(),
            part_proofs: merklearray::Proof::default(),
            merkle_signature_salt_version: 0,
            reveals: BTreeMap::new(),
            positions_to_reveal: vec![],
        };
        let msg = StateProofMessage {
            first_attested_round: 1,
            last_attested_round: 512,
            ..Default::default()
        };
        let stx = build_state_proof_transaction(1000, 1000, [7u8; 32], &sp, &msg);
        assert_eq!(stx.txn.txn_type, algo_types::TxnType::Stpf);
        assert_eq!(stx.txn.sender, Address::STATE_PROOF_SENDER);
        assert_eq!(stx.txn.fee, 0, "state proofs are fee-exempt");
        assert_eq!(stx.txn.first_valid, algo_types::Round(1000));
        assert_eq!(stx.txn.last_valid, algo_types::Round(2000));
        assert_eq!(stx.txn.genesis_hash, [7u8; 32]);
        assert_eq!(stx.sig, [0u8; 64]);
        assert!(stx.msig.is_none() && stx.lsig.is_none());
        assert_eq!(
            stx.txn.state_proof.as_ref().unwrap().signed_weight,
            100
        );
        assert_eq!(
            stx.txn.state_proof_message.as_ref().unwrap().last_attested_round,
            512
        );
    }
}
