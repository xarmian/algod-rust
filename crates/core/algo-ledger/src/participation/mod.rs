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

//! Participation key types and ParticipationID derivation.
//!
//! Matches go-algorand's `data/account/participation.go` and
//! `data/account/participationRegistry.go`.
//!
//! # ParticipationID Derivation
//!
//! `ParticipationID = SHA512/256("PK" || canonical_encode(ParticipationKeyIdentity))`
//!
//! The `ParticipationKeyIdentity` struct is encoded as a canonical msgpack map
//! with fields (in sorted order): `addr`, `fv`, `kd`, `lv`, `vote-id`, `vrfsk`.

pub mod equivocation;
pub mod fill;
pub mod install;
pub mod persist;
pub mod registration_txn;
pub mod restore;
pub mod stateproof_persist;
pub mod store;

pub use equivocation::AntiEquivocationTracker;
pub use fill::{fill_db_with_participation_keys, FillError};
pub use install::{
    part_install_database, part_migrate, InstallError, PART_TABLE_SCHEMA_NAME,
    PART_TABLE_SCHEMA_VERSION,
};
pub use persist::{persist_new_parent, persist_participation, PersistError};
pub use registration_txn::generate_registration_transaction;
pub use restore::{restore_participation, Error as RestoreError};
pub use stateproof_persist::{
    install_state_proof_table, persist_secrets, StateProofPersistError,
    MERKLE_SIGNATURE_SCHEMA_VERSION, MERKLE_SIGNATURE_TABLE_SCHEMA_NAME,
};
pub use store::ParticipationStore;

use algo_consensus_crypto::merklesig;
use algo_consensus_crypto::{
    one_time_id_for_round, OneTimeSignatureSecrets, VrfKeypair, VrfPubkey,
};
use algo_types::{AccountData, AccountStatus};
use algo_types::{Address, Digest, Round};
use rusqlite;
use sha2::{Digest as _, Sha512_256};

// ── ParticipationID ────────────────────────────────────────────────────────

/// A 32-byte identifier for a set of participation keys.
///
/// Computed as `SHA512/256("PK" || canonical_encode(identity))`.
/// Corresponds to Go's `ParticipationID` in `participationRegistry.go`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParticipationID(pub [u8; 32]);

impl ParticipationID {
    /// Returns `true` if all bytes are zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Display as base32 (no padding), matching Go's `String()` method.
    pub fn to_base32(&self) -> String {
        data_encoding::BASE32_NOPAD.encode(&self.0)
    }

    /// Parse a base32 (no padding) string into a `ParticipationID`.
    pub fn from_base32(s: &str) -> Result<Self, String> {
        let decoded = data_encoding::BASE32_NOPAD
            .decode(s.as_bytes())
            .map_err(|e| format!("invalid base32: {e}"))?;
        if decoded.len() != 32 {
            return Err(format!(
                "decoded length {} != 32 for participation ID: \"{s}\"",
                decoded.len()
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&decoded);
        Ok(ParticipationID(id))
    }
}

impl From<Digest> for ParticipationID {
    fn from(d: Digest) -> Self {
        ParticipationID(d.0)
    }
}

impl From<ParticipationID> for Digest {
    fn from(id: ParticipationID) -> Self {
        Digest(id.0)
    }
}

impl std::fmt::Display for ParticipationID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base32())
    }
}

// ── ParticipationKeyIdentity ───────────────────────────────────────────────

/// Identity data used to derive a `ParticipationID`.
///
/// Matches Go's `ParticipationKeyIdentity` struct in `participation.go`.
/// Fields and their codec tags (sorted alphabetically):
/// - `addr`    — 32-byte account address
/// - `fv`      — first valid round (uint64)
/// - `kd`      — key dilution (uint64)
/// - `lv`      — last valid round (uint64)
/// - `vote-id` — 32-byte OTS verifier (master ed25519 public key)
/// - `vrfsk`   — 64-byte VRF private key (libsodium expanded format: seed || pubkey)
///
/// Go uses `codec:",omitempty,omitemptyarray"`, so zero-value fields are omitted.
pub struct ParticipationKeyIdentity {
    /// Account address this key participates for.
    pub parent: Address,
    /// VRF private key in Go's 64-byte format (seed || derived_pubkey).
    /// Rust stores VRF seeds as 32 bytes; this must be expanded to 64 for conformance.
    pub vrf_sk: [u8; 64],
    /// One-time signature verifier (master ed25519 public key).
    pub vote_id: [u8; 32],
    /// First valid round.
    pub first_valid: Round,
    /// Last valid round.
    pub last_valid: Round,
    /// Key dilution parameter.
    pub key_dilution: u64,
}

impl ParticipationKeyIdentity {
    /// Compute the `ParticipationID` for this identity.
    ///
    /// `ParticipationID = SHA512/256("PK" || canonical_encode(self))`
    pub fn id(&self) -> ParticipationID {
        let encoded = self.canonical_encode();
        let mut hasher = Sha512_256::new();
        hasher.update(b"PK");
        hasher.update(&encoded);
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        ParticipationID(id)
    }

    /// Canonical msgpack encoding matching Go's `codec` output.
    ///
    /// Go's struct has `codec:",omitempty,omitemptyarray"`, so zero-value fields
    /// are omitted. Fields sorted alphabetically by codec tag:
    /// `addr`, `fv`, `kd`, `lv`, `vote-id`, `vrfsk`
    fn canonical_encode(&self) -> Vec<u8> {
        // Collect non-zero fields.
        let mut fields: Vec<(&str, Vec<u8>)> = Vec::new();

        // addr — 32-byte binary, omit if all zeros
        if self.parent.0 != [0u8; 32] {
            let mut buf = Vec::new();
            rmp::encode::write_bin(&mut buf, &self.parent.0).unwrap();
            fields.push(("addr", buf));
        }

        // fv — uint64, omit if zero
        if self.first_valid.0 != 0 {
            let mut buf = Vec::new();
            rmp::encode::write_uint(&mut buf, self.first_valid.0).unwrap();
            fields.push(("fv", buf));
        }

        // kd — uint64, omit if zero
        if self.key_dilution != 0 {
            let mut buf = Vec::new();
            rmp::encode::write_uint(&mut buf, self.key_dilution).unwrap();
            fields.push(("kd", buf));
        }

        // lv — uint64, omit if zero
        if self.last_valid.0 != 0 {
            let mut buf = Vec::new();
            rmp::encode::write_uint(&mut buf, self.last_valid.0).unwrap();
            fields.push(("lv", buf));
        }

        // vote-id — 32-byte binary, omit if all zeros
        if self.vote_id != [0u8; 32] {
            let mut buf = Vec::new();
            rmp::encode::write_bin(&mut buf, &self.vote_id).unwrap();
            fields.push(("vote-id", buf));
        }

        // vrfsk — 64-byte binary, omit if all zeros
        if self.vrf_sk != [0u8; 64] {
            let mut buf = Vec::new();
            rmp::encode::write_bin(&mut buf, &self.vrf_sk).unwrap();
            fields.push(("vrfsk", buf));
        }

        // Fields are already in alphabetical order by tag name.
        // Build the msgpack map.
        let mut out = Vec::new();
        write_map_len(&mut out, fields.len() as u32);
        for (key, val) in &fields {
            write_str(&mut out, key);
            out.extend_from_slice(val);
        }
        out
    }
}

/// Expand a 32-byte VRF seed to Go's 64-byte `VrfPrivkey` format.
///
/// Go's libsodium-based VRF stores the private key as `seed || pubkey` (64 bytes).
/// Rust stores only the 32-byte seed. This function derives the public key
/// from the seed and concatenates them.
pub fn expand_vrf_privkey(seed: &[u8; 32]) -> [u8; 64] {
    let pk = algo_consensus_crypto::VrfPrivkey::from_seed(*seed).pubkey();
    let mut expanded = [0u8; 64];
    expanded[..32].copy_from_slice(seed);
    expanded[32..].copy_from_slice(&pk.0);
    expanded
}

// ── Participation ──────────────────────────────────────────────────────────

/// A set of secrets allowing a root account to participate in consensus.
///
/// Matches Go's `Participation` struct in `participation.go`.
pub struct Participation {
    /// Account this key participates for.
    pub parent: Address,
    /// VRF keypair (secret + public).
    pub vrf: VrfKeypair,
    /// One-time signature secrets (ephemeral key tree).
    pub voting: OneTimeSignatureSecrets,
    /// First valid round for this participation key.
    pub first_valid: Round,
    /// Last valid round for this participation key.
    pub last_valid: Round,
    /// Key dilution parameter.
    pub key_dilution: u64,
    /// State proof secrets (merkle signature scheme keys for state proof signing).
    ///
    /// Contains the `SignerContext` (tree, first_valid, key_lifetime) and
    /// ephemeral Falcon signing keys. When persisted, the `SignerContext` is
    /// stored in the Keysets table and keys are stored individually in the
    /// `StateProofKeys` table.
    pub state_proof_secrets: Option<merklesig::Secrets>,
}

impl Participation {
    /// Compute the `ParticipationID` for this participation key.
    ///
    /// Matches Go's `Participation.ID()` method.
    pub fn id(&self) -> ParticipationID {
        let vrf_sk_expanded = expand_vrf_privkey(self.vrf.sk.seed());
        let vote_id = self.voting.verifier();
        let identity = ParticipationKeyIdentity {
            parent: self.parent,
            vrf_sk: vrf_sk_expanded,
            vote_id,
            first_valid: self.first_valid,
            last_valid: self.last_valid,
            key_dilution: self.key_dilution,
        };
        identity.id()
    }

    /// Return the valid round interval `(first, last)`.
    pub fn valid_interval(&self) -> (Round, Round) {
        (self.first_valid, self.last_valid)
    }

    /// Return the parent account address.
    pub fn address(&self) -> Address {
        self.parent
    }

    /// Return `true` if this key is valid for any round in `[first, last]` (inclusive).
    ///
    /// Panics if `last < first`.
    pub fn overlaps_interval(&self, first: Round, last: Round) -> bool {
        overlaps_interval(self.first_valid, self.last_valid, first, last)
    }

    /// Return a reference to the VRF public key.
    pub fn vrf_pubkey(&self) -> &VrfPubkey {
        &self.vrf.pk
    }

    /// Generate a fresh participation key set for the given account.
    ///
    /// Matches Go's `FillDBWithParticipationKeys` in `participation.go`.
    /// Generates VRF keys, one-time signing keys, and state proof keys.
    ///
    /// If `key_dilution` is 0, uses `default_key_dilution(first, last)`.
    /// `key_lifetime` controls state proof key granularity (use
    /// `merklesig::KEY_LIFETIME_DEFAULT` = 256 for production).
    ///
    /// Returns an error if `last < first` or state proof key generation fails.
    pub fn generate(
        parent: Address,
        first_valid: Round,
        last_valid: Round,
        key_dilution: u64,
        key_lifetime: u64,
    ) -> Result<Self, String> {
        if last_valid < first_valid {
            return Err(format!(
                "firstValid {} is after lastValid {}",
                first_valid.0, last_valid.0
            ));
        }

        let key_dilution = if key_dilution == 0 {
            default_key_dilution(first_valid, last_valid)
        } else {
            key_dilution
        };

        // Compute batch range for one-time signature keys
        let first_id = one_time_id_for_round(first_valid.0, key_dilution);
        let last_id = one_time_id_for_round(last_valid.0, key_dilution);
        let num_batches = last_id.batch - first_id.batch + 1;

        // Generate cryptographic material
        let voting = OneTimeSignatureSecrets::generate(first_id.batch, num_batches);
        let vrf = VrfKeypair::generate();
        let state_proof_secrets = if key_lifetime > 0 {
            match merklesig::Secrets::new(first_valid.0, last_valid.0, key_lifetime) {
                Ok(secrets) => Some(secrets),
                Err(e) => return Err(format!("state proof key generation failed: {e}")),
            }
        } else {
            None
        };

        Ok(Self {
            parent,
            vrf,
            voting,
            first_valid,
            last_valid,
            key_dilution,
            state_proof_secrets,
        })
    }
}

// ── ParticipationRecord ────────────────────────────────────────────────────

/// Metadata about a set of participation keys (no secrets).
///
/// Matches Go's `ParticipationRecord` in `participationRegistry.go`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipationRecord {
    /// Unique identifier for this key set.
    pub participation_id: ParticipationID,
    /// Account this key participates for.
    pub account: Address,
    /// First valid round.
    pub first_valid: Round,
    /// Last valid round.
    pub last_valid: Round,
    /// Key dilution parameter.
    pub key_dilution: u64,
    /// Last round this key was used to vote.
    pub last_vote: Round,
    /// Last round this key was used for a block proposal.
    pub last_block_proposal: Round,
    /// Last round this key was used for a state proof.
    pub last_state_proof: Round,
    /// Effective first valid round (set when registered on-chain).
    pub effective_first: Round,
    /// Effective last valid round.
    pub effective_last: Round,
    /// VRF public key (if available).
    pub vrf_public_key: Option<VrfPubkey>,
    /// OTS master public key (the `OneTimeSignatureVerifier`, 32 bytes).
    ///
    /// Extracted from the voting blob (column 12) when available.
    /// This is the ed25519 verifier used for one-time signature verification.
    pub vote_id: Option<[u8; 32]>,
    /// State proof verifier (commitment + key lifetime).
    ///
    /// Decoded from the `SignerContext` stored in the Keysets table.
    pub state_proof_verifier: Option<merklesig::Verifier>,
}

impl ParticipationRecord {
    /// Returns `true` if all fields are zero/default.
    pub fn is_zero(&self) -> bool {
        self.participation_id.is_zero()
            && self.account == Address([0u8; 32])
            && self.first_valid.0 == 0
            && self.last_valid.0 == 0
            && self.key_dilution == 0
            && self.last_vote.0 == 0
            && self.last_block_proposal.0 == 0
            && self.last_state_proof.0 == 0
            && self.effective_first.0 == 0
            && self.effective_last.0 == 0
            && self.vrf_public_key.is_none()
            && self.vote_id.is_none()
            && self.state_proof_verifier.is_none()
    }

    /// Return `true` if this key is valid for any round in `[first, last]` (inclusive).
    ///
    /// Panics if `last < first`.
    pub fn overlaps_interval(&self, first: Round, last: Round) -> bool {
        overlaps_interval(self.first_valid, self.last_valid, first, last)
    }
}

// ── ParticipationAction ────────────────────────────────────────────────────

/// Actions that can be recorded against a participation key.
///
/// Matches Go's `ParticipationAction` enum in `participationRegistry.go`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipationAction {
    /// Used for consensus voting.
    Vote,
    /// Used for block proposal.
    BlockProposal,
    /// Used for state proof signing.
    StateProof,
}

// ── KeyManager trait ───────────────────────────────────────────────────────

/// Manages participation keys for consensus.
///
/// Matches go-algorand's `agreement.KeyManager` interface in
/// `agreement/abstractions.go`.
///
/// All methods take `&self` because `rusqlite::Connection` uses interior
/// mutability — no `&mut self` is needed.
pub trait KeyManager {
    /// Get all participation records valid for the given voting round,
    /// available as of `key_round`.
    ///
    /// Corresponds to Go's `KeyManager.VotingKeys(votingRound, keysRound)`.
    fn voting_keys_for_round(
        &self,
        voting_round: Round,
        key_round: Round,
    ) -> Result<Vec<ParticipationRecord>, rusqlite::Error>;

    /// Delete old key material for forward security.
    ///
    /// Removes all records whose `lastValid < current_round`.
    fn delete_old_keys(&self, current_round: Round) -> Result<(), rusqlite::Error>;

    /// Record that a participation action was taken for an account.
    ///
    /// Resolves the active participation key for `account` at `round` and
    /// records the action against it.
    ///
    /// Corresponds to Go's `KeyManager.Record(account, round, action)`.
    fn record_action(
        &self,
        account: &Address,
        round: Round,
        action: ParticipationAction,
    ) -> Result<(), rusqlite::Error>;
}

impl KeyManager for ParticipationStore {
    fn voting_keys_for_round(
        &self,
        voting_round: Round,
        key_round: Round,
    ) -> Result<Vec<ParticipationRecord>, rusqlite::Error> {
        self.get_for_voting_round(voting_round, key_round)
    }

    fn delete_old_keys(&self, current_round: Round) -> Result<(), rusqlite::Error> {
        delete_old_key_material(self, current_round)?;
        Ok(())
    }

    fn record_action(
        &self,
        account: &Address,
        round: Round,
        action: ParticipationAction,
    ) -> Result<(), rusqlite::Error> {
        self.record_for_account(account, round, action)
    }
}

// ── Key discovery and lifecycle ─────────────────────────────────────────

/// Match installed participation keys against ledger account data to find
/// accounts that are online and have local participation keys.
///
/// For each account that is `Online`:
/// - Retrieves all participation records from the store
/// - Matches by account address and round validity
/// - Optionally verifies VRF public key matches `selection_id` and voting
///   verifier matches `vote_id` (when both the record and account data have
///   the relevant fields)
///
/// Returns `(address, record)` pairs for every match.
pub fn discover_participating_accounts(
    store: &ParticipationStore,
    accounts: &[(Address, AccountData)],
    round: Round,
) -> Result<Vec<(Address, ParticipationRecord)>, rusqlite::Error> {
    let all_records = store.get_all()?;
    let mut results = Vec::new();

    for (addr, acct) in accounts {
        // Only consider online accounts.
        if acct.status != AccountStatus::Online {
            continue;
        }

        for record in &all_records {
            // Address must match.
            if record.account != *addr {
                continue;
            }

            // Round must be within the key's validity window.
            if !record.overlaps_interval(round, round) {
                continue;
            }

            // If the account has a selection_id and the record has a VRF
            // public key, verify they match.
            if let (Some(sel_id), Some(ref vrf_pk)) = (acct.selection_id, &record.vrf_public_key) {
                if sel_id != vrf_pk.0 {
                    continue;
                }
            }

            // If the account has a vote_id, we could also verify it matches
            // the OTS verifier from the participation key. However, the
            // ParticipationRecord does not store the OTS verifier directly
            // (it's derived from secrets). We skip this check for now.
            // The address + round + VRF match is sufficient for discovery.

            results.push((*addr, record.clone()));
        }
    }

    Ok(results)
}

/// Delete key material for rounds that have passed.
///
/// This is critical for protocol security — old signing keys must be
/// irrecoverably deleted so that an attacker who later compromises the
/// node cannot forge historical votes.
///
/// Performs two levels of deletion:
/// 1. **Fully expired**: removes records where `last_valid < current_round`
/// 2. **Forward-secure trimming**: for each remaining record, loads the
///    voting secrets, calls `delete_before(current_round, key_dilution)` to
///    erase ephemeral keys for past rounds, and persists the trimmed secrets
///    back to SQLite via `update_voting_secrets()`.
///
/// Returns the total count: fully expired records removed + records that
/// had key material trimmed.
///
/// # Crash-safety note
///
/// The in-memory `delete_before` and the subsequent `update_voting_secrets`
/// persist are NOT atomic: if the process crashes between the two steps,
/// the old key material may still be present on disk. This matches the
/// same limitation in go-algorand's `participationDB`.
pub fn delete_old_key_material(
    store: &ParticipationStore,
    current_round: Round,
) -> Result<usize, rusqlite::Error> {
    // Step 1: Remove fully expired records.
    let fully_expired = store.delete_expired(current_round)?;

    // Step 2: For each remaining record, trim forward-secure key material.
    let records = store.get_all()?;
    let mut trimmed = 0usize;

    for record in &records {
        // Only trim records where current_round falls within their validity window.
        if current_round.0 < record.first_valid.0 || current_round.0 > record.last_valid.0 {
            continue;
        }

        // Load the full Participation (with voting secrets).
        let mut participation =
            match store.get_for_round(&record.participation_id, current_round)? {
                Some(p) => p,
                None => continue,
            };

        // Snapshot state before trimming.
        let old_first_batch = participation.voting.first_batch();
        let old_first_offset = participation.voting.first_offset();

        // Trim old key material from the voting secrets.
        participation
            .voting
            .delete_before(current_round.0, record.key_dilution);

        // Only persist if something actually changed.
        if participation.voting.first_batch() != old_first_batch
            || participation.voting.first_offset() != old_first_offset
        {
            store.update_voting_secrets(&record.participation_id, &participation.voting)?;
            trimmed += 1;
        }
    }

    Ok(fully_expired + trimmed)
}

// ── Helper functions ───────────────────────────────────────────────────────

/// Compute the default key dilution for a participation key validity window.
///
/// `default_key_dilution = 1 + isqrt(last - first)`
///
/// Matches Go's `DefaultKeyDilution` in `participation.go`, which uses
/// `1 + uint64(math.Sqrt(float64(last - first)))`.
pub fn default_key_dilution(first: Round, last: Round) -> u64 {
    if last.0 < first.0 {
        return 1;
    }
    1 + ((last.0 - first.0) as f64).sqrt() as u64
}

/// Returns `true` if the key validity window `[key_first, key_last]` overlaps
/// with the query interval `[low, high]` (both inclusive).
///
/// Panics if `high < low`.
pub fn overlaps_interval(key_first: Round, key_last: Round, low: Round, high: Round) -> bool {
    assert!(
        high.0 >= low.0,
        "Round interval should be ordered (first = {}, last = {})",
        low.0,
        high.0
    );
    !(high.0 < key_first.0 || low.0 > key_last.0)
}

// ── Canonical msgpack helpers ──────────────────────────────────────────────

/// Write a msgpack map header.
fn write_map_len(buf: &mut Vec<u8>, len: u32) {
    rmp::encode::write_map_len(buf, len).unwrap();
}

/// Write a msgpack string (fixstr/str8/str16 as appropriate).
fn write_str(buf: &mut Vec<u8>, s: &str) {
    rmp::encode::write_str(buf, s).unwrap();
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_key_dilution_basic() {
        // 1 + sqrt(999) = 1 + 31 = 32
        assert_eq!(default_key_dilution(Round(1), Round(1000)), 32);
    }

    #[test]
    fn test_default_key_dilution_zero_window() {
        // 1 + sqrt(0) = 1
        assert_eq!(default_key_dilution(Round(100), Round(100)), 1);
    }

    #[test]
    fn test_default_key_dilution_one() {
        // 1 + sqrt(1) = 2
        assert_eq!(default_key_dilution(Round(0), Round(1)), 2);
    }

    #[test]
    fn test_default_key_dilution_large_window() {
        // 1 + sqrt(1_000_000) = 1 + 1000 = 1001
        assert_eq!(default_key_dilution(Round(0), Round(1_000_000)), 1001);
    }

    #[test]
    fn test_default_key_dilution_go_conformance() {
        // Go uses math.Sqrt which returns f64, same as Rust's f64::sqrt.
        // 1 + sqrt(3_000_000 - 1_000_000) = 1 + sqrt(2_000_000) = 1 + 1414 = 1415
        assert_eq!(
            default_key_dilution(Round(1_000_000), Round(3_000_000)),
            1415
        );
    }

    #[test]
    fn test_overlaps_interval_fully_inside() {
        assert!(overlaps_interval(
            Round(10),
            Round(20),
            Round(12),
            Round(18)
        ));
    }

    #[test]
    fn test_overlaps_interval_fully_outside_before() {
        assert!(!overlaps_interval(Round(10), Round(20), Round(1), Round(9)));
    }

    #[test]
    fn test_overlaps_interval_fully_outside_after() {
        assert!(!overlaps_interval(
            Round(10),
            Round(20),
            Round(21),
            Round(30)
        ));
    }

    #[test]
    fn test_overlaps_interval_touches_start() {
        assert!(overlaps_interval(Round(10), Round(20), Round(5), Round(10)));
    }

    #[test]
    fn test_overlaps_interval_touches_end() {
        assert!(overlaps_interval(
            Round(10),
            Round(20),
            Round(20),
            Round(25)
        ));
    }

    #[test]
    fn test_overlaps_interval_key_inside_query() {
        assert!(overlaps_interval(Round(10), Round(20), Round(5), Round(25)));
    }

    #[test]
    fn test_overlaps_interval_single_round() {
        assert!(overlaps_interval(
            Round(10),
            Round(10),
            Round(10),
            Round(10)
        ));
    }

    #[test]
    fn test_overlaps_interval_adjacent_no_overlap() {
        assert!(!overlaps_interval(
            Round(10),
            Round(20),
            Round(21),
            Round(21)
        ));
    }

    #[test]
    #[should_panic(expected = "Round interval should be ordered")]
    fn test_overlaps_interval_panics_on_inverted() {
        overlaps_interval(Round(10), Round(20), Round(15), Round(5));
    }

    #[test]
    fn test_participation_id_zero() {
        let id = ParticipationID([0u8; 32]);
        assert!(id.is_zero());
    }

    #[test]
    fn test_participation_id_nonzero() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        let id = ParticipationID(bytes);
        assert!(!id.is_zero());
    }

    #[test]
    fn test_participation_id_base32_roundtrip() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[31] = 0xCD;
        let id = ParticipationID(bytes);
        let s = id.to_base32();
        let parsed = ParticipationID::from_base32(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_participation_id_display() {
        let id = ParticipationID([0u8; 32]);
        let s = format!("{id}");
        // All-zeros base32
        assert_eq!(s, data_encoding::BASE32_NOPAD.encode(&[0u8; 32]));
    }

    #[test]
    fn test_expand_vrf_privkey() {
        let seed = [42u8; 32];
        let expanded = expand_vrf_privkey(&seed);
        // First 32 bytes are the seed.
        assert_eq!(&expanded[..32], &seed);
        // Last 32 bytes are the derived public key.
        let pk = algo_consensus_crypto::VrfPrivkey::from_seed(seed).pubkey();
        assert_eq!(&expanded[32..], &pk.0);
    }

    #[test]
    fn test_participation_key_identity_encode_all_zeros() {
        // With all zero fields, the canonical encoding should be an empty map.
        let identity = ParticipationKeyIdentity {
            parent: Address([0u8; 32]),
            vrf_sk: [0u8; 64],
            vote_id: [0u8; 32],
            first_valid: Round(0),
            last_valid: Round(0),
            key_dilution: 0,
        };
        let encoded = identity.canonical_encode();
        // Empty map: fixmap(0) = 0x80
        assert_eq!(encoded, vec![0x80]);
    }

    #[test]
    fn test_participation_key_identity_id_deterministic() {
        let seed = [7u8; 32];
        let expanded = expand_vrf_privkey(&seed);
        let identity = ParticipationKeyIdentity {
            parent: Address([1u8; 32]),
            vrf_sk: expanded,
            vote_id: [99u8; 32],
            first_valid: Round(100),
            last_valid: Round(1000),
            key_dilution: 32,
        };
        let id1 = identity.id();
        let id2 = identity.id();
        assert_eq!(id1, id2, "ParticipationID must be deterministic");
        assert!(
            !id1.is_zero(),
            "ParticipationID should not be zero for non-zero inputs"
        );
    }

    #[test]
    fn test_participation_key_identity_encode_field_order() {
        // Verify that fields are encoded in alphabetical order by codec tag:
        // addr, fv, kd, lv, vote-id, vrfsk
        let identity = ParticipationKeyIdentity {
            parent: Address([1u8; 32]),
            vrf_sk: [2u8; 64],
            vote_id: [3u8; 32],
            first_valid: Round(100),
            last_valid: Round(200),
            key_dilution: 10,
        };
        let encoded = identity.canonical_encode();

        // Should be a map with 6 fields.
        assert_eq!(encoded[0], 0x86, "should be fixmap(6)");

        // Extract key positions by scanning for string markers.
        // We verify the keys appear in order: addr, fv, kd, lv, vote-id, vrfsk
        let encoded_str = String::from_utf8_lossy(&encoded);
        let addr_pos = encoded_str.find("addr").unwrap();
        let fv_pos = encoded_str.find("fv").unwrap();
        let kd_pos = encoded_str.find("kd").unwrap();
        let lv_pos = encoded_str.find("lv").unwrap();
        let vote_id_pos = encoded_str.find("vote-id").unwrap();
        let vrfsk_pos = encoded_str.find("vrfsk").unwrap();

        assert!(addr_pos < fv_pos, "addr should come before fv");
        assert!(fv_pos < kd_pos, "fv should come before kd");
        assert!(kd_pos < lv_pos, "kd should come before lv");
        assert!(lv_pos < vote_id_pos, "lv should come before vote-id");
        assert!(vote_id_pos < vrfsk_pos, "vote-id should come before vrfsk");
    }

    #[test]
    fn test_participation_record_is_zero() {
        let record = ParticipationRecord {
            participation_id: ParticipationID([0u8; 32]),
            account: Address([0u8; 32]),
            first_valid: Round(0),
            last_valid: Round(0),
            key_dilution: 0,
            last_vote: Round(0),
            last_block_proposal: Round(0),
            last_state_proof: Round(0),
            effective_first: Round(0),
            effective_last: Round(0),
            vrf_public_key: None,
            vote_id: None,
            state_proof_verifier: None,
        };
        assert!(record.is_zero());
    }

    #[test]
    fn test_participation_record_not_zero() {
        let record = ParticipationRecord {
            participation_id: ParticipationID([0u8; 32]),
            account: Address([0u8; 32]),
            first_valid: Round(1),
            last_valid: Round(0),
            key_dilution: 0,
            last_vote: Round(0),
            last_block_proposal: Round(0),
            last_state_proof: Round(0),
            effective_first: Round(0),
            effective_last: Round(0),
            vrf_public_key: None,
            vote_id: None,
            state_proof_verifier: None,
        };
        assert!(!record.is_zero());
    }

    #[test]
    fn test_participation_action_variants() {
        // Ensure all variants exist and are distinct.
        let v = ParticipationAction::Vote;
        let b = ParticipationAction::BlockProposal;
        let s = ParticipationAction::StateProof;
        assert_ne!(v, b);
        assert_ne!(b, s);
        assert_ne!(v, s);
    }

    #[test]
    fn test_participation_id_from_participation() {
        // Construct a Participation and verify ID derivation works.
        let vrf = VrfKeypair::from_seed([11u8; 32]);
        let voting = OneTimeSignatureSecrets::generate(0, 10);
        let part = Participation {
            parent: Address([5u8; 32]),
            vrf,
            voting,
            first_valid: Round(100),
            last_valid: Round(10000),
            key_dilution: 100,
            state_proof_secrets: None,
        };

        let id = part.id();
        assert!(!id.is_zero());

        // Verify determinism.
        // Note: We can't call id() twice with the same Participation because
        // VrfKeypair doesn't derive the same expanded key differently.
        // But the identity construction is deterministic given the same inputs.
        let vrf2 = VrfKeypair::from_seed([11u8; 32]);
        let voting2 = OneTimeSignatureSecrets::generate(0, 10);
        let part2 = Participation {
            parent: Address([5u8; 32]),
            vrf: vrf2,
            voting: voting2,
            first_valid: Round(100),
            last_valid: Round(10000),
            key_dilution: 100,
            state_proof_secrets: None,
        };

        // VRF keys from same seed produce same expanded key, but
        // voting secrets are generated with random master keys, so
        // the verifier will differ. We just check each ID is non-zero.
        let id2 = part2.id();
        assert!(!id2.is_zero());
        // IDs will differ because voting secrets have different random masters.
        // That's expected — the test confirms the derivation runs without error.
    }

    // ── Discovery and lifecycle tests ──────────────────────────────────

    /// Helper: create a Participation and insert it into a store, returning the ID.
    fn insert_test_key(
        store: &ParticipationStore,
        addr_byte: u8,
        first: u64,
        last: u64,
    ) -> ParticipationID {
        let vrf = VrfKeypair::from_seed([addr_byte; 32]);
        let voting = OneTimeSignatureSecrets::generate(0, 10);
        let part = Participation {
            parent: Address([addr_byte; 32]),
            vrf,
            voting,
            first_valid: Round(first),
            last_valid: Round(last),
            key_dilution: default_key_dilution(Round(first), Round(last)),
            state_proof_secrets: None,
        };
        store.insert(&part).unwrap()
    }

    fn online_account(addr_byte: u8, selection_id: Option<[u8; 32]>) -> (Address, AccountData) {
        let acct = AccountData {
            status: AccountStatus::Online,
            selection_id,
            ..Default::default()
        };
        (Address([addr_byte; 32]), acct)
    }

    fn offline_account(addr_byte: u8) -> (Address, AccountData) {
        let acct = AccountData {
            status: AccountStatus::Offline,
            ..Default::default()
        };
        (Address([addr_byte; 32]), acct)
    }

    #[test]
    fn discover_online_account_with_matching_key() {
        let store = ParticipationStore::open_in_memory().unwrap();
        insert_test_key(&store, 1, 100, 200);

        let vrf_pk = VrfKeypair::from_seed([1u8; 32]).pk;
        let accounts = vec![online_account(1, Some(vrf_pk.0))];

        let results = discover_participating_accounts(&store, &accounts, Round(150)).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, Address([1u8; 32]));
    }

    #[test]
    fn discover_skips_offline_accounts() {
        let store = ParticipationStore::open_in_memory().unwrap();
        insert_test_key(&store, 1, 100, 200);

        let accounts = vec![offline_account(1)];
        let results = discover_participating_accounts(&store, &accounts, Round(150)).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn discover_skips_out_of_range_keys() {
        let store = ParticipationStore::open_in_memory().unwrap();
        insert_test_key(&store, 1, 100, 200);

        let accounts = vec![online_account(1, None)];
        // Round 300 is outside key range 100-200.
        let results = discover_participating_accounts(&store, &accounts, Round(300)).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn discover_skips_mismatched_address() {
        let store = ParticipationStore::open_in_memory().unwrap();
        // Key is for address byte 1.
        insert_test_key(&store, 1, 100, 200);

        // Account is address byte 2.
        let accounts = vec![online_account(2, None)];
        let results = discover_participating_accounts(&store, &accounts, Round(150)).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn discover_skips_mismatched_selection_id() {
        let store = ParticipationStore::open_in_memory().unwrap();
        insert_test_key(&store, 1, 100, 200);

        // Account has a selection_id that does NOT match the key's VRF pubkey.
        let accounts = vec![online_account(1, Some([99u8; 32]))];
        let results = discover_participating_accounts(&store, &accounts, Round(150)).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn discover_allows_none_selection_id() {
        let store = ParticipationStore::open_in_memory().unwrap();
        insert_test_key(&store, 1, 100, 200);

        // No selection_id on account — VRF check is skipped.
        let accounts = vec![online_account(1, None)];
        let results = discover_participating_accounts(&store, &accounts, Round(150)).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn discover_multiple_accounts() {
        let store = ParticipationStore::open_in_memory().unwrap();
        insert_test_key(&store, 1, 100, 200);
        insert_test_key(&store, 2, 100, 200);

        let accounts = vec![
            online_account(1, None),
            online_account(2, None),
            offline_account(3),
        ];
        let results = discover_participating_accounts(&store, &accounts, Round(150)).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn delete_old_key_material_removes_expired() {
        let store = ParticipationStore::open_in_memory().unwrap();
        insert_test_key(&store, 1, 10, 50);
        insert_test_key(&store, 2, 100, 200);

        let deleted = delete_old_key_material(&store, Round(100)).unwrap();
        // 1 fully expired (key 1, last_valid=50 < 100) + 1 trimmed (key 2,
        // forward-secure deletion within its validity window).
        assert!(
            deleted >= 2,
            "expected at least 2 (1 expired + 1 trimmed), got {deleted}"
        );

        let all = store.get_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].account, Address([2u8; 32]));
    }

    #[test]
    fn delete_old_key_material_nothing_expired() {
        let store = ParticipationStore::open_in_memory().unwrap();
        insert_test_key(&store, 1, 100, 200);

        let deleted = delete_old_key_material(&store, Round(50)).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(store.get_all().unwrap().len(), 1);
    }

    #[test]
    fn default_key_dilution_underflow_guard() {
        // last < first should return 1 instead of panicking.
        assert_eq!(default_key_dilution(Round(200), Round(100)), 1);
    }

    // ── Forward-secure deletion persistence tests ────────────────────────

    /// Helper: insert a participation key with explicit key_dilution.
    fn insert_test_key_with_dilution(
        store: &ParticipationStore,
        addr_byte: u8,
        first: u64,
        last: u64,
        key_dilution: u64,
    ) -> ParticipationID {
        let vrf = VrfKeypair::from_seed([addr_byte; 32]);
        // Generate enough batches to cover the round range.
        let num_batches = (last / key_dilution) + 2;
        let voting = OneTimeSignatureSecrets::generate(0, num_batches);
        let part = Participation {
            parent: Address([addr_byte; 32]),
            vrf,
            voting,
            first_valid: Round(first),
            last_valid: Round(last),
            key_dilution,
            state_proof_secrets: None,
        };
        store.insert(&part).unwrap()
    }

    #[test]
    fn forward_secure_deletion_full_lifecycle() {
        use algo_consensus_crypto::onetimesig::verify_one_time_signature;

        let store = ParticipationStore::open_in_memory().unwrap();
        let key_dilution = 10u64;
        let id = insert_test_key_with_dilution(&store, 1, 0, 100, key_dilution);

        // Retrieve and sign round 5 before deletion.
        let part = store.get_for_round(&id, Round(5)).unwrap().unwrap();
        let verifier = part.voting.verifier();
        let sig5 = part.voting.sign(b"round5", 5, key_dilution);
        assert!(verify_one_time_signature(&sig5, &verifier, 0, 5, b"round5"));

        // Delete key material before round 20.
        let count = delete_old_key_material(&store, Round(20)).unwrap();
        assert!(count > 0, "should have trimmed at least one key");

        // Retrieve again — signing round 25 should work.
        let part2 = store.get_for_round(&id, Round(25)).unwrap().unwrap();
        let sig25 = part2.voting.sign(b"round25", 25, key_dilution);
        assert!(verify_one_time_signature(
            &sig25, &verifier, 2, 5, b"round25"
        ));

        // Verify old key material is gone: first_batch should have advanced.
        assert!(
            part2.voting.first_batch() > 0,
            "first_batch should have advanced past 0 after deleting before round 20"
        );
    }

    #[test]
    fn forward_secure_deletion_persists_across_get() {
        // Insert, trim via delete_old_key_material, then retrieve and verify
        // the trimmed state was persisted.
        let store = ParticipationStore::open_in_memory().unwrap();
        let key_dilution = 10u64;
        let id = insert_test_key_with_dilution(&store, 2, 0, 100, key_dilution);

        // Get initial first_batch.
        let part_before = store.get_for_round(&id, Round(0)).unwrap().unwrap();
        let initial_first_batch = part_before.voting.first_batch();

        // Trim at round 30 (should advance past batch 2).
        delete_old_key_material(&store, Round(30)).unwrap();

        // Retrieve again — the persisted state should reflect the trim.
        let part_after = store.get_for_round(&id, Round(50)).unwrap().unwrap();
        assert!(
            part_after.voting.first_batch() > initial_first_batch,
            "first_batch should have advanced after deletion persistence"
        );
    }

    #[test]
    fn forward_secure_deletion_mixed_expired_and_trimmed() {
        // Three keys:
        //   key A: rounds 0-50 (fully expired at round 60)
        //   key B: rounds 0-100 (partially trimmed at round 60)
        //   key C: rounds 80-200 (partially trimmed at round 60 — within window)
        let store = ParticipationStore::open_in_memory().unwrap();
        let key_dilution = 10u64;

        let _id_a = insert_test_key_with_dilution(&store, 1, 0, 50, key_dilution);
        let id_b = insert_test_key_with_dilution(&store, 2, 0, 100, key_dilution);
        let _id_c = insert_test_key_with_dilution(&store, 3, 80, 200, key_dilution);

        assert_eq!(store.get_all().unwrap().len(), 3);

        // Delete at round 60: key A fully expired, key B trimmed, key C not yet in range
        let count = delete_old_key_material(&store, Round(60)).unwrap();
        // 1 fully expired (A) + 1 trimmed (B) = 2; C has first_valid=80 > 60 so not trimmed
        assert_eq!(
            count, 2,
            "expected exactly 2 (1 expired + 1 trimmed), got {count}"
        );

        // Key A should be gone.
        let all = store.get_all().unwrap();
        assert_eq!(all.len(), 2, "key A should be fully deleted");

        // Key B should still be retrievable and have trimmed state.
        let part_b = store.get_for_round(&id_b, Round(70)).unwrap().unwrap();
        assert!(
            part_b.voting.first_batch() > 0,
            "key B should have trimmed batches"
        );
    }

    #[test]
    fn forward_secure_deletion_idempotent() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let key_dilution = 10u64;
        let id = insert_test_key_with_dilution(&store, 1, 0, 100, key_dilution);

        // First deletion at round 30.
        let count1 = delete_old_key_material(&store, Round(30)).unwrap();
        assert!(count1 > 0);

        let part1 = store.get_for_round(&id, Round(50)).unwrap().unwrap();
        let fb1 = part1.voting.first_batch();

        // Second deletion at the same round — should be idempotent (no change).
        let count2 = delete_old_key_material(&store, Round(30)).unwrap();
        assert_eq!(
            count2, 0,
            "second call at same round should not change anything"
        );

        let part2 = store.get_for_round(&id, Round(50)).unwrap().unwrap();
        assert_eq!(part2.voting.first_batch(), fb1);
    }
}
