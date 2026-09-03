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

//! Independent state-proof voter-set formation (issue #758).
//!
//! Before this module, algod-rust had zero code path for the mechanism that
//! bounds *which* online accounts get committed into a block's state-proof
//! voters commitment: `StateProofTopVoters` (added to `ConsensusParams` by
//! issue #747) was inert struct data with nothing reading it.
//!
//! This module ports the *selection and commitment* half of go-algorand's
//! voters machinery:
//!
//! - `ledger/acctonline.go::TopOnlineAccounts` + `ledger/onlinetopheap.go`
//!   (rank online accounts by normalized balance, ties broken by address
//!   descending; truncate to the top `StateProofTopVoters`), and
//! - `ledger/ledgercore/votersForRound.go::LoadTree` (turn the selected
//!   accounts into a `basics.Participant` array -- rewards-adjusted weight,
//!   `NoKeysCommitment` fallback for accounts with no committed state-proof
//!   key -- then build the vector-commitment Merkle tree over them using
//!   `stateproof.HashType` (`crypto.Sumhash`)).
//!
//! # Known gap -- deferred to a follow-up issue
//!
//! This module implements the pure selection/commitment math only. It does
//! **not** yet implement:
//!
//! - the cross-round "voters tracker" that snapshots this selection at each
//!   round `r` where `(r + StateProofVotersLookback) % StateProofInterval
//!   == 0` and caches it until it is consumed `StateProofVotersLookback`
//!   rounds later, at the next multiple of `StateProofInterval`
//!   (`ledger/voters.go::votersTracker`, `votersRoundForStateProofRound`);
//! - wiring the result into block production (`block_header.rs`'s
//!   `next_state_proof_tracking` still always leaves the header's `"v"`
//!   voters-commitment / `"t"` online-total-weight fields at zero) or into
//!   block validation's independent cross-check of an incoming block's own
//!   `state_proof_tracking` (go: `ledger/eval/eval.go::endOfBlock`'s
//!   `eval.validate` branch);
//! - the network-wide *running* total-online-stake tracker go maintains
//!   independently of any single top-N query (`onlineAccounts.onlineTotalsEx`).
//!   [`build_voters_tree`]'s returned `total_weight` is only the sum of the
//!   *selected* top-N participants' rewards-adjusted balances, which
//!   under-counts go's `StateProofOnlineTotalWeight` whenever more than `n`
//!   accounts are online -- callers must not treat it as a drop-in
//!   replacement for that broader total.
//!
//! Wiring this into block production/validation, plus a byte-level oracle
//! fixture against a live go-algorand voters commitment, is filed as
//! follow-up issue xarmian/algod-rust#780.

use algo_consensus_crypto::{merklearray, merklesig, stateproof as crypto_sp};
use algo_types::Address;

/// One online account as of a "voters round" snapshot -- the fields
/// `TopOnlineAccounts`/`LoadTree` read. Mirrors go's `ledgercore.OnlineAccount`
/// restricted to what voter-set formation needs.
///
/// Callers are expected to have already filtered to accounts with
/// `AccountStatus::Online` (there is no `status` field here to re-check --
/// matching go's `TopOnlineAccounts`, which is only ever fed already-online
/// candidates by its caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlineAccountCandidate {
    pub address: Address,
    pub micro_algos: u64,
    pub rewards_base: u64,
    pub vote_first_valid: u64,
    pub vote_last_valid: u64,
    /// The account's committed state-proof key commitment
    /// (`AccountData::state_proof_id`), or all-zero when the account never
    /// registered one.
    pub state_proof_id: [u8; 64],
}

/// Errors from voters-tree construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VotersError {
    /// go: `votersTracker.LoadTree: overflow adding rewards %d + %d`.
    RewardsOverflow { micro_algos: u64, rewards_base: u64 },
    /// Overflow summing selected participants' rewards-adjusted weights.
    TotalWeightOverflow,
    /// The underlying vector-commitment tree construction failed.
    Merkle(String),
}

impl std::fmt::Display for VotersError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RewardsOverflow {
                micro_algos,
                rewards_base,
            } => write!(
                f,
                "votersTracker.LoadTree: overflow adding rewards to {micro_algos} (rewards_base {rewards_base})"
            ),
            Self::TotalWeightOverflow => {
                write!(f, "votersTracker.LoadTree: overflow summing total weight")
            }
            Self::Merkle(e) => write!(f, "voters commitment tree: {e}"),
        }
    }
}

impl std::error::Error for VotersError {}

/// go's `merklesignature.NoKeysCommitment`: the commitment value substituted
/// for an account that never registered a state-proof key.
///
/// Go computes this at `init()` time by building an intentionally-empty
/// Merkle signature scheme and reading its verifier's commitment. Because
/// `merklearray.Tree.Root()` special-cases a zero-length array as the
/// zero-length digest (`crypto/merklearray/merkle.go:171-174`) and
/// `GetVerifier` copies that (empty) root into a fixed-size `[64]byte`
/// commitment, the resulting constant is simply all-zero -- see this
/// workspace's `no_keys_window_produces_empty_tree` test
/// (`algo-consensus-crypto/tests/mss_new_test.rs`) for the equivalent
/// derivation on this side.
pub const NO_KEYS_COMMITMENT: [u8; 64] = [0u8; 64];

/// go's `AccountData.NormalizedOnlineBalance` ranking key plus
/// `onlineTopHeap.Less`'s address tie-break, packaged for sorting: rank by
/// normalized balance descending, ties broken by address descending
/// (`bytes.Compare(addr_i, addr_j) > 0` wins).
fn ranking_key(candidate: &OnlineAccountCandidate, reward_unit: u64) -> (u64, [u8; 32]) {
    let norm = crate::rewards::normalized_online_balance(
        algo_types::AccountStatus::Online,
        candidate.micro_algos,
        candidate.rewards_base,
        reward_unit,
    );
    (norm, candidate.address.0)
}

/// go's `onlineAccounts.TopOnlineAccounts` selection step (the ranking half;
/// see the module doc for what is *not* ported): filter to accounts whose
/// voting key is valid at `vote_rnd` (`VoteFirstValid <= vote_rnd <=
/// VoteLastValid`), rank by normalized balance descending -- ties broken by
/// address descending, matching `ledger/onlinetopheap.go`'s heap order
/// exactly -- and truncate to the top `n`. The result is already in the
/// order go's `LoadTree` iterates it (`Participants[i]` for `i`-th popped),
/// i.e. commitment order.
pub fn select_top_online_accounts(
    candidates: &[OnlineAccountCandidate],
    n: u64,
    vote_rnd: u64,
    reward_unit: u64,
) -> Vec<OnlineAccountCandidate> {
    let mut valid: Vec<&OnlineAccountCandidate> = candidates
        .iter()
        .filter(|c| c.vote_first_valid <= vote_rnd && vote_rnd <= c.vote_last_valid)
        .collect();

    valid.sort_by(|a, b| {
        let (a_norm, a_addr) = ranking_key(a, reward_unit);
        let (b_norm, b_addr) = ranking_key(b, reward_unit);
        // Descending normalized balance, then descending address.
        b_norm.cmp(&a_norm).then_with(|| b_addr.cmp(&a_addr))
    });

    valid.into_iter().take(n as usize).cloned().collect()
}

/// go's `PendingRewards` (`data/basics/userBalance.go:445`) with
/// `OverflowTracker` semantics: `None` on either the `rewards_level -
/// rewards_base` underflow or the `reward_units * delta` overflow that go's
/// `OverflowTracker.Sub`/`Mul` would flag.
fn pending_rewards_checked(
    reward_unit: u64,
    micro_algos: u64,
    rewards_base: u64,
    rewards_level: u64,
) -> Option<u64> {
    let reward_units = micro_algos.checked_div(reward_unit)?;
    let delta = rewards_level.checked_sub(rewards_base)?;
    reward_units.checked_mul(delta)
}

/// go's `votersForRound.createStateProofParticipant`
/// (`ledger/ledgercore/votersForRound.go:100`): substitute
/// [`NO_KEYS_COMMITMENT`] for an account that never registered a
/// state-proof key (all-zero commitment), and use the default key lifetime
/// (real registered keys don't yet carry a per-account lifetime).
fn create_state_proof_participant(state_proof_id: [u8; 64], weight: u64) -> crypto_sp::Participant {
    let commitment = if state_proof_id == [0u8; 64] {
        NO_KEYS_COMMITMENT
    } else {
        state_proof_id
    };
    crypto_sp::Participant {
        pk: merklesig::Verifier {
            commitment,
            key_lifetime: merklesig::KEY_LIFETIME_DEFAULT,
        },
        weight,
    }
}

/// go's `votersForRound.LoadTree` (`ledger/ledgercore/votersForRound.go:122`)
/// -- the `basics.Participant` array construction half only (see
/// [`commit_participants`] for the vector-commitment tree half, and
/// [`build_voters_tree`]/[`build_voters_tree_and_participants`] for callers
/// that need both).
///
/// `rewards_level` is the block header's `RewardsLevel` at the snapshot
/// round (go: `hdr.RewardsLevel`); `reward_unit` is `params.RewardUnit`.
///
/// Returns `(participants, total_weight)` where `total_weight` is the sum
/// of the *selected* participants' rewards-adjusted balances -- see the
/// module doc's "known gap" for how this differs from go's
/// `StateProofOnlineTotalWeight`. `participants` is already in commitment
/// order (index == vector-commitment array position), matching `selected`'s
/// order.
///
/// Split out from [`build_voters_tree`] by issue #912: a state-proof
/// signing/proving daemon needs the participant array itself (to rebuild a
/// `stateproof::Prover`), not just the commitment root -- see
/// `algo_ledger::voters_tracker::record_voters_snapshot`, which persists
/// this return value's `participants` alongside the existing compact
/// `(root, total_weight)` snapshot.
pub fn build_participants(
    selected: &[OnlineAccountCandidate],
    rewards_level: u64,
    reward_unit: u64,
) -> Result<(Vec<crypto_sp::Participant>, u64), VotersError> {
    let mut participants = Vec::with_capacity(selected.len());
    let mut total_weight: u64 = 0;

    for acct in selected {
        let rewards = pending_rewards_checked(
            reward_unit,
            acct.micro_algos,
            acct.rewards_base,
            rewards_level,
        )
        .ok_or(VotersError::RewardsOverflow {
            micro_algos: acct.micro_algos,
            rewards_base: acct.rewards_base,
        })?;
        let money = acct
            .micro_algos
            .checked_add(rewards)
            .ok_or(VotersError::RewardsOverflow {
                micro_algos: acct.micro_algos,
                rewards_base: acct.rewards_base,
            })?;
        total_weight = total_weight
            .checked_add(money)
            .ok_or(VotersError::TotalWeightOverflow)?;
        participants.push(create_state_proof_participant(acct.state_proof_id, money));
    }

    Ok((participants, total_weight))
}

/// Build the vector-commitment Merkle tree over an already-constructed
/// participant array, using `stateproof.HashType` (`crypto.Sumhash`) --
/// matches the tree-construction half of go's `votersForRound.LoadTree`.
///
/// Deterministic in the participant array's order/content only (see
/// `tree_is_deterministic_for_the_same_input`/`commitment_is_order_sensitive`
/// below) -- callers may rebuild this from a persisted `Vec<Participant>`
/// (issue #912) and reproduce byte-for-byte the same tree, including its
/// root, that was computed at snapshot time.
pub fn commit_participants(
    participants: &[crypto_sp::Participant],
) -> Result<merklearray::Tree, VotersError> {
    let array = crypto_sp::ParticipantsArray(participants.to_vec());
    let factory = merklearray::HashFactory::new(merklearray::HashType::Sumhash);
    merklearray::build_vector_commitment_tree(&array, factory)
        .map_err(|e| VotersError::Merkle(e.to_string()))
}

/// go's `votersForRound.LoadTree` (`ledger/ledgercore/votersForRound.go:122`):
/// turn a selected top-N account slice (already in commitment order -- see
/// [`select_top_online_accounts`]) into the `basics.Participant` array and
/// build the vector-commitment Merkle tree over it.
///
/// Returns `(root, total_weight)` only -- see
/// [`build_voters_tree_and_participants`] for a variant that also returns
/// the participant array itself (needed to persist a full voters snapshot,
/// issue #912).
pub fn build_voters_tree(
    selected: &[OnlineAccountCandidate],
    rewards_level: u64,
    reward_unit: u64,
) -> Result<(Vec<u8>, u64), VotersError> {
    let (root, total_weight, _participants) =
        build_voters_tree_and_participants(selected, rewards_level, reward_unit)?;
    Ok((root, total_weight))
}

/// Like [`build_voters_tree`], but also returns the constructed
/// `Vec<Participant>` array itself -- the shape
/// `algo_ledger::voters_tracker::record_voters_snapshot` needs to persist a
/// full voters snapshot (issue #912), not just its compact commitment.
pub fn build_voters_tree_and_participants(
    selected: &[OnlineAccountCandidate],
    rewards_level: u64,
    reward_unit: u64,
) -> Result<(Vec<u8>, u64, Vec<crypto_sp::Participant>), VotersError> {
    let (participants, total_weight) = build_participants(selected, rewards_level, reward_unit)?;
    let tree = commit_participants(&participants)?;
    Ok((tree.root(), total_weight, participants))
}

// ── Participant-array persistence codec (issue #912) ───────────────────
//
// `LedgerStore::put_voters_participants`/`get_voters_participants` persist
// the full `Vec<Participant>` array a voters snapshot selected, so it
// round-trips through storage byte-for-byte: `Participant` is `(pk:
// merklesig::Verifier { commitment: [u8; 64], key_lifetime: u64 }, weight:
// u64)`. `Verifier` already has a self-delimiting `to_msgpack`/
// `from_msgpack` pair (`merklesig.rs`); this format concatenates a
// little-endian `u32` count with each participant's `Verifier` msgpack
// followed by its `weight` as little-endian `u64` -- deterministic and
// simple enough not to need a full msgpack array wrapper, matching this
// crate's existing hand-rolled encodings for fixed-shape internal blobs
// (e.g. `stateproof_worker::db`'s `Signature::to_msgpack`/`from_msgpack`
// usage).

/// Encode a participant array for storage. See the section doc above for
/// the exact format.
pub fn encode_participants(participants: &[crypto_sp::Participant]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + participants.len() * 80);
    buf.extend_from_slice(&(participants.len() as u32).to_le_bytes());
    for p in participants {
        buf.extend_from_slice(&p.pk.to_msgpack());
        buf.extend_from_slice(&p.weight.to_le_bytes());
    }
    buf
}

/// Decode a participant array previously produced by [`encode_participants`].
pub fn decode_participants(data: &[u8]) -> Result<Vec<crypto_sp::Participant>, String> {
    if data.len() < 4 {
        return Err(format!(
            "decode_participants: buffer too short for count prefix: {} bytes",
            data.len()
        ));
    }
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut rest = &data[4..];
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let (pk, after_pk) = merklesig::Verifier::from_msgpack(rest)
            .map_err(|e| format!("decode_participants: participant {i} pk: {e}"))?;
        if after_pk.len() < 8 {
            return Err(format!(
                "decode_participants: participant {i}: buffer too short for weight"
            ));
        }
        let weight = u64::from_le_bytes(after_pk[0..8].try_into().unwrap());
        rest = &after_pk[8..];
        out.push(crypto_sp::Participant { pk, weight });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REWARD_UNIT: u64 = 1_000_000;

    fn addr(byte: u8) -> Address {
        Address([byte; 32])
    }

    fn candidate(address: Address, micro_algos: u64) -> OnlineAccountCandidate {
        OnlineAccountCandidate {
            address,
            micro_algos,
            rewards_base: 0,
            vote_first_valid: 0,
            vote_last_valid: 1_000_000,
            state_proof_id: [0u8; 64],
        }
    }

    // ── select_top_online_accounts: ranking + tie-break oracle ─────────

    #[test]
    fn selects_by_normalized_balance_descending() {
        let low = candidate(addr(1), 1_000_000);
        let high = candidate(addr(2), 5_000_000);
        let mid = candidate(addr(3), 2_000_000);
        let selected = select_top_online_accounts(
            &[low.clone(), high.clone(), mid.clone()],
            10,
            100,
            REWARD_UNIT,
        );
        assert_eq!(
            selected.iter().map(|c| c.address).collect::<Vec<_>>(),
            vec![high.address, mid.address, low.address],
            "must be sorted strictly descending by balance"
        );
    }

    #[test]
    fn ties_break_by_address_descending() {
        // Equal balance, equal rewards_base => equal normalized balance.
        // go's onlineTopHeap.Less: on a tie, `bytes.Compare(addr_i, addr_j) >
        // 0` wins, i.e. the numerically LARGER address is emitted first.
        let low_addr = candidate(addr(0x01), 1_000_000);
        let high_addr = candidate(addr(0xFF), 1_000_000);
        let selected = select_top_online_accounts(
            &[low_addr.clone(), high_addr.clone()],
            10,
            100,
            REWARD_UNIT,
        );
        assert_eq!(
            selected.iter().map(|c| c.address).collect::<Vec<_>>(),
            vec![high_addr.address, low_addr.address],
            "on a balance tie the larger address must sort first"
        );
    }

    #[test]
    fn truncates_to_n() {
        let accounts: Vec<_> = (1u8..=5)
            .map(|i| candidate(addr(i), i as u64 * 1_000_000))
            .collect();
        let selected = select_top_online_accounts(&accounts, 2, 100, REWARD_UNIT);
        assert_eq!(selected.len(), 2);
        // Top 2 by balance: addr(5) then addr(4).
        assert_eq!(selected[0].address, addr(5));
        assert_eq!(selected[1].address, addr(4));
    }

    #[test]
    fn excludes_accounts_whose_vote_key_is_not_valid_at_vote_rnd() {
        let mut expired = candidate(addr(9), 10_000_000);
        expired.vote_last_valid = 50; // vote_rnd below will be 100
        let valid = candidate(addr(1), 1_000_000);
        let selected = select_top_online_accounts(&[expired, valid.clone()], 10, 100, REWARD_UNIT);
        assert_eq!(
            selected,
            vec![valid],
            "an account whose participation key has expired by vote_rnd must be excluded \
             even though its balance is far higher"
        );
    }

    #[test]
    fn excludes_accounts_not_yet_valid_at_vote_rnd() {
        let mut not_yet = candidate(addr(9), 10_000_000);
        not_yet.vote_first_valid = 200; // vote_rnd below is 100
        let valid = candidate(addr(1), 1_000_000);
        let selected = select_top_online_accounts(&[not_yet, valid.clone()], 10, 100, REWARD_UNIT);
        assert_eq!(selected, vec![valid]);
    }

    #[test]
    fn n_larger_than_candidate_count_returns_all_valid() {
        let a = candidate(addr(1), 1_000_000);
        let b = candidate(addr(2), 2_000_000);
        let selected = select_top_online_accounts(&[a.clone(), b.clone()], 1024, 100, REWARD_UNIT);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn empty_candidates_yields_empty_selection() {
        let selected = select_top_online_accounts(&[], 1024, 100, REWARD_UNIT);
        assert!(selected.is_empty());
    }

    // ── build_voters_tree: participant construction + commitment ───────

    #[test]
    fn no_state_proof_key_falls_back_to_no_keys_commitment() {
        let c = candidate(addr(1), 5_000_000);
        assert_eq!(c.state_proof_id, [0u8; 64]);
        let (root, total_weight) = build_voters_tree(&[c], 0, REWARD_UNIT).unwrap();
        assert!(!root.is_empty());
        assert_eq!(total_weight, 5_000_000);
    }

    #[test]
    fn registered_state_proof_key_is_committed_verbatim() {
        let mut c = candidate(addr(1), 5_000_000);
        c.state_proof_id = [0x42u8; 64];
        let (root_with_key, _) = build_voters_tree(&[c.clone()], 0, REWARD_UNIT).unwrap();

        let mut no_key = c;
        no_key.state_proof_id = [0u8; 64];
        let (root_without_key, _) = build_voters_tree(&[no_key], 0, REWARD_UNIT).unwrap();

        assert_ne!(
            root_with_key, root_without_key,
            "a registered state-proof key must change the commitment vs. the NoKeysCommitment fallback"
        );
    }

    #[test]
    fn weight_includes_pending_rewards() {
        // rewards_level=10, rewards_base=0, reward_unit=1_000_000,
        // micro_algos=5_000_000 => reward_units=5, delta=10 => rewards=50,
        // money = 5_000_050.
        let mut c = candidate(addr(1), 5_000_000);
        c.rewards_base = 0;
        let (_, total_weight) = build_voters_tree(&[c], 10, REWARD_UNIT).unwrap();
        assert_eq!(total_weight, 5_000_050);
    }

    #[test]
    fn rewards_underflow_is_reported_as_overflow_error() {
        // rewards_base > rewards_level: go's OverflowTracker.Sub would flag
        // this rather than wrapping.
        let mut c = candidate(addr(1), 5_000_000);
        c.rewards_base = 100;
        let err = build_voters_tree(&[c], 10, REWARD_UNIT).unwrap_err();
        assert!(matches!(err, VotersError::RewardsOverflow { .. }));
    }

    #[test]
    fn tree_is_deterministic_for_the_same_input() {
        let a = candidate(addr(1), 5_000_000);
        let b = candidate(addr(2), 3_000_000);
        let (root1, w1) = build_voters_tree(&[a.clone(), b.clone()], 0, REWARD_UNIT).unwrap();
        let (root2, w2) = build_voters_tree(&[a, b], 0, REWARD_UNIT).unwrap();
        assert_eq!(root1, root2);
        assert_eq!(w1, w2);
    }

    #[test]
    fn commitment_is_order_sensitive() {
        // Vector commitments bind to position: reordering the same two
        // participants must change the root, mirroring go's positional
        // (non-sparse) vector commitment semantics.
        let a = candidate(addr(1), 5_000_000);
        let b = candidate(addr(2), 3_000_000);
        let (root_ab, _) = build_voters_tree(&[a.clone(), b.clone()], 0, REWARD_UNIT).unwrap();
        let (root_ba, _) = build_voters_tree(&[b, a], 0, REWARD_UNIT).unwrap();
        assert_ne!(root_ab, root_ba);
    }

    #[test]
    fn empty_selection_builds_a_tree_without_erroring() {
        let (root, total_weight) = build_voters_tree(&[], 0, REWARD_UNIT).unwrap();
        assert_eq!(total_weight, 0);
        // An empty vector commitment still yields a well-defined (non-error)
        // root; its exact value is an implementation detail of
        // `merklearray::build_vector_commitment_tree` already covered by
        // that module's own tests.
        let _ = root;
    }

    // ── End-to-end: select then build (the real call sequence) ─────────

    #[test]
    fn select_then_build_respects_state_proof_top_voters_cap() {
        // 5 online accounts, cap = 2: only the top 2 by balance are
        // committed, matching StateProofTopVoters bounding the voter set.
        let accounts: Vec<_> = (1u8..=5)
            .map(|i| candidate(addr(i), i as u64 * 1_000_000))
            .collect();
        let selected = select_top_online_accounts(&accounts, 2, 100, REWARD_UNIT);
        assert_eq!(selected.len(), 2);
        let (root, total_weight) = build_voters_tree(&selected, 0, REWARD_UNIT).unwrap();
        assert!(!root.is_empty());
        // 5_000_000 + 4_000_000 (top 2 by balance, addr(5) and addr(4)).
        assert_eq!(total_weight, 9_000_000);
    }

    // ── build_voters_tree_and_participants / codec (issue #912) ────────

    #[test]
    fn build_voters_tree_and_participants_matches_build_voters_tree() {
        let a = candidate(addr(1), 5_000_000);
        let b = candidate(addr(2), 3_000_000);
        let (root, weight) = build_voters_tree(&[a.clone(), b.clone()], 0, REWARD_UNIT).unwrap();
        let (root2, weight2, participants) =
            build_voters_tree_and_participants(&[a, b], 0, REWARD_UNIT).unwrap();
        assert_eq!(root, root2, "must produce the identical commitment root");
        assert_eq!(weight, weight2);
        assert_eq!(participants.len(), 2);
    }

    #[test]
    fn commit_participants_rebuilds_the_same_root_as_build_voters_tree() {
        // The whole point of persisting only the participant array (issue
        // #912) rather than the tree itself: rebuilding the tree from the
        // persisted array must reproduce the exact root computed at
        // snapshot time.
        let a = candidate(addr(1), 5_000_000);
        let mut b = candidate(addr(2), 3_000_000);
        b.state_proof_id = [0x77u8; 64];
        let (root, _weight, participants) =
            build_voters_tree_and_participants(&[a, b], 7, REWARD_UNIT).unwrap();
        let rebuilt = commit_participants(&participants).unwrap();
        assert_eq!(root, rebuilt.root());
    }

    #[test]
    fn participants_codec_round_trips_byte_for_byte() {
        let a = candidate(addr(1), 5_000_000);
        let mut b = candidate(addr(2), 3_000_000);
        b.state_proof_id = [0xABu8; 64];
        let (_, _, participants) =
            build_voters_tree_and_participants(&[a, b], 3, REWARD_UNIT).unwrap();

        let encoded = encode_participants(&participants);
        let decoded = decode_participants(&encoded).unwrap();
        assert_eq!(decoded, participants);

        // The rebuilt tree from the round-tripped array must still commit
        // to the same root.
        let root_before = commit_participants(&participants).unwrap().root();
        let root_after = commit_participants(&decoded).unwrap().root();
        assert_eq!(root_before, root_after);
    }

    #[test]
    fn participants_codec_round_trips_empty_array() {
        let encoded = encode_participants(&[]);
        let decoded = decode_participants(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_participants_rejects_truncated_buffer() {
        assert!(decode_participants(&[0u8; 2]).is_err());
        // A count prefix claiming one participant but no payload.
        let mut buf = 1u32.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 3]);
        assert!(decode_participants(&buf).is_err());
    }
}
