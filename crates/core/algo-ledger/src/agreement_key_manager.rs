//! Bridge implementation connecting `ParticipationStore` to the agreement
//! protocol's `AgreementKeyManager` trait.
//!
//! Maps between the ledger's `ParticipationRecord` and the agreement crate's
//! `ParticipationRecord`, and delegates to `ParticipationStore` for key
//! storage and action recording.

use algo_agreement::traits::{
    AgreementKeyManager, ParticipationAction as AgreementAction,
    ParticipationRecord as AgreementParticipationRecord,
};
use algo_types::{Address, Round};

use crate::participation::{
    ParticipationAction as LedgerAction, ParticipationRecord as LedgerParticipationRecord,
    ParticipationStore,
};

// ---------------------------------------------------------------------------
// From conversion: ledger ParticipationRecord -> agreement ParticipationRecord
// ---------------------------------------------------------------------------

impl From<&LedgerParticipationRecord> for AgreementParticipationRecord {
    fn from(rec: &LedgerParticipationRecord) -> Self {
        AgreementParticipationRecord {
            address: rec.account,
            vote_id: rec.vote_id.unwrap_or([0u8; 32]),
            selection_id: rec.vrf_public_key.map(|pk| pk.0).unwrap_or([0u8; 32]),
            vote_first_valid: rec.first_valid,
            vote_last_valid: rec.last_valid,
            vote_key_dilution: rec.key_dilution,
        }
    }
}

// ---------------------------------------------------------------------------
// ParticipationAction conversion
// ---------------------------------------------------------------------------

/// Convert an agreement-side `ParticipationAction` to a ledger-side one.
fn to_ledger_action(action: AgreementAction) -> LedgerAction {
    match action {
        AgreementAction::Proposed => LedgerAction::BlockProposal,
        AgreementAction::Voted => LedgerAction::Vote,
        AgreementAction::StateProof => LedgerAction::StateProof,
    }
}

// ---------------------------------------------------------------------------
// AgreementKeyManagerBridge
// ---------------------------------------------------------------------------

/// Bridges `ParticipationStore` to the agreement protocol's
/// `AgreementKeyManager` trait.
///
/// Mirrors Go's `KeyManager` implementation in `data/account` which is
/// passed to the agreement service.
pub struct AgreementKeyManagerBridge {
    store: ParticipationStore,
}

impl AgreementKeyManagerBridge {
    /// Create a new bridge wrapping the given participation store.
    pub fn new(store: ParticipationStore) -> Self {
        Self { store }
    }
}

impl AgreementKeyManager for AgreementKeyManagerBridge {
    fn voting_keys(
        &self,
        voting_round: Round,
        keys_round: Round,
    ) -> Vec<AgreementParticipationRecord> {
        match self.store.get_for_voting_round(voting_round, keys_round) {
            Ok(records) => records
                .iter()
                .filter(|rec| {
                    if rec.vote_id.is_none() || rec.vrf_public_key.is_none() {
                        tracing::warn!(
                            account = %rec.account,
                            participation_id = %rec.participation_id,
                            vote_id_present = rec.vote_id.is_some(),
                            vrf_key_present = rec.vrf_public_key.is_some(),
                            round = %voting_round,
                            "filtering out participation record with missing vote_id or VRF key — \
                             it would produce invalid votes"
                        );
                        false
                    } else {
                        true
                    }
                })
                .map(AgreementParticipationRecord::from)
                .collect(),
            Err(e) => {
                tracing::warn!("failed to get voting keys for round {voting_round}: {e}");
                Vec::new()
            }
        }
    }

    fn record(&self, account: &Address, round: Round, action: AgreementAction) {
        let ledger_action = to_ledger_action(action);
        if let Err(e) = self.store.record_for_account(account, round, ledger_action) {
            tracing::warn!("failed to record participation action for {}: {e}", account);
        }
    }

    fn signing_keys_for(
        &self,
        account: &Address,
        voting_round: Round,
        keys_round: Round,
    ) -> Option<algo_agreement::AccountSigningKeys> {
        // Find the account's participation record effective for this round
        // (same selection the public `voting_keys` uses), then load that exact
        // key's secrets by participation ID. Selecting per (account, round)
        // rather than once at startup is what handles key rotation and
        // not-yet-effective keys.
        let records = self
            .store
            .get_for_voting_round(voting_round, keys_round)
            .map_err(|e| {
                tracing::warn!("signing_keys_for: get_for_voting_round({voting_round}): {e}")
            })
            .ok()?;
        let record = records.iter().find(|r| &r.account == account)?;
        match self
            .store
            .get_for_round(&record.participation_id, voting_round)
        {
            Ok(Some(part)) => Some(algo_agreement::AccountSigningKeys {
                vrf: part.vrf,
                ots: part.voting,
            }),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    "signing_keys_for: get_for_round({}): {e}",
                    record.participation_id
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::participation::{Participation, ParticipationID, ParticipationRecord as LedgerRec};
    use algo_consensus_crypto::VrfPubkey;

    #[test]
    fn signing_keys_for_tracks_rotation() {
        // An account that rotates from key A to key B mid-life: signing_keys_for
        // must return A's secrets while A is the effective key and B's secrets
        // after the rotation — selecting per (account, round), not once.
        let store = ParticipationStore::open_in_memory().unwrap();
        let account = Address([5u8; 32]);
        let key_a = Participation::generate(account, Round(0), Round(2000), 10_000, 0).unwrap();
        let key_b = Participation::generate(account, Round(0), Round(2000), 10_000, 0).unwrap();
        let vrf_a = key_a.vrf_pubkey().0;
        let vrf_b = key_b.vrf_pubkey().0;
        assert_ne!(vrf_a, vrf_b);
        let id_a = store.insert(&key_a).unwrap();
        let id_b = store.insert(&key_b).unwrap();
        // A active from round 1; B active from round 600 (deactivates A at 599).
        store.register(&id_a, Round(1)).unwrap();
        store.register(&id_b, Round(600)).unwrap();
        let bridge = AgreementKeyManagerBridge::new(store);

        let early = bridge
            .signing_keys_for(&account, Round(400), Round(400))
            .expect("key A active at round 400");
        assert_eq!(early.vrf.pk.0, vrf_a, "early round → rotated-from key A");

        let late = bridge
            .signing_keys_for(&account, Round(700), Round(700))
            .expect("key B active at round 700");
        assert_eq!(late.vrf.pk.0, vrf_b, "later round → rotated-to key B");
    }

    #[test]
    fn signing_keys_for_unknown_account_is_none() {
        let store = ParticipationStore::open_in_memory().unwrap();
        let bridge = AgreementKeyManagerBridge::new(store);
        assert!(bridge
            .signing_keys_for(&Address([0u8; 32]), Round(1), Round(1))
            .is_none());
    }

    #[test]
    fn from_ledger_record_basic() {
        let ledger_rec = LedgerRec {
            participation_id: ParticipationID([1u8; 32]),
            account: Address([2u8; 32]),
            first_valid: Round(100),
            last_valid: Round(200),
            key_dilution: 10,
            last_vote: Round(0),
            last_block_proposal: Round(0),
            last_state_proof: Round(0),
            effective_first: Round(0),
            effective_last: Round(0),
            vrf_public_key: Some(VrfPubkey([3u8; 32])),
            vote_id: Some([4u8; 32]),
            state_proof_verifier: None,
        };

        let agreement_rec = AgreementParticipationRecord::from(&ledger_rec);

        assert_eq!(agreement_rec.address, Address([2u8; 32]));
        assert_eq!(agreement_rec.vote_id, [4u8; 32]);
        assert_eq!(agreement_rec.selection_id, [3u8; 32]);
        assert_eq!(agreement_rec.vote_first_valid, Round(100));
        assert_eq!(agreement_rec.vote_last_valid, Round(200));
        assert_eq!(agreement_rec.vote_key_dilution, 10);
    }

    #[test]
    fn from_ledger_record_missing_keys() {
        let ledger_rec = LedgerRec {
            participation_id: ParticipationID([0u8; 32]),
            account: Address([1u8; 32]),
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

        let agreement_rec = AgreementParticipationRecord::from(&ledger_rec);

        assert_eq!(agreement_rec.vote_id, [0u8; 32]);
        assert_eq!(agreement_rec.selection_id, [0u8; 32]);
    }

    #[test]
    fn action_conversion() {
        assert!(matches!(
            to_ledger_action(AgreementAction::Proposed),
            LedgerAction::BlockProposal
        ));
        assert!(matches!(
            to_ledger_action(AgreementAction::Voted),
            LedgerAction::Vote
        ));
        assert!(matches!(
            to_ledger_action(AgreementAction::StateProof),
            LedgerAction::StateProof
        ));
    }

    // ----------------------------------------------------------------------
    // Port of go-algorand v4.6.0-stable agreement/keyManager_test.go.
    //
    // TASK-66 (PLAN-31 §3.15). The Go file is 91 LOC of pure test
    // infrastructure — it defines a `recordingKeyManager` helper and zero
    // `Test*` functions. The helper is consumed by the agreement
    // pseudonode tests (see TASK-65 port for the consumer side).
    //
    // The Rust port lives here, alongside the production
    // `AgreementKeyManagerBridge`, so future ledger-bridge tests can
    // reuse the same recorder pattern when they need to assert on what
    // the agreement service called back through the trait. A Rust
    // counterpart of `RecordingKeyManager` is also present in the
    // pseudonode tests (different surface — it captures `voting_keys`
    // call args; this one mirrors Go more closely by capturing
    // `record()` invocations and supporting `validate_vote_round`).
    //
    // The tests below exercise the helper itself — without that, a
    // helper port would land untested and silently rot.

    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Last-recorded rounds per `AgreementAction` for a single account.
    /// Modeled with explicit fields rather than `HashMap<AgreementAction,
    /// Round>` because `AgreementAction` doesn't derive `Hash` (and a
    /// production-code derive change is out of scope for a test-port task).
    #[derive(Default, Debug, Clone)]
    struct ActionRounds {
        voted: Option<Round>,
        proposed: Option<Round>,
        state_proof: Option<Round>,
    }

    /// A test-only `AgreementKeyManager` that:
    ///
    /// * Filters the configured key set by `voting_round` overlap when
    ///   `voting_keys` is called (mirrors Go's `acc.OverlapsInterval`
    ///   check at `keyManager_test.go:48`).
    /// * Records every `record(account, round, action)` invocation in a
    ///   `(address → action → round)` map (mirrors Go's `recording`
    ///   field, lines 76-83).
    /// * Provides `validate_vote_round(address, round)` which checks that
    ///   BOTH `Voted` and `Proposed` actions were recorded at the given
    ///   round for the given address (mirrors Go's `ValidateVoteRound`
    ///   helper at lines 85-91).
    ///
    /// Uses `RefCell` for interior mutability since `AgreementKeyManager`
    /// takes `&self` on `record`. Test-only — does not need to be `Sync`.
    struct RecordingKeyManager {
        keys: Vec<AgreementParticipationRecord>,
        recording: RefCell<HashMap<Address, ActionRounds>>,
    }

    impl RecordingKeyManager {
        fn new(keys: Vec<AgreementParticipationRecord>) -> Self {
            Self {
                keys,
                recording: RefCell::new(HashMap::new()),
            }
        }

        /// Mirrors Go's `recordingKeyManager.ValidateVoteRound`. Returns
        /// `Ok(())` when both `Voted` and `Proposed` were recorded at
        /// `round` for `address`; returns `Err` describing what's missing
        /// otherwise. Returning `Result` (rather than panicking) keeps
        /// the helper composable with Rust's `?` and works without a
        /// `&mut TestContext` parameter.
        fn validate_vote_round(&self, address: Address, round: Round) -> Result<(), String> {
            let recording = self.recording.borrow();
            let actions = recording
                .get(&address)
                .ok_or_else(|| format!("no recorded actions for address {address}"))?;
            if actions.voted != Some(round) {
                return Err(format!(
                    "expected Voted at round {round}, got {:?}",
                    actions.voted,
                ));
            }
            if actions.proposed != Some(round) {
                return Err(format!(
                    "expected Proposed at round {round}, got {:?}",
                    actions.proposed,
                ));
            }
            Ok(())
        }
    }

    impl AgreementKeyManager for RecordingKeyManager {
        fn voting_keys(
            &self,
            voting_round: Round,
            _keys_round: Round,
        ) -> Vec<AgreementParticipationRecord> {
            self.keys
                .iter()
                .filter(|rec| {
                    rec.vote_first_valid.0 <= voting_round.0
                        && voting_round.0 <= rec.vote_last_valid.0
                })
                .cloned()
                .collect()
        }

        fn record(&self, account: &Address, round: Round, action: AgreementAction) {
            let mut recording = self.recording.borrow_mut();
            let entry = recording.entry(*account).or_default();
            match action {
                AgreementAction::Voted => entry.voted = Some(round),
                AgreementAction::Proposed => entry.proposed = Some(round),
                AgreementAction::StateProof => entry.state_proof = Some(round),
            }
        }
    }

    fn participation_record(
        addr_byte: u8,
        first_valid: Round,
        last_valid: Round,
    ) -> AgreementParticipationRecord {
        AgreementParticipationRecord {
            address: Address([addr_byte; 32]),
            vote_id: [0u8; 32],
            selection_id: [0u8; 32],
            vote_first_valid: first_valid,
            vote_last_valid: last_valid,
            vote_key_dilution: 100,
        }
    }

    #[test]
    fn recording_key_manager_initial_state_is_empty() {
        let km = RecordingKeyManager::new(Vec::new());
        assert!(km.recording.borrow().is_empty());
        // No registered keys means voting_keys always returns empty.
        let returned = km.voting_keys(Round(1), Round(0));
        assert!(returned.is_empty());
    }

    /// Mirrors Go's `VotingKeys` / `OverlapsInterval` filter at
    /// `keyManager_test.go:46-69`: only keys whose `[first_valid,
    /// last_valid]` interval contains `voting_round` come back.
    #[test]
    fn recording_key_manager_voting_keys_filters_by_round_overlap() {
        let km = RecordingKeyManager::new(vec![
            participation_record(1, Round(0), Round(50)),
            participation_record(2, Round(100), Round(200)),
            participation_record(3, Round(150), Round(300)),
        ]);

        // Round 0 — only key 1 overlaps.
        let r0 = km.voting_keys(Round(0), Round(0));
        let r0_addrs: Vec<_> = r0.iter().map(|r| r.address).collect();
        assert_eq!(r0_addrs, vec![Address([1u8; 32])]);

        // Round 175 — keys 2 and 3 overlap.
        let r175 = km.voting_keys(Round(175), Round(0));
        let r175_addrs: Vec<_> = r175.iter().map(|r| r.address).collect();
        assert_eq!(r175_addrs, vec![Address([2u8; 32]), Address([3u8; 32])],);

        // Round 75 — no overlaps.
        let r75 = km.voting_keys(Round(75), Round(0));
        assert!(r75.is_empty());

        // Boundary inclusivity: vote_last_valid is inclusive (Go uses
        // `OverlapsInterval(votingRound, votingRound)` which is closed).
        let r50 = km.voting_keys(Round(50), Round(0));
        let r50_addrs: Vec<_> = r50.iter().map(|r| r.address).collect();
        assert_eq!(r50_addrs, vec![Address([1u8; 32])]);
        let r100 = km.voting_keys(Round(100), Round(0));
        let r100_addrs: Vec<_> = r100.iter().map(|r| r.address).collect();
        assert_eq!(r100_addrs, vec![Address([2u8; 32])]);
    }

    /// Mirrors Go's `Record` storage layout (lines 76-83):
    /// `recording[acct][action] = round`.
    #[test]
    fn recording_key_manager_record_stores_per_action_round() {
        let km = RecordingKeyManager::new(Vec::new());
        let acct = Address([7u8; 32]);

        km.record(&acct, Round(42), AgreementAction::Voted);
        km.record(&acct, Round(43), AgreementAction::Proposed);

        let recording = km.recording.borrow();
        let actions = recording.get(&acct).expect("address present");
        assert_eq!(actions.voted, Some(Round(42)));
        assert_eq!(actions.proposed, Some(Round(43)));
        assert_eq!(actions.state_proof, None);
    }

    /// Mirrors the success path of Go's `ValidateVoteRound`: both
    /// `Vote` and `BlockProposal` actions recorded at the asserted
    /// round.
    #[test]
    fn validate_vote_round_succeeds_when_both_actions_present() {
        let km = RecordingKeyManager::new(Vec::new());
        let acct = Address([1u8; 32]);

        km.record(&acct, Round(10), AgreementAction::Voted);
        km.record(&acct, Round(10), AgreementAction::Proposed);

        km.validate_vote_round(acct, Round(10))
            .expect("both actions present at round 10");
    }

    #[test]
    fn validate_vote_round_fails_when_only_vote_recorded() {
        let km = RecordingKeyManager::new(Vec::new());
        let acct = Address([1u8; 32]);

        km.record(&acct, Round(10), AgreementAction::Voted);
        // Proposed missing.

        let err = km
            .validate_vote_round(acct, Round(10))
            .expect_err("Proposed action absent must fail validation");
        assert!(
            err.contains("Proposed"),
            "error message must mention Proposed: {err}",
        );
    }

    #[test]
    fn validate_vote_round_fails_when_only_proposal_recorded() {
        let km = RecordingKeyManager::new(Vec::new());
        let acct = Address([1u8; 32]);

        km.record(&acct, Round(10), AgreementAction::Proposed);
        // Voted missing.

        let err = km
            .validate_vote_round(acct, Round(10))
            .expect_err("Voted action absent must fail validation");
        assert!(
            err.contains("Voted"),
            "error message must mention Voted: {err}",
        );
    }

    #[test]
    fn validate_vote_round_fails_when_actions_at_wrong_round() {
        let km = RecordingKeyManager::new(Vec::new());
        let acct = Address([1u8; 32]);

        km.record(&acct, Round(9), AgreementAction::Voted);
        km.record(&acct, Round(9), AgreementAction::Proposed);

        // Asserting round 10, but the recording is at round 9.
        let err = km
            .validate_vote_round(acct, Round(10))
            .expect_err("recorded round mismatch must fail validation");
        assert!(
            err.contains("Round(9)") || err.contains("10"),
            "error message must mention the round mismatch: {err}",
        );
    }

    #[test]
    fn validate_vote_round_fails_for_unknown_address() {
        let km = RecordingKeyManager::new(Vec::new());
        let unknown = Address([42u8; 32]);

        let err = km
            .validate_vote_round(unknown, Round(10))
            .expect_err("unknown address must fail validation");
        assert!(
            err.contains("no recorded actions"),
            "error message must mention missing recording: {err}",
        );
    }
}
