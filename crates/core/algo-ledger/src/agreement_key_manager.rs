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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::participation::{ParticipationID, ParticipationRecord as LedgerRec};
    use algo_consensus_crypto::VrfPubkey;

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
}
