//! Pure (I/O-free) builder for key-registration transactions.
//!
//! Mirrors go-algorand's keyreg constructors in `libgoal/transactions.go`:
//! `generateRegistrationTransaction` (online, from a
//! `model.ParticipationKey`), the bare `MakeUnsignedGoOfflineTx` body
//! (offline), and `MakeUnsignedBecomeNonparticipatingTx` (nonparticipating).
//!
//! The builder is deliberately free of network access: callers fetch suggested
//! params + participation material via the [`TxnPipeline`](crate::TxnPipeline)
//! and feed the resulting values in, so the construction stays unit-testable
//! against fixtures.

use algo_rest_client::AccountParticipation;
use algo_types::{Address, Round, Transaction, TxnType};

use crate::error::{PipelineError, Result};

/// The online voting/selection/state-proof material for a go-online keyreg,
/// validated to the on-chain field sizes.
#[derive(Debug, Clone)]
struct OnlineKeys {
    vote_pk: [u8; 32],
    selection_pk: [u8; 32],
    state_proof_pk: [u8; 64],
    vote_first: u64,
    vote_last: u64,
    vote_key_dilution: u64,
}

/// Which flavor of keyreg to build.
#[derive(Debug, Clone)]
enum Kind {
    /// Bring an account online with the given participation keys.
    Online(OnlineKeys),
    /// Bring an account offline (bare keyreg, no voting fields).
    Offline,
    /// Permanently mark an account non-participating (`nonpart = true`).
    Nonparticipating,
}

/// Builder for a key-registration [`Transaction`].
///
/// Construct via [`KeyregBuilder::online`], [`KeyregBuilder::offline`], or
/// [`KeyregBuilder::nonparticipating`]; set the header fields (validity window,
/// fee, genesis, lease, note); then [`build`](KeyregBuilder::build).
#[derive(Debug, Clone)]
pub struct KeyregBuilder {
    sender: Address,
    kind: Kind,
    fee: u64,
    first_valid: u64,
    last_valid: u64,
    genesis_hash: [u8; 32],
    genesis_id: String,
    lease: [u8; 32],
    note: Vec<u8>,
}

impl KeyregBuilder {
    fn base(sender: Address, kind: Kind) -> Self {
        KeyregBuilder {
            sender,
            kind,
            fee: 0,
            first_valid: 0,
            last_valid: 0,
            genesis_hash: [0u8; 32],
            genesis_id: String::new(),
            lease: [0u8; 32],
            note: Vec::new(),
        }
    }

    /// Build a go-online keyreg from a node-reported participation key.
    ///
    /// Validates the key sizes (vote/selection = 32 bytes, state-proof = 64)
    /// and that a state-proof key is present, matching go-algorand's
    /// `generateRegistrationTransaction` (`libgoal/transactions.go:222`).
    pub fn online(sender: Address, part: &AccountParticipation) -> Result<Self> {
        let vote_pk: [u8; 32] =
            part.vote_participation_key
                .as_slice()
                .try_into()
                .map_err(|_| {
                    PipelineError::InvalidKeyreg(format!(
                        "voting key is the wrong size, should be 32 but it is {}",
                        part.vote_participation_key.len()
                    ))
                })?;
        let selection_pk: [u8; 32] = part
            .selection_participation_key
            .as_slice()
            .try_into()
            .map_err(|_| {
                PipelineError::InvalidKeyreg(format!(
                    "selection key is the wrong size, should be 32 but it is {}",
                    part.selection_participation_key.len()
                ))
            })?;
        let state_proof_pk: [u8; 64] = match part.state_proof_key.as_ref() {
            Some(bytes) => bytes.as_slice().try_into().map_err(|_| {
                PipelineError::InvalidKeyreg(format!(
                    "state proof key is the wrong size, should be 64 but it is {}",
                    bytes.len()
                ))
            })?,
            None => {
                return Err(PipelineError::InvalidKeyreg(
                    "state proof key is missing".into(),
                ))
            }
        };
        Ok(Self::base(
            sender,
            Kind::Online(OnlineKeys {
                vote_pk,
                selection_pk,
                state_proof_pk,
                vote_first: part.vote_first_valid,
                vote_last: part.vote_last_valid,
                vote_key_dilution: part.vote_key_dilution,
            }),
        ))
    }

    /// Build a go-offline keyreg (clears the account's voting keys).
    pub fn offline(sender: Address) -> Self {
        Self::base(sender, Kind::Offline)
    }

    /// Build a become-nonparticipating keyreg (`nonpart = true`). Irreversible
    /// on-chain.
    pub fn nonparticipating(sender: Address) -> Self {
        Self::base(sender, Kind::Nonparticipating)
    }

    /// Set the transaction fee (microAlgos).
    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    /// Set the validity window `[first_valid, last_valid]`.
    pub fn validity(mut self, first_valid: u64, last_valid: u64) -> Self {
        self.first_valid = first_valid;
        self.last_valid = last_valid;
        self
    }

    /// Set the genesis hash (required for the transaction to be accepted on a
    /// network that supports genesis hashes, i.e. every current network).
    pub fn genesis_hash(mut self, genesis_hash: [u8; 32]) -> Self {
        self.genesis_hash = genesis_hash;
        self
    }

    /// Set the genesis id (informational; not committed to the txid).
    pub fn genesis_id(mut self, genesis_id: impl Into<String>) -> Self {
        self.genesis_id = genesis_id.into();
        self
    }

    /// Set the 32-byte lease.
    pub fn lease(mut self, lease: [u8; 32]) -> Self {
        self.lease = lease;
        self
    }

    /// Set the note field.
    pub fn note(mut self, note: Vec<u8>) -> Self {
        self.note = note;
        self
    }

    /// Finalize the builder into a [`Transaction`].
    pub fn build(self) -> Result<Transaction> {
        if self.last_valid < self.first_valid {
            return Err(PipelineError::InvalidValidity(format!(
                "last_valid ({}) < first_valid ({})",
                self.last_valid, self.first_valid
            )));
        }

        let mut txn = Transaction {
            txn_type: TxnType::Keyreg,
            sender: self.sender,
            fee: self.fee,
            first_valid: Round(self.first_valid),
            last_valid: Round(self.last_valid),
            genesis_id: self.genesis_id,
            genesis_hash: self.genesis_hash,
            lease: self.lease,
            note: self.note.into(),
            ..Transaction::default()
        };

        match self.kind {
            Kind::Online(keys) => {
                txn.vote_pk = Some(keys.vote_pk);
                txn.selection_pk = Some(keys.selection_pk);
                txn.state_proof_pk = Some(keys.state_proof_pk);
                txn.vote_first = keys.vote_first;
                txn.vote_last = keys.vote_last;
                txn.vote_key_dilution = keys.vote_key_dilution;
            }
            Kind::Offline => {
                // Bare keyreg: no voting fields. Matches go's
                // MakeUnsignedGoOfflineTx body.
            }
            Kind::Nonparticipating => {
                txn.non_participation = true;
            }
        }

        Ok(txn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_participation() -> AccountParticipation {
        AccountParticipation {
            vote_participation_key: vec![0x11; 32],
            selection_participation_key: vec![0x22; 32],
            state_proof_key: Some(vec![0x33; 64]),
            vote_first_valid: 100,
            vote_last_valid: 2000,
            vote_key_dilution: 45,
        }
    }

    #[test]
    fn online_builds_go_compatible_keyreg_fields() {
        let sender = Address([0xAA; 32]);
        let txn = KeyregBuilder::online(sender, &sample_participation())
            .unwrap()
            .fee(1000)
            .validity(500, 1500)
            .genesis_hash([0x9; 32])
            .build()
            .unwrap();

        assert_eq!(txn.txn_type, TxnType::Keyreg);
        assert_eq!(txn.sender, sender);
        assert_eq!(txn.fee, 1000);
        assert_eq!(txn.first_valid, Round(500));
        assert_eq!(txn.last_valid, Round(1500));
        assert_eq!(txn.vote_pk, Some([0x11; 32]));
        assert_eq!(txn.selection_pk, Some([0x22; 32]));
        assert_eq!(txn.state_proof_pk, Some([0x33; 64]));
        assert_eq!(txn.vote_first, 100);
        assert_eq!(txn.vote_last, 2000);
        assert_eq!(txn.vote_key_dilution, 45);
        assert!(!txn.non_participation);
    }

    #[test]
    fn offline_is_a_bare_keyreg() {
        let sender = Address([0xBB; 32]);
        let txn = KeyregBuilder::offline(sender)
            .fee(1000)
            .validity(10, 1010)
            .build()
            .unwrap();

        assert_eq!(txn.txn_type, TxnType::Keyreg);
        assert_eq!(txn.sender, sender);
        assert_eq!(txn.vote_pk, None);
        assert_eq!(txn.selection_pk, None);
        assert_eq!(txn.state_proof_pk, None);
        assert_eq!(txn.vote_first, 0);
        assert_eq!(txn.vote_last, 0);
        assert_eq!(txn.vote_key_dilution, 0);
        assert!(!txn.non_participation);
    }

    #[test]
    fn nonparticipating_sets_the_flag_only() {
        let txn = KeyregBuilder::nonparticipating(Address([0xCC; 32]))
            .fee(1000)
            .validity(10, 1010)
            .build()
            .unwrap();

        assert_eq!(txn.txn_type, TxnType::Keyreg);
        assert!(txn.non_participation);
        assert_eq!(txn.vote_pk, None);
        assert_eq!(txn.selection_pk, None);
    }

    #[test]
    fn online_rejects_wrong_size_vote_key() {
        let mut part = sample_participation();
        part.vote_participation_key = vec![0x11; 31];
        let err = KeyregBuilder::online(Address([0xAA; 32]), &part).unwrap_err();
        assert!(matches!(err, PipelineError::InvalidKeyreg(_)));
    }

    #[test]
    fn online_rejects_missing_state_proof_key() {
        let mut part = sample_participation();
        part.state_proof_key = None;
        let err = KeyregBuilder::online(Address([0xAA; 32]), &part).unwrap_err();
        assert!(matches!(err, PipelineError::InvalidKeyreg(_)));
    }

    #[test]
    fn build_rejects_inverted_validity_window() {
        let err = KeyregBuilder::offline(Address([0xBB; 32]))
            .validity(1000, 500)
            .build()
            .unwrap_err();
        assert!(matches!(err, PipelineError::InvalidValidity(_)));
    }
}
