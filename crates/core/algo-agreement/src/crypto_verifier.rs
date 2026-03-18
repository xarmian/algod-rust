// Real CryptoVerifier implementation for the agreement protocol.
//
// Performs actual cryptographic verification of votes, proposals, and bundles
// using the VRF and OTS verification functions from algo-consensus-crypto.
//
// This is a synchronous implementation: verification is performed inline when
// a request is submitted, and the result is immediately placed on the output
// channel. This matches Go's behavior for the common case (the pool crypto
// verifier spawns workers, but the verification itself is synchronous per item).

use std::sync::Arc;

use tracing::debug;

use crate::ledger_reader::LedgerReader;
use crate::traits::{
    CryptoBundleRequest, CryptoProposalRequest, CryptoResult, CryptoVerifier, CryptoVoteRequest,
    CryptoVoteVerifyResult, PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
};
use crate::vote::{RawVote, UnauthenticatedVote, VoteVerifyParams};

// ---------------------------------------------------------------------------
// AsyncCryptoVerifier
// ---------------------------------------------------------------------------

/// A real `CryptoVerifier` that performs actual cryptographic verification.
///
/// For votes, it verifies:
/// - The VRF credential proof (sortition)
/// - The one-time signature (OTS) on the raw vote
///
/// For proposals, it passes results through — the block validator catches
/// invalid blocks later in the ensure action, matching Go's separation of
/// concerns (proposal crypto is mostly about block validation).
///
/// For bundles, it verifies each vote in the bundle individually by
/// reconstructing the full `UnauthenticatedVote` from the bundle's shared
/// round/period/step/proposal and each `VoteAuthenticator`.
///
/// Verification is synchronous: results are placed on the output channel
/// immediately after verification completes. This avoids the complexity of
/// a thread pool while still providing real cryptographic verification.
pub struct AsyncCryptoVerifier<L: LedgerReader + Send + Sync + 'static> {
    ledger: Arc<L>,

    /// Channel pair for vote verification results.
    vote_tx: crossbeam_channel::Sender<CryptoVoteVerifyResult>,
    vote_rx: crossbeam_channel::Receiver<CryptoVoteVerifyResult>,

    /// Channel pair for proposal verification results.
    proposal_tx: crossbeam_channel::Sender<CryptoResult>,
    proposal_rx: crossbeam_channel::Receiver<CryptoResult>,

    /// Channel pair for bundle verification results.
    bundle_tx: crossbeam_channel::Sender<CryptoResult>,
    bundle_rx: crossbeam_channel::Receiver<CryptoResult>,
}

impl<L: LedgerReader + Send + Sync + 'static> AsyncCryptoVerifier<L> {
    /// Create a new `AsyncCryptoVerifier` backed by the given ledger.
    ///
    /// The ledger is used to look up account data (vote keys, VRF selection
    /// keys, balances) needed for vote verification.
    pub fn new(ledger: Arc<L>) -> Self {
        let (vote_tx, vote_rx) = crossbeam_channel::unbounded();
        let (proposal_tx, proposal_rx) = crossbeam_channel::unbounded();
        let (bundle_tx, bundle_rx) = crossbeam_channel::unbounded();
        Self {
            ledger,
            vote_tx,
            vote_rx,
            proposal_tx,
            proposal_rx,
            bundle_tx,
            bundle_rx,
        }
    }

    /// Verify a single vote against the ledger.
    ///
    /// Looks up the voter's account data (OTS master key, VRF selection key,
    /// balance, etc.) from the ledger and delegates to
    /// `UnauthenticatedVote::verify()`.
    fn verify_vote_inner(&self, request: &CryptoVoteRequest) -> CryptoVoteVerifyResult {
        let uv = &request.message.unauthenticated_vote;
        let rv = &uv.raw_vote;

        // Look up membership + account data from the ledger.
        let lookup_result = crate::ledger_reader::membership_from_ledger(
            self.ledger.as_ref(),
            &rv.sender,
            request.round,
            request.period,
            rv.step,
        );

        let (membership, record, cparams) = match lookup_result {
            Ok(v) => v,
            Err(e) => {
                return CryptoVoteVerifyResult {
                    vote: None,
                    message: request.message.clone(),
                    task_index: request.task_index,
                    err: Some(crate::events::SerializableError::new(format!(
                        "ledger lookup failed for vote verification: {e}"
                    ))),
                    cancelled: false,
                };
            }
        };

        let params = VoteVerifyParams {
            membership,
            vote_id: record.vote_id,
            vote_first_valid: record.vote_first_valid,
            vote_last_valid: record.vote_last_valid,
            vote_key_dilution: record.vote_key_dilution,
            consensus_params: cparams,
        };

        match uv.verify(&params) {
            Ok(vote) => CryptoVoteVerifyResult {
                vote: Some(vote),
                message: request.message.clone(),
                task_index: request.task_index,
                err: None,
                cancelled: false,
            },
            Err(e) => CryptoVoteVerifyResult {
                vote: None,
                message: request.message.clone(),
                task_index: request.task_index,
                err: Some(crate::events::SerializableError::new(format!(
                    "vote verification failed: {e}"
                ))),
                cancelled: false,
            },
        }
    }

    /// Verify a bundle by verifying each vote it contains.
    ///
    /// Reconstructs full `UnauthenticatedVote`s from the bundle's shared
    /// round/period/step/proposal and each `VoteAuthenticator`, then verifies
    /// each one individually.
    ///
    /// If any vote fails verification, the entire bundle is rejected.
    fn verify_bundle_inner(&self, request: &CryptoBundleRequest) -> CryptoResult {
        let ub = &request.message.unauthenticated_bundle;

        // Verify each regular vote authenticator in the bundle.
        for va in &ub.votes {
            // Reconstruct the full UnauthenticatedVote from the bundle's
            // shared fields and the authenticator's per-vote fields.
            let uv = UnauthenticatedVote {
                raw_vote: RawVote {
                    sender: va.sender,
                    round: ub.round,
                    period: ub.period,
                    step: ub.step,
                    proposal: ub.proposal,
                },
                cred: va.cred.clone(),
                sig: va.sig.clone(),
            };

            let lookup_result = crate::ledger_reader::membership_from_ledger(
                self.ledger.as_ref(),
                &va.sender,
                request.round,
                request.period,
                uv.raw_vote.step,
            );

            let (membership, record, cparams) = match lookup_result {
                Ok(v) => v,
                Err(e) => {
                    return CryptoResult {
                        message: request.message.clone(),
                        task_index: request.task_index,
                        err: Some(crate::events::SerializableError::new(format!(
                            "ledger lookup failed for bundle vote verification: {e}"
                        ))),
                        cancelled: false,
                    };
                }
            };

            let params = VoteVerifyParams {
                membership,
                vote_id: record.vote_id,
                vote_first_valid: record.vote_first_valid,
                vote_last_valid: record.vote_last_valid,
                vote_key_dilution: record.vote_key_dilution,
                consensus_params: cparams,
            };

            if let Err(e) = uv.verify(&params) {
                return CryptoResult {
                    message: request.message.clone(),
                    task_index: request.task_index,
                    err: Some(crate::events::SerializableError::new(format!(
                        "bundle vote verification failed: {e}"
                    ))),
                    cancelled: false,
                };
            }
        }

        // Verify equivocation votes — each has two signatures for two
        // different proposals. Both must verify with the same credential.
        for eva in &ub.equivocation_votes {
            for i in 0..2 {
                let uv = UnauthenticatedVote {
                    raw_vote: RawVote {
                        sender: eva.sender,
                        round: ub.round,
                        period: ub.period,
                        step: ub.step,
                        proposal: eva.proposals[i],
                    },
                    cred: eva.cred.clone(),
                    sig: eva.sigs[i].clone(),
                };

                let lookup_result = crate::ledger_reader::membership_from_ledger(
                    self.ledger.as_ref(),
                    &eva.sender,
                    request.round,
                    request.period,
                    uv.raw_vote.step,
                );

                let (membership, record, cparams) = match lookup_result {
                    Ok(v) => v,
                    Err(e) => {
                        return CryptoResult {
                            message: request.message.clone(),
                            task_index: request.task_index,
                            err: Some(crate::events::SerializableError::new(format!(
                                "ledger lookup failed for equivocation vote verification: {e}"
                            ))),
                            cancelled: false,
                        };
                    }
                };

                let params = VoteVerifyParams {
                    membership,
                    vote_id: record.vote_id,
                    vote_first_valid: record.vote_first_valid,
                    vote_last_valid: record.vote_last_valid,
                    vote_key_dilution: record.vote_key_dilution,
                    consensus_params: cparams,
                };

                if let Err(e) = uv.verify(&params) {
                    return CryptoResult {
                        message: request.message.clone(),
                        task_index: request.task_index,
                        err: Some(crate::events::SerializableError::new(format!(
                            "equivocation vote verification failed: {e}"
                        ))),
                        cancelled: false,
                    };
                }
            }
        }

        // All votes verified successfully.
        CryptoResult {
            message: request.message.clone(),
            task_index: request.task_index,
            err: None,
            cancelled: false,
        }
    }
}

impl<L: LedgerReader + Send + Sync + 'static> CryptoVerifier for AsyncCryptoVerifier<L> {
    fn verify_vote(&self, request: CryptoVoteRequest) {
        let result = self.verify_vote_inner(&request);
        if result.err.is_some() {
            debug!(
                task_index = request.task_index,
                round = %request.round,
                "vote verification failed: {:?}",
                result.err
            );
        }
        let _ = self.vote_tx.send(result);
    }

    fn verify_proposal(&self, request: CryptoProposalRequest) {
        // For proposals, the verification is primarily about the block content
        // (which is handled by the block validator in the ensure action).
        // The crypto action for proposals in Go validates the proposal payload
        // via `up.validate()` which checks block validity.
        //
        // For now, we pass the proposal through — the block validator will
        // catch invalid blocks when they are ensured. This matches the Go
        // behavior where proposal verification is about block validation, not
        // signature verification (votes carry the signatures).
        debug!(
            task_index = request.task_index,
            round = %request.round,
            pinned = request.pinned,
            "proposal verification (pass-through to block validator)"
        );
        let result = CryptoResult {
            message: request.message,
            task_index: request.task_index,
            err: None,
            cancelled: false,
        };
        let _ = self.proposal_tx.send(result);
    }

    fn verify_bundle(&self, request: CryptoBundleRequest) {
        let result = self.verify_bundle_inner(&request);
        if result.err.is_some() {
            debug!(
                task_index = request.task_index,
                round = %request.round,
                "bundle verification failed: {:?}",
                result.err
            );
        }
        let _ = self.bundle_tx.send(result);
    }

    fn verified_votes(&self) -> &crossbeam_channel::Receiver<CryptoVoteVerifyResult> {
        &self.vote_rx
    }

    fn verified(&self, tag: &str) -> &crossbeam_channel::Receiver<CryptoResult> {
        match tag {
            PROPOSAL_PAYLOAD_TAG => &self.proposal_rx,
            VOTE_BUNDLE_TAG => &self.bundle_rx,
            _ => panic!("AsyncCryptoVerifier::verified called with unknown tag: {tag}"),
        }
    }

    fn channel_full(&self, _tag: &str) -> bool {
        // Unbounded channels are never full.
        false
    }

    fn quit(&self) {
        // No background workers to shut down — synchronous verification.
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::InternalMessage;
    use crate::step::Period;
    use crate::stubs::StubLedger;
    use crate::vote::UnauthenticatedVote;
    use algo_types::{ConsensusParams, Round};

    fn v41_params() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

    #[test]
    fn async_crypto_verifier_implements_trait() {
        fn _assert<T: CryptoVerifier>() {}
        _assert::<AsyncCryptoVerifier<StubLedger>>();
    }

    #[test]
    fn async_crypto_verifier_vote_with_bad_keys_returns_error() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier = AsyncCryptoVerifier::new(ledger);

        let request = CryptoVoteRequest {
            message: InternalMessage {
                tag: "AV".to_string(),
                unauthenticated_vote: UnauthenticatedVote::default(),
                ..InternalMessage::default()
            },
            task_index: 42,
            round: Round(10),
            period: Period(0),
        };

        verifier.verify_vote(request);

        // Should get an error result because the ledger has no account data
        // for the zero-address sender.
        let result = verifier
            .verified_votes()
            .try_recv()
            .expect("should have a result");
        assert_eq!(result.task_index, 42);
        assert!(
            result.err.is_some(),
            "expected error for missing account data"
        );
        assert!(result.vote.is_none());
    }

    #[test]
    fn async_crypto_verifier_proposal_passthrough() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier = AsyncCryptoVerifier::new(ledger);

        let request = CryptoProposalRequest {
            message: InternalMessage {
                tag: "PP".to_string(),
                ..InternalMessage::default()
            },
            task_index: 7,
            round: Round(5),
            period: Period(0),
            pinned: false,
        };

        verifier.verify_proposal(request);

        let result = verifier
            .verified(PROPOSAL_PAYLOAD_TAG)
            .try_recv()
            .expect("should have a result");
        assert_eq!(result.task_index, 7);
        assert!(result.err.is_none());
    }

    #[test]
    fn async_crypto_verifier_channel_never_full() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier = AsyncCryptoVerifier::new(ledger);
        assert!(!verifier.channel_full("AV"));
        assert!(!verifier.channel_full("PP"));
        assert!(!verifier.channel_full("VB"));
    }
}
