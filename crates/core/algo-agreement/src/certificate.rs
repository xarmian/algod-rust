// Certificate types and authentication, matching go-algorand/agreement/certificate.go.
//
// A Certificate is essentially an unauthenticatedBundle for the cert step.
// It proves that agreement was reached on a block in a given round.

use algo_types::{Digest, Round};

use crate::bundle::{BundleError, UnauthenticatedBundle, VoteAuthenticator};
use crate::ledger_reader::LedgerReader;
use crate::step::{Period, CERT};
use crate::vote::ProposalValue;

/// A certificate proving agreement was reached on a block.
///
/// Mirrors Go's `agreement.Certificate`, which is a type alias for
/// `unauthenticatedBundle`. A valid certificate always has step = CERT.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The round this certificate is for.
    pub round: Round,
    /// The period within the round.
    pub period: Period,
    /// The proposal value that was agreed upon.
    pub proposal: ProposalValue,
    /// The vote authenticators proving quorum was reached.
    pub votes: Vec<VoteAuthenticator>,
}

impl Default for Certificate {
    fn default() -> Self {
        Self {
            round: Round(0),
            period: Period(0),
            proposal: crate::vote::BOTTOM,
            votes: Vec::new(),
        }
    }
}

/// Errors from certificate authentication.
#[derive(Debug, Clone)]
pub enum CertificateError {
    /// The certificate step is not CERT.
    WrongStep,
    /// The certificate round doesn't match the block.
    RoundMismatch {
        cert_round: Round,
        block_round: Round,
    },
    /// The certificate's block digest doesn't match.
    DigestMismatch {
        cert_digest: Digest,
        block_digest: Digest,
    },
    /// Bundle verification failed.
    BundleError(BundleError),
}

impl std::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongStep => write!(f, "certificate step is not cert"),
            Self::RoundMismatch {
                cert_round,
                block_round,
            } => write!(
                f,
                "certificate round {cert_round} != block round {block_round}"
            ),
            Self::DigestMismatch {
                cert_digest,
                block_digest,
            } => write!(
                f,
                "certificate digest {cert_digest:?} != block digest {block_digest:?}"
            ),
            Self::BundleError(e) => write!(f, "bundle verification failed: {e}"),
        }
    }
}

impl std::error::Error for CertificateError {}

impl From<BundleError> for CertificateError {
    fn from(e: BundleError) -> Self {
        Self::BundleError(e)
    }
}

impl Certificate {
    /// Create a Certificate from an UnauthenticatedBundle.
    ///
    /// Mirrors Go's `Certificate(e.Bundle)` — in Go, Certificate is a type
    /// alias for unauthenticatedBundle.
    pub fn from_bundle(b: &UnauthenticatedBundle) -> Self {
        Self {
            round: b.round,
            period: b.period,
            proposal: b.proposal,
            votes: b.votes.clone(),
        }
    }

    /// Convert this certificate to an `UnauthenticatedBundle` for verification.
    ///
    /// The bundle step is always CERT.
    pub fn to_unauthenticated_bundle(&self) -> UnauthenticatedBundle {
        UnauthenticatedBundle {
            round: self.round,
            period: self.period,
            step: CERT,
            proposal: self.proposal,
            votes: self.votes.clone(),
            equivocation_votes: vec![],
        }
    }

    /// Authenticate the certificate against a block.
    ///
    /// Mirrors Go's `Certificate.Authenticate()`:
    /// 1. Check that the step is CERT
    /// 2. Check that the round matches
    /// 3. Check that the block digest matches
    /// 4. Verify the underlying bundle (quorum check)
    ///
    /// Parameters:
    /// - `block_round`: the round of the block
    /// - `block_digest`: the digest of the block
    /// - `l`: ledger reader for looking up membership data
    pub fn authenticate(
        &self,
        block_round: Round,
        block_digest: Digest,
        l: &dyn LedgerReader,
    ) -> Result<(), CertificateError> {
        // Step 1: verify claims
        self.claims_to_authenticate(block_round, block_digest)?;

        // Step 2: verify the bundle
        let bundle = self.to_unauthenticated_bundle();
        bundle.verify(l)?;

        Ok(())
    }

    /// Check that this certificate claims to authenticate the given block.
    ///
    /// Mirrors Go's `Certificate.claimsToAuthenticate()`.
    fn claims_to_authenticate(
        &self,
        block_round: Round,
        block_digest: Digest,
    ) -> Result<(), CertificateError> {
        // Right round?
        if self.round != block_round {
            return Err(CertificateError::RoundMismatch {
                cert_round: self.round,
                block_round,
            });
        }
        // Right digest?
        if self.proposal.block_digest != block_digest {
            return Err(CertificateError::DigestMismatch {
                cert_digest: self.proposal.block_digest,
                block_digest,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger_reader::{LedgerError, OnlineAccountData};
    use crate::seed::Seed;
    use crate::step::Period;
    use algo_types::{Address, ConsensusParams};

    // ── MockLedgerReader ─────────────────────────────────────────────────

    struct MockLedgerReader {
        params: ConsensusParams,
    }

    impl MockLedgerReader {
        fn new() -> Self {
            Self {
                params: algo_types::consensus::consensus_params_for_version(
                    algo_types::CONSENSUS_V41,
                )
                .expect("v41 params"),
            }
        }
    }

    impl LedgerReader for MockLedgerReader {
        fn seed(&self, _round: Round) -> Result<Seed, LedgerError> {
            Ok(Seed([0xab; 32]))
        }

        fn lookup_agreement(
            &self,
            _round: Round,
            _addr: &Address,
        ) -> Result<OnlineAccountData, LedgerError> {
            Err(LedgerError::Other("account not found".to_string()))
        }

        fn circulation(&self, _rnd: Round, _vote_rnd: Round) -> Result<u64, LedgerError> {
            Ok(10_000_000)
        }

        fn lookup_digest(&self, _round: Round) -> Result<Digest, LedgerError> {
            Ok(Digest([0u8; 32]))
        }

        fn consensus_params(&self, _round: Round) -> Result<ConsensusParams, LedgerError> {
            Ok(self.params.clone())
        }

        fn next_round(&self) -> Round {
            Round(1)
        }

        fn consensus_version(&self, _round: Round) -> Result<String, LedgerError> {
            Ok(algo_types::CONSENSUS_V41.to_string())
        }

        fn wait_for_round(&self, _round: Round) -> Result<(), LedgerError> {
            Ok(())
        }

        fn round_notify(&self, round: Round) -> crossbeam_channel::Receiver<Round> {
            let (tx, rx) = crossbeam_channel::bounded(1);
            let _ = tx.send(round);
            rx
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────

    #[test]
    fn certificate_round_mismatch() {
        let cert = Certificate {
            round: Round(100),
            period: Period(0),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![],
        };

        let ledger = MockLedgerReader::new();
        let result = cert.authenticate(Round(200), Digest([0xaa; 32]), &ledger);
        assert!(matches!(
            result,
            Err(CertificateError::RoundMismatch { .. })
        ));
    }

    #[test]
    fn certificate_digest_mismatch() {
        let cert = Certificate {
            round: Round(100),
            period: Period(0),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![],
        };

        let ledger = MockLedgerReader::new();
        let result = cert.authenticate(Round(100), Digest([0xff; 32]), &ledger);
        assert!(matches!(
            result,
            Err(CertificateError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn certificate_empty_votes_insufficient_quorum() {
        let cert = Certificate {
            round: Round(100),
            period: Period(0),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![],
        };

        let ledger = MockLedgerReader::new();
        let result = cert.authenticate(Round(100), Digest([0xaa; 32]), &ledger);
        // Should fail with insufficient quorum (empty bundle)
        assert!(
            matches!(
                result,
                Err(CertificateError::BundleError(
                    BundleError::InsufficientQuorum { .. }
                ))
            ),
            "expected InsufficientQuorum, got: {result:?}"
        );
    }

    #[test]
    fn certificate_claims_to_authenticate_success() {
        let cert = Certificate {
            round: Round(100),
            period: Period(0),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![],
        };

        let result = cert.claims_to_authenticate(Round(100), Digest([0xaa; 32]));
        assert!(result.is_ok());
    }

    #[test]
    fn certificate_to_unauthenticated_bundle() {
        let cert = Certificate {
            round: Round(100),
            period: Period(0),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x01; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![],
        };

        let bundle = cert.to_unauthenticated_bundle();
        assert_eq!(bundle.round, Round(100));
        assert_eq!(bundle.period, Period(0));
        assert_eq!(bundle.step, CERT);
        assert_eq!(bundle.proposal, cert.proposal);
        assert!(bundle.votes.is_empty());
        assert!(bundle.equivocation_votes.is_empty());
    }

    #[test]
    fn certificate_error_display() {
        let err = CertificateError::WrongStep;
        assert_eq!(format!("{err}"), "certificate step is not cert");

        let err = CertificateError::RoundMismatch {
            cert_round: Round(100),
            block_round: Round(200),
        };
        assert!(format!("{err}").contains("100"));
        assert!(format!("{err}").contains("200"));

        let err = CertificateError::BundleError(BundleError::ProposeStep);
        assert!(format!("{err}").contains("propose"));
    }
}
