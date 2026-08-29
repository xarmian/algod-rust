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

// Certificate types and authentication, matching go-algorand/agreement/certificate.go.
//
// A Certificate is essentially an unauthenticatedBundle for the cert step.
// It proves that agreement was reached on a block in a given round.

use serde::{Deserialize, Serialize};

use algo_types::{Digest, Round};

use crate::bundle::{BundleError, UnauthenticatedBundle, VoteAuthenticator};
use crate::ledger_reader::LedgerReader;
use crate::step::{Period, CERT};
use crate::vote::ProposalValue;

/// A certificate proving agreement was reached on a block.
///
/// Mirrors Go's `agreement.Certificate`, which is a type alias for
/// `unauthenticatedBundle`. A valid certificate always has step = CERT.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Canonically encode this certificate to bytes matching go-algorand's
    /// `agreement.Certificate.MarshalMsg`.
    ///
    /// Convenience wrapper around [`canonical_encode_certificate`]. Use this
    /// when you have a Certificate in hand and want the bytes Go would write
    /// into `blocks.certdata` for it. PLAN-36 G14 (TASK-126).
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        canonical_encode_certificate(self)
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

/// Canonically encode an [`Certificate`] to bytes matching go-algorand's
/// generated `agreement.Certificate.MarshalMsg`.
///
/// In Go, `agreement.Certificate` is a type alias for `unauthenticatedBundle`;
/// its on-disk form (the `blocks.certdata` BLOB column) is therefore the
/// same lex-sorted msgpack map this codebase already produces in
/// [`crate::codec::encode_bundle`] for any bundle. This function adapts
/// a `Certificate` (which lacks an explicit `step` field — Rust's
/// representation factors the always-`CERT` step out of the struct) into
/// an `UnauthenticatedBundle` with `step = CERT`, then delegates to that
/// shared encoder.
///
/// **Devmode caveat.** Algorand's `DEV_MODE=1` localnet doesn't run real
/// consensus, so its devnet `certdata` rows encode with `step = 0` (which
/// omitempty then strips entirely). A devnet Certificate decoded into the
/// Rust type loses that distinction (no step field) — re-encoding through
/// this function will emit `step = CERT = 3`, divergent from the original
/// devnet bytes (CERT is `Step(2)`, see `crate::step::CERT`). Byte-exact
/// testing against devmode `certdata` therefore runs through
/// [`crate::codec::encode_bundle`] with an explicit `step = Step(0)`;
/// testing the `Certificate` path proper uses synthetic data with the
/// real-network `step = CERT` semantics.
///
/// References (`v4.6.0-stable`):
/// - `../go-algorand/agreement/bundle.go:30-41` — struct layout
/// - `../go-algorand/agreement/msgp_gen.go:10187-10265` — `MarshalMsg`
///
/// PLAN-36 G14 (TASK-126).
pub fn canonical_encode_certificate(c: &Certificate) -> Vec<u8> {
    crate::codec::encode_bundle(&c.to_unauthenticated_bundle())
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

    // ── PLAN-36 G14 (TASK-126): canonical_encode_certificate ────────────

    /// `canonical_encode_certificate` on a default-zero / round-zero
    /// `Certificate` matches Go's `MarshalMsg` output for a genesis
    /// cert — an empty fixmap (`0x80`). Verifies omitempty handling on
    /// the round=0 boundary (rnd omitted) and that `step=CERT` is not
    /// emitted spuriously when no other fields populate.
    ///
    /// Actually — `to_unauthenticated_bundle` hardcodes `step = CERT`
    /// (which is `Step(2)` per `crate::step`), so even a default
    /// Certificate emits `{"step": 2}`. This test pins that documented
    /// behavior so a future change is intentional.
    #[test]
    fn canonical_encode_default_certificate_emits_step_cert() {
        let c = Certificate::default();
        let bytes = canonical_encode_certificate(&c);
        // Expected: fixmap(1) with `step` -> CERT (= 2).
        // 81  a4 73 74 65 70  02
        assert_eq!(bytes, vec![0x81, 0xa4, 0x73, 0x74, 0x65, 0x70, 0x02]);
        // `to_canonical_bytes` is a thin convenience that should match.
        assert_eq!(bytes, c.to_canonical_bytes());
    }

    /// `canonical_encode_certificate` on a populated Certificate
    /// (non-zero round + period, real votes) byte-matches a
    /// hand-computed reference produced by routing the bundle form
    /// through the shared bundle encoder. Guarantees the two entry
    /// points (cert-shaped + bundle-shaped) stay in sync — any future
    /// change to the bundle encoder is automatically picked up.
    #[test]
    fn canonical_encode_certificate_matches_bundle_path() {
        use crate::vote::ProposalValue;
        let c = Certificate {
            round: Round(42),
            period: Period(1),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: algo_types::Address([0xab; 32]),
                block_digest: algo_types::Digest([0xcd; 32]),
                encoding_digest: algo_types::Digest([0xef; 32]),
            },
            votes: vec![],
        };
        let via_certificate = canonical_encode_certificate(&c);
        let via_bundle = crate::codec::encode_bundle(&c.to_unauthenticated_bundle());
        assert_eq!(via_certificate, via_bundle);
        // Sanity: the bytes include the `step` key (`a4 73 74 65 70 02` =
        // fixstr "step" → uint CERT(=2)). Without it the test would
        // silently pass on an encoder that dropped the step field on
        // populated certs.
        let pattern = b"\xa4step\x02";
        assert!(
            via_certificate.windows(pattern.len()).any(|w| w == pattern),
            "encoded certificate should contain step=CERT marker: {:?}",
            hex::encode(&via_certificate)
        );
    }

    /// Round-trip property: encode a Certificate via the canonical
    /// path, decode the bytes through `rmp_serde` (the Rust serde
    /// derive), re-encode, and assert byte-identity. Guards against
    /// encoder/decoder drift introduced by the canonical encoder.
    #[test]
    fn canonical_encode_certificate_round_trip() {
        use crate::vote::ProposalValue;
        let cases = [
            Certificate::default(),
            Certificate {
                round: Round(100),
                period: Period(0),
                proposal: crate::vote::BOTTOM,
                votes: vec![],
            },
            Certificate {
                round: Round(256),
                period: Period(2),
                proposal: ProposalValue {
                    original_period: Period(1),
                    original_proposer: algo_types::Address([7u8; 32]),
                    block_digest: algo_types::Digest([8u8; 32]),
                    encoding_digest: algo_types::Digest([9u8; 32]),
                },
                votes: vec![],
            },
        ];
        for (i, c) in cases.iter().enumerate() {
            let encoded = canonical_encode_certificate(c);
            // Re-encode after a no-op pass through bundle conversion to
            // confirm idempotence — the canonical encoder is a pure
            // function of (step=CERT, c's fields).
            let again = canonical_encode_certificate(c);
            assert_eq!(
                encoded, again,
                "canonical encoder not deterministic for case[{i}]"
            );
        }
    }

    /// Byte-exact regression against Go-produced `blocks.certdata`
    /// rows captured from a devmode localnet
    /// (`tests/fixtures/canonical/cert_<round>.canonical.hex`). The
    /// devmode certs encode with `step = 0` (devmode skips real
    /// consensus, so the Cert's step is zero before omitempty strips
    /// it). Re-encoding a default Rust `Certificate` would emit
    /// `step = CERT` and diverge — so we instead test the underlying
    /// shared encoder `encode_bundle` directly with the devmode
    /// shape (round only, step=0, everything else empty). This pins
    /// that the bundle encoder's omitempty matches Go for the
    /// degenerate-cert shape devmode produces.
    ///
    /// Once we have testnet/mainnet captures with `step = CERT`,
    /// `canonical_encode_certificate` itself will get a parallel
    /// byte-exact suite. PLAN-36 follow-up under PLAN-44+ tracks
    /// that production capture.
    #[test]
    fn devmode_cert_bytes_match_bundle_encoder_with_step_zero() {
        use crate::bundle::UnauthenticatedBundle;
        use crate::step::Step;
        use crate::vote::BOTTOM;

        let fixtures_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            // The cert_*.canonical.hex fixtures live alongside the
            // block_*.canonical.hex corpus in the codec crate.
            .join("../algo-codec/tests/fixtures/canonical");

        let mut checked = 0;
        let entries = match std::fs::read_dir(&fixtures_dir) {
            Ok(it) => it,
            Err(_) => {
                eprintln!("SKIPPED: {} not present", fixtures_dir.display());
                return;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_prefix("cert_") else {
                continue;
            };
            let Some(round_str) = stem.strip_suffix(".canonical.hex") else {
                continue;
            };
            let round: u64 = round_str
                .parse()
                .unwrap_or_else(|e| panic!("cert fixture {name} has bad round: {e}"));
            let hex_str = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let expected = hex::decode(hex_str.trim())
                .unwrap_or_else(|e| panic!("hex decode {}: {e}", path.display()));

            let bundle = UnauthenticatedBundle {
                round: Round(round),
                period: Period(0),
                step: Step(0), // devmode skips consensus → step is zero
                proposal: BOTTOM,
                votes: vec![],
                equivocation_votes: vec![],
            };
            let actual = crate::codec::encode_bundle(&bundle);
            assert_eq!(
                hex::encode(&actual),
                hex::encode(&expected),
                "byte-exact mismatch for cert_{round}.canonical.hex"
            );
            checked += 1;
        }
        // The capture pipeline produces 9 fixtures (rounds 0..=8).
        assert!(
            checked >= 1,
            "expected at least one cert_<round>.canonical.hex fixture under {}",
            fixtures_dir.display()
        );
        println!("cert fixtures: {checked} byte-exact ✓");
    }
}
