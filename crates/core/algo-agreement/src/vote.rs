// Vote types matching go-algorand/agreement/vote.go.
//
// rawVote is the inner struct authenticated with ephemeral keys.
// unauthenticatedVote wraps rawVote with a VRF credential and OTS signature.
// Vote is the verified form with a proven Credential and weight.

use algo_consensus_crypto::{one_time_id_for_round, verify_one_time_signature, OneTimeSignature};
use algo_types::{Address, ConsensusParams, Digest, Round};

use crate::credential::{Credential, Membership, UnauthenticatedCredential};
#[cfg(test)]
use crate::hashable::hash_obj;
use crate::hashable::Hashable;
use crate::step::{Period, Step, CERT, PROPOSE, SOFT};

// ── ProposalValue ──────────────────────────────────────────────────────────

/// A triplet identifying a proposed block: its digest, encoding digest,
/// the period it was originally proposed in, and the original proposer.
///
/// Mirrors Go's `agreement.proposalValue`.
///
/// The zero value is called `bottom` in Go and represents the absence of
/// a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProposalValue {
    /// The period in which this proposal was originally made.
    /// Go: `OriginalPeriod period`, codec:"oper"
    pub original_period: Period,
    /// The address of the original proposer.
    /// Go: `OriginalProposer basics.Address`, codec:"oprop"
    pub original_proposer: Address,
    /// The block digest (block.Digest()).
    /// Go: `BlockDigest crypto.Digest`, codec:"dig"
    pub block_digest: Digest,
    /// The encoding digest (crypto.HashObj(proposal)).
    /// Go: `EncodingDigest crypto.Digest`, codec:"encdig"
    pub encoding_digest: Digest,
}

impl Default for ProposalValue {
    fn default() -> Self {
        BOTTOM
    }
}

/// The "bottom" proposal value — the zero/default value.
/// Votes for bottom are only allowed in the `down` step.
pub const BOTTOM: ProposalValue = ProposalValue {
    original_period: Period(0),
    original_proposer: Address([0u8; 32]),
    block_digest: Digest([0u8; 32]),
    encoding_digest: Digest([0u8; 32]),
};

/// Returns `true` if this is the bottom (zero) proposal value.
impl ProposalValue {
    pub fn is_bottom(&self) -> bool {
        *self == BOTTOM
    }
}

/// Canonical msgpack encoding of a `ProposalValue`, matching Go's
/// generated `proposalValue.MarshalMsg` in `agreement/msgp_gen.go`.
///
/// Omitempty, fields sorted alphabetically by codec tag:
///   "dig"    -> BlockDigest (bin32)
///   "encdig" -> EncodingDigest (bin32)
///   "oper"   -> OriginalPeriod (uint64)
///   "oprop"  -> OriginalProposer (bin32)
fn encode_proposal_value(pv: &ProposalValue) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // Count non-empty fields
    let mut count: u8 = 0;
    let dig_empty = pv.block_digest.0 == [0u8; 32];
    let encdig_empty = pv.encoding_digest.0 == [0u8; 32];
    let oper_empty = pv.original_period.0 == 0;
    let oprop_empty = pv.original_proposer.0 == [0u8; 32];

    if !dig_empty {
        count += 1;
    }
    if !encdig_empty {
        count += 1;
    }
    if !oper_empty {
        count += 1;
    }
    if !oprop_empty {
        count += 1;
    }

    // fixmap header
    buf.push(0x80 | count);

    if count == 0 {
        return buf;
    }

    // "dig" -> BlockDigest
    if !dig_empty {
        buf.extend_from_slice(&[0xa3, b'd', b'i', b'g']);
        rmp::encode::write_bin(&mut buf, &pv.block_digest.0).unwrap();
    }

    // "encdig" -> EncodingDigest
    if !encdig_empty {
        buf.extend_from_slice(&[0xa6, b'e', b'n', b'c', b'd', b'i', b'g']);
        rmp::encode::write_bin(&mut buf, &pv.encoding_digest.0).unwrap();
    }

    // "oper" -> OriginalPeriod
    if !oper_empty {
        buf.extend_from_slice(&[0xa4, b'o', b'p', b'e', b'r']);
        rmp::encode::write_uint(&mut buf, pv.original_period.0).unwrap();
    }

    // "oprop" -> OriginalProposer
    if !oprop_empty {
        buf.extend_from_slice(&[0xa5, b'o', b'p', b'r', b'o', b'p']);
        rmp::encode::write_bin(&mut buf, &pv.original_proposer.0).unwrap();
    }

    buf
}

// ── RawVote ────────────────────────────────────────────────────────────────

/// The inner vote struct that gets signed with ephemeral keys.
///
/// Mirrors Go's `agreement.rawVote`.
///
/// Msgpack field order (alphabetical by codec tag, omitempty):
///   "per"  -> Period (uint64)
///   "prop" -> Proposal (proposalValue, sub-map)
///   "rnd"  -> Round (uint64)
///   "snd"  -> Sender (bin32)
///   "step" -> Step (uint64)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawVote {
    /// The voter's address.
    pub sender: Address,
    /// The round being voted on.
    pub round: Round,
    /// The period of the vote.
    pub period: Period,
    /// The step of the vote.
    pub step: Step,
    /// The proposal being voted for.
    pub proposal: ProposalValue,
}

/// Canonical msgpack encoding of a `RawVote`, matching Go's
/// generated `rawVote.MarshalMsg` in `agreement/msgp_gen.go`.
fn encode_raw_vote(rv: &RawVote) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // Count non-empty fields
    let mut count: u8 = 0;
    let per_empty = rv.period.0 == 0;
    let prop_empty = rv.proposal.is_bottom();
    let rnd_empty = rv.round.0 == 0;
    let snd_empty = rv.sender.0 == [0u8; 32];
    let step_empty = rv.step.0 == 0;

    if !per_empty {
        count += 1;
    }
    if !prop_empty {
        count += 1;
    }
    if !rnd_empty {
        count += 1;
    }
    if !snd_empty {
        count += 1;
    }
    if !step_empty {
        count += 1;
    }

    // fixmap header
    buf.push(0x80 | count);

    if count == 0 {
        return buf;
    }

    // "per" -> Period
    if !per_empty {
        buf.extend_from_slice(&[0xa3, b'p', b'e', b'r']);
        rmp::encode::write_uint(&mut buf, rv.period.0).unwrap();
    }

    // "prop" -> Proposal (inline sub-encoding)
    if !prop_empty {
        buf.extend_from_slice(&[0xa4, b'p', b'r', b'o', b'p']);
        buf.extend_from_slice(&encode_proposal_value(&rv.proposal));
    }

    // "rnd" -> Round
    if !rnd_empty {
        buf.extend_from_slice(&[0xa3, b'r', b'n', b'd']);
        rmp::encode::write_uint(&mut buf, rv.round.0).unwrap();
    }

    // "snd" -> Sender
    if !snd_empty {
        buf.extend_from_slice(&[0xa3, b's', b'n', b'd']);
        rmp::encode::write_bin(&mut buf, &rv.sender.0).unwrap();
    }

    // "step" -> Step
    if !step_empty {
        buf.extend_from_slice(&[0xa4, b's', b't', b'e', b'p']);
        rmp::encode::write_uint(&mut buf, rv.step.0).unwrap();
    }

    buf
}

impl Hashable for RawVote {
    /// HashID = `"VO"` (protocol.Vote).
    fn hash_id() -> &'static [u8] {
        b"VO"
    }

    fn to_be_hashed(&self) -> Vec<u8> {
        encode_raw_vote(self)
    }
}

// ── UnauthenticatedVote ────────────────────────────────────────────────────

/// An unauthenticated vote received from the network.
///
/// Contains a raw vote, a VRF credential proof, and a one-time signature.
///
/// Mirrors Go's `agreement.unauthenticatedVote`.
#[derive(Debug, Clone)]
pub struct UnauthenticatedVote {
    /// The raw vote content.
    pub raw_vote: RawVote,
    /// The VRF credential (not yet verified).
    pub cred: UnauthenticatedCredential,
    /// The one-time signature over hash_obj(raw_vote).
    pub sig: OneTimeSignature,
}

impl Default for UnauthenticatedVote {
    fn default() -> Self {
        Self {
            raw_vote: RawVote {
                sender: Address([0u8; 32]),
                round: Round(0),
                period: Period(0),
                step: Step(0),
                proposal: BOTTOM,
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: OneTimeSignature {
                sig: [0u8; 64],
                pk: [0u8; 32],
                pk_sig_old: [0u8; 64],
                pk2: [0u8; 32],
                pk1_sig: [0u8; 64],
                pk2_sig: [0u8; 64],
            },
        }
    }
}

// ── Vote (verified) ────────────────────────────────────────────────────────

/// A verified vote with a proven credential and weight.
///
/// Mirrors Go's `agreement.vote`.
#[derive(Debug, Clone)]
pub struct Vote {
    /// The raw vote content.
    pub raw_vote: RawVote,
    /// The verified credential with sortition weight.
    pub cred: Credential,
    /// The one-time signature.
    pub sig: OneTimeSignature,
}

impl Default for Vote {
    fn default() -> Self {
        Self {
            raw_vote: RawVote {
                sender: Address([0u8; 32]),
                round: Round(0),
                period: Period(0),
                step: Step(0),
                proposal: BOTTOM,
            },
            cred: Credential {
                weight: 0,
                vrf_out: Digest([0u8; 32]),
                domain_separation_enabled: false,
                hashable: crate::credential::HashableCredential::default(),
                proof: [0u8; 80],
            },
            sig: OneTimeSignature {
                sig: [0u8; 64],
                pk: [0u8; 32],
                pk_sig_old: [0u8; 64],
                pk2: [0u8; 32],
                pk1_sig: [0u8; 64],
                pk2_sig: [0u8; 64],
            },
        }
    }
}

impl Vote {
    /// Convert back to an unauthenticated vote.
    pub fn to_unauthenticated(&self) -> UnauthenticatedVote {
        UnauthenticatedVote {
            raw_vote: self.raw_vote.clone(),
            cred: UnauthenticatedCredential::new(self.cred.proof),
            sig: self.sig.clone(),
        }
    }
}

// ── Vote verification ──────────────────────────────────────────────────────

/// Errors that can occur during vote verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteError {
    /// The proposal is bottom but the step does not allow it.
    BottomNotAllowed { step: Step },
    /// In the propose step, the sender doesn't match the original proposer.
    ProposerMismatch,
    /// The original period is in the future relative to the vote's period.
    FuturePeriod {
        vote_period: Period,
        original_period: Period,
    },
    /// The round is before VoteFirstValid.
    RoundBeforeFirstValid { round: Round, first_valid: Round },
    /// The round is after VoteLastValid.
    RoundAfterLastValid { round: Round, last_valid: Round },
    /// OTS signature verification failed.
    OtsVerificationFailed,
    /// VRF credential verification failed.
    CredentialVerificationFailed(String),
}

impl std::fmt::Display for VoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BottomNotAllowed { step } => {
                write!(f, "votes from step {step} cannot validate bottom")
            }
            Self::ProposerMismatch => {
                write!(f, "proposal-vote sender mismatches with proposal-value")
            }
            Self::FuturePeriod {
                vote_period,
                original_period,
            } => {
                write!(
                    f,
                    "proposal-vote in period {vote_period} claims to repropose block from future period {original_period}"
                )
            }
            Self::RoundBeforeFirstValid { round, first_valid } => {
                write!(
                    f,
                    "vote in round {round} before VoteFirstValid {first_valid}"
                )
            }
            Self::RoundAfterLastValid { round, last_valid } => {
                write!(f, "vote in round {round} after VoteLastValid {last_valid}")
            }
            Self::OtsVerificationFailed => write!(f, "OTS signature verification failed"),
            Self::CredentialVerificationFailed(msg) => {
                write!(f, "credential verification failed: {msg}")
            }
        }
    }
}

impl std::error::Error for VoteError {}

/// Parameters needed for vote verification, encapsulating ledger lookups
/// that the caller must provide.
#[derive(Debug, Clone)]
pub struct VoteVerifyParams {
    /// The membership for credential verification (address, selection key, stake, etc.).
    pub membership: Membership,
    /// The OTS master public key (OneTimeSignatureVerifier / VoteID).
    pub vote_id: [u8; 32],
    /// VoteFirstValid for the account.
    pub vote_first_valid: Round,
    /// VoteLastValid for the account (0 means no upper bound).
    pub vote_last_valid: Round,
    /// The account's key dilution (0 means use default).
    pub vote_key_dilution: u64,
    /// Consensus parameters for the round.
    pub consensus_params: ConsensusParams,
}

impl UnauthenticatedVote {
    /// Verify this vote against the provided parameters.
    ///
    /// Performs the same checks as Go's `unauthenticatedVote.verify`:
    /// 1. Validate proposal constraints (bottom not allowed for propose/soft/cert)
    /// 2. Check round validity window (VoteFirstValid..VoteLastValid)
    /// 3. Verify the one-time signature on hash_obj(raw_vote)
    /// 4. Verify the VRF credential
    ///
    /// On success, returns a `Vote` with the verified credential.
    pub fn verify(&self, params: &VoteVerifyParams) -> Result<Vote, VoteError> {
        let rv = &self.raw_vote;

        // Step-specific proposal validation (matches Go's switch in verify)
        match rv.step {
            PROPOSE => {
                // In propose step with matching period, sender must match original proposer.
                if rv.period == rv.proposal.original_period
                    && rv.sender != rv.proposal.original_proposer
                {
                    return Err(VoteError::ProposerMismatch);
                }
                // Original period cannot be in the future.
                if rv.proposal.original_period.0 > rv.period.0 {
                    return Err(VoteError::FuturePeriod {
                        vote_period: rv.period,
                        original_period: rv.proposal.original_period,
                    });
                }
                // Fallthrough: also check bottom
                if rv.proposal.is_bottom() {
                    return Err(VoteError::BottomNotAllowed { step: rv.step });
                }
            }
            SOFT | CERT => {
                if rv.proposal.is_bottom() {
                    return Err(VoteError::BottomNotAllowed { step: rv.step });
                }
            }
            _ => {}
        }

        // Check round validity window
        if rv.round < params.vote_first_valid {
            return Err(VoteError::RoundBeforeFirstValid {
                round: rv.round,
                first_valid: params.vote_first_valid,
            });
        }

        if params.vote_last_valid.0 != 0 && rv.round > params.vote_last_valid {
            return Err(VoteError::RoundAfterLastValid {
                round: rv.round,
                last_valid: params.vote_last_valid,
            });
        }

        // Compute ephemeral key ID for this round
        let effective_kd = if params.vote_key_dilution > 0 {
            params.vote_key_dilution
        } else {
            params.consensus_params.default_key_dilution
        };
        let eph_id = one_time_id_for_round(rv.round.0, effective_kd);

        // Verify OTS signature on hash_obj(raw_vote)
        // OTS signs the domain-separated message: hash_id || canonical_encode(raw_vote)
        let msg = [RawVote::hash_id(), rv.to_be_hashed().as_slice()].concat();
        if !verify_one_time_signature(
            &self.sig,
            &params.vote_id,
            eph_id.batch,
            eph_id.offset,
            &msg,
        ) {
            return Err(VoteError::OtsVerificationFailed);
        }

        // Verify credential
        let cred = self
            .cred
            .verify(&params.consensus_params, &params.membership)
            .map_err(|e| VoteError::CredentialVerificationFailed(e.to_string()))?;

        Ok(Vote {
            raw_vote: rv.clone(),
            cred,
            sig: self.sig.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::Seed;
    use crate::selector::Selector;
    use crate::step::{DOWN, NEXT};

    // ── ProposalValue tests ────────────────────────────────────────────

    #[test]
    fn proposal_value_bottom_is_zero() {
        assert!(BOTTOM.is_bottom());
    }

    #[test]
    fn proposal_value_non_bottom() {
        let pv = ProposalValue {
            original_period: Period(0),
            original_proposer: Address([0u8; 32]),
            block_digest: Digest([0x01; 32]),
            encoding_digest: Digest([0u8; 32]),
        };
        assert!(!pv.is_bottom());
    }

    #[test]
    fn proposal_value_encoding_empty_map() {
        let pv = BOTTOM;
        let encoded = encode_proposal_value(&pv);
        assert_eq!(encoded, vec![0x80]); // fixmap(0)
    }

    #[test]
    fn proposal_value_encoding_field_order() {
        let pv = ProposalValue {
            original_period: Period(1),
            original_proposer: Address([0xaa; 32]),
            block_digest: Digest([0xbb; 32]),
            encoding_digest: Digest([0xcc; 32]),
        };
        let encoded = encode_proposal_value(&pv);

        // fixmap(4)
        assert_eq!(encoded[0], 0x84);

        // Find field positions
        let encoded_str = String::from_utf8_lossy(&encoded);
        let dig_pos = encoded_str.find("dig").unwrap();
        let encdig_pos = encoded_str.find("encdig").unwrap();
        let oper_pos = encoded_str.find("oper").unwrap();
        let oprop_pos = encoded_str.find("oprop").unwrap();

        assert!(dig_pos < encdig_pos, "dig must come before encdig");
        assert!(encdig_pos < oper_pos, "encdig must come before oper");
        assert!(oper_pos < oprop_pos, "oper must come before oprop");
    }

    // ── RawVote tests ──────────────────────────────────────────────────

    #[test]
    fn raw_vote_hash_id_is_vo() {
        assert_eq!(RawVote::hash_id(), b"VO");
    }

    #[test]
    fn raw_vote_encoding_empty() {
        let rv = RawVote {
            sender: Address([0u8; 32]),
            round: Round(0),
            period: Period(0),
            step: Step(0),
            proposal: BOTTOM,
        };
        let encoded = encode_raw_vote(&rv);
        assert_eq!(encoded, vec![0x80]); // fixmap(0) — all fields are zero/empty
    }

    #[test]
    fn raw_vote_encoding_field_order() {
        let rv = RawVote {
            sender: Address([0xaa; 32]),
            round: Round(42),
            period: Period(1),
            step: Step(2),
            proposal: ProposalValue {
                original_period: Period(1),
                original_proposer: Address([0xbb; 32]),
                block_digest: Digest([0xcc; 32]),
                encoding_digest: Digest([0xdd; 32]),
            },
        };
        let encoded = encode_raw_vote(&rv);

        // fixmap(5)
        assert_eq!(encoded[0], 0x85);

        // Verify field order: per, prop, rnd, snd, step
        let encoded_str = String::from_utf8_lossy(&encoded);
        let per_pos = encoded_str.find("per").unwrap();
        let prop_pos = encoded_str.find("prop").unwrap();
        let rnd_pos = encoded_str.find("rnd").unwrap();
        let snd_pos = encoded_str.find("snd").unwrap();
        let step_pos = encoded_str.find("step").unwrap();

        assert!(per_pos < prop_pos, "per must come before prop");
        assert!(prop_pos < rnd_pos, "prop must come before rnd");
        assert!(rnd_pos < snd_pos, "rnd must come before snd");
        assert!(snd_pos < step_pos, "snd must come before step");
    }

    #[test]
    fn raw_vote_hash_obj_deterministic() {
        let rv = RawVote {
            sender: Address([0x42; 32]),
            round: Round(100),
            period: Period(0),
            step: Step(1),
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: Address([0x42; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
        };
        let d1 = hash_obj(&rv);
        let d2 = hash_obj(&rv);
        assert_eq!(d1, d2);
    }

    #[test]
    fn raw_vote_different_round_different_hash() {
        let rv1 = RawVote {
            sender: Address([0x42; 32]),
            round: Round(100),
            period: Period(0),
            step: Step(1),
            proposal: BOTTOM,
        };
        let rv2 = RawVote {
            sender: Address([0x42; 32]),
            round: Round(101),
            period: Period(0),
            step: Step(1),
            proposal: BOTTOM,
        };
        assert_ne!(hash_obj(&rv1), hash_obj(&rv2));
    }

    // ── one_time_id_for_round tests ─────────────────────────────────────

    #[test]
    fn one_time_id_basic() {
        let id = one_time_id_for_round(1000, 100);
        assert_eq!(id.batch, 10);
        assert_eq!(id.offset, 0);
    }

    #[test]
    fn one_time_id_with_offset() {
        let id = one_time_id_for_round(1042, 100);
        assert_eq!(id.batch, 10);
        assert_eq!(id.offset, 42);
    }

    #[test]
    fn one_time_id_round_zero() {
        let id = one_time_id_for_round(0, 100);
        assert_eq!(id.batch, 0);
        assert_eq!(id.offset, 0);
    }

    #[test]
    fn one_time_id_dilution_one() {
        let id = one_time_id_for_round(42, 1);
        assert_eq!(id.batch, 42);
        assert_eq!(id.offset, 0);
    }

    #[test]
    #[should_panic(expected = "key_dilution must be > 0")]
    fn one_time_id_zero_dilution_panics() {
        one_time_id_for_round(100, 0);
    }

    // ── Vote verification tests ────────────────────────────────────────

    #[test]
    fn vote_verify_bottom_not_allowed_propose() {
        // Use sender = zero address to match BOTTOM's original_proposer,
        // so the proposer-mismatch check passes and we reach the bottom check.
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x00; 32]),
                round: Round(100),
                period: Period(0),
                step: PROPOSE,
                proposal: BOTTOM,
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        };

        let params = make_verify_params(Round(100));
        let err = uv.verify(&params).unwrap_err();
        assert_eq!(err, VoteError::BottomNotAllowed { step: PROPOSE });
    }

    #[test]
    fn vote_verify_bottom_not_allowed_soft() {
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(100),
                period: Period(0),
                step: SOFT,
                proposal: BOTTOM,
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        };

        let params = make_verify_params(Round(100));
        let err = uv.verify(&params).unwrap_err();
        assert_eq!(err, VoteError::BottomNotAllowed { step: SOFT });
    }

    #[test]
    fn vote_verify_bottom_not_allowed_cert() {
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(100),
                period: Period(0),
                step: CERT,
                proposal: BOTTOM,
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        };

        let params = make_verify_params(Round(100));
        let err = uv.verify(&params).unwrap_err();
        assert_eq!(err, VoteError::BottomNotAllowed { step: CERT });
    }

    #[test]
    fn vote_verify_bottom_allowed_down() {
        // Down step allows bottom — it should pass the bottom check
        // (but will fail later on OTS verification since we use zero keys)
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(100),
                period: Period(0),
                step: DOWN,
                proposal: BOTTOM,
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        };

        let params = make_verify_params(Round(100));
        let err = uv.verify(&params).unwrap_err();
        // Should NOT be BottomNotAllowed — it should fail on OTS or credential
        assert!(
            !matches!(err, VoteError::BottomNotAllowed { .. }),
            "down step should allow bottom, got: {err}"
        );
    }

    #[test]
    fn vote_verify_bottom_allowed_next() {
        // Next step allows bottom
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(100),
                period: Period(0),
                step: NEXT,
                proposal: BOTTOM,
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        };

        let params = make_verify_params(Round(100));
        let err = uv.verify(&params).unwrap_err();
        assert!(
            !matches!(err, VoteError::BottomNotAllowed { .. }),
            "next step should allow bottom, got: {err}"
        );
    }

    #[test]
    fn vote_verify_proposer_mismatch() {
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(100),
                period: Period(0),
                step: PROPOSE,
                proposal: ProposalValue {
                    original_period: Period(0),             // same as vote period
                    original_proposer: Address([0x02; 32]), // different from sender
                    block_digest: Digest([0xaa; 32]),
                    encoding_digest: Digest([0xbb; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        };

        let params = make_verify_params(Round(100));
        let err = uv.verify(&params).unwrap_err();
        assert_eq!(err, VoteError::ProposerMismatch);
    }

    #[test]
    fn vote_verify_future_period() {
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(100),
                period: Period(1),
                step: PROPOSE,
                proposal: ProposalValue {
                    original_period: Period(5), // future relative to vote's period=1
                    original_proposer: Address([0x01; 32]),
                    block_digest: Digest([0xaa; 32]),
                    encoding_digest: Digest([0xbb; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        };

        let params = make_verify_params(Round(100));
        let err = uv.verify(&params).unwrap_err();
        assert_eq!(
            err,
            VoteError::FuturePeriod {
                vote_period: Period(1),
                original_period: Period(5),
            }
        );
    }

    #[test]
    fn vote_verify_round_before_first_valid() {
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(50),
                period: Period(0),
                step: NEXT,
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: Address([0x01; 32]),
                    block_digest: Digest([0xaa; 32]),
                    encoding_digest: Digest([0xbb; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        };

        let mut params = make_verify_params(Round(50));
        params.vote_first_valid = Round(100); // round 50 < first_valid 100
        let err = uv.verify(&params).unwrap_err();
        assert_eq!(
            err,
            VoteError::RoundBeforeFirstValid {
                round: Round(50),
                first_valid: Round(100),
            }
        );
    }

    #[test]
    fn vote_verify_round_after_last_valid() {
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(200),
                period: Period(0),
                step: NEXT,
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: Address([0x01; 32]),
                    block_digest: Digest([0xaa; 32]),
                    encoding_digest: Digest([0xbb; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        };

        let mut params = make_verify_params(Round(200));
        params.vote_last_valid = Round(150); // round 200 > last_valid 150
        let err = uv.verify(&params).unwrap_err();
        assert_eq!(
            err,
            VoteError::RoundAfterLastValid {
                round: Round(200),
                last_valid: Round(150),
            }
        );
    }

    #[test]
    fn vote_verify_last_valid_zero_means_no_limit() {
        // When vote_last_valid is 0, there's no upper bound check
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: Address([0x01; 32]),
                round: Round(999_999),
                period: Period(0),
                step: NEXT,
                proposal: ProposalValue {
                    original_period: Period(0),
                    original_proposer: Address([0x01; 32]),
                    block_digest: Digest([0xaa; 32]),
                    encoding_digest: Digest([0xbb; 32]),
                },
            },
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: make_zero_sig(),
        };

        let mut params = make_verify_params(Round(999_999));
        params.vote_last_valid = Round(0); // 0 = no limit
                                           // Should pass the round check but fail on OTS
        let err = uv.verify(&params).unwrap_err();
        assert!(
            matches!(err, VoteError::OtsVerificationFailed),
            "expected OTS failure (not round check), got: {err}"
        );
    }

    #[test]
    fn vote_verify_with_real_ots() {
        // End-to-end test: generate OTS keys, sign a vote, verify it.
        use algo_consensus_crypto::vrf::VrfKeypair;
        use algo_consensus_crypto::{one_time_id_for_round, OneTimeSignatureSecrets};

        let round = 1000u64;
        let key_dilution = 100u64;

        // Generate OTS secrets covering the right batch range
        let id = one_time_id_for_round(round, key_dilution);
        let secrets = OneTimeSignatureSecrets::generate(id.batch, 1);
        let verifier = secrets.verifier();

        // Create the raw vote
        let sender = Address([0x42; 32]);
        let rv = RawVote {
            sender,
            round: Round(round),
            period: Period(0),
            step: NEXT,
            proposal: ProposalValue {
                original_period: Period(0),
                original_proposer: sender,
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
        };

        // Sign the raw vote with OTS
        let msg = [RawVote::hash_id(), rv.to_be_hashed().as_slice()].concat();
        let ots_sig = secrets.sign(&msg, round, key_dilution);

        // Create the unauthenticated vote
        // We need a valid VRF credential too, but for this test we'll check
        // that OTS passes and credential fails (since we use a dummy cred).
        let uv = UnauthenticatedVote {
            raw_vote: rv,
            cred: UnauthenticatedCredential::new([0u8; 80]),
            sig: ots_sig,
        };

        let vrf_kp = VrfKeypair::from_seed([7u8; 32]);
        let params = VoteVerifyParams {
            membership: Membership {
                address: sender,
                selection_id: *vrf_kp.pk.as_bytes(),
                balance: 5_000_000,
                total_money: 10_000_000,
                selector: Selector {
                    seed: Seed([0xab; 32]),
                    round: Round(round),
                    period: Period(0),
                    step: NEXT,
                },
            },
            vote_id: verifier,
            vote_first_valid: Round(0),
            vote_last_valid: Round(0), // no limit
            vote_key_dilution: key_dilution,
            consensus_params: algo_types::consensus::consensus_params_for_version(
                algo_types::CONSENSUS_V41,
            )
            .expect("v41 params"),
        };

        // The OTS should pass but credential will fail since we used a dummy proof
        let err = uv.verify(&params).unwrap_err();
        assert!(
            matches!(err, VoteError::CredentialVerificationFailed(_)),
            "expected credential failure (OTS should pass), got: {err}"
        );
    }

    // ── Test helpers ───────────────────────────────────────────────────

    fn make_zero_sig() -> OneTimeSignature {
        OneTimeSignature {
            sig: [0u8; 64],
            pk: [0u8; 32],
            pk_sig_old: [0u8; 64],
            pk2: [0u8; 32],
            pk1_sig: [0u8; 64],
            pk2_sig: [0u8; 64],
        }
    }

    fn make_verify_params(round: Round) -> VoteVerifyParams {
        use algo_consensus_crypto::vrf::VrfKeypair;

        let vrf_kp = VrfKeypair::from_seed([7u8; 32]);
        VoteVerifyParams {
            membership: Membership {
                address: Address([0x01; 32]),
                selection_id: *vrf_kp.pk.as_bytes(),
                balance: 5_000_000,
                total_money: 10_000_000,
                selector: Selector {
                    seed: Seed([0xab; 32]),
                    round,
                    period: Period(0),
                    step: NEXT,
                },
            },
            vote_id: [0u8; 32],
            vote_first_valid: Round(0),
            vote_last_valid: Round(0),
            vote_key_dilution: 100,
            consensus_params: algo_types::consensus::consensus_params_for_version(
                algo_types::CONSENSUS_V41,
            )
            .expect("v41 params"),
        }
    }
}
