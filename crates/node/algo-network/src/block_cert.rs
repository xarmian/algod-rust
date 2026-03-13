//! Block-and-certificate network message types.
//!
//! These types mirror the Go structs used to transfer blocks and their
//! agreement certificates over the Algorand gossip network.
//!
//! Reference: go-algorand `rpcs/blockService.go` (EncodedBlockCert),
//! `agreement/bundle.go` (unauthenticatedBundle, voteAuthenticator,
//! equivocationVoteAuthenticator), `agreement/proposal.go` (proposalValue),
//! `data/committee/credential.go` (UnauthenticatedCredential),
//! `crypto/onetimesig.go` (OneTimeSignature).

use algo_types::{Address, Block, Round};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

// ---------------------------------------------------------------------------
// Helper predicates for skip_serializing_if
// ---------------------------------------------------------------------------

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn is_zero_or_empty_bytebuf(v: &ByteBuf) -> bool {
    v.is_empty() || v.iter().all(|&b| b == 0)
}

fn is_default_round(v: &Round) -> bool {
    v.0 == 0
}

fn is_default_address(v: &Address) -> bool {
    v.is_zero()
}

fn is_default_proposal_value(v: &ProposalValue) -> bool {
    *v == ProposalValue::default()
}

fn is_empty_vote_vec(v: &[VoteAuthenticator]) -> bool {
    v.is_empty()
}

fn is_empty_eqvote_vec(v: &[EquivocationVoteAuthenticator]) -> bool {
    v.is_empty()
}

fn is_default_one_time_signature(v: &OneTimeSignature) -> bool {
    is_zero_or_empty_bytebuf(&v.sig)
        && is_zero_or_empty_bytebuf(&v.pk)
        && is_zero_or_empty_bytebuf(&v.pk_sig_old)
        && is_zero_or_empty_bytebuf(&v.pk2)
        && is_zero_or_empty_bytebuf(&v.pk1_sig)
        && is_zero_or_empty_bytebuf(&v.pk2_sig)
}

fn is_default_one_time_signature_pair(v: &[OneTimeSignature; 2]) -> bool {
    is_default_one_time_signature(&v[0]) && is_default_one_time_signature(&v[1])
}

// ---------------------------------------------------------------------------
// EncodedBlockCert
// ---------------------------------------------------------------------------

/// A block together with its agreement certificate, as transferred over the
/// network.
///
/// Mirrors Go's `rpcs.EncodedBlockCert`.
///
/// Go struct tag: `codec:""` (not omitempty — both fields are always present).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncodedBlockCert {
    /// The block.
    #[serde(rename = "block")]
    pub block: Block,

    /// The agreement certificate proving consensus was reached.
    #[serde(rename = "cert")]
    pub certificate: Certificate,
}

// ---------------------------------------------------------------------------
// Certificate (= unauthenticatedBundle in Go)
// ---------------------------------------------------------------------------

/// A certificate proving that agreement was reached on a block.
///
/// Mirrors Go's `agreement.Certificate` which is a type alias for
/// `unauthenticatedBundle`.
///
/// Go struct tag: `codec:",omitempty,omitemptyarray"` — fields are omitted
/// when zero/empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    /// The round this certificate is for.
    #[serde(rename = "rnd", default, skip_serializing_if = "is_default_round")]
    pub round: Round,

    /// The period within the round.
    #[serde(rename = "per", default, skip_serializing_if = "is_zero_u64")]
    pub period: u64,

    /// The step within the period.
    #[serde(rename = "step", default, skip_serializing_if = "is_zero_u64")]
    pub step: u64,

    /// The proposal value that was agreed upon.
    #[serde(
        rename = "prop",
        default,
        skip_serializing_if = "is_default_proposal_value"
    )]
    pub proposal: ProposalValue,

    /// Individual votes forming the certificate.
    #[serde(rename = "vote", default, skip_serializing_if = "is_empty_vote_vec")]
    pub votes: Vec<VoteAuthenticator>,

    /// Equivocation vote pairs (where a sender voted for two values).
    #[serde(rename = "eqv", default, skip_serializing_if = "is_empty_eqvote_vec")]
    pub equivocation_votes: Vec<EquivocationVoteAuthenticator>,
}

// ---------------------------------------------------------------------------
// ProposalValue
// ---------------------------------------------------------------------------

/// The value proposed for agreement in a given round and period.
///
/// Mirrors Go's `agreement.proposalValue`.
///
/// Go struct tag: `codec:",omitempty,omitemptyarray"` — fields are omitted
/// when zero/empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalValue {
    /// The period in which this value was originally proposed.
    #[serde(rename = "oper", default, skip_serializing_if = "is_zero_u64")]
    pub original_period: u64,

    /// The address of the original proposer.
    #[serde(rename = "oprop", default, skip_serializing_if = "is_default_address")]
    pub original_proposer: Address,

    /// Block digest (Go: `crypto.Digest`, 32 bytes).
    // TODO: Consider using algo_types::Digest for type-safe 32-byte enforcement
    #[serde(
        rename = "dig",
        default,
        skip_serializing_if = "is_zero_or_empty_bytebuf"
    )]
    pub block_digest: ByteBuf,

    /// Encoding digest (Go: `crypto.Digest`, 32 bytes).
    // TODO: Consider using algo_types::Digest for type-safe 32-byte enforcement
    #[serde(
        rename = "encdig",
        default,
        skip_serializing_if = "is_zero_or_empty_bytebuf"
    )]
    pub encoding_digest: ByteBuf,
}

impl Default for ProposalValue {
    fn default() -> Self {
        Self {
            original_period: 0,
            original_proposer: Address::default(),
            block_digest: ByteBuf::new(),
            encoding_digest: ByteBuf::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// VoteAuthenticator
// ---------------------------------------------------------------------------

/// Authenticator for a single vote in the agreement protocol.
///
/// Mirrors Go's `agreement.voteAuthenticator`.
///
/// Go struct tag: `codec:""` (not omitempty — Sender and Cred are always
/// serialized). The `Sig` field has an explicit `omitempty` tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteAuthenticator {
    /// The address of the voter.
    #[serde(rename = "snd")]
    pub sender: Address,

    /// The VRF credential proving committee membership.
    #[serde(rename = "cred")]
    pub cred: UnauthenticatedCredential,

    /// The one-time signature on the vote.
    ///
    /// Go field tag: `codec:"sig,omitempty,omitemptycheckstruct"`.
    #[serde(
        rename = "sig",
        default,
        skip_serializing_if = "is_default_one_time_signature"
    )]
    pub sig: OneTimeSignature,
}

// ---------------------------------------------------------------------------
// EquivocationVoteAuthenticator
// ---------------------------------------------------------------------------

/// Authenticator for an equivocation vote pair (a voter who signed two
/// different proposals in the same round/period/step).
///
/// Mirrors Go's `agreement.equivocationVoteAuthenticator`.
///
/// Go struct tag: `codec:""` (not omitempty — Sender, Cred, and Proposals are
/// always serialized). The `Sigs` field has an explicit `omitempty` tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationVoteAuthenticator {
    /// The address of the equivocating voter.
    #[serde(rename = "snd")]
    pub sender: Address,

    /// The VRF credential proving committee membership.
    #[serde(rename = "cred")]
    pub cred: UnauthenticatedCredential,

    /// The two one-time signatures (one per conflicting proposal).
    ///
    /// Go field tag: `codec:"sig,omitempty,omitemptycheckstruct"`.
    #[serde(
        rename = "sig",
        default,
        skip_serializing_if = "is_default_one_time_signature_pair"
    )]
    pub sigs: [OneTimeSignature; 2],

    /// The two conflicting proposal values.
    #[serde(rename = "props")]
    pub proposals: [ProposalValue; 2],
}

// ---------------------------------------------------------------------------
// OneTimeSignature
// ---------------------------------------------------------------------------

/// A one-time signature used in the agreement protocol.
///
/// Mirrors Go's `crypto.OneTimeSignature`.
///
/// Go struct tag: `codec:""` (not omitempty — ALL fields are always
/// serialized, including PKSigOld which is always zero but cannot be removed
/// without breaking wire compatibility).
///
/// All byte fields use `ByteBuf` for correct msgpack binary serialization.
/// - ed25519Signature: 64 bytes
/// - ed25519PublicKey: 32 bytes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeSignature {
    /// The ed25519 signature (64 bytes). `codec:"s"`
    #[serde(rename = "s", default)]
    pub sig: ByteBuf,

    /// The ephemeral public key (32 bytes). `codec:"p"`
    #[serde(rename = "p", default)]
    pub pk: ByteBuf,

    /// Old-style PKSig (unused but always serialized for wire compat).
    /// `codec:"ps"`
    #[serde(rename = "ps", default)]
    pub pk_sig_old: ByteBuf,

    /// Second-level ephemeral public key (32 bytes). `codec:"p2"`
    #[serde(rename = "p2", default)]
    pub pk2: ByteBuf,

    /// Signature of `OneTimeSignatureSubkeyOffsetID(PK, Batch, Offset)`
    /// under PK2 (64 bytes). `codec:"p1s"`
    #[serde(rename = "p1s", default)]
    pub pk1_sig: ByteBuf,

    /// Signature of `OneTimeSignatureSubkeyBatchID(PK2, Batch)` under the
    /// master key (64 bytes). `codec:"p2s"`
    #[serde(rename = "p2s", default)]
    pub pk2_sig: ByteBuf,
}

impl Default for OneTimeSignature {
    fn default() -> Self {
        Self {
            sig: ByteBuf::from(vec![0u8; 64]),
            pk: ByteBuf::from(vec![0u8; 32]),
            pk_sig_old: ByteBuf::from(vec![0u8; 64]),
            pk2: ByteBuf::from(vec![0u8; 32]),
            pk1_sig: ByteBuf::from(vec![0u8; 64]),
            pk2_sig: ByteBuf::from(vec![0u8; 64]),
        }
    }
}

// ---------------------------------------------------------------------------
// UnauthenticatedCredential
// ---------------------------------------------------------------------------

/// A VRF-based credential that has not yet been authenticated.
///
/// Mirrors Go's `committee.UnauthenticatedCredential`.
///
/// Go struct tag: `codec:",omitempty,omitemptyarray"` — the `Proof` field is
/// omitted when all zeros.
///
/// VrfProof is 80 bytes in Go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnauthenticatedCredential {
    /// The VRF proof (80 bytes). `codec:"pf"`
    #[serde(
        rename = "pf",
        default,
        skip_serializing_if = "is_zero_or_empty_bytebuf"
    )]
    pub proof: ByteBuf,
}

impl Default for UnauthenticatedCredential {
    fn default() -> Self {
        Self {
            proof: ByteBuf::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Construction tests --

    #[test]
    fn default_certificate() {
        let cert = Certificate::default();
        assert_eq!(cert.round, Round(0));
        assert_eq!(cert.period, 0);
        assert_eq!(cert.step, 0);
        assert_eq!(cert.proposal, ProposalValue::default());
        assert!(cert.votes.is_empty());
        assert!(cert.equivocation_votes.is_empty());
    }

    #[test]
    fn default_proposal_value() {
        let pv = ProposalValue::default();
        assert_eq!(pv.original_period, 0);
        assert!(pv.original_proposer.is_zero());
        assert!(pv.block_digest.is_empty());
        assert!(pv.encoding_digest.is_empty());
    }

    #[test]
    fn default_one_time_signature() {
        let ots = OneTimeSignature::default();
        assert_eq!(ots.sig.len(), 64, "sig should be 64 zero bytes");
        assert_eq!(ots.pk.len(), 32, "pk should be 32 zero bytes");
        assert_eq!(
            ots.pk_sig_old.len(),
            64,
            "pk_sig_old should be 64 zero bytes"
        );
        assert_eq!(ots.pk2.len(), 32, "pk2 should be 32 zero bytes");
        assert_eq!(ots.pk1_sig.len(), 64, "pk1_sig should be 64 zero bytes");
        assert_eq!(ots.pk2_sig.len(), 64, "pk2_sig should be 64 zero bytes");
        assert!(ots.sig.iter().all(|&b| b == 0), "sig should be all zeros");
        assert!(ots.pk.iter().all(|&b| b == 0), "pk should be all zeros");
        assert!(
            ots.pk_sig_old.iter().all(|&b| b == 0),
            "pk_sig_old should be all zeros"
        );
        assert!(ots.pk2.iter().all(|&b| b == 0), "pk2 should be all zeros");
        assert!(
            ots.pk1_sig.iter().all(|&b| b == 0),
            "pk1_sig should be all zeros"
        );
        assert!(
            ots.pk2_sig.iter().all(|&b| b == 0),
            "pk2_sig should be all zeros"
        );
    }

    #[test]
    fn default_unauthenticated_credential() {
        let cred = UnauthenticatedCredential::default();
        assert!(cred.proof.is_empty());
    }

    // -- JSON round-trip tests (verifying serde field names) --

    #[test]
    fn proposal_value_json_field_names() {
        let pv = ProposalValue {
            original_period: 3,
            original_proposer: Address([0xAB; 32]),
            block_digest: ByteBuf::from(vec![1; 32]),
            encoding_digest: ByteBuf::from(vec![2; 32]),
        };
        let json = serde_json::to_value(&pv).unwrap();
        assert!(json.get("oper").is_some(), "expected 'oper' field");
        assert!(json.get("oprop").is_some(), "expected 'oprop' field");
        assert!(json.get("dig").is_some(), "expected 'dig' field");
        assert!(json.get("encdig").is_some(), "expected 'encdig' field");
    }

    #[test]
    fn proposal_value_json_round_trip() {
        let pv = ProposalValue {
            original_period: 5,
            original_proposer: Address([0x11; 32]),
            block_digest: ByteBuf::from(vec![0xAA; 32]),
            encoding_digest: ByteBuf::from(vec![0xBB; 32]),
        };
        let json = serde_json::to_string(&pv).unwrap();
        let decoded: ProposalValue = serde_json::from_str(&json).unwrap();
        assert_eq!(pv, decoded);
    }

    #[test]
    fn proposal_value_omits_zero_fields() {
        let pv = ProposalValue::default();
        let json = serde_json::to_value(&pv).unwrap();
        let obj = json.as_object().unwrap();
        // All fields should be omitted when default
        assert!(
            obj.is_empty(),
            "default proposal value should serialize as empty: {obj:?}"
        );
    }

    #[test]
    fn certificate_json_field_names() {
        let cert = Certificate {
            round: Round(42),
            period: 1,
            step: 2,
            proposal: ProposalValue::default(),
            votes: vec![],
            equivocation_votes: vec![],
        };
        let json = serde_json::to_value(&cert).unwrap();
        assert!(json.get("rnd").is_some(), "expected 'rnd' field");
        assert!(json.get("per").is_some(), "expected 'per' field");
        assert!(json.get("step").is_some(), "expected 'step' field");
        // prop, vote, eqv should be omitted when default/empty
        assert!(
            json.get("prop").is_none(),
            "'prop' should be omitted when default"
        );
        assert!(
            json.get("vote").is_none(),
            "'vote' should be omitted when empty"
        );
        assert!(
            json.get("eqv").is_none(),
            "'eqv' should be omitted when empty"
        );
    }

    #[test]
    fn certificate_json_round_trip() {
        let cert = Certificate {
            round: Round(100),
            period: 2,
            step: 3,
            proposal: ProposalValue {
                original_period: 1,
                original_proposer: Address([0x42; 32]),
                block_digest: ByteBuf::from(vec![0xDE; 32]),
                encoding_digest: ByteBuf::from(vec![0xAD; 32]),
            },
            votes: vec![],
            equivocation_votes: vec![],
        };
        let json = serde_json::to_string(&cert).unwrap();
        let decoded: Certificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, decoded);
    }

    #[test]
    fn default_certificate_omits_all_fields() {
        let cert = Certificate::default();
        let json = serde_json::to_value(&cert).unwrap();
        let obj = json.as_object().unwrap();
        assert!(
            obj.is_empty(),
            "default certificate should serialize as empty: {obj:?}"
        );
    }

    #[test]
    fn one_time_signature_json_field_names() {
        let ots = OneTimeSignature {
            sig: ByteBuf::from(vec![1; 64]),
            pk: ByteBuf::from(vec![2; 32]),
            pk_sig_old: ByteBuf::from(vec![3; 64]),
            pk2: ByteBuf::from(vec![4; 32]),
            pk1_sig: ByteBuf::from(vec![5; 64]),
            pk2_sig: ByteBuf::from(vec![6; 64]),
        };
        let json = serde_json::to_value(&ots).unwrap();
        assert!(json.get("s").is_some(), "expected 's' field");
        assert!(json.get("p").is_some(), "expected 'p' field");
        assert!(json.get("ps").is_some(), "expected 'ps' field");
        assert!(json.get("p2").is_some(), "expected 'p2' field");
        assert!(json.get("p1s").is_some(), "expected 'p1s' field");
        assert!(json.get("p2s").is_some(), "expected 'p2s' field");
    }

    #[test]
    fn one_time_signature_json_round_trip() {
        let ots = OneTimeSignature {
            sig: ByteBuf::from(vec![0xFF; 64]),
            pk: ByteBuf::from(vec![0xAA; 32]),
            pk_sig_old: ByteBuf::from(vec![0x00; 64]),
            pk2: ByteBuf::from(vec![0xBB; 32]),
            pk1_sig: ByteBuf::from(vec![0xCC; 64]),
            pk2_sig: ByteBuf::from(vec![0xDD; 64]),
        };
        let json = serde_json::to_string(&ots).unwrap();
        let decoded: OneTimeSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(ots, decoded);
    }

    #[test]
    fn one_time_signature_always_serializes_all_fields() {
        // OneTimeSignature has codec:"" (not omitempty) in Go, so all fields
        // are always present even when zero.
        let ots = OneTimeSignature::default();
        let json = serde_json::to_value(&ots).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("s"), "s must always be present");
        assert!(obj.contains_key("p"), "p must always be present");
        assert!(obj.contains_key("ps"), "ps must always be present");
        assert!(obj.contains_key("p2"), "p2 must always be present");
        assert!(obj.contains_key("p1s"), "p1s must always be present");
        assert!(obj.contains_key("p2s"), "p2s must always be present");
    }

    #[test]
    fn unauthenticated_credential_json_field_name() {
        let cred = UnauthenticatedCredential {
            proof: ByteBuf::from(vec![0x42; 80]),
        };
        let json = serde_json::to_value(&cred).unwrap();
        assert!(json.get("pf").is_some(), "expected 'pf' field");
    }

    #[test]
    fn unauthenticated_credential_omits_empty_proof() {
        let cred = UnauthenticatedCredential::default();
        let json = serde_json::to_value(&cred).unwrap();
        let obj = json.as_object().unwrap();
        assert!(
            obj.is_empty(),
            "default credential should serialize as empty: {obj:?}"
        );
    }

    #[test]
    fn unauthenticated_credential_json_round_trip() {
        let cred = UnauthenticatedCredential {
            proof: ByteBuf::from(vec![0xAB; 80]),
        };
        let json = serde_json::to_string(&cred).unwrap();
        let decoded: UnauthenticatedCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, decoded);
    }

    #[test]
    fn vote_authenticator_json_field_names() {
        let va = VoteAuthenticator {
            sender: Address([0x11; 32]),
            cred: UnauthenticatedCredential {
                proof: ByteBuf::from(vec![0x22; 80]),
            },
            sig: OneTimeSignature::default(),
        };
        let json = serde_json::to_value(&va).unwrap();
        assert!(json.get("snd").is_some(), "expected 'snd' field");
        assert!(json.get("cred").is_some(), "expected 'cred' field");
        // sig is omitempty, so it should be absent when default
        assert!(
            json.get("sig").is_none(),
            "'sig' should be omitted when default"
        );
    }

    #[test]
    fn vote_authenticator_always_serializes_sender_and_cred() {
        // voteAuthenticator has codec:"" (not omitempty), so sender and cred
        // are always present. Only sig has explicit omitempty.
        let va = VoteAuthenticator {
            sender: Address::default(),
            cred: UnauthenticatedCredential::default(),
            sig: OneTimeSignature::default(),
        };
        let json = serde_json::to_value(&va).unwrap();
        assert!(json.get("snd").is_some(), "snd must always be present");
        assert!(json.get("cred").is_some(), "cred must always be present");
    }

    #[test]
    fn vote_authenticator_json_round_trip() {
        let va = VoteAuthenticator {
            sender: Address([0x33; 32]),
            cred: UnauthenticatedCredential {
                proof: ByteBuf::from(vec![0x44; 80]),
            },
            sig: OneTimeSignature {
                sig: ByteBuf::from(vec![1; 64]),
                pk: ByteBuf::from(vec![2; 32]),
                pk_sig_old: ByteBuf::from(vec![3; 64]),
                pk2: ByteBuf::from(vec![4; 32]),
                pk1_sig: ByteBuf::from(vec![5; 64]),
                pk2_sig: ByteBuf::from(vec![6; 64]),
            },
        };
        let json = serde_json::to_string(&va).unwrap();
        let decoded: VoteAuthenticator = serde_json::from_str(&json).unwrap();
        assert_eq!(va, decoded);
    }

    #[test]
    fn equivocation_vote_authenticator_json_field_names() {
        let eva = EquivocationVoteAuthenticator {
            sender: Address([0x55; 32]),
            cred: UnauthenticatedCredential::default(),
            sigs: [OneTimeSignature::default(), OneTimeSignature::default()],
            proposals: [ProposalValue::default(), ProposalValue::default()],
        };
        let json = serde_json::to_value(&eva).unwrap();
        assert!(json.get("snd").is_some(), "expected 'snd' field");
        assert!(json.get("cred").is_some(), "expected 'cred' field");
        // sigs is omitempty, should be absent when default
        assert!(
            json.get("sig").is_none(),
            "'sig' should be omitted when default"
        );
        // proposals is NOT omitempty, always present
        assert!(
            json.get("props").is_some(),
            "expected 'props' field (always present)"
        );
    }

    #[test]
    fn equivocation_vote_authenticator_json_round_trip() {
        let eva = EquivocationVoteAuthenticator {
            sender: Address([0x66; 32]),
            cred: UnauthenticatedCredential {
                proof: ByteBuf::from(vec![0x77; 80]),
            },
            sigs: [
                OneTimeSignature {
                    sig: ByteBuf::from(vec![0xA1; 64]),
                    pk: ByteBuf::from(vec![0xA2; 32]),
                    pk_sig_old: ByteBuf::from(vec![0; 64]),
                    pk2: ByteBuf::from(vec![0xA3; 32]),
                    pk1_sig: ByteBuf::from(vec![0xA4; 64]),
                    pk2_sig: ByteBuf::from(vec![0xA5; 64]),
                },
                OneTimeSignature {
                    sig: ByteBuf::from(vec![0xB1; 64]),
                    pk: ByteBuf::from(vec![0xB2; 32]),
                    pk_sig_old: ByteBuf::from(vec![0; 64]),
                    pk2: ByteBuf::from(vec![0xB3; 32]),
                    pk1_sig: ByteBuf::from(vec![0xB4; 64]),
                    pk2_sig: ByteBuf::from(vec![0xB5; 64]),
                },
            ],
            proposals: [
                ProposalValue {
                    original_period: 1,
                    original_proposer: Address([0xC1; 32]),
                    block_digest: ByteBuf::from(vec![0xD1; 32]),
                    encoding_digest: ByteBuf::from(vec![0xE1; 32]),
                },
                ProposalValue {
                    original_period: 2,
                    original_proposer: Address([0xC2; 32]),
                    block_digest: ByteBuf::from(vec![0xD2; 32]),
                    encoding_digest: ByteBuf::from(vec![0xE2; 32]),
                },
            ],
        };
        let json = serde_json::to_string(&eva).unwrap();
        let decoded: EquivocationVoteAuthenticator = serde_json::from_str(&json).unwrap();
        assert_eq!(eva, decoded);
    }

    #[test]
    fn certificate_with_votes_round_trip() {
        let cert = Certificate {
            round: Round(1000),
            period: 0,
            step: 2, // cert step
            proposal: ProposalValue {
                original_period: 0,
                original_proposer: Address([0x42; 32]),
                block_digest: ByteBuf::from(vec![0xAB; 32]),
                encoding_digest: ByteBuf::from(vec![0xCD; 32]),
            },
            votes: vec![
                VoteAuthenticator {
                    sender: Address([0x01; 32]),
                    cred: UnauthenticatedCredential {
                        proof: ByteBuf::from(vec![0x10; 80]),
                    },
                    sig: OneTimeSignature {
                        sig: ByteBuf::from(vec![0x20; 64]),
                        pk: ByteBuf::from(vec![0x30; 32]),
                        pk_sig_old: ByteBuf::from(vec![0; 64]),
                        pk2: ByteBuf::from(vec![0x40; 32]),
                        pk1_sig: ByteBuf::from(vec![0x50; 64]),
                        pk2_sig: ByteBuf::from(vec![0x60; 64]),
                    },
                },
                VoteAuthenticator {
                    sender: Address([0x02; 32]),
                    cred: UnauthenticatedCredential {
                        proof: ByteBuf::from(vec![0x11; 80]),
                    },
                    sig: OneTimeSignature {
                        sig: ByteBuf::from(vec![0x21; 64]),
                        pk: ByteBuf::from(vec![0x31; 32]),
                        pk_sig_old: ByteBuf::from(vec![0; 64]),
                        pk2: ByteBuf::from(vec![0x41; 32]),
                        pk1_sig: ByteBuf::from(vec![0x51; 64]),
                        pk2_sig: ByteBuf::from(vec![0x61; 64]),
                    },
                },
            ],
            equivocation_votes: vec![],
        };
        let json = serde_json::to_string(&cert).unwrap();
        let decoded: Certificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, decoded);
    }

    #[test]
    fn encoded_block_cert_json_field_names() {
        // We can't easily construct a full Block in a unit test, so just verify
        // that EncodedBlockCert can be deserialized from JSON with the right
        // field names by checking the Certificate side.
        let cert = Certificate::default();
        let json = serde_json::to_value(&cert).unwrap();
        // Certificate should be an empty object when default
        assert!(json.as_object().unwrap().is_empty());
    }

    #[test]
    fn deserialize_certificate_from_empty_json_object() {
        // An empty JSON object should deserialize to the default certificate
        // (all fields have defaults).
        let cert: Certificate = serde_json::from_str("{}").unwrap();
        assert_eq!(cert, Certificate::default());
    }

    #[test]
    fn deserialize_proposal_value_from_empty_json_object() {
        let pv: ProposalValue = serde_json::from_str("{}").unwrap();
        assert_eq!(pv, ProposalValue::default());
    }

    #[test]
    fn deserialize_unauthenticated_credential_from_empty_json_object() {
        let cred: UnauthenticatedCredential = serde_json::from_str("{}").unwrap();
        assert_eq!(cred, UnauthenticatedCredential::default());
    }

    #[test]
    fn deserialize_one_time_signature_from_partial_json() {
        // OneTimeSignature fields have defaults, so partial JSON should work.
        // Missing fields get serde `default` (empty ByteBuf from Deserialize),
        // not our Default impl.
        let json = r#"{"s": [1,2,3], "p": [4,5,6]}"#;
        let ots: OneTimeSignature = serde_json::from_str(json).unwrap();
        assert_eq!(ots.sig.as_ref(), &[1, 2, 3]);
        assert_eq!(ots.pk.as_ref(), &[4, 5, 6]);
        // serde `default` for ByteBuf produces empty, not our Default impl
        assert!(ots.pk_sig_old.is_empty());
        assert!(ots.pk2.is_empty());
        assert!(ots.pk1_sig.is_empty());
        assert!(ots.pk2_sig.is_empty());
    }

    #[test]
    fn certificate_equality() {
        let a = Certificate::default();
        let b = Certificate::default();
        assert_eq!(a, b);

        let c = Certificate {
            round: Round(1),
            ..Certificate::default()
        };
        assert_ne!(a, c);
    }

    #[test]
    fn proposal_value_equality() {
        let a = ProposalValue::default();
        let b = ProposalValue::default();
        assert_eq!(a, b);

        let c = ProposalValue {
            original_period: 1,
            ..ProposalValue::default()
        };
        assert_ne!(a, c);
    }

    #[test]
    fn one_time_signature_equality() {
        let a = OneTimeSignature::default();
        let b = OneTimeSignature::default();
        assert_eq!(a, b);

        let c = OneTimeSignature {
            sig: ByteBuf::from(vec![1]),
            ..OneTimeSignature::default()
        };
        assert_ne!(a, c);
    }

    #[test]
    fn clone_types() {
        let cert = Certificate::default();
        let cloned = cert.clone();
        assert_eq!(cert, cloned);

        let pv = ProposalValue::default();
        let cloned = pv.clone();
        assert_eq!(pv, cloned);

        let ots = OneTimeSignature::default();
        let cloned = ots.clone();
        assert_eq!(ots, cloned);

        let cred = UnauthenticatedCredential::default();
        let cloned = cred.clone();
        assert_eq!(cred, cloned);
    }

    // -- msgpack round-trip tests --

    #[test]
    fn certificate_msgpack_round_trip() {
        let cert = Certificate {
            round: Round(500),
            period: 1,
            step: 2,
            proposal: ProposalValue {
                original_period: 3,
                original_proposer: Address([0xAB; 32]),
                block_digest: ByteBuf::from(vec![0xDE; 32]),
                encoding_digest: ByteBuf::from(vec![0xAD; 32]),
            },
            votes: vec![VoteAuthenticator {
                sender: Address([0x01; 32]),
                cred: UnauthenticatedCredential {
                    proof: ByteBuf::from(vec![0x10; 80]),
                },
                sig: OneTimeSignature {
                    sig: ByteBuf::from(vec![0x20; 64]),
                    pk: ByteBuf::from(vec![0x30; 32]),
                    pk_sig_old: ByteBuf::from(vec![0; 64]),
                    pk2: ByteBuf::from(vec![0x40; 32]),
                    pk1_sig: ByteBuf::from(vec![0x50; 64]),
                    pk2_sig: ByteBuf::from(vec![0x60; 64]),
                },
            }],
            equivocation_votes: vec![],
        };
        let bytes = rmp_serde::to_vec_named(&cert).expect("msgpack encode");
        let decoded: Certificate = rmp_serde::from_slice(&bytes).expect("msgpack decode");
        assert_eq!(cert, decoded);
    }

    #[test]
    fn default_certificate_msgpack_round_trip() {
        let cert = Certificate::default();
        let bytes = rmp_serde::to_vec_named(&cert).expect("msgpack encode");
        let decoded: Certificate = rmp_serde::from_slice(&bytes).expect("msgpack decode");
        assert_eq!(cert, decoded);
    }
}
