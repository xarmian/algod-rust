//! Certificate cross-verification helpers (PLAN-32 / TASK-88).
//!
//! The library holds the small amount of glue code that converts a
//! `BlockResponse` fetched over REST into the `(Block, Certificate)` pair
//! [`algo_agreement::Certificate::authenticate`] expects. The binary
//! (`src/main.rs`) wires it to the REST client, a sqlite-backed
//! `AgreementLedgerBridge`, and a CLI.
//!
//! Two directions are covered:
//!
//! **Go → Rust** (PLAN-32 / TASK-88, the original scope):
//!   - fetch (block, cert) from a Go algod REST node
//!   - decode cert from its msgpack-native form
//!   - call `Certificate::authenticate` against an algod-rust ledger
//!     that is caught up to the target round.
//!
//! **Rust → Go** (issue #470 §2): now that `algod-rust participate`
//! runs with real participation keys (#469) and its votes land in the
//! certificates the cluster commits, we additionally
//!   - assert the Rust account's vote is present in the cert bundle for
//!     rounds where it was selected ([`rust_vote_rounds`]), and
//!   - export a self-contained JSON bundle
//!     ([`GoVerifyInput`]) that `tools/cert-authenticate` feeds to
//!     go-algorand's own `agreement.Certificate.Authenticate`, so the
//!     same certificate is authenticated under BOTH implementations.
//!
//! The exported bundle carries the raw `(block, cert)` msgpack bytes
//! exactly as the Go node served them, plus the ledger facts
//! `agreement.LedgerReader` needs, read out of the **Rust** ledger. Any
//! divergence between Rust's view of stake / seed / circulation and what
//! the votes actually committed to shows up as a Go-side authentication
//! failure, which is precisely the cross-check we want.

use std::collections::BTreeMap;

use algo_agreement::{codec as agreement_codec, Certificate, LedgerReader};
use algo_codec::compute_block_digest;
use algo_types::{Address, Block, BlockResponse, Digest, Round};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Certificate extracted from a [`BlockResponse`] + the block's locally
/// computed digest.
#[derive(Debug, Clone)]
pub struct VerifiablePair {
    pub block: Block,
    pub block_digest: Digest,
    pub certificate: Certificate,
}

/// Convert a [`BlockResponse`] (as returned by the REST client) into the
/// shape `Certificate::authenticate` consumes.
///
/// Fails if the response lacks a cert or the cert msgpack Value can't be
/// re-encoded / decoded into an `UnauthenticatedBundle`.
pub fn pair_from_response(resp: BlockResponse) -> Result<VerifiablePair> {
    let BlockResponse { block, cert } = resp;
    let cert_value = cert.context("response has no `cert` field — cannot verify")?;

    // Re-encode the rmpv::Value back to canonical msgpack bytes and
    // decode as an UnauthenticatedBundle via the agreement codec. This
    // keeps us on the same decode path the algod-rust gossip layer uses
    // and avoids depending on a parallel Certificate serde shape.
    let mut cert_bytes = Vec::<u8>::new();
    rmpv::encode::write_value(&mut cert_bytes, &cert_value)
        .context("re-encoding cert rmpv::Value to msgpack")?;
    let bundle = agreement_codec::decode_bundle(&cert_bytes)
        .map_err(|e| anyhow::anyhow!("decode_bundle: {e}"))?;
    let certificate = Certificate::from_bundle(&bundle);

    let block_digest = compute_block_digest(&block);
    Ok(VerifiablePair {
        block,
        block_digest,
        certificate,
    })
}

/// Does `cert` contain at least one vote cast by `account`?
///
/// The certificate is a cert-step bundle; every `VoteAuthenticator` in
/// it carries the voter's `sender` address verbatim. A Rust vote being
/// present in a cert the *Go* nodes committed is direct evidence that Go
/// counted it toward the quorum.
pub fn cert_contains_sender(cert: &Certificate, account: &Address) -> bool {
    cert.votes.iter().any(|v| &v.sender == account)
}

/// Number of distinct senders in a certificate (useful in reports —
/// a healthy 4-node cluster commits with 3 or 4 distinct voters).
pub fn cert_senders(cert: &Certificate) -> Vec<Address> {
    let mut out: Vec<Address> = cert.votes.iter().map(|v| v.sender).collect();
    out.sort_by_key(|a| a.0);
    out.dedup_by_key(|a| a.0);
    out
}

/// Filter `rounds` down to those whose certificate contains a vote from
/// `account`. `certs` is an iterator of `(round, cert)` pairs.
pub fn rust_vote_rounds<'a, I>(certs: I, account: &Address) -> Vec<u64>
where
    I: IntoIterator<Item = (u64, &'a Certificate)>,
{
    certs
        .into_iter()
        .filter(|(_, c)| cert_contains_sender(c, account))
        .map(|(r, _)| r)
        .collect()
}

// ── Rust → Go export bundle (issue #470 §2) ─────────────────────────────

/// Online-account facts `agreement.LedgerReader.LookupAgreement` must
/// return for one voter, as read out of the Rust ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoVerifyAccount {
    /// Address in Algorand base32-with-checksum form.
    pub address: String,
    /// `MicroAlgosWithRewards`.
    pub micro_algos: u64,
    /// Base64 `VoteID` (OTS master verifier).
    pub vote_id_b64: String,
    /// Base64 `SelectionID` (VRF verifier).
    pub selection_id_b64: String,
    pub vote_first_valid: u64,
    pub vote_last_valid: u64,
    pub vote_key_dilution: u64,
    pub incentive_eligible: bool,
    pub last_proposed: u64,
    pub last_heartbeat: u64,
    /// Base64 `StateProofID` (64-byte merkle-signature commitment).
    pub state_proof_id_b64: String,
}

/// Everything `tools/cert-authenticate` needs to authenticate one
/// round's certificate under go-algorand semantics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoVerifyRound {
    pub round: u64,
    /// Base64 of the raw msgpack `{block, cert}` envelope exactly as the
    /// Go node's `/v2/blocks/{r}?format=msgpack` returned it. The Go
    /// helper decodes it into `rpcs.EncodedBlockCert`, so the block
    /// digest is recomputed by Go rather than trusted from Rust.
    pub block_cert_msgpack_b64: String,
    /// Digest Rust computed for the block, hex — the Go helper compares
    /// against its own so a codec divergence is reported explicitly
    /// rather than as an opaque "wrong hash" cert error.
    pub rust_block_digest_hex: String,
    /// Consensus version string at `params_round(round)`.
    pub consensus_version: String,
    pub params_round: u64,
    pub balance_round: u64,
    pub seed_round: u64,
    /// Base64 of the 32-byte VRF seed at `seed_round`.
    pub seed_b64: String,
    /// `Circulation(balance_round, round)` in microAlgos.
    pub circulation: u64,
    /// One entry per distinct voter in the certificate.
    pub accounts: Vec<GoVerifyAccount>,
    /// Whether the Rust participant's vote is in this cert.
    pub rust_vote_present: bool,
}

/// Top-level export file consumed by `tools/cert-authenticate`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoVerifyInput {
    /// Rust participant address (base32), if one was configured.
    pub rust_account: Option<String>,
    pub rounds: Vec<GoVerifyRound>,
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Build the per-round Go-verification record from a decoded pair plus
/// the ledger the Rust verifier just used.
///
/// Returns `Err` when the ledger cannot answer one of the lookups the Go
/// verifier will need — that is a genuine problem worth surfacing rather
/// than exporting a record Go is guaranteed to reject.
pub fn build_go_verify_round(
    round: u64,
    raw_block_cert: &[u8],
    pair: &VerifiablePair,
    ledger: &dyn LedgerReader,
    rust_account: Option<&Address>,
) -> Result<GoVerifyRound> {
    let r = Round(round);
    let params_round = algo_agreement::params_round(r);
    let cparams = ledger
        .consensus_params(params_round)
        .map_err(|e| anyhow::anyhow!("consensus_params({}): {e}", params_round.0))?;
    let consensus_version = ledger
        .consensus_version(params_round)
        .map_err(|e| anyhow::anyhow!("consensus_version({}): {e}", params_round.0))?;
    let balance_round = algo_agreement::balance_round(r, &cparams);
    let seed_round = algo_agreement::seed_round(r, &cparams);
    let seed = ledger
        .seed(seed_round)
        .map_err(|e| anyhow::anyhow!("seed({}): {e}", seed_round.0))?;
    let circulation = ledger
        .circulation(balance_round, r)
        .map_err(|e| anyhow::anyhow!("circulation({}, {}): {e}", balance_round.0, r.0))?;

    // De-dupe voters (a bundle can hold several votes per sender only in
    // the equivocation case, but be defensive).
    let mut accounts: BTreeMap<[u8; 32], GoVerifyAccount> = BTreeMap::new();
    for addr in cert_senders(&pair.certificate) {
        let oad = ledger
            .lookup_agreement(balance_round, &addr)
            .map_err(|e| anyhow::anyhow!("lookup_agreement({}, {addr}): {e}", balance_round.0))?;
        accounts.insert(
            addr.0,
            GoVerifyAccount {
                address: addr.to_string(),
                micro_algos: oad.micro_algos,
                vote_id_b64: b64(&oad.vote_id),
                selection_id_b64: b64(&oad.selection_id),
                vote_first_valid: oad.vote_first_valid.0,
                vote_last_valid: oad.vote_last_valid.0,
                vote_key_dilution: oad.vote_key_dilution,
                incentive_eligible: oad.incentive_eligible,
                last_proposed: oad.last_proposed.0,
                last_heartbeat: oad.last_heartbeat.0,
                state_proof_id_b64: b64(&oad.state_proof_id),
            },
        );
    }

    Ok(GoVerifyRound {
        round,
        block_cert_msgpack_b64: b64(raw_block_cert),
        rust_block_digest_hex: hex::encode(pair.block_digest.as_bytes()),
        consensus_version,
        params_round: params_round.0,
        balance_round: balance_round.0,
        seed_round: seed_round.0,
        seed_b64: b64(seed.as_bytes()),
        circulation,
        accounts: accounts.into_values().collect(),
        rust_vote_present: rust_account
            .map(|a| cert_contains_sender(&pair.certificate, a))
            .unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_agreement::VoteAuthenticator;
    use algo_types::Block;

    fn authenticator(sender: [u8; 32]) -> VoteAuthenticator {
        VoteAuthenticator {
            sender: Address(sender),
            cred: algo_agreement::UnauthenticatedCredential::new([0u8; 80]),
            sig: algo_consensus_crypto::onetimesig::OneTimeSignature {
                sig: [0u8; 64],
                pk: [0u8; 32],
                pk_sig_old: [0u8; 64],
                pk2: [0u8; 32],
                pk1_sig: [0u8; 64],
                pk2_sig: [0u8; 64],
            },
        }
    }

    fn cert_with_senders(senders: &[[u8; 32]]) -> Certificate {
        Certificate {
            round: Round(7),
            votes: senders.iter().copied().map(authenticator).collect(),
            ..Certificate::default()
        }
    }

    #[test]
    fn cert_contains_sender_matches_exact_address() {
        let cert = cert_with_senders(&[[1u8; 32], [2u8; 32]]);
        assert!(cert_contains_sender(&cert, &Address([2u8; 32])));
        assert!(!cert_contains_sender(&cert, &Address([3u8; 32])));
    }

    #[test]
    fn cert_contains_sender_on_empty_bundle_is_false() {
        let cert = cert_with_senders(&[]);
        assert!(!cert_contains_sender(&cert, &Address([1u8; 32])));
    }

    #[test]
    fn cert_senders_dedupes_and_sorts() {
        let cert = cert_with_senders(&[[9u8; 32], [1u8; 32], [9u8; 32]]);
        let senders = cert_senders(&cert);
        assert_eq!(senders.len(), 2);
        assert_eq!(senders[0], Address([1u8; 32]));
        assert_eq!(senders[1], Address([9u8; 32]));
    }

    #[test]
    fn rust_vote_rounds_selects_only_matching_rounds() {
        let with = cert_with_senders(&[[1u8; 32], [7u8; 32]]);
        let without = cert_with_senders(&[[1u8; 32]]);
        let rounds = rust_vote_rounds(
            vec![(10u64, &with), (11u64, &without), (12u64, &with)],
            &Address([7u8; 32]),
        );
        assert_eq!(rounds, vec![10, 12]);
    }

    #[test]
    fn rust_vote_rounds_empty_when_account_never_votes() {
        let cert = cert_with_senders(&[[1u8; 32]]);
        assert!(rust_vote_rounds(vec![(1u64, &cert)], &Address([7u8; 32])).is_empty());
    }

    #[test]
    fn go_verify_input_round_trips_through_json() {
        let input = GoVerifyInput {
            rust_account: Some("ABC".into()),
            rounds: vec![GoVerifyRound {
                round: 42,
                block_cert_msgpack_b64: "AAEC".into(),
                rust_block_digest_hex: "ff".repeat(32),
                consensus_version: "future".into(),
                params_round: 40,
                balance_round: 0,
                seed_round: 0,
                seed_b64: b64(&[0u8; 32]),
                circulation: 1_000_000,
                accounts: vec![],
                rust_vote_present: true,
            }],
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: GoVerifyInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    /// Regression: `pair_from_response` rejects a response with a
    /// missing `cert` field. (We pass `?format=msgpack` so cert is
    /// usually present, but defensively guard in case a future change
    /// in Go's envelope omits it.)
    #[test]
    fn pair_from_response_requires_cert() {
        let resp = BlockResponse {
            block: Block::default(),
            cert: None,
        };
        let err = pair_from_response(resp).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no `cert`"), "unexpected error: {msg}");
    }
}
