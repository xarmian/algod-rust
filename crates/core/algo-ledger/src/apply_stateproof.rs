//! Ledger-side application of `StateProofTx` transactions.
//!
//! Ports go-algorand's `ledger/apply/stateproof.go` (`apply.StateProof`) and
//! the weight-acceptability half of `stateproof/verify/stateproof.go`
//! (`verify.ValidateStateProof`, `calculateAcceptableStateProofWeight`). The
//! actual cryptographic verification (`crypto/stateproof.Verifier.Verify`)
//! is ported separately in `algo_consensus_crypto::stateproof`.
//!
//! # Verification-context tracker (issue #632)
//!
//! go's `apply.StateProof` resolves the verification context (voters
//! commitment + online total weight + protocol version for the relevant
//! voting round) two ways, selected by `StateProofUseTrackerVerification`
//! (true from v38, `config/consensus.go:1364` — i.e. true for every
//! consensus version this repo currently targets, including V41):
//!
//! - **Tracker path** (`ledger/spverificationtracker.go`'s
//!   `LookupVerificationContext`): a dedicated cache populated when each
//!   "voters round" block (`round % StateProofInterval == 0`) is applied,
//!   independent of whether that block's own header is still retained —
//!   this is real go-algorand's actual behavior at the versions this repo
//!   targets, not a fallback.
//! - **Header path** (pre-v38 fallback,
//!   `gatherVerificationContextUsingBlockHeaders`,
//!   `ledger/apply/stateproof.go:78`): reads `StateProofTracking` straight
//!   out of the two relevant block headers.
//!
//! `resolve_verification_context` below mirrors this: it prefers a tracker
//! entry (populated by `record_state_proof_verification_context`, called
//! from `apply::apply_block_impl` on every "voters round" block, mirroring
//! go's `spVerificationTracker.newBlock`/`appendCommitContext`) and falls
//! back to the header-derived path when no tracker entry exists — covering
//! both pre-v38 protocols and any round the tracker hasn't (yet) recorded
//! (e.g. a chain replayed from genesis before this tracker existed). Old
//! entries are pruned via `prune_state_proof_verification_contexts`,
//! mirroring go's `DeleteOldSPContexts`.

use std::collections::BTreeMap;

use algo_consensus_crypto::{merklearray, merklesig, stateproof as crypto_sp};
use algo_error::AlgoError;
use algo_types::consensus::{consensus_params_for_version, ConsensusParams};
use algo_types::{
    FalconVerifier as WireFalconVerifier, MerkleProof as WireMerkleProof,
    MerkleSignature as WireMerkleSignature, Participant as WireParticipant, Reveal as WireReveal,
    SigSlotCommit as WireSigSlotCommit, StateProofBody, StateProofMessage, Transaction,
};
use sha2::{Digest, Sha256};

use crate::apply::ApplyContext;
use crate::apply::ApplyData;
use crate::store_trait::LedgerStore;

/// `protocol.StateProofBasic` — the only supported state-proof type.
const STATE_PROOF_BASIC: u64 = 0;

/// Domain separation prefix for a `stateproofmsg.Message` hash (go:
/// `protocol.StateProofMessage = "spm"`).
const STATE_PROOF_MESSAGE_PREFIX: &[u8] = b"spm";

fn ledger_err(message: impl Into<String>) -> AlgoError {
    AlgoError::Ledger {
        message: message.into(),
    }
}

/// Apply a `StateProofTx`.
///
/// Matches go's `apply.StateProof` (`ledger/apply/stateproof.go:38`):
/// 1. Reject unsupported `StateProofType`.
/// 2. Enforce that the proof is for exactly the round the ledger's tracked
///    `StateProofNext` expects (read from the previous block header's
///    `StateProofTracking`).
/// 3. When `ctx.validate` (mirrors go's `eval.validate` — false only for
///    trusted replay of already-accepted blocks), resolve the verification
///    context and run the full cryptographic verification.
///
/// State-proof transactions carry no fee, so `ApplyData::default()` is
/// always the (only) return value on success — the actual `StateProofNext`
/// advancement is derived by the caller from the *block's own* header
/// tracking (see `apply::apply_block_with_delta_mode`'s `state_proof_next`
/// field), not tracked here.
pub fn apply_state_proof<L: LedgerStore>(
    store: &L,
    ctx: &ApplyContext,
    txn: &Transaction,
) -> Result<ApplyData, AlgoError> {
    if txn.state_proof_type != STATE_PROOF_BASIC {
        return Err(ledger_err(format!(
            "applyStateProof: state proof type not supported - type {}",
            txn.state_proof_type
        )));
    }

    let message = txn
        .state_proof_message
        .as_ref()
        .ok_or_else(|| ledger_err("applyStateProof: missing state proof message"))?;
    let last_round_in_interval = message.last_attested_round;

    let prev_hdr = store
        .get_block_header(ctx.round.saturating_sub(1))?
        .ok_or_else(|| {
            ledger_err(format!(
                "applyStateProof: no header for round {} (previous round)",
                ctx.round.saturating_sub(1)
            ))
        })?;
    let next_state_proof_rnd =
        crate::block_header::state_proof_next_round(&prev_hdr.state_proof_tracking);

    if next_state_proof_rnd == 0 || next_state_proof_rnd != last_round_in_interval {
        return Err(ledger_err(format!(
            "applyStateProof: expected different state proof round - expecting state proof for \
             {next_state_proof_rnd}, but new state proof is for {last_round_in_interval}"
        )));
    }

    if ctx.validate {
        let verification_context = resolve_verification_context(store, last_round_in_interval)?;

        let params =
            consensus_params_for_version(&verification_context.version).ok_or_else(|| {
                ledger_err(format!(
                    "applyStateProof: unknown protocol '{}'",
                    verification_context.version
                ))
            })?;

        if params.state_proof_interval == 0 {
            return Err(ledger_err(
                "applyStateProof: state proofs are not enabled for this protocol",
            ));
        }
        if last_round_in_interval % params.state_proof_interval != 0 {
            return Err(ledger_err(format!(
                "applyStateProof: state proof at {last_round_in_interval} for non-multiple of \
                 {}",
                params.state_proof_interval
            )));
        }

        let online_total_weight = verification_context.online_total_weight;

        let acceptable_weight = calculate_acceptable_state_proof_weight(
            online_total_weight,
            &params,
            last_round_in_interval,
            ctx.round,
        );

        let body = txn
            .state_proof
            .as_ref()
            .ok_or_else(|| ledger_err("applyStateProof: missing state proof body"))?;

        if body.signed_weight < acceptable_weight {
            return Err(ledger_err(format!(
                "applyStateProof: insufficient weight at round {}: {} < {acceptable_weight}",
                ctx.round, body.signed_weight
            )));
        }

        let proven_weight = muldiv_u64_u32(
            online_total_weight,
            params.state_proof_weight_threshold,
            1u64 << 32,
        )
        .ok_or_else(|| {
            ledger_err("applyStateProof: overflow computing provenWeight".to_string())
        })?;

        let verifier = crypto_sp::Verifier::new(
            verification_context.voters_commitment,
            proven_weight,
            params.state_proof_strength_target,
        )
        .map_err(|e| ledger_err(format!("applyStateProof: {e}")))?;

        let crypto_proof =
            convert_state_proof(body).map_err(|e| ledger_err(format!("applyStateProof: {e}")))?;
        let msg_hash = state_proof_message_hash(message);

        verifier
            .verify(last_round_in_interval, msg_hash, &crypto_proof)
            .map_err(|e| ledger_err(format!("applyStateProof: state proof crypto error: {e}")))?;
    }

    Ok(ApplyData::default())
}

// ── Verification-context tracker ────────────────────────────────────────

/// The data needed to verify a state proof for one round interval: voters
/// commitment, online total weight, and the protocol version whose security
/// parameters (`StateProofWeightThreshold`, `StateProofStrengthTarget`,
/// `StateProofInterval`) govern that interval. Matches go's
/// `ledgercore.StateProofVerificationContext` (minus the redundant
/// `LastAttestedRound` field, which is the tracker's lookup key here).
#[derive(Debug)]
struct VerificationContext {
    voters_commitment: Vec<u8>,
    online_total_weight: u64,
    version: String,
}

/// Resolve the verification context for a state proof attesting to
/// `last_round_in_interval`, preferring the tracker (real go-algorand
/// behavior at v38+) and falling back to reading it directly out of the
/// two relevant block headers (pre-v38, or a round the tracker hasn't
/// recorded — e.g. a chain replayed before this tracker existed). See the
/// module doc for the full picture.
fn resolve_verification_context<L: LedgerStore>(
    store: &L,
    last_round_in_interval: u64,
) -> Result<VerificationContext, AlgoError> {
    if let Some(bytes) = store.get_state_proof_verification_context(last_round_in_interval)? {
        return decode_verification_context(&bytes).map_err(|e| {
            ledger_err(format!(
                "applyStateProof: corrupt tracked verification context for round \
                 {last_round_in_interval}: {e}"
            ))
        });
    }

    // Matches go's `gatherVerificationContextUsingBlockHeaders`
    // (`ledger/apply/stateproof.go:77`): `lastRoundHdr.CurrentProtocol` is
    // used *only* to locate `votersRnd`'s offset. Every downstream security
    // parameter is then read from `votersHdr.CurrentProtocol` via
    // `MakeStateProofVerificationContext`'s `Version` field
    // (`ledger/ledgercore/stateproofverification.go:49`) — NOT from
    // `lastRoundHdr` again. Using the wrong header here would silently
    // verify against the wrong version's security thresholds if a future
    // protocol upgrade ever changes them mid-interval.
    let last_round_hdr = store
        .get_block_header(last_round_in_interval)?
        .ok_or_else(|| {
            ledger_err(format!(
                "applyStateProof: no header for last attested round {last_round_in_interval}"
            ))
        })?;
    let gather_params =
        consensus_params_for_version(&last_round_hdr.current_protocol).ok_or_else(|| {
            ledger_err(format!(
                "applyStateProof: unknown protocol '{}'",
                last_round_hdr.current_protocol
            ))
        })?;

    let voters_round = last_round_in_interval.saturating_sub(gather_params.state_proof_interval);
    let voters_hdr = store.get_block_header(voters_round)?.ok_or_else(|| {
        ledger_err(format!(
            "applyStateProof: no header for voters round {voters_round}"
        ))
    })?;

    Ok(VerificationContext {
        voters_commitment: crate::block_header::state_proof_voters_commitment(
            &voters_hdr.state_proof_tracking,
        ),
        online_total_weight: crate::block_header::state_proof_online_total_weight(
            &voters_hdr.state_proof_tracking,
        ),
        version: voters_hdr.current_protocol,
    })
}

/// Record a verification context for the block just applied, if it's a
/// "voters round" (`round % StateProofInterval == 0`) — mirrors go's
/// `spVerificationTracker.newBlock`/`appendCommitContext`
/// (`ledger/spverificationtracker.go:88-102`): every such block seeds the
/// verification context for the state proof interval starting after it,
/// i.e. for `last_attested_round = round + StateProofInterval`.
///
/// Called from `apply::apply_block_impl` on every applied block (own
/// production or replay/sync), independent of whether that block will ever
/// itself carry a `StateProofTx` — the tracker records *voters* data, not
/// proof data.
pub(crate) fn record_state_proof_verification_context<L: LedgerStore>(
    store: &mut L,
    round: u64,
    current_protocol: &str,
    state_proof_tracking: &Option<rmpv::Value>,
    state_proof_interval: u64,
) -> Result<(), AlgoError> {
    if state_proof_interval == 0 || round % state_proof_interval != 0 {
        return Ok(());
    }
    let last_attested_round = round + state_proof_interval;
    let ctx = VerificationContext {
        voters_commitment: crate::block_header::state_proof_voters_commitment(state_proof_tracking),
        online_total_weight: crate::block_header::state_proof_online_total_weight(
            state_proof_tracking,
        ),
        version: current_protocol.to_string(),
    };
    store.put_state_proof_verification_context(
        last_attested_round,
        &encode_verification_context(&ctx),
    )
}

/// Prune verification-context entries that are no longer needed because a
/// state proof for that round has already been applied and `StateProofNext`
/// has advanced past it — mirrors go's `DeleteOldSPContexts`
/// (`ledger/spverificationtracker.go:136-138`, keyed by
/// `pendingDeleteContexts`' `stateProofNextRound`, i.e. the block's own
/// post-apply `StateProofNext`).
pub(crate) fn prune_state_proof_verification_contexts<L: LedgerStore>(
    store: &mut L,
    new_state_proof_next: u64,
) -> Result<(), AlgoError> {
    if new_state_proof_next == 0 {
        return Ok(());
    }
    store.delete_state_proof_verification_contexts_before(new_state_proof_next)
}

/// Encode a [`VerificationContext`] to a plain binary blob for the
/// verification-context tracker's local store. Internal, node-private
/// format — this data never crosses the wire or affects consensus (it's a
/// pure verification-context cache), so byte-level parity with go's own DB
/// blob encoding isn't required, only matching read/write/lookup behavior.
fn encode_verification_context(ctx: &VerificationContext) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 4 + ctx.voters_commitment.len() + 4 + ctx.version.len());
    out.extend_from_slice(&ctx.online_total_weight.to_le_bytes());
    out.extend_from_slice(&(ctx.voters_commitment.len() as u32).to_le_bytes());
    out.extend_from_slice(&ctx.voters_commitment);
    out.extend_from_slice(&(ctx.version.len() as u32).to_le_bytes());
    out.extend_from_slice(ctx.version.as_bytes());
    out
}

fn decode_verification_context(bytes: &[u8]) -> Result<VerificationContext, String> {
    let mut pos = 0usize;
    let take = |pos: &mut usize, n: usize, bytes: &[u8]| -> Result<Vec<u8>, String> {
        let end = pos.checked_add(n).ok_or("length overflow")?;
        let slice = bytes.get(*pos..end).ok_or("truncated")?.to_vec();
        *pos = end;
        Ok(slice)
    };

    let weight_bytes = take(&mut pos, 8, bytes)?;
    let online_total_weight = u64::from_le_bytes(weight_bytes.try_into().unwrap());

    let commit_len_bytes = take(&mut pos, 4, bytes)?;
    let commit_len = u32::from_le_bytes(commit_len_bytes.try_into().unwrap()) as usize;
    let voters_commitment = take(&mut pos, commit_len, bytes)?;

    let ver_len_bytes = take(&mut pos, 4, bytes)?;
    let ver_len = u32::from_le_bytes(ver_len_bytes.try_into().unwrap()) as usize;
    let ver_bytes = take(&mut pos, ver_len, bytes)?;
    let version = String::from_utf8(ver_bytes).map_err(|e| e.to_string())?;

    Ok(VerificationContext {
        voters_commitment,
        online_total_weight,
        version,
    })
}

/// `a*b/d`, computed in 128-bit precision (`a`, `d`: u64; `b`: u32), matching
/// go's `basics.Muldiv` usage for `provenWeight = total * WeightThreshold /
/// (1<<32)`. Returns `None` if the result doesn't fit in `u64`.
fn muldiv_u64_u32(a: u64, b: u32, d: u64) -> Option<u64> {
    let product = (a as u128) * (b as u128);
    let result = product / (d as u128);
    u64::try_from(result).ok()
}

/// Compute the acceptable signed weight for a state proof appearing in a
/// transaction with a particular `first_valid` round.
///
/// Matches go's `calculateAcceptableStateProofWeight`
/// (`stateproof/verify/stateproof.go:56`) exactly, including its "safe
/// fallback to accept a larger proof" (return `0`, i.e. no minimum) on the
/// arithmetic-overflow paths that are unreachable at realistic weight
/// magnitudes.
fn calculate_acceptable_state_proof_weight(
    total: u64,
    proto: &ConsensusParams,
    last_attested_round: u64,
    first_valid: u64,
) -> u64 {
    let half_period = proto.state_proof_interval / 2;

    let offset = first_valid.saturating_sub(last_attested_round);
    if offset == 0 {
        return total;
    }

    let offset = offset.saturating_sub(half_period);
    if offset == 0 {
        return total;
    }

    let Some(proven_weight) = muldiv_u64_u32(total, proto.state_proof_weight_threshold, 1u64 << 32)
    else {
        return 0;
    };
    if proven_weight > total {
        return 0;
    }

    if offset >= half_period {
        return proven_weight;
    }

    let Some(scaled_weight) = muldiv_u64_u32(
        total - proven_weight,
        (half_period - offset) as u32,
        half_period,
    ) else {
        return 0;
    };

    proven_weight.checked_add(scaled_weight).unwrap_or(0)
}

/// Hash a `StateProofMessage`, matching go's `stateproofmsg.Message.Hash`
/// (`data/stateproofmsg/message.go:46`): `SHA256("spm" ||
/// canonical_msgpack(message))`.
pub fn state_proof_message_hash(msg: &StateProofMessage) -> crypto_sp::MessageHash {
    let encoded = algo_codec::canonical_encode_state_proof_message(msg);
    let mut hasher = Sha256::new();
    hasher.update(STATE_PROOF_MESSAGE_PREFIX);
    hasher.update(&encoded);
    hasher.finalize().into()
}

// ── Wire → crypto type conversion ───────────────────────────────────────

fn convert_hash_factory(hf: Option<&algo_types::HashFactory>) -> merklearray::HashFactory {
    let hash_type = hf
        .and_then(|h| merklearray::HashType::from_u16(h.hash_type))
        .unwrap_or_default();
    merklearray::HashFactory::new(hash_type)
}

fn convert_merkle_proof(p: Option<&WireMerkleProof>) -> merklearray::Proof {
    let Some(p) = p else {
        return merklearray::Proof::default();
    };
    let path = p
        .path
        .as_ref()
        .map(|entries| {
            entries
                .iter()
                .map(|e| e.as_ref().map(|b| b.to_vec()).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();
    merklearray::Proof {
        path,
        hash_factory: convert_hash_factory(p.hash_factory.as_ref()),
        tree_depth: p.tree_depth,
    }
}

fn convert_falcon_verifier(fv: Option<&WireFalconVerifier>) -> merklesig::FalconVerifier {
    let mut out = merklesig::FalconVerifier::default();
    if let Some(fv) = fv {
        let n = fv.public_key.len().min(out.k.len());
        out.k[..n].copy_from_slice(&fv.public_key[..n]);
    }
    out
}

fn convert_merkle_signature(sig: Option<&WireMerkleSignature>) -> merklesig::Signature {
    let Some(sig) = sig else {
        return merklesig::Signature::default();
    };
    merklesig::Signature {
        signature: sig.signature.to_vec(),
        vector_commitment_index: sig.vector_commitment_index,
        proof: merklearray::SingleLeafProof {
            proof: convert_merkle_proof(sig.proof.as_ref()),
        },
        verifying_key: convert_falcon_verifier(sig.verifying_key.as_ref()),
    }
}

fn convert_sig_slot(slot: Option<&WireSigSlotCommit>) -> crypto_sp::SigSlotCommit {
    match slot {
        None => crypto_sp::SigSlotCommit::default(),
        Some(s) => crypto_sp::SigSlotCommit {
            sig: convert_merkle_signature(s.sig.as_ref()),
            l: s.l,
        },
    }
}

fn convert_participant(p: Option<&WireParticipant>) -> crypto_sp::Participant {
    let (commitment, key_lifetime, weight) = match p {
        None => ([0u8; 64], 0, 0),
        Some(p) => {
            let (commitment, key_lifetime) = match p.pk.as_ref() {
                Some(v) => (v.commitment, v.key_lifetime),
                None => ([0u8; 64], 0),
            };
            (commitment, key_lifetime, p.weight)
        }
    };
    crypto_sp::Participant {
        pk: merklesig::Verifier {
            commitment,
            key_lifetime,
        },
        weight,
    }
}

fn convert_reveal(r: &WireReveal) -> crypto_sp::Reveal {
    crypto_sp::Reveal {
        sig_slot: convert_sig_slot(r.sig_slot.as_ref()),
        part: convert_participant(r.part.as_ref()),
    }
}

fn convert_state_proof(sp: &StateProofBody) -> Result<crypto_sp::StateProof, String> {
    let mut reveals = BTreeMap::new();
    if let Some(rs) = &sp.reveals {
        for (pos, r) in rs {
            reveals.insert(*pos, convert_reveal(r));
        }
    }
    Ok(crypto_sp::StateProof {
        sig_commit: sp.sig_commit.to_vec(),
        signed_weight: sp.signed_weight,
        sig_proofs: convert_merkle_proof(sp.sig_proofs.as_ref()),
        part_proofs: convert_merkle_proof(sp.part_proofs.as_ref()),
        merkle_signature_salt_version: sp.merkle_signature_salt_version,
        reveals,
        positions_to_reveal: sp.positions_to_reveal.clone().unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::LedgerState;
    use algo_types::consensus::CONSENSUS_V41;
    use algo_types::{Address, BlockHeader, Round};
    use serde_bytes::ByteBuf;
    use std::collections::BTreeMap as StdBTreeMap;

    fn put_header(store: &mut LedgerState, hdr: &BlockHeader) {
        let bytes = algo_codec::canonical_encode_block_header(hdr);
        store
            .put_block(hdr.round.0, &hdr.current_protocol, &bytes, &[])
            .unwrap();
    }

    /// Build a `"spt"` tracking value with the given `n`/`v`/`t` fields under
    /// map key `0` (`protocol.StateProofBasic`), matching the wire shape
    /// `block_header::state_proof_next_round`/`state_proof_voters_commitment`/
    /// `state_proof_online_total_weight` read back out.
    fn tracking_value(
        next: u64,
        voters_commitment: &[u8],
        total_weight: u64,
    ) -> Option<rmpv::Value> {
        let mut fields = Vec::new();
        if next != 0 {
            fields.push((rmpv::Value::from("n"), rmpv::Value::from(next)));
        }
        if !voters_commitment.is_empty() {
            fields.push((
                rmpv::Value::from("v"),
                rmpv::Value::Binary(voters_commitment.to_vec()),
            ));
        }
        if total_weight != 0 {
            fields.push((rmpv::Value::from("t"), rmpv::Value::from(total_weight)));
        }
        Some(rmpv::Value::Map(vec![(
            rmpv::Value::from(0u64),
            rmpv::Value::Map(fields),
        )]))
    }

    fn header_at(round: u64, protocol: &str, tracking: Option<rmpv::Value>) -> BlockHeader {
        BlockHeader {
            round: Round(round),
            current_protocol: protocol.to_string(),
            state_proof_tracking: tracking,
            ..BlockHeader::default()
        }
    }

    #[test]
    fn rejects_unsupported_state_proof_type() {
        let store = LedgerState::new();
        let ctx = ApplyContext::new_replay(0, Address::ZERO, 10);
        let txn = Transaction {
            txn_type: "stpf".into(),
            state_proof_type: 1,
            ..Default::default()
        };

        let err = apply_state_proof(&store, &ctx, &txn).unwrap_err();
        assert!(
            format!("{err}").contains("not supported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_round_mismatch() {
        let mut store = LedgerState::new();
        put_header(
            &mut store,
            &header_at(9, CONSENSUS_V41, tracking_value(500, &[], 0)),
        );
        let ctx = ApplyContext::new_replay(0, Address::ZERO, 10);

        let txn = Transaction {
            txn_type: "stpf".into(),
            state_proof_message: Some(StateProofMessage {
                last_attested_round: 600,
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = apply_state_proof(&store, &ctx, &txn).unwrap_err();
        assert!(
            format!("{err}").contains("expected different state proof round"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_when_state_proof_next_is_zero() {
        // A ledger that has never initialized StateProofNext (n absent/0)
        // must reject any state proof, matching go's `nextStateProofRnd == 0`
        // guard (`ledger/apply/stateproof.go:45`).
        let mut store = LedgerState::new();
        put_header(&mut store, &header_at(9, CONSENSUS_V41, None));
        let ctx = ApplyContext::new_replay(0, Address::ZERO, 10);

        let txn = Transaction {
            txn_type: "stpf".into(),
            state_proof_message: Some(StateProofMessage {
                last_attested_round: 256,
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = apply_state_proof(&store, &ctx, &txn).unwrap_err();
        assert!(
            format!("{err}").contains("expected different state proof round"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_insufficient_signed_weight_when_validating() {
        let mut store = LedgerState::new();
        // Round-matching setup: round 256's txn expects a proof for round 256
        // (offset == 0 branch), so the previous header (255) carries n=256.
        put_header(
            &mut store,
            &header_at(255, CONSENSUS_V41, tracking_value(256, &[], 0)),
        );
        // last_round_hdr (round 256) -- only its protocol matters here.
        put_header(&mut store, &header_at(256, CONSENSUS_V41, None));
        // voters_hdr (round 256 - 256 = 0): a large online total weight, so
        // the round-256-== atRound branch demands the full amount.
        put_header(
            &mut store,
            &header_at(0, CONSENSUS_V41, tracking_value(0, &[9u8; 64], 1_000_000)),
        );

        // ctx.round == last_attested_round (offset == 0) => go's
        // `calculateAcceptableStateProofWeight` demands the *full* online
        // total weight (1_000_000) be signed.
        let mut ctx = ApplyContext::new_replay(0, Address::ZERO, 256);
        ctx.validate = true;

        let txn = Transaction {
            txn_type: "stpf".into(),
            state_proof_message: Some(StateProofMessage {
                last_attested_round: 256,
                ..Default::default()
            }),
            state_proof: Some(StateProofBody {
                signed_weight: 100, // far below the 1_000_000 required
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = apply_state_proof(&store, &ctx, &txn).unwrap_err();
        assert!(
            format!("{err}").contains("insufficient weight"),
            "unexpected error: {err}"
        );
    }

    /// Issue #632: the verification-context tracker must survive the
    /// voters-round block header being pruned/unavailable — the whole point
    /// of a dedicated tracker (`ledger/spverificationtracker.go`) rather than
    /// go's pre-v38 `gatherVerificationContextUsingBlockHeaders` fallback.
    /// Without a tracker entry, deleting the voters header (round 0) makes
    /// `resolve_verification_context` fail; with one recorded (as
    /// `apply::apply_block_impl` would on every applied "voters round"
    /// block), it must still succeed.
    #[test]
    fn tracker_survives_voters_header_pruning() {
        const LAST_ATTESTED: u64 = 256;
        const VOTERS_ROUND: u64 = 0;

        let mut store = LedgerState::new();
        put_header(
            &mut store,
            &header_at(255, CONSENSUS_V41, tracking_value(LAST_ATTESTED, &[], 0)),
        );
        put_header(&mut store, &header_at(LAST_ATTESTED, CONSENSUS_V41, None));
        let voters_commitment = vec![7u8; 64];
        put_header(
            &mut store,
            &header_at(
                VOTERS_ROUND,
                CONSENSUS_V41,
                tracking_value(0, &voters_commitment, 42),
            ),
        );

        // Baseline: with the voters header present, resolution succeeds via
        // the header-derived fallback.
        let ctx_before =
            resolve_verification_context(&store, LAST_ATTESTED).expect("header path must work");
        assert_eq!(ctx_before.voters_commitment, voters_commitment);
        assert_eq!(ctx_before.online_total_weight, 42);

        // Prune the voters header (round 0) -- simulates it having fallen
        // out of retention. The header-derived path can no longer resolve
        // this round.
        store.forget_before(1).unwrap();
        assert!(store.get_block_header(VOTERS_ROUND).unwrap().is_none());
        let err = resolve_verification_context(&store, LAST_ATTESTED).unwrap_err();
        assert!(
            format!("{err}").contains("no header for voters round"),
            "expected the header-path failure without a tracker entry, got: {err}"
        );

        // Record the tracker entry for that voters-round block (as
        // `apply_block_impl` would have when round 0 was originally
        // applied), then confirm resolution succeeds even with the header
        // still gone.
        record_state_proof_verification_context(
            &mut store,
            VOTERS_ROUND,
            CONSENSUS_V41,
            &tracking_value(0, &voters_commitment, 42),
            algo_types::consensus::consensus_params_for_version(CONSENSUS_V41)
                .unwrap()
                .state_proof_interval,
        )
        .unwrap();

        let ctx_after = resolve_verification_context(&store, LAST_ATTESTED)
            .expect("tracker path must succeed without the header");
        assert_eq!(ctx_after.voters_commitment, voters_commitment);
        assert_eq!(ctx_after.online_total_weight, 42);
        assert_eq!(ctx_after.version, CONSENSUS_V41);
    }

    #[test]
    fn tracker_prunes_entries_before_new_state_proof_next() {
        let mut store = LedgerState::new();
        let ctx = VerificationContext {
            voters_commitment: vec![1, 2, 3],
            online_total_weight: 10,
            version: CONSENSUS_V41.to_string(),
        };
        store
            .put_state_proof_verification_context(256, &encode_verification_context(&ctx))
            .unwrap();
        store
            .put_state_proof_verification_context(512, &encode_verification_context(&ctx))
            .unwrap();

        prune_state_proof_verification_contexts(&mut store, 512).unwrap();

        assert!(store
            .get_state_proof_verification_context(256)
            .unwrap()
            .is_none());
        assert!(store
            .get_state_proof_verification_context(512)
            .unwrap()
            .is_some());
    }

    #[test]
    fn record_state_proof_verification_context_ignores_non_voters_rounds() {
        let mut store = LedgerState::new();
        record_state_proof_verification_context(
            &mut store,
            5, // not a multiple of any real StateProofInterval
            CONSENSUS_V41,
            &tracking_value(0, &[9u8; 32], 100),
            256,
        )
        .unwrap();
        // 5 + 256 = 261 -- must not have been recorded.
        assert!(store
            .get_state_proof_verification_context(261)
            .unwrap()
            .is_none());
    }

    /// Genuine, end-to-end accept case: real Falcon-1024 keys/signatures and
    /// real merkle vector-commitment trees, verified through the full
    /// `apply_state_proof` path (round matching, block-header-based
    /// verification-context resolution, wire<->crypto conversion, and the
    /// real `crypto/stateproof.Verifier.Verify` port) against real `v41`
    /// consensus parameters (`StateProofWeightThreshold` = 30%,
    /// `StateProofStrengthTarget` = 256) -- not a mock.
    ///
    /// Uses a single participant holding the entire online weight (so every
    /// sampled coin trivially falls within its `[0, weight)` range,
    /// regardless of the coin's value) revealed `NUM_REVEALS` times -- the
    /// smallest reveal count that satisfies the real `verifyWeights`
    /// security bound at these real v41 parameters (independent of the
    /// weight's actual magnitude, since the bound depends only on the
    /// `signedWeight`/`provenWeight` ratio, which the 30% threshold fixes).
    /// A multi-participant coin-sampling round trip (where *which* position
    /// gets revealed depends on the deterministic coin draw, not a fixed
    /// list) is exercised by go-algorand's own state proofs on a live
    /// network; the crypto-layer tests in `algo-consensus-crypto::stateproof`
    /// additionally cover multi-way tampering (forged signature, tampered
    /// commitment root, tampered weight) with real crypto.
    #[test]
    fn accepts_genuine_state_proof_and_advances() {
        use algo_consensus_crypto::{merklesig, stateproof as crypto_sp};

        const WEIGHT: u64 = 1_000_000_000;
        const NUM_REVEALS: usize = 150;
        const LAST_ATTESTED: u64 = 256;
        const VOTERS_ROUND: u64 = 0;

        // Single participant holding the full online weight. (No signing
        // yet: the message hash participants sign over depends on
        // `voters_commitment`, i.e. the participant-commitment tree root --
        // so keys/the participant tree must exist first.)
        let secrets = merklesig::Secrets::new(LAST_ATTESTED, LAST_ATTESTED, 1).unwrap();
        let participant = crypto_sp::Participant {
            pk: secrets.get_verifier(),
            weight: WEIGHT,
        };

        struct SigArray(Vec<crypto_sp::SigSlotCommit>);
        impl merklearray::Array for SigArray {
            fn length(&self) -> u64 {
                self.0.len() as u64
            }
            fn marshal(
                &self,
                pos: u64,
            ) -> Result<Box<dyn merklearray::Hashable>, merklearray::MerkleError> {
                // Re-derive via the crate-internal builder is not accessible
                // here (private); build the leaf inline using the same
                // format `build_committable_signature` produces for a
                // non-empty, valid slot.
                let slot = &self.0[pos as usize];
                let sig_bytes = slot
                    .sig
                    .get_fixed_length_hashable_representation()
                    .map_err(|e| merklearray::MerkleError::ArrayError(e.to_string()))?;
                struct Leaf {
                    l: u64,
                    sig_bytes: Vec<u8>,
                }
                impl merklearray::Hashable for Leaf {
                    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
                        let mut data = Vec::with_capacity(8 + self.sig_bytes.len());
                        data.extend_from_slice(&self.l.to_le_bytes());
                        data.extend_from_slice(&self.sig_bytes);
                        (b"sps", data)
                    }
                }
                Ok(Box::new(Leaf {
                    l: slot.l,
                    sig_bytes,
                }))
            }
        }

        struct PartArray(Vec<crypto_sp::Participant>);
        impl merklearray::Array for PartArray {
            fn length(&self) -> u64 {
                self.0.len() as u64
            }
            fn marshal(
                &self,
                pos: u64,
            ) -> Result<Box<dyn merklearray::Hashable>, merklearray::MerkleError> {
                let p = &self.0[pos as usize];
                struct Leaf {
                    weight: u64,
                    key_lifetime: u64,
                    commitment: [u8; 64],
                }
                impl merklearray::Hashable for Leaf {
                    fn to_be_hashed(&self) -> (&[u8], Vec<u8>) {
                        let mut data = Vec::with_capacity(80);
                        data.extend_from_slice(&self.weight.to_le_bytes());
                        data.extend_from_slice(&self.key_lifetime.to_le_bytes());
                        data.extend_from_slice(&self.commitment);
                        (b"spp", data)
                    }
                }
                Ok(Box::new(Leaf {
                    weight: p.weight,
                    key_lifetime: p.pk.key_lifetime,
                    commitment: p.pk.commitment,
                }))
            }
        }

        let factory = merklearray::HashFactory::new(merklearray::HashType::Sha512_256);

        // Participant-commitment tree first: `voters_commitment` (its root)
        // is part of the message the participant signs over, so it must be
        // known before signing happens.
        let part_tree = merklearray::build_vector_commitment_tree(
            &PartArray(vec![participant.clone()]),
            factory,
        )
        .unwrap();
        let part_commit = part_tree.root();

        let message = algo_types::StateProofMessage {
            block_headers_commitment: ByteBuf::new(),
            voters_commitment: ByteBuf::from(part_commit.clone()),
            ln_proven_weight: 0, // informational only; not checked by apply
            first_attested_round: 0,
            last_attested_round: LAST_ATTESTED,
        };
        let msg_hash = state_proof_message_hash(&message);

        // Sign: the participant's Falcon signature is over `msg_hash`, which
        // depends on the real `voters_commitment` above.
        let signer = secrets.get_signer(LAST_ATTESTED);
        let sig = signer.sign_bytes(&msg_hash).unwrap();
        let sig_slot = crypto_sp::SigSlotCommit { sig, l: 0 };

        let sig_tree =
            merklearray::build_vector_commitment_tree(&SigArray(vec![sig_slot.clone()]), factory)
                .unwrap();
        let sig_commit = sig_tree.root();
        let sig_proof = sig_tree.prove(&[0]).unwrap();
        let part_proof = part_tree.prove(&[0]).unwrap();

        let mut reveals = StdBTreeMap::new();
        reveals.insert(
            0u64,
            crypto_sp::Reveal {
                sig_slot,
                part: participant,
            },
        );

        let crypto_proof = crypto_sp::StateProof {
            sig_commit,
            signed_weight: WEIGHT,
            sig_proofs: sig_proof,
            part_proofs: part_proof,
            merkle_signature_salt_version: 0,
            reveals,
            // The lone participant's [0, WEIGHT) range covers every possible
            // sampled coin, so revealing position 0 NUM_REVEALS times
            // satisfies coin-weight sampling regardless of the actual coin
            // values drawn.
            positions_to_reveal: vec![0u64; NUM_REVEALS],
        };

        // ── Convert to wire types (the reverse of `convert_state_proof`) ──
        let wire_proof = wire_state_proof(&crypto_proof);

        // ── Ledger headers ──────────────────────────────────────────────
        let mut store = LedgerState::new();
        put_header(
            &mut store,
            &header_at(
                LAST_ATTESTED - 1,
                CONSENSUS_V41,
                tracking_value(LAST_ATTESTED, &[], 0),
            ),
        );
        put_header(&mut store, &header_at(LAST_ATTESTED, CONSENSUS_V41, None));
        put_header(
            &mut store,
            &header_at(
                VOTERS_ROUND,
                CONSENSUS_V41,
                tracking_value(0, &part_commit, WEIGHT),
            ),
        );

        let mut ctx = ApplyContext::new_replay(0, Address::ZERO, LAST_ATTESTED);
        ctx.validate = true;

        let txn = Transaction {
            txn_type: "stpf".into(),
            state_proof_message: Some(message),
            state_proof: Some(wire_proof),
            ..Default::default()
        };

        apply_state_proof(&store, &ctx, &txn)
            .expect("genuine state proof must be accepted end-to-end");
    }

    // ── crypto -> wire conversion (test-only; the reverse of the
    // wire -> crypto conversion this module uses at runtime) ──────────────

    fn wire_hash_factory(hf: merklearray::HashFactory) -> algo_types::HashFactory {
        algo_types::HashFactory {
            hash_type: hf.hash_type as u16,
        }
    }

    fn wire_merkle_proof(p: &merklearray::Proof) -> WireMerkleProof {
        WireMerkleProof {
            path: Some(
                p.path
                    .iter()
                    .map(|d| {
                        if d.is_empty() {
                            None
                        } else {
                            Some(ByteBuf::from(d.clone()))
                        }
                    })
                    .collect(),
            ),
            hash_factory: Some(wire_hash_factory(p.hash_factory)),
            tree_depth: p.tree_depth,
        }
    }

    fn wire_falcon_verifier(
        v: &algo_consensus_crypto::merklesig::FalconVerifier,
    ) -> WireFalconVerifier {
        WireFalconVerifier {
            public_key: ByteBuf::from(v.k.to_vec()),
        }
    }

    fn wire_merkle_signature(
        s: &algo_consensus_crypto::merklesig::Signature,
    ) -> WireMerkleSignature {
        WireMerkleSignature {
            signature: ByteBuf::from(s.signature.clone()),
            vector_commitment_index: s.vector_commitment_index,
            proof: Some(wire_merkle_proof(&s.proof.proof)),
            verifying_key: Some(wire_falcon_verifier(&s.verifying_key)),
        }
    }

    fn wire_sig_slot(s: &algo_consensus_crypto::stateproof::SigSlotCommit) -> WireSigSlotCommit {
        WireSigSlotCommit {
            sig: Some(wire_merkle_signature(&s.sig)),
            l: s.l,
        }
    }

    fn wire_mss_verifier(
        v: &algo_consensus_crypto::merklesig::Verifier,
    ) -> algo_types::MerkleSignatureVerifier {
        algo_types::MerkleSignatureVerifier {
            commitment: v.commitment,
            key_lifetime: v.key_lifetime,
        }
    }

    fn wire_participant(p: &algo_consensus_crypto::stateproof::Participant) -> WireParticipant {
        WireParticipant {
            pk: Some(wire_mss_verifier(&p.pk)),
            weight: p.weight,
        }
    }

    fn wire_reveal(r: &algo_consensus_crypto::stateproof::Reveal) -> WireReveal {
        WireReveal {
            sig_slot: Some(wire_sig_slot(&r.sig_slot)),
            part: Some(wire_participant(&r.part)),
        }
    }

    fn wire_state_proof(sp: &algo_consensus_crypto::stateproof::StateProof) -> StateProofBody {
        StateProofBody {
            sig_commit: ByteBuf::from(sp.sig_commit.clone()),
            signed_weight: sp.signed_weight,
            sig_proofs: Some(wire_merkle_proof(&sp.sig_proofs)),
            part_proofs: Some(wire_merkle_proof(&sp.part_proofs)),
            merkle_signature_salt_version: sp.merkle_signature_salt_version,
            reveals: Some(
                sp.reveals
                    .iter()
                    .map(|(k, v)| (*k, wire_reveal(v)))
                    .collect(),
            ),
            positions_to_reveal: Some(sp.positions_to_reveal.clone()),
        }
    }
}
