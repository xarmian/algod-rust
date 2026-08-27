//! Ledger-side application of `stpf` (StateProof) transactions.
//!
//! Port of go-algorand's `ledger/apply/stateproof.go`'s `apply.StateProof`
//! plus the weight/round checks from `stateproof/verify/stateproof.go`'s
//! `ValidateStateProof` — the actual cryptographic core
//! (`crypto/stateproof.Verifier.Verify`) lives in
//! `algo_consensus_crypto::stateproof::verify` and is only *called* here.
//!
//! Before this module existed, `apply.rs` applied every `stpf` transaction
//! as a structural no-op with zero verification (see issue #626) — this is
//! the fix: round-window enforcement, voters-header resolution, and the
//! full crypto check are now real.

use algo_error::AlgoError;
use algo_types::{ConsensusParams, Round, Transaction};

use crate::store_trait::LedgerStore;

/// `protocol.StateProofBasic` — the only state proof type accepted on-chain.
const STATE_PROOF_BASIC: u64 = 0;

/// Compute `a*b/divisor` using a `u128` intermediate to avoid `u64`
/// overflow on the multiply, mirroring go's `basics.Muldiv`. Returns `None`
/// if the multiply itself is unrepresentable (never happens for realistic
/// microalgos-scale inputs) or the quotient doesn't fit back in `u64`.
fn muldiv_u64(a: u64, b: u64, divisor: u128) -> Option<u64> {
    let prod = (a as u128).checked_mul(b as u128)?;
    u64::try_from(prod / divisor).ok()
}

/// `stateproof/verify/stateproof.go: calculateAcceptableStateProofWeight`.
///
/// The minimum `SignedWeight` a state proof must carry to be accepted at
/// `first_valid`, given how many rounds have elapsed since
/// `last_attested_round`: 100% while signatures are still being gossiped,
/// linearly relaxing down to `StateProofWeightThreshold` over the second
/// half of the interval, and pinned at that floor beyond it.
///
/// On the arithmetic-overflow path go falls back to "accept any weight"
/// (logs a warning, returns 0) rather than wedging state-proof progress —
/// mirrored here by returning `0` from `muldiv_u64`'s `None`.
fn calculate_acceptable_state_proof_weight(
    total_weight: u64,
    proto: &ConsensusParams,
    last_attested_round: u64,
    first_valid: u64,
) -> u64 {
    let half_period = proto.state_proof_interval / 2;

    let offset = first_valid.saturating_sub(last_attested_round);
    if offset == 0 {
        return total_weight;
    }
    let offset = offset.saturating_sub(half_period);
    if offset == 0 {
        return total_weight;
    }

    let proven_weight = match muldiv_u64(
        total_weight,
        proto.state_proof_weight_threshold as u64,
        1u128 << 32,
    ) {
        Some(w) if w <= total_weight => w,
        _ => return 0,
    };

    if offset >= half_period {
        return proven_weight;
    }

    let diff = total_weight.saturating_sub(proven_weight);
    let divisor = half_period.max(1);
    let scaled = match muldiv_u64(diff, half_period - offset, divisor as u128) {
        Some(s) => s,
        None => return 0,
    };
    proven_weight.saturating_add(scaled)
}

/// `data/stateproofmsg/message.go: Message.Hash()` — `SHA256("spm" ||
/// canonical_msgpack(message))`.
pub fn state_proof_message_hash(msg: &algo_types::StateProofMessage) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let encoded = algo_codec::canonical_encode_state_proof_message(msg);
    let mut hasher = Sha256::new();
    hasher.update(b"spm");
    hasher.update(&encoded);
    hasher.finalize().into()
}

/// The ledger's currently-tracked `StateProofNext` round, as of just before
/// applying round `at_round` — read from the previous block header's own
/// `StateProofTracking` (which every block already carries as
/// consensus-agreed data; see `state_proof_tracking_basic`). Defaults to `0`
/// (never accept) if there is no prior header or state proofs have never
/// been bootstrapped, matching go's initial `StateProofNextRound == 0`.
fn current_state_proof_next<L: LedgerStore>(store: &L, at_round: u64) -> Result<u64, AlgoError> {
    if at_round == 0 {
        return Ok(0);
    }
    let prev_hdr = store.get_block_header(at_round - 1)?;
    Ok(prev_hdr
        .and_then(|h| h.state_proof_tracking_basic())
        .map(|t| t.next_round)
        .unwrap_or(0))
}

/// Apply a `stpf` transaction: type + round-window checks always, full
/// cryptographic verification when `validate` is set. Returns the new
/// `StateProofNext` round on success (`lastRoundInInterval +
/// StateProofInterval`), matching `apply.StateProof`.
///
/// Mirrors `ledger/apply/stateproof.go: StateProof(tx, atRound, sp,
/// validate)`. Uses `gatherVerificationContextUsingBlockHeaders`'s approach
/// unconditionally (deriving the voters commitment / proven weight from the
/// voters block header) rather than go's `StateProofUseTrackerVerification`
/// tracker-backed path — algod-rust has no dedicated state-proof-
/// verification tracker (see issue #626's follow-up), and the header-derived
/// values are the same consensus-committed data either way.
pub fn apply_state_proof<L: LedgerStore>(
    store: &L,
    txn: &Transaction,
    at_round: u64,
    consensus: &ConsensusParams,
    validate: bool,
) -> Result<Round, AlgoError> {
    if txn.state_proof_type != STATE_PROOF_BASIC {
        return Err(AlgoError::Ledger {
            message: format!(
                "applyStateProof: state proof type not supported - type {}",
                txn.state_proof_type
            ),
        });
    }

    let msg = txn
        .state_proof_message
        .as_ref()
        .ok_or_else(|| AlgoError::Ledger {
            message: "applyStateProof: missing state proof message".to_string(),
        })?;
    let last_round_in_interval = msg.last_attested_round;

    let next_state_proof_rnd = current_state_proof_next(store, at_round)?;
    if next_state_proof_rnd == 0 || next_state_proof_rnd != last_round_in_interval {
        return Err(AlgoError::Ledger {
            message: format!(
                "applyStateProof: expected different state proof round - expecting state proof for {next_state_proof_rnd}, but new state proof is for {last_round_in_interval}"
            ),
        });
    }

    if validate {
        if consensus.state_proof_interval == 0 {
            return Err(AlgoError::Ledger {
                message: "applyStateProof: state proofs are not enabled".to_string(),
            });
        }

        let voters_round = last_round_in_interval.saturating_sub(consensus.state_proof_interval);
        let voters_hdr =
            store
                .get_block_header(voters_round)?
                .ok_or_else(|| AlgoError::Ledger {
                    message: format!(
                        "applyStateProof: missing voters block header at round {voters_round}"
                    ),
                })?;
        let tracking = voters_hdr.state_proof_tracking_basic().ok_or_else(|| AlgoError::Ledger {
            message: format!("applyStateProof: voters block header at round {voters_round} has no state proof tracking data"),
        })?;

        let sp = txn.state_proof.as_ref().ok_or_else(|| AlgoError::Ledger {
            message: "applyStateProof: missing state proof body".to_string(),
        })?;

        let acceptable_weight = calculate_acceptable_state_proof_weight(
            tracking.online_total_weight,
            consensus,
            last_round_in_interval,
            at_round,
        );
        if sp.signed_weight < acceptable_weight {
            return Err(AlgoError::Ledger {
                message: format!(
                    "applyStateProof: insufficient weight at round {at_round}: {} < {acceptable_weight}",
                    sp.signed_weight
                ),
            });
        }

        let proven_weight = muldiv_u64(
            tracking.online_total_weight,
            consensus.state_proof_weight_threshold as u64,
            1u128 << 32,
        )
        .ok_or_else(|| AlgoError::Ledger {
            message: format!(
                "applyStateProof: overflow computing provenWeight[{last_round_in_interval}]"
            ),
        })?;

        let hash = state_proof_message_hash(msg);
        algo_consensus_crypto::stateproof::verify(
            &tracking.voters_commitment,
            proven_weight,
            consensus.state_proof_strength_target,
            at_round,
            &hash,
            sp,
        )
        .map_err(|e| AlgoError::Ledger {
            message: format!("applyStateProof: state proof crypto error: {e}"),
        })?;
    }

    Ok(Round(
        last_round_in_interval + consensus.state_proof_interval,
    ))
}
