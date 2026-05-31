//! Top-level participation key generation orchestrator.
//!
//! Mirrors `../go-algorand/data/account/participation.go:219-269`
//! (v4.5.1-stable): validates inputs, computes the OTS batch range,
//! generates VRF + OTS + Falcon MSS secrets, persists the full set into a
//! fresh erasable partkey DB. Used by `algokey part generate`
//! ([[TASK-180]]).

use algo_consensus_crypto::{
    merklesig, one_time_id_for_round, OneTimeSignatureSecrets, VrfKeypair,
};
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_CURRENT_VERSION};
use algo_types::{Address, Round};
use thiserror::Error;

use crate::erasable_db::ErasableDb;
use crate::participation::{
    default_key_dilution, persist_participation, Participation, PersistError,
};

/// Errors from [`fill_db_with_participation_keys`].
#[derive(Debug, Error)]
pub enum FillError {
    /// `last_valid < first_valid`. Mirrors Go's wording at
    /// `participation.go:228`.
    #[error("FillDBWithParticipationKeys: firstValid {first} is after lastValid {last}")]
    InvalidRange { first: u64, last: u64 },
    /// `last - first` exceeds `ConsensusParams.MaxKeyregValidPeriod`.
    /// Mirrors Go's wording at `participation.go:233`.
    #[error("the validity period for mss is too large: the limit is {limit}")]
    ValidityPeriodTooLarge { limit: u64 },
    /// Underlying state-proof secret generation failed (Falcon keygen or
    /// merkle build).
    #[error("state proof key generation: {0}")]
    StateProof(String),
    /// Persistence (partkey schema install or row INSERT) failed.
    #[error("persist: {0}")]
    Persist(#[from] PersistError),
}

/// Generate and persist a fresh participation key set into `db`.
///
/// Mirrors `account.FillDBWithParticipationKeys` (`participation.go:225`):
///
/// 1. Validate `last_valid >= first_valid`.
/// 2. Read `MaxKeyregValidPeriod` from the current consensus params; if
///    non-zero, error when `last - first > limit`.
/// 3. Decompose the round range into OTS `(batch, offset)` IDs via
///    `OneTimeIDForRound`; the number of OTS batches is
///    `last_id.batch - first_id.batch + 1`.
/// 4. Generate cryptographic material: voting OTS secrets, VRF keypair,
///    Falcon MSS secrets (one ephemeral key per round multiple of
///    `KEY_LIFETIME_DEFAULT = 256` in the participation window).
/// 5. Assemble the [`Participation`] and persist via
///    [`persist_participation`], which chains in the StateProofKeys
///    table writer when state-proof secrets are present.
///
/// Returns the freshly-generated `Participation`. The on-disk
/// representation is byte-equal (modulo key randomness) to what Go's
/// `FillDBWithParticipationKeys` produces; the round-trip with the
/// existing Phase B reader is exercised by the integration test.
pub fn fill_db_with_participation_keys(
    db: &mut ErasableDb,
    address: Address,
    first_valid: Round,
    last_valid: Round,
    key_dilution: u64,
) -> Result<Participation, FillError> {
    if last_valid.0 < first_valid.0 {
        return Err(FillError::InvalidRange {
            first: first_valid.0,
            last: last_valid.0,
        });
    }

    // Enforce `MaxKeyregValidPeriod` from the *current* consensus version,
    // matching go's `FillDBWithParticipationKeys`, which reads
    // `config.Consensus[protocol.ConsensusCurrentVersion].MaxKeyregValidPeriod`
    // (../go-algorand/data/account/participation.go:231). We resolve the params
    // explicitly from `CONSENSUS_CURRENT_VERSION` (V41) rather than relying on
    // `ConsensusParams::default()` — the bound is consensus-critical, so the
    // version it comes from must be unambiguous, not an implementation detail of
    // `Default`. Mirrors the live-params resolution in the server path's
    // `generate_participation_keys` (node_interface_impl.rs).
    let max_valid_period = consensus_params_for_version(CONSENSUS_CURRENT_VERSION)
        .map(|p| p.max_keyreg_valid_period)
        .unwrap_or(0);
    if max_valid_period != 0 && last_valid.0.saturating_sub(first_valid.0) > max_valid_period {
        return Err(FillError::ValidityPeriodTooLarge {
            limit: max_valid_period,
        });
    }

    // Default the dilution if the caller passed zero. Matches the way
    // `algokey part generate` defaults the flag before invoking the
    // orchestrator (`part.go:59-61`); we duplicate the default here so
    // direct callers also benefit.
    let key_dilution = if key_dilution == 0 {
        default_key_dilution(first_valid, last_valid)
    } else {
        key_dilution
    };

    // OTS batch range.
    let first_id = one_time_id_for_round(first_valid.0, key_dilution);
    let last_id = one_time_id_for_round(last_valid.0, key_dilution);
    let num_batches = last_id.batch - first_id.batch + 1;

    // Cryptographic material.
    let voting = OneTimeSignatureSecrets::generate(first_id.batch, num_batches);
    let vrf = VrfKeypair::generate();
    let state_proof_secrets =
        merklesig::Secrets::new(first_valid.0, last_valid.0, merklesig::KEY_LIFETIME_DEFAULT)
            .map_err(|e| FillError::StateProof(format!("{e}")))?;

    let part = Participation {
        parent: address,
        vrf,
        voting,
        first_valid,
        last_valid,
        key_dilution,
        state_proof_secrets: Some(state_proof_secrets),
    };

    persist_participation(db, &part)?;
    Ok(part)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_range_matches_go_wording() {
        // We can't easily construct an ErasableDb in a unit test; we just
        // assert the error message formatting, since the early `if` guards
        // before we touch the DB.
        let err = FillError::InvalidRange {
            first: 100,
            last: 50,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("firstValid 100 is after lastValid 50"),
            "actual: {msg}"
        );
    }

    #[test]
    fn validity_period_too_large_matches_go_wording() {
        let err = FillError::ValidityPeriodTooLarge { limit: 16777215 };
        let msg = format!("{err}");
        assert!(
            msg.contains("the validity period for mss is too large: the limit is 16777215"),
            "actual: {msg}"
        );
    }
}
