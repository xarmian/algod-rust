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

//! Construction of a `StateProofMessage` from local ledger state -- the
//! signer/prover-side counterpart to [`crate::apply_stateproof`]'s
//! verify-only reading of an already-built message.
//!
//! Ports go-algorand's `stateproof/stateproofMessageGenerator.go`
//! (`GenerateStateProofMessage`, `createHeaderCommitment`,
//! `calculateLnProvenWeight`, `FetchLightHeaders`) -- issue #814's
//! live-daemon-wiring scope. A signing/proving node needs this to build the
//! exact message its local participation keys sign over, and to reconstruct
//! the message the `SigCollector`/[`algo_consensus_crypto::stateproof::Prover`]
//! hashes when gathering peers' signatures for the same round.

use algo_consensus_crypto::light_block_header::{LightBlockHeader, LightBlockHeaderArray};
use algo_consensus_crypto::merklearray::{build_vector_commitment_tree, HashFactory, HashType};
use algo_consensus_crypto::stateproof::calculate_ln_proven_weight;
use algo_error::AlgoError;
use algo_types::consensus::ConsensusParams;
use algo_types::{BlockHeader, StateProofMessage};
use serde_bytes::ByteBuf;

use crate::block_header::{state_proof_online_total_weight, state_proof_voters_commitment};
use crate::store_trait::LedgerStore;

fn ledger_err(message: impl Into<String>) -> AlgoError {
    AlgoError::Ledger {
        message: message.into(),
    }
}

/// Build the [`LightBlockHeader`] go's `BlockHeader.ToLightBlockHeader`
/// would produce for `hdr`, given the resolved consensus `params` governing
/// it (`StateProofBlockHashInLightHeader`).
fn to_light_block_header(hdr: &BlockHeader, params: &ConsensusParams) -> LightBlockHeader {
    let mut light = LightBlockHeader {
        round: hdr.round.0,
        genesis_hash: hdr.genesis_hash,
        sha256_txn_commitment: hdr.txn256,
        ..Default::default()
    };
    if params.state_proof_block_hash_in_light_header {
        light.block_hash = algo_codec::compute_block_header_digest(hdr).0;
    } else {
        light.seed = hdr.seed;
    }
    light
}

/// Fetch the `state_proof_interval` light headers ending at (and including)
/// `latest_round`, in round order.
///
/// Matches go's `FetchLightHeaders` (`stateproofMessageGenerator.go:123`).
pub fn fetch_light_headers<L: LedgerStore>(
    store: &L,
    state_proof_interval: u64,
    latest_round: u64,
) -> Result<Vec<LightBlockHeader>, AlgoError> {
    let first_round = latest_round.saturating_sub(state_proof_interval).saturating_add(1);
    let mut out = Vec::with_capacity(state_proof_interval as usize);
    for round in first_round..=latest_round {
        let hdr = store.get_block_header(round)?.ok_or_else(|| {
            ledger_err(format!(
                "fetch_light_headers: no block header retained for round {round} \
                 (needed to build the state-proof header commitment for round \
                 {latest_round}, interval {state_proof_interval})"
            ))
        })?;
        let params = algo_types::consensus::consensus_params_for_version(&hdr.current_protocol)
            .ok_or_else(|| {
                ledger_err(format!(
                    "fetch_light_headers: unknown consensus protocol '{}' at round {round}",
                    hdr.current_protocol
                ))
            })?;
        out.push(to_light_block_header(&hdr, &params));
    }
    Ok(out)
}

/// Build the `BlockHeadersCommitment`: the SHA-256 vector-commitment tree
/// root over every light header in the just-closed interval.
///
/// Matches go's `createHeaderCommitment`
/// (`stateproofMessageGenerator.go:98`).
pub fn create_header_commitment<L: LedgerStore>(
    store: &L,
    params: &ConsensusParams,
    latest_round_header: &BlockHeader,
) -> Result<Vec<u8>, AlgoError> {
    let interval = params.state_proof_interval;
    if latest_round_header.round.0 < interval {
        return Err(ledger_err(
            "create_header_commitment: state-proof round must be >= state_proof_interval",
        ));
    }
    let light_headers = fetch_light_headers(store, interval, latest_round_header.round.0)?;
    let array = LightBlockHeaderArray(light_headers);
    let factory = HashFactory::new(HashType::Sha256);
    let tree = build_vector_commitment_tree(&array, factory)
        .map_err(|e| ledger_err(format!("create_header_commitment: {e}")))?;
    Ok(tree.root())
}

/// Build the `StateProofMessage` for the state proof attesting to `round`
/// (a `StateProofInterval` multiple).
///
/// Matches go's `GenerateStateProofMessage`
/// (`stateproofMessageGenerator.go:55`): the block-headers commitment over
/// the just-closed interval, the voters commitment carried on `round`'s own
/// header (the vector-commitment root over the *previous* interval's
/// selected online accounts -- see `crate::voters_tracker`), the
/// natural-log-encoded proven weight, and the attested round range
/// `(votersRound+1 ..= round)`.
pub fn generate_state_proof_message<L: LedgerStore>(
    store: &L,
    round: u64,
) -> Result<StateProofMessage, AlgoError> {
    let hdr = store.get_block_header(round)?.ok_or_else(|| {
        ledger_err(format!(
            "generate_state_proof_message: no block header for round {round}"
        ))
    })?;
    let params = algo_types::consensus::consensus_params_for_version(&hdr.current_protocol)
        .ok_or_else(|| {
            ledger_err(format!(
                "generate_state_proof_message: unknown consensus protocol '{}'",
                hdr.current_protocol
            ))
        })?;

    let voters_round = round.saturating_sub(params.state_proof_interval);
    let commitment = create_header_commitment(store, &params, &hdr)?;

    let total_weight = state_proof_online_total_weight(&hdr.state_proof_tracking);
    let ln_proven_weight = calculate_ln_proven_weight(total_weight, params.state_proof_weight_threshold)
        .map_err(|e| ledger_err(format!("generate_state_proof_message: {e}")))?;

    Ok(StateProofMessage {
        block_headers_commitment: ByteBuf::from(commitment),
        voters_commitment: ByteBuf::from(state_proof_voters_commitment(&hdr.state_proof_tracking)),
        ln_proven_weight,
        first_attested_round: voters_round + 1,
        last_attested_round: hdr.round.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::LedgerState;
    use algo_types::consensus::CONSENSUS_V41;
    use algo_types::Round;

    fn tracking_value(voters_commitment: &[u8], total_weight: u64) -> Option<rmpv::Value> {
        let mut fields = Vec::new();
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

    fn put_header(store: &mut LedgerState, hdr: &BlockHeader) {
        let bytes = algo_codec::canonical_encode_block_header(hdr);
        store
            .put_block(hdr.round.0, &hdr.current_protocol, &bytes, &[])
            .unwrap();
    }

    fn header_at(round: u64, tracking: Option<rmpv::Value>) -> BlockHeader {
        BlockHeader {
            round: Round(round),
            current_protocol: CONSENSUS_V41.to_string(),
            genesis_hash: [0xAB; 32],
            txn256: [round as u8; 32],
            state_proof_tracking: tracking,
            ..BlockHeader::default()
        }
    }

    const INTERVAL: u64 = 256; // v41's StateProofInterval

    #[test]
    fn fetch_light_headers_errors_when_a_round_is_missing() {
        let store = LedgerState::new();
        let err = fetch_light_headers(&store, INTERVAL, INTERVAL);
        assert!(err.is_err(), "no headers retained -> must error, not panic");
    }

    #[test]
    fn fetch_light_headers_returns_the_full_interval_in_order() {
        let mut store = LedgerState::new();
        for r in 1..=INTERVAL {
            put_header(&mut store, &header_at(r, None));
        }
        let headers = fetch_light_headers(&store, INTERVAL, INTERVAL).unwrap();
        assert_eq!(headers.len(), INTERVAL as usize);
        for (i, h) in headers.iter().enumerate() {
            assert_eq!(h.round, (i as u64) + 1);
        }
        // v41 has StateProofBlockHashInLightHeader=true -> block_hash set,
        // seed left zero.
        assert_ne!(headers[0].block_hash, [0u8; 32]);
        assert_eq!(headers[0].seed, [0u8; 32]);
    }

    #[test]
    fn generate_state_proof_message_builds_expected_fields() {
        let mut store = LedgerState::new();
        for r in 1..=INTERVAL {
            put_header(&mut store, &header_at(r, None));
        }
        let voters_commitment = vec![0xCDu8; 64];
        let total_weight = 5_000_000u64;
        put_header(
            &mut store,
            &header_at(INTERVAL, tracking_value(&voters_commitment, total_weight)),
        );

        let msg = generate_state_proof_message(&store, INTERVAL).unwrap();
        assert_eq!(msg.voters_commitment.as_ref(), voters_commitment.as_slice());
        assert_eq!(msg.first_attested_round, 1, "votersRound(0)+1");
        assert_eq!(msg.last_attested_round, INTERVAL);
        assert!(!msg.block_headers_commitment.is_empty());

        let expected_ln = algo_consensus_crypto::stateproof::calculate_ln_proven_weight(
            total_weight,
            algo_types::consensus::consensus_params_for_version(CONSENSUS_V41)
                .unwrap()
                .state_proof_weight_threshold,
        )
        .unwrap();
        assert_eq!(msg.ln_proven_weight, expected_ln);
    }

    #[test]
    fn generate_state_proof_message_is_deterministic() {
        let mut store = LedgerState::new();
        for r in 1..=INTERVAL {
            put_header(&mut store, &header_at(r, None));
        }
        put_header(
            &mut store,
            &header_at(INTERVAL, tracking_value(&[0xEEu8; 64], 42)),
        );
        let a = generate_state_proof_message(&store, INTERVAL).unwrap();
        let b = generate_state_proof_message(&store, INTERVAL).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn generate_state_proof_message_errors_on_unknown_round() {
        let store = LedgerState::new();
        assert!(generate_state_proof_message(&store, INTERVAL).is_err());
    }
}
