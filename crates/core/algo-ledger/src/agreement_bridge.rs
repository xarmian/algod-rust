//! Bridge implementation connecting `SqliteLedger` to the agreement protocol's
//! `LedgerReader` and `LedgerWriter` traits.
//!
//! Mirrors go-algorand's `node/impls.go` `agreementLedger` struct which wraps
//! a `*data.Ledger` and implements the `agreement.Ledger` interface.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tracing::warn;

use algo_agreement::{
    Certificate, LedgerError, LedgerReader, LedgerWriter, OnlineAccountData, Seed,
};
use algo_types::consensus::consensus_params_for_version;
use algo_types::{Address, ConsensusParams, Digest, Round};

use crate::sqlite::SqliteLedger;
use crate::store_trait::LedgerStore;

// ---------------------------------------------------------------------------
// AgreementLedgerBridge
// ---------------------------------------------------------------------------

/// Bridges `SqliteLedger` to the agreement protocol's `LedgerReader` and
/// `LedgerWriter` traits.
///
/// Mirrors Go's `agreementLedger` in `node/impls.go`.
///
/// The inner ledger is wrapped in `Arc<Mutex<..>>` to satisfy the `&self`
/// requirement of the agreement traits while allowing interior mutation
/// (block writes, round advancement).
pub struct AgreementLedgerBridge {
    ledger: Arc<Mutex<SqliteLedger>>,
}

impl AgreementLedgerBridge {
    /// Create a new bridge wrapping the given ledger.
    pub fn new(ledger: Arc<Mutex<SqliteLedger>>) -> Self {
        Self { ledger }
    }

    /// Helper: get the protocol version string for a given round by reading
    /// the block header's proto field from the blocks table.
    fn protocol_for_round(&self, round: Round) -> Result<String, LedgerError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;

        // Round 0 uses the genesis protocol.
        if round.0 == 0 {
            return Ok(ledger.protocol().to_string());
        }

        ledger
            .get_block_proto(round.0)
            .map_err(|e| LedgerError::Other(format!("get_block_proto: {e}")))?
            .ok_or(LedgerError::RoundNotAvailable(round))
    }
}

impl LedgerReader for AgreementLedgerBridge {
    fn next_round(&self) -> Round {
        let ledger = match self.ledger.lock() {
            Ok(l) => l,
            Err(e) => {
                warn!("ledger lock poisoned in next_round: {e}");
                return Round(0);
            }
        };
        // next_round = current_round + 1 (current_round is the last committed)
        Round(ledger.current_round().0.saturating_add(1))
    }

    fn seed(&self, round: Round) -> Result<Seed, LedgerError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;

        // The seed is stored in the block header. We need to decode the block
        // header for the given round and extract the seed field.
        let hdr_data = ledger
            .get_block_header_data(round.0)
            .map_err(|e| LedgerError::Other(format!("get_block_header_data: {e}")))?
            .ok_or(LedgerError::RoundNotAvailable(round))?;

        // Parse the msgpack block header to extract the seed.
        // The seed is stored under codec key "seed" as a 32-byte binary.
        extract_seed_from_header(&hdr_data).ok_or_else(|| {
            LedgerError::Other(format!("seed not found in header for round {round}"))
        })
    }

    fn lookup_agreement(
        &self,
        round: Round,
        addr: &Address,
    ) -> Result<OnlineAccountData, LedgerError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;

        // Check that the round is available.
        if round.0 > ledger.current_round().0 {
            return Err(LedgerError::RoundNotAvailable(round));
        }

        // Look up the account data.
        // Note: SqliteLedger stores the latest state snapshot, not per-round
        // historical data. For a full implementation, we would need to support
        // historical lookups (using online accounts table or catchpoint data).
        // For now, we return the current account state which is correct when
        // agreement is operating at the latest round.
        let acct = ledger.get_account(addr).unwrap_or_default();

        Ok(OnlineAccountData {
            micro_algos: acct.micro_algos,
            vote_id: acct.vote_id.unwrap_or([0u8; 32]),
            selection_id: acct.selection_id.unwrap_or([0u8; 32]),
            vote_first_valid: Round(acct.vote_first_valid),
            vote_last_valid: Round(acct.vote_last_valid),
            vote_key_dilution: acct.vote_key_dilution,
            incentive_eligible: acct.incentive_eligible,
            last_proposed: Round(acct.last_proposed),
            last_heartbeat: Round(acct.last_heartbeat),
            state_proof_id: acct.state_proof_id.unwrap_or([0u8; 64]),
        })
    }

    fn circulation(&self, rnd: Round, _vote_rnd: Round) -> Result<u64, LedgerError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;

        if rnd.0 > ledger.current_round().0 {
            return Err(LedgerError::RoundNotAvailable(rnd));
        }

        // TODO: Implement proper online stake calculation.
        // The full implementation should query the onlineaccounts table
        // (or accounttotals) to return the total amount of online money
        // in circulation that is eligible for voting. For now, return 0
        // as a placeholder; the agreement service will need this to be
        // properly implemented for committee membership checks.
        let _ = &ledger;
        Ok(0)
    }

    fn lookup_digest(&self, round: Round) -> Result<Digest, LedgerError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;

        let hdr_data = ledger
            .get_block_header_data(round.0)
            .map_err(|e| LedgerError::Other(format!("get_block_header_data: {e}")))?
            .ok_or(LedgerError::RoundNotAvailable(round))?;

        // The block digest is the SHA512/256 hash of the canonical header encoding
        // with the "BH" domain separator.
        Ok(hash_block_header(&hdr_data))
    }

    fn consensus_params(&self, round: Round) -> Result<ConsensusParams, LedgerError> {
        let proto = self.protocol_for_round(round)?;
        consensus_params_for_version(&proto)
            .ok_or_else(|| LedgerError::Other(format!("unknown consensus version: {proto}")))
    }

    fn consensus_version(&self, round: Round) -> Result<String, LedgerError> {
        self.protocol_for_round(round)
    }

    fn wait_for_round(&self, round: Round) -> Result<(), LedgerError> {
        // Polling implementation. A condvar/channel upgrade path is available
        // once the agreement service event loop is fully async.
        const POLL_INTERVAL: Duration = Duration::from_millis(50);
        const MAX_POLLS: u32 = 6000; // 5 minutes max wait

        for _ in 0..MAX_POLLS {
            {
                let ledger = self
                    .ledger
                    .lock()
                    .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;
                if ledger.current_round().0 >= round.0 {
                    return Ok(());
                }
            }
            thread::sleep(POLL_INTERVAL);
        }

        Err(LedgerError::Other(format!(
            "timed out waiting for round {round}"
        )))
    }
}

impl LedgerWriter for AgreementLedgerBridge {
    fn ensure_block(&self, block: &algo_types::Block, _cert: &Certificate) {
        let mut ledger = self.ledger.lock().expect("ledger lock poisoned");

        // Check if this block's round has already been committed.
        let next_round = ledger.current_round().0 + 1;
        if block.round.0 < next_round {
            // Block already committed; idempotent.
            return;
        }

        // Store the block and certificate atomically.
        // In a full implementation, this would also apply the block's
        // transactions to update account state. For now, we store the
        // raw block data.
        //
        // TODO: Apply block state changes (transactions, rewards, etc.)
        // when the full block evaluation pipeline is integrated.
        let blk_data = match algo_codec::encode_block(block) {
            Ok(data) => data,
            Err(e) => {
                warn!(
                    "ensure_block: failed to encode block for round {}: {e}",
                    block.round
                );
                return;
            }
        };

        // Encode the header portion using canonical encoding.
        let hdr_data = algo_codec::canonical_encode_block_header_from_block(block);
        let proto = &block.current_protocol;
        if let Err(e) = ledger.put_block(block.round.0, proto, &hdr_data, &blk_data) {
            warn!(
                "ensure_block: failed to put block for round {}: {e}",
                block.round
            );
        }

        // TODO: Serialize and store the certificate once Certificate
        // implements Serialize/msgpack encoding.
    }

    fn ensure_validated_block(&self, vb: &dyn algo_agreement::ValidatedBlock, cert: &Certificate) {
        self.ensure_block(vb.block(), cert);
    }

    fn ensure_digest(&self, _cert: &Certificate) {
        // In Go, this sends the certificate to the catchup service to fetch
        // the matching block. For now, this is a no-op stub.
        //
        // TODO: Integrate with block fetcher / catchup service to retrieve
        // the block matching this certificate's digest.
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the committee seed from a msgpack-encoded block header.
///
/// The seed is stored under codec key `"seed"` as a 32-byte binary value.
fn extract_seed_from_header(hdr_data: &[u8]) -> Option<Seed> {
    let value: rmpv::Value = rmpv::decode::read_value(&mut &hdr_data[..]).ok()?;
    let map = value.as_map()?;
    for (k, v) in map {
        if k.as_str() == Some("seed") {
            let bytes = v.as_slice()?;
            if bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(bytes);
                return Some(Seed::from(seed));
            }
        }
    }
    None
}

/// Compute the block header digest: `SHA512/256("BH" || hdr_data)`.
fn hash_block_header(hdr_data: &[u8]) -> Digest {
    use sha2::{Digest as _, Sha512_256};

    let mut hasher = Sha512_256::new();
    hasher.update(b"BH");
    hasher.update(hdr_data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    algo_types::Digest(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_block_header_deterministic() {
        let data = b"test header data";
        let d1 = hash_block_header(data);
        let d2 = hash_block_header(data);
        assert_eq!(d1, d2);
    }

    #[test]
    fn hash_block_header_different_input() {
        let d1 = hash_block_header(b"header1");
        let d2 = hash_block_header(b"header2");
        assert_ne!(d1, d2);
    }

    #[test]
    fn extract_seed_from_empty_returns_none() {
        assert!(extract_seed_from_header(&[]).is_none());
    }
}
