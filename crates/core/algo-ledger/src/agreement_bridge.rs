//! Bridge implementation connecting `SqliteLedger` to the agreement protocol's
//! `LedgerReader` and `LedgerWriter` traits.
//!
//! Mirrors go-algorand's `node/impls.go` `agreementLedger` struct which wraps
//! a `*data.Ledger` and implements the `agreement.Ledger` interface.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crossbeam_channel;

use tracing::{debug, warn};

use algo_agreement::{
    AsyncVoteVerifier, Certificate, LedgerError, LedgerReader, LedgerWriter, NetworkAdvancer,
    NoOpNetworkAdvancer, OnlineAccountData, PendingUnmatchedCertificate, Seed,
};
use algo_types::consensus::consensus_params_for_version;
use algo_types::{Address, ConsensusParams, Digest, Round};

use algo_error::AlgoError;

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
    /// Condvar notified when a new block is committed (round advances).
    /// Paired with the `ledger` mutex.
    round_advanced: Arc<Condvar>,
    /// Channel sender for pending unmatched certificates.
    ///
    /// When `ensure_digest` is called, a `PendingUnmatchedCertificate` is sent
    /// on this channel to be picked up by the catchup service.
    /// Mirrors Go's `agreementLedger.UnmatchedPendingCertificates`.
    pending_cert_tx: Option<crossbeam_channel::Sender<PendingUnmatchedCertificate>>,
    /// Receiver clone kept solely for draining stale certificates inside
    /// `ensure_digest`, mirroring Go's drain-before-send pattern:
    ///
    /// ```go
    /// select {
    /// case <-l.UnmatchedPendingCertificates:  // drain old
    /// default:
    /// }
    /// l.UnmatchedPendingCertificates <- cert   // send new
    /// ```
    ///
    /// This is safe despite the crossbeam MPMC semantics because:
    /// 1. `ensure_digest` is only called from the single-threaded agreement
    ///    service (Go's guarantee #3).
    /// 2. With MPMC, either this bridge's `try_recv` or the catchup service's
    ///    `recv` may consume the stale certificate first — either outcome is
    ///    fine since the stale certificate is being superseded anyway.
    /// 3. After the drain, the channel has capacity for at least one item, so
    ///    the subsequent `send` always succeeds and the newest certificate
    ///    ends up on the channel for the catchup service to consume.
    pending_cert_rx: Option<crossbeam_channel::Receiver<PendingUnmatchedCertificate>>,
    /// Network advancer for signaling progress to the network layer.
    ///
    /// Mirrors Go's `agreementLedger.n.OnNetworkAdvance()`.
    network_advancer: Arc<dyn NetworkAdvancer>,
}

impl AgreementLedgerBridge {
    /// Create a new bridge wrapping the given ledger.
    ///
    /// Uses a no-op network advancer and no pending certificate channel.
    /// This is suitable for tests and for callers that don't need catchup.
    pub fn new(ledger: Arc<Mutex<SqliteLedger>>) -> Self {
        Self {
            ledger,
            round_advanced: Arc::new(Condvar::new()),
            pending_cert_tx: None,
            pending_cert_rx: None,
            network_advancer: Arc::new(NoOpNetworkAdvancer),
        }
    }

    /// Create a new bridge with a custom network advancer and a shared condvar.
    ///
    /// This is suitable for the catchup service's own bridge: it shares the
    /// same `round_advanced` condvar as the agreement bridge so that blocks
    /// committed by the catchup service wake any agreement threads blocked in
    /// `wait_for_round` or `round_notify`.
    pub fn new_with_advancer_and_condvar(
        ledger: Arc<Mutex<SqliteLedger>>,
        network_advancer: Arc<dyn NetworkAdvancer>,
        round_advanced: Arc<Condvar>,
    ) -> Self {
        Self {
            ledger,
            round_advanced,
            pending_cert_tx: None,
            pending_cert_rx: None,
            network_advancer,
        }
    }

    /// Returns a clone of the `round_advanced` condvar.
    ///
    /// This is used to share the condvar with the catchup bridge so that
    /// catchup-committed blocks wake agreement waiters.
    pub fn round_advanced_condvar(&self) -> Arc<Condvar> {
        Arc::clone(&self.round_advanced)
    }

    /// Create a new bridge with catchup support.
    ///
    /// Returns `(bridge, receiver)` where:
    /// - `bridge` is the `AgreementLedgerBridge` configured with a bounded(1)
    ///   channel for pending certificates and the given network advancer.
    /// - `receiver` is the receiving end of the pending certificate channel,
    ///   to be consumed by the catchup service.
    ///
    /// Mirrors Go's `makeAgreementLedger` in `node/impls.go`.
    pub fn new_with_catchup(
        ledger: Arc<Mutex<SqliteLedger>>,
        network_advancer: Arc<dyn NetworkAdvancer>,
    ) -> (
        Self,
        crossbeam_channel::Receiver<PendingUnmatchedCertificate>,
    ) {
        let (tx, rx) = crossbeam_channel::bounded(1);
        let bridge = Self {
            ledger,
            round_advanced: Arc::new(Condvar::new()),
            pending_cert_tx: Some(tx),
            pending_cert_rx: Some(rx.clone()),
            network_advancer,
        };
        (bridge, rx)
    }

    /// Retrieve the certificate for a given round.
    ///
    /// Decodes the stored certificate bytes back into a `Certificate`.
    /// Returns an error if no certificate is stored for the round or if
    /// decoding fails.
    pub fn get_cert_for_round(&self, round: Round) -> Result<Certificate, LedgerError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;

        let cert_bytes = ledger
            .get_block_cert(round.0)
            .map_err(|e| LedgerError::Other(format!("get_block_cert: {e}")))?
            .ok_or_else(|| {
                LedgerError::Other(format!("no certificate stored for round {round}"))
            })?;

        let bundle = algo_agreement::codec::decode_bundle(&cert_bytes)
            .map_err(|e| LedgerError::Other(format!("decode_bundle: {e}")))?;

        Ok(Certificate::from_bundle(&bundle))
    }

    /// Attempt to commit a block + certificate + state application in a single
    /// transaction.  Returns `Ok(())` on success or an `AlgoError` on failure
    /// (the transaction is rolled back automatically on error).
    fn try_commit_block(
        ledger: &mut SqliteLedger,
        block: &algo_types::Block,
        proto: &str,
        hdr_data: &[u8],
        blk_data: &[u8],
        cert_bytes: &[u8],
    ) -> Result<(), AlgoError> {
        // Begin a transaction so that block storage and state application
        // are atomic. If begin_block fails (e.g., already in a transaction),
        // fall back to non-transactional mode.
        let in_txn = ledger.begin_block().is_ok();

        let result = (|| -> Result<(), AlgoError> {
            ledger.put_block(block.round.0, proto, hdr_data, blk_data)?;
            ledger.put_block_cert(block.round.0, cert_bytes)?;
            crate::apply::apply_block(ledger, block)?;
            Ok(())
        })();

        if let Err(e) = result {
            if in_txn {
                let _ = ledger.rollback_block();
            }
            return Err(e);
        }

        if in_txn {
            ledger.commit_block()?;
        }

        Ok(())
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

        // Try historical lookup from the onlineaccounts table first.
        // This mirrors Go's LookupAgreement which queries the online accounts
        // tracker at the specified round, not just the latest snapshot.
        let acct = match ledger.get_online_account_at_round(addr, round.0) {
            Ok(Some(acct)) => acct,
            Ok(None) | Err(_) => {
                // Fall back to current account state if no historical data
                // is available (e.g., onlineaccounts table not populated).
                ledger.get_account(addr).unwrap_or_default()
            }
        };

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

        // Shared with `GetSupply`'s `online-stake` field (node_interface_impl.rs)
        // so both consult the same per-round-snapshot-else-current-aggregate
        // rule -- mirrors Go's `onlineCirculation` (`ledger/acctonline.go`).
        ledger
            .online_circulation_at_round(rnd.0)
            .map_err(|e| LedgerError::Other(format!("online_circulation_at_round: {e}")))
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
        if let Ok(proto) = self.protocol_for_round(round) {
            return Ok(proto);
        }

        // Go's `Ledger.ConsensusVersion` (data/ledger.go:267) does not give
        // up when the requested round has no block header yet: for a
        // *future* round it deduces the version from the latest committed
        // header, because absent a scheduled upgrade the protocol cannot
        // change before `NextProtocolSwitchOn`. Agreement relies on this —
        // it asks for `NextRound()`'s version at startup and on every round
        // interruption, and that round is by definition not committed.
        //
        // Without the deduction the agreement service logged
        // "unable to retrieve consensus version for round N, defaulting to
        // the binary consensus version" every round and ran the whole
        // player on the binary's built-in params rather than the network's
        // (issue #478).
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;
        let latest = ledger.current_round();
        if round.0 < latest.0 {
            // An older round we genuinely do not have: unknowable.
            return Err(LedgerError::RoundNotAvailable(round));
        }
        let latest_proto = if latest.0 == 0 {
            ledger.protocol().to_string()
        } else {
            ledger
                .get_block_proto(latest.0)
                .map_err(|e| LedgerError::Other(format!("get_block_proto: {e}")))?
                .ok_or(LedgerError::RoundNotAvailable(latest))?
        };
        let hdr = ledger
            .get_block_header(latest.0)
            .map_err(|e| LedgerError::Other(format!("get_block_header: {e}")))?
            .ok_or(LedgerError::RoundNotAvailable(latest))?;
        // No upgrade pending, or the requested round is still before the
        // switch-on round: the protocol is unchanged. Otherwise report the
        // upgrade target, matching Go.
        if hdr.next_protocol_switch_on.0 == 0 || round.0 < hdr.next_protocol_switch_on.0 {
            Ok(latest_proto)
        } else if !hdr.next_protocol.is_empty() {
            Ok(hdr.next_protocol.clone())
        } else {
            Err(LedgerError::RoundNotAvailable(round))
        }
    }

    fn wait_for_round(&self, round: Round) -> Result<(), LedgerError> {
        const TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes max wait

        let mut ledger = self
            .ledger
            .lock()
            .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;

        // Use condvar-based waiting instead of polling.
        // The condvar is notified by ensure_block when a new block is committed.
        let deadline = std::time::Instant::now() + TIMEOUT;
        while ledger.current_round().0 < round.0 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(LedgerError::Other(format!(
                    "timed out waiting for round {round}"
                )));
            }
            let (guard, result) = self
                .round_advanced
                .wait_timeout(ledger, remaining)
                .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;
            ledger = guard;
            if result.timed_out() && ledger.current_round().0 < round.0 {
                return Err(LedgerError::Other(format!(
                    "timed out waiting for round {round}"
                )));
            }
        }

        Ok(())
    }

    fn round_notify(&self, round: Round) -> crossbeam_channel::Receiver<Round> {
        // Check if the round is already available.
        {
            let ledger = match self.ledger.lock() {
                Ok(l) => l,
                Err(_) => {
                    // Lock poisoned — return a channel that never fires.
                    let (_tx, rx) = crossbeam_channel::bounded(1);
                    return rx;
                }
            };
            if ledger.current_round().0 >= round.0 {
                // Already available — return an immediately-ready channel.
                let (tx, rx) = crossbeam_channel::bounded(1);
                let _ = tx.send(round);
                return rx;
            }
        }

        // Spawn a short-lived thread that waits on the Condvar for the round
        // to be reached, then sends a single notification on the channel.
        let (tx, rx) = crossbeam_channel::bounded(1);
        let ledger = Arc::clone(&self.ledger);
        let condvar = Arc::clone(&self.round_advanced);

        std::thread::Builder::new()
            .name(format!("round-notify-{}", round.0))
            .spawn(move || {
                const TIMEOUT: Duration = Duration::from_secs(300);
                let deadline = std::time::Instant::now() + TIMEOUT;

                let mut guard = match ledger.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };

                while guard.current_round().0 < round.0 {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        return; // timed out — drop the sender, receiver sees disconnect
                    }
                    let (g, result) = match condvar.wait_timeout(guard, remaining) {
                        Ok(pair) => pair,
                        Err(_) => return,
                    };
                    guard = g;
                    if result.timed_out() && guard.current_round().0 < round.0 {
                        return;
                    }
                }

                let _ = tx.send(round);
            })
            .expect("failed to spawn round-notify thread");

        rx
    }
}

impl LedgerWriter for AgreementLedgerBridge {
    fn ensure_block(&self, block: &algo_types::Block, cert: &Certificate) {
        // Retry loop mirrors Go's `EnsureBlock` in `data/ledger.go`:
        //
        //   for l.LastRound() < round {
        //       err := l.AddBlock(*block, c)
        //       if err == nil { break }
        //       ...
        //       time.Sleep(100 * time.Millisecond)
        //   }
        //
        // Transient errors (SQLite busy, lock contention) are retried up to a
        // maximum count. Permanent errors (encoding failures) return immediately.
        const MAX_RETRIES: u32 = 100;
        const RETRY_DELAY: Duration = Duration::from_millis(100);

        // Pre-encode the block and header outside the retry loop — these are
        // deterministic and will not change between attempts. Encoding failure
        // is permanent and not retryable.
        let blk_data = algo_codec::canonical_encode_block(block);
        let hdr_data = algo_codec::canonical_encode_block_header_from_block(block);
        let proto = &block.current_protocol;

        // Pre-encode the certificate.
        let bundle = cert.to_unauthenticated_bundle();
        let cert_bytes = algo_agreement::codec::encode_bundle(&bundle);

        for attempt in 0..=MAX_RETRIES {
            let mut ledger = match self.ledger.lock() {
                Ok(l) => l,
                Err(e) => {
                    warn!("ledger lock poisoned in ensure_block: {e}");
                    return;
                }
            };

            // Check if this block's round has already been committed.
            let next_round = ledger.current_round().0 + 1;
            if block.round.0 < next_round {
                // Block already committed (by us or by catchup); idempotent.
                debug!(
                    "ensure_block: block round {} already committed, current round {}",
                    block.round.0,
                    next_round - 1
                );
                return;
            }

            if block.round.0 > next_round {
                warn!(
                    "ensure_block: block round {} is ahead of next expected round {}, \
                     skipping (needs catchup)",
                    block.round.0, next_round
                );
                return;
            }

            // Attempt to commit the block.
            let err = match Self::try_commit_block(
                &mut ledger,
                block,
                proto,
                &hdr_data,
                &blk_data,
                &cert_bytes,
            ) {
                Ok(()) => {
                    // Success — release the lock before notifying waiters.
                    drop(ledger);

                    // Notify any threads waiting in wait_for_round.
                    self.round_advanced.notify_all();

                    // Let the network know that we've made some progress.
                    // Mirrors Go's `l.n.OnNetworkAdvance()`.
                    self.network_advancer.on_network_advance();
                    return;
                }
                Err(e) => e,
            };

            // Determine if the error is transient (retryable).
            let err_msg = format!("{err}");
            let is_transient = err_msg.contains("database is locked")
                || err_msg.contains("SQLITE_BUSY")
                || err_msg.contains("busy");

            if !is_transient {
                // Permanent error — no point retrying.
                warn!(
                    "ensure_block: permanent error writing block {} to ledger: {err}",
                    block.round
                );
                return;
            }

            // Transient error — release the lock, sleep, and retry.
            if attempt < MAX_RETRIES {
                warn!(
                    "ensure_block: transient error writing block {} to ledger \
                     (attempt {}/{}): {err}",
                    block.round,
                    attempt + 1,
                    MAX_RETRIES
                );
                drop(ledger);
                std::thread::sleep(RETRY_DELAY);
            } else {
                warn!(
                    "ensure_block: giving up on block {} after {} retries: {err}",
                    block.round, MAX_RETRIES
                );
            }
        }
    }

    fn ensure_validated_block(&self, vb: &dyn algo_agreement::ValidatedBlock, cert: &Certificate) {
        self.ensure_block(vb.block(), cert);
    }

    fn ensure_digest(&self, cert: &Certificate, verifier: &AsyncVoteVerifier) {
        // Let the network know that we've made some progress.
        // This might be controversial since we haven't received the entire
        // block, but we did get the certificate, which means that network
        // connections are likely to be just fine.
        // Mirrors Go's `l.n.OnNetworkAdvance()`.
        self.network_advancer.on_network_advance();

        if let (Some(tx), Some(rx)) = (&self.pending_cert_tx, &self.pending_cert_rx) {
            // Drain any stale pending certificate from the channel.
            //
            // Mirrors Go's pattern in `node/impls.go`:
            //   select {
            //   case pendingCert := <-l.UnmatchedPendingCertificates:
            //       log("flushed pending cert for round %d in favor of round %d", ...)
            //   default:
            //   }
            match rx.try_recv() {
                Ok(old) => {
                    debug!(
                        "ensure_digest: flushed pending certificate for round {} \
                         in favor of new certificate for round {}",
                        old.cert.round, cert.round
                    );
                }
                Err(_) => {
                    // Channel was empty — nothing to drain.
                }
            }

            let pending = PendingUnmatchedCertificate {
                cert: cert.clone(),
                vote_verifier: verifier.clone(),
            };

            // The channel send is guaranteed to be non-blocking because:
            // 1. The channel capacity is 1.
            // 2. We just drained a single item (if any) above.
            // 3. EnsureDigest is called with the agreement service's
            //    single-caller guarantee.
            // 4. No other senders exist.
            //
            // We use `send` (blocking) to match Go's blocking channel send,
            // but in practice this will never block given the guarantees above.
            match tx.send(pending) {
                Ok(()) => {
                    debug!(
                        "ensure_digest: sent pending certificate for round {}",
                        cert.round
                    );
                }
                Err(_) => {
                    warn!(
                        "ensure_digest: certificate channel disconnected for round {}",
                        cert.round
                    );
                }
            }
        }
    }
}

impl crate::catchup_service::CatchupLedger for AgreementLedgerBridge {
    fn next_round(&self) -> Round {
        // Delegate to the LedgerReader implementation which already
        // locks the inner SqliteLedger and returns current_round + 1.
        <Self as LedgerReader>::next_round(self)
    }

    fn ensure_block(&self, block: &algo_types::Block, cert: &Certificate) {
        // Delegate to the LedgerWriter implementation.
        <Self as LedgerWriter>::ensure_block(self, block, cert);
    }

    fn authenticate_block(
        &self,
        block: &algo_types::Block,
        cert: &Certificate,
    ) -> Result<(), String> {
        // Mirrors Go's `catchup.Service.fetchAndWrite` calling
        // `s.auth.Authenticate(block, cert)`: check that the certificate
        // claims this exact block *and* that its votes form a quorum
        // against the online stake this ledger knows about.
        let digest = algo_codec::compute_block_digest(block);
        cert.authenticate(block.round, digest, self)
            .map_err(|e| e.to_string())
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
    use algo_agreement::{AsyncVoteVerifier, Certificate, LedgerWriter, NetworkAdvancer};
    use algo_types::Round;
    use std::sync::atomic::{AtomicU64, Ordering};

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

    // -- Helper: tracking network advancer --

    /// A `NetworkAdvancer` that counts how many times `on_network_advance` is called.
    struct TrackingNetworkAdvancer {
        call_count: AtomicU64,
    }

    impl TrackingNetworkAdvancer {
        fn new() -> Self {
            Self {
                call_count: AtomicU64::new(0),
            }
        }

        fn call_count(&self) -> u64 {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl NetworkAdvancer for TrackingNetworkAdvancer {
        fn on_network_advance(&self) {
            self.call_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn make_cert(round: u64) -> Certificate {
        Certificate {
            round: Round(round),
            ..Certificate::default()
        }
    }

    // -- Tests --

    #[test]
    fn ensure_digest_sends_cert_on_channel() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let advancer = Arc::new(NoOpNetworkAdvancer);
        let (bridge, rx) = AgreementLedgerBridge::new_with_catchup(ledger, advancer);

        let cert = make_cert(10);
        let verifier = AsyncVoteVerifier::new();
        bridge.ensure_digest(&cert, &verifier);

        // The certificate should appear on the channel.
        let pending = rx
            .try_recv()
            .expect("expected a pending certificate on the channel");
        assert_eq!(pending.cert.round, Round(10));
    }

    #[test]
    fn ensure_digest_drain_before_send() {
        // Send two certs in sequence via ensure_digest; only the latest
        // should be on the channel (the first is drained by the second call).
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let advancer = Arc::new(NoOpNetworkAdvancer);
        let (bridge, rx) = AgreementLedgerBridge::new_with_catchup(ledger, advancer);

        let verifier = AsyncVoteVerifier::new();

        // First call: sends cert for round 5.
        bridge.ensure_digest(&make_cert(5), &verifier);

        // Second call: should drain round 5 and send round 10.
        bridge.ensure_digest(&make_cert(10), &verifier);

        // Only the latest certificate (round 10) should be on the channel.
        let pending = rx.try_recv().expect("expected a pending certificate");
        assert_eq!(pending.cert.round, Round(10));

        // Channel should now be empty.
        assert!(
            rx.try_recv().is_err(),
            "channel should be empty after receiving the latest cert"
        );
    }

    #[test]
    fn ensure_digest_no_channel_does_not_panic() {
        // Bridge created via `new()` has no channel — ensure_digest should be a no-op.
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(ledger);

        let cert = make_cert(7);
        let verifier = AsyncVoteVerifier::new();

        // This must not panic.
        bridge.ensure_digest(&cert, &verifier);
    }

    #[test]
    fn ensure_digest_calls_on_network_advance() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let advancer = Arc::new(TrackingNetworkAdvancer::new());
        let (bridge, _rx) =
            AgreementLedgerBridge::new_with_catchup(ledger, Arc::clone(&advancer) as _);

        let cert = make_cert(1);
        let verifier = AsyncVoteVerifier::new();

        assert_eq!(advancer.call_count(), 0);
        bridge.ensure_digest(&cert, &verifier);
        assert_eq!(advancer.call_count(), 1);

        // Calling again increments the counter.
        bridge.ensure_digest(&make_cert(2), &verifier);
        assert_eq!(advancer.call_count(), 2);
    }

    #[test]
    fn new_with_catchup_returns_working_receiver() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let advancer = Arc::new(NoOpNetworkAdvancer);
        let (bridge, rx) = AgreementLedgerBridge::new_with_catchup(ledger, advancer);

        // The receiver should initially be empty.
        assert!(
            rx.try_recv().is_err(),
            "receiver should be empty before any ensure_digest call"
        );

        // After an ensure_digest call, the receiver should have a value.
        let verifier = AsyncVoteVerifier::new();
        bridge.ensure_digest(&make_cert(42), &verifier);

        let pending = rx
            .try_recv()
            .expect("receiver should have a value after ensure_digest");
        assert_eq!(pending.cert.round, Round(42));

        // And empty again after receiving.
        assert!(rx.try_recv().is_err(), "receiver should be empty again");
    }

    // -- Certificate storage tests --

    /// Build a minimal block for round 1 that can be committed via ensure_block.
    fn make_round1_block() -> algo_types::Block {
        algo_types::Block {
            round: Round(1),
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            ..algo_types::Block::default()
        }
    }

    /// Build a certificate with non-default fields so we can verify round-trip fidelity.
    fn make_cert_with_proposal(round: u64) -> Certificate {
        use algo_agreement::{Period, ProposalValue};
        Certificate {
            round: Round(round),
            period: Period(2),
            proposal: ProposalValue {
                original_period: Period(1),
                original_proposer: Address([0x42; 32]),
                block_digest: Digest([0xaa; 32]),
                encoding_digest: Digest([0xbb; 32]),
            },
            votes: vec![],
        }
    }

    #[test]
    fn ensure_block_stores_cert_and_round_trip() {
        // Create a bridge with an in-memory ledger.
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));

        let block = make_round1_block();
        let cert = make_cert_with_proposal(1);

        // Commit the block with the certificate.
        bridge.ensure_block(&block, &cert);

        // Round-trip: retrieve the certificate and verify it matches.
        let recovered = bridge
            .get_cert_for_round(Round(1))
            .expect("should retrieve cert for round 1");

        assert_eq!(recovered.round, cert.round);
        assert_eq!(recovered.period, cert.period);
        assert_eq!(recovered.proposal, cert.proposal);
        assert_eq!(recovered.votes.len(), cert.votes.len());
    }

    #[test]
    fn ensure_block_stores_cert_raw_bytes() {
        // Verify that get_block_cert returns Some(bytes) after ensure_block.
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));

        let block = make_round1_block();
        let cert = make_cert_with_proposal(1);

        bridge.ensure_block(&block, &cert);

        // Directly check the store has cert bytes.
        let ledger_guard = ledger.lock().unwrap();
        let cert_bytes = ledger_guard
            .get_block_cert(1)
            .expect("get_block_cert should not error");
        assert!(
            cert_bytes.is_some(),
            "cert bytes should be present after ensure_block"
        );

        // The bytes should be decodable back to a bundle.
        let bundle = algo_agreement::codec::decode_bundle(cert_bytes.as_ref().unwrap())
            .expect("cert bytes should decode to a valid bundle");
        assert_eq!(bundle.round, Round(1));
    }

    #[test]
    fn ensure_block_idempotent_retains_first_cert() {
        // Calling ensure_block twice for the same round should be a no-op the
        // second time: the first certificate is retained.
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));

        let block = make_round1_block();
        let cert1 = make_cert_with_proposal(1);

        // First call commits the block and certificate.
        bridge.ensure_block(&block, &cert1);

        // Build a second certificate with different fields for the same round.
        let cert2 = {
            use algo_agreement::{Period, ProposalValue};
            Certificate {
                round: Round(1),
                period: Period(99),
                proposal: ProposalValue {
                    original_period: Period(77),
                    original_proposer: Address([0xff; 32]),
                    block_digest: Digest([0x11; 32]),
                    encoding_digest: Digest([0x22; 32]),
                },
                votes: vec![],
            }
        };

        // Second call with a different cert should be a no-op (round already committed).
        bridge.ensure_block(&block, &cert2);

        // The stored certificate should still be the first one.
        let recovered = bridge
            .get_cert_for_round(Round(1))
            .expect("should retrieve cert for round 1");

        assert_eq!(recovered.round, cert1.round);
        assert_eq!(
            recovered.period, cert1.period,
            "first cert's period should be retained"
        );
        assert_eq!(
            recovered.proposal, cert1.proposal,
            "first cert's proposal should be retained"
        );
    }

    #[test]
    fn get_cert_for_round_missing_returns_error() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(ledger);

        // No block committed for round 5 — should return an error.
        let result = bridge.get_cert_for_round(Round(5));
        match &result {
            Err(LedgerError::Other(msg)) => {
                assert!(
                    msg.contains("no certificate stored"),
                    "expected 'no certificate stored' in error message, got: {msg}"
                );
            }
            other => {
                panic!("expected LedgerError::Other with 'no certificate stored', got: {other:?}")
            }
        }
    }
}
