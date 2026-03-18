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

    /// Create a new bridge with a custom network advancer but no catchup channel.
    ///
    /// This is suitable for the catchup service's own bridge, which needs to
    /// call `on_network_advance()` when committing blocks but does not produce
    /// pending certificates.
    pub fn new_with_advancer(
        ledger: Arc<Mutex<SqliteLedger>>,
        network_advancer: Arc<dyn NetworkAdvancer>,
    ) -> Self {
        Self {
            ledger,
            round_advanced: Arc::new(Condvar::new()),
            pending_cert_tx: None,
            pending_cert_rx: None,
            network_advancer,
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

        // Try per-round online supply from onlineroundparamstail first.
        // This mirrors Go's onlineCirculation which looks up OnlineRoundParamsData
        // containing the OnlineSupply for the specific round.
        if let Ok(Some(supply)) = ledger.online_supply_at_round(rnd.0) {
            return Ok(supply);
        }

        // Fall back to current totals from the accounttotals table.
        // This is the aggregate online stake and is correct when operating
        // at or near the latest round.
        ledger
            .online_stake()
            .map_err(|e| LedgerError::Other(format!("online_stake: {e}")))
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
    fn ensure_block(&self, block: &algo_types::Block, _cert: &Certificate) {
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
            // Block already committed; idempotent.
            return;
        }

        if block.round.0 > next_round {
            warn!("ensure_block: block round {} is ahead of next expected round {}, skipping (needs catchup)", block.round.0, next_round);
            return;
        }

        // Encode the block for storage.
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

        // Begin a transaction so that block storage and state application
        // are atomic. If begin_block fails (e.g., already in a transaction),
        // fall back to non-transactional mode.
        let in_txn = ledger.begin_block().is_ok();

        // Store the raw block data.
        if let Err(e) = ledger.put_block(block.round.0, proto, &hdr_data, &blk_data) {
            warn!(
                "ensure_block: failed to put block for round {}: {e}",
                block.round
            );
            if in_txn {
                let _ = ledger.rollback_block();
            }
            return;
        }

        // Apply the block's state changes (transactions, rewards, round
        // advancement). This mirrors Go's EnsureBlock which calls
        // l.Ledger.EnsureBlock(&e, c) and internally validates + applies.
        if let Err(e) = crate::apply::apply_block(&mut *ledger, block) {
            warn!(
                "ensure_block: failed to apply block for round {}: {e}",
                block.round
            );
            if in_txn {
                let _ = ledger.rollback_block();
            }
            return;
        }

        // Commit the transaction.
        if in_txn {
            if let Err(e) = ledger.commit_block() {
                warn!(
                    "ensure_block: failed to commit block for round {}: {e}",
                    block.round
                );
                return;
            }
        }

        // Release the lock before notifying waiters.
        drop(ledger);

        // Notify any threads waiting in wait_for_round.
        self.round_advanced.notify_all();

        // Let the network know that we've made some progress.
        // Mirrors Go's `l.n.OnNetworkAdvance()` in `EnsureBlock` / `EnsureValidatedBlock`.
        self.network_advancer.on_network_advance();
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
}
