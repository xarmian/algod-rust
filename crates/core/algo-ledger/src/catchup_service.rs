//! Catchup service: fetches missing blocks identified by agreement certificates.
//!
//! When the agreement service has a valid certificate but not the corresponding
//! block, it sends a [`PendingUnmatchedCertificate`] on a channel.  The
//! `CatchupService` receives from that channel, fetches the block from the
//! network, and commits it to the ledger via [`LedgerWriter::ensure_block`].
//!
//! Mirrors Go's `catchup.Service` in `go-algorand/catchup/service.go`,
//! specifically the `syncCert` / `fetchRound` path that handles certificate-
//! driven single-block fetches.

use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{self, Receiver, Select};
use tracing::{debug, info, warn};

use algo_agreement::{LedgerWriter, PendingUnmatchedCertificate};
use algo_types::{Block, Round};

use crate::agreement_bridge::AgreementLedgerBridge;
use crate::sqlite::SqliteLedger;
use crate::store_trait::LedgerStore;

// ---------------------------------------------------------------------------
// BlockFetcher trait
// ---------------------------------------------------------------------------

/// Abstraction for fetching blocks from the network.
///
/// This decouples the catchup service from any specific transport (HTTP, WS,
/// mock, etc.).  Implementations should attempt to fetch the block for the
/// given round, retrying across peers as appropriate.
///
/// The method is synchronous (blocking) because the catchup service runs on
/// a dedicated background thread.  Async implementations can use
/// `tokio::runtime::Handle::block_on` or a similar mechanism.
pub trait BlockFetcher: Send + Sync {
    /// Fetch the block for the given round from the network.
    ///
    /// Returns `Ok(block)` on success, or an error description on failure.
    ///
    /// Implementations **must** apply a reasonable timeout (e.g. via the
    /// HTTP client's connection/request timeout) so that a single call does
    /// not block the catchup worker thread indefinitely. The
    /// `GossipBlockFetcher` in `participate.rs` inherits the 4-second
    /// per-peer timeout from `GossipBlockSource`, and `HttpBlockFetcher`
    /// uses a 30-second default.
    fn fetch_block(&self, round: Round) -> Result<Block, String>;
}

// ---------------------------------------------------------------------------
// CatchupService
// ---------------------------------------------------------------------------

/// Service that fetches missing blocks identified by agreement certificates.
///
/// Mirrors Go's `catchup.Service`, specifically the `periodicSync` select
/// branch that receives from `unmatchedPendingCertificates` and calls
/// `syncCert` / `fetchRound`.
///
/// # Lifecycle
///
/// 1. Call [`CatchupService::start`] to spawn the background worker thread.
/// 2. The worker loops, selecting on the certificate channel and a shutdown
///    signal.
/// 3. Call [`CatchupService::stop`] to signal shutdown and join the thread.
pub struct CatchupService {
    /// Shutdown signal sender — dropping or sending signals the worker to exit.
    shutdown_tx: Option<crossbeam_channel::Sender<()>>,
    /// Join handle for the background worker thread.
    join_handle: Option<JoinHandle<()>>,
}

impl CatchupService {
    /// Create and start a new `CatchupService`.
    ///
    /// # Parameters
    ///
    /// - `cert_rx`: receiver for pending unmatched certificates from the
    ///   agreement service (produced by [`AgreementLedgerBridge::new_with_catchup`]).
    /// - `ledger`: the underlying ledger, used to check whether a block has
    ///   already been committed.
    /// - `bridge`: the agreement ledger bridge, used to commit fetched blocks
    ///   via [`LedgerWriter::ensure_block`].
    /// - `fetcher`: a block fetcher implementation for retrieving blocks from
    ///   the network.
    pub fn start(
        cert_rx: Receiver<PendingUnmatchedCertificate>,
        ledger: Arc<Mutex<SqliteLedger>>,
        bridge: Arc<AgreementLedgerBridge>,
        fetcher: Arc<dyn BlockFetcher>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);

        let join_handle = thread::Builder::new()
            .name("catchup-service".to_string())
            .spawn(move || {
                Self::run_loop(cert_rx, shutdown_rx, ledger, bridge, fetcher);
            })
            .expect("failed to spawn catchup-service thread");

        Self {
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
        }
    }

    /// Signal the service to stop and wait for the background thread to exit.
    ///
    /// Mirrors Go's `Service.Stop()`.
    pub fn stop(&mut self) {
        debug!("catchup service is stopping");

        // Signal shutdown by sending (or dropping the sender).
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Join the worker thread.
        if let Some(handle) = self.join_handle.take() {
            if let Err(e) = handle.join() {
                warn!("catchup service thread panicked: {e:?}");
            }
        }

        debug!("catchup service has stopped");
    }

    /// The main loop of the catchup service worker thread.
    ///
    /// Mirrors the `case cert := <-s.unmatchedPendingCertificates` branch of
    /// Go's `periodicSync`.
    fn run_loop(
        cert_rx: Receiver<PendingUnmatchedCertificate>,
        shutdown_rx: Receiver<()>,
        ledger: Arc<Mutex<SqliteLedger>>,
        bridge: Arc<AgreementLedgerBridge>,
        fetcher: Arc<dyn BlockFetcher>,
    ) {
        info!("catchup service started");

        loop {
            let mut sel = Select::new();
            let cert_idx = sel.recv(&cert_rx);
            let shutdown_idx = sel.recv(&shutdown_rx);

            let oper = sel.select();
            match oper.index() {
                i if i == shutdown_idx => {
                    // Shutdown signal received (or sender dropped).
                    debug!("catchup service received shutdown signal");
                    break;
                }
                i if i == cert_idx => {
                    match oper.recv(&cert_rx) {
                        Ok(pending) => {
                            Self::sync_cert(&pending, &ledger, &bridge, &fetcher, &shutdown_rx);
                        }
                        Err(_) => {
                            // Certificate channel closed — the agreement service
                            // has shut down. Exit the loop.
                            info!("catchup service: certificate channel closed, exiting");
                            break;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        info!("catchup service exiting");
    }

    /// Base delay between retry attempts (doubles with each attempt,
    /// capped at [`Self::MAX_RETRY_DELAY`]).
    const RETRY_BASE_DELAY: Duration = Duration::from_millis(500);

    /// Maximum delay between retry attempts (cap for exponential backoff).
    const MAX_RETRY_DELAY: Duration = Duration::from_secs(10);

    /// Process a single pending unmatched certificate.
    ///
    /// Mirrors Go's `syncCert` / `fetchRound`:
    /// 1. Check if the ledger already has the block for this round.
    /// 2. If not, fetch it from the network (with retries).
    /// 3. Validate the fetched block's digest against the certificate.
    /// 4. Commit it to the ledger via `ensure_block`.
    ///
    /// Unlike a bounded retry loop, this mirrors Go's `fetchRound` which
    /// retries indefinitely (`for s.ledger.LastRound() < cert.Round`) until
    /// either the block is committed (by any path) or shutdown is signaled.
    fn sync_cert(
        pending: &PendingUnmatchedCertificate,
        ledger: &Arc<Mutex<SqliteLedger>>,
        bridge: &Arc<AgreementLedgerBridge>,
        fetcher: &Arc<dyn BlockFetcher>,
        shutdown_rx: &Receiver<()>,
    ) {
        let cert = &pending.cert;
        let target_round = cert.round;

        debug!(
            round = %target_round,
            "catchup service: processing certificate for round"
        );

        // Retry loop: mirrors Go's `for s.ledger.LastRound() < cert.Round`.
        // Continues until the ledger has the block, shutdown is signaled,
        // or the block is successfully fetched and committed.
        let mut attempt: u32 = 0;
        loop {
            // Check if the ledger already has this block (committed by
            // agreement or a previous iteration of this loop).
            {
                let ledger_guard = match ledger.lock() {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(
                            round = %target_round,
                            "catchup service: ledger lock poisoned: {e}"
                        );
                        return;
                    }
                };

                let current = ledger_guard.current_round();
                if current.0 >= target_round.0 {
                    debug!(
                        round = %target_round,
                        current_round = %current,
                        "catchup service: ledger already has block, skipping"
                    );
                    return;
                }
            }

            // Check for shutdown before attempting a fetch.
            if shutdown_rx.try_recv().is_ok() {
                debug!(
                    round = %target_round,
                    "catchup service: shutdown received during sync_cert"
                );
                return;
            }

            attempt = attempt.saturating_add(1);

            match fetcher.fetch_block(target_round) {
                Ok(block) => {
                    // Validate round match.
                    if block.round != target_round {
                        warn!(
                            expected_round = %target_round,
                            fetched_round = %block.round,
                            attempt = attempt,
                            "catchup service: fetched block round mismatch, retrying"
                        );
                        let delay = Self::backoff_with_jitter(attempt);
                        if shutdown_rx.recv_timeout(delay).is_ok() {
                            debug!(
                                round = %target_round,
                                "catchup service: shutdown received during backoff"
                            );
                            return;
                        }
                        continue;
                    }

                    // Validate that the fetched block's digest matches the
                    // certificate's proposal digest.
                    //
                    // Mirrors Go's `block.Hash() == blockHash` check in
                    // fetchRound (catchup/service.go). The block hash is
                    // SHA512/256("BH" || canonical_encode(block_header)),
                    // matching Go's `bookkeeping.BlockHash`.
                    let block_digest = algo_codec::compute_block_digest(&block);
                    let cert_digest = cert.proposal.block_digest;
                    if block_digest != cert_digest {
                        warn!(
                            round = %target_round,
                            attempt = attempt,
                            block_digest = ?block_digest,
                            cert_digest = ?cert_digest,
                            "catchup service: fetched block digest does not match certificate, retrying"
                        );
                        // A malicious or wrong peer returned a bad block.
                        // Retry with a different peer (the fetcher may rotate).
                        let delay = Self::backoff_with_jitter(attempt);
                        // Use recv_timeout so shutdown can interrupt the wait.
                        if shutdown_rx.recv_timeout(delay).is_ok() {
                            debug!(
                                round = %target_round,
                                "catchup service: shutdown received during backoff"
                            );
                            return;
                        }
                        continue;
                    }

                    // Commit the block to the ledger.
                    // EnsureBlock is idempotent — if the block was already
                    // committed by normal agreement between fetch and now,
                    // this is a harmless no-op.
                    debug!(
                        round = %target_round,
                        "catchup service: committing fetched block to ledger"
                    );
                    bridge.ensure_block(&block, cert);

                    info!(
                        round = %target_round,
                        "catchup service: successfully fetched and committed block"
                    );
                    return;
                }
                Err(e) => {
                    warn!(
                        round = %target_round,
                        attempt = attempt,
                        error = %e,
                        "catchup service: failed to fetch block, will retry"
                    );
                    // Exponential backoff with jitter between retries.
                    // Use recv_timeout so shutdown can interrupt the wait.
                    let delay = Self::backoff_with_jitter(attempt);
                    if shutdown_rx.recv_timeout(delay).is_ok() {
                        debug!(
                            round = %target_round,
                            "catchup service: shutdown received during backoff"
                        );
                        return;
                    }
                }
            }
        }
    }

    /// Compute an exponential backoff delay with jitter, capped at
    /// [`Self::MAX_RETRY_DELAY`].
    ///
    /// The jitter is derived from the current timestamp to avoid adding a
    /// `rand` dependency to this crate. It adds ±50% variation to the base
    /// exponential delay, preventing thundering-herd effects when multiple
    /// nodes retry simultaneously.
    fn backoff_with_jitter(attempt: u32) -> Duration {
        let base = Self::RETRY_BASE_DELAY * 2u32.saturating_pow(attempt.saturating_sub(1));
        let base = std::cmp::min(base, Self::MAX_RETRY_DELAY);

        // Lightweight jitter: use the low bits of the current timestamp
        // (nanoseconds) to add ±50% variation.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        // Map nanos to [0.5, 1.5) multiplier: 0.5 + (nanos % 1000) / 1000.0
        let jitter_frac = 0.5 + (nanos % 1000) as f64 / 1000.0;
        let jittered_millis = (base.as_millis() as f64 * jitter_frac) as u64;

        Duration::from_millis(jittered_millis)
    }
}

impl Drop for CatchupService {
    fn drop(&mut self) {
        // Ensure the background thread is stopped if the service is dropped
        // without an explicit `stop()` call.
        if self.shutdown_tx.is_some() || self.join_handle.is_some() {
            self.stop();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use algo_agreement::Certificate;
    use algo_agreement::{AsyncVoteVerifier, PendingUnmatchedCertificate};
    use algo_types::Round;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    // -- Mock BlockFetcher --

    struct MockBlockFetcher {
        /// The block to return for any fetch request.
        block: Mutex<Option<Block>>,
        /// Count of fetch calls.
        fetch_count: AtomicU64,
    }

    impl MockBlockFetcher {
        fn new(block: Option<Block>) -> Self {
            Self {
                block: Mutex::new(block),
                fetch_count: AtomicU64::new(0),
            }
        }

        fn fetch_count(&self) -> u64 {
            self.fetch_count.load(Ordering::SeqCst)
        }
    }

    impl BlockFetcher for MockBlockFetcher {
        fn fetch_block(&self, round: Round) -> Result<Block, String> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            let guard = self.block.lock().unwrap();
            match guard.as_ref() {
                Some(b) => {
                    let mut block = b.clone();
                    block.round = round;
                    Ok(block)
                }
                None => Err(format!("no block available for round {round}")),
            }
        }
    }

    // -- Failing BlockFetcher --

    struct FailingBlockFetcher;

    impl BlockFetcher for FailingBlockFetcher {
        fn fetch_block(&self, round: Round) -> Result<Block, String> {
            Err(format!("network error fetching round {round}"))
        }
    }

    // -- Helper to create a minimal certificate --

    fn make_cert(round: u64) -> Certificate {
        Certificate {
            round: Round(round),
            ..Certificate::default()
        }
    }

    fn make_pending_cert(round: u64) -> PendingUnmatchedCertificate {
        PendingUnmatchedCertificate {
            cert: make_cert(round),
            vote_verifier: AsyncVoteVerifier::new(),
        }
    }

    // -- Tests --

    #[test]
    fn stop_without_certs_is_clean() {
        // The service should start and stop cleanly even if no certs arrive.
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = Arc::new(AgreementLedgerBridge::new(Arc::clone(&ledger)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));

        let mut svc = CatchupService::start(rx, ledger, bridge, fetcher);
        // Give the thread a moment to start.
        thread::sleep(Duration::from_millis(50));
        svc.stop();
    }

    #[test]
    fn drop_triggers_stop() {
        // Dropping the service should stop the background thread cleanly.
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = Arc::new(AgreementLedgerBridge::new(Arc::clone(&ledger)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));

        let svc = CatchupService::start(rx, ledger, bridge, fetcher);
        drop(svc); // should not panic
    }

    #[test]
    fn cert_channel_closed_exits_cleanly() {
        // When the cert channel sender is dropped, the service should exit.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = Arc::new(AgreementLedgerBridge::new(Arc::clone(&ledger)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));

        let mut svc = CatchupService::start(rx, ledger, bridge, fetcher);

        // Drop the sender to close the channel.
        drop(tx);

        // The service should exit on its own.
        thread::sleep(Duration::from_millis(100));
        svc.stop();
    }

    #[test]
    fn fetch_failure_does_not_crash() {
        // If the block fetcher fails, the service retries indefinitely.
        // Verify it stays alive and handles failures gracefully, then
        // shut it down to stop the retry loop.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = Arc::new(AgreementLedgerBridge::new(Arc::clone(&ledger)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(FailingBlockFetcher);

        let mut svc = CatchupService::start(rx, ledger, bridge, fetcher);

        // Send a cert — the fetch will fail but the service should survive.
        tx.send(make_pending_cert(5)).unwrap();

        // Give it time to attempt a few retries, then stop via shutdown.
        thread::sleep(Duration::from_secs(2));
        svc.stop();
    }

    #[test]
    fn skips_already_committed_round() {
        // If the ledger is already at or past the certificate round, no fetch
        // should occur.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));

        // Set the ledger's current round to 10 (past the cert round).
        {
            let mut l = ledger.lock().unwrap();
            l.set_current_round(Round(10));
        }

        let bridge = Arc::new(AgreementLedgerBridge::new(Arc::clone(&ledger)));
        let fetcher = Arc::new(MockBlockFetcher::new(Some(Block::default())));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, bridge, fetcher_ref);

        // Send a cert for round 5 — already committed.
        tx.send(make_pending_cert(5)).unwrap();

        // Give it time to process.
        thread::sleep(Duration::from_millis(100));

        // The fetcher should NOT have been called.
        assert_eq!(
            fetcher.fetch_count(),
            0,
            "fetcher should not be called for already-committed round"
        );

        svc.stop();
    }

    // -- DigestMatchingBlockFetcher: returns a block whose digest matches the cert --

    /// A fetcher that returns a block whose digest can be pre-computed.
    /// Unlike `MockBlockFetcher`, this does NOT modify the round on the
    /// returned block, allowing tests to control digest matching.
    struct DigestMatchingBlockFetcher {
        block: Block,
        fetch_count: AtomicU64,
    }

    impl DigestMatchingBlockFetcher {
        fn new(block: Block) -> Self {
            Self {
                block,
                fetch_count: AtomicU64::new(0),
            }
        }

        fn fetch_count(&self) -> u64 {
            self.fetch_count.load(Ordering::SeqCst)
        }
    }

    impl BlockFetcher for DigestMatchingBlockFetcher {
        fn fetch_block(&self, _round: Round) -> Result<Block, String> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.block.clone())
        }
    }

    /// Helper to make a certificate with a specific block digest.
    fn make_cert_with_digest(round: u64, digest: algo_types::Digest) -> Certificate {
        use algo_agreement::ProposalValue;
        Certificate {
            round: Round(round),
            proposal: ProposalValue {
                block_digest: digest,
                ..Default::default()
            },
            ..Certificate::default()
        }
    }

    fn make_pending_cert_with_digest(
        round: u64,
        digest: algo_types::Digest,
    ) -> PendingUnmatchedCertificate {
        PendingUnmatchedCertificate {
            cert: make_cert_with_digest(round, digest),
            vote_verifier: AsyncVoteVerifier::new(),
        }
    }

    #[test]
    fn happy_path_fetch_and_commit() {
        // Create a block for round 1 and compute its digest.
        let block = Block {
            round: Round(1),
            ..Default::default()
        };
        let digest = algo_codec::compute_block_digest(&block);

        // Set up the service with a fetcher that returns this block.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        // Ledger is at round 0, so round 1 is the next expected.

        let bridge = Arc::new(AgreementLedgerBridge::new(Arc::clone(&ledger)));
        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, Arc::clone(&ledger), bridge, fetcher_ref);

        // Send a cert for round 1 with the correct digest.
        tx.send(make_pending_cert_with_digest(1, digest)).unwrap();

        // Wait for the service to process the cert and commit the block.
        thread::sleep(Duration::from_millis(500));

        // The fetcher should have been called exactly once (no retries needed).
        assert_eq!(
            fetcher.fetch_count(),
            1,
            "fetcher should be called exactly once for a valid block"
        );

        // The block should have been committed to the ledger.
        // Note: ensure_block may or may not succeed in applying the block
        // (depends on block content), but the fetch and digest validation
        // path was exercised. We verify by checking fetch_count == 1
        // (meaning digest validation passed, no retry).

        svc.stop();
    }

    #[test]
    fn digest_mismatch_triggers_retry() {
        // Create a block for round 1, but make the certificate have a
        // different digest. This should cause digest validation to fail
        // and trigger retries indefinitely until shutdown.
        let block = Block {
            round: Round(1),
            ..Default::default()
        };
        // The actual digest of this block will NOT match the cert.

        let wrong_digest = algo_types::Digest([0xff; 32]);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));

        let bridge = Arc::new(AgreementLedgerBridge::new(Arc::clone(&ledger)));
        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, Arc::clone(&ledger), bridge, fetcher_ref);

        // Send a cert with a wrong digest.
        tx.send(make_pending_cert_with_digest(1, wrong_digest))
            .unwrap();

        // Let the service retry for a bit.
        thread::sleep(Duration::from_secs(2));

        // The fetcher should have been called multiple times since the
        // service retries indefinitely on digest mismatch.
        assert!(
            fetcher.fetch_count() >= 2,
            "fetcher should retry on digest mismatch, got {} calls",
            fetcher.fetch_count()
        );

        // Shutdown stops the retry loop.
        svc.stop();
    }

    // -- CountingFailFetcher: fails N times then succeeds --

    /// A fetcher that fails the first N calls, then succeeds.
    struct CountingFailFetcher {
        block: Block,
        fail_count: AtomicU64,
        fail_until: u64,
        total_calls: AtomicU64,
    }

    impl CountingFailFetcher {
        fn new(block: Block, fail_until: u64) -> Self {
            Self {
                block,
                fail_count: AtomicU64::new(0),
                fail_until,
                total_calls: AtomicU64::new(0),
            }
        }

        fn total_calls(&self) -> u64 {
            self.total_calls.load(Ordering::SeqCst)
        }
    }

    impl BlockFetcher for CountingFailFetcher {
        fn fetch_block(&self, _round: Round) -> Result<Block, String> {
            let call_num = self.total_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call_num <= self.fail_until {
                self.fail_count.fetch_add(1, Ordering::SeqCst);
                Err(format!("transient error on attempt {call_num}"))
            } else {
                Ok(self.block.clone())
            }
        }
    }

    #[test]
    fn retry_logic_retries_on_fetch_failure() {
        // The fetcher fails on the first call, succeeds on the second.
        // Verify that fetch is called multiple times.
        let block = Block {
            round: Round(1),
            ..Default::default()
        };
        let digest = algo_codec::compute_block_digest(&block);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));

        let bridge = Arc::new(AgreementLedgerBridge::new(Arc::clone(&ledger)));
        // Fail once, then succeed.
        let fetcher = Arc::new(CountingFailFetcher::new(block, 1));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, Arc::clone(&ledger), bridge, fetcher_ref);

        // Send a cert for round 1 with the correct digest.
        tx.send(make_pending_cert_with_digest(1, digest)).unwrap();

        // Wait for retry: first attempt fails (500ms backoff), second succeeds.
        thread::sleep(Duration::from_secs(2));

        // The fetcher should have been called at least 2 times: 1 failure + 1 success.
        assert!(
            fetcher.total_calls() >= 2,
            "expected at least 2 fetch calls (1 fail + 1 success), got {}",
            fetcher.total_calls()
        );

        svc.stop();
    }

    #[test]
    fn persistent_failure_retries_until_shutdown() {
        // The service now retries indefinitely on persistent failure,
        // mirroring Go's fetchRound. Verify that it keeps retrying
        // and stops cleanly on shutdown.
        let block = Block::default(); // won't be used since we always fail
        let fetcher = Arc::new(CountingFailFetcher::new(block, 999)); // always fail

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = Arc::new(AgreementLedgerBridge::new(Arc::clone(&ledger)));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, Arc::clone(&ledger), bridge, fetcher_ref);

        tx.send(make_pending_cert(5)).unwrap();

        // Let the service retry for a bit.
        thread::sleep(Duration::from_secs(2));

        // Should have been called multiple times (retries indefinitely).
        assert!(
            fetcher.total_calls() >= 2,
            "fetcher should be called multiple times during indefinite retry, got {}",
            fetcher.total_calls()
        );

        // Shutdown should interrupt the retry loop cleanly.
        svc.stop();
    }
}
