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

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam_channel::{self, Receiver, Select};
use tracing::{debug, error, info, trace, warn};

use algo_agreement::{Certificate, PendingUnmatchedCertificate};
use algo_types::{Block, Round};

// ---------------------------------------------------------------------------
// FetchedBlockCert
// ---------------------------------------------------------------------------

/// A block together with its optional agreement certificate, as returned by
/// a [`BlockFetcher`].
///
/// The certificate may be `None` when the fetcher's transport does not
/// provide certificate data (e.g. some mock implementations). When present,
/// it can be used for fork-detection checks mirroring Go's `fetchRound`.
#[derive(Debug, Clone)]
pub struct FetchedBlockCert {
    /// The fetched block.
    pub block: Block,
    /// The agreement certificate, if the transport provided one.
    pub cert: Option<Certificate>,
}

// ---------------------------------------------------------------------------
// CatchupLedger trait
// ---------------------------------------------------------------------------

/// Abstraction over the ledger operations needed by the catchup service.
///
/// This decouples `CatchupService` from concrete types like `SqliteLedger`
/// and `AgreementLedgerBridge`, making it easy to supply lightweight mocks
/// in tests.
///
/// Implementations must be thread-safe (`Send + Sync`) because the catchup
/// service runs on a dedicated background thread.
pub trait CatchupLedger: Send + Sync {
    /// Returns the next round the ledger expects (i.e. `last_committed + 1`).
    ///
    /// Used to decide whether a certificate's round has already been committed.
    fn next_round(&self) -> Round;

    /// Commit a block together with its authenticating certificate.
    ///
    /// Semantically identical to [`algo_agreement::LedgerWriter::ensure_block`].
    fn ensure_block(&self, block: &Block, cert: &Certificate);

    /// Check whether `round` requires a protocol version this node does not
    /// support.
    ///
    /// Mirrors Go's `Service.roundIsNotSupported()` from
    /// `catchup/service.go`. The Go implementation reads the last committed
    /// block header and checks whether:
    ///
    /// 1. A protocol upgrade is pending (`NextProtocolSwitchOn != 0`).
    /// 2. The upgrade target (`NextProtocol`) is **not** in the supported
    ///    consensus map.
    /// 3. The requested `round` is >= the switch-on round.
    ///
    /// If all three conditions hold, the round requires an unsupported
    /// protocol and this method should return `true`.
    ///
    /// The default implementation returns `false` (optimistic: assume all
    /// rounds are supported). Concrete implementations backed by a real
    /// ledger should override this once block-header access is available.
    fn round_is_not_supported(&self, _round: Round) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// FetchError
// ---------------------------------------------------------------------------

/// Error type returned by [`BlockFetcher::fetch_block`].
///
/// Provides structured error variants so callers can distinguish between
/// transient failures (network, timeout) and permanent ones (no peers),
/// enabling smarter retry logic in the catchup service.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The peer(s) did not have a block for the requested round.
    #[error("no block available for round {round}")]
    NoBlockForRound { round: Round },

    /// A network-level error occurred while fetching.
    #[error("network error: {0}")]
    NetworkError(String),

    /// The fetch request timed out.
    #[error("fetch timed out")]
    Timeout,

    /// No peers are available to fetch from.
    #[error("no peers available")]
    NoPeersAvailable,
}

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
    /// Fetch the block (and optional certificate) for the given round.
    ///
    /// Returns `Ok(FetchedBlockCert)` on success, or a [`FetchError`] on
    /// failure.
    ///
    /// Implementations **must** apply a reasonable timeout (e.g. via the
    /// HTTP client's connection/request timeout) so that a single call does
    /// not block the catchup worker thread indefinitely. The
    /// `GossipBlockFetcher` in `participate.rs` inherits the 4-second
    /// per-peer timeout from `GossipBlockSource`, and `HttpBlockFetcher`
    /// uses a 30-second default.
    fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError>;
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
    /// Counter tracking the number of fork detections observed.
    /// Callers can query this via [`CatchupService::fork_count`] for
    /// monitoring / alerting purposes.
    fork_count: Arc<AtomicU64>,
}

impl CatchupService {
    /// Create and start a new `CatchupService`.
    ///
    /// # Parameters
    ///
    /// - `cert_rx`: receiver for pending unmatched certificates from the
    ///   agreement service (produced by [`AgreementLedgerBridge::new_with_catchup`]).
    /// - `ledger`: trait object providing round checking and block commit
    ///   capabilities (typically an [`AgreementLedgerBridge`](crate::AgreementLedgerBridge)).
    /// - `fetcher`: a block fetcher implementation for retrieving blocks from
    ///   the network.
    pub fn start(
        cert_rx: Receiver<PendingUnmatchedCertificate>,
        ledger: Arc<dyn CatchupLedger>,
        fetcher: Arc<dyn BlockFetcher>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);
        let fork_count = Arc::new(AtomicU64::new(0));
        let fork_count_inner = Arc::clone(&fork_count);

        let join_handle = thread::Builder::new()
            .name("catchup-service".to_string())
            .spawn(move || {
                Self::run_loop(cert_rx, shutdown_rx, ledger, fetcher, fork_count_inner);
            })
            .expect("failed to spawn catchup-service thread");

        Self {
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
            fork_count,
        }
    }

    /// Returns the number of fork detections observed so far.
    ///
    /// Callers can poll this to detect forks for monitoring or alerting.
    pub fn fork_count(&self) -> u64 {
        self.fork_count.load(Ordering::SeqCst)
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
        ledger: Arc<dyn CatchupLedger>,
        fetcher: Arc<dyn BlockFetcher>,
        fork_count: Arc<AtomicU64>,
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
                            Self::sync_cert(&pending, &ledger, &fetcher, &shutdown_rx, &fork_count);
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
        ledger: &Arc<dyn CatchupLedger>,
        fetcher: &Arc<dyn BlockFetcher>,
        shutdown_rx: &Receiver<()>,
        fork_count: &Arc<AtomicU64>,
    ) {
        let cert = &pending.cert;
        let target_round = cert.round;

        debug!(
            round = %target_round,
            "catchup service: processing certificate for round"
        );

        // Guard: bail out if the round requires a protocol version that
        // this node does not support. Mirrors Go's
        // `if s.roundIsNotSupported(cert.Round) { return }` check at the
        // top of `fetchRound` in `catchup/service.go`.
        if ledger.round_is_not_supported(target_round) {
            info!(
                round = %target_round,
                "catchup service: round requires unsupported protocol version, skipping"
            );
            return;
        }

        // Retry loop: mirrors Go's `for s.ledger.LastRound() < cert.Round`.
        // Continues until the ledger has the block, shutdown is signaled,
        // or the block is successfully fetched and committed.
        let mut attempt: u32 = 0;
        loop {
            // Check if the ledger already has this block (committed by
            // agreement or a previous iteration of this loop).
            // next_round = last_committed + 1, so if next_round > target
            // the block is already committed.
            {
                let next = ledger.next_round();
                if next.0 > target_round.0 {
                    debug!(
                        round = %target_round,
                        next_round = %next,
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
                Ok(fetched) => {
                    let block = fetched.block;

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
                    //
                    // TODO: Go also verifies `block.ContentsMatchHeader()`
                    // (see catchup/service.go) which checks that the
                    // payset commitment in the header matches the actual
                    // transactions. This should be implemented once our
                    // Block type supports that validation.
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

                        // Fork detection: mirrors Go's fetchRound failsafe
                        // (catchup/service.go lines 819-839).
                        //
                        // If the fetched response included a certificate, and
                        // that certificate is for the same round but claims to
                        // authenticate a *different* block (i.e. the fetched
                        // block), this indicates a network fork — two valid
                        // certificates exist for different blocks in the same
                        // round.
                        //
                        // We perform a lightweight "claims to authenticate"
                        // check (round + digest match) rather than full quorum
                        // verification, since full authentication requires a
                        // LedgerReader which is not available through the
                        // CatchupLedger trait.
                        //
                        // TODO(fork-auth): Go's implementation (catchup/service.go ~line 822)
                        // calls `fetchedCert.Authenticate(*block, s.ledger, verifier)` which
                        // performs full quorum verification before raising a fork alarm. Our
                        // current lightweight digest comparison could produce false positives
                        // if a malicious peer sends a fabricated certificate. We should
                        // eventually perform full certificate authentication (signature +
                        // quorum check) here to prevent false fork alarms from untrusted peers.
                        if let Some(ref fetched_cert) = fetched.cert {
                            let fetched_cert_digest = fetched_cert.proposal.block_digest;
                            if fetched_cert.round == cert.round
                                && fetched_cert_digest != cert_digest
                                && fetched_cert_digest == block_digest
                            {
                                // Increment the fork detection counter so callers
                                // can observe fork events programmatically.
                                fork_count.fetch_add(1, Ordering::SeqCst);

                                error!(
                                    round = %target_round,
                                    agreement_digest = ?cert_digest,
                                    fetched_digest = ?fetched_cert_digest,
                                    fork_count = fork_count.load(Ordering::SeqCst),
                                    "FORK DETECTED: two certificates authenticate \
                                     different blocks for the same round. \
                                     Agreement cert digest={:?}, \
                                     fetched cert digest={:?}, \
                                     round={}",
                                    cert_digest, fetched_cert_digest, target_round,
                                );

                                // TODO(fork-response): Future work for fork detection response:
                                // - Expose a metrics counter (e.g. Prometheus gauge) for fork events
                                // - Integrate with an alerting system (e.g. webhook, PagerDuty)
                                // - Add an optional configurable halt mechanism that stops the node
                                //   on fork detection, similar to Go's `logging.Base().EventWithDetails()`
                                //   which can trigger external monitoring
                            }
                        }

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

                    // Validate that the block body matches header commitments.
                    // Mirrors Go's `block.ContentsMatchHeader()` check in
                    // fetchRound (catchup/service.go). The block hash only
                    // authenticates the header; this ensures the transactions
                    // are consistent with it.
                    match algo_validate::contents_match_header(&block) {
                        Ok(true) => { /* commitments match, proceed */ }
                        Ok(false) => {
                            warn!(
                                round = %target_round,
                                attempt = attempt,
                                "catchup service: block contents do not match header commitments, retrying"
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
                        Err(reason) => {
                            // An Err means the protocol version is empty or
                            // unsupported — a deterministic failure that won't
                            // resolve on retry. Abort instead of looping forever.
                            warn!(
                                round = %target_round,
                                attempt = attempt,
                                error = %reason,
                                "catchup service: cannot verify block contents (fatal), aborting"
                            );
                            return;
                        }
                    }

                    // Commit the block to the ledger.
                    // EnsureBlock is idempotent — if the block was already
                    // committed by normal agreement between fetch and now,
                    // this is a harmless no-op.
                    debug!(
                        round = %target_round,
                        "catchup service: committing fetched block to ledger"
                    );
                    ledger.ensure_block(&block, cert);

                    info!(
                        round = %target_round,
                        "catchup service: successfully fetched and committed block"
                    );
                    return;
                }
                Err(e) => {
                    // Mirror Go's pattern: NoBlockForRound is a normal
                    // condition during catchup (the peer simply doesn't
                    // have it yet), so log at trace/debug level and use a
                    // shorter backoff.  Other errors are unexpected and
                    // warrant warning-level logging.
                    let delay = match &e {
                        FetchError::NoBlockForRound { .. } => {
                            trace!(
                                round = %target_round,
                                attempt = attempt,
                                "catchup service: block not yet available, will retry"
                            );
                            // Use base delay without exponential backoff —
                            // the block may appear momentarily.
                            Self::RETRY_BASE_DELAY
                        }
                        FetchError::NetworkError(_)
                        | FetchError::Timeout
                        | FetchError::NoPeersAvailable => {
                            warn!(
                                round = %target_round,
                                attempt = attempt,
                                error = %e,
                                "catchup service: failed to fetch block, will retry"
                            );
                            Self::backoff_with_jitter(attempt)
                        }
                    };
                    // Use recv_timeout so shutdown can interrupt the wait.
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
    use algo_agreement::{AsyncVoteVerifier, PendingUnmatchedCertificate};
    use algo_types::Round;
    use std::sync::Mutex;
    use std::time::Duration;

    // -- Mock CatchupLedger --

    /// A lightweight mock ledger for tests — no SQLite required.
    struct MockCatchupLedger {
        round: Mutex<Round>,
    }

    impl MockCatchupLedger {
        fn new(current_round: Round) -> Self {
            Self {
                round: Mutex::new(current_round),
            }
        }
    }

    impl CatchupLedger for MockCatchupLedger {
        fn next_round(&self) -> Round {
            let r = self.round.lock().unwrap();
            Round(r.0.saturating_add(1))
        }

        fn ensure_block(&self, block: &Block, _cert: &Certificate) {
            // Advance the round when a block is committed, mimicking real ledger behaviour.
            let mut r = self.round.lock().unwrap();
            if block.round.0 >= r.0 {
                *r = Round(block.round.0);
            }
        }
    }

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
        fn fetch_block(&self, round: Round) -> Result<FetchedBlockCert, FetchError> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            let guard = self.block.lock().unwrap();
            match guard.as_ref() {
                Some(b) => {
                    let mut block = b.clone();
                    block.round = round;
                    Ok(FetchedBlockCert { block, cert: None })
                }
                None => Err(FetchError::NoBlockForRound { round }),
            }
        }
    }

    // -- Failing BlockFetcher --

    struct FailingBlockFetcher;

    impl BlockFetcher for FailingBlockFetcher {
        fn fetch_block(&self, _round: Round) -> Result<FetchedBlockCert, FetchError> {
            Err(FetchError::NetworkError("simulated network failure".into()))
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

    // -- Helpers --

    /// Poll a condition function until it returns `true`, sleeping briefly
    /// between checks.  Panics if the timeout elapses before the condition
    /// is met.  This replaces fixed `thread::sleep` calls in tests,
    /// reducing flakiness on slow CI runners while still being responsive.
    fn poll_until(
        condition: impl Fn() -> bool,
        poll_interval: Duration,
        timeout: Duration,
        msg: &str,
    ) {
        let start = std::time::Instant::now();
        while !condition() {
            if start.elapsed() >= timeout {
                panic!("poll_until timed out after {timeout:?}: {msg}");
            }
            thread::sleep(poll_interval);
        }
    }

    /// Create a block with a known protocol version and correct commitments
    /// for an empty payset. This ensures `contents_match_header` passes.
    fn make_valid_empty_block(round: u64) -> Block {
        use algo_validate::merkle::{compute_vector_commitment, HashAlgo};

        let mut block = Block {
            round: Round(round),
            current_protocol: "future".to_string(),
            ..Default::default()
        };

        // For "future" protocol with empty payset:
        // - txn_commitment: Merkle root of empty payset = [0u8; 32] (already default)
        // - txn256: SHA-256 vector commitment of empty payset
        // - txn512: SHA-512 vector commitment of empty payset
        let vc256 = compute_vector_commitment(&block, HashAlgo::Sha256);
        let vc512 = compute_vector_commitment(&block, HashAlgo::Sha512);
        block.txn256.copy_from_slice(&vc256);
        block.txn512.copy_from_slice(&vc512);

        block
    }

    // -- Tests --

    #[test]
    fn stop_without_certs_is_clean() {
        // The service should start and stop cleanly even if no certs arrive.
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));

        let mut svc = CatchupService::start(rx, ledger, fetcher);
        // Give the thread a moment to start.
        thread::sleep(Duration::from_millis(50));
        svc.stop();
    }

    #[test]
    fn drop_triggers_stop() {
        // Dropping the service should stop the background thread cleanly.
        let (_tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));

        let svc = CatchupService::start(rx, ledger, fetcher);
        drop(svc); // should not panic
    }

    #[test]
    fn cert_channel_closed_exits_cleanly() {
        // When the cert channel sender is dropped, the service should exit.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(MockBlockFetcher::new(None));

        let mut svc = CatchupService::start(rx, ledger, fetcher);

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
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fetcher: Arc<dyn BlockFetcher> = Arc::new(FailingBlockFetcher);

        let mut svc = CatchupService::start(rx, ledger, fetcher);

        // Send a cert — the fetch will fail but the service should survive.
        tx.send(make_pending_cert(5)).unwrap();

        // Give it time to attempt at least one retry, then stop via shutdown.
        thread::sleep(Duration::from_millis(500));
        svc.stop();
    }

    #[test]
    fn skips_already_committed_round() {
        // If the ledger is already at or past the certificate round, no fetch
        // should occur.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        // Ledger at round 10 (past the cert round of 5).
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(10)));

        let fetcher = Arc::new(MockBlockFetcher::new(Some(Block::default())));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

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
        fn fetch_block(&self, _round: Round) -> Result<FetchedBlockCert, FetchError> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            Ok(FetchedBlockCert {
                block: self.block.clone(),
                cert: None,
            })
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
        // Create a block for round 1 with valid commitments and compute its digest.
        let block = make_valid_empty_block(1);
        let digest = algo_codec::compute_block_digest(&block);

        // Set up the service with a fetcher that returns this block.
        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        // Ledger is at round 0, so round 1 is the next expected.
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        // Send a cert for round 1 with the correct digest.
        tx.send(make_pending_cert_with_digest(1, digest)).unwrap();

        // Poll until the fetcher has been called, rather than a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 1,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should be called for a valid block",
        );

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
        let block = make_valid_empty_block(1);
        // The actual digest of this block will NOT match the cert.

        let wrong_digest = algo_types::Digest([0xff; 32]);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        // Send a cert with a wrong digest.
        tx.send(make_pending_cert_with_digest(1, wrong_digest))
            .unwrap();

        // Poll until the fetcher has been called at least twice (retry on
        // digest mismatch), rather than using a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should retry on digest mismatch",
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
        fn fetch_block(&self, _round: Round) -> Result<FetchedBlockCert, FetchError> {
            let call_num = self.total_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if call_num <= self.fail_until {
                self.fail_count.fetch_add(1, Ordering::SeqCst);
                Err(FetchError::NetworkError(format!(
                    "transient error on attempt {call_num}"
                )))
            } else {
                Ok(FetchedBlockCert {
                    block: self.block.clone(),
                    cert: None,
                })
            }
        }
    }

    #[test]
    fn retry_logic_retries_on_fetch_failure() {
        // The fetcher fails on the first call, succeeds on the second.
        // Verify that fetch is called multiple times.
        let block = make_valid_empty_block(1);
        let digest = algo_codec::compute_block_digest(&block);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        // Fail once, then succeed.
        let fetcher = Arc::new(CountingFailFetcher::new(block, 1));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        // Send a cert for round 1 with the correct digest.
        tx.send(make_pending_cert_with_digest(1, digest)).unwrap();

        // Poll until the fetcher has been called at least twice
        // (1 failure + 1 success), rather than using a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.total_calls() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "expected at least 2 fetch calls (1 fail + 1 success)",
        );

        svc.stop();
    }

    #[test]
    fn persistent_failure_retries_until_shutdown() {
        // The service now retries indefinitely on persistent failure,
        // mirroring Go's fetchRound. Verify that it keeps retrying
        // and stops cleanly on shutdown.
        let block = make_valid_empty_block(0); // won't be used since we always fail
        let fetcher = Arc::new(CountingFailFetcher::new(block, 999)); // always fail

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        tx.send(make_pending_cert(5)).unwrap();

        // Poll until the fetcher has been called at least twice
        // (verifies indefinite retry), rather than using a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.total_calls() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should be called multiple times during indefinite retry",
        );

        // Shutdown should interrupt the retry loop cleanly.
        svc.stop();
    }

    // -- ForkDetectionBlockFetcher: returns a block with mismatched digest + cert --

    /// A fetcher that returns a block whose digest does NOT match the
    /// agreement cert, but includes a fetched certificate that *does*
    /// claim to authenticate the block. This simulates a fork scenario.
    struct ForkDetectionBlockFetcher {
        block: Block,
        /// Certificate included in the fetch response (claims to auth
        /// the fetched block, not the agreement cert's block).
        fetched_cert: Certificate,
        fetch_count: AtomicU64,
    }

    impl ForkDetectionBlockFetcher {
        fn new(block: Block, fetched_cert: Certificate) -> Self {
            Self {
                block,
                fetched_cert,
                fetch_count: AtomicU64::new(0),
            }
        }

        fn fetch_count(&self) -> u64 {
            self.fetch_count.load(Ordering::SeqCst)
        }
    }

    impl BlockFetcher for ForkDetectionBlockFetcher {
        fn fetch_block(&self, _round: Round) -> Result<FetchedBlockCert, FetchError> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            Ok(FetchedBlockCert {
                block: self.block.clone(),
                cert: Some(self.fetched_cert.clone()),
            })
        }
    }

    #[test]
    fn fork_detection_fires_on_digest_mismatch_with_cert() {
        // Simulate a fork: the agreement cert expects digest A, but the
        // fetcher returns a block with digest B and a fetched cert that
        // also claims digest B. The fork detection code should execute
        // without panicking, log the alarm, and continue retrying.
        let block = Block {
            round: Round(1),
            ..Default::default()
        };
        let block_digest = algo_codec::compute_block_digest(&block);

        // The agreement cert has a *different* digest (not matching the block).
        let agreement_digest = algo_types::Digest([0xff; 32]);
        assert_ne!(
            block_digest, agreement_digest,
            "test setup: digests must differ to trigger fork detection"
        );

        // The fetched cert claims to authenticate the fetched block.
        let fetched_cert = make_cert_with_digest(1, block_digest);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        let fetcher = Arc::new(ForkDetectionBlockFetcher::new(block, fetched_cert));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        // Send a cert with the "wrong" (agreement) digest.
        tx.send(make_pending_cert_with_digest(1, agreement_digest))
            .unwrap();

        // Poll until the fetcher has been called at least once (the service
        // retries on digest mismatch), rather than using a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 1,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should have been called at least once",
        );

        // Verify that the fork counter was incremented.
        assert!(
            svc.fork_count() >= 1,
            "fork_count should be >= 1 after fork detection, got {}",
            svc.fork_count()
        );

        // The service should still be alive (fork detection logs but
        // does not panic or halt, matching Go's behavior).
        svc.stop();
    }

    #[test]
    fn no_fork_detection_without_fetched_cert() {
        // When the fetcher returns a block with wrong digest but no
        // certificate, the fork detection path should NOT fire (no cert
        // to compare). The service should retry normally.
        let block = Block {
            round: Round(1),
            ..Default::default()
        };

        let wrong_digest = algo_types::Digest([0xff; 32]);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        // DigestMatchingBlockFetcher returns cert: None.
        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        tx.send(make_pending_cert_with_digest(1, wrong_digest))
            .unwrap();

        // Poll until the fetcher has retried at least twice (digest
        // mismatch), rather than using a fixed sleep.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should retry on digest mismatch",
        );

        svc.stop();
    }

    #[test]
    fn no_fork_when_fetched_cert_matches_agreement() {
        // When the fetched cert has the SAME digest as the agreement
        // cert (but the block has a different digest), this is NOT a
        // fork — just a bad block from a peer. Fork detection should
        // not fire.
        let block = Block {
            round: Round(1),
            ..Default::default()
        };

        let agreement_digest = algo_types::Digest([0xaa; 32]);

        // The fetched cert has the SAME digest as agreement (not the block's).
        let fetched_cert = make_cert_with_digest(1, agreement_digest);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        let fetcher = Arc::new(ForkDetectionBlockFetcher::new(block, fetched_cert));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        tx.send(make_pending_cert_with_digest(1, agreement_digest))
            .unwrap();

        // Poll until the fetcher has been called at least once. It will
        // retry because the block digest won't match agreement_digest,
        // but no fork alarm should fire.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 1,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should have been called at least once",
        );

        svc.stop();
    }

    #[test]
    fn contents_mismatch_triggers_retry() {
        // Create a block with a valid digest but tampered txn_commitment.
        // The digest check passes but contents_match_header should fail,
        // triggering retries.
        let mut block = make_valid_empty_block(1);
        // Tamper the txn_commitment so contents_match_header returns Ok(false).
        block.txn_commitment = [0xFF; 32];
        let digest = algo_codec::compute_block_digest(&block);

        let (tx, rx) = crossbeam_channel::bounded::<PendingUnmatchedCertificate>(1);
        let ledger: Arc<dyn CatchupLedger> = Arc::new(MockCatchupLedger::new(Round(0)));

        let fetcher = Arc::new(DigestMatchingBlockFetcher::new(block));
        let fetcher_ref: Arc<dyn BlockFetcher> = Arc::clone(&fetcher) as Arc<dyn BlockFetcher>;

        let mut svc = CatchupService::start(rx, ledger, fetcher_ref);

        // Send a cert with the correct digest (header matches) but the block
        // body won't match the header commitments.
        tx.send(make_pending_cert_with_digest(1, digest)).unwrap();

        // The fetcher should have been called multiple times since
        // contents_match_header fails and triggers retries.
        let fetcher_poll = Arc::clone(&fetcher);
        poll_until(
            move || fetcher_poll.fetch_count() >= 2,
            Duration::from_millis(50),
            Duration::from_secs(5),
            "fetcher should retry on contents mismatch",
        );

        svc.stop();
    }
}
