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

//! An async worker pool for transaction-group signature verification,
//! mirroring go's `StreamToBatch` architecture
//! (`data/transactions/verify/txnBatch.go`): incoming groups are queued,
//! opportunistically batched, and verified off the caller's task, with
//! graceful shutdown, cancellation, and per-job panic isolation.
//!
//! This is not a literal port of go's goroutine-pool/`execpool.BatchProcessor`
//! machinery -- the bar (per issue #1017) is matching the *behavioral*
//! guarantees go's tests pin, using whatever concurrency primitive fits
//! algod-rust's async runtime (tokio):
//!
//! - **Batched dispatch**: jobs submitted close together are opportunistically
//!   grouped (up to [`BatchVerifierConfig::max_batch_size`], within
//!   [`BatchVerifierConfig::batch_linger`]) so a burst of gossip traffic
//!   doesn't spawn a task per group.
//! - **Graceful shutdown**: [`BatchVerifier::shutdown`] stops accepting new
//!   work and waits for every worker to drain its already-queued jobs before
//!   returning -- nothing queued is silently dropped.
//! - **Cancellation**: [`BatchVerifier::cancel`] (or dropping the last
//!   verifier and cancelling its token) stops workers from picking up further
//!   batches; in-flight submissions are rejected rather than left hanging.
//! - **Panic/error isolation per batch**: one job's verification panicking
//!   (Go: `ProcessBatch`'s own `recover()`) is caught and reported as an
//!   error for *that* job only -- the rest of the batch, and the worker
//!   itself, keep running.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use algo_error::AlgoError;
use algo_types::SignedTransaction;

use crate::rules::ConsensusParams;
use crate::verified_txn_cache::{verify_transaction_group_cached, VerificationContext};
use crate::VerifiedTransactionCache;

/// A single transaction group to verify, together with the context real
/// verification needs. Mirrors go's `UnverifiedTxnSigJob` (minus the
/// `BacklogMessage` passthrough -- callers correlate results via the
/// returned future instead of an out-of-band channel).
#[derive(Debug, Clone)]
pub struct BatchVerifyRequest {
    pub group: Vec<SignedTransaction>,
    pub context: VerificationContext,
    pub params: ConsensusParams,
}

/// Tuning knobs for a [`BatchVerifier`]. Mirrors the shape of go's
/// `MakeStreamToBatch` parameters (worker count, batch size) without
/// depending on go's specific defaults, which are tuned for a goroutine
/// pool rather than tokio tasks.
#[derive(Debug, Clone, Copy)]
pub struct BatchVerifierConfig {
    /// Number of concurrent worker tasks pulling from the shared queue.
    pub num_workers: usize,
    /// Maximum number of jobs a worker batches together before verifying.
    pub max_batch_size: usize,
    /// How long a worker waits for more jobs to arrive before verifying
    /// whatever it already has, once it has at least one job in hand.
    pub batch_linger: Duration,
    /// Bounded channel capacity for queued-but-not-yet-picked-up jobs.
    pub queue_capacity: usize,
}

impl Default for BatchVerifierConfig {
    fn default() -> Self {
        BatchVerifierConfig {
            num_workers: 4,
            max_batch_size: 32,
            batch_linger: Duration::from_millis(2),
            queue_capacity: 1024,
        }
    }
}

/// A verification job actually performed by a worker. Pluggable purely so
/// tests can inject panics/failures without depending on crafting a real
/// malformed signature -- production code should always go through
/// [`BatchVerifier::spawn`], which wires up real `verify_transaction_group_cached`.
type VerifyJob =
    dyn Fn(&BatchVerifyRequest, &VerifiedTransactionCache) -> Result<(), AlgoError> + Send + Sync;

fn default_verify(
    request: &BatchVerifyRequest,
    cache: &VerifiedTransactionCache,
) -> Result<(), AlgoError> {
    verify_transaction_group_cached(&request.group, &request.context, &request.params, cache)
}

struct QueuedJob {
    request: BatchVerifyRequest,
    respond: oneshot::Sender<Result<(), AlgoError>>,
}

/// An async worker pool verifying transaction groups off the caller's task.
/// See the module docs for the behavioral guarantees this provides.
///
/// Internally, a single dispatcher task owns the job queue (`mpsc::Receiver`)
/// exclusively -- no lock sharing, no risk of a worker parking mid-receive
/// while holding a lock other workers need. The dispatcher groups incoming
/// jobs into batches and hands each batch to a bounded pool of concurrent
/// batch-processing tasks (bounded via a [`tokio::sync::Semaphore`] sized to
/// `num_workers`), which is what actually gives "up to N batches verifying
/// concurrently."
pub struct BatchVerifier {
    sender: mpsc::Sender<QueuedJob>,
    cancel: CancellationToken,
    dispatcher: StdMutex<Option<JoinHandle<()>>>,
}

impl BatchVerifier {
    /// Spawn a pool that verifies against `cache` using the real
    /// [`verify_transaction_group_cached`] (cache-hit skip + populate on
    /// success).
    pub fn spawn(config: BatchVerifierConfig, cache: Arc<VerifiedTransactionCache>) -> Self {
        Self::spawn_with_verifier(config, cache, Arc::new(default_verify))
    }

    /// Like [`BatchVerifier::spawn`], but with a caller-supplied verification
    /// closure. Exposed so tests can exercise panic isolation and failure
    /// paths without needing a genuinely malformed signature; production
    /// callers should use [`BatchVerifier::spawn`].
    pub fn spawn_with_verifier(
        config: BatchVerifierConfig,
        cache: Arc<VerifiedTransactionCache>,
        verify_fn: Arc<VerifyJob>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(config.queue_capacity.max(1));
        let cancel = CancellationToken::new();
        let dispatcher_cancel = cancel.clone();
        let max_batch_size = config.max_batch_size.max(1);
        let batch_linger = config.batch_linger;
        let permits = Arc::new(tokio::sync::Semaphore::new(config.num_workers.max(1)));

        let dispatcher = tokio::spawn(dispatcher_loop(
            receiver,
            cache,
            verify_fn,
            dispatcher_cancel,
            max_batch_size,
            batch_linger,
            permits,
        ));

        BatchVerifier {
            sender,
            cancel,
            dispatcher: StdMutex::new(Some(dispatcher)),
        }
    }

    /// Submit a group for verification, awaiting the result. Returns an
    /// error immediately (without touching the queue) once the pool has
    /// been cancelled, mirroring go's tests asserting that a cancelled
    /// `StreamToBatch` rejects further work rather than accepting it and
    /// hanging.
    pub fn verify(
        &self,
        request: BatchVerifyRequest,
    ) -> impl Future<Output = Result<(), AlgoError>> + '_ {
        let cancel = self.cancel.clone();
        let sender = self.sender.clone();
        async move {
            if cancel.is_cancelled() {
                return Err(AlgoError::Validation {
                    message: "batch verifier is cancelled".into(),
                });
            }
            let (respond, response) = oneshot::channel();
            sender
                .send(QueuedJob { request, respond })
                .await
                .map_err(|_| AlgoError::Validation {
                    message: "batch verifier has shut down".into(),
                })?;
            response.await.map_err(|_| AlgoError::Validation {
                message: "batch verifier worker dropped the job without responding".into(),
            })?
        }
    }

    /// Stop the pool from picking up any further batch. Jobs already queued
    /// or mid-batch are still delivered a result (best-effort drain), not
    /// silently dropped -- but no new submission is accepted after this
    /// returns (see [`BatchVerifier::verify`]'s early check).
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Gracefully stop the pool: stop accepting new submissions, then wait
    /// for the dispatcher to drain whatever is already queued (and every
    /// batch-processing task it spawned for that work) before returning.
    /// Mirrors go's `TxnGroupBatchSigVerifier`/pool shutdown -- queued work
    /// is completed, not abandoned.
    pub async fn shutdown(self) {
        // Dropping the sender closes the channel once all in-flight
        // `verify()` calls' clones are also dropped; the dispatcher observes
        // the close via `recv() == None` after draining what's already
        // queued.
        drop(self.sender);
        let handle = self
            .dispatcher
            .lock()
            .expect("dispatcher mutex poisoned")
            .take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }
}

/// The single task that owns the job queue: pull at least one job,
/// opportunistically extend the batch up to `max_batch_size` within
/// `batch_linger`, then hand the batch to a spawned task (gated by
/// `permits`, giving up to `num_workers` batches verifying concurrently).
/// Exits once the channel closes (graceful shutdown) after every spawned
/// batch task has been joined.
#[allow(clippy::too_many_arguments)]
async fn dispatcher_loop(
    mut receiver: mpsc::Receiver<QueuedJob>,
    cache: Arc<VerifiedTransactionCache>,
    verify_fn: Arc<VerifyJob>,
    cancel: CancellationToken,
    max_batch_size: usize,
    batch_linger: Duration,
    permits: Arc<tokio::sync::Semaphore>,
) {
    let mut in_flight: Vec<JoinHandle<()>> = Vec::new();

    loop {
        let first = tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            job = receiver.recv() => job,
        };
        let Some(first) = first else {
            // Channel closed (graceful shutdown) or cancelled while idle --
            // either way, no more NEW batches are started. Join whatever is
            // already running before returning so shutdown() waits for real
            // completion, not just the dispatcher's own exit.
            break;
        };

        let mut batch = vec![first];
        let deadline = tokio::time::Instant::now() + batch_linger;
        while batch.len() < max_batch_size {
            match tokio::time::timeout_at(deadline, receiver.recv()).await {
                Ok(Some(job)) => batch.push(job),
                Ok(None) => break, // channel closed; verify what we have
                Err(_) => break,   // linger elapsed; verify what we have
            }
        }

        // Bound concurrency at `num_workers` batches in flight. Acquiring
        // the permit here (before spawning) means a burst larger than the
        // worker count naturally backs up in the dispatcher loop rather
        // than spawning unboundedly many tasks.
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore never closed");
        let cache = cache.clone();
        let verify_fn = verify_fn.clone();
        in_flight.push(tokio::spawn(async move {
            let _permit = permit;
            process_batch(batch, &cache, &verify_fn);
        }));

        // Reap finished handles so `in_flight` doesn't grow unboundedly
        // over a long-lived pool's lifetime.
        in_flight.retain(|h| !h.is_finished());
    }

    for handle in in_flight {
        let _ = handle.await;
    }
}

/// Verify every job in a batch with panic isolation: one job's verification
/// panicking (Go: `ProcessBatch`'s own `recover()`) is caught and reported
/// as an error for *that* job only -- the rest of the batch still gets a
/// real result.
fn process_batch(
    batch: Vec<QueuedJob>,
    cache: &VerifiedTransactionCache,
    verify_fn: &Arc<VerifyJob>,
) {
    for job in batch {
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| verify_fn(&job.request, cache)))
            .unwrap_or_else(|payload| {
                let msg = panic_message(&payload);
                Err(AlgoError::Validation {
                    message: format!("panic while verifying transaction batch: {msg}"),
                })
            });
        let _ = job.respond.send(outcome);
    }
}

/// Best-effort extraction of a panic payload's message, for the error text
/// surfaced to the caller whose job panicked.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::{Address, Round, Transaction};
    use ed25519_dalek::{Signer, SigningKey};

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn test_context() -> VerificationContext {
        VerificationContext {
            spec_addrs: crate::rules::SpecialAddresses::default(),
            consensus_version: "future".to_string(),
        }
    }

    fn test_params() -> ConsensusParams {
        crate::rules::consensus_params_for_version("future").unwrap()
    }

    /// Build a validly-signed single-txn group so real verification (via
    /// `BatchVerifier::spawn`) succeeds.
    fn valid_request(note: u64) -> BatchVerifyRequest {
        let key = test_signing_key();
        let pk = key.verifying_key();
        let sender = Address(pk.to_bytes());
        let txn = Transaction {
            txn_type: "pay".into(),
            sender,
            fee: 1000,
            first_valid: Round(1),
            last_valid: Round(1000),
            receiver: Address([0x42; 32]),
            amount: 1000,
            genesis_id: "test-v1".into(),
            genesis_hash: [0xAA; 32],
            note: serde_bytes::ByteBuf::from(note.to_be_bytes().to_vec()),
            ..Default::default()
        };
        let canonical = algo_codec::canonical_encode_transaction(&txn);
        let mut msg = Vec::with_capacity(2 + canonical.len());
        msg.extend_from_slice(b"TX");
        msg.extend_from_slice(&canonical);
        let sig = key.sign(&msg);
        BatchVerifyRequest {
            group: vec![SignedTransaction {
                txn,
                sig: sig.to_bytes(),
                ..Default::default()
            }],
            context: test_context(),
            params: test_params(),
        }
    }

    /// Representative case 1 (go: `TestStreamToBatchPoolShutdown`):
    /// `shutdown()` still delivers a result for work submitted beforehand,
    /// rather than abandoning it.
    #[tokio::test]
    async fn graceful_shutdown_delivers_queued_results() {
        let cache = Arc::new(VerifiedTransactionCache::new(100));
        let verifier = BatchVerifier::spawn(
            BatchVerifierConfig {
                num_workers: 1,
                ..Default::default()
            },
            cache,
        );

        let result = verifier.verify(valid_request(1)).await;
        assert!(result.is_ok(), "valid group should verify: {result:?}");

        // Graceful shutdown must return (not hang) and not panic.
        verifier.shutdown().await;
    }

    /// Representative case 2 (go: `TestStreamToBatchCtxCancel`): once
    /// cancelled, the pool rejects further submissions instead of accepting
    /// them and hanging.
    #[tokio::test]
    async fn cancellation_rejects_further_submissions() {
        let cache = Arc::new(VerifiedTransactionCache::new(100));
        let verifier = BatchVerifier::spawn(BatchVerifierConfig::default(), cache);

        // Sanity: works before cancellation.
        assert!(verifier.verify(valid_request(1)).await.is_ok());

        verifier.cancel();

        let err = verifier
            .verify(valid_request(2))
            .await
            .expect_err("submission after cancellation must be rejected");
        assert!(err.to_string().contains("cancelled"));

        verifier.shutdown().await;
    }

    /// Representative case 3 (go: `TestProcessBatchRecoversPanic`): one
    /// job's verification panicking is isolated to that job -- it's
    /// reported as an error, and a different job processed in the same
    /// batch still gets its own (successful) result rather than the whole
    /// worker/batch going down.
    #[tokio::test]
    async fn panic_in_one_job_does_not_affect_others_in_the_batch() {
        let cache = Arc::new(VerifiedTransactionCache::new(100));
        let verify_fn: Arc<VerifyJob> = Arc::new(
            |request: &BatchVerifyRequest, cache: &VerifiedTransactionCache| {
                // Sentinel: a group whose sole txn has amount == u64::MAX means
                // "panic," anything else verifies for real.
                if request
                    .group
                    .first()
                    .is_some_and(|t| t.txn.amount == u64::MAX)
                {
                    panic!("injected test panic");
                }
                default_verify(request, cache)
            },
        );
        let verifier = BatchVerifier::spawn_with_verifier(
            BatchVerifierConfig {
                num_workers: 1,
                max_batch_size: 8,
                batch_linger: Duration::from_millis(20),
                ..Default::default()
            },
            cache,
            verify_fn,
        );

        let mut panicking = valid_request(1);
        panicking.group[0].txn.amount = u64::MAX;
        let good = valid_request(2);

        // Submit concurrently so the worker has a chance to batch them
        // together (the linger above gives it room to do so).
        let (panicking_result, good_result) =
            tokio::join!(verifier.verify(panicking), verifier.verify(good));

        let panic_err = panicking_result.expect_err("panicking job must surface as an error");
        assert!(panic_err.to_string().contains("panic"));
        assert!(
            good_result.is_ok(),
            "a different job in the same batch must still succeed: {good_result:?}"
        );

        verifier.shutdown().await;
    }

    /// A cache hit is honored inside the pool too: a group verified once
    /// (via `spawn`'s real cache-backed verifier) is a cache hit on a
    /// second submission, and this is transparent to the caller -- it just
    /// gets `Ok(())` again.
    #[tokio::test]
    async fn pool_honors_verified_transaction_cache() {
        let cache = Arc::new(VerifiedTransactionCache::new(100));
        let verifier = BatchVerifier::spawn(BatchVerifierConfig::default(), cache.clone());

        let request = valid_request(3);
        assert!(verifier.verify(request.clone()).await.is_ok());

        // The group is now a cache hit.
        let unverified = cache.get_unverified_transaction_groups(
            std::slice::from_ref(&request.group),
            &request.context,
        );
        assert!(unverified.is_empty());

        // Resubmitting must still succeed (via the cache-hit skip path).
        assert!(verifier.verify(request).await.is_ok());

        verifier.shutdown().await;
    }
}
