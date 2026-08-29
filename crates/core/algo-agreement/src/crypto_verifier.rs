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

// Real CryptoVerifier implementation for the agreement protocol.
//
// Performs actual cryptographic verification of votes, proposals, and bundles
// using the VRF and OTS verification functions from algo-consensus-crypto.
//
// Verification is dispatched to background worker threads via bounded
// channels. The demux loop enqueues requests and selects on output channels,
// never blocking on verification itself.
//
// Mirrors Go's `poolCryptoVerifier` in `agreement/cryptoVerifier.go`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use tracing::{debug, warn};

use algo_types::Round;

use crate::events::Proposal;
use crate::ledger_reader::LedgerReader;
use crate::step::Period;
use crate::traits::{
    BlockValidator, CryptoBundleRequest, CryptoProposalRequest, CryptoResult, CryptoVerifier,
    CryptoVoteRequest, CryptoVoteVerifyResult, ValidatedBlock, AGREEMENT_VOTE_TAG,
    PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
};
use crate::vote::{RawVote, UnauthenticatedVote, VoteVerifyParams};

// ---------------------------------------------------------------------------
// Constants: worker pool sizes (matching Go's cryptoVerifier.go)
// ---------------------------------------------------------------------------

/// Number of vote verification worker threads.
///
/// Go uses `runtime.NumCPU()` for vote parallelism; we hardcode 16 to match
/// Go's typical server configuration. On a machine with a different core
/// count the Go implementation would differ, but 16 is a reasonable default
/// that matches the original Go constant `voteParallelism = 16`.
const VOTE_PARALLELISM: usize = 16;

/// Number of proposal verification worker threads.
///
/// Go spawns 1 goroutine for proposals with an internal exec pool; Rust uses
/// dedicated worker threads. The value 4 mirrors Go's
/// `proposalParallelism = 4`.
const PROPOSAL_PARALLELISM: usize = 4;

/// Number of bundle verification worker threads.
///
/// Go spawns 1 goroutine for bundles with an internal exec pool; Rust uses
/// dedicated worker threads. The value 2 mirrors Go's
/// `bundleParallelism = 2`.
const BUNDLE_PARALLELISM: usize = 2;

// ---------------------------------------------------------------------------
// Internal request wrappers (attach cancellation tokens)
// ---------------------------------------------------------------------------

/// Internal vote request sent to the worker thread pool.
/// Wraps the public `CryptoVoteRequest` with a cancellation token.
struct InternalVoteRequest {
    request: CryptoVoteRequest,
    cancel: Arc<AtomicBool>,
}

/// Internal proposal request sent to the worker thread pool.
/// Wraps the public `CryptoProposalRequest` with a cancellation token.
struct InternalProposalRequest {
    request: CryptoProposalRequest,
    cancel: Arc<AtomicBool>,
}

/// Internal bundle request sent to the worker thread pool.
/// Wraps the public `CryptoBundleRequest` with a cancellation token.
struct InternalBundleRequest {
    request: CryptoBundleRequest,
    cancel: Arc<AtomicBool>,
}

// ---------------------------------------------------------------------------
// PendingRequestsContext -- cancellation token management
// ---------------------------------------------------------------------------

/// Key for indexing period-level cancellation contexts within a round.
///
/// Mirrors Go's `cryptoRequestCtxKey`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CryptoRequestCtxKey {
    period: Period,
    /// If true, this key represents a cert bundle (period should be 0).
    certify: bool,
    /// If true, this key represents a pinned proposal (period should be 0).
    pinned: bool,
}

/// Per-period cancellation context.
///
/// Mirrors Go's `periodRequestsContext`. Instead of Go's `context.Context`
/// tree, we use `Arc<AtomicBool>` tokens: setting to `true` means cancelled.
struct PeriodRequestsContext {
    /// The cancellation token for this period. Shared with all requests
    /// submitted under this (round, period) combination.
    cancelled: Arc<AtomicBool>,
    /// Optional cancellation token for the currently-active proposal.
    /// When a new proposal arrives for the same (round, period), the old
    /// proposal's token is set to `true` before creating a new one.
    proposal_cancelled: Option<Arc<AtomicBool>>,
}

/// Per-round cancellation context.
///
/// Mirrors Go's `roundRequestsContext`.
struct RoundRequestsContext {
    /// The round-level cancellation token. When this is set to `true`,
    /// all requests for this round are considered cancelled.
    cancelled: Arc<AtomicBool>,
    /// Period-level contexts within this round.
    periods: HashMap<CryptoRequestCtxKey, PeriodRequestsContext>,
}

/// Manages cancellation tokens for all pending crypto verification requests.
///
/// Mirrors Go's `pendingRequestsContext` from `cryptoRequestContext.go`.
///
/// The demux calls `clear_stale_contexts` on each new request to cancel
/// requests from old rounds/periods. Workers check their token before and
/// after verification and set `cancelled: true` on the result if stale.
struct PendingRequestsContext {
    rounds: HashMap<Round, RoundRequestsContext>,
}

impl PendingRequestsContext {
    fn new() -> Self {
        Self {
            rounds: HashMap::new(),
        }
    }

    /// Get or create the period-level context for a given round + key.
    ///
    /// Mirrors Go's `getReqCtx`.
    fn get_req_ctx(
        &mut self,
        round: Round,
        pkey: CryptoRequestCtxKey,
    ) -> &mut PeriodRequestsContext {
        // Create round context if needed.
        let round_ctx = self
            .rounds
            .entry(round)
            .or_insert_with(|| RoundRequestsContext {
                cancelled: Arc::new(AtomicBool::new(false)),
                periods: HashMap::new(),
            });

        // Create period context if needed, deriving from round context.
        // (In Go, the period context is derived from the round context via
        // context.WithCancel. Here we just create a fresh AtomicBool; the
        // round-level token is checked separately by clear_stale_contexts.)
        round_ctx
            .periods
            .entry(pkey)
            .or_insert_with(|| PeriodRequestsContext {
                cancelled: Arc::new(AtomicBool::new(false)),
                proposal_cancelled: None,
            })
    }

    /// Returns a cancellation token for a vote request.
    ///
    /// Mirrors Go's `addVote`.
    fn add_vote(&mut self, round: Round, period: Period) -> Arc<AtomicBool> {
        let pkey = CryptoRequestCtxKey {
            period,
            certify: false,
            pinned: false,
        };
        self.get_req_ctx(round, pkey).cancelled.clone()
    }

    /// Returns a cancellation token for a proposal request.
    /// Cancels any previous proposal for the same (round, period/pinned).
    ///
    /// Mirrors Go's `addProposal`.
    fn add_proposal(&mut self, round: Round, period: Period, pinned: bool) -> Arc<AtomicBool> {
        let pkey = if pinned {
            CryptoRequestCtxKey {
                period: Period(0),
                certify: false,
                pinned: true,
            }
        } else {
            CryptoRequestCtxKey {
                period,
                certify: false,
                pinned: false,
            }
        };

        let period_ctx = self.get_req_ctx(round, pkey);

        // Cancel the old proposal for this (round, period).
        if let Some(ref old_cancel) = period_ctx.proposal_cancelled {
            old_cancel.store(true, Ordering::Release);
        }

        // Create a new proposal-specific cancellation token.
        let new_cancel = Arc::new(AtomicBool::new(false));
        period_ctx.proposal_cancelled = Some(new_cancel.clone());
        new_cancel
    }

    /// Returns a cancellation token for a bundle request.
    ///
    /// Mirrors Go's `addBundle`.
    fn add_bundle(&mut self, round: Round, period: Period, certify: bool) -> Arc<AtomicBool> {
        let pkey = if certify {
            CryptoRequestCtxKey {
                period: Period(0),
                certify: true,
                pinned: false,
            }
        } else {
            CryptoRequestCtxKey {
                period,
                certify: false,
                pinned: false,
            }
        };
        self.get_req_ctx(round, pkey).cancelled.clone()
    }

    /// Cancel and remove contexts for stale rounds/periods.
    ///
    /// Mirrors Go's `clearStaleContexts`:
    /// - At round r+2 we can clear tasks from round r.
    /// - At period p+3 we can clear tasks from period p (unless pinned/certify).
    fn clear_stale_contexts(&mut self, r: Round, p: Period, pinned: bool, certify: bool) {
        // Cancel old rounds: round + 2 <= r
        let old_rounds: Vec<Round> = self
            .rounds
            .keys()
            .filter(|&&round| round.0 + 2 <= r.0)
            .copied()
            .collect();
        for old_round in old_rounds {
            if let Some(round_ctx) = self.rounds.remove(&old_round) {
                round_ctx.cancelled.store(true, Ordering::Release);
                // Also cancel all period-level tokens.
                for period_ctx in round_ctx.periods.values() {
                    period_ctx.cancelled.store(true, Ordering::Release);
                    if let Some(ref prop) = period_ctx.proposal_cancelled {
                        prop.store(true, Ordering::Release);
                    }
                }
            }
        }

        // If pinned or certify, do not clear period tasks.
        if pinned || certify {
            return;
        }

        // Cancel old periods within the current round: period + 3 <= p
        if let Some(round_ctx) = self.rounds.get_mut(&r) {
            let old_periods: Vec<CryptoRequestCtxKey> = round_ctx
                .periods
                .keys()
                .filter(|pkey| !pkey.pinned && !pkey.certify && pkey.period.0 + 3 <= p.0)
                .cloned()
                .collect();
            for pkey in old_periods {
                if let Some(period_ctx) = round_ctx.periods.remove(&pkey) {
                    period_ctx.cancelled.store(true, Ordering::Release);
                    if let Some(ref prop) = period_ctx.proposal_cancelled {
                        prop.store(true, Ordering::Release);
                    }
                }
            }
            // If no more periods remain, remove the round entry.
            if round_ctx.periods.is_empty() {
                self.rounds.remove(&r);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AsyncCryptoVerifier
// ---------------------------------------------------------------------------

/// A real `CryptoVerifier` that performs actual cryptographic verification
/// using a pool of worker threads.
///
/// For votes, it verifies:
/// - The VRF credential proof (sortition)
/// - The one-time signature (OTS) on the raw vote
///
/// For proposals, it performs full block validation via the `BlockValidator`,
/// matching Go's `up.validate(ctx, round, ledger, validator)`.
///
/// For bundles, it verifies each vote in the bundle individually by
/// reconstructing the full `UnauthenticatedVote` from the bundle's shared
/// round/period/step/proposal and each `VoteAuthenticator`.
///
/// Verification is dispatched to background worker threads via bounded
/// channels. The demux loop enqueues requests and selects on output channels,
/// never blocking on verification itself.
///
/// Mirrors Go's `poolCryptoVerifier`.
pub struct AsyncCryptoVerifier<
    L: LedgerReader + Send + Sync + 'static,
    BV: BlockValidator + Send + Sync + 'static = NoOpValidator,
> {
    #[allow(dead_code)]
    ledger: Arc<L>,

    // -- Bounded input channels (senders, wrapped in Mutex<Option> so quit()
    //    can explicitly drop them to close channels and unblock workers) --
    vote_in_tx: Mutex<Option<crossbeam_channel::Sender<InternalVoteRequest>>>,
    proposal_in_tx: Mutex<Option<crossbeam_channel::Sender<InternalProposalRequest>>>,
    bundle_in_tx: Mutex<Option<crossbeam_channel::Sender<InternalBundleRequest>>>,

    // -- Bounded input channels (receivers, kept for len/capacity queries) --
    vote_in_rx: crossbeam_channel::Receiver<InternalVoteRequest>,
    proposal_in_rx: crossbeam_channel::Receiver<InternalProposalRequest>,
    bundle_in_rx: crossbeam_channel::Receiver<InternalBundleRequest>,

    // -- Bounded output channels (receivers, exposed via verified_*) --
    vote_out_rx: crossbeam_channel::Receiver<CryptoVoteVerifyResult>,
    proposal_out_rx: crossbeam_channel::Receiver<CryptoResult>,
    bundle_out_rx: crossbeam_channel::Receiver<CryptoResult>,

    // -- Bounded output channels (senders, kept alive so the output channels
    //    don't close when workers exit; also needed for channel_full capacity queries) --
    #[allow(dead_code)]
    vote_out_tx: crossbeam_channel::Sender<CryptoVoteVerifyResult>,
    #[allow(dead_code)]
    proposal_out_tx: crossbeam_channel::Sender<CryptoResult>,
    #[allow(dead_code)]
    bundle_out_tx: crossbeam_channel::Sender<CryptoResult>,

    /// A receiver that never yields, returned for unknown tags.
    never_rx: crossbeam_channel::Receiver<CryptoResult>,

    /// Quit signal sender. Dropping this closes the channel, which causes all
    /// workers to observe a `recv` on `quit_rx` and exit their loops, even
    /// if they are blocked on a full output `send`. Wrapped in
    /// `Mutex<Option<...>>` so `quit()` can explicitly drop it.
    quit_signal_tx: Mutex<Option<crossbeam_channel::Sender<()>>>,

    /// Worker thread handles. Wrapped in Mutex<Option<...>> so quit(&self)
    /// can take ownership and join.
    worker_handles: Mutex<Option<Vec<thread::JoinHandle<()>>>>,

    /// Cancellation context for pending requests.
    /// Wrapped in Mutex because verify_* take &self but need mutable access.
    /// Only accessed from the demux loop thread, so contention is zero.
    cancellation: Mutex<PendingRequestsContext>,

    /// Marker for the validator type parameter.
    _validator: std::marker::PhantomData<BV>,
}

// ---------------------------------------------------------------------------
// Worker functions
// ---------------------------------------------------------------------------

/// Vote worker loop: receives votes, verifies them, sends results.
///
/// Uses `crossbeam_channel::select!` on both input recv and output send so
/// that a quit signal can interrupt the worker even when blocked on a full
/// output channel. This prevents the deadlock where `quit()` joins workers
/// that are stuck trying to send into a channel nobody is reading.
fn vote_worker<L: LedgerReader + Send + Sync + 'static>(
    rx: crossbeam_channel::Receiver<InternalVoteRequest>,
    tx: crossbeam_channel::Sender<CryptoVoteVerifyResult>,
    quit_rx: crossbeam_channel::Receiver<()>,
    ledger: Arc<L>,
) {
    loop {
        // Wait for either a new request or a quit signal.
        let internal = crossbeam_channel::select! {
            recv(rx) -> msg => match msg {
                Ok(req) => req,
                Err(_) => break, // Input channel closed.
            },
            recv(quit_rx) -> _ => break,
        };

        let request = &internal.request;

        // Check cancellation before doing expensive work.
        if internal.cancel.load(Ordering::Acquire) {
            let result = CryptoVoteVerifyResult {
                vote: None,
                message: request.message.clone(),
                task_index: request.task_index,
                err: Some(crate::events::SerializableError::new(
                    "vote verification cancelled".to_string(),
                )),
                cancelled: true,
            };
            // Use select! on send so quit signal can interrupt a full channel.
            crossbeam_channel::select! {
                send(tx, result) -> _ => {},
                recv(quit_rx) -> _ => break,
            }
            continue;
        }

        let mut result = verify_vote_impl(ledger.as_ref(), request);
        if let Some(ref err) = result.err {
            let rv = &request.message.unauthenticated_vote.raw_vote;
            warn!(
                event = "vote_verify_failed",
                sender = ?rv.sender,
                round = rv.round.0,
                period = rv.period.0,
                step = %rv.step,
                err = %err,
                "incoming vote failed verification"
            );
        }

        // Check cancellation again after verification.
        if internal.cancel.load(Ordering::Acquire) {
            result.cancelled = true;
        }

        // Use select! on send so quit signal can interrupt a full channel.
        crossbeam_channel::select! {
            send(tx, result) -> _ => {},
            recv(quit_rx) -> _ => break,
        }
    }
}

/// Proposal worker loop: receives proposals, validates via BlockValidator, sends results.
///
/// Uses `crossbeam_channel::select!` on both input recv and output send so
/// that a quit signal can interrupt the worker even when blocked on a full
/// output channel.
fn proposal_worker<BV: BlockValidator + Send + Sync + 'static>(
    rx: crossbeam_channel::Receiver<InternalProposalRequest>,
    tx: crossbeam_channel::Sender<CryptoResult>,
    quit_rx: crossbeam_channel::Receiver<()>,
    validator: Arc<BV>,
) {
    loop {
        let internal = crossbeam_channel::select! {
            recv(rx) -> msg => match msg {
                Ok(req) => req,
                Err(_) => break,
            },
            recv(quit_rx) -> _ => break,
        };

        let request = &internal.request;

        // Check cancellation before doing expensive work.
        if internal.cancel.load(Ordering::Acquire) {
            let mut m = request.message.clone();
            // Set proposal on the message even when cancelled, matching Go.
            m.proposal = Some(Proposal {
                unauthenticated_proposal: m.unauthenticated_proposal.clone(),
                ..Proposal::default()
            });
            let result = CryptoResult {
                message: m,
                task_index: request.task_index,
                err: Some(crate::events::SerializableError::new(
                    "proposal verification cancelled".to_string(),
                )),
                cancelled: true,
            };
            crossbeam_channel::select! {
                send(tx, result) -> _ => {},
                recv(quit_rx) -> _ => break,
            }
            continue;
        }

        let mut result = verify_proposal_impl(validator.as_ref(), request);

        // Check cancellation again after verification.
        if internal.cancel.load(Ordering::Acquire) {
            result.cancelled = true;
            if result.err.is_none() {
                result.err = Some(crate::events::SerializableError::new(
                    "proposal verification cancelled".to_string(),
                ));
            }
        }

        crossbeam_channel::select! {
            send(tx, result) -> _ => {},
            recv(quit_rx) -> _ => break,
        }
    }
}

/// Bundle worker loop: receives bundles, verifies each vote, sends results.
///
/// Uses `crossbeam_channel::select!` on both input recv and output send so
/// that a quit signal can interrupt the worker even when blocked on a full
/// output channel.
fn bundle_worker<L: LedgerReader + Send + Sync + 'static>(
    rx: crossbeam_channel::Receiver<InternalBundleRequest>,
    tx: crossbeam_channel::Sender<CryptoResult>,
    quit_rx: crossbeam_channel::Receiver<()>,
    ledger: Arc<L>,
) {
    loop {
        let internal = crossbeam_channel::select! {
            recv(rx) -> msg => match msg {
                Ok(req) => req,
                Err(_) => break,
            },
            recv(quit_rx) -> _ => break,
        };

        let request = &internal.request;

        // Check cancellation before doing expensive work.
        if internal.cancel.load(Ordering::Acquire) {
            let result = CryptoResult {
                message: request.message.clone(),
                task_index: request.task_index,
                err: Some(crate::events::SerializableError::new(
                    "bundle verification cancelled".to_string(),
                )),
                cancelled: true,
            };
            crossbeam_channel::select! {
                send(tx, result) -> _ => {},
                recv(quit_rx) -> _ => break,
            }
            continue;
        }

        let mut result = verify_bundle_impl(ledger.as_ref(), request);

        // Check cancellation again after verification.
        if internal.cancel.load(Ordering::Acquire) {
            result.cancelled = true;
        }

        crossbeam_channel::select! {
            send(tx, result) -> _ => {},
            recv(quit_rx) -> _ => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Verification logic (free functions, shared between workers and tests)
// ---------------------------------------------------------------------------

/// Verify a single vote against the ledger.
///
/// Looks up the voter's account data (OTS master key, VRF selection key,
/// balance, etc.) from the ledger and delegates to
/// `UnauthenticatedVote::verify()`.
fn verify_vote_impl<L: LedgerReader>(
    ledger: &L,
    request: &CryptoVoteRequest,
) -> CryptoVoteVerifyResult {
    let uv = &request.message.unauthenticated_vote;
    let rv = &uv.raw_vote;

    // Look up membership + account data from the ledger.
    let lookup_result = crate::ledger_reader::membership_from_ledger(
        ledger,
        &rv.sender,
        request.round,
        request.period,
        rv.step,
    );

    let (membership, record, cparams) = match lookup_result {
        Ok(v) => v,
        Err(e) => {
            return CryptoVoteVerifyResult {
                vote: None,
                message: request.message.clone(),
                task_index: request.task_index,
                err: Some(crate::events::SerializableError::new(format!(
                    "ledger lookup failed for vote verification: {e}"
                ))),
                cancelled: false,
            };
        }
    };

    let params = VoteVerifyParams {
        membership,
        vote_id: record.vote_id,
        vote_first_valid: record.vote_first_valid,
        vote_last_valid: record.vote_last_valid,
        vote_key_dilution: record.vote_key_dilution,
        consensus_params: cparams,
    };

    match uv.verify(&params) {
        Ok(vote) => {
            // Go stores the authenticated vote *on the message* before
            // handing the response back —
            // `req.message.Vote = v` in
            // `AsyncVoteVerifier.executeVoteVerification`
            // (agreement/asyncVoteVerifier.go:107) — because the demux
            // forwards only `r.message` into the `voteVerified` event
            // (`agreement/demux.go:345`).  Without this the
            // `proposalManager` sees a `VoteVerified` event whose
            // `input.vote` is `None` and panics on the very first
            // successfully-verified proposal-vote (issue #478).
            let mut message = request.message.clone();
            message.vote = Some(vote.clone());
            CryptoVoteVerifyResult {
                vote: Some(vote),
                message,
                task_index: request.task_index,
                err: None,
                cancelled: false,
            }
        }
        Err(e) => CryptoVoteVerifyResult {
            vote: None,
            message: request.message.clone(),
            task_index: request.task_index,
            err: Some(crate::events::SerializableError::new(format!(
                "vote verification failed: {e}"
            ))),
            cancelled: false,
        },
    }
}

/// Verify a proposal via the BlockValidator.
///
/// Mirrors Go's `verifyProposalPayload` which calls `up.validate(ctx, round, ledger, validator)`.
/// On success, attaches the `ValidatedBlock` to the `Proposal` so that
/// the ensure action can call `ensure_validated_block` instead of the
/// slower `ensure_block` (which would re-validate from scratch).
fn verify_proposal_impl<BV: BlockValidator>(
    validator: &BV,
    request: &CryptoProposalRequest,
) -> CryptoResult {
    let up = &request.message.unauthenticated_proposal;
    let mut m = request.message.clone();

    match validator.validate(&up.block) {
        Ok(validated) => {
            // Attach the validated block to the proposal, mirroring Go's
            // `makeProposalFromValidatedBlock` which stores `ve` in the
            // proposal struct.
            m.proposal = Some(Proposal {
                unauthenticated_proposal: up.clone(),
                validated_at: std::time::Duration::ZERO,
                received_at: std::time::Duration::ZERO,
                validated_block: Some({
                    // BlockValidator::validate returns Box<dyn ValidatedBlock>.
                    // The ValidatedBlock trait requires Send + Sync, so this
                    // coercion is safe.
                    let boxed: Box<dyn ValidatedBlock + Send + Sync> = validated;
                    Arc::from(boxed)
                }),
            });
            CryptoResult {
                message: m,
                task_index: request.task_index,
                err: None,
                cancelled: false,
            }
        }
        Err(e) => {
            // Validation failed. Do NOT set the proposal on the message —
            // a None proposal signals to the caller that validation failed.
            CryptoResult {
                message: m,
                task_index: request.task_index,
                err: Some(crate::events::SerializableError::new(format!(
                    "rejected invalid proposalPayload: {e}"
                ))),
                cancelled: false,
            }
        }
    }
}

/// Verify a bundle by verifying each vote it contains.
///
/// Mirrors Go's `unauthenticatedBundle.verify` (agreement/bundle.go:141):
/// reconstructs full `UnauthenticatedVote`s from the bundle's shared
/// round/period/step/proposal and each `VoteAuthenticator`, verifies each
/// one, sums the verified credential weights, and rejects the bundle if
/// the total does not reach the step's quorum
/// (Go: "bundle: did not see enough votes").
///
/// On success the *authenticated* votes are handed back on
/// `message.verified_bundle_votes` (regular votes first, then each
/// equivocation pair flattened as v0, v1) — exactly the votes list Go's
/// `voteAggregator.handle` (bundleVerified arm) replays into the vote
/// tracker so the threshold the bundle proves is observed locally.
/// Dropping them instead left every recovery bundle "without significant
/// state change" and deadlocked next-vote recovery at 50/50 stake
/// (issue #497).
fn verify_bundle_impl<L: LedgerReader>(ledger: &L, request: &CryptoBundleRequest) -> CryptoResult {
    let ub = &request.message.unauthenticated_bundle;

    let bundle_err = |msg: String| CryptoResult {
        message: request.message.clone(),
        task_index: request.task_index,
        err: Some(crate::events::SerializableError::new(msg)),
        cancelled: false,
    };

    // Go: bundles for the propose step are invalid.
    if ub.step == crate::step::PROPOSE {
        return bundle_err("unauthenticatedBundle.verify: b.Step = propose".to_string());
    }

    // Go: cap the bundle size by the step threshold (a quorum never needs
    // more votes than the threshold, so anything larger is malformed).
    let proto = match ledger.consensus_params(crate::lookback::params_round(ub.round)) {
        Ok(p) => p,
        Err(e) => {
            return bundle_err(format!(
                "unauthenticatedBundle.verify: could not get consensus params for round {}: {e}",
                crate::lookback::params_round(ub.round).0
            ));
        }
    };
    let threshold = ub.step.committee_threshold(&proto);
    let num_votes = ub.votes.len() as u64;
    let num_eq = ub.equivocation_votes.len() as u64;
    if num_votes > threshold || num_eq > threshold || num_votes + num_eq > threshold {
        return bundle_err(format!(
            "unauthenticatedBundle.verify: bundle too large: len(votes) = {num_votes}, \
             len(equivocation_votes) = {num_eq}; step threshold = {threshold}"
        ));
    }

    // Go: reject duplicate senders across both vote lists.
    let mut voters = std::collections::HashSet::with_capacity(ub.votes.len());
    for va in &ub.votes {
        if !voters.insert(va.sender) {
            return bundle_err(format!(
                "unauthenticatedBundle.verify: vote by {:?} was duplicated in bundle",
                va.sender
            ));
        }
    }
    for eva in &ub.equivocation_votes {
        if !voters.insert(eva.sender) {
            return bundle_err(format!(
                "unauthenticatedBundle.verify: equivocating vote pair by {:?} was duplicated in bundle",
                eva.sender
            ));
        }
    }

    // The authenticated votes the aggregator will replay, plus the total
    // verified weight for the quorum check.
    let mut verified_votes: Vec<crate::vote::Vote> =
        Vec::with_capacity(ub.votes.len() + 2 * ub.equivocation_votes.len());
    let mut total_weight: u64 = 0;

    // Verify each regular vote authenticator in the bundle.
    for va in &ub.votes {
        let uv = UnauthenticatedVote {
            raw_vote: RawVote {
                sender: va.sender,
                round: ub.round,
                period: ub.period,
                step: ub.step,
                proposal: ub.proposal,
            },
            cred: va.cred.clone(),
            sig: va.sig.clone(),
        };

        let lookup_result = crate::ledger_reader::membership_from_ledger(
            ledger,
            &va.sender,
            request.round,
            request.period,
            uv.raw_vote.step,
        );

        let (membership, record, cparams) = match lookup_result {
            Ok(v) => v,
            Err(e) => {
                return CryptoResult {
                    message: request.message.clone(),
                    task_index: request.task_index,
                    err: Some(crate::events::SerializableError::new(format!(
                        "ledger lookup failed for bundle vote verification: {e}"
                    ))),
                    cancelled: false,
                };
            }
        };

        let params = VoteVerifyParams {
            membership,
            vote_id: record.vote_id,
            vote_first_valid: record.vote_first_valid,
            vote_last_valid: record.vote_last_valid,
            vote_key_dilution: record.vote_key_dilution,
            consensus_params: cparams,
        };

        match uv.verify(&params) {
            Ok(vote) => {
                total_weight += vote.cred.weight;
                verified_votes.push(vote);
            }
            Err(e) => {
                return CryptoResult {
                    message: request.message.clone(),
                    task_index: request.task_index,
                    err: Some(crate::events::SerializableError::new(format!(
                        "bundle vote verification failed: {e}"
                    ))),
                    cancelled: false,
                };
            }
        }
    }

    // Verify equivocation votes -- each has two signatures for two
    // different proposals. Both must verify with the same credential.
    // The pair's credential weight counts once toward the quorum
    // (Go: `weight += res.ev.Cred.Weight`), but both authenticated votes
    // are replayed so the voteTracker performs its equivocation handling.
    for eva in &ub.equivocation_votes {
        let mut pair_weight_counted = false;
        for i in 0..2 {
            let uv = UnauthenticatedVote {
                raw_vote: RawVote {
                    sender: eva.sender,
                    round: ub.round,
                    period: ub.period,
                    step: ub.step,
                    proposal: eva.proposals[i],
                },
                cred: eva.cred.clone(),
                sig: eva.sigs[i].clone(),
            };

            let lookup_result = crate::ledger_reader::membership_from_ledger(
                ledger,
                &eva.sender,
                request.round,
                request.period,
                uv.raw_vote.step,
            );

            let (membership, record, cparams) = match lookup_result {
                Ok(v) => v,
                Err(e) => {
                    return CryptoResult {
                        message: request.message.clone(),
                        task_index: request.task_index,
                        err: Some(crate::events::SerializableError::new(format!(
                            "ledger lookup failed for equivocation vote verification: {e}"
                        ))),
                        cancelled: false,
                    };
                }
            };

            let params = VoteVerifyParams {
                membership,
                vote_id: record.vote_id,
                vote_first_valid: record.vote_first_valid,
                vote_last_valid: record.vote_last_valid,
                vote_key_dilution: record.vote_key_dilution,
                consensus_params: cparams,
            };

            match uv.verify(&params) {
                Ok(vote) => {
                    if !pair_weight_counted {
                        total_weight += vote.cred.weight;
                        pair_weight_counted = true;
                    }
                    verified_votes.push(vote);
                }
                Err(e) => {
                    return CryptoResult {
                        message: request.message.clone(),
                        task_index: request.task_index,
                        err: Some(crate::events::SerializableError::new(format!(
                            "equivocation vote verification failed: {e}"
                        ))),
                        cancelled: false,
                    };
                }
            }
        }
    }

    // Go (agreement/bundle.go:263): the verified weight must reach the
    // step's quorum, or the bundle proves nothing.
    if !ub.step.reaches_quorum(&proto, total_weight) {
        return bundle_err(format!(
            "bundle: did not see enough votes: {} < {}",
            total_weight,
            ub.step.committee_threshold(&proto)
        ));
    }

    // All votes verified successfully — hand the authenticated votes back
    // for the vote aggregator to replay (Go returns `bundle{U, Votes,
    // EquivocationVotes}` here; the aggregator flattens them the same way).
    let mut message = request.message.clone();
    message.verified_bundle_votes = verified_votes;
    CryptoResult {
        message,
        task_index: request.task_index,
        err: None,
        cancelled: false,
    }
}

// ---------------------------------------------------------------------------
// NoOpValidator — default validator for backward compatibility
// ---------------------------------------------------------------------------

/// A no-op `BlockValidator` that accepts all blocks.
///
/// Used as the default type parameter for `AsyncCryptoVerifier` to maintain
/// backward compatibility with call sites that don't yet pass a validator.
pub struct NoOpValidator;

impl BlockValidator for NoOpValidator {
    fn validate(
        &self,
        block: &algo_types::Block,
    ) -> Result<Box<dyn crate::traits::ValidatedBlock>, crate::traits::AgreementError> {
        Ok(Box::new(NoOpValidatedBlock {
            block: block.clone(),
        }))
    }
}

struct NoOpValidatedBlock {
    block: algo_types::Block,
}

impl crate::traits::ValidatedBlock for NoOpValidatedBlock {
    fn block(&self) -> &algo_types::Block {
        &self.block
    }
}

// ---------------------------------------------------------------------------
// Constructor and trait implementation
// ---------------------------------------------------------------------------

impl<L: LedgerReader + Send + Sync + 'static> AsyncCryptoVerifier<L, NoOpValidator> {
    /// Create a new `AsyncCryptoVerifier` with a no-op block validator.
    ///
    /// This constructor maintains backward compatibility with existing call
    /// sites that don't yet have a block validator. Proposals pass through
    /// without block-level validation (the ensure action will catch invalid
    /// blocks).
    ///
    /// For full proposal validation, use `new_with_validator` instead.
    pub fn new(ledger: Arc<L>) -> Self {
        Self::new_with_validator(ledger, Arc::new(NoOpValidator))
    }
}

impl<L: LedgerReader + Send + Sync + 'static, BV: BlockValidator + Send + Sync + 'static>
    AsyncCryptoVerifier<L, BV>
{
    /// Create a new `AsyncCryptoVerifier` with a real block validator.
    ///
    /// Spawns worker threads for parallel verification of votes, proposals,
    /// and bundles.
    pub fn new_with_validator(ledger: Arc<L>, validator: Arc<BV>) -> Self {
        // Bounded input/output channels:
        let (vote_in_tx, vote_in_rx) =
            crossbeam_channel::bounded::<InternalVoteRequest>(VOTE_PARALLELISM);
        let (vote_out_tx, vote_out_rx) =
            crossbeam_channel::bounded::<CryptoVoteVerifyResult>(3 * VOTE_PARALLELISM);

        let (proposal_in_tx, proposal_in_rx) =
            crossbeam_channel::bounded::<InternalProposalRequest>(1);
        let base_buffer = 3;
        // max_votes formula: in_cap + out_cap + parallelism = N + 3N + N = 5N.
        // This is equivalent to Go's `5 * numCPU` on a 16-core machine (5 * 16 = 80).
        // It sizes the proposal output channel large enough to hold all vote results
        // that could be in-flight simultaneously.
        let max_votes = VOTE_PARALLELISM + 3 * VOTE_PARALLELISM + VOTE_PARALLELISM;
        let (proposal_out_tx, proposal_out_rx) =
            crossbeam_channel::bounded::<CryptoResult>(max_votes + base_buffer);

        let (bundle_in_tx, bundle_in_rx) = crossbeam_channel::bounded::<InternalBundleRequest>(1);
        let (bundle_out_tx, bundle_out_rx) = crossbeam_channel::bounded::<CryptoResult>(3);

        // Quit signal channel: dropping the sender closes it, which makes all
        // workers' `recv(quit_rx)` arms fire in their select! loops, unblocking
        // them even if they are stuck on a full output send. We use bounded(0)
        // so no memory is wasted — it is purely a close-notification channel.
        let (quit_signal_tx, quit_signal_rx) = crossbeam_channel::bounded::<()>(0);

        // Spawn workers.
        let mut handles =
            Vec::with_capacity(VOTE_PARALLELISM + PROPOSAL_PARALLELISM + BUNDLE_PARALLELISM);

        for i in 0..VOTE_PARALLELISM {
            let rx = vote_in_rx.clone();
            let tx = vote_out_tx.clone();
            let qrx = quit_signal_rx.clone();
            let l = ledger.clone();
            handles.push(
                thread::Builder::new()
                    .name(format!("vote-worker-{i}"))
                    .spawn(move || vote_worker(rx, tx, qrx, l))
                    .expect("failed to spawn vote worker thread"),
            );
        }

        for i in 0..PROPOSAL_PARALLELISM {
            let rx = proposal_in_rx.clone();
            let tx = proposal_out_tx.clone();
            let qrx = quit_signal_rx.clone();
            let v = validator.clone();
            handles.push(
                thread::Builder::new()
                    .name(format!("proposal-worker-{i}"))
                    .spawn(move || proposal_worker(rx, tx, qrx, v))
                    .expect("failed to spawn proposal worker thread"),
            );
        }

        for i in 0..BUNDLE_PARALLELISM {
            let rx = bundle_in_rx.clone();
            let tx = bundle_out_tx.clone();
            let qrx = quit_signal_rx.clone();
            let l = ledger.clone();
            handles.push(
                thread::Builder::new()
                    .name(format!("bundle-worker-{i}"))
                    .spawn(move || bundle_worker(rx, tx, qrx, l))
                    .expect("failed to spawn bundle worker thread"),
            );
        }

        Self {
            ledger,
            vote_in_tx: Mutex::new(Some(vote_in_tx)),
            vote_in_rx,
            vote_out_tx,
            vote_out_rx,
            proposal_in_tx: Mutex::new(Some(proposal_in_tx)),
            proposal_in_rx,
            proposal_out_tx,
            proposal_out_rx,
            bundle_in_tx: Mutex::new(Some(bundle_in_tx)),
            bundle_in_rx,
            bundle_out_tx,
            bundle_out_rx,
            never_rx: crossbeam_channel::never(),
            quit_signal_tx: Mutex::new(Some(quit_signal_tx)),
            worker_handles: Mutex::new(Some(handles)),
            cancellation: Mutex::new(PendingRequestsContext::new()),
            _validator: std::marker::PhantomData,
        }
    }
}

impl<L: LedgerReader + Send + Sync + 'static, BV: BlockValidator + Send + Sync + 'static>
    CryptoVerifier for AsyncCryptoVerifier<L, BV>
{
    fn verify_vote(&self, request: CryptoVoteRequest) {
        let cancel = {
            let mut ctx = self.cancellation.lock().unwrap();
            ctx.clear_stale_contexts(request.round, request.period, false, false);
            ctx.add_vote(request.round, request.period)
        };
        let internal = InternalVoteRequest { request, cancel };
        // Clone the sender out of the mutex before sending so that quit()
        // can acquire the lock even if this send blocks on a full channel.
        let tx = {
            let guard = self.vote_in_tx.lock().unwrap();
            guard.as_ref().map(|tx| tx.clone())
        };
        if let Some(tx) = tx {
            // Try non-blocking first; fall back to blocking (matches Go's channel send).
            match tx.try_send(internal) {
                Ok(()) => {}
                Err(crossbeam_channel::TrySendError::Full(req)) => {
                    warn!(
                        task_index = req.request.task_index,
                        round = %req.request.round,
                        "vote input channel full, blocking send"
                    );
                    let _ = tx.send(req).map_err(|_| {
                        warn!("vote input channel disconnected during blocking send");
                    });
                }
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                    warn!(
                        "vote input channel disconnected, request dropped (verifier shutting down)"
                    );
                }
            }
        }
    }

    fn verify_proposal(&self, request: CryptoProposalRequest) {
        let cancel = {
            let mut ctx = self.cancellation.lock().unwrap();
            ctx.clear_stale_contexts(request.round, request.period, request.pinned, false);
            ctx.add_proposal(request.round, request.period, request.pinned)
        };
        let internal = InternalProposalRequest { request, cancel };
        // Clone the sender out of the mutex before sending so that quit()
        // can acquire the lock even if this send blocks on a full channel.
        let tx = {
            let guard = self.proposal_in_tx.lock().unwrap();
            guard.as_ref().map(|tx| tx.clone())
        };
        if let Some(tx) = tx {
            match tx.try_send(internal) {
                Ok(()) => {}
                Err(crossbeam_channel::TrySendError::Full(req)) => {
                    debug!(
                        task_index = req.request.task_index,
                        round = %req.request.round,
                        "proposal input channel full, blocking send"
                    );
                    let _ = tx.send(req).map_err(|_| {
                        warn!("proposal input channel disconnected during blocking send");
                    });
                }
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                    warn!("proposal input channel disconnected, request dropped (verifier shutting down)");
                }
            }
        }
    }

    fn verify_bundle(&self, request: CryptoBundleRequest) {
        let cancel = {
            let mut ctx = self.cancellation.lock().unwrap();
            ctx.clear_stale_contexts(request.round, request.period, false, request.certify);
            ctx.add_bundle(request.round, request.period, request.certify)
        };
        let internal = InternalBundleRequest { request, cancel };
        // Clone the sender out of the mutex before sending so that quit()
        // can acquire the lock even if this send blocks on a full channel.
        let tx = {
            let guard = self.bundle_in_tx.lock().unwrap();
            guard.as_ref().map(|tx| tx.clone())
        };
        if let Some(tx) = tx {
            match tx.try_send(internal) {
                Ok(()) => {}
                Err(crossbeam_channel::TrySendError::Full(req)) => {
                    debug!(
                        task_index = req.request.task_index,
                        round = %req.request.round,
                        "bundle input channel full, blocking send"
                    );
                    let _ = tx.send(req).map_err(|_| {
                        warn!("bundle input channel disconnected during blocking send");
                    });
                }
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                    warn!("bundle input channel disconnected, request dropped (verifier shutting down)");
                }
            }
        }
    }

    fn verified_votes(&self) -> &crossbeam_channel::Receiver<CryptoVoteVerifyResult> {
        &self.vote_out_rx
    }

    fn verified(&self, tag: &str) -> &crossbeam_channel::Receiver<CryptoResult> {
        match tag {
            PROPOSAL_PAYLOAD_TAG => &self.proposal_out_rx,
            VOTE_BUNDLE_TAG => &self.bundle_out_rx,
            _ => {
                warn!("AsyncCryptoVerifier::verified called with unknown tag: {tag}");
                &self.never_rx
            }
        }
    }

    fn channel_full(&self, tag: &str) -> bool {
        match tag {
            // Mirrors Go's ChannelFull formulas:
            AGREEMENT_VOTE_TAG => {
                // votes.in full OR insufficient output capacity to absorb pending work
                self.vote_in_rx.len() == self.vote_in_rx.capacity().unwrap_or(0)
                    || self
                        .vote_out_rx
                        .capacity()
                        .unwrap_or(0)
                        .saturating_sub(self.vote_out_rx.len())
                        < VOTE_PARALLELISM + self.vote_in_rx.len()
            }
            PROPOSAL_PAYLOAD_TAG => {
                // proposals.in full OR output has more than 1 pending result
                self.proposal_in_rx.len() == self.proposal_in_rx.capacity().unwrap_or(0)
                    || self.proposal_out_rx.len() > 1
            }
            VOTE_BUNDLE_TAG => {
                // bundles.in full OR insufficient output capacity
                self.bundle_in_rx.len() == self.bundle_in_rx.capacity().unwrap_or(0)
                    || self
                        .bundle_out_rx
                        .capacity()
                        .unwrap_or(0)
                        .saturating_sub(self.bundle_out_rx.len())
                        < 2
            }
            _ => {
                warn!("AsyncCryptoVerifier::channel_full called with unknown tag: {tag}");
                false
            }
        }
    }

    fn quit(&self) {
        // Close all input channels by dropping the senders. This causes
        // workers to see RecvError and exit their loops.
        // Mirrors Go's close(c.votes.in) + close(c.bundles.in) + close(c.proposals.in).
        {
            let mut guard = self.vote_in_tx.lock().unwrap();
            *guard = None;
        }
        {
            let mut guard = self.proposal_in_tx.lock().unwrap();
            *guard = None;
        }
        {
            let mut guard = self.bundle_in_tx.lock().unwrap();
            *guard = None;
        }

        // Drop the quit signal sender. This closes the quit channel, which
        // unblocks any worker stuck in a `select!` on a full output send.
        // Must happen BEFORE joining workers to avoid deadlock.
        {
            let mut guard = self.quit_signal_tx.lock().unwrap();
            *guard = None;
        }

        // Join all worker threads (mirrors Go's wg.Wait()).
        let handles = {
            let mut guard = self.worker_handles.lock().unwrap();
            guard.take()
        };
        if let Some(handles) = handles {
            for h in handles {
                let _ = h.join();
            }
        }
    }
}

impl<L: LedgerReader + Send + Sync + 'static, BV: BlockValidator + Send + Sync + 'static> Drop
    for AsyncCryptoVerifier<L, BV>
{
    fn drop(&mut self) {
        // Ensure channels are closed so workers can exit.
        // (quit() may have already done this; the Option<Sender> handles
        // double-close gracefully.)
        {
            let mut guard = self.vote_in_tx.lock().unwrap();
            *guard = None;
        }
        {
            let mut guard = self.proposal_in_tx.lock().unwrap();
            *guard = None;
        }
        {
            let mut guard = self.bundle_in_tx.lock().unwrap();
            *guard = None;
        }

        // Drop the quit signal sender to unblock workers stuck on full
        // output sends. Must happen BEFORE joining.
        {
            let mut guard = self.quit_signal_tx.lock().unwrap();
            *guard = None;
        }

        // Join any remaining worker threads.
        let handles = {
            let mut guard = self.worker_handles.lock().unwrap();
            guard.take()
        };
        if let Some(handles) = handles {
            for h in handles {
                let _ = h.join();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::InternalMessage;
    use crate::step::Period;
    use crate::stubs::{StubBlockValidator, StubLedger};
    use crate::vote::UnauthenticatedVote;
    use algo_types::{ConsensusParams, Round};
    use std::time::Duration;

    fn v41_params() -> ConsensusParams {
        algo_types::consensus::consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params")
    }

    #[test]
    fn async_crypto_verifier_implements_trait() {
        fn _assert<T: CryptoVerifier>() {}
        _assert::<AsyncCryptoVerifier<StubLedger>>();
        _assert::<AsyncCryptoVerifier<StubLedger, StubBlockValidator>>();
    }

    #[test]
    fn async_crypto_verifier_vote_with_bad_keys_returns_error() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let validator = Arc::new(StubBlockValidator::accepting());
        let verifier = AsyncCryptoVerifier::new_with_validator(ledger, validator);

        let request = CryptoVoteRequest {
            message: InternalMessage {
                tag: "AV".to_string(),
                unauthenticated_vote: UnauthenticatedVote::default(),
                ..InternalMessage::default()
            },
            task_index: 42,
            round: Round(10),
            period: Period(0),
        };

        verifier.verify_vote(request);

        // Should get an error result because the ledger has no account data
        // for the zero-address sender. Worker thread processes asynchronously.
        let result = verifier
            .verified_votes()
            .recv_timeout(Duration::from_secs(5))
            .expect("should have a result within 5s");
        assert_eq!(result.task_index, 42);
        assert!(
            result.err.is_some(),
            "expected error for missing account data"
        );
        assert!(result.vote.is_none());
    }

    #[test]
    fn async_crypto_verifier_proposal_passthrough() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let validator = Arc::new(StubBlockValidator::accepting());
        let verifier = AsyncCryptoVerifier::new_with_validator(ledger, validator);

        let request = CryptoProposalRequest {
            message: InternalMessage {
                tag: "PP".to_string(),
                ..InternalMessage::default()
            },
            task_index: 7,
            round: Round(5),
            period: Period(0),
            pinned: false,
        };

        verifier.verify_proposal(request);

        let result = verifier
            .verified(PROPOSAL_PAYLOAD_TAG)
            .recv_timeout(Duration::from_secs(5))
            .expect("should have a result within 5s");
        assert_eq!(result.task_index, 7);
        assert!(result.err.is_none());

        // The verifier should attach a Proposal with a ValidatedBlock to the
        // message on success, so that the ensure action can use the fast path.
        let proposal = result
            .message
            .proposal
            .as_ref()
            .expect("proposal should be populated after successful verification");
        assert!(
            proposal.validated_block.is_some(),
            "validated_block should be Some after successful block validation"
        );
    }

    /// When the block validator rejects the block, verify_proposal should
    /// return an error and NOT attach a validated block.
    #[test]
    fn async_crypto_verifier_proposal_rejected_no_validated_block() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let validator = Arc::new(StubBlockValidator::rejecting("bad block"));
        let verifier = AsyncCryptoVerifier::new_with_validator(ledger, validator);

        let request = CryptoProposalRequest {
            message: InternalMessage {
                tag: "PP".to_string(),
                ..InternalMessage::default()
            },
            task_index: 8,
            round: Round(5),
            period: Period(0),
            pinned: false,
        };

        verifier.verify_proposal(request);

        let result = verifier
            .verified(PROPOSAL_PAYLOAD_TAG)
            .recv_timeout(Duration::from_secs(5))
            .expect("should have a result within 5s");
        assert_eq!(result.task_index, 8);
        assert!(
            result.err.is_some(),
            "expected error when block validation fails"
        );
        // When validation fails, the proposal field should not be set.
        assert!(
            result.message.proposal.is_none(),
            "proposal should remain None when block validation fails"
        );
    }

    #[test]
    fn async_crypto_verifier_channel_full_initially_false() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier = AsyncCryptoVerifier::new(ledger);
        // With empty channels, nothing should be full.
        assert!(!verifier.channel_full("AV"));
        assert!(!verifier.channel_full("PP"));
        assert!(!verifier.channel_full("VB"));
    }

    #[test]
    fn pending_requests_context_add_vote() {
        let mut ctx = PendingRequestsContext::new();
        let token = ctx.add_vote(Round(10), Period(1));
        assert!(!token.load(Ordering::Acquire));

        // Same round+period returns the same token.
        let token2 = ctx.add_vote(Round(10), Period(1));
        assert!(Arc::ptr_eq(&token, &token2));
    }

    #[test]
    fn pending_requests_context_add_proposal_cancels_old() {
        let mut ctx = PendingRequestsContext::new();
        let token1 = ctx.add_proposal(Round(10), Period(1), false);
        assert!(!token1.load(Ordering::Acquire));

        // Adding a new proposal for the same (round, period) cancels the old one.
        let token2 = ctx.add_proposal(Round(10), Period(1), false);
        assert!(
            token1.load(Ordering::Acquire),
            "old proposal should be cancelled"
        );
        assert!(
            !token2.load(Ordering::Acquire),
            "new proposal should not be cancelled"
        );
    }

    #[test]
    fn pending_requests_context_clear_stale_rounds() {
        let mut ctx = PendingRequestsContext::new();
        let token_r8 = ctx.add_vote(Round(8), Period(0));
        let token_r9 = ctx.add_vote(Round(9), Period(0));
        let token_r10 = ctx.add_vote(Round(10), Period(0));

        // At round 10, rounds where round + 2 <= 10 (i.e., round <= 8) are stale.
        ctx.clear_stale_contexts(Round(10), Period(0), false, false);

        assert!(
            token_r8.load(Ordering::Acquire),
            "round 8 should be cancelled"
        );
        assert!(
            !token_r9.load(Ordering::Acquire),
            "round 9 should NOT be cancelled"
        );
        assert!(
            !token_r10.load(Ordering::Acquire),
            "round 10 should NOT be cancelled"
        );
    }

    #[test]
    fn pending_requests_context_clear_stale_periods() {
        let mut ctx = PendingRequestsContext::new();
        let token_p0 = ctx.add_vote(Round(10), Period(0));
        let token_p1 = ctx.add_vote(Round(10), Period(1));
        let token_p3 = ctx.add_vote(Round(10), Period(3));

        // At period 3, periods where period + 3 <= 3 (i.e., period <= 0) are stale.
        ctx.clear_stale_contexts(Round(10), Period(3), false, false);

        assert!(
            token_p0.load(Ordering::Acquire),
            "period 0 should be cancelled"
        );
        assert!(
            !token_p1.load(Ordering::Acquire),
            "period 1 should NOT be cancelled"
        );
        assert!(
            !token_p3.load(Ordering::Acquire),
            "period 3 should NOT be cancelled"
        );
    }

    #[test]
    fn pending_requests_context_pinned_skips_period_clearing() {
        let mut ctx = PendingRequestsContext::new();
        let token_p0 = ctx.add_vote(Round(10), Period(0));

        // With pinned=true, period clearing is skipped.
        ctx.clear_stale_contexts(Round(10), Period(5), true, false);

        assert!(
            !token_p0.load(Ordering::Acquire),
            "period 0 should NOT be cancelled when pinned"
        );
    }

    #[test]
    fn pending_requests_context_certify_skips_period_clearing() {
        let mut ctx = PendingRequestsContext::new();
        let token_p0 = ctx.add_vote(Round(10), Period(0));

        // With certify=true, period clearing is skipped.
        ctx.clear_stale_contexts(Round(10), Period(5), false, true);

        assert!(
            !token_p0.load(Ordering::Acquire),
            "period 0 should NOT be cancelled when certify"
        );
    }

    #[test]
    fn async_crypto_verifier_with_validator() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let validator = Arc::new(StubBlockValidator::accepting());
        let verifier = AsyncCryptoVerifier::new_with_validator(ledger, validator);

        let request = CryptoProposalRequest {
            message: InternalMessage {
                tag: "PP".to_string(),
                ..InternalMessage::default()
            },
            task_index: 99,
            round: Round(5),
            period: Period(0),
            pinned: false,
        };

        verifier.verify_proposal(request);

        let result = verifier
            .verified(PROPOSAL_PAYLOAD_TAG)
            .recv_timeout(Duration::from_secs(5))
            .expect("should have a result within 5s");
        assert_eq!(result.task_index, 99);
        assert!(
            result.err.is_none(),
            "accepting validator should pass: {:?}",
            result.err
        );
    }

    #[test]
    fn async_crypto_verifier_rejecting_validator() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let validator = Arc::new(StubBlockValidator::rejecting("bad block"));
        let verifier = AsyncCryptoVerifier::new_with_validator(ledger, validator);

        let request = CryptoProposalRequest {
            message: InternalMessage {
                tag: "PP".to_string(),
                ..InternalMessage::default()
            },
            task_index: 50,
            round: Round(5),
            period: Period(0),
            pinned: false,
        };

        verifier.verify_proposal(request);

        let result = verifier
            .verified(PROPOSAL_PAYLOAD_TAG)
            .recv_timeout(Duration::from_secs(5))
            .expect("should have a result within 5s");
        assert_eq!(result.task_index, 50);
        assert!(result.err.is_some(), "rejecting validator should fail");
        let err_msg = format!("{}", result.err.unwrap());
        assert!(
            err_msg.contains("bad block"),
            "error should contain reject reason: {err_msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Additional comprehensive tests
    // -----------------------------------------------------------------------

    /// Helper: create a vote request with the given task_index, round, and period.
    fn make_vote_request(task_index: u64, round: Round, period: Period) -> CryptoVoteRequest {
        CryptoVoteRequest {
            message: InternalMessage {
                tag: "AV".to_string(),
                unauthenticated_vote: UnauthenticatedVote::default(),
                ..InternalMessage::default()
            },
            task_index,
            round,
            period,
        }
    }

    /// Helper: create a proposal request with the given task_index, round, and period.
    fn make_proposal_request(
        task_index: u64,
        round: Round,
        period: Period,
        pinned: bool,
    ) -> CryptoProposalRequest {
        CryptoProposalRequest {
            message: InternalMessage {
                tag: "PP".to_string(),
                ..InternalMessage::default()
            },
            task_index,
            round,
            period,
            pinned,
        }
    }

    // (a) Thread pool concurrency: submit multiple vote requests simultaneously
    //     and verify they complete. With 16 workers, many requests should be
    //     processed concurrently.
    #[test]
    fn thread_pool_concurrent_vote_processing() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier = AsyncCryptoVerifier::new(ledger);

        let num_requests = 32u64;

        // Submit all requests as fast as possible.
        for i in 0..num_requests {
            verifier.verify_vote(make_vote_request(i, Round(10), Period(0)));
        }

        // Collect all results. With 16 workers, these should arrive quickly.
        let mut received = Vec::new();
        for _ in 0..num_requests {
            let result = verifier
                .verified_votes()
                .recv_timeout(Duration::from_secs(10))
                .expect("should receive all results within timeout");
            received.push(result.task_index);
        }

        // All task indices should be present (order may vary due to parallelism).
        received.sort();
        let expected: Vec<u64> = (0..num_requests).collect();
        assert_eq!(
            received, expected,
            "all submitted tasks should produce results"
        );
    }

    // (b) channel_full() with bounded channels: fill the vote input channel
    //     to capacity, verify channel_full(AV) returns true.
    #[test]
    fn channel_full_vote_bounded() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier = AsyncCryptoVerifier::new(ledger);

        // The vote input channel has capacity VOTE_PARALLELISM (16).
        // The vote output channel has capacity 3 * VOTE_PARALLELISM (48).
        //
        // channel_full("AV") is true when:
        //   vote_in_rx.len() == capacity  OR
        //   vote_out_rx capacity - vote_out_rx.len() < VOTE_PARALLELISM + vote_in_rx.len()
        //
        // Workers will immediately start draining the input channel, so we
        // need to fill both input and output to trigger the condition.
        //
        // Submit enough requests to fill the output channel. Since each vote
        // request results in an error (no account data), workers process quickly.
        // We need to submit enough that the output channel backs up.
        //
        // output capacity = 48, so submit more than 48 requests to fill it.
        // But workers will process and fill the output channel. The input channel
        // will only be full if we can outpace workers + output is full.
        //
        // Strategy: submit many requests, wait for output to fill, then check
        // channel_full.

        // First, fill the output channel by submitting requests and NOT draining output.
        // Output channel capacity = 3 * 16 = 48.
        // After ~48 results are on the output channel, workers will block on send.
        // At that point, submitting more will fill the input channel.
        let total_to_submit = 48 + VOTE_PARALLELISM + VOTE_PARALLELISM;
        for i in 0..total_to_submit as u64 {
            verifier.verify_vote(make_vote_request(i, Round(10), Period(0)));
        }

        // Wait a moment for workers to process and fill the output channel.
        thread::sleep(Duration::from_millis(500));

        // Now channel_full should be true because the output channel is full
        // and/or the input channel has queued items.
        assert!(
            verifier.channel_full(AGREEMENT_VOTE_TAG),
            "vote channel should be full after flooding with requests"
        );

        // Drain one result from the output channel.
        let _ = verifier
            .verified_votes()
            .recv_timeout(Duration::from_secs(1))
            .expect("should have at least one result");

        // Drain all results to clean up.
        // (Drop verifier to shut down workers first, then drain is not needed.)
        verifier.quit();
    }

    // (c) Stale context cancellation end-to-end: submit a vote for round R,
    //     then submit for round R+3 (triggering stale clearing for R).
    //     The round-R vote should have cancelled: true.
    #[test]
    fn stale_context_cancellation_end_to_end() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier = AsyncCryptoVerifier::new(ledger);

        // Submit a vote for round 5.
        verifier.verify_vote(make_vote_request(100, Round(5), Period(0)));

        // Wait for it to be processed. The result will have an error (no
        // account data) but since the worker checks the cancel token before
        // AND after verification, the cancellation check after verification
        // can see the flag if we trigger it quickly.
        //
        // However, since workers are fast, the round-5 vote likely completes
        // before we can cancel it. To test actual cancellation, we need a
        // scenario where the cancellation token is set before the worker
        // picks up the request.
        //
        // We'll test at the PendingRequestsContext level instead, then verify
        // the integration works through the verifier.
        //
        // First, verify the PendingRequestsContext correctly cancels:
        {
            let mut ctx = PendingRequestsContext::new();
            let token_r5 = ctx.add_vote(Round(5), Period(0));
            assert!(!token_r5.load(Ordering::Acquire));

            // A vote at round 8 triggers clearing for round 5 (5 + 2 <= 8).
            ctx.clear_stale_contexts(Round(8), Period(0), false, false);
            assert!(
                token_r5.load(Ordering::Acquire),
                "round 5 vote should be cancelled when round 8 arrives"
            );
        }

        // Integration test: submit many votes for round 5 to fill input channel,
        // then immediately trigger round 8 to cancel them.
        let ledger2 = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier2 = AsyncCryptoVerifier::new(ledger2);

        // Submit a vote for round 5.
        verifier2.verify_vote(make_vote_request(200, Round(5), Period(0)));

        // Now submit a vote for round 8, which triggers clear_stale_contexts
        // for round <= 6 (i.e., round 5 is stale since 5 + 2 <= 8).
        verifier2.verify_vote(make_vote_request(201, Round(8), Period(0)));

        // Collect both results.
        let mut results = Vec::new();
        for _ in 0..2 {
            let r = verifier2
                .verified_votes()
                .recv_timeout(Duration::from_secs(5))
                .expect("should get result");
            results.push(r);
        }

        // The round-8 result should not be cancelled.
        let r8_result = results.iter().find(|r| r.task_index == 201).unwrap();
        assert!(!r8_result.cancelled, "round 8 vote should NOT be cancelled");

        // The round-5 result may or may not be cancelled depending on worker
        // timing, but the cancellation token mechanism works (verified above).
        // We just verify both results arrived.
        assert_eq!(results.len(), 2, "should receive both results");

        verifier.quit();
        verifier2.quit();
    }

    // (d) Proposal validation integration: accepting vs rejecting validator.
    #[test]
    fn proposal_validation_accepting_and_rejecting() {
        // Test with accepting validator.
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let accepting = Arc::new(StubBlockValidator::accepting());
        let verifier = AsyncCryptoVerifier::new_with_validator(ledger, accepting);

        verifier.verify_proposal(make_proposal_request(1, Round(5), Period(0), false));
        let result = verifier
            .verified(PROPOSAL_PAYLOAD_TAG)
            .recv_timeout(Duration::from_secs(5))
            .expect("should get result");
        assert_eq!(result.task_index, 1);
        assert!(result.err.is_none(), "accepting validator should succeed");
        assert!(!result.cancelled);
        verifier.quit();

        // Test with rejecting validator.
        let ledger2 = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let rejecting = Arc::new(StubBlockValidator::rejecting("invalid block content"));
        let verifier2 = AsyncCryptoVerifier::new_with_validator(ledger2, rejecting);

        verifier2.verify_proposal(make_proposal_request(2, Round(5), Period(0), false));
        let result2 = verifier2
            .verified(PROPOSAL_PAYLOAD_TAG)
            .recv_timeout(Duration::from_secs(5))
            .expect("should get result");
        assert_eq!(result2.task_index, 2);
        assert!(result2.err.is_some(), "rejecting validator should fail");
        let err_msg = format!("{}", result2.err.unwrap());
        assert!(
            err_msg.contains("invalid block content"),
            "error should contain reject reason: {err_msg}"
        );
        assert!(!result2.cancelled);
        verifier2.quit();
    }

    // (e) Clean shutdown: create verifier, submit work, call quit(), verify
    //     it completes without hanging.
    #[test]
    fn clean_shutdown_completes_promptly() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier = AsyncCryptoVerifier::new(ledger);

        // Submit some work.
        for i in 0..10 {
            verifier.verify_vote(make_vote_request(i, Round(10), Period(0)));
        }
        verifier.verify_proposal(make_proposal_request(100, Round(10), Period(0), false));

        // Call quit() with a timeout to ensure it doesn't hang.
        let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);
        let verifier_arc = Arc::new(Mutex::new(Some(verifier)));
        let v = verifier_arc.clone();
        let handle = thread::spawn(move || {
            if let Some(verifier) = v.lock().unwrap().take() {
                verifier.quit();
            }
            let _ = done_tx.send(());
        });

        let quit_completed = done_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        assert!(quit_completed, "quit() should complete within 5 seconds");
        handle.join().expect("quit thread should not panic");
    }

    // (f) Backpressure integration: verify channel_full returns correct tag type.
    #[test]
    fn backpressure_channel_full_tags() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier = AsyncCryptoVerifier::new(ledger);

        // Initially, no channels are full.
        assert!(!verifier.channel_full(AGREEMENT_VOTE_TAG));
        assert!(!verifier.channel_full(PROPOSAL_PAYLOAD_TAG));
        assert!(!verifier.channel_full(VOTE_BUNDLE_TAG));

        // Unknown tag should return false.
        assert!(!verifier.channel_full("UNKNOWN"));

        // Fill the proposal output channel by submitting many proposals and
        // not draining. The proposal output channel has capacity
        // max_votes + base_buffer = 80 + 3 = 83. The proposal input channel
        // has capacity 1. With 4 proposal workers, after submitting enough
        // proposals we should see channel_full(PP) return true.
        //
        // channel_full(PP) = proposal_in full OR proposal_out.len() > 1
        //
        // Since we're not draining proposals, after 2+ proposals are verified
        // the output channel len > 1 and channel_full(PP) should be true.
        for i in 0..5u64 {
            verifier.verify_proposal(make_proposal_request(i, Round(10), Period(0), false));
        }

        // Wait for proposals to be processed.
        thread::sleep(Duration::from_millis(500));

        // With 5 proposals submitted and none drained, output len should be > 1.
        assert!(
            verifier.channel_full(PROPOSAL_PAYLOAD_TAG),
            "proposal channel should be full when output has multiple results"
        );

        verifier.quit();
    }

    // (g) quit() while workers are blocked on full output: fill output channels,
    //     submit work that would require workers to send results, then call
    //     quit(). Verify quit() returns promptly (doesn't deadlock).
    #[test]
    fn quit_while_workers_blocked_on_full_output() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let verifier = AsyncCryptoVerifier::new(ledger);

        // Vote output capacity = 3 * VOTE_PARALLELISM = 48.
        // We need to fill it so workers block on send.
        //
        // Submit many vote requests, do NOT drain the output channel.
        // Workers will process them quickly (ledger lookup fails fast) and
        // eventually block when the output channel is full.
        let flood_count = 48 + VOTE_PARALLELISM * 2;
        for i in 0..flood_count as u64 {
            verifier.verify_vote(make_vote_request(i, Round(10), Period(0)));
        }

        // Wait for output channel to fill and workers to start blocking.
        thread::sleep(Duration::from_millis(500));

        // Now call quit(). This should NOT deadlock because the quit signal
        // channel interrupts workers' select! on the output send.
        let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);
        let handle = thread::spawn(move || {
            verifier.quit();
            let _ = done_tx.send(());
        });

        let quit_completed = done_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        assert!(
            quit_completed,
            "quit() should complete promptly even when workers are blocked on full output"
        );
        handle.join().expect("quit thread should not panic");
    }

    // Additional: verify that Drop also shuts down cleanly.
    #[test]
    fn drop_shuts_down_cleanly() {
        let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);
        let handle = thread::spawn(move || {
            let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
            let verifier = AsyncCryptoVerifier::new(ledger);

            // Submit some work.
            for i in 0..5 {
                verifier.verify_vote(make_vote_request(i, Round(10), Period(0)));
            }

            // Drop the verifier (goes out of scope).
            drop(verifier);
            let _ = done_tx.send(());
        });

        let drop_completed = done_rx.recv_timeout(Duration::from_secs(5)).is_ok();
        assert!(drop_completed, "drop should complete within 5 seconds");
        handle.join().expect("drop thread should not panic");
    }

    // Additional: verify concurrent proposal + vote + bundle processing.
    #[test]
    fn concurrent_mixed_request_types() {
        let ledger = Arc::new(StubLedger::new(v41_params(), Round(100)));
        let validator = Arc::new(StubBlockValidator::accepting());
        let verifier = AsyncCryptoVerifier::new_with_validator(ledger, validator);

        // Submit a mix of request types concurrently.
        verifier.verify_vote(make_vote_request(1, Round(10), Period(0)));
        verifier.verify_proposal(make_proposal_request(2, Round(10), Period(0), false));
        verifier.verify_vote(make_vote_request(3, Round(10), Period(0)));

        // Collect vote results.
        let mut vote_indices = Vec::new();
        for _ in 0..2 {
            let r = verifier
                .verified_votes()
                .recv_timeout(Duration::from_secs(5))
                .expect("should get vote result");
            vote_indices.push(r.task_index);
        }
        vote_indices.sort();
        assert_eq!(vote_indices, vec![1, 3]);

        // Collect proposal result.
        let proposal_result = verifier
            .verified(PROPOSAL_PAYLOAD_TAG)
            .recv_timeout(Duration::from_secs(5))
            .expect("should get proposal result");
        assert_eq!(proposal_result.task_index, 2);
        assert!(proposal_result.err.is_none());

        verifier.quit();
    }
}
