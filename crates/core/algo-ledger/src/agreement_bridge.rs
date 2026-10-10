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

//! Bridge implementation connecting `SqliteLedger` to the agreement protocol's
//! `LedgerReader` and `LedgerWriter` traits.
//!
//! Mirrors go-algorand's `node/impls.go` `agreementLedger` struct which wraps
//! a `*data.Ledger` and implements the `agreement.Ledger` interface.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::apply_stall::{StallTransition, STALL_BACKOFF_MAX};

use crossbeam_channel;

use tracing::{debug, error, info, warn};

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
    /// Number of `round-notify-*` OS threads ever spawned by
    /// [`LedgerReader::round_notify`] (issue #1650 regression metric).
    notify_threads_spawned: AtomicU64,
    /// The live waiter for the most recently requested round, so repeated
    /// `round_notify` calls for the same round share one thread (issue #1650).
    notify_cache: Mutex<Option<PendingNotify>>,
    /// Deterministic block-apply failure tracking (issue #1677). Shared via
    /// [`Self::with_apply_stall_tracker`] across bridge rebuilds and with the
    /// REST/metrics adapter.
    apply_stall: Arc<crate::ApplyStallTracker>,
}

/// SQLite messages that mean "try again": a locked/busy database. One shared
/// marker set drives both the in-call retry ([`is_transient_store_message`])
/// and the local-fault filter ([`is_local_store_fault_message`]).
const TRANSIENT_STORE_MARKERS: [&str; 3] = ["database is locked", "sqlite_busy", "busy"];
/// Other SQLite/store faults that are local to this node (not evidence
/// against a block).
const LOCAL_STORE_FAULT_MARKERS: [&str; 8] = [
    "disk i/o",
    "disk is full",
    "readonly",
    "database is",
    "unable to open",
    "cannot start a transaction",
    "out of memory",
    "locked",
];

fn is_transient_store_message(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    TRANSIENT_STORE_MARKERS.iter().any(|k| m.contains(k))
}

/// Whether `msg` looks like a local SQLite/store fault. Filtered by message
/// because the store reports these as untyped `AlgoError::Ledger`.
fn is_local_store_fault_message(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    TRANSIENT_STORE_MARKERS
        .iter()
        .chain(LOCAL_STORE_FAULT_MARKERS.iter())
        .any(|k| m.contains(k))
}

/// Where in `try_commit_block` a commit failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitStage {
    /// Writing the block / certificate rows or committing the SQLite
    /// transaction: local storage, never a verdict on the block content.
    Store,
    /// Applying the block's content to the ledger state.
    Apply,
}

/// A failed `try_commit_block`, tagged with the stage that produced it.
#[derive(Debug)]
pub(crate) struct CommitFailure {
    pub(crate) stage: CommitStage,
    pub(crate) error: AlgoError,
}

impl CommitFailure {
    fn new(stage: CommitStage, error: AlgoError) -> Self {
        Self { stage, error }
    }

    /// Whether this failure is evidence the *block content* cannot be
    /// applied (so repeats are a deterministic invalid-block stall, issue
    /// #1677), as opposed to a local fault (SQLite I/O, disk full, ...),
    /// which keeps the normal retry cadence and never enters the stalled
    /// state.
    ///
    /// Stage and error variant form an allow-list: only the apply stage can
    /// condemn a block, and only through the variants the apply/AVM layers
    /// use for content verdicts. Because the store reports its own faults as
    /// the untyped `AlgoError::Ledger`, local faults inside the apply stage
    /// are filtered by message ([`is_local_store_fault_message`]); a store
    /// fault with an unrecognised message is still treated as a content
    /// failure.
    pub(crate) fn is_block_content_failure(&self) -> bool {
        self.stage == CommitStage::Apply
            && !is_local_store_fault_message(&self.error.to_string())
            && matches!(
                self.error,
                AlgoError::Ledger { .. }
                    | AlgoError::Validation { .. }
                    | AlgoError::Avm { .. }
                    | AlgoError::AvmLogicSig { .. }
                    | AlgoError::Codec { .. }
                    | AlgoError::Eval { .. }
                    | AlgoError::AppDoesNotExist { .. }
                    | AlgoError::ApprovalRejected { .. }
            )
    }
}

/// A still-running `round_notify` waiter thread and the channel it feeds.
struct PendingNotify {
    round: u64,
    rx: crossbeam_channel::Receiver<Round>,
    /// Cleared by the waiter thread when it exits (delivered, timed out, or
    /// lock poisoned), so a dead waiter is never handed out again.
    alive: Arc<AtomicBool>,
}

/// Clears the flag when the waiter thread exits, however it exits.
struct AliveGuard(Arc<AtomicBool>);

impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl AgreementLedgerBridge {
    /// How many `round-notify-*` threads this bridge has ever spawned.
    pub fn notify_threads_spawned(&self) -> u64 {
        self.notify_threads_spawned.load(Ordering::SeqCst)
    }

    /// Share `tracker` instead of this bridge's private one, so the stall
    /// state survives bridge rebuilds and is visible to the REST adapter.
    pub fn with_apply_stall_tracker(mut self, tracker: Arc<crate::ApplyStallTracker>) -> Self {
        self.apply_stall = tracker;
        self
    }

    /// The block-apply failure tracker (issue #1677).
    pub fn apply_stall_tracker(&self) -> &Arc<crate::ApplyStallTracker> {
        &self.apply_stall
    }

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
            notify_threads_spawned: AtomicU64::new(0),
            notify_cache: Mutex::new(None),
            apply_stall: Arc::new(crate::ApplyStallTracker::new()),
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
            notify_threads_spawned: AtomicU64::new(0),
            notify_cache: Mutex::new(None),
            apply_stall: Arc::new(crate::ApplyStallTracker::new()),
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
        Self::new_with_catchup_and_condvar(ledger, network_advancer, Arc::new(Condvar::new()))
    }

    /// Create a new bridge with catchup support, reusing a caller-supplied
    /// `round_advanced` condvar instead of minting a fresh one.
    ///
    /// This is [`new_with_catchup`](Self::new_with_catchup) plus the
    /// condvar-sharing behavior of
    /// [`new_with_advancer_and_condvar`](Self::new_with_advancer_and_condvar):
    /// needed when the *agreement* bridge itself (not just the catchup
    /// bridge) has to be torn down and rebuilt in place: a live
    /// catchpoint-catchup pause/resume cycle (issue #940) stops and
    /// reconstructs the agreement `Service` (and the `AgreementLedgerBridge`
    /// plus certificate channel it owns) without restarting sibling
    /// services, namely the pool-block-follower, heartbeat, and
    /// state-proof-worker threads, that are still blocked waiting on the
    /// *original* condvar instance. Passing that original `Arc<Condvar>`
    /// back in here on every rebuild keeps those waiters correctly woken
    /// across the whole node lifetime, not just until the first pause.
    pub fn new_with_catchup_and_condvar(
        ledger: Arc<Mutex<SqliteLedger>>,
        network_advancer: Arc<dyn NetworkAdvancer>,
        round_advanced: Arc<Condvar>,
    ) -> (
        Self,
        crossbeam_channel::Receiver<PendingUnmatchedCertificate>,
    ) {
        let (tx, rx) = crossbeam_channel::bounded(1);
        let bridge = Self {
            ledger,
            round_advanced,
            pending_cert_tx: Some(tx),
            pending_cert_rx: Some(rx.clone()),
            network_advancer,
            notify_threads_spawned: AtomicU64::new(0),
            notify_cache: Mutex::new(None),
            apply_stall: Arc::new(crate::ApplyStallTracker::new()),
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
    ) -> Result<(), CommitFailure> {
        // Begin a transaction so that block storage and state application
        // are atomic. If begin_block fails (e.g., already in a transaction),
        // fall back to non-transactional mode.
        // Issue #1654 diagnostics: time each stage so a slow first commit
        // after a catchup names its stage in the log.
        // Issue #1757: the apply stage also reports its AVM/non-AVM split
        // (`apply_avm` is `Some` only for that stage) so a heavy round is
        // attributed from the log alone, in the same single warning with a
        // single elapsed reading.
        let slow = |stage: &str, since: std::time::Instant, apply_avm: Option<Duration>| {
            let elapsed = since.elapsed();
            if elapsed > Duration::from_secs(1) {
                let elapsed_ms = elapsed.as_millis() as u64;
                match apply_avm {
                    Some(avm) => {
                        let avm_ms = avm.as_millis() as u64;
                        warn!(
                            round = %block.round,
                            stage,
                            elapsed_ms,
                            avm_ms,
                            non_avm_ms = elapsed_ms.saturating_sub(avm_ms),
                            txns = block.payset.len(),
                            "try_commit_block: slow stage"
                        );
                    }
                    None => warn!(
                        round = %block.round,
                        stage,
                        elapsed_ms,
                        "try_commit_block: slow stage"
                    ),
                }
            }
        };
        let t = std::time::Instant::now();
        let in_txn = match ledger.begin_block() {
            Ok(()) => true,
            // An earlier block's ROLLBACK is still failing: never fall back to
            // non-transactional apply on top of that half-applied block.
            Err(e) if ledger.has_pending_abort() => {
                return Err(CommitFailure::new(CommitStage::Store, e));
            }
            Err(_) => false,
        };
        slow("begin_block", t, None);

        let result = (|| -> Result<(), CommitFailure> {
            let t = std::time::Instant::now();
            ledger
                .put_block(block.round.0, proto, hdr_data, blk_data)
                .map_err(|e| CommitFailure::new(CommitStage::Store, e))?;
            slow("put_block", t, None);
            let t = std::time::Instant::now();
            ledger
                .put_block_cert(block.round.0, cert_bytes)
                .map_err(|e| CommitFailure::new(CommitStage::Store, e))?;
            slow("put_block_cert", t, None);
            let t = std::time::Instant::now();
            // Issue #1678: per-block follow-path timing. The AVM accumulator
            // is reset here and taken right after the apply (the only
            // reset/take site), on this one thread.
            crate::follow_timing::reset_avm_time();
            let applied = crate::apply::apply_block_executing_app_calls(ledger, block);
            let timing = crate::follow_timing::follow_timing();
            let avm = crate::follow_timing::take_avm_time();
            if let Some(avm) = avm {
                timing.avm.observe(avm);
            }
            match &applied {
                Ok(()) => timing.apply.observe(t.elapsed()),
                Err(_) => timing.apply_failed.observe(t.elapsed()),
            }
            // Also for a failed apply: a slow rejection is just as relevant.
            slow("apply_block", t, Some(avm.unwrap_or_default()));
            applied.map_err(|e| CommitFailure::new(CommitStage::Apply, e))?;
            Ok(())
        })();

        if let Err(e) = result {
            if in_txn {
                let _ = ledger.rollback_block();
            }
            return Err(e);
        }

        if in_txn {
            let t = std::time::Instant::now();
            if let Err(e) = ledger.commit_block() {
                crate::follow_timing::follow_timing()
                    .commit_failed
                    .observe(t.elapsed());
                return Err(CommitFailure::new(CommitStage::Store, e));
            }
            crate::follow_timing::follow_timing()
                .commit
                .observe(t.elapsed());
            slow("commit_block", t, None);
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

        // go's `LookupAgreement`: the account's `onlineaccounts` row at or
        // before `round`, rewards folded in (`MicroAlgosWithRewards`, issue
        // #1654); an account with no such row, or one that was not online
        // then, is the empty `OnlineAccountData{}` -- no fallback to its
        // current state. One shared helper, so the policy lives in one place
        // (`SqliteLedger::lookup_agreement_account`; issue #1795).
        let Some(acct) = ledger
            .lookup_agreement_account(addr, round.0)
            .map_err(|e| LedgerError::Other(format!("lookup_agreement: {e}")))?
        else {
            return Ok(OnlineAccountData::default());
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

    fn circulation(&self, rnd: Round, vote_rnd: Round) -> Result<u64, LedgerError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|e| LedgerError::Other(format!("ledger lock poisoned: {e}")))?;

        if rnd.0 > ledger.current_round().0 {
            return Err(LedgerError::RoundNotAvailable(rnd));
        }

        // Shared with `GetSupply`'s `online-stake` field (node_interface_impl.rs)
        // so both consult the same per-round-snapshot-else-current-aggregate
        // rule, including the expired-participation-key exclusion -- mirrors
        // Go's `onlineCirculation` (`ledger/acctonline.go`).
        ledger
            .online_circulation_at_round(rnd.0, vote_rnd.0)
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

        // Issue #1650: the demux calls this on every event it handles, so a
        // thread per call exhausts the OS thread budget within a minute of
        // live mainnet gossip. Share one waiter per pending round: a repeat
        // call for the same round gets a clone of the live waiter's channel
        // (the demux only ever holds the newest receiver, so the single
        // one-shot message reaches it).
        let mut cache = match self.notify_cache.lock() {
            Ok(c) => c,
            Err(_) => {
                let (_tx, rx) = crossbeam_channel::bounded(1);
                return rx;
            }
        };
        if let Some(pending) = cache.as_ref() {
            if pending.round == round.0 && pending.alive.load(Ordering::SeqCst) {
                return pending.rx.clone();
            }
        }

        // Spawn a short-lived thread that waits on the Condvar for the round
        // to be reached, then sends a single notification on the channel.
        let (tx, rx) = crossbeam_channel::bounded(1);
        let ledger = Arc::clone(&self.ledger);
        let condvar = Arc::clone(&self.round_advanced);
        let alive = Arc::new(AtomicBool::new(true));
        let alive_for_thread = Arc::clone(&alive);

        self.notify_threads_spawned.fetch_add(1, Ordering::SeqCst);
        let spawn_result = std::thread::Builder::new()
            .name(format!("round-notify-{}", round.0))
            .spawn(move || {
                let _alive = AliveGuard(alive_for_thread);
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
            });

        // A thread-spawn failure (EAGAIN under OS thread pressure) must
        // degrade this round's notification, not panic the demux thread:
        // log and return a receiver that never fires (mirrors the
        // lock-poisoned branch above).
        match spawn_result {
            Ok(_) => {
                *cache = Some(PendingNotify {
                    round: round.0,
                    rx: rx.clone(),
                    alive,
                });
            }
            Err(e) => {
                tracing::error!(
                    round = round.0,
                    error = %e,
                    "failed to spawn round-notify thread; returning a receiver that will never                      fire for this round instead of panicking (issue #1650)"
                );
            }
        }

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

        let ensure_started = std::time::Instant::now();
        for attempt in 0..=MAX_RETRIES {
            let lock_wait_started = std::time::Instant::now();
            let mut ledger = match self.ledger.lock() {
                Ok(l) => l,
                Err(e) => {
                    warn!("ledger lock poisoned in ensure_block: {e}");
                    crate::follow_timing::follow_timing()
                        .ensure_block_failed
                        .observe(ensure_started.elapsed());
                    return;
                }
            };
            // Issue #1654 diagnostics: separate waiting for the ledger lock
            // (held by someone else) from the commit itself.
            if lock_wait_started.elapsed() > Duration::from_secs(1) {
                warn!(
                    round = %block.round,
                    waited_ms = lock_wait_started.elapsed().as_millis() as u64,
                    "ensure_block: waited a long time for the ledger lock"
                );
            }
            let commit_started = std::time::Instant::now();

            // An earlier block's ROLLBACK may have failed with its transaction
            // still open: the in-memory round then still reflects that
            // half-applied block, so finish the abort BEFORE trusting
            // `current_round` below. If it still cannot be rolled back this is
            // a failed attempt; never apply on top of it.
            if let Err(e) = ledger.heal_pending_abort() {
                drop(ledger);
                crate::follow_timing::follow_timing()
                    .ensure_block_failed
                    .observe(ensure_started.elapsed());
                self.apply_stall.count_local_failure();
                warn!(
                    round = %block.round,
                    "ensure_block: cannot start a block: {e}"
                );
                return;
            }

            // Check if this block's round has already been committed.
            let next_round = ledger.current_round().0 + 1;
            if block.round.0 < next_round {
                // Block already committed (by us or by catchup); idempotent.
                crate::follow_timing::follow_timing()
                    .ensure_block_already_committed
                    .inc();
                debug!(
                    "ensure_block: block round {} already committed, current round {}",
                    block.round.0,
                    next_round - 1
                );
                // Any stall on this round or an earlier one is obsolete.
                self.apply_stall.observe_ledger_round(next_round - 1);
                return;
            }

            if block.round.0 > next_round {
                warn!(
                    "ensure_block: block round {} is ahead of next expected round {}, \
                     skipping (needs catchup)",
                    block.round.0, next_round
                );
                // Routine: the catchup service fetches the gap. Counted, but not
                // a failure.
                crate::follow_timing::follow_timing()
                    .ensure_block_skipped_ahead
                    .inc();
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
                    if commit_started.elapsed() > Duration::from_secs(1) {
                        warn!(
                            round = %block.round,
                            commit_ms = commit_started.elapsed().as_millis() as u64,
                            "ensure_block: slow commit"
                        );
                    }
                    // Success — release the lock before notifying waiters.
                    drop(ledger);
                    // Only the successful attempt: lock wait + commit.
                    crate::follow_timing::follow_timing()
                        .ensure_block
                        .observe(lock_wait_started.elapsed());

                    // Issue #1677: a commit ends any stalled-on-invalid-block
                    // state (e.g. a different, valid block for the round).
                    if let StallTransition::Left { round, failures } =
                        self.apply_stall.observe_ledger_round(block.round.0)
                    {
                        info!(
                            stalled_round = round,
                            failures,
                            committed_round = %block.round,
                            "ensure_block: no longer stalled on an invalid block"
                        );
                    }

                    // Notify any threads waiting in wait_for_round.
                    self.round_advanced.notify_all();

                    // Let the network know that we've made some progress.
                    // Mirrors Go's `l.n.OnNetworkAdvance()`.
                    self.network_advancer.on_network_advance();
                    return;
                }
                Err(e) => e,
            };
            let content_failure = err.is_block_content_failure();
            let err = err.error;

            // Determine if the error is transient (retryable).
            let err_msg = format!("{err}");
            let is_transient = is_transient_store_message(&err_msg);

            if !is_transient {
                // Permanent error — no point retrying inside this call.
                //
                // Issue #1677: the catchup service re-submits the same block
                // every sync pass, so log by transition: the original
                // `permanent error writing block` line the first time a
                // (block, error) pair is seen (the soak log scan keys on it),
                // one ERROR when the repeat makes it a deterministic stall,
                // and only debug lines for further repeats.
                drop(ledger);
                crate::follow_timing::follow_timing()
                    .ensure_block_failed
                    .observe(ensure_started.elapsed());
                if !content_failure {
                    // A local fault (storage stage, I/O, ...): not evidence
                    // against the block, so no stalled state; today's
                    // behaviour (WARN per attempt, normal retry cadence).
                    self.apply_stall.count_local_failure();
                    warn!(
                        "ensure_block: permanent error writing block {} to ledger: {err}",
                        block.round
                    );
                    return;
                }
                let failed_digest = algo_codec::compute_block_digest(block);
                match self.apply_stall.record_failure_at_with_digest(
                    block.round.0,
                    &err_msg,
                    std::time::Instant::now(),
                    Some(failed_digest),
                ) {
                    StallTransition::NewFailure => warn!(
                        "ensure_block: permanent error writing block {} to ledger: {err}",
                        block.round
                    ),
                    StallTransition::Entered => {
                        error!(
                            round = %block.round,
                            "ensure_block: stalled on invalid block {}: two failed attempts for the same round; retries now back off exponentially (cap {}s): {err}",
                            block.round,
                            STALL_BACKOFF_MAX.as_secs()
                        );
                    }
                    _ => debug!(
                        "ensure_block: permanent error writing block {} to ledger (repeat): {err}",
                        block.round
                    ),
                }
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
                crate::follow_timing::follow_timing()
                    .ensure_block_retries
                    .inc();
                std::thread::sleep(RETRY_DELAY);
            } else {
                crate::follow_timing::follow_timing()
                    .ensure_block_failed
                    .observe(ensure_started.elapsed());
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
    fn apply_stall_retry_in(&self, next_round: Round) -> Option<Duration> {
        // A stall on a round the ledger already reached (catchpoint jump,
        // follow apply, another bridge) is stale. The caller already holds
        // the ledger's next round, so no second ledger lock is taken.
        self.apply_stall
            .observe_ledger_round(next_round.0.saturating_sub(1));
        self.apply_stall.retry_in()
    }

    fn apply_stall_failed_digest(&self) -> Option<algo_types::Digest> {
        self.apply_stall.failed_block_digest()
    }

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

    /// Issue #1650: the agreement demux calls `round_notify` on every event it
    /// handles (go's `ledger.Wait` per `demux.next`). Spawning an OS thread per
    /// call exhausted the thread budget within a minute against live mainnet
    /// gossip (`fork: Resource temporarily unavailable`, then thread-spawn
    /// panics). Repeated calls for the same pending round must share one waiter.
    #[test]
    fn round_notify_shares_one_waiter_thread_for_repeated_calls_on_the_same_round() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));

        let mut receivers = Vec::new();
        for _ in 0..500 {
            receivers.push(bridge.round_notify(Round(1_000)));
        }
        assert_eq!(
            bridge.notify_threads_spawned(),
            1,
            "500 round_notify calls for the same pending round must spawn exactly one thread"
        );

        // A different round gets its own waiter (rounds advance monotonically,
        // so this is bounded by rounds, not by events).
        let _ = bridge.round_notify(Round(1_001));
        assert_eq!(bridge.notify_threads_spawned(), 2);

        // An already-available round never needs a thread.
        let _ = bridge.round_notify(Round(0));
        assert_eq!(bridge.notify_threads_spawned(), 2);
    }

    // -- LookupAgreement (issue #824 theme 6 — go's `TestLookupAgreement`) --

    #[test]
    fn lookup_agreement_returns_online_accounts_voting_data() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let addr = Address([1u8; 32]);
        {
            let mut l = ledger.lock().unwrap();
            let acct = algo_types::AccountData {
                micro_algos: 1_000_000,
                status: algo_types::AccountStatus::Online,
                vote_id: Some([7u8; 32]),
                selection_id: Some([8u8; 32]),
                vote_first_valid: 0,
                vote_last_valid: 1_000_000,
                vote_key_dilution: 100,
                ..Default::default()
            };
            l.set_account(&addr, acct.clone());
            // The online-accounts history row the commit would have written.
            l.put_online_account_at_round(&addr, 0, &acct).unwrap();
        }
        let bridge = AgreementLedgerBridge::new(ledger);

        let oad = bridge.lookup_agreement(Round(0), &addr).unwrap();
        assert_eq!(oad.micro_algos, 1_000_000);
        assert_eq!(oad.vote_id, [7u8; 32]);
        assert_eq!(oad.selection_id, [8u8; 32]);
        assert_eq!(oad.vote_key_dilution, 100);
    }

    #[test]
    fn lookup_agreement_returns_empty_for_offline_account() {
        // Regression: go's `TestLookupAgreement` asserts an offline
        // account's agreement lookup is the all-zero `OnlineAccountData{}`
        // (`data/basics/testing/userBalance.go::OnlineAccountData` clears
        // non-Online accounts out entirely) -- even though the account
        // itself has a real balance and (stale) voting-key material on
        // file. Before this fix, `lookup_agreement`'s fallback path read
        // the raw account row regardless of status, leaking an offline
        // account's balance/keys into agreement's stake/committee
        // calculations.
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let addr = Address([2u8; 32]);
        {
            let mut l = ledger.lock().unwrap();
            l.set_account(
                &addr,
                algo_types::AccountData {
                    micro_algos: 5_000_000,
                    status: algo_types::AccountStatus::Offline,
                    // Stale voting key material left over from when the
                    // account was last online -- must not leak through.
                    vote_id: Some([9u8; 32]),
                    selection_id: Some([9u8; 32]),
                    vote_last_valid: 1_000_000,
                    ..Default::default()
                },
            );
        }
        let bridge = AgreementLedgerBridge::new(ledger);

        let oad = bridge.lookup_agreement(Round(0), &addr).unwrap();
        assert_eq!(
            oad,
            OnlineAccountData::default(),
            "an offline account's agreement lookup must be entirely empty, not just its \
             balance zeroed"
        );
    }

    /// go's `LookupAgreement`: an account whose first online row is after the
    /// lookup round is the empty `OnlineAccountData{}` at that round (no
    /// fallback to its current state) and has its data from the row's round.
    #[test]
    fn lookup_agreement_is_empty_before_the_accounts_first_online_row() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let addr = Address([4u8; 32]);
        {
            let mut l = ledger.lock().unwrap();
            let acct = algo_types::AccountData {
                micro_algos: 2_000_000,
                status: algo_types::AccountStatus::Online,
                vote_id: Some([7u8; 32]),
                selection_id: Some([8u8; 32]),
                vote_last_valid: 1_000_000,
                ..Default::default()
            };
            l.set_account(&addr, acct.clone());
            l.put_online_account_at_round(&addr, 5, &acct).unwrap();
            l.set_current_round(Round(5));
        }
        let bridge = AgreementLedgerBridge::new(ledger);
        assert_eq!(
            bridge.lookup_agreement(Round(0), &addr).unwrap(),
            OnlineAccountData::default()
        );
        assert_eq!(
            bridge
                .lookup_agreement(Round(5), &addr)
                .unwrap()
                .micro_algos,
            2_000_000
        );
    }

    #[test]
    fn lookup_agreement_returns_empty_for_unknown_account() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(ledger);
        let oad = bridge
            .lookup_agreement(Round(0), &Address([3u8; 32]))
            .unwrap();
        assert_eq!(oad, OnlineAccountData::default());
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

    /// `new_with_catchup_and_condvar` must reuse the *exact* condvar instance
    /// passed in, not mint a fresh one — this is what lets a pause/resume
    /// cycle (issue #940) rebuild the agreement bridge without breaking
    /// sibling threads still waiting on the original condvar via
    /// `wait_for_round`/`round_notify`.
    #[test]
    fn new_with_catchup_and_condvar_reuses_the_given_condvar() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let advancer = Arc::new(NoOpNetworkAdvancer);
        let shared_condvar = Arc::new(Condvar::new());

        let (bridge, _rx) = AgreementLedgerBridge::new_with_catchup_and_condvar(
            ledger,
            advancer,
            Arc::clone(&shared_condvar),
        );

        assert!(
            Arc::ptr_eq(&bridge.round_advanced_condvar(), &shared_condvar),
            "bridge must reuse the exact condvar Arc passed in, not create a new one"
        );
    }

    /// The certificate channel plumbing must work identically to
    /// `new_with_catchup` — the condvar-sharing variant is otherwise the
    /// same constructor.
    #[test]
    fn new_with_catchup_and_condvar_returns_working_receiver() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let advancer = Arc::new(NoOpNetworkAdvancer);
        let (bridge, rx) = AgreementLedgerBridge::new_with_catchup_and_condvar(
            ledger,
            advancer,
            Arc::new(Condvar::new()),
        );

        assert!(rx.try_recv().is_err());
        let verifier = AsyncVoteVerifier::new();
        bridge.ensure_digest(&make_cert(7), &verifier);
        let pending = rx.try_recv().expect("receiver should have a value");
        assert_eq!(pending.cert.round, Round(7));
    }

    // -- Deterministic apply failure tracking (issue #1677) --

    /// A round-1 block whose only payment is from an unfunded account: it
    /// fails to apply, identically, every time.
    fn make_unapplyable_round1_block() -> algo_types::Block {
        let mut stx = algo_types::SignedTransaction::default();
        stx.txn.txn_type = "pay".into();
        stx.txn.sender = Address([1u8; 32]);
        stx.txn.receiver = Address([2u8; 32]);
        stx.txn.amount = 1_000_000;
        stx.txn.fee = 1_000;
        stx.txn.last_valid = Round(1_000_000);
        algo_types::Block {
            payset: vec![stx],
            ..make_round1_block()
        }
    }

    #[test]
    fn repeated_deterministic_apply_failure_stalls_and_backs_off() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
        let block = make_unapplyable_round1_block();
        let cert = make_cert_with_proposal(1);

        bridge.ensure_block(&block, &cert);
        assert!(bridge.apply_stall_tracker().stall().is_none());
        assert!(
            crate::catchup_service::CatchupLedger::apply_stall_retry_in(&bridge, Round(1))
                .is_none()
        );

        bridge.ensure_block(&block, &cert);
        let stall = bridge.apply_stall_tracker().stall().expect("stalled");
        assert_eq!(stall.round, 1);
        assert_eq!(stall.consecutive_failures, 2);
        assert!(
            crate::catchup_service::CatchupLedger::apply_stall_retry_in(&bridge, Round(1))
                .is_some()
        );
        assert_eq!(bridge.apply_stall_tracker().failures_total(), 2);
        // The ledger never advanced.
        assert_eq!(ledger.lock().unwrap().current_round().0, 0);
    }

    #[test]
    fn committing_a_valid_block_clears_the_stall() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
        let bad = make_unapplyable_round1_block();
        let cert = make_cert_with_proposal(1);
        bridge.ensure_block(&bad, &cert);
        bridge.ensure_block(&bad, &cert);
        assert!(bridge.apply_stall_tracker().stall().is_some());

        bridge.ensure_block(&make_round1_block(), &cert);
        assert_eq!(ledger.lock().unwrap().current_round().0, 1);
        assert!(bridge.apply_stall_tracker().stall().is_none());
    }

    #[test]
    fn only_apply_stage_content_errors_count_as_block_failures() {
        let ledger_err = || AlgoError::Ledger {
            message: "x".into(),
        };
        let f = |stage, e| CommitFailure::new(stage, e).is_block_content_failure();
        // Storage-stage failures (put_block / cert / commit) never condemn.
        assert!(!f(CommitStage::Store, ledger_err()));
        // Local faults even in the apply stage.
        assert!(!f(
            CommitStage::Apply,
            AlgoError::Io(std::io::Error::other("disk full"))
        ));
        assert!(!f(
            CommitStage::Apply,
            AlgoError::Network {
                message: "n".into()
            }
        ));
        // Content verdicts.
        assert!(f(CommitStage::Apply, ledger_err()));
        assert!(f(
            CommitStage::Apply,
            AlgoError::Avm {
                message: "a".into()
            }
        ));
        assert!(f(
            CommitStage::Apply,
            AlgoError::Validation {
                message: "v".into()
            }
        ));
        // Typed apply verdicts added with the go-text close errors (#1776):
        // a committed block that hits one must still stall (#1677).
        assert!(f(
            CommitStage::Apply,
            AlgoError::Eval {
                message: "cannot close: 1 outstanding assets".into()
            }
        ));
        assert!(f(
            CommitStage::Apply,
            AlgoError::AppDoesNotExist { app_id: 7 }
        ));
        assert!(f(
            CommitStage::Apply,
            AlgoError::ApprovalRejected {
                app_id: 7,
                reason: None
            }
        ));
        assert!(!f(
            CommitStage::Store,
            AlgoError::Eval {
                message: "cannot close: 1 outstanding assets".into()
            }
        ));
    }

    #[test]
    fn local_store_fault_messages_are_never_block_content_failures() {
        // Real rusqlite/SQLite message strings, as the store wraps them.
        for m in [
            "apply error: disk I/O error",
            "apply error: database or disk is full",
            "apply error: attempt to write a readonly database",
            "apply error: unable to open database file",
            "apply error: cannot start a transaction within a transaction",
            "apply error: out of memory",
            "apply error: database table is locked",
            "apply error: database is locked",
            "apply error: SQLITE_BUSY",
        ] {
            let f = CommitFailure::new(CommitStage::Apply, AlgoError::Ledger { message: m.into() });
            assert!(!f.is_block_content_failure(), "{m}");
            assert!(is_local_store_fault_message(m), "{m}");
        }
        // The transient subset (in-call retry) is shared, not a second list.
        assert!(is_transient_store_message("database is locked"));
        assert!(!is_transient_store_message("disk I/O error"));
        // A content verdict is not a local fault.
        let content = CommitFailure::new(
            CommitStage::Apply,
            AlgoError::Ledger {
                message: "tx 0xabc: balance below minimum".into(),
            },
        );
        assert!(content.is_block_content_failure());
    }

    #[test]
    fn stall_is_dropped_when_the_ledger_advances_by_another_path() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
        let bad = make_unapplyable_round1_block();
        let cert = make_cert_with_proposal(1);
        bridge.ensure_block(&bad, &cert);
        bridge.ensure_block(&bad, &cert);
        assert!(
            crate::catchup_service::CatchupLedger::apply_stall_retry_in(&bridge, Round(1))
                .is_some()
        );
        // Another bridge / catchpoint jump commits round 1: no commit through this bridge.
        let other = AgreementLedgerBridge::new(Arc::clone(&ledger));
        other.ensure_block(&make_round1_block(), &cert);
        assert_eq!(ledger.lock().unwrap().current_round().0, 1);
        assert!(bridge.apply_stall_tracker().stall().is_some());
        assert!(
            crate::catchup_service::CatchupLedger::apply_stall_retry_in(&bridge, Round(2))
                .is_none()
        );
        assert!(bridge.apply_stall_tracker().stall().is_none());
    }

    #[test]
    fn shared_tracker_is_visible_across_bridges() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let tracker = Arc::new(crate::ApplyStallTracker::new());
        let a = AgreementLedgerBridge::new(Arc::clone(&ledger))
            .with_apply_stall_tracker(Arc::clone(&tracker));
        let bad = make_unapplyable_round1_block();
        let cert = make_cert_with_proposal(1);
        a.ensure_block(&bad, &cert);
        a.ensure_block(&bad, &cert);
        assert!(tracker.stall().is_some());
    }

    /// Issue #1678: failed applies, failed `ensure_block` calls and the
    /// idempotent early return are visible, not silently missing.
    #[test]
    fn ensure_block_failure_and_idempotent_paths_are_counted() {
        let t = crate::follow_timing::follow_timing();
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
        let (apply_failed, failed) = (t.apply_failed.count(), t.ensure_block_failed.count());
        bridge.ensure_block(
            &make_unapplyable_round1_block(),
            &make_cert_with_proposal(1),
        );
        assert!(
            t.apply_failed.count() > apply_failed,
            "failed apply observed"
        );
        assert!(
            t.ensure_block_failed.count() > failed,
            "failed ensure observed"
        );

        let ok = make_round1_block();
        bridge.ensure_block(&ok, &make_cert_with_proposal(1));
        let already = t.ensure_block_already_committed.get();
        bridge.ensure_block(&ok, &make_cert_with_proposal(1));
        assert!(t.ensure_block_already_committed.get() > already);
    }

    /// Issue #1761: an `ensure_block` skipped because the block is ahead of
    /// the ledger (routine, needs catchup) has its own counter and is NOT
    /// recorded as a failure.
    #[test]
    fn ensure_block_ahead_of_ledger_is_counted_as_skipped_not_failed() {
        let t = crate::follow_timing::follow_timing();
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
        let skipped = t.ensure_block_skipped_ahead.get();
        let mut ahead = make_round1_block();
        ahead.round = Round(5);
        bridge.ensure_block(&ahead, &make_cert_with_proposal(5));
        assert!(
            t.ensure_block_skipped_ahead.get() > skipped,
            "ahead-of-ledger skip counted"
        );
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
            equivocation_votes: vec![],
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
                equivocation_votes: vec![],
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

    /// Issue #1664: the node's follow path (`ensure_block` ->
    /// `try_commit_block`) committed blocks with `ApplyMode::Replay`, which
    /// never runs the AVM and therefore never reaches the box create/delete
    /// call sites. An app account's `total_boxes`/`total_box_bytes` (and the
    /// box store itself) froze at their catchpoint values, so the account's
    /// minimum balance diverged from go-algorand's (mainnet block 65595332,
    /// app account N7NYG...: balance 100000 < computed minimum 162600).
    /// go always evaluates app calls, so a committed block containing an
    /// `appl` transaction must update box accounting.
    #[test]
    fn ensure_block_applies_box_create_and_delete_to_app_account_totals() {
        use algo_types::{AccountData, AppParams, Block, BoxRef, SignedTransaction, Transaction};
        use serde_bytes::ByteBuf;
        use std::collections::BTreeMap;

        let creator = Address([1u8; 32]);
        let sender = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let app_id = 950u64;
        let app_addr = Address(crate::avm_context::app_address(app_id));

        let assemble = |src: &str| {
            algo_avm::assembler::assemble_string(src)
                .expect("program must assemble")
                .program
        };
        // First call puts a box; second call deletes it.
        let put = assemble(concat!(
            "#pragma version 8\n",
            "byte \"mybox\"\n",
            "byte \"hello\"\n",
            "box_put\n",
            "int 1\n",
            "return\n",
        ));
        let del = assemble(concat!(
            "#pragma version 8\n",
            "byte \"mybox\"\n",
            "box_del\n",
            "pop\n",
            "int 1\n",
            "return\n",
        ));

        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        {
            let mut l = ledger.lock().unwrap();
            for (addr, bal) in [
                (creator, 50_000_000u64),
                (sender, 50_000_000),
                (app_addr, 10_000_000),
            ] {
                l.set_account(
                    &addr,
                    AccountData {
                        micro_algos: bal,
                        ..Default::default()
                    },
                );
            }
            l.set_account(&fee_sink, AccountData::default());
            l.set_app_params(
                app_id,
                AppParams {
                    creator,
                    approval_program: put,
                    clear_state_program: vec![0x08, 0x81, 0x01],
                    global_state: BTreeMap::new(),
                    ..Default::default()
                },
            );
        }
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));

        let call_block = |round: u64| {
            let stx = SignedTransaction {
                txn: Transaction {
                    txn_type: "appl".into(),
                    sender,
                    fee: 1_000,
                    first_valid: Round(1),
                    last_valid: Round(1000),
                    application_id: app_id,
                    boxes: Some(vec![BoxRef {
                        index: 0,
                        name: Some(ByteBuf::from(b"mybox".to_vec())),
                    }]),
                    ..Default::default()
                },
                ..Default::default()
            };
            Block {
                round: Round(round),
                fee_sink,
                current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
                payset: vec![stx],
                ..Block::default()
            }
        };

        bridge.ensure_block(&call_block(1), &make_cert_with_proposal(1));
        {
            let l = ledger.lock().unwrap();
            assert_eq!(l.current_round(), Round(1), "round 1 must commit");
            let acct = l.get_account(&app_addr).unwrap();
            assert_eq!(acct.total_boxes, 1, "box_put must be counted");
            assert_eq!(
                acct.total_box_bytes,
                (b"mybox".len() + b"hello".len()) as u64
            );
            assert_eq!(l.get_box(app_id, b"mybox"), Some(b"hello".to_vec()));
        }

        // Swap in the deleting program, then call again.
        {
            let mut l = ledger.lock().unwrap();
            let mut params = l.get_app_params(app_id).unwrap();
            params.approval_program = del;
            l.set_app_params(app_id, params);
        }
        bridge.ensure_block(&call_block(2), &make_cert_with_proposal(2));
        let l = ledger.lock().unwrap();
        assert_eq!(l.current_round(), Round(2), "round 2 must commit");
        let acct = l.get_account(&app_addr).unwrap();
        assert_eq!(acct.total_boxes, 0, "box_del must be counted");
        assert_eq!(acct.total_box_bytes, 0);
        assert_eq!(l.get_box(app_id, b"mybox"), None);
    }

    /// Issue #1664: `global LatestTimestamp` is the previous block's
    /// timestamp in go; executing app calls on the follow path used the
    /// block's own timestamp, so any program logging or storing it diverged
    /// (mainnet round 65609682: logged ...792 where go recorded ...78f).
    #[test]
    fn ensure_block_runs_app_calls_with_previous_block_timestamp() {
        use algo_types::{AccountData, AppParams, Block, BoxRef, SignedTransaction, Transaction};
        use serde_bytes::ByteBuf;

        let creator = Address([1u8; 32]);
        let sender = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let app_id = 951u64;
        let program = algo_avm::assembler::assemble_string(concat!(
            "#pragma version 8
",
            "byte \"ts\"
",
            "global LatestTimestamp
",
            "itob
",
            "box_put
",
            "int 1
",
            "return
",
        ))
        .expect("program must assemble")
        .program;

        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        {
            let mut l = ledger.lock().unwrap();
            for (addr, bal) in [
                (creator, 50_000_000u64),
                (sender, 50_000_000),
                (Address(crate::avm_context::app_address(app_id)), 10_000_000),
            ] {
                l.set_account(
                    &addr,
                    AccountData {
                        micro_algos: bal,
                        ..Default::default()
                    },
                );
            }
            l.set_account(&fee_sink, AccountData::default());
            l.set_app_params(
                app_id,
                AppParams {
                    creator,
                    approval_program: program,
                    clear_state_program: vec![0x08, 0x81, 0x01],
                    ..Default::default()
                },
            );
        }
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
        let block = |round: u64, timestamp: i64, payset: Vec<SignedTransaction>| Block {
            round: Round(round),
            timestamp,
            fee_sink,
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset,
            ..Block::default()
        };
        bridge.ensure_block(&block(1, 1000, vec![]), &make_cert_with_proposal(1));
        let call = SignedTransaction {
            txn: Transaction {
                txn_type: "appl".into(),
                sender,
                fee: 1_000,
                first_valid: Round(1),
                last_valid: Round(1000),
                application_id: app_id,
                boxes: Some(vec![BoxRef {
                    index: 0,
                    name: Some(ByteBuf::from(b"ts".to_vec())),
                }]),
                ..Default::default()
            },
            ..Default::default()
        };
        let timing = crate::follow_timing::follow_timing();
        let avm_before = timing.avm.count();
        let apply_before = timing.apply.count();
        let commit_before = timing.commit.count();
        let total_before = timing.ensure_block.count();
        bridge.ensure_block(&block(2, 1003, vec![call]), &make_cert_with_proposal(2));
        // Issue #1678: the follow path records its per-block timings (other
        // tests share the process-wide histograms, hence `>=`).
        assert!(timing.avm.count() > avm_before, "AVM time observed");
        assert!(timing.apply.count() > apply_before, "apply time observed");
        assert!(
            timing.commit.count() > commit_before,
            "commit time observed"
        );
        assert!(
            timing.ensure_block.count() > total_before,
            "total ensure_block time observed"
        );
        let l = ledger.lock().unwrap();
        assert_eq!(l.current_round(), Round(2));
        assert_eq!(
            l.get_box(app_id, b"ts"),
            Some(1000u64.to_be_bytes().to_vec()),
            "LatestTimestamp must be the previous block's timestamp"
        );
    }

    /// Issue #1664: a block's payset omits each transaction's genesis
    /// id/hash; go restores them on decode, so `txn TxID` is the id of the
    /// full transaction. Executing app calls on the stored form hashed a
    /// different id (mainnet shuffle app 3729063730 picked other NFTs).
    #[test]
    fn ensure_block_runs_app_calls_with_the_full_transaction_id() {
        use algo_types::{AccountData, AppParams, Block, BoxRef, SignedTransaction, Transaction};
        use serde_bytes::ByteBuf;

        let creator = Address([1u8; 32]);
        let sender = Address([2u8; 32]);
        let fee_sink = Address([3u8; 32]);
        let app_id = 952u64;
        let program = algo_avm::assembler::assemble_string(concat!(
            "#pragma version 8
",
            "byte \"id\"
",
            "txn TxID
",
            "box_put
",
            "int 1
",
            "return
",
        ))
        .expect("program must assemble")
        .program;
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        {
            let mut l = ledger.lock().unwrap();
            for (addr, bal) in [
                (creator, 50_000_000u64),
                (sender, 50_000_000),
                (Address(crate::avm_context::app_address(app_id)), 10_000_000),
            ] {
                l.set_account(
                    &addr,
                    AccountData {
                        micro_algos: bal,
                        ..Default::default()
                    },
                );
            }
            l.set_account(&fee_sink, AccountData::default());
            l.set_app_params(
                app_id,
                AppParams {
                    creator,
                    approval_program: program,
                    clear_state_program: vec![0x08, 0x81, 0x01],
                    ..Default::default()
                },
            );
        }
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
        let stored = SignedTransaction {
            txn: Transaction {
                txn_type: "appl".into(),
                sender,
                fee: 1_000,
                first_valid: Round(1),
                last_valid: Round(1000),
                application_id: app_id,
                boxes: Some(vec![BoxRef {
                    index: 0,
                    name: Some(ByteBuf::from(b"id".to_vec())),
                }]),
                ..Default::default()
            },
            has_genesis_id: true,
            ..Default::default()
        };
        let mut full = stored.txn.clone();
        full.genesis_id = "test-v1".into();
        full.genesis_hash = [7u8; 32];
        let block = Block {
            round: Round(1),
            fee_sink,
            genesis_id: "test-v1".into(),
            genesis_hash: [7u8; 32],
            current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
            payset: vec![stored],
            ..Block::default()
        };
        bridge.ensure_block(&block, &make_cert_with_proposal(1));
        let l = ledger.lock().unwrap();
        assert_eq!(l.current_round(), Round(1));
        assert_eq!(
            l.get_box(app_id, b"id"),
            Some(algo_codec::compute_txn_id(&full).0.to_vec()),
            "TxID must be the id of the transaction with its genesis fields"
        );
    }

    #[test]
    fn ensure_block_never_applies_on_top_of_a_block_whose_rollback_failed() {
        let ledger = Arc::new(Mutex::new(SqliteLedger::open_in_memory().unwrap()));
        let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
        {
            // A half-applied block whose ROLLBACK keeps failing (twice).
            let mut l = ledger.lock().unwrap();
            l.begin_block().unwrap();
            l.set_current_round(Round(1));
            l.fail_rollback_count = 2;
            let _ = l.rollback_block();
        }
        // First attempt: the heal inside begin_block fails -> failed attempt,
        // nothing applied or stored.
        bridge.ensure_block(&make_round1_block(), &make_cert_with_proposal(1));
        {
            let l = ledger.lock().unwrap();
            assert!(
                l.has_pending_abort(),
                "abort still pending, nothing applied"
            );
            assert!(l.get_block_data(1).unwrap().is_none());
        }
        // Second attempt heals and commits normally.
        bridge.ensure_block(&make_round1_block(), &make_cert_with_proposal(1));
        assert_eq!(ledger.lock().unwrap().current_round().0, 1);
    }
}
