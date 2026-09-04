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

//! Autonomous state-proof signing/proving daemon (issue #814's live-daemon-
//! wiring scope, following on from PR #898's algorithmic core and issue
//! #912's voters-participant-array persistence precursor).
//!
//! Mirrors go-algorand's `stateproof.Worker`: watches every locally-held
//! state-proof participation key, signs eligible rounds
//! (`algo_ledger::stateproof_worker::sign_state_proof_message`), gathers its
//! own and peers' signatures into a per-round
//! [`algo_ledger::stateproof_worker::StateProofRuntime`] (via a new gossip
//! `Tag::StateProofSig` handler this module registers), and once a round has
//! gathered enough signed weight, builds the `StateProof` and submits a
//! `StateProofTx` through the same local-submission path any other
//! locally-originated transaction uses
//! ([`algo_network::local_tx_broadcast::LocalTxBroadcaster`]).
//!
//! **Deliberately opt-in, unlike go's always-on `Worker`** -- gated behind
//! `config.json`'s `EnableStateProofWorker` (default `false`), because this
//! introduces a new gossip wire message type peers need to understand and
//! autonomous transaction construction/broadcast that has not yet
//! accumulated the same production mileage as the rest of this node's
//! participation path. See `crate::commands::heartbeat_service` (issue
//! #820) for the established pattern this module follows: a dedicated
//! background thread woken by the same `round_advanced` condvar the pool
//! follower and heartbeat service already share.
//!
//! # Scope (see issue #814's Progress section for the full writeup)
//!
//! - Only the primary WS-gossip node (`algo_network::WebsocketNetwork`) is
//!   wired for `Tag::StateProofSig` -- not the libp2p P2P transport. This
//!   matches `ops/mixed-cluster/`'s topology (go-algorand relays speak the
//!   WS gossip protocol) and keeps this pass's live-cluster verification
//!   scope tractable.
//! - No disk-persisted `provers` table (go's `stateproof/db.go`'s
//!   `provers` table) -- see `StateProofRuntime`'s own doc comment for the
//!   in-memory-cache rationale.
//! - `StateProofRuntime::try_build` always targets the full proven-weight
//!   threshold rather than go's `AcceptableStateProofWeight` incremental
//!   schedule -- strictly safe, just potentially slower to produce the very
//!   first proof of a round (see that function's doc comment).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use algo_ledger::participation::ParticipationStore;
use algo_ledger::stateproof_message::generate_state_proof_message;
use algo_ledger::stateproof_worker::{
    build_state_proof_transaction, db, is_eligible_signing_round, next_state_proof_round,
    sign_state_proof_message, SigFromAddr, SigOutcome, StateProofRuntime, StateProofSigningKey,
};
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::SqliteLedger;
use algo_network::handler::{MessageHandler, TaggedMessageHandler};
use algo_network::local_tx_broadcast::LocalTxBroadcaster;
use algo_network::message::{IncomingMessage, OutgoingMessage};
use algo_network::{ForwardingPolicy, GossipNode, Tag};
use algo_types::consensus::consensus_params_for_version;
use algo_types::Round;

/// Same fallback poll interval as the heartbeat service (issue #820) --
/// state-proof round-eligibility windows span whole `StateProofInterval`s
/// (>= 256 rounds), far longer than any plausible poll delay.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// For every eligible signing round in `(*next_round - 1, current]` (i.e.
/// `*next_round..=current`), sign with every locally-held, currently-valid
/// state-proof key, persist each signature (`from_this_node = true`,
/// idempotent against a re-signed round), insert it into `runtime` (so this
/// node's own weight is counted immediately, without waiting for its own
/// gossip message to round-trip back), and collect the produced
/// [`SigFromAddr`]s for the caller to broadcast. Advances `*next_round` past
/// every round considered, matching go's `signer()` loop
/// (`signer.go:44-58`).
///
/// Errors reading the ledger/participation store for one round are logged
/// and skipped (that round is still marked considered) -- matching go's
/// `signStateProof`, which logs a warning and returns rather than crashing
/// the worker.
pub fn find_and_sign_eligible_rounds<L: LedgerStore>(
    store: &L,
    part_store: &ParticipationStore,
    sig_conn: &rusqlite::Connection,
    runtime: &mut StateProofRuntime,
    current: Round,
    next_round: &mut u64,
) -> Vec<SigFromAddr> {
    let hdr = match store.get_block_header(current.0) {
        Ok(Some(h)) => h,
        Ok(None) => return Vec::new(),
        Err(e) => {
            warn!(round = current.0, error = %e, "stateproof: failed to read block header");
            return Vec::new();
        }
    };
    let params = match consensus_params_for_version(&hdr.current_protocol) {
        Some(p) => p,
        None => {
            warn!(proto = %hdr.current_protocol, "stateproof: unknown consensus protocol version");
            return Vec::new();
        }
    };
    if params.state_proof_interval == 0 {
        *next_round = current.0 + 1;
        return Vec::new();
    }

    let mut out = Vec::new();
    while *next_round <= current.0 {
        let round = *next_round;
        *next_round += 1;

        if !is_eligible_signing_round(round, params.state_proof_interval) {
            continue;
        }

        let records = match part_store.get_for_voting_round(Round(round), Round(round)) {
            Ok(r) => r,
            Err(e) => {
                warn!(round, error = %e, "stateproof: failed to read participation store");
                continue;
            }
        };
        if records.is_empty() {
            continue;
        }

        let mut secrets_holder = Vec::new();
        for record in &records {
            match part_store.get_for_round(&record.participation_id, Round(round)) {
                Ok(Some(p)) => {
                    if let Some(secrets) = p.state_proof_secrets {
                        secrets_holder.push((record.account, record.first_valid.0, record.last_valid.0, secrets));
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(round, account = %record.account, error = %e, "stateproof: failed to load signing secrets");
                }
            }
        }
        if secrets_holder.is_empty() {
            continue;
        }

        let message = match generate_state_proof_message(store, round) {
            Ok(m) => m,
            Err(e) => {
                warn!(round, error = %e, "stateproof: failed to build state proof message");
                continue;
            }
        };
        let msg_hash = algo_ledger::apply_stateproof::state_proof_message_hash(&message);

        let keys: Vec<StateProofSigningKey> = secrets_holder
            .iter()
            .map(|(account, first_valid, last_valid, secrets)| StateProofSigningKey {
                account: *account,
                first_valid: *first_valid,
                last_valid: *last_valid,
                secrets,
            })
            .collect();
        let sigs = sign_state_proof_message(msg_hash, round, &keys, |addr| {
            db::sig_exists_in_db(sig_conn, round, addr).unwrap_or(false)
        });

        for sfa in sigs {
            if let Err(e) = db::add_pending_sig(
                sig_conn,
                round,
                &db::PendingSig {
                    signer: sfa.signer_address,
                    sig: sfa.sig.clone(),
                    from_this_node: true,
                },
            ) {
                warn!(round, signer = %sfa.signer_address, error = %e, "stateproof: failed to persist own signature");
            }
            if let Err(e) = runtime.handle_sig(store, &sfa) {
                warn!(round, signer = %sfa.signer_address, error = %e, "stateproof: failed to insert own signature into runtime");
            }
            info!(round, signer = %sfa.signer_address, "stateproof: signed state proof message");
            out.push(sfa);
        }
    }
    out
}

/// Gossip handler for `Tag::StateProofSig` -- decodes an incoming
/// [`SigFromAddr`], inserts it into the shared [`StateProofRuntime`], and
/// persists it (marked `from_this_node = false`) on acceptance. Mirrors the
/// insertion half of go's `Worker.handleSigMessage`/`handleSig`
/// (`worker.go:312`, `builder.go:343`) -- see this module's doc comment for
/// what's out of scope (the `Disconnect` forwarding-policy nuances around
/// stalled-chain recovery, `meetsBroadcastPolicy`).
pub struct StateProofSigHandler {
    ledger: Arc<Mutex<SqliteLedger>>,
    runtime: Arc<Mutex<StateProofRuntime>>,
    sig_conn: Arc<Mutex<rusqlite::Connection>>,
}

impl StateProofSigHandler {
    pub fn new(
        ledger: Arc<Mutex<SqliteLedger>>,
        runtime: Arc<Mutex<StateProofRuntime>>,
        sig_conn: Arc<Mutex<rusqlite::Connection>>,
    ) -> Self {
        Self {
            ledger,
            runtime,
            sig_conn,
        }
    }
}

fn ignore_message() -> OutgoingMessage {
    OutgoingMessage {
        action: ForwardingPolicy::Ignore,
        tag: Tag::StateProofSig,
        payload: Vec::new(),
        topics: None,
    }
}

#[async_trait]
impl MessageHandler for StateProofSigHandler {
    async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        let sfa = match SigFromAddr::from_msgpack(&msg.data) {
            Ok(s) => s,
            Err(e) => {
                debug!(sender = %msg.sender, error = %e, "stateproof: failed to decode incoming StateProofSig");
                return ignore_message();
            }
        };

        let outcome = {
            let ledger = match self.ledger.lock() {
                Ok(l) => l,
                Err(_) => return ignore_message(),
            };
            let mut runtime = match self.runtime.lock() {
                Ok(r) => r,
                Err(_) => return ignore_message(),
            };
            runtime.handle_sig(&*ledger, &sfa)
        };

        match outcome {
            Ok(SigOutcome::Broadcast) => {
                if let Ok(conn) = self.sig_conn.lock() {
                    if let Err(e) = db::add_pending_sig(
                        &conn,
                        sfa.round,
                        &db::PendingSig {
                            signer: sfa.signer_address,
                            sig: sfa.sig.clone(),
                            from_this_node: false,
                        },
                    ) {
                        // A unique-constraint failure here just means we'd
                        // already stored this exact (round, signer) pair --
                        // harmless; anything else is worth a log line.
                        debug!(round = sfa.round, signer = %sfa.signer_address, error = %e, "stateproof: could not persist gossiped signature");
                    }
                }
                info!(round = sfa.round, signer = %sfa.signer_address, sender = %msg.sender, "stateproof: accepted signature from peer");
                OutgoingMessage {
                    action: ForwardingPolicy::Broadcast,
                    tag: Tag::StateProofSig,
                    payload: msg.data,
                    topics: None,
                }
            }
            Ok(SigOutcome::Ignore) => ignore_message(),
            Err(e) => {
                debug!(round = sfa.round, signer = %sfa.signer_address, error = %e, "stateproof: rejected incoming signature");
                ignore_message()
            }
        }
    }
}

/// Register the `Tag::StateProofSig` handler and construct the shared
/// runtime/db state a [`spawn`]ed background loop needs. Callers register
/// the returned [`TaggedMessageHandler`] on the primary gossip node's
/// multiplexer *before* starting the network listener (matching this
/// codebase's other tag-handler registration ordering), then pass the
/// returned `runtime`/`sig_conn` into [`spawn`].
pub fn build_handler(
    ledger: Arc<Mutex<SqliteLedger>>,
    sig_conn: Arc<Mutex<rusqlite::Connection>>,
) -> (TaggedMessageHandler, Arc<Mutex<StateProofRuntime>>) {
    let runtime = Arc::new(Mutex::new(StateProofRuntime::new()));
    let handler = TaggedMessageHandler {
        tag: Tag::StateProofSig,
        handler: Arc::new(StateProofSigHandler::new(
            ledger,
            Arc::clone(&runtime),
            sig_conn,
        )),
    };
    (handler, runtime)
}

/// Open (creating if needed) the `sigs` table database at `path`, or an
/// in-memory database when `path` is `None` (test/ephemeral use).
pub fn open_sig_db(path: Option<&std::path::Path>) -> rusqlite::Result<rusqlite::Connection> {
    let conn = match path {
        Some(p) => rusqlite::Connection::open(p)?,
        None => rusqlite::Connection::open_in_memory()?,
    };
    db::install_sigs_table(&conn)?;
    Ok(conn)
}

/// The background loop body. Mirrors [`crate::commands::heartbeat_service`]'s
/// `run_loop` structure: runs until `stop` is set, woken by
/// `round_advanced` (falling back to `poll_interval`). Each iteration signs
/// any newly-eligible rounds, broadcasts the resulting signatures over
/// gossip, and tries to build+submit any round that has gathered enough
/// weight.
#[allow(clippy::too_many_arguments)]
fn run_loop(
    ledger: &Arc<Mutex<SqliteLedger>>,
    part_store: &ParticipationStore,
    sig_conn: &Arc<Mutex<rusqlite::Connection>>,
    runtime: &Arc<Mutex<StateProofRuntime>>,
    gossip_node: &Arc<dyn GossipNode>,
    broadcaster: &LocalTxBroadcaster,
    genesis_hash: [u8; 32],
    round_advanced: &Condvar,
    stop: &AtomicBool,
    poll_interval: Duration,
    rt_handle: &tokio::runtime::Handle,
) {
    let wait_gate = Mutex::new(());

    // Start signing from the round the ledger's own tracker says it still
    // needs a proof for -- mirrors go's `Worker.signer`'s
    // `nextStateProofRound(latest)` at startup.
    let mut next_round: u64 = {
        let l = match ledger.lock() {
            Ok(l) => l,
            Err(_) => return,
        };
        let latest = l.current_round();
        let state_proof_next_round = l
            .get_block_header(latest.0)
            .ok()
            .flatten()
            .map(|h| algo_ledger::block_header::state_proof_next_round(&h.state_proof_tracking))
            .unwrap_or(0);
        next_state_proof_round(state_proof_next_round, latest.0)
    };

    while !stop.load(Ordering::Relaxed) {
        let current = {
            let l = match ledger.lock() {
                Ok(l) => l,
                Err(_) => break,
            };
            l.current_round()
        };

        // 1. Sign any newly-eligible rounds and broadcast the results.
        let sigs = {
            let l = match ledger.lock() {
                Ok(l) => l,
                Err(_) => break,
            };
            let conn = match sig_conn.lock() {
                Ok(c) => c,
                Err(_) => break,
            };
            let mut rt = match runtime.lock() {
                Ok(r) => r,
                Err(_) => break,
            };
            find_and_sign_eligible_rounds(&*l, part_store, &conn, &mut rt, current, &mut next_round)
        };
        for sfa in sigs {
            let payload = sfa.to_msgpack();
            if let Err(e) = rt_handle.block_on(gossip_node.broadcast(Tag::StateProofSig, payload, false, None))
            {
                warn!(round = sfa.round, error = %e, "stateproof: failed to broadcast own signature");
            }
        }

        // 1b. Prune stale in-progress provers before attempting to build.
        // `StateProofRuntime::try_build` scans `self.provers` in ascending
        // round order and stops at the first round that isn't ready yet
        // (state proofs are chained -- round N+interval's proof can't be
        // submitted before round N's), mirroring go's `tryBroadcast`. But
        // unlike a single-node testbed, a real multi-node network races: any
        // OTHER online signer can independently gather enough weight and
        // commit round N's `StateProofTx` first, advancing the ledger's
        // `StateProofNextRound` past N without this node's own local prover
        // for N ever reaching its own weight threshold. Go's worker handles
        // this via `OnPrepareVoterCommit`/`trimProversCache`, invoked on
        // every new block; this is the equivalent, invoked once per loop
        // iteration from the ledger's own committed state. Without it, a
        // single lost race permanently wedges `try_build`'s ascending scan
        // on a round that will now never gather more signatures (peers stop
        // broadcasting for an already-superseded round), silently blocking
        // every later round's build forever. Found live during issue #814's
        // shortened-`StateProofInterval` mixed-cluster verification: the
        // three go-algorand relays (90% combined stake) routinely built and
        // committed real `StateProofTx`s among themselves before the Rust
        // node (10% stake, plus real signature-gossip propagation delay)
        // ever finished gathering its own.
        {
            let needed_round = {
                let l = match ledger.lock() {
                    Ok(l) => l,
                    Err(_) => break,
                };
                l.get_block_header(current.0)
                    .ok()
                    .flatten()
                    .map(|h| algo_ledger::block_header::state_proof_next_round(&h.state_proof_tracking))
                    .unwrap_or(0)
            };
            if needed_round > 0 {
                if let Ok(mut rt) = runtime.lock() {
                    rt.prune(needed_round);
                }
            }
        }

        // 2. Try to build+submit any round that's now ready.
        let built = {
            let mut rt = match runtime.lock() {
                Ok(r) => r,
                Err(_) => break,
            };
            rt.try_build()
        };
        for (round, proof, message) in built {
            let stx = build_state_proof_transaction(current.0, algo_types::consensus::consensus_params_for_version(
                    // max_txn_life for the *current* protocol governs a
                    // freshly-submitted transaction's validity window --
                    // matches go's `config.Consensus[latestHeader.CurrentProtocol].MaxTxnLife`.
                    &{
                        let l = ledger.lock().ok();
                        l.and_then(|l| l.get_block_header(current.0).ok().flatten())
                            .map(|h| h.current_protocol)
                            .unwrap_or_default()
                    },
                )
                .map(|p| p.max_txn_life)
                .unwrap_or(1000),
                genesis_hash,
                &proof,
                &message,
            );
            match rt_handle.block_on(broadcaster.submit_group(vec![stx])) {
                Ok(txid) => {
                    info!(round, txid = %txid, "stateproof: submitted StateProofTx");
                    if let Ok(mut rt) = runtime.lock() {
                        rt.mark_submitted(round);
                    }
                }
                Err(e) => {
                    warn!(round, error = %e, "stateproof: failed to submit StateProofTx");
                }
            }
        }

        if stop.load(Ordering::Relaxed) {
            break;
        }
        let guard = wait_gate.lock().expect("wait_gate mutex poisoned");
        let _ = round_advanced.wait_timeout(guard, poll_interval);
    }
}

/// Spawn the autonomous state-proof service as a dedicated background
/// thread. Returns a stop flag and join handle; call
/// `stop.store(true, Ordering::Relaxed)` then `join_handle.join()` to shut
/// it down (mirroring `heartbeat_service::spawn`'s shutdown sequence).
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    ledger: Arc<Mutex<SqliteLedger>>,
    part_store: ParticipationStore,
    sig_conn: Arc<Mutex<rusqlite::Connection>>,
    runtime: Arc<Mutex<StateProofRuntime>>,
    gossip_node: Arc<dyn GossipNode>,
    broadcaster: Arc<LocalTxBroadcaster>,
    genesis_hash: [u8; 32],
    round_advanced: Arc<Condvar>,
    rt_handle: tokio::runtime::Handle,
    poll_interval: Duration,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);
    let join = std::thread::Builder::new()
        .name("stateproof-service".to_string())
        .spawn(move || {
            run_loop(
                &ledger,
                &part_store,
                &sig_conn,
                &runtime,
                &gossip_node,
                &broadcaster,
                genesis_hash,
                &round_advanced,
                &stop_for_thread,
                poll_interval,
                &rt_handle,
            );
        })
        .expect("failed to spawn stateproof-service thread");
    (stop, join)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_consensus_crypto::merklesig;
    use algo_ledger::participation::Participation;
    use algo_ledger::voters_tracker::record_voters_snapshot;
    use algo_ledger::LedgerState;
    use algo_types::consensus::CONSENSUS_V41;
    use algo_types::{AccountData, AccountStatus, Address, BlockHeader};

    fn tracking(voters_commitment: &[u8], total_weight: u64) -> Option<rmpv::Value> {
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

    #[test]
    fn find_and_sign_eligible_rounds_signs_local_keys_and_advances_next_round() {
        let params = algo_types::consensus::consensus_params_for_version(CONSENSUS_V41).unwrap();
        let mut store = LedgerState::new();
        let part_store = ParticipationStore::open_in_memory().expect("part store");
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        db::install_sigs_table(&conn).unwrap();
        let mut runtime = StateProofRuntime::new();

        const SNAPSHOT_ROUND: u64 = 240;
        const VOTERS_ROUND: u64 = 256;
        const STATE_PROOF_ROUND: u64 = 512;

        // One online account with a real MSS key, registered locally too.
        let secrets =
            merklesig::Secrets::new(STATE_PROOF_ROUND, STATE_PROOF_ROUND, 1).expect("mss keygen");
        let commitment = secrets.get_verifier().commitment;
        let addr = Address([1u8; 32]);
        store.set_account(
            &addr,
            AccountData {
                micro_algos: 5_000_000,
                status: AccountStatus::Online,
                vote_first_valid: 0,
                vote_last_valid: STATE_PROOF_ROUND + 1000,
                state_proof_id: Some(commitment),
                ..Default::default()
            },
        );
        record_voters_snapshot(&mut store, SNAPSHOT_ROUND, 0, &params).unwrap();
        let (root, total_weight) = store.get_voters_snapshot(SNAPSHOT_ROUND).unwrap().unwrap();

        put_header(
            &mut store,
            &BlockHeader {
                round: Round(VOTERS_ROUND),
                current_protocol: CONSENSUS_V41.to_string(),
                genesis_hash: [0xABu8; 32],
                txn256: [VOTERS_ROUND as u8; 32],
                state_proof_tracking: tracking(&root, total_weight),
                ..BlockHeader::default()
            },
        );
        for r in (VOTERS_ROUND + 1)..STATE_PROOF_ROUND {
            put_header(
                &mut store,
                &BlockHeader {
                    round: Round(r),
                    current_protocol: CONSENSUS_V41.to_string(),
                    genesis_hash: [0xABu8; 32],
                    txn256: [(r % 256) as u8; 32],
                    ..BlockHeader::default()
                },
            );
        }
        put_header(
            &mut store,
            &BlockHeader {
                round: Round(STATE_PROOF_ROUND),
                current_protocol: CONSENSUS_V41.to_string(),
                genesis_hash: [0xABu8; 32],
                txn256: [STATE_PROOF_ROUND as u8; 32],
                state_proof_tracking: tracking(&root, total_weight),
                ..BlockHeader::default()
            },
        );

        // Register the local participation key with state-proof secrets.
        let part = Participation {
            parent: addr,
            vrf: algo_consensus_crypto::VrfKeypair::generate(),
            voting: algo_consensus_crypto::OneTimeSignatureSecrets::generate(0, 10),
            first_valid: Round(0),
            last_valid: Round(STATE_PROOF_ROUND + 1000),
            key_dilution: 10,
            state_proof_secrets: Some(secrets),
        };
        let id = part_store.insert(&part).expect("insert participation");
        part_store.register(&id, Round(1)).expect("register");

        let mut next_round = STATE_PROOF_ROUND; // start right at the eligible round
        let sigs = find_and_sign_eligible_rounds(
            &store,
            &part_store,
            &conn,
            &mut runtime,
            Round(STATE_PROOF_ROUND),
            &mut next_round,
        );
        assert_eq!(sigs.len(), 1, "the one locally-held key must sign");
        assert_eq!(sigs[0].signer_address, addr);
        assert_eq!(sigs[0].round, STATE_PROOF_ROUND);
        assert_eq!(next_round, STATE_PROOF_ROUND + 1);
        assert!(db::sig_exists_in_db(&conn, STATE_PROOF_ROUND, addr).unwrap());
        assert_eq!(runtime.signed_weight(STATE_PROOF_ROUND), Some(5_000_000));

        // Calling again over the same already-considered window signs
        // nothing new (round already advanced past).
        let sigs2 = find_and_sign_eligible_rounds(
            &store,
            &part_store,
            &conn,
            &mut runtime,
            Round(STATE_PROOF_ROUND),
            &mut next_round,
        );
        assert!(sigs2.is_empty());
    }

    #[test]
    fn find_and_sign_eligible_rounds_noop_when_state_proofs_disabled() {
        let mut store = LedgerState::new();
        put_header(
            &mut store,
            &BlockHeader {
                round: Round(10),
                current_protocol: algo_types::consensus::CONSENSUS_V33.to_string(),
                ..BlockHeader::default()
            },
        );
        let part_store = ParticipationStore::open_in_memory().expect("part store");
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        db::install_sigs_table(&conn).unwrap();
        let mut runtime = StateProofRuntime::new();
        let mut next_round = 1u64;
        let sigs = find_and_sign_eligible_rounds(
            &store,
            &part_store,
            &conn,
            &mut runtime,
            Round(10),
            &mut next_round,
        );
        assert!(sigs.is_empty());
        assert_eq!(next_round, 11, "advances past the disabled round without looping");
    }
}
