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

//! Autonomous heartbeat service (issue #820's priority item).
//!
//! Mirrors go-algorand's `heartbeat/service.go`: watches every locally-held
//! participation key each round and, if the account it participates for is
//! under an active challenge (`Payouts.ChallengeInterval`/
//! `ChallengeGracePeriod`, `algo_ledger::heartbeat::find_challenge`) and
//! hasn't been seen since before the challenge, proactively constructs,
//! signs (via the accepting LogicSig -- see
//! `algo_ledger::heartbeat_builder`), and submits a fee-exempt `hb`
//! transaction through the same local-submission path any other
//! locally-originated transaction uses
//! ([`algo_network::local_tx_broadcast::LocalTxBroadcaster`]).
//!
//! This module is split into:
//! - [`find_and_build_heartbeats`]: the per-round decision+construction
//!   pass. Pure enough to unit-test directly against a real (in-memory)
//!   [`SqliteLedger`] + [`ParticipationStore`] without any threads or
//!   async runtime -- see the tests below.
//! - [`spawn`] / the background loop: the autonomous part, structured like
//!   `run_pool_block_follower` in `participate.rs` (a dedicated
//!   `std::thread` woken by the same `round_advanced` condvar the pool
//!   follower and catchup service already share, bounded by a
//!   `poll_interval` fallback so a missed notification can't wedge the
//!   service forever).
//!
//! ## Why a dedicated thread, not a `tokio::spawn`
//!
//! `find_and_build_heartbeats` and the participation-key lookups it drives
//! are synchronous (`rusqlite`); only the final submission
//! (`LocalTxBroadcaster::submit_group`) is async. Mirroring
//! `run_pool_block_follower`'s existing thread + condvar pattern (rather
//! than inventing a second concurrency style in this file) keeps the round
//! wait synchronous and bridges into async only at the one call that needs
//! it, via `rt_handle.block_on`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use tracing::{debug, info, warn};

use algo_ledger::heartbeat::StoreHeaderProvider;
use algo_ledger::heartbeat::{find_challenge, needs_heartbeat, ChallengePeriod};
use algo_ledger::heartbeat_builder::{build_heartbeat_transaction, HeartbeatParams};
use algo_ledger::participation::ParticipationStore;
use algo_ledger::store_trait::LedgerStore;
use algo_ledger::SqliteLedger;
use algo_network::local_tx_broadcast::LocalTxBroadcaster;
use algo_types::consensus::consensus_params_for_version;
use algo_types::{Address, Round, SignedTransaction};

/// Default fallback poll interval: how often the service re-checks even if
/// `round_advanced` is never notified. Matches the pool-block-follower's
/// own 200ms default cadence in spirit; heartbeat decisions are cheap
/// (bounded by the number of locally-held participation keys) so polling
/// this often is not a meaningful cost, and the grace-period window
/// (`ChallengeGracePeriod`, currently 200 rounds ~ almost 10 minutes) is
/// far longer than any plausible poll delay.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// For one round, find every locally-held participation key whose account
/// is under an active ("risky") challenge and hasn't been seen since
/// before it, and build a signed heartbeat transaction for each.
///
/// Mirrors Go's `Service.findChallenged` + `Service.prepareHeartbeat`
/// combined into one pass (Go keeps them separate because `prepareHeartbeat`
/// is only called after the caller's `suppress` map has filtered
/// `findChallenged`'s results -- that filtering happens one level up, in
/// the [`spawn`]ed loop here, so this function itself doesn't need to know
/// about suppression).
///
/// Returns `(hb_address, signed_heartbeat_txn)` pairs. Errors reading the
/// ledger or participation store are treated as "nothing to do this round"
/// (logged, not propagated) -- matching Go's `loop`, which logs and
/// continues to the next round rather than crashing the service.
pub fn find_and_build_heartbeats<L: LedgerStore>(
    store: &L,
    part_store: &ParticipationStore,
    current: Round,
) -> Vec<(Address, SignedTransaction)> {
    let hdr = match store.get_block_header(current.0) {
        Ok(Some(h)) => h,
        Ok(None) => {
            debug!(
                round = current.0,
                "heartbeat: no block header at current round yet"
            );
            return Vec::new();
        }
        Err(e) => {
            warn!(round = current.0, error = %e, "heartbeat: failed to read block header");
            return Vec::new();
        }
    };

    let params = match consensus_params_for_version(&hdr.current_protocol) {
        Some(p) => p,
        None => {
            warn!(proto = %hdr.current_protocol, "heartbeat: unknown consensus protocol version");
            return Vec::new();
        }
    };

    let provider = StoreHeaderProvider { store };
    let challenge = find_challenge(&params, current.0, &provider, ChallengePeriod::Risky);
    if challenge.is_zero() {
        return Vec::new();
    }

    let records = match part_store.get_for_voting_round(current, current) {
        Ok(r) => r,
        Err(e) => {
            warn!(round = current.0, error = %e, "heartbeat: failed to read participation store");
            return Vec::new();
        }
    };

    let challenge_discount = params.txn_size_pricing_enabled();
    let mut out = Vec::new();
    for record in records {
        // Only a key whose OneTimeSignatureVerifier matches the account's
        // *currently registered* VoteID is the live key for this account --
        // a stale/rotated-out local key must not heartbeat under someone
        // else's registration. Mirrors Go:
        // `acct.VoteID != pr.Voting.OneTimeSignatureVerifier`.
        let Some(record_vote_id) = record.vote_id else {
            continue;
        };

        let account = store.get_account(&record.account).unwrap_or_default();
        let needed = needs_heartbeat(
            &challenge,
            &record.account.0,
            account.vote_id,
            record_vote_id,
            account.incentive_eligible,
            account.last_proposed,
            account.last_heartbeat,
        );
        if !needed {
            continue;
        }

        let participation = match part_store.get_for_round(&record.participation_id, current) {
            Ok(Some(p)) => p,
            Ok(None) => {
                debug!(
                    account = %record.account,
                    "heartbeat: participation record has no loadable secrets for this round"
                );
                continue;
            }
            Err(e) => {
                warn!(account = %record.account, error = %e, "heartbeat: failed to load signing secrets");
                continue;
            }
        };

        let stx = build_heartbeat_transaction(HeartbeatParams {
            hb_address: record.account,
            voting: &participation.voting,
            vote_id: record_vote_id,
            key_dilution: record.key_dilution,
            genesis_hash: hdr.genesis_hash,
            latest_round: current,
            latest_seed: hdr.seed,
            challenge_discount,
        });
        info!(account = %record.account, round = current.0, "heartbeat: account needs a heartbeat");
        out.push((record.account, stx));
    }
    out
}

/// The background loop body. Runs until `stop` is set, waking on
/// `round_advanced` (falling back to `poll_interval` if it's never
/// notified). Each iteration reads the current round, computes any needed
/// heartbeats via [`find_and_build_heartbeats`], and submits each one not
/// currently suppressed (i.e. not already covered by a still-`LastValid`
/// heartbeat this service sent earlier in the same grace period).
///
/// Mirrors Go's `Service.loop`, including its `suppress` map: "Don't
/// bother heartbeating again until the last one expires. If it is
/// accepted, we won't need to (because we won't be under challenge any
/// more)."
fn run_loop(
    ledger: &Arc<Mutex<SqliteLedger>>,
    part_store: &ParticipationStore,
    broadcaster: &LocalTxBroadcaster,
    round_advanced: &Condvar,
    stop: &AtomicBool,
    poll_interval: Duration,
    rt_handle: &tokio::runtime::Handle,
) {
    // Paired only with `round_advanced` for `wait_timeout`'s API -- same
    // rationale as `run_pool_block_follower`'s own `wait_gate`: it does not
    // guard any shared state, it just gives the condvar a mutex to park on.
    let wait_gate = Mutex::new(());
    let mut suppress: HashMap<Address, Round> = HashMap::new();

    while !stop.load(Ordering::Relaxed) {
        let current = match ledger.lock() {
            Ok(l) => l.current_round(),
            Err(_) => break, // poisoned -- nothing sane left to do
        };

        let candidates = {
            let l = match ledger.lock() {
                Ok(l) => l,
                Err(_) => break,
            };
            find_and_build_heartbeats(&*l, part_store, current)
        };

        for (address, stx) in candidates {
            if let Some(&suppressed_until) = suppress.get(&address) {
                if suppressed_until >= current {
                    continue;
                }
            }
            let last_valid = stx.txn.last_valid;
            match rt_handle.block_on(broadcaster.submit_group(vec![stx])) {
                Ok(txid) => {
                    info!(
                        %address,
                        txid = %txid,
                        round = current.0,
                        last_valid = last_valid.0,
                        "heartbeat: submitted heartbeat transaction"
                    );
                    // Don't heartbeat again until this one expires -- if
                    // it's accepted, the account won't be challenged any
                    // more; if it isn't, we'll retry once it does.
                    suppress.insert(address, last_valid);
                }
                Err(e) => {
                    warn!(%address, round = current.0, error = %e, "heartbeat: failed to submit heartbeat transaction");
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

/// Spawn the autonomous heartbeat service as a dedicated background
/// thread. Returns a stop flag and join handle; call
/// `stop.store(true, Ordering::Relaxed)` then `join_handle.join()` to shut
/// it down (mirroring `participate.rs`'s pool-block-follower shutdown
/// sequence).
pub fn spawn(
    ledger: Arc<Mutex<SqliteLedger>>,
    part_store: ParticipationStore,
    broadcaster: Arc<LocalTxBroadcaster>,
    round_advanced: Arc<Condvar>,
    rt_handle: tokio::runtime::Handle,
    poll_interval: Duration,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);
    let join = std::thread::Builder::new()
        .name("heartbeat-service".to_string())
        .spawn(move || {
            run_loop(
                &ledger,
                &part_store,
                &broadcaster,
                &round_advanced,
                &stop_for_thread,
                poll_interval,
                &rt_handle,
            );
        })
        .expect("failed to spawn heartbeat-service thread");
    (stop, join)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_consensus_crypto::one_time_id_for_round;
    use algo_ledger::participation::Participation;
    use algo_types::consensus::CONSENSUS_V41;
    use algo_types::AccountData;

    /// A minimal ledger with `n` blocks committed (rounds `1..=n`) all
    /// under V41, so `find_challenge` has real headers with a real seed to
    /// look at. Uses `algo_ledger::make_genesis_block` + direct
    /// `put_block`/account writes rather than the full agreement/apply
    /// pipeline -- this module only needs `get_block_header` and
    /// `get_account` to behave like the real ledger, not full consensus
    /// semantics.
    fn ledger_at_round(round: u64, seed_byte: u8) -> SqliteLedger {
        let mut ledger = SqliteLedger::open_in_memory().expect("in-memory ledger");
        for r in 1..=round {
            let hdr = algo_types::BlockHeader {
                round: Round(r),
                current_protocol: CONSENSUS_V41.to_string(),
                genesis_hash: [0xAA; 32],
                seed: [seed_byte; 32],
                ..Default::default()
            };
            let hdr_bytes =
                algo_codec::canonical_encode_block_header_from_block(&algo_types::Block {
                    round: hdr.round,
                    current_protocol: hdr.current_protocol.clone(),
                    genesis_hash: hdr.genesis_hash,
                    seed: hdr.seed,
                    ..Default::default()
                });
            ledger
                .put_block(r, CONSENSUS_V41, &hdr_bytes, &hdr_bytes)
                .expect("put_block");
        }
        ledger
    }

    fn make_participation(account: Address) -> (Participation, [u8; 32]) {
        let key = Participation::generate(account, Round(0), Round(3000), 10, 0)
            .expect("generate participation key");
        let vote_id = key.voting.verifier();
        (key, vote_id)
    }

    #[test]
    fn find_and_build_heartbeats_empty_when_no_challenge() {
        // interval=1000, grace=200 for V41; round 500 is well before any
        // challenge window opens (needs round >= interval == 1000).
        let ledger = ledger_at_round(500, 0xAB);
        let part_store = ParticipationStore::open_in_memory().expect("part store");
        let out = find_and_build_heartbeats(&ledger, &part_store, Round(500));
        assert!(out.is_empty());
    }

    #[test]
    fn find_and_build_heartbeats_empty_with_no_participation_keys() {
        // Round 2150 is inside the risky window for a challenge issued at
        // round 2000 (interval=1000, grace=200: risky window is
        // (2100, 2200]), but with no participation keys registered at all,
        // there's nothing to check.
        let ledger = ledger_at_round(2150, 0xF8); // seed 1111_1000...
        let part_store = ParticipationStore::open_in_memory().expect("part store");
        let out = find_and_build_heartbeats(&ledger, &part_store, Round(2150));
        assert!(out.is_empty());
    }

    #[test]
    fn find_and_build_heartbeats_produces_heartbeat_for_challenged_eligible_account() {
        let mut ledger = ledger_at_round(2150, 0xF8); // matches challenge seed below
        let part_store = ParticipationStore::open_in_memory().expect("part store");

        // Address chosen so its first 5 bits match seed 0xF8 (1111_1000):
        // 0xFF = 1111_1111 -- first 5 bits (11111) match.
        let account = Address([0xFF; 32]);
        let (key, vote_id) = make_participation(account);
        let id = part_store.insert(&key).expect("insert key");
        part_store.register(&id, Round(1)).expect("register key");

        // Mark the account online, incentive-eligible, and never having
        // heartbeated/proposed -- i.e. genuinely stale as of the challenge
        // round (2000).
        let acct = AccountData {
            micro_algos: 1_000_000,
            status: algo_types::AccountStatus::Online,
            incentive_eligible: true,
            vote_id: Some(vote_id),
            vote_key_dilution: 10,
            last_proposed: 0,
            last_heartbeat: 0,
            ..Default::default()
        };
        // set_account is a LedgerStore method; use it directly.
        ledger.set_account(&account, acct);

        let out = find_and_build_heartbeats(&ledger, &part_store, Round(2150));
        assert_eq!(out.len(), 1, "expected exactly one heartbeat candidate");
        let (addr, stx) = &out[0];
        assert_eq!(*addr, account);
        assert_eq!(stx.txn.txn_type, algo_types::TxnType::Hb);
        let hb = stx.txn.heartbeat.as_ref().expect("heartbeat fields");
        assert_eq!(hb.address, account);
        assert_eq!(hb.vote_id, vote_id);
    }

    #[test]
    fn find_and_build_heartbeats_skips_account_that_already_heartbeated() {
        let mut ledger = ledger_at_round(2150, 0xF8);
        let part_store = ParticipationStore::open_in_memory().expect("part store");

        let account = Address([0xFF; 32]);
        let (key, vote_id) = make_participation(account);
        let id = part_store.insert(&key).expect("insert key");
        part_store.register(&id, Round(1)).expect("register key");

        let acct = AccountData {
            micro_algos: 1_000_000,
            status: algo_types::AccountStatus::Online,
            incentive_eligible: true,
            vote_id: Some(vote_id),
            vote_key_dilution: 10,
            last_proposed: 0,
            // Heartbeated at round 2000 == the challenge round -> not stale.
            last_heartbeat: 2000,
            ..Default::default()
        };
        ledger.set_account(&account, acct);

        let out = find_and_build_heartbeats(&ledger, &part_store, Round(2150));
        assert!(out.is_empty());
    }

    #[test]
    fn find_and_build_heartbeats_skips_non_incentive_eligible_account() {
        let mut ledger = ledger_at_round(2150, 0xF8);
        let part_store = ParticipationStore::open_in_memory().expect("part store");

        let account = Address([0xFF; 32]);
        let (key, vote_id) = make_participation(account);
        let id = part_store.insert(&key).expect("insert key");
        part_store.register(&id, Round(1)).expect("register key");

        let acct = AccountData {
            micro_algos: 1_000_000,
            status: algo_types::AccountStatus::Online,
            incentive_eligible: false, // not opted into payouts
            vote_id: Some(vote_id),
            vote_key_dilution: 10,
            last_proposed: 0,
            last_heartbeat: 0,
            ..Default::default()
        };
        ledger.set_account(&account, acct);

        let out = find_and_build_heartbeats(&ledger, &part_store, Round(2150));
        assert!(out.is_empty());
    }

    #[test]
    fn find_and_build_heartbeats_skips_stale_but_non_matching_address() {
        let mut ledger = ledger_at_round(2150, 0xF8); // 1111_1000...
        let part_store = ParticipationStore::open_in_memory().expect("part store");

        // 0x00 -- first bit 0, does not match seed's leading 1-bits.
        let account = Address([0x00; 32]);
        let (key, vote_id) = make_participation(account);
        let id = part_store.insert(&key).expect("insert key");
        part_store.register(&id, Round(1)).expect("register key");

        let acct = AccountData {
            micro_algos: 1_000_000,
            status: algo_types::AccountStatus::Online,
            incentive_eligible: true,
            vote_id: Some(vote_id),
            vote_key_dilution: 10,
            last_proposed: 0,
            last_heartbeat: 0,
            ..Default::default()
        };
        ledger.set_account(&account, acct);

        let out = find_and_build_heartbeats(&ledger, &part_store, Round(2150));
        assert!(out.is_empty());
    }

    #[test]
    fn find_and_build_heartbeats_skips_stale_vote_id_key() {
        // The registered on-chain VoteID doesn't match this locally-held
        // key's verifier -- e.g. a key that was rotated out. Must not
        // heartbeat with it.
        let mut ledger = ledger_at_round(2150, 0xF8);
        let part_store = ParticipationStore::open_in_memory().expect("part store");

        let account = Address([0xFF; 32]);
        let (key, _vote_id) = make_participation(account);
        let id = part_store.insert(&key).expect("insert key");
        part_store.register(&id, Round(1)).expect("register key");

        let acct = AccountData {
            micro_algos: 1_000_000,
            status: algo_types::AccountStatus::Online,
            incentive_eligible: true,
            vote_id: Some([0xEE; 32]), // different from this key's verifier
            vote_key_dilution: 10,
            last_proposed: 0,
            last_heartbeat: 0,
            ..Default::default()
        };
        ledger.set_account(&account, acct);

        let out = find_and_build_heartbeats(&ledger, &part_store, Round(2150));
        assert!(out.is_empty());
    }

    // ── one_time_id_for_round smoke import (keeps the dev-dependency honest) ──
    #[test]
    fn one_time_id_for_round_smoke() {
        let id = one_time_id_for_round(500, 10);
        assert_eq!(id.batch, 50);
    }
}
