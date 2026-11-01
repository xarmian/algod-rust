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

//! Issue #1764: the agreement bridge's committed reads (`seed`,
//! `lookup_digest`, `lookup_agreement`, `consensus_version`) are served
//! without the ledger mutex and equal the locked accessors.

use super::*;
use crate::store_trait::LedgerStore;
use algo_types::{AccountData, AccountStatus};

/// msgpack `{"seed": bin(32)}`, the only header field `seed()` reads.
fn seed_header(seed: [u8; 32]) -> Vec<u8> {
    let v = rmpv::Value::Map(vec![(
        rmpv::Value::from("seed"),
        rmpv::Value::Binary(seed.to_vec()),
    )]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &v).unwrap();
    out
}

const ADDR: Address = Address([1u8; 32]);

/// A file-backed ledger with committed rounds 1..=3 (headers carry a
/// per-round seed) and an online account with history from round 1.
fn file_bridge_ledger() -> (tempfile::TempDir, Arc<Mutex<SqliteLedger>>) {
    let dir = tempfile::tempdir().unwrap();
    let mut l = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    let online = AccountData {
        micro_algos: 42_000,
        status: AccountStatus::Online,
        vote_id: Some([7u8; 32]),
        selection_id: Some([8u8; 32]),
        vote_last_valid: 1_000_000,
        vote_key_dilution: 100,
        ..Default::default()
    };
    for r in 1..=3u64 {
        l.begin_block().unwrap();
        l.set_current_round(Round(r));
        l.put_block(r, "v41", &seed_header([r as u8; 32]), b"blk")
            .unwrap();
        if r == 1 {
            l.put_online_account_at_round(&ADDR, 1, &online).unwrap();
        }
        l.commit_block().unwrap();
    }
    (dir, Arc::new(Mutex::new(l)))
}

/// Run `f` on this thread while another thread holds the ledger mutex (a
/// slow block apply), returning how long `f` took.
fn timed_while_ledger_locked(ledger: &Arc<Mutex<SqliteLedger>>, f: impl FnOnce()) -> Duration {
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = {
        let ledger = Arc::clone(ledger);
        std::thread::spawn(move || {
            let _g = ledger.lock().unwrap();
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(Duration::from_secs(20));
        })
    };
    locked_rx.recv().unwrap();
    let t = std::time::Instant::now();
    f();
    let elapsed = t.elapsed();
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    elapsed
}

#[test]
fn committed_reads_do_not_wait_for_a_held_ledger_mutex() {
    let (_dir, ledger) = file_bridge_ledger();
    // Built while the mutex is free, as at node start.
    let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
    let elapsed = timed_while_ledger_locked(&ledger, || {
        assert_eq!(bridge.seed(Round(2)).unwrap(), Seed::from([2u8; 32]));
        assert!(bridge.lookup_digest(Round(3)).is_ok());
        assert_eq!(
            bridge
                .lookup_agreement(Round(2), &ADDR)
                .unwrap()
                .micro_algos,
            42_000
        );
        assert_eq!(bridge.consensus_version(Round(2)).unwrap(), "v41");
        // Future round: deduced from the latest committed header.
        assert_eq!(bridge.consensus_version(Round(4)).unwrap(), "v41");
        assert!(matches!(
            bridge.seed(Round(9)),
            Err(LedgerError::RoundNotAvailable(_))
        ));
    });
    assert!(
        elapsed < Duration::from_secs(2),
        "agreement reads waited behind the held ledger mutex: {elapsed:?}"
    );
}

/// The lock-free answers equal what the locked accessors yield.
#[test]
fn lock_free_agreement_reads_equal_the_locked_accessors() {
    let (_dir, ledger) = file_bridge_ledger();
    let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
    let expected: Vec<_> = {
        let l = ledger.lock().unwrap();
        (1..=3u64)
            .map(|r| {
                let hdr = l.get_block_header_data(r).unwrap().unwrap();
                (
                    r,
                    hash_block_header(&hdr),
                    extract_seed_from_header(&hdr).unwrap(),
                    online_account_data(l.lookup_agreement_account(&ADDR, r).unwrap_or(None)),
                )
            })
            .collect()
    };
    for (r, digest, seed, oad) in expected {
        assert_eq!(bridge.lookup_digest(Round(r)).unwrap(), digest);
        assert_eq!(bridge.seed(Round(r)).unwrap(), seed);
        assert_eq!(
            bridge.lookup_agreement(Round(r), &ADDR).unwrap(),
            oad,
            "round {r}"
        );
    }
}

/// A round beyond the commit is refused exactly as the locked path does.
#[test]
fn lookup_agreement_beyond_the_committed_round_is_not_available() {
    let (_dir, ledger) = file_bridge_ledger();
    let bridge = AgreementLedgerBridge::new(ledger);
    assert!(matches!(
        bridge.lookup_agreement(Round(4), &ADDR),
        Err(LedgerError::RoundNotAvailable(Round(4)))
    ));
}

// ---------------------------------------------------------------------------
// Issue #1893: `circulation` and `get_cert_for_round` without the ledger mutex
// ---------------------------------------------------------------------------

fn encoded_cert(round: u64) -> (Certificate, Vec<u8>) {
    use algo_agreement::{Period, ProposalValue};
    let cert = Certificate {
        step: algo_agreement::CERT,
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
    };
    let bytes = algo_agreement::codec::encode_bundle(&cert.to_unauthenticated_bundle());
    (cert, bytes)
}

/// File-backed ledger with rounds 1..=4: round 2 carries a certificate,
/// headers carry rewards levels, accounts 1/2 are online (vote-last-valid 3 /
/// 50) so the expired-stake exclusion is exercised.
fn circulation_bridge_ledger() -> (tempfile::TempDir, Arc<Mutex<SqliteLedger>>) {
    let dir = tempfile::tempdir().unwrap();
    let mut l = SqliteLedger::open_with_prefix(&dir.path().join("ledger")).unwrap();
    l.set_protocol(algo_types::consensus::CONSENSUS_V41.to_string());
    l.put_account_totals_seed(9_000_000, 0, 0, 0, 0, 0).unwrap();
    let online = |micro_algos, vote_last_valid| AccountData {
        micro_algos,
        status: AccountStatus::Online,
        vote_id: Some([7u8; 32]),
        selection_id: Some([8u8; 32]),
        vote_last_valid,
        vote_key_dilution: 100,
        ..Default::default()
    };
    for r in 1..=4u64 {
        l.begin_block().unwrap();
        l.set_current_round(Round(r));
        l.put_block_header_fixture(r, r * 1_000).unwrap();
        if r == 1 {
            l.put_online_account_at_round(&Address([1; 32]), r, &online(5_000_000, 3))
                .unwrap();
            l.put_online_account_at_round(&Address([2; 32]), r, &online(2_000_000, 50))
                .unwrap();
        }
        if r == 2 {
            l.put_block_cert(2, &encoded_cert(2).1).unwrap();
        }
        l.commit_block().unwrap();
    }
    (dir, Arc::new(Mutex::new(l)))
}

#[test]
fn circulation_and_cert_do_not_wait_for_a_held_ledger_mutex() {
    let (_dir, ledger) = circulation_bridge_ledger();
    let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
    let (want_cert, _) = encoded_cert(2);
    let expected_circ = ledger
        .lock()
        .unwrap()
        .online_circulation_at_round(3, 4)
        .unwrap();
    assert_ne!(expected_circ, 9_000_000, "expired stake must be excluded");

    // After: the bridge answers from the pool.
    let lock_free = timed_while_ledger_locked(&ledger, || {
        assert_eq!(
            bridge.circulation(Round(3), Round(4)).unwrap(),
            expected_circ
        );
        let got = bridge.get_cert_for_round(Round(2)).unwrap();
        assert_eq!(got.round, want_cert.round);
        assert_eq!(got.period, want_cert.period);
        assert_eq!(got.proposal, want_cert.proposal);
        // A committed block without a certificate / an uncommitted round.
        assert!(bridge.get_cert_for_round(Round(3)).is_err());
        assert!(bridge.get_cert_for_round(Round(9)).is_err());
    });
    // The locked equivalents wait out the whole hold (see the pool-level
    // before/after numbers in `read_pool_tests`).
    println!("held-lock bridge circulation + get_cert_for_round (lock-free): {lock_free:?}");
    assert!(
        lock_free < Duration::from_secs(2),
        "circulation/get_cert_for_round waited behind the held ledger mutex: {lock_free:?}"
    );
}

/// The bridge answers (value and error variant) exactly as the locked
/// accessors do, for committed rounds, uncommitted rounds and vote rounds
/// either side of the key expiry.
#[test]
fn circulation_and_cert_equal_the_locked_accessors() {
    let (_dir, ledger) = circulation_bridge_ledger();
    let bridge = AgreementLedgerBridge::new(Arc::clone(&ledger));
    for round in 0..=5u64 {
        for vote in [0u64, 2, 3, 4, 49, 50, 51, 1_000] {
            let locked = ledger
                .lock()
                .unwrap()
                .online_circulation_at_round(round, vote);
            let got = bridge.circulation(Round(round), Round(vote));
            if round > 4 {
                assert!(
                    matches!(got, Err(LedgerError::RoundNotAvailable(Round(r))) if r == round),
                    "round {round}: {got:?}"
                );
            } else {
                assert_eq!(got.unwrap(), locked.unwrap(), "round {round} vote {vote}");
            }
        }
    }
    for round in 0..=5u64 {
        let locked = ledger.lock().unwrap().get_block_cert(round).unwrap();
        let got = bridge.get_cert_for_round(Round(round));
        match locked {
            Some(bytes) => {
                let want = Certificate::from_bundle(
                    &algo_agreement::codec::decode_bundle(&bytes).unwrap(),
                );
                let got = got.unwrap();
                assert_eq!((got.round, got.period), (want.round, want.period));
            }
            None => assert!(got.is_err(), "round {round}"),
        }
    }
}
