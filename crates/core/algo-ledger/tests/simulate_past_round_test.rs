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

//! `simulate` at a past `Request.Round` from retained undo data (issue #2148).
//!
//! go serves any round back to its tracker `dbRound`, reading accounts and
//! `Totals` as of the requested round. A ledger with the undo journal on
//! (`LedgerStore::set_undo_window`) rewinds to the requested round for the
//! duration of the simulation and puts the latest state back afterwards.

use algo_ledger::apply::pool_fixtures::TEST_GENESIS_HASH;
use algo_ledger::simulation::{SimulationRequest, Simulator, SimulatorError};
use algo_ledger::sqlite::SqliteLedger;
use algo_ledger::LedgerStore;
use algo_types::{AccountData, AccountStatus, Address, Round, SignedTransaction, Transaction};

const SENDER: Address = Address([0xAA; 32]);
const RECEIVER: Address = Address([0xBB; 32]);
const POOL: Address = Address([0xEE; 32]);
const FEE_SINK: Address = Address([0xFE; 32]);

fn header(round: u64, level: u64, recalc: u64) -> algo_types::BlockHeader {
    algo_types::BlockHeader {
        round: Round(round),
        current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
        genesis_hash: TEST_GENESIS_HASH,
        rewards_pool: POOL,
        fee_sink: FEE_SINK,
        rewards_level: level,
        rewards_rate: 250,
        rewards_recalculation_round: Round(recalc),
        ..Default::default()
    }
}

fn sender_with(micro_algos: u64, rewards_base: u64) -> AccountData {
    AccountData {
        status: AccountStatus::Offline,
        micro_algos,
        rewards_base,
        ..Default::default()
    }
}

/// A ledger of three rounds, each its own commit span: the sender holds
/// 50 Algo at rounds 1 and 2 and 100 000 µAlgo (below the 200 000 payment
/// the tests simulate) from round 3 on. Rewards level 10 / 20 / 30.
fn ledger_with_history(window: u64, recalc_at: [u64; 3]) -> SqliteLedger {
    let mut l = SqliteLedger::open_in_memory().expect("in-memory ledger");
    l.set_protocol(algo_types::consensus::CONSENSUS_V41.to_string());
    l.set_genesis_hash(TEST_GENESIS_HASH);
    l.set_fee_sink(FEE_SINK);
    l.set_rewards_pool(POOL);
    l.set_account(
        &POOL,
        AccountData {
            status: AccountStatus::NotParticipating,
            micro_algos: 10_000_000_000_000,
            ..Default::default()
        },
    );
    l.set_account(&FEE_SINK, AccountData::default());
    l.set_account(&SENDER, sender_with(50_000_000, 10));
    // Reward units: the sender's 50 (the pool and fee sink do not take part).
    l.put_account_totals_seed(0, 0, 50_000_000, 50, 10_000_000_000_000, 10_000_000)
        .expect("seed totals");
    l.set_undo_window(window);
    for (i, level) in [10u64, 20, 30].into_iter().enumerate() {
        let round = i as u64 + 1;
        l.begin_block().expect("begin");
        if round == 3 {
            // the round-3 block spends nearly everything the sender has
            l.set_account(&SENDER, sender_with(100_000, 30));
        }
        let hdr = header(round, level, recalc_at[i]);
        let bytes = algo_codec::canonical_encode_block_header(&hdr);
        l.put_block(round, &hdr.current_protocol, &bytes, &[])
            .expect("put_block");
        l.set_rewards_level(level);
        l.set_rewards_rate(250);
        l.set_rewards_recalculation_round(recalc_at[i]);
        l.set_current_round(Round(round));
        l.commit_block().expect("commit");
    }
    l
}

fn pay() -> Vec<SignedTransaction> {
    vec![SignedTransaction {
        txn: Transaction {
            txn_type: "pay".into(),
            sender: SENDER,
            receiver: RECEIVER,
            amount: 200_000,
            fee: 1000,
            first_valid: 1.into(),
            last_valid: 1000.into(),
            genesis_hash: TEST_GENESIS_HASH,
            ..Default::default()
        },
        ..Default::default()
    }]
}

fn simulate_at(l: &mut SqliteLedger, round: u64) -> Result<String, SimulatorError> {
    let result = Simulator::new(l).simulate(SimulationRequest {
        txn_groups: vec![pay()],
        allow_empty_signatures: true,
        round: Some(Round(round)),
        ..Default::default()
    })?;
    Ok(result.txn_groups[0]
        .failure_message
        .clone()
        .unwrap_or_default())
}

/// The sender changed after round 2: simulating at round 2 sees the balance
/// of round 2 (the payment succeeds), at round 3 the balance of round 3 (it
/// insufficient balances), and the latest state is put back each time.
#[test]
fn a_past_round_is_simulated_on_the_state_of_that_round() {
    let mut l = ledger_with_history(100, [500_000; 3]);
    let sender_now = l.get_account(&SENDER);
    assert_eq!(sender_now.as_ref().unwrap().micro_algos, 100_000);

    assert_eq!(simulate_at(&mut l, 2).expect("round 2 is served"), "");
    assert_eq!(l.get_account(&SENDER), sender_now, "latest state restored");
    assert_eq!(simulate_at(&mut l, 1).expect("round 1 is served"), "");
    assert_eq!(l.get_account(&SENDER), sender_now, "latest state restored");

    let at_latest = simulate_at(&mut l, 3).expect("the latest round is served");
    assert!(at_latest.contains("insufficient balance"), "{at_latest}");
    assert_eq!(l.get_account(&SENDER), sender_now);
    assert_eq!(l.current_round(), Round(3));
    assert_eq!(l.rewards_level(), 30, "the rewards state is restored");
}

/// The retained window is the earliest servable round; older ones fail with
/// go's `RoundOffsetError` text, and a ledger that retains nothing serves
/// only its latest round.
#[test]
fn rounds_older_than_the_window_fail_with_go_s_text() {
    // Two rounds of undo data: round 3 and round 2 are retained, so the
    // earliest `start` is 1.
    let mut l = ledger_with_history(2, [500_000; 3]);
    assert_eq!(simulate_at(&mut l, 1).expect("round 1 is served"), "");
    let err = simulate_at(&mut l, 0).expect_err("round 0 is before the window");
    assert!(
        err.to_string().contains("round 0 before dbRound 1"),
        "{err}"
    );

    // Nothing retained: only the latest round.
    let mut l = ledger_with_history(0, [500_000; 3]);
    let err = simulate_at(&mut l, 2).expect_err("no undo data");
    assert!(
        err.to_string().contains("round 2 before dbRound 3"),
        "{err}"
    );
    assert!(simulate_at(&mut l, 3)
        .expect("latest")
        .contains("insufficient balance"));
}

/// Issue #2123 (second comment): `start + 1` is the historical header's rewards
/// recalculation round but not the latest's. The block simulated at round 2
/// is round 3; round 2's header says round 3 recalculates the rate from the
/// pool, which the latest state's rewards fields (recalculation round
/// 500 000) would skip. The rewards state of the simulated block comes whole
/// from the header of `start`.
#[test]
fn the_rewards_state_comes_from_the_header_of_the_past_round() {
    let sender_rewards = |recalc_at: [u64; 3]| {
        let mut l = ledger_with_history(100, recalc_at);
        let result = Simulator::new(&mut l)
            .simulate(SimulationRequest {
                txn_groups: vec![pay()],
                allow_empty_signatures: true,
                round: Some(Round(2)),
                ..Default::default()
            })
            .expect("round 2 is served");
        let g = &result.txn_groups[0];
        assert_eq!(g.failure_message, None);
        g.txn_results[0].apply_data.as_ref().unwrap().sender_rewards
    };
    // The latest state says recalculate at 500 000 in both; only round 2's
    // header differs.
    let plain = sender_rewards([500_000, 500_000, 500_000]);
    let recalculating = sender_rewards([500_000, 3, 500_000]);
    assert_eq!(
        plain,
        50 * (20 + 250 / 50 - 10),
        "level 20 from the header advanced by rate / units, base 10, 50 units"
    );
    assert_ne!(
        recalculating, plain,
        "the rate is refreshed from the pool as of round 2"
    );
}

fn rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        return status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            .map_or(0, |kb| kb * 1024);
    }
    #[cfg(windows)]
    {
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("(Get-Process -Id {}).WorkingSet64", std::process::id()),
            ])
            .output()
            .expect("powershell");
        return String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(0);
    }
    #[allow(unreachable_code)]
    0
}

fn key(i: u32) -> Address {
    let mut a = [0u8; 32];
    a[..4].copy_from_slice(&i.to_be_bytes());
    Address(a)
}

/// Memory and lock cost of the undo journal (issue #2148):
/// `cargo test -p algo-ledger --release --test simulate_past_round_test -- --ignored --nocapture`.
///
/// `TOUCHED` accounts are written per round (a busy mainnet round touches
/// 1 000 - 5 000), for 400 rounds, each in its own commit span, on a ledger of
/// 20 000 plain accounts. Prints, per setting, the journal's own estimate of
/// its retained bytes and rounds and the RSS delta over the same run without a
/// journal, then the time a rewind to the earliest servable round (writes every
/// touched key, twice) holds the ledger for.
#[test]
#[ignore = "benchmark: prints measurements"]
fn undo_journal_memory_and_rewind_cost() {
    fn run(
        touched: u32,
        window: u64,
        budget: usize,
    ) -> (
        u64,
        (usize, usize),
        std::time::Duration,
        std::time::Duration,
        std::time::Duration,
    ) {
        let mut l = SqliteLedger::open_in_memory().expect("ledger");
        l.set_protocol(algo_types::consensus::CONSENSUS_V41.to_string());
        l.set_genesis_hash(TEST_GENESIS_HASH);
        l.set_fee_sink(FEE_SINK);
        l.set_rewards_pool(POOL);
        for i in 0..20_000u32 {
            l.set_account(&key(i), sender_with(10_000_000, 0));
        }
        l.set_account(&SENDER, sender_with(50_000_000, 0));
        l.set_account(&POOL, sender_with(1_000_000_000_000, 0));
        l.set_account(&FEE_SINK, sender_with(1_000_000, 0));
        l.set_undo_window(window);
        l.set_undo_budget_bytes(budget);
        let rss0 = rss_bytes();
        let apply = std::time::Instant::now();
        for round in 1..=400u64 {
            l.begin_block().expect("begin");
            for k in 0..touched {
                let i = ((round as u32).wrapping_mul(7919) + k * 3) % 20_000;
                // apply reads an account before it writes it back
                let _ = l.get_account(&key(i));
                l.set_account(&key(i), sender_with(10_000_000 + round, round));
            }
            let hdr = header(round, round, 500_000);
            let bytes = algo_codec::canonical_encode_block_header(&hdr);
            l.put_block(round, &hdr.current_protocol, &bytes, &[])
                .expect("put_block");
            l.set_current_round(Round(round));
            l.commit_block().expect("commit");
        }
        let apply = apply.elapsed();
        let rss = rss_bytes().saturating_sub(rss0);
        let retained = l.undo_retained();
        let (mut rewind_near, mut rewind_far) =
            (std::time::Duration::ZERO, std::time::Duration::ZERO);
        if window > 0 {
            let earliest = l.earliest_simulate_round();
            let t = std::time::Instant::now();
            simulate_at(&mut l, 399).expect("latest - 1");
            rewind_near = t.elapsed();
            let t = std::time::Instant::now();
            simulate_at(&mut l, earliest.0).expect("earliest");
            rewind_far = t.elapsed();
        }
        (rss, retained, apply, rewind_near, rewind_far)
    }
    for touched in [500u32, 2000] {
        for (name, window, budget) in [
            ("off", 0u64, 0usize),
            ("320 rounds, no budget", 320, usize::MAX),
            (
                "320 rounds, 16 MiB budget",
                320,
                algo_ledger::undo_journal::DEFAULT_UNDO_BUDGET_BYTES,
            ),
        ] {
            let runs: Vec<_> = (0..3).map(|_| run(touched, window, budget)).collect();
            let mut rss: Vec<u64> = runs.iter().map(|r| r.0).collect();
            rss.sort();
            let mut apply: Vec<_> = runs.iter().map(|r| r.2).collect();
            apply.sort();
            let mut far: Vec<_> = runs.iter().map(|r| r.4).collect();
            far.sort();
            let mut near: Vec<_> = runs.iter().map(|r| r.3).collect();
            near.sort();
            println!(
                "touched {touched:>4}/round, {name:<26}: rss delta median {:>7.1} MiB (runs {:?}), journal est {:>6.1} MiB / {} rounds, apply median {:?}, rewind to latest-1 {:?}, to earliest {:?}",
                rss[1] as f64 / 1048576.0,
                rss.iter().map(|b| (*b as f64 / 1048576.0).round()).collect::<Vec<_>>(),
                runs[0].1 .0 as f64 / 1048576.0,
                runs[0].1 .1,
                apply[1],
                near[1],
                far[1],
            );
        }
    }
}
