//! Integration tests for the per-transaction-group state-delta tracer (TASK-256).

use std::collections::HashSet;

use algo_ledger::{
    apply_block_capturing_group_deltas, apply_block_with_delta, LedgerState, TxnGroupDeltaTracer,
};
use algo_types::{Address, Block, Digest, Round, SignedTransaction};

fn make_state(balances: &[(Address, u64)], fee_sink: Address) -> LedgerState {
    let mut state = LedgerState::new();
    state.fee_sink = fee_sink;
    for (addr, bal) in balances {
        state.get_or_default_account(addr).micro_algos = *bal;
    }
    state
}

fn pay_txn(sender: Address, receiver: Address, amount: u64, group: [u8; 32]) -> SignedTransaction {
    let mut stx = SignedTransaction::default();
    stx.txn.txn_type = "pay".into();
    stx.txn.sender = sender;
    stx.txn.receiver = receiver;
    stx.txn.amount = amount;
    stx.txn.fee = 1000;
    stx.txn.last_valid = Round(1000);
    stx.txn.group = group;
    stx
}

fn minimal_block(fee_sink: Address, round: u64, payset: Vec<SignedTransaction>) -> Block {
    Block {
        round: Round(round),
        branch: [0u8; 32],
        seed: [0u8; 32],
        txn_commitment: [0u8; 32],
        timestamp: 0,
        genesis_id: String::new(),
        genesis_hash: [0u8; 32],
        proposer: Address::ZERO,
        fee_sink,
        rewards_pool: Address::ZERO,
        rewards_level: 0,
        rewards_rate: 0,
        rewards_residue: 0,
        rewards_recalculation_round: Round(0),
        current_protocol: algo_types::consensus::CONSENSUS_V41.to_string(),
        next_protocol: String::new(),
        next_protocol_approvals: 0,
        next_protocol_switch_on: Round(0),
        next_protocol_vote_before: Round(0),
        txn_counter: 0,
        fees_collected: 0,
        bonus: 0,
        proposer_payout: 0,
        prev512: [0u8; 64],
        txn256: [0u8; 32],
        txn512: [0u8; 64],
        state_proof_tracking: None,
        upgrade_propose: String::new(),
        upgrade_delay: 0,
        upgrade_approve: false,
        expired_participation_accounts: None,
        absent_participation_accounts: None,
        payset,
    }
}

/// Collect the set of addresses appearing in a delta's account records.
fn delta_addrs(delta: &algo_ledger::state_delta::StateDelta) -> HashSet<Address> {
    delta.accts.accts.iter().map(|r| r.addr).collect()
}

#[test]
fn captures_per_group_deltas_indexed_by_txn_and_group_id() {
    let a = Address([1u8; 32]);
    let b = Address([2u8; 32]);
    let c = Address([4u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let g1 = [0x77u8; 32]; // shared group hash for the atomic group

    let balances = [(a, 5_000_000), (b, 1_000_000), (c, 0), (fee_sink, 0)];

    // Block: an atomic group {a->b, b->c} followed by a standalone {a->c}.
    let payset = vec![
        pay_txn(a, b, 200_000, g1),
        pay_txn(b, c, 100_000, g1),
        pay_txn(a, c, 50_000, [0u8; 32]),
    ];

    let mut state = make_state(&balances, fee_sink);
    let block = minimal_block(fee_sink, 1, payset);

    let mut tracer = TxnGroupDeltaTracer::new(8);
    apply_block_capturing_group_deltas(&mut state, &block, &mut tracer).unwrap();

    // Two groups captured for round 1.
    let groups = tracer.get_deltas_for_round(1).expect("round 1 retained");
    assert_eq!(
        groups.len(),
        2,
        "expected one atomic group + one standalone"
    );

    // The atomic group is indexed by both txn IDs and the group ID; all resolve
    // to the same delta, which touches a, b, c (+ fee sink).
    let atomic = &groups[0];
    assert!(
        atomic.ids.contains(&Digest(g1)),
        "atomic group must be indexed by its group id"
    );
    assert_eq!(
        atomic.ids.len(),
        3,
        "two txn ids + one group id index the atomic group"
    );
    for id in &atomic.ids {
        let d = tracer.get_delta_for_id(id).expect("id resolves to a delta");
        assert_eq!(delta_addrs(d), delta_addrs(&atomic.delta));
    }
    let atomic_addrs = delta_addrs(&atomic.delta);
    assert!(atomic_addrs.contains(&a) && atomic_addrs.contains(&b) && atomic_addrs.contains(&c));

    // The standalone group has a single txn id and no group id.
    let standalone = &groups[1];
    assert_eq!(standalone.ids.len(), 1);
    assert!(!standalone.ids.contains(&Digest([0u8; 32])));

    // Unknown id resolves to nothing.
    assert!(tracer.get_delta_for_id(&Digest([0x99u8; 32])).is_none());
}

/// Blocks whose payset contains a transaction type the diff-based delta cannot
/// fully reconstruct (anything beyond pay/keyreg) are left unretained, so the
/// endpoints report the delta as unavailable rather than serving a partial one
/// (consistent with the per-round delta cache's completeness gate).
#[test]
fn incomplete_block_is_not_captured() {
    let creator = Address([1u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let balances = [(creator, 5_000_000), (fee_sink, 0)];

    // An asset-config create — not pay/keyreg, so the block is delta-incomplete.
    let mut acfg = SignedTransaction::default();
    acfg.txn.txn_type = "acfg".into();
    acfg.txn.sender = creator;
    acfg.txn.fee = 1000;
    acfg.txn.last_valid = Round(1000);
    acfg.txn.config_asset = 0; // create
    acfg.txn.asset_params = Some(algo_types::AssetParams {
        total: 1_000_000,
        ..Default::default()
    });

    let mut state = make_state(&balances, fee_sink);
    let block = minimal_block(fee_sink, 1, vec![acfg]);

    let mut tracer = TxnGroupDeltaTracer::new(8);
    apply_block_capturing_group_deltas(&mut state, &block, &mut tracer).unwrap();

    // The round is not retained → endpoints will report "unavailable".
    assert!(
        !tracer.has_round(1),
        "incomplete block must not be captured"
    );
    assert!(tracer.get_deltas_for_round(1).is_none());
}

#[test]
fn per_group_deltas_aggregate_to_round_delta() {
    let a = Address([1u8; 32]);
    let b = Address([2u8; 32]);
    let c = Address([4u8; 32]);
    let fee_sink = Address([3u8; 32]);
    let g1 = [0x77u8; 32];
    let balances = [(a, 5_000_000), (b, 1_000_000), (c, 0), (fee_sink, 0)];

    let payset = vec![
        pay_txn(a, b, 200_000, g1),
        pay_txn(b, c, 100_000, g1),
        pay_txn(a, c, 50_000, [0u8; 32]),
    ];

    // Per-group capture.
    let mut s1 = make_state(&balances, fee_sink);
    let block = minimal_block(fee_sink, 1, payset.clone());
    let mut tracer = TxnGroupDeltaTracer::new(8);
    apply_block_capturing_group_deltas(&mut s1, &block, &mut tracer).unwrap();

    let mut union: HashSet<Address> = HashSet::new();
    for g in tracer.get_deltas_for_round(1).unwrap() {
        union.extend(delta_addrs(&g.delta));
    }

    // Whole-round delta (independent apply).
    let mut s2 = make_state(&balances, fee_sink);
    let round_delta = apply_block_with_delta(&mut s2, &block).unwrap();
    let round_addrs: HashSet<Address> = round_delta.accts.accts.iter().map(|r| r.addr).collect();

    // The union of per-group account deltas reconstructs the round's changed
    // accounts.
    assert_eq!(
        union, round_addrs,
        "per-group account deltas must aggregate to the round delta's accounts"
    );
}
