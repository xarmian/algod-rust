//! Construction of the next block's header — the Rust analogue of
//! go-algorand's `bookkeeping.MakeBlock(prev)` (`data/bookkeeping/block.go`).
//!
//! A fresh block evaluator starts from the *next* round's header skeleton:
//! `round = prev.round + 1`, `branch = prev.Hash()`, an advanced rewards state,
//! a clamped timestamp, and carried-over upgrade/genesis/special-address fields.
//! The seed, proposer, payset and txn commitments are filled later (the seed and
//! proposer by the producer/agreement, the payset and commitments by the
//! evaluator when it assembles transactions).
//!
//! Scope vs go: algod-rust never *proposes* protocol upgrades and `ConsensusParams`
//! does not model the upgrade-vote params (`UpgradeThreshold`, `UpgradeVoteRounds`,
//! `ApprovedUpgrades`, wait-rounds). So the upgrade machinery here ports only the
//! parameter-free, faithful parts: the protocol switch-over at `NextProtocolSwitchOn`
//! and carry-forward of the upgrade state. A pending proposal reaching its vote
//! deadline (which would need the threshold to decide) is rejected rather than
//! guessed — block production in algod-rust only happens on dev/localnet and
//! single-node agreement, where no upgrade is ever in flight.

use algo_codec::{compute_block_header_digest, compute_block_header_digest_512};
use algo_error::AlgoError;
use algo_types::consensus::consensus_params_for_version;
use algo_types::{Address, BlockHeader, ConsensusParams, Round};

use crate::rewards::RewardsState;

/// The upgrade-state fields carried on a block header, resolved for the next
/// round. Mirrors the subset of go's `UpgradeState` we advance.
struct NextUpgradeState {
    current_protocol: String,
    next_protocol: String,
    next_protocol_approvals: u64,
    next_protocol_vote_before: Round,
    next_protocol_switch_on: Round,
}

/// Advance the upgrade state from `prev` to its next round.
///
/// algod-rust casts no upgrade vote, so this only carries the prior state
/// forward and applies the parameter-free protocol switch-over at
/// `NextProtocolSwitchOn` (go `applyUpgradeVote`, the switch branch). A pending
/// proposal at its `NextProtocolVoteBefore` deadline cannot be resolved without
/// `UpgradeThreshold` (unmodeled) and is rejected.
fn next_upgrade_state(prev: &BlockHeader, next_round: u64) -> Result<NextUpgradeState, AlgoError> {
    // No pending proposal: carry the (empty) upgrade state forward.
    if prev.next_protocol.is_empty() {
        return Ok(NextUpgradeState {
            current_protocol: prev.current_protocol.clone(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_vote_before: Round(0),
            next_protocol_switch_on: Round(0),
        });
    }

    // A proposal is in flight. Switch over once we reach the switch-on round.
    if next_round == prev.next_protocol_switch_on.0 {
        return Ok(NextUpgradeState {
            current_protocol: prev.next_protocol.clone(),
            next_protocol: String::new(),
            next_protocol_approvals: 0,
            next_protocol_vote_before: Round(0),
            next_protocol_switch_on: Round(0),
        });
    }

    // Resolving the vote at its deadline (go's "clear failed proposal" branch)
    // needs UpgradeThreshold, which ConsensusParams does not model. algod-rust
    // does not produce blocks across an upgrade, so reject rather than guess.
    if next_round == prev.next_protocol_vote_before.0 {
        return Err(AlgoError::Ledger {
            message: format!(
                "make_next_block_header: cannot resolve in-flight protocol upgrade vote at \
                 round {next_round} (NextProtocolVoteBefore) — upgrade-vote params are not modeled"
            ),
        });
    }

    // Otherwise carry the pending proposal forward unchanged.
    Ok(NextUpgradeState {
        current_protocol: prev.current_protocol.clone(),
        next_protocol: prev.next_protocol.clone(),
        next_protocol_approvals: prev.next_protocol_approvals,
        next_protocol_vote_before: prev.next_protocol_vote_before,
        next_protocol_switch_on: prev.next_protocol_switch_on,
    })
}

/// Clamp `timestamp` to go's `MakeBlock` rule: never earlier than the previous
/// block, never more than `MaxTimestampIncrement` ahead of it. A non-positive
/// previous timestamp (genesis) imposes no clamp.
fn clamp_timestamp(timestamp: i64, prev_timestamp: i64, params: &ConsensusParams) -> i64 {
    if prev_timestamp <= 0 {
        return timestamp;
    }
    if timestamp < prev_timestamp {
        prev_timestamp
    } else if timestamp > prev_timestamp + params.max_timestamp_increment {
        prev_timestamp + params.max_timestamp_increment
    } else {
        timestamp
    }
}

/// Build the next block's header skeleton from the previous header, mirroring
/// go-algorand's `bookkeeping.MakeBlock(prev)` combined with the evaluator's
/// rewards advance.
///
/// - `round = prev.round + 1`; `branch = prev.Hash()` ([`compute_block_header_digest`]);
///   `prev512 = prev.Hash512()` when `enable_sha512_block_hash` (v41+).
/// - `timestamp` is the proposer's wall-clock time, clamped per [`clamp_timestamp`].
/// - `rewards` is the advanced [`RewardsState`] the caller computed via
///   `next_rewards_state` from ledger reads (mirroring go's evaluator).
/// - genesis id/hash, fee sink, rewards pool, and bonus are carried from `prev`.
/// - `txn_counter` carries `prev`'s value; the evaluator adds the assembled
///   transaction count when it fills the payset.
/// - seed, proposer, payset, and txn commitments are left zero/empty for later
///   stages to fill.
///
/// The protocol governing the new block (and hence the params used for the
/// timestamp clamp and the 512-hash gate) is the resolved protocol *after* any
/// switch-over — matching go, which looks up params for `upgradeState.CurrentProtocol`.
///
/// `bonus` is carried forward unchanged: `ConsensusParams` does not model the
/// `BonusPlan` (base-amount onset / decay), so the onset/decay transitions are
/// not applied — consistent with the modern-protocol simplifications documented
/// on `make_genesis_block`. For a fresh localnet (genesis bonus 0) this is exact.
///
/// Returns an error if the resolved protocol is unknown or an in-flight upgrade
/// vote would need the unmodeled `UpgradeThreshold` to resolve (see
/// [`next_upgrade_state`]).
pub fn make_next_block_header(
    prev: &BlockHeader,
    timestamp: i64,
    rewards: RewardsState,
) -> Result<BlockHeader, AlgoError> {
    let next_round = prev.round.0 + 1;
    let upgrade = next_upgrade_state(prev, next_round)?;

    // Params for the protocol the new block runs under (post switch-over),
    // matching go's `config.Consensus[upgradeState.CurrentProtocol]`.
    let params = consensus_params_for_version(&upgrade.current_protocol).ok_or_else(|| {
        AlgoError::Ledger {
            message: format!(
                "make_next_block_header: unknown protocol '{}'",
                upgrade.current_protocol
            ),
        }
    })?;

    let branch = compute_block_header_digest(prev).0;
    let prev512 = if params.enable_sha512_block_hash {
        compute_block_header_digest_512(prev)
    } else {
        [0u8; 64]
    };

    Ok(BlockHeader {
        round: Round(next_round),
        branch,
        prev512,
        // Filled later by the producer/agreement (seed) and finish step (proposer).
        seed: [0u8; 32],
        proposer: Address::ZERO,
        timestamp: clamp_timestamp(timestamp, prev.timestamp, &params),
        // Special addresses and genesis identity carry over unchanged.
        genesis_id: prev.genesis_id.clone(),
        genesis_hash: prev.genesis_hash,
        fee_sink: prev.fee_sink,
        rewards_pool: prev.rewards_pool,
        // Advanced rewards state (computed by the caller from ledger reads).
        rewards_level: rewards.rewards_level,
        rewards_rate: rewards.rewards_rate,
        rewards_residue: rewards.rewards_residue,
        rewards_recalculation_round: Round(rewards.rewards_recalculation_round),
        // Resolved upgrade state; no vote is cast.
        current_protocol: upgrade.current_protocol,
        next_protocol: upgrade.next_protocol,
        next_protocol_approvals: upgrade.next_protocol_approvals,
        next_protocol_vote_before: upgrade.next_protocol_vote_before,
        next_protocol_switch_on: upgrade.next_protocol_switch_on,
        upgrade_propose: String::new(),
        upgrade_delay: 0,
        upgrade_approve: false,
        // Bonus carried forward (BonusPlan onset/decay not modeled — see above).
        bonus: prev.bonus,
        // The evaluator adds the assembled transaction count.
        txn_counter: prev.txn_counter,
        // State-proof tracking carries forward (algod-rust produces no state proofs).
        state_proof_tracking: prev.state_proof_tracking.clone(),
        // Filled by the evaluator when it assembles the payset.
        txn_commitment: [0u8; 32],
        txn256: [0u8; 32],
        txn512: [0u8; 64],
        fees_collected: 0,
        proposer_payout: 0,
        expired_participation_accounts: None,
        absent_participation_accounts: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::CONSENSUS_V41;

    fn v41_params() -> ConsensusParams {
        consensus_params_for_version(CONSENSUS_V41).expect("v41 params")
    }

    fn prev_header() -> BlockHeader {
        BlockHeader {
            round: Round(5),
            seed: [7u8; 32],
            timestamp: 1000,
            genesis_id: "net-x".to_string(),
            genesis_hash: [9u8; 32],
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            rewards_level: 11,
            current_protocol: CONSENSUS_V41.to_string(),
            txn_counter: 42,
            bonus: 1234,
            txn_commitment: [3u8; 32],
            ..BlockHeader::default()
        }
    }

    fn rewards() -> RewardsState {
        RewardsState {
            rewards_level: 100,
            rewards_rate: 200,
            rewards_residue: 7,
            rewards_recalculation_round: 500,
        }
    }

    #[test]
    fn advances_round_branch_and_carries_fields() {
        let prev = prev_header();
        let hdr = make_next_block_header(&prev, 1500, rewards()).expect("make header");

        assert_eq!(hdr.round, Round(6), "round = prev + 1");
        assert_eq!(
            hdr.branch,
            compute_block_header_digest(&prev).0,
            "branch = prev.Hash()",
        );
        // Rewards injected from the advanced state.
        assert_eq!(hdr.rewards_level, 100);
        assert_eq!(hdr.rewards_rate, 200);
        assert_eq!(hdr.rewards_residue, 7);
        assert_eq!(hdr.rewards_recalculation_round, Round(500));
        // Carried over.
        assert_eq!(hdr.genesis_id, "net-x");
        assert_eq!(hdr.genesis_hash, [9u8; 32]);
        assert_eq!(hdr.fee_sink, Address([1u8; 32]));
        assert_eq!(hdr.rewards_pool, Address([2u8; 32]));
        assert_eq!(hdr.bonus, 1234, "bonus carried forward");
        assert_eq!(hdr.txn_counter, 42, "txn_counter carried (evaluator adds)");
        assert_eq!(hdr.current_protocol, CONSENSUS_V41);
        // Left for later stages.
        assert_eq!(hdr.seed, [0u8; 32], "seed unset");
        assert_eq!(hdr.proposer, Address::ZERO, "proposer unset");
        assert_eq!(hdr.txn_commitment, [0u8; 32], "commitment unset");
        assert_eq!(hdr.fees_collected, 0);
    }

    #[test]
    fn sets_prev512_under_sha512_block_hash() {
        // v41 enables the SHA-512 block hash → prev512 = prev.Hash512().
        assert!(v41_params().enable_sha512_block_hash);
        let prev = prev_header();
        let hdr = make_next_block_header(&prev, 1500, rewards()).expect("make header");
        assert_eq!(hdr.prev512, compute_block_header_digest_512(&prev));
        assert_ne!(hdr.prev512, [0u8; 64], "prev512 must be set under v41");
    }

    #[test]
    fn clamps_timestamp() {
        let params = v41_params();
        let inc = params.max_timestamp_increment;
        let prev = prev_header(); // prev.timestamp = 1000

        // Too early → clamped up to prev.
        let early = make_next_block_header(&prev, 500, rewards()).unwrap();
        assert_eq!(early.timestamp, 1000);
        // Too late → clamped to prev + max increment.
        let late = make_next_block_header(&prev, 1000 + inc + 10_000, rewards()).unwrap();
        assert_eq!(late.timestamp, 1000 + inc);
        // Within range → unchanged.
        let ok = make_next_block_header(&prev, 1000 + inc - 1, rewards()).unwrap();
        assert_eq!(ok.timestamp, 1000 + inc - 1);
    }

    #[test]
    fn genesis_timestamp_imposes_no_clamp() {
        let prev = BlockHeader {
            timestamp: 0,
            ..prev_header()
        };
        let hdr = make_next_block_header(&prev, 42, rewards()).unwrap();
        assert_eq!(hdr.timestamp, 42, "no clamp when prev timestamp <= 0");
    }

    #[test]
    fn no_pending_upgrade_carries_empty_state() {
        let hdr = make_next_block_header(&prev_header(), 1500, rewards()).unwrap();
        assert!(hdr.next_protocol.is_empty());
        assert_eq!(hdr.next_protocol_approvals, 0);
        assert_eq!(hdr.next_protocol_vote_before, Round(0));
        assert_eq!(hdr.next_protocol_switch_on, Round(0));
        assert!(hdr.upgrade_propose.is_empty());
        assert!(!hdr.upgrade_approve);
    }

    #[test]
    fn switches_protocol_at_switch_on_round() {
        // Pending proposal to switch to v41 at round 6 (= next round). The new
        // block runs the switched-to protocol and clears the pending state.
        let prev = BlockHeader {
            round: Round(5),
            current_protocol: "some-older-proto".to_string(),
            next_protocol: CONSENSUS_V41.to_string(),
            next_protocol_approvals: 3,
            next_protocol_vote_before: Round(4),
            next_protocol_switch_on: Round(6),
            ..BlockHeader::default()
        };
        let hdr = make_next_block_header(&prev, 0, rewards()).expect("switch ok");
        assert_eq!(
            hdr.current_protocol, CONSENSUS_V41,
            "switched to next protocol"
        );
        assert!(hdr.next_protocol.is_empty(), "pending proposal cleared");
        assert_eq!(hdr.next_protocol_switch_on, Round(0));
    }

    #[test]
    fn carries_pending_proposal_before_decision() {
        // Pending proposal, but this round is neither the vote deadline nor the
        // switch-on round → carry it forward unchanged.
        let prev = BlockHeader {
            round: Round(5),
            current_protocol: CONSENSUS_V41.to_string(),
            next_protocol: CONSENSUS_V41.to_string(),
            next_protocol_approvals: 2,
            next_protocol_vote_before: Round(100),
            next_protocol_switch_on: Round(200),
            ..BlockHeader::default()
        };
        let hdr = make_next_block_header(&prev, 0, rewards()).unwrap();
        assert_eq!(hdr.next_protocol, CONSENSUS_V41);
        assert_eq!(hdr.next_protocol_approvals, 2);
        assert_eq!(hdr.next_protocol_vote_before, Round(100));
        assert_eq!(hdr.next_protocol_switch_on, Round(200));
    }

    #[test]
    fn rejects_unresolvable_upgrade_vote_deadline() {
        // Pending proposal reaching its vote deadline needs UpgradeThreshold
        // (unmodeled) → error rather than guess.
        let prev = BlockHeader {
            round: Round(5),
            current_protocol: CONSENSUS_V41.to_string(),
            next_protocol: CONSENSUS_V41.to_string(),
            next_protocol_vote_before: Round(6),
            next_protocol_switch_on: Round(20),
            ..BlockHeader::default()
        };
        assert!(make_next_block_header(&prev, 0, rewards()).is_err());
    }

    #[test]
    fn rejects_unknown_protocol() {
        let prev = BlockHeader {
            round: Round(5),
            current_protocol: "no-such-protocol".to_string(),
            ..BlockHeader::default()
        };
        assert!(make_next_block_header(&prev, 0, rewards()).is_err());
    }
}
