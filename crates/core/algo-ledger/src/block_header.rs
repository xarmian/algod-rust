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

/// Compute the proposer bonus ("bi") for the round after `prev`.
///
/// Direct port of go-algorand `data/bookkeeping/block.go`'s `NextBonus` /
/// `computeBonus` (v4.6.0-stable, lines 579–604), driven by the `BonusPlan`
/// consensus params (`config/consensus.go`, `BonusPlan` at line 653, values set
/// for v40 at lines 1422–1424):
///
/// ```text
/// if curPlan.BaseAmount != 0 {
///     upgrading := curPlan != prevPlan || current == 1
///     if current == curPlan.BaseRound || (upgrading && current > curPlan.BaseRound) {
///         return curPlan.BaseAmount
///     }
/// }
/// if curPlan.DecayInterval != 0 && current%curPlan.DecayInterval == 0 {
///     return NewPercent(99).DivvyAlgos(prevBonus)   // floor(prev * 99 / 100)
/// }
/// return prevBonus
/// ```
///
/// `params` are the params for the round being built (post upgrade switch-over)
/// and `prev_params` those of `prev.current_protocol` — matching go's
/// `NextBonus`, which looks up `config.Consensus[prev.CurrentProtocol]`.
pub fn next_bonus(
    prev: &BlockHeader,
    params: &ConsensusParams,
    prev_params: &ConsensusParams,
) -> u64 {
    let current = prev.round.0.saturating_add(1);
    compute_bonus(
        current,
        prev.bonus,
        (
            params.bonus_base_round,
            params.bonus_base_amount,
            params.bonus_decay_interval,
        ),
        (
            prev_params.bonus_base_round,
            prev_params.bonus_base_amount,
            prev_params.bonus_decay_interval,
        ),
    )
}

/// Guts of [`next_bonus`], taking the two `BonusPlan`s as
/// `(base_round, base_amount, decay_interval)` tuples so it can be unit tested
/// directly (go's `computeBonus`).
fn compute_bonus(
    current: u64,
    prev_bonus: u64,
    cur_plan: (u64, u64, u64),
    prev_plan: (u64, u64, u64),
) -> u64 {
    let (base_round, base_amount, decay_interval) = cur_plan;

    // Set the amount if it's non-zero...
    if base_amount != 0 {
        let upgrading = cur_plan != prev_plan || current == 1;
        // The time has come if the baseRound arrives, or at upgrade time if
        // baseRound has already passed.
        if current == base_round || (upgrading && current > base_round) {
            return base_amount;
        }
    }

    if decay_interval != 0 && current % decay_interval == 0 {
        // Decay by 1%: go's `basics.NewPercent(99).DivvyAlgos(prevBonus)`,
        // i.e. floor(prevBonus * 99 / 100) (`data/basics/fraction.go`).
        return ((prev_bonus as u128 * 99) / 100) as u64;
    }

    prev_bonus
}

/// Fixed-point scale for `basics.Micros` — 6 digits of precision, so `1e6`
/// represents "1.0" (a completely full block, or a 100% congestion tax).
const MICROS_UNIT: u128 = 1_000_000;

/// Compute the `"ld"` (Load) header field for the round that just finished
/// assembling `block_size` bytes of transactions, out of `max_size` allowed.
///
/// Direct port of go-algorand `ledger/eval/eval.go`'s `ComputeLoad`
/// (v4.7.0-beta, PR #6548): `Load` is a fixed-point fraction with 6 digits of
/// precision (1,000,000 = completely full). `max_size == 0` can't happen for a
/// real consensus version, but is handled the same way go's overflow branch
/// is: "fully loaded" rather than a divide-by-zero panic.
pub fn compute_load(block_size: u64, max_size: u64) -> u64 {
    if max_size == 0 {
        return MICROS_UNIT as u64;
    }
    let load = (MICROS_UNIT * block_size as u128) / max_size as u128;
    load.min(MICROS_UNIT) as u64
}

/// Compute the `"ct"` (CongestionTax) header field for the round after one
/// that had `prev_load` fullness and `prev_tax` congestion tax.
///
/// Direct port of go-algorand `data/bookkeeping/block.go`'s
/// `NextCongestionTax` (v4.7.0-beta, PR #6548). Called unconditionally (like
/// go's `MakeBlock`/`PreCheck`) regardless of whether `LoadTracking` is on for
/// the round being built — `prev_load` is 0 whenever tracking wasn't active
/// for the previous round, which naturally decays any inherited tax back to 0
/// (or tapers it, if a downgrade left a nonzero tax behind; see the
/// `congestion_tracking_downgrade` test in go's `block_test.go`).
///
/// A block that is exactly half full (`prev_load == 500_000`) is the
/// equilibrium point — the tax carries forward unchanged. Below that, the tax
/// decreases (by up to 10% for a fully empty block); above it, the tax
/// increases (by up to 10% for a fully-loaded block). Arithmetic saturates at
/// `u64::MAX` rather than overflowing, matching go's `Micros.Mul`/
/// `basics.AddSaturate`/`basics.SubSaturate`.
pub fn next_congestion_tax(prev_load: u64, prev_tax: u64) -> u64 {
    const PER_BLOCK_MAX_CHANGE: u128 = 100_000; // 10%
    const HALF: u128 = 500_000; // 50%

    let prev_load = prev_load as u128;
    let prev_tax = prev_tax as u128;

    if prev_load <= HALF {
        // Decrease (or hold, at exactly half load).
        let down_factor = PER_BLOCK_MAX_CHANGE * (HALF - prev_load) / HALF;
        // down_factor <= PER_BLOCK_MAX_CHANGE < MICROS_UNIT, so this never
        // underflows.
        let tax_decrease = saturating_mul_micros(prev_tax, MICROS_UNIT - down_factor);
        tax_decrease
            .saturating_sub(down_factor)
            .min(u64::MAX as u128) as u64
    } else {
        // Increase.
        let up_factor = PER_BLOCK_MAX_CHANGE * (prev_load - HALF) / HALF;
        let tax_increase = saturating_mul_micros(prev_tax, MICROS_UNIT + up_factor);
        tax_increase.saturating_add(up_factor).min(u64::MAX as u128) as u64
    }
}

/// go `basics.Micros.Mul`: `a * b / 1e6`, saturating at `u64::MAX` on
/// overflow rather than wrapping.
fn saturating_mul_micros(a: u128, b: u128) -> u128 {
    let product = a.saturating_mul(b) / MICROS_UNIT;
    product.min(u64::MAX as u128)
}

/// Read `StateProofTracking[StateProofBasic].StateProofNextRound` (the `"n"`
/// field under map key `0`) out of an encoded `"spt"` value, defaulting to 0
/// when absent — mirroring go's zero-value map lookup at
/// `ledger/eval/eval.go:770`.
pub(crate) fn state_proof_next_round(tracking: &Option<rmpv::Value>) -> u64 {
    let Some(rmpv::Value::Map(types)) = tracking.as_ref() else {
        return 0;
    };
    let basic = types
        .iter()
        .find(|(k, _)| k.as_u64() == Some(STATE_PROOF_BASIC))
        .map(|(_, v)| v);
    let Some(rmpv::Value::Map(fields)) = basic else {
        return 0;
    };
    fields
        .iter()
        .find(|(k, _)| k.as_str() == Some("n"))
        .and_then(|(_, v)| v.as_u64())
        .unwrap_or(0)
}

/// Read `StateProofTracking[StateProofBasic].VotersCommitment` (the `"v"`
/// field under map key `0`) out of an encoded `"spt"` value, defaulting to
/// empty when absent.
pub(crate) fn state_proof_voters_commitment(tracking: &Option<rmpv::Value>) -> Vec<u8> {
    let Some(rmpv::Value::Map(types)) = tracking.as_ref() else {
        return Vec::new();
    };
    let basic = types
        .iter()
        .find(|(k, _)| k.as_u64() == Some(STATE_PROOF_BASIC))
        .map(|(_, v)| v);
    let Some(rmpv::Value::Map(fields)) = basic else {
        return Vec::new();
    };
    fields
        .iter()
        .find(|(k, _)| k.as_str() == Some("v"))
        .and_then(|(_, v)| v.as_slice())
        .map(|b| b.to_vec())
        .unwrap_or_default()
}

/// Read `StateProofTracking[StateProofBasic].StateProofOnlineTotalWeight`
/// (the `"t"` field under map key `0`) out of an encoded `"spt"` value,
/// defaulting to 0 when absent.
pub(crate) fn state_proof_online_total_weight(tracking: &Option<rmpv::Value>) -> u64 {
    let Some(rmpv::Value::Map(types)) = tracking.as_ref() else {
        return 0;
    };
    let basic = types
        .iter()
        .find(|(k, _)| k.as_u64() == Some(STATE_PROOF_BASIC))
        .map(|(_, v)| v);
    let Some(rmpv::Value::Map(fields)) = basic else {
        return 0;
    };
    fields
        .iter()
        .find(|(k, _)| k.as_str() == Some("t"))
        .and_then(|(_, v)| v.as_u64())
        .unwrap_or(0)
}

/// `protocol.StateProofBasic` — the only state-proof type
/// (`protocol/stateproof.go`: `StateProofBasic StateProofType = 0`,
/// `NumStateProofTypes = 1`).
const STATE_PROOF_BASIC: u64 = 0;

/// Build the `"spt"` (state-proof tracking) map for the round after `prev`.
///
/// Ports the two halves of go's tracking maintenance:
///
/// - `ledger/eval/eval.go:770–782` (`startEvaluator`): the next-state-proof
///   round is inherited from the previous header's tracking entry; when it is
///   still zero (state proofs just enabled / fresh chain) it is *initialized* to
///   `roundUp(round + StateProofVotersLookback, StateProofInterval) + StateProofInterval`.
/// - `ledger/eval/eval.go:1391–1400` (`endOfBlock`): the produced block carries
///   a one-entry map keyed by `protocol.StateProofBasic` holding the voters
///   commitment (`"v"`), the online total weight (`"t"`) and that next round
///   (`"n"`).
///
/// On a fresh v41 localnet (interval 256, lookback 16) round 1 therefore gets
/// `{0: {"n": 512}}` — `"v"`/`"t"` are zero (and omitted by the canonical
/// encoder) because go's `stateProofVotersAndTotal`
/// (`ledger/eval/eval.go:1333–1349`) returns zeroes for every round that is not
/// a multiple of `StateProofInterval`.
///
/// # Known gap
///
/// `"v"`/`"t"` are always left zero here. On rounds that *are* a multiple of
/// `StateProofInterval` go fills them from `VotersForStateProof`, i.e. the root
/// of a vector commitment over the online participants' state-proof keys — a
/// voters tracker and Merkle-tree machinery algod-rust does not have. Blocks
/// produced by algod-rust at round % 256 == 0 will therefore omit `"v"`/`"t"`
/// where go-algorand would set them.
fn next_state_proof_tracking(
    prev: &BlockHeader,
    next_round: u64,
    params: &ConsensusParams,
) -> Option<rmpv::Value> {
    // go: `if eval.proto.StateProofInterval > 0` (eval.go:1390).
    let interval = params.state_proof_interval;
    if interval == 0 {
        return None;
    }

    let mut next = state_proof_next_round(&prev.state_proof_tracking);
    if next == 0 {
        // First block after state proofs are enabled: the first block carrying
        // a vector commitment to the voters is the next multiple of the
        // interval at or after `round + lookback`; the first state proof itself
        // lands one interval after that (eval.go:773–782).
        let voters_round = round_up_to_multiple_of(
            next_round.saturating_add(params.state_proof_voters_lookback),
            interval,
        );
        next = voters_round.saturating_add(interval);
    }

    // One entry, keyed by StateProofBasic. Zero-valued fields ("v" voters
    // commitment, "t" online total weight) are omitted, matching go's
    // `codec:",omitempty"` on StateProofTrackingData.
    let mut fields = Vec::new();
    if next != 0 {
        fields.push((rmpv::Value::from("n"), rmpv::Value::from(next)));
    }
    Some(rmpv::Value::Map(vec![(
        rmpv::Value::from(STATE_PROOF_BASIC),
        rmpv::Value::Map(fields),
    )]))
}

/// go `basics.Round.RoundUpToMultipleOf` (`data/basics/units.go:161`):
/// `(round + n - 1) / n * n`.
fn round_up_to_multiple_of(round: u64, n: u64) -> u64 {
    round.saturating_add(n - 1) / n * n
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
/// - genesis id/hash, fee sink and rewards pool are carried from `prev`.
/// - `bonus` is recomputed by [`next_bonus`] (go's `NextBonus`) and
///   `state_proof_tracking` by `next_state_proof_tracking` (go's `endOfBlock`
///   StateProofTracking map) — see those for the ported formulas and the one
///   known gap (voters commitment / total weight).
/// - `txn_counter` carries `prev`'s value; the evaluator adds the assembled
///   transaction count when it fills the payset.
/// - seed, proposer, payset, and txn commitments are left zero/empty for later
///   stages to fill.
///
/// The protocol governing the new block (and hence the params used for the
/// timestamp clamp and the 512-hash gate) is the resolved protocol *after* any
/// switch-over — matching go, which looks up params for `upgradeState.CurrentProtocol`.
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

    // Params of the protocol `prev` ran under, needed by go's `NextBonus` to
    // detect a plan change (upgrade) between the two rounds.
    let prev_params =
        consensus_params_for_version(&prev.current_protocol).unwrap_or_else(|| params.clone());
    let bonus = next_bonus(prev, &params, &prev_params);
    let state_proof_tracking = next_state_proof_tracking(prev, next_round, &params);

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
        // Proposer bonus per the BonusPlan (go `NextBonus`).
        bonus,
        // The evaluator adds the assembled transaction count.
        txn_counter: prev.txn_counter,
        // State-proof tracking (go `endOfBlock`'s StateProofTracking map).
        state_proof_tracking,
        // Filled by the evaluator when it assembles the payset.
        txn_commitment: [0u8; 32],
        txn256: [0u8; 32],
        txn512: [0u8; 64],
        fees_collected: 0,
        proposer_payout: 0,
        expired_participation_accounts: None,
        absent_participation_accounts: None,
        // Congestion tax for the round after `prev`, per go's `NextCongestionTax`
        // — computed unconditionally (see that function's doc comment).
        congestion_tax: next_congestion_tax(prev.load, prev.congestion_tax),
        // Load is 0 in the skeleton (go's `MakeBlock` leaves it unset too): it
        // depends on the size of *this* round's own payset, which isn't known
        // until the caller has finished assembling it. The producer sets it
        // from [`compute_load`] once the final transaction-byte total and
        // `load_tracking`/`max_txn_bytes_per_block` params are known (go's
        // `endOfBlock`).
        load: 0,
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

    // ── Bonus payout ("bi") ─────────────────────────────────────
    // go: data/bookkeeping/block.go `computeBonus`; plan values from
    // config/consensus.go v40 (BaseAmount 10_000_000, DecayInterval 1_000_000).

    const V40_PLAN: (u64, u64, u64) = (0, 10_000_000, 1_000_000);

    #[test]
    fn bonus_starts_at_base_amount_on_first_round() {
        // current == 1 counts as "upgrading", so the base amount applies even
        // though the plan did not change.
        assert_eq!(compute_bonus(1, 0, V40_PLAN, V40_PLAN), 10_000_000);
    }

    #[test]
    fn bonus_applies_base_amount_at_upgrade() {
        // Plan differs from the previous round's plan → upgrade, and the base
        // round (0) has already passed → set the base amount.
        assert_eq!(compute_bonus(500, 7, V40_PLAN, (0, 0, 0)), 10_000_000);
    }

    #[test]
    fn bonus_applies_base_amount_exactly_at_base_round() {
        let plan = (900, 10_000_000, 1_000_000);
        assert_eq!(compute_bonus(900, 7, plan, plan), 10_000_000);
        // Before the base round, with no plan change, nothing happens.
        assert_eq!(compute_bonus(899, 7, plan, plan), 7);
    }

    #[test]
    fn bonus_carries_forward_between_decays() {
        assert_eq!(compute_bonus(2, 10_000_000, V40_PLAN, V40_PLAN), 10_000_000);
        assert_eq!(
            compute_bonus(999_999, 10_000_000, V40_PLAN, V40_PLAN),
            10_000_000
        );
    }

    #[test]
    fn bonus_decays_one_percent_on_interval() {
        // floor(prev * 99 / 100), go's NewPercent(99).DivvyAlgos.
        assert_eq!(
            compute_bonus(1_000_000, 10_000_000, V40_PLAN, V40_PLAN),
            9_900_000
        );
        assert_eq!(compute_bonus(2_000_000, 101, V40_PLAN, V40_PLAN), 99);
        // No decay configured → carry forward.
        assert_eq!(compute_bonus(1_000_000, 101, (0, 0, 0), (0, 0, 0)), 101);
    }

    #[test]
    fn first_produced_block_gets_ten_algo_bonus() {
        // Fresh localnet: genesis (round 0, bonus 0) → round 1 carries 10 Algos,
        // matching go's live value on a v41 dev-mode chain (issue #462).
        let genesis = BlockHeader {
            round: Round(0),
            current_protocol: CONSENSUS_V41.to_string(),
            bonus: 0,
            ..BlockHeader::default()
        };
        let hdr = make_next_block_header(&genesis, 1, rewards()).unwrap();
        assert_eq!(hdr.bonus, 10_000_000);
        // And the next round carries it forward unchanged.
        let hdr2 = make_next_block_header(&hdr, 2, rewards()).unwrap();
        assert_eq!(hdr2.bonus, 10_000_000);
    }

    // ── State proof tracking ("spt") ────────────────────────────

    fn spt_next_round(hdr: &BlockHeader) -> u64 {
        state_proof_next_round(&hdr.state_proof_tracking)
    }

    #[test]
    fn rounds_up_to_multiple() {
        assert_eq!(round_up_to_multiple_of(17, 256), 256);
        assert_eq!(round_up_to_multiple_of(256, 256), 256);
        assert_eq!(round_up_to_multiple_of(257, 256), 512);
        assert_eq!(round_up_to_multiple_of(0, 256), 0);
    }

    #[test]
    fn initializes_state_proof_tracking_on_first_block() {
        // v41: interval 256, lookback 16 → votersRound = roundUp(1+16, 256) =
        // 256, first state proof at 256+256 = 512. go's live localnet value is
        // `{0: {"n": 512}}` (issue #462).
        let genesis = BlockHeader {
            round: Round(0),
            current_protocol: CONSENSUS_V41.to_string(),
            ..BlockHeader::default()
        };
        let hdr = make_next_block_header(&genesis, 1, rewards()).unwrap();
        assert_eq!(
            hdr.state_proof_tracking,
            Some(rmpv::Value::Map(vec![(
                rmpv::Value::from(0u64),
                rmpv::Value::Map(vec![(rmpv::Value::from("n"), rmpv::Value::from(512u64))]),
            )])),
            "one StateProofBasic entry carrying only the next round",
        );
        assert_eq!(spt_next_round(&hdr), 512);
    }

    #[test]
    fn carries_state_proof_next_round_forward() {
        let genesis = BlockHeader {
            round: Round(0),
            current_protocol: CONSENSUS_V41.to_string(),
            ..BlockHeader::default()
        };
        let mut hdr = make_next_block_header(&genesis, 1, rewards()).unwrap();
        for _ in 0..5 {
            hdr = make_next_block_header(&hdr, 1, rewards()).unwrap();
            assert_eq!(
                spt_next_round(&hdr),
                512,
                "next state proof round stays put until a state proof lands",
            );
        }
    }

    #[test]
    fn omits_state_proof_tracking_before_v34() {
        // v33 has StateProofInterval == 0 → go never builds the map.
        let prev = BlockHeader {
            round: Round(5),
            current_protocol: algo_types::consensus::CONSENSUS_V33.to_string(),
            ..BlockHeader::default()
        };
        let hdr = make_next_block_header(&prev, 0, rewards()).unwrap();
        assert_eq!(hdr.state_proof_tracking, None);
    }

    #[test]
    fn reads_missing_or_malformed_tracking_as_zero() {
        assert_eq!(state_proof_next_round(&None), 0);
        assert_eq!(state_proof_next_round(&Some(rmpv::Value::Nil)), 0);
        assert_eq!(
            state_proof_next_round(&Some(rmpv::Value::Map(vec![]))),
            0,
            "no StateProofBasic entry",
        );
        assert_eq!(
            state_proof_next_round(&Some(rmpv::Value::Map(vec![(
                rmpv::Value::from(0u64),
                rmpv::Value::Map(vec![]),
            )]))),
            0,
            "entry present but \"n\" omitted (zero value)",
        );
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

    // ── Load tracking ("ld"/"ct") ───────────────────────────────
    // go: data/bookkeeping/block.go `NextCongestionTax`, `TestNextCongestionTax`
    // (data/bookkeeping/block_test.go, v4.7.0-beta / PR #6548). Every row here
    // is a value pulled directly from that Go table so the port is checked
    // against the real oracle, not just "looks reasonable" arithmetic.

    #[test]
    fn next_congestion_tax_matches_go_oracle_table() {
        let cases: &[(u64, u64, u64)] = &[
            // An empty block wants to decrease final price by 10%. So unless
            // the previous tax rate was > 10%, it zeros it out.
            (0, 0, 0),
            (0, 1, 0),
            (0, 1_000, 0),
            (0, 99_999, 0),
            (0, 100_000, 0),
            (0, 200_000, 80_000), // 1.2*0.9 = 1.08 -> 8% tax
            // A quarter full block wants to decrease final price by 5%.
            (250_000, 50_000, 0),   // 1.05*0.95 = 0.9975 -> 0% tax
            (250_000, 51_000, 0),   // 1.051*0.95 = 0.99845 -> 0% tax
            (250_000, 52_000, 0),   // 1.052*0.95 = 0.9994 -> 0% tax
            (250_000, 53_000, 350), // 1.053*0.95 = 1.00035 -> 350 micros tax
            (250_000, 1_000_000_000, 949_950_000), // 1001*0.95 = 950.95
            // A half full block wants to keep the final price the same.
            (500_000, 0, 0),
            (500_000, 1, 1),
            (500_000, u64::MAX, u64::MAX),
            // A 3/4 full block increases final price by 5%.
            (750_000, 0, 50_000),
            (750_000, 1, 50_001),
            (750_000, u64::MAX - 10, u64::MAX), // Saturate
            (750_000, u64::MAX, u64::MAX),      // Saturate
            (1_000_000, 0, 100_000),
            (1_000_000, 2_000_000, 2_300_000),
            (1_000_000, u64::MAX - 10, u64::MAX), // Saturate
            (1_000_000, u64::MAX, u64::MAX),      // Saturate
        ];
        for &(load, prev_tax, expected) in cases {
            assert_eq!(
                next_congestion_tax(load, prev_tax),
                expected,
                "load={load} prev_tax={prev_tax}",
            );
        }
    }

    // go: data/bookkeeping/block_test.go `TestBlockHeaderCongestionValidation`
    // subtest "congestion_fees_enabled" — 75% load causing a 5% price bump on
    // top of a 200% tax rate.
    #[test]
    fn next_congestion_tax_75_percent_load_on_200_percent_tax() {
        assert_eq!(next_congestion_tax(750_000, 2 * 1_000_000), 2_150_000);
    }

    // go: `TestBlockHeaderCongestionCreation` subtest "congestion_fees_enabled".
    #[test]
    fn next_congestion_tax_from_60_percent_load() {
        assert_eq!(next_congestion_tax(600_000, 100_000), 122_000);
    }

    // go: `TestBlockHeaderCongestionCreation` subtest "congestion_fees_disabled"
    // — a nonzero inherited tax tapers down even with prev_load == 0 (e.g.
    // after downgrading away from LoadTracking).
    #[test]
    fn next_congestion_tax_tapers_with_zero_load() {
        assert_eq!(next_congestion_tax(0, 2_000_000), 1_700_000);
    }

    #[test]
    fn make_next_block_header_sets_congestion_tax_and_defers_load() {
        let prev = BlockHeader {
            round: Round(10),
            current_protocol: CONSENSUS_V41.to_string(),
            load: 600_000,
            congestion_tax: 100_000,
            ..prev_header()
        };
        let hdr = make_next_block_header(&prev, 1500, rewards()).unwrap();
        assert_eq!(
            hdr.congestion_tax,
            next_congestion_tax(prev.load, prev.congestion_tax),
            "congestion_tax computed from prev round's Load/CongestionTax",
        );
        assert_eq!(
            hdr.load, 0,
            "Load is 0 in the skeleton; the producer fills it once the \
             payset is assembled",
        );
    }

    // go: ledger/eval/eval.go `ComputeLoad`.
    #[test]
    fn compute_load_scales_block_size_to_micros() {
        assert_eq!(compute_load(0, 1_000_000), 0, "empty block");
        assert_eq!(compute_load(1_000_000, 1_000_000), 1_000_000, "full block");
        assert_eq!(compute_load(500_000, 1_000_000), 500_000, "half full");
        assert_eq!(compute_load(250_000, 1_000_000), 250_000, "quarter full");
    }

    #[test]
    fn compute_load_clamps_at_full_and_handles_zero_max() {
        // go's Muldiv-overflow branch: "can't happen, but we'll say fully
        // loaded" rather than dividing by zero.
        assert_eq!(compute_load(1, 0), 1_000_000);
        // Load can never exceed 1,000,000 even if block_size > max_size.
        assert_eq!(compute_load(2_000_000, 1_000_000), 1_000_000);
    }
}
