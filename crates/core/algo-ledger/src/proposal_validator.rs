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

// State-aware proposal validation for the participating node (issue #1798).
//
// `algo_validate::validate_block` (behind `BlockValidatorBridge`) is
// stateless, so it cannot judge a peer proposal's `FeesCollected`,
// `Proposer` and `ProposerPayout` header fields: those depend on the fee
// sink and proposer balances after the payset. go validates every proposal
// through the ledger evaluator (`validateForPayouts` in `endOfBlock`) before
// voting for it. This wrapper adds that check, against the committed ledger
// state, after the stateless validation.
//
// Liveness: only a genuine `validateForPayouts` verdict rejects a proposal.
// Anything that merely prevents the check from running (ledger busy or not
// yet at the previous round, no scratch rollback available, a payset
// transaction not evaluable here) is waited out within a small bounded
// budget where waiting can help, then falls back to the stateless verdict
// with a warning and a counter, so the new check can never cost the node a
// block go accepts.
//
// Failing open on "no verdict" is a deliberate liveness choice. The residual
// adversarial window it leaves (a proposal that makes the check unevaluable
// and carries a bad payout) is closed by #1803, the validating apply on the
// commit path.
//
// Known cost (tracked in #1781): the ledger mutex is held for the whole
// scratch Execute of the payset, the same way the proposer's own scratch
// evaluation holds it. The guard is dropped before any post-processing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use algo_agreement::{AgreementError, BlockValidator, ValidatedBlock};
use algo_types::Block;
use tracing::warn;

use crate::shadow_execute::{scratch_validate_payouts, PayoutCheck};
use crate::sqlite::SqliteLedger;
use crate::store_trait::LedgerStore;

/// How long a proposal waits for the ledger (busy, or behind by a round)
/// before falling back to the stateless verdict. Well inside an agreement
/// step deadline.
pub const PAYOUT_CHECK_BUDGET: Duration = Duration::from_millis(1500);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

static FALLBACKS: AtomicU64 = AtomicU64::new(0);

/// Number of proposals accepted on the stateless verdict alone because the
/// payout check could not be evaluated. A test and diagnostic counter only:
/// it is not exported to the node's metrics; the `warn!` emitted on every
/// fallback is the operator-facing signal.
pub fn payout_check_fallbacks() -> u64 {
    FALLBACKS.load(Ordering::Relaxed)
}

/// Wraps a stateless [`BlockValidator`] with go's `validateForPayouts`
/// evaluated on a rolled-back scratch apply over the ledger.
pub struct PayoutCheckingValidator<V: BlockValidator> {
    inner: V,
    ledger: Arc<Mutex<SqliteLedger>>,
    budget: Duration,
}

enum Attempt {
    /// A genuine verdict: `Err` carries the `validateForPayouts` message.
    Verdict(Result<(), String>),
    /// No verdict; `retry` says whether waiting may help.
    NoVerdict { reason: String, retry: bool },
}

impl<V: BlockValidator> PayoutCheckingValidator<V> {
    pub fn new(inner: V, ledger: Arc<Mutex<SqliteLedger>>) -> Self {
        Self::with_budget(inner, ledger, PAYOUT_CHECK_BUDGET)
    }

    pub fn with_budget(inner: V, ledger: Arc<Mutex<SqliteLedger>>, budget: Duration) -> Self {
        Self {
            inner,
            ledger,
            budget,
        }
    }

    fn attempt(&self, block: &Block) -> Attempt {
        let mut ledger = match self.ledger.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                return Attempt::NoVerdict {
                    reason: "ledger busy".into(),
                    retry: true,
                }
            }
            Err(TryLockError::Poisoned(_)) => {
                return Attempt::NoVerdict {
                    reason: "ledger lock poisoned".into(),
                    retry: false,
                }
            }
        };
        let current = ledger.current_round().0;
        if block.round.0 <= current {
            // Already final: a round at or below the committed one is
            // settled (its certified block is in the ledger), so there is no
            // pre-block state left to judge this proposal against and
            // nothing it could still change.
            return Attempt::Verdict(Ok(()));
        }
        if block.round.0 > current + 1 {
            return Attempt::NoVerdict {
                reason: format!(
                    "ledger at round {current} is behind the proposal for round {}",
                    block.round.0
                ),
                retry: true,
            };
        }
        // The guard is held only for the scratch evaluation itself and is
        // dropped when this function returns, before any post-processing.
        match scratch_validate_payouts(&mut *ledger, block) {
            PayoutCheck::Valid => Attempt::Verdict(Ok(())),
            PayoutCheck::Violation(v) => Attempt::Verdict(Err(v)),
            PayoutCheck::NoVerdict { reason, transient } => Attempt::NoVerdict {
                reason,
                retry: transient,
            },
        }
    }
}

impl<V: BlockValidator> BlockValidator for PayoutCheckingValidator<V> {
    fn validate(&self, block: &Block) -> Result<Box<dyn ValidatedBlock>, AgreementError> {
        let validated = self.inner.validate(block)?;
        let deadline = Instant::now() + self.budget;
        loop {
            match self.attempt(block) {
                Attempt::Verdict(Ok(())) => return Ok(validated),
                Attempt::Verdict(Err(violation)) => {
                    return Err(AgreementError::ValidationFailed(violation))
                }
                Attempt::NoVerdict { reason, retry } => {
                    if retry && Instant::now() < deadline {
                        std::thread::sleep(POLL_INTERVAL);
                        continue;
                    }
                    FALLBACKS.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        round = block.round.0,
                        %reason,
                        "payout check could not be evaluated; accepting on the stateless verdict"
                    );
                    return Ok(validated);
                }
            }
        }
    }

    fn set_prev_timestamp(&self, ts: i64) {
        self.inner.set_prev_timestamp(ts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_agreement::StubBlockValidator;
    use algo_types::consensus::CONSENSUS_V41;
    use algo_types::{Address, Round};

    /// An empty V41 proposal for `round`: payouts enabled, no fees, no bonus,
    /// so the allowance is 0 and any payout is over it.
    fn proposal(round: u64, payout: u64) -> Block {
        Block {
            round: Round(round),
            current_protocol: CONSENSUS_V41.to_string(),
            proposer: Address([9u8; 32]),
            proposer_payout: payout,
            fee_sink: Address([3u8; 32]),
            ..Block::default()
        }
    }

    fn ledger_at(round: u64) -> Arc<Mutex<SqliteLedger>> {
        let mut l = SqliteLedger::open_in_memory().unwrap();
        l.set_current_round(Round(round));
        Arc::new(Mutex::new(l))
    }

    fn validator(
        ledger: &Arc<Mutex<SqliteLedger>>,
        budget: Duration,
    ) -> PayoutCheckingValidator<StubBlockValidator> {
        PayoutCheckingValidator::with_budget(
            StubBlockValidator::accepting(),
            ledger.clone(),
            budget,
        )
    }

    #[test]
    fn genuine_verdict_rejects_and_valid_payout_passes() {
        let ledger = ledger_at(0);
        let v = validator(&ledger, Duration::from_millis(200));
        let err = v.validate(&proposal(1, 5)).err().expect("over allowance");
        assert!(err.to_string().contains("5 payout, 0 is allowed"), "{err}");
        v.validate(&proposal(1, 0)).map(|_| ()).expect("payout 0");
    }

    /// A scratch apply that cannot run (an open lease journal makes the
    /// store refuse to roll back) is not a verdict: the proposal is accepted
    /// on the stateless result, counted and warned about.
    #[test]
    fn unsupported_scratch_does_not_reject_a_valid_proposal() {
        let ledger = ledger_at(0);
        let _leaked = ledger.lock().unwrap().save_scratch_state().expect("open");
        let before = payout_check_fallbacks();
        let v = validator(&ledger, Duration::from_millis(100));
        // Even a payout that WOULD be rejected passes: no verdict was reached.
        v.validate(&proposal(1, 5))
            .map(|_| ())
            .expect("must fall back to the stateless verdict");
        assert!(payout_check_fallbacks() > before);
    }

    /// A proposal for a round past the next one waits for the ledger to reach
    /// round - 1 and is then judged (and rejected here), rather than failing.
    #[test]
    fn lagging_ledger_is_waited_for_then_judged() {
        let ledger = ledger_at(0);
        let advancer = {
            let ledger = ledger.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                ledger.lock().unwrap().set_current_round(Round(1));
            })
        };
        let v = validator(&ledger, Duration::from_secs(5));
        let err = v
            .validate(&proposal(2, 5))
            .err()
            .expect("judged after wait");
        assert!(err.to_string().contains("is allowed"), "{err}");
        advancer.join().unwrap();
    }

    /// If the ledger never catches up within the budget the stateless verdict
    /// stands.
    #[test]
    fn ledger_that_never_catches_up_falls_back() {
        let ledger = ledger_at(0);
        let before = payout_check_fallbacks();
        let v = validator(&ledger, Duration::from_millis(60));
        v.validate(&proposal(5, 5)).map(|_| ()).expect("fallback");
        assert!(payout_check_fallbacks() > before);
    }

    /// A round at or below the committed one is already final.
    #[test]
    fn already_committed_round_passes() {
        let ledger = ledger_at(3);
        let v = validator(&ledger, Duration::from_millis(60));
        v.validate(&proposal(3, 5)).map(|_| ()).expect("final");
    }

    /// A busy ledger is waited for within the budget.
    #[test]
    fn busy_ledger_is_waited_for() {
        let ledger = ledger_at(0);
        let holder = {
            let ledger = ledger.clone();
            std::thread::spawn(move || {
                let _g = ledger.lock().unwrap();
                std::thread::sleep(Duration::from_millis(150));
            })
        };
        std::thread::sleep(Duration::from_millis(30));
        let v = validator(&ledger, Duration::from_secs(5));
        let err = v
            .validate(&proposal(1, 5))
            .err()
            .expect("judged after wait");
        assert!(err.to_string().contains("is allowed"), "{err}");
        holder.join().unwrap();
    }

    /// go `WithProposer`: before payouts are enabled the proposer stays unset,
    /// so a block finished by agreement still passes `validateForPayouts`
    /// (which rejects a proposer when payouts are disabled).
    #[test]
    fn finished_block_on_a_pre_payouts_protocol_passes_validation() {
        use algo_agreement::{PoolUnfinishedBlock, Seed, UnfinishedBlock};
        let ledger = ledger_at(0);
        let v = validator(&ledger, Duration::from_millis(200));
        let template = Block {
            round: Round(1),
            current_protocol: algo_types::consensus::CONSENSUS_V38.to_string(),
            fee_sink: Address([3u8; 32]),
            ..Block::default()
        };
        let finished =
            PoolUnfinishedBlock::new(template).finish_block(Seed([7; 32]), Address([9; 32]), true);
        assert_eq!(finished.proposer, Address::ZERO);
        v.validate(&finished)
            .map(|_| ())
            .expect("pre-payouts finished block must validate");

        // With payouts enabled the proposer is set and the block validates.
        let template = Block {
            round: Round(1),
            current_protocol: CONSENSUS_V41.to_string(),
            fee_sink: Address([3u8; 32]),
            ..Block::default()
        };
        let finished =
            PoolUnfinishedBlock::new(template).finish_block(Seed([7; 32]), Address([9; 32]), true);
        assert_eq!(finished.proposer, Address([9; 32]));
        v.validate(&finished)
            .map(|_| ())
            .expect("payouts-enabled finished block must validate");
    }

    /// A payout verdict is a typed rejection, never a "no verdict" fallback.
    #[test]
    fn payout_violation_is_classified_as_a_verdict() {
        let ledger = ledger_at(0);
        let mut l = ledger.lock().unwrap();
        match scratch_validate_payouts(&mut *l, &proposal(1, 5)) {
            PayoutCheck::Violation(m) => assert!(m.contains("is allowed"), "{m}"),
            other => panic!("expected a violation, got {other:?}"),
        }
    }
}
