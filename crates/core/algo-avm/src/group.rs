//! Group-level execution context -- pooled budget and app call tracking.
//!
//! In the AVM, application call budgets are pooled across all top-level app
//! calls in an atomic group. Each top-level app call contributes 700 to the
//! shared pool. Inner app calls consume from the same pool but do not add
//! to it.

use algo_error::AlgoError;

use crate::eval::{APP_BUDGET_PER_CALL, LOGICSIG_BUDGET};

/// Maximum number of transactions in an atomic group (per go-algorand).
pub const MAX_GROUP_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// GroupBudget
// ---------------------------------------------------------------------------

/// Tracks the pooled opcode budget across all app calls in an atomic group.
///
/// Initialized to `APP_BUDGET_PER_CALL * num_app_calls`. Each opcode
/// execution consumes from this pool. Inner app calls draw from the same
/// pool but do not increase it (only top-level app calls contribute).
#[derive(Debug)]
pub struct GroupBudget {
    remaining: i64,
}

impl GroupBudget {
    /// Create a new budget for a group with `num_app_calls` top-level
    /// application call transactions.
    pub fn new(num_app_calls: usize) -> Self {
        let n = i64::try_from(num_app_calls).expect("group size too large for budget");
        GroupBudget {
            remaining: APP_BUDGET_PER_CALL.saturating_mul(n),
        }
    }

    /// Create a new budget for LogicSig evaluation across an atomic group.
    ///
    /// Each transaction in the group contributes `LOGICSIG_BUDGET` (20,000)
    /// opcodes to the shared pool, regardless of transaction type.
    pub fn for_logicsig(group_size: usize) -> Self {
        let n = i64::try_from(group_size).expect("group size too large for budget");
        GroupBudget {
            remaining: LOGICSIG_BUDGET.saturating_mul(n),
        }
    }

    /// Consume `cost` units from the budget.
    ///
    /// Returns an error if the budget would go negative.
    pub fn consume(&mut self, cost: i64) -> Result<(), AlgoError> {
        let new_remaining = self.remaining - cost;
        if new_remaining < 0 {
            return Err(AlgoError::Avm {
                message: format!(
                    "pooled budget exhausted: tried to consume {cost} with {remaining} remaining",
                    remaining = self.remaining
                ),
            });
        }
        self.remaining = new_remaining;
        Ok(())
    }

    /// Return the remaining budget.
    pub fn remaining(&self) -> i64 {
        self.remaining
    }

    /// Add extra budget (e.g. when an inner app call adds to the pool).
    pub fn add(&mut self, extra: i64) {
        self.remaining += extra;
    }
}

// ---------------------------------------------------------------------------
// GroupContext
// ---------------------------------------------------------------------------

/// Tracks group-level state during evaluation of an atomic transaction group.
///
/// Holds the pooled budget and the current app call index within the group.
#[derive(Debug)]
pub struct GroupContext {
    /// Pooled opcode budget shared across all app calls in the group.
    pub budget: GroupBudget,
    /// Total number of app calls in this group.
    pub num_app_calls: usize,
    /// Index of the app call currently being evaluated (0-based).
    pub app_call_index: usize,
}

impl GroupContext {
    /// Create a new group context for a group with `num_app_calls` top-level
    /// application call transactions.
    pub fn new(num_app_calls: usize) -> Self {
        debug_assert!(
            num_app_calls <= MAX_GROUP_SIZE,
            "num_app_calls ({num_app_calls}) exceeds MAX_GROUP_SIZE ({MAX_GROUP_SIZE})"
        );
        GroupContext {
            budget: GroupBudget::new(num_app_calls),
            num_app_calls,
            app_call_index: 0,
        }
    }

    /// Advance to the next app call in the group.
    pub fn advance_app_call(&mut self) {
        self.app_call_index += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_initialization() {
        let budget = GroupBudget::new(1);
        assert_eq!(budget.remaining(), 700);

        let budget = GroupBudget::new(3);
        assert_eq!(budget.remaining(), 2100);

        let budget = GroupBudget::new(0);
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn test_budget_consume() {
        let mut budget = GroupBudget::new(1);
        assert!(budget.consume(100).is_ok());
        assert_eq!(budget.remaining(), 600);

        assert!(budget.consume(600).is_ok());
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn test_budget_consume_exact() {
        let mut budget = GroupBudget::new(1);
        assert!(budget.consume(700).is_ok());
        assert_eq!(budget.remaining(), 0);
    }

    #[test]
    fn test_budget_exhausted() {
        let mut budget = GroupBudget::new(1);
        assert!(budget.consume(100).is_ok());
        let err = budget.consume(601).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("pooled budget exhausted"), "got: {msg}");
        // Budget should not have changed on failure.
        assert_eq!(budget.remaining(), 600);
    }

    #[test]
    fn test_budget_add() {
        let mut budget = GroupBudget::new(1);
        budget.add(700);
        assert_eq!(budget.remaining(), 1400);
    }

    #[test]
    fn test_budget_remaining_reflects_consumption() {
        let mut budget = GroupBudget::new(2);
        assert_eq!(budget.remaining(), 1400);
        budget.consume(200).unwrap();
        assert_eq!(budget.remaining(), 1200);
        budget.consume(500).unwrap();
        assert_eq!(budget.remaining(), 700);
    }

    #[test]
    fn test_group_context_new() {
        let ctx = GroupContext::new(4);
        assert_eq!(ctx.num_app_calls, 4);
        assert_eq!(ctx.app_call_index, 0);
        assert_eq!(ctx.budget.remaining(), 2800);
    }

    #[test]
    fn test_group_context_advance() {
        let mut ctx = GroupContext::new(3);
        assert_eq!(ctx.app_call_index, 0);
        ctx.advance_app_call();
        assert_eq!(ctx.app_call_index, 1);
        ctx.advance_app_call();
        assert_eq!(ctx.app_call_index, 2);
        ctx.advance_app_call();
        assert_eq!(ctx.app_call_index, 3);
    }
}
