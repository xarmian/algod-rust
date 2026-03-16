// Lookback round arithmetic, matching go-algorand/agreement/selector.go
// and go-algorand/agreement/params.go.

use algo_types::{ConsensusParams, Round};

/// Returns the round whose consensus parameters govern agreement for
/// round `r`.  Matches Go's `agreement.ParamsRound`.
///
/// `ParamsRound(r) = r.SubSaturate(2)`.
pub fn params_round(r: Round) -> Round {
    r.sub_saturate(2)
}

/// Returns how far back agreement looks when considering balances for
/// voting stake.  Matches Go's `agreement.BalanceLookback`.
///
/// `BalanceLookback = 2 * SeedRefreshInterval * SeedLookback`.
pub fn balance_lookback(params: &ConsensusParams) -> u64 {
    2 * params.seed_refresh_interval * params.seed_lookback
}

/// Returns the round whose online-stake snapshot is used for
/// agreement on round `r`.  Matches Go's `agreement.BalanceRound`.
///
/// `BalanceRound(r) = r.SubSaturate(BalanceLookback)`.
pub fn balance_round(r: Round, params: &ConsensusParams) -> Round {
    r.sub_saturate(balance_lookback(params))
}

/// Returns the round whose seed is used for sortition in round `r`.
/// Matches Go's `seedRound` in `agreement/selector.go`.
///
/// `seedRound(r) = r.SubSaturate(SeedLookback)`.
pub fn seed_round(r: Round, params: &ConsensusParams) -> Round {
    r.sub_saturate(params.seed_lookback)
}

/// Returns the effective key dilution: `key_dilution` if positive,
/// otherwise `default`.  Matches Go's common pattern for determining
/// the key-dilution value to use.
pub fn effective_key_dilution(key_dilution: u64, default: u64) -> u64 {
    if key_dilution > 0 {
        key_dilution
    } else {
        default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::consensus::consensus_params_for_version;

    fn v41_params() -> ConsensusParams {
        consensus_params_for_version(algo_types::CONSENSUS_V41)
            .expect("v41 params must exist")
    }

    // ── params_round ────────────────────────────────────────────────

    #[test]
    fn params_round_normal() {
        assert_eq!(params_round(Round(100)), Round(98));
    }

    #[test]
    fn params_round_saturates_at_zero() {
        assert_eq!(params_round(Round(0)), Round(0));
        assert_eq!(params_round(Round(1)), Round(0));
        assert_eq!(params_round(Round(2)), Round(0));
        assert_eq!(params_round(Round(3)), Round(1));
    }

    // ── balance_lookback ────────────────────────────────────────────

    #[test]
    fn balance_lookback_v41() {
        let p = v41_params();
        // v41: seed_refresh_interval = 80, seed_lookback = 2 → 2*80*2 = 320
        assert_eq!(balance_lookback(&p), 2 * p.seed_refresh_interval * p.seed_lookback);
        assert_eq!(balance_lookback(&p), 320);
    }

    // ── balance_round ───────────────────────────────────────────────

    #[test]
    fn balance_round_normal() {
        let p = v41_params();
        let lb = balance_lookback(&p);
        let r = Round(1000);
        assert_eq!(balance_round(r, &p), Round(1000 - lb));
    }

    #[test]
    fn balance_round_saturates() {
        let p = v41_params();
        // For round 0 (or any round < lookback), should saturate to 0
        assert_eq!(balance_round(Round(0), &p), Round(0));
        assert_eq!(balance_round(Round(100), &p), Round(0)); // 100 < 320
    }

    #[test]
    fn balance_round_exact_boundary() {
        let p = v41_params();
        let lb = balance_lookback(&p);
        // Exactly at the boundary
        assert_eq!(balance_round(Round(lb), &p), Round(0));
        assert_eq!(balance_round(Round(lb + 1), &p), Round(1));
    }

    // ── seed_round ──────────────────────────────────────────────────

    #[test]
    fn seed_round_normal() {
        let p = v41_params();
        assert_eq!(seed_round(Round(100), &p), Round(100 - p.seed_lookback));
    }

    #[test]
    fn seed_round_saturates() {
        let p = v41_params();
        assert_eq!(seed_round(Round(0), &p), Round(0));
        assert_eq!(seed_round(Round(1), &p), Round(0));
    }

    // ── effective_key_dilution ───────────────────────────────────────

    #[test]
    fn effective_key_dilution_uses_provided_when_positive() {
        assert_eq!(effective_key_dilution(42, 10000), 42);
    }

    #[test]
    fn effective_key_dilution_uses_default_when_zero() {
        assert_eq!(effective_key_dilution(0, 10000), 10000);
    }

    // ── Round::sub_saturate ─────────────────────────────────────────

    #[test]
    fn round_sub_saturate() {
        assert_eq!(Round(10).sub_saturate(3), Round(7));
        assert_eq!(Round(3).sub_saturate(3), Round(0));
        assert_eq!(Round(2).sub_saturate(5), Round(0));
        assert_eq!(Round(0).sub_saturate(1), Round(0));
    }
}
