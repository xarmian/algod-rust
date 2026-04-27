// `setup_p` and consensus-version override helpers for white-box tests.
//
// Mirrors go-algorand `agreement/player_test.go::setupP` and
// `agreement/player_test.go::overrideConfigWithDynamicFilterParam`.

use algo_types::{ConsensusParams, Round, CONSENSUS_V41};

use crate::events::ConsensusVersionView;
use crate::player::Player;
use crate::router::RootRouter;
use crate::step::{Period, Step};
use crate::types::{
    filter_timeout, CredentialArrivalHistory, Deadline, TimeoutType,
    DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY,
};

use super::io_automata::IoAutomataConcretePlayer;
use super::vote_maker::VoteMakerHelper;

/// The consensus-version string the white-box tests pin to. Mirrors Go's
/// `protocol.ConsensusCurrentVersion`. We use `CONSENSUS_V41` because the
/// permutation test relies on dynamic-filter-timeout being a recognized
/// flag (introduced in v39 and propagated forward).
pub const CONSENSUS_VERSION_FOR_TEST: &str = CONSENSUS_V41;

/// Set up a fresh `Player + RootRouter + IoTrace + VoteMakerHelper` triple
/// at `(round, period, step)`.
///
/// Mirrors Go's `setupP(t, r, p, s)` in `player_test.go:502`. The returned
/// helper has its random proposal-value pre-populated via
/// `VoteMakerHelper::setup`, so callers can immediately fabricate votes.
///
/// The player's deadline is set to `(filter_timeout(period, params), Filter)`
/// — matching Go's `Deadline{Duration: FilterTimeout(p, ...), Type: TimeoutFilter}`.
pub fn setup_p(
    round: Round,
    period: Period,
    step: Step,
    params: &ConsensusParams,
) -> (Player, IoAutomataConcretePlayer, VoteMakerHelper) {
    let mut player = Player {
        round,
        period,
        step,
        deadline: Deadline {
            duration: filter_timeout(period, params),
            timeout_type: TimeoutType::Filter,
        },
        lowest_credential_arrivals: CredentialArrivalHistory::new(
            DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY,
        ),
        ..Player::default()
    };
    // Match Go's setupP: re-initialize the credential history after
    // construction (Go does this via a separate makeCredentialArrivalHistory
    // call before assignment).
    player.lowest_credential_arrivals =
        CredentialArrivalHistory::new(DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY);

    let router = RootRouter::new(&player);
    let machine = IoAutomataConcretePlayer::new(player.clone(), router, params.clone());

    let mut helper = VoteMakerHelper::new();
    helper.setup();

    (player, machine, helper)
}

/// Wrapper carrying a `ConsensusParams` plus a `ConsensusVersionView` keyed
/// off the same version string. Mirrors the `(version, params, cleanup)`
/// triple Go's `overrideConfigWithDynamicFilterParam` returns.
pub struct OverriddenConsensus {
    /// The version string events should carry in their `proto` field.
    pub version: String,
    /// The consensus params the player should use when handling events.
    pub params: ConsensusParams,
    /// A `ConsensusVersionView` populated with the version string. Provided
    /// for convenience so test callers can attach it to events without
    /// rebuilding the struct each iteration.
    pub view: ConsensusVersionView,
}

/// Return a `ConsensusParams` derived from V41 with the dynamic-filter
/// timeout flag flipped to `enable`.
///
/// Mirrors Go's `overrideConfigWithDynamicFilterParam(enable)` in
/// `agreement/player_test.go`. The Go version mutates the global
/// `config.Consensus[V41]` map and returns a cleanup closure that restores
/// it; we instead just clone the params, flip the bit, and hand the result
/// back. No globals, no thread-safety concerns, no cleanup needed.
///
/// The returned `version` string is `CONSENSUS_VERSION_FOR_TEST` so the
/// caller can stamp it into `MessageEvent.proto.version` directly. Two
/// calls (with `false` and `true`) cover Go's `playerPermutationCheck(t,
/// false)` and `playerPermutationCheck(t, true)` runs respectively.
pub fn override_consensus_with_dynamic_filter(enable: bool) -> OverriddenConsensus {
    let mut params =
        algo_types::consensus::consensus_params_for_version(CONSENSUS_VERSION_FOR_TEST)
            .expect("v41 consensus params");
    params.dynamic_filter_timeout = enable;
    OverriddenConsensus {
        version: CONSENSUS_VERSION_FOR_TEST.to_string(),
        params,
        view: ConsensusVersionView {
            err: None,
            version: CONSENSUS_VERSION_FOR_TEST.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::step::SOFT;

    #[test]
    fn setup_p_at_round_period_step() {
        let oc = override_consensus_with_dynamic_filter(false);
        let (player, _machine, _helper) = setup_p(Round(209), Period(0), SOFT, &oc.params);
        assert_eq!(player.round, Round(209));
        assert_eq!(player.period, Period(0));
        assert_eq!(player.step, SOFT);
        assert_eq!(player.deadline.timeout_type, TimeoutType::Filter);
    }

    #[test]
    fn override_dynamic_filter_off() {
        let oc = override_consensus_with_dynamic_filter(false);
        assert!(!oc.params.dynamic_filter_timeout);
        assert_eq!(oc.view.version, CONSENSUS_VERSION_FOR_TEST);
    }

    #[test]
    fn override_dynamic_filter_on() {
        let oc = override_consensus_with_dynamic_filter(true);
        assert!(oc.params.dynamic_filter_timeout);
    }
}
