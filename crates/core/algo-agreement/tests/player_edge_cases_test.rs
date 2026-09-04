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

// Player-integration tests for a batch of `setupP`/`ioAutomata`-driven
// white-box scenarios from go-algorand's `agreement/player_test.go` — Phase
// 17 issue #825, theme 1 ("Player state-machine edge cases").
//
// Scope note: theme 1 lists a much larger set of scenarios (offset-start
// rounds, late block proposals in period 0, several ISV/ICV sub-cases,
// pipelined-threshold handling, bundle/payload/pipelined verification
// requests, own/future-round proposal-payload propagation) than this file
// covers. Per the issue's guidance this pass is deliberately conservative:
// it ports the six *named* regression tests plus the two highest-priority
// network-input-hardening scenarios (bottom-bundle proposal,
// malformed-bundle disconnect), all of which build on the already-ported
// `setupP`/`ioAutomata` harness (`test_support::{setup_p, IoAutomataConcretePlayer,
// VoteMakerHelper}`) with no new test infrastructure required.
//
// Explicitly NOT covered here (left open for a follow-up):
// - `TestPlayerOffsetStart` / `TestPlayerLateBlockProposalPeriod0` /
//   `TestPlayerSynchronous` — these use a *different*, unported harness
//   (`testPlayerSetup`/`readOnlyFixture10`/`testBlockFactory`, real
//   participation-key/ledger fixtures) rather than `setupP`. Porting them
//   requires building that fixture harness from scratch, which is a
//   separate, larger undertaking.
//
// Ported scenarios (see also `docs/phase17/parity_agreement.md`):
// - `TestPlayerProposesBottomBundle`
// - `TestPlayerDisconnectsFromMalformedBundles`
// - `TestPlayerRegression_EnsuresCertThreshFromOldPeriod_8ba23942`
// - `TestPlayer_RejectsCertThresholdFromPreviousRound`
// - `TestPlayer_CertThresholdDoesNotBlock`
// - `TestPlayer_CertThresholdDoesNotBlockFuturePeriod`
// - `TestPlayer_CertThresholdCommitsFuturePeriodIfAlreadyHasBlock`
// - `TestPlayer_PayloadAfterCertThresholdCommits`
// - `TestPlayerAlwaysResynchsPinnedValue` (`player_always_resynchs_pinned_value`)
//   ported for issue #920's investigation of the 5-node
//   `fast_recovery_late_five_node`/`fast_recovery_redo_five_node` flakiness
//   (see `service_multi_node_test.rs`'s module doc comment). Passes
//   reliably: the `enter_period`/`partition_policy` "always resynch the
//   pinned value" mechanic this white-box test probes is correctly
//   implemented. Issue #920's residual multi-node flakiness traces to a
//   different gap (the 5-node harness's `TestingNetwork` has no
//   payload-catch-up path below `Player::partitioned()`'s period-3
//   threshold, where `partition_policy` -- the only pin-payload-relay
//   mechanic -- is gated off), not to anything this test exercises.
// - ISV (Issue Soft Vote) sub-cases: `TestPlayerISVDoesNotSoftVoteBottom`,
//   `TestPlayerISVVoteForStartingValue`, `TestPlayerISVVoteNoVoteSansProposal`,
//   `TestPlayerISVVoteForReProposal`, `TestPlayerISVNoVoteForUnsupportedReProposal`
//   (`player_isv_*`).
// - ICV (Issue Cert Vote) sub-cases: `TestPlayerICVOnSoftThresholdSamePeriod`,
//   `TestPlayerICVOnSoftThresholdPrePayload`,
//   `TestPlayerICVOnSoftThresholdThenPayloadNoProposalVote`,
//   `TestPlayerICVNoVoteForUncommittableProposal`,
//   `TestPlayerICVPanicOnSoftBottomThreshold` (`player_icv_*`).
// - Verification-request/pipelining sub-cases: `TestPlayerRequestsVoteVerification`,
//   `TestPlayerRequestsProposalVoteVerification`,
//   `TestPlayerRequestsBundleVerification`, `TestPlayerRequestsPayloadVerification`,
//   `TestPlayerRequestsPipelinedPayloadVerification`,
//   `TestPlayerHandlesPipelinedThresholds` (`player_requests_*`,
//   `player_handles_pipelined_thresholds`).
// All of the above are now ported below (this pass), using the same
// `setupP` harness with no new test infrastructure required.
//
// Ported scenarios (see also `docs/phase17/parity_agreement.md`):

use algo_agreement::test_support::{
    override_consensus_with_dynamic_filter, setup_p, IoAutomataConcretePlayer, VoteMakerHelper,
};
use algo_agreement::{
    Action, ActionType, Certificate, ConsensusVersionView, Event, EventType, InternalMessage,
    MessageEvent, Proposal, ProposalValue, SerializableError, TimeoutEvent, UnauthenticatedBundle,
    UnauthenticatedCredential, VoteAuthenticator, BOTTOM, CERT, NEXT, PROPOSE, SOFT,
};
use algo_types::{ConsensusParams, Round, CONSENSUS_V41};

fn proto_view() -> ConsensusVersionView {
    ConsensusVersionView {
        err: None,
        version: CONSENSUS_V41.to_string(),
    }
}

fn test_params() -> ConsensusParams {
    override_consensus_with_dynamic_filter(false).params
}

/// Fabricate `n` verified votes at `(round, period, step, value)` and drive
/// each through the machine as a `voteVerified` event. Mirrors the common
/// go-algorand pattern of looping `helper.MakeVerifiedVote` +
/// `messageEvent{T: voteVerified, ...}` for a batch of votes (used instead
/// of a single `bundleVerified` event when the test wants to exercise the
/// individual-vote accumulation path).
fn send_votes(
    machine: &mut IoAutomataConcretePlayer,
    helper: &mut VoteMakerHelper,
    n: usize,
    round: Round,
    period: algo_agreement::Period,
    step: algo_agreement::Step,
    value: ProposalValue,
) {
    for i in 0..n {
        let vote = helper.make_verified_vote(i, round, period, step, value);
        let msg = MessageEvent {
            t: EventType::VoteVerified,
            input: InternalMessage {
                vote: Some(vote.clone()),
                unauthenticated_vote: vote.to_unauthenticated(),
                ..InternalMessage::default()
            },
            proto: proto_view(),
            ..MessageEvent::default()
        };
        machine
            .transition(Event::Message(msg))
            .expect("voteVerified transition should not panic");
    }
}

/// Dispatch a single `bundleVerified` event for a synthesized bundle of `n`
/// votes at `(round, period, step, value)`. Mirrors the
/// `unauthenticatedBundle{...}` + `messageEvent{T: bundleVerified, ...}`
/// construction repeated throughout `player_test.go`.
fn send_bundle_verified(
    machine: &mut IoAutomataConcretePlayer,
    helper: &mut VoteMakerHelper,
    round: Round,
    period: algo_agreement::Period,
    step: algo_agreement::Step,
    value: ProposalValue,
) -> Certificate {
    let bundle = helper.make_verified_bundle(round, period, step, value, &test_params());
    let msg = MessageEvent {
        t: EventType::BundleVerified,
        input: InternalMessage {
            verified_bundle_votes: bundle.votes.clone(),
            unauthenticated_bundle: bundle.u.clone(),
            ..InternalMessage::default()
        },
        proto: proto_view(),
        ..MessageEvent::default()
    };
    machine
        .transition(Event::Message(msg))
        .expect("bundleVerified transition should not panic");
    Certificate::from_bundle(&bundle.u)
}

/// Dispatch a `payloadVerified` event for `proposal`.
fn send_payload_verified(machine: &mut IoAutomataConcretePlayer, proposal: &Proposal) {
    let msg = MessageEvent {
        t: EventType::PayloadVerified,
        input: InternalMessage {
            proposal: Some(proposal.clone()),
            unauthenticated_proposal: proposal.unauthenticated_proposal.clone(),
            ..InternalMessage::default()
        },
        proto: proto_view(),
        ..MessageEvent::default()
    };
    machine
        .transition(Event::Message(msg))
        .expect("payloadVerified transition should not panic");
}

fn contains_ensure_for(
    machine: &IoAutomataConcretePlayer,
    cert: &Certificate,
    payload_digest: algo_types::Digest,
) -> bool {
    machine.trace().contains_action_fn(|a| match a {
        Action::Ensure(ea) => {
            ea.certificate.round == cert.round
                && ea.certificate.period == cert.period
                && ea.certificate.proposal == cert.proposal
                && ea.payload.unauthenticated_proposal.block_digest() == payload_digest
        }
        _ => false,
    })
}

fn contains_stage_digest_for(machine: &IoAutomataConcretePlayer, cert: &Certificate) -> bool {
    machine.trace().contains_action_fn(|a| match a {
        Action::StageDigest(sa) => {
            sa.certificate.round == cert.round
                && sa.certificate.period == cert.period
                && sa.certificate.proposal == cert.proposal
        }
        _ => false,
    })
}

// ---------------------------------------------------------------------------
// Proposals: bottom-bundle fast-forward should trigger an assemble attempt.
// Mirrors Go's `TestPlayerProposesBottomBundle` (`player_test.go:1427`).
// ---------------------------------------------------------------------------

#[test]
fn player_proposes_bottom_bundle() {
    let r = Round(209);
    let p = algo_agreement::Period(11);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(
        r,
        algo_agreement::Period(p.0 - 1),
        algo_agreement::SOFT,
        &params,
    );

    // A next-value bundle for bottom at period p-1 should fast-forward the
    // player into period p and trigger an assemble attempt (the player has
    // no staged/pinned value, so it must build a fresh proposal).
    //
    // Go's test constructs the bundle envelope without an explicit `Step`
    // field (defaulting to the zero step); the replay logic
    // (`vote_aggregator::handle`) determines the threshold purely from each
    // individual vote's own step, so the bundle-level step is immaterial —
    // we set it explicitly here for clarity rather than reproducing Go's
    // laxness.
    let n = NEXT.committee_threshold(&params) as usize;
    send_votes_via_bundle(
        &mut machine,
        &mut helper,
        n,
        r,
        algo_agreement::Period(p.0 - 1),
        NEXT,
        BOTTOM,
    );

    assert_eq!(
        machine.player().period,
        p,
        "player did not fast forward to new period"
    );
    let assembled = machine.trace().contains_action_fn(|a| {
        matches!(a, Action::Pseudonode(pa) if pa.t == ActionType::Assemble && pa.round == r && pa.period == p)
    });
    assert!(
        assembled,
        "player should try to assemble new proposal; trace:\n{}",
        machine.trace()
    );
}

/// Thin wrapper so `player_proposes_bottom_bundle` can send a bundle built
/// from raw votes (rather than `send_bundle_verified`'s single-value
/// threshold shortcut) while keeping the same `n` used for the threshold.
fn send_votes_via_bundle(
    machine: &mut IoAutomataConcretePlayer,
    helper: &mut VoteMakerHelper,
    n: usize,
    round: Round,
    period: algo_agreement::Period,
    step: algo_agreement::Step,
    value: ProposalValue,
) {
    let mut votes = Vec::with_capacity(n);
    for i in 0..n {
        votes.push(helper.make_verified_vote(i, round, period, step, value));
    }
    let unauth = UnauthenticatedBundle {
        round,
        period,
        step,
        proposal: value,
        votes: votes
            .iter()
            .map(|v| VoteAuthenticator {
                sender: v.raw_vote.sender,
                cred: UnauthenticatedCredential::new(v.cred.proof),
                sig: v.sig.clone(),
            })
            .collect(),
        equivocation_votes: Vec::new(),
    };
    let msg = MessageEvent {
        t: EventType::BundleVerified,
        input: InternalMessage {
            verified_bundle_votes: votes,
            unauthenticated_bundle: unauth,
            ..InternalMessage::default()
        },
        proto: proto_view(),
        ..MessageEvent::default()
    };
    machine
        .transition(Event::Message(msg))
        .expect("bundleVerified transition should not panic");
}

// ---------------------------------------------------------------------------
// Malformed bundles must disconnect the sending peer. Mirrors Go's
// `TestPlayerDisconnectsFromMalformedBundles` (`player_test.go:2361`).
// ---------------------------------------------------------------------------

#[test]
fn player_disconnects_from_malformed_bundles() {
    let r = Round(201221);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, _helper) = setup_p(r, p, CERT, &params);

    let msg = MessageEvent {
        t: EventType::BundleVerified,
        input: InternalMessage::default(),
        err: Some(SerializableError::new("test error")),
        proto: proto_view(),
        ..MessageEvent::default()
    };
    machine
        .transition(Event::Message(msg))
        .expect("bundleVerified transition should not panic");

    let disconnected = machine.trace().contains_action_fn(
        |a| matches!(a, Action::Network(na) if na.t == ActionType::Disconnect && na.err.is_some()),
    );
    assert!(
        disconnected,
        "player should disconnect due to malformed bundle; trace:\n{}",
        machine.trace()
    );
}

// ---------------------------------------------------------------------------
// Regression 8ba23942: a cert threshold for an *old period within the same
// round* (period 0, after the player already fast-forwarded to period 1 via
// a next-bundle) must still be honored if it was the freshest threshold —
// not silently ignored. Mirrors Go's
// `TestPlayerRegression_EnsuresCertThreshFromOldPeriod_8ba23942`
// (`player_test.go:2717`).
// ---------------------------------------------------------------------------

#[test]
fn player_regression_ensures_cert_thresh_from_old_period_8ba23942() {
    let r = Round(20);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);
    let payload = algo_agreement::test_support::make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();

    // Fast-forward to period 1 via a next-value bundle at period 0.
    send_bundle_verified(&mut machine, &mut helper, r, p, NEXT, pv);
    assert_eq!(
        machine.player().period,
        algo_agreement::Period(p.0 + 1),
        "player did not fast forward to new period"
    );

    // Deliver the payload (accepted since the next quorum pinned pv).
    send_payload_verified(&mut machine, &payload);

    // Now deliver cert votes for *period 0* (the old period) individually.
    // Since this is the freshest cert threshold the player has for this
    // round, it must still be honored and commit the block/round.
    let n = CERT.committee_threshold(&params) as usize;
    send_votes(&mut machine, &mut helper, n, r, p, CERT, pv);

    assert_eq!(
        machine.player().round,
        Round(r.0 + 1),
        "player did not enter new round"
    );
    assert_eq!(
        machine.player().period,
        algo_agreement::Period(0),
        "player did not enter period 0 in new round"
    );
    let expected_cert = Certificate {
        round: r,
        period: p,
        proposal: pv,
        votes: Vec::new(),
    };
    assert!(
        contains_ensure_for(
            &machine,
            &expected_cert,
            payload.unauthenticated_proposal.block_digest()
        ),
        "player should try to ensure block on ledger; trace:\n{}",
        machine.trace()
    );
}

// ---------------------------------------------------------------------------
// A cert threshold for a *previous round* must never move the player and
// must never be staged. Mirrors Go's
// `TestPlayer_RejectsCertThresholdFromPreviousRound` (`player_test.go:2793`).
// ---------------------------------------------------------------------------

#[test]
fn player_rejects_cert_threshold_from_previous_round() {
    let r = Round(20);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);
    let pv = helper.make_random_proposal_value();

    let n = CERT.committee_threshold(&params) as usize;
    send_votes(
        &mut machine,
        &mut helper,
        n,
        Round(r.0 - 1),
        algo_agreement::Period(p.0 + 1),
        CERT,
        pv,
    );

    assert_eq!(
        machine.player().round,
        r,
        "player entered new round... bad!"
    );
    assert_eq!(machine.player().period, p, "player changed periods... bad!");

    let bad_cert = Certificate {
        round: Round(r.0 - 1),
        period: algo_agreement::Period(p.0 + 1),
        proposal: pv,
        votes: Vec::new(),
    };
    assert!(
        !contains_stage_digest_for(&machine, &bad_cert),
        "player should not try to stage anything; trace:\n{}",
        machine.trace()
    );
}

// ---------------------------------------------------------------------------
// A cert threshold in the *current* period must give the ledger a stage-digest
// hint even without a payload in hand. Mirrors Go's
// `TestPlayer_CertThresholdDoesNotBlock` (`player_test.go:2904`).
// ---------------------------------------------------------------------------

#[test]
fn player_cert_threshold_does_not_block() {
    let r = Round(20);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);
    let pv = helper.make_random_proposal_value();

    let n = CERT.committee_threshold(&params) as usize;
    send_votes(&mut machine, &mut helper, n, r, p, CERT, pv);

    assert_eq!(
        machine.player().round,
        r,
        "player entered new round... bad!"
    );
    assert_eq!(machine.player().period, p, "player changed periods... bad!");

    let cert = Certificate {
        round: r,
        period: p,
        proposal: pv,
        votes: Vec::new(),
    };
    assert!(
        contains_stage_digest_for(&machine, &cert),
        "player should have staged something but didn't; trace:\n{}",
        machine.trace()
    );
}

// ---------------------------------------------------------------------------
// Same as above but the cert threshold is for a *future period* in the same
// round: the player should fast-forward into that period AND still stage the
// digest. Mirrors Go's `TestPlayer_CertThresholdDoesNotBlockFuturePeriod`
// (`player_test.go:2940`).
// ---------------------------------------------------------------------------

#[test]
fn player_cert_threshold_does_not_block_future_period() {
    let r = Round(20);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);
    let pv = helper.make_random_proposal_value();

    let n = CERT.committee_threshold(&params) as usize;
    send_votes(
        &mut machine,
        &mut helper,
        n,
        r,
        algo_agreement::Period(p.0 + 1),
        CERT,
        pv,
    );

    assert_eq!(
        machine.player().round,
        r,
        "player entered new round... bad!"
    );
    assert_eq!(
        machine.player().period,
        algo_agreement::Period(p.0 + 1),
        "player should have changed periods but didn't"
    );

    let cert = Certificate {
        round: r,
        period: algo_agreement::Period(p.0 + 1),
        proposal: pv,
        votes: Vec::new(),
    };
    assert!(
        contains_stage_digest_for(&machine, &cert),
        "player should have staged something but didn't; trace:\n{}",
        machine.trace()
    );
}

// ---------------------------------------------------------------------------
// A cert threshold for a future period in the same round, when the player
// already holds the corresponding payload, should commit the block directly
// (skip the stage-digest round trip) and advance to the next round. Mirrors
// Go's `TestPlayer_CertThresholdCommitsFuturePeriodIfAlreadyHasBlock`
// (`player_test.go:3016`).
// ---------------------------------------------------------------------------

#[test]
fn player_cert_threshold_commits_future_period_if_already_has_block() {
    let r = Round(20);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);
    let payload = algo_agreement::test_support::make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();

    // Give the player a proposal/payload for the current period.
    let proposal_vote = helper.make_verified_vote(0, r, p, PROPOSE, pv);
    let msg = MessageEvent {
        t: EventType::VoteVerified,
        input: InternalMessage {
            vote: Some(proposal_vote.clone()),
            unauthenticated_vote: proposal_vote.to_unauthenticated(),
            ..InternalMessage::default()
        },
        proto: proto_view(),
        ..MessageEvent::default()
    };
    machine
        .transition(Event::Message(msg))
        .expect("voteVerified transition should not panic");
    send_payload_verified(&mut machine, &payload);

    // Cert threshold arrives for period p+2 (a future period) via a single
    // bundleVerified event (individual votes would get filtered as stale
    // relative to the player's still-period-0 freshness window).
    let cert = send_bundle_verified(
        &mut machine,
        &mut helper,
        r,
        algo_agreement::Period(p.0 + 2),
        CERT,
        pv,
    );

    assert_eq!(
        machine.player().round,
        Round(r.0 + 1),
        "player did not enter new round... bad!"
    );
    assert_eq!(
        machine.player().period,
        algo_agreement::Period(0),
        "player should have entered period 0 of new round but didn't"
    );
    assert!(
        contains_ensure_for(
            &machine,
            &cert,
            payload.unauthenticated_proposal.block_digest()
        ),
        "player should have committed a block but didn't; trace:\n{}",
        machine.trace()
    );
}

// ---------------------------------------------------------------------------
// Mirror image of the above: the cert threshold for a future period arrives
// *before* the payload. It should stage-digest first, then commit once the
// payload arrives afterward. Mirrors Go's
// `TestPlayer_PayloadAfterCertThresholdCommits` (`player_test.go:3081`).
// ---------------------------------------------------------------------------

#[test]
fn player_payload_after_cert_threshold_commits() {
    let r = Round(20);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);
    let payload = algo_agreement::test_support::make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();

    let cert = send_bundle_verified(
        &mut machine,
        &mut helper,
        r,
        algo_agreement::Period(p.0 + 2),
        CERT,
        pv,
    );

    assert_eq!(
        machine.player().round,
        r,
        "player entered new round... bad!"
    );
    assert_eq!(
        machine.player().period,
        algo_agreement::Period(p.0 + 2),
        "player should have changed periods but didn't"
    );
    assert!(
        contains_stage_digest_for(&machine, &cert),
        "player should have staged something but didn't; trace:\n{}",
        machine.trace()
    );
    machine.reset_trace();

    // Now deliver the payload; the player should commit.
    send_payload_verified(&mut machine, &payload);

    assert_eq!(
        machine.player().round,
        Round(r.0 + 1),
        "player did not enter new round... bad!"
    );
    assert_eq!(
        machine.player().period,
        algo_agreement::Period(0),
        "player should have entered period 0 but didn't"
    );
    assert!(
        contains_ensure_for(
            &machine,
            &cert,
            payload.unauthenticated_proposal.block_digest()
        ),
        "player should have committed but didn't; trace:\n{}",
        machine.trace()
    );
}

// ---------------------------------------------------------------------------
// A pinned value must be relayed (both its freshest bundle AND its payload)
// even across a multi-hop fast-forward where it wasn't re-staged in the
// intermediate period. Mirrors Go's `TestPlayerAlwaysResynchsPinnedValue`
// (`player_test.go:3139`) — previously deferred (see this file's module doc
// comment); ported now for issue #920's investigation of whether the
// 5-node `fast_recovery_redo_five_node`/`fast_recovery_late_five_node`
// flakiness traces back to this exact "always resynchs pinned value"
// mechanic.
//
// White-box trace: a payload is staged for period p-2 (soft step). A
// next-value bundle for that SAME value at period p-2 fast-forwards the
// player into period p-1 (no payload re-staged there). A SECOND next-value
// bundle for the SAME value, now at period p-1, fast-forwards into period p
// in one transition. The player must have relayed both the freshest bundle
// (the period p-1 one that triggered the final hop) AND the original
// payload (still only staged from period p-2), proving the pinned value
// survives a hop where it wasn't restaged, not just a same-period resync.
// ---------------------------------------------------------------------------

#[test]
fn player_always_resynchs_pinned_value() {
    let r = Round(209);
    let p = algo_agreement::Period(12);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(
        r,
        algo_agreement::Period(p.0 - 2),
        algo_agreement::SOFT,
        &params,
    );

    let payload = algo_agreement::test_support::make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();

    // Store a payload for period p-2: one propose-step vote for `pv`,
    // followed by the verified payload itself.
    send_votes(
        &mut machine,
        &mut helper,
        1,
        r,
        algo_agreement::Period(p.0 - 2),
        PROPOSE,
        pv,
    );
    send_payload_verified(&mut machine, &payload);

    // Next-value bundle at period p-2 fast-forwards into period p-1.
    send_bundle_verified(
        &mut machine,
        &mut helper,
        r,
        algo_agreement::Period(p.0 - 2),
        NEXT,
        pv,
    );

    // Second next-value bundle, now at period p-1 (which has no staged
    // payload of its own), fast-forwards into period p in one transition.
    // Only this final transition's trace is asserted on, mirroring Go's
    // `pM.resetTrace()` right before it.
    let final_bundle_period = algo_agreement::Period(p.0 - 1);
    machine.reset_trace();
    send_bundle_verified(&mut machine, &mut helper, r, final_bundle_period, NEXT, pv);

    assert_eq!(
        machine.player().period,
        p,
        "player did not fast forward to new period"
    );

    let rezeroed = machine
        .trace()
        .contains_action_fn(|a| matches!(a, Action::Rezero(ra) if ra.round == r));
    assert!(
        rezeroed,
        "player should reset clock; trace:\n{}",
        machine.trace()
    );

    let resynched_bundle = machine.trace().contains_action_fn(|a| match a {
        Action::Network(na) => {
            na.t == ActionType::Broadcast
                && na.tag == algo_agreement::VOTE_BUNDLE_TAG
                && na.unauthenticated_bundle.round == r
                && na.unauthenticated_bundle.period == final_bundle_period
                && na.unauthenticated_bundle.step == NEXT
                && na.unauthenticated_bundle.proposal == pv
        }
        _ => false,
    });
    assert!(
        resynched_bundle,
        "player should relay freshest bundle = next value bundle; trace:\n{}",
        machine.trace()
    );

    let expected_digest = payload.unauthenticated_proposal.block_digest();
    let resynched_payload = machine.trace().contains_action_fn(|a| match a {
        Action::Network(na) => {
            na.t == ActionType::Broadcast
                && na.tag == algo_agreement::PROPOSAL_PAYLOAD_TAG
                && na.compound_message.proposal.block_digest() == expected_digest
        }
        _ => false,
    });
    assert!(
        resynched_payload,
        "player should relay payload even if not staged in previous period; trace:\n{}",
        machine.trace()
    );
}

// ---------------------------------------------------------------------------
// Shared helpers for the ISV/ICV/verification-request sub-cases below.
// ---------------------------------------------------------------------------

/// Dispatch a bare `timeoutEvent` (soft-vote-timeout fire). Mirrors Go's
/// `makeTimeoutEvent()` — no round/period is attached; the player consults
/// its own internal state for freshness.
fn send_timeout(machine: &mut IoAutomataConcretePlayer) {
    let msg = TimeoutEvent {
        t: EventType::Timeout,
        random_entropy: 7,
        round: Round(0),
        proto: proto_view(),
    };
    machine
        .transition(Event::Timeout(msg))
        .expect("timeout transition should not panic");
}

/// Whether the trace contains a soft-vote (`attest`, step `SOFT`) for the
/// given `(round, period, value)`.
fn contains_soft_vote_for(
    machine: &IoAutomataConcretePlayer,
    round: Round,
    period: algo_agreement::Period,
    value: ProposalValue,
) -> bool {
    machine.trace().contains_action_fn(|a| {
        matches!(a, Action::Pseudonode(pa)
            if pa.t == ActionType::Attest
                && pa.round == round
                && pa.period == period
                && pa.step == SOFT
                && pa.proposal == value)
    })
}

/// Whether the trace contains a cert vote (`attest`, step `CERT`) for the
/// given `(round, period, value)`.
fn contains_cert_vote_for(
    machine: &IoAutomataConcretePlayer,
    round: Round,
    period: algo_agreement::Period,
    value: ProposalValue,
) -> bool {
    machine.trace().contains_action_fn(|a| {
        matches!(a, Action::Pseudonode(pa)
            if pa.t == ActionType::Attest
                && pa.round == round
                && pa.period == period
                && pa.step == CERT
                && pa.proposal == value)
    })
}

/// Whether the trace contains ANY `attest` (vote-issuing) action at all.
/// Mirrors Go's `pM.getTrace().ContainsFn(func(b event) bool { ... e.action.t()
/// == attest ... })` idiom used by the "should not issue any vote" tests.
fn contains_any_attest(machine: &IoAutomataConcretePlayer) -> bool {
    machine
        .trace()
        .contains_action_fn(|a| matches!(a, Action::Pseudonode(pa) if pa.t == ActionType::Attest))
}

/// Dispatch a `votePresent`/`bundlePresent`/`payloadPresent` message event
/// (an unauthenticated, not-yet-verified message the player must ask the
/// crypto verifier about).
fn send_present(machine: &mut IoAutomataConcretePlayer, t: EventType, input: InternalMessage) {
    let msg = MessageEvent {
        t,
        input,
        proto: proto_view(),
        ..MessageEvent::default()
    };
    machine
        .transition(Event::Message(msg))
        .expect("*Present transition should not panic");
}

// ---------------------------------------------------------------------------
// ISV (Issue Soft Vote) sub-cases. Mirror Go's `TestPlayerISV*`
// (`player_test.go:517-787`).
// ---------------------------------------------------------------------------

#[test]
fn player_isv_does_not_soft_vote_bottom() {
    // Every soft vote is associated with a proposalValue != bottom: a lone
    // verified vote for bottom at the soft step must not itself trigger a
    // soft-vote issuance.
    let r = Round(209);
    let p = algo_agreement::Period(1);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, SOFT, &params);

    let pv = BOTTOM;
    send_votes(&mut machine, &mut helper, 1, r, p, SOFT, pv);

    assert!(
        !contains_soft_vote_for(&machine, r, p, pv),
        "player should not issue soft vote; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_isv_vote_for_starting_value() {
    // If we see a next-value quorum, and no next-bottom quorum, vote for
    // that value regardless once the soft-vote timeout fires.
    let r = Round(209);
    let p = algo_agreement::Period(11);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, SOFT, &params);

    let pv = helper.make_random_proposal_value();
    send_bundle_verified(
        &mut machine,
        &mut helper,
        r,
        algo_agreement::Period(p.0 - 1),
        NEXT,
        pv,
    );

    send_timeout(&mut machine);

    assert!(
        contains_soft_vote_for(&machine, r, p, pv),
        "player should issue soft vote; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_isv_vote_no_vote_sans_proposal() {
    // If there's no proposal, even seeing a next-value-bottom quorum must
    // not issue a soft vote (or any vote at all).
    let r = Round(209);
    let p = algo_agreement::Period(11);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, SOFT, &params);

    let pv = BOTTOM;
    send_bundle_verified(
        &mut machine,
        &mut helper,
        r,
        algo_agreement::Period(p.0 - 1),
        NEXT,
        pv,
    );

    send_timeout(&mut machine);

    assert!(
        !contains_any_attest(&machine),
        "player should not issue any vote, especially soft vote; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_isv_vote_for_reproposal() {
    // Even if we saw bottom, if we see a reproposal, AND a next-value
    // quorum (not just a next-bottom quorum), vote for it.
    let r = Round(209);
    let p = algo_agreement::Period(11);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, SOFT, &params);

    // Bottom quorum at period p-1, step `next` — this is how the player
    // got into period p in the first place.
    send_bundle_verified(
        &mut machine,
        &mut helper,
        r,
        algo_agreement::Period(p.0 - 1),
        NEXT,
        BOTTOM,
    );

    // Value quorum at period p-1, step `next+1`.
    let pv = helper.make_random_proposal_value();
    send_bundle_verified(
        &mut machine,
        &mut helper,
        r,
        algo_agreement::Period(p.0 - 1),
        algo_agreement::Step(NEXT.0 + 1),
        pv,
    );

    // Reproposal (single propose-step vote) for the same value at period p.
    send_votes(&mut machine, &mut helper, 1, r, p, PROPOSE, pv);

    send_timeout(&mut machine);

    assert!(
        contains_soft_vote_for(&machine, r, p, pv),
        "player should issue soft vote; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_isv_no_vote_for_unsupported_reproposal() {
    // If there's no next-value quorum, don't support the reproposal.
    let r = Round(209);
    let p = algo_agreement::Period(11);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, SOFT, &params);

    // Bottom quorum at period p-1, step `next` — this is how the player
    // got into period p in the first place.
    let pv = BOTTOM;
    send_bundle_verified(
        &mut machine,
        &mut helper,
        r,
        algo_agreement::Period(p.0 - 1),
        NEXT,
        pv,
    );

    // Reproposal for a random value, but with no supporting next-value
    // quorum.
    let reproposed = helper.make_random_proposal_value();
    send_votes(&mut machine, &mut helper, 1, r, p, PROPOSE, reproposed);

    send_timeout(&mut machine);

    assert!(
        !contains_soft_vote_for(&machine, r, p, reproposed),
        "player should not issue soft vote without corresponding next threshold; trace:\n{}",
        machine.trace()
    );
}

// ---------------------------------------------------------------------------
// ICV (Issue Cert Vote) sub-cases. Mirror Go's `TestPlayerICV*`
// (`player_test.go:790-1078`).
// ---------------------------------------------------------------------------

#[test]
fn player_icv_on_soft_threshold_same_period() {
    // Basic cert-vote check: proposal vote + payload delivered first, THEN
    // the soft threshold arrives. Also proves cert-voting doesn't require
    // the freeze timer to have fired.
    let r = Round(12);
    let p = algo_agreement::Period(1);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, SOFT, &params);

    let payload = algo_agreement::test_support::make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();

    send_votes(&mut machine, &mut helper, 1, r, p, PROPOSE, pv);
    send_payload_verified(&mut machine, &payload);
    send_bundle_verified(&mut machine, &mut helper, r, p, SOFT, pv);

    assert!(
        contains_cert_vote_for(&machine, r, p, pv),
        "player should issue cert vote; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_icv_on_soft_threshold_pre_payload() {
    // Cert voting when the soft bundle is received BEFORE the proposal
    // payload. Should still generate a cert vote.
    let r = Round(12);
    let p = algo_agreement::Period(1);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, SOFT, &params);

    let payload = algo_agreement::test_support::make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();

    send_bundle_verified(&mut machine, &mut helper, r, p, SOFT, pv);
    send_votes(&mut machine, &mut helper, 1, r, p, PROPOSE, pv);
    send_payload_verified(&mut machine, &payload);

    assert!(
        contains_cert_vote_for(&machine, r, p, pv),
        "player should issue cert vote; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_icv_on_soft_threshold_then_payload_no_proposal_vote() {
    // If there's no proposal vote at all, a soft threshold followed by the
    // payload should still trigger a cert vote.
    let r = Round(12);
    let p = algo_agreement::Period(1);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, SOFT, &params);

    let payload = algo_agreement::test_support::make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();

    send_bundle_verified(&mut machine, &mut helper, r, p, SOFT, pv);
    send_payload_verified(&mut machine, &payload);

    assert!(
        contains_cert_vote_for(&machine, r, p, pv),
        "player should issue cert vote; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_icv_no_vote_for_uncommittable_proposal() {
    // A soft threshold for a value with no corresponding payload must not
    // trigger a cert vote, and must not move the player out of the soft
    // step.
    let r = Round(12);
    let p = algo_agreement::Period(1);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, SOFT, &params);

    let pv = helper.make_random_proposal_value();
    send_votes(&mut machine, &mut helper, 1, r, p, PROPOSE, pv);
    send_bundle_verified(&mut machine, &mut helper, r, p, SOFT, pv);

    assert!(
        !contains_cert_vote_for(&machine, r, p, pv),
        "player should not issue cert vote; trace:\n{}",
        machine.trace()
    );
    assert_eq!(
        machine.player().step,
        SOFT,
        "player should not move out of soft step"
    );
}

#[test]
fn player_icv_panic_on_soft_bottom_threshold() {
    // The player should never observe a softThreshold for bottom — this is
    // treated as an invariant violation (panic) mirroring Go's own
    // `panic("bad state: got softThreshold for bottom")`-class defensive
    // check.
    let r = Round(209);
    let p = algo_agreement::Period(1);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, algo_agreement::Step(0), &params);

    let pv = BOTTOM;
    // Note: Go constructs this bundle with no explicit `Step` field (so it
    // defaults to the zero step); the replay logic determines the
    // threshold purely from each individual vote's own step, so the
    // bundle-level step is immaterial (see `player_proposes_bottom_bundle`
    // above for the same note) — we set it explicitly here for clarity.
    let n = SOFT.committee_threshold(&params) as usize;
    let mut votes = Vec::with_capacity(n);
    for i in 0..n {
        votes.push(helper.make_verified_vote(i, r, p, SOFT, pv));
    }
    let unauth = UnauthenticatedBundle {
        round: r,
        period: p,
        step: algo_agreement::Step(0),
        proposal: pv,
        votes: votes
            .iter()
            .map(|v| VoteAuthenticator {
                sender: v.raw_vote.sender,
                cred: UnauthenticatedCredential::new(v.cred.proof),
                sig: v.sig.clone(),
            })
            .collect(),
        equivocation_votes: Vec::new(),
    };
    let msg = MessageEvent {
        t: EventType::BundleVerified,
        input: InternalMessage {
            verified_bundle_votes: votes,
            unauthenticated_bundle: unauth,
            ..InternalMessage::default()
        },
        proto: proto_view(),
        ..MessageEvent::default()
    };
    let result = machine.transition(Event::Message(msg));
    assert!(
        result.is_err(),
        "player should never see softThreshold = bottom without panicking"
    );
}

// ---------------------------------------------------------------------------
// Verification-request / pipelining sub-cases. Mirror Go's
// `TestPlayerRequests*Verification` and `TestPlayerHandlesPipelinedThresholds`
// (`player_test.go:2401-2600`, `2603-2715`).
// ---------------------------------------------------------------------------

#[test]
fn player_requests_vote_verification() {
    let r = Round(201221);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);
    let pv = helper.make_random_proposal_value();
    let vote = helper.make_verified_vote(0, r, p, SOFT, pv);

    send_present(
        &mut machine,
        EventType::VotePresent,
        InternalMessage {
            unauthenticated_vote: vote.to_unauthenticated(),
            ..InternalMessage::default()
        },
    );

    let verified = machine.trace().contains_action_fn(|a| match a {
        Action::Crypto(ca) => {
            ca.t == ActionType::VerifyVote && ca.round == r && ca.period == p && ca.task_index == 0
        }
        _ => false,
    });
    assert!(
        verified,
        "player should verify vote; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_requests_proposal_vote_verification() {
    let r = Round(1);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);
    let pv = helper.make_random_proposal_value();
    let vote = helper.make_verified_vote(0, r, p, PROPOSE, pv);

    send_present(
        &mut machine,
        EventType::VotePresent,
        InternalMessage {
            unauthenticated_vote: vote.to_unauthenticated(),
            ..InternalMessage::default()
        },
    );

    let verified = machine.trace().contains_action_fn(|a| match a {
        Action::Crypto(ca) => {
            ca.t == ActionType::VerifyVote && ca.round == r && ca.period == p && ca.task_index == 1
        }
        _ => false,
    });
    assert!(
        verified,
        "player should verify proposal vote with task index 1; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_requests_bundle_verification() {
    let r = Round(201221);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, _helper) = setup_p(r, p, CERT, &params);

    let bundle = UnauthenticatedBundle {
        round: r,
        period: p,
        step: algo_agreement::Step(0),
        proposal: BOTTOM,
        votes: Vec::new(),
        equivocation_votes: Vec::new(),
    };
    send_present(
        &mut machine,
        EventType::BundlePresent,
        InternalMessage {
            unauthenticated_bundle: bundle,
            ..InternalMessage::default()
        },
    );

    let verified = machine.trace().contains_action_fn(|a| match a {
        Action::Crypto(ca) => ca.t == ActionType::VerifyBundle && ca.round == r && ca.period == p,
        _ => false,
    });
    assert!(
        verified,
        "player should verify bundle; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_requests_payload_verification() {
    let r = Round(201221);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);
    let payload = algo_agreement::test_support::make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();

    // Submit a proposal/initial payload (propose-step vote).
    send_votes(&mut machine, &mut helper, 1, r, p, PROPOSE, pv);

    send_present(
        &mut machine,
        EventType::PayloadPresent,
        InternalMessage {
            unauthenticated_proposal: payload.unauthenticated_proposal.clone(),
            ..InternalMessage::default()
        },
    );

    let verified = machine.trace().contains_action_fn(|a| match a {
        Action::Crypto(ca) => ca.t == ActionType::VerifyPayload && ca.round == r && ca.period == p,
        _ => false,
    });
    assert!(
        verified,
        "player should verify payload; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_requests_pipelined_payload_verification() {
    let r = Round(201221);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);

    // A payload for round r+1 arrives while the player is still at round r
    // — it must NOT trigger an immediate verify request (it's for a future
    // round).
    let payload_two = algo_agreement::test_support::make_random_proposal_payload(Round(r.0 + 1));
    let pv_two = payload_two.unauthenticated_proposal.value();
    send_votes(
        &mut machine,
        &mut helper,
        1,
        Round(r.0 + 1),
        algo_agreement::Period(0),
        PROPOSE,
        pv_two,
    );
    send_present(
        &mut machine,
        EventType::PayloadPresent,
        InternalMessage {
            unauthenticated_proposal: payload_two.unauthenticated_proposal.clone(),
            ..InternalMessage::default()
        },
    );
    let verified_early = machine.trace().contains_action_fn(
        |a| matches!(a, Action::Crypto(ca) if ca.t == ActionType::VerifyPayload),
    );
    assert!(
        !verified_early,
        "player should not verify payload from r + 1 while still in round r; trace:\n{}",
        machine.trace()
    );

    // Now commit round r via the usual propose/payload/cert-bundle path.
    let payload = algo_agreement::test_support::make_random_proposal_payload(r);
    let pv = payload.unauthenticated_proposal.value();
    send_votes(&mut machine, &mut helper, 1, r, p, PROPOSE, pv);
    send_payload_verified(&mut machine, &payload);
    let cert = send_bundle_verified(&mut machine, &mut helper, r, p, CERT, pv);

    assert_eq!(
        machine.player().round,
        Round(r.0 + 1),
        "player did not enter new round"
    );
    assert_eq!(
        machine.player().period,
        algo_agreement::Period(0),
        "player did not enter period 0 in new round"
    );
    assert!(
        contains_ensure_for(
            &machine,
            &cert,
            payload.unauthenticated_proposal.block_digest()
        ),
        "player should try to ensure block/digest on ledger; trace:\n{}",
        machine.trace()
    );

    // The pipelined payload first seen in the previous round should now be
    // (re-)requested for verification.
    let verified_pipelined = machine.trace().contains_action_fn(|a| match a {
        Action::Crypto(ca) => ca.t == ActionType::VerifyPayload && ca.round == Round(r.0 + 1),
        _ => false,
    });
    assert!(
        verified_pipelined,
        "player should verify pipelined payload first seen in previous round; trace:\n{}",
        machine.trace()
    );
}

#[test]
fn player_handles_pipelined_thresholds() {
    // Make sure we stage a pipelined soft threshold after entering the new
    // round: verified soft votes for round r+1 arrive individually (a
    // bundle would be rejected by freshness rules) while the player is
    // still at round r; once the player enters round r+1, delivering the
    // matching payload should trigger an immediate verify request (proving
    // the pipelined soft threshold was staged, not discarded).
    let r = Round(20);
    let p = algo_agreement::Period(0);
    let params = test_params();
    let (_player, mut machine, mut helper) = setup_p(r, p, CERT, &params);

    let payload = algo_agreement::test_support::make_random_proposal_payload(Round(r.0 + 1));
    let pv = payload.unauthenticated_proposal.value();
    let n = SOFT.committee_threshold(&params) as usize;
    send_votes(&mut machine, &mut helper, n, Round(r.0 + 1), p, SOFT, pv);

    // Now enter the next round via the usual propose/payload/cert-bundle
    // path.
    let payload_two = algo_agreement::test_support::make_random_proposal_payload(r);
    let pv_two = payload_two.unauthenticated_proposal.value();
    send_votes(&mut machine, &mut helper, 1, r, p, PROPOSE, pv_two);
    send_payload_verified(&mut machine, &payload_two);
    send_bundle_verified(&mut machine, &mut helper, r, p, CERT, pv_two);

    assert_eq!(
        machine.player().round,
        Round(r.0 + 1),
        "player did not enter new round"
    );

    // We verify the pipelined soft threshold was staged indirectly: send
    // the matching payload and confirm it gets a verify request.
    send_present(
        &mut machine,
        EventType::PayloadPresent,
        InternalMessage {
            unauthenticated_proposal: payload.unauthenticated_proposal.clone(),
            ..InternalMessage::default()
        },
    );
    let verified = machine.trace().contains_action_fn(|a| match a {
        Action::Crypto(ca) => ca.t == ActionType::VerifyPayload && ca.round == Round(r.0 + 1),
        _ => false,
    });
    assert!(
        verified,
        "player should verify pipelined payload first seen in previous round; trace:\n{}",
        machine.trace()
    );
}
