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
// - ISV/ICV sub-cases, pipelined-threshold and verification-request tests
//   (`TestPlayerISV*`, `TestPlayerICV*`, `TestPlayerRequests*Verification`,
//   `TestPlayerHandlesPipelinedThresholds`, `TestPlayerRequestsPipelinedPayloadVerification`).
// - `TestPlayerAlwaysResynchsPinnedValue` — not attempted in this pass. It
//   needs a multi-hop trace assertion (rezero + relay-bundle + relay-payload
//   all in one transition) that's meaningfully more involved than the other
//   scenarios here; left open rather than rushed, per this issue's guidance
//   to prioritize verified-correct coverage over breadth.
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

use algo_agreement::test_support::{
    override_consensus_with_dynamic_filter, setup_p, IoAutomataConcretePlayer, VoteMakerHelper,
};
use algo_agreement::{
    Action, ActionType, Certificate, ConsensusVersionView, Event, EventType, InternalMessage,
    MessageEvent, Proposal, ProposalValue, SerializableError, UnauthenticatedBundle,
    UnauthenticatedCredential, VoteAuthenticator, BOTTOM, CERT, NEXT, PROPOSE,
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
