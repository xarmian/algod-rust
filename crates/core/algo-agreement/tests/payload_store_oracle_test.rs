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

// Replays the scripted held-payload scenarios of
// `tests/fixtures/payload_store/scenarios.jsonl`, which go v5.1.1's real
// player produced (`tools/payload-store-oracle`), through this crate's
// player and compares, after every step, the player's round/period/step and
// the actions it emitted. They cover go's `held`/`requestOrHold`/`resumeHeld`/
// `verifyHeldPayload`, the cancelled-payloadVerified re-pipelining and the
// proposalManager's round-age checks. Issue #2552.

use std::collections::HashMap;

use algo_agreement::test_support::{
    make_random_proposal_payload, override_consensus_with_dynamic_filter, setup_p,
};
use algo_agreement::{
    Action, ConsensusVersionView, Event, EventType, InternalMessage, MessageEvent, Period,
    Proposal, ProposalValue, SerializableError, Step, BOTTOM,
};
use algo_types::{Round, CONSENSUS_V41};
use serde_json::Value;

fn summarize(a: &Action) -> Option<String> {
    Some(match a {
        Action::Crypto(c) => format!(
            "crypto:{}:r{}:p{}:s{}:pin={}",
            c.t, c.round.0, c.period.0, c.step.0, c.pinned
        ),
        Action::Network(n) => format!("net:{}:{}", n.t, n.tag),
        Action::Pseudonode(p) => format!("pseudo:{}:r{}:p{}", p.t, p.round.0, p.period.0),
        Action::Rezero(r) => format!("rezero:r{}", r.round.0),
        Action::Ensure(e) => format!("ensure:r{}", e.certificate.round.0),
        Action::StageDigest(s) => format!("stage:r{}", s.certificate.round.0),
        _ => return None,
    })
}

#[test]
fn held_payload_scenarios_match_go_step_for_step() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/payload_store/scenarios.jsonl");
    let text = std::fs::read_to_string(path).expect("fixture");
    let params = override_consensus_with_dynamic_filter(false).params;
    let proto = ConsensusVersionView {
        err: None,
        version: CONSENSUS_V41.to_string(),
    };
    let mut scenarios = 0;
    for line in text.lines() {
        let sc: Value = serde_json::from_str(line).unwrap();
        let name = sc["name"].as_str().unwrap().to_string();
        let start = sc["start"].as_array().unwrap();
        let (_player, mut machine, mut helper) = setup_p(
            Round(start[0].as_u64().unwrap()),
            Period(start[1].as_u64().unwrap()),
            Step(start[2].as_u64().unwrap()),
            &params,
        );
        let mut payloads: HashMap<String, Proposal> = HashMap::new();
        let mut values: HashMap<String, ProposalValue> = HashMap::new();
        for (i, p) in sc["props"].as_array().unwrap().iter().enumerate() {
            let mut payload = make_random_proposal_payload(Round(p["round"].as_u64().unwrap()));
            // distinct blocks, so distinct proposal-values
            payload.unauthenticated_proposal.block.timestamp = i as i64 + 1;
            let n = p["name"].as_str().unwrap().to_string();
            values.insert(n.clone(), payload.unauthenticated_proposal.value());
            payloads.insert(n, payload);
        }
        let value_of = |prop: &str| values.get(prop).copied().unwrap_or(BOTTOM);
        let mut voter = 0;
        for (i, (step, want)) in sc["steps"]
            .as_array()
            .unwrap()
            .iter()
            .zip(sc["results"].as_array().unwrap())
            .enumerate()
        {
            let before = machine.trace().actions().count();
            let g = |k: &str| step[k].as_u64().unwrap_or(0);
            let prop = step["prop"].as_str().unwrap_or("");
            let msg = match step["op"].as_str().unwrap() {
                "vote" => {
                    let v = helper.make_verified_vote(
                        voter,
                        Round(g("round")),
                        Period(g("period")),
                        Step(g("step")),
                        value_of(prop),
                    );
                    voter += 1;
                    MessageEvent {
                        t: EventType::VoteVerified,
                        input: InternalMessage {
                            vote: Some(v.clone()),
                            unauthenticated_vote: v.to_unauthenticated(),
                            ..InternalMessage::default()
                        },
                        proto: proto.clone(),
                        ..MessageEvent::default()
                    }
                }
                "payload_present" => MessageEvent {
                    t: EventType::PayloadPresent,
                    input: InternalMessage {
                        unauthenticated_proposal: payloads[prop].unauthenticated_proposal.clone(),
                        message_handle: Some(std::sync::Arc::new("h".to_string())),
                        ..InternalMessage::default()
                    },
                    proto: proto.clone(),
                    ..MessageEvent::default()
                },
                "payload_verified" => {
                    let cancelled = step["cancelled"].as_bool().unwrap_or(false);
                    MessageEvent {
                        t: EventType::PayloadVerified,
                        input: InternalMessage {
                            // the verifier may leave the proposal empty on a
                            // cancelled result
                            proposal: (!cancelled).then(|| payloads[prop].clone()),
                            unauthenticated_proposal: payloads[prop]
                                .unauthenticated_proposal
                                .clone(),
                            ..InternalMessage::default()
                        },
                        cancelled,
                        err: cancelled.then(|| SerializableError::new("cancelled")),
                        proto: proto.clone(),
                        ..MessageEvent::default()
                    }
                }
                "bundle" => {
                    let b = helper.make_verified_bundle(
                        Round(g("round")),
                        Period(g("period")),
                        Step(g("step")),
                        value_of(prop),
                        &params,
                    );
                    MessageEvent {
                        t: EventType::BundleVerified,
                        input: InternalMessage {
                            verified_bundle_votes: b.votes.clone(),
                            unauthenticated_bundle: b.u.clone(),
                            ..InternalMessage::default()
                        },
                        proto: proto.clone(),
                        ..MessageEvent::default()
                    }
                }
                other => panic!("op {other}"),
            };
            machine
                .transition(Event::Message(msg))
                .unwrap_or_else(|e| panic!("{name} step {i}: {e}"));
            let got: Vec<String> = machine
                .trace()
                .actions()
                .skip(before)
                .filter_map(summarize)
                .collect();
            let want_actions: Vec<String> = want["actions"]
                .as_array()
                .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect())
                .unwrap_or_default();
            assert_eq!(got, want_actions, "{name} step {i} ({step}): actions");
            let p = machine.player();
            assert_eq!(
                (p.round.0, p.period.0, p.step.0),
                (
                    want["round"].as_u64().unwrap(),
                    want["period"].as_u64().unwrap(),
                    want["step"].as_u64().unwrap()
                ),
                "{name} step {i} ({step}): player"
            );
        }
        scenarios += 1;
    }
    assert!(scenarios >= 18, "fixture truncated: {scenarios}");
}
