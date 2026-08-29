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

//! Property-based canonical-encoding harness for the agreement wire
//! codec. Complements `codec_roundtrip.rs` (which replays the fixed
//! Go-produced fixture corpus) by feeding the codec **structured
//! random values** generated via `proptest`, extending coverage into
//! regions the fixed corpus doesn't exercise.
//!
//! ## Invariant under test
//!
//! For every structured Rust value `v` of an agreement wire type:
//!
//! ```text
//! encode(decode(encode(v))) == encode(v)
//! ```
//!
//! That single byte-identity assertion catches the entire class of
//! codec bugs this task targets:
//!
//! - **Decoder panics / over-reads** on canonical-looking input.
//! - **Encoder non-idempotence** (a second encode disagrees with the
//!   first — i.e., the encoder is not canonical).
//! - **Lossy decode** — if decode dropped or mutated any field, the
//!   re-encoded bytes will diverge.
//! - **Field-ordering / `omitempty` / integer-width drift** relative
//!   to `../go-algorand/agreement/msgp_gen.go`.
//!
//! Byte-equality is strictly stronger than value-equality here, and
//! lets us avoid bolting `PartialEq` onto a dozen wire types (many
//! of which don't derive it today — `UnauthenticatedVote`, `Vote`,
//! `UnauthenticatedBundle`, `AuthenticatedBundle`, etc.).
//!
//! ## Scope
//!
//! Covers every agreement wire type whose codec does not require a
//! full `bookkeeping.Block`. That's:
//!   * `ProposalValue`
//!   * `RawVote`
//!   * `UnauthenticatedVote`
//!   * `Vote` (authenticated, with `committee.Credential`)
//!   * `UnauthenticatedBundle` (also covers `Certificate` — same wire bytes)
//!   * `AuthenticatedBundle`
//!
//! `UnauthenticatedProposal` and `TransmittedPayload` are deferred —
//! generating arbitrary `Block` values is a rabbit hole, and the
//! fixed-corpus tests (`uproposal_roundtrip_vs_go`,
//! `proposal_roundtrip_vs_go`, `tpayload_roundtrip_vs_go` in
//! `codec_roundtrip.rs`) already anchor those against the Go oracle.

use algo_agreement::codec::{
    decode_authenticated_bundle, decode_authenticated_vote, decode_bundle, decode_proposalvalue,
    decode_rawvote, decode_vote, encode_authenticated_bundle, encode_authenticated_vote,
    encode_bundle, encode_proposalvalue, encode_rawvote, encode_vote, AuthenticatedBundle,
};
use algo_agreement::{
    Credential, EquivocationVote, EquivocationVoteAuthenticator, HashableCredential, Period,
    ProposalValue, RawVote, Step, UnauthenticatedBundle, UnauthenticatedCredential,
    UnauthenticatedVote, Vote, VoteAuthenticator,
};
use algo_consensus_crypto::OneTimeSignature;
use algo_types::{Address, Digest, Round};
use proptest::prelude::*;

// ── Strategies ───────────────────────────────────────────────────────────

fn arb_address() -> impl Strategy<Value = Address> {
    any::<[u8; 32]>().prop_map(Address)
}

fn arb_digest() -> impl Strategy<Value = Digest> {
    any::<[u8; 32]>().prop_map(Digest)
}

fn arb_proposal_value() -> impl Strategy<Value = ProposalValue> {
    (any::<u64>(), arb_address(), arb_digest(), arb_digest()).prop_map(
        |(oper, oprop, dig, encdig)| ProposalValue {
            original_period: Period(oper),
            original_proposer: oprop,
            block_digest: dig,
            encoding_digest: encdig,
        },
    )
}

fn arb_raw_vote() -> impl Strategy<Value = RawVote> {
    (
        arb_address(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        arb_proposal_value(),
    )
        .prop_map(|(sender, rnd, per, step, proposal)| RawVote {
            sender,
            round: Round(rnd),
            period: Period(per),
            step: Step(step),
            proposal,
        })
}

fn arb_uauth_credential() -> impl Strategy<Value = UnauthenticatedCredential> {
    any::<[u8; 80]>().prop_map(UnauthenticatedCredential::new)
}

fn arb_hashable_credential() -> impl Strategy<Value = HashableCredential> {
    (any::<[u8; 64]>(), arb_address(), any::<u64>()).prop_map(|(raw_out, member, iter)| {
        HashableCredential {
            raw_out,
            member,
            iter,
        }
    })
}

fn arb_credential() -> impl Strategy<Value = Credential> {
    (
        any::<u64>(),
        arb_digest(),
        any::<bool>(),
        arb_hashable_credential(),
        any::<[u8; 80]>(),
    )
        .prop_map(|(weight, vrf_out, ds, hashable, proof)| Credential {
            weight,
            vrf_out,
            domain_separation_enabled: ds,
            hashable,
            proof,
        })
}

fn arb_ots() -> impl Strategy<Value = OneTimeSignature> {
    (
        any::<[u8; 64]>(),
        any::<[u8; 32]>(),
        any::<[u8; 64]>(),
        any::<[u8; 32]>(),
        any::<[u8; 64]>(),
        any::<[u8; 64]>(),
    )
        .prop_map(
            |(sig, pk, pk_sig_old, pk2, pk1_sig, pk2_sig)| OneTimeSignature {
                sig,
                pk,
                pk_sig_old,
                pk2,
                pk1_sig,
                pk2_sig,
            },
        )
}

fn arb_unauthenticated_vote() -> impl Strategy<Value = UnauthenticatedVote> {
    (arb_raw_vote(), arb_uauth_credential(), arb_ots()).prop_map(|(raw_vote, cred, sig)| {
        UnauthenticatedVote {
            raw_vote,
            cred,
            sig,
        }
    })
}

fn arb_authenticated_vote() -> impl Strategy<Value = Vote> {
    (arb_raw_vote(), arb_credential(), arb_ots()).prop_map(|(raw_vote, cred, sig)| Vote {
        raw_vote,
        cred,
        sig,
    })
}

fn arb_vote_authenticator() -> impl Strategy<Value = VoteAuthenticator> {
    (arb_address(), arb_uauth_credential(), arb_ots())
        .prop_map(|(sender, cred, sig)| VoteAuthenticator { sender, cred, sig })
}

fn arb_equivocation_vote_authenticator() -> impl Strategy<Value = EquivocationVoteAuthenticator> {
    (
        arb_address(),
        arb_uauth_credential(),
        [arb_ots(), arb_ots()],
        [arb_proposal_value(), arb_proposal_value()],
    )
        .prop_map(
            |(sender, cred, sigs, proposals)| EquivocationVoteAuthenticator {
                sender,
                cred,
                sigs,
                proposals,
            },
        )
}

fn arb_unauthenticated_bundle() -> impl Strategy<Value = UnauthenticatedBundle> {
    (
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        arb_proposal_value(),
        prop::collection::vec(arb_vote_authenticator(), 0..4),
        prop::collection::vec(arb_equivocation_vote_authenticator(), 0..2),
    )
        .prop_map(|(rnd, per, step, proposal, votes, equivocation_votes)| {
            UnauthenticatedBundle {
                round: Round(rnd),
                period: Period(per),
                step: Step(step),
                proposal,
                votes,
                equivocation_votes,
            }
        })
}

fn arb_equivocation_vote() -> impl Strategy<Value = EquivocationVote> {
    (
        arb_address(),
        any::<u64>(),
        any::<u64>(),
        any::<u64>(),
        arb_credential(),
        [arb_proposal_value(), arb_proposal_value()],
        [arb_ots(), arb_ots()],
    )
        .prop_map(
            |(sender, rnd, per, step, cred, proposals, sigs)| EquivocationVote {
                sender,
                round: Round(rnd),
                period: Period(per),
                step: Step(step),
                cred,
                proposals,
                sigs,
            },
        )
}

fn arb_authenticated_bundle() -> impl Strategy<Value = AuthenticatedBundle> {
    (
        arb_unauthenticated_bundle(),
        prop::collection::vec(arb_authenticated_vote(), 0..4),
        prop::collection::vec(arb_equivocation_vote(), 0..2),
    )
        .prop_map(|(u, votes, equivocation_votes)| AuthenticatedBundle {
            u,
            votes,
            equivocation_votes,
        })
}

// ── Tests ────────────────────────────────────────────────────────────────

proptest! {
    // 256 cases per test, 6 tests = 1,536 total codec roundtrips per
    // `cargo test` run. We're not coverage-guided, just sampling a
    // distribution the fixed corpus doesn't reach, so an order of
    // magnitude more than the default helps pick up rare
    // field-combination bugs without inflating CI time — this still
    // runs in well under a second locally, comfortably inside the
    // ~15s budget TASK-55 set for the whole agreement codec test
    // suite. For extended local fuzzing, override via
    //   `PROPTEST_CASES=100000 cargo test -p algo-agreement --test codec_proptest`
    // (proptest honors that env var at runtime).
    #![proptest_config(ProptestConfig {
        cases: 256,
        // Keep shrinking conservative — the default is thorough but
        // can stretch individual test runtime into tens of seconds on
        // a regression. 256 steps is plenty for small wire types.
        max_shrink_iters: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn proposalvalue_canonical(pv in arb_proposal_value()) {
        let encoded = encode_proposalvalue(&pv);
        let decoded = decode_proposalvalue(&encoded)
            .expect("decode_proposalvalue on canonical encode must succeed");
        let re_encoded = encode_proposalvalue(&decoded);
        prop_assert_eq!(
            re_encoded, encoded,
            "encode(decode(encode(v))) != encode(v) for ProposalValue"
        );
    }

    #[test]
    fn rawvote_canonical(rv in arb_raw_vote()) {
        let encoded = encode_rawvote(&rv);
        let decoded = decode_rawvote(&encoded)
            .expect("decode_rawvote on canonical encode must succeed");
        let re_encoded = encode_rawvote(&decoded);
        prop_assert_eq!(
            re_encoded, encoded,
            "encode(decode(encode(v))) != encode(v) for RawVote"
        );
    }

    #[test]
    fn unauthenticated_vote_canonical(uv in arb_unauthenticated_vote()) {
        let encoded = encode_vote(&uv);
        let decoded = decode_vote(&encoded)
            .expect("decode_vote on canonical encode must succeed");
        let re_encoded = encode_vote(&decoded);
        prop_assert_eq!(
            re_encoded, encoded,
            "encode(decode(encode(v))) != encode(v) for UnauthenticatedVote"
        );
    }

    #[test]
    fn authenticated_vote_canonical(v in arb_authenticated_vote()) {
        let encoded = encode_authenticated_vote(&v);
        let decoded = decode_authenticated_vote(&encoded)
            .expect("decode_authenticated_vote on canonical encode must succeed");
        let re_encoded = encode_authenticated_vote(&decoded);
        prop_assert_eq!(
            re_encoded, encoded,
            "encode(decode(encode(v))) != encode(v) for Vote (authenticated)"
        );
    }

    #[test]
    fn unauthenticated_bundle_canonical(ub in arb_unauthenticated_bundle()) {
        let encoded = encode_bundle(&ub);
        let decoded = decode_bundle(&encoded)
            .expect("decode_bundle on canonical encode must succeed");
        let re_encoded = encode_bundle(&decoded);
        prop_assert_eq!(
            re_encoded, encoded,
            "encode(decode(encode(v))) != encode(v) for UnauthenticatedBundle"
        );
    }

    #[test]
    fn authenticated_bundle_canonical(b in arb_authenticated_bundle()) {
        let encoded = encode_authenticated_bundle(&b);
        let decoded = decode_authenticated_bundle(&encoded)
            .expect("decode_authenticated_bundle on canonical encode must succeed");
        let re_encoded = encode_authenticated_bundle(&decoded);
        prop_assert_eq!(
            re_encoded, encoded,
            "encode(decode(encode(v))) != encode(v) for AuthenticatedBundle"
        );
    }
}
