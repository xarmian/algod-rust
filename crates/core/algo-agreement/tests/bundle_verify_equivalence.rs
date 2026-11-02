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

//! Differential test for issue #2145: `UnauthenticatedBundle::verify`
//! (parallel vote verification) must accept and reject exactly the same
//! bundles, with exactly the same error, as the original strictly
//! sequential implementation kept as
//! `UnauthenticatedBundle::verify_reference_sequential`.
//!
//! The bundles hold real votes: real one-time signatures and real VRF
//! credentials that win sortition against the test ledger. A seeded
//! mutation generator then flips signature / credential bits, swaps
//! senders, drops, duplicates and reorders votes, adds unknown voters and
//! equivocation pairs, breaks ledger lookups and changes the claimed
//! proposal, round and step. Every case must give identical results.

use algo_agreement::{UnauthenticatedBundle, UnauthenticatedCredential, CERT, SOFT};
use algo_types::{Address, Round};

#[path = "support/bundle_fixture.rs"]
mod fixture;
use fixture::*;

/// Both implementations, rendered so errors and verified bundles compare
/// field for field (`Bundle`/`BundleError` have no `PartialEq`).
fn both(b: &UnauthenticatedBundle, l: &TestLedger) -> (String, String) {
    let new = format!("{:?}", b.verify(l));
    let old = format!("{:?}", b.verify_reference_sequential(l));
    (new, old)
}

#[test]
fn parallel_verify_matches_sequential_reference_on_real_and_mutated_bundles() {
    let voters = pool(12);
    let good_ledger = ledger(&voters);
    let p = proposal(0x11);
    let base = bundle(&voters, CERT, p);

    // The unmutated bundle really is valid, so the Ok path is exercised.
    let (new, old) = both(&base, &good_ledger);
    assert!(new.starts_with("Ok("), "baseline must verify: {new}");
    assert_eq!(new, old);

    let mut rng = Rng(0x2145);
    let mut ok_cases = 1;
    let mut err_cases = 0;
    for case in 0..48 {
        let mut b = base.clone();
        let mut l = ledger(&voters);
        let which = case % 16;
        let i = rng.below(b.votes.len().max(1));
        match which {
            0 => {} // untouched
            1 => b.votes[i].sig.sig[rng.below(64)] ^= 1 << rng.below(8),
            2 => b.votes[i].sig.pk2_sig[rng.below(64)] ^= 1 << rng.below(8),
            3 => {
                b.votes[i].cred = UnauthenticatedCredential::new({
                    let mut pr;
                    pr = b.votes[i].cred.proof;
                    pr[rng.below(80)] ^= 1 << rng.below(8);
                    pr
                })
            }
            4 => {
                // a vote claiming another voter's address
                let j = (i + 1) % b.votes.len();
                b.votes[i].sender = b.votes[j].sender;
            }
            5 => {
                // drop a random run of votes (quorum may fail)
                let n = 1 + rng.below(6);
                for _ in 0..n {
                    let k = rng.below(b.votes.len());
                    b.votes.remove(k);
                }
            }
            6 => {
                let dup = b.votes[i].clone();
                b.votes.push(dup);
            }
            7 => {
                // unknown voter appended
                let mut extra = b.votes[0].clone();
                extra.sender = Address([0xEE; 32]);
                b.votes.push(extra);
            }
            8 => b.proposal = proposal(0x22),
            9 => b.round = Round(ROUND + 1),
            10 => b.step = SOFT,
            11 => {
                // reorder: the failing index must follow the new order
                b.votes.reverse();
                b.votes[i].sig.sig[0] ^= 1;
            }
            12 => {
                // a valid equivocation pair for voter 0, who also appears
                // as a plain vote -> duplicate voter
                b.equivocation_votes
                    .push(equivocation(&voters[0], CERT, p, proposal(0x33)));
            }
            13 => {
                // genuine equivocation by a voter removed from the votes
                let who = b.votes.remove(i).sender;
                let v = voters.iter().find(|v| v.addr == who).unwrap();
                b.equivocation_votes
                    .push(equivocation(v, CERT, p, proposal(0x44)));
                if rng.below(2) == 0 {
                    b.equivocation_votes[0].sigs[1].sig[3] ^= 1;
                }
            }
            14 => {
                let who = b.votes[i].sender;
                match rng.below(3) {
                    0 => {
                        l.fail_lookup.insert(who);
                    }
                    1 => l.fail_circulation = true,
                    _ => l.fail_seed = true,
                }
            }
            _ => {
                // two bad votes: the lowest index must win
                let a = rng.below(b.votes.len());
                let c = rng.below(b.votes.len());
                b.votes[a].sig.sig[1] ^= 4;
                b.votes[c].sig.pk1_sig[2] ^= 8;
            }
        }
        let (new, old) = both(&b, &l);
        assert_eq!(new, old, "case {case} (mutation {which})");
        if new.starts_with("Ok(") {
            ok_cases += 1;
        } else {
            err_cases += 1;
        }
    }
    assert!(
        ok_cases >= 2 && err_cases >= 20,
        "ok={ok_cases} err={err_cases}"
    );
}

/// Small and degenerate shapes: empty bundle, one vote, equivocation-only.
#[test]
fn parallel_verify_matches_reference_on_degenerate_shapes() {
    let voters = pool(12);
    let l = ledger(&voters);
    let p = proposal(0x11);
    for n in [0usize, 1, 2, 3] {
        let b = bundle(&voters[..n], CERT, p);
        let (new, old) = both(&b, &l);
        assert_eq!(new, old, "{n} votes");
    }
    let mut b = bundle(&[], CERT, p);
    b.equivocation_votes
        .push(equivocation(&voters[0], CERT, p, proposal(0x33)));
    let (new, old) = both(&b, &l);
    assert_eq!(new, old, "equivocation only");
}
