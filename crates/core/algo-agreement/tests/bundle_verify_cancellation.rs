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

//! Issue #2145 review: an invalid bundle must not cost the node more than a
//! bounded amount of verification work, and the answer must still be the
//! error of the first failing vote in bundle order.
//!
//! This test counts verifications through a process-global counter, so it
//! lives in its own test binary and runs its cases sequentially in one test.

use std::sync::atomic::Ordering;

use algo_agreement::{UnauthenticatedBundle, CERT, VOTE_VERIFY_RUNS};

#[path = "support/bundle_fixture.rs"]
mod fixture;
use fixture::*;

/// Upper bound on the verifications an invalid bundle may start: one wave
/// of work (twice the verifier pool size, capped at 16 by default).
const MAX_WASTE: usize = 16;

fn runs_for(b: &UnauthenticatedBundle, l: &TestLedger) -> (String, usize) {
    let before = VOTE_VERIFY_RUNS.load(Ordering::SeqCst);
    let res = format!("{:?}", b.verify(l));
    (res, VOTE_VERIFY_RUNS.load(Ordering::SeqCst) - before)
}

#[test]
fn invalid_bundles_stop_early_and_report_the_first_failure() {
    let voters = pool(60);
    let l = ledger(&voters);
    let p = proposal(0x11);

    // 1. A forged first vote among 60: bounded work, same error as the
    //    sequential reference.
    let mut b = bundle(&voters, CERT, p);
    b.votes[0].sig.sig[0] ^= 1;
    let (res, runs) = runs_for(&b, &l);
    assert_eq!(res, format!("{:?}", b.verify_reference_sequential(&l)));
    assert!(res.contains("index: 0"), "{res}");
    assert!(
        runs <= MAX_WASTE,
        "{runs} verifications for a bad first vote"
    );

    // 2. Two bad votes: the lower index wins no matter which finishes first.
    let mut b = bundle(&voters, CERT, p);
    b.votes[3].sig.sig[0] ^= 1;
    b.votes[40].sig.sig[0] ^= 1;
    let (res, runs) = runs_for(&b, &l);
    assert_eq!(res, format!("{:?}", b.verify_reference_sequential(&l)));
    assert!(res.contains("index: 3"), "{res}");
    assert!(runs <= MAX_WASTE, "{runs} verifications");

    // 3. A forged first plain vote plus many equivocation votes: the
    //    equivocation voters are never even looked up.
    let mut b = bundle(&voters[..10], CERT, p);
    for v in &voters[10..40] {
        b.equivocation_votes
            .push(equivocation(v, CERT, p, proposal(0x33)));
    }
    b.votes[0].sig.sig[0] ^= 1;
    l.lookups.lock().unwrap().clear();
    let (res, runs) = runs_for(&b, &l);
    // snapshot before the reference runs (it looks everything up)
    let looked_up = l.lookups.lock().unwrap().clone();
    assert_eq!(res, format!("{:?}", b.verify_reference_sequential(&l)));
    assert!(res.contains("index: 0"), "{res}");
    assert!(runs <= MAX_WASTE, "{runs} verifications");
    let eq_addrs: Vec<_> = voters[10..40].iter().map(|v| v.addr).collect();
    assert!(
        !looked_up.iter().any(|a| eq_addrs.contains(a)),
        "equivocation voters looked up although a plain vote had failed"
    );
}
