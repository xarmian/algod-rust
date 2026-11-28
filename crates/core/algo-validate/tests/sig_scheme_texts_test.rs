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

//! Every signature scheme (`f1`, `f5`, `ed`, `ls`) of go-algorand v5.1.1-stable
//! under the `future` protocol, pinned to go (issue #2546).
//!
//! `fixtures/sig_scheme_texts.jsonl` is produced by
//! `tools/sig-scheme-text-oracle`: go builds, per scheme and per variant of the
//! envelope, a `SignedTxn` (top-level `pqsig`, and for the key schemes a
//! delegated LogicSig), runs it through `verify.TxnGroup` and records the
//! go-encoded bytes with the full error text. Each case is decoded here from
//! go's bytes, must re-encode byte for byte, and must give go's verdict and
//! text through the verified-group path (go's `verify.TxnGroup`) and the same
//! verdict and text through the per-transaction path.

use algo_avm::group::GroupBudget;
use algo_error::AlgoError;
use algo_validate::{
    consensus_params_for_version, verify_member_reason, verify_transaction_group_cached,
    verify_transaction_signature, SpecialAddresses, VerificationContext, VerifiedTransactionCache,
};

const FIXTURE: &str = include_str!("fixtures/sig_scheme_texts.jsonl");

/// go's reason for a member's failure (the `<err>` of its frame).
fn text(stx: &algo_types::SignedTransaction, e: AlgoError) -> String {
    verify_member_reason(stx, &e)
}

/// go's `transaction <Summary> invalid : <reason>` frame, stripped.
fn unframed(full: &str) -> &str {
    match full.find(" invalid : ") {
        Some(at) if full.starts_with("transaction ") && full[..at].contains(" from ") => {
            &full[at + " invalid : ".len()..]
        }
        _ => full,
    }
}

#[test]
fn sig_scheme_cases_match_go_on_the_pool_path() {
    let cases: Vec<serde_json::Value> = FIXTURE
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("fixture line is JSON"))
        .collect();
    assert_eq!(cases.len(), 90, "fixture must carry every case");

    let mut mismatches = Vec::new();
    let mut accepted = 0;
    for case in &cases {
        let name = format!(
            "{} {} / {}",
            case["scheme"].as_str().unwrap(),
            case["kind"].as_str().unwrap(),
            case["name"].as_str().unwrap()
        );
        let bytes = hex::decode(case["stxn"].as_str().unwrap()).unwrap();
        let group = algo_codec::decode_signed_txn_stream(&bytes).expect("go's SignedTxn decodes");
        assert_eq!(group.len(), 1, "{name}");
        // The wire form is byte-exact: go's encoding re-encodes unchanged.
        assert_eq!(
            hex::encode(algo_codec::canonical_encode_signed_transaction(&group[0])),
            case["stxn"].as_str().unwrap(),
            "{name}: re-encoding differs from go's bytes"
        );

        let protocol = case["protocol"].as_str().unwrap();
        let consensus = consensus_params_for_version(protocol).expect("known protocol");
        let full = case["want"].as_str().unwrap();
        let want = unframed(full);
        assert_eq!(
            case["framed"].as_bool().unwrap(),
            want.len() != full.len(),
            "{name}"
        );
        if full.is_empty() {
            accepted += 1;
        }

        let mut budget = GroupBudget::for_logicsig(1);
        let got = verify_transaction_signature(&group[0], &group, 0, &mut budget, &consensus)
            .err()
            .map(|e| text(&group[0], e))
            .unwrap_or_default();

        let context = VerificationContext {
            spec_addrs: SpecialAddresses::default(),
            consensus_version: protocol.to_string(),
        };
        let cache = VerifiedTransactionCache::new(16);
        let cached = verify_transaction_group_cached(&group, &context, &consensus, &cache)
            .err()
            .map(|e| text(&group[0], e))
            .unwrap_or_default();

        if cached != want || got != want {
            mismatches.push(format!(
                "{name}:\n    go:     {want:?}\n    rust:   {got:?}\n    cached: {cached:?}"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} cases differ from go v5.1.1:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
    assert_eq!(
        accepted, 7,
        "go accepts the six valid key-scheme cases and the valid ls case"
    );
}
