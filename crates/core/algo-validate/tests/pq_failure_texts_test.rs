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

//! Post-quantum (Falcon-1024) signature failure texts on the pool path,
//! pinned to go-algorand v5.1.1-stable (issues #2438, #2546).
//!
//! `fixtures/pq_failure_texts.jsonl` is produced by
//! `tools/pq-failure-text-oracle/run-in-docker.sh`: go builds each
//! `SignedTxn` (top-level `pqsig` and PQ-delegated LogicSig) and runs it
//! through `verify.TxnGroup`, recording the error text of `SaltedKeySig.Verify` /
//! `VerifyFalcon1024` as wrapped by `stxnCoreChecks` /
//! `logicSigSanityCheckBatchPrep`, in full: go's `transaction <Summary> invalid : `
//! frame is stripped here and compared in `go_dump_test`. Each
//! case is decoded here from go's own bytes and verified the way the pool
//! does.

use algo_avm::group::GroupBudget;
use algo_error::AlgoError;
use algo_validate::{
    consensus_params_for_version, verify_transaction_group_cached, verify_transaction_signature,
    SpecialAddresses, VerificationContext, VerifiedTransactionCache,
};

const FIXTURE: &str = include_str!("fixtures/pq_failure_texts.jsonl");

fn pool_cases() -> Vec<serde_json::Value> {
    FIXTURE
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("fixture line is JSON"))
        .filter(|c| c["path"] == "pool")
        .collect()
}

fn text(e: AlgoError) -> String {
    match e {
        AlgoError::Validation { message } => message,
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[test]
fn pq_failure_texts_match_go_on_the_pool_path() {
    let cases = pool_cases();
    assert_eq!(cases.len(), 34, "fixture must carry every pool case");
    let mut mismatches = Vec::new();
    for case in &cases {
        let name = format!(
            "{} / {}",
            case["kind"].as_str().unwrap(),
            case["name"].as_str().unwrap()
        );
        let bytes = hex::decode(case["stxn"].as_str().unwrap()).unwrap();
        let group = algo_codec::decode_signed_txn_stream(&bytes).expect("go's SignedTxn decodes");
        assert_eq!(group.len(), 1, "{name}");
        let protocol = case["protocol"].as_str().unwrap();
        let consensus = consensus_params_for_version(protocol).expect("known protocol");
        // go's text is recorded in full; these functions return the reason
        // inside go's `transaction %+v invalid : ` frame, which the REST path
        // adds (`go_dump_test` pins the frame itself, issue #2451).
        let full = case["want"].as_str().unwrap();
        // go v5.1's frame is `transaction <SignedTxn.Summary()> invalid : `.
        let want = match full.find(" invalid : ") {
            Some(at) if full.starts_with("transaction ") && full[..at].contains(" from ") => {
                &full[at + " invalid : ".len()..]
            }
            _ => full,
        };
        assert_eq!(
            case["framed"].as_bool().unwrap(),
            want.len() != full.len(),
            "{name}"
        );

        let mut budget = GroupBudget::for_logicsig(1);
        let got = verify_transaction_signature(&group[0], &group, 0, &mut budget, &consensus)
            .err()
            .map(text)
            .unwrap_or_default();

        // The verified-group cache path (gossip / pool admission) must give
        // the same verdict and text.
        let context = VerificationContext {
            spec_addrs: SpecialAddresses::default(),
            consensus_version: protocol.to_string(),
        };
        let cache = VerifiedTransactionCache::new(16);
        let cached = verify_transaction_group_cached(&group, &context, &consensus, &cache)
            .err()
            .map(text)
            .unwrap_or_default();

        // go runs `logicSigGroupSizeCheck` for the whole group before any member's
        // signature: an `ls`-scheme proof's arguments are decoded there, so go's
        // text for such a case is the group check's. The member-level function
        // (`got`) reaches the scheme check first, as `saltedKeySigLogicSigVerify`
        // does; the group path (`cached`) is go's text.
        let member_text = if case["name"].as_str().unwrap() == "logicsig scheme not enabled" {
            "signature scheme not enabled"
        } else {
            want
        };
        if got != member_text || cached != want {
            mismatches.push(format!(
                "{name}:\n    go:     {want:?}\n    rust:   {got:?}\n    cached: {cached:?}"
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "PQ failure texts differ from go v5.1.1:\n{}",
        mismatches.join("\n")
    );
}
