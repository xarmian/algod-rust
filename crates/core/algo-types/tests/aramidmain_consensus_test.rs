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

//! The vendored aramidmain `consensus.json` (issue #2070): custom protocol
//! names (`aramidmain-v1.0/1..3`, not URL-shaped) must load through the same
//! `ConsensusProtocols.Merge` path go-algorand uses, and every field the file
//! sets must be a field algod-rust models (none silently dropped).

use std::collections::{BTreeSet, HashMap};

use algo_types::consensus::{
    built_in_consensus_protocols, merge_consensus_protocols, parse_consensus_overrides,
    preload_consensus_protocols_with_bundle, ConsensusParamsOverride,
};

const BUNDLE: &str = include_str!("../../../../bin/algod-rust/consensus/aramidmain-consensus.json");

/// Fields go-algorand's own struct no longer has (removed once permanently
/// on, so go ignores them while decoding this file) or that algod-rust treats
/// as unconditionally on (`ApplyData`, `TxnCounter` exist in go v5.0.4 but are
/// on in every protocol this node targets). The aramidmain protocols must set
/// each of them to `true`/zero so ignoring them is behaviour-preserving.
const GO_REMOVED_OR_ALWAYS_ON: &[&str] = &[
    "ApplyData",
    "TxnCounter",
    "EnableAccountDataResourceSeparation",
    "EnableBatchVerification",
    "EnableExtraPagesOnAppUpdate",
    "EnableOnlineAccountCatchpoints",
    "CompactCertRounds",
    "CompactCertSecKQ",
    "CompactCertTopVoters",
    "CompactCertVotersLookback",
    "CompactCertWeightThreshold",
];

#[test]
fn every_aramidmain_field_is_modelled_or_permanently_on() {
    let known: BTreeSet<String> =
        match serde_json::to_value(ConsensusParamsOverride::default()).unwrap() {
            serde_json::Value::Object(m) => m.keys().cloned().collect(),
            _ => unreachable!(),
        };
    let raw: HashMap<String, serde_json::Map<String, serde_json::Value>> =
        serde_json::from_str(BUNDLE).unwrap();
    let mut unknown = BTreeSet::new();
    for (proto, fields) in raw.iter().filter(|(p, _)| p.starts_with("aramidmain-")) {
        for (k, v) in fields {
            if known.contains(k) {
                continue;
            }
            if GO_REMOVED_OR_ALWAYS_ON.contains(&k.as_str()) {
                let ok = matches!(v, serde_json::Value::Bool(true)) || v.as_u64() == Some(0);
                assert!(ok, "{proto}: {k}={v} is ignored but not on/zero");
            } else {
                unknown.insert(format!("{proto}: {k}"));
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "consensus.json fields not modelled by ConsensusParamsOverride: {unknown:#?}"
    );
}

#[test]
fn custom_protocols_merge_like_go() {
    let merged = merge_consensus_protocols(
        built_in_consensus_protocols(),
        parse_consensus_overrides(BUNDLE).unwrap(),
    );
    for n in 1..=3 {
        assert!(merged.contains_key(&format!("aramidmain-v1.0/{n}")), "/{n}");
    }
    let p1 = &merged["aramidmain-v1.0/1"];
    assert_eq!(p1.approved_upgrade, Some(("aramidmain-v1.0/2", 10000)));
    assert_eq!(p1.logic_sig_version, 6);
    let p2 = &merged["aramidmain-v1.0/2"];
    assert_eq!(p2.approved_upgrade, Some(("aramidmain-v1.0/3", 1000)));
    assert_eq!(p2.logic_sig_version, 10);
    assert_eq!(p2.state_proof_interval, 256);
    let p3 = &merged["aramidmain-v1.0/3"];
    assert_eq!(p3.approved_upgrade, None);
    assert_eq!(p3.logic_sig_version, 12);
    assert_eq!(p3.max_app_txn_accounts, 8);
    assert_eq!(p3.max_app_access, 16);
    assert!(p3.payouts_enabled && p3.enable_app_versioning);
    assert_eq!(p3.payouts_max_balance, 70_000_000_000_000);
    // fee pooling is absent from /3 but must stay on (DefaultTrue).
    assert!(p3.enable_fee_pooling);
}

/// The file also redefines the standard versions with stale (older-go)
/// definitions, e.g. `future`. The bundle must only supply protocols the
/// binary does not already define (DIV-006), leaving built-ins untouched.
#[test]
fn bundle_adds_only_unknown_protocols() {
    let base = built_in_consensus_protocols();
    let merged = preload_consensus_protocols_with_bundle(None, base.clone(), Some(BUNDLE)).unwrap();
    for (k, v) in &base {
        assert_eq!(merged.get(k), Some(v), "built-in {k} must be untouched");
    }
    let mut added: Vec<_> = merged.keys().filter(|k| !base.contains_key(*k)).collect();
    added.sort();
    assert_eq!(
        added,
        [
            "aramidmain-v1.0/1",
            "aramidmain-v1.0/2",
            "aramidmain-v1.0/3"
        ]
    );
}

/// A `<data_dir>/consensus.json` is merged after the bundle and wins per
/// protocol version, wholesale like go.
#[test]
fn skipped_bundle_protocols_are_reported() {
    let base = built_in_consensus_protocols();
    let skipped = algo_types::consensus::bundled_protocols_already_defined(&base, BUNDLE);
    assert!(skipped.contains(&"future".to_string()), "{skipped:?}");
    assert!(!skipped.iter().any(|v| v.starts_with("aramidmain-")));
}

#[test]
fn data_dir_file_overrides_bundle() {
    let dir = std::env::temp_dir().join(format!("aramid-consensus-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut o = parse_consensus_overrides(BUNDLE).unwrap();
    o.retain(|k, _| k == "aramidmain-v1.0/3");
    o.get_mut("aramidmain-v1.0/3").unwrap().min_txn_fee = 4242;
    algo_types::consensus::save_configurable_consensus(&dir, &o).unwrap();
    let merged = preload_consensus_protocols_with_bundle(
        Some(&dir),
        built_in_consensus_protocols(),
        Some(BUNDLE),
    )
    .unwrap();
    assert_eq!(merged["aramidmain-v1.0/3"].min_txn_fee, 4242);
    assert_eq!(merged["aramidmain-v1.0/2"].min_txn_fee, 1000);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A block header whose `proto`/`upgradeprop` are custom (non-URL)
/// protocol names decodes to exactly those strings.
#[test]
fn custom_protocol_block_header_decodes() {
    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 3).unwrap();
    rmp::encode::write_str(&mut buf, "proto").unwrap();
    rmp::encode::write_str(&mut buf, "aramidmain-v1.0/2").unwrap();
    rmp::encode::write_str(&mut buf, "nextproto").unwrap();
    rmp::encode::write_str(&mut buf, "aramidmain-v1.0/3").unwrap();
    rmp::encode::write_str(&mut buf, "rnd").unwrap();
    rmp::encode::write_uint(&mut buf, 7).unwrap();
    let h = algo_types::BlockHeader::decode_from_bytes(&buf).expect("decode");
    assert_eq!(h.current_protocol, "aramidmain-v1.0/2");
    assert_eq!(h.round, algo_types::Round(7));
}
