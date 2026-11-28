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

//! Issue #2543: the whole `config.Consensus` table of go-algorand
//! `v5.1.1-stable` (every version, every `ConsensusParams` field), dumped by
//! `tools/consensus-table-oracle`, must equal algod-rust's built-in table.
//!
//! Two checks:
//! * every field *name* go marshals is a field algod-rust models
//!   (`ConsensusParamsOverride` ignores unknown keys, so without this a
//!   go-only field would be silently dropped);
//! * loading the go table through the `consensus.json` path
//!   (`parse_consensus_overrides` + `merge_consensus_protocols`) yields, for
//!   every version go knows, exactly `consensus_params_for_version`.
//!
//! go-removed fields (`PQSchemeEnabled`, `PQSigEnabled`,
//! `PQSchemeFeeContribution` were methods, never struct fields) do not
//! appear in the dump.

use std::collections::{BTreeSet, HashMap};

use algo_types::consensus::{
    built_in_consensus_protocols, merge_consensus_protocols, parse_consensus_overrides,
    ConsensusParamsOverride, HISTORICAL_APPROVED_UPGRADES, KNOWN_PROTOCOL_VERSIONS,
};

const GO_TABLE: &str = include_str!("fixtures/go_consensus_table.json");

#[test]
fn every_go_consensus_field_is_modelled() {
    let table: serde_json::Value = serde_json::from_str(GO_TABLE).unwrap();
    let ours = serde_json::to_value(ConsensusParamsOverride::default()).unwrap();
    let ours: BTreeSet<&String> = ours.as_object().unwrap().keys().collect();
    let mut go_keys = BTreeSet::new();
    for params in table.as_object().unwrap().values() {
        go_keys.extend(params.as_object().unwrap().keys().cloned());
    }
    // `ApplyData` (v14+) and `TxnCounter` (v17+) are historical block-format
    // flags go still carries; algod-rust's block codec always accepts both
    // (they are true in every version from v14/v17 on, including every version
    // a v5.1.1 node can validate), so there is nothing to gate on.
    let missing: Vec<&String> = go_keys
        .iter()
        .filter(|k| !ours.contains(k) && !["ApplyData", "TxnCounter"].contains(&k.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "go fields algod-rust does not model: {missing:?}"
    );
    // go v5.1.1's new fields are among them.
    for k in [
        "AllowGroupedHeartbeats",
        "EnableSigSchemeFalcon512",
        "EnableSigSchemeEd25519",
        "EnableSigSchemeLogicSig",
        "RequireLogicSigArgAccess",
        "DiscardFailedInnerClearStateDelta",
        "EnablePQSchemeFalcon1024",
    ] {
        assert!(go_keys.contains(k), "{k} missing from the go dump");
    }
}

#[test]
fn go_consensus_table_equals_the_built_in_table() {
    let go_versions: BTreeSet<String> =
        serde_json::from_str::<HashMap<String, serde_json::Value>>(GO_TABLE)
            .unwrap()
            .into_keys()
            .collect();
    let known: BTreeSet<String> = KNOWN_PROTOCOL_VERSIONS
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(go_versions, known, "version sets differ");

    let from_go =
        merge_consensus_protocols(HashMap::new(), parse_consensus_overrides(GO_TABLE).unwrap());
    let built_in = built_in_consensus_protocols();
    let go_raw: HashMap<String, serde_json::Value> = serde_json::from_str(GO_TABLE).unwrap();
    // Fields compared separately or not comparable through this path:
    // * `approved_upgrade` models one live edge of go's `ApprovedUpgrades`
    //   map (see `HISTORICAL_APPROVED_UPGRADES`); checked below.
    // * `enable_fee_pooling`, `enable_logicsig_size_pooling`: go deleted both
    //   struct fields once permanently on, so a go dump carries no key and the
    //   override loader defaults them to true (`DefaultTrue`); algod-rust's
    //   built-in table keeps the historical per-version value.
    const SKIP: [&str; 4] = [
        "approved_upgrade",
        "enable_fee_pooling",
        "enable_logicsig_size_pooling",
        "support_signed_txn_in_block",
    ];
    let mut bad = Vec::new();
    for v in &go_versions {
        let (gd, bd) = (
            field_map(&format!("{:?}", from_go[v])),
            field_map(&format!("{:?}", built_in[v])),
        );
        let keys: BTreeSet<&String> = gd.keys().chain(bd.keys()).collect();
        for k in keys {
            if SKIP.contains(&k.as_str()) {
                continue;
            }
            if gd.get(k) != bd.get(k) {
                bad.push(format!(
                    "{v}: {k}: go {:?} / rust {:?}",
                    gd.get(k),
                    bd.get(k)
                ));
            }
        }
        if let Some((target, delay)) = built_in[v].approved_upgrade {
            let edge = go_raw[v]["ApprovedUpgrades"][target].as_u64();
            if edge != Some(delay) {
                bad.push(format!(
                    "{v}: approved_upgrade ({target}, {delay}) not in go's map ({edge:?})"
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} differences:
{}",
        bad.len(),
        bad.join(
            "
"
        )
    );
}

/// Every non-alpha/fnet `vN.ApprovedUpgrades[vM]` edge of go's table is in
/// `HISTORICAL_APPROVED_UPGRADES` with the same delay, and vice versa.
#[test]
fn go_approved_upgrade_edges_equal_the_historical_table() {
    let go_raw: HashMap<String, serde_json::Value> = serde_json::from_str(GO_TABLE).unwrap();
    let mut go_edges = BTreeSet::new();
    for (from, p) in &go_raw {
        if from.starts_with("alpha") || from.starts_with("fnet") || from == "future" {
            continue;
        }
        for (to, d) in p["ApprovedUpgrades"].as_object().into_iter().flatten() {
            go_edges.insert((from.clone(), to.clone(), d.as_u64().unwrap()));
        }
    }
    let ours: BTreeSet<(String, String, u64)> = HISTORICAL_APPROVED_UPGRADES
        .iter()
        .map(|(a, b, d)| (a.to_string(), b.to_string(), *d))
        .collect();
    assert_eq!(go_edges, ours);
}

/// Splits a derived-`Debug` struct into `field -> value` (values may contain
/// ", " inside tuples/vectors, so a token that is not `ident: ...` continues
/// the previous value).
fn field_map(debug: &str) -> HashMap<String, String> {
    let body = debug
        .trim_start_matches("ConsensusParams { ")
        .trim_end_matches(" }");
    let mut out: Vec<(String, String)> = Vec::new();
    for tok in body.split(", ") {
        let is_field = tok.split_once(": ").is_some_and(|(k, _)| {
            !k.is_empty()
                && k.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        });
        if is_field {
            let (k, v) = tok.split_once(": ").unwrap();
            out.push((k.to_string(), v.to_string()));
        } else if let Some(last) = out.last_mut() {
            last.1.push_str(", ");
            last.1.push_str(tok);
        }
    }
    out.into_iter().collect()
}

/// `docker/config/vfuture-consensus.json` (the `tools/vfuture-consensus-override`
/// output the mixed-cluster and wire tests load) is go v5.1.1's `future`
/// entry except for the one field the tool overrides (issue #2543: it was
/// still the v5.0.5 shape, `LogicSigVersion` 13 without the SigScheme flags and
/// the `MaxAbsolute*` raises, which a `consensus.json` replaces wholesale and
/// go enforces as 0 when absent).
#[test]
fn vfuture_override_fixture_is_go_future_except_the_block_size() {
    let table: serde_json::Value = serde_json::from_str(GO_TABLE).unwrap();
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../docker/config/vfuture-consensus.json"
    ))
    .unwrap();
    let mut go_future = table["future"].clone();
    go_future["MaxTxnBytesPerBlock"] = serde_json::json!(4096);
    assert_eq!(fixture["future"], go_future);
}
