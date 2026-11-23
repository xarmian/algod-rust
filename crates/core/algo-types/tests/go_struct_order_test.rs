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

//! `src/go_struct_order.json` (issue #2426): go's struct-from-array field
//! order, dumped from go's types by `tools/strict-decode-oracle` and checked
//! there against go's generated decoders. Every go type a reader names in
//! `rmp_decode::struct_keys` must be in it, and a few orders are pinned here
//! by hand from go's declarations.

use std::collections::BTreeMap;

fn schema() -> BTreeMap<String, Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Field {
        key: String,
    }
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/go_struct_order.json"
    ))
    .expect("go_struct_order.json");
    let all: BTreeMap<String, Vec<Field>> = serde_json::from_str(&text).expect("valid JSON");
    all.into_iter()
        .map(|(t, fs)| (t, fs.into_iter().map(|f| f.key).collect()))
        .collect()
}

/// Every go type the readers of this crate and of `algo-agreement` name: the
/// last string literal of a `struct_keys(..)` / `struct_keys_with(..)` call and
/// the one of a `Sch::Struct("<go type>", ..)`.
fn named_types() -> Vec<String> {
    let mut out = Vec::new();
    for dir in ["/src", "/../algo-agreement/src"] {
        for entry in std::fs::read_dir(format!("{}{dir}", env!("CARGO_MANIFEST_DIR"))).unwrap() {
            let path = entry.unwrap().path();
            // (`rmp_decode.rs` defines `struct_keys`; the readers call it)
            if path.extension().is_none_or(|e| e != "rs") || path.ends_with("rmp_decode.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for (needle, until) in [
                ("struct_keys(", ';'),
                ("struct_keys_with(", ';'),
                ("Sch::Struct(\"", ','),
            ] {
                let mut rest = text.as_str();
                while let Some(i) = rest.find(needle) {
                    rest = &rest[i + needle.len()..];
                    let call: String = rest.chars().take_while(|c| *c != until).collect();
                    let from = if needle.starts_with("Sch") {
                        // the literal ends at the quote before the comma
                        call.trim_end_matches('"').to_string()
                    } else {
                        // the last string literal of the call
                        match call.rfind('"') {
                            Some(end) => match call[..end].rfind('"') {
                                Some(start) => call[start + 1..end].to_string(),
                                None => continue,
                            },
                            None => continue,
                        }
                    };
                    out.push(from);
                }
            }
        }
    }
    out
}

#[test]
#[ignore = "Phase 26 carve-out: transactions.PQSig became SaltedKeySig; the decoders move with the SigScheme registry (#2546, go v5.1.0-beta)"]
fn every_named_go_type_is_in_the_schema() {
    let schema = schema();
    let named = named_types();
    assert!(named.len() >= 30, "found only {} readers", named.len());
    for t in named {
        assert!(
            schema.contains_key(&t),
            "{t} is not in go_struct_order.json"
        );
    }
}

#[test]
fn orders_follow_gos_declarations() {
    let s = schema();
    let keys = |t: &str| s[t].iter().map(String::as_str).collect::<Vec<_>>();
    // `SignedTxn`, then `ApplyData` (`ca aca rs rr rc dt caid apid`), flattened
    assert_eq!(
        keys("transactions.SignedTxnInBlock"),
        [
            "sig", "msig", "lsig", "pqsig", "txn", "sgnr", "ca", "aca", "rs", "rr", "rc", "dt",
            "caid", "apid", "hgi", "hgh"
        ]
    );
    assert_eq!(
        keys("transactions.SignedTxn"),
        ["sig", "msig", "lsig", "pqsig", "txn", "sgnr"]
    );
    assert_eq!(
        keys("transactions.ApplyData"),
        ["ca", "aca", "rs", "rr", "rc", "dt", "caid", "apid"]
    );
    assert_eq!(
        keys("transactions.EvalDelta"),
        ["gd", "ld", "sa", "lg", "itx"]
    );
    assert_eq!(keys("basics.StateSchema"), ["nui", "nbs"]);
    // the embedded Header, Keyreg, ... of a transaction are flattened in place
    let txn = keys("transactions.Transaction");
    assert_eq!(&txn[..5], ["type", "snd", "fee", "fv", "lv"]);
    assert_eq!(txn.len(), 49);
}
