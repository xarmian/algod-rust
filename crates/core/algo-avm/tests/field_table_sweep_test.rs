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

//! Whole-table completeness/invariant sweep for the AVM field enums
//! (`global`, `txn`/`itxn_field`, `asset_params_get`, `app_params_get`/
//! `app_params_set`, `acct_params_get`, `block`).
//!
//! Mirrors, structurally, go-algorand's per-field-table whole-sweep tests in
//! `data/transactions/logic/fields_test.go` (`TestGlobalVersionsAndTypes`,
//! `TestTxnFieldVersions`, `TestITxnFieldVersions`,
//! `TestAssetParamsFieldsVersions`, `TestAppParamsGetFieldsVersions`,
//! `TestAppParamsSetFieldsVersions`, `TestAcctParamsFieldsVersions`,
//! `TestBlockFieldsVersions`) and `backwardCompat_test.go`
//! (`TestBackwardCompatGlobalFields`, `TestBackwardCompatTxnFields`). Those
//! go tests are full assembler+evaluator round trips (assemble at every
//! version, run, check the rejection message); algod-rust already has
//! per-field `version_gate_*`/`test_*_field_version_*` tests exercising that
//! same assembler/eval path for the fields that matter most (see
//! `crates/core/algo-avm/src/ops/*.rs`). What's missing -- and what this
//! file adds -- is the *whole-table* structural half: every field's version
//! metadata, swept across the complete enum at once, so a newly-added field
//! that is individually correct but breaks a cross-cutting invariant (an
//! out-of-range version, or a field settable before it is even readable)
//! doesn't slip through unnoticed.

use algo_avm::fields::{
    AcctParamsField, AppParamsField, AssetParamsField, BlockField, GlobalField, TxnField,
};
use algo_avm::opcode::MAX_AVM_VERSION;

/// Decode every byte 0..=255 through `from_u8`, returning `(index, version)`
/// for every index the enum actually defines. Field enums are declared with
/// sequential values starting at 0 (see `field_enum!` in `fields.rs`), so
/// this is the field-table analogue of `opcode_table_sweep_test.rs`'s
/// `all_named_opcode_versions`.
fn field_versions<T>(
    decode: impl Fn(u8) -> Option<T>,
    version: impl Fn(&T) -> u8,
) -> Vec<(u8, u8)> {
    (0u16..=255)
        .filter_map(|byte| decode(byte as u8).map(|f| (byte as u8, version(&f))))
        .collect()
}

/// A field table must define a contiguous range of indices `0..N` with no
/// gaps -- go-algorand's `*FieldSpecs` arrays are indexed positionally with
/// no holes, and `field_enum!` mirrors that by construction, but a manual
/// edit could still skip a discriminant by mistake. Also asserts each
/// field's *read* version lies in the valid `0..=MAX_AVM_VERSION` range: `0`
/// is a legitimate value here (go-algorand's `fieldSpec.version == 0` means
/// "no gate, available since the very first AVM version", e.g.
/// `GlobalField::MinTxnFee`/`TxnField::Sender`), distinct from the separate
/// `set_version`/`itx_version` axis where `0` instead means "never
/// settable".
fn check_contiguous_and_versioned(entries: &[(u8, u8)]) -> Result<(), String> {
    if entries.is_empty() {
        return Err("field table is empty".to_string());
    }
    for (i, &(idx, version)) in entries.iter().enumerate() {
        if idx as usize != i {
            return Err(format!(
                "field table has a gap: expected index {i}, found {idx}"
            ));
        }
        if version > MAX_AVM_VERSION {
            return Err(format!(
                "field {idx} has out-of-range version {version} (must be 0..={MAX_AVM_VERSION})"
            ));
        }
    }
    Ok(())
}

/// A field that is settable (non-zero `set_version`/`itx_version`) must not
/// become settable *before* it is even readable -- mirrors the ordering
/// go-algorand's `appParamsFieldSpecs`/`txnFieldSpecs` tables maintain by
/// construction (`setVersion`/`itxVersion` >= `version` whenever nonzero).
fn check_set_not_before_get(entries: &[(u8, u8, u8)]) -> Result<(), String> {
    for &(idx, get_version, set_version) in entries {
        if set_version != 0 && set_version < get_version {
            return Err(format!(
                "field {idx} is settable at v{set_version} but only readable from v{get_version}"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TDD: the checkers themselves must catch a synthetic regression first.
// ---------------------------------------------------------------------------

#[test]
fn contiguity_checker_catches_synthetic_gap() {
    assert!(check_contiguous_and_versioned(&[(0, 1), (1, 2), (2, 3)]).is_ok());

    // Index 1 is missing -- the kind of typo that could slip into a
    // hand-maintained match arm without a whole-table sweep to catch it.
    let broken = [(0u8, 1u8), (2, 3)];
    let err = check_contiguous_and_versioned(&broken).expect_err("must catch the gap");
    assert!(err.contains("gap"), "unexpected error: {err}");
}

#[test]
fn contiguity_checker_catches_out_of_range_version() {
    // 0 is a legitimate "no gate, available since v1" read-version -- must
    // NOT be flagged.
    assert!(check_contiguous_and_versioned(&[(0u8, 0u8)]).is_ok());

    let broken = [(0u8, MAX_AVM_VERSION + 1)];
    let err = check_contiguous_and_versioned(&broken).expect_err("must catch bad version");
    assert!(err.contains("out-of-range"), "unexpected error: {err}");
}

#[test]
fn set_not_before_get_checker_catches_synthetic_regression() {
    assert!(check_set_not_before_get(&[(0, 5, 0), (1, 5, 5), (2, 5, 7)]).is_ok());

    // A field claiming to be settable at v4 while only readable from v5 --
    // structurally impossible (you can't set a field you can't yet name).
    let broken = [(0u8, 5u8, 4u8)];
    let err = check_set_not_before_get(&broken).expect_err("must catch the inversion");
    assert!(err.contains("settable"), "unexpected error: {err}");
}

// ---------------------------------------------------------------------------
// Real-table sweeps
// ---------------------------------------------------------------------------

#[test]
fn global_field_table_is_contiguous_and_versioned() {
    let entries = field_versions(|b| GlobalField::from_u8(b).ok(), GlobalField::version);
    check_contiguous_and_versioned(&entries).expect("GlobalField table");
}

#[test]
fn txn_field_table_is_contiguous_and_versioned() {
    let entries = field_versions(|b| TxnField::from_u8(b).ok(), TxnField::version);
    check_contiguous_and_versioned(&entries).expect("TxnField table");
}

#[test]
fn asset_params_field_table_is_contiguous_and_versioned() {
    let entries = field_versions(
        |b| AssetParamsField::from_u8(b).ok(),
        AssetParamsField::version,
    );
    check_contiguous_and_versioned(&entries).expect("AssetParamsField table");
}

#[test]
fn app_params_field_table_is_contiguous_and_versioned() {
    let entries = field_versions(|b| AppParamsField::from_u8(b).ok(), AppParamsField::version);
    check_contiguous_and_versioned(&entries).expect("AppParamsField table");
}

#[test]
fn acct_params_field_table_is_contiguous_and_versioned() {
    let entries = field_versions(
        |b| AcctParamsField::from_u8(b).ok(),
        AcctParamsField::version,
    );
    check_contiguous_and_versioned(&entries).expect("AcctParamsField table");
}

#[test]
fn block_field_table_is_contiguous_and_versioned() {
    let entries = field_versions(|b| BlockField::from_u8(b).ok(), BlockField::version);
    check_contiguous_and_versioned(&entries).expect("BlockField table");
}

/// Mirrors `TestITxnFieldVersions`: every `TxnField` with a nonzero
/// `itx_version` (settable via `itxn_field`) must not be settable before it
/// is readable via `txn`/`gtxn`.
#[test]
fn txn_field_itx_version_never_precedes_read_version() {
    let entries: Vec<(u8, u8, u8)> = (0u16..=255)
        .filter_map(|b| {
            TxnField::from_u8(b as u8)
                .ok()
                .map(|f| (b as u8, f.version(), f.itx_version()))
        })
        .collect();
    assert!(!entries.is_empty());
    check_set_not_before_get(&entries).expect("TxnField itx_version ordering");
}

/// Mirrors `TestAppParamsSetFieldsVersions`: every `AppParamsField` with a
/// nonzero `set_version` (settable via `app_params_set`) must not be
/// settable before it is readable via `app_params_get`.
#[test]
fn app_params_field_set_version_never_precedes_get_version() {
    let entries: Vec<(u8, u8, u8)> = (0u16..=255)
        .filter_map(|b| {
            AppParamsField::from_u8(b as u8)
                .ok()
                .map(|f| (b as u8, f.version(), f.set_version()))
        })
        .collect();
    assert!(!entries.is_empty());
    check_set_not_before_get(&entries).expect("AppParamsField set_version ordering");

    // At least one field must actually be settable, or this sweep would
    // pass vacuously (mirrors go's TestAppParamsSetFieldsVersions, which
    // iterates every appParamsFieldSpecs entry and exercises the `setVersion
    // == 0` "not settable" branch for most of them, but the feature only
    // means something if some field is genuinely settable).
    let any_settable = (0u16..=255).any(|b| {
        AppParamsField::from_u8(b as u8)
            .map(|f| f.set_version() > 0)
            .unwrap_or(false)
    });
    assert!(
        any_settable,
        "expected at least one AppParamsField to be settable via app_params_set"
    );
}
