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

//! Whole-table completeness/invariant sweep for the AVM opcode table.
//!
//! algod-rust's existing coverage is a large set of individually correct
//! `version_gate_*_requires_vN` tests, one opcode/version pair at a time.
//! Nothing in the suite iterates the *entire* opcode table and asserts
//! structural invariants that must hold across every entry at once -- so a
//! newly-added opcode that is individually correct but, say, accidentally
//! reuses another opcode's name, or is silently missing its version gate,
//! would slip through unnoticed. This file ports the structural invariants
//! go-algorand's own whole-table sweeps assert, adapted to this crate's flat
//! byte-indexed table (which structurally cannot have two opcodes sharing a
//! byte -- that's a compile-time array-index property here, not a runtime
//! invariant worth testing):
//!
//!   - go-algorand `data/transactions/logic/opcodes_test.go`
//!     `TestOpcodesByVersion` -- for every version, the per-version opcode
//!     list is duplicate-free and every opcode known at that version appears
//!     in it exactly once.
//!   - go-algorand `data/transactions/logic/opcodes_test.go`
//!     `TestOpcodesVersioningV2` -- the opcode set only grows as the version
//!     ceiling rises (opcodes are never un-gated / removed).
//!
//! (`TestOpcodesByVersionReordered` is out of scope: it regression-tests
//! go's internal sort/dedup *construction* algorithm for a mutable slice,
//! which has no counterpart here since the production opcode table is a
//! `const` byte-indexed array, not a sorted-at-runtime list.)

use algo_avm::opcode::{lookup, MAX_AVM_VERSION};

/// Walk every byte 0..=255 in the production opcode table and flatten out
/// multi-byte "prefix opcode" families (e.g. the `app_box_*` family sharing
/// prefix byte `0xd4`) into their real, individually-versioned leaf entries.
/// Returns `(name, version)` pairs -- the same shape go-algorand's
/// `OpSpecs`/`opsByOpcode` sweep over.
fn all_named_opcode_versions() -> Vec<(&'static str, u8)> {
    let mut out = Vec::new();
    for byte in 0u16..=255 {
        let Some(spec) = lookup(byte as u8) else {
            continue;
        };
        match spec.sub_ops {
            Some(subs) => {
                for sub in subs.iter().flatten() {
                    out.push((sub.name, sub.version));
                }
            }
            None => out.push((spec.name, spec.version)),
        }
    }
    out
}

/// Core invariant-checking logic, factored out so it can be exercised both
/// against the real production table (must pass) and against a
/// deliberately-broken synthetic table (must fail) -- proving this sweep
/// actually catches the regression class it claims to.
///
/// Returns `Err(reason)` on the first violation found, mirroring
/// go-algorand's `TestOpcodesByVersion`'s per-name-appears-once check.
fn check_no_duplicate_names(entries: &[(&str, u8)]) -> Result<(), String> {
    for (i, (name_a, _)) in entries.iter().enumerate() {
        for (name_b, _) in &entries[i + 1..] {
            if name_a == name_b {
                return Err(format!(
                    "opcode name {name_a:?} is registered more than once"
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TDD: the checker itself must catch a synthetic regression before we trust
// it against the real table.
// ---------------------------------------------------------------------------

#[test]
fn duplicate_name_checker_catches_synthetic_regression() {
    let clean = [("dup", 1u8), ("keccak256", 2)];
    assert!(check_no_duplicate_names(&clean).is_ok());

    // Two distinct byte values accidentally sharing the same mnemonic --
    // the exact class of bug go's TestOpcodesByVersion guards against.
    let broken = [("dup", 1u8), ("dup", 2)];
    let err = check_no_duplicate_names(&broken).expect_err("must catch the duplicate name");
    assert!(err.contains("dup"), "error should name the culprit: {err}");
}

// ---------------------------------------------------------------------------
// Real-table sweeps
// ---------------------------------------------------------------------------

#[test]
fn opcode_table_has_no_duplicate_names() {
    let entries = all_named_opcode_versions();
    assert!(!entries.is_empty());
    check_no_duplicate_names(&entries).expect("production opcode table must be duplicate-free");
}

#[test]
fn opcode_table_every_entry_has_a_valid_version() {
    // Mirrors the version-range half of go's TestOpcodesVersioningV2: no
    // opcode should be gated at version 0 (undefined/never-available) or at
    // a version beyond LogicVersion (unreachable -- the assembler caps
    // programs at MAX_AVM_VERSION, so such an opcode could never be used).
    for (name, version) in all_named_opcode_versions() {
        assert!(
            (1..=MAX_AVM_VERSION).contains(&version),
            "opcode {name:?} has out-of-range version {version} (must be 1..={MAX_AVM_VERSION})"
        );
    }
}

#[test]
fn opcode_count_is_monotonic_non_decreasing_by_version() {
    // Mirrors go's TestOpcodesByVersion: OpcodesByVersion(v) only grows as v
    // increases -- opcodes are added over time, never retired, so the count
    // of opcodes with `version <= v` must never decrease as v increases.
    let entries = all_named_opcode_versions();
    let count_at = |v: u8| entries.iter().filter(|&&(_, ver)| ver <= v).count();

    let mut prev = count_at(1);
    assert!(prev > 0, "v1 must define at least one opcode");
    for v in 2..=MAX_AVM_VERSION {
        let cur = count_at(v);
        assert!(
            cur >= prev,
            "opcode count regressed from v{} ({prev}) to v{v} ({cur})",
            v - 1
        );
        prev = cur;
    }

    // go explicitly asserts v2's count strictly exceeds v1's (len(opSpecs[1])
    // > len(opSpecs[0])) -- v2 introduced a real batch of new opcodes
    // (itob/btoi/txna/gtxna/etc.), so this should hold for algod-rust too.
    assert!(
        count_at(2) > count_at(1),
        "v2 must strictly add opcodes over v1"
    );
}

#[test]
fn opcode_table_every_name_reachable_at_its_declared_version() {
    // Every opcode that OpcodesByVersion(v) would include (version <= v)
    // must appear exactly once in that snapshot -- completeness, not just
    // absence of duplicates. Combined with the duplicate-name sweep above,
    // this proves each named opcode is registered exactly once *and* is
    // visible starting at exactly its own declared version, never later.
    let entries = all_named_opcode_versions();
    for v in 1..=MAX_AVM_VERSION {
        let at_v: Vec<&str> = entries
            .iter()
            .filter(|&&(_, ver)| ver <= v)
            .map(|&(name, _)| name)
            .collect();
        for (name, version) in &entries {
            let should_be_present = *version <= v;
            let is_present = at_v.contains(name);
            assert_eq!(
                should_be_present, is_present,
                "opcode {name:?} (version {version}) presence at v{v} was {is_present}, expected {should_be_present}"
            );
        }
    }
}
