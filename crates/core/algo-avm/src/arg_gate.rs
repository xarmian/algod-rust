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

//! go's argument gate (`EvalContext.step`, `data/transactions/logic/eval.go`):
//! before an opcode runs, and before its cost is charged, go checks the stack
//! height (`stack underflow in <op>`) and then every argument from argument 0
//! upward (`<op> arg <i> wanted <T> but got <U>`), from the opcode's `proto`
//! argument types (`opcodes.go`).
//!
//! algod-rust's opcode handlers pop lazily from the top, which reports the
//! wrong argument (the top one) and charges the cost first. The table
//! (`arg_gate_table.rs`, GENERATED from go's own `proto` tables by
//! `scripts/gen_arg_gate_table.py`; the `go_op_protos.jsonl` fixture is dumped
//! by `tools/avm-op-protos`) lets `AvmMachine::step` run go's gate before
//! dispatch. It lists every opcode go gates the same way in every run mode.
//! Mode-restricted opcodes keep their own handling (go checks the mode before
//! the gate). A row is go's own type list, so it can only make an error exact:
//! any error the gate raises, go raises too. Issue #2200, #2225.

/// go's name of a uint64 value / argument type (`StackType.String()`).
pub(crate) const UINT64_NAME: &str = "uint64";
/// go's name of a byte-string value / argument type.
pub(crate) const BYTES_NAME: &str = "[]byte";

/// What the gate compares: go's `opCompat(argType.AVMType, value type)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ArgKind {
    Uint,
    Bytes,
    Any,
}

impl ArgKind {
    /// go's AVM type name (`uint64`, `[]byte`, `any`): the one mapping, shared
    /// with `AvmValue::type_name`.
    #[cfg(test)]
    pub(crate) fn type_name(self) -> &'static str {
        match self {
            ArgKind::Uint => UINT64_NAME,
            ArgKind::Bytes => BYTES_NAME,
            ArgKind::Any => "any",
        }
    }
}

/// An argument type of go's `proto`: the AVM type the gate compares and the
/// `StackType.String()` name go prints in `wanted <name>` (`bigint`,
/// `[32]byte`, `boxName`, ...).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct ArgType {
    kind: ArgKind,
    name: &'static str,
}

impl ArgType {
    const fn new(kind: ArgKind, name: &'static str) -> Self {
        Self { kind, name }
    }

    /// go's `StackType.String()` for the type an argument wants.
    pub(crate) fn name(self) -> &'static str {
        self.name
    }

    #[cfg(test)]
    pub(crate) fn kind(self) -> ArgKind {
        self.kind
    }
}

pub(crate) const UINT: ArgType = ArgType::new(ArgKind::Uint, UINT64_NAME);
pub(crate) const BYTES: ArgType = ArgType::new(ArgKind::Bytes, BYTES_NAME);
pub(crate) const ANY: ArgType = ArgType::new(ArgKind::Any, "any");
pub(crate) const BIGINT: ArgType = ArgType::new(ArgKind::Bytes, "bigint");
pub(crate) const BYTES32: ArgType = ArgType::new(ArgKind::Bytes, "[32]byte");
pub(crate) const BYTES33: ArgType = ArgType::new(ArgKind::Bytes, "[33]byte");
pub(crate) const BYTES64: ArgType = ArgType::new(ArgKind::Bytes, "[64]byte");
pub(crate) const BYTES80: ArgType = ArgType::new(ArgKind::Bytes, "[80]byte");
pub(crate) const BYTES1793: ArgType = ArgType::new(ArgKind::Bytes, "[1793]byte");

/// Whether `value` satisfies go's `opCompat` for an argument of type `want`.
#[inline(always)]
pub(crate) fn accepts(want: ArgType, value: &crate::machine::AvmValue) -> bool {
    use crate::machine::AvmValue;
    match want.kind {
        ArgKind::Any => true,
        ArgKind::Uint => matches!(value, AvmValue::Uint64(_)),
        ArgKind::Bytes => matches!(value, AvmValue::Bytes(_)),
    }
}

/// Whether go lets the opcode run in `mode` for a program of `version`: go
/// checks the mode set of the PROGRAM's version before the argument gate
/// (`ed25519verify` is LogicSig-only before v5). Opcodes whose mode set never
/// changes are not in the table (their own mode handling applies).
#[inline(always)]
pub(crate) fn mode_allows(opcode: u8, version: u8, mode: crate::machine::ExecMode) -> bool {
    let Some(steps) = crate::arg_gate_table::MODE_VARIANTS[opcode as usize] else {
        return true;
    };
    let bit = match mode {
        crate::machine::ExecMode::LogicSig => 1,
        crate::machine::ExecMode::Application => 2,
    };
    let modes = steps
        .iter()
        .rev()
        .find(|(from, _)| *from <= version)
        .map_or(0, |(_, modes)| *modes);
    modes & bit != 0
}

/// go's argument types for the single-byte opcode `opcode`, if this table
/// lists it (for the newest spec: see [`gate_for`] for a program's version).
#[inline]
pub(crate) fn arg_types(opcode: u8) -> Option<&'static [ArgType]> {
    crate::arg_gate_table::TABLE[opcode as usize]
}

/// The argument types go gates `opcode` with in a program of `version`: the
/// table row, unless go's spec for the opcode changed after that version (then
/// the older spec is not in the table and the opcode keeps its lazy pops).
#[inline(always)]
pub(crate) fn gate_for(opcode: u8, version: u8) -> Option<&'static [ArgType]> {
    if version < crate::arg_gate_table::MIN_VERSION[opcode as usize] {
        return None;
    }
    arg_types(opcode)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One line of `tests/fixtures/go_op_protos.jsonl` (go's `proto` dump).
    #[derive(serde::Deserialize)]
    struct GoOp {
        opcode: u8,
        name: String,
        version: u64,
        modes: u8,
        stable: bool,
        #[serde(default)]
        variants: Vec<GoVariant>,
        args: Vec<GoArg>,
    }

    #[derive(serde::Deserialize)]
    struct GoVariant {
        from: u8,
        modes: u8,
    }

    #[derive(serde::Deserialize)]
    struct GoArg {
        avm: String,
        name: String,
    }

    /// The shared exclusion list (`tests/fixtures/arg_gate_exclusions.json`,
    /// also read by the generator): `(gate_excluded, version_exceptions)`.
    fn exclusions() -> (Vec<u8>, Vec<u8>) {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/arg_gate_exclusions.json"))
                .expect("exclusions json");
        let bytes = |key: &str| -> Vec<u8> {
            v[key]
                .as_object()
                .expect("object")
                .keys()
                .map(|k| u8::from_str_radix(k.trim_start_matches("0x"), 16).expect("byte"))
                .collect()
        };
        (bytes("gate_excluded"), bytes("version_exceptions"))
    }

    fn go_ops() -> Vec<GoOp> {
        include_str!("../tests/fixtures/go_op_protos.jsonl")
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("fixture line"))
            .collect()
    }

    /// The table is exactly go's: every opcode byte go gates the same way in
    /// every mode has a row with go's type list (kind and printed name), and
    /// no other byte has one. The fixture is go-algorand v5.0.4-stable's own
    /// `proto` data, so a wrong or missing row fails here.
    #[test]
    fn the_table_equals_gos_proto_arguments() {
        let ops = go_ops();
        let (gate_excluded, _) = exclusions();
        let mut seen = std::collections::HashSet::new();
        for op in &ops {
            let shared = ops.iter().filter(|o| o.opcode == op.opcode).count() > 1;
            let gated = op.modes == 3
                && !op.args.is_empty()
                && !shared
                && !gate_excluded.contains(&op.opcode);
            let row = arg_types(op.opcode);
            if !gated {
                assert!(
                    row.is_none(),
                    "0x{:02x} {} is mode-restricted, argument-less or shared by a prefix family: no row",
                    op.opcode,
                    op.name
                );
                continue;
            }
            seen.insert(op.opcode);
            let row = row.unwrap_or_else(|| panic!("0x{:02x} {} has no row", op.opcode, op.name));
            let want: Vec<(&str, &str)> = op
                .args
                .iter()
                .map(|a| (a.avm.as_str(), a.name.as_str()))
                .collect();
            let have: Vec<(&str, &str)> = row
                .iter()
                .map(|t| (t.kind().type_name(), t.name()))
                .collect();
            assert_eq!(have, want, "0x{:02x} {}", op.opcode, op.name);
            // Gated from the version go's FINAL spec starts at (0 = always).
            let want_min = op
                .variants
                .last()
                .filter(|_| !op.stable)
                .map_or(0, |v| v.from);
            assert_eq!(
                crate::arg_gate_table::MIN_VERSION[op.opcode as usize],
                want_min,
                "0x{:02x} {}: first gated version",
                op.opcode,
                op.name
            );
        }
        for byte in 0..=255u8 {
            if arg_types(byte).is_some() {
                assert!(
                    seen.contains(&byte),
                    "row for 0x{byte:02x} is not in go's table"
                );
            }
        }
        assert!(seen.len() >= 100, "the gate covers {} opcodes", seen.len());
    }

    /// Every gate row belongs to an opcode algod-rust defines: a row for an
    /// undefined byte would be dead data (or hide a typo in the fixture).
    #[test]
    fn every_row_names_a_defined_opcode() {
        for byte in 0..=255u8 {
            if arg_types(byte).is_some() {
                crate::opcode::lookup(byte)
                    .unwrap_or_else(|| panic!("gate row for undefined opcode 0x{byte:02x}"));
            }
        }
    }

    /// algod-rust registers every go opcode under go's name and at go's
    /// version (one byte at a time: prefix families, whose leaves share a
    /// byte, are checked by the family tests). A version gap would make
    /// algod-rust accept programs go rejects, or the reverse; the named
    /// `version_exceptions` of the shared exclusion list are the only bytes not
    /// compared.
    #[test]
    fn every_go_opcode_is_registered_at_gos_name_and_version() {
        let ops = go_ops();
        let (_, version_exceptions) = exclusions();
        for op in &ops {
            if ops.iter().filter(|o| o.opcode == op.opcode).count() > 1 {
                continue;
            }
            if version_exceptions.contains(&op.opcode) {
                continue;
            }
            let spec = crate::opcode::lookup(op.opcode)
                .unwrap_or_else(|| panic!("0x{:02x} {} is not registered", op.opcode, op.name));
            assert_eq!(spec.name, op.name, "0x{:02x}", op.opcode);
            assert_eq!(
                u64::from(spec.version),
                op.version,
                "0x{:02x} {}: go introduces it at version {}",
                op.opcode,
                op.name,
                op.version
            );
        }
    }

    /// A gate row longer than what the handler pops could reject stacks the
    /// handler accepts. Wherever the opcode table states the handler's pop
    /// count it equals the row's length. The opcodes whose pop count is
    /// dynamic (`-1`: the depth or the label count is an immediate) cannot be
    /// compared; they are named here so a change is noticed, and for each of
    /// them go's `proto` is ONE `any` argument, which is never more than the
    /// handler needs (an immediate of 0 still needs one value).
    #[test]
    fn gate_rows_agree_with_the_handlers_pop_counts() {
        let mut dynamic = Vec::new();
        for byte in 0..=255u8 {
            let Some(row) = arg_types(byte) else { continue };
            let spec = crate::opcode::lookup(byte).expect("defined");
            if spec.stack_pops < 0 {
                assert_eq!(row.len(), 1, "0x{byte:02x} {}", spec.name);
                dynamic.push(spec.name);
                continue;
            }
            assert_eq!(
                row.len(),
                spec.stack_pops as usize,
                "0x{byte:02x} {}: go's proto has {} arguments, the handler pops {}",
                spec.name,
                row.len(),
                spec.stack_pops
            );
        }
        assert_eq!(
            dynamic,
            ["dig", "cover", "uncover", "match"],
            "opcodes with a dynamic pop count"
        );
    }

    /// Every algod-rust opcode that pops values has a gate row or a NAMED,
    /// deliberate exclusion: go gates it per run mode (`modes != 3`), or it is
    /// in `EXCLUDED`. A new opcode (or a mode change) fails here until it is
    /// classified, instead of silently keeping the lazy pop order.
    #[test]
    fn every_opcode_with_pops_has_a_row_or_a_named_exclusion() {
        let ops = go_ops();
        let (gate_excluded, _) = exclusions();
        for byte in 0..=255u8 {
            let Some(spec) = crate::opcode::lookup(byte) else {
                continue;
            };
            if spec.sub_ops.is_some() || spec.stack_pops <= 0 || arg_types(byte).is_some() {
                continue;
            }
            let go = ops
                .iter()
                .find(|o| o.opcode == byte)
                .unwrap_or_else(|| panic!("0x{byte:02x} {} is not a go opcode", spec.name));
            // Mode-restricted, or its mode set changes between versions
            // (`MODE_VARIANTS` gives it a version-dependent mode check), or
            // named in the shared exclusion list.
            let mode_restricted = go.modes != 3 || !go.stable;
            assert!(
                mode_restricted || gate_excluded.contains(&byte),
                "0x{byte:02x} {} pops {} but has no gate row and no named exclusion",
                spec.name,
                spec.stack_pops
            );
        }
    }

    /// The version-dependent mode table is exactly go's: one entry per opcode
    /// whose mode set differs between versions, with go's steps.
    #[test]
    fn mode_variants_equal_gos() {
        let mut seen = std::collections::HashSet::new();
        for op in go_ops() {
            if op.stable {
                continue;
            }
            let mut steps: Vec<(u8, u8)> = op.variants.iter().map(|v| (v.from, v.modes)).collect();
            let differs = steps.iter().any(|(_, m)| *m != steps[0].1);
            if !differs {
                assert!(
                    crate::arg_gate_table::MODE_VARIANTS[op.opcode as usize].is_none(),
                    "0x{:02x} {}: only its argument types vary",
                    op.opcode,
                    op.name
                );
                continue;
            }
            seen.insert(op.opcode);
            let have = crate::arg_gate_table::MODE_VARIANTS[op.opcode as usize]
                .unwrap_or_else(|| panic!("0x{:02x} {} has no mode variants", op.opcode, op.name));
            steps.sort_unstable();
            assert_eq!(have.to_vec(), steps, "0x{:02x} {}", op.opcode, op.name);
        }
        for byte in 0..=255u8 {
            if crate::arg_gate_table::MODE_VARIANTS[byte as usize].is_some() {
                assert!(seen.contains(&byte), "mode variants for 0x{byte:02x}");
            }
        }
        assert!(
            seen.contains(&0x04),
            "ed25519verify is LogicSig-only before v5"
        );
    }

    /// An opcode whose go spec changed between versions is gated from the
    /// version its final spec starts at: `ed25519verify` from v5.
    #[test]
    fn a_late_stable_opcode_is_gated_from_its_final_specs_version() {
        for version in 1..=4u8 {
            assert!(gate_for(0x04, version).is_none(), "v{version}");
        }
        for version in 5..=13u8 {
            assert_eq!(
                gate_for(0x04, version).map(<[ArgType]>::len),
                Some(3),
                "v{version}"
            );
        }
        // An always-stable opcode is gated in every version.
        assert!(gate_for(0x08, 1).is_some());
    }
}
