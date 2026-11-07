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

/// What the gate compares: go's `opCompat(argType.AVMType, value type)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ArgKind {
    Uint,
    Bytes,
    Any,
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

pub(crate) const UINT: ArgType = ArgType::new(ArgKind::Uint, "uint64");
pub(crate) const BYTES: ArgType = ArgType::new(ArgKind::Bytes, "[]byte");
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

/// go's argument types for the single-byte opcode `opcode`, if this table
/// lists it.
#[inline]
pub(crate) fn arg_types(opcode: u8) -> Option<&'static [ArgType]> {
    crate::arg_gate_table::TABLE[opcode as usize]
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
        args: Vec<GoArg>,
    }

    #[derive(serde::Deserialize)]
    struct GoArg {
        avm: String,
        name: String,
    }

    /// Opcodes go gates that the table deliberately leaves out (see
    /// `EXCLUDED` in `scripts/gen_arg_gate_table.py`).
    const EXCLUDED: &[u8] = &[0x07];

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
        let mut seen = std::collections::HashSet::new();
        for op in &ops {
            let shared = ops.iter().filter(|o| o.opcode == op.opcode).count() > 1;
            let gated =
                op.modes == 3 && !op.args.is_empty() && !shared && !EXCLUDED.contains(&op.opcode);
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
                .map(|t| {
                    let kind = match t.kind() {
                        ArgKind::Uint => "uint64",
                        ArgKind::Bytes => "[]byte",
                        ArgKind::Any => "any",
                    };
                    (kind, t.name())
                })
                .collect();
            assert_eq!(have, want, "0x{:02x} {}", op.opcode, op.name);
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

    /// Opcodes whose registered version is deliberately not compared with go's
    /// (named, with a neutral reason): `0x86` (version registration under
    /// review).
    const VERSION_UNDER_REVIEW: &[u8] = &[0x86];

    /// algod-rust registers every go opcode under go's name and at go's
    /// version (one byte at a time: prefix families, whose leaves share a
    /// byte, are checked by the family tests). A version gap would make
    /// algod-rust accept programs go rejects, or the reverse; the named
    /// exceptions in `VERSION_UNDER_REVIEW` are the only bytes not compared.
    #[test]
    fn every_go_opcode_is_registered_at_gos_name_and_version() {
        let ops = go_ops();
        for op in &ops {
            if ops.iter().filter(|o| o.opcode == op.opcode).count() > 1 {
                continue;
            }
            if VERSION_UNDER_REVIEW.contains(&op.opcode) {
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
            let mode_restricted = go.modes != 3;
            assert!(
                mode_restricted || EXCLUDED.contains(&byte),
                "0x{byte:02x} {} pops {} but has no gate row and no named exclusion",
                spec.name,
                spec.stack_pops
            );
        }
    }
}
