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

//! go's static check of a program (`logic.CheckSignature` /
//! `logic.CheckContract` -> `check`/`checkStep`,
//! `data/transactions/logic/eval.go`; issues #2225, #2286).
//!
//! A node runs the check BEFORE it evaluates a LogicSig
//! (`verify.logicSigSanityCheck`) and when an application is created or
//! updated (`ledger/apply/application.go` `checkPrograms`), so a malformed
//! program never reaches the runtime `step` texts
//! (`program ends without immediate value(s)`): the error is reported as
//! `pc=%3d <err>`. `step`'s own `<op> changed stack height improperly` /
//! `<op> produced <T> but intended <U>` are invariants of go's own opcode
//! implementations (they cannot be reached by any program), so they have no
//! counterpart here.
//!
//! [`static_check`] ports the part of `checkStep` that walks the instruction
//! stream: the opcode is known at the program's version, the run mode allows
//! it, the immediates (fixed-size and the variable-length ones) fit in the
//! program, the branch targets lie inside the program on instruction
//! boundaries, and the program's version is not above the node's maximum.
//!
//! The rule of this module is CONSERVATIVE: a construct that is not ported
//! (the pre-v4 static cost bound, the immediates of prefix families, the
//! transaction-group version minimums, ...) makes the check return `None`, it
//! never rejects a program go accepts. Every rejection is validated against
//! go's own verdict by the `check/` vectors of `avm-opcode-capture`, and every
//! vector go's check passes must pass here too (`avm_opcode_conformance`).

use crate::machine::ExecMode;
use crate::opcode::{self, ImmKind, Mode};

/// Go's `binary.Uvarint`: `(value, bytes read)`; the count is `0` when the
/// buffer ends first and negative on 64-bit overflow.
fn uvarint(buf: &[u8]) -> (u64, isize) {
    let mut x: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate() {
        if i == 10 {
            return (0, -((i + 1) as isize));
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return (0, -((i + 1) as isize));
            }
            return (x | (u64::from(b) << shift), (i + 1) as isize);
        }
        x |= u64::from(b & 0x7f) << shift;
        shift += 7;
    }
    (0, 0)
}

/// Go's `binary.Varint` (zigzag over [`uvarint`]).
fn varint(buf: &[u8]) -> (i64, isize) {
    let (ux, n) = uvarint(buf);
    let mut x = (ux >> 1) as i64;
    if ux & 1 != 0 {
        x = !x;
    }
    (x, n)
}

/// go's `parseIntImmArgs` (`assembler.go`): the end of an `intcblock` /
/// `pushints` immediate, or go's error text.
fn int_block_end(program: &[u8], mut pos: usize) -> Result<usize, String> {
    let (count, used) = uvarint(&program[pos.min(program.len())..]);
    if used <= 0 {
        return Err(format!("could not decode length of int list at pc={pos}"));
    }
    pos += used as usize;
    if count > program.len() as u64 {
        return Err("const int list with too many items".to_string());
    }
    for i in 0..count {
        if pos >= program.len() {
            return Err("const int list ran past end of program".to_string());
        }
        let (_, used) = uvarint(&program[pos..]);
        if used <= 0 {
            return Err(format!("could not decode int const[{i}] at pc={pos}"));
        }
        pos += used as usize;
    }
    Ok(pos)
}

/// go's `parseByteImmArgs` (`assembler.go`) for `bytecblock` / `pushbytess`.
fn byte_block_end(program: &[u8], mut pos: usize) -> Result<usize, String> {
    let (count, used) = uvarint(&program[pos.min(program.len())..]);
    if used <= 0 {
        return Err(format!("could not decode length of bytes list at pc={pos}"));
    }
    pos += used as usize;
    if count > program.len() as u64 {
        return Err("const bytes list with too many items".to_string());
    }
    for i in 0..count {
        if pos >= program.len() {
            return Err("const bytes list ran past end of program".to_string());
        }
        let (len, used) = uvarint(&program[pos..]);
        if used <= 0 {
            return Err(format!("could not decode []byte const[{i}] at pc={pos}"));
        }
        pos += used as usize;
        let end = (pos as u64).checked_add(len);
        match end {
            Some(end) if end <= program.len() as u64 => pos = end as usize,
            _ => return Err("const bytes list ran past end of program".to_string()),
        }
    }
    Ok(pos)
}

/// go's `appsEnabledVersion`: the lowest program version an application call
/// may run (`data/transactions/logic/eval.go`).
const APPS_ENABLED_VERSION: u8 = 2;

/// Opcodes whose static cost is looked up by an immediate field
/// (`costByField` / `field(..).costs(..)`): go reports `<op> reported
/// non-positive cost` for a field value it has no cost for, before any other
/// check of the instruction. That text is not ported, so the walk ends here.
const COST_BY_IMMEDIATE: [u8; 14] = [
    0x05, 0x06, 0x07, 0x5e, 0x5f, 0xd0, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
];

/// The branch bookkeeping of `check`: which offsets began an instruction and
/// which are targeted by a branch (go's `instructionStarts`/`branchTargets`).
struct Targets {
    starts: Vec<bool>,
    targets: Vec<bool>,
}

impl Targets {
    /// go's `checkBranch` / `checkBranchVarint` / `checkSwitch` tail: a branch
    /// that goes backwards must land on an instruction that already began.
    fn note(&mut self, target: usize, backwards: bool) -> Result<(), String> {
        if backwards && !self.starts[target] {
            return Err(format!(
                "back branch target {target} is not an aligned instruction"
            ));
        }
        self.targets[target] = true;
        Ok(())
    }
}

/// go's `check` of a program run in `mode`: `Some("pc=%3d <err>")` for the
/// first instruction go's static check rejects, among the cases this module
/// ports (see the module docs); `None` otherwise.
pub fn static_check(program: &[u8], mode: ExecMode) -> Option<String> {
    let (version, vlen) = uvarint(program);
    if vlen <= 0 || version > u64::from(u8::MAX) {
        return None;
    }
    let version = version as u8;
    // go's `begin`: a version beyond the newest the node supports.
    if version > opcode::MAX_AVM_VERSION {
        return Some(format!(
            "program version {version} greater than max supported version {}",
            opcode::MAX_AVM_VERSION
        ));
    }
    // go's `begin`: an application call in the group needs `appsEnabledVersion`
    // (`computeMinAvmVersion`), returned without a `pc=` frame. A LogicSig's
    // minimum depends on the rest of its group (rekeying), which is not
    // known here.
    if mode == ExecMode::Application && version < APPS_ENABLED_VERSION {
        return Some(format!(
            "program version must be >= {APPS_ENABLED_VERSION} for this transaction group, but have version {version}"
        ));
    }
    let len = program.len();
    let mut pc = vlen as usize;
    let mut t = Targets {
        starts: vec![false; len + 1],
        targets: vec![false; len + 1],
    };
    let fail = |pc: usize, msg: String| Some(format!("pc={pc:>3} {msg}"));
    while pc < len {
        t.starts[pc] = true;
        let op = program[pc];
        let spec = opcode::lookup(op).filter(|s| s.version <= version);
        let Some(spec) = spec else {
            return fail(pc, format!("illegal opcode 0x{op:02x}"));
        };
        if spec.sub_ops.is_some() {
            // A prefix family: resolve the sub-opcode as go does, but its
            // immediates are not ported.
            let Some(&sub) = program.get(pc + 1) else {
                return fail(pc, format!("prefix opcode 0x{op:02x} missing sub-opcode"));
            };
            let known = spec
                .sub_ops
                .and_then(|subs| subs.get(sub as usize))
                .is_some_and(|s| s.is_some());
            if !known {
                return fail(
                    pc,
                    format!("prefix opcode 0x{op:02x} with improper sub-opcode 0x{sub:02x}"),
                );
            }
            return None;
        }
        // go: `(cx.runMode & spec.Modes) == 0` for the spec of the program's
        // version. The per-version mode sets (`ed25519verify`) come from the
        // generated table; every other opcode has one mode set.
        let mode_ok = if crate::arg_gate_table::MODE_VARIANTS[op as usize].is_some() {
            crate::arg_gate::mode_allows(op, version, mode)
        } else {
            !matches!(
                (spec.mode, mode),
                (Mode::Application, ExecMode::LogicSig) | (Mode::LogicSig, ExecMode::Application)
            )
        };
        if !mode_ok {
            return fail(pc, format!("{} not allowed in current mode", spec.name));
        }
        let varint_branch =
            opcode::is_varint_branch_opcode(op) && version >= opcode::VARINT_BRANCH_VERSION;
        let size = if varint_branch {
            None
        } else {
            match spec.imm {
                ImmKind::None => Some(1),
                ImmKind::Uint8 => Some(2),
                ImmKind::Uint8Uint8 | ImmKind::Int16 => Some(3),
                ImmKind::Uint8Uint8Uint8 => Some(4),
                _ => None,
            }
        };
        let next;
        if let Some(size) = size {
            if size > 1 && pc + size > len {
                return fail(pc, "program ends without immediate value(s)".to_string());
            }
            if COST_BY_IMMEDIATE.contains(&op) {
                return None;
            }
            if spec.imm == ImmKind::Int16 {
                // go's `checkBranch` for `bnz`/`bz`/`b`/`callsub`.
                let offset = i64::from(i16::from_be_bytes([program[pc + 1], program[pc + 2]]));
                if offset < 0 && version < 4 {
                    // `%x` of a negative int.
                    return fail(pc, format!("negative branch offset -{:x}", -offset));
                }
                let target = pc as i64 + 3 + offset;
                let too_far = if version >= 2 {
                    target > len as i64 || target < 0
                } else {
                    target >= len as i64 || target < 0
                };
                if too_far {
                    return fail(pc, format!("branch target {target} outside of program"));
                }
                if let Err(e) = t.note(target as usize, target < pc as i64 + 3) {
                    return fail(pc, e);
                }
            }
            next = pc + size;
        } else if varint_branch {
            let (offset, used) = varint(program.get(pc + 1..).unwrap_or(&[]));
            if used == 0 {
                return fail(pc, "program ends without branch target".to_string());
            }
            if used < 0 {
                return fail(pc, "branch offset varint overflows int64".to_string());
            }
            let instr_size = 1 + used as usize;
            let target = if offset < 0 {
                pc as i64 + offset
            } else {
                (pc + instr_size) as i64 + offset
            };
            if target > len as i64 || target < 0 {
                return fail(pc, format!("branch target {target} outside of program"));
            }
            if let Err(e) = t.note(target as usize, target < pc as i64) {
                return fail(pc, e);
            }
            next = pc + instr_size;
        } else {
            match spec.imm {
                ImmKind::Varuint => {
                    let pos = pc + 1;
                    let (_, used) = uvarint(program.get(pos..).unwrap_or(&[]));
                    if used <= 0 {
                        return fail(pc, format!("could not decode int at program[{pos}]"));
                    }
                    next = pos + used as usize;
                }
                ImmKind::VaruintBytes => {
                    let mut pos = pc + 1;
                    let (blen, used) = uvarint(program.get(pos..).unwrap_or(&[]));
                    if used <= 0 {
                        return fail(pc, format!("could not decode length at program[{pos}]"));
                    }
                    pos += used as usize;
                    match (pos as u64).checked_add(blen) {
                        Some(end) if end <= len as u64 => next = end as usize,
                        _ => return fail(pc, format!("pushbytes too long at program[{pos}]")),
                    }
                }
                ImmKind::IntcBlock | ImmKind::PushInts => match int_block_end(program, pc + 1) {
                    Ok(end) => next = end,
                    Err(e) => return fail(pc, e),
                },
                ImmKind::BytecBlock | ImmKind::PushBytess => {
                    match byte_block_end(program, pc + 1) {
                        Ok(end) => next = end,
                        Err(e) => return fail(pc, e),
                    }
                }
                ImmKind::Labels => {
                    // go's `checkSwitch` / `switchTarget`.
                    let Some(&count) = program.get(pc + 1) else {
                        return fail(pc, format!("bare {} opcode at end of program", spec.name));
                    };
                    let count = usize::from(count);
                    let eoi = pc + 2 + 2 * count;
                    for i in 0..count {
                        if eoi > len {
                            return fail(
                                pc,
                                format!("{} opcode claims to extend beyond program", spec.name),
                            );
                        }
                        let at = pc + 2 + 2 * i;
                        let offset = i64::from(i16::from_be_bytes([program[at], program[at + 1]]));
                        let target = eoi as i64 + offset;
                        if target > len as i64 || target < 0 {
                            return fail(pc, format!("branch target {target} outside of program"));
                        }
                        if let Err(e) = t.note(target as usize, target < eoi as i64) {
                            return fail(pc, e);
                        }
                    }
                    next = eoi;
                }
                _ => return None,
            }
        }
        // go: a branch target inside the instruction just walked is not an
        // instruction boundary (reported at the pc AFTER the instruction).
        for p in pc + 1..next.min(len + 1) {
            if t.targets[p] {
                return fail(
                    next,
                    format!("branch target {p} is not an aligned instruction"),
                );
            }
        }
        pc = next;
    }
    None
}

/// [`static_check`] of a LogicSig program (`logic.CheckSignature`).
pub fn logicsig_static_check(program: &[u8]) -> Option<String> {
    static_check(program, ExecMode::LogicSig)
}

/// [`static_check`] of an application program (`logic.CheckContract`).
pub fn contract_static_check(program: &[u8]) -> Option<String> {
    static_check(program, ExecMode::Application)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_program_passes() {
        // v8: int 1
        assert_eq!(logicsig_static_check(&[8, 0x81, 1]), None);
        assert_eq!(contract_static_check(&[8, 0x81, 1]), None);
    }

    #[test]
    fn a_truncated_fixed_size_immediate_is_go_s_text_and_pc() {
        // v8: pushint 1; txn <missing field>
        assert_eq!(
            logicsig_static_check(&[8, 0x81, 1, 0x31]).as_deref(),
            Some("pc=  3 program ends without immediate value(s)")
        );
    }

    #[test]
    fn the_run_mode_decides_which_opcodes_are_allowed() {
        // v8: `balance` (application only) and `arg_0` (LogicSig only).
        assert_eq!(
            logicsig_static_check(&[8, 0x60]).as_deref(),
            Some("pc=  1 balance not allowed in current mode")
        );
        assert_eq!(contract_static_check(&[8, 0x60]), None);
        assert_eq!(logicsig_static_check(&[8, 0x2d]), None);
        assert!(contract_static_check(&[8, 0x2d])
            .is_some_and(|e| e.ends_with("not allowed in current mode")));
    }

    #[test]
    fn a_forward_branch_to_the_end_of_the_program_is_fine_and_past_it_is_not() {
        // v8: b +0 (to the end of the program, 4)
        assert_eq!(logicsig_static_check(&[8, 0x42, 0, 0]), None);
        // b +1: one byte past the end.
        assert_eq!(
            logicsig_static_check(&[8, 0x42, 0, 1]).as_deref(),
            Some("pc=  1 branch target 5 outside of program")
        );
    }

    #[test]
    fn varuint_decoding_follows_go() {
        assert_eq!(uvarint(&[0x01]), (1, 1));
        assert_eq!(uvarint(&[0xac, 0x02]), (300, 2));
        assert_eq!(uvarint(&[0xac]), (0, 0));
        assert!(uvarint(&[0xff; 11]).1 < 0);
        assert_eq!(varint(&[0x03]), (-2, 1));
        assert_eq!(varint(&[0x04]), (2, 1));
    }
}
