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

//! go's static check of a LogicSig program (`logic.CheckSignature` ->
//! `check`/`checkStep`, `data/transactions/logic/eval.go`; issue #2225).
//!
//! A node runs the check BEFORE it evaluates a LogicSig
//! (`verify.logicSigSanityCheck`), so a malformed program never reaches the
//! runtime `step` texts (`program ends without immediate value(s)`): the error
//! is reported as `pc=%3d <err>`. `step`'s own `<op> changed stack height
//! improperly` / `<op> produced <T> but intended <U>` are invariants of go's
//! own opcode implementations (they cannot be reached by any program), so they
//! have no counterpart here.
//!
//! [`logicsig_static_check`] ports the part of `checkStep` that decodes the
//! instruction stream (opcode known at the program's version, run mode,
//! immediate sizes, the variable-length immediates) with go's texts and pcs.
//! The checks that need a branch-target pass, prefix-family immediates and the
//! static cost bound are not ported: for such a program it returns `None` and
//! the evaluator's own errors apply.

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

/// go's `check` of a LogicSig program: `Some("pc=%3d <err>")` for the first
/// instruction go's static check rejects, among the cases this module ports
/// (see the module docs); `None` otherwise.
pub fn logicsig_static_check(program: &[u8]) -> Option<String> {
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
    let mut pc = vlen as usize;
    let fail = |pc: usize, msg: String| Some(format!("pc={pc:>3} {msg}"));
    while pc < program.len() {
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
        if spec.mode == Mode::Application {
            return fail(pc, format!("{} not allowed in current mode", spec.name));
        }
        let varint_branch =
            opcode::is_varint_branch_opcode(op) && version >= opcode::VARINT_BRANCH_VERSION;
        let fixed = |size: usize| -> Option<usize> { Some(size) };
        let size = if varint_branch {
            None
        } else {
            match spec.imm {
                ImmKind::None => fixed(1),
                ImmKind::Uint8 => fixed(2),
                ImmKind::Uint8Uint8 | ImmKind::Int16 => fixed(3),
                ImmKind::Uint8Uint8Uint8 => fixed(4),
                _ => None,
            }
        };
        if let Some(size) = size {
            if size > 1 && pc + size > program.len() {
                return fail(pc, "program ends without immediate value(s)".to_string());
            }
            pc += size;
            continue;
        }
        if varint_branch {
            let (_, used) = uvarint(program.get(pc + 1..).unwrap_or(&[]));
            if used == 0 {
                return fail(pc, "program ends without branch target".to_string());
            }
            if used < 0 {
                return fail(pc, "branch offset varint overflows int64".to_string());
            }
            pc += 1 + used as usize;
            continue;
        }
        match spec.imm {
            ImmKind::Varuint => {
                let pos = pc + 1;
                let (_, used) = uvarint(program.get(pos..).unwrap_or(&[]));
                if used <= 0 {
                    return fail(pc, format!("could not decode int at program[{pos}]"));
                }
                pc = pos + used as usize;
            }
            ImmKind::VaruintBytes => {
                let mut pos = pc + 1;
                let (len, used) = uvarint(program.get(pos..).unwrap_or(&[]));
                if used <= 0 {
                    return fail(pc, format!("could not decode length at program[{pos}]"));
                }
                pos += used as usize;
                match (pos as u64).checked_add(len) {
                    Some(end) if end <= program.len() as u64 => pc = end as usize,
                    _ => return fail(pc, format!("pushbytes too long at program[{pos}]")),
                }
            }
            ImmKind::IntcBlock | ImmKind::PushInts => match int_block_end(program, pc + 1) {
                Ok(end) => pc = end,
                Err(e) => return fail(pc, e),
            },
            ImmKind::BytecBlock | ImmKind::PushBytess => match byte_block_end(program, pc + 1) {
                Ok(end) => pc = end,
                Err(e) => return fail(pc, e),
            },
            ImmKind::Labels => {
                let Some(&count) = program.get(pc + 1) else {
                    return fail(pc, format!("bare {} opcode at end of program", spec.name));
                };
                pc += 2 + 2 * usize::from(count);
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_program_passes() {
        // v8: int 1
        assert_eq!(logicsig_static_check(&[8, 0x81, 1]), None);
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
    fn varuint_decoding_follows_go() {
        assert_eq!(uvarint(&[0x01]), (1, 1));
        assert_eq!(uvarint(&[0xac, 0x02]), (300, 2));
        assert_eq!(uvarint(&[0xac]), (0, 0));
        assert!(uvarint(&[0xff; 11]).1 < 0);
    }
}
