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

//! The assembler's static stack-type tracker: a port of go-algorand's
//! `ProgramKnowledge`, `trackStack`, `getSpec`'s pseudo-op protos, the
//! `typed(...)` refine functions and `OpStream.returns`
//! (`data/transactions/logic/assembler.go`, `eval.go`).
//!
//! Every opcode's per-version `proto` (argument and return [`StackType`]s with
//! their bounds and names), its refine function's name, its field-group
//! immediates and every field's own type come from
//! [`crate::type_track_table`], GENERATED from go-algorand's own tables by
//! `scripts/gen_type_track_table.py` (`tools/avm-op-types`). Only the refine
//! functions themselves (`typeDup`, `typeFrameDig`, ...) are ported by hand;
//! a test keeps their list in sync with the go dump. History: issue #829
//! (an incremental slice), issue #2368 (the full port, driven by the
//! ARC56Registry reassembly corpus).

use crate::assembler::OpStream;
use crate::type_track_table::OPS;

/// go's `avmType` (`eval.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Avm {
    None,
    Any,
    Uint64,
    Bytes,
}

const MAX_UINT64: u64 = u64::MAX;
const MAX_STRING_SIZE: u64 = 4096;

/// go's `StackType`: an AVM type, a `[min, max]` bound (value for uint64,
/// length for `[]byte`) and the name it prints. The name is derived from the
/// type and bound exactly like `NewStackType` does, unless a table type carries
/// an `alias` (`address`, `bool`, `bigint`, `boxName`, ...), so derived
/// equality is go's struct equality (`Name`, `AVMType`, `Bound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackType {
    avm: Avm,
    min: u64,
    max: u64,
    alias: Option<&'static str>,
}

/// go's `StackAny`.
pub(crate) const ANY: StackType = StackType::new(Avm::Any, 0, 0, None);
/// go's `StackUint64`.
pub(crate) const UINT64: StackType = StackType::new(Avm::Uint64, 0, MAX_UINT64, None);
/// go's `StackBytes`.
pub(crate) const BYTES: StackType = StackType::new(Avm::Bytes, 0, MAX_STRING_SIZE, None);
/// go's `StackNone`.
const NONE: StackType = StackType::new(Avm::None, 0, 0, None);

impl StackType {
    pub(crate) const fn new(avm: Avm, min: u64, max: u64, alias: Option<&'static str>) -> Self {
        Self {
            avm,
            min,
            max,
            alias,
        }
    }

    /// go's `NewStackType` with no explicit name.
    fn bounded(avm: Avm, min: u64, max: u64) -> Self {
        Self::new(avm, min, max, None)
    }

    /// go's `StackType.Typed`.
    pub(crate) fn typed(self) -> bool {
        matches!(self.avm, Avm::Uint64 | Avm::Bytes)
    }

    /// go's `StackType.union`.
    fn union(self, b: StackType) -> StackType {
        if self.avm != b.avm {
            return ANY;
        }
        Self::bounded(self.avm, self.min.min(b.min), self.max.max(b.max))
    }

    /// go's `StackType.narrowed`.
    fn narrowed(self, min: u64, max: u64) -> StackType {
        Self::bounded(self.avm, min, max)
    }

    /// go's `StackType.widened`.
    fn widened(self) -> StackType {
        match self.avm {
            Avm::Bytes => BYTES,
            Avm::Uint64 => UINT64,
            // go panics for `none`; it is never on a stack being widened
            // (`typeEquals` only sees values pushed by earlier opcodes).
            Avm::Any | Avm::None => ANY,
        }
    }

    /// go's `StackType.constInt`.
    fn const_int(self) -> Option<u64> {
        (self.avm == Avm::Uint64 && self.min == self.max).then_some(self.min)
    }

    /// go's `StackType.overlaps`.
    pub(crate) fn overlaps(self, expected: StackType) -> bool {
        if self.avm == Avm::None || expected.avm == Avm::None {
            return false;
        }
        if self.avm == Avm::Any || expected.avm == Avm::Any {
            return true;
        }
        if self.avm != expected.avm {
            return false;
        }
        self.min <= expected.max && self.max >= expected.min
    }
}

impl std::fmt::Display for StackType {
    /// go's `StackType.String`: the alias, or `NewStackType`'s derived name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(a) = self.alias {
            return f.write_str(a);
        }
        let (min, max) = (self.min, self.max);
        match self.avm {
            Avm::None => f.write_str("none"),
            Avm::Any => f.write_str("any"),
            Avm::Uint64 => {
                if min == max {
                    write!(f, "{min}")
                } else if min == 0 && max != 0 {
                    if max != MAX_UINT64 {
                        write!(f, "uint64 (<= {max})")
                    } else {
                        f.write_str("uint64")
                    }
                } else if min != 0 && max != 0 {
                    write!(f, "uint64 ({min}-{max})")
                } else {
                    f.write_str("uint64")
                }
            }
            Avm::Bytes => {
                if min == max {
                    write!(f, "[{min}]byte")
                } else if min == 0 && max != 0 {
                    if max != MAX_STRING_SIZE {
                        write!(f, "[<={max}]byte")
                    } else {
                        f.write_str("[]byte")
                    }
                } else if min != 0 && max != 0 {
                    write!(f, "[{min}-{max}]byte")
                } else {
                    f.write_str("[]byte")
                }
            }
        }
    }
}

/// One field of a field group (generated).
pub(crate) struct FieldEntry {
    pub name: &'static str,
    #[allow(dead_code)]
    pub version: u8,
    pub ty: StackType,
}

/// One immediate of an opcode (generated): a field-group selector or not.
pub(crate) struct ImmEntry {
    /// go's `immediate.Name` (`i`, `n`, `f`, ...): named in immediate parse errors.
    pub name: &'static str,
    pub group: Option<&'static [FieldEntry]>,
}

/// An opcode's proto from the version it starts at (generated).
pub(crate) struct Variant {
    pub from: u8,
    pub args: &'static [StackType],
    pub returns: &'static [StackType],
    pub refine: &'static str,
}

/// An opcode (generated).
pub(crate) struct OpEntry {
    pub name: &'static str,
    pub version: u8,
    pub deadens: bool,
    pub imms: &'static [ImmEntry],
    pub variants: &'static [Variant],
}

/// go's name of opcode `op`'s immediate `idx` (`i`, `n`, ...), for parse errors;
/// `i` when the opcode has no such immediate.
pub(crate) fn imm_name(op: &str, idx: usize) -> &'static str {
    op_entry(op)
        .and_then(|e| e.imms.get(idx))
        .map_or("i", |i| i.name)
}

fn op_entry(name: &str) -> Option<&'static OpEntry> {
    OPS.binary_search_by(|e| e.name.cmp(name))
        .ok()
        .map(|i| &OPS[i])
}

impl OpEntry {
    /// `OpsByName[version][name]`'s proto, if the opcode exists at `version`.
    fn variant_at(&self, version: u8) -> Option<&'static Variant> {
        if self.version > version {
            return None;
        }
        self.variants.iter().rev().find(|v| v.from <= version)
    }
}

/// go's `ProgramKnowledge`: what is statically known about the stack and the
/// scratch space at the current point of the program.
#[derive(Debug, Clone)]
pub(crate) struct Knowledge {
    /// The types known to be on the value stack. Empty in dead code.
    pub(crate) stack: Vec<StackType>,
    /// go's `bottom`: `StackNone` at program start, `StackAny` after a reset
    /// (`true`): the stack "virtually" holds an infinite list of `any` below
    /// `stack`.
    bottom_any: bool,
    /// Dead code: no type checking errors are reported.
    pub(crate) deadcode: bool,
    /// The frame pointer, or -1 when not known.
    fp: i64,
    scratch: [StackType; 256],
}

/// go's `StackZeroUint64`: an untouched scratch slot reads as zero.
// Go gives it the name "0", which is also what `NewStackType` derives for a
// constant 0, so it equals a tracked `int 0` (go compares the whole struct).
const ZERO_UINT64: StackType = StackType::new(Avm::Uint64, 0, 0, None);

impl Knowledge {
    pub(crate) fn new() -> Self {
        Self {
            stack: Vec::new(),
            bottom_any: false,
            deadcode: false,
            fp: -1,
            scratch: [ZERO_UINT64; 256],
        }
    }

    fn bottom(&self) -> StackType {
        if self.bottom_any {
            ANY
        } else {
            NONE
        }
    }

    fn top(&self) -> StackType {
        self.stack.last().copied().unwrap_or_else(|| self.bottom())
    }

    fn pop(&mut self) -> StackType {
        match self.stack.pop() {
            Some(t) => t,
            None => self.bottom(),
        }
    }

    pub(crate) fn deaden(&mut self) {
        self.stack.clear();
        self.deadcode = true;
    }

    /// go's `label`: control may enter from elsewhere.
    pub(crate) fn label(&mut self) {
        if self.deadcode {
            self.reset();
        }
    }

    /// go's `reset`: clear what is known and permit any stack value.
    pub(crate) fn reset(&mut self) {
        self.stack.clear();
        self.bottom_any = true;
        self.fp = -1;
        self.deadcode = false;
        self.scratch = [ANY; 256];
    }
}

/// go's `reJoin`.
fn rejoin(instruction: &str, args: &[&str]) -> String {
    let mut s = instruction.to_string();
    for a in args {
        s.push(' ');
        s.push_str(a);
    }
    s
}

/// Parse like go's `strconv.ParseInt(s, 0, bits)`, returning only the value.
fn go_parse_int(s: &str, bits: u32) -> Option<i64> {
    let (neg, body) = match s.as_bytes().first()? {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    let u = go_parse_uint_base0(body, 64)?;
    let limit = 1u128 << (bits - 1);
    if neg {
        if (u as u128) > limit {
            return None;
        }
        Some((u as i128).wrapping_neg() as i64)
    } else {
        if (u as u128) >= limit {
            return None;
        }
        Some(u as i64)
    }
}

/// `strconv.ParseUint(s, 0, 64)` (base prefixes, `_` separators).
pub(crate) fn go_parse_uint_base0(s: &str, _bits: u32) -> Option<u64> {
    go_parse_uint_base0_err(s).ok()
}

/// `strconv.ParseUint(s, 0, 64)` with go's `NumError` reason: `invalid syntax`
/// or `value out of range`.
pub(crate) fn go_parse_uint_base0_err(s: &str) -> Result<u64, &'static str> {
    const SYNTAX: &str = "invalid syntax";
    const RANGE: &str = "value out of range";
    let b = s.as_bytes();
    if b.is_empty() {
        return Err(SYNTAX);
    }
    let (base, digits): (u32, &str) = if b[0] == b'0' && s.len() >= 3 {
        match b[1] {
            b'b' | b'B' => (2, &s[2..]),
            b'o' | b'O' => (8, &s[2..]),
            b'x' | b'X' => (16, &s[2..]),
            _ => (8, &s[1..]),
        }
    } else if b[0] == b'0' {
        (8, &s[1..])
    } else {
        (10, s)
    };
    if !underscore_ok(s) {
        return Err(SYNTAX);
    }
    let mut n: u64 = 0;
    let mut overflow = false;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        let Some(d) = c.to_digit(base) else {
            return Err(SYNTAX);
        };
        match n
            .checked_mul(u64::from(base))
            .and_then(|v| v.checked_add(u64::from(d)))
        {
            Some(v) => n = v,
            None => overflow = true,
        }
    }
    if overflow {
        Err(RANGE)
    } else {
        Ok(n)
    }
}

/// go's `underscoreOK` (strconv/atoi.go).
fn underscore_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    let mut saw = b'^';
    if !b.is_empty() && (b[0] == b'-' || b[0] == b'+') {
        i = 1;
    }
    let mut hex = false;
    if b.len() >= i + 2
        && b[i] == b'0'
        && matches!(b[i + 1].to_ascii_lowercase(), b'b' | b'o' | b'x')
    {
        hex = b[i + 1].eq_ignore_ascii_case(&b'x');
        i += 2;
        saw = b'0';
    }
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() || (hex && (b'a'..=b'f').contains(&c.to_ascii_lowercase())) {
            saw = b'0';
        } else if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            if saw == b'_' {
                return false;
            }
            saw = b'!';
        }
        i += 1;
    }
    saw != b'_'
}

/// go's `getImm`: the immediate at `idx`, within `-128..=127` (`signed`) or
/// `0..=255`.
fn get_imm(args: &[&str], idx: usize, signed: bool) -> Option<i64> {
    let s = args.get(idx)?;
    let n = go_parse_int(s, 9)?;
    if signed {
        (-128..=127).contains(&n).then_some(n)
    } else {
        (0..=255).contains(&n).then_some(n)
    }
}

/// What a refine function returns: go's `(nargs, nreturns, err)`.
#[derive(Default)]
struct Refined {
    args: Option<Vec<StackType>>,
    returns: Option<Vec<StackType>>,
    err: Option<String>,
}

fn any_types(n: usize) -> Vec<StackType> {
    vec![ANY; n]
}

fn refined(args: Option<Vec<StackType>>, returns: Option<Vec<StackType>>) -> Refined {
    Refined {
        args,
        returns,
        err: None,
    }
}

fn refine_err(msg: String) -> Refined {
    Refined {
        err: Some(msg),
        ..Refined::default()
    }
}

/// The `typed(...)` refine functions of go's `assembler.go`, keyed by the
/// function name `tools/avm-op-types` dumps. `fields` is the `TxnFields`
/// group (for `typeTxField`).
fn run_refine(
    name: &str,
    pgm: &mut Knowledge,
    args: &[&str],
    txn_fields: Option<&'static [FieldEntry]>,
) -> Refined {
    let top = pgm.stack.len() as isize - 1;
    let st = |i: isize| pgm.stack[i as usize];
    match name {
        "typeSwap" => {
            let mut swapped = [ANY, ANY];
            if top >= 0 {
                swapped[0] = st(top);
                if top >= 1 {
                    swapped[1] = st(top - 1);
                }
            }
            refined(None, Some(swapped.to_vec()))
        }
        "typeDig" => {
            let Some(n) = get_imm(args, 0, false) else {
                return Refined::default();
            };
            let depth = n as usize + 1;
            let mut returns = any_types(depth + 1);
            let idx = pgm.stack.len() as isize - depth as isize;
            if idx >= 0 {
                let idx = idx as usize;
                returns[..depth].copy_from_slice(&pgm.stack[idx..]);
                returns[depth] = pgm.stack[idx];
            }
            refined(Some(any_types(depth)), Some(returns))
        }
        "typeBury" => {
            let Some(n) = get_imm(args, 0, false) else {
                return Refined::default();
            };
            if n == 0 {
                return refine_err("bury 0 always fails".to_string());
            }
            let n = n as usize;
            let idx = top - n as isize;
            if idx < 0 {
                if !pgm.bottom_any {
                    // By demanding n+1 elements, we trigger an error.
                    return refined(Some(any_types(n + 1)), None);
                }
                return Refined::default();
            }
            let idx = idx as usize;
            let typ = pgm.top();
            let mut returns = pgm.stack[idx..idx + n].to_vec();
            returns[0] = typ;
            refined(Some(pgm.stack[idx..].to_vec()), Some(returns))
        }
        "typeFrameDig" => {
            let Some(n) = get_imm(args, 0, true) else {
                return Refined::default();
            };
            if pgm.fp == -1 {
                return Refined::default();
            }
            let idx = pgm.fp + n;
            if idx < 0 {
                return refine_err(format!("frame_dig {} in sub with {} args", n, pgm.fp));
            }
            if idx as usize >= pgm.stack.len() {
                return refine_err("frame_dig above stack".to_string());
            }
            refined(None, Some(vec![pgm.stack[idx as usize]]))
        }
        "typeFrameBury" => {
            let Some(n) = get_imm(args, 0, true) else {
                return Refined::default();
            };
            let typ = pgm.top();
            if pgm.fp == -1 {
                for s in pgm.stack.iter_mut() {
                    if *s != typ {
                        *s = ANY;
                    }
                }
                return Refined::default();
            }
            let idx = pgm.fp + n;
            if idx < 0 {
                return refine_err(format!("frame_bury {} in sub with {} args", n, pgm.fp));
            }
            let top_i = pgm.stack.len() as i64 - 1;
            if idx >= top_i {
                return refine_err("frame_bury above stack".to_string());
            }
            let idx = idx as usize;
            let depth = (top_i as usize) - idx;
            let mut returns = pgm.stack[idx..idx + depth].to_vec();
            returns[0] = typ;
            refined(Some(pgm.stack[idx..].to_vec()), Some(returns))
        }
        "typeEquals" => {
            if top >= 0 {
                let w = st(top).widened();
                return refined(Some(vec![w, w]), None);
            }
            Refined::default()
        }
        "typeDup" => {
            if top >= 0 {
                return refined(None, Some(vec![st(top), st(top)]));
            }
            Refined::default()
        }
        "typeDupTwo" => {
            let mut two = [ANY, ANY];
            if top >= 0 {
                two[1] = st(top);
                if top >= 1 {
                    two[0] = st(top - 1);
                }
            }
            refined(None, Some(vec![two[0], two[1], two[0], two[1]]))
        }
        "typeSelect" => {
            if top >= 2 {
                return refined(None, Some(vec![st(top - 1).union(st(top - 2))]));
            }
            Refined::default()
        }
        "typeSetBit" => {
            if top >= 2 {
                return refined(None, Some(vec![st(top - 2)]));
            }
            Refined::default()
        }
        "typeCover" => {
            let Some(n) = get_imm(args, 0, false) else {
                return Refined::default();
            };
            let depth = n as usize + 1;
            let mut returns = any_types(depth);
            let idx = pgm.stack.len() as isize - depth as isize;
            if idx >= 0 {
                let idx = idx as usize;
                returns[0] = pgm.stack[pgm.stack.len() - 1];
                for i in idx..pgm.stack.len() - 1 {
                    returns[i - idx + 1] = pgm.stack[i];
                }
            }
            refined(Some(any_types(depth)), Some(returns))
        }
        "typeUncover" => {
            let Some(n) = get_imm(args, 0, false) else {
                return Refined::default();
            };
            let depth = n as usize + 1;
            let mut returns = any_types(depth);
            let idx = pgm.stack.len() as isize - depth as isize;
            if idx >= 0 {
                let idx = idx as usize;
                returns[depth - 1] = pgm.stack[idx];
                for i in idx + 1..pgm.stack.len() {
                    returns[i - idx - 1] = pgm.stack[i];
                }
            }
            refined(Some(any_types(depth)), Some(returns))
        }
        "typeTxField" => {
            if args.len() != 1 {
                return Refined::default();
            }
            match txn_fields.and_then(|g| g.iter().find(|f| f.name == args[0])) {
                Some(f) => refined(Some(vec![f.ty]), None),
                None => Refined::default(),
            }
        }
        "typeStore" => {
            let Some(i) = get_imm(args, 0, false) else {
                return Refined::default();
            };
            if top >= 0 {
                pgm.scratch[i as usize] = st(top);
            }
            Refined::default()
        }
        "typeStores" => {
            if top < 0 {
                return Refined::default();
            }
            if top >= 1 {
                if let Some(idx) = st(top - 1).const_int() {
                    let v = st(top);
                    // go indexes `scratchSpace[idx]` unchecked (a panic for
                    // idx >= 256); an out-of-range constant is ignored here.
                    if let Some(slot) = pgm.scratch.get_mut(idx as usize) {
                        *slot = v;
                    }
                    return Refined::default();
                }
            }
            let v = st(top);
            for s in pgm.scratch.iter_mut() {
                *s = s.union(v);
            }
            Refined::default()
        }
        "typeLoad" => {
            let Some(i) = get_imm(args, 0, false) else {
                return Refined::default();
            };
            refined(None, Some(vec![pgm.scratch[i as usize]]))
        }
        "typeProto" => {
            let (Some(a), Some(_)) = (get_imm(args, 0, false), get_imm(args, 1, false)) else {
                return Refined::default();
            };
            if !pgm.stack.is_empty() || !pgm.bottom_any {
                return refine_err("proto must be unreachable from previous PC".to_string());
            }
            pgm.stack = any_types(a as usize);
            pgm.fp = a;
            Refined::default()
        }
        "typeLoads" => {
            if top < 0 {
                return Refined::default();
            }
            if let Some(v) = st(top).const_int() {
                if let Some(slot) = pgm.scratch.get(v as usize) {
                    return refined(None, Some(vec![*slot]));
                }
                return Refined::default();
            }
            let first = pgm.scratch[0];
            if pgm.scratch.iter().any(|s| *s != first) {
                return Refined::default();
            }
            refined(None, Some(vec![first]))
        }
        "typePopN" => {
            let Some(n) = get_imm(args, 0, false) else {
                return Refined::default();
            };
            refined(Some(any_types(n as usize)), None)
        }
        "typeDupN" => {
            let Some(n) = get_imm(args, 0, false) else {
                return Refined::default();
            };
            if top < 0 {
                return Refined::default();
            }
            refined(None, Some(vec![st(top); n as usize + 1]))
        }
        "typePushBytess" => refined(None, Some(vec![BYTES; args.len()])),
        "typePushInts" => refined(None, Some(vec![UINT64; args.len()])),
        "typeBzero" => refined(
            Some(vec![UINT64.narrowed(0, MAX_STRING_SIZE)]),
            Some(vec![BYTES]),
        ),
        "typeMatch" => refined(Some(any_types(args.len() + 1)), None),
        other => {
            if let Some(max) = other.strip_prefix("typeByteMath:") {
                let max: u64 = max.parse().unwrap_or(0);
                return refined(None, Some(vec![StackType::bounded(Avm::Bytes, 0, max)]));
            }
            debug_assert!(other.is_empty(), "unported refine function {other}");
            Refined::default()
        }
    }
}

/// The spec `getSpec` resolves for one instruction, as the tracker needs it.
struct Spec {
    /// The name error messages use (`txn without immediates`, ...).
    instruction: String,
    args: Vec<StackType>,
    returns: Vec<StackType>,
    refine: String,
    /// The opcode whose group immediates assemble the field immediates.
    asm_entry: Option<&'static OpEntry>,
    /// The tracked opcode's own entry (for `deadens`, `typeTxField`'s group).
    entry: Option<&'static OpEntry>,
    name: String,
}

/// go's `pseudoOps` table: `(immediate count -> real opcode)`; the arity-free
/// full pseudo-ops (`int`, `byte`, `addr`, `method`) are handled separately.
fn pseudo_targets(name: &str) -> Option<&'static [(usize, &'static str)]> {
    match name {
        "txn" => Some(&[(1, "txn"), (2, "txna")]),
        "gtxn" => Some(&[(2, "gtxn"), (3, "gtxna")]),
        "gtxns" => Some(&[(1, "gtxns"), (2, "gtxnsa")]),
        "extract" => Some(&[(0, "extract3"), (2, "extract")]),
        "replace" => Some(&[(0, "replace3"), (1, "replace2")]),
        _ => None,
    }
}

/// `OpsByName[version][name]`, falling back to the newest version like
/// `prepareVersionedPseudoTable`.
fn pseudo_variant(real: &str, version: u8) -> Option<(&'static OpEntry, &'static Variant)> {
    let e = op_entry(real)?;
    let v = e.variant_at(version).or_else(|| e.variants.last())?;
    Some((e, v))
}

/// go's `getSpec` (the tracker's view of it): `None` when go gives up, so
/// nothing is tracked.
fn get_spec(ops: &OpStream, name: &str, argc: usize) -> Option<Spec> {
    let version = ops.effective_version();
    match name {
        "int" | "byte" | "addr" | "method" => {
            let refine = match name {
                "int" => "typePushInt",
                "byte" => "typeByte",
                _ => "",
            };
            let ret = if name == "int" { UINT64 } else { BYTES };
            let instruction = if argc == 0 {
                format!("{name} without immediates")
            } else {
                name.to_string()
            };
            return Some(Spec {
                instruction,
                args: vec![],
                returns: vec![ret],
                refine: refine.to_string(),
                asm_entry: None,
                entry: None,
                name: name.to_string(),
            });
        }
        _ => {}
    }
    if let Some(targets) = pseudo_targets(name) {
        let instruction = if argc == 0 {
            format!("{name} without immediates")
        } else {
            name.to_string()
        };
        if let Some((_, real)) = targets.iter().find(|(n, _)| *n == argc) {
            let (entry, v) = pseudo_variant(real, version)?;
            return Some(Spec {
                instruction,
                args: v.args.to_vec(),
                returns: v.returns.to_vec(),
                refine: v.refine.to_string(),
                asm_entry: Some(entry),
                entry: Some(entry),
                name: name.to_string(),
            });
        }
        // go's `mergeProtos`: the immediate count matched no spec, so type
        // tracking uses a proto combining all of them.
        let mut args: Option<Vec<StackType>> = None;
        let mut returns: Option<Vec<StackType>> = None;
        for (_, real) in targets {
            let (_, v) = pseudo_variant(real, version)?;
            match (&mut args, &mut returns) {
                (None, None) => {
                    args = Some(v.args.to_vec());
                    returns = Some(v.returns.to_vec());
                }
                (Some(a), Some(r)) => {
                    if a.len() != v.args.len() || r.len() != v.returns.len() {
                        return None;
                    }
                    for (x, y) in a.iter_mut().zip(v.args) {
                        if x != y {
                            *x = ANY;
                        }
                    }
                    for (x, y) in r.iter_mut().zip(v.returns) {
                        if x != y {
                            *x = ANY;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        return Some(Spec {
            instruction,
            args: args.unwrap_or_default(),
            returns: returns.unwrap_or_default(),
            refine: String::new(),
            asm_entry: None,
            entry: None,
            name: name.to_string(),
        });
    }
    let entry = op_entry(name)?;
    let v = entry.variant_at(version)?;
    // `itxn`/`gitxn` hand a different immediate count to `itxna`/`gitxna`.
    let asm_entry = match (name, argc) {
        ("itxn", 2) => op_entry("itxna"),
        ("gitxn", 3) => op_entry("gitxna"),
        _ => Some(entry),
    };
    Some(Spec {
        instruction: name.to_string(),
        args: v.args.to_vec(),
        returns: v.returns.to_vec(),
        refine: v.refine.to_string(),
        asm_entry,
        entry: Some(entry),
        name: name.to_string(),
    })
}

fn type_error(ops: &mut OpStream, col: usize, msg: String) {
    if ops.type_track_reporting {
        let line = ops.source_line;
        ops.record_error(line, col, msg);
    }
}

/// go's `trackStack`.
fn track_stack(
    ops: &mut OpStream,
    col: usize,
    args: &[StackType],
    returns: &[StackType],
    instruction: &str,
    tokens: &[&str],
) {
    if ops.known.deadcode {
        return;
    }
    let argcount = args.len();
    if argcount > ops.known.stack.len() && !ops.known.bottom_any {
        let msg = format!(
            "{} expects {} stack arguments but stack height is {}",
            rejoin(instruction, tokens),
            argcount,
            ops.known.stack.len()
        );
        type_error(ops, col, msg);
    } else {
        for i in (0..argcount).rev() {
            let want = args[i];
            let got = ops.known.pop();
            if !got.overlaps(want) {
                let msg = format!(
                    "{} arg {} wanted type {} got {}",
                    rejoin(instruction, tokens),
                    i,
                    want,
                    got
                );
                type_error(ops, col, msg);
            }
        }
    }
    ops.known.stack.extend_from_slice(returns);
}

/// go's `OpStream.returns`: specialise the first `any` of the top
/// `n_returns` stack entries to `replacement`.
fn specialise_returns(ops: &mut OpStream, n_returns: usize, replacement: StackType) {
    if ops.known.deadcode {
        return;
    }
    let end = ops.known.stack.len();
    if n_returns > end {
        return;
    }
    for t in ops.known.stack[end - n_returns..].iter_mut() {
        if t.avm == Avm::Any {
            *t = replacement;
            return;
        }
    }
}

/// The first half of go's `asmDefault` for the opcode that assembles the
/// instruction: the immediates are checked in order and, once the field-group
/// immediate names a typed field, `ops.returns` refines the tracked return
/// type before any later error (e.g. a too-new field) stops assembly.
fn refine_field_return(ops: &mut OpStream, spec: &Spec, args: &[&str]) {
    let Some(entry) = spec.asm_entry else { return };
    // Opcodes with their own assembler function never reach `ops.returns`.
    if matches!(entry.name, "itxn_field" | "app_params_set") {
        return;
    }
    if args.len() != entry.imms.len() {
        return;
    }
    let n_returns = entry
        .variant_at(ops.effective_version())
        .or_else(|| entry.variants.last())
        .map_or(0, |v| v.returns.len());
    for (imm, arg) in entry.imms.iter().zip(args) {
        match imm.group {
            Some(group) => {
                let Some(f) = group.iter().find(|f| f.name == *arg) else {
                    return;
                };
                if f.ty.typed() {
                    specialise_returns(ops, n_returns, f.ty);
                }
            }
            None => {
                // go's `byteImm`: an unsigned immediate of at most 255.
                match go_parse_uint_base0(arg, 64) {
                    Some(v) if v <= 255 => {}
                    _ => return,
                }
            }
        }
    }
}

/// go's refine functions for the pseudo-ops `int` and `byte`.
fn pseudo_refine(
    name: &str,
    args: &[&str],
    parse_binary: &dyn Fn(&[&str]) -> Option<usize>,
) -> Option<Vec<StackType>> {
    match name {
        // typePushInt: one entry per token, decimal-parseable ones constant.
        "typePushInt" => Some(
            args.iter()
                .map(|a| match a.parse::<u64>() {
                    Ok(v) if a.bytes().all(|b| b.is_ascii_digit()) => {
                        StackType::bounded(Avm::Uint64, v, v)
                    }
                    _ => UINT64,
                })
                .collect(),
        ),
        // typeByte
        "typeByte" => {
            if args.is_empty() {
                return Some(vec![BYTES]);
            }
            let l = parse_binary(args).unwrap_or(0) as u64;
            Some(vec![StackType::bounded(Avm::Bytes, l, l)])
        }
        _ => None,
    }
}

/// Tracks one instruction's effect on the static type stack (go's per
/// instruction block in `parseText`, before the opcode is assembled),
/// reporting type errors like any other assembly error. `col` is the column of
/// the mnemonic token; `byte_len` returns the decoded length of a `byte`
/// literal's tokens.
pub(crate) fn track_instruction(
    ops: &mut OpStream,
    col: usize,
    mnemonic: &str,
    args: &[&str],
    byte_len: &dyn Fn(&[&str]) -> Option<usize>,
) {
    let Some(spec) = get_spec(ops, mnemonic, args.len()) else {
        return;
    };
    let mut arg_types = spec.args.clone();
    let mut return_types = spec.returns.clone();
    if spec.refine == "typePushInt" || spec.refine == "typeByte" {
        if let Some(r) = pseudo_refine(&spec.refine, args, byte_len) {
            return_types = r;
        }
    } else if !spec.refine.is_empty() {
        let txn_fields = op_entry("itxn_field")
            .and_then(|e| e.imms.first())
            .and_then(|i| i.group);
        let r = run_refine(&spec.refine, &mut ops.known, args, txn_fields);
        if let Some(e) = r.err {
            type_error(ops, col, e);
        }
        if let Some(a) = r.args {
            arg_types = a;
        }
        if let Some(rt) = r.returns {
            return_types = rt;
        }
    }
    track_stack(ops, col, &arg_types, &return_types, &spec.instruction, args);
    refine_field_return(ops, &spec, args);
    let deadens = spec.entry.is_some_and(|e| e.deadens);
    if deadens {
        ops.known.deaden();
    }
    if spec.name == "callsub" {
        // `retsub` returns right after the `callsub`: an entry point like a label.
        ops.known.label();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlaps_matches_go_semantics() {
        assert!(ANY.overlaps(UINT64));
        assert!(UINT64.overlaps(ANY));
        assert!(ANY.overlaps(ANY));
        assert!(UINT64.overlaps(UINT64));
        assert!(BYTES.overlaps(BYTES));
        assert!(!UINT64.overlaps(BYTES));
        assert!(!BYTES.overlaps(UINT64));
        assert!(!NONE.overlaps(ANY));
        let b32 = StackType::new(Avm::Bytes, 32, 32, None);
        assert!(b32.overlaps(BYTES));
        assert!(!b32.overlaps(StackType::new(Avm::Bytes, 33, 33, None)));
    }

    #[test]
    fn union_matches_go_semantics() {
        assert_eq!(UINT64.union(UINT64), UINT64);
        assert_eq!(BYTES.union(BYTES), BYTES);
        assert_eq!(UINT64.union(BYTES), ANY);
        assert_eq!(ANY.union(UINT64), ANY);
        let a = StackType::new(Avm::Bytes, 3, 3, None);
        let b = StackType::new(Avm::Bytes, 5, 5, None);
        assert_eq!(a.union(b).to_string(), "[3-5]byte");
    }

    #[test]
    fn display_matches_go_names() {
        assert_eq!(UINT64.to_string(), "uint64");
        assert_eq!(BYTES.to_string(), "[]byte");
        assert_eq!(ANY.to_string(), "any");
        assert_eq!(StackType::new(Avm::Uint64, 7, 7, None).to_string(), "7");
        assert_eq!(
            StackType::new(Avm::Uint64, 0, 5, None).to_string(),
            "uint64 (<= 5)"
        );
        assert_eq!(
            StackType::new(Avm::Uint64, 2, 5, None).to_string(),
            "uint64 (2-5)"
        );
        assert_eq!(
            StackType::new(Avm::Bytes, 0, 5, None).to_string(),
            "[<=5]byte"
        );
        assert_eq!(
            StackType::new(Avm::Bytes, 32, 32, Some("address")).to_string(),
            "address"
        );
    }

    #[test]
    fn parse_int_matches_go_base_zero() {
        assert_eq!(go_parse_int("0x10", 9), Some(16));
        assert_eq!(go_parse_int("0b11", 9), Some(3));
        assert_eq!(go_parse_int("017", 9), Some(15));
        assert_eq!(go_parse_int("1_0", 9), Some(10));
        assert_eq!(go_parse_int("-256", 9), Some(-256));
        assert_eq!(go_parse_int("256", 9), None);
        assert_eq!(go_parse_int("_1", 9), None);
        assert_eq!(go_parse_int("0", 9), Some(0));
        assert_eq!(go_parse_int("", 9), None);
    }

    #[test]
    fn every_refine_function_of_the_go_table_is_ported() {
        let mut p = Knowledge::new();
        for e in OPS {
            for v in e.variants {
                if v.refine.is_empty() {
                    continue;
                }
                // `run_refine` debug-asserts on an unported name.
                let _ = run_refine(v.refine, &mut p, &[], None);
            }
        }
    }
}
