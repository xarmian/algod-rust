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

//! TEAL disassembler: converts AVM bytecode back into TEAL source text.
//!
//! [`disassemble`] is a port of go-algorand's `logic.Disassemble`
//! (`data/transactions/logic/assembler.go`: `disassembleInstrumented` and
//! `disassemble`): one forward pass over the raw bytes that numbers labels in
//! the order each branch target is first met, re-runs itself once when a
//! backward jump names a label that was not yet known, and reports exactly
//! go's error strings (issue #2367, epic #2364). [`pc_details`] renders the
//! already-parsed program of a running machine instead.

use std::collections::{HashMap, HashSet};

use crate::bytecode::{self, Immediates, Instruction, Program};
use crate::fields;
use crate::opcode::{self, ImmKind, Mode, OpSpec};

/// Disassemble AVM bytecode into TEAL source text.
///
/// Produces exactly the text, or exactly the error string, of go-algorand's
/// `Disassemble()`. A program whose version is newer than this implementation
/// supports is not an error but the single comment line go prints for it, and
/// so is an undecodable version prefix (`// invalid version`, which includes
/// the empty program).
/// `AssembleString(Disassemble(program))` produces the same bytecode for the
/// programs the assembler can express.
pub fn disassemble(program: &[u8]) -> Result<String, String> {
    let (version, vlen) = uvarint(program);
    if vlen <= 0 {
        return Ok("// invalid version\n".to_string());
    }
    if version > u64::from(opcode::MAX_AVM_VERSION) {
        return Ok(format!("// unsupported version {version}\n"));
    }
    let version = version as u8;
    let mut pass = disassemble_pass(program, version, vlen as usize, None)?;
    if pass.rerun {
        // A back-jump named a label that did not exist yet: go runs the whole
        // disassembly again with every label found by the first pass.
        let labels = std::mem::take(&mut pass.pending);
        pass = disassemble_pass(program, version, vlen as usize, Some(labels))?;
        if pass.rerun {
            return Err("rerun even though we had labels".to_string());
        }
    }
    let mut text = format!("#pragma version {version}\n");
    // If reassembling this program at its own version would auto-salt it
    // by default (i.e. it's a v13+ stateless program whose hash happens to
    // be on-curve — either untouched legacy bytes, or bytes an explicit
    // `#pragma autosalt false` opted out of salting), emit that pragma so
    // `AssembleString(Disassemble(program))` round-trips to the same bytes
    // instead of silently re-salting (and thus changing the hash). Matches
    // go-algorand's `finalizeDisassemblyWithPragmas` (`assembler.go`).
    if crate::assembler::default_auto_salt_applies(version, pass.has_stateful_ops, program) {
        text.push_str("#pragma autosalt false\n");
    }
    text.push_str(&pass.body);
    Ok(text)
}

/// go's `binary.Uvarint`: the value and the bytes read, `0` when `buf` ends
/// inside the varint and `-(bytes read)` when it overflows 64 bits.
fn uvarint(buf: &[u8]) -> (u64, i64) {
    let (mut x, mut s) = (0u64, 0u32);
    for (i, &b) in buf.iter().enumerate() {
        if i == 10 {
            return (0, -(i as i64 + 1));
        }
        if b < 0x80 {
            if i == 9 && b > 1 {
                return (0, -(i as i64 + 1));
            }
            return (x | (u64::from(b) << s), i as i64 + 1);
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    (0, 0)
}

/// go's `binary.Varint` (zigzag over [`uvarint`]).
fn varint(buf: &[u8]) -> (i64, i64) {
    let (ux, n) = uvarint(buf);
    let mut x = (ux >> 1) as i64;
    if ux & 1 != 0 {
        x = !x;
    }
    (x, n)
}

/// One go `immediate` of an opcode: its kind and, for the single-byte kinds,
/// the name go prints in decode errors.
enum Imm {
    Byte(&'static str),
    Int8(&'static str),
    Label,
    Int,
    Bytes,
    Ints,
    Bytess,
    Labels,
}

/// The immediates of `spec` as go's `OpDetails.Immediates` lists them.
fn immediates_of(spec: &OpSpec) -> Vec<Imm> {
    let names = bytecode::uint8_immediate_names(spec.name).unwrap_or(&[]);
    let byte = |i: usize| {
        let n = names.get(i).copied().unwrap_or("?");
        if matches!(spec.name, "frame_dig" | "frame_bury") {
            Imm::Int8(n)
        } else {
            Imm::Byte(n)
        }
    };
    match spec.imm {
        ImmKind::None => vec![],
        ImmKind::Uint8 => vec![byte(0)],
        ImmKind::Uint8Uint8 => vec![byte(0), byte(1)],
        ImmKind::Uint8Uint8Uint8 => vec![byte(0), byte(1), byte(2)],
        ImmKind::Int16 | ImmKind::BranchVarint => vec![Imm::Label],
        ImmKind::Varuint => vec![Imm::Int],
        ImmKind::VaruintBytes => vec![Imm::Bytes],
        ImmKind::IntcBlock | ImmKind::PushInts => vec![Imm::Ints],
        ImmKind::BytecBlock | ImmKind::PushBytess => vec![Imm::Bytess],
        ImmKind::Labels => vec![Imm::Labels],
    }
}

/// How a single-byte immediate resolves through go's `FieldGroup.Names`.
enum Group {
    /// The immediate is a plain number.
    None,
    /// The byte names a field.
    Name(&'static str),
    /// A group immediate whose byte names nothing (go's "invalid immediate").
    Invalid,
}

/// go's `imm.Group.Names[b]` for the `imm_idx`-th immediate of `op`. The
/// transaction-field groups differ per opcode: the scalar opcodes list only
/// non-array fields, the `*a`/`*as` opcodes only array fields, and
/// `itxn_field`/`gitxn` every field.
fn group_name(op: &str, imm_idx: usize, b: u8) -> Group {
    let txn_names = |want_array: Option<bool>| match fields::txn_field_name(b) {
        Some(n) => {
            let array = fields::TxnField::from_u8(b).is_ok_and(|f| f.is_array());
            if want_array.is_none_or(|w| w == array) {
                Group::Name(n)
            } else {
                Group::Invalid
            }
        }
        None => Group::Invalid,
    };
    match (op, imm_idx) {
        ("txn", 0) | ("gtxn", 1) | ("gtxns", 0) | ("itxn", 0) => txn_names(Some(false)),
        ("txna", 0)
        | ("gtxna", 1)
        | ("gtxnsa", 0)
        | ("txnas", 0)
        | ("gtxnas", 1)
        | ("gtxnsas", 0)
        | ("itxna", 0)
        | ("itxnas", 0)
        | ("gitxna", 1)
        | ("gitxnas", 1) => txn_names(Some(true)),
        ("itxn_field", 0) | ("gitxn", 1) => txn_names(None),
        // Only the box-access fields are settable with app_params_set.
        ("app_params_set", 0) if b < 11 => Group::Invalid,
        _ if fields::opcode_immediate_is_field(op, imm_idx) => {
            match fields::field_name_for_opcode(op, imm_idx, b) {
                Some(n) => Group::Name(n),
                None => Group::Invalid,
            }
        }
        _ => Group::None,
    }
}

struct Pass {
    body: String,
    has_stateful_ops: bool,
    rerun: bool,
    pending: HashMap<i64, String>,
}

/// One run of go's `disassembleInstrumented` loop over `program`. `labels` is
/// the label set of an earlier pass (go's "retains all the labels found in the
/// first pass").
fn disassemble_pass(
    program: &[u8],
    version: u8,
    vlen: usize,
    labels: Option<HashMap<i64, String>>,
) -> Result<Pass, String> {
    let mut d = Dis {
        program,
        pc: vlen,
        next_pc: 0,
        version,
        label_count: 0,
        pending: labels.unwrap_or_default(),
        rerun: false,
        intc: Vec::new(),
        bytec: Vec::new(),
    };
    let mut body = String::new();
    let mut has_stateful_ops = false;
    // go resolves version 0 against the v1 opcode set.
    let ceiling = version.max(1);
    while d.pc < program.len() {
        d.output_label_if_needed(&mut body);
        let byte = program[d.pc];
        let top = opcode::lookup(byte).filter(|s| s.version <= ceiling);
        let mut op = top;
        if let (Some(t), true) = (top, d.pc + 1 < program.len()) {
            if let Some(subs) = t.sub_ops {
                let sub = program[d.pc + 1] as usize;
                if let Some(s) = subs
                    .get(sub)
                    .and_then(Option::as_ref)
                    .filter(|s| s.version <= ceiling)
                {
                    op = Some(s);
                }
            }
        }
        if op.is_some_and(|s| s.mode == Mode::Application) {
            has_stateful_ops = true;
        }
        let Some(spec) = op.filter(|s| s.sub_ops.is_none()) else {
            // go's getOpSpecError
            return Err(match top.filter(|t| t.sub_ops.is_some()) {
                Some(_) if d.pc + 1 >= program.len() => {
                    format!("prefix opcode 0x{byte:02x} missing sub-opcode")
                }
                Some(_) => format!(
                    "prefix opcode 0x{byte:02x} with improper sub-opcode 0x{:02x}",
                    program[d.pc + 1]
                ),
                None => format!("illegal opcode 0x{byte:02x}"),
            });
        };
        // proto marks a subroutine entry point and must always have a label so
        // that the disassembly can be validly reassembled (go-algorand PR
        // #6594): one that is never the target of a callsub gets a fresh label
        // here, which also forces the rerun that prints it.
        if spec.name == "proto" && !d.pending.contains_key(&(d.pc as i64)) {
            d.label_count += 1;
            let label = format!("label{}", d.label_count);
            d.put_label(label, d.pc as i64);
        }
        let line = d.instruction(spec)?;
        body.push_str(&line);
        body.push('\n');
        d.pc = d.next_pc;
    }
    d.output_label_if_needed(&mut body);
    Ok(Pass {
        body,
        has_stateful_ops,
        rerun: d.rerun,
        pending: d.pending,
    })
}

struct Dis<'a> {
    program: &'a [u8],
    pc: usize,
    next_pc: usize,
    version: u8,
    label_count: usize,
    pending: HashMap<i64, String>,
    rerun: bool,
    intc: Vec<u64>,
    bytec: Vec<&'a [u8]>,
}

impl<'a> Dis<'a> {
    fn put_label(&mut self, label: String, target: i64) {
        self.pending.insert(target, label);
        if target <= self.pc as i64 {
            self.rerun = true;
        }
    }

    fn output_label_if_needed(&self, out: &mut String) {
        if let Some(label) = self.pending.get(&(self.pc as i64)) {
            out.push_str(label);
            out.push_str(":\n");
        }
    }

    /// The label name of `target`, allocating the next one on first sight.
    fn label_for(&mut self, target: i64) -> String {
        if let Some(known) = self.pending.get(&target) {
            return known.clone();
        }
        self.label_count += 1;
        let label = format!("label{}", self.label_count);
        self.put_label(label.clone(), target);
        label
    }

    /// go's `disassemble`: the text of the single instruction at `self.pc`,
    /// setting `self.next_pc` past it.
    fn instruction(&mut self, spec: &'static OpSpec) -> Result<String, String> {
        let program = self.program;
        let mut out = spec.name.to_string();
        let mut pc = self.pc + 1;
        if spec.sub_opcode != 0 {
            pc += 1; // skip the sub-opcode byte; immediates follow
        }
        let varint_branch = self.version >= opcode::VARINT_BRANCH_VERSION
            && opcode::is_varint_branch_opcode(spec.opcode);
        let imms = if varint_branch {
            vec![Imm::Label]
        } else {
            immediates_of(spec)
        };
        for (idx, imm) in imms.iter().enumerate() {
            out.push(' ');
            match imm {
                Imm::Byte(name) | Imm::Int8(name) => {
                    if pc + 1 > program.len() {
                        return Err(format!(
                            "program end while reading immediate {name} for {}",
                            spec.name
                        ));
                    }
                    let b = program[pc];
                    match group_name(spec.name, idx, b) {
                        Group::Name(n) => out.push_str(n),
                        Group::Invalid => {
                            return Err(format!("invalid immediate {name} for {}: {b}", spec.name));
                        }
                        Group::None if matches!(imm, Imm::Int8(_)) => {
                            out.push_str(&(b as i8).to_string());
                        }
                        Group::None => out.push_str(&b.to_string()),
                    }
                    if spec.name == "intc" && (b as usize) < self.intc.len() {
                        out.push_str(&format!(" // {}", self.intc[b as usize]));
                    }
                    if spec.name == "bytec" && (b as usize) < self.bytec.len() {
                        out.push_str(&format!(
                            " // {}",
                            guess_byte_format(self.bytec[b as usize])
                        ));
                    }
                    pc += 1;
                }
                Imm::Label => {
                    let (offset, offset_len) = if varint_branch {
                        let (v, n) = varint(&program[pc..]);
                        if n <= 0 {
                            return Err(format!("could not decode label for {}", spec.name));
                        }
                        (v, n as usize)
                    } else {
                        if pc + 2 > program.len() {
                            return Err(format!(
                                "program end while reading label for {}",
                                spec.name
                            ));
                        }
                        (decode_branch_offset(program, pc), 2)
                    };
                    let mut target = offset
                        .wrapping_add(pc as i64)
                        .wrapping_add(offset_len as i64);
                    if varint_branch && offset < 0 {
                        // back-jump from the instruction start
                        target = (pc as i64 - 1).wrapping_add(offset);
                    }
                    out.push_str(&self.label_for(target));
                    pc += offset_len;
                }
                Imm::Int => {
                    let (val, n) = uvarint(&program[pc..]);
                    if n <= 0 {
                        return Err(format!("could not decode immediate uint for {}", spec.name));
                    }
                    out.push_str(&val.to_string());
                    pc += n as usize;
                }
                Imm::Bytes => {
                    let (length, n) = uvarint(&program[pc..]);
                    if n <= 0 {
                        return Err(format!(
                            "could not decode immediate bytes for {}",
                            spec.name
                        ));
                    }
                    pc += n as usize;
                    let end = (pc as u64).wrapping_add(length);
                    if end > program.len() as u64 || end < pc as u64 {
                        return Err(format!(
                            "could not decode immediate bytes for {}",
                            spec.name
                        ));
                    }
                    let constant = &program[pc..end as usize];
                    out.push_str(&format!(
                        "0x{} // {}",
                        bytes_to_hex(constant),
                        guess_byte_format(constant)
                    ));
                    pc = end as usize;
                }
                Imm::Ints => {
                    let (ints, next) = parse_int_imm_args(program, pc)?;
                    out.push_str(
                        &ints
                            .iter()
                            .map(u64::to_string)
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                    if spec.name == "intcblock" {
                        self.intc = ints;
                    }
                    pc = next;
                }
                Imm::Bytess => {
                    let (items, next) = parse_byte_imm_args(program, pc)?;
                    out.push_str(
                        &items
                            .iter()
                            .map(|b| format!("0x{}", bytes_to_hex(b)))
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                    if spec.name == "bytecblock" {
                        self.bytec = items;
                    }
                    pc = next;
                }
                Imm::Labels => {
                    let (targets, next) =
                        parse_labels(program, pc).map_err(|e| format!("{e} for {}", spec.name))?;
                    let labels: Vec<String> =
                        targets.into_iter().map(|t| self.label_for(t)).collect();
                    out.push_str(&labels.join(" "));
                    pc = next;
                }
            }
        }
        if let Some(n) = spec.name.strip_prefix("intc_") {
            let idx = n.bytes().next().map(|b| usize::from(b.wrapping_sub(b'0')));
            if let Some(v) = idx.and_then(|i| self.intc.get(i)) {
                out.push_str(&format!(" // {v}"));
            }
        }
        if let Some(n) = spec.name.strip_prefix("bytec_") {
            let idx = n.bytes().next().map(|b| usize::from(b.wrapping_sub(b'0')));
            if let Some(v) = idx.and_then(|i| self.bytec.get(i)) {
                out.push_str(&format!(" // {}", guess_byte_format(v)));
            }
        }
        self.next_pc = pc;
        Ok(out)
    }
}

/// go's `decodeBranchOffset`: a big-endian int16.
fn decode_branch_offset(program: &[u8], pos: usize) -> i64 {
    i64::from(i16::from_be_bytes([program[pos], program[pos + 1]]))
}

/// go's `parseIntImmArgs`.
fn parse_int_imm_args(program: &[u8], pos: usize) -> Result<(Vec<u64>, usize), String> {
    let (count, n) = uvarint(&program[pos..]);
    if n <= 0 {
        return Err(format!("could not decode length of int list at pc={pos}"));
    }
    let mut pos = pos + n as usize;
    if count > program.len() as u64 {
        return Err("const int list with too many items".to_string());
    }
    let mut ints = Vec::with_capacity(count as usize);
    for i in 0..count {
        if pos >= program.len() {
            return Err("const int list ran past end of program".to_string());
        }
        let (v, n) = uvarint(&program[pos..]);
        if n <= 0 {
            return Err(format!("could not decode int const[{i}] at pc={pos}"));
        }
        ints.push(v);
        pos += n as usize;
    }
    Ok((ints, pos))
}

/// go's `parseByteImmArgs`.
fn parse_byte_imm_args(program: &[u8], pos: usize) -> Result<(Vec<&[u8]>, usize), String> {
    let (count, n) = uvarint(&program[pos..]);
    if n <= 0 {
        return Err(format!("could not decode length of bytes list at pc={pos}"));
    }
    let mut pos = pos + n as usize;
    if count > program.len() as u64 {
        return Err("const bytes list with too many items".to_string());
    }
    let mut items = Vec::with_capacity(count as usize);
    for i in 0..count {
        if pos >= program.len() {
            return Err("const bytes list ran past end of program".to_string());
        }
        let (len, n) = uvarint(&program[pos..]);
        if n <= 0 {
            return Err(format!("could not decode []byte const[{i}] at pc={pos}"));
        }
        pos += n as usize;
        let end = (pos as u64).wrapping_add(len);
        if end > program.len() as u64 || end < pos as u64 {
            return Err("const bytes list ran past end of program".to_string());
        }
        items.push(&program[pos..end as usize]);
        pos = end as usize;
    }
    Ok((items, pos))
}

/// go's `parseLabels` (switch/match): the absolute branch targets.
fn parse_labels(program: &[u8], pos: usize) -> Result<(Vec<i64>, usize), String> {
    if pos >= program.len() {
        return Err("could not decode label count".to_string());
    }
    let count = program[pos] as usize;
    let mut pos = pos + 1;
    let end = pos + 2 * count; // end of op: offset is applied to this position
    if end > program.len() {
        return Err("could not decode labels".to_string());
    }
    let mut targets = Vec::with_capacity(count);
    for _ in 0..count {
        targets.push(end as i64 + decode_branch_offset(program, pos));
        pos += 2;
    }
    Ok((targets, pos))
}

/// go's `pcDetails` (`data/transactions/logic/eval.go`): the disassembly of
/// the instruction at byte offset `pc` (the version byte counts) and of up to
/// two instructions before it, with newlines turned into `; `. This is the
/// `opcodes=` of the `Details` go prints for a failed application call in
/// simulate. Empty when `pc` is not the start of an instruction.
pub fn pc_details(parsed: &Program, pc: usize) -> String {
    let Ok((text, offsets)) = disassemble_parsed(parsed) else {
        return String::new();
    };
    const MAX_ADDITIONAL_OPCODES: usize = 2;
    for (i, (opc, _)) in offsets.iter().enumerate() {
        if *opc != pc {
            continue;
        }
        let start = i.saturating_sub(MAX_ADDITIONAL_OPCODES);
        let start_text = offsets[start].1;
        let end_text = offsets.get(i + 1).map_or(text.len(), |(_, off)| *off);
        return text[start_text..end_text]
            .trim_end_matches('\n')
            .replace('\n', "; ");
    }
    String::new()
}

/// The disassembly of `parsed`, and for every instruction the pair `(byte
/// offset with the version byte, offset of its text)` (go's `pcOffset`: after
/// the label line that precedes it). Used by [`pc_details`] only; it renders a
/// program that already parsed, so unlike [`disassemble`] it never meets a
/// malformed one.
fn disassemble_parsed(parsed: &Program) -> Result<(String, Vec<(usize, usize)>), String> {
    let header = if parsed.version < 128 { 1 } else { 2 };
    let mut offsets: Vec<(usize, usize)> = Vec::with_capacity(parsed.instructions.len());

    // Two-pass disassembly:
    // Pass 1: identify branch targets and assign labels
    // Pass 2: emit TEAL text

    let labels = collect_labels(parsed);
    let intc = collect_intc_block(parsed);
    let bytec = collect_bytec_block(parsed);

    let mut out = String::new();
    out.push_str(&format!("#pragma version {}\n", parsed.version));
    for instr in &parsed.instructions {
        // Emit label if this offset is a branch target
        if let Some(label) = labels.get(&instr.offset) {
            out.push_str(&format!("{}:\n", label));
        }

        let spec = opcode::resolve_spec(instr.opcode, instr.sub_opcode);
        let name = spec.map(|s| s.name).unwrap_or("???");

        let mut line = name.to_string();

        match &instr.immediates {
            Immediates::None => {
                // intc_N and bytec_N comments
                if name.starts_with("intc_") {
                    let idx = (name.as_bytes()[name.len() - 1] - b'0') as usize;
                    if idx < intc.len() {
                        line.push_str(&format!(" // {}", intc[idx]));
                    }
                } else if name.starts_with("bytec_") {
                    let idx = (name.as_bytes()[name.len() - 1] - b'0') as usize;
                    if idx < bytec.len() {
                        line.push_str(&format!(" // {}", guess_byte_format(&bytec[idx])));
                    }
                }
            }
            Immediates::Uint8(b) => {
                // Try field name resolution
                if let Some(field_name) = fields::field_name_for_opcode(name, 0, *b) {
                    line.push_str(&format!(" {}", field_name));
                } else if name == "frame_dig" || name == "frame_bury" {
                    // int8 immediate
                    line.push_str(&format!(" {}", *b as i8));
                } else if fields::opcode_immediate_is_field(name, 0) {
                    // This position resolves through a named field group,
                    // but the byte doesn't name any known field -- matches
                    // go-algorand's `Disassemble` ("invalid immediate %s
                    // for %s", assembler.go) instead of silently printing
                    // the raw byte.
                    return Err(format!("invalid immediate f for {}", name));
                } else {
                    line.push_str(&format!(" {}", b));
                }
                // intc/bytec comments
                if name == "intc" && (*b as usize) < intc.len() {
                    line.push_str(&format!(" // {}", intc[*b as usize]));
                }
                if name == "bytec" && (*b as usize) < bytec.len() {
                    line.push_str(&format!(" // {}", guess_byte_format(&bytec[*b as usize])));
                }
            }
            Immediates::Uint8Pair(a, b) => {
                // First immediate
                if let Some(field_name) = fields::field_name_for_opcode(name, 0, *a) {
                    line.push_str(&format!(" {}", field_name));
                } else if fields::opcode_immediate_is_field(name, 0) {
                    return Err(format!("invalid immediate f for {}", name));
                } else {
                    line.push_str(&format!(" {}", a));
                }
                // Second immediate
                if let Some(field_name) = fields::field_name_for_opcode(name, 1, *b) {
                    line.push_str(&format!(" {}", field_name));
                } else if fields::opcode_immediate_is_field(name, 1) {
                    return Err(format!("invalid immediate f for {}", name));
                } else {
                    line.push_str(&format!(" {}", b));
                }
            }
            Immediates::Uint8Triple(a, b, c) => {
                // First immediate
                if let Some(field_name) = fields::field_name_for_opcode(name, 0, *a) {
                    line.push_str(&format!(" {}", field_name));
                } else if fields::opcode_immediate_is_field(name, 0) {
                    return Err(format!("invalid immediate f for {}", name));
                } else {
                    line.push_str(&format!(" {}", a));
                }
                // Second immediate
                if let Some(field_name) = fields::field_name_for_opcode(name, 1, *b) {
                    line.push_str(&format!(" {}", field_name));
                } else if fields::opcode_immediate_is_field(name, 1) {
                    return Err(format!("invalid immediate f for {}", name));
                } else {
                    line.push_str(&format!(" {}", b));
                }
                // Third immediate
                line.push_str(&format!(" {}", c));
            }
            Immediates::Int16(_offset) => {
                // Branch instruction — use label
                let target = compute_branch_target(instr);
                if let Some(label) = labels.get(&target) {
                    line.push_str(&format!(" {}", label));
                } else {
                    // Fallback: use raw target
                    line.push_str(&format!(" {}", target));
                }
            }
            Immediates::BranchVarint(offset, varint_len) => {
                // bnz/bz/b/callsub at LogicSigVersion >= 13 — use label.
                let target = bytecode::varint_branch_target(instr.offset, *varint_len, *offset);
                let target = if target >= 0 { target as usize } else { 0 };
                if let Some(label) = labels.get(&target) {
                    line.push_str(&format!(" {}", label));
                } else {
                    line.push_str(&format!(" {}", target));
                }
            }
            Immediates::Varuint(val) => {
                line.push_str(&format!(" {}", val));
            }
            Immediates::Bytes(bytes) => {
                let hex_str = bytes_to_hex(bytes);
                let fmt = guess_byte_format(bytes);
                line.push_str(&format!(" 0x{} // {}", hex_str, fmt));
            }
            Immediates::IntBlock(vals) => {
                for v in vals {
                    line.push(' ');
                    line.push_str(&format!("{}", v));
                }
            }
            Immediates::ByteBlock(entries) => {
                for bv in entries {
                    line.push(' ');
                    line.push_str(&format!("0x{}", bytes_to_hex(bv)));
                }
            }
            Immediates::PushInts(vals) => {
                for v in vals {
                    line.push_str(&format!(" {}", v));
                }
            }
            Immediates::PushBytess(entries) => {
                for bv in entries {
                    line.push_str(&format!(" 0x{}", bytes_to_hex(bv)));
                }
            }
            Immediates::Labels(offsets) => {
                // switch/match — resolve each offset to a label
                let end_of_instr = compute_labels_end(instr, offsets.len());
                for offset in offsets {
                    let target = (end_of_instr as isize + *offset as isize) as usize;
                    if let Some(label) = labels.get(&target) {
                        line.push_str(&format!(" {}", label));
                    } else {
                        line.push_str(&format!(" {}", target));
                    }
                }
            }
        }

        offsets.push((header + instr.offset, out.len()));
        out.push_str(&line);
        out.push('\n');
    }

    // Emit any trailing label
    let end_offset = parsed
        .instructions
        .last()
        .map(|i| i.offset + instruction_size(i))
        .unwrap_or(0);
    if let Some(label) = labels.get(&end_offset) {
        out.push_str(&format!("{}:\n", label));
    }

    Ok((out, offsets))
}

/// Compute the branch target (offset within the code section) for a branch instruction.
fn compute_branch_target(instr: &Instruction) -> usize {
    if let Immediates::Int16(offset) = instr.immediates {
        // Target = end of this instruction + offset
        // Instruction is: opcode (1 byte) + offset (2 bytes) = 3 bytes from instr.offset
        let end_of_instr = instr.offset + 3;
        (end_of_instr as isize + offset as isize) as usize
    } else {
        0
    }
}

/// Compute the end offset for a Labels (switch/match) instruction.
fn compute_labels_end(instr: &Instruction, count: usize) -> usize {
    // Layout: opcode (1) + count (1) + count*2 bytes of offsets
    instr.offset + 1 + 1 + count * 2
}

/// Compute the total size (in bytes) of an instruction including its immediates.
///
/// Only used for the program's final trailing-label offset (line ~194);
/// mid-program instruction boundaries come from `Instruction::offset`
/// itself, not from summing sizes.
fn instruction_size(instr: &Instruction) -> usize {
    // Header is 2 bytes (prefix + sub-opcode) for a multi-byte "prefix
    // opcode" instruction (e.g. the `app_box_*` family at 0xd4), 1 byte
    // otherwise -- must match `header_len` in `opcode::resolve`/
    // `bytecode::parse`. Every match arm below assumes a 1-byte header, so
    // add the extra byte up front rather than in each arm.
    let header_extra = if instr.sub_opcode.is_some() { 1 } else { 0 };
    header_extra
        + match &instr.immediates {
            Immediates::None => 1,
            Immediates::Uint8(_) => 2,
            Immediates::Uint8Pair(_, _) => 2 + 1,
            Immediates::Uint8Triple(_, _, _) => 4,
            Immediates::Int16(_) => 3,
            Immediates::Varuint(v) => 1 + varuint_size(*v),
            Immediates::Bytes(b) => 1 + varuint_size(b.len() as u64) + b.len(),
            Immediates::IntBlock(vals) => {
                1 + varuint_size(vals.len() as u64)
                    + vals.iter().map(|v| varuint_size(*v)).sum::<usize>()
            }
            Immediates::ByteBlock(entries) => {
                1 + varuint_size(entries.len() as u64)
                    + entries
                        .iter()
                        .map(|b| varuint_size(b.len() as u64) + b.len())
                        .sum::<usize>()
            }
            Immediates::PushInts(vals) => {
                1 + varuint_size(vals.len() as u64)
                    + vals.iter().map(|v| varuint_size(*v)).sum::<usize>()
            }
            Immediates::PushBytess(entries) => {
                1 + varuint_size(entries.len() as u64)
                    + entries
                        .iter()
                        .map(|b| varuint_size(b.len() as u64) + b.len())
                        .sum::<usize>()
            }
            Immediates::Labels(offsets) => 1 + 1 + offsets.len() * 2,
            Immediates::BranchVarint(_, len) => 1 + len,
        }
}

fn varuint_size(mut v: u64) -> usize {
    let mut size = 0;
    loop {
        size += 1;
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    size
}

/// Collect all branch targets from the program and assign label names.
fn collect_labels(program: &Program) -> HashMap<usize, String> {
    let mut targets: Vec<usize> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();

    for instr in &program.instructions {
        match &instr.immediates {
            Immediates::Int16(offset) => {
                let target = compute_branch_target(instr);
                if seen.insert(target) {
                    targets.push(target);
                }
                let _ = offset;
            }
            Immediates::Labels(offsets) => {
                let end_of_instr = compute_labels_end(instr, offsets.len());
                for offset in offsets {
                    let target = (end_of_instr as isize + *offset as isize) as usize;
                    if seen.insert(target) {
                        targets.push(target);
                    }
                }
            }
            Immediates::BranchVarint(offset, varint_len) => {
                let target = bytecode::varint_branch_target(instr.offset, *varint_len, *offset);
                if target >= 0 {
                    let target = target as usize;
                    if seen.insert(target) {
                        targets.push(target);
                    }
                }
            }
            _ => {}
        }

        // A `proto` marks a subroutine entry point. go-algorand's
        // disassembler always synthesizes a label immediately before a
        // `proto` that isn't already a recorded branch target (e.g. a
        // subroutine reached only by `b`, skipping over it, rather than by
        // `callsub`) — see assembler.go's `disassembleInstrumented`, fixed by
        // go-algorand PR #6594. Without this, a dead subroutine's `proto`
        // would disassemble with no preceding label, which go-algorand's
        // stricter assembler (a `typeProto` "unreachable from previous PC"
        // check that algod-rust does not yet implement) rejects on
        // reassembly. Mirror the label regardless, so disassembly text
        // matches go-algorand's and a future stricter check doesn't
        // reintroduce this exact bug.
        if opcode::lookup(instr.opcode).map(|s| s.name) == Some("proto")
            && seen.insert(instr.offset)
        {
            targets.push(instr.offset);
        }
    }

    // Sort targets and assign label names
    targets.sort();
    let mut labels = HashMap::new();
    for (i, &target) in targets.iter().enumerate() {
        labels.insert(target, format!("label{}", i + 1));
    }
    labels
}

/// Extract the intcblock values from the program (if present).
fn collect_intc_block(program: &Program) -> Vec<u64> {
    for instr in &program.instructions {
        if instr.opcode == 0x20 {
            // intcblock
            if let Immediates::IntBlock(vals) = &instr.immediates {
                return vals.clone();
            }
        }
    }
    Vec::new()
}

/// Extract the bytecblock values from the program (if present).
fn collect_bytec_block(program: &Program) -> Vec<Vec<u8>> {
    for instr in &program.instructions {
        if instr.opcode == 0x26 {
            // bytecblock
            if let Immediates::ByteBlock(entries) = &instr.immediates {
                return entries.clone();
            }
        }
    }
    Vec::new()
}

/// Format a byte slice for display, matching go-algorand's `guessByteFormat`.
fn guess_byte_format(bytes: &[u8]) -> String {
    if bytes.len() == 32 {
        // Could be an Algorand address — encode as addr
        let addr = encode_algorand_address(bytes);
        return format!("addr {}", addr);
    }
    if all_printable_ascii(bytes) {
        // go's `%#v` of a string: only the quote and the backslash need
        // escaping inside printable ASCII.
        let mut quoted = String::with_capacity(bytes.len() + 2);
        quoted.push('"');
        for &b in bytes {
            if b == b'"' || b == b'\\' {
                quoted.push('\\');
            }
            quoted.push(char::from(b));
        }
        quoted.push('"');
        return quoted;
    }
    format!("0x{}", bytes_to_hex(bytes))
}

fn all_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| (32..=126).contains(&b))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Encode 32 bytes as an Algorand address (base32 with checksum).
fn encode_algorand_address(pubkey: &[u8]) -> String {
    use sha2::{Digest, Sha512_256};
    let hash = Sha512_256::digest(pubkey);
    let checksum = &hash[28..32];

    let mut addr_bytes = Vec::with_capacity(36);
    addr_bytes.extend_from_slice(pubkey);
    addr_bytes.extend_from_slice(checksum);

    data_encoding::BASE32_NOPAD.encode(&addr_bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::assemble_string;

    #[test]
    fn test_disassemble_simple() {
        // Version 2, intcblock [1], intc_0, return
        let program = vec![
            0x02, // version 2
            0x20, 0x01, 0x01, // intcblock [1]
            0x22, // intc_0
            0x43, // return
        ];
        let text = disassemble(&program).unwrap();
        assert!(text.contains("#pragma version 2"));
        assert!(text.contains("intcblock 1"));
        assert!(text.contains("intc_0"));
        assert!(text.contains("return"));
    }

    #[test]
    fn test_disassemble_with_labels() {
        // Version 2, b +2, err, intcblock [1], intc_0, return
        let program = vec![
            0x02, // version 2
            0x42, 0x00, 0x01, // b +1 (skip next instruction)
            0x00, // err
            0x20, 0x01, 0x01, // intcblock [1]
            0x22, // intc_0
            0x43, // return
        ];
        let text = disassemble(&program).unwrap();
        assert!(text.contains("#pragma version 2"));
        assert!(text.contains("b label"));
    }

    #[test]
    fn test_disassemble_global_field() {
        let program = vec![
            0x02, // version 2
            0x32, 0x00, // global MinTxnFee
        ];
        let text = disassemble(&program).unwrap();
        assert!(text.contains("global MinTxnFee"));
    }

    #[test]
    fn test_disassemble_txn_field() {
        let program = vec![
            0x02, // version 2
            0x31, 0x00, // txn Sender
        ];
        let text = disassemble(&program).unwrap();
        assert!(text.contains("txn Sender"));
    }

    #[test]
    fn test_disassemble_txna_aliasing() {
        // Mirrors go-algorand's TestDisassembleTxna
        // (data/transactions/logic/assembler_test.go): `txn Accounts 0`
        // assembles to the same bytecode as `txna Accounts 0` and both must
        // disassemble back to the `txna` spelling, at every version from
        // gtxna's introduction (v2) through the current max version.
        for v in 2..=13u8 {
            let txna_source = format!("#pragma version {v}\ntxna Accounts 0\npop\n");
            let txna_ops = assemble_string(&txna_source).unwrap();
            let txna_disassembled = disassemble(&txna_ops.program).unwrap();
            assert!(
                txna_disassembled.contains("txna Accounts 0"),
                "v{v}: expected 'txna Accounts 0' in {txna_disassembled}"
            );

            // `txn Accounts 0` (an array field with an index) is a pseudo-op
            // that assembles to the txna opcode -- verify the resulting
            // bytecode is byte-identical and disassembles identically.
            let txn_alias_source = format!("#pragma version {v}\ntxn Accounts 0\npop\n");
            let txn_alias_ops = assemble_string(&txn_alias_source).unwrap();
            assert_eq!(
                txna_ops.program, txn_alias_ops.program,
                "v{v}: `txn Accounts 0` should assemble identically to `txna Accounts 0`"
            );
            let txn_alias_disassembled = disassemble(&txn_alias_ops.program).unwrap();
            assert_eq!(
                txna_disassembled, txn_alias_disassembled,
                "v{v}: disassembly of the txn-alias form should match the txna form"
            );
        }
    }

    #[test]
    fn test_disassemble_gtxna_aliasing() {
        // Mirrors go-algorand's TestDisassembleGtxna.
        for v in 2..=13u8 {
            let gtxna_source = format!("#pragma version {v}\ngtxna 0 Accounts 0\npop\n");
            let gtxna_ops = assemble_string(&gtxna_source).unwrap();
            let gtxna_disassembled = disassemble(&gtxna_ops.program).unwrap();
            assert!(
                gtxna_disassembled.contains("gtxna 0 Accounts 0"),
                "v{v}: expected 'gtxna 0 Accounts 0' in {gtxna_disassembled}"
            );

            let gtxn_alias_source = format!("#pragma version {v}\ngtxn 0 Accounts 0\npop\n");
            let gtxn_alias_ops = assemble_string(&gtxn_alias_source).unwrap();
            assert_eq!(
                gtxna_ops.program, gtxn_alias_ops.program,
                "v{v}: `gtxn 0 Accounts 0` should assemble identically to `gtxna 0 Accounts 0`"
            );
            let gtxn_alias_disassembled = disassemble(&gtxn_alias_ops.program).unwrap();
            assert_eq!(
                gtxna_disassembled, gtxn_alias_disassembled,
                "v{v}: disassembly of the gtxn-alias form should match the gtxna form"
            );
        }
    }

    #[test]
    fn test_roundtrip_simple() {
        let source = "#pragma version 2\nint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        // Reassemble the disassembled text
        let ops2 = assemble_string(&text).unwrap();
        assert_eq!(ops.program, ops2.program);
    }

    #[test]
    fn test_roundtrip_with_branches() {
        let source = "#pragma version 2\nint 1\nbnz end\nint 0\nend:\nint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        let ops2 = assemble_string(&text).unwrap();
        assert_eq!(ops.program, ops2.program);
    }

    #[test]
    fn test_roundtrip_pushint() {
        let source = "#pragma version 3\npushint 42\nreturn\n";
        let ops = assemble_string(source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        let ops2 = assemble_string(&text).unwrap();
        assert_eq!(ops.program, ops2.program);
    }

    /// Port of go-algorand's `TestDisassembleBytecblock`: disassembling a
    /// program that references an `intcblock`/`bytecblock` both directly
    /// (`intc_0`.."intc 4", `bytec_0`.."bytec 4") and again through a
    /// `pushints`/`pushbytess` instruction (which pushes its own literal
    /// values, unrelated to the const blocks, but is followed by more
    /// const-block references) must decode every `intc_N`/`bytec_N`/`intc
    /// n`/`bytec n` reference to its exact value-comment, in both places --
    /// not just the single decode go's `test_bytecblock`-equivalent
    /// (`bytecode::tests::test_bytecblock`) checks. This asserts the emitted
    /// source line-by-line, matching go's `requireDisassembledSource`.
    #[test]
    fn test_disassemble_bytecblock_value_comments_intc_and_bytec() {
        let intc_source = "#pragma version 8\n\
intcblock 0 1 2 3 4 5\n\
intc_0 // 0\n\
intc_1 // 1\n\
intc_2 // 2\n\
intc_3 // 3\n\
intc 4 // 4\n\
pushints 6\n\
intc_0 // 0\n\
intc_1 // 1\n\
intc_2 // 2\n\
intc_3 // 3\n\
intc 4 // 4\n";
        let ops = assemble_string(intc_source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        assert_eq!(text, intc_source);
        // And the disassembled text must reassemble to the identical bytes.
        let ops2 = assemble_string(&text).unwrap();
        assert_eq!(ops.program, ops2.program);

        let bytec_source = "#pragma version 8\n\
bytecblock 0x6869 0x414243 0x74657374 0x666f7572 0x6c617374\n\
bytec_0 // \"hi\"\n\
bytec_1 // \"ABC\"\n\
bytec_2 // \"test\"\n\
bytec_3 // \"four\"\n\
bytec 4 // \"last\"\n\
pushbytess 0x6576696c\n\
bytec_0 // \"hi\"\n\
bytec_1 // \"ABC\"\n\
bytec_2 // \"test\"\n\
bytec_3 // \"four\"\n\
bytec 4 // \"last\"\n";
        let ops = assemble_string(bytec_source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        assert_eq!(text, bytec_source);
        let ops2 = assemble_string(&text).unwrap();
        assert_eq!(ops.program, ops2.program);
    }

    #[test]
    fn test_disassemble_pushbytes() {
        let program = vec![
            0x03, // version 3
            0x80, 0x03, 0x01, 0x02, 0x03, // pushbytes 0x010203
        ];
        let text = disassemble(&program).unwrap();
        assert!(text.contains("pushbytes 0x010203"));
    }

    #[test]
    fn test_empty_program() {
        // go: `binary.Uvarint` of nothing reads zero bytes, so the program has
        // no decodable version and `Disassemble` returns that comment.
        assert_eq!(disassemble(&[]).unwrap(), "// invalid version\n");
    }

    /// Port of go-algorand's `TestDisassembleDeadSubroutine`
    /// (data/transactions/logic/assembler_test.go, added by PR #6594,
    /// commit 03a79c91d): a subroutine that is skipped over by `b` (not
    /// reached via `callsub`) and thus never a recorded branch target must
    /// still get a label synthesized immediately before its `proto` opcode
    /// during disassembly, so that reassembling the disassembly round-trips
    /// to identical bytecode. `frame_dig`/`proto`/`retsub` are available
    /// from AVM version 8 (fpVersion) onward, up through this crate's
    /// `MAX_AVM_VERSION`.
    #[test]
    fn test_roundtrip_dead_subroutine() {
        for v in 8..=crate::opcode::MAX_AVM_VERSION {
            let source = format!(
                "#pragma version {v}\nb main\n\ndead_sub:\nproto 2 1\nframe_dig -2\nframe_dig -1\n+\nretsub\n\nmain:\nint 1\n"
            );
            let ops = assemble_string(&source)
                .unwrap_or_else(|e| panic!("v={v}: failed to assemble source: {e:?}"));
            let text = disassemble(&ops.program)
                .unwrap_or_else(|e| panic!("v={v}: failed to disassemble: {e}"));
            // The disassembly must contain a label immediately before the
            // dead subroutine's `proto`, matching go-algorand's
            // disassembleInstrumented (PR #6594) — not just an incidentally
            // round-tripping bytecode.
            assert!(
                text.contains(":\nproto 2 1\n"),
                "v={v}: expected a label immediately before the dead subroutine's proto\ndisassembly:\n{text}"
            );
            let ops2 = assemble_string(&text).unwrap_or_else(|e| {
                panic!(
                    "v={v}: disassembly of program with dead subroutine could not be reassembled: {e:?}\n{text}"
                )
            });
            assert_eq!(
                ops.program, ops2.program,
                "v={v}: round-trip bytecode mismatch\ndisassembly:\n{text}"
            );
        }
    }

    // -------------------------------------------------------------------
    // app_box_* foreign-box opcodes (prefix 0xd4, issue #662): the
    // disassembler must print the correct per-sub-opcode mnemonic (not the
    // synthetic prefix-family name) and round-trip through the assembler
    // back to identical bytes.
    // -------------------------------------------------------------------

    #[test]
    fn test_disassemble_app_box_create_shows_real_mnemonic() {
        let source = "#pragma version 13\nint 7\nbyte \"k\"\nint 10\napp_box_create\n";
        let ops = assemble_string(source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        assert!(
            text.contains("app_box_create"),
            "expected the real per-sub-opcode mnemonic, got:\n{text}"
        );
        assert!(
            !text.contains("app_box\n") && !text.contains("app_box "),
            "must not print the synthetic prefix-family stub name:\n{text}"
        );
    }

    #[test]
    fn test_disassemble_app_box_create_roundtrips() {
        let source = "#pragma version 13\nint 7\nbyte \"k\"\nint 10\napp_box_create\n";
        let ops = assemble_string(source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        let ops2 = assemble_string(&text)
            .unwrap_or_else(|e| panic!("disassembly could not be reassembled: {e:?}\n{text}"));
        assert_eq!(
            ops.program, ops2.program,
            "round-trip bytecode mismatch\ndisassembly:\n{text}"
        );
    }

    #[test]
    fn test_disassemble_app_box_as_last_instruction_end_label_correct() {
        // Regression test for the end-offset-off-by-one bug: when the
        // program's *last* instruction is a two-byte-header app_box_*
        // opcode, a branch that targets the end of the program (here, a
        // trailing label with nothing after it) must resolve to the real
        // end offset -- after the sub-opcode byte, not one byte short of it.
        let source =
            "#pragma version 13\nint 0\nbnz done\nint 7\nbyte \"k\"\nint 10\napp_box_create\ndone:\n";
        let ops = assemble_string(source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        // A trailing label must actually appear in the disassembly (the
        // disassembler assigns its own generic label names, so this doesn't
        // check for "done" literally) -- with the off-by-one bug,
        // `end_offset` would be one byte short of the real program end, so
        // `labels.get(&end_offset)` would miss it and the label would
        // silently vanish instead of round-tripping.
        assert!(
            text.trim_end().ends_with(':'),
            "expected a trailing label line, got:\n{text}"
        );
        let ops2 = assemble_string(&text)
            .unwrap_or_else(|e| panic!("disassembly could not be reassembled: {e:?}\n{text}"));
        assert_eq!(
            ops.program, ops2.program,
            "round-trip bytecode mismatch\ndisassembly:\n{text}"
        );
    }

    // -------------------------------------------------------------------
    // Ported from go-algorand's `TestDisassembleBadMultiOp`
    // (data/transactions/logic/assembler_test.go): a clean error for a
    // multi-byte "prefix opcode" (the `app_box_*` family at 0xd4) whose
    // sub-opcode byte is missing or unrecognized, at the `disassemble()`
    // entry point rather than just the underlying `opcode::resolve` unit.
    // -------------------------------------------------------------------

    #[test]
    fn test_disassemble_bad_multi_op_missing_sub_opcode() {
        let err = disassemble(&[crate::opcode::FOREIGN_BOX_VERSION, 0xd4]).unwrap_err();
        assert!(
            err.contains("0xd4 missing sub-opcode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_disassemble_bad_multi_op_improper_sub_opcode() {
        let err = disassemble(&[crate::opcode::FOREIGN_BOX_VERSION, 0xd4, 0x00]).unwrap_err();
        assert!(
            err.contains("0xd4 with improper sub-opcode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_disassemble_bad_multi_op_valid_sub_opcode() {
        let text = disassemble(&[crate::opcode::FOREIGN_BOX_VERSION, 0xd4, 0x01]).unwrap();
        assert!(
            text.contains("app_box_create"),
            "expected app_box_create in disassembly:\n{text}"
        );
    }

    // -------------------------------------------------------------------
    // Ported from go-algorand's `TestDisassembleBadBranch`: a branch
    // (`bnz`/`bz`/`b`) with a missing or truncated offset must be a clean
    // error; a branch that decodes fine but targets past the end of the
    // program, or a negative (back-jump) offset, must NOT error at
    // disassemble time -- go-algorand explicitly documents both as "would
    // be reasonable to error here" but doesn't, and algod-rust's
    // `bytecode::parse` likewise only validates that the two offset bytes
    // are physically present, not that the resulting target is in range.
    // -------------------------------------------------------------------

    #[test]
    fn test_disassemble_bad_branch() {
        for br in [0x40u8, 0x41, 0x42] {
            // Bare opcode, no offset bytes at all.
            assert!(
                disassemble(&[2, br]).is_err(),
                "opcode 0x{br:02x} with no offset should error"
            );
            // Only one of the two offset bytes present.
            assert!(
                disassemble(&[2, br, 0x01]).is_err(),
                "opcode 0x{br:02x} with 1 offset byte should error"
            );
            // Full offset, target jumps past the end of the program: go
            // does not error here, and neither does algod-rust (bounds are
            // not validated at parse/disassemble time).
            assert!(
                disassemble(&[2, br, 0x00, 0x05]).is_ok(),
                "opcode 0x{br:02x} jumping past program end should not error at disassemble time"
            );
            // Negative (back) offset: also not an error at disassemble time.
            assert!(
                disassemble(&[2, br, 0xff, 0x02]).is_ok(),
                "opcode 0x{br:02x} with a negative offset should not error at disassemble time"
            );
            // Full offset followed by a trailing instruction byte: fine.
            assert!(
                disassemble(&[2, br, 0x00, 0x01, 0x00]).is_ok(),
                "opcode 0x{br:02x} with a trailing instruction should not error"
            );
        }
    }

    // -------------------------------------------------------------------
    // Ported from go-algorand's `TestDisassembleBadSwitch`/
    // `TestDisassembleBadMatch`: a `switch`/`match` program whose label
    // list is truncated must report a clean, name-specific decode error
    // (see `bytecode::parse_immediates`'s `ImmKind::Labels` handling) when
    // routed through `disassemble()`.
    // -------------------------------------------------------------------

    #[test]
    fn test_disassemble_bad_switch() {
        let source = "\nint 1\nswitch label1 label2\nlabel1:\nlabel2:\n";
        let full = format!("#pragma version 8\n{source}");
        let ops = assemble_string(&full).unwrap();

        // The full program disassembles cleanly.
        assert!(disassemble(&ops.program).is_ok());

        // Chop off all the labels, but keep the label count.
        let truncated = &ops.program[..ops.program.len() - 4];
        let err = disassemble(truncated).unwrap_err();
        assert!(
            err.contains("could not decode labels for switch"),
            "unexpected error: {err}"
        );

        // Chop off before the label count.
        let truncated = &ops.program[..ops.program.len() - 5];
        let err = disassemble(truncated).unwrap_err();
        assert!(
            err.contains("could not decode label count for switch"),
            "unexpected error: {err}"
        );

        // Chop off half of a label.
        let truncated = &ops.program[..ops.program.len() - 1];
        let err = disassemble(truncated).unwrap_err();
        assert!(
            err.contains("could not decode labels for switch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_disassemble_bad_match() {
        let source = "\nint 40\nint 45\nint 40\nmatch label1 label2\nlabel1:\nlabel2:\n";
        let full = format!("#pragma version 8\n{source}");
        let ops = assemble_string(&full).unwrap();

        assert!(disassemble(&ops.program).is_ok());

        // Return the label count, but chop off the labels themselves.
        let truncated = &ops.program[..ops.program.len() - 5];
        let err = disassemble(truncated).unwrap_err();
        assert!(
            err.contains("could not decode label count for match"),
            "unexpected error: {err}"
        );

        let truncated = &ops.program[..ops.program.len() - 1];
        let err = disassemble(truncated).unwrap_err();
        assert!(
            err.contains("could not decode labels for match"),
            "unexpected error: {err}"
        );
    }
}
