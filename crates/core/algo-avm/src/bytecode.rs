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

//! Bytecode parser for AVM (TEAL) programs.
//!
//! Parses raw `&[u8]` into a structured `Program` containing a version byte
//! and a vector of `Instruction`s, each with typed immediates.

use algo_error::AlgoError;

use crate::opcode::{self, ImmKind, MAX_AVM_VERSION};

/// A parsed AVM program.
#[derive(Debug, Clone)]
pub struct Program {
    /// AVM version (0..=MAX_AVM_VERSION). `0` is go-algorand's ancient v1
    /// alias (see `parse`'s doc comment) rather than a distinct version.
    pub version: u8,
    /// Parsed instruction stream.
    pub instructions: Vec<Instruction>,
}

/// A single parsed instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// The opcode byte (the *prefix* byte, for a multi-byte instruction).
    pub opcode: u8,
    /// The second byte of a multi-byte "prefix opcode" instruction (e.g. the
    /// `app_box_*` family sharing prefix byte `0xd4`), or `None` for an
    /// ordinary single-byte opcode. Mirrors go-algorand's
    /// `OpDetails.SubOpcode` (`opcodes.go:162`) once resolved.
    pub sub_opcode: Option<u8>,
    /// Byte offset of this instruction within the program (after the version byte).
    pub offset: usize,
    /// Parsed immediate arguments.
    pub immediates: Immediates,
}

/// Immediate argument data for an instruction.
#[derive(Debug, Clone, PartialEq)]
pub enum Immediates {
    /// No immediate arguments.
    None,
    /// Single uint8.
    Uint8(u8),
    /// Two uint8 values.
    Uint8Pair(u8, u8),
    /// Three uint8 values.
    Uint8Triple(u8, u8, u8),
    /// Signed int16 branch offset (big-endian).
    Int16(i16),
    /// Single varuint value (e.g. pushint).
    Varuint(u64),
    /// Varuint-length-prefixed byte array (e.g. pushbytes).
    Bytes(Vec<u8>),
    /// intcblock: list of varuint values.
    IntBlock(Vec<u64>),
    /// bytecblock: list of byte arrays.
    ByteBlock(Vec<Vec<u8>>),
    /// pushints: list of varuint values.
    PushInts(Vec<u64>),
    /// pushbytess: list of byte arrays.
    PushBytess(Vec<Vec<u8>>),
    /// switch/match: uint8 count + list of int16 branch offsets.
    Labels(Vec<i16>),
    /// Varint-encoded (zigzag+ULEB128) branch offset for `bnz`/`bz`/`b`/
    /// `callsub` at `LogicSigVersion >= opcode::VARINT_BRANCH_VERSION`.
    /// Fields: `(offset, bytes_consumed)`. `bytes_consumed` is the actual
    /// encoded length read from the program bytes (not necessarily the
    /// minimal encoding an assembler would emit — a hand-crafted or
    /// adversarial program may pad with redundant continuation bytes, which
    /// `binary.Varint` on the go-algorand side accepts), and is needed both
    /// to compute this instruction's total byte size and to reproduce the
    /// forward-jump base point (`instr_offset + 1 + bytes_consumed`).
    BranchVarint(i64, usize),
}

/// Compute the raw (possibly out-of-range) target byte offset for a
/// varint-encoded branch immediate.
///
/// Mirrors go-algorand's `branchTargetVarint`
/// (`data/transactions/logic/eval.go`): a **negative** `offset` is a
/// back-jump measured from the **start** of the instruction (`instr_offset`);
/// a **non-negative** `offset` is a forward-jump measured from the **end** of
/// the instruction (`instr_offset + 1 + varint_len`, i.e. past the opcode
/// byte and the varint's own encoded bytes).
///
/// Returns `i128` rather than `usize`/`isize` so that even an adversarial,
/// maximal-magnitude (10-byte varint, up to `i64::MIN`/`i64::MAX`) `offset`
/// cannot overflow before the caller performs its own `0..=program_len`
/// bounds check — this function itself never panics or wraps.
pub fn varint_branch_target(instr_offset: usize, varint_len: usize, offset: i64) -> i128 {
    let base: i128 = if offset < 0 {
        instr_offset as i128
    } else {
        instr_offset as i128 + 1 + varint_len as i128
    };
    base + offset as i128
}

/// Decode a signed zigzag+ULEB128 varint at `data[pos..]`, matching Go's
/// `encoding/binary.Varint` exactly (including accepting non-minimal /
/// redundant encodings, and the same two distinct failure modes):
/// - buffer runs out before a terminating (high-bit-clear) byte is found
///   ("program ends without branch target", matching `bytesRead == 0`)
/// - the value would need more than the 10 bytes a 64-bit varint can ever
///   need ("branch offset varint overflows int64", matching `bytesRead < 0`)
///
/// Returns `(value, bytes_consumed)`.
pub fn read_branch_varint(data: &[u8], pos: usize) -> Result<(i64, usize), AlgoError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = pos;

    loop {
        if i >= data.len() {
            return Err(AlgoError::Avm {
                message: "program ends without branch target".to_string(),
            });
        }
        let b = data[i];
        if shift >= 63 && b > 1 {
            return Err(AlgoError::Avm {
                message: "branch offset varint overflows int64".to_string(),
            });
        }
        result |= ((b & 0x7f) as u64) << shift;
        i += 1;
        if b & 0x80 == 0 {
            let consumed = i - pos;
            // Zigzag decode, matching Go's binary.Varint:
            //   x := int64(ux >> 1); if ux&1 != 0 { x = ^x }
            let value = (result >> 1) as i64;
            let value = if result & 1 != 0 { !value } else { value };
            return Ok((value, consumed));
        }
        shift += 7;
    }
}

/// Decode an unsigned LEB128 varuint from `data` starting at `pos`.
/// Returns `(value, bytes_consumed)`.
/// Matches Go's `binary.Uvarint` behavior.
pub fn read_varuint(data: &[u8], pos: usize) -> Result<(u64, usize), AlgoError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = pos;

    loop {
        if i >= data.len() {
            return Err(AlgoError::Avm {
                message: format!("varuint: unexpected end of data at offset {i}"),
            });
        }
        let b = data[i];
        if shift >= 63 && b > 1 {
            return Err(AlgoError::Avm {
                message: format!("varuint: overflow at offset {i}"),
            });
        }
        result |= ((b & 0x7f) as u64) << shift;
        i += 1;
        if b & 0x80 == 0 {
            return Ok((result, i - pos));
        }
        shift += 7;
    }
}

/// Validate a `count` read from an attacker-controlled varint (the declared
/// item count of `intcblock`/`bytecblock`/`pushints`/`pushbytess`) against
/// the actual bytes remaining in `code`, and return it as a trusted `usize`
/// *before* the caller uses it to size a `Vec::with_capacity` allocation.
///
/// Every list entry -- a varuint (`intcblock`/`pushints`) or a
/// varuint-length-prefixed byte string (`bytecblock`/`pushbytess`) -- needs
/// at least 1 byte of encoding, so `count` can never legitimately exceed the
/// number of bytes left in the program after the count varint itself
/// (`code.len() - (pos + header_len)`). Without this check, a crafted
/// program can encode a near-`u64::MAX` count and crash the process via a
/// `Vec::with_capacity` capacity-overflow panic or an attempted
/// multi-exabyte allocation (issue #1164) -- go-algorand's equivalent
/// parsers (`parseIntImmArgs`/`parseByteImmArgs`,
/// `data/transactions/logic/assembler.go`) reject the same malformed input
/// cleanly via an analogous "too many items" bound check before allocating.
fn check_const_list_count(
    code: &[u8],
    pos: usize,
    header_len: usize,
    count: u64,
    op_name: &str,
) -> Result<usize, AlgoError> {
    // `pos + header_len <= code.len()` always holds here: `read_varuint`
    // only returns `Ok` once it has consumed bytes strictly within `code`.
    let remaining = (code.len() - (pos + header_len)) as u64;
    if count > remaining {
        return Err(AlgoError::Avm {
            message: format!(
                "{op_name}: const list with too many items ({count} declared, only {remaining} bytes remain)"
            ),
        });
    }
    Ok(count as usize)
}

/// Reproduce go-algorand's pre-v13 `bytecblock`/`pushbytess` parsing bug
/// (`EvalContext.byteImmArgs`, `data/transactions/logic/eval.go`): before
/// the fix that shipped in v13, a byte-constant list whose *final* entry
/// was empty **and** whose declared length ended exactly at the end of the
/// program was rejected as `errShortByteImmArgs` ("const bytes list ran
/// past end of program"), even though the entry fits -- an off-by-one in
/// the original bounds check. go-algorand deliberately keeps reproducing
/// this at versions below 13 for determinism on historical chain data
/// (the fix only applies going forward), and stops applying it once
/// `LogicSigVersion` reaches 13. algod-rust has no separate historical
/// per-block "which interpreter version was live then" concept in this
/// parser, so it gates on the program's own declared `version` byte --
/// the same source already used by the `MAX_STRING_SIZE` check just above
/// this call site.
fn check_trailing_empty_byte_imm(
    version: u8,
    pos: usize,
    consumed: usize,
    code_len: usize,
    entries: &[Vec<u8>],
    op_name: &str,
) -> Result<(), AlgoError> {
    if version >= 13 {
        return Ok(());
    }
    if pos + consumed == code_len {
        if let Some(last) = entries.last() {
            if last.is_empty() {
                return Err(AlgoError::Avm {
                    message: format!("{op_name}: const bytes list ran past end of program"),
                });
            }
        }
    }
    Ok(())
}

/// Read a big-endian int16 from `data` at `pos`.
fn read_int16(data: &[u8], pos: usize) -> Result<i16, AlgoError> {
    if pos + 2 > data.len() {
        return Err(AlgoError::Avm {
            message: format!("int16: unexpected end of data at offset {pos}"),
        });
    }
    Ok(i16::from_be_bytes([data[pos], data[pos + 1]]))
}

/// Decode a TEAL program's version prefix as a full LEB128 varuint, matching
/// go-algorand's `transactions.ProgramVersion` (`data/transactions/transaction.go`):
///
/// ```go
/// func ProgramVersion(bytecode []byte) (version uint64, length int, err error) {
///     if len(bytecode) == 0 {
///         return 0, 0, errors.New("invalid program (empty)")
///     }
///     version, vlen := binary.Uvarint(bytecode)
///     if vlen <= 0 {
///         return 0, 0, errors.New("invalid version")
///     }
///     return version, vlen, nil
/// }
/// ```
///
/// go decodes the version as a real varuint, not a fixed single byte: any
/// real assembler only ever emits a canonical single-byte encoding (every
/// supported version is `< 128`, so no continuation bit is ever needed), but
/// a non-canonical/padded encoding -- e.g. version 1 as `0x81 0x00` -- is
/// still structurally valid and must decode to the same version, just with
/// instructions starting one byte later (`length` bytes in, not a fixed 1).
/// `vlen <= 0` is go's `binary.Uvarint` overflow signal (e.g. 10+
/// continuation-bit bytes with no terminator within the 64-bit budget,
/// go's `TestInvalidVersion`'s 12-byte all-`0xff` case) and is rejected with
/// exactly `"invalid version"`, reproduced here via [`read_varuint`]'s
/// existing overflow/truncation detection (issue #1216).
///
/// Returns `(version, vlen)`, where `vlen` is the number of raw bytes the
/// version prefix consumed and where the instruction stream begins. The
/// decoded `u64` is narrowed to `u8` only after the `MAX_AVM_VERSION`
/// range check below, since every version this AVM actually supports fits.
fn parse_version_prefix(raw: &[u8]) -> Result<(u8, usize), AlgoError> {
    if raw.is_empty() {
        return Err(AlgoError::Avm {
            message: "program is empty".to_string(),
        });
    }

    let (version, vlen) = read_varuint(raw, 0).map_err(|_| AlgoError::Avm {
        message: "invalid version".to_string(),
    })?;
    if version > MAX_AVM_VERSION as u64 {
        return Err(AlgoError::Avm {
            message: format!(
                "unsupported AVM version {version} (supported: 0..={MAX_AVM_VERSION})"
            ),
        });
    }
    Ok((version as u8, vlen))
}

/// Peek a program's declared AVM version without fully parsing it, for the
/// pre-eval gating checks (`check_program_version_allowed`/
/// `check_pre_shared_resources_access`/`check_min_avm_version`) that run
/// before -- and independently of -- the full [`parse`] call. Returns `None`
/// on an empty program or an undecodable/out-of-range version prefix; those
/// cases are left for `parse` itself to reject with its proper error, so
/// callers should simply skip the corresponding pre-check when this returns
/// `None` rather than synthesizing a version.
pub fn peek_version(raw: &[u8]) -> Option<u8> {
    parse_version_prefix(raw).ok().map(|(version, _)| version)
}

/// Parse a TEAL program from raw bytes.
///
/// The version prefix is a LEB128 varuint (see [`parse_version_prefix`]),
/// not a fixed single byte -- the instruction stream begins wherever that
/// varuint ends (`vlen`, 1 byte for every canonical encoding any real
/// assembler emits, more for a non-canonical padded one). Version `0` is
/// accepted as go-algorand's backward-compatible alias for v1
/// (`data/transactions/logic/opcodes.go`'s `init()`: "v1 allowed execution
/// of program with version 0 ... version 0 array is populated with v1
/// opcodes with the version overwritten to 0") -- it predates the
/// version-byte convention and is resolved against the v1 opcode set
/// exactly like a real version-1 program.
pub fn parse(raw: &[u8]) -> Result<Program, AlgoError> {
    let (version, vlen) = parse_version_prefix(raw)?;

    // go-algorand treats version byte 0 as an alias for v1: `opsByOpcode[0]`/
    // `OpsByName[0]` are populated from the same v1 `OpSpec` entries as
    // `opsByOpcode[1]`/`OpsByName[1]`, with `Version` overwritten to 0
    // (`data/transactions/logic/opcodes.go`'s `init()`, "Migration from v1 to
    // v2 ... v1 allowed execution of program with version 0 ... To preserve
    // backward compatibility version 0 array is populated with v1 opcodes
    // with the version overwritten to 0"). This predates the version-byte
    // convention itself and is exercised by
    // `TestBackwardCompatTEALv1`/`backwardCompat_test.go:253`. Only the
    // per-opcode version ceiling below needs the v0->v1 alias; every other
    // version comparison in this codebase already treats `version <= 1`
    // uniformly (see `opcode::effective_cost`), so `Program.version` itself
    // stays the literal byte (0), not the aliased value.
    let opcode_ceiling_version = version.max(1);

    let code = &raw[vlen..]; // instruction bytes (offsets are relative to this slice)
    let mut pc: usize = 0;
    let mut instructions = Vec::new();

    while pc < code.len() {
        let offset = pc;
        let op_byte = code[pc];

        // `opcode::resolve` handles both ordinary single-byte opcodes and
        // multi-byte "prefix opcode" families (go-algorand's SubOpcode/
        // SubOps mechanism): `header_len` is 1 for the former, 2 (prefix +
        // sub-opcode byte) for the latter. No production opcode registers
        // `sub_ops` yet, so this is currently always 1 in practice, but the
        // decoder is wired end-to-end so a future prefix family (e.g. the
        // `app_box_*` opcodes at 0xd4) needs no further changes here.
        let (spec, header_len) = opcode::resolve(code, pc).map_err(|message| AlgoError::Avm {
            message: format!("{message} at offset {offset}"),
        })?;
        let sub_opcode = if header_len > 1 {
            Some(code[pc + 1])
        } else {
            None
        };
        pc += header_len;

        if spec.version > opcode_ceiling_version {
            return Err(AlgoError::Avm {
                message: format!(
                    "opcode {} (0x{op_byte:02x}) requires AVM v{}, but program is v{version}",
                    spec.name, spec.version,
                ),
            });
        }

        // At LogicSigVersion >= VARINT_BRANCH_VERSION, bnz/bz/b/callsub switch
        // from the table's static `Int16` immediate kind to a varint-encoded
        // offset (go-algorand PR #6600, `varintBranchVersion`). switch/match
        // are untouched -- only these four opcode bytes are affected, and
        // only at v13+; below that they keep the legacy fixed-2-byte form.
        let imm_kind = if version >= opcode::VARINT_BRANCH_VERSION
            && opcode::is_varint_branch_opcode(op_byte)
        {
            ImmKind::BranchVarint
        } else {
            spec.imm
        };

        let (immediates, consumed) = parse_immediates(code, pc, imm_kind, spec.name, version)?;
        pc += consumed;

        // go-algorand PR #6692 ("avm: improve byte constant immediate
        // reporting"): starting at LogicSigVersion 13, bytecblock/pushbytess
        // reject any individual byte constant exceeding maxStringSize at
        // execution time (`EvalContext.byteImmArgs`, eval.go). algod-rust
        // parses the whole program once up front rather than lazily
        // per-opcode, so this is the equivalent point to enforce it: it runs
        // before any opcode executes, on every parse (both the pre-execution
        // check pass and eval itself). Below v13 this check does not apply;
        // only the (already-existing, unconditional) assembler-time check
        // constrains pre-v13 byte constants.
        if version >= 13 {
            let entries = match &immediates {
                Immediates::ByteBlock(entries) | Immediates::PushBytess(entries) => Some(entries),
                _ => None,
            };
            if let Some(entries) = entries {
                for (i, b) in entries.iter().enumerate() {
                    if b.len() > opcode::MAX_STRING_SIZE {
                        return Err(AlgoError::Avm {
                            message: format!(
                                "{} arg {i} is too big ({} bytes, limit {})",
                                spec.name,
                                b.len(),
                                opcode::MAX_STRING_SIZE
                            ),
                        });
                    }
                }
            }
        }

        instructions.push(Instruction {
            opcode: op_byte,
            sub_opcode,
            offset,
            immediates,
        });
    }

    Ok(Program {
        version,
        instructions,
    })
}

/// Parse immediate arguments starting at `pos` in `code`, returning
/// `(Immediates, bytes_consumed)`.
fn parse_immediates(
    code: &[u8],
    pos: usize,
    kind: ImmKind,
    op_name: &str,
    version: u8,
) -> Result<(Immediates, usize), AlgoError> {
    match kind {
        ImmKind::None => Ok((Immediates::None, 0)),

        ImmKind::Uint8 => {
            let b = read_immediate_byte(code, pos, op_name, 0)?;
            Ok((Immediates::Uint8(b), 1))
        }

        ImmKind::Uint8Uint8 => {
            let a = read_immediate_byte(code, pos, op_name, 0)?;
            let b = read_immediate_byte(code, pos + 1, op_name, 1)?;
            Ok((Immediates::Uint8Pair(a, b), 2))
        }

        ImmKind::Uint8Uint8Uint8 => {
            let a = read_immediate_byte(code, pos, op_name, 0)?;
            let b = read_immediate_byte(code, pos + 1, op_name, 1)?;
            let c = read_immediate_byte(code, pos + 2, op_name, 2)?;
            Ok((Immediates::Uint8Triple(a, b, c), 3))
        }

        ImmKind::Int16 => {
            let v = read_int16(code, pos)?;
            Ok((Immediates::Int16(v), 2))
        }

        ImmKind::Varuint => {
            let (val, consumed) = read_varuint(code, pos)?;
            Ok((Immediates::Varuint(val), consumed))
        }

        ImmKind::VaruintBytes => {
            let (len, hdr) = read_varuint(code, pos)?;
            let len = len as usize;
            let start = pos + hdr;
            if start + len > code.len() {
                return Err(AlgoError::Avm {
                    message: format!(
                        "pushbytes: need {len} bytes at offset {start}, have {}",
                        code.len() - start
                    ),
                });
            }
            let bytes = code[start..start + len].to_vec();
            Ok((Immediates::Bytes(bytes), hdr + len))
        }

        ImmKind::IntcBlock => {
            let (count, mut consumed) = read_varuint(code, pos)?;
            let count = check_const_list_count(code, pos, consumed, count, "intcblock")?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let (val, n) = read_varuint(code, pos + consumed)?;
                values.push(val);
                consumed += n;
            }
            Ok((Immediates::IntBlock(values), consumed))
        }

        ImmKind::BytecBlock => {
            let (count, mut consumed) = read_varuint(code, pos)?;
            let count = check_const_list_count(code, pos, consumed, count, "bytecblock")?;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let (len, hdr) = read_varuint(code, pos + consumed)?;
                consumed += hdr;
                let len = len as usize;
                let start = pos + consumed;
                if start + len > code.len() {
                    return Err(AlgoError::Avm {
                        message: format!(
                            "bytecblock: need {len} bytes at offset {start}, have {}",
                            code.len() - start
                        ),
                    });
                }
                entries.push(code[start..start + len].to_vec());
                consumed += len;
            }
            check_trailing_empty_byte_imm(
                version,
                pos,
                consumed,
                code.len(),
                &entries,
                "bytecblock",
            )?;
            Ok((Immediates::ByteBlock(entries), consumed))
        }

        ImmKind::PushInts => {
            let (count, mut consumed) = read_varuint(code, pos)?;
            let count = check_const_list_count(code, pos, consumed, count, "pushints")?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let (val, n) = read_varuint(code, pos + consumed)?;
                values.push(val);
                consumed += n;
            }
            Ok((Immediates::PushInts(values), consumed))
        }

        ImmKind::PushBytess => {
            let (count, mut consumed) = read_varuint(code, pos)?;
            let count = check_const_list_count(code, pos, consumed, count, "pushbytess")?;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let (len, hdr) = read_varuint(code, pos + consumed)?;
                consumed += hdr;
                let len = len as usize;
                let start = pos + consumed;
                if start + len > code.len() {
                    return Err(AlgoError::Avm {
                        message: format!(
                            "pushbytess: need {len} bytes at offset {start}, have {}",
                            code.len() - start
                        ),
                    });
                }
                entries.push(code[start..start + len].to_vec());
                consumed += len;
            }
            check_trailing_empty_byte_imm(
                version,
                pos,
                consumed,
                code.len(),
                &entries,
                "pushbytess",
            )?;
            Ok((Immediates::PushBytess(entries), consumed))
        }

        ImmKind::Labels => {
            // Mirrors go-algorand's `parseLabels` (`assembler.go`) bounds
            // checking and error wording exactly: a single up-front check
            // that the whole label list fits, rather than per-item checks,
            // so a truncated switch/match reports "could not decode label
            // count for <op>" (count byte itself missing) or "could not
            // decode labels for <op>" (count byte present but the offset
            // list runs past the end of the program) -- see
            // `TestDisassembleBadSwitch`/`TestDisassembleBadMatch`.
            if pos >= code.len() {
                return Err(AlgoError::Avm {
                    message: format!("could not decode label count for {op_name}"),
                });
            }
            let count = code[pos] as usize;
            let end = pos + 1 + 2 * count;
            if end > code.len() {
                return Err(AlgoError::Avm {
                    message: format!("could not decode labels for {op_name}"),
                });
            }
            let mut offsets = Vec::with_capacity(count);
            for i in 0..count {
                let label_pos = pos + 1 + i * 2;
                let v = read_int16(code, label_pos)?;
                offsets.push(v);
            }
            Ok((Immediates::Labels(offsets), 1 + count * 2))
        }

        ImmKind::BranchVarint => {
            let (offset, consumed) = read_branch_varint(code, pos)?;
            Ok((Immediates::BranchVarint(offset, consumed), consumed))
        }
    }
}

fn read_byte(data: &[u8], pos: usize) -> Result<u8, AlgoError> {
    if pos >= data.len() {
        return Err(AlgoError::Avm {
            message: format!("unexpected end of program at offset {pos}"),
        });
    }
    Ok(data[pos])
}

/// go-algorand's per-opcode immediate mnemonic letters (`immediates(...)`/
/// `field(...)` calls in `data/transactions/logic/opcodes.go`), keyed by
/// opcode name, in declaration order. Used only to reproduce go's exact
/// `Disassemble` truncation wording ("program end while reading immediate
/// %s for %s", `assembler.go:3071`) for opcodes whose immediates are single
/// bytes (`ImmKind::Uint8`/`Uint8Uint8`/`Uint8Uint8Uint8`) -- see
/// `TestAssembleDisassembleErrors`. Opcodes not listed here (or a position
/// beyond the listed slice) fall back to the older generic "unexpected end
/// of program at offset N" wording rather than guessing a wrong letter.
fn uint8_immediate_names(op_name: &str) -> Option<&'static [&'static str]> {
    Some(match op_name {
        "ecdsa_verify" | "ecdsa_pk_decompress" | "ecdsa_pk_recover" => &["v"],
        "intc" | "bytec" => &["i"],
        "arg" => &["n"],
        "txn" | "global" | "gtxns" | "itxn" | "itxn_field" | "txnas" | "gtxnsas" | "itxnas"
        | "block" | "asset_holding_get" | "asset_params_get" | "app_params_get"
        | "acct_params_get" | "voter_params_get" => &["f"],
        "load" | "store" | "gloads" => &["i"],
        "gaid" => &["t"],
        "bury" | "popn" | "dupn" | "dig" | "cover" | "uncover" => &["n"],
        "replace2" => &["s"],
        "base64_decode" => &["e"],
        "json_ref" => &["r"],
        "frame_dig" | "frame_bury" => &["i"],
        "vrf_verify" => &["s"],
        "ec_add"
        | "ec_scalar_mul"
        | "ec_pairing_check"
        | "ec_multi_scalar_mul"
        | "ec_subgroup_check"
        | "ec_map_to" => &["g"],
        "mimc" | "poseidon2" => &["c"],
        "gtxn" => &["t", "f"],
        "txna" | "gtxnsa" | "itxna" => &["f", "i"],
        "gload" => &["t", "i"],
        "proto" => &["a", "r"],
        "gitxn" | "gtxnas" | "gitxnas" => &["t", "f"],
        "extract" => &["s", "l"],
        "substring" => &["s", "e"],
        "gtxna" | "gitxna" => &["t", "f", "i"],
        _ => return None,
    })
}

/// Read a single immediate byte at `pos`, reporting go's exact
/// `"program end while reading immediate %s for %s"` wording on truncation
/// when `op_name`/`imm_index` resolve to a known immediate letter (see
/// [`uint8_immediate_names`]), falling back to [`read_byte`]'s generic
/// wording otherwise.
fn read_immediate_byte(
    data: &[u8],
    pos: usize,
    op_name: &str,
    imm_index: usize,
) -> Result<u8, AlgoError> {
    if pos >= data.len() {
        if let Some(name) = uint8_immediate_names(op_name).and_then(|names| names.get(imm_index)) {
            return Err(AlgoError::Avm {
                message: format!("program end while reading immediate {name} for {op_name}"),
            });
        }
    }
    read_byte(data, pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal valid program with given version + code bytes.
    fn prog(version: u8, code: &[u8]) -> Vec<u8> {
        let mut p = vec![version];
        p.extend_from_slice(code);
        p
    }

    #[test]
    fn test_empty_program() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn test_version_zero_is_accepted_as_v1_alias() {
        // go-algorand: version byte 0 is a backward-compatible alias for v1
        // (`opcodes.go`'s `init()` populates `opsByOpcode[0]`/`OpsByName[0]`
        // from the same v1 `OpSpec`s as `opsByOpcode[1]`/`OpsByName[1]`).
        // `bytecode::parse` must accept it and resolve v1 opcodes rather
        // than unconditionally rejecting version 0 (issue #1124).
        let p = parse(&[0]).expect("version 0 must parse as a v1 alias");
        assert_eq!(p.version, 0, "Program.version keeps the literal byte");
        assert!(p.instructions.is_empty());
    }

    #[test]
    fn test_version_zero_resolves_v1_opcodes_identically_to_v1() {
        // `program_v1_bytes`-style parity: the same v1-era code parses to
        // the same instructions whether the version byte is 0 or 1.
        let code = &[0x20, 0x01, 0x01, 0x22, 0x08]; // intcblock 1; intc_0; +
        let v0 = parse(&prog(0, code)).expect("version 0 program must parse");
        let v1 = parse(&prog(1, code)).expect("version 1 program must parse");
        assert_eq!(v0.instructions.len(), v1.instructions.len());
        for (a, b) in v0.instructions.iter().zip(v1.instructions.iter()) {
            assert_eq!(a.opcode, b.opcode);
            assert_eq!(a.sub_opcode, b.sub_opcode);
            assert_eq!(a.offset, b.offset);
        }
    }

    #[test]
    fn test_version_zero_rejects_opcode_introduced_after_v1() {
        // An opcode that requires v2+ (`addw`, opcode 0x1e, version 2) must
        // still be rejected under the v0 alias exactly as it would under a
        // real v1 program -- v0 is an alias for v1's opcode set, not an
        // escape hatch to newer opcodes.
        let v2_only_code = &[0x1e]; // addw (AVM v2+)
        assert!(parse(&prog(0, v2_only_code)).is_err());
        assert!(parse(&prog(1, v2_only_code)).is_err());
    }

    #[test]
    fn test_version_too_high() {
        assert!(parse(&[MAX_AVM_VERSION + 1]).is_err());
    }

    /// Port of go-algorand's `TestInvalidVersion`
    /// (`data/transactions/logic/eval_test.go`): a 12-byte sequence of
    /// continuation-bit-set `0xff` bytes has no terminating (high-bit-clear)
    /// byte within the 10 bytes a 64-bit varuint can ever need, so
    /// `transactions.ProgramVersion`'s `binary.Uvarint` call reports
    /// `vlen <= 0` (overflow) and go rejects with exactly `"invalid
    /// version"`. `bytecode::parse` must decode the version prefix via a
    /// real varuint read (issue #1216) and surface that same wording, not
    /// the generic "unsupported AVM version" text a fixed-`raw[0]` read
    /// would produce (`0xff` = 255 happens to also exceed
    /// `MAX_AVM_VERSION`, so the old code accidentally rejected too, but
    /// via the wrong mechanism and the wrong message).
    #[test]
    fn test_invalid_version_all_0xff_matches_go_test_invalid_version() {
        let raw = [0xffu8; 12];
        let err = parse(&raw).unwrap_err().to_string();
        assert!(
            err.contains("invalid version"),
            "unexpected error message: {err}"
        );
    }

    /// A non-canonical (padded) but structurally valid single-value varuint
    /// version prefix -- version 1 encoded as two bytes (continuation bit
    /// set on `0x81`, terminated by `0x00`) instead of the canonical
    /// single-byte `0x01` -- must decode to version 1 with instructions
    /// starting at byte offset 2, not the fixed offset 1 the old
    /// `raw[0]`/`&raw[1..]` code always used. go-algorand's
    /// `transactions.ProgramVersion` (`binary.Uvarint`) accepts this
    /// encoding identically to the canonical one; only the returned `vlen`
    /// (where instructions begin) differs.
    #[test]
    fn test_noncanonical_padded_version_prefix_accepted_with_correct_offset() {
        // 0x81 0x00 = varuint(1) padded to 2 bytes, followed by a single
        // `err` opcode (0x00) at what must be recognized as offset 0 of the
        // instruction stream (raw byte offset 2).
        let raw = [0x81u8, 0x00, 0x00];
        let p = parse(&raw).expect("non-canonical 2-byte version prefix must be accepted");
        assert_eq!(p.version, 1, "padded prefix must decode to version 1");
        assert_eq!(p.instructions.len(), 1);
        assert_eq!(
            p.instructions[0].offset, 0,
            "instruction offset is relative to the code slice, which must start at raw vlen=2"
        );
        assert_eq!(p.instructions[0].opcode, 0x00);
    }

    #[test]
    fn test_version_only() {
        // Version byte with no instructions is valid (empty program).
        let p = parse(&[1]).unwrap();
        assert_eq!(p.version, 1);
        assert!(p.instructions.is_empty());
    }

    #[test]
    fn test_simple_program() {
        // Version 1, pushint 1, return (v2 — but let's use v2 program)
        // Actually: intcblock [1], intc_0, return
        // intcblock 0x20, count=1, value=1
        // intc_0 = 0x22
        // But `return` is v2, so use version 2.
        let raw = prog(
            2,
            &[
                0x20, 0x01, 0x01, // intcblock [1]
                0x22, // intc_0
                0x43, // return
            ],
        );
        let p = parse(&raw).unwrap();
        assert_eq!(p.version, 2);
        assert_eq!(p.instructions.len(), 3);

        // intcblock
        assert_eq!(p.instructions[0].opcode, 0x20);
        assert_eq!(p.instructions[0].offset, 0);
        assert_eq!(p.instructions[0].immediates, Immediates::IntBlock(vec![1]));

        // intc_0
        assert_eq!(p.instructions[1].opcode, 0x22);
        assert_eq!(p.instructions[1].immediates, Immediates::None);

        // return
        assert_eq!(p.instructions[2].opcode, 0x43);
    }

    #[test]
    fn test_intcblock_multiple() {
        let raw = prog(
            1,
            &[
                0x20, 0x03, // intcblock, count=3
                0x00, // value 0
                0x2a, // value 42
                0x80, 0x01, // value 128 (varuint: 0x80 0x01)
            ],
        );
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions.len(), 1);
        assert_eq!(
            p.instructions[0].immediates,
            Immediates::IntBlock(vec![0, 42, 128])
        );
    }

    #[test]
    fn test_bytecblock() {
        let raw = prog(
            1,
            &[
                0x26, 0x02, // bytecblock, count=2
                0x03, b'f', b'o', b'o', // len=3, "foo"
                0x02, 0xAB, 0xCD, // len=2, [0xAB, 0xCD]
            ],
        );
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions.len(), 1);
        assert_eq!(
            p.instructions[0].immediates,
            Immediates::ByteBlock(vec![b"foo".to_vec(), vec![0xAB, 0xCD]])
        );
    }

    /// At LogicSigVersion >= 13, `bytecblock` must reject an individual byte
    /// constant exceeding `MAX_STRING_SIZE` (4096 bytes) -- go-algorand PR
    /// #6692 / `EvalContext.byteImmArgs` (data/transactions/logic/eval.go).
    #[test]
    fn test_bytecblock_oversized_constant_rejected_at_v13() {
        let oversized = vec![0u8; crate::opcode::MAX_STRING_SIZE + 1];
        let mut code = vec![0x26]; // bytecblock
        crate::assembler::write_varuint_to_vec(&mut code, 1); // count=1
        crate::assembler::write_varuint_to_vec(&mut code, oversized.len() as u64);
        code.extend_from_slice(&oversized);

        let raw = prog(13, &code);
        let err = parse(&raw).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("too big") && msg.contains("4096"),
            "unexpected error message: {msg}"
        );
    }

    /// The same oversized-constant program is accepted below v13: no size
    /// limit is enforced at parse/execution time pre-v13 (only the
    /// assembler-time check, which this parse-level test bypasses, applied).
    #[test]
    fn test_bytecblock_oversized_constant_allowed_below_v13() {
        let oversized = vec![0u8; crate::opcode::MAX_STRING_SIZE + 1];
        let mut code = vec![0x26]; // bytecblock
        crate::assembler::write_varuint_to_vec(&mut code, 1); // count=1
        crate::assembler::write_varuint_to_vec(&mut code, oversized.len() as u64);
        code.extend_from_slice(&oversized);

        let raw = prog(12, &code);
        let p = parse(&raw).unwrap();
        assert_eq!(
            p.instructions[0].immediates,
            Immediates::ByteBlock(vec![oversized])
        );
    }

    /// Same size-limit enforcement applies to `pushbytess` at v13+.
    #[test]
    fn test_pushbytess_oversized_constant_rejected_at_v13() {
        let oversized = vec![0u8; crate::opcode::MAX_STRING_SIZE + 1];
        let mut code = vec![0x82]; // pushbytess
        crate::assembler::write_varuint_to_vec(&mut code, 1); // count=1
        crate::assembler::write_varuint_to_vec(&mut code, oversized.len() as u64);
        code.extend_from_slice(&oversized);

        let raw = prog(13, &code);
        let err = parse(&raw).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("too big") && msg.contains("4096"),
            "unexpected error message: {msg}"
        );
    }

    /// A `bytecblock` at v13 whose constants are all within the size limit
    /// still parses fine (the check must not reject valid programs).
    #[test]
    fn test_bytecblock_within_limit_allowed_at_v13() {
        let ok_sized = vec![0u8; crate::opcode::MAX_STRING_SIZE];
        let mut code = vec![0x26]; // bytecblock
        crate::assembler::write_varuint_to_vec(&mut code, 1); // count=1
        crate::assembler::write_varuint_to_vec(&mut code, ok_sized.len() as u64);
        code.extend_from_slice(&ok_sized);

        let raw = prog(13, &code);
        let p = parse(&raw).unwrap();
        assert_eq!(
            p.instructions[0].immediates,
            Immediates::ByteBlock(vec![ok_sized])
        );
    }

    #[test]
    fn test_pushint() {
        // pushint requires v3+
        let raw = prog(3, &[0x81, 0x05]); // pushint 5
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions[0].immediates, Immediates::Varuint(5));
    }

    #[test]
    fn test_pushbytes() {
        let raw = prog(3, &[0x80, 0x03, 0x01, 0x02, 0x03]); // pushbytes [1,2,3]
        let p = parse(&raw).unwrap();
        assert_eq!(
            p.instructions[0].immediates,
            Immediates::Bytes(vec![1, 2, 3])
        );
    }

    #[test]
    fn test_branch_offset() {
        // bnz with offset 0x0100 = 256
        let raw = prog(
            1,
            &[
                0x20, 0x01, 0x01, // intcblock [1]
                0x22, // intc_0
                0x40, 0x01, 0x00, // bnz +256
            ],
        );
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions[2].opcode, 0x40);
        assert_eq!(p.instructions[2].immediates, Immediates::Int16(256));
    }

    #[test]
    fn test_negative_branch_offset() {
        // b with offset -1 (0xFFFF in big-endian)
        let raw = prog(2, &[0x42, 0xFF, 0xFF]); // b -1
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions[0].immediates, Immediates::Int16(-1));
    }

    #[test]
    fn test_txn_field_immediate() {
        // txn Sender (field 0)
        let raw = prog(1, &[0x31, 0x00]);
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions[0].immediates, Immediates::Uint8(0));
    }

    #[test]
    fn test_gtxn_two_immediates() {
        // gtxn 0 Sender (group idx 0, field 0)
        let raw = prog(1, &[0x33, 0x00, 0x00]);
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions[0].immediates, Immediates::Uint8Pair(0, 0));
    }

    #[test]
    fn test_gtxna_three_immediates() {
        // gtxna 1 ApplicationArgs 2  (group=1, field=26, idx=2)
        let raw = prog(2, &[0x37, 0x01, 0x1a, 0x02]);
        let p = parse(&raw).unwrap();
        assert_eq!(
            p.instructions[0].immediates,
            Immediates::Uint8Triple(1, 0x1a, 2)
        );
    }

    #[test]
    fn test_switch_labels() {
        // switch with 3 targets
        let raw = prog(
            8,
            &[
                0x81, 0x00, // pushint 0
                0x8d, // switch
                0x03, // count = 3
                0x00, 0x01, // offset +1
                0x00, 0x02, // offset +2
                0xFF, 0xFE, // offset -2
            ],
        );
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions.len(), 2);
        assert_eq!(
            p.instructions[1].immediates,
            Immediates::Labels(vec![1, 2, -2])
        );
    }

    /// Port of go-algorand's `TestDisassembleBadSwitch`
    /// (`data/transactions/logic/assembler_test.go`): a truncated `switch`
    /// label list must report a clean, name-specific decode error rather
    /// than a generic bounds message.
    #[test]
    fn test_switch_truncated_label_count_missing() {
        // switch opcode is the very last byte -- no count byte follows.
        let raw = prog(8, &[0x81, 0x00 /* pushint 0 */, 0x8d /* switch */]);
        let err = parse(&raw).unwrap_err().to_string();
        assert!(
            err.contains("could not decode label count for switch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_switch_truncated_labels_list_short() {
        // count says 2 labels, but only 1 offset (2 bytes) follows.
        let raw = prog(
            8,
            &[
                0x81, 0x00, // pushint 0
                0x8d, // switch
                0x02, // count = 2
                0x00, 0x01, // offset +1 (only one of the two present)
            ],
        );
        let err = parse(&raw).unwrap_err().to_string();
        assert!(
            err.contains("could not decode labels for switch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_switch_truncated_labels_list_all_missing() {
        // count says 2 labels, but zero offset bytes follow.
        let raw = prog(
            8,
            &[
                0x81, 0x00, // pushint 0
                0x8d, // switch
                0x02, // count = 2
            ],
        );
        let err = parse(&raw).unwrap_err().to_string();
        assert!(
            err.contains("could not decode labels for switch"),
            "unexpected error: {err}"
        );
    }

    /// Port of go-algorand's `TestDisassembleBadMatch`.
    #[test]
    fn test_match_truncated_label_count_missing() {
        let raw = prog(8, &[0x81, 0x00 /* pushint 0 */, 0x8e /* match */]);
        let err = parse(&raw).unwrap_err().to_string();
        assert!(
            err.contains("could not decode label count for match"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_match_truncated_labels_list_short() {
        let raw = prog(
            8,
            &[
                0x81, 0x00, // pushint 0
                0x8e, // match
                0x02, // count = 2
                0x00, 0x01, // offset +1 (only one of the two present)
            ],
        );
        let err = parse(&raw).unwrap_err().to_string();
        assert!(
            err.contains("could not decode labels for match"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_pushints() {
        let raw = prog(
            8,
            &[
                0x83, // pushints
                0x03, // count = 3
                0x01, // 1
                0x02, // 2
                0x80, 0x02, // 256
            ],
        );
        let p = parse(&raw).unwrap();
        assert_eq!(
            p.instructions[0].immediates,
            Immediates::PushInts(vec![1, 2, 256])
        );
    }

    #[test]
    fn test_pushbytess() {
        let raw = prog(
            8,
            &[
                0x82, // pushbytess
                0x02, // count = 2
                0x02, 0xAA, 0xBB, // len=2, [0xAA, 0xBB]
                0x01, 0xCC, // len=1, [0xCC]
            ],
        );
        let p = parse(&raw).unwrap();
        assert_eq!(
            p.instructions[0].immediates,
            Immediates::PushBytess(vec![vec![0xAA, 0xBB], vec![0xCC]])
        );
    }

    #[test]
    fn test_proto_two_uint8() {
        // proto 2 1 (2 args, 1 return)
        let raw = prog(8, &[0x8a, 0x02, 0x01]);
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions[0].immediates, Immediates::Uint8Pair(2, 1));
    }

    #[test]
    fn test_frame_dig() {
        // frame_dig -1 (encoded as uint8 = 255, interpreted as int8 = -1 at runtime)
        let raw = prog(8, &[0x8b, 0xFF]);
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions[0].immediates, Immediates::Uint8(0xFF));
    }

    #[test]
    fn test_unknown_opcode() {
        // 0x99 is not defined
        let raw = prog(1, &[0x99]);
        assert!(parse(&raw).is_err());
    }

    #[test]
    fn test_version_too_low_for_opcode() {
        // pushint requires v3, but program is v1
        let raw = prog(1, &[0x81, 0x05]);
        assert!(parse(&raw).is_err());
    }

    #[test]
    fn test_truncated_intcblock() {
        // intcblock says count=2 but only 1 value
        let raw = prog(1, &[0x20, 0x02, 0x01]);
        assert!(parse(&raw).is_err());
    }

    /// Port of go-algorand's `TestShortBytecblock`: assemble a real
    /// `bytecblock` program, fake its count byte up to 50 (far more entries
    /// than are actually present), then parse every possible truncated
    /// prefix of the program -- each one must fail cleanly with a bounds
    /// error, never panic or silently succeed. `test_bytecblock` above only
    /// checks a single well-formed decode; this exercises the exhaustive
    /// truncation sweep go's version runs across every prefix length.
    #[test]
    fn test_truncated_bytecblock_exhaustive_prefixes() {
        let ops = crate::assembler::assemble_string(
            "#pragma version 4\nbytecblock 0x123456 0xababcdcd \"test\"\n",
        )
        .expect("bytecblock program should assemble");
        let mut program = ops.program;
        // program[0] = version, program[1] = bytecblock opcode (0x26),
        // program[2] = count varuint (originally 3) -- fake it to 50.
        assert_eq!(program[1], 0x26, "expected bytecblock opcode at index 1");
        program[2] = 50;

        for i in 2..program.len() {
            let prefix = &program[..i];
            assert!(
                parse(prefix).is_err(),
                "truncated bytecblock prefix of length {i} must fail to parse, got Ok"
            );
        }
    }

    #[test]
    fn test_truncated_branch() {
        // bnz with only 1 byte of offset
        let raw = prog(
            1,
            &[
                0x20, 0x01, 0x01, // intcblock [1]
                0x22, // intc_0
                0x40, 0x01, // bnz missing second byte
            ],
        );
        assert!(parse(&raw).is_err());
    }

    #[test]
    fn test_truncated_pushbytes() {
        // pushbytes says length=5 but only 2 bytes follow
        let raw = prog(3, &[0x80, 0x05, 0x01, 0x02]);
        assert!(parse(&raw).is_err());
    }

    #[test]
    fn test_varuint_encoding() {
        // Test varuint decoding directly
        let (v, n) = read_varuint(&[0x00], 0).unwrap();
        assert_eq!((v, n), (0, 1));

        let (v, n) = read_varuint(&[0x7f], 0).unwrap();
        assert_eq!((v, n), (127, 1));

        let (v, n) = read_varuint(&[0x80, 0x01], 0).unwrap();
        assert_eq!((v, n), (128, 2));

        let (v, n) = read_varuint(&[0xAC, 0x02], 0).unwrap();
        assert_eq!((v, n), (300, 2));

        // Max: 2^64 - 1
        let (v, n) = read_varuint(
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
            0,
        )
        .unwrap();
        assert_eq!(v, u64::MAX);
        assert_eq!(n, 10);
    }

    #[test]
    fn test_varuint_overflow() {
        // This should overflow (value > u64::MAX)
        let result = read_varuint(
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02],
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_varuint_truncated() {
        // 0x80 says "more bytes follow" but there are none
        let result = read_varuint(&[0x80], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_instruction_offsets() {
        // Verify that instruction offsets track correctly
        let raw = prog(
            3,
            &[
                0x81, 0x01, // pushint 1 (offset 0, consumes 2 bytes)
                0x81, 0x02, // pushint 2 (offset 2, consumes 2 bytes)
                0x08, // + (offset 4, consumes 1 byte)
            ],
        );
        let p = parse(&raw).unwrap();
        assert_eq!(p.instructions[0].offset, 0);
        assert_eq!(p.instructions[1].offset, 2);
        assert_eq!(p.instructions[2].offset, 4);
    }

    /// Port of go-algorand's `TestShortBytecblock2`
    /// (`data/transactions/logic/eval_test.go:3385`): four hand-crafted
    /// malformed `bytecblock` programs whose declared item count is either
    /// near `u64::MAX` (the first two) or otherwise wildly exceeds the
    /// bytes actually remaining in the program (all four). go-algorand
    /// rejects all four cleanly with a "const bytes list" error
    /// (`errTooManyItems`/`errShortByteImmArgs`,
    /// `data/transactions/logic/assembler.go`'s `parseByteImmArgs`) rather
    /// than crashing.
    ///
    /// Before the fix for issue #1164, the first two programs crashed this
    /// process outright (`Vec::with_capacity` on a near-`u64::MAX` count is
    /// a capacity-overflow panic / OOM abort) rather than returning `Err` --
    /// which is exactly why this test exists: `parse` returning `Err` is
    /// the *fixed* behavior, not the historical one.
    #[test]
    fn test_short_bytecblock2_rejected_cleanly() {
        let sources = [
            "02260180fe83f88fe0bf80ff01aa",
            "01260180fe83f88fe0bf80ff01aa",
            "0026efbfbdefbfbd02",
            "0026efbfbdefbfbd30",
        ];
        for src in sources {
            let raw = hex::decode(src).expect("valid hex fixture");
            let result = parse(&raw);
            assert!(
                result.is_err(),
                "program {src} must be rejected, not silently accepted"
            );
            let msg = result.unwrap_err().to_string();
            assert!(
                msg.contains("bytecblock") || msg.contains("bytes"),
                "unexpected error for {src}: {msg}"
            );
        }
    }

    /// Fuzz-style regression guard for issue #1164: a `bytecblock` (or
    /// `intcblock`/`pushints`/`pushbytess`) whose declared item count is
    /// encoded as the maximal 10-byte varuint (decoding to `u64::MAX`) must
    /// be rejected with a clean `Err`, never a panic/abort, regardless of
    /// how few bytes actually remain in the program.
    #[test]
    fn test_extreme_varuint_count_rejected_without_panic_or_abort() {
        // u64::MAX encoded as a 10-byte LEB128 varuint.
        let max_varuint = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

        // intcblock (0x20): count=u64::MAX, then nothing.
        let mut intcblock_code = vec![0x20];
        intcblock_code.extend_from_slice(&max_varuint);
        assert!(parse(&prog(1, &intcblock_code)).is_err());

        // bytecblock (0x26): count=u64::MAX, then nothing.
        let mut bytecblock_code = vec![0x26];
        bytecblock_code.extend_from_slice(&max_varuint);
        assert!(parse(&prog(1, &bytecblock_code)).is_err());

        // pushints (0x83): count=u64::MAX, then nothing.
        let mut pushints_code = vec![0x83];
        pushints_code.extend_from_slice(&max_varuint);
        assert!(parse(&prog(8, &pushints_code)).is_err());

        // pushbytess (0x82): count=u64::MAX, then nothing.
        let mut pushbytess_code = vec![0x82];
        pushbytess_code.extend_from_slice(&max_varuint);
        assert!(parse(&prog(8, &pushbytess_code)).is_err());
    }

    /// The bound must be exact, not just "doesn't crash": a count equal to
    /// the actual number of trailing 1-byte varuint entries is still
    /// accepted (each entry is the minimal single-byte varuint `0x00`).
    #[test]
    fn test_const_list_count_at_exact_boundary_is_accepted() {
        let mut code = vec![0x20]; // intcblock
        crate::assembler::write_varuint_to_vec(&mut code, 3); // count=3
        code.extend_from_slice(&[0x00, 0x00, 0x00]); // 3 single-byte entries
        let p = parse(&prog(1, &code)).expect("exact boundary count must parse");
        assert_eq!(
            p.instructions[0].immediates,
            Immediates::IntBlock(vec![0, 0, 0])
        );

        // One more than the bytes available must be rejected.
        let mut code = vec![0x20]; // intcblock
        crate::assembler::write_varuint_to_vec(&mut code, 4); // count=4
        code.extend_from_slice(&[0x00, 0x00, 0x00]); // only 3 entries present
        assert!(parse(&prog(1, &code)).is_err());
    }

    /// Port of go-algorand's `TestTrailingEmptyByteImm`
    /// (`data/transactions/logic/eval_test.go`): a `bytecblock`/`pushbytess`
    /// immediate list whose *final* constant is empty and whose declared
    /// length ends exactly at the end of the program reproduces a
    /// historical go-algorand parsing bug at versions before 13
    /// (`EvalContext.byteImmArgs`, `data/transactions/logic/eval.go`) --
    /// go-algorand deliberately treats that shape as
    /// `errShortByteImmArgs` ("const bytes list ran past end of program")
    /// pre-v13 for determinism on historical chain data, and stopped doing
    /// so once the v13 fix (`checkByteImmArgs`/`parseByteImmArgs`,
    /// `data/transactions/logic/assembler.go`) landed. algod-rust parses
    /// the whole program in a single static pass (see the
    /// `MAX_STRING_SIZE` comment above `parse`), so go's separate
    /// Check()-vs-Eval() split collapses into `parse()`'s single return
    /// value here.
    #[test]
    fn test_trailing_empty_byte_imm() {
        for opcode in [0x26u8 /* bytecblock */, 0x82u8 /* pushbytess */] {
            // "trailing": a single empty final constant, ending exactly at
            // the end of the program -- rejected before v13, accepted at
            // v13+.
            let trailing_code = vec![opcode, 0x01, 0x00]; // count=1, len=0
            let pre13 = parse(&prog(12, &trailing_code));
            assert!(
                pre13.is_err(),
                "opcode {opcode:#x}: trailing empty constant must be rejected before v13"
            );
            let msg = pre13.unwrap_err().to_string();
            assert!(
                msg.contains("ran past end of program"),
                "opcode {opcode:#x}: unexpected error message: {msg}"
            );

            let at13 = parse(&prog(13, &trailing_code));
            assert!(
                at13.is_ok(),
                "opcode {opcode:#x}: trailing empty constant must be accepted at v13+: {:?}",
                at13.err()
            );

            // "short": the declared length (5) genuinely runs past the end
            // of the program -- a real overrun, rejected at every version.
            let short_code = vec![opcode, 0x01, 0x05, 0x01, 0x02]; // count=1, len=5, only 2 bytes follow
            assert!(parse(&prog(12, &short_code)).is_err());
            assert!(parse(&prog(13, &short_code)).is_err());

            // "mid": an empty constant that is *not* the final entry --
            // must parse cleanly at every version even though it too ends
            // exactly at the program boundary (guards against a naive
            // "did the list reach exactly the end of the buffer" check
            // misfiring on a non-trailing empty entry).
            let mid_code = vec![opcode, 0x02, 0x00, 0x01, 0x61]; // count=2: [], "a"
            assert!(parse(&prog(12, &mid_code)).is_ok());
            assert!(parse(&prog(13, &mid_code)).is_ok());
        }
    }
}
