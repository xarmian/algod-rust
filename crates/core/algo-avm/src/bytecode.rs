//! Bytecode parser for AVM (TEAL) programs.
//!
//! Parses raw `&[u8]` into a structured `Program` containing a version byte
//! and a vector of `Instruction`s, each with typed immediates.

use algo_error::AlgoError;

use crate::opcode::{self, ImmKind, MAX_AVM_VERSION};

/// A parsed AVM program.
#[derive(Debug, Clone)]
pub struct Program {
    /// AVM version (1..=MAX_AVM_VERSION).
    pub version: u8,
    /// Parsed instruction stream.
    pub instructions: Vec<Instruction>,
}

/// A single parsed instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// The opcode byte.
    pub opcode: u8,
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

/// Read a big-endian int16 from `data` at `pos`.
fn read_int16(data: &[u8], pos: usize) -> Result<i16, AlgoError> {
    if pos + 2 > data.len() {
        return Err(AlgoError::Avm {
            message: format!("int16: unexpected end of data at offset {pos}"),
        });
    }
    Ok(i16::from_be_bytes([data[pos], data[pos + 1]]))
}

/// Parse a TEAL program from raw bytes.
///
/// The first byte is the version. The remaining bytes are the instruction stream.
pub fn parse(raw: &[u8]) -> Result<Program, AlgoError> {
    if raw.is_empty() {
        return Err(AlgoError::Avm {
            message: "program is empty".to_string(),
        });
    }

    let version = raw[0];
    if version == 0 || version > MAX_AVM_VERSION {
        return Err(AlgoError::Avm {
            message: format!(
                "unsupported AVM version {version} (supported: 1..={MAX_AVM_VERSION})"
            ),
        });
    }

    let code = &raw[1..]; // instruction bytes (offsets are relative to this slice)
    let mut pc: usize = 0;
    let mut instructions = Vec::new();

    while pc < code.len() {
        let offset = pc;
        let op_byte = code[pc];
        pc += 1;

        let spec = opcode::lookup(op_byte).ok_or_else(|| AlgoError::Avm {
            message: format!("unknown opcode 0x{op_byte:02x} at offset {offset}"),
        })?;

        if spec.version > version {
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

        let (immediates, consumed) = parse_immediates(code, pc, imm_kind)?;
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
) -> Result<(Immediates, usize), AlgoError> {
    match kind {
        ImmKind::None => Ok((Immediates::None, 0)),

        ImmKind::Uint8 => {
            let b = read_byte(code, pos)?;
            Ok((Immediates::Uint8(b), 1))
        }

        ImmKind::Uint8Uint8 => {
            let a = read_byte(code, pos)?;
            let b = read_byte(code, pos + 1)?;
            Ok((Immediates::Uint8Pair(a, b), 2))
        }

        ImmKind::Uint8Uint8Uint8 => {
            let a = read_byte(code, pos)?;
            let b = read_byte(code, pos + 1)?;
            let c = read_byte(code, pos + 2)?;
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
            let count = count as usize;
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
            let count = count as usize;
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
            Ok((Immediates::ByteBlock(entries), consumed))
        }

        ImmKind::PushInts => {
            let (count, mut consumed) = read_varuint(code, pos)?;
            let count = count as usize;
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
            let count = count as usize;
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
            Ok((Immediates::PushBytess(entries), consumed))
        }

        ImmKind::Labels => {
            let count = read_byte(code, pos)? as usize;
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
    fn test_version_zero() {
        assert!(parse(&[0]).is_err());
    }

    #[test]
    fn test_version_too_high() {
        assert!(parse(&[MAX_AVM_VERSION + 1]).is_err());
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
}
