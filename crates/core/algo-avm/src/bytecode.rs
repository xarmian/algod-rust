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

        let (immediates, consumed) = parse_immediates(code, pc, spec.imm)?;
        pc += consumed;

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
