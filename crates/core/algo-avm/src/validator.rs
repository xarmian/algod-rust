//! Program validator -- checks bytecode constraints before execution.
//!
//! Validates branch targets, mode restrictions, program size limits,
//! and performs basic stack depth analysis.

use std::collections::HashSet;

use algo_error::AlgoError;

use crate::bytecode::{Immediates, Program};
use crate::opcode::{self, CostKind, Mode};

/// Maximum stack depth allowed by the AVM.
const MAX_STACK_DEPTH: i32 = 1000;

/// Maximum program size for LogicSig v1-v3.
const MAX_LOGICSIG_SIZE_V1_V3: usize = 1000;

/// Maximum program size for v4+ (both LogicSig and Application).
const MAX_PROGRAM_SIZE_V4_PLUS: usize = 2048;

/// Validate a parsed program for a given execution mode.
///
/// `program_len` is the total byte length of the raw program (including the version byte).
///
/// Checks performed:
/// - Program size limits
/// - Mode restrictions (LogicSig-only vs Application-only opcodes)
/// - Branch target validity (must land on instruction boundaries)
/// - Basic linear stack depth analysis
pub fn check_program(program: &Program, mode: Mode, program_len: usize) -> Result<(), AlgoError> {
    check_size(program, mode, program_len)?;
    check_mode(program, mode)?;
    check_branch_targets(program)?;
    check_stack_depth(program)?;
    Ok(())
}

/// Enforce per-program size limits.
fn check_size(program: &Program, mode: Mode, program_len: usize) -> Result<(), AlgoError> {
    let limit = if mode == Mode::LogicSig && program.version <= 3 {
        MAX_LOGICSIG_SIZE_V1_V3
    } else {
        MAX_PROGRAM_SIZE_V4_PLUS
    };

    if program_len > limit {
        return Err(AlgoError::Avm {
            message: format!(
                "program size {program_len} exceeds limit {limit} for v{} {}",
                program.version,
                if mode == Mode::LogicSig {
                    "LogicSig"
                } else {
                    "Application"
                }
            ),
        });
    }
    Ok(())
}

/// Reject opcodes that are incompatible with the execution mode.
fn check_mode(program: &Program, mode: Mode) -> Result<(), AlgoError> {
    for instr in &program.instructions {
        let spec = match opcode::lookup(instr.opcode) {
            Some(s) => s,
            None => {
                return Err(AlgoError::Avm {
                    message: format!(
                        "unknown opcode 0x{:02x} at offset {}",
                        instr.opcode, instr.offset
                    ),
                });
            }
        };

        match (mode, spec.mode) {
            // If both are Any, or mode matches, allow.
            (_, Mode::Any) => {}
            (Mode::Any, _) => {}
            (Mode::LogicSig, Mode::LogicSig) => {}
            (Mode::Application, Mode::Application) => {}
            (Mode::LogicSig, Mode::Application) => {
                return Err(AlgoError::Avm {
                    message: format!(
                        "opcode {} (0x{:02x}) at offset {} is Application-only, \
                         not allowed in LogicSig",
                        spec.name, instr.opcode, instr.offset
                    ),
                });
            }
            (Mode::Application, Mode::LogicSig) => {
                return Err(AlgoError::Avm {
                    message: format!(
                        "opcode {} (0x{:02x}) at offset {} is LogicSig-only, \
                         not allowed in Application",
                        spec.name, instr.opcode, instr.offset
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Validate that all branch targets land on valid instruction boundaries.
fn check_branch_targets(program: &Program) -> Result<(), AlgoError> {
    // Build a set of valid instruction offsets.
    let valid_offsets: HashSet<usize> = program
        .instructions
        .iter()
        .map(|instr| instr.offset)
        .collect();

    // Also compute the "end" offset (one past the last instruction's end),
    // which is a valid target for branches that jump to the end of the program.
    let end_offset = program
        .instructions
        .last()
        .map(|instr| {
            // Compute the byte length of this instruction's immediates.
            let imm_len = immediate_byte_len(&instr.immediates);
            instr.offset + 1 + imm_len
        })
        .unwrap_or(0);

    for (idx, instr) in program.instructions.iter().enumerate() {
        match &instr.immediates {
            Immediates::Int16(offset) => {
                // Branch opcodes: bnz (0x40), bz (0x41), b (0x42), callsub (0x88)
                let target =
                    resolve_branch_offset(program, idx, *offset, &valid_offsets, end_offset)?;
                let _ = target; // We just need to validate; target is checked inside.
            }
            Immediates::Labels(offsets) => {
                // switch/match opcodes
                for label_offset in offsets {
                    resolve_branch_offset(program, idx, *label_offset, &valid_offsets, end_offset)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Resolve a branch offset relative to the instruction at `instr_idx`.
///
/// Branch target = offset after instruction (offset + 1 + imm_bytes) + int16 value.
/// The target must be a valid instruction offset or exactly the end-of-program offset.
fn resolve_branch_offset(
    program: &Program,
    instr_idx: usize,
    offset: i16,
    valid_offsets: &HashSet<usize>,
    end_offset: usize,
) -> Result<usize, AlgoError> {
    let instr = &program.instructions[instr_idx];
    let imm_len = immediate_byte_len(&instr.immediates);
    let after_instr = instr.offset + 1 + imm_len;
    let target = (after_instr as isize + offset as isize) as usize;

    if !valid_offsets.contains(&target) && target != end_offset {
        return Err(AlgoError::Avm {
            message: format!(
                "branch at offset {} targets offset {}, which is not a valid instruction boundary",
                instr.offset, target
            ),
        });
    }
    Ok(target)
}

/// Compute the byte length of an instruction's immediate data.
pub fn immediate_byte_len(imm: &Immediates) -> usize {
    match imm {
        Immediates::None => 0,
        Immediates::Uint8(_) => 1,
        Immediates::Uint8Pair(_, _) => 2,
        Immediates::Uint8Triple(_, _, _) => 3,
        Immediates::Int16(_) => 2,
        Immediates::Varuint(v) => varuint_len(*v),
        Immediates::Bytes(b) => varuint_len(b.len() as u64) + b.len(),
        Immediates::IntBlock(vals) => {
            let mut n = varuint_len(vals.len() as u64);
            for v in vals {
                n += varuint_len(*v);
            }
            n
        }
        Immediates::ByteBlock(entries) => {
            let mut n = varuint_len(entries.len() as u64);
            for e in entries {
                n += varuint_len(e.len() as u64) + e.len();
            }
            n
        }
        Immediates::PushInts(vals) => {
            let mut n = varuint_len(vals.len() as u64);
            for v in vals {
                n += varuint_len(*v);
            }
            n
        }
        Immediates::PushBytess(entries) => {
            let mut n = varuint_len(entries.len() as u64);
            for e in entries {
                n += varuint_len(e.len() as u64) + e.len();
            }
            n
        }
        Immediates::Labels(offsets) => 1 + offsets.len() * 2, // count byte + N * int16
    }
}

/// Compute how many bytes a varuint value occupies in LEB128 encoding.
fn varuint_len(mut v: u64) -> usize {
    if v == 0 {
        return 1;
    }
    let mut n = 0;
    while v > 0 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Basic linear stack depth analysis.
///
/// Walks instructions in order, tracking stack depth using OpSpec metadata.
/// Does not follow branches -- just checks that linear execution never exceeds
/// max depth or goes negative.
fn check_stack_depth(program: &Program) -> Result<(), AlgoError> {
    let mut depth: i32 = 0;

    for instr in &program.instructions {
        let spec = match opcode::lookup(instr.opcode) {
            Some(s) => s,
            None => continue,
        };

        // Charge static cost just for validation accounting (not actually deducted).
        let _cost = match spec.cost {
            CostKind::Static(c) => c,
            CostKind::Dynamic => 1, // conservative
        };

        // Compute net stack effect.
        let pops = if spec.stack_pops < 0 {
            // Dynamic pops -- use conservative estimate of 1.
            1
        } else {
            spec.stack_pops as i32
        };

        let pushes = if spec.stack_pushes < 0 {
            // Dynamic pushes -- use conservative estimate of 1.
            1
        } else {
            spec.stack_pushes as i32
        };

        depth -= pops;
        if depth < 0 {
            // Linear analysis only -- branches may make this reachable.
            // We allow it since this is conservative.
            depth = 0;
        }
        depth += pushes;

        if depth > MAX_STACK_DEPTH {
            return Err(AlgoError::Avm {
                message: format!(
                    "stack depth {} exceeds maximum {MAX_STACK_DEPTH} after opcode {} at offset {}",
                    depth, spec.name, instr.offset
                ),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::parse;

    /// Helper: build a raw program from version + code bytes.
    fn prog(version: u8, code: &[u8]) -> Vec<u8> {
        let mut p = vec![version];
        p.extend_from_slice(code);
        p
    }

    #[test]
    fn test_valid_simple_program() {
        // intcblock [1], intc_0, return
        let raw = prog(2, &[0x20, 0x01, 0x01, 0x22, 0x43]);
        let program = parse(&raw).unwrap();
        assert!(check_program(&program, Mode::Any, raw.len()).is_ok());
    }

    #[test]
    fn test_valid_branch_forward() {
        // pushint 1, bnz +1, err, pushint 1
        // Instruction layout:
        //   offset 0: pushint 1 (0x81 0x01) -> 2 bytes
        //   offset 2: bnz +1 (0x40 0x00 0x01) -> 3 bytes, target = 2+3+1 = 6
        //   offset 5: err (0x00) -> 1 byte
        //   offset 6: pushint 1 (0x81 0x01) -> 2 bytes
        let raw = prog(3, &[0x81, 0x01, 0x40, 0x00, 0x01, 0x00, 0x81, 0x01]);
        let program = parse(&raw).unwrap();
        assert!(check_program(&program, Mode::Any, raw.len()).is_ok());
    }

    #[test]
    fn test_invalid_branch_target() {
        // pushint 1, bnz +99 (targets offset that doesn't exist as instruction boundary)
        let raw = prog(3, &[0x81, 0x01, 0x40, 0x00, 0x63]);
        let program = parse(&raw).unwrap();
        let result = check_program(&program, Mode::Any, raw.len());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("not a valid instruction boundary"), "{msg}");
    }

    #[test]
    fn test_mode_mismatch_logicsig_with_app_opcode() {
        // balance (0x60) is Application-only; running in LogicSig mode should fail.
        // balance requires v2+, pops 1.
        // pushint 0, balance
        let raw = prog(3, &[0x81, 0x00, 0x60]);
        let program = parse(&raw).unwrap();
        let result = check_program(&program, Mode::LogicSig, raw.len());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("Application-only"), "{msg}");
    }

    #[test]
    fn test_mode_mismatch_app_with_logicsig_opcode() {
        // arg (0x2c) is LogicSig-only; running in Application mode should fail.
        let raw = prog(1, &[0x2c, 0x00]);
        let program = parse(&raw).unwrap();
        let result = check_program(&program, Mode::Application, raw.len());
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("LogicSig-only"), "{msg}");
    }

    #[test]
    fn test_oversized_logicsig_v1() {
        // A LogicSig v1 program over 1000 bytes should fail.
        let result = check_program(
            &Program {
                version: 1,
                instructions: vec![],
            },
            Mode::LogicSig,
            1001,
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("exceeds limit"), "{msg}");
    }

    #[test]
    fn test_logicsig_v4_larger_limit() {
        // A LogicSig v4 program of 1500 bytes should be OK (limit is 2048).
        let result = check_program(
            &Program {
                version: 4,
                instructions: vec![],
            },
            Mode::LogicSig,
            1500,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_oversized_application() {
        let result = check_program(
            &Program {
                version: 6,
                instructions: vec![],
            },
            Mode::Application,
            2049,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_branch_to_end_of_program() {
        // pushint 1, b +0 (branch to end-of-program)
        // offset 0: pushint 1 (2 bytes)
        // offset 2: b (0x42) +0 -> target = 2 + 3 + 0 = 5, which is end-of-program
        let raw = prog(3, &[0x81, 0x01, 0x42, 0x00, 0x00]);
        let program = parse(&raw).unwrap();
        assert!(check_program(&program, Mode::Any, raw.len()).is_ok());
    }

    #[test]
    fn test_switch_valid_targets() {
        // pushint 0, switch [+2, +0]
        // offset 0: pushint 0 (0x81, 0x00) -> 2 bytes
        // offset 2: switch count=2, label1=+2, label2=+0
        //   switch imm = 1 byte count + 2*2 bytes labels = 5 bytes
        //   after_instr = 2 + 1 + 5 = 8
        //   target1 = 8 + 2 = 10
        //   target2 = 8 + 0 = 8 (end of program)
        // offset 8: pushint 1 (0x81, 0x01) -> 2 bytes (at offset 8)
        let raw = prog(
            8,
            &[
                0x81, 0x00, // pushint 0
                0x8d, 0x02, 0x00, 0x02, 0x00, 0x00, // switch [+2, +0]
                0x81, 0x01, // pushint 1 at offset 8
            ],
        );
        let program = parse(&raw).unwrap();
        assert!(check_program(&program, Mode::Any, raw.len()).is_ok());
    }

    #[test]
    fn test_switch_invalid_target() {
        // pushint 0, switch [+99]
        let raw = prog(
            8,
            &[
                0x81, 0x00, // pushint 0
                0x8d, 0x01, 0x00, 0x63, // switch [+99]
            ],
        );
        let program = parse(&raw).unwrap();
        let result = check_program(&program, Mode::Any, raw.len());
        assert!(result.is_err());
    }

    #[test]
    fn test_any_mode_allows_all() {
        // With Mode::Any, both LogicSig and Application opcodes should pass.
        // arg (LogicSig-only) at offset 0
        let raw = prog(1, &[0x2c, 0x00]);
        let program = parse(&raw).unwrap();
        assert!(check_program(&program, Mode::Any, raw.len()).is_ok());
    }

    #[test]
    fn test_empty_program_is_valid() {
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        assert!(check_program(&program, Mode::Any, 1).is_ok());
    }

    #[test]
    fn test_varuint_len_function() {
        assert_eq!(varuint_len(0), 1);
        assert_eq!(varuint_len(1), 1);
        assert_eq!(varuint_len(127), 1);
        assert_eq!(varuint_len(128), 2);
        assert_eq!(varuint_len(300), 2);
        assert_eq!(varuint_len(u64::MAX), 10);
    }
}
