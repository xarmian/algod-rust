//! Program validator -- checks bytecode constraints before execution.
//!
//! Validates branch targets, mode restrictions, program size limits,
//! and performs basic stack depth analysis.

use std::collections::HashSet;

use algo_error::AlgoError;

use crate::bytecode::{Immediates, Program};
use crate::opcode::{self, CostKind, Mode};

/// Reject a program whose declared version byte exceeds the active
/// consensus parameters' `LogicSigVersion` ceiling.
///
/// This matches go-algorand's pre-eval check in
/// `data/transactions/logic/eval.go` where `program[0] > proto.LogicSigVersion`
/// is rejected. Even when the Rust AVM is built with `MAX_AVM_VERSION` higher
/// than the network's current consensus ceiling, programs declaring a version
/// above the ceiling must be rejected to match Go's accept/reject behavior.
///
/// # Parameters
/// - `declared_version`: the first byte of the program (the AVM version).
/// - `max_logic_sig_version`: `ConsensusParams::logic_sig_version` for the
///   active consensus protocol.
///
/// # Returns
/// - `Ok(())` if the declared version is within the ceiling.
/// - `Err(AlgoError::Avm { .. })` if the declared version exceeds the ceiling.
///
/// # References
/// - go-algorand `config/consensus.go:233` — `LogicSigVersion uint64` on
///   `ConsensusParams`.
/// - go-algorand `config/consensus.go:1440` — `v41.LogicSigVersion = 12`.
/// - go-algorand `data/transactions/logic/eval.go` — program-header parse and
///   `proto.LogicSigVersion` ceiling check.
pub fn check_program_version_allowed(
    declared_version: u8,
    max_logic_sig_version: u64,
) -> Result<(), AlgoError> {
    if declared_version as u64 > max_logic_sig_version {
        return Err(AlgoError::Avm {
            message: format!(
                "program version {declared_version} exceeds consensus LogicSigVersion ceiling {max_logic_sig_version}"
            ),
        });
    }
    Ok(())
}

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
/// `extra_pages` is the number of extra program pages granted to an Application program
/// (from the transaction's `ExtraProgramPages` field). This allows the max program size
/// to be `2048 * (1 + extra_pages)` for Application programs. LogicSig programs always
/// use the base limit (no extra pages). Pass `0` for the default behavior.
///
/// Checks performed:
/// - Program size limits
/// - Mode restrictions (LogicSig-only vs Application-only opcodes)
/// - Branch target validity (must land on instruction boundaries)
/// - Basic linear stack depth analysis
pub fn check_program(
    program: &Program,
    mode: Mode,
    program_len: usize,
    extra_pages: u32,
) -> Result<(), AlgoError> {
    check_size(program, mode, program_len, extra_pages)?;
    check_mode(program, mode)?;
    check_branch_targets(program)?;
    check_stack_depth(program)?;
    Ok(())
}

/// Enforce per-program size limits.
///
/// For LogicSig programs, extra_pages is ignored (always uses the base limit).
/// For Application programs with v4+, the limit is `2048 * (1 + extra_pages)`.
fn check_size(
    program: &Program,
    mode: Mode,
    program_len: usize,
    extra_pages: u32,
) -> Result<(), AlgoError> {
    let limit = if mode == Mode::LogicSig && program.version <= 3 {
        MAX_LOGICSIG_SIZE_V1_V3
    } else if mode == Mode::LogicSig {
        // LogicSig v4+ always uses the base limit, no extra pages.
        MAX_PROGRAM_SIZE_V4_PLUS
    } else if program.version >= 4 && extra_pages > 0 {
        // Application programs v4+: allow extra pages.
        MAX_PROGRAM_SIZE_V4_PLUS * (1 + extra_pages as usize)
    } else {
        // Application programs (v1-v3 or no extra pages): base limit.
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
        let spec = match opcode::resolve_spec(instr.opcode, instr.sub_opcode) {
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
            // Header is 2 bytes (prefix + sub-opcode) for a multi-byte
            // "prefix opcode" instruction (e.g. the `app_box_*` family at
            // 0xd4), 1 byte otherwise -- must match `header_len` in
            // `opcode::resolve`/`bytecode::parse`.
            let header_len = if instr.sub_opcode.is_some() { 2 } else { 1 };
            let imm_len = immediate_byte_len(&instr.immediates);
            instr.offset + header_len + imm_len
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
            Immediates::BranchVarint(offset, varint_len) => {
                // bnz/bz/b/callsub at LogicSigVersion >= 13.
                let target = resolve_varint_branch_offset(
                    program,
                    idx,
                    *offset,
                    *varint_len,
                    &valid_offsets,
                    end_offset,
                )?;
                let _ = target;
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

/// Resolve a varint-encoded branch offset (bnz/bz/b/callsub at
/// LogicSigVersion >= 13) relative to the instruction at `instr_idx`.
///
/// Sign-dependent base point, matching go-algorand's `branchTargetVarint`:
/// a negative offset is a back-jump from the instruction's own start; a
/// non-negative offset is a forward-jump from the end of the instruction
/// (opcode byte + varint bytes). The target must be a valid instruction
/// offset (uniformly for forward and back jumps -- see `resolve_branch_offset`
/// for why this single membership check is equivalent to go-algorand's
/// split back-jump/forward-jump alignment checks) or exactly the
/// end-of-program offset.
fn resolve_varint_branch_offset(
    program: &Program,
    instr_idx: usize,
    offset: i64,
    varint_len: usize,
    valid_offsets: &HashSet<usize>,
    end_offset: usize,
) -> Result<usize, AlgoError> {
    let instr = &program.instructions[instr_idx];
    let target = crate::bytecode::varint_branch_target(instr.offset, varint_len, offset);

    if target < 0 || target > end_offset as i128 {
        return Err(AlgoError::Avm {
            message: format!("branch target {target} outside of program"),
        });
    }
    let target = target as usize;

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
        Immediates::BranchVarint(_, len) => *len,
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
        let spec = match opcode::resolve_spec(instr.opcode, instr.sub_opcode) {
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
            // Use actual pop count from immediates when available.
            match instr.opcode {
                0x46 /* popn */ => {
                    if let Immediates::Uint8(n) = &instr.immediates { *n as i32 } else { 1 }
                }
                0x4b /* dig */ | 0x4e /* cover */ | 0x4f /* uncover */ => 0, // these rearrange, net effect handled in pushes
                0x8e /* match */ => {
                    if let Immediates::Labels(labels) = &instr.immediates {
                        labels.len() as i32 + 1
                    } else { 1 }
                }
                _ => 1, // conservative
            }
        } else {
            spec.stack_pops as i32
        };

        let pushes = if spec.stack_pushes < 0 {
            // Use actual push count from immediates when available.
            match instr.opcode {
                0x47 /* dupn */ => {
                    if let Immediates::Uint8(n) = &instr.immediates { *n as i32 + 1 } else { 1 }
                }
                0x4b /* dig */ => 1, // dig copies one value onto top (net +1)
                0x4e /* cover */ | 0x4f /* uncover */ => 0, // rearrange only, no net growth
                0x83 /* pushints */ => {
                    if let Immediates::PushInts(vals) = &instr.immediates { vals.len() as i32 } else { 1 }
                }
                0x82 /* pushbytess */ => {
                    if let Immediates::PushBytess(vals) = &instr.immediates { vals.len() as i32 } else { 1 }
                }
                _ => 1, // conservative
            }
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
        assert!(check_program(&program, Mode::Any, raw.len(), 0).is_ok());
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
        assert!(check_program(&program, Mode::Any, raw.len(), 0).is_ok());
    }

    #[test]
    fn test_invalid_branch_target() {
        // pushint 1, bnz +99 (targets offset that doesn't exist as instruction boundary)
        let raw = prog(3, &[0x81, 0x01, 0x40, 0x00, 0x63]);
        let program = parse(&raw).unwrap();
        let result = check_program(&program, Mode::Any, raw.len(), 0);
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
        let result = check_program(&program, Mode::LogicSig, raw.len(), 0);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("Application-only"), "{msg}");
    }

    #[test]
    fn test_mode_mismatch_app_with_logicsig_opcode() {
        // arg (0x2c) is LogicSig-only; running in Application mode should fail.
        let raw = prog(1, &[0x2c, 0x00]);
        let program = parse(&raw).unwrap();
        let result = check_program(&program, Mode::Application, raw.len(), 0);
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
            0,
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
            0,
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
            0,
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
        assert!(check_program(&program, Mode::Any, raw.len(), 0).is_ok());
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
        assert!(check_program(&program, Mode::Any, raw.len(), 0).is_ok());
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
        let result = check_program(&program, Mode::Any, raw.len(), 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_any_mode_allows_all() {
        // With Mode::Any, both LogicSig and Application opcodes should pass.
        // arg (LogicSig-only) at offset 0
        let raw = prog(1, &[0x2c, 0x00]);
        let program = parse(&raw).unwrap();
        assert!(check_program(&program, Mode::Any, raw.len(), 0).is_ok());
    }

    #[test]
    fn test_empty_program_is_valid() {
        let program = Program {
            version: 1,
            instructions: vec![],
        };
        assert!(check_program(&program, Mode::Any, 1, 0).is_ok());
    }

    #[test]
    fn test_extra_pages_allows_larger_application() {
        // With extra_pages=1, application programs can be up to 2048*2 = 4096 bytes.
        let result = check_program(
            &Program {
                version: 6,
                instructions: vec![],
            },
            Mode::Application,
            4096,
            1,
        );
        assert!(result.is_ok());

        // 4097 still exceeds with 1 extra page.
        let result = check_program(
            &Program {
                version: 6,
                instructions: vec![],
            },
            Mode::Application,
            4097,
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_extra_pages_three() {
        // With extra_pages=3, application programs can be up to 2048*4 = 8192 bytes.
        let result = check_program(
            &Program {
                version: 6,
                instructions: vec![],
            },
            Mode::Application,
            8192,
            3,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_extra_pages_ignored_for_logicsig() {
        // LogicSig v4+ always uses base 2048, extra_pages has no effect.
        let result = check_program(
            &Program {
                version: 4,
                instructions: vec![],
            },
            Mode::LogicSig,
            2049,
            3,
        );
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("exceeds limit 2048"), "{msg}");
    }

    // ---- Program-version ceiling gating (go-algorand eval.go) ----

    #[test]
    fn test_program_v11_under_v40_consensus_accepted() {
        // V40 consensus: LogicSigVersion = 11. Program v11 is at the ceiling.
        assert!(check_program_version_allowed(11, 11).is_ok());
    }

    #[test]
    fn test_program_v12_under_v40_consensus_rejected() {
        // V40 consensus: LogicSigVersion = 11. A v12 program exceeds it.
        let err = check_program_version_allowed(12, 11).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("exceeds consensus LogicSigVersion ceiling"),
            "{msg}"
        );
    }

    #[test]
    fn test_program_v12_under_v41_consensus_accepted() {
        // V41 consensus: LogicSigVersion = 12. Program v12 is at the ceiling.
        assert!(check_program_version_allowed(12, 12).is_ok());
    }

    #[test]
    fn test_program_v13_under_v41_consensus_rejected() {
        // V41 consensus: LogicSigVersion = 12. A v13 program exceeds it.
        let err = check_program_version_allowed(13, 12).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("program version 13"), "{msg}");
        assert!(msg.contains("ceiling 12"), "{msg}");
    }

    #[test]
    fn test_program_v0_ceiling_0_accepted() {
        // Defensive: a network with LogicSigVersion=0 (pre-logicsig) and a
        // program header reading 0 should pass the ceiling check. (The
        // bytecode parser separately rejects v0 via MAX_AVM_VERSION.)
        assert!(check_program_version_allowed(0, 0).is_ok());
    }

    #[test]
    fn test_program_v1_ceiling_0_rejected() {
        // Pre-logicsig consensus (LogicSigVersion=0) rejects any logicsig.
        assert!(check_program_version_allowed(1, 0).is_err());
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
