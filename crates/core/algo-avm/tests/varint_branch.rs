//! Tests for variable-length (varint) branch encoding at LogicSigVersion >= 13
//! (go-algorand PR #6600, `varintBranchVersion`) -- issue #661.
//!
//! `bnz` (0x40), `bz` (0x41), `b` (0x42), `callsub` (0x88) switch from a
//! fixed 2-byte big-endian `int16` offset to a zigzag+ULEB128
//! (`binary.Varint`) encoded offset at v13+. The base point is
//! sign-dependent: a negative offset back-jumps from the *start* of the
//! instruction; a non-negative offset forward-jumps from the *end* of the
//! instruction (opcode byte + its own encoded varint bytes). `switch`/
//! `match` (0x8d/0x8e) are unaffected at any version.
//!
//! Reference: go-algorand (`../go-algorand` @ v5.0.0-stable)
//! `data/transactions/logic/eval.go` `branchTargetVarint`/`checkBranchVarint`,
//! `data/transactions/logic/opcodes.go` `varintBranchVersion`,
//! `data/transactions/logic/assembler.go` `findBranchSizes`/`resolveLabels`.

use algo_avm::assembler::assemble_string;
use algo_avm::bytecode::Immediates;
use algo_avm::disassembler::disassemble;
use algo_avm::{parse, AvmMachine, ExecMode, NullContext};

/// Helper: parse + run a raw (post-version-byte) program, returning
/// `Ok(pass)` (true = approve, false = reject) or the execution error.
fn run_program(version: u8, code: &[u8]) -> Result<bool, algo_error::AlgoError> {
    let mut raw = vec![version];
    raw.extend_from_slice(code);
    let program = parse(&raw)?;
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    machine.run(&mut NullContext)
}

// ---------------------------------------------------------------------------
// (a) small positive forward offset (single varint byte)
// ---------------------------------------------------------------------------

/// v13 program: `pushint 1; bnz +1(byte varint); err; pushint 1; return`.
///
/// Byte layout (post-version):
///   offset 0: 0x81 0x01        pushint 1                (2 bytes)
///   offset 2: 0x40 0x02        bnz, varint offset=+1     (2 bytes: opcode + 1 varint byte)
///   offset 4: 0x00             err                       (1 byte)
///   offset 5: 0x81 0x01        pushint 1                 (2 bytes)  <- branch target
///   offset 7: 0x43             return                    (1 byte)
///
/// bnz's instruction end (`after_instr`) = 2 + 1(opcode) + 1(varint) = 4.
/// Forward jump: target = after_instr + offset = 4 + 1 = 5, landing exactly
/// on the second `pushint 1` -- a valid instruction start, skipping `err`.
/// zigzag(1) = 1<<1 = 2 = 0x02 (fits in one byte, no continuation bit).
#[test]
fn test_bnz_varint_small_forward_offset() {
    let code: &[u8] = &[
        0x81, 0x01, // pushint 1
        0x40, 0x02, // bnz +1 (varint, 1 byte)
        0x00, // err (must be skipped)
        0x81, 0x01, // pushint 1  <- target
        0x43, // return
    ];
    let result = run_program(13, code).unwrap();
    assert!(result, "bnz should branch over err and return pass");
}

/// Same bytes at LogicSigVersion 12 must NOT be interpreted as a varint
/// branch -- `0x02` alone is only 2 of the required 2 fixed offset bytes,
/// so the (legacy) fixed-2-byte decode reads `0x02, 0x00` (offset=+512),
/// producing an entirely different (and here, out-of-bounds/misaligned)
/// target. This pins that the version gate actually distinguishes the two
/// encodings rather than always using one or the other.
#[test]
fn test_same_bytes_below_v13_use_legacy_fixed_2byte_encoding() {
    let code: &[u8] = &[
        0x81, 0x01, // pushint 1
        0x40, 0x02, 0x00, // bnz +512 (legacy fixed 2-byte offset)
        0x81, 0x01, // pushint 1
        0x43, // return
    ];
    // offset after bnz (fixed 3-byte instr) = 2+3 = 5; target = 5+512 = 517,
    // which is past the end of this (8-byte) program -- must error.
    let err = run_program(12, code).unwrap_err();
    assert!(
        err.to_string().contains("outside of program") || err.to_string().contains("not"),
        "expected out-of-range/misaligned branch error, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// (b) small negative back offset + (mixed forward/back) execution parity
// ---------------------------------------------------------------------------

/// A countdown loop using both a forward branch (`bz done`, to exit) and a
/// backward branch (`b loop`, to continue) at v13, assembled from TEAL
/// source so the varint widths are computed by the assembler itself. This
/// exercises the sign-dependent base point for both directions together and
/// pins the resulting bytecode's execution trace.
#[test]
fn test_mixed_forward_and_back_varint_branches_execute_correctly() {
    let source = "\
#pragma version 13
int 3
store 0
loop:
load 0
bz done
load 0
int 1
-
store 0
b loop
done:
int 1
return
";
    let ops = assemble_string(source).expect("assembly should succeed");
    assert_eq!(ops.program[0], 13);

    let program = parse(&ops.program).unwrap();
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    let result = machine.run(&mut NullContext).unwrap();
    assert!(result, "loop should terminate and return pass");
}

/// Direct byte-level pin for a small back-jump: `pushint 1; loop: pushint 1;
/// bnz loop-varint; ...`. Rather than looping forever, use `bz` with a
/// stack value that goes to zero after the loop body decrements it, via
/// hand-verified byte offsets (oracle: go-algorand's
/// `branchTargetVarint`/`checkBranchVarint`, `eval.go`).
///
/// Layout:
///   0: 0x81 0x02        pushint 2         (2 bytes)   -- counter
/// loop (offset 2):
///   2: 0x35 0x00        store 0           (2 bytes)   [first pass: pops 2]
///   4: 0x34 0x00        load 0            (2 bytes)
///   6: 0x81 0x01        pushint 1         (2 bytes)
///   8: 0x09             -                 (1 byte)
///   9: 0x81 0x00        pushint 0         (2 bytes)
///  11: 0x34 0x00        -- unused placeholder removed below --
///
/// This hand-rolled layout got complex to keep byte-exact while also
/// exercising a *back* branch; the loop-via-assembler test above already
/// pins back-branch correctness end-to-end. This test instead pins a
/// minimal, purely back-jump-to-self-loop-once byte encoding: `b` jumping
/// backward exactly to the start of the *previous* instruction (the
/// smallest possible nonzero back offset), executed once via a bz guard.
///
///   0: 0x81 0x00        pushint 0                      (2 bytes)
///   2: 0x40 0x?         bnz skip_back (varint, +N)      -- skip the back-jump on iteration 2
///   ...
///
/// To keep this deterministic and simple, assemble it via source instead
/// (see `test_back_branch_lands_on_recorded_instruction_start` below for the
/// raw-byte back-jump-alignment negative case, which is the sharper
/// consensus-relevant assertion for the back-jump base point).
#[test]
fn test_back_branch_varint_offset_is_negative_and_minimal() {
    // `#pragma version 13\nloop:\nint 1\nreturn\n` has no back branch, so
    // build one explicitly: `start: b start` is rejected at assembly time
    // (branch to start of same instruction), so use a 1-instruction body:
    // `start: int 1\npop\nb start` never terminates -- instead assert on
    // the *encoded bytes* of a known-good back branch via the assembler,
    // which is safe because we never execute it.
    //
    // `#pragma autosalt false` is required here: this specific source's
    // unsalted program hash happens to decode as a valid Edwards25519
    // curve point, so the auto-salt search (issue #664 / PR #692) would
    // otherwise splice extra intcblock bytes into the program and shift
    // every offset this test hand-verifies below. Suppressing it keeps the
    // byte layout the deterministic, hand-computed one this test actually
    // means to pin (the varint-branch encoding), independent of whatever
    // the auto-salt feature does elsewhere -- see issue #694.
    let source = "#pragma version 13\n#pragma autosalt false\nstart:\nint 1\npop\nb start\n";
    let ops = assemble_string(source).expect("assembly should succeed");
    // `int 1` is referenced once, so constant optimization emits `pushint 1`
    // directly (no intcblock). Program (post version byte): pushint 1
    // (0x81,0x01) + pop (0x48) + b (opcode 0x42 + varint).
    // start label = offset 0 (`pending`-relative, before the version byte).
    // b's opcode_pos = 0 (pushint) + 2 (pop) + 1 (pop's 1 byte) = 3.
    // jump = dest(0) - opcode_pos(3) = -3 -> zigzag(-3) = 5 = 0x05 (1 byte).
    let prog = &ops.program;
    let b_opcode_idx = prog
        .iter()
        .position(|&b| b == 0x42)
        .expect("b opcode present");
    assert_eq!(
        prog.len(),
        b_opcode_idx + 2,
        "b's varint offset should be exactly 1 byte for this small back-jump"
    );
    assert_eq!(
        prog[b_opcode_idx + 1],
        0x05,
        "zigzag(-3) must encode as 0x05"
    );

    // Round-trip through the disassembler/reassembler.
    let text = disassemble(prog).unwrap();
    let ops2 = assemble_string(&text).unwrap();
    assert_eq!(ops.program, ops2.program);
}

// ---------------------------------------------------------------------------
// (c) offset requiring 2+ varint bytes
// ---------------------------------------------------------------------------

/// Pad enough instructions between a `b` and its forward target that the
/// byte distance exceeds what a 1-byte zigzag varint can hold (63), forcing
/// a 2-byte encoding. Verified both via the parsed `Immediates::BranchVarint`
/// length and via successful execution (the branch must still land exactly
/// on the target instruction).
#[test]
fn test_branch_offset_requiring_two_or_more_varint_bytes() {
    let mut source = String::from("#pragma version 13\nb target\n");
    // Each "int 1\npop\n" is 2 bytes (intc_0) + 1 byte (pop) = 3 bytes once
    // constant-optimized... but at v13 with a single distinct int value,
    // the optimizer will (v4+) use an intcblock + intc_0, so pad with
    // varied byte pushes instead to guarantee a stable per-line size
    // without depending on constant-optimization behavior.
    for i in 0..40u32 {
        source.push_str(&format!("pushint {}\npop\n", i));
    }
    source.push_str("target:\nint 1\nreturn\n");

    let ops = assemble_string(&source).expect("assembly should succeed");
    let program = parse(&ops.program).unwrap();

    // Find the `b` instruction (opcode 0x42) and confirm its varint needed
    // more than 1 byte.
    let b_instr = program
        .instructions
        .iter()
        .find(|i| i.opcode == 0x42)
        .expect("b instruction present");
    match &b_instr.immediates {
        Immediates::BranchVarint(_offset, len) => {
            assert!(
                *len >= 2,
                "expected a >=2-byte varint offset for a ~120-byte forward jump, got {len} bytes"
            );
        }
        other => panic!("expected BranchVarint immediate, got {other:?}"),
    }

    // Execution must still land exactly on `target` (int 1; return -> pass).
    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    let result = machine.run(&mut NullContext).unwrap();
    assert!(result, "branch must land exactly on target across padding");

    // And it must round-trip through the disassembler.
    let text = disassemble(&ops.program).unwrap();
    let ops2 = assemble_string(&text).unwrap();
    assert_eq!(ops.program, ops2.program);
}

// ---------------------------------------------------------------------------
// (d) back-jump target that is NOT an instruction start (must error)
// ---------------------------------------------------------------------------

/// Hand-crafted raw program: `pushint 1; b <back-jump into the middle of
/// pushint 1's own literal byte>`. This is a back-jump (offset is negative)
/// whose target does not land on any recorded instruction-start boundary,
/// which go-algorand's `checkBranchVarint` rejects
/// ("back branch target ... is not an aligned instruction").
///
/// Layout:
///   0: 0x81 0x01   pushint 1        (2 bytes; offset 1 is the literal `01`,
///                                    not an instruction start)
///   2: 0x42 0x01   b, varint=-1     (2 bytes: opcode_pos=2, target=2-1=1)
///
/// Both the static validator (`validator::check_program`) and actual
/// execution must reject this.
#[test]
fn test_back_branch_not_aligned_to_instruction_start_errors() {
    let code: &[u8] = &[
        0x81, 0x01, // pushint 1 (offset 0-1; offset 1 is mid-instruction)
        0x42, 0x01, // b, varint offset = zigzag_decode(0x01) = -1
    ];

    // Sanity: zigzag_decode(1) == -1 (ux=1 is odd -> negative branch:
    // x = !(1>>1) = !0 = -1).
    let (offset, len) = algo_avm::bytecode::read_branch_varint(code, 3).unwrap();
    assert_eq!((offset, len), (-1, 1));

    // Execution must error.
    let err = run_program(13, code).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("does not match any instruction") || msg.contains("not"),
        "expected a misaligned-branch-target error, got: {msg}"
    );

    // Static validation must also reject it.
    let mut raw = vec![13u8];
    raw.extend_from_slice(code);
    let program = parse(&raw).unwrap();
    let validation = algo_avm::validator::check_program(
        &program,
        algo_avm::opcode::Mode::LogicSig,
        raw.len(),
        0,
    );
    assert!(
        validation.is_err(),
        "static validator should also reject a back-jump into the middle of an instruction"
    );
}

/// The assembler itself must refuse to emit a program whose back branch
/// would jump to the start of its *own* instruction (ambiguous under the
/// sign-based dispatch) -- matches go-algorand's `resolveLabels` check.
#[test]
fn test_assembler_rejects_branch_to_start_of_own_instruction() {
    // A label placed immediately before its own unconditional branch:
    // `here: b here` -- dest == opcode_pos.
    let source = "#pragma version 13\nhere:\nb here\n";
    let result = assemble_string(source);
    assert!(
        result.is_err(),
        "branch to the start of its own instruction must be rejected at assembly time"
    );
}

// ---------------------------------------------------------------------------
// switch/match remain fixed 2-byte at v13+ (unaffected by this issue)
// ---------------------------------------------------------------------------

#[test]
fn test_switch_match_unaffected_by_varint_branch_version() {
    let source = "\
#pragma version 13
int 0
switch label0 label1
label0:
int 1
return
label1:
int 2
return
";
    let ops = assemble_string(source).expect("assembly should succeed");
    let program = parse(&ops.program).unwrap();
    let switch_instr = program
        .instructions
        .iter()
        .find(|i| i.opcode == 0x8d)
        .expect("switch instruction present");
    match &switch_instr.immediates {
        Immediates::Labels(offsets) => assert_eq!(offsets.len(), 2),
        other => panic!("switch must still decode as Immediates::Labels, got {other:?}"),
    }

    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    let result = machine.run(&mut NullContext).unwrap();
    assert!(result);
}

// ---------------------------------------------------------------------------
// callsub varint behavior
// ---------------------------------------------------------------------------

/// `callsub` at v13+ must decode as a varint branch and correctly integrate
/// with the `proto`/`retsub` frame machinery (the `from_callsub` handshake
/// keys off `machine.pc`, the *instruction index*, so it is unaffected by
/// the underlying byte-width change -- but the branch target computation
/// itself must be correct for this to reach `proto` at all).
#[test]
fn test_callsub_varint_branch_v13() {
    let source = "\
#pragma version 13
callsub add
int 1
return

add:
proto 0 0
int 41
int 1
+
pop
retsub
";
    let ops = assemble_string(source).expect("assembly should succeed");
    let program = parse(&ops.program).unwrap();

    let callsub_instr = program
        .instructions
        .iter()
        .find(|i| i.opcode == 0x88)
        .expect("callsub instruction present");
    assert!(
        matches!(callsub_instr.immediates, Immediates::BranchVarint(_, _)),
        "callsub must decode as BranchVarint at v13"
    );

    let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 20_000);
    let result = machine.run(&mut NullContext).unwrap();
    assert!(
        result,
        "callsub -> proto -> retsub -> int 1; return should pass"
    );
}

// ---------------------------------------------------------------------------
// Assembler emits minimal-width varint at v13+
// ---------------------------------------------------------------------------

#[test]
fn test_assembler_emits_minimal_width_varint_and_roundtrips() {
    let source = "#pragma version 13\nb end\nend:\nint 1\nreturn\n";
    let ops = assemble_string(source).expect("assembly should succeed");
    // version(1) + b(0x42) + varint(1 byte, since target is immediately
    // adjacent: opcode_pos=1, offset_position=3, dest=3, jump=3-3=0 ->
    // zigzag(0)=0, 1 byte) + intcblock[1](3) + intc_0(1) + return(1).
    assert_eq!(ops.program[0], 13);
    assert_eq!(ops.program[1], 0x42, "b opcode");
    assert_eq!(
        ops.program[2], 0x00,
        "zigzag(0) == 0, minimal 1-byte encoding"
    );

    let text = disassemble(&ops.program).unwrap();
    let ops2 = assemble_string(&text).unwrap();
    assert_eq!(ops.program, ops2.program);
}
