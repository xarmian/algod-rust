//! Opcode implementations -- dispatch from opcode byte to handler functions.
//!
//! Each sub-module groups related opcodes. Most handlers are stubs that will
//! be implemented in Wave 3.

pub mod arithmetic;
pub mod bytes;
pub mod constants;
pub mod crypto;
pub mod ec;
pub mod falcon;
pub mod flow;
pub mod global;
pub mod helpers;
pub mod itxn;
pub mod logic;
pub mod stack;
pub mod state;
pub mod txn;
pub mod vrf;

use algo_error::AlgoError;

use crate::bytecode::Instruction;
use crate::context::AvmContext;
use crate::machine::{AvmMachine, ExecMode};
use crate::opcode::{self, Mode};

/// Shared hex decoder for test code across ops sub-modules.
#[cfg(test)]
pub(crate) fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Check that the opcode is allowed in the current execution mode.
///
/// This is a defense-in-depth runtime check. The validator's `check_mode()`
/// already rejects mode-incompatible opcodes at parse time, but we enforce
/// again at dispatch time to match go-algorand's eval loop behavior.
fn check_runtime_mode(machine: &AvmMachine, opcode_byte: u8) -> Result<(), AlgoError> {
    if let Some(spec) = opcode::lookup(opcode_byte) {
        match (machine.mode, spec.mode) {
            (_, Mode::Any) | (ExecMode::Application, Mode::Application) => {}
            (ExecMode::LogicSig, Mode::Application) => {
                return Err(AlgoError::Avm {
                    message: format!("opcode {} not allowed in LogicSig mode", spec.name),
                });
            }
            (ExecMode::Application, Mode::LogicSig) => {
                return Err(AlgoError::Avm {
                    message: format!("opcode {} not allowed in Application mode", spec.name),
                });
            }
            (ExecMode::LogicSig, Mode::LogicSig) => {}
        }
    }
    Ok(())
}

/// Dispatch an instruction to its handler.
///
/// The `ctx` parameter provides external state access.  Existing pure-opcode
/// handlers ignore it; future state-access opcodes will use it.
pub fn dispatch(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    // Defense-in-depth: enforce mode restrictions at runtime.
    check_runtime_mode(machine, instruction.opcode)?;

    match instruction.opcode {
        // ---- Error ----
        0x00 => flow::op_err(machine, instruction),

        // ---- Crypto / Hash ----
        0x01 => crypto::op_sha256(machine, instruction),
        0x02 => crypto::op_keccak256(machine, instruction),
        0x03 => crypto::op_sha512_256(machine, instruction),
        0x04 => crypto::op_ed25519verify(machine, instruction, ctx),
        0x05 => crypto::op_ecdsa_verify(machine, instruction),
        0x06 => crypto::op_ecdsa_pk_decompress(machine, instruction),
        0x07 => crypto::op_ecdsa_pk_recover(machine, instruction),

        // ---- Constants ----
        0x20 => constants::op_intcblock(machine, instruction),
        0x21 => constants::op_intc(machine, instruction),
        0x22 => constants::op_intc_n(machine, instruction), // intc_0
        0x23 => constants::op_intc_n(machine, instruction), // intc_1
        0x24 => constants::op_intc_n(machine, instruction), // intc_2
        0x25 => constants::op_intc_n(machine, instruction), // intc_3
        0x26 => constants::op_bytecblock(machine, instruction),
        0x27 => constants::op_bytec(machine, instruction),
        0x28 => constants::op_bytec_n(machine, instruction), // bytec_0
        0x29 => constants::op_bytec_n(machine, instruction), // bytec_1
        0x2a => constants::op_bytec_n(machine, instruction), // bytec_2
        0x2b => constants::op_bytec_n(machine, instruction), // bytec_3
        0x80 => constants::op_pushbytes(machine, instruction),
        0x81 => constants::op_pushint(machine, instruction),
        0x82 => constants::op_pushbytess(machine, instruction),
        0x83 => constants::op_pushints(machine, instruction),

        // ---- LogicSig arguments ----
        0x2c => txn::op_arg(machine, instruction, ctx),
        0x2d => txn::op_arg_n(machine, instruction, ctx), // arg_0
        0x2e => txn::op_arg_n(machine, instruction, ctx), // arg_1
        0x2f => txn::op_arg_n(machine, instruction, ctx), // arg_2
        0x30 => txn::op_arg_n(machine, instruction, ctx), // arg_3

        // ---- Txn / Gtxn field access ----
        0x31 => txn::op_txn(machine, instruction, ctx),
        // ---- Global field access ----
        0x32 => global::op_global(machine, instruction, ctx),
        0x33 => txn::op_gtxn(machine, instruction, ctx),
        0x36 => txn::op_txna(machine, instruction, ctx),
        0x37 => txn::op_gtxna(machine, instruction, ctx),
        0x38 => txn::op_gtxns(machine, instruction, ctx),
        0x39 => txn::op_gtxnsa(machine, instruction, ctx),

        // ---- Dynamic txn array access (v5+) ----
        0xc0 => txn::op_txnas(machine, instruction, ctx),
        0xc1 => txn::op_gtxnas(machine, instruction, ctx),
        0xc2 => txn::op_gtxnsas(machine, instruction, ctx),
        0xc3 => txn::op_args(machine, instruction, ctx),
        0xc4 => state::op_gloadss(machine, instruction, ctx),

        // ---- Logic / bitwise ----
        0x10 => logic::op_and(machine, instruction),
        0x11 => logic::op_or(machine, instruction),
        0x19 => logic::op_bitwise_or(machine, instruction),
        0x1a => logic::op_bitwise_and(machine, instruction),
        0x1b => logic::op_bitwise_xor(machine, instruction),
        0x1c => logic::op_bitwise_not(machine, instruction),

        // ---- Scratch space ----
        0x34 => stack::op_load(machine, instruction),
        0x35 => stack::op_store(machine, instruction),
        0x3a => state::op_gload(machine, instruction, ctx),
        0x3b => state::op_gloads(machine, instruction, ctx),
        0x3c => state::op_gaid(machine, instruction, ctx),
        0x3d => state::op_gaids(machine, instruction, ctx),
        0x3e => stack::op_loads(machine, instruction),
        0x3f => stack::op_stores(machine, instruction),

        // ---- Stack manipulation ----
        0x45 => stack::op_bury(machine, instruction),
        0x46 => stack::op_popn(machine, instruction),
        0x47 => stack::op_dupn(machine, instruction),
        0x48 => stack::op_pop(machine, instruction),
        0x49 => stack::op_dup(machine, instruction),
        0x4a => stack::op_dup2(machine, instruction),
        0x4b => stack::op_dig(machine, instruction),
        0x4c => stack::op_swap(machine, instruction),
        0x4d => stack::op_select(machine, instruction),
        0x4e => stack::op_cover(machine, instruction),
        0x4f => stack::op_uncover(machine, instruction),

        // ---- Flow control ----
        0x40 => flow::op_bnz(machine, instruction),
        0x41 => flow::op_bz(machine, instruction),
        0x42 => flow::op_b(machine, instruction),
        0x43 => flow::op_return(machine, instruction),
        0x44 => flow::op_assert(machine, instruction),
        0x84 => crypto::op_ed25519verify_bare(machine, instruction),
        0x85 => crypto::op_falcon_verify(machine, instruction),
        0x86 => crypto::op_sumhash512(machine, instruction),
        0x87 => crypto::op_sha512(machine, instruction),
        0x88 => flow::op_callsub(machine, instruction),
        0x89 => flow::op_retsub(machine, instruction),
        0x8a => flow::op_proto(machine, instruction),
        0x8b => flow::op_frame_dig(machine, instruction),
        0x8c => flow::op_frame_bury(machine, instruction),
        0x8d => flow::op_switch(machine, instruction),
        0x8e => flow::op_match(machine, instruction),

        // ---- Bit/byte manipulation ----
        0x53 => logic::op_getbit(machine, instruction),
        0x54 => logic::op_setbit(machine, instruction),
        0x55 => logic::op_getbyte(machine, instruction),
        0x56 => logic::op_setbyte(machine, instruction),

        // ---- Arithmetic ----
        0x08 => arithmetic::op_add(machine, instruction),
        0x09 => arithmetic::op_sub(machine, instruction),
        0x0a => arithmetic::op_div(machine, instruction),
        0x0b => arithmetic::op_mul(machine, instruction),
        0x0c => arithmetic::op_lt(machine, instruction),
        0x0d => arithmetic::op_gt(machine, instruction),
        0x0e => arithmetic::op_le(machine, instruction),
        0x0f => arithmetic::op_ge(machine, instruction),
        0x12 => arithmetic::op_eq(machine, instruction),
        0x13 => arithmetic::op_neq(machine, instruction),
        0x14 => arithmetic::op_not(machine, instruction),
        0x18 => arithmetic::op_modulo(machine, instruction),
        0x1d => arithmetic::op_mulw(machine, instruction),
        0x1e => arithmetic::op_addw(machine, instruction),
        0x1f => arithmetic::op_divmodw(machine, instruction),
        0x90 => arithmetic::op_shl(machine, instruction),
        0x91 => arithmetic::op_shr(machine, instruction),
        0x92 => arithmetic::op_sqrt(machine, instruction),
        0x93 => arithmetic::op_bitlen(machine, instruction),
        0x94 => arithmetic::op_exp(machine, instruction),
        0x95 => arithmetic::op_expw(machine, instruction),
        0x97 => arithmetic::op_divw(machine, instruction),
        0x98 => crypto::op_sha3_256(machine, instruction),

        // ---- Byte string operations ----
        0x15 => bytes::op_len(machine, instruction),
        0x16 => bytes::op_itob(machine, instruction),
        0x17 => bytes::op_btoi(machine, instruction),
        0x50 => bytes::op_concat(machine, instruction),
        0x51 => bytes::op_substring(machine, instruction),
        0x52 => bytes::op_substring3(machine, instruction),
        0x57 => bytes::op_extract(machine, instruction),
        0x58 => bytes::op_extract3(machine, instruction),
        0x59 => bytes::op_extract_uint16(machine, instruction),
        0x5a => bytes::op_extract_uint32(machine, instruction),
        0x5b => bytes::op_extract_uint64(machine, instruction),
        0x5c => bytes::op_replace2(machine, instruction),
        0x5d => bytes::op_replace3(machine, instruction),

        // ---- Encoding / JSON ----
        0x5e => crypto::op_base64_decode(machine, instruction),
        0x5f => crypto::op_json_ref(machine, instruction),

        // ---- App state ----
        0x60 => state::op_balance(machine, instruction, ctx),
        0x61 => state::op_app_opted_in(machine, instruction, ctx),
        0x62 => state::op_app_local_get(machine, instruction, ctx),
        0x63 => state::op_app_local_get_ex(machine, instruction, ctx),
        0x64 => state::op_app_global_get(machine, instruction, ctx),
        0x65 => state::op_app_global_get_ex(machine, instruction, ctx),
        0x66 => state::op_app_local_put(machine, instruction, ctx),
        0x67 => state::op_app_global_put(machine, instruction, ctx),
        0x68 => state::op_app_local_del(machine, instruction, ctx),
        0x69 => state::op_app_global_del(machine, instruction, ctx),

        // ---- Asset / App / Account queries ----
        0x70 => state::op_asset_holding_get(machine, instruction, ctx),
        0x71 => state::op_asset_params_get(machine, instruction, ctx),
        0x72 => state::op_app_params_get(machine, instruction, ctx),
        0x73 => state::op_acct_params_get(machine, instruction, ctx),

        // ---- Voter / stake (v11+) ----
        0x74 => state::op_voter_params_get(machine, instruction, ctx),
        0x75 => state::op_online_stake(machine, instruction, ctx),

        // ---- App params set (foreignBoxVersion / v5.0.0-stable) ----
        0x76 => state::op_app_params_set(machine, instruction, ctx),

        // ---- Min balance ----
        0x78 => state::op_min_balance(machine, instruction, ctx),

        // ---- Big-integer byte-math ----
        0x96 => bytes::op_bsqrt(machine, instruction),
        0xa0 => bytes::op_badd(machine, instruction),
        0xa1 => bytes::op_bsub(machine, instruction),
        0xa2 => bytes::op_bdiv(machine, instruction),
        0xa3 => bytes::op_bmul(machine, instruction),
        0xa4 => bytes::op_blt(machine, instruction),
        0xa5 => bytes::op_bgt(machine, instruction),
        0xa6 => bytes::op_ble(machine, instruction),
        0xa7 => bytes::op_bge(machine, instruction),
        0xa8 => bytes::op_beq(machine, instruction),
        0xa9 => bytes::op_bne(machine, instruction),
        0xaa => bytes::op_bmod(machine, instruction),
        0xab => bytes::op_bbitwise_or(machine, instruction),
        0xac => bytes::op_bbitwise_and(machine, instruction),
        0xad => bytes::op_bbitwise_xor(machine, instruction),
        0xae => bytes::op_bbitwise_not(machine, instruction),
        0xaf => bytes::op_bzero(machine, instruction),

        // ---- Logging ----
        0xb0 => state::op_log(machine, instruction, ctx),

        // ---- Inner transactions ----
        0xb1 => itxn::op_itxn_begin(machine, instruction, ctx),
        0xb2 => itxn::op_itxn_field(machine, instruction, ctx),
        0xb3 => itxn::op_itxn_submit(machine, instruction, ctx),
        0xb4 => itxn::op_itxn(machine, instruction, ctx),
        0xb5 => itxn::op_itxna(machine, instruction, ctx),
        0xb6 => itxn::op_itxn_next(machine, instruction, ctx),
        0xb7 => itxn::op_gitxn(machine, instruction, ctx),
        0xb8 => itxn::op_gitxna(machine, instruction, ctx),

        // ---- Box storage (v8+) ----
        0xb9 => state::op_box_create(machine, instruction, ctx),
        0xba => state::op_box_extract(machine, instruction, ctx),
        0xbb => state::op_box_replace(machine, instruction, ctx),
        0xbc => state::op_box_del(machine, instruction, ctx),
        0xbd => state::op_box_len(machine, instruction, ctx),
        0xbe => state::op_box_get(machine, instruction, ctx),
        0xbf => state::op_box_put(machine, instruction, ctx),

        // ---- Dynamic inner txn array access (v6+) ----
        0xc5 => itxn::op_itxnas(machine, instruction, ctx),
        0xc6 => itxn::op_gitxnas(machine, instruction, ctx),

        // ---- VRF / Block field access (v7+) ----
        0xd0 => crypto::op_vrf_verify(machine, instruction),
        0xd1 => state::op_block(machine, instruction, ctx),

        // ---- Box splice/resize (v10+) ----
        0xd2 => state::op_box_splice(machine, instruction, ctx),
        0xd3 => state::op_box_resize(machine, instruction, ctx),

        // ---- Foreign box opcodes (v13+, multi-byte prefix 0xd4) ----
        0xd4 => match instruction.sub_opcode {
            Some(0x01) => state::op_app_box_create(machine, instruction, ctx),
            Some(0x02) => state::op_app_box_extract(machine, instruction, ctx),
            Some(0x03) => state::op_app_box_replace(machine, instruction, ctx),
            Some(0x04) => state::op_app_box_del(machine, instruction, ctx),
            Some(0x05) => state::op_app_box_len(machine, instruction, ctx),
            Some(0x06) => state::op_app_box_get(machine, instruction, ctx),
            Some(0x07) => state::op_app_box_put(machine, instruction, ctx),
            Some(0x08) => state::op_app_box_splice(machine, instruction, ctx),
            Some(0x09) => state::op_app_box_resize(machine, instruction, ctx),
            // Unreachable in practice: `opcode::resolve` (used by
            // `bytecode::parse`) already rejects any other sub-opcode byte
            // for prefix 0xd4 before an `Instruction` can exist.
            other => Err(AlgoError::Avm {
                message: format!("app_box_* opcode with invalid sub-opcode {other:?}"),
            }),
        },

        // ---- Elliptic curve opcodes (v10+) ----
        0xe0 => ec::op_ec_add(machine, instruction),
        0xe1 => ec::op_ec_scalar_mul(machine, instruction),
        0xe2 => ec::op_ec_pairing_check(machine, instruction),
        0xe3 => ec::op_ec_multi_scalar_mul(machine, instruction),
        0xe4 => ec::op_ec_subgroup_check(machine, instruction),
        0xe5 => ec::op_ec_map_to(machine, instruction),

        // ---- MiMC hash (v11+) ----
        0xe6 => crypto::op_mimc(machine, instruction),

        // ---- Poseidon2 hash (v13+) ----
        0xe7 => crypto::op_poseidon2(machine, instruction),

        // ---- Everything else: not yet implemented ----
        _ => {
            let name = crate::opcode::lookup(instruction.opcode)
                .map(|s| s.name)
                .unwrap_or("unknown");
            Err(AlgoError::Avm {
                message: format!(
                    "opcode {} (0x{:02x}) not yet implemented",
                    name, instruction.opcode
                ),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode;
    use crate::context::NullContext;
    use crate::machine::{AvmMachine, ExecMode};

    /// Build a raw program from version byte + code bytes.
    fn prog(version: u8, code: &[u8]) -> Vec<u8> {
        let mut p = vec![version];
        p.extend_from_slice(code);
        p
    }

    /// Step the machine N times.
    fn step_n(m: &mut AvmMachine, ctx: &mut dyn AvmContext, n: usize) -> Result<(), AlgoError> {
        for _ in 0..n {
            m.step(ctx)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Runtime mode enforcement: app-only opcodes in LogicSig mode must fail
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_global_put_rejected_in_logicsig_mode() {
        // pushbytes "key", pushint 42, app_global_put (0x67)
        // app_global_put is Application-only
        let raw = prog(
            5,
            &[
                0x80, 0x03, b'k', b'e', b'y', // pushbytes "key"
                0x81, 0x2a, // pushint 42
                0x67, // app_global_put
            ],
        );
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        // Step past pushbytes and pushint, then app_global_put should fail
        let result = step_n(&mut m, &mut NullContext, 3);
        assert!(
            result.is_err(),
            "app_global_put should fail in LogicSig mode"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not allowed in LogicSig mode"),
            "expected 'not allowed in LogicSig mode', got: {msg}"
        );
    }

    #[test]
    fn test_log_rejected_in_logicsig_mode() {
        // pushbytes "hello", log (0xb0)
        // log is Application-only
        let raw = prog(
            5,
            &[
                0x80, 0x05, b'h', b'e', b'l', b'l', b'o', // pushbytes "hello"
                0xb0, // log
            ],
        );
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        let result = step_n(&mut m, &mut NullContext, 2);
        assert!(result.is_err(), "log should fail in LogicSig mode");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not allowed in LogicSig mode"),
            "expected 'not allowed in LogicSig mode', got: {msg}"
        );
    }

    #[test]
    fn test_itxn_begin_rejected_in_logicsig_mode() {
        // itxn_begin (0xb1) is Application-only
        let raw = prog(5, &[0xb1]);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        let result = m.step(&mut NullContext);
        assert!(result.is_err(), "itxn_begin should fail in LogicSig mode");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not allowed in LogicSig mode"),
            "expected 'not allowed in LogicSig mode', got: {msg}"
        );
    }

    #[test]
    fn test_balance_rejected_in_logicsig_mode() {
        // pushint 0, balance (0x60) is Application-only
        let raw = prog(5, &[0x81, 0x00, 0x60]);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        let result = step_n(&mut m, &mut NullContext, 2);
        assert!(result.is_err(), "balance should fail in LogicSig mode");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not allowed in LogicSig mode"),
            "expected 'not allowed in LogicSig mode', got: {msg}"
        );
    }

    #[test]
    fn test_gload_rejected_in_logicsig_mode() {
        // gload 0 0 (0x3a) is Application-only
        let raw = prog(5, &[0x3a, 0x00, 0x00]);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        let result = m.step(&mut NullContext);
        assert!(result.is_err(), "gload should fail in LogicSig mode");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("not allowed in LogicSig mode"),
            "expected 'not allowed in LogicSig mode', got: {msg}"
        );
    }

    #[test]
    fn test_arithmetic_still_works_in_logicsig_mode() {
        // pushint 3, pushint 4, + => 7 on stack, then pushint 1 for pass
        let raw = prog(
            3,
            &[
                0x81, 0x03, // pushint 3
                0x81, 0x04, // pushint 4
                0x08, // +
                0x81, 0x01, // pushint 1 (for truthy top of stack)
            ],
        );
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        // Run the first 3 instructions: pushint 3, pushint 4, add
        step_n(&mut m, &mut NullContext, 3).unwrap();
        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], crate::machine::AvmValue::Uint64(7));
    }

    #[test]
    fn test_crypto_still_works_in_logicsig_mode() {
        // pushbytes "hello", sha256 => hash on stack
        let raw = prog(
            3,
            &[
                0x80, 0x05, b'h', b'e', b'l', b'l', b'o', // pushbytes "hello"
                0x01, // sha256
            ],
        );
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::LogicSig, 20000);
        step_n(&mut m, &mut NullContext, 2).unwrap();
        assert_eq!(m.stack.len(), 1);
        // sha256("hello") should produce 32 bytes
        if let crate::machine::AvmValue::Bytes(b) = &m.stack[0] {
            assert_eq!(b.len(), 32);
        } else {
            panic!("expected bytes on stack after sha256");
        }
    }

    #[test]
    fn test_app_only_opcodes_work_in_application_mode() {
        // Verify that app_global_put does NOT get rejected in Application mode.
        // It may still fail due to NullContext, but NOT due to mode restriction.
        let raw = prog(
            5,
            &[
                0x80, 0x03, b'k', b'e', b'y', // pushbytes "key"
                0x81, 0x2a, // pushint 42
                0x67, // app_global_put
            ],
        );
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 20000);
        let result = step_n(&mut m, &mut NullContext, 3);
        // It may fail for other reasons (NullContext), but not mode restriction
        if let Err(e) = &result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("not allowed in"),
                "should not get mode error in Application mode, got: {msg}"
            );
        }
    }
}
