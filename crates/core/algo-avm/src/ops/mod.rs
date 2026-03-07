//! Opcode implementations -- dispatch from opcode byte to handler functions.
//!
//! Each sub-module groups related opcodes. Most handlers are stubs that will
//! be implemented in Wave 3.

pub mod arithmetic;
pub mod bytes;
pub mod constants;
pub mod flow;
pub mod global;
pub mod helpers;
pub mod itxn;
pub mod logic;
pub mod stack;
pub mod state;
pub mod txn;

use algo_error::AlgoError;

use crate::bytecode::Instruction;
use crate::context::AvmContext;
use crate::machine::AvmMachine;

/// Dispatch an instruction to its handler.
///
/// The `ctx` parameter provides external state access.  Existing pure-opcode
/// handlers ignore it; future state-access opcodes will use it.
pub fn dispatch(
    machine: &mut AvmMachine,
    instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    match instruction.opcode {
        // ---- Error ----
        0x00 => flow::op_err(machine, instruction),

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

        // ---- Dynamic inner txn array access (v6+) ----
        0xc5 => itxn::op_itxnas(machine, instruction, ctx),
        0xc6 => itxn::op_gitxnas(machine, instruction, ctx),

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
