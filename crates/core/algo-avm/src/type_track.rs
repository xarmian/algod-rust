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

//! Static stack-type-tracking pass for the TEAL assembler (issue #829).
//!
//! Mirrors a deliberately incremental slice of go-algorand's compile-time
//! stack-type inference: `data/transactions/logic/assembler.go`'s
//! `ProgramKnowledge` (the tracked `stack` of [`StackType`]s, its
//! `deadcode`/`bottom` fields, and its `scratchSpace` -- see below),
//! `trackStack` (arg/return checking against the tracked stack), and the
//! handful of `type*` "refine" functions (`typeSwap`, `typeDup`,
//! `typeDupTwo`, `typeSelect`, `typeSetBit`, `typeDig`, `typeEquals`,
//! `typeStore`, `typeLoad`, `typeStores`, `typeLoads`) whose return type (or,
//! for the scratch-space four, a side effect on `scratchSpace`) depends on
//! what's actually tracked on the stack rather than a fixed per-opcode
//! proto.
//!
//! # What this slice covers
//!
//! - Straight-line (branch-free) instruction sequences: arithmetic/logic/
//!   comparison opcodes with a fixed uint64/bytes proto, literal pushes
//!   (`int`, `byte`, `pushint`, `pushbytes`, `intc*`, `bytec*`, `addr`,
//!   `arg*`, `method`), and the stack-shuffling opcodes above whose return
//!   type is data-dependent.
//! - **Branch-merge unification** (`TestBranchAssemblyTypeCheck`,
//!   `TestTypeTracking`, `TestTypeTrackingRegression`): mirrors go's actual
//!   algorithm exactly, which turns out to be simpler than a full
//!   per-predecessor CFG merge. go tracks two extra bits of state
//!   alongside the stack (`ProgramKnowledge.deadcode`/`bottom`,
//!   `assembler.go:307-380`):
//!   - `b`/`callsub`/`retsub`/`err`/`return` (`OpSpec.deadens`,
//!     `opcodes.go:520-527`) mark everything until the next label as dead
//!     code: no type checks or stack-effect tracking happen there (the
//!     tracked stack is left empty), so a real type mistake inside dead
//!     code is never reported. `callsub` additionally reopens analysis
//!     immediately (its own target is a label-like entry point, since
//!     `retsub` returns right after it), rather than waiting for a
//!     textual label.
//!   - Reaching a label after dead code reopens analysis with a
//!     *permissive* stack: further underflow (asking for more stack
//!     arguments than are currently tracked) is silently satisfied by an
//!     implicit, unlimited supply of [`StackType::Any`] rather than
//!     reported as a height error, mirroring `bottom` becoming `StackAny`.
//!   - Critically, a label reached *without* preceding dead code (e.g.
//!     immediately after a conditional `bnz`/`bz`, which does not deaden)
//!     does **not** reset anything -- go simply trusts that whatever's
//!     tracked along the fallthrough path also describes the state at any
//!     jump into that label, and keeps analyzing with it unchanged. This is
//!     asymmetric and not a true meet-over-all-predecessors dataflow
//!     join, but it is exactly go's real behavior, confirmed against
//!     `TestBranchAssemblyTypeCheck`/`TestTypeTracking`.
//!
//! `switch` was moved out of the old "permanently disable" set into the
//! normal-tracking path in this slice: like `bnz`/`bz`, go's `switch`
//! does not deaden (index-out-of-range falls through), and it already
//! had a fixed, exact proto (`Uint64` pop, no push) in [`TYPE_TABLE`].
//!
//! - **Scratch-slot per-index type tracking** (`TestScratchTypeCheck`, and
//!   the message-observable case of `TestScratchBounds`): mirrors go's
//!   `ProgramKnowledge.scratchSpace` (see [`OpStream::scratch_space`]) --
//!   `store i`/`load i` (a fixed immediate slot) read/write that slot's
//!   exact type; `stores`/`loads` (a *dynamic* slot index popped from the
//!   stack at runtime) resolve the slot exactly only when the index is a
//!   compile-time-constant `int` literal sitting right underneath (tracked
//!   via [`OpStream::type_stack_const`], mirroring go's narrow
//!   `StackType.constInt()` use in `typeStores`/`typeLoads`); otherwise
//!   `stores` conservatively unions *every* slot with the stored value's
//!   type (go can't know which slot was actually written), and `loads`
//!   falls back to a shared type only if literally every slot currently
//!   agrees, else `Any`. All four slots start as `Uint64` (an untouched
//!   scratch slot reads as zero at runtime) and reset to `Any` -- never back
//!   to `Uint64` -- wherever [`OpStream::type_track_bottom_permissive`] is
//!   set (a label reached through dead code, or a `callsub`), mirroring
//!   go's `ProgramKnowledge.reset`.
//!
//! On a type mismatch this reports the same diagnostic shape as
//! go-algorand's `typeErrorf` calls in `trackStack`: `"<instr> arg <i>
//! wanted type <want> got <got>"` or `"<instr> expects <n> stack arguments
//! but stack height is <h>"`.
//!
//! - **`#pragma typetrack false`/`true`** (part of `TestTypeTracking`):
//!   mirrors go's manual off/on toggle mid-program (`assembler.go:2501-2519`,
//!   `OpStream.typeTracking`/`typeErrorf`, `assembler.go:256,294,2039-2043`).
//!   This gates only whether a mismatch is *reported* -- the tracked stack
//!   (and scratch-space) keeps evolving underneath regardless, exactly like
//!   go's `trackStack` unconditionally popping/pushing `ops.known.stack`
//!   and only `typeErrorf` checking the flag. Toggling from off back to on
//!   resets tracked knowledge to a permissive state (mirrors
//!   `ops.known.reset()`, called from the pragma handler,
//!   `assembler.go:2513-2517`), exactly like reaching a label after dead
//!   code; toggling off, or re-declaring the current state, does not reset.
//!   See [`OpStream::type_track_reporting`](crate::assembler::OpStream) and
//!   the `#pragma typetrack` handling in
//!   [`assemble_string`](crate::assembler::assemble_string).
//!
//! - **Fixed-immediate-arity opcodes** (`TestDupPopNTyping`): `popn n`,
//!   `dupn n`, `cover n`, and `uncover n` all read a single immediate byte
//!   directly from the bytecode at assembly time, so (unlike `match`/`txn`/
//!   `pushbytess`/below) their pop/push counts are fully known statically.
//!   Ports go's `typePopN`/`typeDupN`/`typeCover`/`typeUncover`
//!   (`assembler.go:1486-1524,1621-1646`) directly -- see the `"popn"` /
//!   `"dupn"` / `"cover"` / `"uncover"` arms of [`refined_types`]. `popn n`
//!   pops `n` opaque (`Any`) values with no return; `dupn n` leaves `n+1`
//!   copies of the popped value's actual tracked type on top; `cover n` /
//!   `uncover n` rotate the top `n+1` stack slots (`Any` going in, the
//!   actual tracked types coming back out in the rotated order, whenever
//!   that many slots are currently tracked).
//!
//! # What's deferred (tracked as follow-up work under issue #829)
//!
//! - **Dispatch- or variable-length-immediate stack effects** this slice
//!   still can't model precisely enough to keep the tracked stack height in
//!   sync with the real one -- unchanged from before: `match` (label-count
//!   dependent), `txn`/`gtxn`/`gtxns` (dispatch to a different real opcode
//!   depending on immediate count), and `pushbytess`/`pushints` (a
//!   variable-length immediate array) permanently disable tracking for the
//!   rest of the program (see [`hard_disables_tracking`] and the
//!   dynamic-arity fallback in [`track_instruction`]). This remains
//!   conservative by construction: it can only *lose* precision, never
//!   *fabricate* an error, so it cannot make a currently-valid program newly
//!   fail to assemble.
//! - **Bounds-refined types** (`TestMatchTyping`, `TestArgType`,
//!   `TestTypeComplaints`, sized-type diagnostics like `[32]byte`, and
//!   `TestScratchBounds`'s direct `os.known.scratchSpace[i].Bound`
//!   assertions): go's `StackType` also carries a `[min, max]` length/value
//!   bound (`NewStackType`, `eval.go`); this slice's [`StackType`] is
//!   bound-free (`Uint64` / `Bytes` / `Any`), matching go's `overlaps`
//!   exactly for these opcodes (bounds only ever narrow the plain-
//!   `StackUint64`/`StackBytes` case, which is what every opcode here uses)
//!   but not reproducing go's `[N]byte`/`(<= N)`-style diagnostic text, nor
//!   `TestScratchBounds`'s exact numeric `Bound` values (only its one
//!   message-observable assertion -- the final `testProg` call, an
//!   AVMType-level mismatch -- is covered; see [`OpStream::type_stack_const`]
//!   for the narrow, purpose-built constant-tracking this slice does
//!   instead of general bound propagation).
//! - `TestTxTypes`: exercises the deferred `txn` dispatch behavior above.
//!
//! See `docs/phase17/parity_txn_logic.md` for the full go-test mapping.

use crate::assembler::OpStream;
use crate::opcode;

/// A statically tracked stack-slot type. Mirrors go-algorand's `avmType`
/// (`eval.go`) without its bounds refinement (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StackType {
    Uint64,
    Bytes,
    /// Could be either type -- unifies with anything. Mirrors go's
    /// `StackAny`.
    Any,
}

use StackType::{Any, Bytes, Uint64};

impl StackType {
    /// Mirrors go's `StackType.overlaps` (`eval.go:1030-1051`) restricted to
    /// the bound-free case: `Any` overlaps everything, otherwise the two
    /// types must match exactly.
    fn overlaps(self, expected: StackType) -> bool {
        self == Any || expected == Any || self == expected
    }
}

impl std::fmt::Display for StackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Uint64 => "uint64",
            Bytes => "[]byte",
            Any => "any",
        })
    }
}

/// Mirrors go's `StackType.union` (`eval.go:991-1000`) restricted to the
/// bound-free case: same type through, otherwise `Any`.
fn union(a: StackType, b: StackType) -> StackType {
    if a == b {
        a
    } else {
        Any
    }
}

/// Static arg/return type table for opcodes with a fixed, data-independent
/// proto. Mirrors the relevant subset of go-algorand's per-opcode `proto(..)`
/// strings (`opcodes.go`). Opcodes not listed here fall back to
/// [`StackType::Any`] for every argument/return slot (using the pop/push
/// counts already in [`opcode::OpSpec`]) -- always safe, since `Any`
/// overlaps everything and never manufactures a spurious mismatch.
const TYPE_TABLE: &[(&str, &[StackType], &[StackType])] = &[
    // ---- Arithmetic / comparison / logic (proto "ii:i") ----
    ("+", &[Uint64, Uint64], &[Uint64]),
    ("-", &[Uint64, Uint64], &[Uint64]),
    ("*", &[Uint64, Uint64], &[Uint64]),
    ("/", &[Uint64, Uint64], &[Uint64]),
    ("%", &[Uint64, Uint64], &[Uint64]),
    ("<", &[Uint64, Uint64], &[Uint64]),
    (">", &[Uint64, Uint64], &[Uint64]),
    ("<=", &[Uint64, Uint64], &[Uint64]),
    (">=", &[Uint64, Uint64], &[Uint64]),
    ("&&", &[Uint64, Uint64], &[Uint64]),
    ("||", &[Uint64, Uint64], &[Uint64]),
    ("|", &[Uint64, Uint64], &[Uint64]),
    ("&", &[Uint64, Uint64], &[Uint64]),
    ("^", &[Uint64, Uint64], &[Uint64]),
    // ---- Unary uint64 (proto "i:i") ----
    ("!", &[Uint64], &[Uint64]),
    ("~", &[Uint64], &[Uint64]),
    // ---- Type conversion ----
    ("itob", &[Uint64], &[Bytes]),
    ("btoi", &[Bytes], &[Uint64]),
    ("len", &[Bytes], &[Uint64]),
    ("concat", &[Bytes, Bytes], &[Bytes]),
    // ---- Wide arithmetic (proto "ii:ii" / "iiii:iiii") ----
    ("mulw", &[Uint64, Uint64], &[Uint64, Uint64]),
    ("addw", &[Uint64, Uint64], &[Uint64, Uint64]),
    (
        "divmodw",
        &[Uint64, Uint64, Uint64, Uint64],
        &[Uint64, Uint64, Uint64, Uint64],
    ),
    // ---- ==/!= base proto ("aa:T"); `refined_types` overrides the args
    // once both operand types are known, but the fixed uint64 (boolean)
    // return always applies. ----
    ("==", &[Any, Any], &[Uint64]),
    ("!=", &[Any, Any], &[Uint64]),
    // ---- select/setbit: proto fixes everything but the return type,
    // which `refined_types` overrides. ----
    ("select", &[Any, Any, Uint64], &[Any]),
    ("setbit", &[Any, Uint64, Uint64], &[Any]),
    // ---- dig: static fallback proto ("a:aa") used only when the
    // immediate can't be parsed; `refined_types` normally overrides both
    // sides using the actual depth. ----
    ("dig", &[Any], &[Any, Any]),
    // ---- Literal / constant-pool pushes ----
    ("pushint", &[], &[Uint64]),
    ("pushbytes", &[], &[Bytes]),
    ("intc", &[], &[Uint64]),
    ("intc_0", &[], &[Uint64]),
    ("intc_1", &[], &[Uint64]),
    ("intc_2", &[], &[Uint64]),
    ("intc_3", &[], &[Uint64]),
    ("bytec", &[], &[Bytes]),
    ("bytec_0", &[], &[Bytes]),
    ("bytec_1", &[], &[Bytes]),
    ("bytec_2", &[], &[Bytes]),
    ("bytec_3", &[], &[Bytes]),
    ("arg", &[], &[Bytes]),
    ("arg_0", &[], &[Bytes]),
    ("arg_1", &[], &[Bytes]),
    ("arg_2", &[], &[Bytes]),
    ("arg_3", &[], &[Bytes]),
    // ---- Branch/exit condition types. `bnz`/`bz`/`switch` don't deaden
    // (go's `OpSpec.deadens`, `opcodes.go:520-527` -- execution may fall
    // through past any of them), so tracking continues normally after
    // them; `return` does deaden (see `deadens_tracking`). ----
    ("bnz", &[Uint64], &[]),
    ("bz", &[Uint64], &[]),
    ("switch", &[Uint64], &[]),
    ("return", &[Uint64], &[]),
    ("assert", &[Uint64], &[]),
    // ---- Scratch-space load/store base protos (opcodes.go:611-627):
    // `load`/`store` take a fixed immediate slot index (not a stack arg);
    // `loads`/`stores` take a dynamic uint64 index off the stack. All four
    // push/pop an `Any` value, refined to the tracked slot's exact type (or
    // used to update it) by `refined_types` below. ----
    ("load", &[], &[Any]),
    ("store", &[Any], &[]),
    ("loads", &[Uint64], &[Any]),
    ("stores", &[Uint64, Any], &[]),
];

fn table_lookup(mnemonic: &str) -> Option<(&'static [StackType], &'static [StackType])> {
    TYPE_TABLE
        .iter()
        .find(|(name, _, _)| *name == mnemonic)
        .map(|(_, a, r)| (*a, *r))
}

/// Mnemonics that are looked up directly (not via [`opcode::lookup_by_name`])
/// because they never reach `asm_regular`: pseudo-ops that assemble to an
/// `intc`/`bytec` reference rather than being real opcodes themselves.
/// Always push exactly one value of a fixed type, regardless of the literal
/// written (mirrors go's `typePushInt`/`typeByte`, `assembler.go:1666-1690`,
/// which is likewise unconditional).
fn literal_push_type(mnemonic: &str) -> Option<StackType> {
    match mnemonic {
        "int" => Some(Uint64),
        "byte" | "addr" | "method" => Some(Bytes),
        _ => None,
    }
}

/// Mnemonics that unconditionally end or divert control flow, marking
/// everything until the next label as dead code. Mirrors go's
/// `OpSpec.deadens` (`opcodes.go:520-527`) exactly: `bnz`/`bz`/`switch` are
/// deliberately *not* included here (a conditional branch, or an
/// out-of-range `switch` index, can fall through to the next instruction),
/// unlike this module's previous "permanently disable on any branch" logic.
/// See [`OpStream::type_track_deadcode`](crate::assembler::OpStream) and
/// the module docs' branch-merge section.
fn deadens_tracking(mnemonic: &str) -> bool {
    matches!(mnemonic, "b" | "callsub" | "retsub" | "err" | "return")
}

/// Mnemonics whose stack effect is dispatch- or arity-dependent in a way
/// this slice doesn't model (`txn`/`gtxn`/`gtxns` resolve to a different
/// real opcode -- with a different pop count -- depending on how many
/// immediates were written; see `asm_pseudo_txn`). Tracking these using the
/// wrong arity would desynchronize the tracked stack height from the real
/// one and risk a false type error on unrelated, legitimate code further
/// down the program, so this slice disables tracking *before* touching
/// them at all, rather than best-effort checking them like
/// [`disables_tracking`]'s set. The `*a`/`gtxnsa` real-opcode forms are
/// included too (not just the pseudo mnemonics that dispatch to them):
/// they pop a field-array index off the stack that go-algorand's own
/// `TestTxTypes` models as `uint64` (deferred here, see module docs), and
/// this repo's own array-index-immediate tests (e.g.
/// `test_txn_pseudo_arity_dispatches_to_array_opcode`) assemble them
/// standalone with no preceding push, purely to compare bytecode shape.
fn hard_disables_tracking(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "txn" | "gtxn" | "gtxns" | "txna" | "gtxna" | "gtxnsa"
    )
}

/// A side effect a refine function has on [`OpStream::scratch_space`]
/// (go's `pgm.scratchSpace[i] = ...` assignments inside `typeStore`/
/// `typeStores`, `assembler.go:1543-1576` -- unlike every other refine
/// function, these two mutate `ProgramKnowledge` rather than just
/// overriding the args/returns passed to `trackStack`).
#[derive(Debug, Clone, Copy)]
enum ScratchEffect {
    /// `store i` / `stores` with a known-constant index: set exactly one
    /// slot to the stored value's type (`typeStore`; `typeStores`'s
    /// `isConst` branch).
    Set(usize, StackType),
    /// `stores` with a non-constant index: mirrors `typeStores`'s fallback
    /// (`assembler.go:1570-1574`) -- since the actual written slot isn't
    /// known, every slot is conservatively widened to the union of its
    /// current type and the stored value's type, rather than picked
    /// arbitrarily or left untouched.
    UnionAll(StackType),
}

/// Refine functions for opcodes whose args and/or returns depend on the
/// types currently tracked on the stack rather than a fixed proto. Mirrors
/// go's `refineFunc`s (`assembler.go:1323-1484,1543-1619`). Returns `None`
/// when this mnemonic has no refine function; returns `Some((args_override,
/// returns_override, scratch_effect))` otherwise, where either of the first
/// two being `None` means "use the [`TYPE_TABLE`]/default proto for that
/// side" (matching go's `nargs`/`nreturns` being `nil`).
///
/// `consts` is [`OpStream::type_stack_const`] (parallel to `stack`): the
/// compile-time-constant value of each tracked entry, when known -- used by
/// `loads`/`stores` to resolve a dynamic scratch-slot index exactly when
/// it's a literal, mirroring go's `StackType.constInt()` (see
/// [`OpStream::type_stack_const`]'s doc comment for what this narrow slice
/// of go's real bound-tracking does and doesn't reproduce). `scratch` is
/// [`OpStream::scratch_space`], read (not mutated) here; the caller applies
/// any returned [`ScratchEffect`] afterward.
#[allow(clippy::type_complexity)]
fn refined_types(
    stack: &[StackType],
    consts: &[Option<u64>],
    scratch: &[StackType; 256],
    mnemonic: &str,
    args: &[&str],
) -> Option<(
    Option<Vec<StackType>>,
    Option<Vec<StackType>>,
    Option<ScratchEffect>,
)> {
    let len = stack.len();
    match mnemonic {
        // typeSwap (assembler.go:1323-1333): returns become whatever was on
        // top (order swapped); args stay the default `Any`/`Any`.
        "swap" => {
            let mut swapped = [Any, Any];
            if len >= 1 {
                swapped[0] = stack[len - 1];
                if len >= 2 {
                    swapped[1] = stack[len - 2];
                }
            }
            Some((None, Some(swapped.to_vec()), None))
        }
        // typeDup (assembler.go:1450-1456).
        "dup" => {
            let top = if len >= 1 { stack[len - 1] } else { Any };
            Some((None, Some(vec![top, top]), None))
        }
        // typeDupTwo (assembler.go:1458-1468): duplicates the top two.
        "dup2" => {
            let mut two = [Any, Any];
            if len >= 1 {
                two[1] = stack[len - 1];
                if len >= 2 {
                    two[0] = stack[len - 2];
                }
            }
            Some((None, Some(vec![two[0], two[1], two[0], two[1]]), None))
        }
        // typeSelect (assembler.go:1470-1476): result is the union of the
        // two non-selector operands.
        "select" => {
            let result = if len >= 3 {
                union(stack[len - 2], stack[len - 3])
            } else {
                Any
            };
            Some((None, Some(vec![result]), None))
        }
        // typeSetBit (assembler.go:1478-1484): result keeps the target's
        // (bottom arg's) type.
        "setbit" => {
            let result = if len >= 3 { stack[len - 3] } else { Any };
            Some((None, Some(vec![result]), None))
        }
        // typeEquals (assembler.go:1439-1448): both operands must be the
        // same avm type as whatever's on top; return type is the fixed
        // boolean from TYPE_TABLE.
        "==" | "!=" => {
            let top = if !stack.is_empty() {
                stack[len - 1]
            } else {
                Any
            };
            Some((Some(vec![top, top]), None, None))
        }
        // typeDig (assembler.go:1335-1350): pops/returns `n+1` items,
        // duplicating the one at depth `n`.
        "dig" => {
            let n: usize = args.first()?.parse().ok()?;
            let depth = n + 1;
            let mut returns = vec![Any; depth + 1];
            if len >= depth {
                let idx = len - depth;
                returns[..depth].copy_from_slice(&stack[idx..]);
                returns[depth] = stack[idx];
            }
            Some((Some(vec![Any; depth]), Some(returns), None))
        }
        // typeStore (assembler.go:1543-1553): a known slot index (`store`
        // always has a literal immediate, never a stack arg) gets set to
        // whatever type is currently on top of the tracked stack -- the
        // value `store` is about to pop. No args/returns override (the
        // fixed `Any` pop from [`TYPE_TABLE`] applies).
        "store" => {
            let idx = scratch_slot_immediate(args);
            let effect = match (idx, stack.last()) {
                (Some(i), Some(&top)) => Some(ScratchEffect::Set(i, top)),
                _ => None,
            };
            Some((None, None, effect))
        }
        // typeLoad (assembler.go:1578-1584): pushes the tracked type of the
        // known slot index instead of the default `Any`.
        "load" => {
            let ret = scratch_slot_immediate(args).map(|i| vec![scratch[i]]);
            Some((None, ret, None))
        }
        // typeStores (assembler.go:1555-1576): the index is a *dynamic*
        // stack value (second from top; the value being stored is on top --
        // proto `"ia:"`). When it's a compile-time constant (pushed by a
        // literal `int`, tracked via `consts`), exactly that slot is set;
        // otherwise every slot is conservatively unioned with the stored
        // value's type, since the real target slot isn't known statically.
        "stores" => {
            if len == 0 {
                return Some((None, None, None));
            }
            let value_ty = stack[len - 1];
            if len >= 2 {
                if let Some(i) = const_scratch_index(consts, len - 2) {
                    return Some((None, None, Some(ScratchEffect::Set(i, value_ty))));
                }
            }
            Some((None, None, Some(ScratchEffect::UnionAll(value_ty))))
        }
        // typeLoads (assembler.go:1601-1619): the index (top of stack) is
        // dynamic. When it's a compile-time constant, pushes exactly that
        // slot's type; otherwise, mirrors go's fallback of pushing a known
        // type only if *every* scratch slot currently shares one (still
        // useful after a plain `store` to every slot, or the all-`Uint64`/
        // all-`Any` initial/post-reset states), else falls back to the
        // default `Any`.
        "loads" => {
            if len == 0 {
                return Some((None, None, None));
            }
            if let Some(i) = const_scratch_index(consts, len - 1) {
                return Some((None, Some(vec![scratch[i]]), None));
            }
            let first = scratch[0];
            let uniform = scratch.iter().all(|&t| t == first);
            Some((None, uniform.then(|| vec![first]), None))
        }
        // typePopN (assembler.go:1621-1627): `popn n` pops exactly `n`
        // values, each accepting any type -- there's no return.
        "popn" => {
            let n: usize = args.first()?.parse().ok()?;
            Some((Some(vec![Any; n]), Some(vec![]), None))
        }
        // typeDupN (assembler.go:1629-1646): `dupn n` (base proto `"a:"`
        // already supplies the single fixed `Any` pop, so args isn't
        // overridden here) leaves `n+1` copies of the popped value on top --
        // typed as whatever's actually on top of the tracked stack (read
        // before the pop happens), or `Any` when that's unknown.
        "dupn" => {
            let n: usize = args.first()?.parse().ok()?;
            let top = if len >= 1 { stack[len - 1] } else { Any };
            Some((None, Some(vec![top; n + 1]), None))
        }
        // typeCover (assembler.go:1486-1506): `cover n` moves the top value
        // down `n` positions, i.e. rotates the top `depth = n+1` stack slots
        // (the top value plus the `n` items below it). Every value in that
        // range is accepted as `Any` on the way in (args is always the
        // opaque `anyTypes(depth)`); the pushed types mirror the actual
        // rotation, refined to the real tracked types whenever the full
        // `depth` is currently known (falling back to `Any` for any slot
        // that isn't).
        "cover" => {
            let n: usize = args.first()?.parse().ok()?;
            let depth = n + 1;
            let mut returns = vec![Any; depth];
            if len >= depth {
                let idx = len - depth;
                returns[0] = stack[len - 1];
                returns[1..depth].copy_from_slice(&stack[idx..len - 1]);
            }
            Some((Some(vec![Any; depth]), Some(returns), None))
        }
        // typeUncover (assembler.go:1508-1524): `uncover n` moves the value
        // `n` positions down the stack up to the top -- the same `depth =
        // n+1` window as `cover`, rotated the opposite way.
        "uncover" => {
            let n: usize = args.first()?.parse().ok()?;
            let depth = n + 1;
            let mut returns = vec![Any; depth];
            if len >= depth {
                let idx = len - depth;
                returns[depth - 1] = stack[idx];
                returns[..depth - 1].copy_from_slice(&stack[idx + 1..len]);
            }
            Some((Some(vec![Any; depth]), Some(returns), None))
        }
        _ => None,
    }
}

/// Parses `load`/`store`'s single immediate-slot-index argument, mirroring
/// go's `getImm(args, 0, false)` (`assembler.go:1289-...`) used by
/// `typeStore`/`typeLoad`: `None` for a missing or unparsable argument (the
/// rest of assembly reports its own diagnostic for that; nothing to refine
/// here), or an out-of-range index (there are only 256 scratch slots).
fn scratch_slot_immediate(args: &[&str]) -> Option<usize> {
    args.first()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&i| i < 256)
}

/// Reads `consts[pos]` (the compile-time-constant value of the tracked
/// stack entry at `pos`, if any -- see [`OpStream::type_stack_const`]) as a
/// scratch-slot index, mirroring go's `StackType.constInt()` calls in
/// `typeStores`/`typeLoads`. `None` when the entry isn't a known constant,
/// or the constant is out of the 256-slot range.
fn const_scratch_index(consts: &[Option<u64>], pos: usize) -> Option<usize> {
    consts
        .get(pos)
        .copied()
        .flatten()
        .map(|v| v as usize)
        .filter(|&i| i < 256)
}

/// Join an instruction's mnemonic with its immediate-argument tokens for
/// error messages, mirroring go's `reJoin` (`assembler.go:2045-2053`) --
/// e.g. `dig 2` rather than just `dig`.
fn rejoin(mnemonic: &str, args: &[&str]) -> String {
    if args.is_empty() {
        mnemonic.to_string()
    } else {
        format!("{mnemonic} {}", args.join(" "))
    }
}

/// Checks that the tracked type stack has `arg_types` on it (reporting a
/// type error if not), pops them, then pushes `return_types`. Mirrors go's
/// `OpStream.trackStack` (`assembler.go:2056-2096`), including its choice
/// to still push `return_types` even after an arg-count/type mismatch --
/// this avoids one reported mistake cascading into a wall of unrelated
/// height errors for the rest of the program.
///
/// When [`OpStream::type_track_bottom_permissive`] is set (analysis has
/// resumed after a label following dead code -- see the module docs), an
/// arg count exceeding the tracked stack's real height is *not* reported as
/// an error: go's `ProgramKnowledge.pop` returns `bottom` (`StackAny`) for
/// any position past the top of the real stack (`assembler.go:345-353`),
/// so missing entries are treated as an implicit, always-overlapping `Any`
/// rather than a height mismatch. This is what [`StackType::Any`]'s
/// `.unwrap_or(Any)` fallback below reproduces for each individual pop.
fn apply_stack_effect(
    ops: &mut OpStream,
    mnemonic: &str,
    args: &[&str],
    arg_types: &[StackType],
    return_types: &[StackType],
) {
    let argcount = arg_types.len();
    if argcount > ops.type_stack.len() && !ops.type_track_bottom_permissive {
        // Mirrors go's `typeErrorf` (`assembler.go:2039-2043`): a mismatch
        // is only *recorded* while `#pragma typetrack` reporting is on --
        // see `OpStream::type_track_reporting`'s doc comment. The
        // bookkeeping above/below (the height check itself, and the
        // pop/push loop) runs unconditionally either way.
        if ops.type_track_reporting {
            ops.record_error(
                ops.source_line,
                0,
                format!(
                    "{} expects {} stack arguments but stack height is {}",
                    rejoin(mnemonic, args),
                    argcount,
                    ops.type_stack.len(),
                ),
            );
        }
    } else {
        for i in (0..argcount).rev() {
            let want = arg_types[i];
            // Any position past the top of the real tracked stack is
            // treated as an implicit `Any` (see doc comment above) rather
            // than popped -- this only actually happens when
            // `type_track_bottom_permissive` let the height check above
            // through with too few real entries.
            let got = ops.type_stack.pop().unwrap_or(Any);
            // Keep `type_stack_const` in lockstep with `type_stack` (see its
            // doc comment) -- popping past the tracked stack's real height
            // (the `bottom_permissive` case above) is safe: `Vec::pop` on an
            // empty vec is a no-op `None`, same as `type_stack`'s.
            ops.type_stack_const.pop();
            if !got.overlaps(want) && ops.type_track_reporting {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!(
                        "{} arg {} wanted type {} got {}",
                        rejoin(mnemonic, args),
                        i,
                        want,
                        got,
                    ),
                );
            }
        }
    }

    if !return_types.is_empty() {
        ops.type_stack.extend_from_slice(return_types);
        // None of the pushed values are themselves known constants -- a
        // fresh literal is only ever tracked via the `literal_push_type`
        // path in `track_instruction`, not through a `trackStack` return.
        ops.type_stack_const
            .extend(std::iter::repeat(None).take(return_types.len()));
    }
}

/// Tracks one assembled instruction's effect on the static type stack,
/// reporting a type error on the same [`OpStream::errors`](crate::assembler::AssemblyError)
/// list as any other assembly error. No-op once
/// [`OpStream::type_track_disabled`] is set. See the module docs for scope.
pub(crate) fn track_instruction(ops: &mut OpStream, mnemonic: &str, args: &[&str]) {
    if ops.type_track_disabled {
        return;
    }

    // Mirrors go's `trackStack`'s `if ops.known.deadcode { return }`
    // (assembler.go:2058-2060): no type checks or stack-effect tracking
    // happen for an instruction reached only through dead code -- the
    // tracked stack stays exactly as [`deadens_tracking`] left it (empty)
    // until the next label reopens analysis. This deliberately skips
    // `hard_disables_tracking` too: an opcode this slice can't model
    // precisely (e.g. `txn`) appearing in unreachable code has no stack
    // effect to get wrong, so it must not spend the *permanent* disable on
    // dead code.
    if ops.type_track_deadcode {
        return;
    }

    if hard_disables_tracking(mnemonic) {
        ops.type_track_disabled = true;
        return;
    }

    if let Some(pushed) = literal_push_type(mnemonic) {
        // Mirrors go's `typePushInt` (`assembler.go:1666-1677`): an `int`
        // literal's compile-time value is tracked (base-10-parseable
        // only -- a named constant or non-decimal literal falls back to
        // `None`, same as go's `strconv.ParseUint` failure) so a later
        // `loads`/`stores` sitting right on top of it can resolve its
        // scratch-slot index exactly. `byte`/`addr`/`method` never carry a
        // usable scratch index, so they're never const-tracked.
        let konst = (mnemonic == "int")
            .then(|| args.first().and_then(|s| s.parse::<u64>().ok()))
            .flatten();
        ops.type_stack.push(pushed);
        ops.type_stack_const.push(konst);
        return;
    }

    let spec = match opcode::lookup_by_name(mnemonic) {
        // Not a real opcode (or a pseudo-op this slice doesn't model, e.g.
        // `extract`/`replace`'s own arity dispatch) -- the rest of assembly
        // will report its own error if this mnemonic is genuinely invalid;
        // nothing to track here either way.
        None => return,
        Some(s) => s,
    };

    let refine = refined_types(
        &ops.type_stack,
        &ops.type_stack_const,
        &ops.scratch_space,
        mnemonic,
        args,
    );
    let table = table_lookup(mnemonic);

    let arg_types = refine
        .as_ref()
        .and_then(|(a, _, _)| a.clone())
        .or_else(|| table.map(|(a, _)| a.to_vec()))
        .or_else(|| (spec.stack_pops >= 0).then(|| vec![Any; spec.stack_pops as usize]));
    let return_types = refine
        .as_ref()
        .and_then(|(_, r, _)| r.clone())
        .or_else(|| table.map(|(_, r)| r.to_vec()))
        .or_else(|| (spec.stack_pushes >= 0).then(|| vec![Any; spec.stack_pushes as usize]));

    let (arg_types, return_types) = match (arg_types, return_types) {
        (Some(a), Some(r)) => (a, r),
        // Dynamic pop/push count with no refine function and no explicit
        // table entry (e.g. `pushbytess`, `pushints`, `match`, or `popn`/
        // `dupn`/`cover`/`uncover` with an immediate that failed to parse --
        // which normally can't happen, since a bad immediate there is
        // already a separate assembly error on its own) -- this slice can't
        // keep the tracked stack height in sync, so stop rather than guess.
        _ => {
            ops.type_track_disabled = true;
            return;
        }
    };

    // Apply `store`/`stores`' scratch-space side effect (mirrors go setting
    // `pgm.scratchSpace[...]` directly inside `typeStore`/`typeStores`,
    // unconditionally and *before* `trackStack` pops/checks the args --
    // see `refined_types`' doc comment). Unlike the args/returns override,
    // this always takes effect regardless of any type mismatch reported by
    // `apply_stack_effect` below, matching go exactly.
    if let Some(effect) = refine.and_then(|(_, _, e)| e) {
        match effect {
            ScratchEffect::Set(i, ty) => ops.scratch_space[i] = ty,
            ScratchEffect::UnionAll(ty) => {
                for slot in ops.scratch_space.iter_mut() {
                    *slot = union(*slot, ty);
                }
            }
        }
    }

    apply_stack_effect(ops, mnemonic, args, &arg_types, &return_types);

    if deadens_tracking(mnemonic) {
        ops.type_stack.clear();
        ops.type_stack_const.clear();
        ops.type_track_deadcode = true;
        if mnemonic == "callsub" {
            // Mirrors go's assemble loop: `callsub` deadens (its own
            // `retsub` returns from an arbitrary caller, so nothing about
            // the stack past this point is known from *this* call site),
            // but is immediately followed by `ops.known.label()`
            // (assembler.go:2234-2237) rather than waiting for a textual
            // label -- `retsub` returns right after the `callsub`, making
            // it an entry point like any other label. `label()` resets
            // `scratchSpace` to all-`Any` too when called on deadcode
            // (`assembler.go:364-380`), which is always true here (`b`/
            // `callsub`/etc. above just set it) -- see
            // `OpStream::scratch_space`'s doc comment.
            ops.type_track_deadcode = false;
            ops.type_track_bottom_permissive = true;
            ops.scratch_space = [Any; 256];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlaps_matches_go_semantics() {
        assert!(Any.overlaps(Uint64));
        assert!(Uint64.overlaps(Any));
        assert!(Any.overlaps(Any));
        assert!(Uint64.overlaps(Uint64));
        assert!(Bytes.overlaps(Bytes));
        assert!(!Uint64.overlaps(Bytes));
        assert!(!Bytes.overlaps(Uint64));
    }

    #[test]
    fn union_matches_go_semantics() {
        assert_eq!(union(Uint64, Uint64), Uint64);
        assert_eq!(union(Bytes, Bytes), Bytes);
        assert_eq!(union(Uint64, Bytes), Any);
        assert_eq!(union(Any, Uint64), Any);
    }

    #[test]
    fn display_matches_go_avm_type_string() {
        assert_eq!(Uint64.to_string(), "uint64");
        assert_eq!(Bytes.to_string(), "[]byte");
        assert_eq!(Any.to_string(), "any");
    }
}
