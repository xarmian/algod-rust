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
//! `ProgramKnowledge` (the tracked `stack` of [`StackType`]s, plus its
//! `deadcode`/`bottom` fields -- see below), `trackStack` (arg/return
//! checking against the tracked stack), and the handful of `type*` "refine"
//! functions (`typeSwap`, `typeDup`, `typeDupTwo`, `typeSelect`,
//! `typeSetBit`, `typeDig`, `typeEquals`) whose return type depends on
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
//! On a type mismatch this reports the same diagnostic shape as
//! go-algorand's `typeErrorf` calls in `trackStack`: `"<instr> arg <i>
//! wanted type <want> got <got>"` or `"<instr> expects <n> stack arguments
//! but stack height is <h>"`.
//!
//! # What's deferred (tracked as follow-up work under issue #829)
//!
//! - **Scratch-slot type tracking** (`TestScratchTypeCheck`,
//!   `TestScratchBounds`): `load`/`loads`/`store`/`stores` are tracked only
//!   for their generic pop/push counts, not the per-slot type go tracks via
//!   `ProgramKnowledge.scratchSpace`. (`TestTypeTrackingRegression`
//!   happens to pass anyway: it only exercises `load`/`store` typing as
//!   `Any`, which this slice already produces generically, without needing
//!   go's `scratchSpace[i]`-specific type refinement.)
//! - **`#pragma typetrack false`/`true`** (part of `TestTypeTracking`):
//!   go supports manually toggling tracking off/on mid-program
//!   (`assembler.go:2513-2517`); this slice has no equivalent pragma at
//!   all, so it isn't modeled -- unrelated to (and safely orthogonal to)
//!   the deadcode/label handling above, since it's a distinct on/off
//!   switch rather than part of the label-driven state machine.
//! - **Dynamic- or arity-dependent stack effects** this slice still can't
//!   model precisely enough to keep the tracked stack height in sync with
//!   the real one -- unchanged from before: `match`/`txn`/`gtxn`/`gtxns`/
//!   `popn`/`dupn`/`cover`/`uncover`/`pushbytess`/`pushints` permanently
//!   disable tracking for the rest of the program (see
//!   [`hard_disables_tracking`] and the dynamic-arity fallback in
//!   [`track_instruction`]). This remains conservative by construction: it
//!   can only *lose* precision, never *fabricate* an error, so it cannot
//!   make a currently-valid program newly fail to assemble.
//! - **Bounds-refined types** (`TestMatchTyping`, `TestArgType`,
//!   `TestTypeComplaints`, sized-type diagnostics like `[32]byte`):
//!   go's `StackType` also carries a `[min, max]` length/value bound
//!   (`NewStackType`, `eval.go`); this slice's [`StackType`] is bound-free
//!   (`Uint64` / `Bytes` / `Any`), matching go's `overlaps` exactly for
//!   these opcodes (bounds only ever narrow the plain-`StackUint64`/
//!   `StackBytes` case, which is what every opcode here uses) but not
//!   reproducing go's `[N]byte`/`(<= N)`-style diagnostic text.
//! - `TestTxTypes`, `TestDupPopNTyping`: exercise the deferred
//!   dynamic-arity/`txn` behavior above.
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

/// Refine functions for opcodes whose args and/or returns depend on the
/// types currently tracked on the stack rather than a fixed proto. Mirrors
/// go's `refineFunc`s (`assembler.go:1323-1484`). Returns `None` when this
/// mnemonic has no refine function; returns `Some((args_override,
/// returns_override))` otherwise, where either side being `None` means
/// "use the [`TYPE_TABLE`]/default proto for that side" (matching go's
/// `nargs`/`nreturns` being `nil`).
#[allow(clippy::type_complexity)]
fn refined_types(
    stack: &[StackType],
    mnemonic: &str,
    args: &[&str],
) -> Option<(Option<Vec<StackType>>, Option<Vec<StackType>>)> {
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
            Some((None, Some(swapped.to_vec())))
        }
        // typeDup (assembler.go:1450-1456).
        "dup" => {
            let top = if len >= 1 { stack[len - 1] } else { Any };
            Some((None, Some(vec![top, top])))
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
            Some((None, Some(vec![two[0], two[1], two[0], two[1]])))
        }
        // typeSelect (assembler.go:1470-1476): result is the union of the
        // two non-selector operands.
        "select" => {
            let result = if len >= 3 {
                union(stack[len - 2], stack[len - 3])
            } else {
                Any
            };
            Some((None, Some(vec![result])))
        }
        // typeSetBit (assembler.go:1478-1484): result keeps the target's
        // (bottom arg's) type.
        "setbit" => {
            let result = if len >= 3 { stack[len - 3] } else { Any };
            Some((None, Some(vec![result])))
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
            Some((Some(vec![top, top]), None))
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
            Some((Some(vec![Any; depth]), Some(returns)))
        }
        _ => None,
    }
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
    } else {
        for i in (0..argcount).rev() {
            let want = arg_types[i];
            // Any position past the top of the real tracked stack is
            // treated as an implicit `Any` (see doc comment above) rather
            // than popped -- this only actually happens when
            // `type_track_bottom_permissive` let the height check above
            // through with too few real entries.
            let got = ops.type_stack.pop().unwrap_or(Any);
            if !got.overlaps(want) {
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
        ops.type_stack.push(pushed);
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

    let refine = refined_types(&ops.type_stack, mnemonic, args);
    let table = table_lookup(mnemonic);

    let arg_types = refine
        .as_ref()
        .and_then(|(a, _)| a.clone())
        .or_else(|| table.map(|(a, _)| a.to_vec()))
        .or_else(|| (spec.stack_pops >= 0).then(|| vec![Any; spec.stack_pops as usize]));
    let return_types = refine
        .as_ref()
        .and_then(|(_, r)| r.clone())
        .or_else(|| table.map(|(_, r)| r.to_vec()))
        .or_else(|| (spec.stack_pushes >= 0).then(|| vec![Any; spec.stack_pushes as usize]));

    let (arg_types, return_types) = match (arg_types, return_types) {
        (Some(a), Some(r)) => (a, r),
        // Dynamic pop/push count with no refine function and no explicit
        // table entry (e.g. `popn`, `dupn`, `cover`, `uncover`,
        // `pushbytess`, `pushints`, `match`) -- this slice can't keep the
        // tracked stack height in sync, so stop rather than guess.
        _ => {
            ops.type_track_disabled = true;
            return;
        }
    };

    apply_stack_effect(ops, mnemonic, args, &arg_types, &return_types);

    if deadens_tracking(mnemonic) {
        ops.type_stack.clear();
        ops.type_track_deadcode = true;
        if mnemonic == "callsub" {
            // Mirrors go's assemble loop: `callsub` deadens (its own
            // `retsub` returns from an arbitrary caller, so nothing about
            // the stack past this point is known from *this* call site),
            // but is immediately followed by `ops.known.label()`
            // (assembler.go:2234-2237) rather than waiting for a textual
            // label -- `retsub` returns right after the `callsub`, making
            // it an entry point like any other label.
            ops.type_track_deadcode = false;
            ops.type_track_bottom_permissive = true;
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
