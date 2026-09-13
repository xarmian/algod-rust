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

//! TEAL assembler: converts TEAL source text into AVM bytecode.
//!
//! Implements the assembly pipeline matching go-algorand's `AssembleString`:
//! - Tokenization of source lines
//! - Pragma version detection
//! - Label collection and resolution
//! - Pseudo-op handling (int, byte, addr, method)
//! - Constant block optimization (v4+)
//! - Field name resolution

use std::collections::HashMap;

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha512_256};

use crate::fields;
use crate::opcode::{self, ImmKind, Mode, MAX_AVM_VERSION};
use crate::type_track;

/// The first AVM version where constant optimization is enabled.
const OPTIMIZE_CONSTANTS_ENABLED_VERSION: u8 = 4;

/// Default assembler version when no `#pragma version` is specified.
const ASSEMBLER_DEFAULT_VERSION: u8 = 1;

/// AVM version where back-branches were introduced.
const BACK_BRANCH_ENABLED_VERSION: u8 = 4;

/// First AVM version at which stateless (non-app) programs are
/// automatically salted so their program hash cannot be a valid
/// Edwards25519 curve point (and thus cannot collide with a spendable
/// on-curve ed25519 address). Matches go-algorand's
/// `LogicSigOffCurveVersion` (`data/transactions/logic/opcodes.go`).
const LOGIC_SIG_OFF_CURVE_VERSION: u8 = 13;

/// Number of salt candidates tried by the auto-salt search — chosen so the
/// salt value always fits a single-byte varint. Matches go-algorand's
/// `assemblerSaltSearchLimit` (`assembler.go`).
const ASSEMBLER_SALT_SEARCH_LIMIT: u64 = 128;

/// Domain-separation prefix used when hashing program bytes into a LogicSig
/// address. Matches go-algorand's `protocol.Program` `HashID`.
const PROGRAM_HASH_PREFIX: &[u8] = b"Program";

/// State of the `#pragma autosalt` directive for the program being
/// assembled. Mirrors go-algorand's `autoSaltMode` (`assembler.go`):
/// `Unset` applies the version-gated default
/// ([`default_auto_salt_applies`]), while `On`/`Off` come from an explicit
/// `#pragma autosalt true|false` and override that default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutoSaltMode {
    Unset,
    On,
    Off,
}

/// Reports whether `program`'s hash decodes as a valid Edwards25519 curve
/// point. If it does, those bytes could also be a valid ed25519 public key,
/// so a LogicSig using this program as a contract-account address could in
/// principle collide with a spendable on-curve address. Matches
/// go-algorand's `ProgramHashIsEdwards25519Point` (`program.go`), which
/// hashes `"Program" || program` (SHA-512/256) and decodes it the same way
/// `filippo.io/edwards25519`'s `Point.SetBytes` does — accepting some
/// non-canonical point encodings and not checking prime-order-subgroup
/// membership. `curve25519-dalek`'s `CompressedEdwardsY::decompress` follows
/// the same reference algorithm, so it matches that acceptance behavior.
pub(crate) fn program_hash_is_edwards25519_point(program: &[u8]) -> bool {
    let mut hasher = Sha512_256::new();
    hasher.update(PROGRAM_HASH_PREFIX);
    hasher.update(program);
    let hash: [u8; 32] = hasher.finalize().into();
    CompressedEdwardsY(hash).decompress().is_some()
}

/// Reports whether the version-gated auto-salt default applies: `program`
/// is assembled at `LOGIC_SIG_OFF_CURVE_VERSION` or later, contains no
/// application-only opcodes, and its hash is currently on-curve. Matches
/// go-algorand's `defaultAutoSaltApplies` (`assembler.go`); also used by the
/// disassembler to decide whether to emit `#pragma autosalt false` so a
/// round-tripped legacy/pre-salted program doesn't get re-salted (which
/// would change its hash) on reassembly.
pub(crate) fn default_auto_salt_applies(
    version: u8,
    has_stateful_ops: bool,
    program: &[u8],
) -> bool {
    version >= LOGIC_SIG_OFF_CURVE_VERSION
        && !has_stateful_ops
        && program_hash_is_edwards25519_point(program)
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// An error produced during assembly, with source location information.
#[derive(Debug, Clone)]
pub struct AssemblyError {
    pub line: usize,
    pub col: usize,
    pub message: String,
}

impl std::fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for AssemblyError {}

/// A non-fatal warning produced during assembly, with source location
/// information. Unlike [`AssemblyError`], one or more warnings never stop
/// assembly from succeeding. Matches go-algorand's `sourceError` as used for
/// `OpStream.Warnings` (`assembler.go`).
#[derive(Debug, Clone)]
pub struct AssemblyWarning {
    pub line: usize,
    pub col: usize,
    pub message: String,
}

impl std::fmt::Display for AssemblyWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.col, self.message)
    }
}

impl std::error::Error for AssemblyWarning {}

// ---------------------------------------------------------------------------
// Source location
// ---------------------------------------------------------------------------

/// A position in source code (0-based line and column).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceLocation {
    pub line: usize,
    pub col: usize,
}

// ---------------------------------------------------------------------------
// Internal reference types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LabelReference {
    /// Position within `pending` where the offset should be written.
    position: usize,
    /// The label name.
    label: String,
    /// Line number for error reporting.
    line: usize,
    /// End of the full instruction containing this label ref (for offset computation).
    offset_position: usize,
    /// `true` for a varint-encoded branch (`bnz`/`bz`/`b`/`callsub` at
    /// LogicSigVersion >= `opcode::VARINT_BRANCH_VERSION`); `false` for the
    /// legacy fixed 2-byte encoding (also used by `switch`/`match`, which
    /// are never varint-encoded at any version). Mirrors go-algorand's
    /// `labelReference.varint` (`assembler.go`).
    varint: bool,
}

#[derive(Debug, Clone)]
struct IntReference {
    value: u64,
    /// Position within `pending` of the opcode that was emitted for this reference.
    position: usize,
}

#[derive(Debug, Clone)]
struct ByteReference {
    value: Vec<u8>,
    /// Position within `pending` of the opcode that was emitted for this reference.
    position: usize,
}

/// A `#define NAME substitution` macro definition (go's `ops.macros[name]`,
/// `assembler.go:277`). `body` is the raw, unexpanded token list following
/// the name -- it may itself reference other macros (expanded lazily at
/// each *use* site, not at definition time -- see `next_statement`) and may
/// contain a literal `;`, letting one macro usage expand into multiple
/// statements (`#define -> ; store` in go's `TestMacros`). `line` is the
/// `#define` directive's own source line, used to attribute a
/// [`recheck_macro_names`] failure to where the macro was *defined* rather
/// than to whatever later line caused the recheck (mirrors go's
/// `ops.macros[macroName][0]` token, which carries its own line).
#[derive(Debug, Clone)]
struct MacroDef {
    line: usize,
    body: Vec<String>,
}

// ---------------------------------------------------------------------------
// OpStream — main assembler state
// ---------------------------------------------------------------------------

/// The main assembler state, accumulating bytecode during assembly.
pub struct OpStream {
    /// Final assembled program bytes (set after successful assembly).
    pub program: Vec<u8>,
    /// AVM version for the program.
    pub version: u8,
    /// Errors accumulated during assembly.
    pub errors: Vec<AssemblyError>,
    /// Non-fatal warnings accumulated during assembly. Assembly can still
    /// succeed (`Ok`) with warnings present.
    pub warnings: Vec<AssemblyWarning>,
    /// PC-to-source-line mapping.
    pub offset_to_source: HashMap<usize, SourceLocation>,

    // Internal state
    pending: Vec<u8>,
    labels: HashMap<String, usize>,
    label_references: Vec<LabelReference>,

    /// Currently defined `#define` macros, keyed by name. Mirrors go's
    /// `ops.macros` (`assembler.go:277`). Consulted by `next_statement`
    /// (go's `nextStatement`) to expand macro-name tokens in place before
    /// each statement is assembled.
    macros: HashMap<String, MacroDef>,

    intc: Vec<u64>,
    intc_refs: Vec<IntReference>,
    cnt_intc_block: usize,
    has_pseudo_int: bool,

    bytec: Vec<Vec<u8>>,
    bytec_refs: Vec<ByteReference>,
    cnt_bytec_block: usize,
    has_pseudo_byte: bool,

    pub(crate) source_line: usize,

    /// Set once any assembled opcode is `Mode::Application`-only. Mirrors
    /// go-algorand's `OpStream.HasStatefulOps`; gates auto-salt (which only
    /// ever applies to stateless/LogicSig programs).
    has_stateful_ops: bool,
    /// State of the `#pragma autosalt` directive (defaults to the
    /// version-gated behavior until overridden).
    auto_salt: AutoSaltMode,
    /// Source line of the `#pragma autosalt` directive that set
    /// [`Self::auto_salt`], if any. Used to attribute `shouldAutoSalt`'s
    /// warnings to the pragma line, matching go-algorand's
    /// `OpStream.autoSaltToken`.
    auto_salt_line: usize,

    /// Static stack-type-tracking state (issue #829). Mirrors a slice of
    /// go-algorand's `ProgramKnowledge.stack` -- the types statically known
    /// to be on the value stack at the current point in a straight-line
    /// instruction sequence. See the `type_track` module docs for exactly
    /// what this incremental pass covers.
    pub(crate) type_stack: Vec<type_track::StackType>,
    /// Parallel to [`Self::type_stack`] (always the same length): the
    /// compile-time-constant `u64` value of the corresponding tracked stack
    /// entry, when known. Mirrors the narrow slice of go-algorand's
    /// `StackType.Bound`/`constInt()` (`eval.go:944-1024`) this pass needs --
    /// just enough to recognize a literal `int N` value sitting under
    /// `loads`/`stores` so their scratch-slot index can be resolved exactly
    /// (`typeLoads`/`typeStores`, `assembler.go:1555-1619`), not go's full
    /// `[min,max]` bound propagation through arithmetic (that remains
    /// deferred -- see the `type_track` module docs' "Bounds-refined types"
    /// section). `Some(v)` only for a value just pushed by a literal `int v`
    /// (base-10-parseable, mirroring `typePushInt`'s
    /// `strconv.ParseUint(..., 10, 64)`); `None` for everything else,
    /// including every opcode's *result* (this pass never re-derives a
    /// constant from an operation, only from the literal push itself).
    pub(crate) type_stack_const: Vec<Option<u64>>,
    /// The statically known type of each of the 256 scratch slots. Mirrors
    /// go-algorand's `ProgramKnowledge.scratchSpace` (`assembler.go:334`).
    /// Starts as [`type_track::StackType::Uint64`] for every slot (mirrors
    /// `newOpStream`'s `o.known.scratchSpace[i] = StackZeroUint64`,
    /// `assembler.go:300-302` -- an untouched scratch slot reads as the
    /// zero-valued uint64 at runtime) and is reset to
    /// [`type_track::StackType::Any`] for every slot -- never back to
    /// `Uint64` -- at the same points [`Self::type_track_bottom_permissive`]
    /// is set (mirrors `ProgramKnowledge.reset`, `assembler.go:371-380`,
    /// called from `label()`/the `callsub` reopening -- see
    /// [`type_track::track_instruction`] and the label-handling code in
    /// [`assemble_string`]).
    pub(crate) scratch_space: [type_track::StackType; 256],
    /// Once set, `type_track::track_instruction` stops tracking (and
    /// stops reporting type errors) for the rest of the program. Set on
    /// any opcode this slice doesn't model precisely enough to keep the
    /// tracked stack height in sync with the real one (e.g. `txn`'s
    /// arity-dependent dispatch, `match`'s dynamic label count). Unlike
    /// [`Self::type_track_deadcode`], this never turns back off.
    pub(crate) type_track_disabled: bool,
    /// Mirrors go-algorand's `ProgramKnowledge.deadcode`
    /// (`assembler.go:323-325`): set after an opcode that unconditionally
    /// ends or diverts control flow (`b`, `retsub`, `err`, `return`, or
    /// `callsub` before it immediately reopens analysis -- see
    /// [`type_track::track_instruction`]). While set, `track_instruction`
    /// skips all type checking and stack-effect tracking (the tracked
    /// stack is left empty), matching go's `trackStack`'s
    /// `if ops.known.deadcode { return }`. Cleared -- along with setting
    /// [`Self::type_track_bottom_permissive`] -- the next time a label is
    /// reached, mirroring `ProgramKnowledge.label`/`reset`.
    pub(crate) type_track_deadcode: bool,
    /// Mirrors go-algorand's `ProgramKnowledge.bottom` becoming `StackAny`
    /// after a `reset()` (`assembler.go:314-321,371-380`): once set, a
    /// stack-height/arg-count check that would otherwise fail because the
    /// tracked stack doesn't (yet) have enough real entries is treated as
    /// satisfied by an implicit, unlimited supply of
    /// [`type_track::StackType::Any`] underneath it, instead of being
    /// reported as a "wrong number of stack arguments" error. This is what
    /// lets analysis safely resume after a label or `callsub` without
    /// knowing what the incoming stack actually looked like. Never cleared
    /// once set (matches go: `bottom` only ever moves from `StackNone` to
    /// `StackAny`, never back).
    pub(crate) type_track_bottom_permissive: bool,
    /// Whether a type mismatch found by [`type_track::track_instruction`]
    /// is actually *reported* as an assembly error. Mirrors go-algorand's
    /// `OpStream.typeTracking` (`assembler.go:256,294`, default `true`),
    /// toggled by `#pragma typetrack true|false`. Unlike
    /// [`Self::type_track_disabled`], this does **not** stop the pass from
    /// running -- the tracked stack (and scratch-space state) keeps
    /// evolving underneath even while reporting is off, exactly like go's
    /// `trackStack` unconditionally popping/pushing `ops.known.stack`
    /// (`assembler.go:2056-2096`) and only `typeErrorf`
    /// (`assembler.go:2039-2043`) checking this flag before recording
    /// anything. See the `#pragma typetrack` handling in
    /// [`assemble_string`] for the off-to-on reset behavior.
    pub(crate) type_track_reporting: bool,
}

impl OpStream {
    fn new() -> Self {
        Self {
            program: Vec::new(),
            version: 0, // will be set by pragma or default
            errors: Vec::new(),
            warnings: Vec::new(),
            offset_to_source: HashMap::new(),
            pending: Vec::new(),
            labels: HashMap::new(),
            label_references: Vec::new(),
            macros: HashMap::new(),
            intc: Vec::new(),
            intc_refs: Vec::new(),
            cnt_intc_block: 0,
            has_pseudo_int: false,
            bytec: Vec::new(),
            bytec_refs: Vec::new(),
            cnt_bytec_block: 0,
            has_pseudo_byte: false,
            source_line: 0,
            has_stateful_ops: false,
            auto_salt: AutoSaltMode::Unset,
            auto_salt_line: 0,
            type_stack: Vec::new(),
            type_stack_const: Vec::new(),
            scratch_space: [type_track::StackType::Uint64; 256],
            type_track_disabled: false,
            type_track_deadcode: false,
            type_track_bottom_permissive: false,
            type_track_reporting: true,
        }
    }

    pub(crate) fn record_error(&mut self, line: usize, col: usize, msg: String) {
        self.errors.push(AssemblyError {
            line,
            col,
            message: msg,
        });
    }

    fn record_warning(&mut self, line: usize, col: usize, msg: String) {
        self.warnings.push(AssemblyWarning {
            line,
            col,
            message: msg,
        });
    }

    fn record_source_location(&mut self, line: usize, col: usize) {
        // Go uses 0-based lines in OffsetToSource (line - 1).
        self.offset_to_source.insert(
            self.pending.len(),
            SourceLocation {
                line: line.saturating_sub(1),
                col,
            },
        );
    }

    // ---------- int literal handling ----------

    fn write_intc(&mut self, const_index: usize) {
        match const_index {
            0 => self.pending.push(0x22), // intc_0
            1 => self.pending.push(0x23), // intc_1
            2 => self.pending.push(0x24), // intc_2
            3 => self.pending.push(0x25), // intc_3
            i if i <= 255 => {
                self.pending.push(0x21); // intc
                self.pending.push(i as u8);
            }
            _ => {
                self.record_error(
                    self.source_line,
                    0,
                    "cannot have more than 256 int constants".into(),
                );
            }
        }
    }

    fn int_literal(&mut self, val: u64) {
        self.has_pseudo_int = true;

        let const_index = if let Some(idx) = self.intc.iter().position(|&v| v == val) {
            idx
        } else {
            if self.cnt_intc_block > 0 {
                self.record_error(
                    self.source_line,
                    0,
                    format!("value {val} does not appear in existing intcblock"),
                );
                return;
            }
            let idx = self.intc.len();
            self.intc.push(val);
            idx
        };

        self.intc_refs.push(IntReference {
            value: val,
            position: self.pending.len(),
        });
        self.write_intc(const_index);
    }

    // ---------- byte literal handling ----------

    fn write_bytec(&mut self, const_index: usize) {
        match const_index {
            0 => self.pending.push(0x28), // bytec_0
            1 => self.pending.push(0x29), // bytec_1
            2 => self.pending.push(0x2a), // bytec_2
            3 => self.pending.push(0x2b), // bytec_3
            i if i <= 255 => {
                self.pending.push(0x27); // bytec
                self.pending.push(i as u8);
            }
            _ => {
                self.record_error(
                    self.source_line,
                    0,
                    "cannot have more than 256 byte constants".into(),
                );
            }
        }
    }

    fn byte_literal(&mut self, val: Vec<u8>) {
        self.has_pseudo_byte = true;

        let const_index = if let Some(idx) = self
            .bytec
            .iter()
            .position(|v| v.as_slice() == val.as_slice())
        {
            idx
        } else {
            if self.cnt_bytec_block > 0 {
                self.record_error(
                    self.source_line,
                    0,
                    format!(
                        "value 0x{} does not appear in existing bytecblock",
                        hex::encode(&val)
                    ),
                );
                return;
            }
            let idx = self.bytec.len();
            self.bytec.push(val.clone());
            idx
        };

        self.bytec_refs.push(ByteReference {
            value: val,
            position: self.pending.len(),
        });
        self.write_bytec(const_index);
    }

    // ---------- label resolution ----------

    /// Shrink varint-encoded branch placeholders to their minimum needed
    /// size, via the same fixed-point iteration as go-algorand's
    /// `findBranchSizes`: shrinking one branch changes the byte distance
    /// (and therefore the encoded width) of any other branch whose jump
    /// spans it, so this repeats until no further branch can shrink.
    /// Distances only ever shrink (never grow) as bytes are removed, so
    /// this always terminates. Offset bytes stay zero-filled throughout --
    /// `resolve_labels` writes the actual encoded values afterward, once
    /// every placeholder's final width is stable.
    fn find_branch_sizes(&mut self) {
        loop {
            let mut edits: Vec<(usize, usize, usize)> = Vec::new(); // (position, old_len, needed_len)
            for lr in &self.label_references {
                if !lr.varint {
                    continue; // switch/match references stay fixed 2-byte
                }
                let dest = match self.labels.get(&lr.label) {
                    Some(&d) => d,
                    None => continue, // undefined labels are reported by resolve_labels
                };
                let opcode_pos = lr.position - 1;
                if dest == opcode_pos {
                    continue; // will be rejected by resolve_labels
                }
                let jump: i64 = if dest < opcode_pos {
                    // Back-jump from instruction start: no instr-size dependency.
                    dest as i64 - opcode_pos as i64
                } else {
                    dest as i64 - lr.offset_position as i64
                };
                let needed = zigzag_varint_len(jump);
                let old_len = lr.offset_position - lr.position;
                if needed < old_len {
                    edits.push((lr.position, old_len, needed));
                }
            }
            if edits.is_empty() {
                break;
            }
            // Apply from the highest position down, so each edit's own
            // (still-unprocessed) lower-numbered siblings keep their
            // originally-collected positions valid.
            edits.sort_by_key(|e| e.0);
            for &(position, old_len, needed) in edits.iter().rev() {
                let delta = needed as isize - old_len as isize;
                replace_bytes(&mut self.pending, position, old_len, &vec![0u8; needed]);
                // NOTE: deliberately *not* `adjust_positions_after` (which
                // shifts a tracked position only when it is strictly greater
                // than the edit's own start). That boundary is wrong here:
                // a varint branch's own `offset_position` sits exactly at
                // `position + old_len` (the end of its own placeholder), as
                // does any label defined immediately after the branch (a
                // very common case -- see e.g. `b end\nend:\n...`). Both
                // must shift once this edit shrinks the placeholder, so the
                // boundary has to be the *end* of the edited region.
                self.shift_positions_at_or_after(position + old_len, delta);
            }
        }
    }

    /// Shift every tracked byte position that is `>= boundary` by `delta`,
    /// leaving positions `< boundary` untouched. Used by `find_branch_sizes`
    /// after replacing `[position, position+old_len)` with a shorter
    /// zero-filled placeholder (`boundary = position + old_len`, i.e. the
    /// end of the edited region) -- matches go-algorand's `applyEdits`
    /// `cumDelta` semantics for a single edit. This differs from
    /// `adjust_positions_after` (used by constant optimization), whose
    /// simpler `position`-only boundary is correct only when no tracked
    /// position ever sits exactly at the end of the edited region; a varint
    /// branch's own `offset_position` (and any label right after it)
    /// routinely does.
    fn shift_positions_at_or_after(&mut self, boundary: usize, delta: isize) {
        for r in &mut self.intc_refs {
            if r.position >= boundary {
                r.position = (r.position as isize + delta) as usize;
            }
        }
        for r in &mut self.bytec_refs {
            if r.position >= boundary {
                r.position = (r.position as isize + delta) as usize;
            }
        }
        for pos in self.labels.values_mut() {
            if *pos >= boundary {
                *pos = (*pos as isize + delta) as usize;
            }
        }
        for lr in &mut self.label_references {
            if lr.position >= boundary {
                lr.position = (lr.position as isize + delta) as usize;
            }
            if lr.offset_position >= boundary {
                lr.offset_position = (lr.offset_position as isize + delta) as usize;
            }
        }
        let mut new_map = HashMap::new();
        for (&pos, &loc) in &self.offset_to_source {
            if pos >= boundary {
                new_map.insert((pos as isize + delta) as usize, loc);
            } else {
                new_map.insert(pos, loc);
            }
        }
        self.offset_to_source = new_map;
    }

    fn resolve_labels(&mut self) {
        let raw = &mut self.pending;
        let mut reported: std::collections::HashSet<String> = std::collections::HashSet::new();

        for lr in &self.label_references {
            let dest = match self.labels.get(&lr.label) {
                Some(&d) => d,
                None => {
                    if !reported.contains(&lr.label) {
                        self.errors.push(AssemblyError {
                            line: lr.line,
                            col: 0,
                            message: format!("reference to undefined label {:?}", lr.label),
                        });
                        reported.insert(lr.label.clone());
                    }
                    continue;
                }
            };

            if self.version < BACK_BRANCH_ENABLED_VERSION && dest < lr.offset_position {
                self.errors.push(AssemblyError {
                    line: lr.line,
                    col: 0,
                    message: format!(
                        "label {:?} is a back reference, back jump support was introduced in v4",
                        lr.label,
                    ),
                });
                continue;
            }

            // Backward compatibility: v0/v1 do not allow a branch to land
            // exactly past the last instruction (i.e. at the very end of
            // the program). v2 lifted this restriction, matching go's
            // `resolveLabels` (`assembler.go:2668-2672`): `if ops.Version <=
            // 1 { if dest == ops.pending.Len() { ... "is too far away" } }`.
            if self.version <= 1 && dest == raw.len() {
                self.errors.push(AssemblyError {
                    line: lr.line,
                    col: 0,
                    message: format!("label {:?} is too far away", lr.label),
                });
                continue;
            }

            if lr.varint {
                let opcode_pos = lr.position - 1;
                if dest == opcode_pos {
                    // Jumping to the start of the same instruction would be
                    // ambiguous under the sign-based back/forward dispatch
                    // (a zero offset means "forward"), so it is disallowed
                    // at assembly time -- matches go-algorand's resolveLabels.
                    self.errors.push(AssemblyError {
                        line: lr.line,
                        col: 0,
                        message: format!("branch to start of same instruction: {:?} ", lr.label),
                    });
                    continue;
                }
                // Back-jumps use the start of the instruction as the
                // reference point, which avoids any dependency on this
                // instruction's own (possibly still-shrinking) size.
                let jump: i64 = if dest < opcode_pos {
                    dest as i64 - opcode_pos as i64
                } else {
                    dest as i64 - lr.offset_position as i64
                };

                let placeholder_size = lr.offset_position - lr.position;
                let limit: i64 = 1i64 << (7 * placeholder_size - 1);
                if jump < -limit || jump >= limit {
                    self.errors.push(AssemblyError {
                        line: lr.line,
                        col: 0,
                        message: format!("label {:?} is too far away", lr.label),
                    });
                    continue;
                }

                let encoded = zigzag_varint_encode(jump);
                if encoded.len() != placeholder_size {
                    // find_branch_sizes guarantees the placeholder has
                    // already shrunk to exactly this jump's minimal width;
                    // a mismatch here would be an assembler bug, not a
                    // program error, but avoid panicking on the (untrusted
                    // by construction, but let's not trust ourselves either)
                    // program text either way.
                    self.errors.push(AssemblyError {
                        line: lr.line,
                        col: 0,
                        message: format!(
                            "internal error: branch varint size mismatch for label {:?}",
                            lr.label
                        ),
                    });
                    continue;
                }
                raw[lr.position..lr.position + encoded.len()].copy_from_slice(&encoded);
                continue;
            }

            let jump = dest as isize - lr.offset_position as isize;
            if !(-0x8000..=0x7fff).contains(&jump) {
                self.errors.push(AssemblyError {
                    line: lr.line,
                    col: 0,
                    message: format!("label {:?} is too far away", lr.label),
                });
                continue;
            }

            let jump = jump as i16;
            let bytes = jump.to_be_bytes();
            raw[lr.position] = bytes[0];
            raw[lr.position + 1] = bytes[1];
        }
    }

    // ---------- constant optimization (v4+) ----------

    fn optimize_int_constants(&mut self) {
        if self.intc_refs.is_empty() {
            return;
        }

        // Count frequency of each constant value
        struct ConstFreq {
            value: u64,
            freq: usize,
            first_seen: usize,
        }

        let mut freqs: Vec<ConstFreq> = self
            .intc
            .iter()
            .enumerate()
            .map(|(i, &v)| ConstFreq {
                value: v,
                freq: 0,
                first_seen: i,
            })
            .collect();

        for r in &self.intc_refs {
            for f in &mut freqs {
                if f.value == r.value {
                    f.freq += 1;
                    break;
                }
            }
        }

        // Sort by descending frequency (stable — preserves first-seen order for ties)
        freqs.sort_by(|a, b| b.freq.cmp(&a.freq).then(a.first_seen.cmp(&b.first_seen)));

        // Process refs from last to first position to avoid invalidating earlier positions
        let mut sorted_refs = self.intc_refs.clone();
        sorted_refs.sort_by_key(|r| std::cmp::Reverse(r.position));

        for r in &sorted_refs {
            let (new_index, singleton) = freqs
                .iter()
                .enumerate()
                .find(|(_, f)| f.value == r.value)
                .map(|(i, f)| (i, f.freq == 1))
                .unwrap();

            // Determine current instruction length
            let current_op = self.pending[r.position];
            let current_len = match current_op {
                0x22..=0x25 => 1, // intc_0..3
                0x21 => 2,        // intc N
                _ => 1,           // shouldn't happen
            };

            // Build new instruction bytes
            let new_bytes = if singleton {
                // Use pushint for singletons
                let mut buf = vec![0x81u8]; // pushint opcode
                write_varuint_to_vec(&mut buf, r.value);
                buf
            } else {
                match new_index {
                    0 => vec![0x22],          // intc_0
                    1 => vec![0x23],          // intc_1
                    2 => vec![0x24],          // intc_2
                    3 => vec![0x25],          // intc_3
                    n => vec![0x21, n as u8], // intc N
                }
            };

            let position_delta = new_bytes.len() as isize - current_len as isize;

            // Replace bytes
            replace_bytes(&mut self.pending, r.position, current_len, &new_bytes);

            if position_delta == 0 {
                continue;
            }

            // Update all positions that come after this replacement
            self.adjust_positions_after(r.position, position_delta);
        }

        // Build the optimized constant block (only non-singletons)
        let optimized: Vec<u64> = freqs
            .iter()
            .filter(|f| f.freq > 1)
            .map(|f| f.value)
            .collect();
        self.intc = optimized;
    }

    fn optimize_byte_constants(&mut self) {
        if self.bytec_refs.is_empty() {
            return;
        }

        struct ConstFreq {
            value: Vec<u8>,
            freq: usize,
            first_seen: usize,
        }

        let mut freqs: Vec<ConstFreq> = self
            .bytec
            .iter()
            .enumerate()
            .map(|(i, v)| ConstFreq {
                value: v.clone(),
                freq: 0,
                first_seen: i,
            })
            .collect();

        for r in &self.bytec_refs {
            for f in &mut freqs {
                if f.value == r.value {
                    f.freq += 1;
                    break;
                }
            }
        }

        freqs.sort_by(|a, b| b.freq.cmp(&a.freq).then(a.first_seen.cmp(&b.first_seen)));

        let mut sorted_refs = self.bytec_refs.clone();
        sorted_refs.sort_by_key(|r| std::cmp::Reverse(r.position));

        for r in &sorted_refs {
            let (new_index, singleton) = freqs
                .iter()
                .enumerate()
                .find(|(_, f)| f.value == r.value)
                .map(|(i, f)| (i, f.freq == 1))
                .unwrap();

            let current_op = self.pending[r.position];
            let current_len = match current_op {
                0x28..=0x2b => 1, // bytec_0..3
                0x27 => 2,        // bytec N
                _ => 1,
            };

            let new_bytes = if singleton {
                let mut buf = vec![0x80u8]; // pushbytes opcode
                write_varuint_to_vec(&mut buf, r.value.len() as u64);
                buf.extend_from_slice(&r.value);
                buf
            } else {
                match new_index {
                    0 => vec![0x28],
                    1 => vec![0x29],
                    2 => vec![0x2a],
                    3 => vec![0x2b],
                    n => vec![0x27, n as u8],
                }
            };

            let position_delta = new_bytes.len() as isize - current_len as isize;
            replace_bytes(&mut self.pending, r.position, current_len, &new_bytes);

            if position_delta == 0 {
                continue;
            }

            self.adjust_positions_after(r.position, position_delta);
        }

        let optimized: Vec<Vec<u8>> = freqs
            .iter()
            .filter(|f| f.freq > 1)
            .map(|f| f.value.clone())
            .collect();
        self.bytec = optimized;
    }

    fn adjust_positions_after(&mut self, position: usize, delta: isize) {
        for r in &mut self.intc_refs {
            if r.position > position {
                r.position = (r.position as isize + delta) as usize;
            }
        }
        for r in &mut self.bytec_refs {
            if r.position > position {
                r.position = (r.position as isize + delta) as usize;
            }
        }
        for pos in self.labels.values_mut() {
            if *pos > position {
                *pos = (*pos as isize + delta) as usize;
            }
        }
        for lr in &mut self.label_references {
            if lr.position > position {
                lr.position = (lr.position as isize + delta) as usize;
                lr.offset_position = (lr.offset_position as isize + delta) as usize;
            }
        }
        let mut new_map = HashMap::new();
        for (&pos, &loc) in &self.offset_to_source {
            if pos > position {
                new_map.insert((pos as isize + delta) as usize, loc);
            } else {
                new_map.insert(pos, loc);
            }
        }
        self.offset_to_source = new_map;
    }

    // ---------- prepend constant blocks ----------

    /// Builds the completed program: version byte, then any automatic
    /// intcblock/bytecblock, then the pending instruction bytes. Returns the
    /// program bytes and the prefix length (version byte + cblocks).
    ///
    /// Pure (does not mutate `self`) so the auto-salt search
    /// ([`Self::finalize_with_auto_intc_salt`]) can call it repeatedly
    /// against different trial `intc` values without side effects; the
    /// offset-to-source fixup that go-algorand's `prependCBlocks` callers
    /// apply once, after the final prefix length is known, lives in
    /// [`Self::adjust_offset_to_source`]. Matches go-algorand's
    /// `prependCBlocks` (`assembler.go`).
    fn prepend_cblocks(&self) -> (Vec<u8>, usize) {
        let mut pre = Vec::new();
        // Version byte
        pre.push(self.version);

        if !self.intc.is_empty() && self.cnt_intc_block == 0 {
            pre.push(0x20); // intcblock opcode
            write_varuint_to_vec(&mut pre, self.intc.len() as u64);
            for &iv in &self.intc {
                write_varuint_to_vec(&mut pre, iv);
            }
        }
        if !self.bytec.is_empty() && self.cnt_bytec_block == 0 {
            pre.push(0x26); // bytecblock opcode
            write_varuint_to_vec(&mut pre, self.bytec.len() as u64);
            for bv in &self.bytec {
                write_varuint_to_vec(&mut pre, bv.len() as u64);
                pre.extend_from_slice(bv);
            }
        }

        let pbl = pre.len();
        let mut out = pre;
        out.extend_from_slice(&self.pending);
        (out, pbl)
    }

    /// Shifts every recorded source-location offset by `prefix_len` (the
    /// version byte plus any cblocks prepended by [`Self::finalize_program`]).
    /// Matches go-algorand's `adjustOffsetToSource` (`assembler.go`).
    fn adjust_offset_to_source(&mut self, prefix_len: usize) {
        let mut new_map = HashMap::with_capacity(self.offset_to_source.len());
        for (&pos, &loc) in &self.offset_to_source {
            new_map.insert(pos + prefix_len, loc);
        }
        self.offset_to_source = new_map;
    }

    // ---------- auto-salt ----------

    /// Reports whether [`Self::finalize_program`] should append a salt so
    /// `program`'s hash is off-curve. Matches go-algorand's `shouldAutoSalt`
    /// (`assembler.go`), including its two diagnostic warnings for an
    /// explicit `#pragma autosalt` that's likely a no-op or ineffective.
    fn should_auto_salt(&mut self, program: &[u8]) -> bool {
        match self.auto_salt {
            AutoSaltMode::Off => {
                if !self.has_stateful_ops && program_hash_is_edwards25519_point(program) {
                    self.record_warning(
                        self.auto_salt_line,
                        0,
                        "#pragma autosalt false leaves program hash on curve".into(),
                    );
                }
                false
            }
            AutoSaltMode::On => {
                if self.has_stateful_ops {
                    self.record_warning(
                        self.auto_salt_line,
                        0,
                        "#pragma autosalt true used with stateful opcodes".into(),
                    );
                }
                program_hash_is_edwards25519_point(program)
            }
            AutoSaltMode::Unset => {
                default_auto_salt_applies(self.version, self.has_stateful_ops, program)
            }
        }
    }

    /// Constructs the final program bytes, auto-salting a v13+ stateless
    /// program whose hash would otherwise be on-curve. Matches go-algorand's
    /// `finalizeProgram` (`assembler.go`).
    fn finalize_program(&mut self) -> Result<(Vec<u8>, usize), String> {
        let (program, prefix_len) = self.prepend_cblocks();
        if !self.should_auto_salt(&program) {
            return Ok((program, prefix_len));
        }

        if !self.intc.is_empty() && self.cnt_intc_block == 0 {
            self.finalize_with_auto_intc_salt()
        } else {
            Self::finalize_with_trailing_intc_salt(program, prefix_len)
        }
    }

    /// Extends the program's own auto-generated intcblock with a trailing
    /// salt constant, trying each of the [`ASSEMBLER_SALT_SEARCH_LIMIT`]
    /// candidates until the resulting program hash is off-curve. Used when
    /// the program already has an automatic (non-manual) intcblock. Matches
    /// go-algorand's `finalizeProgramWithAutoIntcSalt` (`assembler.go`).
    fn finalize_with_auto_intc_salt(&mut self) -> Result<(Vec<u8>, usize), String> {
        let original_len = self.intc.len();
        self.intc.push(0);
        let mut result = None;
        for salt in 0..ASSEMBLER_SALT_SEARCH_LIMIT {
            self.intc[original_len] = salt;
            let (program, prefix_len) = self.prepend_cblocks();
            if !program_hash_is_edwards25519_point(&program) {
                result = Some((program, prefix_len));
                break;
            }
        }
        // Matches go-algorand's `defer` restoring `ops.intc` to its
        // source-derived length regardless of search outcome.
        self.intc.truncate(original_len);
        result.ok_or_else(|| {
            "could not find an automatic intcblock salt that yields an off-curve program".into()
        })
    }

    /// Appends a brand-new trailing one-value intcblock holding a salt
    /// constant, trying each of the [`ASSEMBLER_SALT_SEARCH_LIMIT`]
    /// candidates until the resulting program hash is off-curve. Used when
    /// the program has no automatic intcblock to extend (no int literals, or
    /// a manual `intcblock`). Matches go-algorand's
    /// `finalizeProgramWithTrailingIntcSalt` (`assembler.go`).
    fn finalize_with_trailing_intc_salt(
        program: Vec<u8>,
        prefix_len: usize,
    ) -> Result<(Vec<u8>, usize), String> {
        let mut candidate = program;
        candidate.extend_from_slice(&[0x20, 1, 0]); // intcblock, count=1, value placeholder
        let salt_offset = candidate.len() - 1;

        for salt in 0..ASSEMBLER_SALT_SEARCH_LIMIT {
            candidate[salt_offset] = salt as u8;
            if !program_hash_is_edwards25519_point(&candidate) {
                return Ok((candidate, prefix_len));
            }
        }
        Err("could not find a trailing intcblock salt that yields an off-curve program".into())
    }
}

// ---------------------------------------------------------------------------
// `#define` macro expansion
// ---------------------------------------------------------------------------
//
// go-algorand's assembler lets source text `#define NAME substitution`
// macros that are textually substituted wherever `NAME` appears as a later
// token, including inside another macro's body (macro chaining) and even
// as a `;` statement separator (`assembler.go:2432-2455`'s `define`,
// `assembler.go:2098-2114`'s `nextStatement`). See the `TestMacros` port in
// this module's tests.

/// Pseudo-op mnemonics (go's `pseudoOps` map keys, `assembler.go:1804-
/// 1816`) -- these are never real opcode names, so a macro can't be named
/// after one either (`checkMacroName`, `assembler.go:2415-2417`).
const PSEUDO_OP_NAMES: &[&str] = &[
    "int", "byte", "addr", "method", "txn", "gtxn", "gtxns", "extract", "replace",
];

/// Characters allowed in a macro name besides letters/digits (go's
/// `otherAllowedChars`, `assembler.go:2378`).
const MACRO_NAME_OTHER_CHARS: &[char] = &[
    '+', '-', '*', '/', '^', '%', '&', '|', '~', '!', '>', '<', '=', '?', '_',
];

/// Whether `name` is a field name recognized by *any* field-selector
/// immediate group (`TxnField`, `GlobalField`, `AssetHoldingField`, ...).
/// Mirrors go's `fieldNames[version]`, which unions every field-group name
/// used by any opcode available at that version (`opcodes.go:999-1010`);
/// this checks the union across all versions rather than narrowing to
/// exactly the fields reachable at `ops.version`; unlike the opcode-name
/// check just below, a macro named after a real field name is being
/// rejected regardless of when this codebase happened to grow support for
/// that specific field, so a version-widened conservative check errs the
/// same direction go's real per-version set would.
fn is_any_field_name(name: &str) -> bool {
    fields::global_field_by_name(name).is_some()
        || fields::txn_field_by_name(name).is_some()
        || fields::asset_holding_field_by_name(name).is_some()
        || fields::asset_params_field_by_name(name).is_some()
        || fields::app_params_field_by_name(name).is_some()
        || fields::acct_params_field_by_name(name).is_some()
        || fields::voter_params_field_by_name(name).is_some()
        || fields::ecdsa_curve_by_name(name).is_some()
        || fields::ec_group_by_name(name).is_some()
        || fields::base64_encoding_by_name(name).is_some()
        || fields::json_ref_type_by_name(name).is_some()
        || fields::vrf_standard_by_name(name).is_some()
        || fields::block_field_by_name(name).is_some()
        || fields::mimc_config_by_name(name).is_some()
        || fields::poseidon2_config_by_name(name).is_some()
}

/// Validates a candidate macro name, matching go's `checkMacroName`
/// (`assembler.go:2380-2430`). `ops.version == 0` stands in for go's
/// `assemblerNoVersion` sentinel (version not yet settled by a `#pragma
/// version` or the first real instruction) -- the opcode/field-name checks
/// only activate once a version is known, mirroring go exactly (see
/// [`recheck_macro_names`], invoked the moment the version does become
/// known, to re-validate every macro defined while it wasn't).
fn check_macro_name(name: &str, ops: &OpStream) -> Result<(), String> {
    let mut chars = name.chars();
    let first = chars.next();
    let second = chars.next();
    for c in name.chars() {
        if !c.is_alphanumeric() && !MACRO_NAME_OTHER_CHARS.contains(&c) {
            return Err(format!("{c} character not allowed in macro name"));
        }
    }
    if let Some(first) = first {
        if first.is_ascii_digit() {
            return Err(format!("Cannot begin macro name with number: {name}"));
        }
        if name.chars().count() > 1 && (first == '-' || first == '+') {
            if let Some(second) = second {
                if second.is_ascii_digit() {
                    return Err(format!("Cannot begin macro name with number: {name}"));
                }
            }
        }
    }
    // Parentheses aren't allowed characters, so `b64(...)`/`base64(...)`
    // syntax can't collide with a macro name -- only the bare directive
    // names need excluding.
    if matches!(name, "b64" | "base64" | "b32" | "base32") {
        return Err(format!("Cannot use {name} as macro name"));
    }
    if parse_named_int(name).is_some() {
        return Err(format!(
            "Named constants cannot be used as macro names: {name}"
        ));
    }
    if PSEUDO_OP_NAMES.contains(&name) {
        return Err(format!("Macro names cannot be pseudo-ops: {name}"));
    }
    if ops.version != 0 {
        if let Some(spec) = opcode::lookup_by_name(name) {
            if spec.version <= ops.version {
                return Err(format!("Macro names cannot be opcodes: {name}"));
            }
        }
        if is_any_field_name(name) {
            return Err(format!("Macro names cannot be field names: {name}"));
        }
    }
    if ops.labels.contains_key(name) {
        return Err(format!("Labels cannot be used as macro names: {name}"));
    }
    Ok(())
}

/// Searches for a macro-expansion cycle reachable from `start`, matching
/// go's `cycle` (`assembler.go:2343-2357`): only a chain that eventually
/// expands back to `start` itself counts (not any cycle elsewhere in the
/// macro graph -- every other currently-defined macro was already checked
/// cycle-free when *it* was defined). Returns the cycle as a chain of
/// macro names (`start -> ... -> start`) for the error message, or `None`.
fn find_macro_cycle(macros: &HashMap<String, MacroDef>, start: &str) -> Option<Vec<String>> {
    fn walk(
        macros: &HashMap<String, MacroDef>,
        name: &str,
        previous: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        let def = macros.get(name)?;
        if let Some(root) = previous.first() {
            if root == name {
                let mut cyc = previous.clone();
                cyc.push(name.to_string());
                return Some(cyc);
            }
        }
        for tok in def.body.clone() {
            previous.push(name.to_string());
            let found = walk(macros, &tok, previous);
            previous.pop();
            if found.is_some() {
                return found;
            }
        }
        None
    }
    let mut previous = Vec::new();
    walk(macros, start, &mut previous)
}

/// Re-validates every currently-defined macro's name against `ops.version`,
/// removing (and reporting) any that's no longer valid now that the
/// version is known -- mirrors go's `recheckMacroNames` (`assembler.go:
/// 2359-2376`), called the moment `ops.Version` first settles (either an
/// explicit `#pragma version` or the default applied at the first real
/// instruction). A macro name that didn't collide with anything while the
/// version was still unknown may turn out to collide with a real
/// opcode/field name once it is.
fn recheck_macro_names(ops: &mut OpStream) {
    let names: Vec<String> = ops.macros.keys().cloned().collect();
    for name in names {
        if let Err(e) = check_macro_name(&name, ops) {
            let line = ops
                .macros
                .get(&name)
                .map(|d| d.line)
                .unwrap_or(ops.source_line);
            ops.record_error(line, 0, e);
            ops.macros.remove(&name);
        }
    }
}

/// Handles one `#define NAME substitution` directive line. `tokens` is the
/// directive's entire, un-split token list (`tokens[0] == "#define"`).
/// Mirrors go's `define` (`assembler.go:2432-2455`).
fn handle_define(ops: &mut OpStream, tokens: &[&str]) {
    if tokens.len() < 3 {
        ops.record_error(
            ops.source_line,
            0,
            "define directive requires a name and body".into(),
        );
        return;
    }
    let name = tokens[1].to_string();
    if let Err(e) = check_macro_name(&name, ops) {
        ops.record_error(ops.source_line, 0, e);
        return;
    }
    let body: Vec<String> = tokens[2..].iter().map(|s| s.to_string()).collect();
    let saved = ops.macros.insert(
        name.clone(),
        MacroDef {
            line: ops.source_line,
            body,
        },
    );
    if let Some(cycle) = find_macro_cycle(&ops.macros, &name) {
        match saved {
            Some(prev) => {
                ops.macros.insert(name.clone(), prev);
            }
            None => {
                ops.macros.remove(&name);
            }
        }
        ops.record_error(
            ops.source_line,
            0,
            format!("macro expansion cycle discovered: {}", cycle.join(" -> ")),
        );
    }
}

/// A statement token paired with its 0-based source column (see
/// [`tokenize_line_with_cols`]).
type ColToken = (usize, String);

/// Expands macro-name tokens in place and splits at the next literal `;`
/// token, matching go's `nextStatement` (`assembler.go:2098-2114`): a
/// macro's own body can contain a literal `;` (`#define -> ; store`), so
/// this operates on the live token stream -- not on statements already
/// split at the character level -- and re-examines the same position after
/// each expansion in case the replacement's own first token is itself a
/// (different, non-cyclical) macro name. Returns `(current, rest)`: the
/// tokens making up this statement, and whatever tokens remain
/// unprocessed on the line.
fn next_statement(ops: &OpStream, mut tokens: Vec<ColToken>) -> (Vec<ColToken>, Vec<ColToken>) {
    let mut i = 0usize;
    while i < tokens.len() {
        if let Some(def) = ops.macros.get(&tokens[i].1) {
            // A macro-expanded token has no column of its own (the macro
            // body's tokens aren't re-tokenized from a specific source
            // line here); attribute the whole expansion to the macro
            // invocation's own column, which is strictly better than the
            // previous always-0 and still correct for the common
            // non-macro case this issue targets.
            let col = tokens[i].0;
            let mut expanded = tokens[..i].to_vec();
            expanded.extend(def.body.iter().cloned().map(|s| (col, s)));
            expanded.extend_from_slice(&tokens[i + 1..]);
            tokens = expanded;
            continue;
        }
        if tokens[i].1 == ";" {
            let rest = tokens[i + 1..].to_vec();
            tokens.truncate(i);
            return (tokens, rest);
        }
        i += 1;
    }
    (tokens, Vec::new())
}

/// Dispatches a `#`-prefixed directive line (`#pragma ...` / `#define
/// ...`) using its entire, un-split token list. Mirrors go's `directives`
/// map lookup (`assembler.go:2116-2118,2166-2177`) -- an unrecognized
/// directive is a hard error, not silently skipped.
fn handle_directive(ops: &mut OpStream, tokens: &[&str], version_set: &mut bool) {
    match &tokens[0][1..] {
        "pragma" => handle_pragma(ops, tokens, version_set),
        "define" => handle_define(ops, tokens),
        other => {
            ops.record_error(ops.source_line, 0, format!("unknown directive: {other}"));
        }
    }
}

/// Handles one `#pragma ...` directive line. `tokens` is the directive's
/// entire, un-split token list (`tokens[0] == "#pragma"`).
fn handle_pragma(ops: &mut OpStream, tokens: &[&str], version_set: &mut bool) {
    let parts = tokens;
    if parts.len() == 1 {
        // #pragma with no keyword
        ops.record_error(ops.source_line, 0, "empty pragma".into());
    } else if parts[1] == "version" {
        if parts.len() == 2 {
            // #pragma version (no number)
            ops.record_error(ops.source_line, 0, "no version value".into());
        } else if parts.len() > 3 {
            // #pragma version N extra
            ops.record_error(
                ops.source_line,
                0,
                "unexpected tokens after version value".into(),
            );
        } else {
            // #pragma version N
            if !ops.pending.is_empty() {
                ops.record_error(
                    ops.source_line,
                    0,
                    "#pragma version is only allowed before instructions".into(),
                );
            }
            if let Ok(v) = parts[2].parse::<u8>() {
                if v == 0 || v > MAX_AVM_VERSION {
                    ops.record_error(ops.source_line, 0, format!("unsupported version: {v}"));
                } else {
                    let was_unknown = ops.version == 0;
                    ops.version = v;
                    *version_set = true;
                    if was_unknown {
                        recheck_macro_names(ops);
                    }
                }
            } else {
                ops.record_error(ops.source_line, 0, format!("invalid version: {}", parts[2]));
            }
        }
    } else if parts[1] == "autosalt" {
        if parts.len() == 2 {
            // #pragma autosalt (no value)
            ops.record_error(ops.source_line, 0, "no autosalt value".into());
        } else if parts.len() > 3 {
            // #pragma autosalt VALUE extra
            ops.record_error(
                ops.source_line,
                0,
                "unexpected tokens after autosalt value".into(),
            );
        } else if !ops.pending.is_empty() {
            ops.record_error(
                ops.source_line,
                0,
                "#pragma autosalt is only allowed before instructions".into(),
            );
        } else if let Some(on) = parse_pragma_bool(parts[2]) {
            ops.auto_salt = if on {
                AutoSaltMode::On
            } else {
                AutoSaltMode::Off
            };
            ops.auto_salt_line = ops.source_line;
        } else {
            ops.record_error(
                ops.source_line,
                0,
                format!("bad #pragma autosalt: {:?}", parts[2]),
            );
        }
    } else if parts[1] == "typetrack" {
        if parts.len() == 2 {
            // #pragma typetrack (no value)
            ops.record_error(ops.source_line, 0, "no typetrack value".into());
        } else if parts.len() > 3 {
            // #pragma typetrack VALUE extra
            ops.record_error(
                ops.source_line,
                0,
                "unexpected tokens after typetrack value".into(),
            );
        } else if let Some(on) = parse_pragma_bool(parts[2]) {
            // Mirrors go's `#pragma typetrack` handling
            // (`assembler.go:2501-2519`): unlike `version`/
            // `autosalt`, this pragma has no "only allowed
            // before instructions" restriction -- it can
            // toggle mid-program, any number of times
            // (`TestTypeTracking`'s "Turning type tracking
            // off and then back on" cases).
            //
            // Note this only gates whether a mismatch is
            // *reported* -- the tracked stack itself keeps
            // evolving underneath even while reporting is
            // off, exactly like go's `trackStack` still
            // popping/pushing `ops.known.stack` regardless
            // of `ops.typeTracking` and only `typeErrorf`
            // checking the flag (`assembler.go:2039-2043,
            // 2056-2096`). See
            // `type_track::track_instruction`/
            // `apply_stack_effect`.
            let was_reporting = ops.type_track_reporting;
            ops.type_track_reporting = on;
            // Mirrors `assembler.go:2513-2517`: toggling
            // from off to on resets tracked knowledge to a
            // permissive "unknown incoming stack" state
            // (`ops.known.reset()`), exactly like reaching a
            // label after dead code -- whatever was tracked
            // while reporting was off (which may have
            // silently drifted from reality, since
            // mismatched pops/pushes still happened without
            // being reported) is discarded rather than
            // trusted. Toggling off, or declaring the
            // already-current state again (on-to-on or
            // off-to-off), does *not* reset --
            // `TestTypeTracking`'s "consecutively does _not_
            // reset" case.
            if !was_reporting && on {
                ops.type_stack.clear();
                ops.type_stack_const.clear();
                ops.scratch_space = [type_track::StackType::Any; 256];
                ops.type_track_deadcode = false;
                ops.type_track_bottom_permissive = true;
            }
        } else {
            ops.record_error(
                ops.source_line,
                0,
                format!("bad #pragma typetrack: {:?}", parts[2]),
            );
        }
    } else {
        // #pragma <unknown>
        ops.record_error(
            ops.source_line,
            0,
            format!("unsupported pragma directive: {}", parts[1]),
        );
    }
}

/// Processes one already macro-expanded, `;`-split statement: label
/// handling followed by mnemonic + immediate-argument dispatch. `current`
/// is never empty (callers skip empty statements from adjacent `;`
/// tokens).
fn process_statement(ops: &mut OpStream, current: &[ColToken]) {
    let mut tok_idx = 0;

    // Handle labels
    if current[0].1.ends_with(':') {
        let label = &current[0].1[..current[0].1.len() - 1];
        // Mirrors go's label-vs-macro-name conflict check at the
        // `createLabel` call site (`assembler.go:2192-2199`): checked
        // *before* the ordinary duplicate-label check, and skips creating
        // the label entirely on a conflict.
        if ops.macros.contains_key(label) {
            ops.record_error(
                ops.source_line,
                0,
                format!("Cannot create label with same name as macro: {label}"),
            );
        } else if ops.labels.contains_key(label) {
            ops.record_error(ops.source_line, 0, format!("duplicate label {:?}", label));
        } else {
            ops.labels.insert(label.to_string(), ops.pending.len());
        }
        // A label is a possible entry point from elsewhere in the
        // program (a branch target). Mirrors go-algorand's
        // `ProgramKnowledge.label`/`reset` (assembler.go:364-380),
        // called from `createLabel` (assembler.go:390): if the
        // instructions since the last label unconditionally
        // diverted control flow (`type_track_deadcode`), the
        // knowledge accumulated up to here doesn't describe what's
        // actually on the stack at this label, so analysis reopens
        // with permissive "any" knowledge instead. Otherwise (a
        // label reached by ordinary fallthrough, e.g. right after a
        // conditional `bnz`/`bz`) go does *not* reset -- it simply
        // trusts that whatever's tracked from the fallthrough path
        // also describes any jump into this label, and keeps
        // analyzing with the tracked stack as-is. See the
        // `type_track` module docs for what's still deferred, and
        // the `#pragma typetrack` handling above for the other spot
        // this same reset shape (minus `type_track_disabled`, which
        // the pragma never touches -- see its handling above) is
        // triggered. Mirrors go's `ProgramKnowledge.reset`
        // (`assembler.go:371-380`) resetting `scratchSpace` to
        // `StackAny` for every slot alongside `bottom`/`deadcode` --
        // see `Self::scratch_space`'s doc comment.
        if !ops.type_track_disabled && ops.type_track_deadcode {
            ops.type_track_deadcode = false;
            ops.type_track_bottom_permissive = true;
            ops.scratch_space = [type_track::StackType::Any; 256];
        }
        tok_idx = 1;
        if tok_idx >= current.len() {
            return;
        }
    }

    let mnemonic = current[tok_idx].1.as_str();
    let args: Vec<&str> = current[tok_idx + 1..]
        .iter()
        .map(|s| s.1.as_str())
        .collect();

    // Mirrors go's `line, column := current[0].line, current[0].col`
    // (assembler.go:2208): the column of this statement's instruction
    // token (after any leading label has been consumed), not a hardcoded
    // 0 -- see issue #1394.
    let col = current[tok_idx].0;
    ops.record_source_location(ops.source_line, col);
    type_track::track_instruction(ops, mnemonic, &args);
    assemble_instruction(ops, mnemonic, &args);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Assemble a TEAL program from source text into AVM bytecode.
///
/// Returns an `OpStream` containing the assembled `program` bytes and any
/// errors. If there are errors, `program` will be empty.
pub fn assemble_string(text: &str) -> Result<OpStream, Vec<AssemblyError>> {
    let mut ops = OpStream::new();

    if text.trim().is_empty() {
        ops.record_error(0, 0, "Cannot assemble empty program text".into());
        return Err(ops.errors);
    }

    // First pass: parse lines, emit preliminary bytecode
    let lines: Vec<&str> = text.lines().collect();
    let mut version_set = false;

    for (line_idx, &line_text) in lines.iter().enumerate() {
        ops.source_line = line_idx + 1; // 1-based

        let full_tokens = tokenize_line_with_cols(line_text);
        if full_tokens.is_empty() {
            continue;
        }

        // Directive lines (`#pragma`/`#define`) consume the entire line's
        // tokens (including any literal `;`) as one call and never fall
        // through to statement processing -- mirrors go's `parseText`
        // (assembler.go:2165-2177): a directive is recognized by its first
        // token alone, with no per-statement splitting for that line.
        // Directives don't need per-token columns (they don't feed
        // `record_source_location`), so strip them down to plain text.
        if full_tokens[0].1.starts_with('#') {
            let directive_tokens: Vec<&str> = full_tokens.iter().map(|(_, t)| *t).collect();
            handle_directive(&mut ops, &directive_tokens, &mut version_set);
            continue;
        }

        // If no version set yet, default -- and, like go's parseText
        // (assembler.go:2183-2187), recheck every macro defined so far now
        // that a version is implicitly known.
        if !version_set && ops.version == 0 {
            ops.version = ASSEMBLER_DEFAULT_VERSION;
            version_set = true;
            recheck_macro_names(&mut ops);
        }

        // Statement loop: repeatedly expand macros and split at the next
        // `;` token (`next_statement`, go's `nextStatement`) until the
        // line's tokens are exhausted. This has to run on the whole
        // line's token stream rather than on statements pre-split at the
        // character level, since a macro's body may itself contain a
        // literal `;` (see `next_statement`'s doc comment).
        let tokens: Vec<ColToken> = full_tokens
            .iter()
            .map(|(col, s)| (*col, s.to_string()))
            .collect();
        let (mut current, mut rest) = next_statement(&ops, tokens);
        while !current.is_empty() || !rest.is_empty() {
            if !current.is_empty() {
                process_statement(&mut ops, &current);
            }
            let next = next_statement(&ops, rest);
            current = next.0;
            rest = next.1;
        }
    }

    if !version_set && ops.version == 0 {
        ops.version = ASSEMBLER_DEFAULT_VERSION;
    }

    // Empty program check (comment-only or pragma-only programs)
    if ops.pending.is_empty() && ops.errors.is_empty() {
        ops.record_error(
            0,
            0,
            "empty program; at least one instruction is required".into(),
        );
    }

    // Constant optimization for v4+
    if ops.version >= OPTIMIZE_CONSTANTS_ENABLED_VERSION {
        if ops.cnt_intc_block == 0 && ops.has_pseudo_int {
            ops.optimize_int_constants();
        }
        if ops.cnt_bytec_block == 0 && ops.has_pseudo_byte {
            ops.optimize_byte_constants();
        }
    }

    // Shrink varint-encoded branches to their minimal width, then resolve
    // all label references (fixed-width and varint) to their final bytes.
    ops.find_branch_sizes();
    ops.resolve_labels();

    if !ops.errors.is_empty() {
        return Err(ops.errors.clone());
    }

    // Prepend version byte and constant blocks, auto-salting a v13+
    // stateless program whose hash would otherwise be on-curve.
    match ops.finalize_program() {
        Ok((program, prefix_len)) => {
            ops.program = program;
            ops.adjust_offset_to_source(prefix_len);
        }
        Err(message) => {
            ops.record_error(ops.source_line, 0, message);
            return Err(ops.errors.clone());
        }
    }

    Ok(ops)
}

// ---------------------------------------------------------------------------
// Instruction assembly
// ---------------------------------------------------------------------------

fn assemble_instruction(ops: &mut OpStream, mnemonic: &str, args: &[&str]) {
    match mnemonic {
        "int" => asm_int(ops, args),
        "byte" => asm_byte(ops, args),
        "addr" => asm_addr(ops, args),
        "method" => asm_method(ops, args),
        "intcblock" => asm_intc_block(ops, args),
        "bytecblock" => asm_bytec_block(ops, args),
        "txn" | "gtxn" | "gtxns" | "replace" | "extract" => asm_pseudo_arity(ops, mnemonic, args),
        _ => asm_regular(ops, mnemonic, args),
    }
}

// ---------------------------------------------------------------------------
// `txn`/`gtxn`/`gtxns`/`replace`/`extract` pseudo-op arity dispatch
// ---------------------------------------------------------------------------
//
// go-algorand's assembler treats these mnemonics as "pseudo-ops": the
// *number of immediates supplied* (not the mnemonic itself) picks the real
// opcode to assemble -- `txn Field` (1 immediate) is the real `txn` opcode,
// while `txn Field i` (2 immediates) transparently assembles as `txna`
// (assembler.go:1804-1816's `pseudoOps` table):
//
//   "txn":     {1: OpSpec{Name: "txn"},     2: OpSpec{Name: "txna"}},
//   "gtxn":    {2: OpSpec{Name: "gtxn"},    3: OpSpec{Name: "gtxna"}},
//   "gtxns":   {1: OpSpec{Name: "gtxns"},   2: OpSpec{Name: "gtxnsa"}},
//   "extract": {0: OpSpec{Name: "extract3"}, 2: OpSpec{Name: "extract"}},
//   "replace": {0: OpSpec{Name: "replace3"}, 1: OpSpec{Name: "replace2"}},
//
// `replace` (issue #945) follows the exact same immediate-count dispatch
// shape as `txn`/`gtxn`/`gtxns`: `replace` with a literal byte-offset
// immediate (1 immediate) assembles as the fixed-offset `replace2`;
// `replace` with no immediate (the offset instead comes off the stack, 0
// immediates) assembles as `replace3`.
//
// `extract` (issue #1388) follows the same shape: bare `extract` (0
// immediates, start/length come off the stack) assembles as `extract3`;
// `extract N M` (2 immediates, literal start/length) assembles as the real
// `extract` opcode.
//
// go-algorand's `getSpec` (assembler.go:1735-1773) resolves the target spec
// by arity, but keeps reporting diagnostics under the *pseudo* mnemonic
// (`pseudo.Name = name` at assembler.go:1755) rather than the dispatched-to
// opcode's own name -- e.g. `txn Accounts 0 1` (3 immediates, no arity
// matches) is `"txn expects 1 or 2 immediate arguments"`, not a `txna`-named
// error. `asm_pseudo_arity` mirrors that: it looks up the dispatched-to
// opcode's `OpSpec` to borrow its opcode byte/`ImmKind`/version, but always
// reports errors under the original pseudo mnemonic.

/// The `(immediate count -> real opcode name)` arity table for one
/// pseudo-op mnemonic, mirroring a single entry of go-algorand's
/// `pseudoOps` map (assembler.go:1804-1816).
fn pseudo_arity_table(mnemonic: &str) -> &'static [(usize, &'static str)] {
    match mnemonic {
        "txn" => &[(1, "txn"), (2, "txna")],
        "gtxn" => &[(2, "gtxn"), (3, "gtxna")],
        "gtxns" => &[(1, "gtxns"), (2, "gtxnsa")],
        "replace" => &[(0, "replace3"), (1, "replace2")],
        "extract" => &[(0, "extract3"), (2, "extract")],
        _ => &[],
    }
}

/// go-algorand's `joinIntsOnOr("immediate argument", counts...)`
/// (assembler.go:1699-1720), specialized to the small immediate-count lists
/// `pseudoImmediatesError` builds from a `pseudoOps` arity table.
fn join_immediate_counts(counts: &[usize]) -> String {
    if counts.len() == 1 {
        return match counts[0] {
            0 => "no immediate arguments".to_string(),
            1 => "1 immediate argument".to_string(),
            n => format!("{n} immediate arguments"),
        };
    }
    let mut sorted = counts.to_vec();
    sorted.sort_unstable();
    let mut msg = String::new();
    for (i, val) in sorted.iter().enumerate() {
        if i + 1 < sorted.len() {
            msg.push_str(&format!("{val} or "));
        } else {
            msg.push_str(&format!("{val} "));
        }
    }
    msg.push_str("immediate arguments");
    msg
}

/// Assemble a `txn`/`gtxn`/`gtxns`/`replace`/`extract` pseudo-op, dispatching
/// by immediate count to the real opcode -- the scalar opcode or its
/// array-indexed (`txna`/`gtxna`/`gtxnsa`) sibling, `replace3`/`replace2`, or
/// `extract3`/`extract` -- per go-algorand's `pseudoOps` table
/// (assembler.go:1804-1816).
fn asm_pseudo_arity(ops: &mut OpStream, mnemonic: &str, args: &[&str]) {
    let table = pseudo_arity_table(mnemonic);
    match table.iter().find(|(n, _)| *n == args.len()) {
        Some(&(_, target)) => {
            let spec = match opcode::lookup_by_name(target) {
                Some(s) => s,
                None => {
                    ops.record_error(ops.source_line, 0, format!("unknown opcode: {:?}", target));
                    return;
                }
            };
            // go's getSpec (assembler.go:1756-1759): version-gate under the
            // pseudo mnemonic, citing the immediate count that was used --
            // e.g. "txn opcode with 2 immediates was introduced in v2".
            if spec.version > ops.version {
                let phrase = if args.len() == 1 {
                    "1 immediate".to_string()
                } else {
                    format!("{} immediates", args.len())
                };
                ops.record_error(
                    ops.source_line,
                    0,
                    format!(
                        "{mnemonic} opcode with {phrase} was introduced in v{}",
                        spec.version
                    ),
                );
                return;
            }
            asm_regular_named(ops, target, mnemonic, args);
        }
        None => {
            // go's pseudoImmediatesError (assembler.go:1722-1730).
            let counts: Vec<usize> = table.iter().map(|(n, _)| *n).collect();
            ops.record_error(
                ops.source_line,
                0,
                format!("{mnemonic} expects {}", join_immediate_counts(&counts)),
            );
        }
    }
}

/// Parses a `#pragma autosalt`/`#pragma typetrack`-style boolean value.
/// Matches the spelling set accepted by go-algorand's `strconv.ParseBool`
/// (`1`/`t`/`T`/`TRUE`/`true`/`True`, `0`/`f`/`F`/`FALSE`/`false`/`False`).
fn parse_pragma_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

fn asm_int(ops: &mut OpStream, args: &[&str]) {
    if args.len() != 1 {
        ops.record_error(
            ops.source_line,
            0,
            "int expects 1 immediate argument".into(),
        );
        return;
    }

    // After backBranchEnabledVersion, if there's a manual cblock, use pushint
    if ops.cnt_intc_block > 0 && ops.version >= BACK_BRANCH_ENABLED_VERSION {
        asm_push_int(ops, args);
        return;
    }
    if ops.cnt_intc_block > 1 {
        if ops.version >= 3 {
            asm_push_int(ops, args);
            return;
        }
        ops.record_error(
            ops.source_line,
            0,
            format!("int {} used with manual intcblocks. Use intc.", args[0]),
        );
        return;
    }

    // Check named constants
    if let Some(val) = parse_named_int(args[0]) {
        ops.int_literal(val);
        return;
    }

    match args[0].parse::<u64>() {
        Ok(val) => ops.int_literal(val),
        Err(_) => {
            // Try parsing with 0x prefix
            if args[0].starts_with("0x") || args[0].starts_with("0X") {
                match u64::from_str_radix(&args[0][2..], 16) {
                    Ok(val) => ops.int_literal(val),
                    Err(_) => ops.record_error(
                        ops.source_line,
                        0,
                        format!("unable to parse {:?} as integer", args[0]),
                    ),
                }
            } else {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("unable to parse {:?} as integer", args[0]),
                );
            }
        }
    }
}

fn asm_push_int(ops: &mut OpStream, args: &[&str]) {
    if args.len() != 1 {
        ops.record_error(
            ops.source_line,
            0,
            "pushint expects 1 immediate argument".into(),
        );
        return;
    }
    let val = if let Some(v) = parse_named_int(args[0]) {
        v
    } else {
        match parse_u64(args[0]) {
            Ok(v) => v,
            Err(_) => {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("unable to parse {:?} as integer", args[0]),
                );
                return;
            }
        }
    };
    ops.pending.push(0x81); // pushint
    write_varuint_to_vec(&mut ops.pending, val);
}

fn asm_byte(ops: &mut OpStream, args: &[&str]) {
    if args.is_empty() {
        ops.record_error(
            ops.source_line,
            0,
            "byte needs byte literal argument".into(),
        );
        return;
    }

    // After backBranchEnabledVersion, if there's a manual cblock, use pushbytes
    if ops.cnt_bytec_block > 0 && ops.version >= BACK_BRANCH_ENABLED_VERSION {
        asm_push_bytes(ops, args);
        return;
    }
    if ops.cnt_bytec_block > 1 {
        if ops.version >= 3 {
            asm_push_bytes(ops, args);
            return;
        }
        ops.record_error(
            ops.source_line,
            0,
            format!("byte {} used with manual bytecblocks. Use bytec.", args[0]),
        );
        return;
    }

    match parse_binary_args(args) {
        Ok((val, consumed)) => {
            if args.len() != consumed {
                ops.record_error(
                    ops.source_line,
                    0,
                    "byte with extraneous argument".to_string(),
                );
                return;
            }
            if val.len() > opcode::MAX_STRING_SIZE {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!(
                        "byte value is too big ({} bytes, limit {})",
                        val.len(),
                        opcode::MAX_STRING_SIZE
                    ),
                );
                return;
            }
            ops.byte_literal(val)
        }
        Err(e) => ops.record_error(ops.source_line, 0, format!("byte {e}")),
    }
}

fn asm_push_bytes(ops: &mut OpStream, args: &[&str]) {
    if args.is_empty() {
        ops.record_error(
            ops.source_line,
            0,
            "pushbytes needs byte literal argument".into(),
        );
        return;
    }
    match parse_binary_args(args) {
        Ok((val, consumed)) => {
            if args.len() != consumed {
                ops.record_error(
                    ops.source_line,
                    0,
                    "pushbytes with extraneous argument".to_string(),
                );
                return;
            }
            if val.len() > opcode::MAX_STRING_SIZE {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!(
                        "pushbytes value is too big ({} bytes, limit {})",
                        val.len(),
                        opcode::MAX_STRING_SIZE
                    ),
                );
                return;
            }
            ops.pending.push(0x80); // pushbytes
            write_varuint_to_vec(&mut ops.pending, val.len() as u64);
            ops.pending.extend_from_slice(&val);
        }
        Err(e) => ops.record_error(ops.source_line, 0, format!("pushbytes {e}")),
    }
}

fn asm_addr(ops: &mut OpStream, args: &[&str]) {
    if args.len() != 1 {
        ops.record_error(
            ops.source_line,
            0,
            "addr expects 1 immediate argument".into(),
        );
        return;
    }
    match decode_algorand_address(args[0]) {
        Ok(bytes) => ops.byte_literal(bytes),
        Err(e) => ops.record_error(ops.source_line, 0, format!("addr: {e}")),
    }
}

fn asm_method(ops: &mut OpStream, args: &[&str]) {
    if args.len() != 1 {
        ops.record_error(
            ops.source_line,
            0,
            "method expects 1 immediate argument".into(),
        );
        return;
    }
    let arg = args[0];
    if arg.len() > 1 && arg.starts_with('"') && arg.ends_with('"') {
        match parse_string_literal(arg) {
            Ok(sig_bytes) => {
                // go's asmMethod calls abi.VerifyMethodSignature and warns
                // (non-fatally, since the ABI isn't governed by the core
                // protocol) if the string isn't a well-formed ARC-4 method
                // signature. Assembly still succeeds either way.
                if let Ok(sig_str) = std::str::from_utf8(&sig_bytes) {
                    if let Err(e) = algo_abi::parse_method_signature(sig_str) {
                        ops.record_warning(
                            ops.source_line,
                            0,
                            format!("invalid ARC-4 ABI method signature for method op: {e}"),
                        );
                    }
                }
                use sha2::{Digest, Sha512_256};
                let hash = Sha512_256::digest(&sig_bytes);
                ops.byte_literal(hash[..4].to_vec());
            }
            Err(e) => ops.record_error(ops.source_line, 0, format!("method: {e}")),
        }
    } else {
        ops.record_error(
            ops.source_line,
            0,
            "unable to parse method signature".into(),
        );
    }
}

fn asm_intc_block(ops: &mut OpStream, args: &[&str]) {
    let mut vals = Vec::new();
    for arg in args {
        match parse_u64(arg) {
            Ok(v) => {
                vals.push(v);
            }
            Err(_) => ops.record_error(
                ops.source_line,
                0,
                format!("unable to parse {:?} as integer", arg),
            ),
        }
    }
    ops.pending.push(0x20); // intcblock opcode
    write_varuint_to_vec(&mut ops.pending, vals.len() as u64);
    for v in &vals {
        write_varuint_to_vec(&mut ops.pending, *v);
    }
    // Mirrors go's `asmIntCBlock` (assembler.go:912-926): a manual intcblock
    // reached only through unconditionally-diverted control flow (dead code,
    // e.g. after an unconditional `b`/`callsub`/`retsub`/`err`/`return` and
    // before the next label) does not become the "currently live" intcblock
    // that `int`/`intc N` resolve against -- go's own `int` literal lookup
    // (`TestManualCBlocksPreBackBranch`) keeps "seeing" the last *reachable*
    // manual cblock instead. `type_track_deadcode` (set by branch/flow
    // opcodes, cleared at the next label) is computed in the same pass
    // just before this runs (`process_statement` calls
    // `type_track::track_instruction` first), so it accurately reflects
    // reachability here.
    if !ops.type_track_deadcode {
        if ops.has_pseudo_int {
            ops.record_error(ops.source_line, 0, "intcblock following int".into());
        }
        ops.intc_refs.clear();
        ops.intc = vals;
        ops.cnt_intc_block += 1;
    }
}

fn asm_bytec_block(ops: &mut OpStream, args: &[&str]) {
    ops.pending.push(0x26); // bytecblock opcode
    let mut vals: Vec<Vec<u8>> = Vec::new();
    let mut remaining = args;
    while !remaining.is_empty() {
        match parse_binary_args(remaining) {
            Ok((val, consumed)) => {
                if val.len() > opcode::MAX_STRING_SIZE {
                    ops.record_error(
                        ops.source_line,
                        0,
                        format!(
                            "bytecblock arg {} is too big ({} bytes, limit {})",
                            vals.len(),
                            val.len(),
                            opcode::MAX_STRING_SIZE
                        ),
                    );
                    remaining = &remaining[consumed..];
                    continue;
                }
                vals.push(val);
                remaining = &remaining[consumed..];
            }
            Err(e) => {
                ops.record_error(ops.source_line, 0, format!("bytecblock {e}"));
                // Skip this arg and continue to accumulate further errors
                remaining = &remaining[1..];
            }
        }
    }
    write_varuint_to_vec(&mut ops.pending, vals.len() as u64);
    for bv in &vals {
        write_varuint_to_vec(&mut ops.pending, bv.len() as u64);
        ops.pending.extend_from_slice(bv);
    }

    // Mirrors go's `asmByteCBlock` (assembler.go:960-976): same
    // dead-code-skip rule as `asm_intc_block` above, for byte constants.
    if !ops.type_track_deadcode {
        if ops.has_pseudo_byte {
            ops.record_error(
                ops.source_line,
                0,
                "bytecblock following byte/addr/method".into(),
            );
        }
        ops.bytec_refs.clear();
        ops.bytec = vals;
        ops.cnt_bytec_block += 1;
    }
}

fn asm_regular(ops: &mut OpStream, mnemonic: &str, args: &[&str]) {
    asm_regular_named(ops, mnemonic, mnemonic, args);
}

/// Assemble a "regular" (non-pseudo, non-`int`/`byte`/`addr`/`method`) opcode,
/// looking up the opcode spec under `lookup_name` but reporting every
/// diagnostic and resolving every field immediate under `display_name`.
///
/// These differ only when called from `asm_pseudo_arity`: `txn`/`gtxn`/
/// `gtxns`/`replace` dispatch by arity to the real opcode (`lookup_name`,
/// e.g. `"txna"`) but
/// keep reporting errors under the pseudo mnemonic the user actually wrote
/// (`display_name`, e.g. `"txn"`), matching go-algorand's `getSpec`
/// (`pseudo.Name = name`, assembler.go:1755). Every other caller passes the
/// same string for both, so behavior for non-pseudo opcodes is unchanged.
fn asm_regular_named(ops: &mut OpStream, lookup_name: &str, mnemonic: &str, args: &[&str]) {
    let spec = match opcode::lookup_by_name(lookup_name) {
        Some(s) => s,
        None => {
            ops.record_error(
                ops.source_line,
                0,
                format!("unknown opcode: {:?}", lookup_name),
            );
            return;
        }
    };

    if spec.version > ops.version {
        ops.record_error(
            ops.source_line,
            0,
            format!(
                "{} opcode was introduced in v{}. Missed #pragma version?",
                mnemonic, spec.version,
            ),
        );
        return;
    }

    if spec.mode == Mode::Application {
        ops.has_stateful_ops = true;
    }

    match spec.imm {
        ImmKind::None => {
            if !args.is_empty() {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("{} expects 0 immediate arguments", mnemonic),
                );
                return;
            }
            ops.pending.push(spec.opcode);
            // Multi-byte "prefix opcode" family (e.g. `app_box_*` at 0xd4):
            // emit the sub-opcode byte right after the shared prefix byte,
            // mirroring go-algorand's two-byte SubOpcode encoding
            // (opcodes.go:162, `OpDetails.SubOpcode`).
            if spec.sub_opcode != 0 {
                ops.pending.push(spec.sub_opcode);
            }
        }
        ImmKind::Uint8 => {
            if args.len() != 1 {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("{} expects 1 immediate argument", mnemonic),
                );
                return;
            }
            // Explicit `intc`/`bytec` mnemonics: mirror go-algorand's
            // `asmIntC`/`asmByteC` (assembler.go:583-609), which route
            // through `writeIntc`/`writeBytec` (assembler.go:429-452,
            // 482-505) instead of the generic 2-byte opcode+immediate
            // form used by every other `Uint8`-immediate opcode. Those
            // special-case constant index 0-3 to the single-byte
            // `intc_0..3`/`bytec_0..3` opcodes (and reject an index past
            // the end of the constant pool built so far, or -- once the
            // pool is large enough -- more than 256 constants), so route
            // here before ever pushing the generic `spec.opcode` byte.
            if mnemonic == "intc" || mnemonic == "bytec" {
                match parse_uint8_or_int8(args[0], mnemonic) {
                    Ok(val) => {
                        let pool_len = if mnemonic == "intc" {
                            ops.intc.len()
                        } else {
                            ops.bytec.len()
                        };
                        if val as usize >= pool_len {
                            ops.record_error(
                                ops.source_line,
                                0,
                                format!("{} {} is not defined", mnemonic, val),
                            );
                            return;
                        }
                        if mnemonic == "intc" {
                            ops.write_intc(val as usize);
                        } else {
                            ops.write_bytec(val as usize);
                        }
                    }
                    Err(e) => {
                        ops.record_error(ops.source_line, 0, format!("{mnemonic} {e}"));
                    }
                }
                return;
            }
            ops.pending.push(spec.opcode);
            // Check if this opcode uses a field group
            if let Some(val) = resolve_field_immediate(ops, mnemonic, args[0]) {
                if let Some(field_version) = field_group_version_at(mnemonic, 0, val) {
                    if field_version > ops.version {
                        ops.record_error(
                            ops.source_line,
                            0,
                            format!(
                                "{} {} field was introduced in v{}. Missed #pragma version?",
                                mnemonic, args[0], field_version,
                            ),
                        );
                        // Remove the opcode we just pushed since the field
                        // isn't usable at this program version.
                        ops.pending.pop();
                        return;
                    }
                }
                ops.pending.push(val);
            } else if let Ok(val) = parse_uint8_or_int8(args[0], mnemonic) {
                ops.pending.push(val);
            } else if is_field_group_immediate(mnemonic, 0) {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("{} unknown field: {:?}", mnemonic, args[0]),
                );
                // Remove the opcode we just pushed since the arg is invalid
                ops.pending.pop();
            } else {
                // Plain numeric immediate (load, store, frame_dig, ...):
                // report the actual parse/range error rather than a
                // generic "unknown field" -- there's no field name to speak
                // of here, matching go's byteImm/int8Imm error text.
                let e =
                    parse_uint8_or_int8(args[0], mnemonic).expect_err("Ok already handled above");
                ops.record_error(ops.source_line, 0, format!("{mnemonic} {e}"));
                ops.pending.pop();
            }
        }
        ImmKind::Uint8Uint8 => {
            if args.len() != 2 {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("{} expects 2 immediate arguments", mnemonic),
                );
                return;
            }
            ops.pending.push(spec.opcode);
            for (i, arg) in args.iter().enumerate() {
                if let Some(val) = resolve_field_immediate_at(ops, mnemonic, arg, i) {
                    if let Some(field_version) = field_group_version_at(mnemonic, i, val) {
                        if field_version > ops.version {
                            ops.record_error(
                                ops.source_line,
                                0,
                                format!(
                                    "{} {} field was introduced in v{}. Missed #pragma version?",
                                    mnemonic, arg, field_version,
                                ),
                            );
                            continue;
                        }
                    }
                    ops.pending.push(val);
                } else if let Ok(val) = parse_uint8_or_int8(arg, mnemonic) {
                    ops.pending.push(val);
                } else {
                    ops.record_error(
                        ops.source_line,
                        0,
                        format!("{} unknown field: {:?}", mnemonic, arg),
                    );
                }
            }
        }
        ImmKind::Uint8Uint8Uint8 => {
            if args.len() != 3 {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("{} expects 3 immediate arguments", mnemonic),
                );
                return;
            }
            ops.pending.push(spec.opcode);
            for (i, arg) in args.iter().enumerate() {
                if let Some(val) = resolve_field_immediate_at(ops, mnemonic, arg, i) {
                    if let Some(field_version) = field_group_version_at(mnemonic, i, val) {
                        if field_version > ops.version {
                            ops.record_error(
                                ops.source_line,
                                0,
                                format!(
                                    "{} {} field was introduced in v{}. Missed #pragma version?",
                                    mnemonic, arg, field_version,
                                ),
                            );
                            continue;
                        }
                    }
                    ops.pending.push(val);
                } else if let Ok(val) = parse_uint8_or_int8(arg, mnemonic) {
                    ops.pending.push(val);
                } else {
                    ops.record_error(
                        ops.source_line,
                        0,
                        format!("{} unknown field: {:?}", mnemonic, arg),
                    );
                }
            }
        }
        ImmKind::Int16 => {
            // Branch instruction: bnz/bz/b/callsub. At LogicSigVersion >=
            // VARINT_BRANCH_VERSION these switch to a varint-encoded offset
            // (go-algorand PR #6600); below that they keep the legacy fixed
            // 2-byte big-endian encoding assembled below.
            if ops.version >= opcode::VARINT_BRANCH_VERSION
                && opcode::is_varint_branch_opcode(spec.opcode)
            {
                asm_branch_varint(ops, spec.opcode, mnemonic, args);
                return;
            }

            if args.len() != 1 {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("{} expects 1 immediate argument", mnemonic),
                );
                return;
            }
            let label = args[0].to_string();
            ops.pending.push(spec.opcode);
            let offset_pos = ops.pending.len();
            ops.pending.push(0); // placeholder
            ops.pending.push(0);
            let end_of_instruction = ops.pending.len();
            ops.label_references.push(LabelReference {
                position: offset_pos,
                label,
                line: ops.source_line,
                offset_position: end_of_instruction,
                varint: false,
            });
        }
        ImmKind::Varuint => {
            // pushint
            if args.len() != 1 {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("{} expects 1 immediate argument", mnemonic),
                );
                return;
            }
            match parse_u64(args[0]) {
                Ok(val) => {
                    ops.pending.push(spec.opcode);
                    write_varuint_to_vec(&mut ops.pending, val);
                }
                Err(e) => ops.record_error(ops.source_line, 0, format!("{mnemonic}: {e}")),
            }
        }
        ImmKind::VaruintBytes => {
            // pushbytes
            if args.is_empty() {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("{} needs byte literal argument", mnemonic),
                );
                return;
            }
            match parse_binary_args(args) {
                Ok((val, _consumed)) => {
                    if val.len() > opcode::MAX_STRING_SIZE {
                        ops.record_error(
                            ops.source_line,
                            0,
                            format!(
                                "{mnemonic} value is too big ({} bytes, limit {})",
                                val.len(),
                                opcode::MAX_STRING_SIZE
                            ),
                        );
                        return;
                    }
                    ops.pending.push(spec.opcode);
                    write_varuint_to_vec(&mut ops.pending, val.len() as u64);
                    ops.pending.extend_from_slice(&val);
                }
                Err(e) => ops.record_error(ops.source_line, 0, format!("{mnemonic} {e}")),
            }
        }
        ImmKind::IntcBlock => {
            // Manual intcblock (shouldn't reach here since we handle it above, but just in case)
            asm_intc_block(ops, args);
        }
        ImmKind::BytecBlock => {
            asm_bytec_block(ops, args);
        }
        ImmKind::Labels => {
            // switch/match
            ops.pending.push(spec.opcode);
            let num_labels = args.len();
            if num_labels > 255 {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("{} cannot take more than 255 labels", mnemonic),
                );
                return;
            }
            ops.pending.push(num_labels as u8);
            let op_end_pos = ops.pending.len() + 2 * num_labels;
            for arg in args {
                let label = arg.to_string();
                let pos = ops.pending.len();
                ops.pending.push(0);
                ops.pending.push(0);
                ops.label_references.push(LabelReference {
                    position: pos,
                    label,
                    line: ops.source_line,
                    offset_position: op_end_pos,
                    varint: false,
                });
            }
        }
        ImmKind::PushInts => {
            // pushints
            ops.pending.push(spec.opcode);
            write_varuint_to_vec(&mut ops.pending, args.len() as u64);
            for arg in args {
                match parse_u64(arg) {
                    Ok(v) => write_varuint_to_vec(&mut ops.pending, v),
                    Err(e) => ops.record_error(ops.source_line, 0, format!("{mnemonic}: {e}")),
                }
            }
        }
        ImmKind::BranchVarint => {
            // Never a static table entry (see opcode::ImmKind::BranchVarint's
            // doc comment) -- the ImmKind::Int16 arm above dispatches to
            // asm_branch_varint directly once ops.version >=
            // VARINT_BRANCH_VERSION, without ever assigning this kind to
            // spec.imm. Unreachable in practice; handled defensively rather
            // than via a wildcard so a future real table entry using this
            // kind doesn't silently fall through unassembled.
            ops.record_error(
                ops.source_line,
                0,
                format!("{mnemonic}: unexpected BranchVarint immediate kind"),
            );
        }
        ImmKind::PushBytess => {
            // pushbytess
            ops.pending.push(spec.opcode);
            let mut vals: Vec<Vec<u8>> = Vec::new();
            let mut remaining = args;
            while !remaining.is_empty() {
                match parse_binary_args(remaining) {
                    Ok((val, consumed)) => {
                        if val.len() > opcode::MAX_STRING_SIZE {
                            ops.record_error(
                                ops.source_line,
                                0,
                                format!(
                                    "{mnemonic} arg {} is too big ({} bytes, limit {})",
                                    vals.len(),
                                    val.len(),
                                    opcode::MAX_STRING_SIZE
                                ),
                            );
                            remaining = &remaining[consumed..];
                            continue;
                        }
                        vals.push(val);
                        remaining = &remaining[consumed..];
                    }
                    Err(e) => {
                        ops.record_error(ops.source_line, 0, format!("{mnemonic} {e}"));
                        break;
                    }
                }
            }
            write_varuint_to_vec(&mut ops.pending, vals.len() as u64);
            for bv in &vals {
                write_varuint_to_vec(&mut ops.pending, bv.len() as u64);
                ops.pending.extend_from_slice(bv);
            }
        }
    }
}

/// Number of placeholder bytes initially reserved for a varint-encoded
/// branch offset. `find_branch_sizes` shrinks these down to the minimum
/// needed size once all label positions are known. 3 bytes covers offsets
/// up to +/-2^20, far beyond any program's max size -- matches
/// go-algorand's `varintBranchInitialSize`.
const VARINT_BRANCH_INITIAL_SIZE: usize = 3;

/// Assemble a varint-encoded branch (`bnz`/`bz`/`b`/`callsub` at
/// LogicSigVersion >= `opcode::VARINT_BRANCH_VERSION`). Reserves
/// `VARINT_BRANCH_INITIAL_SIZE` zero-filled placeholder bytes; the actual
/// minimal-width varint offset is written later by `find_branch_sizes` +
/// `resolve_labels`, once every label's final position is known.
fn asm_branch_varint(ops: &mut OpStream, opcode_byte: u8, mnemonic: &str, args: &[&str]) {
    if args.len() != 1 {
        ops.record_error(
            ops.source_line,
            0,
            format!("{} expects 1 immediate argument", mnemonic),
        );
        return;
    }
    let label = args[0].to_string();
    ops.pending.push(opcode_byte);
    let offset_pos = ops.pending.len();
    for _ in 0..VARINT_BRANCH_INITIAL_SIZE {
        ops.pending.push(0); // placeholder
    }
    let end_of_instruction = ops.pending.len();
    ops.label_references.push(LabelReference {
        position: offset_pos,
        label,
        line: ops.source_line,
        offset_position: end_of_instruction,
        varint: true,
    });
}

// ---------------------------------------------------------------------------
// Field name resolution
// ---------------------------------------------------------------------------

/// For opcodes that take a field name as their single uint8 immediate.
fn resolve_field_immediate(ops: &OpStream, mnemonic: &str, arg: &str) -> Option<u8> {
    resolve_field_immediate_at(ops, mnemonic, arg, 0)
}

/// Resolve a field name to its byte index, depending on which immediate position
/// and which opcode we're dealing with.
fn resolve_field_immediate_at(
    _ops: &OpStream,
    mnemonic: &str,
    arg: &str,
    imm_index: usize,
) -> Option<u8> {
    match (mnemonic, imm_index) {
        ("txn", 0)
        | ("txna", 0)
        | ("txnas", 0)
        | ("itxn", 0)
        | ("itxna", 0)
        | ("itxnas", 0)
        | ("itxn_field", 0) => fields::txn_field_by_name(arg),

        ("gtxn", 1)
        | ("gtxna", 1)
        | ("gtxns", 0)
        | ("gtxnsa", 0)
        | ("gtxnas", 1)
        | ("gtxnsas", 0)
        | ("gitxn", 1)
        | ("gitxna", 1)
        | ("gitxnas", 1) => fields::txn_field_by_name(arg),

        ("global", 0) => fields::global_field_by_name(arg),

        ("asset_holding_get", 0) => fields::asset_holding_field_by_name(arg),
        ("asset_params_get", 0) => fields::asset_params_field_by_name(arg),
        ("app_params_get", 0) | ("app_params_set", 0) => fields::app_params_field_by_name(arg),
        ("acct_params_get", 0) => fields::acct_params_field_by_name(arg),
        ("voter_params_get", 0) => fields::voter_params_field_by_name(arg),

        ("ecdsa_verify", 0) | ("ecdsa_pk_decompress", 0) | ("ecdsa_pk_recover", 0) => {
            fields::ecdsa_curve_by_name(arg)
        }

        ("ec_add", 0)
        | ("ec_scalar_mul", 0)
        | ("ec_pairing_check", 0)
        | ("ec_multi_scalar_mul", 0)
        | ("ec_subgroup_check", 0)
        | ("ec_map_to", 0) => fields::ec_group_by_name(arg),

        ("base64_decode", 0) => fields::base64_encoding_by_name(arg),
        ("json_ref", 0) => fields::json_ref_type_by_name(arg),
        ("vrf_verify", 0) => fields::vrf_standard_by_name(arg),
        ("block", 0) => fields::block_field_by_name(arg),
        ("mimc", 0) => fields::mimc_config_by_name(arg),
        ("poseidon2", 0) => fields::poseidon2_config_by_name(arg),

        _ => None,
    }
}

/// Returns the AVM version at which the given field-group immediate byte
/// (already resolved by [`resolve_field_immediate_at`] for this exact
/// `(mnemonic, imm_index)`) was introduced -- mirrors go-algorand's
/// `asmDefault` check (`assembler.go:1240-1245`): `if fs.Version() >
/// ops.Version { error("... field was introduced in vN. Missed #pragma
/// version?") }`. Every arm here must match [`resolve_field_immediate_at`]'s
/// dispatch table exactly, since it is only ever called with a byte that
/// function just produced.
fn field_group_version_at(mnemonic: &str, imm_index: usize, byte: u8) -> Option<u8> {
    match (mnemonic, imm_index) {
        // `itxn_field` is go-algorand's odd one out here: it has its own
        // `asmItxnField` (assembler.go:1128-1145), gating on the field's
        // *settable-in-an-inner-txn* version (`fs.itxVersion`), not its
        // ordinary *readable* version (`fs.version`) used by every other
        // txn-field-group mnemonic below. A field with `itx_version() == 0`
        // can never be set via `itxn_field` at any version (go reports
        // `"... is not allowed."` for that, a distinct, pre-existing gap
        // this issue doesn't address) -- returning `None` here just skips
        // the version gate for it, same as before this fix.
        ("itxn_field", 0) => {
            let v = fields::TxnField::from_u8(byte).ok()?.itx_version();
            if v == 0 {
                None
            } else {
                Some(v)
            }
        }

        ("txn", 0)
        | ("txna", 0)
        | ("txnas", 0)
        | ("itxn", 0)
        | ("itxna", 0)
        | ("itxnas", 0)
        | ("gtxn", 1)
        | ("gtxna", 1)
        | ("gtxns", 0)
        | ("gtxnsa", 0)
        | ("gtxnas", 1)
        | ("gtxnsas", 0)
        | ("gitxn", 1)
        | ("gitxna", 1)
        | ("gitxnas", 1) => fields::TxnField::from_u8(byte).ok().map(|f| f.version()),

        ("global", 0) => fields::GlobalField::from_u8(byte).ok().map(|f| f.version()),

        ("asset_holding_get", 0) => fields::AssetHoldingField::from_u8(byte)
            .ok()
            .map(|f| f.version()),
        ("asset_params_get", 0) => fields::AssetParamsField::from_u8(byte)
            .ok()
            .map(|f| f.version()),
        ("app_params_get", 0) | ("app_params_set", 0) => fields::AppParamsField::from_u8(byte)
            .ok()
            .map(|f| f.version()),
        ("acct_params_get", 0) => fields::AcctParamsField::from_u8(byte)
            .ok()
            .map(|f| f.version()),
        ("voter_params_get", 0) => fields::VoterParamsField::from_u8(byte)
            .ok()
            .map(|f| f.version()),

        ("ecdsa_verify", 0) | ("ecdsa_pk_decompress", 0) | ("ecdsa_pk_recover", 0) => {
            fields::EcdsaCurve::from_u8(byte).ok().map(|f| f.version())
        }

        ("ec_add", 0)
        | ("ec_scalar_mul", 0)
        | ("ec_pairing_check", 0)
        | ("ec_multi_scalar_mul", 0)
        | ("ec_subgroup_check", 0)
        | ("ec_map_to", 0) => fields::EcGroup::from_u8(byte).ok().map(|f| f.version()),

        ("base64_decode", 0) => fields::Base64Encoding::from_u8(byte)
            .ok()
            .map(|f| f.version()),
        ("json_ref", 0) => fields::JSONRefType::from_u8(byte).ok().map(|f| f.version()),
        ("vrf_verify", 0) => fields::VrfStandard::from_u8(byte).ok().map(|f| f.version()),
        ("block", 0) => fields::BlockField::from_u8(byte).ok().map(|f| f.version()),
        ("mimc", 0) => fields::MimcConfig::from_u8(byte).ok().map(|f| f.version()),
        ("poseidon2", 0) => fields::Poseidon2Config::from_u8(byte)
            .ok()
            .map(|f| f.version()),

        _ => None,
    }
}

/// True iff `(mnemonic, imm_index)` is one of [`resolve_field_immediate_at`]'s
/// field-group immediates (a `txn`-style field name, an `ecdsa_verify`
/// curve, etc.) -- mirrors that function's match arms without doing the
/// resolution, so a plain numeric-immediate opcode like `load`/`store`/
/// `frame_dig` (no group at all) can be told apart from a field-group
/// opcode that was given an unrecognized field name (e.g. `txn BadField`).
/// go-algorand keeps this same distinction (assembler.go:1203-1273): a
/// group immediate that fails to resolve reports `"unknown field"`, while a
/// plain immediate that fails to parse reports the parse error itself.
fn is_field_group_immediate(mnemonic: &str, imm_index: usize) -> bool {
    matches!(
        (mnemonic, imm_index),
        ("txn", 0)
            | ("txna", 0)
            | ("txnas", 0)
            | ("itxn", 0)
            | ("itxna", 0)
            | ("itxnas", 0)
            | ("itxn_field", 0)
            | ("gtxn", 1)
            | ("gtxna", 1)
            | ("gtxns", 0)
            | ("gtxnsa", 0)
            | ("gtxnas", 1)
            | ("gtxnsas", 0)
            | ("gitxn", 1)
            | ("gitxna", 1)
            | ("gitxnas", 1)
            | ("global", 0)
            | ("asset_holding_get", 0)
            | ("asset_params_get", 0)
            | ("app_params_get", 0)
            | ("app_params_set", 0)
            | ("acct_params_get", 0)
            | ("voter_params_get", 0)
            | ("ecdsa_verify", 0)
            | ("ecdsa_pk_decompress", 0)
            | ("ecdsa_pk_recover", 0)
            | ("ec_add", 0)
            | ("ec_scalar_mul", 0)
            | ("ec_pairing_check", 0)
            | ("ec_multi_scalar_mul", 0)
            | ("ec_subgroup_check", 0)
            | ("ec_map_to", 0)
            | ("base64_decode", 0)
            | ("json_ref", 0)
            | ("vrf_verify", 0)
            | ("block", 0)
            | ("mimc", 0)
            | ("poseidon2", 0)
    )
}

// ---------------------------------------------------------------------------
// Named integer constants (txn types, OnCompletion)
// ---------------------------------------------------------------------------

fn parse_named_int(name: &str) -> Option<u64> {
    // Transaction type names (short form)
    match name {
        "unknown" => return Some(0),
        "pay" => return Some(1),
        "keyreg" => return Some(2),
        "acfg" => return Some(3),
        "axfer" => return Some(4),
        "afrz" => return Some(5),
        "appl" => return Some(6),
        "stpf" => return Some(7),
        "hb" => return Some(8),
        // Long form
        "Payment" => return Some(1),
        "KeyRegistration" => return Some(2),
        "AssetConfig" => return Some(3),
        "AssetTransfer" => return Some(4),
        "AssetFreeze" => return Some(5),
        "ApplicationCall" => return Some(6),
        _ => {}
    }

    // OnCompletion constants
    match name {
        "NoOp" => return Some(0),
        "OptIn" => return Some(1),
        "CloseOut" => return Some(2),
        "ClearState" => return Some(3),
        "UpdateApplication" => return Some(4),
        "DeleteApplication" => return Some(5),
        _ => {}
    }

    None
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_uint8_or_int8(s: &str, mnemonic: &str) -> Result<u8, String> {
    // frame_dig/frame_bury are the *only* opcodes in go-algorand whose
    // immediate is `immInt8` (opcodes.go:713-714) -- a signed byte in
    // -128..=127, encoded on the wire as its two's-complement `u8` bit
    // pattern. go's `int8Imm` (assembler.go:1098) parses with
    // `strconv.ParseInt(value, 10, 8)`, which itself rejects anything
    // outside that range (rather than falling back to an unsigned parse),
    // so e.g. `frame_dig 128` must fail to assemble, not silently succeed
    // by being read as an unsigned byte.
    if mnemonic == "frame_dig" || mnemonic == "frame_bury" {
        return s
            .parse::<i8>()
            .map(|v| v as u8)
            .map_err(|_| format!("unable to parse {s:?} as int8"));
    }
    // Every other opcode with a plain byte immediate (load, store, ...) uses
    // go's `byteImm` (assembler.go:1087), which parses with
    // `strconv.ParseUint(value, 0, 64)` -- unsigned only. A negative literal
    // therefore fails to parse rather than wrapping into the `u8` range
    // (e.g. `load -100` must be rejected, not silently reinterpreted as
    // `load 156`), and a value over 255 is a distinct "beyond 255" error.
    match s.parse::<u64>() {
        Ok(v) if v > 255 => Err(format!("i beyond 255: {v}")),
        Ok(v) => Ok(v as u8),
        Err(_) => Err(format!("unable to parse {s:?} as integer")),
    }
}

fn parse_u64(s: &str) -> Result<u64, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| e.to_string())
    } else if s.starts_with("0o") || s.starts_with("0O") {
        u64::from_str_radix(&s[2..], 8).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

/// Parse a binary argument (byte literal). Returns (bytes, tokens_consumed).
fn parse_binary_args(args: &[&str]) -> Result<(Vec<u8>, usize), String> {
    if args.is_empty() {
        return Err("missing argument".into());
    }
    let arg = args[0];

    // base64(...) / b64(...)
    if arg.starts_with("base64(") || arg.starts_with("b64(") {
        let open = arg.find('(').unwrap();
        let close = arg
            .find(')')
            .ok_or_else(|| format!("argument {} lacks closing parenthesis", arg))?;
        if close != arg.len() - 1 {
            return Err(format!(
                "argument {} must end at first closing parenthesis",
                arg
            ));
        }
        let encoded = &arg[open + 1..close];
        let val = base64_decode(encoded)?;
        return Ok((val, 1));
    }

    // base32(...) / b32(...)
    if arg.starts_with("base32(") || arg.starts_with("b32(") {
        let open = arg.find('(').unwrap();
        let close = arg
            .find(')')
            .ok_or_else(|| format!("argument {} lacks closing parenthesis", arg))?;
        if close != arg.len() - 1 {
            return Err(format!(
                "argument {} must end at first closing parenthesis",
                arg
            ));
        }
        let encoded = &arg[open + 1..close];
        let val = base32_decode(encoded)?;
        return Ok((val, 1));
    }

    // 0x hex literal
    if arg.starts_with("0x") || arg.starts_with("0X") {
        let hex_str = &arg[2..];
        let val = hex::decode(hex_str).map_err(|e| e.to_string())?;
        return Ok((val, 1));
    }

    // base64 / b64 as separate token
    if arg == "base64" || arg == "b64" {
        if args.len() < 2 {
            return Err(format!("{} needs byte literal argument", arg));
        }
        let val = base64_decode(args[1])?;
        return Ok((val, 2));
    }

    // base32 / b32 as separate token
    if arg == "base32" || arg == "b32" {
        if args.len() < 2 {
            return Err(format!("{} needs byte literal argument", arg));
        }
        let val = base32_decode(args[1])?;
        return Ok((val, 2));
    }

    // String literal
    if arg.len() > 1 && arg.starts_with('"') && arg.ends_with('"') {
        let val = parse_string_literal(arg)?;
        return Ok((val, 1));
    }

    Err(format!("arg did not parse: {}", arg))
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.to_string())
}

fn base32_decode(s: &str) -> Result<Vec<u8>, String> {
    // Try without padding first, then with
    let alphabet = data_encoding::BASE32;
    let no_pad = data_encoding::BASE32_NOPAD;

    no_pad
        .decode(s.as_bytes())
        .or_else(|_| alphabet.decode(s.as_bytes()))
        .map_err(|e| e.to_string())
}

fn parse_string_literal(input: &str) -> Result<Vec<u8>, String> {
    if input.len() < 2 || !input.starts_with('"') || !input.ends_with('"') {
        return Err("no quotes".into());
    }
    let inner = &input[1..input.len() - 1];
    let bytes = inner.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 1;
            if i >= bytes.len() {
                return Err("non-terminated escape sequence".into());
            }
            match bytes[i] {
                b'n' => result.push(b'\n'),
                b'r' => result.push(b'\r'),
                b't' => result.push(b'\t'),
                b'\\' => result.push(b'\\'),
                b'"' => result.push(b'"'),
                b'x' => {
                    i += 1;
                    if i + 1 >= bytes.len() {
                        return Err("non-terminated hex sequence".into());
                    }
                    let hex_str =
                        std::str::from_utf8(&bytes[i..i + 2]).map_err(|e| e.to_string())?;
                    let byte = u8::from_str_radix(hex_str, 16).map_err(|e| e.to_string())?;
                    result.push(byte);
                    i += 1; // will be incremented again below
                }
                c => return Err(format!("invalid escape sequence \\{}", c as char)),
            }
        } else {
            result.push(bytes[i]);
        }
        i += 1;
    }
    Ok(result)
}

/// Decode an Algorand address (base32 with checksum) into 32 bytes.
fn decode_algorand_address(addr: &str) -> Result<Vec<u8>, String> {
    let decoded = base32_decode(addr.trim_end_matches('='))
        .or_else(|_| base32_decode(addr))
        .map_err(|e| format!("invalid address encoding: {e}"))?;

    if decoded.len() != 36 {
        return Err(format!(
            "invalid address length: expected 36 bytes, got {}",
            decoded.len()
        ));
    }

    // First 32 bytes are the public key, last 4 are checksum
    let pubkey = &decoded[..32];
    let checksum = &decoded[32..36];

    // Verify checksum: last 4 bytes of SHA512/256 of the public key
    use sha2::{Digest, Sha512_256};
    let hash = Sha512_256::digest(pubkey);
    let expected = &hash[28..32];

    if checksum != expected {
        return Err("address checksum mismatch".into());
    }

    Ok(pubkey.to_vec())
}

/// Tokenize an entire TEAL source line into a flat, whitespace-separated
/// token stream, preserving string literals as single tokens and emitting
/// `;` as its own explicit single-character token rather than splitting
/// the line into statements up front. An unescaped `//` (outside a string
/// literal) ends tokenization for the rest of the line, including
/// anything past a `;` that would otherwise have followed it.
///
/// Matches go-algorand's `tokensFromLine` (`data/transactions/logic/
/// assembler.go`): a `#pragma`/`#define` directive line needs its whole,
/// un-split token list (see `handle_directive`), and macro expansion can
/// turn a single textual statement into several by substituting a `;`
/// into the middle of it (`#define -> ; store`) -- both need `;` to still
/// be a first-class token here rather than something already consumed by
/// a separate statement-splitting pass. [`next_statement`] does that
/// splitting afterward, at the token level, once macros have been
/// expanded.
#[cfg(test)]
fn tokenize_line(line: &str) -> Vec<&str> {
    tokenize_line_with_cols(line)
        .into_iter()
        .map(|(_, tok)| tok)
        .collect()
}

/// Same tokenization as [`tokenize_line`], but also returns each token's
/// starting column (0-based, matching go's `token.col` from
/// `tokensFromLine`, `assembler.go:1945-2020`) so callers that need to
/// report a precise source location (`OpStream::record_source_location`)
/// can thread it through instead of assuming column 0 -- see issue #1394.
fn tokenize_line_with_cols(line: &str) -> Vec<(usize, &str)> {
    let mut tokens = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0usize;
    // Tracks whether we're inside a `base64`/`b64` literal, matching
    // go's `tokensFromLine` `inBase64` flag: once a `base64`/`b64`
    // bare-prefix token or `base64(`/`b64(` paren form is seen, `//`
    // detection is suppressed until the literal ends -- `//` is a legal
    // base64 substring, not a comment start, inside one.
    let mut in_base64 = false;
    while i < bytes.len() {
        // Skip whitespace
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // An unescaped `//` outside a string or base64 literal ends the
        // whole line.
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' && !in_base64 {
            break;
        }
        if bytes[i] == b';' {
            tokens.push((i, &line[i..i + 1]));
            i += 1;
            continue;
        }
        let start = i;
        if bytes[i] == b'"' {
            // String literal — consume until closing quote
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2; // skip escape
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
        } else {
            // Regular token: consume until whitespace, `;`, or `//`.
            // Also tracks the `base64(`/`b64(` paren form: once the
            // token text preceding an open paren is exactly "base64" or
            // "b64", `//` inside the parens is not a comment start until
            // the matching `)` is seen.
            while i < bytes.len() {
                if bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b';' {
                    break;
                }
                if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' && !in_base64 {
                    break;
                }
                if bytes[i] == b'(' {
                    let prefix = &line[start..i];
                    if prefix == "base64" || prefix == "b64" {
                        in_base64 = true;
                    }
                } else if bytes[i] == b')' && in_base64 {
                    in_base64 = false;
                }
                i += 1;
            }
        }
        let tok = &line[start..i];
        tokens.push((start, tok));
        // Bare `base64`/`b64` prefix form: the token just completed is
        // either the base64 literal itself (clear the flag) or, if it's
        // exactly "base64"/"b64", the prefix that opens one (the *next*
        // token is the literal, so set the flag for it).
        if in_base64 {
            in_base64 = false;
        } else if tok == "base64" || tok == "b64" {
            in_base64 = true;
        }
    }
    tokens
}

// ---------------------------------------------------------------------------
// Varuint encoding
// ---------------------------------------------------------------------------

/// Encode a u64 as unsigned LEB128 (varuint) and append to a Vec.
pub fn write_varuint_to_vec(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

/// Returns the number of bytes needed to encode a varuint.
fn varuint_len(mut val: u64) -> usize {
    let mut len = 0;
    loop {
        len += 1;
        val >>= 7;
        if val == 0 {
            break;
        }
    }
    len
}

/// Zigzag-encode a signed value to the unsigned form Go's
/// `encoding/binary.PutVarint` feeds to `PutUvarint`:
/// `ux := uint64(x) << 1; if x < 0 { ux = ^ux }`. All-unsigned arithmetic
/// (via `wrapping_shl`) so this never overflow-panics, even for
/// `i64::MIN`/`i64::MAX`.
fn zigzag_encode(v: i64) -> u64 {
    let ux = (v as u64).wrapping_shl(1);
    if v < 0 {
        !ux
    } else {
        ux
    }
}

/// Number of bytes `v` would occupy as a zigzag+ULEB128 branch offset --
/// matches Go's `binary.PutVarint`'s output length without allocating.
fn zigzag_varint_len(v: i64) -> usize {
    varuint_len(zigzag_encode(v))
}

/// Encode `v` as a zigzag+ULEB128 varint (Go's `binary.PutVarint`).
fn zigzag_varint_encode(v: i64) -> Vec<u8> {
    let mut buf = Vec::new();
    write_varuint_to_vec(&mut buf, zigzag_encode(v));
    buf
}

/// Replace `original_len` bytes starting at `index` in `s` with `new_bytes`.
fn replace_bytes(s: &mut Vec<u8>, index: usize, original_len: usize, new_bytes: &[u8]) {
    let tail = s[index + original_len..].to_vec();
    s.truncate(index);
    s.extend_from_slice(new_bytes);
    s.extend_from_slice(&tail);
}

// Simple hex encode fallback (since we may not have the `hex` crate)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd-length hex string".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_v2_program() {
        let source = "#pragma version 2\nint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(ops.version, 2);
        // Expected: version=2, intcblock [1], intc_0, return
        // v2 < v4, no optimization → intcblock prepended
        assert_eq!(ops.program[0], 2); // version
        assert_eq!(ops.program[1], 0x20); // intcblock
        assert_eq!(ops.program[2], 1); // count=1
        assert_eq!(ops.program[3], 1); // value=1
        assert_eq!(ops.program[4], 0x22); // intc_0
        assert_eq!(ops.program[5], 0x43); // return
        assert_eq!(ops.program.len(), 6);
    }

    #[test]
    fn test_v1_simple() {
        let source = "#pragma version 1\nint 1\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(ops.version, 1);
        assert_eq!(ops.program[0], 1);
        assert_eq!(ops.program[1], 0x20); // intcblock
        assert_eq!(ops.program[2], 1); // count=1
        assert_eq!(ops.program[3], 1); // value=1
        assert_eq!(ops.program[4], 0x22); // intc_0
    }

    /// `app_params_set` is App-mode only, but the assembler doesn't enforce
    /// mode at assembly time (that's the validator's job) -- this pins that
    /// the named-field immediate resolves to the correct byte (`fields::
    /// app_params_field_by_name`, `AppForeignBoxReads` = 11) end-to-end
    /// through `assemble_string`, matching go-algorand's `asmAppParamsSet`.
    // ── issue #830 Phase 17 missing-test sweep (parity_txn_logic.md),
    // ported from go-algorand's assembler_test.go ─────────────────────

    #[test]
    fn test_assemble_default_version_is_one() {
        // TestAssembleDefault: with no `#pragma version` line, the
        // assembler defaults to version 1 -- and type-checking still runs
        // at that default version, so `byte 0x...; int 1; +` (mixing a
        // []byte value into a uint64-only opcode) is still a type error.
        let source = "byte 0x1122334455\nint 1\n+\n";
        let errs = expect_errors(source);
        assert!(
            errs.iter()
                .any(|e| e.message.contains("+ arg 0 wanted type uint64")),
            "{errs:?}"
        );

        // Confirm the default version really is 1: a v2+-only opcode (e.g.
        // `txna`) used with no `#pragma version` must fail as "not
        // available" at v1, not merely fail differently for some other
        // reason.
        let errs = expect_errors("txna Accounts 0\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("txna") && e.message.contains("v2")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_assemble_base64_byte_literal() {
        // TestAssembleBase64: `byte base64 <lit>` and `byte b64 <lit>`
        // decode identically, produce the raw decoded bytes in the
        // assembled program, and round-trip through Disassemble ->
        // re-assemble to the same bytecode (mirrors testProg's own
        // round-trip check).
        use base64::Engine;
        let expected: Vec<u8> = (0u8..32).collect();
        let lit = base64::engine::general_purpose::STANDARD.encode(&expected);

        for keyword in ["base64", "b64"] {
            let source = format!("#pragma version 2\nbyte {keyword} {lit}\n");
            let ops = assemble_string(&source).unwrap();
            assert!(
                ops.program
                    .windows(expected.len())
                    .any(|w| w == expected.as_slice()),
                "decoded base64 bytes not found in assembled program for {keyword:?}: {:?}",
                ops.program
            );

            let dis = crate::disassembler::disassemble(&ops.program).unwrap();
            let ops2 = assemble_string(&dis).unwrap();
            assert_eq!(
                ops.program, ops2.program,
                "disassemble/reassemble round-trip mismatch for {keyword:?}"
            );
        }
    }

    // ── go-algorand's TestAssembleBase64 (assembler_test.go:1865),
    // issue #1382 ──
    // go's own fixture uses base64 literals that *start with*, contain,
    // and *end with* `//` (a legal base64 substring), interleaved with
    // real `//` line comments and a bare `==`/`&&`/`||` instruction
    // stream, to exercise the assembler's `inBase64` tracking end-to-end.
    // Previously this crate's `tokenize_line` had no `inBase64` tracking
    // at all, so a literal starting with `//` (not glued to a preceding
    // token) was misread as a comment start and silently truncated the
    // whole line. This locks the fix at the assemble level against go's
    // exact expected bytecode (both the default and constant-optimized
    // encodings).
    #[test]
    fn test_assemble_base64_byte_literal_containing_double_slash() {
        // Confirms tokenize_line's `inBase64` fix (issue #1382) also holds
        // at the assemble level: a base64 literal containing `//` -- as a
        // prefix, a suffix, or embedded via the paren form -- decodes to
        // exactly the expected bytes instead of being silently truncated
        // at the first `//` (which is a legal base64 substring, not a
        // comment start, inside such a literal).
        //
        // The byte values below were chosen (searching outputs of
        // `base64.b64encode`) purely so their encoding exercises `//` in
        // each position; go's own `TestAssembleBase64` fixture also does
        // this but with a hand-crafted literal whose non-canonical
        // padding bits this crate's stricter `base64` decoder rejects --
        // an unrelated base64-decode-leniency difference, not what this
        // test is about -- so real encode-derived (thus canonically
        // valid) literals are used here instead.
        let cases: [(&str, &[u8]); 3] = [
            ("byte base64 //AA", &[0xff, 0xf0, 0x00]), // `//` prefix, bare form
            ("byte base64 AA//", &[0x00, 0x0f, 0xff]), // `//` suffix, bare form
            ("byte b64(A//A)", &[0x03, 0xff, 0xc0]),   // `//` embedded, paren form
        ];
        for (line, expected) in cases {
            let source = format!("#pragma version 2\n{line}\n");
            let ops = assemble_string(&source).unwrap_or_else(|e| panic!("{line:?}: {e:?}"));
            assert!(
                ops.program.windows(expected.len()).any(|w| w == expected),
                "{line:?}: expected {expected:?} bytes not found in {:?}",
                ops.program
            );
        }
    }

    #[test]
    fn test_assemble_versions_txna_gating() {
        // TestAssembleVersions: `txna Accounts 0` assembles at v2+ (it was
        // introduced in v2) and is rejected with a "introduced in v2"-style
        // message at v1.
        assemble_string("#pragma version 2\ntxna Accounts 0\n").unwrap();
        let errs = expect_errors("#pragma version 1\ntxna Accounts 0\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("txna") && e.message.contains("v2")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_assemble_asset_holding_get_argument_errors() {
        // TestAssembleAsset: asset_holding_get / asset_params_get
        // assembler-level error paths -- wrong stack height, wrong
        // immediate-argument count, unknown field name, and (the class of
        // misuse this test used to flag as a real parity gap, now fixed by
        // `type_track.rs`'s `asset_holding_get`/`asset_params_get` refine
        // arms) a wrong *stack-argument type*.
        for v in 2..=13u8 {
            let errs = expect_errors(&format!("#pragma version {v}\nasset_holding_get ABC 1\n"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("expects 2 stack arguments")),
                "v{v}: {errs:?}"
            );

            let errs = expect_errors(&format!(
                "#pragma version {v}\nint 1\nasset_holding_get ABC 1\n"
            ));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("expects 2 stack arguments")),
                "v{v}: {errs:?}"
            );

            let errs = expect_errors(&format!(
                "#pragma version {v}\nint 1\nint 1\nasset_holding_get ABC 1\n"
            ));
            assert!(
                errs.iter().any(|e| e
                    .message
                    .contains("asset_holding_get expects 1 immediate argument")),
                "v{v}: {errs:?}"
            );

            let errs = expect_errors(&format!(
                "#pragma version {v}\nint 1\nint 1\nasset_holding_get ABC\n"
            ));
            assert!(
                errs.iter().any(|e| e
                    .message
                    .contains("asset_holding_get unknown field: \"ABC\"")),
                "v{v}: {errs:?}"
            );

            // asset_params_get's popped asset-id argument must be uint64,
            // not []byte -- trackStack runs *before* the immediate-count
            // check (`spec.asm`/`asmDefault`'s `checkArgCount`), so this
            // type mismatch is reported even though "ABC 1" is also the
            // wrong immediate-argument count for asset_params_get.
            let errs = expect_errors(&format!(
                "#pragma version {v}\nbyte 0x1234\nasset_params_get ABC 1\n"
            ));
            assert!(
                errs.iter().any(|e| e
                    .message
                    .contains("asset_params_get ABC 1 arg 0 wanted type uint64")),
                "v{v}: {errs:?}"
            );

            // AssetUnitName is known (via the field-based return-type
            // refinement) to push []byte, not uint64.
            let errs = expect_errors(&format!(
                "#pragma version {v}\nint 1\nasset_params_get AssetUnitName\npop\nint 1\n+\n"
            ));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("+ arg 0 wanted type uint64")),
                "v{v}: {errs:?}"
            );

            // AssetTotal is known to push uint64, not []byte.
            let errs = expect_errors(&format!(
                "#pragma version {v}\nint 1\nasset_params_get AssetTotal\npop\nbyte 0x12\nconcat\n"
            ));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("concat arg 0 wanted type []byte")),
                "v{v}: {errs:?}"
            );

            // testLine-style: "int 1" first supplies asset_params_get's
            // single stack argument, isolating the immediate-count / unknown
            // -field errors from any stack-height/type error.
            let errs = expect_errors(&format!(
                "#pragma version {v}\nint 1\nasset_params_get ABC 1\nint 1\n"
            ));
            assert!(
                errs.iter().any(|e| e
                    .message
                    .contains("asset_params_get expects 1 immediate argument")),
                "v{v}: {errs:?}"
            );

            let errs = expect_errors(&format!(
                "#pragma version {v}\nint 1\nasset_params_get ABC\nint 1\n"
            ));
            assert!(
                errs.iter().any(|e| e
                    .message
                    .contains("asset_params_get unknown field: \"ABC\"")),
                "v{v}: {errs:?}"
            );
        }
    }

    #[test]
    fn test_assemble_asset_holding_get_direct_ref_version_gating() {
        // TestAssembleAsset (via evalStateful_test.go's directRefEnabledVersion
        // split): below v4, asset_holding_get's account argument is a
        // foreign-accounts-array index (uint64 only); a []byte direct
        // address reference is a type error. From v4 on, a []byte account
        // reference is accepted (proto widens to `Any`).
        let errs = expect_errors(
            "#pragma version 3\nbyte 0x1234\nint 1\nasset_holding_get AssetBalance\n",
        );
        assert!(
            errs.iter()
                .any(|e| e.message.contains("arg 0 wanted type uint64")),
            "{errs:?}"
        );

        assemble_string("#pragma version 4\nbyte 0x1234\nint 1\nasset_holding_get AssetBalance\n")
            .expect("v4+ accepts a []byte direct account reference");
    }

    #[test]
    fn test_assemble_app_params_get_and_acct_params_get_return_type_refinement() {
        // TestAssembleAsset's asset_params_get field-type-refinement pattern
        // extended to app_params_get / acct_params_get (same
        // `type_track.rs` refine arms).
        let errs = expect_errors(
            "#pragma version 13\nint 1\napp_params_get AppApprovalProgram\npop\nint 1\n+\n",
        );
        assert!(
            errs.iter()
                .any(|e| e.message.contains("+ arg 0 wanted type uint64")),
            "{errs:?}"
        );

        let errs = expect_errors(
            "#pragma version 13\nint 1\napp_params_get AppGlobalNumUint\npop\nbyte 0x12\nconcat\n",
        );
        assert!(
            errs.iter()
                .any(|e| e.message.contains("concat arg 0 wanted type []byte")),
            "{errs:?}"
        );

        // acct_params_get's popped account argument must overlap `Any`
        // (always true), but its returned value is refined per field:
        // AcctAuthAddr pushes []byte, not uint64.
        let errs = expect_errors(
            "#pragma version 13\nint 1\nacct_params_get AcctAuthAddr\npop\nint 1\n+\n",
        );
        assert!(
            errs.iter()
                .any(|e| e.message.contains("+ arg 0 wanted type uint64")),
            "{errs:?}"
        );

        // app_params_get's popped app-id argument must be uint64, not
        // []byte.
        let errs = expect_errors("#pragma version 13\nbyte 0x1234\napp_params_get AppCreator\n");
        assert!(
            errs.iter().any(|e| e
                .message
                .contains("app_params_get AppCreator arg 0 wanted type uint64")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_disassemble_single_op_no_duplicate_arg_0_entries() {
        // TestDisassembleSingleOp: disassembling a program that is *only*
        // `arg_0` must not produce a doubled/garbled `arg_0` entry in the
        // output, and the disassembly must reassemble back to the same
        // bytecode.
        for v in 1..=13u8 {
            let source = format!("#pragma version {v}\narg_0\n");
            let ops = assemble_string(&source).unwrap();
            let dis = crate::disassembler::disassemble(&ops.program).unwrap();
            assert_eq!(
                dis.matches("arg_0").count(),
                1,
                "v{v}: expected exactly one arg_0 entry in disassembly, got: {dis:?}"
            );
            let ops2 = assemble_string(&dis).unwrap();
            assert_eq!(ops.program, ops2.program, "v{v}: round-trip mismatch");
        }
    }

    #[test]
    fn test_disassemble_last_label_round_trips() {
        // TestDisassembleLastLabel: a label as the very last line of a
        // program (nothing after it) must disassemble and reassemble
        // cleanly -- the disassembler still emits the trailing label even
        // though no instruction follows it.
        for v in 2..=13u8 {
            let source = format!("#pragma version {v}\nintcblock 1\nintc_0\nbnz label1\nlabel1:\n");
            let ops = assemble_string(&source).unwrap();
            let dis = crate::disassembler::disassemble(&ops.program).unwrap();
            assert!(
                dis.contains("label1:"),
                "v{v}: expected trailing label in disassembly: {dis:?}"
            );
            let ops2 = assemble_string(&dis).unwrap();
            assert_eq!(ops.program, ops2.program, "v{v}: round-trip mismatch");
        }
    }

    #[test]
    fn test_app_params_set_foreign_box_reads_assembles() {
        let source = "#pragma version 13\nint 1\napp_params_set AppForeignBoxReads\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(ops.version, 13);
        // pushint 1 (single reference -> pushint, no intcblock), then
        // app_params_set with immediate byte 11 (AppForeignBoxReads).
        assert_eq!(&ops.program[..], &[13, 0x81, 0x01, 0x76, 0x0b]);
    }

    #[test]
    fn test_app_params_set_family_box_access_assembles() {
        let source = "#pragma version 13\nint 0\napp_params_set AppFamilyBoxAccess\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(&ops.program[..], &[13, 0x81, 0x00, 0x76, 0x0c]);
    }

    // -----------------------------------------------------------------------
    // app_box_* foreign-box opcodes (prefix 0xd4, issue #662): the assembler
    // must emit the two-byte prefix+sub-opcode header for these mnemonics,
    // matching go-algorand's `OpDetails.SubOpcode` two-byte encoding.
    // -----------------------------------------------------------------------

    #[test]
    fn test_app_box_create_assembles_two_byte_header() {
        let source = "#pragma version 13\nint 7\nbyte \"k\"\nint 10\napp_box_create\n";
        let ops = assemble_string(source).unwrap();
        // version, pushint 7, pushbytes "k", pushint 10, then 0xd4 0x01.
        assert_eq!(ops.program[ops.program.len() - 2..], [0xd4, 0x01]);
    }

    #[test]
    fn test_app_box_put_assembles_two_byte_header() {
        let source = "#pragma version 13\nint 7\nbyte \"k\"\nbyte \"v\"\napp_box_put\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(ops.program[ops.program.len() - 2..], [0xd4, 0x07]);
    }

    #[test]
    fn test_app_box_mnemonic_rejects_immediate_args() {
        // app_box_get takes no assembler-level immediate arguments (all its
        // operands are stack args) -- passing one must be a hard error, not
        // silently accepted.
        let source = "#pragma version 13\napp_box_get 5\n";
        let result = assemble_string(source);
        assert!(result.is_err());
    }

    #[test]
    fn test_app_box_create_below_v13_rejected() {
        let source = "#pragma version 12\nint 7\nbyte \"k\"\nint 10\napp_box_create\n";
        match assemble_string(source) {
            Ok(_) => panic!("expected a version error"),
            Err(errs) => assert!(
                errs.iter().any(|e| e.message.contains("v13")),
                "{:?}",
                errs.iter().map(|e| &e.message).collect::<Vec<_>>()
            ),
        }
    }

    #[test]
    fn test_labels_and_branches() {
        let source = "#pragma version 2\nb end\nint 0\nend:\nint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(ops.version, 2);
        // The program should have a branch to the label 'end'
        assert!(!ops.program.is_empty());
    }

    #[test]
    fn test_byte_hex() {
        let source = "#pragma version 2\nbyte 0x0102\npop\nint 1\n";
        let ops = assemble_string(source).unwrap();
        assert!(ops.program.len() > 2);
    }

    #[test]
    fn test_byte_string() {
        let source = "#pragma version 2\nbyte \"hello\"\npop\nint 1\n";
        let ops = assemble_string(source).unwrap();
        assert!(ops.program.len() > 2);
    }

    #[test]
    fn test_constant_optimization_v4() {
        // v4+ should optimize constants
        let source = "#pragma version 4\nint 1\nint 2\nint 1\n+\n+\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(ops.version, 4);
        // int 1 is used twice → goes into intcblock
        // int 2 is used once → pushed via pushint
        assert!(!ops.program.is_empty());
    }

    #[test]
    fn test_global_field() {
        let source = "#pragma version 2\nglobal MinTxnFee\n";
        let ops = assemble_string(source).unwrap();
        // global opcode = 0x32, field MinTxnFee = 0
        let prog = &ops.program;
        // Find the global opcode
        let pos = prog.iter().position(|&b| b == 0x32).unwrap();
        assert_eq!(prog[pos + 1], 0); // MinTxnFee = 0
    }

    #[test]
    fn test_txn_field() {
        let source = "#pragma version 2\ntxn Sender\n";
        let ops = assemble_string(source).unwrap();
        let pos = ops.program.iter().position(|&b| b == 0x31).unwrap();
        assert_eq!(ops.program[pos + 1], 0); // Sender = 0
    }

    // ── Field-group version gating (issue #1403) ────────────────────────
    // go-algorand's assembler statically rejects a field-group immediate
    // (a `global`/`txn`/`itxn_field`/... field name) whose spec version is
    // newer than the program's declared `#pragma version`
    // (`assembler.go:1240-1245`, "%s %s field was introduced in v%d. Missed
    // #pragma version?"). algod-rust previously resolved the field byte
    // without ever checking this.

    #[test]
    fn test_global_field_too_new_for_pragma_version_rejected() {
        // OpcodeBudget is a GlobalField introduced at v6.
        let errs = expect_errors("#pragma version 1\nglobal OpcodeBudget\n");
        assert!(
            errs.iter().any(|e| e.message
                == "global OpcodeBudget field was introduced in v6. Missed #pragma version?"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_txn_field_too_new_for_pragma_version_rejected() {
        // StateProofPK is a TxnField introduced at v6.
        let errs = expect_errors("#pragma version 2\ntxn StateProofPK\n");
        assert!(
            errs.iter().any(|e| e.message
                == "txn StateProofPK field was introduced in v6. Missed #pragma version?"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_itxn_field_too_new_for_pragma_version_rejected() {
        // VotePK became settable via itxn_field at itxVersion 6 (TxnField's
        // `itx_version`, not `version` -- but itxn_field's dispatch reuses
        // TxnField::version() for the assemble-time gate here, same as
        // `txn`, so a field whose *read* version is already >= the pragma
        // is what this test needs; RejectVersion (v12) covers that cleanly
        // for itxn_field too.
        let errs = expect_errors("#pragma version 6\nitxn_field RejectVersion\n");
        assert!(
            errs.iter().any(|e| e.message
                == "itxn_field RejectVersion field was introduced in v12. Missed #pragma version?"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_acct_params_get_field_too_new_for_pragma_version_rejected() {
        // AcctIncentiveEligible is an AcctParamsField introduced at v11
        // (incentiveVersion); acct_params_get itself exists from v6.
        let errs =
            expect_errors("#pragma version 6\nint 0\nacct_params_get AcctIncentiveEligible\n");
        assert!(
            errs.iter().any(|e| e.message
                == "acct_params_get AcctIncentiveEligible field was introduced in v11. Missed #pragma version?"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_asset_params_get_field_too_new_for_pragma_version_rejected() {
        // AssetCreator is an AssetParamsField introduced at v5;
        // asset_params_get itself exists from v2.
        let errs = expect_errors("#pragma version 2\nint 0\nasset_params_get AssetCreator\n");
        assert!(
            errs.iter().any(|e| e.message
                == "asset_params_get AssetCreator field was introduced in v5. Missed #pragma version?"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_ecdsa_curve_too_new_for_pragma_version_rejected() {
        // Secp256r1 was added at fidoVersion (7); ecdsa_pk_decompress itself
        // exists from v5.
        let source =
            "#pragma version 5\nbyte 0x0102030405060708090a0b0c0d0e0f10111213141516171819202122232425\necdsa_pk_decompress Secp256r1\n";
        let errs = expect_errors(source);
        assert!(
            errs.iter().any(|e| e.message
                == "ecdsa_pk_decompress Secp256r1 field was introduced in v7. Missed #pragma version?"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_field_at_or_below_pragma_version_still_assembles() {
        // Sanity: fields introduced at-or-before the declared version, and
        // opcodes/fields shared across versions, must keep assembling.
        for source in [
            "#pragma version 6\nglobal OpcodeBudget\n",
            "#pragma version 12\ntxn StateProofPK\n",
            "#pragma version 12\nint 1\nitxn_field RejectVersion\n",
            "#pragma version 11\nint 0\nacct_params_get AcctIncentiveEligible\n",
            "#pragma version 5\nint 0\nasset_params_get AssetCreator\n",
        ] {
            assert!(
                assemble_string(source).is_ok(),
                "expected {source:?} to assemble cleanly"
            );
        }
    }

    /// Ported from go-algorand's `TestBackwardCompatGlobalFields`
    /// (`data/transactions/logic/backwardCompat_test.go`): every
    /// `GlobalField` introduced after v1 must be rejected by the assembler
    /// at every version below its introduction, with go's exact
    /// "was introduced in vN. Missed #pragma version?" message. This covers
    /// the assemble-time half of the go test (the runtime `EvalSignature`
    /// half -- "invalid global field" -- is already covered by `op_global`'s
    /// existing runtime version check and its own tests).
    #[test]
    fn test_backward_compat_global_fields_exhaustive_sweep_ported_from_go() {
        let mut swept = 0;
        for index in 0u8..=u8::MAX {
            let Ok(field) = fields::GlobalField::from_u8(index) else {
                continue;
            };
            let version = field.version();
            if version <= 1 {
                continue;
            }
            let name = fields::global_field_name(index).expect("named field must have a name");
            swept += 1;
            for v in 1..version {
                let source = format!("#pragma version {v}\nglobal {name}\n");
                let errs = expect_errors(&source);
                let expected = format!(
                    "global {name} field was introduced in v{version}. Missed #pragma version?"
                );
                assert!(
                    errs.iter().any(|e| e.message == expected),
                    "v{v} global {name}: expected {expected:?}, got {errs:?}"
                );
            }
            // At exactly the introduction version, it must assemble.
            let source = format!("#pragma version {version}\nglobal {name}\n");
            assert!(
                assemble_string(&source).is_ok(),
                "expected {source:?} to assemble cleanly"
            );
        }
        assert!(
            swept > 1,
            "expected more than one post-v1 GlobalField to be swept"
        );
    }

    /// Ported from go-algorand's `TestBackwardCompatTxnFields`
    /// (`data/transactions/logic/backwardCompat_test.go`): every
    /// (non-array) `TxnField` introduced after v1 must be rejected by the
    /// assembler, via both `txn` and `gtxn 0`, at every version below its
    /// introduction. Array fields (`Accounts`, `Applications`, etc.) are
    /// excluded: go itself asserts a different, array-specific arity error
    /// for those when used in scalar form ("field of %s can only be used
    /// with N immediates"), which algod-rust doesn't yet implement -- a
    /// separate, pre-existing gap outside this issue's scope.
    #[test]
    fn test_backward_compat_txn_fields_exhaustive_sweep_ported_from_go() {
        let mut swept = 0;
        for index in 0u8..=u8::MAX {
            let Ok(field) = fields::TxnField::from_u8(index) else {
                continue;
            };
            if field.is_array() {
                continue;
            }
            let version = field.version();
            if version <= 1 {
                continue;
            }
            let name = field.to_string();
            swept += 1;
            for (op_text, mnemonic) in [
                (format!("txn {name}"), "txn"),
                (format!("gtxn 0 {name}"), "gtxn"),
            ] {
                for v in 1..version {
                    let source = format!("#pragma version {v}\n{op_text}\n");
                    let errs = expect_errors(&source);
                    let expected = format!(
                        "{mnemonic} {name} field was introduced in v{version}. Missed #pragma version?"
                    );
                    assert!(
                        errs.iter().any(|e| e.message == expected),
                        "v{v} {op_text:?}: expected {expected:?}, got {errs:?}"
                    );
                }
                // At exactly the introduction version, it must assemble.
                let source = format!("#pragma version {version}\n{op_text}\n");
                assert!(
                    assemble_string(&source).is_ok(),
                    "expected {source:?} to assemble cleanly"
                );
            }
        }
        assert!(
            swept > 1,
            "expected more than one post-v1 non-array TxnField to be swept"
        );
    }

    #[test]
    fn test_error_unknown_opcode() {
        let source = "#pragma version 2\nfoobar\n";
        let result = assemble_string(source);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_missing_label() {
        let source = "#pragma version 2\nb nonexistent\n";
        let result = assemble_string(source);
        assert!(result.is_err());
    }

    // ── Assembler-time error-message parity (issue #823 theme 4), ported
    // from go-algorand's assembler_test.go ─────────────────────────────

    /// `assemble_string` should fail for `source`; return the collected
    /// errors. `OpStream` isn't `Debug`, so this avoids `.unwrap_err()`.
    fn expect_errors(source: &str) -> Vec<AssemblyError> {
        match assemble_string(source) {
            Err(errs) => errs,
            Ok(_) => panic!("expected assembly to fail for {source:?}"),
        }
    }

    #[test]
    fn test_error_duplicate_label() {
        // TestAssembleRejectDupLabel: a second definition of the same
        // label is rejected, with the label name in the message.
        let source = "#pragma version 8\nXXX: int 1; pop\nXXX: int 1; pop\nint 1\n";
        let errs = expect_errors(source);
        assert!(
            errs.iter()
                .any(|e| e.message.contains("duplicate label") && e.message.contains("XXX")),
            "expected a duplicate-label error, got: {errs:?}"
        );
    }

    #[test]
    fn test_error_branch_args_wrong_immediate_count() {
        // TestBranchArgs: `b`/`bz`/`bnz`/`callsub` each require exactly one
        // immediate argument (a single label).
        for (source, mnemonic) in [
            ("#pragma version 8\nb\n", "b"),
            ("#pragma version 8\nb lab1 lab2\n", "b"),
            ("#pragma version 8\nint 1; bz\n", "bz"),
            ("#pragma version 8\nint 1; bz a b\n", "bz"),
            ("#pragma version 8\nint 1; bnz\n", "bnz"),
            ("#pragma version 8\nint 1; bnz c d\n", "bnz"),
            ("#pragma version 8\ncallsub\n", "callsub"),
            ("#pragma version 8\ncallsub one two\n", "callsub"),
        ] {
            let errs = expect_errors(source);
            let expected = format!("{mnemonic} expects 1 immediate argument");
            assert!(
                errs.iter().any(|e| e.message == expected),
                "source {source:?}: expected {expected:?}, got: {errs:?}"
            );
        }
    }

    #[test]
    fn test_error_arg_wrong_immediate_count() {
        // TestAssembleArg: `arg` with no immediate is rejected up front.
        let errs = expect_errors("#pragma version 8\narg\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "arg expects 1 immediate argument"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_arg_unparseable_immediate_reports_parse_error() {
        // TestAssembleArg's second case: `arg x` (a non-numeric immediate)
        // is rejected with a parse-failure message rather than being
        // silently accepted or reported as a generic "unknown field" error
        // -- go's message is "unable to parse argument...".
        let errs = expect_errors("#pragma version 8\narg x\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("arg") && e.message.contains("unable to parse")),
            "arg x: expected an 'unable to parse' error, got: {errs:?}"
        );
    }

    #[test]
    fn test_immediate_ranges_load_store_ok() {
        // TestAssembleImmediateRanges: values within range assemble fine.
        // `store`'s immediate is an unsigned byte, so 0 is in range;
        // `load`'s max is 255.
        assert!(assemble_string("#pragma version 8\nint 1; store 0;\n").is_ok());
        assert!(assemble_string("#pragma version 8\nload 255;\n").is_ok());
    }

    #[test]
    fn test_immediate_ranges_load_store_out_of_range() {
        // TestAssembleImmediateRanges: go's `byteImm` (assembler.go:1087)
        // parses `load`/`store`'s scratch-slot immediate with
        // `strconv.ParseUint` -- unsigned only, 0..=255. A negative literal
        // must fail to parse (not wrap into the u8 range, e.g. `load -100`
        // must NOT silently become `load 156`), and a value over 255 is a
        // distinct "beyond 255" error.
        let errs = expect_errors("#pragma version 8\nint 1; store -1000;\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("store") && e.message.contains("unable to parse")),
            "store -1000: expected an 'unable to parse' error, got: {errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nload -100;\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("load") && e.message.contains("unable to parse")),
            "load -100: expected an 'unable to parse' error, got: {errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 1; store 256;\n");
        assert!(
            errs.iter().any(|e| e.message == "store i beyond 255: 256"),
            "store 256: expected 'store i beyond 255: 256', got: {errs:?}"
        );
    }

    #[test]
    fn test_immediate_ranges_frame_dig_bury_ok() {
        // TestAssembleImmediateRanges: frame_dig/frame_bury take a signed
        // int8 immediate (-128..=127); the full range assembles fine.
        assert!(assemble_string("#pragma version 8\nframe_dig -1;\n").is_ok());
        assert!(assemble_string("#pragma version 8\nframe_dig 127;\n").is_ok());
        assert!(assemble_string("#pragma version 8\nint 1; frame_bury -128;\n").is_ok());
    }

    #[test]
    fn test_immediate_ranges_frame_dig_bury_out_of_range() {
        // TestAssembleImmediateRanges: go's `int8Imm` (assembler.go:1098)
        // parses with `strconv.ParseInt(value, 10, 8)`, which itself
        // rejects anything outside -128..=127 -- `frame_dig 128` and
        // `frame_bury -129` must be rejected at assembly time, not
        // silently accepted with a truncated/wrapped immediate byte.
        let errs = expect_errors("#pragma version 8\nframe_dig 128;\n");
        assert!(
            errs.iter().any(
                |e| e.message.starts_with("frame_dig") && e.message.contains("unable to parse")
            ),
            "frame_dig 128: expected an 'unable to parse' error, got: {errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 1; frame_bury -129;\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("frame_bury")
                    && e.message.contains("unable to parse")),
            "frame_bury -129: expected an 'unable to parse' error, got: {errs:?}"
        );
    }

    #[test]
    fn test_several_errors_all_reported() {
        // TestSeveralErrors: an undefined-label reference and an unknown
        // txn field on separate lines are BOTH reported in one pass, not
        // just the first one encountered.
        let source = "#pragma version 8\nint 1\nbnz nowhere\ntxn XYZ\nint 2\n";
        let errs = expect_errors(source);
        assert!(
            errs.iter()
                .any(|e| e.message.contains("undefined label") && e.message.contains("nowhere")),
            "missing undefined-label error: {errs:?}"
        );
        assert!(
            errs.len() > 1,
            "expected multiple errors to be collected, got: {errs:?}"
        );
    }

    // ── `txn`/`gtxn`/`gtxns` pseudo-op arity dispatch (issue #877), ported
    // from go-algorand's TestAssembleTxna (assembler_test.go:1063) ──────

    #[test]
    fn test_txn_pseudo_arity_dispatches_to_array_opcode() {
        // `txn Field i` (2 immediates) assembles identically to
        // `txna Field i` -- go-algorand's pseudoOps table dispatches "txn"
        // to the real `txna` opcode based purely on immediate count
        // (assembler.go:1811).
        let txn = assemble_string("#pragma version 8\ntxn Accounts 0\n").unwrap();
        let txna = assemble_string("#pragma version 8\ntxna Accounts 0\n").unwrap();
        assert_eq!(txn.program, txna.program);

        // `gtxn t Field i` (3 immediates) -> `gtxna` (assembler.go:1812).
        let gtxn = assemble_string("#pragma version 8\ngtxn 0 Accounts 1\n").unwrap();
        let gtxna = assemble_string("#pragma version 8\ngtxna 0 Accounts 1\n").unwrap();
        assert_eq!(gtxn.program, gtxna.program);

        // `gtxns Field i` (2 immediates) -> `gtxnsa` (assembler.go:1813).
        // `gtxns`/`gtxnsa` both pop a dynamic uint64 transaction index off
        // the stack (issue #829, slice 6's `TYPE_TABLE` entry), so a
        // priming `int 0` is needed here -- without it, either form is
        // itself a genuine type error at program start (go's own
        // `bottom.AVMType == avmNone` height check; see `testLine`'s
        // `"int 1\n" + line + "\nint 1\n"` wrapping in `assembler_test.go`,
        // which every real go-algorand single-line test relies on for the
        // same reason).
        let gtxns = assemble_string("#pragma version 8\nint 0\ngtxns Accounts 0\npop\n").unwrap();
        let gtxnsa = assemble_string("#pragma version 8\nint 0\ngtxnsa Accounts 0\npop\n").unwrap();
        assert_eq!(gtxns.program, gtxnsa.program);
    }

    #[test]
    fn test_txn_pseudo_arity_scalar_form_still_works() {
        // The 1-/2-/1-immediate scalar forms (real `txn`/`gtxn`/`gtxns`)
        // must keep working unchanged once the pseudo-op dispatch is added.
        let txn = assemble_string("#pragma version 8\ntxn Sender\n").unwrap();
        assert!(!txn.program.is_empty());

        let gtxn = assemble_string("#pragma version 8\ngtxn 0 Sender\n").unwrap();
        assert!(!gtxn.program.is_empty());

        // `gtxns` (proto "i:a") pops a dynamic uint64 index -- see the
        // priming-value note on `test_txn_pseudo_arity_dispatches_to_array_opcode`.
        let gtxns = assemble_string("#pragma version 8\nint 0\ngtxns Sender\npop\n").unwrap();
        assert!(!gtxns.program.is_empty());
    }

    #[test]
    fn test_txn_pseudo_arity_wrong_immediate_count_errors() {
        // TestAssembleTxna: an immediate count matching neither arity in the
        // pseudoOps table is rejected with a combined "N or M" message
        // (go's joinIntsOnOr, assembler.go:1699-1730).
        for (source, expected) in [
            (
                "#pragma version 8\ntxn\n",
                "txn expects 1 or 2 immediate arguments",
            ),
            (
                "#pragma version 8\ntxn Accounts 0 1\n",
                "txn expects 1 or 2 immediate arguments",
            ),
            (
                "#pragma version 8\ngtxn 0 Sender 1 2\n",
                "gtxn expects 2 or 3 immediate arguments",
            ),
            (
                "#pragma version 8\ngtxn 0 Accounts 1 2\n",
                "gtxn expects 2 or 3 immediate arguments",
            ),
        ] {
            let errs = expect_errors(source);
            assert!(
                errs.iter().any(|e| e.message == expected),
                "source {source:?}: expected {expected:?}, got: {errs:?}"
            );
        }
    }

    #[test]
    fn test_txn_pseudo_arity_version_gating() {
        // TestAssembleTxna: the array-form dispatch target is only
        // available once its own opcode version is reached, and the error
        // names the *pseudo* mnemonic plus how many immediates were given
        // (assembler.go:1756-1759).
        let errs = expect_errors("#pragma version 1\ntxn Accounts 0\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "txn opcode with 2 immediates was introduced in v2"),
            "unexpected errors: {errs:?}"
        );

        let errs = expect_errors("#pragma version 1\ngtxn 0 Sender 0\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "gtxn opcode with 3 immediates was introduced in v2"),
            "unexpected errors: {errs:?}"
        );
    }

    // ── `replace` pseudo-op arity dispatch (issue #945), ported from
    // go-algorand's TestReplacePseudo (assembler_test.go:3553) ───────────

    #[test]
    fn test_replace_pseudo_immediate_dispatches_to_replace2() {
        // `replace N` (1 immediate) assembles identically to `replace2 N`
        // -- go's pseudoOps table dispatches "replace" to the real
        // `replace2` opcode based purely on immediate count
        // (assembler.go:1815).
        let replace =
            assemble_string("#pragma version 8\nbyte 0x0000\nbyte 0x1234\nreplace 0\n").unwrap();
        let replace2 =
            assemble_string("#pragma version 8\nbyte 0x0000\nbyte 0x1234\nreplace2 0\n").unwrap();
        assert_eq!(replace.program, replace2.program);
    }

    #[test]
    fn test_replace_pseudo_no_immediate_dispatches_to_replace3() {
        // `replace` (0 immediates, offset comes off the stack) assembles
        // identically to `replace3` (assembler.go:1815).
        let replace =
            assemble_string("#pragma version 8\nbyte 0x0000\nint 0\nbyte 0x1234\nreplace\n")
                .unwrap();
        let replace3 =
            assemble_string("#pragma version 8\nbyte 0x0000\nint 0\nbyte 0x1234\nreplace3\n")
                .unwrap();
        assert_eq!(replace.program, replace3.program);
    }

    #[test]
    fn test_replace_pseudo_wrong_arity_errors() {
        // TestReplacePseudo: an immediate count matching neither arity in
        // the pseudoOps table is rejected with a combined "N or M" message,
        // reported under the arg-height check for the 3-stack-argument
        // form when no immediate was given at all but the stack is short.
        let errs = expect_errors("#pragma version 8\nbyte 0x0000\nbyte 0x1234\nreplace\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "replace expects 3 stack arguments but stack height is 2"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_replace_pseudo_type_error_uses_pseudo_mnemonic() {
        // TestReplacePseudo: `replace 0` with a non-`[]byte` argument on
        // top of the stack (a `Uint64` from a stray `int 0`) is a type
        // error reported under the pseudo mnemonic "replace 0", not the
        // dispatched-to opcode's own name.
        let errs = expect_errors("#pragma version 8\nbyte 0x0000\nint 0\nbyte 0x1234\nreplace 0\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "replace 0 arg 0 wanted type []byte got uint64"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_replace_pseudo_version_gating() {
        // `replace`/`replace2`/`replace3` were introduced in v7 -- using
        // the pseudo-op below that version is rejected the same way
        // `txn`/`gtxn`'s array-form dispatch is (`asm_pseudo_arity`).
        let errs = expect_errors("#pragma version 6\nbyte 0x0000\nbyte 0x1234\nreplace 0\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "replace opcode with 1 immediate was introduced in v7"),
            "unexpected errors: {errs:?}"
        );
    }

    // ── `extract` pseudo-op arity dispatch (issue #1388) ──────────────────
    // go's pseudoOps table (assembler.go:1814) dispatches bare `extract` (0
    // immediates, start/length come off the stack) to the real `extract3`
    // opcode, and `extract N M` (2 immediates) to the real `extract` opcode.

    #[test]
    fn test_extract_pseudo_no_immediates_dispatches_to_extract3() {
        let extract =
            assemble_string("#pragma version 8\nbyte 0x0000\nint 0\nint 1\nextract\n").unwrap();
        let extract3 =
            assemble_string("#pragma version 8\nbyte 0x0000\nint 0\nint 1\nextract3\n").unwrap();
        assert_eq!(extract.program, extract3.program);
    }

    #[test]
    fn test_extract_pseudo_two_immediates_dispatches_to_extract() {
        // `extract N M` (2 immediates) assembles as the real 2-immediate
        // `extract` opcode (byte 0x57), not `extract3` (byte 0x58).
        let extract = assemble_string("#pragma version 8\nbyte 0x0000\nextract 0 1\n").unwrap();
        assert!(
            extract.program.contains(&0x57),
            "program: {:?}",
            extract.program
        );
        assert!(
            !extract.program.contains(&0x58),
            "program: {:?}",
            extract.program
        );
    }

    #[test]
    fn test_extract_pseudo_wrong_arity_errors() {
        // An immediate count matching neither arity (1 immediate) in the
        // pseudoOps table is rejected with a combined "N or M" message.
        let errs = expect_errors("#pragma version 8\nbyte 0x0000\nextract 0\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "extract expects 0 or 2 immediate arguments"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_extract_pseudo_version_gating() {
        // `extract`/`extract3` were introduced in v5.
        let errs = expect_errors("#pragma version 4\nbyte 0x0000\nextract 0 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "extract opcode with 2 immediates was introduced in v5"),
            "unexpected errors: {errs:?}"
        );
    }

    // ── `#define` macro expansion (issue #945), ported from go-algorand's
    // TestMacros (assembler_test.go:3673) ────────────────────────────────

    #[test]
    fn test_macro_basic_single_token_substitution() {
        let with_macro = assemble_string(
            "#pragma version 8\n#define none 0\n#define one 1\npushint none\npushint one\n+\n",
        )
        .unwrap();
        let without_macro =
            assemble_string("#pragma version 8\npushint 0\npushint 1\n+\n").unwrap();
        assert_eq!(with_macro.program, without_macro.program);
    }

    #[test]
    fn test_macro_body_containing_semicolon_splits_statement() {
        // `#define ==? ==; bnz` -- the macro body itself contains a `;`,
        // so a single textual `==? label1` usage expands into *two*
        // statements: `==` then `bnz label1`. This is the case that rules
        // out expanding macros only after a line has already been split
        // into `;`-delimited statements at the character level.
        let with_macro = assemble_string(
            "#pragma version 8\n#define ==? ==; bnz\npushint 1\npushint 2\n==? label1\nerr\nlabel1:\npushint 1\n",
        )
        .unwrap();
        let without_macro = assemble_string(
            "#pragma version 8\npushint 1\npushint 2\n==\nbnz label1\nerr\nlabel1:\npushint 1\n",
        )
        .unwrap();
        assert_eq!(with_macro.program, without_macro.program);
    }

    #[test]
    fn test_macro_redefinition_and_chaining() {
        // Redefining a macro after it's already been used elsewhere picks
        // up the new definition for later uses (macros are expanded at
        // each *use* site, not resolved once at definition time), and one
        // macro's body can itself reference other macros.
        let with_macro = assemble_string(
            "#pragma version 8\n#define rowSize 3\n#define columnSize 5\n#define tableDimensions rowSize columnSize\npushbytes 0x100000000000\nsubstring tableDimensions\n#define rowSize 0\n#define columnSize 1\nsubstring tableDimensions\n",
        )
        .unwrap();
        let without_macro = assemble_string(
            "#pragma version 8\npushbytes 0x100000000000\nsubstring 3 5\nsubstring 0 1\n",
        )
        .unwrap();
        assert_eq!(with_macro.program, without_macro.program);
    }

    #[test]
    fn test_macro_self_reference_is_a_cycle() {
        // `#define X X` -- go's TestMacros: a macro whose own body refers
        // to itself is rejected as a cycle at define time, and later use
        // reports "unknown opcode" since the (rejected) macro was never
        // actually recorded.
        let errs = expect_errors("#pragma version 8\n#define X X\nint 3\nX\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "macro expansion cycle discovered: X -> X"),
            "unexpected errors: {errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| e.message == "unknown opcode: \"X\""
                    || e.message.contains("unknown opcode")),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_macro_indirect_cycle_is_rejected() {
        // go's TestMacros: `c -> hey -> x -> d -> c` is a cycle even
        // though no single macro directly refers to itself.
        let errs = expect_errors(
            "#pragma version 8\n#define x a d\n#define d c a\n#define hey wat's up x\n#define c woah hey\nint 1\nc\n",
        );
        assert!(
            errs.iter()
                .any(|e| e.message == "macro expansion cycle discovered: c -> hey -> x -> d -> c"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_macro_name_cannot_be_named_constant() {
        // go's TestMacros: txn-type/OnCompletion named constants can't be
        // used as macro names, regardless of version.
        let errs = expect_errors("#pragma version 8\n#define pay randomm\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "Named constants cannot be used as macro names: pay"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_macro_name_cannot_be_pseudo_op() {
        let errs = expect_errors("#define int 3\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "Macro names cannot be pseudo-ops: int"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_macro_name_opcode_check_is_version_gated() {
        // go's TestMacros: "+" is a real v1 opcode, so a macro named "+"
        // is rejected once the version is known to include it -- but not
        // before, and `recheck_macro_names` re-validates every macro
        // already defined the moment the version becomes known (whether
        // via `#pragma version` or the first real instruction).
        let errs = expect_errors("#define + randommmm\n#pragma version 1\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "Macro names cannot be opcodes: +"),
            "unexpected errors: {errs:?}"
        );

        // "return" isn't a v1 opcode (introduced in v2), so at v1 it's a
        // perfectly fine macro name.
        let ok = assemble_string("#define return random\n#pragma version 1\nint 1\n");
        assert!(ok.is_ok(), "expected success");
    }

    #[test]
    fn test_macro_name_cannot_be_field_name() {
        let errs = expect_errors("#pragma version 8\n#define Sender hello\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "Macro names cannot be field names: Sender"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_macro_name_character_restrictions() {
        // Digit-leading names, and characters outside the allowed set, are
        // rejected (go's `checkMacroName`, assembler.go:2380-2430).
        let errs = expect_errors("#pragma version 8\n#define 1hello one\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "Cannot begin macro name with number: 1hello"),
            "unexpected errors: {errs:?}"
        );

        let errs = expect_errors("#pragma version 8\n#define wh@t 1\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "@ character not allowed in macro name"),
            "unexpected errors: {errs:?}"
        );

        let errs = expect_errors("#pragma version 8\n#define b64 AA\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "Cannot use b64 as macro name"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_macro_name_vs_label_conflicts() {
        // A label can't share a name with a currently-defined macro, and
        // vice versa (go's TestMacros).
        let errs = expect_errors("#pragma version 8\ncoolLabel:\nint 1\n#define coolLabel 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "Labels cannot be used as macro names: coolLabel"),
            "unexpected errors: {errs:?}"
        );

        let errs = expect_errors("#pragma version 8\n#define coolLabel 1\ncoolLabel:\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "Cannot create label with same name as macro: coolLabel"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_define_requires_name_and_body() {
        let errs = expect_errors("#pragma version 8\n#define\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "define directive requires a name and body"),
            "unexpected errors: {errs:?}"
        );

        let errs = expect_errors("#pragma version 8\n#define hello\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message == "define directive requires a name and body"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_unknown_directive_is_an_error() {
        let errs = expect_errors("#bogus\nint 1\n");
        assert!(
            errs.iter().any(|e| e.message == "unknown directive: bogus"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_assemble_constants_intc_bytec_out_of_range_rejected() {
        // TestAssembleConstants: a direct `intc N`/`bytec N` reference past
        // the end of the pool built so far is rejected at assembly time
        // (no `intcblock`/`bytecblock` precedes these, so the pool is
        // empty).
        let errs = expect_errors("#pragma version 8\nintc 1\n");
        assert!(
            errs.iter().any(|e| e.message == "intc 1 is not defined"),
            "unexpected errors: {errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nbytec 1\n");
        assert!(
            errs.iter().any(|e| e.message == "bytec 1 is not defined"),
            "unexpected errors: {errs:?}"
        );
    }

    #[test]
    fn test_assemble_constants_intc_bytec_in_range_ok() {
        // Companion positive case: once the pool has enough entries, the
        // same index assembles cleanly.
        let ops = assemble_string("#pragma version 8\nintcblock 1 2\nintc 1\n").unwrap();
        assert!(!ops.program.is_empty());

        let ops = assemble_string("#pragma version 8\nbytecblock 0x01 0x02\nbytec 1\n").unwrap();
        assert!(!ops.program.is_empty());
    }

    #[test]
    fn test_explicit_intc_bytec_mnemonics_use_short_form_opcodes() {
        // Issue #1381: go-algorand's `writeIntc`/`writeBytec`
        // (assembler.go:429-452, 482-505), called from the explicit
        // `intc`/`bytec` mnemonic handlers `asmIntC`/`asmByteC`
        // (assembler.go:583-609), special-case constant index 0-3 to the
        // single-byte `intc_0..3`/`bytec_0..3` opcodes rather than the
        // generic 2-byte `intc <idx>`/`bytec <idx>` form used for index 4+.
        // This must hold for the *explicit* mnemonic (unlike the `int`/
        // `byte` literal auto-optimization path, which already picked the
        // short form correctly).
        let source = "#pragma version 8\n\
             intcblock 10 20 30 40 50\n\
             intc 0\n\
             intc 1\n\
             intc 2\n\
             intc 3\n\
             intc 4\n\
             pop\npop\npop\npop\npop\n\
             int 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        // program: [version, intcblock(0x20, count=5, 10,20,30,40,50), ...]
        let mut i = 1;
        assert_eq!(ops.program[i], 0x20); // intcblock
        i += 1;
        assert_eq!(ops.program[i], 5); // count
        i += 1;
        for v in [10u8, 20, 30, 40, 50] {
            assert_eq!(ops.program[i], v);
            i += 1;
        }
        assert_eq!(ops.program[i], 0x22, "intc 0 -> intc_0"); // intc_0
        i += 1;
        assert_eq!(ops.program[i], 0x23, "intc 1 -> intc_1"); // intc_1
        i += 1;
        assert_eq!(ops.program[i], 0x24, "intc 2 -> intc_2"); // intc_2
        i += 1;
        assert_eq!(ops.program[i], 0x25, "intc 3 -> intc_3"); // intc_3
        i += 1;
        assert_eq!(ops.program[i], 0x21, "intc 4 -> intc <idx> (long form)"); // intc
        i += 1;
        assert_eq!(ops.program[i], 4); // index immediate

        let source = "#pragma version 8\n\
             bytecblock 0x01 0x02 0x03 0x04 0x05\n\
             bytec 0\n\
             bytec 1\n\
             bytec 2\n\
             bytec 3\n\
             bytec 4\n\
             pop\npop\npop\npop\npop\n\
             int 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        let mut i = 1;
        assert_eq!(ops.program[i], 0x26); // bytecblock
        i += 1;
        assert_eq!(ops.program[i], 5); // count
        i += 1;
        for v in [1u8, 2, 3, 4, 5] {
            assert_eq!(ops.program[i], 1); // length prefix (1 byte each)
            i += 1;
            assert_eq!(ops.program[i], v);
            i += 1;
        }
        assert_eq!(ops.program[i], 0x28, "bytec 0 -> bytec_0"); // bytec_0
        i += 1;
        assert_eq!(ops.program[i], 0x29, "bytec 1 -> bytec_1"); // bytec_1
        i += 1;
        assert_eq!(ops.program[i], 0x2a, "bytec 2 -> bytec_2"); // bytec_2
        i += 1;
        assert_eq!(ops.program[i], 0x2b, "bytec 3 -> bytec_3"); // bytec_3
        i += 1;
        assert_eq!(ops.program[i], 0x27, "bytec 4 -> bytec <idx> (long form)"); // bytec
        i += 1;
        assert_eq!(ops.program[i], 4); // index immediate
    }

    #[test]
    fn test_assemble_jump_to_the_end_byte_exact() {
        // TestAssembleJumpToTheEnd (assembler_test.go:1929-1946), at
        // AssemblerMaxVersion (13, >= varintBranchVersion so `bnz` uses the
        // 1-byte varint offset form): go asserts the exact assembled
        // program bytes `0120010122224000` -- version, intcblock(count=1,
        // val=1), `intc_0`, `intc_0`, `bnz`, offset-varint(0). This is a
        // byte-exact regression pin for issue #1381: before the fix, each
        // explicit `intc 0` mnemonic assembled as the 2-byte generic form
        // (`0x21 0x00`) instead of the single-byte `intc_0` (`0x22`),
        // producing an 11-byte program instead of go's 8 bytes.
        let source = "#pragma version 13\nintcblock 1\nintc 0\nintc 0\nbnz done\ndone:\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(
            ops.program,
            vec![
                opcode::MAX_AVM_VERSION,
                0x20,
                0x01,
                0x01,
                0x22,
                0x22,
                0x40,
                0x00
            ]
        );
    }

    #[test]
    fn test_assemble_branch_too_far() {
        // TestAssembleBranchTooFar: a `b done` whose target sits far enough
        // away (> ~2^20 bytes) that the 3-byte varint branch-offset
        // placeholder can't encode it must be a hard assembly error, not a
        // silent wraparound/truncation.
        const CHUNK_DATA: usize = 4096; // maxStringSize
        const CHUNKS: usize = 260;

        let mut src = String::with_capacity(CHUNKS * (2 * CHUNK_DATA + 32));
        src.push_str("#pragma version 8\n");
        src.push_str("b done\n");
        for _ in 0..CHUNKS {
            src.push_str("pushbytes 0x");
            for _ in 0..CHUNK_DATA {
                src.push_str("00");
            }
            src.push_str("\npop\n");
        }
        src.push_str("done:\nint 1\n");

        let errs = expect_errors(&src);
        assert!(
            errs.iter()
                .any(|e| e.message.contains("too far away") && e.message.contains("done")),
            "expected a branch-too-far error, got {} errors (first: {:?})",
            errs.len(),
            errs.first()
        );
    }

    // ── go-algorand's TestSemiColon (assembler_test.go:3582), issue #1112 ──
    // `;` is a statement separator, equivalent to a newline -- not a
    // comment marker. Locks the already-fixed `tokenize_line`/
    // `next_statement` behavior against regression.

    #[test]
    fn test_semicolon_is_statement_separator_like_newline() {
        // "pushint 0 ; pushint 1 ; +; int 3 ; *" must assemble identically
        // to the newline-separated equivalent, with or without extra
        // whitespace/blank statements around each `;`, and a `//` comment
        // must still swallow everything after it on the line (including a
        // `;` inside the comment).
        let expected = assemble_string("#pragma version 8\npushint 0\npushint 1\n+\nint 3\n*\n")
            .unwrap()
            .program;

        for source in [
            "#pragma version 8\npushint 0 ; pushint 1 ; +; int 3 ; *\n",
            "#pragma version 8\npushint 0; pushint 1; +; int 3; *; // comment; int 2\n",
            "#pragma version 8\npushint 0; ; ; pushint 1 ; +; int 3 ; *//check\n",
        ] {
            let program = assemble_string(source).unwrap().program;
            assert_eq!(
                program, expected,
                "semicolon-separated form {source:?} should assemble identically to the \
                 newline-separated form"
            );
        }
    }

    #[test]
    fn test_semicolon_before_pragma_in_comment_does_not_split_directive() {
        // A `;` inside a `//` comment on a line before `#pragma version`
        // must not be treated as a statement separator that would somehow
        // affect directive parsing -- the whole comment line is discarded
        // before tokens ever reach `next_statement`.
        let expected = assemble_string("#pragma version 7\nint 1\n")
            .unwrap()
            .program;

        for source in [
            "// junk;\n#pragma version 7\nint 1\n",
            "// junk;\n #pragma version 7\nint 1\n",
        ] {
            let program = assemble_string(source).unwrap().program;
            assert_eq!(program, expected, "source {source:?}");
        }
    }

    #[test]
    fn test_semicolon_inside_string_literal_is_not_a_separator() {
        // A `;` inside a quoted byte-string literal is part of the string,
        // not a statement separator -- `byte "test;this"` must stay one
        // token/statement, not split into `byte "test` and `this"`.
        let expected = assemble_string("#pragma version 8\nbyte \"test;this\"\npop\n")
            .unwrap()
            .program;

        for source in [
            "#pragma version 8\nbyte \"test;this\"; pop;\n",
            "#pragma version 8\nbyte \"test;this\"; ; pop;\n",
            "#pragma version 8\nbyte \"test;this\";;;pop;\n",
        ] {
            let program = assemble_string(source).unwrap().program;
            assert_eq!(program, expected, "source {source:?}");
        }
    }

    // ── go-algorand's TestBackwardCompatAssemble (backwardCompat_test.go:
    // 443), issue #1112 ─────────────────────────────────────────────────
    // v1 (and the implicit-v1 default) disallow branching to a label that
    // lands exactly at the end of the program (one past the last
    // instruction); v2+ lifted that restriction.

    #[test]
    fn test_v1_label_at_end_of_program_is_ok_when_unreferenced() {
        // A label that is simply never branched to is fine at any version
        // -- only an actual branch landing there is restricted.
        for source in ["int 1; done:\n", "#pragma version 1\nint 1; done:\n"] {
            assemble_string(source).unwrap();
        }
    }

    #[test]
    fn test_v1_branch_to_end_of_program_label_is_too_far_away() {
        // v0/v1 (implicit-default and explicit) reject `bnz done` when
        // `done:` is the very last thing in the program (dest == end of
        // pending bytes); v2+ allows it.
        let source = "int 1;\n int 1;\n bnz done;\n done:\n";
        for prefixed in [source.to_string(), format!("#pragma version 1\n{source}")] {
            let errs = expect_errors(&prefixed);
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("too far away") && e.message.contains("done")),
                "expected a too-far-away error for {prefixed:?}, got: {errs:?}"
            );
        }

        for version in 2..=MAX_AVM_VERSION {
            let prefixed = format!("#pragma version {version}\n{source}");
            assemble_string(&prefixed)
                .unwrap_or_else(|e| panic!("v{version} should allow branch to program end: {e:?}"));
        }
    }

    // ── go-algorand's TestBackwardCompatTEALv1 (backwardCompat_test.go:
    // 253), issue #1112 ─────────────────────────────────────────────────
    // Pins the exact v1 program bytes for a source exercising every AVM v1
    // opcode, and that assembling the same source without an explicit
    // version (implicit v1) or with an explicit `#pragma version 2`
    // produces byte-identical output up to the version-byte prefix.

    #[test]
    fn test_backward_compat_teal_v1_program_bytes() {
        let source_v1 = r"byte 0x41 // A
sha256
byte 0x559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd
==
byte 0x42
keccak256
byte 0x1f675bff07515f5df96737194ea945c36c41e7b4fcef307b7cd4d0e602a69111
==
&&
byte 0x43
sha512_256
byte 0x34b99f8dde1ba273c0a28cf5b2e4dbe497f8cb2453de0c8ba6d578c9431a62cb
==
&&
arg_0
arg_1
arg_2
ed25519verify
&&
// should be a single 1 on the stack
int 0
+
int 0
-
int 1
/
int 1
*
// should be a single 1 on the stack
int 2
<
int 0
>
int 1
<=
int 1
>=
int 1
&&
int 0
||
int 1
==
int 1
!=
!
// should be a single 1 on the stack
arg_3
len
int 32
==
itob
btoi
% // 1 % 1 = 0
int 1
|
int 1
&
int 0
^
int 0xffffffffffffffff
~
mulw
// should be a two zeros on the stack
==
intc_0
intc_1
==
intc_2
intc_3
==
&&
intc 4
int 1
==
&&
pop  // consume intc_N comparisons and repeat for bytec_N
bytec_0
bytec_1
==
bytec_2
bytec_3
==
&&
bytec 4
byte 0x00
==
&&
pop
// test all txn fields
txn Sender
txn Receiver
!=
txn Fee
txn FirstValid
==
&&
// disabled
// txn FirstValidTime
int 0
txn LastValid
!=
&&
txn Note
txn Lease
!=
&&
txn Amount
txn GroupIndex
!=
&&
txn CloseRemainderTo
txn VotePK
==
&&
txn SelectionPK
txn Type
!=
&&
txn VoteFirst
txn VoteLast
==
&&
txn VoteKeyDilution
txn TypeEnum
!=
&&
txn XferAsset
txn AssetAmount
!=
&&
txn AssetSender
txn AssetReceiver
==
&&
txn AssetCloseTo
txn TxID
==
&&
pop
// repeat for gtxn
gtxn 0 Sender
gtxn 0 Receiver
!=
gtxn 0 Fee
gtxn 0 FirstValid
==
&&
// disabled
// gtxn 0 FirstValidTime
int 0
gtxn 0 LastValid
!=
&&
gtxn 0 Note
gtxn 0 Lease
!=
&&
gtxn 0 Amount
gtxn 0 GroupIndex
!=
&&
gtxn 0 CloseRemainderTo
gtxn 0 VotePK
==
&&
gtxn 0 SelectionPK
gtxn 0 Type
!=
&&
gtxn 0 VoteFirst
gtxn 0 VoteLast
==
&&
gtxn 0 VoteKeyDilution
gtxn 0 TypeEnum
!=
&&
gtxn 0 XferAsset
gtxn 0 AssetAmount
!=
&&
gtxn 0 AssetSender
gtxn 0 AssetReceiver
==
&&
gtxn 0 AssetCloseTo
gtxn 0 TxID
==
&&
pop
// check global (these are set equal in defaultEvalProto())
global MinTxnFee
global MinBalance
==
global MaxTxnLife
global GroupSize
!=
&&
global ZeroAddress
byte 0x0000000000000000000000000000000000000000000000000000000000000000
==
&&
store 0
load 0
&&

// wrap up, should be a two zeros on the stack
bnz ok
err
ok:
int 1
dup
==
";
        let program_v1_hex = "01200500010220ffffffffffffffffff012608014120559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd0142201f675bff07515f5df96737194ea945c36c41e7b4fcef307b7cd4d0e602a6911101432034b99f8dde1ba273c0a28cf5b2e4dbe497f8cb2453de0c8ba6d578c9431a62cb0100200000000000000000000000000000000000000000000000000000000000000000280129122a022b1210270403270512102d2e2f041022082209230a230b240c220d230e230f231022112312231314301525121617182319231a221b21041c1d12222312242512102104231210482829122a2b121027042706121048310031071331013102121022310413103105310613103108311613103109310a1210310b310f1310310c310d1210310e31101310311131121310311331141210311531171210483300003300071333000133000212102233000413103300053300061310330008330016131033000933000a121033000b33000f131033000c33000d121033000e3300101310330011330012131033001333001412103300153300171210483200320112320232041310320327071210350034001040000100234912";
        let program_v1 = hex::decode(program_v1_hex).unwrap_or_else(|e| {
            // The go fixture hex has an even count of chars; if this ever
            // fails it means the pinned constant was mistyped, not a real
            // assembler bug -- fail loudly rather than silently skipping.
            panic!("bad pinned program_v1 hex: {e}")
        });

        // Assembling without an explicit version must produce byte-for-byte
        // the historic v1 program (implicit-default version is 1).
        let ops = assemble_string(source_v1).unwrap();
        assert_eq!(
            ops.program, program_v1,
            "implicit-version assembly of the v1-opcode-exercising source must match the \
             historic pinned v1 program bytes"
        );

        // Assembling the same source with an explicit `#pragma version 2`
        // must match everywhere except the leading version byte.
        let source_v2 = format!("#pragma version 2\n{source_v1}");
        let ops_v2 = assemble_string(&source_v2).unwrap();
        assert_eq!(ops_v2.program[0], 2);
        assert_eq!(
            &ops_v2.program[1..],
            &program_v1[1..],
            "v2 assembly must be byte-identical to the v1 program past the version byte"
        );
    }

    // ── Disassembler error diagnostics (issue #823 theme 4), ported from
    // go-algorand's TestAssembleDisassembleErrors ───────────────────────

    #[test]
    fn test_disassemble_invalid_field_byte_rejected() {
        // Corrupting a txn/txna/gtxn/gtxna/global field-immediate byte to a
        // value that names no known field must be a disassembly error
        // ("invalid immediate f for X"), not a silent raw-number fallback.
        for (source, opcode_byte_index_from_end, mnemonic) in [
            ("#pragma version 8\ntxn Sender\n", 1, "txn"),
            ("#pragma version 8\ntxna Accounts 0\n", 2, "txna"),
            ("#pragma version 8\ngtxn 0 Sender\n", 1, "gtxn"),
            ("#pragma version 8\ngtxna 0 Accounts 0\n", 2, "gtxna"),
            ("#pragma version 8\nglobal MinTxnFee\n", 1, "global"),
        ] {
            let ops = assemble_string(source).unwrap();
            let mut program = ops.program.clone();
            let len = program.len();
            program[len - opcode_byte_index_from_end] = 0x50; // not a valid field byte
            let err = crate::disassembler::disassemble(&program).unwrap_err();
            assert!(
                err.contains(&format!("invalid immediate f for {mnemonic}")),
                "source {source:?}: unexpected error: {err}"
            );
        }
    }

    // Closes the remaining `TestAssembleDisassembleErrors` parity gap noted
    // in Phase 17: go's exact "program end while reading immediate %s for
    // %s" wording (assembler.go:3071) for a program truncated mid-immediate,
    // ported verbatim for each of go's sub-cases (asset_params_get's field
    // byte, gtxna's three immediates one at a time, txna's index byte, and
    // substring's end-offset byte).
    #[test]
    fn test_disassemble_truncated_immediate_reports_go_wording() {
        let truncate_and_expect = |source: &str, drop: usize, expected: &str| {
            let ops = assemble_string(source).unwrap();
            let program = &ops.program[..ops.program.len() - drop];
            let err = crate::disassembler::disassemble(program).unwrap_err();
            assert!(
                err.contains(expected),
                "source {source:?} truncated by {drop}: expected {expected:?}, got {err:?}"
            );
        };

        truncate_and_expect(
            "#pragma version 8\nint 0\nasset_params_get AssetTotal\n",
            1,
            "program end while reading immediate f for asset_params_get",
        );

        // gtxna has three immediates (t, f, i in that declaration order);
        // dropping 1/2/3 trailing bytes must name i/f/t respectively.
        truncate_and_expect(
            "#pragma version 8\ngtxna 0 Accounts 0\n",
            1,
            "program end while reading immediate i for gtxna",
        );
        truncate_and_expect(
            "#pragma version 8\ngtxna 0 Accounts 0\n",
            2,
            "program end while reading immediate f for gtxna",
        );
        truncate_and_expect(
            "#pragma version 8\ngtxna 0 Accounts 0\n",
            3,
            "program end while reading immediate t for gtxna",
        );

        truncate_and_expect(
            "#pragma version 8\ntxna Accounts 0\n",
            1,
            "program end while reading immediate i for txna",
        );

        truncate_and_expect(
            "#pragma version 8\nbyte 0x4141\nsubstring 0 1\n",
            1,
            "program end while reading immediate e for substring",
        );
    }

    #[test]
    fn test_disassemble_illegal_opcode_and_unsupported_version() {
        // 0xff is not (currently) assigned to any opcode.
        let err = crate::disassembler::disassemble(&[8, 0xff]).unwrap_err();
        assert!(
            err.contains("illegal opcode") || err.contains("0xff") || err.contains("unknown"),
            "unexpected error: {err}"
        );

        // Version 0x11 (17) is unsupported.
        let ops = assemble_string("#pragma version 8\nint 1\n").unwrap();
        let mut program = ops.program.clone();
        program[0] = 0x11;
        let err = crate::disassembler::disassemble(&program).unwrap_err();
        assert!(
            err.contains("unsupported") || err.to_lowercase().contains("version"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_string_literal_escapes() {
        let result = parse_string_literal(r#""hello\nworld""#).unwrap();
        assert_eq!(result, b"hello\nworld");
    }

    #[test]
    fn test_parse_string_literal_hex() {
        let result = parse_string_literal(r#""ab\x01cd""#).unwrap();
        assert_eq!(result, b"ab\x01cd");
    }

    #[test]
    fn test_tokenize_line() {
        let tokens = tokenize_line(r#"byte "hello world" 42"#);
        assert_eq!(tokens, vec!["byte", "\"hello world\"", "42"]);
        // A `//` comment strips the trailing text.
        assert_eq!(tokenize_line("int 1 // comment"), vec!["int", "1"]);
        // `;` is its own explicit token -- it is not a comment delimiter
        // (issue #847: this assembler previously, incorrectly, treated it
        // as one, matching go-algorand's `assembler.go` tokenizer instead).
        assert_eq!(
            tokenize_line("int 1 ; return"),
            vec!["int", "1", ";", "return"]
        );
        assert_eq!(
            tokenize_line("zero: int 1; return"),
            vec!["zero:", "int", "1", ";", "return"]
        );
        // `//` and `;` inside a string literal are not separators.
        assert_eq!(
            tokenize_line(r#"byte "hello // world""#),
            vec!["byte", r#""hello // world""#]
        );
        assert_eq!(tokenize_line(r#"byte "a;b""#), vec!["byte", r#""a;b""#]);
        // A `//` comment after some `;`-separated statements ends the
        // whole line -- tokens after the `//` are dropped, matching go's
        // `tokensFromLine` returning immediately on an unescaped `//`.
        assert_eq!(
            tokenize_line("int 1; int 2 // int 3; int 4"),
            vec!["int", "1", ";", "int", "2"]
        );
        // Adjacent/leading/trailing `;` tokens are preserved as-is --
        // `next_statement` is what collapses the empty statements between
        // them.
        assert_eq!(tokenize_line(";int 1;;"), vec![";", "int", "1", ";", ";"]);
        assert_eq!(tokenize_line(""), Vec::<&str>::new());
        assert_eq!(tokenize_line("// only a comment"), Vec::<&str>::new());
    }

    // ── go-algorand's tokensFromLine `inBase64` tracking, issue #1382 ──
    // `base64`/`b64` (bare prefix or `base64(`/`b64(` paren form) suppress
    // `//`-as-comment-start detection until the literal ends, since `//`
    // is a legal base64 substring. Locks `tokenize_line`'s handling of
    // both forms against regression.
    #[test]
    fn test_tokenize_line_base64_literal_suppresses_comment() {
        // Bare form: `//` inside the literal is not a comment start; the
        // literal token ends at the next whitespace, same as any other
        // token.
        assert_eq!(
            tokenize_line("base64 ABC//== rest"),
            vec!["base64", "ABC//==", "rest"]
        );
        assert_eq!(
            tokenize_line("b64 ABC//== rest"),
            vec!["b64", "ABC//==", "rest"]
        );
        // Once the base64 literal token ends, `//` detection resumes
        // normally for subsequent tokens.
        assert_eq!(
            tokenize_line("base64 ABC//== // comment"),
            vec!["base64", "ABC//=="]
        );
        // Paren form: `//` is suppressed until the matching `)`, all as
        // a single token (parens are not token separators).
        assert_eq!(
            tokenize_line("base64(ABC//==) rest"),
            vec!["base64(ABC//==)", "rest"]
        );
        assert_eq!(
            tokenize_line("b64(ABC//==) rest"),
            vec!["b64(ABC//==)", "rest"]
        );
        // After the closing `)`, `//` detection resumes normally.
        assert_eq!(
            tokenize_line("base64(ABC//==) // comment"),
            vec!["base64(ABC//==)"]
        );
        // A prefix that merely looks like base64/b64 (not an exact match)
        // does not enable the suppression.
        assert_eq!(
            tokenize_line("xbase64 ABC//== rest"),
            vec!["xbase64", "ABC"]
        );
    }

    // Full port of go-algorand's `TestTokensFromLine`
    // (`data/transactions/logic/assembler_test.go:1727`), closing out the
    // remaining "partial" gap noted in Phase 17: the two prior tests here
    // covered the `;`-token and base64/b64-literal-suppresses-comment
    // behaviors individually, but not go's full `check(...)` case table.
    // Every `check(line, tokens...)` call from go's test is reproduced
    // here verbatim against `tokenize_line`; rust's tokenizer has a
    // different internal architecture (no macro-expansion pass) but must
    // still agree with go on every one of these token splits.
    #[test]
    fn test_tokenize_line_go_parity_full_sweep() {
        assert_eq!(tokenize_line("op arg"), vec!["op", "arg"]);
        assert_eq!(tokenize_line("op arg // test"), vec!["op", "arg"]);
        assert_eq!(
            tokenize_line("op base64 ABC//=="),
            vec!["op", "base64", "ABC//=="]
        );
        assert_eq!(
            tokenize_line("op base64 base64"),
            vec!["op", "base64", "base64"]
        );
        assert_eq!(
            tokenize_line("op base64 base64 //comment"),
            vec!["op", "base64", "base64"]
        );
        assert_eq!(
            tokenize_line("op base64 base64; op2 //done"),
            vec!["op", "base64", "base64", ";", "op2"]
        );
        assert_eq!(
            tokenize_line("op base64 ABC/=="),
            vec!["op", "base64", "ABC/=="]
        );
        assert_eq!(
            tokenize_line("op base64 ABC/== /"),
            vec!["op", "base64", "ABC/==", "/"]
        );
        assert_eq!(
            tokenize_line("op base64 ABC/== //"),
            vec!["op", "base64", "ABC/=="]
        );
        assert_eq!(
            tokenize_line("op base64 ABC//== //"),
            vec!["op", "base64", "ABC//=="]
        );
        assert_eq!(
            tokenize_line("op b64 ABC//== //"),
            vec!["op", "b64", "ABC//=="]
        );
        assert_eq!(
            tokenize_line("op b64(ABC//==) // comment"),
            vec!["op", "b64(ABC//==)"]
        );
        assert_eq!(
            tokenize_line("op base64(ABC//==) // comment"),
            vec!["op", "base64(ABC//==)"]
        );
        assert_eq!(
            tokenize_line("op b64(ABC/==) // comment"),
            vec!["op", "b64(ABC/==)"]
        );
        assert_eq!(
            tokenize_line("op base64(ABC/==) // comment"),
            vec!["op", "base64(ABC/==)"]
        );
        assert_eq!(tokenize_line("base64(ABC//==)"), vec!["base64(ABC//==)"]);
        assert_eq!(tokenize_line("b(ABC//==)"), vec!["b(ABC"]);
        assert_eq!(tokenize_line("b(ABC//==) //"), vec!["b(ABC"]);
        assert_eq!(tokenize_line("b(ABC ==) //"), vec!["b(ABC", "==)"]);
        assert_eq!(
            tokenize_line("op base64 ABC)"),
            vec!["op", "base64", "ABC)"]
        );
        assert_eq!(
            tokenize_line("op base64 ABC) // comment"),
            vec!["op", "base64", "ABC)"]
        );
        assert_eq!(
            tokenize_line("op base64 ABC//) // comment"),
            vec!["op", "base64", "ABC//)"]
        );
        assert_eq!(tokenize_line(r#"op "test""#), vec!["op", r#""test""#]);
        assert_eq!(
            tokenize_line(r#"op "test1 test2""#),
            vec!["op", r#""test1 test2""#]
        );
        assert_eq!(
            tokenize_line(r#"op "test1 test2" // comment"#),
            vec!["op", r#""test1 test2""#]
        );
        assert_eq!(
            tokenize_line(r#"op "test1 test2 // not a comment""#),
            vec!["op", r#""test1 test2 // not a comment""#]
        );
        assert_eq!(
            tokenize_line(r#"op "test1 test2 // not a comment" // comment"#),
            vec!["op", r#""test1 test2 // not a comment""#]
        );
        assert_eq!(
            tokenize_line(r#"op "test1 test2" //"#),
            vec!["op", r#""test1 test2""#]
        );
        assert_eq!(
            tokenize_line(r#"op "test1 test2"//"#),
            vec!["op", r#""test1 test2""#]
        );
        // Non-terminated string literal: no closing quote at all.
        assert_eq!(
            tokenize_line(r#"op "test1 test2"#),
            vec!["op", r#""test1 test2"#]
        );
        // Non-terminated string literal: trailing backslash-escaped quote
        // does not close it.
        assert_eq!(
            tokenize_line(r#"op "test1 test2\""#),
            vec!["op", "\"test1 test2\\\""]
        );
        // A leading backslash means this is NOT a string literal -- go's
        // tokenizer only treats an *unescaped* `"` as a string opener.
        assert_eq!(
            tokenize_line(r#"op \"test1 test2\""#),
            vec!["op", "\\\"test1", "test2\\\""]
        );
        assert_eq!(tokenize_line(r#""test1 test2""#), vec![r#""test1 test2""#]);
        assert_eq!(
            tokenize_line(r#"\"test1 test2""#),
            vec!["\\\"test1", "test2\""]
        );
        assert_eq!(tokenize_line(r#""" // test"#), vec![r#""""#]);
        assert_eq!(
            tokenize_line("int 1; int 2"),
            vec!["int", "1", ";", "int", "2"]
        );
        assert_eq!(
            tokenize_line("int 1;;;int 2"),
            vec!["int", "1", ";", ";", ";", "int", "2"]
        );
        assert_eq!(
            tokenize_line("int 1; ;int 2;; ; ;; "),
            vec!["int", "1", ";", ";", "int", "2", ";", ";", ";", ";", ";"]
        );
        assert_eq!(tokenize_line(";"), vec![";"]);
        assert_eq!(
            tokenize_line("; ; ;;;;"),
            vec![";", ";", ";", ";", ";", ";"]
        );
        assert_eq!(tokenize_line(" ;"), vec![";"]);
        assert_eq!(tokenize_line(" ; "), vec![";"]);
    }

    #[test]
    fn test_tokenize_line_with_cols() {
        // Plain tokens report their 0-based starting column.
        assert_eq!(tokenize_line_with_cols("int 1"), vec![(0, "int"), (4, "1")]);
        // Leading whitespace shifts the first token's column.
        assert_eq!(tokenize_line_with_cols("  err"), vec![(2, "err")]);
        // A `;`-joined line: the second statement's mnemonic starts at
        // the column right after the `;`+space (matches go's
        // `tokensFromLine`, `assembler.go:1945-2020`).
        assert_eq!(
            tokenize_line_with_cols("err; err"),
            vec![(0, "err"), (3, ";"), (5, "err")]
        );
    }

    /// Issue #1394: `OpStream::record_source_location` must report each
    /// instruction's real source column (go's `current[0].col`,
    /// `assembler.go:2208`), not a hardcoded 0 -- matches go's
    /// `TestAssembleOffsets` (`assembler_test.go:2687`).
    #[test]
    fn test_assemble_offsets_columns() {
        // `err; err` on one line: the first `err` is at column 0, the
        // second (after `; `) is at column 5.
        let source = "err\n// comment\nerr; err\n";
        let ops = assemble_string(source).unwrap();
        let locations: Vec<SourceLocation> = {
            let mut entries: Vec<(usize, SourceLocation)> =
                ops.offset_to_source.iter().map(|(&k, &v)| (k, v)).collect();
            entries.sort_by_key(|(k, _)| *k);
            entries.into_iter().map(|(_, v)| v).collect()
        };
        assert_eq!(
            locations,
            vec![
                SourceLocation { line: 0, col: 0 },
                SourceLocation { line: 2, col: 0 },
                SourceLocation { line: 2, col: 5 },
            ]
        );

        // An instruction preceded by leading whitespace/indentation
        // (e.g. a label body indented by convention) reports the real
        // indented column, not 0. `b` requires v2+.
        let indented_source = "#pragma version 2\nerr\nb label1\nerr\nlabel1:\n  err\n";
        let ops = assemble_string(indented_source).unwrap();
        let mut entries: Vec<(usize, SourceLocation)> =
            ops.offset_to_source.iter().map(|(&k, &v)| (k, v)).collect();
        entries.sort_by_key(|(k, _)| *k);
        let locations: Vec<SourceLocation> = entries.into_iter().map(|(_, v)| v).collect();
        assert_eq!(
            locations,
            vec![
                SourceLocation { line: 1, col: 0 },
                SourceLocation { line: 2, col: 0 },
                SourceLocation { line: 3, col: 0 },
                SourceLocation { line: 5, col: 2 },
            ]
        );
    }

    #[test]
    fn test_named_int_constants() {
        let source = "#pragma version 2\nint pay\nint NoOp\n";
        let ops = assemble_string(source).unwrap();
        // pay=1, NoOp=0
        assert!(!ops.program.is_empty());
    }

    #[test]
    fn test_varuint_encoding() {
        let mut buf = Vec::new();
        write_varuint_to_vec(&mut buf, 0);
        assert_eq!(buf, vec![0]);

        let mut buf = Vec::new();
        write_varuint_to_vec(&mut buf, 127);
        assert_eq!(buf, vec![127]);

        let mut buf = Vec::new();
        write_varuint_to_vec(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        let mut buf = Vec::new();
        write_varuint_to_vec(&mut buf, 300);
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn test_int_named_txn_type() {
        assert_eq!(parse_named_int("pay"), Some(1));
        assert_eq!(parse_named_int("Payment"), Some(1));
        assert_eq!(parse_named_int("NoOp"), Some(0));
        assert_eq!(parse_named_int("DeleteApplication"), Some(5));
        assert_eq!(parse_named_int("random"), None);
    }

    // Ported from go-algorand's `TestOnCompletionConstants`
    // (data/transactions/logic/eval_test.go ~line 1400): for every
    // OnCompletion symbol, `int <Symbol>; int <numeric-value>; ==` must
    // assemble and evaluate to accept(1) -- i.e. the `int` pseudo-op's named
    // constant resolves to exactly the same numeric value as go's
    // `OnCompletion` enum for every one of the 6 symbols (0..=5).
    #[test]
    fn test_on_completion_constants_int_pseudo_op_matches_numeric_value() {
        let cases: &[(&str, u64)] = &[
            ("NoOp", 0),
            ("OptIn", 1),
            ("CloseOut", 2),
            ("ClearState", 3),
            ("UpdateApplication", 4),
            ("DeleteApplication", 5),
        ];
        for (symbol, value) in cases {
            let source =
                format!("#pragma version {MAX_AVM_VERSION}\nint {symbol}\nint {value}\n==\n");
            let ops = assemble_string(&source).unwrap_or_else(|errs| {
                panic!("expected {source:?} to assemble cleanly, got: {errs:?}")
            });
            let program = crate::bytecode::parse(&ops.program).expect("parse assembled program");
            let mut m =
                crate::machine::AvmMachine::new(program, crate::machine::ExecMode::LogicSig, 1000);
            let pass = m
                .run(&mut crate::context::NullContext)
                .unwrap_or_else(|e| panic!("expected {symbol} program to evaluate, got: {e:?}"));
            assert!(pass, "expected `int {symbol}` to equal {value}");
        }
    }

    #[test]
    fn test_method_pseudo_op() {
        let source = "#pragma version 3\nmethod \"add(uint64,uint64)uint64\"\npop\nint 1\n";
        let ops = assemble_string(source).unwrap();
        assert!(!ops.program.is_empty());
    }

    #[test]
    fn test_switch_opcode() {
        let source = "#pragma version 8\nint 0\nswitch label0 label1\nlabel0:\nint 1\nreturn\nlabel1:\nint 2\nreturn\n";
        let ops = assemble_string(source).unwrap();
        assert!(!ops.program.is_empty());
    }

    #[test]
    fn test_empty_program_error() {
        let result = assemble_string("");
        assert!(result.is_err());

        let result = assemble_string("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_pushint_explicit() {
        let source = "#pragma version 3\npushint 42\n";
        let ops = assemble_string(source).unwrap();
        // version=3, pushint 42
        assert_eq!(ops.program[0], 3);
        assert_eq!(ops.program[1], 0x81); // pushint
        assert_eq!(ops.program[2], 42);
    }

    #[test]
    fn test_pushbytes_explicit() {
        let source = "#pragma version 3\npushbytes 0x0102\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(ops.program[0], 3);
        assert_eq!(ops.program[1], 0x80); // pushbytes
        assert_eq!(ops.program[2], 2); // length
        assert_eq!(ops.program[3], 0x01);
        assert_eq!(ops.program[4], 0x02);
    }

    /// go-algorand's `asmByte`/`asmPushBytes`/`asmByteImmArgs`
    /// (data/transactions/logic/assembler.go) reject any byte literal over
    /// `maxStringSize` (4096 bytes) at assembly time, unconditionally (not
    /// version-gated). algod-rust had no equivalent check at all before this
    /// fix (issue #666 item a).
    fn oversized_hex_literal() -> String {
        format!("0x{}", "00".repeat(opcode::MAX_STRING_SIZE + 1))
    }

    #[test]
    fn test_byte_literal_oversized_rejected() {
        let source = format!(
            "#pragma version 2\nbyte {}\npop\nint 1\n",
            oversized_hex_literal()
        );
        let result = assemble_string(&source);
        assert!(result.is_err());
        let msg = format!("{:?}", result.err().unwrap());
        assert!(msg.contains("too big") && msg.contains("4096"), "{msg}");
    }

    #[test]
    fn test_pushbytes_literal_oversized_rejected() {
        let source = format!("#pragma version 3\npushbytes {}\n", oversized_hex_literal());
        let result = assemble_string(&source);
        assert!(result.is_err());
        let msg = format!("{:?}", result.err().unwrap());
        assert!(msg.contains("too big") && msg.contains("4096"), "{msg}");
    }

    // Ports go's `TestManualCBlocksPreBackBranch`
    // (`data/transactions/logic/assembler_test.go:1440`): before
    // `backBranchEnabledVersion` (v4), an `int`/`byte` literal resolves
    // against the most recently *reachable* manual cblock, not simply the
    // most recently *parsed* one. A manual cblock sitting in dead code
    // (unconditionally unreachable, e.g. right after a `b` and before the
    // next label) must not become the "currently live" block -- found and
    // fixed a real gap: `asm_intc_block`/`asm_bytec_block` previously
    // updated `cnt_intc_block`/`ops.intc` (and the byte equivalents)
    // unconditionally, so a dead-code manual cblock silently became "the"
    // live block, causing `int`/`byte` literals that matched the *live*
    // block's values to spuriously error ("value ... used with manual
    // intcblocks") or, worse, literals absent from the live block but
    // present nowhere real to silently succeed via a `pushint`/`pushbytes`
    // fallback instead of go's "value ... does not appear in existing
    // intcblock" rejection. Fixed to mirror go's `asmIntCBlock`/
    // `asmByteCBlock` (`assembler.go:912-976`) exactly: skip the
    // live-block update whenever `OpStream::type_track_deadcode` is set,
    // which is already tracked in the same single assembly pass (via
    // `type_track::track_instruction`, run just before instruction
    // assembly in `process_statement`) for the branch-merge type-tracking
    // work in issue #829.
    #[test]
    fn test_manual_cblocks_pre_back_branch_dead_intcblock_sees_live_block() {
        // "intcblock 10 20; int 10;" -- single manual block, no dead code.
        let src = "#pragma version 3\nintcblock 10 20\nint 10\nreturn\n";
        assert!(assemble_string(src).is_ok());

        // "intcblock 10 20; int 30;" -- 30 isn't in the (only, live) block.
        let src = "#pragma version 3\nintcblock 10 20\nint 30\nreturn\n";
        let err = assemble_string(src).err().unwrap();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("value 30 does not appear in existing intcblock"),
            "{msg}"
        );
    }

    #[test]
    fn test_manual_cblocks_pre_back_branch_dead_intcblock_ignored_by_int() {
        // The second intcblock is dead (unreachable past the unconditional
        // `b skip`) -- `int 10`/`int 3` must "see" only the first, live
        // block ({10, 20}), exactly like go.
        let live_val =
            "#pragma version 3\nintcblock 10 20\nb skip\nintcblock 3 4 5\nskip:\nint 10\nreturn\n";
        let ops = assemble_string(live_val).expect("live value must assemble");
        // intc_0 (0x22) references the live block's first slot (10), not a
        // pushint/pushbytes fallback and not the dead block's slot 0 (3).
        assert!(
            ops.program.windows(1).any(|w| w == [0x22]),
            "expected intc_0 reference in {:?}",
            ops.program
        );

        // 3 only appears in the *dead* block -- go still rejects this with
        // "value 3 does not appear in existing intcblock" because the dead
        // block was never adopted as live. Before the fix, algod-rust
        // instead silently accepted this via a `pushint` fallback (treating
        // two-manual-cblocks-seen as "unknowable", same as the *reachable*
        // multi-block case) -- a real assembler/consensus-relevant gap
        // versus go's "the intcblock in effect is unknowable" behavior only
        // applying when the second block is actually reachable.
        let dead_val =
            "#pragma version 3\nintcblock 10 20\nb skip\nintcblock 3 4 5\nskip:\nint 3\nreturn\n";
        let err = assemble_string(dead_val).err().unwrap();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("value 3 does not appear in existing intcblock"),
            "{msg}"
        );
    }

    #[test]
    fn test_manual_cblocks_pre_back_branch_reachable_second_intcblock_is_unknowable() {
        // Here the second intcblock is reachable (via a *conditional*
        // `bz`), so which block is "in effect" is genuinely unknowable at
        // assembly time -- go forces `intc`/`pushint` instead of `int`.
        // backBranchEnabledVersion-1 (v3) has `pushint` available, so this
        // still succeeds (falls back to pushint rather than an intc ref).
        let src = "#pragma version 3\nintcblock 10 20\ntxn NumAppArgs\nbz skip\nintcblock 3 4 5\nskip:\nint 10\nreturn\n";
        assert!(assemble_string(src).is_ok());

        // backBranchEnabledVersion-2 (v2) has no pushint -- go rejects with
        // "int 10 used with manual intcblocks. Use intc."
        let src = "#pragma version 2\nintcblock 10 20\ntxn NumAppArgs\nbz skip\nintcblock 3 4 5\nskip:\nint 10\nreturn\n";
        let err = assemble_string(src).err().unwrap();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("int 10 used with manual intcblocks. Use intc."),
            "{msg}"
        );
    }

    #[test]
    fn test_manual_cblocks_pre_back_branch_dead_code_byte_analog() {
        // Same dead-code-ignored behavior for `byte`/manual `bytecblock`.
        let live_val = "#pragma version 3\nbytecblock 0x10 0x20\nb skip\nbytecblock 0x03 0x04 0x05\nskip:\nbyte 0x10\nlen\nreturn\n";
        assert!(
            assemble_string(live_val).is_ok(),
            "{:?}",
            assemble_string(live_val).err()
        );

        let dead_val = "#pragma version 3\nbytecblock 0x10 0x20\nb skip\nbytecblock 0x03 0x04 0x05\nskip:\nbyte 0x03\nlen\nreturn\n";
        let err = assemble_string(dead_val).err().unwrap();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("value 0x03 does not appear in existing bytecblock"),
            "{msg}"
        );
    }

    // Ports go's `TestManualCBlockEval`
    // (`data/transactions/logic/eval_test.go`, referenced from
    // `TestManualCBlocks`' doc comment): a manual `intcblock`/`bytecblock`
    // placed entirely in dead code (after an unconditional `b` to a label
    // preceding any use) must not suppress the assembler's normal
    // auto-inserted-constant-block behavior for `int`/`byte` literals
    // appearing later in *live* code -- they compile exactly as if the
    // dead manual block were never there.
    #[test]
    fn test_manual_cblock_eval_dead_intcblock_does_not_block_auto_insertion() {
        let src =
            "#pragma version 2\nb skip\nintcblock 10\nskip:\nint 4\nint 4\n+\nint 8\n==\nreturn\n";
        assert!(
            assemble_string(src).is_ok(),
            "{:?}",
            assemble_string(src).err()
        );
    }

    #[test]
    fn test_manual_cblock_eval_dead_bytecblock_does_not_block_auto_insertion() {
        let src = "#pragma version 2\nb skip\nbytecblock 0x11\nskip:\nbyte 0x2222\nbyte 0x2222\nconcat\nlen\nint 4\n==\nreturn\n";
        assert!(
            assemble_string(src).is_ok(),
            "{:?}",
            assemble_string(src).err()
        );
    }

    #[test]
    fn test_bytecblock_literal_oversized_rejected() {
        let source = format!(
            "#pragma version 3\nbytecblock {}\n",
            oversized_hex_literal()
        );
        let result = assemble_string(&source);
        assert!(result.is_err());
        let msg = format!("{:?}", result.err().unwrap());
        assert!(msg.contains("too big") && msg.contains("4096"), "{msg}");
    }

    #[test]
    fn test_pushbytess_literal_oversized_rejected() {
        let source = format!(
            "#pragma version 8\npushbytess {} 0x01\n",
            oversized_hex_literal()
        );
        let result = assemble_string(&source);
        assert!(result.is_err());
        let msg = format!("{:?}", result.err().unwrap());
        assert!(msg.contains("too big") && msg.contains("4096"), "{msg}");
    }

    #[test]
    fn test_byte_literal_at_limit_allowed() {
        let source = format!(
            "#pragma version 2\nbyte 0x{}\npop\nint 1\n",
            "00".repeat(opcode::MAX_STRING_SIZE)
        );
        assemble_string(&source).unwrap();
    }

    // -----------------------------------------------------------------
    // #pragma autosalt / TEAL v13 auto-salt (issue #664)
    //
    // Reference bytes below were generated from go-algorand v5.0.0-stable's
    // own algorithm: SHA-512/256("Program" || program) decoded with
    // `filippo.io/edwards25519`'s `Point.SetBytes` (the same library
    // go-algorand's `ProgramHashIsEdwards25519Point` uses), driven through
    // go-algorand's exact `finalizeProgramWithAutoIntcSalt` /
    // `finalizeProgramWithTrailingIntcSalt` byte-construction logic — not
    // derived from this crate's implementation.
    // -----------------------------------------------------------------

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_v13_program_is_auto_salted_via_existing_intcblock() {
        // "int 1" is used twice so the v4+ single-use constant optimizer
        // (`optimize_int_constants`) doesn't inline it as `pushint` — it
        // must stay in a real intcblock for this to exercise
        // `finalize_with_auto_intc_salt` rather than the trailing-intcblock
        // path. Unsalted "int 1\nint 1\nreturn" at v13 is 0d200101222243
        // and is on-curve per go-algorand; the assembler must extend the
        // automatic intcblock with salt=2, yielding 0d20020102222243
        // exactly.
        let source = "#pragma version 13\nint 1\nint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(
            ops.program,
            hex_decode("0d20020102222243"),
            "salted program bytes must match go-algorand's assembler output byte-for-byte"
        );
        assert!(
            !program_hash_is_edwards25519_point(&ops.program),
            "salted program hash must be off-curve"
        );
    }

    #[test]
    fn test_v13_program_is_auto_salted_via_trailing_intcblock() {
        // A program with no auto-generated intcblock to extend (pushbytes/
        // pushint only) gets a brand-new trailing intcblock. Unsalted
        // "pushbytes 0x0102\npop\npushint 1\nreturn" at v13 is
        // 0d8002010248810143 (on-curve); go-algorand's search finds
        // salt=3 sufficient.
        let source = "#pragma version 13\npushbytes 0x0102\npop\npushint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(
            ops.program,
            hex_decode("0d8002010248810143200103"),
            "salted program bytes must match go-algorand's assembler output byte-for-byte"
        );
        assert!(!program_hash_is_edwards25519_point(&ops.program));
    }

    #[test]
    fn test_pragma_autosalt_false_suppresses_salting_at_v13() {
        // Same on-curve v13 program as above (`int 1` used twice, so it
        // stays a real intcblock entry), but with autosalt forced off: the
        // assembler must leave the on-curve, unsalted bytes untouched.
        let source = "#pragma version 13\n#pragma autosalt false\nint 1\nint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(ops.program, hex_decode("0d200101222243"));
        assert!(
            program_hash_is_edwards25519_point(&ops.program),
            "unsalted-by-request program is expected to remain on-curve in this fixture"
        );
    }

    #[test]
    fn test_v12_program_is_never_auto_salted() {
        // A version one below LOGIC_SIG_OFF_CURVE_VERSION must never be
        // salted, even though go-algorand confirms this exact program's
        // hash is on-curve. "int 4" used twice keeps it in an intcblock
        // (see test_v13_program_is_auto_salted_via_existing_intcblock).
        let source = "#pragma version 12\nint 4\nint 4\nreturn\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(ops.program, hex_decode("0c200104222243"));
        assert!(
            program_hash_is_edwards25519_point(&ops.program),
            "fixture must be on-curve to actually exercise the version gate"
        );
    }

    #[test]
    fn test_pragma_autosalt_true_forces_salting_below_v13() {
        // `#pragma autosalt true` overrides the version gate and forces
        // salting even at v12, where the default would leave the program
        // on-curve. go-algorand's search finds salt=0 sufficient here,
        // extending the intcblock to [5, 0].
        let source = "#pragma version 12\n#pragma autosalt true\nint 5\nint 5\nreturn\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(ops.program, hex_decode("0c20020500222243"));
        assert!(!program_hash_is_edwards25519_point(&ops.program));
    }

    #[test]
    fn test_autosalt_pragma_only_allowed_before_instructions() {
        let source = "#pragma version 13\nint 1\n#pragma autosalt false\nreturn\n";
        let result = assemble_string(source);
        assert!(result.is_err());
        let msg = format!("{:?}", result.err().unwrap());
        assert!(msg.contains("only allowed before instructions"), "{msg}");
    }

    #[test]
    fn test_autosalt_pragma_bad_value_rejected() {
        let source = "#pragma version 13\n#pragma autosalt maybe\nint 1\nreturn\n";
        let result = assemble_string(source);
        assert!(result.is_err());
        let msg = format!("{:?}", result.err().unwrap());
        assert!(msg.contains("bad #pragma autosalt"), "{msg}");
    }

    #[test]
    fn test_autosalt_false_on_curve_program_produces_warning() {
        // go-algorand's `shouldAutoSalt` (assembler.go) warns
        // "#pragma autosalt false leaves program hash on curve" when the
        // user explicitly disables auto-salt and the resulting (unsalted)
        // program hash is still on-curve. Same fixture as
        // `test_pragma_autosalt_false_suppresses_salting_at_v13`.
        let source = "#pragma version 13\n#pragma autosalt false\nint 1\nint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        assert!(
            program_hash_is_edwards25519_point(&ops.program),
            "fixture must be on-curve to exercise the warning"
        );
        assert_eq!(
            ops.warnings.len(),
            1,
            "expected exactly one warning, got {:?}",
            ops.warnings
        );
        assert!(
            ops.warnings[0]
                .message
                .contains("#pragma autosalt false leaves program hash on curve"),
            "{:?}",
            ops.warnings
        );
    }

    #[test]
    fn test_autosalt_false_off_curve_program_produces_no_warning() {
        // Same directive, but the underlying program is already off-curve
        // (no salting would be needed anyway), so no warning should fire.
        let mut found = None;
        for v in 0u64..64 {
            let src =
                format!("#pragma version 13\n#pragma autosalt false\nint {v}\nint {v}\nreturn\n");
            let ops = assemble_string(&src).unwrap();
            if !program_hash_is_edwards25519_point(&ops.program) {
                found = Some(ops);
                break;
            }
        }
        let ops = found.expect("expected at least one off-curve fixture in range");
        assert!(
            !program_hash_is_edwards25519_point(&ops.program),
            "fixture must be off-curve so the warning genuinely doesn't apply"
        );
        assert!(
            ops.warnings.is_empty(),
            "expected no warnings, got {:?}",
            ops.warnings
        );
    }

    #[test]
    fn test_autosalt_true_with_stateful_ops_produces_warning() {
        // go-algorand's `shouldAutoSalt` warns
        // "#pragma autosalt true used with stateful opcodes" when the user
        // forces auto-salt on for a program that has app-only opcodes
        // (salting is meaningless there — stateful programs are never
        // used as LogicSig contract-account addresses).
        let source =
            "#pragma version 13\n#pragma autosalt true\nint 0\napp_global_get\npop\nint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        assert_eq!(
            ops.warnings.len(),
            1,
            "expected exactly one warning, got {:?}",
            ops.warnings
        );
        assert!(
            ops.warnings[0]
                .message
                .contains("#pragma autosalt true used with stateful opcodes"),
            "{:?}",
            ops.warnings
        );
    }

    #[test]
    fn test_has_stateful_ops_detection_via_autosalt_warning() {
        // TestHasStatefulOps: go exposes a standalone `HasStatefulOps(program
        // []byte)` API and directly asserts it against `int 1` (false),
        // `int 0; int 1; app_opted_in; err` (true), and
        // `int 1; asset_params_get AssetURL; err` (true). algod-rust's
        // equivalent detection is an internal `has_stateful_ops` field used
        // only to gate the `#pragma autosalt true` warning (see
        // `test_autosalt_true_with_stateful_ops_produces_warning` above) --
        // there is no standalone public API to call directly. This test
        // exercises the same detection logic through that one observable
        // surface: `#pragma autosalt true` warns if and only if the program
        // contains a stateful opcode, for each of go's three sample programs.
        let stateless = "#pragma version 8\n#pragma autosalt true\nint 1\nreturn\n";
        let ops = assemble_string(stateless).unwrap();
        assert!(
            ops.warnings.is_empty(),
            "int 1 alone has no stateful ops, expected no autosalt warning: {:?}",
            ops.warnings
        );

        let opted_in =
            "#pragma version 8\n#pragma autosalt true\nint 0\nint 1\napp_opted_in\nerr\n";
        let ops = assemble_string(opted_in).unwrap();
        assert_eq!(
            ops.warnings.len(),
            1,
            "app_opted_in is a stateful op, expected an autosalt warning: {:?}",
            ops.warnings
        );

        let asset_url =
            "#pragma version 8\n#pragma autosalt true\nint 1\nasset_params_get AssetURL\nerr\n";
        let ops = assemble_string(asset_url).unwrap();
        assert_eq!(
            ops.warnings.len(),
            1,
            "asset_params_get is a stateful op, expected an autosalt warning: {:?}",
            ops.warnings
        );
    }

    #[test]
    fn test_assembly_succeeds_with_only_warnings_present() {
        // Warnings must never turn a successful assembly into a failure.
        let source = "#pragma version 13\n#pragma autosalt false\nint 1\nint 1\nreturn\n";
        let result = assemble_string(source);
        assert!(result.is_ok(), "assembly with only warnings must be Ok");
        assert_eq!(result.unwrap().warnings.len(), 1);
    }

    #[test]
    fn test_disassemble_on_curve_v13_program_emits_autosalt_false() {
        // Disassembling raw on-curve v13 bytes (as if hand-crafted, or from
        // an older assembler run before this feature existed) must emit
        // `#pragma autosalt false` so reassembling the disassembly
        // round-trips to the identical bytes instead of silently salting
        // (and changing the hash).
        let program = hex_decode("0d2001012243");
        assert!(program_hash_is_edwards25519_point(&program));
        let text = crate::disassembler::disassemble(&program).unwrap();
        assert!(
            text.contains("#pragma autosalt false"),
            "disassembly must opt out of re-salting an on-curve legacy program:\n{text}"
        );
        let ops2 = assemble_string(&text).unwrap();
        assert_eq!(ops2.program, program);
    }

    #[test]
    fn test_disassemble_already_salted_v13_program_omits_autosalt_pragma() {
        // A program that's already off-curve (because it was salted, or
        // just happens to hash off-curve) round-trips without needing the
        // pragma at all — reassembling it wouldn't re-salt it anyway.
        let program = hex_decode("0d200201002243");
        assert!(!program_hash_is_edwards25519_point(&program));
        let text = crate::disassembler::disassemble(&program).unwrap();
        assert!(!text.contains("#pragma autosalt"));
        let ops2 = assemble_string(&text).unwrap();
        assert_eq!(ops2.program, program);
    }

    // ── Ported from go-algorand's `TestAssembleMatch` (issue #823 theme 1
    // remainder). Covers assembler-time acceptance/rejection of `match`'s
    // label-list syntax. go's version also asserts a final case -- an
    // empty `match` at the top of an otherwise-empty program must fail
    // with "match expects 1 stack argument..." -- which needed the static
    // stack-type-tracking pass this file didn't have yet at the time;
    // that gap has since been closed for `match` (issue #829, slice 6, see
    // `test_assemble_match_alone_is_a_height_error` below). ─────────────

    #[test]
    fn test_assemble_match_undefined_label() {
        let source = "#pragma version 8\npushints 1 1 1\nmatch label1 label2\nlabel1:\n";
        let errs = expect_errors(source);
        assert!(
            errs.iter()
                .any(|e| e.message.contains("undefined label") && e.message.contains("label2")),
            "expected an undefined-label error for label2, got: {errs:?}"
        );
    }

    #[test]
    fn test_assemble_match_no_labels_is_a_noop() {
        // No labels is degenerate but legal -- match just consumes the
        // stack top and always falls through.
        let source = "#pragma version 8\nint 0\nmatch\nint 1\n";
        assemble_string(source).unwrap();
    }

    #[test]
    fn test_assemble_match_two_labels_program_length() {
        let source = "#pragma version 8\npushints 1 2 1\nmatch label1 label2\nlabel1:\nlabel2:\n";
        let ops = assemble_string(source).unwrap();
        // version(1) + pushints (5) + match opcode(1) + count(1) + labels(2*2)
        assert_eq!(ops.program.len(), 1 + 5 + 1 + 1 + 4);
    }

    #[test]
    fn test_assemble_match_byte_array_args() {
        let source = "#pragma version 8\npushbytess \"1\" \"2\" \"1\"\nmatch label1 label2\nlabel1:\nlabel2:\n";
        assemble_string(source).unwrap();
    }

    #[test]
    fn test_assemble_match_255_labels_ok() {
        let labels: Vec<String> = (0..255).map(|i| format!("label{i}")).collect();
        let source = format!(
            "#pragma version {v}\n{pushints}\nmatch {targets}\n{defs}\n",
            v = MAX_AVM_VERSION,
            pushints = "pushint 1\n".repeat(256), // 255 labels, and the match value
            targets = labels.join(" "),
            defs = labels.iter().map(|l| format!("{l}:\n")).collect::<String>(),
        );
        let ops = assemble_string(&source).unwrap();
        // version(1) + pushints (2*256) + match opcode(1) + count(1) + labels(2*255)
        assert_eq!(ops.program.len(), 1 + 2 * 256 + 1 + 1 + 2 * 255);
    }

    #[test]
    fn test_assemble_match_256_labels_too_many() {
        let labels: Vec<String> = (0..256).map(|i| format!("label{i}")).collect();
        let source = format!(
            "#pragma version {v}\n{pushints}\nmatch {targets} extra\n{defs}\n",
            v = MAX_AVM_VERSION,
            pushints = "pushint 1\n".repeat(257), // 256 labels, and the match value
            targets = labels.join(" "),
            defs = labels.iter().map(|l| format!("{l}:\n")).collect::<String>(),
        );
        let errs = expect_errors(&source);
        assert!(
            errs.iter()
                .any(|e| e.message.contains("match cannot take more than 255 labels")),
            "expected a too-many-labels error, got: {errs:?}"
        );
    }

    #[test]
    fn test_assemble_match_allows_duplicate_label_reference() {
        let source = "#pragma version 8\npushints 1 2 1\nmatch label1 label1\nlabel1:\n";
        assemble_string(source).unwrap();
    }

    #[test]
    fn test_assemble_match_empty_match_ok() {
        let source = "#pragma version 8\npushints 1\nmatch\n";
        assemble_string(source).unwrap();
    }

    #[test]
    fn test_assemble_match_empty_match_tracks_stack_through() {
        // Even without static type-tracking, this shape (a match with no
        // labels, followed by an instruction consuming what was under it)
        // must still assemble -- there's nothing match-specific blocking
        // it.
        let source = "#pragma version 8\npushbytess 0xaa 0xbb\npushint 1\nmatch\nconcat\n";
        assemble_string(source).unwrap();
    }

    // ── Static stack-type tracking (issue #829), ported from
    // go-algorand's assembler_test.go straight-line (branch-free) type
    // tracking tests ────────────────────────────────────────────────────

    #[test]
    fn test_type_tracking_stack_height_error() {
        // TestTypeTracking, first case: `+` alone on an empty stack.
        let errs = expect_errors("#pragma version 8\n+\n");
        assert!(
            errs.iter().any(|e| e
                .message
                .contains("+ expects 2 stack arguments but stack height is 0")),
            "{:?}",
            errs.iter().map(|e| &e.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_swap_type_check() {
        // TestSwapTypeCheck.
        let errs = expect_errors("#pragma version 8\nint 1\nbyte 0x1234\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 1")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 1\nbyte 0x1234\nswap\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 0")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nbyte 0x1234\nint 1\nswap\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 1")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_equals_type_check() {
        // TestEqualsTypeCheck.
        for op in ["==", "!="] {
            let errs = expect_errors(&format!("#pragma version 8\nint 1\nbyte 0x1234\n{op}\n"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains(&format!("{op} arg 0"))),
                "{op}: {errs:?}"
            );
            let errs = expect_errors(&format!("#pragma version 8\nbyte 0x1234\nint 1\n{op}\n"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains(&format!("{op} arg 0"))),
                "{op}: {errs:?}"
            );
        }
    }

    #[test]
    fn test_dup_type_check() {
        // TestDupTypeCheck.
        let errs = expect_errors("#pragma version 8\nbyte 0x1234\ndup\nint 1\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 0")),
            "{errs:?}"
        );

        assemble_string("#pragma version 8\nbyte 0x1234\nint 1\ndup\n+\n").unwrap();

        let errs = expect_errors("#pragma version 8\nbyte 0x1234\nint 1\ndup2\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 0")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 1\nbyte 0x1234\ndup2\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 1")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nbyte 0x1234\nint 1\ndup\ndig 1\nlen\n");
        assert!(
            errs.iter().any(|e| e.message.contains("len arg 0")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 1\nbyte 0x1234\ndup\ndig 1\n!\n");
        assert!(
            errs.iter().any(|e| e.message.contains("! arg 0")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_select_type_check() {
        // TestSelectTypeCheck.
        let errs = expect_errors("#pragma version 8\nint 1\nint 2\nint 3\nselect\nlen\n");
        assert!(
            errs.iter().any(|e| e.message.contains("len arg 0")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nbyte 0x1234\nbyte 0x5678\nint 3\nselect\n!\n");
        assert!(
            errs.iter().any(|e| e.message.contains("! arg 0")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_setbit_type_check() {
        // TestSetBitTypeCheck.
        let errs = expect_errors("#pragma version 8\nint 1\nint 2\nint 3\nsetbit\nlen\n");
        assert!(
            errs.iter().any(|e| e.message.contains("len arg 0")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nbyte 0x1234\nint 2\nint 3\nsetbit\n!\n");
        assert!(
            errs.iter().any(|e| e.message.contains("! arg 0")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_branch_assembly_type_check() {
        // TestBranchAssemblyTypeCheck: a label reached by ordinary
        // fallthrough (right after a conditional `bnz`, which doesn't
        // deaden) does not reset tracking -- the bytes value still
        // underneath the (uint64) branch condition is still known to be
        // bytes right after the label.
        assemble_string("#pragma version 8\nbyte 0x1234\nint 0\nbnz flip\nflip:\nbtoi\n").unwrap();
    }

    #[test]
    fn test_type_tracking_branch_confuses_old_analysis_but_reports_locally() {
        // TestTypeTracking: "Branching would have confused the old
        // analysis, but the problem is local to a basic block, so it makes
        // sense to report it." `b confusion` deadens; `label:` is reached
        // through dead code, so it reopens analysis permissively -- but the
        // mistyped `byte "john"; int 2; +` right after that label is still
        // live code within its own basic block and must still be caught.
        let errs = expect_errors(
            "#pragma version 8\nint 1\nb confusion\nlabel:\nbyte 0x1234\nint 2\n+\npop\nconfusion:\nb label\n",
        );
        assert!(
            errs.iter()
                .any(|e| e.message.contains("+ arg 0 wanted type uint64")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_type_tracking_error_in_dead_code_is_not_reported() {
        // TestTypeTracking: "Unless that same error is in dead code." --
        // an `err` right after the label deadens everything until the next
        // label, so the mistyped `byte "john"; int 2; +` past it is never
        // checked.
        assemble_string(
            "#pragma version 8\nint 1\nb confusion\nlabel:\nerr\nbyte 0x1234\nint 2\n+\nconfusion:\nb label\n",
        )
        .unwrap();
    }

    #[test]
    fn test_type_tracking_unconditional_branch_deadens() {
        // TestTypeTracking: "Unconditional branches also deaden." -- the
        // `b done` right after `label:` deadens the mistyped code that
        // follows it, same shape as the `err` case above but via `b`.
        assemble_string(
            "#pragma version 8\nint 1\nb confusion\nlabel:\nb done\nbyte 0x1234\nint 2\n+\nconfusion:\nb label\ndone:\n",
        )
        .unwrap();
    }

    #[test]
    fn test_type_tracking_callsub_wipes_and_reopens() {
        // TestTypeTracking: `callsub A` deadens, then immediately reopens
        // analysis permissively (it's the entry point `retsub` returns to)
        // -- both call-site and subroutine-body sides are exercised.
        //
        // "callsub also wipes our stack knowledge, this tests shows why:
        // it's properly typed" -- `+` right after `callsub A` sees a
        // permissive (post-reset) stack, so no height error even though
        // nothing was actually pushed at the call site.
        assemble_string("#pragma version 8\ncallsub A\n+\nreturn\nA:\nint 1\nint 2\nretsub\n")
            .unwrap();

        // "but we do want to ensure we're not just treating the code after
        // callsub as dead" -- `concat` still gets its own args checked.
        let errs = expect_errors(
            "#pragma version 8\ncallsub A\nint 1\nconcat\nreturn\nA:\nint 1\nint 2\nretsub\n",
        );
        assert!(
            errs.iter().any(|e| e.message.contains("concat arg 1")),
            "{errs:?}"
        );

        // "retsub deadens code, like any unconditional branch" -- the
        // `concat` after `retsub` (with no intervening label) is dead code
        // and must not be reported despite having only one operand type on
        // the (permissive, post-reset) stack.
        assemble_string(
            "#pragma version 8\ncallsub A\n+\nreturn\nA:\nint 1\nint 2\nretsub\nconcat\n",
        )
        .unwrap();
    }

    #[test]
    fn test_type_tracking_regression_scratch_after_callsub() {
        // TestTypeTrackingRegression: exercises that a permissive stack
        // established by `callsub`'s reset doesn't get "stuck" at a
        // particular type on repeated `load`/`store`. `callsub` resets
        // every scratch slot to `Any` (see `OpStream::scratch_space`), so
        // `load 1`'s index (used by `stores`) and both `load 0`s type as
        // `Any` throughout -- `Any` overlaps `stores`' `Uint64` index arg
        // and `+`'s `Uint64` operands alike, so this must still assemble
        // cleanly even with real per-slot scratch tracking now in place.
        assemble_string(
            "#pragma version 8\ncallsub end\nlabel1:\nload 1\nbyte 0x01\nstores\nload 0\nload 0\n+\nend:\n",
        )
        .unwrap();
    }

    // ── Scratch-slot per-index type tracking (issue #829, follow-up
    // slice), ported from go-algorand's `TestScratchTypeCheck` and the
    // message-observable case of `TestScratchBounds` in
    // `assembler_test.go` ──────────────────────────────────────────────

    #[test]
    fn test_scratch_type_check() {
        // TestScratchTypeCheck.

        // All scratch slots should start as uint64.
        assemble_string("#pragma version 8\nload 0\nint 1\n+\n").unwrap();

        // Check load and store accurately using the scratch space.
        let errs = expect_errors("#pragma version 8\nbyte 0x01\nstore 0\nload 0\nint 1\n+\n");
        assert!(
            errs.iter().any(|e| e.message.starts_with("+ arg 0")),
            "{errs:?}"
        );

        // Loads should know the type it's loading if all the slots are the
        // same type.
        let errs = expect_errors("#pragma version 8\nint 0\nloads\nbtoi\n");
        assert!(
            errs.iter().any(|e| e.message.starts_with("btoi arg 0")),
            "{errs:?}"
        );

        // Loads only knows the type when the slot index is a const.
        let errs = expect_errors("#pragma version 8\nbyte 0x01\nstore 0\nint 1\nloads\nbtoi\n");
        assert!(
            errs.iter().any(|e| e.message.starts_with("btoi arg 0")),
            "{errs:?}"
        );

        // Loads doesn't know the type if it's the result of some other
        // expression where we lose information.
        assemble_string("#pragma version 8\nbyte 0x01\nstore 0\nload 0\nbtoi\nloads\nbtoi\n")
            .unwrap();

        // Stores should only set slots to StackAny if they are not the same
        // type as what is being stored.
        let errs = expect_errors(
            "#pragma version 8\nbyte 0x01\nstore 0\nint 3\nbyte 0x01\nstores\nload 0\nint 1\n+\n",
        );
        assert!(
            errs.iter().any(|e| e.message.starts_with("+ arg 0")),
            "{errs:?}"
        );

        // ScratchSpace should reset after hitting a label in dead code.
        assemble_string(
            "#pragma version 8\nbyte 0x01\nstore 0\nb label1\nlabel1:\nload 0\nint 1\n+\n",
        )
        .unwrap();

        // But it should reset to StackAny, not uint64.
        assemble_string("#pragma version 8\nint 1\nstore 0\nb label1\nlabel1:\nload 0\nbtoi\n")
            .unwrap();

        // Callsubs should also reset the scratch space.
        assemble_string(
            "#pragma version 8\ncallsub A\nload 0\nbtoi\nreturn\nA:\nbyte 0x01\nstore 0\nretsub\n",
        )
        .unwrap();

        // But the scratchspace should still be tracked after the callsub.
        let errs = expect_errors(
            "#pragma version 8\ncallsub A\nint 1\nstore 0\nload 0\nbtoi\nreturn\nA:\nretsub\n",
        );
        assert!(
            errs.iter().any(|e| e.message.starts_with("btoi arg 0")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_scratch_bounds_type_mismatch() {
        // TestScratchBounds's one message-observable assertion (its other
        // assertions inspect go's internal `os.known.scratchSpace[i].Bound`
        // directly -- exact numeric bound tracking remains deferred, see
        // the `type_track` module docs' "Bounds-refined types" section):
        // `store 1` records slot 1 as `Bytes`, so `load 1` feeding `return`
        // (which needs `Uint64`) is a type mismatch.
        let errs = expect_errors("#pragma version 8\nbyte 0xff\nstore 1\nload 1\nreturn\n");
        assert!(
            errs.iter().any(|e| e.message.starts_with("return arg 0")
                && e.message.contains("wanted type uint64")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_switch_type_check_does_not_permanently_disable() {
        // Not a direct go-test port, but pins that `switch` (unlike the
        // dynamic-arity opcodes that still hard-disable) keeps tracking
        // live afterward, since go's `switch` doesn't deaden (an
        // out-of-range index falls through) and always has a fixed,
        // single-uint64-pop proto regardless of how many labels follow.
        let errs = expect_errors("#pragma version 8\nbyte 0x1234\nswitch flip\nflip:\nconcat\n");
        assert!(
            errs.iter().any(|e| e.message.starts_with("switch")
                && e.message.contains("arg 0 wanted type uint64")),
            "{errs:?}"
        );
    }

    // ── Fixed-immediate-arity opcodes (issue #829, slice 5): `popn`,
    // `dupn`, `cover`, `uncover` all read a single immediate byte directly
    // from the bytecode at assembly time, so (unlike `match`/`txn`/
    // `pushbytess`) their pop/push counts are fully known statically --
    // ported from go-algorand's `TestDupPopNTyping` (`frames_test.go`) plus
    // new cover/uncover coverage for the same shape ─────────────────────

    #[test]
    fn test_dup_popn_typing() {
        // TestDupPopNTyping: `dupn 2` leaves 3 copies of the pushed `int 8`
        // on top; `+` (uint64) is happy, `concat` (bytes) is not.
        assemble_string("#pragma version 8\nint 8\ndupn 2\n+\npop\n").unwrap();

        let errs = expect_errors("#pragma version 8\nint 8\ndupn 2\nconcat\npop\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("wanted type []byte")),
            "{errs:?}"
        );

        // `popn 1` on an empty stack is a height error, same shape as any
        // other fixed-arg opcode's height check.
        let errs = expect_errors("#pragma version 8\npopn 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("expects 1 stack argument")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_popn_pops_exactly_n_and_type_tracking_continues() {
        // `popn 2` must consume exactly two tracked values and leave
        // tracking live afterward (unlike the hard-disabled dynamic-arity
        // opcodes) -- a mistyped instruction further down is still caught.
        assemble_string("#pragma version 8\nint 1\nint 2\npopn 2\nint 3\npop\n").unwrap();

        let errs =
            expect_errors("#pragma version 8\nint 1\nint 2\npopn 2\nbyte 0x1234\nint 1\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 0")),
            "{errs:?}"
        );

        // Too few values on the stack for `popn 3` is a height error, and
        // the immediate (3), not the opcode's own base arity, drives it.
        let errs = expect_errors("#pragma version 8\nint 1\nint 2\npopn 3\n");
        assert!(
            errs.iter().any(|e| e
                .message
                .contains("expects 3 stack arguments but stack height is 2")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_cover_rotates_tracked_types() {
        // Stack (bottom -> top) before `cover 1`: [uint64, bytes]. `cover 1`
        // moves the top value (bytes) down one position, so afterward the
        // stack is [bytes, uint64] -- the uint64 that was underneath is now
        // on top, and `btoi` (wants bytes) must fail on it.
        let errs = expect_errors("#pragma version 8\nint 1\nbyte 0x1234\ncover 1\nbtoi\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("btoi arg 0")
                    && e.message.contains("wanted type []byte")),
            "{errs:?}"
        );

        // Popping that same rearranged stack down to nothing and pushing
        // two fresh ints must still assemble cleanly -- `cover` itself
        // didn't desync the tracked height.
        assemble_string(
            "#pragma version 8\nint 1\nbyte 0x1234\ncover 1\npop\npop\nint 2\nint 3\n+\npop\n",
        )
        .unwrap();
    }

    #[test]
    fn test_uncover_rotates_tracked_types() {
        // Stack (bottom -> top) before `uncover 1`: [uint64, bytes].
        // `uncover 1` brings the value one position down (uint64) up to the
        // top, leaving [bytes, uint64] -- `len` (wants bytes) must now fail
        // on the uint64 that ended up on top.
        let errs = expect_errors("#pragma version 8\nint 1\nbyte 0x1234\nuncover 1\nlen\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("len arg 0")
                    && e.message.contains("wanted type []byte")),
            "{errs:?}"
        );

        // `cover 1` then `uncover 1` is an exact round trip: the tracked
        // stack ends up back in its original order ([uint64, bytes]), so
        // `len` on the still-bytes top succeeds.
        assemble_string("#pragma version 8\nint 1\nbyte 0x1234\ncover 1\nuncover 1\nlen\npop\n")
            .unwrap();
    }

    #[test]
    fn test_cover_uncover_unknown_depth_falls_back_to_any() {
        // When the covered/uncovered depth exceeds what's currently
        // tracked -- here, right after a `callsub`'s permissive reset (see
        // `test_type_tracking_callsub_wipes_and_reopens`) -- the pushed
        // types fall back to `Any` (matching go's `typeCover`/`typeUncover`
        // leaving `idx < 0` unresolved), and the height check itself is
        // satisfied by the implicit permissive `Any` supply rather than
        // reporting a spurious error.
        assemble_string(
            "#pragma version 8\ncallsub next\ncover 2\npop\npop\npop\nreturn\nnext:\nint 1\nretsub\n",
        )
        .unwrap();
        assemble_string(
            "#pragma version 8\ncallsub next\nuncover 2\npop\npop\npop\nreturn\nnext:\nint 1\nretsub\n",
        )
        .unwrap();
    }

    #[test]
    fn test_type_tracking_continues_through_txn() {
        // Issue #829, slice 6: unlike the earlier hard-disable, `txn` (and
        // its `gtxn`/`gtxns`/`txna`/`gtxna`/`gtxnsa` siblings) no longer
        // disables tracking -- go's assembler always pushes an opaque
        // `StackAny` here regardless of the accessed field's actual type
        // (see the `type_track` module docs), so `txn Sender`'s pushed
        // value overlaps anything and legitimate code afterward keeps
        // being tracked and checked normally.
        assemble_string(
            "#pragma version 8\ntxn Sender\npop\nbyte 0x1234\nint 1\nint 2\n+\npop\npop\n",
        )
        .unwrap();

        // A genuine type mistake further down the program is still caught
        // -- tracking never got permanently disabled by `txn`.
        let errs =
            expect_errors("#pragma version 8\ntxn Sender\npop\nbyte 0x1234\nint 1\n+\npop\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("+ arg 0")
                    && e.message.contains("wanted type uint64")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_type_tracking_does_not_reject_valid_programs() {
        // A grab-bag of legitimately-typed straight-line programs across
        // this slice's covered opcodes must keep assembling cleanly.
        let sources = [
            "#pragma version 8\nint 1\nint 2\n+\nint 3\n*\npop\n",
            "#pragma version 8\nbyte 0x1234\nbyte 0x5678\nconcat\nlen\npop\n",
            "#pragma version 8\nint 1\nint 2\nmulw\npop\npop\n",
            "#pragma version 8\nint 1\nint 2\naddw\npop\npop\n",
            "#pragma version 8\nint 1\nint 2\nint 3\nint 4\ndivmodw\npop\npop\npop\npop\n",
            "#pragma version 8\nint 1\nint 2\n==\npop\n",
            "#pragma version 8\nbyte 0x1234\nbyte 0x1234\n==\npop\n",
            "#pragma version 8\nint 1\nint 2\nswap\n-\npop\n",
            "#pragma version 8\nint 7\ndup\n+\npop\n",
            "#pragma version 8\nint 1\nint 2\ndup2\n+\n+\n+\npop\n",
            "#pragma version 8\nint 1\nint 2\nint 3\ndig 2\npop\npop\npop\npop\n",
            "#pragma version 8\nint 1\nint 0\nint 1\nselect\npop\n",
            "#pragma version 8\nbyte 0x1234\nint 0\nint 1\nsetbit\npop\n",
            "#pragma version 8\nint 1\nreturn\n",
            "#pragma version 8\nint 1\nassert\nint 1\nreturn\n",
        ];
        for source in sources {
            assemble_string(source).unwrap_or_else(|errs| {
                panic!(
                    "expected {source:?} to assemble cleanly, got: {:?}",
                    errs.iter().map(|e| &e.message).collect::<Vec<_>>()
                )
            });
        }
    }

    // ── `#pragma typetrack` (issue #829, "Slice 4") -- ported from go's
    // `TestPragmas`/`TestTypeTracking` (`assembler_test.go:2981-2988,3007,
    // 3466-3491`) ────────────────────────────────────────────────────────

    #[test]
    fn test_pragma_typetrack_no_value() {
        // go: `testProg(t, "#pragma typetrack", assemblerNoVersion,
        // exp(1, "no typetrack value"))` (assembler_test.go:2981-2982).
        let errs = expect_errors("#pragma typetrack\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.line == 1 && e.message == "no typetrack value"),
            "{errs:?}"
        );
    }

    #[test]
    fn test_pragma_typetrack_bad_value() {
        // go: `testProg(t, "#pragma typetrack blah", assemblerNoVersion,
        // exp(1, `bad #pragma typetrack: "blah"`))` (assembler_test.go:2984-2985).
        let errs = expect_errors("#pragma typetrack blah\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.line == 1 && e.message == "bad #pragma typetrack: \"blah\""),
            "{errs:?}"
        );
    }

    #[test]
    fn test_pragma_typetrack_extra_tokens() {
        // go: `testProg(t, "#pragma typetrack false blah", assemblerNoVersion,
        // exp(1, "unexpected extra tokens: blah"))` (assembler_test.go:2987-2988).
        // This repo's version/autosalt pragmas already use a differently
        // worded (but equivalent) message for this case -- matched here for
        // consistency rather than go's exact wording (see
        // `unexpected tokens after autosalt value`/`after version value`).
        let errs = expect_errors("#pragma typetrack false blah\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.line == 1 && e.message == "unexpected tokens after typetrack value"),
            "{errs:?}"
        );
    }

    #[test]
    fn test_pragma_typetrack_false_suppresses_reported_mismatch() {
        // go: "#pragma typetrack false\n concat" assembles cleanly despite
        // `concat` getting two `uint64`s (`assembler_test.go:3466-3472`).
        let source = "#pragma version 8\nint 1\nint 2\n#pragma typetrack false\nconcat\n";
        assemble_string(source).unwrap_or_else(|errs| {
            panic!("expected {source:?} to assemble cleanly, got: {errs:?}")
        });
    }

    #[test]
    fn test_pragma_typetrack_off_then_on_resets_and_allows_follow_on_code() {
        // go: "Turning type tracking off and then back on, allows any
        // follow-on code." (assembler_test.go:3466-3481) -- the first
        // `concat` (tracking off) leaves a bogus `[]byte` on the tracked
        // stack; re-enabling resets to a permissive state, so the second
        // `concat` (now with tracking on) doesn't see that bogus state and
        // also assembles cleanly.
        let source =
            "#pragma version 8\nint 1\nint 2\n#pragma typetrack false\nconcat\n#pragma typetrack true\nconcat\n";
        assemble_string(source).unwrap_or_else(|errs| {
            panic!("expected {source:?} to assemble cleanly, got: {errs:?}")
        });
    }

    #[test]
    fn test_pragma_typetrack_true_consecutively_does_not_reset() {
        // go: "Declaring type tracking on consecutively does _not_ reset
        // type tracking state." (assembler_test.go:3483-3491): the second
        // `#pragma typetrack true` is a no-op (tracking was already on), so
        // the first `concat`'s real type mismatch is reported.
        let source =
            "#pragma version 8\nint 1\nint 2\n#pragma typetrack true\nconcat\n#pragma typetrack true\nconcat\n";
        let errs = expect_errors(source);
        assert!(
            errs.iter().any(|e| e.message.starts_with("concat")
                && e.message.contains("arg 1 wanted type []byte")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_pragma_typetrack_toggle_mid_program_allowed() {
        // Unlike `#pragma version`/`#pragma autosalt`, go's `typetrack`
        // pragma has no "only allowed before instructions" restriction
        // (`assembler.go:2501-2519` has no `ops.pending.Len() > 0` guard,
        // unlike the `version`/`autosalt` cases right above/below it) --
        // toggling after real instructions have already been assembled must
        // not itself be an error.
        assemble_string("#pragma version 8\nint 1\npop\n#pragma typetrack false\nint 2\npop\n")
            .unwrap();
    }

    #[test]
    fn test_pragma_typetrack_default_is_on() {
        // No pragma at all -> tracking behaves as if `#pragma typetrack
        // true` (go's `newOpStream`'s `typeTracking: true`,
        // `assembler.go:294`) -- a genuine mismatch is still reported.
        let errs = expect_errors("#pragma version 8\nint 1\nint 2\nconcat\n");
        assert!(
            errs.iter().any(|e| e.message.starts_with("concat")
                && e.message.contains("arg 1 wanted type []byte")),
            "{errs:?}"
        );
    }

    // Ported from go-algorand's `TestEvalVersions`
    // (data/transactions/logic/eval_test.go ~line 4384): a single combined
    // scenario chaining both version-related rejection paths against the
    // *same* assembled program, rather than the two paths' unit tests
    // (`test_program_v12_under_v40_consensus_rejected` in `validator.rs` and
    // `test_resolve_illegal_opcode` in `opcode.rs`) being exercised
    // independently as they are today:
    //   1. Assembled normally, the program is fine.
    //   2. Under a protocol/consensus LogicSigVersion ceiling below the
    //      program's own declared version, it's rejected *before* any
    //      opcode is even inspected (go: "greater than protocol supported
    //      version 1"; here: `check_program_version_allowed`'s "exceeds
    //      consensus LogicSigVersion ceiling").
    //   3. With the version *byte in the program itself* hacked down to 1
    //      (bypassing the assembler, since real on-chain bytecode is raw
    //      bytes) while the `txna` opcode bytes (v2+) stay in place, parsing
    //      now fails on the opcode itself, not the protocol ceiling (go:
    //      "illegal opcode 0x36"; here: `bytecode::parse`'s "requires AVM
    //      v2, but program is v1" -- this crate's flat single-table design
    //      reports the same underlying fact with different wording, as
    //      established by every other version-gate test in this crate).
    #[test]
    fn test_eval_versions_protocol_ceiling_then_hacked_version_byte() {
        let source =
            "#pragma version 13\nintcblock 1\nintc_0\ntxna ApplicationArgs 0\npop\nint 1\n";
        let ops = assemble_string(source)
            .unwrap_or_else(|errs| panic!("expected {source:?} to assemble, got: {errs:?}"));

        // Step 1: parses fine as assembled.
        let program = crate::bytecode::parse(&ops.program).expect("assembled program must parse");
        assert_eq!(program.version, 13);

        // Step 2: a protocol/consensus ceiling below the program's declared
        // version rejects it outright.
        let ceiling_err =
            crate::validator::check_program_version_allowed(ops.program[0], 1).unwrap_err();
        assert!(
            format!("{ceiling_err}").contains("exceeds consensus LogicSigVersion ceiling"),
            "{ceiling_err}"
        );

        // Step 3: hack the version byte down to 1, keeping the v2+ `txna`
        // opcode bytes intact -- now the failure comes from the opcode
        // itself, not the protocol ceiling.
        let mut hacked = ops.program.clone();
        hacked[0] = 1;
        let err = crate::bytecode::parse(&hacked).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("txna") && msg.contains("v1"),
            "expected an opcode-version-gate error naming txna and v1, got: {msg}"
        );
    }

    // Ported from go-algorand's `TestPush` (data/transactions/logic/eval_test.go
    // ~line 4983): the assembler's automatic `intcblock`/`intc_N` constant
    // consolidation is a genuine program-size optimization, not just a
    // stylistic choice -- these assert the actual byte-length trade-offs go
    // documents: (1) a lone `int 1` costs more than an explicit `pushint 1`
    // because the intcblock overhead isn't amortized over any other
    // constant; (2) `pushint` buys nothing when it merely replaces a
    // reference that would already fit in a single `intc_0..3` byte; (3)
    // `pushint` wins again once the intcblock has grown past 4 entries, so
    // referencing further entries needs the 2-byte `intc N` form.
    #[test]
    fn test_push_program_size_savings_vs_intcblock() {
        fn program_len(source: &str) -> usize {
            assemble_string(&format!("#pragma version 3\n{source}\n"))
                .unwrap_or_else(|errs| panic!("expected {source:?} to assemble, got: {errs:?}"))
                .program
                .len()
        }

        // A lone constant: pushint has no intcblock overhead to pay.
        assert!(
            program_len("pushint 1") < program_len("int 1"),
            "pushint should be smaller than an intcblock-backed `int` for a single constant"
        );

        // Second distinct constant still fits in the 1-byte intc_0..3 range,
        // so pushint buys nothing -- same total size either way.
        assert_eq!(
            program_len("int 2\nint 1"),
            program_len("int 2\npushint 1"),
            "pushint should be a no-op-sized replacement when the intc reference is 1 byte"
        );

        // With more than 4 distinct constants, referencing the 5th needs the
        // 2-byte `intc N` form, so pushint saves a byte again.
        assert!(
            program_len("int 2\nint 3\nint 5\nint 6\npushint 1")
                < program_len("int 2\nint 3\nint 5\nint 6\nint 1"),
            "pushint should be smaller once the intc reference needs 2 bytes"
        );
    }

    // Ported from go-algorand's `TestBnz` (data/transactions/logic/eval_test.go
    // ~line 708): a program with a `bnz`-guarded "straightline" path that
    // static type-tracking cannot prove unreachable (it merges stack shapes
    // across both branch targets) gets flagged with a real assembler-time
    // type error at the merge point, even though the *runtime* branch taken
    // for these specific literal values never actually executes the
    // offending `*` (only one operand on the stack). `#pragma typetrack
    // false` suppresses the static check entirely, so the identical bytecode
    // assembles and evaluates to accept(1) at runtime.
    const BNZ_PLANB_PROGRAM: &str = "\nint 1\nint 2\nint 1\nint 2\n>\nbnz planb\n*\nint 1\nbnz after\nplanb:\n+\nafter:\ndup\npop\n";

    #[test]
    fn test_bnz_static_typetrack_flags_unreachable_straightline_mismatch() {
        let source = format!("#pragma version {MAX_AVM_VERSION}\n{BNZ_PLANB_PROGRAM}");
        let errs = expect_errors(&source);
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("+")
                    && e.message.contains("expects 2 stack arguments")),
            "expected a `+ expects 2 stack arguments` error, got: {errs:?}"
        );
    }

    #[test]
    fn test_bnz_typetrack_false_allows_and_accepts_at_runtime() {
        let source = format!(
            "#pragma version {MAX_AVM_VERSION}\n#pragma typetrack false\n{BNZ_PLANB_PROGRAM}"
        );
        let ops = assemble_string(&source).unwrap_or_else(|errs| {
            panic!("expected {source:?} to assemble cleanly, got: {errs:?}")
        });
        let program = crate::bytecode::parse(&ops.program).expect("parse assembled program");
        let mut m =
            crate::machine::AvmMachine::new(program, crate::machine::ExecMode::LogicSig, 100_000);
        let pass = m
            .run(&mut crate::context::NullContext)
            .expect("expected runtime evaluation to succeed, not error");
        assert!(pass, "expected the program to accept (result 1)");
    }

    // ── Dispatch-/variable-arity opcodes (issue #829, slice 6): `txn`/
    // `gtxn`/`gtxns` (and `txna`/`gtxna`/`gtxnsa`), `pushbytess`/
    // `pushints`, and `match` all used to permanently disable tracking for
    // the rest of the program; this slice models all four precisely
    // instead ──────────────────────────────────────────────────────────

    #[test]
    fn test_match_typing_ported_from_go() {
        // TestMatchTyping (assembler_test.go:4377-4392): a straight-line
        // program mixing `pushint`/`pushbytes`/`txna` (all pushing known or
        // opaque types) into a `match` must assemble cleanly end to end --
        // exercises `txna`'s new `Any` push (see `TYPE_TABLE`) together
        // with `match`'s `N+1` pop.
        let source = "#pragma version 8\n\
             pushint 0\n\
             pushbytes 0xb17ea35d\n\
             txna ApplicationArgs 0\n\
             match done\n\
             dup\n\
             !\n\
             return\n\
             done:\n";
        assemble_string(source).unwrap();
    }

    #[test]
    fn test_assemble_match_alone_is_a_height_error() {
        // TestAssembleMatch's final sub-case (assembler_test.go:4116-4117):
        // even a label-less `match` still pops 1 (the switched-on value),
        // so a bare `match` at the very start of the program -- nothing
        // tracked on the stack yet -- is a genuine height error, not the
        // no-op `test_assemble_match_empty_match_ok`'s shape (which primes
        // the stack with `pushints 1` first).
        let errs = expect_errors("#pragma version 8\nmatch\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("match expects 1 stack argument")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_match_height_error_uses_label_count_plus_one() {
        // `match` pops `N+1` values (N = number of labels); with only 1
        // value tracked and 2 labels written, that's a height error against
        // 3, not the base proto's single `a` pop.
        let errs =
            expect_errors("#pragma version 8\nint 1\nmatch label1 label2\nlabel1:\nlabel2:\n");
        assert!(
            errs.iter().any(|e| e
                .message
                .contains("match label1 label2 expects 3 stack arguments")
                && e.message.contains("stack height is 1")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_pushbytess_pushes_one_bytes_per_literal() {
        // typePushBytess: each of `pushbytess`'s literals is tracked as
        // `Bytes`, so a following arithmetic opcode that wants `Uint64`
        // must fail on it.
        let errs = expect_errors("#pragma version 8\npushbytess 0xaa 0xbb\n+\n");
        assert!(
            errs.iter().any(|e| e.message.starts_with("+ arg")
                && e.message.contains("wanted type uint64 got []byte")),
            "{errs:?}"
        );

        // The correctly-typed use (two bytes values, concatenated) keeps
        // assembling cleanly.
        assemble_string("#pragma version 8\npushbytess 0xaa 0xbb\nconcat\npop\n").unwrap();
    }

    #[test]
    fn test_pushints_pushes_one_uint64_per_literal() {
        // typePushInts: mirror of the `pushbytess` case above, `Uint64`
        // instead of `Bytes`.
        let errs = expect_errors("#pragma version 8\npushints 1 2\nconcat\n");
        assert!(
            errs.iter().any(|e| e.message.starts_with("concat arg 0")
                && e.message.contains("wanted type []byte")),
            "{errs:?}"
        );

        assemble_string("#pragma version 8\npushints 1 2\n+\npop\n").unwrap();
    }

    #[test]
    fn test_txn_family_pushes_any_type() {
        // go's assembler does not look up the accessed field's actual
        // type for `txn`/`gtxn`/`gtxns`/`txna`/`gtxna`/`gtxnsa` -- every
        // one of them always pushes an opaque `StackAny` (see the
        // `type_track` module docs' "`txn`/`gtxn`/`gtxns`..." section), so
        // the pushed value is happily consumed by either a uint64- or a
        // bytes-wanting opcode.
        assemble_string("#pragma version 8\ntxn Sender\nint 1\n+\npop\n").unwrap();
        assemble_string("#pragma version 8\ntxn Fee\nbyte 0x1234\nconcat\npop\n").unwrap();
    }

    #[test]
    fn test_gtxns_pops_a_typed_uint64_index() {
        // Unlike `txn`/`gtxn`/`txna`/`gtxna` (which take every selector as
        // an assembler immediate and pop nothing), `gtxns`/`gtxnsa` pop a
        // *dynamic* transaction-group index off the stack, and that pop is
        // typed `Uint64` -- a `Bytes` value underneath is a genuine type
        // mismatch, matching go's fixed `"i:a"` proto for these two exactly
        // (see `TYPE_TABLE`).
        let errs = expect_errors("#pragma version 8\nbyte 0x1234\ngtxns Sender\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("gtxns Sender arg 0")
                    && e.message.contains("wanted type uint64")),
            "{errs:?}"
        );

        assemble_string("#pragma version 8\nint 0\ngtxns Sender\npop\n").unwrap();
    }

    #[test]
    fn test_type_complaints_ported_from_go() {
        // TestTypeComplaints (eval_test.go:5979-5985): `store 0` reached
        // only after `err`/`return` has already deadened tracking must not
        // itself be flagged, even though a bare `store` needs a stack
        // value and there wouldn't be one live at that point -- already
        // covered by slice 2's dead-code handling, pinned here as a direct
        // port rather than only incidentally exercised elsewhere.
        assemble_string("#pragma version 8\nerr\nstore 0\n").unwrap();
        assemble_string("#pragma version 8\nint 1\nreturn\nstore 0\n").unwrap();
    }

    // ── `itxn_field`'s field-type-aware refinement (issue #829, slice 7):
    // TestTxTypes (assembler_test.go:3373-3384) ─────────────────────────

    #[test]
    fn test_itxn_field_type_checks_ported_from_go() {
        // TestTxTypes: `itxn_field Sender` refines its popped-value type
        // to `Sender`'s own type (`Bytes`, an address in go's bounds-aware
        // model -- see `itxn_field_type`'s doc comment on why the
        // bound-free `Bytes` match here is exactly as precise as go's for
        // this verdict). An `int` value is a genuine type mismatch.
        let errs = expect_errors("#pragma version 8\nitxn_begin\nint 1\nitxn_field Sender\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("itxn_field Sender arg 0")
                    && e.message.contains("wanted type []byte got uint64")),
            "{errs:?}"
        );

        // A `byte` value is correctly typed for `Sender`.
        assemble_string(
            "#pragma version 8\nitxn_begin\nbyte 0x0102030405060708091011121314151617181920212223242526272829303132\nitxn_field Sender\n",
        )
        .unwrap();

        // `itxn_field Amount` refines to `Uint64` -- a `byte` value is a
        // genuine mismatch, the reverse of the `Sender` case above.
        let errs = expect_errors("#pragma version 8\nitxn_begin\nbyte 0x1234\nitxn_field Amount\n");
        assert!(
            errs.iter()
                .any(|e| e.message.starts_with("itxn_field Amount arg 0")
                    && e.message.contains("wanted type uint64 got []byte")),
            "{errs:?}"
        );

        // An `int` value is correctly typed for `Amount`.
        assemble_string("#pragma version 8\nitxn_begin\nint 1\nitxn_field Amount\n").unwrap();
    }

    #[test]
    fn test_itxn_field_missing_arg_is_a_height_error_not_a_type_error() {
        // TestTxTypes: `itxn_field Sender` with nothing on the stack is
        // still just the base proto's ordinary height error -- the field
        // refinement only changes the *type* checked once an argument is
        // actually there to check, matching go's `typeTxField` being
        // consulted only after `trackStack`'s height check passes.
        let errs = expect_errors("#pragma version 8\nitxn_begin\nitxn_field Sender\n");
        assert!(
            errs.iter().any(|e| e
                .message
                .starts_with("itxn_field Sender expects 1 stack argument")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_itxn_field_unrecognized_field_name_falls_back_to_any() {
        // typeTxField's `!ok` early return (assembler.go:1536-1539): an
        // unrecognized field name leaves the base proto's opaque `Any` pop
        // untouched, so any value type is accepted here -- the unknown
        // field name is reported as its own, unrelated assembly error
        // elsewhere, not as a type mismatch.
        let errs = expect_errors("#pragma version 8\nitxn_begin\nint 1\nitxn_field NotAField\n");
        assert!(
            !errs
                .iter()
                .any(|e| e.message.contains("wanted type") && e.message.contains("NotAField")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_dig_asm_ported_from_go() {
        // TestDigAsm (assembler_test.go#L3178): assembly-time immediate
        // arity/parse errors, plus static type-tracking through `dig`.
        let errs = expect_errors("#pragma version 8\nint 1\ndig\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("dig expects 1")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 1\ndig junk\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("unable to parse")),
            "{errs:?}"
        );

        assemble_string("#pragma version 8\nint 1\nbyte 0x1234\nint 2\ndig 2\n+\n").unwrap();

        let errs = expect_errors("#pragma version 8\nbyte 0x32\nbyte 0x1234\nint 2\ndig 2\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 1")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nbyte 0x32\nbyte 0x1234\nint 2\ndig 3\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("dig 3 expects 4")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 1\nbyte 0x1234\nint 2\ndig 12\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("dig 12 expects 13")),
            "{errs:?}"
        );

        // Digging something out does not ruin our knowledge about the
        // types in the middle.
        let errs = expect_errors(
            "#pragma version 8\nint 1\nbyte 0x1234\nbyte 0x1234\ndig 2\ndig 3\n+\npop\n+\n",
        );
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 1")),
            "{errs:?}"
        );

        assemble_string(
            "#pragma version 8\nint 3\npushbytes \"123456\"\nint 1\ndig 2\nsubstring3\n",
        )
        .unwrap();
    }

    #[test]
    fn test_bury_asm_ported_from_go() {
        // TestBuryAsm (assembler_test.go#L3199), full port. Fixed in
        // issue #1364: `type_track.rs`'s `refined_types` now has a `"bury"`
        // arm mirroring go's `typeBury` (height check via the `n+1` pop
        // count, buried-slot type update, and the `bury 0`-always-fails
        // special case).
        let errs = expect_errors("#pragma version 8\nint 1\nbury\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("bury expects 1")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 1\nbury junk\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("unable to parse")),
            "{errs:?}"
        );

        // "the 2 replaces the byte string" -- `bury 1` overwrites the
        // byte-string slot with the int on top, so `+` sees two uint64s.
        assemble_string("#pragma version 8\nint 1\nbyte 0x1234\nint 2\nbury 1\n+\n").unwrap();

        let errs = expect_errors("#pragma version 8\nint 2\nint 2\nbyte 0x1234\nbury 1\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 1")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nbyte 0x32\nbyte 0x1234\nint 2\nbury 3\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("bury 3 expects 4")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 1\nbyte 0x1234\nint 2\nbury 12\n+\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("bury 12 expects 13")),
            "{errs:?}"
        );

        // We do not lose track of the ints between ToS and the bury index.
        let errs = expect_errors("#pragma version 8\nint 0\nint 1\nint 2\nint 4\nbury 3\nconcat\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("concat arg 1 wanted type []byte")),
            "{errs:?}"
        );

        // Even when we are burying into unknown (seems repetitive, but is
        // an easy bug): a permissive bottom (reached via a label after
        // dead code) must not silently swallow this check either.
        let errs = expect_errors(
            "#pragma version 8\nint 0\nint 0\nb LABEL\nLABEL:\nint 1\nint 2\nint 4\nbury 4\nconcat\n",
        );
        assert!(
            errs.iter()
                .any(|e| e.message.contains("concat arg 1 wanted type []byte")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nintcblock 55\nbury 1\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("bury 1 expects 2 stack arguments")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nintcblock 55\nint 2\nbury 1\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("bury 1 expects 2 stack arguments")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 3\nint 2\nbury 0\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("bury 0 always fails")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_proto_asm_ported_from_go() {
        // TestProtoAsm (assembler_test.go#L3331), full port. Fixed in issue
        // #1383: `type_track.rs`'s `track_instruction` now has a `"proto"`
        // special case mirroring go's `typeProto` -- a `proto` reached with
        // a non-empty tracked stack, or without a permissive bottom (i.e.
        // not reached only via dead code / an unconditional branch), is
        // statically rejected.
        let errs = expect_errors("#pragma version 8\nproto 0 0\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("proto must be unreachable")),
            "{errs:?}"
        );

        // `#pragma typetrack false` suppresses the check, like every other
        // static type-tracking diagnostic.
        assemble_string("#pragma version 8\n#pragma typetrack false\nproto 0 0\n").unwrap();

        // Reached only through an unconditional branch (`b a`) -- the `int
        // 1` in between is dead code, and the label reopens analysis with a
        // permissive bottom, so `proto` is fine here.
        assemble_string("#pragma version 8\nb a\nint 1\na:\nproto 0 0\n").unwrap();

        // `main:` is reached only via `callsub`/after an unconditional
        // `return` -- both cases give a permissive bottom, so `proto 2 1`
        // is accepted, and the whole program assembles cleanly (go's own
        // comment on this case -- "This consumes the top arg. We complain."
        // -- is stale: `testProg` is called with no `exp(...)`, i.e. zero
        // errors expected, and `dup; dup` right after restores the height
        // before `retsub` either way).
        assemble_string(
            "#pragma version 8\nint 10\nint 20\ncallsub main\nint 1\nreturn\nmain:\nproto 2 1\n+\ndup\ndup\nretsub\n",
        )
        .unwrap();
    }

    #[test]
    fn test_cover_asm_ported_from_go() {
        // TestCoverAsm (assembler_test.go#L3353).
        assemble_string("#pragma version 8\nint 4\nbyte \"john\"\nint 5\ncover 2\npop\n+\n")
            .unwrap();
        assemble_string("#pragma version 8\nint 4\nbyte \"ayush\"\nint 5\ncover 1\npop\n+\n")
            .unwrap();

        let errs = expect_errors("#pragma version 8\nint 4\nbyte \"john\"\nint 5\ncover 2\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 1")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\nint 4\ncover junk\n");
        assert!(
            errs.iter().any(|e| e.message.contains("unable to parse")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_uncover_asm_ported_from_go() {
        // TestUncoverAsm (assembler_test.go#L3364).
        assemble_string("#pragma version 8\nint 4\nbyte \"john\"\nint 5\nuncover 2\n+\n").unwrap();
        assemble_string("#pragma version 8\nint 4\nbyte \"ayush\"\nint 5\nuncover 1\npop\n+\n")
            .unwrap();
        assemble_string(
            "#pragma version 8\nint 1\nbyte \"jj\"\nbyte \"ayush\"\nbyte \"john\"\nint 5\nuncover 4\n+\n",
        )
        .unwrap();

        let errs = expect_errors("#pragma version 8\nint 4\nbyte \"ayush\"\nint 5\nuncover 1\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 1")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_assemble_balance_type_check_ported_from_go() {
        // TestAssembleBalance (assembler_test.go#L2388): `balance`'s
        // argument type should be `uint64` (foreign-accounts-array index)
        // below `directRefEnabledVersion` (=4), and `Any` (a direct address
        // reference, e.g. an address literal, is also accepted) from v4 on
        // -- opcodes.go:668-669. Below v4, a `[1]byte` value in the
        // `uint64`-only proto must be rejected with "balance arg 0 wanted
        // type uint64 got [1]byte" (issue #1366, fixed via the same
        // version-gated `refined_types` arm `asset_holding_get` already
        // has).
        let source = "byte 0x00\nbalance\nint 1\n==\n";
        const DIRECT_REF_ENABLED_VERSION: u8 = 4;
        for v in 2..DIRECT_REF_ENABLED_VERSION {
            let errs = expect_errors(&format!("#pragma version {v}\n{source}"));
            // go's error also reports the exact bound length ("got
            // [1]byte") -- this module's `StackType` doesn't model bound
            // lengths (see `asset_holding_get`'s equivalent test), so only
            // the "wanted type uint64" half is asserted here.
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("balance arg 0 wanted type uint64")),
                "v{v}: {errs:?}"
            );
        }
        for v in DIRECT_REF_ENABLED_VERSION..=opcode::MAX_AVM_VERSION {
            assemble_string(&format!("#pragma version {v}\n{source}")).unwrap();
        }
    }

    #[test]
    fn test_assemble_min_balance_type_check_ported_from_go() {
        // TestAssembleMinBalance (assembler_test.go#L2404): same pattern as
        // TestAssembleBalance above (issue #1366), for `min_balance`
        // (introduced at v3, opcodes.go:693-694).
        let source = "byte 0x00\nmin_balance\nint 1\n==\n";
        const DIRECT_REF_ENABLED_VERSION: u8 = 4;
        for v in 3..DIRECT_REF_ENABLED_VERSION {
            let errs = expect_errors(&format!("#pragma version {v}\n{source}"));
            // Same bound-length caveat as `test_assemble_balance_type_check_ported_from_go`
            // above.
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("min_balance arg 0 wanted type uint64")),
                "v{v}: {errs:?}"
            );
        }
        for v in DIRECT_REF_ENABLED_VERSION..=opcode::MAX_AVM_VERSION {
            assemble_string(&format!("#pragma version {v}\n{source}")).unwrap();
        }
    }

    #[test]
    fn test_method_warning_ported_from_go() {
        // TestMethodWarning (assembler_test.go#L3091): go's `asmMethod`
        // calls `abi.VerifyMethodSignature` and pushes a non-fatal
        // `AssemblyWarning` ("invalid ARC-4 ABI method signature for
        // method op") when the string literal isn't a well-formed ARC-4
        // method signature -- assembly still succeeds either way.
        let tests: &[(&str, bool)] = &[
            ("abc(uint64)void", true),
            ("abc(uint64)", false),
            ("abc(uint65)void", false),
            ("(uint64)void", false),
            ("abc(uint65,void", false),
        ];
        for (method, pass) in tests {
            let source = format!("method \"{method}\"\nint 1\n");
            for v in 1..=opcode::MAX_AVM_VERSION {
                let ops = assemble_string(&format!("#pragma version {v}\n{source}")).unwrap();
                if *pass {
                    assert!(
                        ops.warnings.is_empty(),
                        "v{v} {method:?}: expected no warnings for a well-formed signature, got {:?}",
                        ops.warnings
                    );
                } else {
                    assert_eq!(
                        ops.warnings.len(),
                        1,
                        "v{v} {method:?}: expected exactly one warning, got {:?}",
                        ops.warnings
                    );
                    assert!(
                        ops.warnings[0]
                            .message
                            .contains("invalid ARC-4 ABI method signature for method op"),
                        "v{v} {method:?}: unexpected warning message {:?}",
                        ops.warnings[0]
                    );
                }
            }
        }
    }

    #[test]
    fn test_assemble_push_consts_ported_from_go() {
        // TestAssemblePushConsts (assembler_test.go#L4121).
        assemble_string("#pragma version 8\npushints\nint 1\n").unwrap();
        assemble_string("#pragma version 8\npushbytess\nint 1\n").unwrap();

        let ops = assemble_string("#pragma version 8\npushints 1 2 3\nint 1\n").unwrap();
        // prefix (2 bytes: version + int 1 pushed at the *end*, so just
        // check the pushints instruction's own encoded length here instead
        // of a fixed total-program length, since our harness always
        // appends a trailing `int 1` to keep the stack balanced for
        // `assemble_string`'s no-args-required success path).
        assert!(ops.program.len() >= 5);

        let ops =
            assemble_string("#pragma version 8\npushbytess \"1\" \"2\" \"33\"\nint 1\n").unwrap();
        assert!(ops.program.len() >= 9);

        // 256 increases size of encoded length to two bytes.
        let vals_str = vec!["1"; 256].join(" ");
        let ops =
            assemble_string(&format!("#pragma version 8\npushints {vals_str}\nint 1\n")).unwrap();
        assert!(ops.program.len() >= 259);

        let vals_str = vec!["\"1\""; 256].join(" ");
        let ops = assemble_string(&format!(
            "#pragma version 8\npushbytess {vals_str}\nint 1\n"
        ))
        .unwrap();
        assert!(ops.program.len() >= 515);

        // Enforce correct types.
        let errs = expect_errors("#pragma version 8\npushints \"1\" \"2\" \"3\"\n");
        assert!(!errs.is_empty(), "{errs:?}");

        let errs = expect_errors("#pragma version 8\npushbytess 1 2 3\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("pushbytess arg did not parse")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\npushints 6 4\nconcat\n");
        assert!(
            errs.iter().any(|e| e.message.contains("concat arg 1")),
            "{errs:?}"
        );

        let errs = expect_errors("#pragma version 8\npushbytess \"x\" \"y\"\n+\n");
        assert!(
            errs.iter().any(|e| e.message.contains("+ arg 1")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_constant_args_ported_from_go() {
        // TestConstantArgs (assembler_test.go#L2191).
        for v in 1..=opcode::MAX_AVM_VERSION {
            let pfx = format!("#pragma version {v}\n");

            let errs = expect_errors(&format!("{pfx}int"));
            assert!(
                errs.iter().any(|e| e.message.contains("int expects 1")),
                "v{v} int: {errs:?}"
            );
            assemble_string(&format!("{pfx}int pay")).unwrap();
            let errs = expect_errors(&format!("{pfx}int pya"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("unable to parse") && e.message.contains("pya")),
                "v{v} int pya: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}int 1 2"));
            assert!(
                errs.iter().any(|e| e.message.contains("int expects 1")),
                "v{v} int 1 2: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}intc"));
            assert!(
                errs.iter().any(|e| e.message.contains("intc expects 1")),
                "v{v} intc: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}intc pay"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("unable to parse") && e.message.contains("pay")),
                "v{v} intc pay: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}intc hi bye"));
            assert!(
                errs.iter().any(|e| e.message.contains("intc expects 1")),
                "v{v} intc hi bye: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}byte"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("byte needs byte literal argument")),
                "v{v} byte: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}byte b32"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("byte b32 needs byte literal argument")),
                "v{v} byte b32: {errs:?}"
            );
            // go rejects `byte 0xaa 0xbb` / `byte b32 X X` with "byte with
            // extraneous argument" (asmByte checks `parseBinaryArgs`'s
            // `consumed` token count against `len(args)`, assembler.go:853).
            let errs = expect_errors(&format!("{pfx}byte 0xaa 0xbb"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("byte with extraneous argument")),
                "v{v} byte 0xaa 0xbb: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}byte b32 MFRGGZDFMY MFRGGZDFMY"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("byte with extraneous argument")),
                "v{v} byte b32 MFRGGZDFMY MFRGGZDFMY: {errs:?}"
            );
            assemble_string(&format!(
                "{pfx}byte 0x{}",
                "aa".repeat(opcode::MAX_STRING_SIZE)
            ))
            .unwrap();
            let errs = expect_errors(&format!(
                "{pfx}byte 0x{}",
                "aa".repeat(opcode::MAX_STRING_SIZE + 1)
            ));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("byte value is too big")),
                "v{v} oversized byte: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}bytec"));
            assert!(
                errs.iter().any(|e| e.message.contains("bytec expects 1")),
                "v{v} bytec: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}bytec 1 x"));
            assert!(
                errs.iter().any(|e| e.message.contains("bytec expects 1")),
                "v{v} bytec 1 x: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}bytec pay"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("unable to parse") && e.message.contains("pay")),
                "v{v} bytec pay: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}addr"));
            assert!(
                errs.iter().any(|e| e.message.contains("addr expects 1")),
                "v{v} addr: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}addr x   y"));
            assert!(
                errs.iter().any(|e| e.message.contains("addr expects 1")),
                "v{v} addr x   y: {errs:?}"
            );
            // go's exact wording is "failed to decode address x ...";
            // algod-rust's `asm_addr` reports the same rejection via a
            // differently-worded "addr: invalid address encoding: ..."
            // message -- same reject verdict, different text.
            let errs = expect_errors(&format!("{pfx}addr x"));
            assert!(
                errs.iter().any(|e| e.message.contains("addr")),
                "v{v} addr x: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}method"));
            assert!(
                errs.iter().any(|e| e.message.contains("method expects 1")),
                "v{v} method: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}method xx yy"));
            assert!(
                errs.iter().any(|e| e.message.contains("method expects 1")),
                "v{v} method xx yy: {errs:?}"
            );
            // go's `parseStringLiteral` reports this exact case ("\x" with
            // zero hex digits before the closing quote) as
            // "non-terminated escape sequence" via a post-loop
            // still-mid-hex-escape check; algod-rust's `parse_string_literal`
            // instead reports "non-terminated hex sequence" for the same
            // input (it doesn't distinguish the zero-hex-digits-remaining
            // case from the one-hex-digit-remaining case the way go's
            // separate in-loop/post-loop checks do) -- same reject verdict
            // (assembly fails either way), different message text.
            let errs = expect_errors(&format!("{pfx}method \"x\\x\""));
            assert!(
                errs.iter().any(|e| e.message.contains("non-terminated")),
                "v{v} method x\\x: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}method xx"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("unable to parse method signature")),
                "v{v} method xx: {errs:?}"
            );
        }

        for v in 3..=opcode::MAX_AVM_VERSION {
            let pfx = format!("#pragma version {v}\n");
            let errs = expect_errors(&format!("{pfx}pushint"));
            assert!(
                errs.iter().any(|e| e.message.contains("pushint expects 1")),
                "v{v} pushint: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}pushint 3 4"));
            assert!(
                errs.iter().any(|e| e.message.contains("pushint expects 1")),
                "v{v} pushint 3 4: {errs:?}"
            );
            // go's exact wording is `unable to parse "x" as integer`;
            // algod-rust's `pushint` reports the underlying Rust integer
            // parse error text instead ("invalid digit found in string") --
            // same reject verdict, different text.
            let errs = expect_errors(&format!("{pfx}pushint x"));
            assert!(!errs.is_empty(), "v{v} pushint x: {errs:?}");
            let errs = expect_errors(&format!("{pfx}pushbytes"));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("pushbytes needs byte literal argument")),
                "v{v} pushbytes: {errs:?}"
            );
            let errs = expect_errors(&format!("{pfx}pushbytes b32"));
            assert!(
                errs.iter().any(|e| e
                    .message
                    .contains("pushbytes b32 needs byte literal argument")),
                "v{v} pushbytes b32: {errs:?}"
            );
            assemble_string(&format!(
                "{pfx}pushbytes 0x{}",
                "aa".repeat(opcode::MAX_STRING_SIZE)
            ))
            .unwrap();
            let errs = expect_errors(&format!(
                "{pfx}pushbytes 0x{}",
                "aa".repeat(opcode::MAX_STRING_SIZE + 1)
            ));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("pushbytes value is too big")),
                "v{v} oversized pushbytes: {errs:?}"
            );
        }

        for v in 8..=opcode::MAX_AVM_VERSION {
            let pfx = format!("#pragma version {v}\n");
            assemble_string(&format!("{pfx}pushints")).unwrap();
            assemble_string(&format!("{pfx}pushints 200")).unwrap();
            assemble_string(&format!("{pfx}pushints 3 4")).unwrap();
            assemble_string(&format!("{pfx}pushbytess")).unwrap();
            assemble_string(&format!("{pfx}pushbytess 0xff")).unwrap();
            assemble_string(&format!("{pfx}pushbytess 0xaa 0xbb")).unwrap();
            assemble_string(&format!(
                "{pfx}bytecblock 0x{}",
                "aa".repeat(opcode::MAX_STRING_SIZE)
            ))
            .unwrap();
            let errs = expect_errors(&format!(
                "{pfx}bytecblock 0x{}",
                "aa".repeat(opcode::MAX_STRING_SIZE + 1)
            ));
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("bytecblock arg 0 is too big")),
                "v{v} oversized bytecblock: {errs:?}"
            );
        }
    }

    // ─── issue #1363 batch: parity_txn_logic.md `partial`-row sweep ───────

    #[test]
    fn test_byte_odd_length_hex_rejected_ported_from_go() {
        // Ports the second (source-level) assertion of go's `TestOpBytes`
        // (assembler_test.go#L1219): `byte 0x7` -- an odd-length hex
        // literal -- is rejected at every AVM version. The first assertion
        // of `TestOpBytes` exercises go's internal `OpStream.byteLiteral`
        // two-phase API directly (bypassing the v4+ single-use constant
        // optimizer that the real `AssembleString` entry point always
        // applies); rust's single-pass assembler has no equivalent
        // pre-optimization unit boundary to reproduce that half.
        for v in 1..=MAX_AVM_VERSION {
            let src = format!("#pragma version {v}\nbyte 0x7\nlen\n");
            let errs = expect_errors(&src);
            assert!(
                errs.iter().any(|e| e.message.to_lowercase().contains("odd")
                    && e.message.to_lowercase().contains("hex")),
                "v{v}: {errs:?}"
            );
        }
    }

    #[test]
    fn test_assemble_reject_neg_jump_ported_from_go() {
        // Ports go's `TestAssembleRejectNegJump` (assembler_test.go#L1813):
        // a `bnz` to a label defined earlier in the source (a back
        // reference) is rejected pre-`BACK_BRANCH_ENABLED_VERSION` (v4)
        // with the "back reference" message, and accepted from v4 on.
        let source = "wat:\nint 1\nbnz wat\nint 2\n";
        for v in 1u8..BACK_BRANCH_ENABLED_VERSION {
            let src = format!("#pragma version {v}\n{source}");
            let errs = expect_errors(&src);
            assert!(
                errs.iter()
                    .any(|e| e.message.contains("is a back reference")),
                "v{v}: {errs:?}"
            );
        }
        for v in BACK_BRANCH_ENABLED_VERSION..=MAX_AVM_VERSION {
            let src = format!("#pragma version {v}\n{source}");
            assemble_string(&src).unwrap_or_else(|e| panic!("v{v} should assemble: {e:?}"));
        }
    }

    #[test]
    fn test_disassemble_int_multi_constant_annotations_ported_from_go() {
        // Ports go's `TestDisassembleInt` (assembler_test.go#L2469): of six
        // `int` literals, the one repeated value (17) goes into the
        // constant block and disassembles with a `// 17` comment; the four
        // singly-used values (27, 37, 47, 5) are inlined as `pushint N`.
        let source = format!(
            "#pragma version {v}\nint 17\nint 27\nint 37\nint 47\nint 5\nint 17\n",
            v = MAX_AVM_VERSION
        );
        let ops = assemble_string(&source).unwrap();
        let text = crate::disassembler::disassemble(&ops.program).unwrap();
        assert!(text.contains("// 17"), "{text}");
        assert!(text.contains("pushint 27"), "{text}");
        assert!(text.contains("pushint 37"), "{text}");
        assert!(text.contains("pushint 47"), "{text}");
        assert!(text.contains("pushint 5"), "{text}");
    }

    #[test]
    fn test_pragma_unsupported_directive_rejected_ported_from_go() {
        // Ports the final assertion of go's `TestAssemblePragmaVersion`
        // (assembler_test.go#L3014): `#pragma unk` is rejected as an
        // unsupported pragma directive. (The earlier `assemblerNoVersion`
        // caller-supplied-expected-version-vs-`#pragma version` mismatch
        // assertions in that same go test exercise `AssembleStringWithVersion`,
        // a production API taking an explicit expected version, that rust's
        // single `assemble_string(text)` entry point -- which always derives
        // the version from the source's own `#pragma version`/default -- has
        // no equivalent surface for; the "defaults to v1 with no pragma"
        // sub-case is already covered by `test_assemble_default_version_is_one`.)
        let errs = expect_errors("#pragma unk\nint 1\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("unsupported pragma directive")
                    && e.message.contains("unk")),
            "{errs:?}"
        );
    }

    #[test]
    fn test_manual_cblocks_ported_from_go() {
        // Ports the previously-untested error/optimization sub-cases of
        // go's `TestManualCBlocks` (assembler_test.go#L1363); the
        // dead-code-manual-cblock-doesn't-block-auto-insertion sub-cases
        // are already covered by `test_manual_cblock_eval_dead_intcblock_does_not_block_auto_insertion`
        // / `..._bytecblock_...` above (ported from the sibling
        // `TestManualCBlockEval`), and the cross-program byte-equality
        // (`checkSame`) assertions mixing `int`/`intc` against a manual
        // block are left for a follow-up (they re-exercise the same
        // manual-cblock-lookup path this test already covers, just via
        // several textually-different-but-equivalent programs).

        // "Despite appearing twice, 500s are pushints because of manual
        // intcblock": once there's a manual `intcblock` at
        // BACK_BRANCH_ENABLED_VERSION+, a repeated `int` literal still
        // compiles to `pushint`, not `intc`, per go's `asmInt`.
        let source = format!(
            "#pragma version {v}\nintcblock 1\nint 500\nint 500\n==\n",
            v = MAX_AVM_VERSION
        );
        let ops = assemble_string(&source).unwrap();
        let pushint_opcode = opcode::lookup_by_name("pushint")
            .expect("pushint exists")
            .opcode;
        assert_eq!(
            ops.program[4], pushint_opcode,
            "expected pushint at byte 4: {:x?}",
            ops.program
        );

        // "But complain if they [ints] do not [appear in the manual block]"
        // -- only pre-BACK_BRANCH_ENABLED_VERSION: at v4+, go's `asmInt`
        // takes the manual-cblock-present branch *before* the
        // does-it-appear check and unconditionally falls back to
        // `pushint` instead (see the `pushint`-conversion assertion
        // above), so this specific rejection is a pre-v4-only path.
        let errs = expect_errors("#pragma version 3\nintcblock 4\nint 3\n");
        assert!(
            errs.iter()
                .any(|e| e.message.contains("value 3 does not appear")),
            "{errs:?}"
        );

        // "Or if the ref comes before the constant block" -- `intcblock`
        // may not follow a plain `int` literal at all, matched or not.
        for v in [3u8, 4u8] {
            let errs = expect_errors(&format!("#pragma version {v}\nint 5\nintcblock 4\n"));
            assert!(
                errs.iter().any(|e| e.message == "intcblock following int"),
                "v{v}: {errs:?}"
            );
            let errs = expect_errors(&format!("#pragma version {v}\nint 4\nintcblock 4\n"));
            assert!(
                errs.iter().any(|e| e.message == "intcblock following int"),
                "v{v}: {errs:?}"
            );
        }

        // Same for `bytecblock` following `byte`/`addr`/`method`.
        for v in [3u8, 4u8] {
            let errs = expect_errors(&format!(
                "#pragma version {v}\naddr RWXCBB73XJITATVQFOI7MVUUQOL2PFDDSDUMW4H4T2SNSX4SEUOQ2MM7F4\nbytecblock 0x44\n"
            ));
            assert!(
                errs.iter()
                    .any(|e| e.message == "bytecblock following byte/addr/method"),
                "v{v}: {errs:?}"
            );
        }
    }
}
