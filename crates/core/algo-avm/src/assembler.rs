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

use crate::fields;
use crate::opcode::{self, ImmKind, MAX_AVM_VERSION};

/// The first AVM version where constant optimization is enabled.
const OPTIMIZE_CONSTANTS_ENABLED_VERSION: u8 = 4;

/// Default assembler version when no `#pragma version` is specified.
const ASSEMBLER_DEFAULT_VERSION: u8 = 1;

/// AVM version where back-branches were introduced.
const BACK_BRANCH_ENABLED_VERSION: u8 = 4;

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

// ---------------------------------------------------------------------------
// Source location
// ---------------------------------------------------------------------------

/// A position in source code (0-based line and column).
#[derive(Debug, Clone, Copy, Default)]
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
    /// PC-to-source-line mapping.
    pub offset_to_source: HashMap<usize, SourceLocation>,

    // Internal state
    pending: Vec<u8>,
    labels: HashMap<String, usize>,
    label_references: Vec<LabelReference>,

    intc: Vec<u64>,
    intc_refs: Vec<IntReference>,
    cnt_intc_block: usize,
    has_pseudo_int: bool,

    bytec: Vec<Vec<u8>>,
    bytec_refs: Vec<ByteReference>,
    cnt_bytec_block: usize,
    has_pseudo_byte: bool,

    source_line: usize,
}

impl OpStream {
    fn new() -> Self {
        Self {
            program: Vec::new(),
            version: 0, // will be set by pragma or default
            errors: Vec::new(),
            offset_to_source: HashMap::new(),
            pending: Vec::new(),
            labels: HashMap::new(),
            label_references: Vec::new(),
            intc: Vec::new(),
            intc_refs: Vec::new(),
            cnt_intc_block: 0,
            has_pseudo_int: false,
            bytec: Vec::new(),
            bytec_refs: Vec::new(),
            cnt_bytec_block: 0,
            has_pseudo_byte: false,
            source_line: 0,
        }
    }

    fn record_error(&mut self, line: usize, col: usize, msg: String) {
        self.errors.push(AssemblyError {
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

    fn prepend_cblocks(&mut self) -> Vec<u8> {
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

        // Fixup offset-to-source mapping: shift all offsets by pbl (which
        // includes the version byte). Matches go-algorand's unconditional shift.
        {
            let shift = pbl;
            let mut new_map = HashMap::new();
            for (&pos, &loc) in &self.offset_to_source {
                new_map.insert(pos + shift, loc);
            }
            self.offset_to_source = new_map;
        }

        out
    }
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

    for (line_idx, line_text) in lines.iter().enumerate() {
        ops.source_line = line_idx + 1; // 1-based
        let trimmed = line_text.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with(';') {
            continue;
        }

        // Strip inline comments
        let code = strip_comment(trimmed);
        if code.is_empty() {
            continue;
        }

        // Handle pragma
        if code.starts_with('#') {
            if code.starts_with("#pragma") {
                let parts: Vec<&str> = code.split_whitespace().collect();
                if parts.len() == 1 {
                    // #pragma with no keyword
                    ops.record_error(ops.source_line, 0, "empty pragma".into());
                } else if parts[1] != "version" {
                    // #pragma <unknown>
                    ops.record_error(
                        ops.source_line,
                        0,
                        format!("unsupported pragma directive: {}", parts[1]),
                    );
                } else if parts.len() == 2 {
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
                            ops.record_error(
                                ops.source_line,
                                0,
                                format!("unsupported version: {v}"),
                            );
                        } else {
                            ops.version = v;
                            version_set = true;
                        }
                    } else {
                        ops.record_error(
                            ops.source_line,
                            0,
                            format!("invalid version: {}", parts[2]),
                        );
                    }
                }
            }
            continue;
        }

        // If no version set yet, default
        if !version_set && ops.version == 0 {
            ops.version = ASSEMBLER_DEFAULT_VERSION;
            version_set = true;
        }

        // Tokenize the line
        let tokens = tokenize(code);
        if tokens.is_empty() {
            continue;
        }

        let mut tok_idx = 0;

        // Handle labels
        if tokens[0].ends_with(':') {
            let label = &tokens[0][..tokens[0].len() - 1];
            if ops.labels.contains_key(label) {
                ops.record_error(ops.source_line, 0, format!("duplicate label {:?}", label));
            } else {
                ops.labels.insert(label.to_string(), ops.pending.len());
            }
            tok_idx = 1;
            if tok_idx >= tokens.len() {
                continue;
            }
        }

        let mnemonic = &tokens[tok_idx];
        let args: Vec<&str> = tokens[tok_idx + 1..].to_vec();

        ops.record_source_location(ops.source_line, 0);
        assemble_instruction(&mut ops, mnemonic, &args);
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

    // Prepend version byte and constant blocks
    ops.program = ops.prepend_cblocks();

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
        _ => asm_regular(ops, mnemonic, args),
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
        Ok((val, _consumed)) => {
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
        Ok((val, _consumed)) => {
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
    if ops.has_pseudo_int {
        ops.record_error(ops.source_line, 0, "intcblock following int".into());
    }
    ops.intc_refs.clear();
    ops.intc = vals;
    ops.cnt_intc_block += 1;
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

fn asm_regular(ops: &mut OpStream, mnemonic: &str, args: &[&str]) {
    let spec = match opcode::lookup_by_name(mnemonic) {
        Some(s) => s,
        None => {
            ops.record_error(
                ops.source_line,
                0,
                format!("unknown opcode: {:?}", mnemonic),
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
            ops.pending.push(spec.opcode);
            // Check if this opcode uses a field group
            if let Some(val) = resolve_field_immediate(ops, mnemonic, args[0]) {
                ops.pending.push(val);
            } else if let Ok(val) = parse_uint8_or_int8(args[0], mnemonic) {
                ops.pending.push(val);
            } else {
                ops.record_error(
                    ops.source_line,
                    0,
                    format!("{} unknown field: {:?}", mnemonic, args[0]),
                );
                // Remove the opcode we just pushed since the arg is invalid
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
        ("app_params_get", 0) => fields::app_params_field_by_name(arg),
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
    // For frame_dig and frame_bury, the immediate is an int8 encoded as uint8
    if mnemonic == "frame_dig" || mnemonic == "frame_bury" {
        if let Ok(v) = s.parse::<i8>() {
            return Ok(v as u8);
        }
    }
    // Try unsigned first
    if let Ok(v) = s.parse::<u64>() {
        if v > 255 {
            return Err(format!("value beyond 255: {v}"));
        }
        return Ok(v as u8);
    }
    // Try signed for int8 fields
    if let Ok(v) = s.parse::<i8>() {
        return Ok(v as u8);
    }
    Err(format!("unable to parse {:?} as integer", s))
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

/// Strip inline comments (// and ;) from a line.
fn strip_comment(line: &str) -> &str {
    // Need to handle string literals containing // or ;
    let mut in_string = false;
    let mut escape = false;
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        if escape {
            escape = false;
            continue;
        }
        if bytes[i] == b'\\' && in_string {
            escape = true;
            continue;
        }
        if bytes[i] == b'"' {
            in_string = !in_string;
            continue;
        }
        if !in_string {
            if bytes[i] == b';' {
                return line[..i].trim_end();
            }
            if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
                return line[..i].trim_end();
            }
        }
    }
    line
}

/// Tokenize a TEAL source line into whitespace-separated tokens,
/// preserving string literals as single tokens.
fn tokenize(line: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip whitespace
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
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
            // Regular token
            while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\t' {
                i += 1;
            }
        }
        tokens.push(&line[start..i]);
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
    fn test_tokenize() {
        let tokens = tokenize(r#"byte "hello world" 42"#);
        assert_eq!(tokens, vec!["byte", "\"hello world\"", "42"]);
    }

    #[test]
    fn test_strip_comment() {
        assert_eq!(strip_comment("int 1 // comment"), "int 1");
        assert_eq!(strip_comment("int 1 ; comment"), "int 1");
        assert_eq!(
            strip_comment(r#"byte "hello // world""#),
            r#"byte "hello // world""#
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
}
