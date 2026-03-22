//! TEAL disassembler: converts AVM bytecode back into TEAL source text.
//!
//! Uses the existing `bytecode::parse()` to parse the program, then reconstructs
//! TEAL source text matching go-algorand's `Disassemble()` output.

use std::collections::{HashMap, HashSet};

use crate::bytecode::{self, Immediates, Instruction, Program};
use crate::fields;
use crate::opcode;

/// Disassemble AVM bytecode into TEAL source text.
///
/// Produces output that matches go-algorand's `Disassemble()` function.
/// `AssembleString(Disassemble(program))` should produce the same bytecode.
pub fn disassemble(program: &[u8]) -> Result<String, String> {
    if program.is_empty() {
        return Err("program is empty".into());
    }

    let parsed = bytecode::parse(program).map_err(|e| e.to_string())?;

    // Two-pass disassembly:
    // Pass 1: identify branch targets and assign labels
    // Pass 2: emit TEAL text

    let labels = collect_labels(&parsed);
    let intc = collect_intc_block(&parsed);
    let bytec = collect_bytec_block(&parsed);

    let mut out = String::new();
    out.push_str(&format!("#pragma version {}\n", parsed.version));

    for instr in &parsed.instructions {
        // Emit label if this offset is a branch target
        if let Some(label) = labels.get(&instr.offset) {
            out.push_str(&format!("{}:\n", label));
        }

        let spec = opcode::lookup(instr.opcode);
        let name = spec.map(|s| s.name).unwrap_or("???");

        let mut line = name.to_string();

        match &instr.immediates {
            Immediates::None => {
                // intc_N and bytec_N comments
                if name.starts_with("intc_") {
                    let idx = (name.as_bytes()[name.len() - 1] - b'0') as usize;
                    if idx < intc.len() {
                        line.push_str(&format!(" // {}", intc[idx]));
                    }
                } else if name.starts_with("bytec_") {
                    let idx = (name.as_bytes()[name.len() - 1] - b'0') as usize;
                    if idx < bytec.len() {
                        line.push_str(&format!(" // {}", guess_byte_format(&bytec[idx])));
                    }
                }
            }
            Immediates::Uint8(b) => {
                // Try field name resolution
                if let Some(field_name) = fields::field_name_for_opcode(name, 0, *b) {
                    line.push_str(&format!(" {}", field_name));
                } else if name == "frame_dig" || name == "frame_bury" {
                    // int8 immediate
                    line.push_str(&format!(" {}", *b as i8));
                } else {
                    line.push_str(&format!(" {}", b));
                }
                // intc/bytec comments
                if name == "intc" && (*b as usize) < intc.len() {
                    line.push_str(&format!(" // {}", intc[*b as usize]));
                }
                if name == "bytec" && (*b as usize) < bytec.len() {
                    line.push_str(&format!(" // {}", guess_byte_format(&bytec[*b as usize])));
                }
            }
            Immediates::Uint8Pair(a, b) => {
                // First immediate
                if let Some(field_name) = fields::field_name_for_opcode(name, 0, *a) {
                    line.push_str(&format!(" {}", field_name));
                } else {
                    line.push_str(&format!(" {}", a));
                }
                // Second immediate
                if let Some(field_name) = fields::field_name_for_opcode(name, 1, *b) {
                    line.push_str(&format!(" {}", field_name));
                } else {
                    line.push_str(&format!(" {}", b));
                }
            }
            Immediates::Uint8Triple(a, b, c) => {
                // First immediate
                if let Some(field_name) = fields::field_name_for_opcode(name, 0, *a) {
                    line.push_str(&format!(" {}", field_name));
                } else {
                    line.push_str(&format!(" {}", a));
                }
                // Second immediate
                if let Some(field_name) = fields::field_name_for_opcode(name, 1, *b) {
                    line.push_str(&format!(" {}", field_name));
                } else {
                    line.push_str(&format!(" {}", b));
                }
                // Third immediate
                line.push_str(&format!(" {}", c));
            }
            Immediates::Int16(_offset) => {
                // Branch instruction — use label
                let target = compute_branch_target(instr);
                if let Some(label) = labels.get(&target) {
                    line.push_str(&format!(" {}", label));
                } else {
                    // Fallback: use raw target
                    line.push_str(&format!(" {}", target));
                }
            }
            Immediates::Varuint(val) => {
                line.push_str(&format!(" {}", val));
            }
            Immediates::Bytes(bytes) => {
                let hex_str = bytes_to_hex(bytes);
                let fmt = guess_byte_format(bytes);
                line.push_str(&format!(" 0x{} // {}", hex_str, fmt));
            }
            Immediates::IntBlock(vals) => {
                for v in vals {
                    line.push(' ');
                    line.push_str(&format!("{}", v));
                }
            }
            Immediates::ByteBlock(entries) => {
                for bv in entries {
                    line.push(' ');
                    line.push_str(&format!("0x{}", bytes_to_hex(bv)));
                }
            }
            Immediates::PushInts(vals) => {
                for v in vals {
                    line.push_str(&format!(" {}", v));
                }
            }
            Immediates::PushBytess(entries) => {
                for bv in entries {
                    line.push_str(&format!(" 0x{}", bytes_to_hex(bv)));
                }
            }
            Immediates::Labels(offsets) => {
                // switch/match — resolve each offset to a label
                let end_of_instr = compute_labels_end(instr, offsets.len());
                for offset in offsets {
                    let target = (end_of_instr as isize + *offset as isize) as usize;
                    if let Some(label) = labels.get(&target) {
                        line.push_str(&format!(" {}", label));
                    } else {
                        line.push_str(&format!(" {}", target));
                    }
                }
            }
        }

        out.push_str(&line);
        out.push('\n');
    }

    // Emit any trailing label
    let end_offset = parsed
        .instructions
        .last()
        .map(|i| i.offset + instruction_size(i))
        .unwrap_or(0);
    if let Some(label) = labels.get(&end_offset) {
        out.push_str(&format!("{}:\n", label));
    }

    Ok(out)
}

/// Compute the branch target (offset within the code section) for a branch instruction.
fn compute_branch_target(instr: &Instruction) -> usize {
    if let Immediates::Int16(offset) = instr.immediates {
        // Target = end of this instruction + offset
        // Instruction is: opcode (1 byte) + offset (2 bytes) = 3 bytes from instr.offset
        let end_of_instr = instr.offset + 3;
        (end_of_instr as isize + offset as isize) as usize
    } else {
        0
    }
}

/// Compute the end offset for a Labels (switch/match) instruction.
fn compute_labels_end(instr: &Instruction, count: usize) -> usize {
    // Layout: opcode (1) + count (1) + count*2 bytes of offsets
    instr.offset + 1 + 1 + count * 2
}

/// Compute the total size (in bytes) of an instruction including its immediates.
fn instruction_size(instr: &Instruction) -> usize {
    match &instr.immediates {
        Immediates::None => 1,
        Immediates::Uint8(_) => 2,
        Immediates::Uint8Pair(_, _) => 2 + 1,
        Immediates::Uint8Triple(_, _, _) => 4,
        Immediates::Int16(_) => 3,
        Immediates::Varuint(v) => 1 + varuint_size(*v),
        Immediates::Bytes(b) => 1 + varuint_size(b.len() as u64) + b.len(),
        Immediates::IntBlock(vals) => {
            1 + varuint_size(vals.len() as u64)
                + vals.iter().map(|v| varuint_size(*v)).sum::<usize>()
        }
        Immediates::ByteBlock(entries) => {
            1 + varuint_size(entries.len() as u64)
                + entries
                    .iter()
                    .map(|b| varuint_size(b.len() as u64) + b.len())
                    .sum::<usize>()
        }
        Immediates::PushInts(vals) => {
            1 + varuint_size(vals.len() as u64)
                + vals.iter().map(|v| varuint_size(*v)).sum::<usize>()
        }
        Immediates::PushBytess(entries) => {
            1 + varuint_size(entries.len() as u64)
                + entries
                    .iter()
                    .map(|b| varuint_size(b.len() as u64) + b.len())
                    .sum::<usize>()
        }
        Immediates::Labels(offsets) => 1 + 1 + offsets.len() * 2,
    }
}

fn varuint_size(mut v: u64) -> usize {
    let mut size = 0;
    loop {
        size += 1;
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    size
}

/// Collect all branch targets from the program and assign label names.
fn collect_labels(program: &Program) -> HashMap<usize, String> {
    let mut targets: Vec<usize> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();

    for instr in &program.instructions {
        match &instr.immediates {
            Immediates::Int16(offset) => {
                let target = compute_branch_target(instr);
                if seen.insert(target) {
                    targets.push(target);
                }
                let _ = offset;
            }
            Immediates::Labels(offsets) => {
                let end_of_instr = compute_labels_end(instr, offsets.len());
                for offset in offsets {
                    let target = (end_of_instr as isize + *offset as isize) as usize;
                    if seen.insert(target) {
                        targets.push(target);
                    }
                }
            }
            _ => {}
        }
    }

    // Sort targets and assign label names
    targets.sort();
    let mut labels = HashMap::new();
    for (i, &target) in targets.iter().enumerate() {
        labels.insert(target, format!("label{}", i + 1));
    }
    labels
}

/// Extract the intcblock values from the program (if present).
fn collect_intc_block(program: &Program) -> Vec<u64> {
    for instr in &program.instructions {
        if instr.opcode == 0x20 {
            // intcblock
            if let Immediates::IntBlock(vals) = &instr.immediates {
                return vals.clone();
            }
        }
    }
    Vec::new()
}

/// Extract the bytecblock values from the program (if present).
fn collect_bytec_block(program: &Program) -> Vec<Vec<u8>> {
    for instr in &program.instructions {
        if instr.opcode == 0x26 {
            // bytecblock
            if let Immediates::ByteBlock(entries) = &instr.immediates {
                return entries.clone();
            }
        }
    }
    Vec::new()
}

/// Format a byte slice for display, matching go-algorand's `guessByteFormat`.
fn guess_byte_format(bytes: &[u8]) -> String {
    if bytes.len() == 32 {
        // Could be an Algorand address — encode as addr
        let addr = encode_algorand_address(bytes);
        return format!("addr {}", addr);
    }
    if all_printable_ascii(bytes) {
        return format!("{:?}", String::from_utf8_lossy(bytes));
    }
    format!("0x{}", bytes_to_hex(bytes))
}

fn all_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| (32..=126).contains(&b))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Encode 32 bytes as an Algorand address (base32 with checksum).
fn encode_algorand_address(pubkey: &[u8]) -> String {
    use sha2::{Digest, Sha512_256};
    let hash = Sha512_256::digest(pubkey);
    let checksum = &hash[28..32];

    let mut addr_bytes = Vec::with_capacity(36);
    addr_bytes.extend_from_slice(pubkey);
    addr_bytes.extend_from_slice(checksum);

    data_encoding::BASE32_NOPAD.encode(&addr_bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::assemble_string;

    #[test]
    fn test_disassemble_simple() {
        // Version 2, intcblock [1], intc_0, return
        let program = vec![
            0x02, // version 2
            0x20, 0x01, 0x01, // intcblock [1]
            0x22, // intc_0
            0x43, // return
        ];
        let text = disassemble(&program).unwrap();
        assert!(text.contains("#pragma version 2"));
        assert!(text.contains("intcblock 1"));
        assert!(text.contains("intc_0"));
        assert!(text.contains("return"));
    }

    #[test]
    fn test_disassemble_with_labels() {
        // Version 2, b +2, err, intcblock [1], intc_0, return
        let program = vec![
            0x02, // version 2
            0x42, 0x00, 0x01, // b +1 (skip next instruction)
            0x00, // err
            0x20, 0x01, 0x01, // intcblock [1]
            0x22, // intc_0
            0x43, // return
        ];
        let text = disassemble(&program).unwrap();
        assert!(text.contains("#pragma version 2"));
        assert!(text.contains("b label"));
    }

    #[test]
    fn test_disassemble_global_field() {
        let program = vec![
            0x02, // version 2
            0x32, 0x00, // global MinTxnFee
        ];
        let text = disassemble(&program).unwrap();
        assert!(text.contains("global MinTxnFee"));
    }

    #[test]
    fn test_disassemble_txn_field() {
        let program = vec![
            0x02, // version 2
            0x31, 0x00, // txn Sender
        ];
        let text = disassemble(&program).unwrap();
        assert!(text.contains("txn Sender"));
    }

    #[test]
    fn test_roundtrip_simple() {
        let source = "#pragma version 2\nint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        // Reassemble the disassembled text
        let ops2 = assemble_string(&text).unwrap();
        assert_eq!(ops.program, ops2.program);
    }

    #[test]
    fn test_roundtrip_with_branches() {
        let source = "#pragma version 2\nint 1\nbnz end\nint 0\nend:\nint 1\nreturn\n";
        let ops = assemble_string(source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        let ops2 = assemble_string(&text).unwrap();
        assert_eq!(ops.program, ops2.program);
    }

    #[test]
    fn test_roundtrip_pushint() {
        let source = "#pragma version 3\npushint 42\nreturn\n";
        let ops = assemble_string(source).unwrap();
        let text = disassemble(&ops.program).unwrap();
        let ops2 = assemble_string(&text).unwrap();
        assert_eq!(ops.program, ops2.program);
    }

    #[test]
    fn test_disassemble_pushbytes() {
        let program = vec![
            0x03, // version 3
            0x80, 0x03, 0x01, 0x02, 0x03, // pushbytes 0x010203
        ];
        let text = disassemble(&program).unwrap();
        assert!(text.contains("pushbytes 0x010203"));
    }

    #[test]
    fn test_empty_program() {
        assert!(disassemble(&[]).is_err());
    }
}
