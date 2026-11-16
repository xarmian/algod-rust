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

//! `abi.VerifyMethodSignature` of go-algorand's `avm-abi` module
//! (`abi/encode.go`, `abi/type.go`): the validation the assembler's `method`
//! pseudo-op runs to decide whether to warn
//! (`invalid ARC-4 ABI method signature for method op: ...`). Only the error
//! values matter here, so the parsed types are not built; every error text is
//! go's.

/// go's `abi.VerifyMethodSignature`.
pub(crate) fn verify_method_signature(method_sig: &str) -> Result<(), String> {
    let (_name, arg_types, ret_type) = parse_method_signature(method_sig)?;
    for (i, arg_type) in arg_types.iter().enumerate() {
        if is_reference_type(arg_type) || is_transaction_type(arg_type) {
            continue;
        }
        type_of(arg_type).map_err(|e| format!("Error parsing argument type at index {i}: {e}"))?;
    }
    if ret_type != "void" {
        type_of(&ret_type).map_err(|e| format!("Error parsing return type: {e}"))?;
    }
    Ok(())
}

fn is_transaction_type(s: &str) -> bool {
    matches!(
        s,
        "txn" | "pay" | "keyreg" | "acfg" | "axfer" | "afrz" | "appl"
    )
}

fn is_reference_type(s: &str) -> bool {
    matches!(s, "account" | "asset" | "application")
}

/// go's `abi.ParseMethodSignature`: `(name, argTypes, returnType)`.
fn parse_method_signature(sig: &str) -> Result<(String, Vec<String>, String), String> {
    let Some(args_start) = sig.find('(') else {
        return Err(format!("No parenthesis in method signature: \"{sig}\""));
    };
    if args_start == 0 {
        return Err(format!("Method signature has no name: \"{sig}\""));
    }
    let mut args_end: Option<usize> = None;
    let mut depth = 0usize;
    for (index, ch) in sig.char_indices() {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            if depth == 0 {
                return Err(format!(
                    "Unpaired parenthesis in method signature: \"{sig}\""
                ));
            }
            depth -= 1;
            if depth == 0 {
                args_end = Some(index);
                break;
            }
        }
    }
    let Some(args_end) = args_end else {
        return Err(format!(
            "Unpaired parenthesis in method signature: \"{sig}\""
        ));
    };
    let name = sig[..args_start].to_string();
    let arg_types = parse_tuple_content(&sig[args_start + 1..args_end])?;
    let return_type = sig[args_end + 1..].to_string();
    Ok((name, arg_types, return_type))
}

/// go's `abi.parseTupleContent`.
fn parse_tuple_content(s: &str) -> Result<Vec<String>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.ends_with(',') || s.starts_with(',') {
        return Err("parsing error: tuple content should not start or end with comma".into());
    }
    if s.contains(",,") {
        return Err("no consecutive commas".into());
    }
    let bytes = s.as_bytes();
    let mut segments: Vec<(usize, usize)> = Vec::new(); // (left, right) of top-level parens
    let mut stack: Vec<usize> = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let chr = bytes[index];
        if chr == b'(' {
            stack.push(index);
        } else if chr == b')' {
            let Some(left) = stack.pop() else {
                return Err(format!("unpaired parentheses: {s}"));
            };
            if stack.is_empty() {
                // increase index until it meets a comma, or the end of the string
                let mut forward = index + 1;
                while forward < bytes.len() && bytes[forward] != b',' {
                    forward += 1;
                }
                index = forward - 1;
                segments.push((left, index));
            }
        }
        index += 1;
    }
    if !stack.is_empty() {
        return Err(format!("unpaired parentheses: {s}"));
    }
    // Take out the tuple-formed types, split, and put them back.
    let mut copied: Vec<u8> = bytes.to_vec();
    for &(left, right) in segments.iter().rev() {
        copied.drain(left..=right);
    }
    let mut parts: Vec<Vec<u8>> = copied.split(|b| *b == b',').map(<[u8]>::to_vec).collect();
    let mut seg_count = 0usize;
    for part in parts.iter_mut() {
        if part.is_empty() {
            let (left, right) = segments[seg_count];
            *part = bytes[left..=right].to_vec();
            seg_count += 1;
        }
    }
    Ok(parts
        .into_iter()
        .map(|p| String::from_utf8_lossy(&p).into_owned())
        .collect())
}

/// `strconv.ParseUint(s, 10, 16)` with go's `NumError` text.
fn parse_uint16(s: &str) -> Result<u64, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "strconv.ParseUint: parsing {}: invalid syntax",
            super::assembler::go_quote(s)
        ));
    }
    match s.parse::<u64>() {
        Ok(v) if v <= u64::from(u16::MAX) => Ok(v),
        _ => Err(format!(
            "strconv.ParseUint: parsing {}: value out of range",
            super::assembler::go_quote(s)
        )),
    }
}

fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// A decimal matching `[1-9][\d]*`.
fn is_positive_decimal(s: &str) -> bool {
    is_decimal(s) && !s.starts_with('0')
}

/// go's `abi.TypeOf`, validation only.
fn type_of(s: &str) -> Result<(), String> {
    if let Some(inner) = s.strip_suffix("[]") {
        return type_of(inner);
    }
    if s.ends_with(']') {
        // `^([a-z\d\[\](),]+)\[(0|[1-9][\d]*)]$`
        let bad = || format!("static array ill formated: \"{s}\"");
        let Some(p) = s.rfind('[') else {
            return Err(bad());
        };
        let elem = &s[..p];
        let len_str = &s[p + 1..s.len() - 1];
        let elem_ok = !elem.is_empty()
            && elem
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"[](),".contains(&b));
        let len_ok = len_str == "0" || is_positive_decimal(len_str);
        if !elem_ok || !len_ok {
            return Err(bad());
        }
        parse_uint16(len_str)?;
        return type_of(elem);
    }
    if let Some(rest) = s.strip_prefix("uint") {
        let size = parse_uint16(rest).map_err(|_| format!("ill formed uint type: \"{s}\""))?;
        if !size.is_multiple_of(8) || !(8..=512).contains(&size) {
            return Err(format!("unsupported uint type bitSize: {size}"));
        }
        return Ok(());
    }
    if s == "byte" {
        return Ok(());
    }
    if let Some(rest) = s.strip_prefix("ufixed") {
        // `^ufixed([1-9][\d]*)x([1-9][\d]*)$`
        let bad = || format!("ill formed ufixed type: \"{s}\"");
        let Some((a, b)) = rest.split_once('x') else {
            return Err(bad());
        };
        if !is_positive_decimal(a) || !is_positive_decimal(b) {
            return Err(bad());
        }
        let size = parse_uint16(a)?;
        let precision = parse_uint16(b)?;
        if !size.is_multiple_of(8) || !(8..=512).contains(&size) {
            return Err(format!("unsupported ufixed type bitSize: {size}"));
        }
        if !(1..=160).contains(&precision) {
            return Err(format!("unsupported ufixed type precision: {precision}"));
        }
        return Ok(());
    }
    if s == "bool" || s == "address" || s == "string" {
        return Ok(());
    }
    if s.len() >= 2 && s.starts_with('(') && s.ends_with(')') {
        let content = parse_tuple_content(&s[1..s.len() - 1])?;
        for t in &content {
            type_of(t)?;
        }
        if content.len() >= usize::from(u16::MAX) {
            return Err("tuple type child type number larger than maximum uint16 error".into());
        }
        return Ok(());
    }
    Err(format!("cannot convert the string \"{s}\" to an ABI type"))
}
