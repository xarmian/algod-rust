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

//! ARC-4 ABI type system: recursive type parser, JSON unmarshaling, and
//! binary encoding/decoding matching go-algorand's `avm-abi/abi` package
//! (not vendored into the `../go-algorand` pin — go-algorand's own `goal`
//! CLI depends on it as an external Go module, so this crate is built
//! directly from the [ARC-4 specification](https://arc.algorand.foundation/ARCs/arc-0004)
//! and cross-checked against `goal`/AVM-observable behavior, e.g. the
//! `method` pseudo-op's selector computation in
//! `crates/core/algo-avm/src/assembler.rs`).
//!
//! Parses ABI type strings like `"uint64"`, `"bool"`, `"(uint64,address)"`,
//! `"uint64[3]"`, `"uint64[]"`, and `"(uint64,(bool,address))"` into a
//! structured [`AbiType`] enum. Supports encoding/decoding values to/from
//! ABI binary format, parsing JSON values into [`AbiValue`] for encoding,
//! and computing ARC-4 method selectors ([`method_selector`]) and
//! signatures ([`Method`]) for `goal app call`/`goal app method`.
//!
//! Originally extracted from `algo-rest-api`'s box-name ABI-encoding helper
//! (`crates/node/algo-rest-api/src/box_name.rs`), which re-exports this
//! crate's public API rather than duplicating it, so `goal-rust`'s ABI CLI
//! subcommand (issue #888) shares one implementation with the REST API's
//! box-name ABI parsing instead of maintaining a second copy.
//!
//! Reference: `github.com/algorand/avm-abi/abi/type.go`, `encode.go`, `json.go`

use std::fmt;

use algo_types::Address;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use num_bigint::BigUint;
use sha2::{Digest, Sha512_256};

// ---------------------------------------------------------------------------
// ABI Type Enum
// ---------------------------------------------------------------------------

/// Represents an ABI type as defined by the Algorand ABI specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiType {
    /// Unsigned integer with bit size in `[8, 512]`, must be a multiple of 8.
    Uint(u16),
    /// Unsigned fixed-point decimal: `ufixed<N>x<M>` with bit size N and precision M.
    Ufixed(u16, u8),
    /// Boolean value.
    Bool,
    /// Single byte (alias for uint8 in encoding, but distinct type).
    Byte,
    /// 32-byte Algorand address.
    Address,
    /// Variable-length byte string (dynamic).
    String,
    /// Static-length array: element type + length.
    ArrayStatic(Box<AbiType>, usize),
    /// Dynamic-length array: element type.
    ArrayDynamic(Box<AbiType>),
    /// Tuple: ordered list of types.
    Tuple(Vec<AbiType>),
}

impl fmt::Display for AbiType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiType::Uint(n) => write!(f, "uint{n}"),
            AbiType::Ufixed(n, m) => write!(f, "ufixed{n}x{m}"),
            AbiType::Bool => write!(f, "bool"),
            AbiType::Byte => write!(f, "byte"),
            AbiType::Address => write!(f, "address"),
            AbiType::String => write!(f, "string"),
            AbiType::ArrayStatic(elem, len) => write!(f, "{elem}[{len}]"),
            AbiType::ArrayDynamic(elem) => write!(f, "{elem}[]"),
            AbiType::Tuple(types) => {
                write!(f, "(")?;
                for (i, t) in types.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{t}")?;
                }
                write!(f, ")")
            }
        }
    }
}

impl AbiType {
    /// Returns `true` if this type is dynamically sized per the ABI spec.
    ///
    /// Dynamic types are: `String`, `ArrayDynamic`, and any `Tuple` or
    /// `ArrayStatic` that contains a dynamic child type.
    pub fn is_dynamic(&self) -> bool {
        match self {
            AbiType::ArrayDynamic(_) | AbiType::String => true,
            AbiType::ArrayStatic(elem, _) => elem.is_dynamic(),
            AbiType::Tuple(children) => children.iter().any(|c| c.is_dynamic()),
            _ => false,
        }
    }

    /// Returns the byte length for static types, or `None` for dynamic types.
    ///
    /// For tuples, consecutive bool fields are packed into bytes (matching Go).
    pub fn byte_len(&self) -> Option<usize> {
        match self {
            AbiType::Uint(n) | AbiType::Ufixed(n, _) => Some(*n as usize / 8),
            AbiType::Bool => Some(1),
            AbiType::Byte => Some(1),
            AbiType::Address => Some(32),
            AbiType::String | AbiType::ArrayDynamic(_) => None,
            AbiType::ArrayStatic(elem, len) => {
                if **elem == AbiType::Bool {
                    // Bool arrays are bit-packed.
                    Some((*len).div_ceil(8))
                } else {
                    Some(elem.byte_len()? * len)
                }
            }
            AbiType::Tuple(children) => {
                let mut size = 0usize;
                let mut i = 0;
                while i < children.len() {
                    if children[i] == AbiType::Bool {
                        // Count consecutive bools and pack them.
                        let mut bool_count = 0;
                        while i + bool_count < children.len()
                            && children[i + bool_count] == AbiType::Bool
                        {
                            bool_count += 1;
                        }
                        size += bool_count.div_ceil(8);
                        i += bool_count;
                    } else {
                        size += children[i].byte_len()?;
                        i += 1;
                    }
                }
                Some(size)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Maximum nesting depth for ABI type parsing, to prevent stack overflow from
/// deeply nested types (e.g. `(((((...))))` or `uint8[][][]...[]`).
const MAX_ABI_DEPTH: usize = 64;

/// Parse an ABI type string into an [`AbiType`].
///
/// Handles all types supported by go-algorand's `abi.TypeOf`:
/// - Basic types: `uint<N>`, `ufixed<N>x<M>`, `bool`, `byte`, `address`, `string`
/// - Static arrays: `<type>[<N>]`
/// - Dynamic arrays: `<type>[]`
/// - Tuples: `(<type>,<type>,...)`
///
/// # Errors
///
/// Returns an error string if the input is malformed or exceeds the maximum
/// nesting depth of 64.
pub fn type_of(s: &str) -> Result<AbiType, String> {
    type_of_inner(s, 0)
}

/// Inner recursive parser with depth tracking.
fn type_of_inner(s: &str, depth: usize) -> Result<AbiType, String> {
    if depth > MAX_ABI_DEPTH {
        return Err(format!(
            "ABI type nesting depth exceeds maximum of {MAX_ABI_DEPTH}"
        ));
    }

    // Dynamic array: ends with "[]"
    if let Some(inner) = s.strip_suffix("[]") {
        let elem = type_of_inner(inner, depth + 1)?;
        return Ok(AbiType::ArrayDynamic(Box::new(elem)));
    }

    // Static array: ends with "[<N>]"
    if s.ends_with(']') {
        return parse_static_array(s, depth);
    }

    // uint<N>
    if let Some(rest) = s.strip_prefix("uint") {
        if rest.is_empty() {
            return Err(format!("ill formed uint type: \"{s}\""));
        }
        let bits: u16 = rest
            .parse()
            .map_err(|_| format!("ill formed uint type: \"{s}\""))?;
        if !(8..=512).contains(&bits) || bits % 8 != 0 {
            return Err(format!("unsupported uint type bitSize: {bits}"));
        }
        return Ok(AbiType::Uint(bits));
    }

    // byte (must be checked before "bool" since "byte" doesn't start with "bool")
    if s == "byte" {
        return Ok(AbiType::Byte);
    }

    // ufixed<N>x<M>
    if let Some(rest) = s.strip_prefix("ufixed") {
        return parse_ufixed(rest, s);
    }

    // bool
    if s == "bool" {
        return Ok(AbiType::Bool);
    }

    // address
    if s == "address" {
        return Ok(AbiType::Address);
    }

    // string
    if s == "string" {
        return Ok(AbiType::String);
    }

    // Tuple: starts with '(' and ends with ')'
    if s.len() >= 2 && s.starts_with('(') && s.ends_with(')') {
        let inner = &s[1..s.len() - 1];
        let parts = parse_tuple_content(inner)?;
        let mut types = Vec::with_capacity(parts.len());
        for part in &parts {
            types.push(type_of_inner(part, depth + 1)?);
        }
        if types.len() >= u16::MAX as usize {
            return Err("tuple type child type number larger than maximum uint16 error".into());
        }
        return Ok(AbiType::Tuple(types));
    }

    Err(format!("cannot convert the string \"{s}\" to an ABI type"))
}

/// Parse a static array type string like `uint64[3]`.
fn parse_static_array(s: &str, depth: usize) -> Result<AbiType, String> {
    // Find the matching '[' by scanning from the end.
    // The regex from Go is: ^([a-z\d\[\](),]+)\[(0|[1-9][\d]*)]$
    // We replicate the logic: find the last '[', validate the length part,
    // and recursively parse the element type.
    let bracket_pos = s
        .rfind('[')
        .ok_or_else(|| format!("static array ill formated: \"{s}\""))?;

    let len_str = &s[bracket_pos + 1..s.len() - 1];
    if len_str.is_empty() {
        return Err(format!("static array ill formated: \"{s}\""));
    }

    // Validate: no leading zeros (unless the length is exactly "0").
    if len_str.len() > 1 && len_str.starts_with('0') {
        return Err(format!("static array ill formated: \"{s}\""));
    }

    let array_len: usize = len_str
        .parse::<u16>()
        .map_err(|_| format!("static array ill formated: \"{s}\""))?
        as usize;

    let elem_str = &s[..bracket_pos];
    let elem = type_of_inner(elem_str, depth + 1)?;

    Ok(AbiType::ArrayStatic(Box::new(elem), array_len))
}

/// Parse the `<N>x<M>` part of a `ufixed<N>x<M>` type string.
fn parse_ufixed(rest: &str, original: &str) -> Result<AbiType, String> {
    let parts: Vec<&str> = rest.splitn(2, 'x').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(format!("ill formed ufixed type: \"{original}\""));
    }

    // Reject leading zeros.
    if (parts[0].len() > 1 && parts[0].starts_with('0'))
        || (parts[1].len() > 1 && parts[1].starts_with('0'))
    {
        return Err(format!("ill formed ufixed type: \"{original}\""));
    }

    let bits: u16 = parts[0]
        .parse()
        .map_err(|_| format!("ill formed ufixed type: \"{original}\""))?;
    let precision: u8 = parts[1]
        .parse()
        .map_err(|_| format!("ill formed ufixed type: \"{original}\""))?;

    if !(8..=512).contains(&bits) || bits % 8 != 0 {
        return Err(format!("unsupported ufixed type bitSize: {bits}"));
    }
    if !(1..=160).contains(&precision) {
        return Err(format!("unsupported ufixed type precision: {precision}"));
    }

    Ok(AbiType::Ufixed(bits, precision))
}

/// Split tuple content string by commas, respecting nested parentheses.
///
/// This is a Rust port of go-algorand's `parseTupleContent`. The input `s`
/// is the content between the outer parentheses of a tuple type string,
/// e.g. for `"(uint64,(bool,address))"` the input would be
/// `"uint64,(bool,address)"`.
///
/// Returns an empty `Vec` for an empty tuple `()`.
fn parse_tuple_content(s: &str) -> Result<Vec<&str>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }

    // Validate: no leading/trailing comma, no consecutive commas.
    if s.starts_with(',') || s.ends_with(',') {
        return Err("parsing error: tuple content should not start or end with comma".into());
    }
    if s.contains(",,") {
        return Err("no consecutive commas".into());
    }

    // Walk `s` and split by top-level commas.
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;

    for (idx, ch) in s.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    return Err(format!("unpaired parentheses: {s}"));
                }
                depth -= 1;
            }
            ',' if depth == 0 => {
                result.push(&s[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(format!("unpaired parentheses: {s}"));
    }
    result.push(&s[start..]);

    Ok(result)
}

// ---------------------------------------------------------------------------
// ABI Value Enum
// ---------------------------------------------------------------------------

/// Represents a parsed ABI value ready for binary encoding.
#[derive(Debug, Clone, PartialEq)]
pub enum AbiValue {
    /// Unsigned integer: value + bit size.
    Uint(BigUint, u16),
    /// Unsigned fixed-point: value + bit size + precision.
    Ufixed(BigUint, u16, u8),
    /// Boolean value.
    Bool(bool),
    /// Single byte.
    Byte(u8),
    /// 32-byte Algorand address.
    Address([u8; 32]),
    /// Variable-length UTF-8 string as bytes.
    String(Vec<u8>),
    /// Static-length array: elements + element type.
    ArrayStatic(Vec<AbiValue>, AbiType),
    /// Dynamic-length array: elements + element type.
    ArrayDynamic(Vec<AbiValue>, AbiType),
    /// Tuple: ordered values.
    Tuple(Vec<AbiValue>),
}

// ---------------------------------------------------------------------------
// JSON Unmarshaling
// ---------------------------------------------------------------------------

/// Parse a JSON string into an [`AbiValue`] given the ABI type.
///
/// This mirrors go-algorand's `Type.UnmarshalFromJSON`.
pub fn unmarshal_from_json(abi_type: &AbiType, json_str: &str) -> Result<AbiValue, String> {
    let json_bytes = json_str.as_bytes();

    match abi_type {
        AbiType::Uint(bits) => {
            let num = parse_json_biguint(json_str)?;
            validate_uint_fits(&num, *bits)?;
            Ok(AbiValue::Uint(num, *bits))
        }
        AbiType::Ufixed(bits, precision) => {
            // Go parses ufixed as a rational number, multiplies by 10^precision,
            // and checks the result is an integer that fits in bit_size bits.
            // E.g. ufixed64x1 with "1.5" → 15.
            let num = parse_ufixed_json(json_str, *precision)?;
            validate_uint_fits(&num, *bits)?;
            Ok(AbiValue::Ufixed(num, *bits, *precision))
        }
        AbiType::Bool => {
            let val: bool = serde_json::from_slice(json_bytes)
                .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to bool: {e}"))?;
            Ok(AbiValue::Bool(val))
        }
        AbiType::Byte => {
            let val: u8 = serde_json::from_slice(json_bytes)
                .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to byte: {e}"))?;
            Ok(AbiValue::Byte(val))
        }
        AbiType::Address => {
            let addr_str: std::string::String =
                serde_json::from_slice(json_bytes).map_err(|e| {
                    format!("cannot cast JSON encoded ({json_str}) to address string: {e}")
                })?;
            let addr = Address::from_algorand_string(&addr_str)
                .map_err(|e| format!("invalid address ({addr_str}): {e}"))?;
            Ok(AbiValue::Address(addr.0))
        }
        AbiType::String => {
            let trimmed = json_str.trim();
            if trimmed.starts_with('"') {
                let s: std::string::String = serde_json::from_slice(json_bytes)
                    .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to string: {e}"))?;
                Ok(AbiValue::String(s.into_bytes()))
            } else if trimmed.starts_with('[') {
                let elems: Vec<u8> = serde_json::from_slice(json_bytes)
                    .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to string: {e}"))?;
                Ok(AbiValue::String(elems))
            } else {
                Err(format!("cannot cast JSON encoded ({json_str}) to string"))
            }
        }
        AbiType::ArrayStatic(elem_type, len) => {
            // If element type is Byte and input is a JSON string, decode as base64
            // (matching Go's json.Unmarshal into []byte).
            if **elem_type == AbiType::Byte && json_str.trim().starts_with('"') {
                let s: std::string::String = serde_json::from_slice(json_bytes)
                    .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to string: {e}"))?;
                let decoded = BASE64
                    .decode(s.as_bytes())
                    .map_err(|e| format!("cannot decode base64 for byte array: {e}"))?;
                if decoded.len() != *len {
                    return Err(format!(
                        "base64 decoded length {} != ABI array elem number {len}",
                        decoded.len()
                    ));
                }
                let values: Vec<AbiValue> = decoded.into_iter().map(AbiValue::Byte).collect();
                return Ok(AbiValue::ArrayStatic(values, *elem_type.clone()));
            }
            let elems: Vec<serde_json::Value> = serde_json::from_slice(json_bytes)
                .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to array: {e}"))?;
            if elems.len() != *len {
                return Err(format!(
                    "JSON array element number {} != ABI array elem number {len}",
                    elems.len()
                ));
            }
            let mut values = Vec::with_capacity(elems.len());
            for elem in &elems {
                let elem_json = serde_json::to_string(elem)
                    .map_err(|e| format!("cannot serialize JSON element: {e}"))?;
                values.push(unmarshal_from_json(elem_type, &elem_json)?);
            }
            Ok(AbiValue::ArrayStatic(values, *elem_type.clone()))
        }
        AbiType::ArrayDynamic(elem_type) => {
            // If element type is Byte and input is a JSON string, decode as base64
            // (matching Go's json.Unmarshal into []byte).
            if **elem_type == AbiType::Byte && json_str.trim().starts_with('"') {
                let s: std::string::String = serde_json::from_slice(json_bytes)
                    .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to string: {e}"))?;
                let decoded = BASE64
                    .decode(s.as_bytes())
                    .map_err(|e| format!("cannot decode base64 for byte array: {e}"))?;
                let values: Vec<AbiValue> = decoded.into_iter().map(AbiValue::Byte).collect();
                return Ok(AbiValue::ArrayDynamic(values, *elem_type.clone()));
            }
            let elems: Vec<serde_json::Value> = serde_json::from_slice(json_bytes)
                .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to array: {e}"))?;
            let mut values = Vec::with_capacity(elems.len());
            for elem in &elems {
                let elem_json = serde_json::to_string(elem)
                    .map_err(|e| format!("cannot serialize JSON element: {e}"))?;
                values.push(unmarshal_from_json(elem_type, &elem_json)?);
            }
            Ok(AbiValue::ArrayDynamic(values, *elem_type.clone()))
        }
        AbiType::Tuple(child_types) => {
            let elems: Vec<serde_json::Value> =
                serde_json::from_slice(json_bytes).map_err(|e| {
                    format!("cannot cast JSON encoded ({json_str}) to array for tuple: {e}")
                })?;
            if elems.len() != child_types.len() {
                return Err(format!(
                    "JSON array element number {} != ABI tuple elem number {}",
                    elems.len(),
                    child_types.len()
                ));
            }
            let mut values = Vec::with_capacity(elems.len());
            for (elem, child_type) in elems.iter().zip(child_types.iter()) {
                let elem_json = serde_json::to_string(elem)
                    .map_err(|e| format!("cannot serialize JSON element: {e}"))?;
                values.push(unmarshal_from_json(child_type, &elem_json)?);
            }
            Ok(AbiValue::Tuple(values))
        }
    }
}

/// Parse a JSON number or string as a `BigUint`.
fn parse_json_biguint(json_str: &str) -> Result<BigUint, String> {
    let trimmed = json_str.trim();
    // Accept both JSON numbers and quoted strings
    let num_str = trimmed.trim_matches('"');
    num_str
        .parse::<BigUint>()
        .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to uint: {e}"))
}

/// Validate that a `BigUint` value fits in `bits` bits.
fn validate_uint_fits(num: &BigUint, bits: u16) -> Result<(), String> {
    if num.bits() > u64::from(bits) {
        return Err(format!(
            "input value bit size {} > abi type bit size {bits}",
            num.bits()
        ));
    }
    Ok(())
}

/// Parse a JSON value as a ufixed decimal: multiply by 10^precision and return
/// the resulting integer. Matches Go's `UnmarshalFromJSON` for Ufixed types.
fn parse_ufixed_json(json_str: &str, precision: u8) -> Result<BigUint, String> {
    let trimmed = json_str.trim().trim_matches('"');
    let prec = precision as usize;

    if let Some(dot_pos) = trimmed.find('.') {
        let int_part = &trimmed[..dot_pos];
        let frac_part = &trimmed[dot_pos + 1..];

        if frac_part.is_empty() {
            return Err(format!(
                "cannot cast JSON encoded ({json_str}) to ufixed: trailing decimal point"
            ));
        }
        if frac_part.len() > prec {
            return Err(format!(
                "cannot cast JSON encoded ({json_str}) to ufixed: fractional part has {} digits but precision is {precision}",
                frac_part.len()
            ));
        }

        let int_val: BigUint = if int_part.is_empty() {
            BigUint::ZERO
        } else {
            int_part
                .parse::<BigUint>()
                .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to ufixed: {e}"))?
        };

        let frac_val: BigUint = frac_part
            .parse::<BigUint>()
            .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to ufixed: {e}"))?;

        // value = int_part * 10^precision + frac_part * 10^(precision - frac_digits)
        let scale = BigUint::from(10u32).pow(prec as u32);
        let frac_scale = BigUint::from(10u32).pow((prec - frac_part.len()) as u32);
        Ok(int_val * scale + frac_val * frac_scale)
    } else {
        // No decimal point — integer value, multiply by 10^precision
        let int_val: BigUint = trimmed
            .parse::<BigUint>()
            .map_err(|e| format!("cannot cast JSON encoded ({json_str}) to ufixed: {e}"))?;
        let scale = BigUint::from(10u32).pow(prec as u32);
        Ok(int_val * scale)
    }
}

// ---------------------------------------------------------------------------
// ABI Encoding
// ---------------------------------------------------------------------------

/// ABI-encode a value to bytes.
///
/// This mirrors go-algorand's `Type.Encode`.
pub fn encode(value: &AbiValue) -> Result<Vec<u8>, String> {
    match value {
        AbiValue::Uint(num, bits) => encode_uint(num, *bits),
        AbiValue::Ufixed(num, bits, _) => encode_uint(num, *bits),
        AbiValue::Bool(b) => {
            if *b {
                Ok(vec![0x80])
            } else {
                Ok(vec![0x00])
            }
        }
        AbiValue::Byte(b) => Ok(vec![*b]),
        AbiValue::Address(addr) => Ok(addr.to_vec()),
        AbiValue::String(bytes) => {
            if bytes.len() > u16::MAX as usize {
                return Err("string length exceeds ABI uint16 maximum".into());
            }
            let mut result = Vec::with_capacity(2 + bytes.len());
            result.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            result.extend_from_slice(bytes);
            Ok(result)
        }
        AbiValue::ArrayStatic(values, elem_type) => encode_array_as_tuple(values, elem_type),
        AbiValue::ArrayDynamic(values, elem_type) => {
            if values.len() > u16::MAX as usize {
                return Err("dynamic array length exceeds ABI uint16 maximum".into());
            }
            let mut result = Vec::new();
            result.extend_from_slice(&(values.len() as u16).to_be_bytes());
            let tuple_bytes = encode_array_as_tuple(values, elem_type)?;
            result.extend_from_slice(&tuple_bytes);
            Ok(result)
        }
        AbiValue::Tuple(values) => encode_tuple_values(values),
    }
}

/// Encode a BigUint as a big-endian byte array, zero-padded to `bits/8` bytes.
fn encode_uint(num: &BigUint, bits: u16) -> Result<Vec<u8>, String> {
    let byte_len = bits as usize / 8;
    let raw = num.to_bytes_be();
    if raw.len() > byte_len {
        return Err(format!(
            "input value bit size {} > abi type bit size {bits}",
            num.bits()
        ));
    }
    let mut result = vec![0u8; byte_len];
    let start = byte_len - raw.len();
    result[start..].copy_from_slice(&raw);
    Ok(result)
}

/// Encode an array (static or dynamic body) as a tuple of homogeneous elements.
fn encode_array_as_tuple(values: &[AbiValue], elem_type: &AbiType) -> Result<Vec<u8>, String> {
    // Build child types list (all the same elem_type)
    let child_types: Vec<AbiType> = vec![elem_type.clone(); values.len()];
    encode_tuple_with_types(values, &child_types)
}

/// Encode tuple values with their corresponding types.
///
/// Implements Go's head/tail encoding with bool packing for consecutive bools.
fn encode_tuple_values(values: &[AbiValue]) -> Result<Vec<u8>, String> {
    // Infer child types from values
    let child_types: Vec<AbiType> = values.iter().map(infer_type).collect();
    encode_tuple_with_types(values, &child_types)
}

/// Core tuple encoding: head/tail layout with bool packing.
fn encode_tuple_with_types(
    values: &[AbiValue],
    child_types: &[AbiType],
) -> Result<Vec<u8>, String> {
    if values.len() != child_types.len() {
        return Err("cannot encode abi tuple: value slice length != child type number".into());
    }

    let n = values.len();
    let mut heads: Vec<Vec<u8>> = vec![Vec::new(); n];
    let mut tails: Vec<Vec<u8>> = vec![Vec::new(); n];
    let mut is_dynamic: Vec<bool> = vec![false; n];

    let mut i = 0;
    while i < n {
        if child_types[i].is_dynamic() {
            // Dynamic: placeholder 2-byte offset in head, encoded value in tail
            heads[i] = vec![0x00, 0x00];
            is_dynamic[i] = true;
            tails[i] = encode(&values[i])?;
            i += 1;
        } else if child_types[i] == AbiType::Bool {
            // Count consecutive bools from position i looking backward
            let before = find_bool_lr(child_types, i, -1);
            // Count consecutive bools from position i looking forward
            let mut after = find_bool_lr(child_types, i, 1);

            if before % 8 != 0 {
                return Err(
                    "cannot encode abi tuple: expected before has number of bool mod 8 == 0".into(),
                );
            }
            if after > 7 {
                after = 7;
            }

            // Pack up to 8 consecutive bools into a single byte
            let mut compressed: u8 = 0;
            for j in 0..=after {
                if let AbiValue::Bool(true) = &values[i + j] {
                    compressed |= 1 << (7 - j);
                }
            }
            heads[i] = vec![compressed];
            // Skip the bools we just packed
            i += after + 1;
        } else {
            heads[i] = encode(&values[i])?;
            i += 1;
        }
    }

    // Calculate total head length
    let head_length: usize = heads.iter().map(|h| h.len()).sum();

    // Fill in dynamic offsets
    let mut tail_curr_length: usize = 0;
    for i in 0..n {
        if is_dynamic[i] {
            let head_value = head_length + tail_curr_length;
            if head_value >= (1 << 16) {
                return Err("cannot encode abi tuple: encode length exceeds uint16 maximum".into());
            }
            heads[i] = (head_value as u16).to_be_bytes().to_vec();
        }
        tail_curr_length += tails[i].len();
    }

    // Concatenate heads + tails
    let mut result = Vec::with_capacity(head_length + tail_curr_length);
    for head in &heads {
        result.extend_from_slice(head);
    }
    for tail in &tails {
        result.extend_from_slice(tail);
    }
    Ok(result)
}

/// Port of Go's `findBoolLR`: count consecutive bool types in a direction from index.
///
/// `delta` is -1 (look left/before) or 1 (look right/after).
/// Returns the count of consecutive bools found (not including start if going backward,
/// or not including start if going forward — matching Go semantics).
fn find_bool_lr(type_list: &[AbiType], index: usize, delta: i32) -> usize {
    let mut until: usize = 0;
    loop {
        let curr = index as i64 + delta as i64 * until as i64;
        if curr < 0 || curr >= type_list.len() as i64 {
            break;
        }
        let curr = curr as usize;
        if type_list[curr] == AbiType::Bool {
            let can_continue =
                (delta > 0 && curr != type_list.len() - 1) || (delta < 0 && curr > 0);
            if can_continue {
                until += 1;
            } else {
                break;
            }
        } else {
            debug_assert!(until > 0, "find_bool_lr: non-bool at starting index");
            until = until.saturating_sub(1);
            break;
        }
    }
    until
}

/// Infer the AbiType from an AbiValue.
fn infer_type(value: &AbiValue) -> AbiType {
    match value {
        AbiValue::Uint(_, bits) => AbiType::Uint(*bits),
        AbiValue::Ufixed(_, bits, prec) => AbiType::Ufixed(*bits, *prec),
        AbiValue::Bool(_) => AbiType::Bool,
        AbiValue::Byte(_) => AbiType::Byte,
        AbiValue::Address(_) => AbiType::Address,
        AbiValue::String(_) => AbiType::String,
        AbiValue::ArrayStatic(elems, elem_type) => {
            AbiType::ArrayStatic(Box::new(elem_type.clone()), elems.len())
        }
        AbiValue::ArrayDynamic(_, elem_type) => AbiType::ArrayDynamic(Box::new(elem_type.clone())),
        AbiValue::Tuple(values) => AbiType::Tuple(values.iter().map(infer_type).collect()),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse an ABI type string and a JSON value string, then ABI-encode to bytes.
///
/// Combines [`type_of`] + [`unmarshal_from_json`] + [`encode`].
pub fn parse_and_encode_abi(type_str: &str, value_str: &str) -> Result<Vec<u8>, String> {
    let abi_type = type_of(type_str)?;
    let abi_value = unmarshal_from_json(&abi_type, value_str)?;
    encode(&abi_value)
}

// ---------------------------------------------------------------------------
// ABI Decoding
// ---------------------------------------------------------------------------

/// ABI-decode `data` as `abi_type`, the inverse of [`encode`].
///
/// Mirrors go-algorand's `Type.Decode` (`avm-abi/abi/type.go`): a straight
/// byte-length read for static scalar types, a length-prefixed read for
/// `string`/dynamic arrays, and the tuple head/tail (with consecutive-bool
/// bit-packing) scheme for tuples and arrays — see [`decode_tuple_types`].
pub fn decode(abi_type: &AbiType, data: &[u8]) -> Result<AbiValue, String> {
    match abi_type {
        AbiType::Uint(bits) => {
            let byte_len = *bits as usize / 8;
            if data.len() != byte_len {
                return Err(format!(
                    "decode uint{bits}: expected {byte_len} bytes, got {}",
                    data.len()
                ));
            }
            Ok(AbiValue::Uint(BigUint::from_bytes_be(data), *bits))
        }
        AbiType::Ufixed(bits, precision) => {
            let byte_len = *bits as usize / 8;
            if data.len() != byte_len {
                return Err(format!(
                    "decode ufixed{bits}x{precision}: expected {byte_len} bytes, got {}",
                    data.len()
                ));
            }
            Ok(AbiValue::Ufixed(
                BigUint::from_bytes_be(data),
                *bits,
                *precision,
            ))
        }
        AbiType::Bool => {
            if data.len() != 1 {
                return Err(format!("decode bool: expected 1 byte, got {}", data.len()));
            }
            Ok(AbiValue::Bool(data[0] & 0x80 != 0))
        }
        AbiType::Byte => {
            if data.len() != 1 {
                return Err(format!("decode byte: expected 1 byte, got {}", data.len()));
            }
            Ok(AbiValue::Byte(data[0]))
        }
        AbiType::Address => {
            if data.len() != 32 {
                return Err(format!(
                    "decode address: expected 32 bytes, got {}",
                    data.len()
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(data);
            Ok(AbiValue::Address(arr))
        }
        AbiType::String => {
            if data.len() < 2 {
                return Err("decode string: missing 2-byte length prefix".into());
            }
            let len = u16::from_be_bytes([data[0], data[1]]) as usize;
            if data.len() != 2 + len {
                return Err(format!(
                    "decode string: length prefix {len} does not match remaining {} bytes",
                    data.len() - 2
                ));
            }
            Ok(AbiValue::String(data[2..].to_vec()))
        }
        AbiType::ArrayStatic(elem, len) => {
            let child_types: Vec<AbiType> = vec![(**elem).clone(); *len];
            let values = decode_tuple_types(&child_types, data)?;
            Ok(AbiValue::ArrayStatic(values, (**elem).clone()))
        }
        AbiType::ArrayDynamic(elem) => {
            if data.len() < 2 {
                return Err("decode dynamic array: missing 2-byte length prefix".into());
            }
            let len = u16::from_be_bytes([data[0], data[1]]) as usize;
            let child_types: Vec<AbiType> = vec![(**elem).clone(); len];
            let values = decode_tuple_types(&child_types, &data[2..])?;
            Ok(AbiValue::ArrayDynamic(values, (**elem).clone()))
        }
        AbiType::Tuple(children) => {
            let values = decode_tuple_types(children, data)?;
            Ok(AbiValue::Tuple(values))
        }
    }
}

/// Decode the head/tail-encoded body of a tuple (or a homogeneous array
/// treated as a tuple of `children.len()` copies of the element type) into
/// one [`AbiValue`] per child type.
///
/// This is the exact inverse of `encode_tuple_with_types`: consecutive
/// `bool` children are unpacked from a single bit-packed byte, dynamic
/// children read a 2-byte offset from the head and resolve their content
/// from the tail (bounded by the next dynamic child's offset, or the end of
/// `data` for the last dynamic child — offsets are non-decreasing because
/// `encode` appends tails in child order), and static non-bool children read
/// their fixed byte length directly from the head.
fn decode_tuple_types(children: &[AbiType], data: &[u8]) -> Result<Vec<AbiValue>, String> {
    let n = children.len();
    let mut segments: Vec<Vec<u8>> = vec![Vec::new(); n];
    let mut dynamic_indices: Vec<usize> = Vec::new();
    let mut dynamic_offsets: Vec<usize> = Vec::new();
    let mut pos = 0usize;
    let mut i = 0usize;

    while i < n {
        if children[i] == AbiType::Bool {
            let before = find_bool_lr(children, i, -1);
            if before % 8 != 0 {
                return Err(
                    "cannot decode abi tuple: expected before has number of bool mod 8 == 0".into(),
                );
            }
            let mut after = find_bool_lr(children, i, 1);
            if after > 7 {
                after = 7;
            }
            if pos >= data.len() {
                return Err("cannot decode abi tuple: bool byte index out of bounds".into());
            }
            let b = data[pos];
            for b_index in 0..=after {
                let mask = 0x80u8 >> b_index;
                segments[i + b_index] = vec![if b & mask != 0 { 0x80 } else { 0x00 }];
            }
            i += after + 1;
            pos += 1;
        } else if children[i].is_dynamic() {
            if pos + 2 > data.len() {
                return Err("cannot decode abi tuple: dynamic offset out of bounds".into());
            }
            let offset = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            dynamic_indices.push(i);
            dynamic_offsets.push(offset);
            pos += 2;
            i += 1;
        } else {
            let len = children[i].byte_len().ok_or_else(|| {
                "cannot decode abi tuple: static type missing byte_len".to_string()
            })?;
            if pos + len > data.len() {
                return Err("cannot decode abi tuple: static field out of bounds".into());
            }
            segments[i] = data[pos..pos + len].to_vec();
            pos += len;
            i += 1;
        }
    }

    for (k, &idx) in dynamic_indices.iter().enumerate() {
        let start = dynamic_offsets[k];
        let end = if k + 1 < dynamic_offsets.len() {
            dynamic_offsets[k + 1]
        } else {
            data.len()
        };
        if start > end || end > data.len() {
            return Err("cannot decode abi tuple: dynamic segment out of bounds".into());
        }
        segments[idx] = data[start..end].to_vec();
    }

    let mut values = Vec::with_capacity(n);
    for (idx, child) in children.iter().enumerate() {
        values.push(decode(child, &segments[idx])?);
    }
    Ok(values)
}

// ---------------------------------------------------------------------------
// JSON display (for CLI output, e.g. `goal app method ... succeeded with
// output: <value>`)
// ---------------------------------------------------------------------------

/// Render a decoded [`AbiValue`] the way go's `goal app method` prints a
/// method's return value: JSON-ish, with `Address` rendered as its base32
/// Algorand string and `Uint`/`Ufixed` rendered as a bare (unquoted)
/// decimal literal — including values wider than 53 bits (`uint256`/
/// `uint512`), which a `serde_json::Value::Number` cannot hold exactly
/// without the `arbitrary_precision` feature, so this builds the JSON text
/// directly instead of going through `serde_json::Value`.
pub fn value_to_json_string(value: &AbiValue) -> String {
    let mut out = std::string::String::new();
    write_value_json(value, &mut out);
    out
}

fn write_json_string_literal(s: &str, out: &mut std::string::String) {
    // Delegate escaping to serde_json (its string `Value` serialization has
    // no numeric-precision pitfalls), then embed the resulting literal.
    out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()));
}

fn write_value_json(value: &AbiValue, out: &mut std::string::String) {
    match value {
        AbiValue::Uint(n, _) | AbiValue::Ufixed(n, _, _) => out.push_str(&n.to_string()),
        AbiValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        AbiValue::Byte(b) => out.push_str(&b.to_string()),
        AbiValue::Address(addr) => {
            write_json_string_literal(&algo_types::Address(*addr).to_algorand_string(), out)
        }
        AbiValue::String(bytes) => {
            write_json_string_literal(&std::string::String::from_utf8_lossy(bytes), out)
        }
        AbiValue::ArrayStatic(values, _) | AbiValue::ArrayDynamic(values, _) => {
            write_json_array(values, out)
        }
        AbiValue::Tuple(values) => write_json_array(values, out),
    }
}

fn write_json_array(values: &[AbiValue], out: &mut std::string::String) {
    out.push('[');
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        write_value_json(v, out);
    }
    out.push(']');
}

// ---------------------------------------------------------------------------
// Method-argument-to-appArgs encoding (the AVM's 16-appArgs limit)
// ---------------------------------------------------------------------------

/// The AVM hard-caps a transaction at 16 `ApplicationArgs` entries. `appArgs[0]`
/// is always the method selector, leaving 15 slots for a method's ABI-value
/// arguments. A method with more than 15 such arguments bundles argument 15
/// onward into a single ARC-4 tuple placed in the 15th slot.
const MAX_INDIVIDUAL_METHOD_ARGS: usize = 15;

/// ABI-encode each of a method's (non-reference, non-transaction) argument
/// values from its JSON CLI representation, applying go-algorand's
/// more-than-15-arguments tuple-bundling rule: with `arg_types.len() <= 15`,
/// each value becomes its own `Vec<u8>` (one `ApplicationArgs` entry each);
/// with more than 15, only the first 14 stay individual and everything from
/// the 15th argument onward is packed into one ARC-4 tuple value (so the
/// result never exceeds 15 entries — leaving room for the selector at
/// `appArgs[0]`).
///
/// Mirrors go-algorand's `cmd/goal/application.go`
/// `parseMethodArgJSONtoByteSlice`, test-for-test against its own
/// `TestParseMethodArgJSONtoByteSlice` (`cmd/goal/application_test.go`).
/// Note this function only handles [`MethodArgType::Abi`] arguments —
/// [`MethodArgType::Reference`]/[`MethodArgType::Transaction`] arguments are
/// resolved through a different path (resource-reference resolution /
/// transaction-group construction) before reaching here, matching go's own
/// split between `addMethodCallArgs`'s ABI-value handling and its
/// reference/transaction-argument handling.
pub fn encode_method_args(
    arg_types: &[AbiType],
    json_args: &[&str],
) -> Result<Vec<Vec<u8>>, String> {
    if arg_types.len() != json_args.len() {
        return Err(format!(
            "cannot encode method args: {} arg types but {} json args",
            arg_types.len(),
            json_args.len()
        ));
    }
    let n = arg_types.len();
    let split = if n > MAX_INDIVIDUAL_METHOD_ARGS {
        MAX_INDIVIDUAL_METHOD_ARGS - 1
    } else {
        n
    };

    let mut out = Vec::with_capacity(split + usize::from(n > MAX_INDIVIDUAL_METHOD_ARGS));
    for i in 0..split {
        let value = unmarshal_from_json(&arg_types[i], json_args[i])?;
        out.push(encode(&value)?);
    }
    if n > MAX_INDIVIDUAL_METHOD_ARGS {
        let mut values = Vec::with_capacity(n - split);
        for i in split..n {
            values.push(unmarshal_from_json(&arg_types[i], json_args[i])?);
        }
        out.push(encode(&AbiValue::Tuple(values))?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ARC-4 method signatures and selectors
// ---------------------------------------------------------------------------

/// One argument type in an ARC-4 method signature: an ordinary ABI value
/// type, an on-chain *reference* type (`account`/`asset`/`application`,
/// encoded on the wire as a single `uint8` index into the transaction's
/// `Accounts`/`ForeignAssets`/`ForeignApps` arrays rather than an ABI
/// value), or a *transaction* type (`pay`/`keyreg`/`acfg`/`axfer`/`afrz`/
/// `appl`/generic `txn`) that consumes a preceding transaction in the
/// enclosing group instead of contributing an application argument at all.
///
/// Mirrors go-algorand's `avm-abi/abi.TransactionType`/`ReferenceType`
/// method-argument handling, as observed in `cmd/goal`'s ABI method-call
/// support (`d3bbe62ca` et al., see issue #888) and the AVM `method`
/// pseudo-op's selector computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodArgType {
    /// An ordinary ABI value type: contributes one ABI-encoded application
    /// argument.
    Abi(AbiType),
    /// A reference to an account/asset/application: contributes one
    /// `uint8` application argument holding the resolved index.
    Reference(ReferenceType),
    /// A transaction argument: no application argument at all; the
    /// argument is satisfied by the transaction immediately preceding this
    /// one in the atomic group.
    Transaction(TransactionType),
}

impl fmt::Display for MethodArgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MethodArgType::Abi(t) => write!(f, "{t}"),
            MethodArgType::Reference(r) => write!(f, "{r}"),
            MethodArgType::Transaction(t) => write!(f, "{t}"),
        }
    }
}

/// An ARC-4 on-chain reference argument type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceType {
    Account,
    Asset,
    Application,
}

impl fmt::Display for ReferenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReferenceType::Account => "account",
            ReferenceType::Asset => "asset",
            ReferenceType::Application => "application",
        })
    }
}

/// An ARC-4 transaction argument type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    /// `txn` — any transaction type.
    Any,
    Pay,
    KeyRegistration,
    AssetConfig,
    AssetTransfer,
    AssetFreeze,
    ApplicationCall,
}

impl fmt::Display for TransactionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransactionType::Any => "txn",
            TransactionType::Pay => "pay",
            TransactionType::KeyRegistration => "keyreg",
            TransactionType::AssetConfig => "acfg",
            TransactionType::AssetTransfer => "axfer",
            TransactionType::AssetFreeze => "afrz",
            TransactionType::ApplicationCall => "appl",
        })
    }
}

/// Parse one top-level method-argument type token: a reference type, a
/// transaction type, or (falling through to the general parser) an ABI
/// value type. Reference/transaction types are recognized by exact keyword
/// match, matching go-algorand's `abi.TypeOf`-adjacent method-arg parsing —
/// they are never valid inside a tuple/array, so this dispatch only
/// applies at the top level of a method signature's argument list.
pub fn parse_method_arg_type(s: &str) -> Result<MethodArgType, String> {
    match s {
        "account" => Ok(MethodArgType::Reference(ReferenceType::Account)),
        "asset" => Ok(MethodArgType::Reference(ReferenceType::Asset)),
        "application" => Ok(MethodArgType::Reference(ReferenceType::Application)),
        "txn" => Ok(MethodArgType::Transaction(TransactionType::Any)),
        "pay" => Ok(MethodArgType::Transaction(TransactionType::Pay)),
        "keyreg" => Ok(MethodArgType::Transaction(TransactionType::KeyRegistration)),
        "acfg" => Ok(MethodArgType::Transaction(TransactionType::AssetConfig)),
        "axfer" => Ok(MethodArgType::Transaction(TransactionType::AssetTransfer)),
        "afrz" => Ok(MethodArgType::Transaction(TransactionType::AssetFreeze)),
        "appl" => Ok(MethodArgType::Transaction(TransactionType::ApplicationCall)),
        _ => type_of(s).map(MethodArgType::Abi),
    }
}

/// A parsed ARC-4 method: name, argument types, and return type (`None` for
/// `void`).
///
/// Mirrors go-algorand's `avm-abi/abi.Method` (the parsed form of a
/// `goal app method --method "name(t1,t2)ret"` inline signature, or one
/// entry of an ARC-4 Contract/Interface JSON file's `methods` array).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Method {
    pub name: std::string::String,
    pub args: Vec<MethodArgType>,
    /// `None` for a `void`-returning method.
    pub returns: Option<AbiType>,
}

impl Method {
    /// Reconstruct the canonical ARC-4 signature string, e.g.
    /// `"add(uint64,uint64)uint64"` or `"empty()void"`.
    pub fn signature(&self) -> std::string::String {
        let args = self
            .args
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let ret = match &self.returns {
            Some(t) => t.to_string(),
            None => "void".to_string(),
        };
        format!("{}({args}){ret}", self.name)
    }

    /// The ARC-4 method selector: the first 4 bytes of
    /// `SHA512/256(self.signature())`.
    pub fn selector(&self) -> [u8; 4] {
        method_selector(&self.signature())
    }

    /// The number of application-call arguments (`appArgs[1..]`) this
    /// method consumes: one per [`MethodArgType::Abi`] or
    /// [`MethodArgType::Reference`] argument (a `uint8` index for
    /// references), zero for [`MethodArgType::Transaction`] arguments
    /// (which instead consume a slot in the enclosing transaction group).
    ///
    /// Mirrors go-algorand's `Method.GetTxCount`/app-arg-count split.
    pub fn app_arg_count(&self) -> usize {
        self.args
            .iter()
            .filter(|a| !matches!(a, MethodArgType::Transaction(_)))
            .count()
    }

    /// The number of leading transactions in the atomic group this method's
    /// [`MethodArgType::Transaction`] arguments consume (immediately
    /// preceding the app-call transaction, in argument order).
    pub fn transaction_arg_count(&self) -> usize {
        self.args
            .iter()
            .filter(|a| matches!(a, MethodArgType::Transaction(_)))
            .count()
    }
}

/// Parse an inline ARC-4 method signature, e.g. `"add(uint64,uint64)uint64"`
/// or `"empty()void"`, as accepted by `goal app method --method`.
///
/// Mirrors go-algorand's `abi.Method`'s signature-string constructor path
/// used by `cmd/goal`'s `--method` flag.
pub fn parse_method_signature(sig: &str) -> Result<Method, String> {
    let open = sig
        .find('(')
        .ok_or_else(|| format!("ill formed method signature: \"{sig}\" (missing '(')"))?;
    let name = &sig[..open];
    if name.is_empty() {
        return Err(format!(
            "ill formed method signature: \"{sig}\" (empty method name)"
        ));
    }

    // Find the matching top-level ')' by paren-depth scan (arg types may
    // themselves contain parenthesized tuples).
    let rest = &sig[open + 1..];
    let mut depth = 1i32;
    let mut close_rel = None;
    for (idx, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close_rel = Some(idx);
                    break;
                }
            }
            _ => {}
        }
    }
    let close_rel = close_rel.ok_or_else(|| {
        format!("ill formed method signature: \"{sig}\" (unbalanced parentheses)")
    })?;

    let args_str = &rest[..close_rel];
    let ret_str = &rest[close_rel + 1..];
    if ret_str.is_empty() {
        return Err(format!(
            "ill formed method signature: \"{sig}\" (missing return type)"
        ));
    }

    let arg_tokens = parse_tuple_content(args_str)?;
    let mut args = Vec::with_capacity(arg_tokens.len());
    for tok in &arg_tokens {
        args.push(parse_method_arg_type(tok)?);
    }

    let returns = if ret_str == "void" {
        None
    } else {
        Some(type_of(ret_str)?)
    };

    Ok(Method {
        name: name.to_string(),
        args,
        returns,
    })
}

/// Compute the ARC-4 method selector for a signature string: the first 4
/// bytes of `SHA512/256(signature)`.
///
/// Mirrors go-algorand's `avm-abi/abi.Method.GetMethodID` and the AVM
/// `method "..."` pseudo-op (`crates/core/algo-avm/src/assembler.rs`'s
/// `asm_method`, which computes the identical value at TEAL-assembly time
/// for a program's own hardcoded selector comparisons).
pub fn method_selector(signature: &str) -> [u8; 4] {
    let hash = Sha512_256::digest(signature.as_bytes());
    let mut selector = [0u8; 4];
    selector.copy_from_slice(&hash[..4]);
    selector
}

// ---------------------------------------------------------------------------
// ARC-4 Contract / Interface JSON (application.json)
// ---------------------------------------------------------------------------

/// One `args[]` entry in an ARC-4 Contract/Interface JSON method
/// description.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MethodArgSpec {
    #[serde(rename = "type")]
    pub type_str: std::string::String,
    #[serde(default)]
    pub name: std::string::String,
    #[serde(default)]
    pub desc: std::string::String,
}

/// The `returns` entry in an ARC-4 Contract/Interface JSON method
/// description.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MethodReturnSpec {
    #[serde(rename = "type")]
    pub type_str: std::string::String,
    #[serde(default)]
    pub desc: std::string::String,
}

/// One `methods[]` entry in an ARC-4 Contract/Interface JSON file.
///
/// Mirrors the ARC-4 (`https://arc.algorand.foundation/ARCs/arc-0004`)
/// `method` JSON object: `{"name", "desc", "args": [...], "returns": {...}}`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct MethodSpec {
    pub name: std::string::String,
    #[serde(default)]
    pub desc: std::string::String,
    #[serde(default)]
    pub args: Vec<MethodArgSpec>,
    pub returns: MethodReturnSpec,
}

impl MethodSpec {
    /// Resolve this JSON spec into a parsed [`Method`] (arg/return type
    /// strings parsed into [`MethodArgType`]/[`AbiType`]).
    pub fn to_method(&self) -> Result<Method, String> {
        let mut args = Vec::with_capacity(self.args.len());
        for a in &self.args {
            args.push(parse_method_arg_type(&a.type_str)?);
        }
        let returns = if self.returns.type_str == "void" {
            None
        } else {
            Some(type_of(&self.returns.type_str)?)
        };
        Ok(Method {
            name: self.name.clone(),
            args,
            returns,
        })
    }
}

/// An ARC-4 Contract JSON file (`{"name", "desc", "networks", "methods"}`):
/// what `goal app method --abi <contract.json>` / the `--method`-by-name
/// lookup path reads.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Contract {
    pub name: std::string::String,
    #[serde(default)]
    pub desc: std::string::String,
    #[serde(default)]
    pub networks: std::collections::HashMap<std::string::String, serde_json::Value>,
    pub methods: Vec<MethodSpec>,
}

/// An ARC-4 Interface JSON file (`{"name", "desc", "methods"}`, no
/// `networks`): the app-id-agnostic sibling of [`Contract`].
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Interface {
    pub name: std::string::String,
    #[serde(default)]
    pub desc: std::string::String,
    pub methods: Vec<MethodSpec>,
}

impl Contract {
    /// Find a method by exact name. Errors if zero or more than one method
    /// shares that name (ARC-4 allows overloading by signature; a caller
    /// with an ambiguous name must disambiguate, matching go's `goal`
    /// behavior of requiring an unambiguous `--method` match).
    pub fn find_method(&self, name: &str) -> Result<&MethodSpec, String> {
        let matches: Vec<&MethodSpec> = self.methods.iter().filter(|m| m.name == name).collect();
        match matches.len() {
            0 => Err(format!("no method named \"{name}\" found in contract")),
            1 => Ok(matches[0]),
            _ => Err(format!(
                "multiple methods named \"{name}\" found in contract; specify the full signature"
            )),
        }
    }
}

impl Interface {
    /// Find a method by exact name (see [`Contract::find_method`]).
    pub fn find_method(&self, name: &str) -> Result<&MethodSpec, String> {
        let matches: Vec<&MethodSpec> = self.methods.iter().filter(|m| m.name == name).collect();
        match matches.len() {
            0 => Err(format!("no method named \"{name}\" found in interface")),
            1 => Ok(matches[0]),
            _ => Err(format!(
                "multiple methods named \"{name}\" found in interface; specify the full signature"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Basic types ---

    #[test]
    fn test_uint_types() {
        assert_eq!(type_of("uint8").unwrap(), AbiType::Uint(8));
        assert_eq!(type_of("uint64").unwrap(), AbiType::Uint(64));
        assert_eq!(type_of("uint256").unwrap(), AbiType::Uint(256));
        assert_eq!(type_of("uint512").unwrap(), AbiType::Uint(512));
    }

    #[test]
    fn test_uint_invalid() {
        assert!(type_of("uint7").is_err());
        assert!(type_of("uint0").is_err());
        assert!(type_of("uint520").is_err());
        assert!(type_of("uint").is_err());
        assert!(type_of("uint-8").is_err());
    }

    #[test]
    fn test_ufixed_types() {
        assert_eq!(type_of("ufixed64x10").unwrap(), AbiType::Ufixed(64, 10));
        assert_eq!(type_of("ufixed8x1").unwrap(), AbiType::Ufixed(8, 1));
        assert_eq!(type_of("ufixed512x160").unwrap(), AbiType::Ufixed(512, 160));
    }

    #[test]
    fn test_ufixed_invalid() {
        assert!(type_of("ufixed7x10").is_err()); // bad bit size
        assert!(type_of("ufixed64x0").is_err()); // precision too low
        assert!(type_of("ufixed64x161").is_err()); // precision too high
        assert!(type_of("ufixed").is_err()); // missing params
        assert!(type_of("ufixed64").is_err()); // missing precision
    }

    #[test]
    fn test_bool() {
        assert_eq!(type_of("bool").unwrap(), AbiType::Bool);
    }

    #[test]
    fn test_byte() {
        assert_eq!(type_of("byte").unwrap(), AbiType::Byte);
    }

    #[test]
    fn test_address() {
        assert_eq!(type_of("address").unwrap(), AbiType::Address);
    }

    #[test]
    fn test_string() {
        assert_eq!(type_of("string").unwrap(), AbiType::String);
    }

    // --- Arrays ---

    #[test]
    fn test_static_array() {
        assert_eq!(
            type_of("uint64[3]").unwrap(),
            AbiType::ArrayStatic(Box::new(AbiType::Uint(64)), 3)
        );
        assert_eq!(
            type_of("bool[8]").unwrap(),
            AbiType::ArrayStatic(Box::new(AbiType::Bool), 8)
        );
        assert_eq!(
            type_of("address[0]").unwrap(),
            AbiType::ArrayStatic(Box::new(AbiType::Address), 0)
        );
    }

    #[test]
    fn test_dynamic_array() {
        assert_eq!(
            type_of("uint64[]").unwrap(),
            AbiType::ArrayDynamic(Box::new(AbiType::Uint(64)))
        );
        assert_eq!(
            type_of("bool[]").unwrap(),
            AbiType::ArrayDynamic(Box::new(AbiType::Bool))
        );
    }

    #[test]
    fn test_nested_array() {
        // uint64[3][]
        assert_eq!(
            type_of("uint64[3][]").unwrap(),
            AbiType::ArrayDynamic(Box::new(AbiType::ArrayStatic(
                Box::new(AbiType::Uint(64)),
                3
            )))
        );
        // uint64[][5]
        assert_eq!(
            type_of("uint64[][5]").unwrap(),
            AbiType::ArrayStatic(
                Box::new(AbiType::ArrayDynamic(Box::new(AbiType::Uint(64)))),
                5
            )
        );
    }

    // --- Tuples ---

    #[test]
    fn test_empty_tuple() {
        assert_eq!(type_of("()").unwrap(), AbiType::Tuple(vec![]));
    }

    #[test]
    fn test_simple_tuple() {
        assert_eq!(
            type_of("(uint64,address)").unwrap(),
            AbiType::Tuple(vec![AbiType::Uint(64), AbiType::Address])
        );
    }

    #[test]
    fn test_nested_tuple() {
        assert_eq!(
            type_of("(uint64,(bool,address))").unwrap(),
            AbiType::Tuple(vec![
                AbiType::Uint(64),
                AbiType::Tuple(vec![AbiType::Bool, AbiType::Address]),
            ])
        );
    }

    #[test]
    fn test_tuple_with_array() {
        assert_eq!(
            type_of("(uint64,bool[3])").unwrap(),
            AbiType::Tuple(vec![
                AbiType::Uint(64),
                AbiType::ArrayStatic(Box::new(AbiType::Bool), 3),
            ])
        );
    }

    #[test]
    fn test_tuple_array() {
        // (uint64,bool)[2]
        assert_eq!(
            type_of("(uint64,bool)[2]").unwrap(),
            AbiType::ArrayStatic(
                Box::new(AbiType::Tuple(vec![AbiType::Uint(64), AbiType::Bool])),
                2
            )
        );
    }

    #[test]
    fn test_tuple_dynamic_array() {
        // (uint64,bool)[]
        assert_eq!(
            type_of("(uint64,bool)[]").unwrap(),
            AbiType::ArrayDynamic(Box::new(AbiType::Tuple(vec![
                AbiType::Uint(64),
                AbiType::Bool,
            ])))
        );
    }

    #[test]
    fn test_complex_nested() {
        // ((uint64,bool),(address,string[]))
        let parsed = type_of("((uint64,bool),(address,string[]))").unwrap();
        assert_eq!(
            parsed,
            AbiType::Tuple(vec![
                AbiType::Tuple(vec![AbiType::Uint(64), AbiType::Bool]),
                AbiType::Tuple(vec![
                    AbiType::Address,
                    AbiType::ArrayDynamic(Box::new(AbiType::String)),
                ]),
            ])
        );
    }

    // --- parse_tuple_content ---

    #[test]
    fn test_parse_tuple_content_empty() {
        assert_eq!(parse_tuple_content("").unwrap(), Vec::<&str>::new());
    }

    #[test]
    fn test_parse_tuple_content_simple() {
        assert_eq!(
            parse_tuple_content("uint64,bool").unwrap(),
            vec!["uint64", "bool"]
        );
    }

    #[test]
    fn test_parse_tuple_content_nested() {
        assert_eq!(
            parse_tuple_content("uint64,(bool,address)").unwrap(),
            vec!["uint64", "(bool,address)"]
        );
    }

    #[test]
    fn test_parse_tuple_content_nested_array() {
        assert_eq!(
            parse_tuple_content("uint64,(bool,address)[3]").unwrap(),
            vec!["uint64", "(bool,address)[3]"]
        );
    }

    #[test]
    fn test_parse_tuple_content_leading_comma() {
        assert!(parse_tuple_content(",uint64").is_err());
    }

    #[test]
    fn test_parse_tuple_content_trailing_comma() {
        assert!(parse_tuple_content("uint64,").is_err());
    }

    #[test]
    fn test_parse_tuple_content_consecutive_commas() {
        assert!(parse_tuple_content("uint64,,bool").is_err());
    }

    // --- is_dynamic ---

    #[test]
    fn test_is_dynamic() {
        assert!(!AbiType::Uint(64).is_dynamic());
        assert!(!AbiType::Bool.is_dynamic());
        assert!(!AbiType::Byte.is_dynamic());
        assert!(!AbiType::Address.is_dynamic());
        assert!(AbiType::String.is_dynamic());
        assert!(AbiType::ArrayDynamic(Box::new(AbiType::Uint(8))).is_dynamic());
        assert!(!AbiType::ArrayStatic(Box::new(AbiType::Uint(8)), 3).is_dynamic());
        assert!(AbiType::ArrayStatic(Box::new(AbiType::String), 3).is_dynamic());
        assert!(!AbiType::Tuple(vec![AbiType::Uint(64), AbiType::Bool]).is_dynamic());
        assert!(AbiType::Tuple(vec![AbiType::Uint(64), AbiType::String]).is_dynamic());
    }

    // --- byte_len ---

    #[test]
    fn test_byte_len_basic() {
        assert_eq!(AbiType::Uint(8).byte_len(), Some(1));
        assert_eq!(AbiType::Uint(64).byte_len(), Some(8));
        assert_eq!(AbiType::Uint(512).byte_len(), Some(64));
        assert_eq!(AbiType::Bool.byte_len(), Some(1));
        assert_eq!(AbiType::Byte.byte_len(), Some(1));
        assert_eq!(AbiType::Address.byte_len(), Some(32));
        assert_eq!(AbiType::String.byte_len(), None);
    }

    #[test]
    fn test_byte_len_ufixed() {
        assert_eq!(AbiType::Ufixed(64, 10).byte_len(), Some(8));
        assert_eq!(AbiType::Ufixed(256, 80).byte_len(), Some(32));
    }

    #[test]
    fn test_byte_len_static_array() {
        assert_eq!(
            AbiType::ArrayStatic(Box::new(AbiType::Uint(64)), 3).byte_len(),
            Some(24)
        );
        // Bool arrays are bit-packed.
        assert_eq!(
            AbiType::ArrayStatic(Box::new(AbiType::Bool), 8).byte_len(),
            Some(1)
        );
        assert_eq!(
            AbiType::ArrayStatic(Box::new(AbiType::Bool), 9).byte_len(),
            Some(2)
        );
    }

    #[test]
    fn test_byte_len_dynamic() {
        assert_eq!(
            AbiType::ArrayDynamic(Box::new(AbiType::Uint(8))).byte_len(),
            None
        );
    }

    #[test]
    fn test_byte_len_tuple() {
        // (uint64, bool, bool, bool) -> 8 + ceil(3/8) = 8 + 1 = 9
        assert_eq!(
            AbiType::Tuple(vec![
                AbiType::Uint(64),
                AbiType::Bool,
                AbiType::Bool,
                AbiType::Bool,
            ])
            .byte_len(),
            Some(9)
        );
    }

    #[test]
    fn test_byte_len_tuple_dynamic_child() {
        assert_eq!(
            AbiType::Tuple(vec![AbiType::Uint(64), AbiType::String]).byte_len(),
            None
        );
    }

    // --- Display round-trip ---

    #[test]
    fn test_display_roundtrip() {
        let cases = vec![
            "uint8",
            "uint64",
            "uint512",
            "ufixed64x10",
            "bool",
            "byte",
            "address",
            "string",
            "uint64[3]",
            "uint64[]",
            "(uint64,bool)",
            "(uint64,(bool,address))",
            "()",
            "((uint64,bool),(address,string[]))",
            "(uint64,bool)[2]",
            "(uint64,bool)[]",
        ];
        for case in cases {
            let parsed = type_of(case).unwrap();
            assert_eq!(parsed.to_string(), case, "round-trip failed for {case}");
        }
    }

    // --- Invalid inputs ---

    #[test]
    fn test_invalid_types() {
        assert!(type_of("").is_err());
        assert!(type_of("foo").is_err());
        assert!(type_of("uint").is_err());
        assert!(type_of("int64").is_err());
        assert!(type_of("(").is_err());
        assert!(type_of(")").is_err());
        assert!(type_of("uint64[").is_err());
    }

    // --- Encoding tests ---

    #[test]
    fn test_encode_uint64() {
        let result = parse_and_encode_abi("uint64", "42").unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0, 0, 0, 42]);
    }

    #[test]
    fn test_encode_uint8() {
        let result = parse_and_encode_abi("uint8", "255").unwrap();
        assert_eq!(result, vec![255]);
    }

    #[test]
    fn test_encode_uint16() {
        let result = parse_and_encode_abi("uint16", "256").unwrap();
        assert_eq!(result, vec![1, 0]);
    }

    #[test]
    fn test_encode_bool_true() {
        let result = parse_and_encode_abi("bool", "true").unwrap();
        assert_eq!(result, vec![0x80]);
    }

    #[test]
    fn test_encode_bool_false() {
        let result = parse_and_encode_abi("bool", "false").unwrap();
        assert_eq!(result, vec![0x00]);
    }

    #[test]
    fn test_encode_byte() {
        let result = parse_and_encode_abi("byte", "42").unwrap();
        assert_eq!(result, vec![42]);
    }

    #[test]
    fn test_encode_address() {
        let result = parse_and_encode_abi(
            "address",
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\"",
        )
        .unwrap();
        assert_eq!(result, vec![0u8; 32]);
    }

    #[test]
    fn test_encode_string() {
        let result = parse_and_encode_abi("string", "\"hello\"").unwrap();
        // 2-byte length prefix (5) + "hello"
        assert_eq!(result, vec![0, 5, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_encode_static_array_uint8() {
        let result = parse_and_encode_abi("uint8[3]", "[1,2,3]").unwrap();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_encode_dynamic_array_uint8() {
        let result = parse_and_encode_abi("uint8[]", "[1,2,3]").unwrap();
        // 2-byte length (3) + elements
        assert_eq!(result, vec![0, 3, 1, 2, 3]);
    }

    #[test]
    fn test_encode_tuple_static() {
        // (uint8,uint16) with values [1, 256]
        let result = parse_and_encode_abi("(uint8,uint16)", "[1,256]").unwrap();
        assert_eq!(result, vec![1, 1, 0]);
    }

    #[test]
    fn test_encode_tuple_with_dynamic() {
        // (uint8,string) with values [1, "ab"]
        let result = parse_and_encode_abi("(uint8,string)", "[1,\"ab\"]").unwrap();
        // head: uint8=1 (1 byte) + offset to tail (2 bytes) = 3 bytes head
        // offset = 3 (pointing to start of tail)
        // tail: string "ab" = [0, 2, 97, 98]
        assert_eq!(result, vec![1, 0, 3, 0, 2, b'a', b'b']);
    }

    #[test]
    fn test_encode_tuple_bool_packing() {
        // (bool,bool,bool) => packed into a single byte
        let result = parse_and_encode_abi("(bool,bool,bool)", "[true,false,true]").unwrap();
        // bits: 1,0,1 => 0b10100000 = 0xA0
        assert_eq!(result, vec![0xA0]);
    }

    #[test]
    fn test_encode_uint_overflow() {
        assert!(parse_and_encode_abi("uint8", "256").is_err());
    }

    #[test]
    fn test_parse_and_encode_abi_end_to_end() {
        // Same as the go-algorand parsing.go flow: type_str => parse => unmarshal => encode
        let result = parse_and_encode_abi("uint64", "42").unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0, 0, 0, 42]);
    }

    // -----------------------------------------------------------------------
    // Wave 3: Comprehensive test coverage
    // -----------------------------------------------------------------------

    // --- Type parsing edge cases ---

    #[test]
    fn test_parse_ufixed_boundary_values() {
        // Min valid: ufixed8x1
        assert_eq!(type_of("ufixed8x1").unwrap(), AbiType::Ufixed(8, 1));
        // Max valid: ufixed512x160
        assert_eq!(type_of("ufixed512x160").unwrap(), AbiType::Ufixed(512, 160));
        // Various valid combinations
        assert_eq!(type_of("ufixed128x10").unwrap(), AbiType::Ufixed(128, 10));
        assert_eq!(type_of("ufixed256x80").unwrap(), AbiType::Ufixed(256, 80));
    }

    #[test]
    fn test_parse_ufixed_leading_zeros_rejected() {
        // Leading zeros in bitsize or precision should be rejected
        assert!(type_of("ufixed008x01").is_err());
        assert!(type_of("ufixed64x010").is_err());
        assert!(type_of("ufixed064x10").is_err());
    }

    #[test]
    fn test_parse_deeply_nested_tuple() {
        // (uint64,(bool,(address,string)))
        let parsed = type_of("(uint64,(bool,(address,string)))").unwrap();
        assert_eq!(
            parsed,
            AbiType::Tuple(vec![
                AbiType::Uint(64),
                AbiType::Tuple(vec![
                    AbiType::Bool,
                    AbiType::Tuple(vec![AbiType::Address, AbiType::String]),
                ]),
            ])
        );
    }

    #[test]
    fn test_parse_array_of_tuples() {
        // (uint64,bool)[3]
        assert_eq!(
            type_of("(uint64,bool)[3]").unwrap(),
            AbiType::ArrayStatic(
                Box::new(AbiType::Tuple(vec![AbiType::Uint(64), AbiType::Bool])),
                3
            )
        );
    }

    #[test]
    fn test_parse_tuple_containing_arrays() {
        // (uint64[],bool[3],string)
        assert_eq!(
            type_of("(uint64[],bool[3],string)").unwrap(),
            AbiType::Tuple(vec![
                AbiType::ArrayDynamic(Box::new(AbiType::Uint(64))),
                AbiType::ArrayStatic(Box::new(AbiType::Bool), 3),
                AbiType::String,
            ])
        );
    }

    #[test]
    fn test_parse_complex_go_reference_types() {
        // From go-algorand type_test.go
        // (uint32,(address,byte,bool[10],ufixed256x10[]),byte[])
        let parsed = type_of("(uint32,(address,byte,bool[10],ufixed256x10[]),byte[])").unwrap();
        assert_eq!(
            parsed,
            AbiType::Tuple(vec![
                AbiType::Uint(32),
                AbiType::Tuple(vec![
                    AbiType::Address,
                    AbiType::Byte,
                    AbiType::ArrayStatic(Box::new(AbiType::Bool), 10),
                    AbiType::ArrayDynamic(Box::new(AbiType::Ufixed(256, 10))),
                ]),
                AbiType::ArrayDynamic(Box::new(AbiType::Byte)),
            ])
        );
    }

    #[test]
    fn test_parse_nested_tuple_variants() {
        // (uint32,(address,byte,bool[10],(ufixed256x10[])))
        let parsed = type_of("(uint32,(address,byte,bool[10],(ufixed256x10[])))").unwrap();
        assert_eq!(
            parsed,
            AbiType::Tuple(vec![
                AbiType::Uint(32),
                AbiType::Tuple(vec![
                    AbiType::Address,
                    AbiType::Byte,
                    AbiType::ArrayStatic(Box::new(AbiType::Bool), 10),
                    AbiType::Tuple(vec![AbiType::ArrayDynamic(Box::new(AbiType::Ufixed(
                        256, 10
                    )))]),
                ]),
            ])
        );

        // ((uint32),(address,(byte,bool[10],ufixed256x10[])))
        let parsed = type_of("((uint32),(address,(byte,bool[10],ufixed256x10[])))").unwrap();
        assert_eq!(
            parsed,
            AbiType::Tuple(vec![
                AbiType::Tuple(vec![AbiType::Uint(32)]),
                AbiType::Tuple(vec![
                    AbiType::Address,
                    AbiType::Tuple(vec![
                        AbiType::Byte,
                        AbiType::ArrayStatic(Box::new(AbiType::Bool), 10),
                        AbiType::ArrayDynamic(Box::new(AbiType::Ufixed(256, 10))),
                    ]),
                ]),
            ])
        );
    }

    #[test]
    fn test_parse_tuple_with_tuple_array_and_bools() {
        // From go-algorand: (bool,bool,(string,uint64)[3])
        let parsed = type_of("(bool,bool,(string,uint64)[3])").unwrap();
        assert_eq!(
            parsed,
            AbiType::Tuple(vec![
                AbiType::Bool,
                AbiType::Bool,
                AbiType::ArrayStatic(
                    Box::new(AbiType::Tuple(vec![AbiType::String, AbiType::Uint(64)])),
                    3
                ),
            ])
        );

        // (bool,(string,uint64)[3],bool)
        let parsed = type_of("(bool,(string,uint64)[3],bool)").unwrap();
        assert_eq!(
            parsed,
            AbiType::Tuple(vec![
                AbiType::Bool,
                AbiType::ArrayStatic(
                    Box::new(AbiType::Tuple(vec![AbiType::String, AbiType::Uint(64)])),
                    3
                ),
                AbiType::Bool,
            ])
        );

        // ((string,uint64)[3],bool,bool)
        let parsed = type_of("((string,uint64)[3],bool,bool)").unwrap();
        assert_eq!(
            parsed,
            AbiType::Tuple(vec![
                AbiType::ArrayStatic(
                    Box::new(AbiType::Tuple(vec![AbiType::String, AbiType::Uint(64)])),
                    3
                ),
                AbiType::Bool,
                AbiType::Bool,
            ])
        );
    }

    #[test]
    fn test_parse_multi_nested_dynamic_arrays() {
        // byte[][][][]
        assert_eq!(
            type_of("byte[][][][]").unwrap(),
            AbiType::ArrayDynamic(Box::new(AbiType::ArrayDynamic(Box::new(
                AbiType::ArrayDynamic(Box::new(AbiType::ArrayDynamic(Box::new(AbiType::Byte))))
            ))))
        );
    }

    // --- Invalid type strings from go-algorand ---

    #[test]
    fn test_invalid_types_from_go_reference() {
        let invalid_cases = vec![
            "uint123x345",
            "uint 128",
            "uint8 ",
            "uint!8",
            "uint[32]",
            "uint-893",
            "ufixed123x345",
            "ufixed 128 x 100",
            "ufixed64x10 ",
            "ufixed!8x2 ",
            "ufixed[32]x16",
            "ufixed-64x+100",
            "uint256 []",
            "byte[] ",
            "[][][]",
            "stuff[]",
            "byte[01]",
            "byte[10 ]",
            "uint64[0x21]",
            "(,uint128,byte[])",
            "(address,ufixed64x5,)",
            "(byte[16],somethingwrong)",
            "(                )",
            "((uint32)",
            "(byte,,byte)",
            "((byte),,(byte))",
        ];
        for case in invalid_cases {
            assert!(type_of(case).is_err(), "expected error for: {case}");
        }
    }

    // --- Display round-trip for complex types ---

    #[test]
    fn test_display_roundtrip_complex() {
        let cases = vec![
            "ufixed128x10",
            "ufixed8x1",
            "ufixed512x160",
            "ufixed256x80",
            "byte[][][][]",
            "bool[128][256]",
            "(uint32,(address,byte,bool[10],ufixed256x10[]),byte[])",
            "(uint32,(address,byte,bool[10],(ufixed256x10[])))",
            "((uint32),(address,(byte,bool[10],ufixed256x10[])))",
            "(bool,bool,(string,uint64)[3])",
            "(bool,(string,uint64)[3],bool)",
            "((string,uint64)[3],bool,bool)",
            "(uint64,(bool,(address,string)))",
            "(uint64[],bool[3],string)",
        ];
        for case in cases {
            let parsed = type_of(case).unwrap();
            assert_eq!(parsed.to_string(), case, "round-trip failed for {case}");
        }
    }

    // --- JSON unmarshaling tests ---

    #[test]
    fn test_unmarshal_uint_from_json() {
        let ty = type_of("uint64").unwrap();
        let val = unmarshal_from_json(&ty, "42").unwrap();
        assert_eq!(val, AbiValue::Uint(BigUint::from(42u64), 64));
    }

    #[test]
    fn test_unmarshal_uint_from_json_string() {
        // Accept quoted strings for large numbers
        let ty = type_of("uint256").unwrap();
        let val = unmarshal_from_json(&ty, "\"999\"").unwrap();
        assert_eq!(val, AbiValue::Uint(BigUint::from(999u64), 256));
    }

    #[test]
    fn test_unmarshal_uint256_large_value() {
        let ty = type_of("uint256").unwrap();
        // 2^128
        let val = unmarshal_from_json(&ty, "\"340282366920938463463374607431768211456\"").unwrap();
        assert_eq!(val, AbiValue::Uint(BigUint::from(1u64) << 128, 256));
    }

    #[test]
    fn test_unmarshal_bool_from_json() {
        let ty = type_of("bool").unwrap();
        assert_eq!(
            unmarshal_from_json(&ty, "true").unwrap(),
            AbiValue::Bool(true)
        );
        assert_eq!(
            unmarshal_from_json(&ty, "false").unwrap(),
            AbiValue::Bool(false)
        );
    }

    #[test]
    fn test_unmarshal_byte_from_json() {
        let ty = type_of("byte").unwrap();
        assert_eq!(
            unmarshal_from_json(&ty, "255").unwrap(),
            AbiValue::Byte(255)
        );
        assert_eq!(unmarshal_from_json(&ty, "0").unwrap(), AbiValue::Byte(0));
    }

    #[test]
    fn test_unmarshal_string_from_json_quoted() {
        let ty = type_of("string").unwrap();
        let val = unmarshal_from_json(&ty, "\"hello world\"").unwrap();
        assert_eq!(val, AbiValue::String(b"hello world".to_vec()));
    }

    #[test]
    fn test_unmarshal_string_from_json_byte_array() {
        // Go allows string to be unmarshaled from a JSON byte array
        let ty = type_of("string").unwrap();
        let val = unmarshal_from_json(&ty, "[65,66,67]").unwrap();
        assert_eq!(val, AbiValue::String(vec![65, 66, 67])); // "ABC"
    }

    #[test]
    fn test_unmarshal_string_empty() {
        let ty = type_of("string").unwrap();
        let val = unmarshal_from_json(&ty, "\"\"").unwrap();
        assert_eq!(val, AbiValue::String(vec![]));
    }

    #[test]
    fn test_unmarshal_static_array_from_json() {
        let ty = type_of("uint8[3]").unwrap();
        let val = unmarshal_from_json(&ty, "[1,2,3]").unwrap();
        assert_eq!(
            val,
            AbiValue::ArrayStatic(
                vec![
                    AbiValue::Uint(BigUint::from(1u8), 8),
                    AbiValue::Uint(BigUint::from(2u8), 8),
                    AbiValue::Uint(BigUint::from(3u8), 8),
                ],
                AbiType::Uint(8)
            )
        );
    }

    #[test]
    fn test_unmarshal_dynamic_array_from_json() {
        let ty = type_of("bool[]").unwrap();
        let val = unmarshal_from_json(&ty, "[true,false,true]").unwrap();
        assert_eq!(
            val,
            AbiValue::ArrayDynamic(
                vec![
                    AbiValue::Bool(true),
                    AbiValue::Bool(false),
                    AbiValue::Bool(true),
                ],
                AbiType::Bool
            )
        );
    }

    #[test]
    fn test_unmarshal_empty_dynamic_array() {
        let ty = type_of("uint64[]").unwrap();
        let val = unmarshal_from_json(&ty, "[]").unwrap();
        assert_eq!(val, AbiValue::ArrayDynamic(vec![], AbiType::Uint(64)));
    }

    #[test]
    fn test_unmarshal_tuple_from_json() {
        let ty = type_of("(uint64,bool,string)").unwrap();
        let val = unmarshal_from_json(&ty, "[42,true,\"hi\"]").unwrap();
        assert_eq!(
            val,
            AbiValue::Tuple(vec![
                AbiValue::Uint(BigUint::from(42u64), 64),
                AbiValue::Bool(true),
                AbiValue::String(b"hi".to_vec()),
            ])
        );
    }

    #[test]
    fn test_unmarshal_nested_tuple_from_json() {
        let ty = type_of("(uint8,(bool,uint16))").unwrap();
        let val = unmarshal_from_json(&ty, "[1,[true,256]]").unwrap();
        assert_eq!(
            val,
            AbiValue::Tuple(vec![
                AbiValue::Uint(BigUint::from(1u8), 8),
                AbiValue::Tuple(vec![
                    AbiValue::Bool(true),
                    AbiValue::Uint(BigUint::from(256u64), 16),
                ]),
            ])
        );
    }

    #[test]
    fn test_unmarshal_empty_tuple() {
        let ty = type_of("()").unwrap();
        let val = unmarshal_from_json(&ty, "[]").unwrap();
        assert_eq!(val, AbiValue::Tuple(vec![]));
    }

    #[test]
    fn test_unmarshal_ufixed_from_json() {
        // Integer input: 42 with precision 10 → 42 * 10^10 = 420000000000
        let ty = type_of("ufixed64x10").unwrap();
        let val = unmarshal_from_json(&ty, "42").unwrap();
        assert_eq!(
            val,
            AbiValue::Ufixed(BigUint::from(420_000_000_000u64), 64, 10)
        );
    }

    // --- JSON unmarshal error cases ---

    #[test]
    fn test_unmarshal_bool_wrong_type() {
        let ty = type_of("bool").unwrap();
        assert!(unmarshal_from_json(&ty, "42").is_err());
        assert!(unmarshal_from_json(&ty, "\"true\"").is_err());
    }

    #[test]
    fn test_unmarshal_uint_overflow() {
        let ty = type_of("uint8").unwrap();
        assert!(unmarshal_from_json(&ty, "256").is_err());
    }

    #[test]
    fn test_unmarshal_uint_negative() {
        let ty = type_of("uint64").unwrap();
        assert!(unmarshal_from_json(&ty, "-1").is_err());
    }

    #[test]
    fn test_unmarshal_static_array_wrong_length() {
        let ty = type_of("uint8[3]").unwrap();
        assert!(unmarshal_from_json(&ty, "[1,2]").is_err());
        assert!(unmarshal_from_json(&ty, "[1,2,3,4]").is_err());
    }

    #[test]
    fn test_unmarshal_tuple_wrong_length() {
        let ty = type_of("(uint8,bool)").unwrap();
        assert!(unmarshal_from_json(&ty, "[1]").is_err());
        assert!(unmarshal_from_json(&ty, "[1,true,3]").is_err());
    }

    #[test]
    fn test_unmarshal_string_wrong_type() {
        let ty = type_of("string").unwrap();
        assert!(unmarshal_from_json(&ty, "42").is_err());
        assert!(unmarshal_from_json(&ty, "true").is_err());
    }

    #[test]
    fn test_unmarshal_byte_overflow() {
        let ty = type_of("byte").unwrap();
        assert!(unmarshal_from_json(&ty, "256").is_err());
    }

    #[test]
    fn test_unmarshal_array_not_json_array() {
        let ty = type_of("uint8[3]").unwrap();
        assert!(unmarshal_from_json(&ty, "\"not an array\"").is_err());
    }

    // --- Encoding correctness tests ---

    #[test]
    fn test_encode_uint256_large_value() {
        // 2^128 = 340282366920938463463374607431768211456
        let result =
            parse_and_encode_abi("uint256", "\"340282366920938463463374607431768211456\"").unwrap();
        // 32 bytes total, byte 16 should be 1, rest 0
        assert_eq!(result.len(), 32);
        assert_eq!(result[15], 1);
        // All bytes before index 15 should be 0
        assert!(result[..15].iter().all(|&b| b == 0));
        // All bytes after index 15 should be 0
        assert!(result[16..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encode_uint256_max_value() {
        // 2^256 - 1
        let max =
            "\"115792089237316195423570985008687907853269984665640564039457584007913129639935\"";
        let result = parse_and_encode_abi("uint256", max).unwrap();
        assert_eq!(result.len(), 32);
        assert!(result.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_encode_uint512_zero() {
        let result = parse_and_encode_abi("uint512", "0").unwrap();
        assert_eq!(result.len(), 64);
        assert!(result.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encode_ufixed64x10() {
        // ufixed64x10 with "0.0000000001" → 0.0000000001 * 10^10 = 1
        let result = parse_and_encode_abi("ufixed64x10", "\"0.0000000001\"").unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_encode_ufixed256x80() {
        // ufixed256x80 with "0" → 0 * 10^80 = 0
        let result = parse_and_encode_abi("ufixed256x80", "0").unwrap();
        assert_eq!(result.len(), 32);
        assert!(result.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encode_string_empty() {
        let result = parse_and_encode_abi("string", "\"\"").unwrap();
        // 2-byte length prefix (0) + empty content
        assert_eq!(result, vec![0, 0]);
    }

    #[test]
    fn test_encode_string_unicode() {
        // UTF-8 multi-byte characters
        let result = parse_and_encode_abi("string", "\"hi\"").unwrap();
        assert_eq!(result, vec![0, 2, b'h', b'i']);
    }

    #[test]
    fn test_encode_string_as_byte_array() {
        // String from JSON byte array
        let result = parse_and_encode_abi("string", "[65,66,67]").unwrap();
        // "ABC" = length 3 + bytes
        assert_eq!(result, vec![0, 3, 65, 66, 67]);
    }

    // --- Static bool array encoding (from go-algorand) ---

    #[test]
    fn test_encode_static_bool_array_5() {
        // {T, F, F, T, T} => 0b10011000
        let result = parse_and_encode_abi("bool[5]", "[true,false,false,true,true]").unwrap();
        assert_eq!(result, vec![0b10011000]);
    }

    #[test]
    fn test_encode_static_bool_array_11() {
        // {F,F,F,T,T,F,T,F,T,F,T} => {0b00011010, 0b10100000}
        let result = parse_and_encode_abi(
            "bool[11]",
            "[false,false,false,true,true,false,true,false,true,false,true]",
        )
        .unwrap();
        assert_eq!(result, vec![0b00011010, 0b10100000]);
    }

    // --- Dynamic bool array encoding ---

    #[test]
    fn test_encode_dynamic_bool_array() {
        // {F,T,F,T,F,T,F,T,F,T} => length(10) + {0b01010101, 0b01000000}
        let result = parse_and_encode_abi(
            "bool[]",
            "[false,true,false,true,false,true,false,true,false,true]",
        )
        .unwrap();
        assert_eq!(result, vec![0x00, 0x0A, 0b01010101, 0b01000000]);
    }

    #[test]
    fn test_encode_dynamic_bool_array_empty() {
        let result = parse_and_encode_abi("bool[]", "[]").unwrap();
        assert_eq!(result, vec![0x00, 0x00]);
    }

    // --- Tuple encoding with mixed static/dynamic (from go-algorand) ---

    #[test]
    fn test_encode_tuple_string_bools_string() {
        // (string,bool,bool,bool,bool,string) with ("ABC", T, F, T, F, "DEF")
        // Head: offset_to_str1(2) + packed_bools(1) + offset_to_str2(2) = 5 bytes
        // offset_to_str1 = 5, offset_to_str2 = 10
        // Tail: str1 = [0,3,'A','B','C'], str2 = [0,3,'D','E','F']
        let result = parse_and_encode_abi(
            "(string,bool,bool,bool,bool,string)",
            "[\"ABC\",true,false,true,false,\"DEF\"]",
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                0x00, 0x05, 0b10100000, 0x00, 0x0A, 0x00, 0x03, b'A', b'B', b'C', 0x00, 0x03, b'D',
                b'E', b'F',
            ]
        );
    }

    // --- Tuple with static bool arrays ---

    #[test]
    fn test_encode_tuple_static_bool_arrays() {
        // (bool[2],bool[2]) with ({T,T},{T,T})
        // Each bool[2] encodes independently (not packed across array boundaries)
        let result =
            parse_and_encode_abi("(bool[2],bool[2])", "[[true,true],[true,true]]").unwrap();
        assert_eq!(result, vec![0b11000000, 0b11000000]);
    }

    #[test]
    fn test_encode_tuple_static_and_dynamic_bool_arrays() {
        // (bool[2],bool[]) with ({T,T},{T,T})
        // Head: bool[2]=0b11000000(1) + offset(2) = 3 bytes
        // offset = 3
        // Tail: bool[] = length(2) + 0b11000000
        let result = parse_and_encode_abi("(bool[2],bool[])", "[[true,true],[true,true]]").unwrap();
        assert_eq!(result, vec![0b11000000, 0x00, 0x03, 0x00, 0x02, 0b11000000]);
    }

    #[test]
    fn test_encode_tuple_two_dynamic_bool_arrays_empty() {
        // (bool[],bool[]) with ({},{})
        // Head: offset1(2) + offset2(2) = 4 bytes
        // offset1 = 4, offset2 = 6
        // Tail: [] = [0,0], [] = [0,0]
        let result = parse_and_encode_abi("(bool[],bool[])", "[[],[]]").unwrap();
        assert_eq!(result, vec![0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_encode_empty_tuple() {
        let result = parse_and_encode_abi("()", "[]").unwrap();
        assert!(result.is_empty());
    }

    // --- Static array encoding ---

    #[test]
    fn test_encode_static_array_uint64() {
        let result = parse_and_encode_abi("uint64[2]", "[1,2]").unwrap();
        let mut expected = vec![0u8; 16];
        expected[7] = 1;
        expected[15] = 2;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encode_static_array_address() {
        // address[0] is valid (zero-length)
        let result = parse_and_encode_abi("address[0]", "[]").unwrap();
        assert!(result.is_empty());
    }

    // --- Dynamic array encoding ---

    #[test]
    fn test_encode_dynamic_array_uint64() {
        let result = parse_and_encode_abi("uint64[]", "[1,2]").unwrap();
        // 2-byte length (2) + 8 bytes per element
        let mut expected = vec![0x00, 0x02];
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encode_dynamic_array_empty() {
        let result = parse_and_encode_abi("uint8[]", "[]").unwrap();
        assert_eq!(result, vec![0x00, 0x00]);
    }

    // --- Nested dynamic elements ---

    #[test]
    fn test_encode_tuple_nested_dynamic() {
        // (uint8,string,uint16) with [1,"ab",2]
        // Head: uint8=1(1) + offset(2) + uint16=2(2) = 5 bytes
        // offset = 5
        // Tail: string "ab" = [0, 2, 'a', 'b']
        let result = parse_and_encode_abi("(uint8,string,uint16)", "[1,\"ab\",2]").unwrap();
        assert_eq!(result, vec![1, 0, 5, 0, 2, 0, 2, b'a', b'b']);
    }

    #[test]
    fn test_encode_tuple_two_dynamic_strings() {
        // (string,string) with ("AB","CD")
        // Head: offset1(2) + offset2(2) = 4 bytes
        // offset1 = 4, offset2 = 8
        // Tail1: [0, 2, 'A', 'B'], Tail2: [0, 2, 'C', 'D']
        let result = parse_and_encode_abi("(string,string)", "[\"AB\",\"CD\"]").unwrap();
        assert_eq!(
            result,
            vec![0x00, 0x04, 0x00, 0x08, 0x00, 0x02, b'A', b'B', 0x00, 0x02, b'C', b'D',]
        );
    }

    // --- Bool packing edge cases ---

    #[test]
    fn test_encode_tuple_8_consecutive_bools() {
        // 8 bools should pack into exactly 1 byte
        let result = parse_and_encode_abi(
            "(bool,bool,bool,bool,bool,bool,bool,bool)",
            "[true,true,true,true,true,true,true,true]",
        )
        .unwrap();
        assert_eq!(result, vec![0xFF]);
    }

    #[test]
    fn test_encode_tuple_9_bools() {
        // 9 bools should pack into 2 bytes
        let result = parse_and_encode_abi(
            "(bool,bool,bool,bool,bool,bool,bool,bool,bool)",
            "[true,false,true,false,true,false,true,false,true]",
        )
        .unwrap();
        // First 8: 10101010 = 0xAA, Next 1: 10000000 = 0x80
        assert_eq!(result, vec![0xAA, 0x80]);
    }

    #[test]
    fn test_encode_tuple_bool_between_static() {
        // (uint8,bool,uint8) - bool not packed with non-bools
        let result = parse_and_encode_abi("(uint8,bool,uint8)", "[1,true,2]").unwrap();
        assert_eq!(result, vec![1, 0x80, 2]);
    }

    // --- parse_and_encode_abi end-to-end complex ---

    #[test]
    fn test_e2e_tuple_with_dynamic_array() {
        // (uint64,string,bool[]) with [399,"should pass",[true,false,false,true]]
        let result = parse_and_encode_abi(
            "(uint64,string,bool[])",
            "[399,\"should pass\",[true,false,false,true]]",
        )
        .unwrap();
        // Verify it produces valid output (non-empty and starts with uint64 encoding)
        assert!(!result.is_empty());
        // First 8 bytes = uint64(399)
        assert_eq!(&result[0..8], &[0, 0, 0, 0, 0, 0, 1, 143]);
    }

    #[test]
    fn test_e2e_nested_tuple() {
        // (uint8,(uint8,uint8)) with [1,[2,3]]
        let result = parse_and_encode_abi("(uint8,(uint8,uint8))", "[1,[2,3]]").unwrap();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_e2e_static_array_of_tuples() {
        // (uint8,uint8)[2] with [[1,2],[3,4]]
        let result = parse_and_encode_abi("(uint8,uint8)[2]", "[[1,2],[3,4]]").unwrap();
        assert_eq!(result, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_e2e_all_uint_sizes_boundary() {
        // Test smallest and largest values at various sizes
        assert_eq!(parse_and_encode_abi("uint8", "0").unwrap(), vec![0]);
        assert_eq!(parse_and_encode_abi("uint8", "255").unwrap(), vec![255]);
        assert_eq!(parse_and_encode_abi("uint16", "0").unwrap(), vec![0, 0]);
        assert_eq!(
            parse_and_encode_abi("uint16", "65535").unwrap(),
            vec![255, 255]
        );
    }

    #[test]
    fn test_e2e_error_invalid_type() {
        assert!(parse_and_encode_abi("invalid", "42").is_err());
    }

    #[test]
    fn test_e2e_error_json_mismatch() {
        assert!(parse_and_encode_abi("uint64", "true").is_err());
        assert!(parse_and_encode_abi("bool", "42").is_err());
        assert!(parse_and_encode_abi("string", "42").is_err());
    }

    // --- is_dynamic additional tests ---

    #[test]
    fn test_is_dynamic_nested_cases() {
        // Static array of dynamic type is dynamic
        assert!(AbiType::ArrayStatic(
            Box::new(AbiType::ArrayDynamic(Box::new(AbiType::Uint(8)))),
            5
        )
        .is_dynamic());
        // Tuple with nested dynamic child
        assert!(AbiType::Tuple(vec![
            AbiType::Uint(64),
            AbiType::Tuple(vec![AbiType::Bool, AbiType::String]),
        ])
        .is_dynamic());
        // Ufixed is static
        assert!(!AbiType::Ufixed(64, 10).is_dynamic());
    }

    // --- byte_len additional tests ---

    #[test]
    fn test_byte_len_bool_packing_in_tuple() {
        // (bool,bool,bool,bool,bool,bool,bool,bool) = 1 byte (8 bools packed)
        let ty = AbiType::Tuple(vec![AbiType::Bool; 8]);
        assert_eq!(ty.byte_len(), Some(1));

        // (bool,bool,bool,bool,bool,bool,bool,bool,bool) = 2 bytes (9 bools)
        let ty = AbiType::Tuple(vec![AbiType::Bool; 9]);
        assert_eq!(ty.byte_len(), Some(2));

        // (uint8, bool, bool, bool, uint8) = 1 + 1 (3 bools packed) + 1 = 3
        let ty = AbiType::Tuple(vec![
            AbiType::Uint(8),
            AbiType::Bool,
            AbiType::Bool,
            AbiType::Bool,
            AbiType::Uint(8),
        ]);
        assert_eq!(ty.byte_len(), Some(3));
    }

    #[test]
    fn test_byte_len_static_array_zero_length() {
        assert_eq!(
            AbiType::ArrayStatic(Box::new(AbiType::Uint(64)), 0).byte_len(),
            Some(0)
        );
    }

    // --- infer_type round-trip ---

    #[test]
    fn test_infer_type_from_value() {
        let val = AbiValue::Uint(BigUint::from(42u64), 64);
        assert_eq!(infer_type(&val), AbiType::Uint(64));

        let val = AbiValue::Ufixed(BigUint::from(1u64), 128, 10);
        assert_eq!(infer_type(&val), AbiType::Ufixed(128, 10));

        let val = AbiValue::Bool(true);
        assert_eq!(infer_type(&val), AbiType::Bool);

        let val = AbiValue::Byte(42);
        assert_eq!(infer_type(&val), AbiType::Byte);

        let val = AbiValue::Address([0u8; 32]);
        assert_eq!(infer_type(&val), AbiType::Address);

        let val = AbiValue::String(vec![1, 2, 3]);
        assert_eq!(infer_type(&val), AbiType::String);

        let val = AbiValue::ArrayStatic(
            vec![AbiValue::Uint(BigUint::from(1u64), 8)],
            AbiType::Uint(8),
        );
        assert_eq!(
            infer_type(&val),
            AbiType::ArrayStatic(Box::new(AbiType::Uint(8)), 1)
        );

        let val = AbiValue::ArrayDynamic(vec![], AbiType::Bool);
        assert_eq!(
            infer_type(&val),
            AbiType::ArrayDynamic(Box::new(AbiType::Bool))
        );

        let val = AbiValue::Tuple(vec![
            AbiValue::Uint(BigUint::from(0u64), 64),
            AbiValue::Bool(false),
        ]);
        assert_eq!(
            infer_type(&val),
            AbiType::Tuple(vec![AbiType::Uint(64), AbiType::Bool])
        );
    }

    // --- parse_tuple_content edge cases ---

    #[test]
    fn test_parse_tuple_content_deeply_nested() {
        assert_eq!(
            parse_tuple_content("uint64,(bool,(address,string))").unwrap(),
            vec!["uint64", "(bool,(address,string))"]
        );
    }

    #[test]
    fn test_parse_tuple_content_multiple_nested() {
        assert_eq!(
            parse_tuple_content("(uint8,uint16),(bool,address)").unwrap(),
            vec!["(uint8,uint16)", "(bool,address)"]
        );
    }

    #[test]
    fn test_parse_tuple_content_unpaired_parens() {
        assert!(parse_tuple_content("(uint64").is_err());
        assert!(parse_tuple_content("uint64)").is_err());
    }

    // --- Fix #1: ufixed decimal JSON unmarshaling ---

    #[test]
    fn test_unmarshal_ufixed64x1_decimal() {
        // ufixed64x1 with "1.5" → 1*10 + 5 = 15
        let result = parse_and_encode_abi("ufixed64x1", "\"1.5\"").unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0, 0, 0, 15]);
    }

    #[test]
    fn test_unmarshal_ufixed128x3_decimal() {
        // ufixed128x3 with "1.234" → 1*1000 + 234 = 1234
        let result = parse_and_encode_abi("ufixed128x3", "\"1.234\"").unwrap();
        assert_eq!(result.len(), 16);
        // 1234 in big-endian 16 bytes
        assert_eq!(result[14], 0x04);
        assert_eq!(result[15], 0xD2);
        assert!(result[..14].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_unmarshal_ufixed_too_many_decimals() {
        // ufixed64x1 with "1.55" should fail — 2 fractional digits > precision 1
        let ty = type_of("ufixed64x1").unwrap();
        assert!(unmarshal_from_json(&ty, "\"1.55\"").is_err());
    }

    #[test]
    fn test_unmarshal_ufixed_integer_scales() {
        // ufixed64x2 with "3" → 3 * 100 = 300
        let result = parse_and_encode_abi("ufixed64x2", "3").unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0, 0, 1, 44]); // 300 = 0x012C
    }

    // --- Fix #2: byte array base64 decoding ---

    #[test]
    fn test_unmarshal_static_byte_array_base64() {
        // base64("AQID") = [1, 2, 3]
        let result = parse_and_encode_abi("byte[3]", "\"AQID\"").unwrap();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_unmarshal_dynamic_byte_array_base64() {
        // base64("AQID") = [1, 2, 3]
        let result = parse_and_encode_abi("byte[]", "\"AQID\"").unwrap();
        // 2-byte length (3) + elements
        assert_eq!(result, vec![0, 3, 1, 2, 3]);
    }

    #[test]
    fn test_unmarshal_static_byte_array_base64_wrong_length() {
        // base64("AQID") = [1, 2, 3] but type expects 2 elements
        let ty = type_of("byte[2]").unwrap();
        assert!(unmarshal_from_json(&ty, "\"AQID\"").is_err());
    }

    #[test]
    fn test_unmarshal_static_byte_array_json_still_works() {
        // JSON array input should still work for byte arrays
        let result = parse_and_encode_abi("byte[3]", "[1,2,3]").unwrap();
        assert_eq!(result, vec![1, 2, 3]);
    }

    // --- Fix #6: find_bool_lr edge case tests ---

    #[test]
    fn test_encode_tuple_single_trailing_bool() {
        // (uint8,bool) — single trailing bool
        let result = parse_and_encode_abi("(uint8,bool)", "[1,true]").unwrap();
        assert_eq!(result, vec![1, 0x80]);
    }

    #[test]
    fn test_encode_tuple_bools_separated_by_non_bool() {
        // (bool,uint8,bool,bool) — bools separated by non-bool
        let result = parse_and_encode_abi("(bool,uint8,bool,bool)", "[true,1,false,true]").unwrap();
        // First bool: 0x80, uint8: 1, then two consecutive bools packed: false=0, true=1 → 0b01000000 = 0x40
        assert_eq!(result, vec![0x80, 1, 0x40]);
    }

    // --- Recursion depth limit tests ---

    #[test]
    fn test_type_of_rejects_deep_nested_tuples() {
        // 65 levels of nested tuples exceeds MAX_ABI_DEPTH (64)
        let deep = "(".repeat(65) + "uint8" + &")".repeat(65);
        let result = type_of(&deep);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("nesting depth exceeds maximum"),
            "expected depth limit error"
        );
    }

    #[test]
    fn test_type_of_rejects_deep_nested_arrays() {
        // 65 levels of dynamic array nesting exceeds MAX_ABI_DEPTH (64)
        let deep = "uint8".to_string() + &"[]".repeat(65);
        let result = type_of(&deep);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("nesting depth exceeds maximum"),
            "expected depth limit error"
        );
    }

    #[test]
    fn test_type_of_allows_moderate_nesting() {
        // 30 levels of nesting should be fine
        let moderate = "(".repeat(30) + "uint8" + &")".repeat(30);
        assert!(type_of(&moderate).is_ok());
    }

    // -----------------------------------------------------------------------
    // Decode round-trips (inverse of encode)
    // -----------------------------------------------------------------------

    fn roundtrip(type_str: &str, value_json: &str) {
        let abi_type = type_of(type_str).unwrap();
        let value = unmarshal_from_json(&abi_type, value_json).unwrap();
        let bytes = encode(&value).unwrap();
        let decoded = decode(&abi_type, &bytes).unwrap();
        let bytes2 = encode(&decoded).unwrap();
        assert_eq!(bytes, bytes2, "roundtrip byte mismatch for {type_str}");
    }

    #[test]
    fn test_decode_uint_roundtrip() {
        roundtrip("uint64", "42");
        roundtrip("uint8", "255");
        roundtrip("uint256", "123456789012345678901234567890");
    }

    #[test]
    fn test_decode_bool() {
        let d = decode(&AbiType::Bool, &[0x80]).unwrap();
        assert_eq!(d, AbiValue::Bool(true));
        let d = decode(&AbiType::Bool, &[0x00]).unwrap();
        assert_eq!(d, AbiValue::Bool(false));
    }

    #[test]
    fn test_decode_string_roundtrip() {
        roundtrip("string", "\"hello world\"");
        roundtrip("string", "\"\"");
    }

    #[test]
    fn test_decode_address_roundtrip() {
        roundtrip(
            "address",
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\"",
        );
    }

    #[test]
    fn test_decode_static_array_roundtrip() {
        roundtrip("uint8[3]", "[1,2,3]");
        roundtrip(
            "bool[9]",
            "[true,false,true,true,false,false,true,false,true]",
        );
    }

    #[test]
    fn test_decode_dynamic_array_roundtrip() {
        roundtrip("uint64[]", "[1,2,3,4,5]");
        roundtrip("string[]", "[\"a\",\"bb\",\"ccc\"]");
    }

    #[test]
    fn test_decode_tuple_roundtrip() {
        roundtrip("(uint8,string)", "[1,\"ab\"]");
        roundtrip("(bool,bool,bool)", "[true,false,true]");
        roundtrip(
            "(uint32,(address,byte,bool[10],ufixed256x10[]),byte[])",
            "[7,[\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ\",9,[true,false,true,false,true,false,true,false,true,false],[\"1.5\"]],\"AQID\"]",
        );
    }

    #[test]
    fn test_decode_referencetest_vector() {
        // Cross-checked against go-algorand's own e2e ABI fixture
        // (`../go-algorand/test/scripts/e2e_subs/e2e-app-abi-method.sh`):
        // `referenceTest(...)uint8[9]` returns `[2,0,2,0,2,1,0,1,0]`, and the
        // TEAL implementation (`app-abi-method-example.teal`) builds that
        // uint8[9] as nine single `setbyte`+`concat` calls with no length
        // prefix — i.e. a plain 9-byte concatenation, confirming uint8[9]
        // static-array encoding has no head/tail indirection.
        let abi_type = type_of("uint8[9]").unwrap();
        let raw: [u8; 9] = [2, 0, 2, 0, 2, 1, 0, 1, 0];
        let decoded = decode(&abi_type, &raw).unwrap();
        let AbiValue::ArrayStatic(values, _) = &decoded else {
            panic!("expected ArrayStatic");
        };
        let bytes: Vec<u8> = values
            .iter()
            .map(|v| match v {
                // The signature uses `uint8[9]`, not `byte[9]`, so elements
                // decode as `AbiValue::Uint(_, 8)`, not `AbiValue::Byte`.
                AbiValue::Uint(n, 8) => n.to_bytes_be().last().copied().unwrap_or(0),
                _ => panic!("expected Uint(_, 8)"),
            })
            .collect();
        assert_eq!(bytes, raw);
        assert_eq!(value_to_json_string(&decoded), "[2,0,2,0,2,1,0,1,0]");
    }

    #[test]
    fn test_decode_length_mismatch_errors() {
        assert!(decode(&AbiType::Uint(64), &[0u8; 4]).is_err());
        assert!(decode(&AbiType::Bool, &[0u8; 2]).is_err());
        assert!(decode(&AbiType::Address, &[0u8; 10]).is_err());
    }

    // -----------------------------------------------------------------------
    // JSON display
    // -----------------------------------------------------------------------

    #[test]
    fn test_value_to_json_string_uint() {
        assert_eq!(
            value_to_json_string(&AbiValue::Uint(BigUint::from(2468u32), 64)),
            "2468"
        );
    }

    #[test]
    fn test_value_to_json_string_bool() {
        assert_eq!(value_to_json_string(&AbiValue::Bool(true)), "true");
        assert_eq!(value_to_json_string(&AbiValue::Bool(false)), "false");
    }

    #[test]
    fn test_value_to_json_string_string() {
        // Matches the go-algorand e2e fixture's printed output for
        // `optIn(string)string`: `"hello Algorand Fan"`.
        assert_eq!(
            value_to_json_string(&AbiValue::String(b"hello Algorand Fan".to_vec())),
            "\"hello Algorand Fan\""
        );
    }

    #[test]
    fn test_value_to_json_string_big_uint() {
        // A uint256 value wider than a JSON-safe integer must not silently
        // lose precision.
        let big = BigUint::from(10u32).pow(30);
        let json = value_to_json_string(&AbiValue::Uint(big.clone(), 256));
        assert_eq!(json, big.to_string());
    }

    // -----------------------------------------------------------------------
    // Method selector
    // -----------------------------------------------------------------------

    #[test]
    fn test_method_selector_return_prefix_known_vector() {
        // The ARC-4 "abi return value" log prefix is the well-known
        // constant 0x151f7c75 = SHA512/256("return")[:4], used throughout
        // the Algorand ABI ecosystem (algosdk's `ABI_RETURN_HASH`, etc.)
        // and directly visible in go-algorand's own generated ABI-method
        // TEAL fixture (`../go-algorand/test/scripts/e2e_subs/tealprogs/
        // app-abi-method-example.teal`: `byte 0x151f7c75`). This is an
        // externally-known vector, not one derived from this crate's own
        // code, so it is a genuine cross-check of `method_selector`'s
        // SHA512/256-then-truncate algorithm.
        assert_eq!(method_selector("return"), [0x15, 0x1f, 0x7c, 0x75]);
    }

    #[test]
    fn test_method_selector_matches_independent_sha512_256() {
        // Recompute the selector independently (calling the `sha2` crate
        // directly rather than `method_selector`) for a handful of
        // signatures pulled from go-algorand's own ABI e2e fixture
        // (`e2e-app-abi-method.sh`), the same pattern used by
        // `resource_resolution::app_address_matches_known_vector` in
        // `goal-rust`.
        for sig in [
            "create(uint64)uint64",
            "optIn(string)string",
            "empty()void",
            "add(uint64,uint64)uint64",
            "payment(pay,uint64)bool",
            "referenceTest(account,application,account,asset,account,asset,asset,application,application)uint8[9]",
            "closeOut()string",
            "update()void",
            "delete()void",
        ] {
            let hash = Sha512_256::digest(sig.as_bytes());
            let mut expected = [0u8; 4];
            expected.copy_from_slice(&hash[..4]);
            assert_eq!(method_selector(sig), expected, "mismatch for {sig}");
        }
    }

    #[test]
    fn test_method_selector_differs_for_different_signatures() {
        // Selectors must be sensitive to the full signature (name + arg
        // types + return type), not just the method name.
        let a = method_selector("add(uint64,uint64)uint64");
        let b = method_selector("add(uint32,uint32)uint32");
        let c = method_selector("subtract(uint64,uint64)uint64");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    // -----------------------------------------------------------------------
    // Method-signature parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_method_signature_simple() {
        let m = parse_method_signature("add(uint64,uint64)uint64").unwrap();
        assert_eq!(m.name, "add");
        assert_eq!(
            m.args,
            vec![
                MethodArgType::Abi(AbiType::Uint(64)),
                MethodArgType::Abi(AbiType::Uint(64)),
            ]
        );
        assert_eq!(m.returns, Some(AbiType::Uint(64)));
        assert_eq!(m.signature(), "add(uint64,uint64)uint64");
    }

    #[test]
    fn test_parse_method_signature_void_no_args() {
        let m = parse_method_signature("empty()void").unwrap();
        assert_eq!(m.name, "empty");
        assert!(m.args.is_empty());
        assert_eq!(m.returns, None);
        assert_eq!(m.signature(), "empty()void");
    }

    #[test]
    fn test_parse_method_signature_reference_and_transaction_args() {
        // From go-algorand's e2e ABI fixture.
        let m = parse_method_signature(
            "referenceTest(account,application,account,asset,account,asset,asset,application,application)uint8[9]",
        )
        .unwrap();
        assert_eq!(m.name, "referenceTest");
        assert_eq!(m.args.len(), 9);
        assert_eq!(m.args[0], MethodArgType::Reference(ReferenceType::Account));
        assert_eq!(
            m.args[1],
            MethodArgType::Reference(ReferenceType::Application)
        );
        assert_eq!(m.args[3], MethodArgType::Reference(ReferenceType::Asset));
        assert_eq!(
            m.returns,
            Some(AbiType::ArrayStatic(Box::new(AbiType::Uint(8)), 9))
        );
        assert_eq!(m.app_arg_count(), 9);
        assert_eq!(m.transaction_arg_count(), 0);

        let m2 = parse_method_signature("payment(pay,uint64)bool").unwrap();
        assert_eq!(
            m2.args,
            vec![
                MethodArgType::Transaction(TransactionType::Pay),
                MethodArgType::Abi(AbiType::Uint(64)),
            ]
        );
        assert_eq!(m2.app_arg_count(), 1);
        assert_eq!(m2.transaction_arg_count(), 1);
    }

    #[test]
    fn test_parse_method_signature_tuple_args() {
        let m = parse_method_signature("f((uint64,bool),string)void").unwrap();
        assert_eq!(m.name, "f");
        assert_eq!(
            m.args,
            vec![
                MethodArgType::Abi(AbiType::Tuple(vec![AbiType::Uint(64), AbiType::Bool])),
                MethodArgType::Abi(AbiType::String),
            ]
        );
    }

    #[test]
    fn test_parse_method_signature_invalid() {
        assert!(parse_method_signature("noparens").is_err());
        assert!(parse_method_signature("f(uint64").is_err());
        assert!(parse_method_signature("(uint64)void").is_err());
        assert!(parse_method_signature("f(uint64)").is_err());
    }

    #[test]
    fn test_parse_method_arg_type_transaction_variants() {
        assert_eq!(
            parse_method_arg_type("txn").unwrap(),
            MethodArgType::Transaction(TransactionType::Any)
        );
        assert_eq!(
            parse_method_arg_type("keyreg").unwrap(),
            MethodArgType::Transaction(TransactionType::KeyRegistration)
        );
        assert_eq!(
            parse_method_arg_type("acfg").unwrap(),
            MethodArgType::Transaction(TransactionType::AssetConfig)
        );
        assert_eq!(
            parse_method_arg_type("axfer").unwrap(),
            MethodArgType::Transaction(TransactionType::AssetTransfer)
        );
        assert_eq!(
            parse_method_arg_type("afrz").unwrap(),
            MethodArgType::Transaction(TransactionType::AssetFreeze)
        );
        assert_eq!(
            parse_method_arg_type("appl").unwrap(),
            MethodArgType::Transaction(TransactionType::ApplicationCall)
        );
    }

    #[test]
    fn test_method_arg_type_display_roundtrip() {
        for (s, expected) in [
            ("account", MethodArgType::Reference(ReferenceType::Account)),
            ("asset", MethodArgType::Reference(ReferenceType::Asset)),
            (
                "application",
                MethodArgType::Reference(ReferenceType::Application),
            ),
            ("txn", MethodArgType::Transaction(TransactionType::Any)),
            ("pay", MethodArgType::Transaction(TransactionType::Pay)),
            ("uint64", MethodArgType::Abi(AbiType::Uint(64))),
        ] {
            let parsed = parse_method_arg_type(s).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }
    }

    // -----------------------------------------------------------------------
    // Contract / Interface JSON parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_contract_json() {
        // Shape mirrors ARC-4's Application.json / Contract JSON schema.
        let json = r#"{
            "name": "ExampleContract",
            "desc": "An example",
            "networks": {},
            "methods": [
                {
                    "name": "add",
                    "desc": "adds two numbers",
                    "args": [
                        {"type": "uint64", "name": "a", "desc": "first"},
                        {"type": "uint64", "name": "b", "desc": "second"}
                    ],
                    "returns": {"type": "uint64", "desc": "sum"}
                },
                {
                    "name": "empty",
                    "args": [],
                    "returns": {"type": "void", "desc": ""}
                }
            ]
        }"#;
        let contract: Contract = serde_json::from_str(json).unwrap();
        assert_eq!(contract.name, "ExampleContract");
        assert_eq!(contract.methods.len(), 2);

        let add = contract.find_method("add").unwrap();
        let method = add.to_method().unwrap();
        assert_eq!(method.signature(), "add(uint64,uint64)uint64");
        assert_eq!(
            method.selector(),
            method_selector("add(uint64,uint64)uint64")
        );

        let empty = contract.find_method("empty").unwrap();
        let method = empty.to_method().unwrap();
        assert_eq!(method.signature(), "empty()void");

        assert!(contract.find_method("missing").is_err());
    }

    #[test]
    fn test_parse_interface_json() {
        let json = r#"{
            "name": "ExampleInterface",
            "methods": [
                {
                    "name": "f",
                    "args": [{"type": "string", "name": "s", "desc": ""}],
                    "returns": {"type": "string", "desc": ""}
                }
            ]
        }"#;
        let iface: Interface = serde_json::from_str(json).unwrap();
        assert_eq!(iface.name, "ExampleInterface");
        let m = iface.find_method("f").unwrap().to_method().unwrap();
        assert_eq!(m.signature(), "f(string)string");
    }

    #[test]
    fn test_contract_find_method_ambiguous() {
        let json = r#"{
            "name": "Overloaded",
            "methods": [
                {"name": "f", "args": [{"type":"uint64","name":"a","desc":""}], "returns": {"type":"void","desc":""}},
                {"name": "f", "args": [{"type":"string","name":"a","desc":""}], "returns": {"type":"void","desc":""}}
            ]
        }"#;
        let contract: Contract = serde_json::from_str(json).unwrap();
        assert!(contract.find_method("f").is_err());
    }

    // -----------------------------------------------------------------------
    // encode_method_args — port of go-algorand's
    // `TestParseMethodArgJSONtoByteSlice` (`cmd/goal/application_test.go`).
    // -----------------------------------------------------------------------

    fn types_of(strs: &[&str]) -> Vec<AbiType> {
        strs.iter().map(|s| type_of(s).unwrap()).collect()
    }

    #[test]
    fn test_encode_method_args_empty() {
        let out = encode_method_args(&[], &[]).unwrap();
        assert_eq!(out, Vec::<Vec<u8>>::new());
    }

    #[test]
    fn test_encode_method_args_single_uint8() {
        let types = types_of(&["uint8"]);
        let out = encode_method_args(&types, &["100"]).unwrap();
        assert_eq!(out, vec![vec![100u8]]);
    }

    #[test]
    fn test_encode_method_args_uint8_uint16() {
        let types = types_of(&["uint8", "uint16"]);
        let out = encode_method_args(&types, &["100", "65535"]).unwrap();
        assert_eq!(out, vec![vec![100u8], vec![255u8, 255u8]]);
    }

    #[test]
    fn test_encode_method_args_15_strings_no_packing() {
        // Exactly at the 15-argument ceiling: still one appArg per value.
        let types = types_of(&["string"; 15]);
        let letters = [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
        ];
        let json_args: Vec<std::string::String> =
            letters.iter().map(|l| format!("\"{l}\"")).collect();
        let json_arg_refs: Vec<&str> = json_args.iter().map(std::string::String::as_str).collect();
        let out = encode_method_args(&types, &json_arg_refs).unwrap();
        assert_eq!(out.len(), 15);
        for (i, l) in letters.iter().enumerate() {
            let mut expected = vec![0u8, 1u8];
            expected.push(l.as_bytes()[0]);
            assert_eq!(out[i], expected, "mismatch at index {i}");
        }
    }

    #[test]
    fn test_encode_method_args_16_strings_bundles_tail_into_tuple() {
        // 16 args exceeds the 15-slot ceiling: the first 14 stay individual
        // ("a".."n"), and the 15th output entry is a 2-element ARC-4 tuple
        // bundling the remaining two values ("o", "p") — go-algorand's exact
        // fixture bytes from `TestParseMethodArgJSONtoByteSlice`.
        let types = types_of(&["string"; 16]);
        let letters = [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p",
        ];
        let json_args: Vec<std::string::String> =
            letters.iter().map(|l| format!("\"{l}\"")).collect();
        let json_arg_refs: Vec<&str> = json_args.iter().map(std::string::String::as_str).collect();
        let out = encode_method_args(&types, &json_arg_refs).unwrap();
        assert_eq!(out.len(), 15);
        for (i, l) in letters.iter().take(14).enumerate() {
            let mut expected = vec![0u8, 1u8];
            expected.push(l.as_bytes()[0]);
            assert_eq!(out[i], expected, "mismatch at index {i}");
        }
        // Tuple of ("o","p"): head = [0,4] [0,7] (2 dynamic-string offsets),
        // tail = string("o") ++ string("p").
        assert_eq!(out[14], vec![0u8, 4, 0, 7, 0, 1, b'o', 0, 1, b'p'],);
    }

    #[test]
    fn test_encode_method_args_mismatched_lengths_errors() {
        let types = types_of(&["uint64"]);
        assert!(encode_method_args(&types, &[]).is_err());
        assert!(encode_method_args(&[], &["1"]).is_err());
    }
}
