//! ABI type system, recursive type parser, JSON unmarshaling, and binary encoding
//! matching go-algorand's `avm-abi/abi` package.
//!
//! Parses ABI type strings like `"uint64"`, `"bool"`, `"(uint64,address)"`,
//! `"uint64[3]"`, `"uint64[]"`, and `"(uint64,(bool,address))"` into a
//! structured [`AbiType`] enum. Supports encoding values to ABI binary format
//! and parsing JSON values into [`AbiValue`] for encoding.
//!
//! Reference: `github.com/algorand/avm-abi/abi/type.go`, `encode.go`, `json.go`

use std::fmt;

use algo_types::Address;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use num_bigint::BigUint;

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
}
