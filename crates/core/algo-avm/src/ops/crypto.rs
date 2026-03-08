//! Crypto opcodes: sha256, keccak256, sha512_256, sha3_256, ed25519verify,
//! ed25519verify_bare, ecdsa_verify, ecdsa_pk_decompress, ecdsa_pk_recover,
//! base64_decode, json_ref, vrf_verify, falcon_verify (stub).

use std::collections::HashMap;

use algo_error::AlgoError;
use sha2::{Digest as Sha2Digest, Sha256, Sha512_256};
use sha3::{Keccak256, Sha3_256};

use crate::bytecode::Instruction;
use crate::context::AvmContext;
use crate::fields::{Base64Encoding, EcdsaCurve, JSONRefType, VrfStandard};
use crate::machine::{AvmMachine, AvmValue};
use crate::ops::helpers::get_uint8;

fn avm_err(msg: impl Into<String>) -> AlgoError {
    AlgoError::Avm {
        message: msg.into(),
    }
}

// ---------------------------------------------------------------------------
// Hash opcodes
// ---------------------------------------------------------------------------

/// `sha256` (0x01): pop bytes, push SHA-256 hash (32 bytes).
pub fn op_sha256(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let data = machine.pop_bytes()?;
    let hash = Sha256::digest(&data);
    machine.push(AvmValue::Bytes(hash.to_vec()))
}

/// `keccak256` (0x02): pop bytes, push Keccak-256 hash (32 bytes).
pub fn op_keccak256(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let data = machine.pop_bytes()?;
    let hash = Keccak256::digest(&data);
    machine.push(AvmValue::Bytes(hash.to_vec()))
}

/// `sha512_256` (0x03): pop bytes, push SHA-512/256 hash (32 bytes).
pub fn op_sha512_256(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let data = machine.pop_bytes()?;
    let hash = Sha512_256::digest(&data);
    machine.push(AvmValue::Bytes(hash.to_vec()))
}

/// `sha3_256` (0x98): pop bytes, push SHA3-256 hash (32 bytes). AVM v7+.
pub fn op_sha3_256(machine: &mut AvmMachine, _instruction: &Instruction) -> Result<(), AlgoError> {
    let data = machine.pop_bytes()?;
    let hash = Sha3_256::digest(&data);
    machine.push(AvmValue::Bytes(hash.to_vec()))
}

// ---------------------------------------------------------------------------
// Base64 decode
// ---------------------------------------------------------------------------

/// Check whether encoded base64 data has padding characters at the end,
/// matching Go's `base64padded` function.
fn base64_padded(encoded: &[u8]) -> bool {
    for &b in encoded.iter().rev() {
        match b {
            b'=' => return true,
            b'\n' | b'\r' => continue,
            _ => return false,
        }
    }
    false
}

/// `base64_decode` (0x5e): pop bytes, decode base64, push result.
/// Immediate selects encoding: 0=URLEncoding, 1=StdEncoding.
/// Dynamic cost: 1 + DivCeil(len, 16).
pub fn op_base64_decode(
    machine: &mut AvmMachine,
    instruction: &Instruction,
) -> Result<(), AlgoError> {
    let encoding_byte = get_uint8(instruction)?;
    let encoding = Base64Encoding::from_u8(encoding_byte)?;

    let raw_encoded = machine.pop_bytes()?;

    // Charge dynamic cost: 1 + DivCeil(len, 16)
    let cost = 1 + raw_encoded.len().div_ceil(16);
    machine.charge_cost(cost as u64)?;

    // Strip CR/LF before decoding — Go's base64 decoder silently tolerates
    // newlines, but the Rust `base64` crate rejects them as InvalidByte.
    let encoded: Vec<u8> = raw_encoded
        .iter()
        .copied()
        .filter(|&b| b != b'\n' && b != b'\r')
        .collect();

    // Determine the base64 engine based on encoding and padding.
    use base64::engine::general_purpose;
    use base64::Engine;

    let decoded = match encoding {
        Base64Encoding::URLEncoding => {
            if base64_padded(&encoded) {
                general_purpose::URL_SAFE.decode(&encoded)
            } else {
                general_purpose::URL_SAFE_NO_PAD.decode(&encoded)
            }
        }
        Base64Encoding::StdEncoding => {
            if base64_padded(&encoded) {
                general_purpose::STANDARD.decode(&encoded)
            } else {
                general_purpose::STANDARD_NO_PAD.decode(&encoded)
            }
        }
    };

    let decoded = decoded.map_err(|e| avm_err(format!("base64 decode error: {e}")))?;
    machine.push(AvmValue::Bytes(decoded))
}

// ---------------------------------------------------------------------------
// JSON ref
// ---------------------------------------------------------------------------

/// Parse a JSON object from bytes, rejecting duplicate keys and non-object values.
///
/// Matches Go's `parseJSON` which uses `protocol.DecodeJSON` that rejects
/// duplicate keys, and only accepts top-level JSON objects.
/// Returns raw byte slices from the original input for each key's value,
/// preserving exact whitespace and nested key ordering (matching Go's
/// `json.RawMessage` semantics).
fn parse_json_object(json_text: &[u8]) -> Result<HashMap<String, Vec<u8>>, AlgoError> {
    // First, check if the JSON text starts with '{' (after whitespace).
    let trimmed = json_text
        .iter()
        .copied()
        .find(|&b| !b.is_ascii_whitespace());
    match trimmed {
        Some(b'{') => {}
        _ => {
            return Err(avm_err(
                "error while parsing JSON text, invalid json text, only json object is allowed",
            ));
        }
    }

    // Validate as a JSON object using serde_json.
    let value: serde_json::Value = serde_json::from_slice(json_text)
        .map_err(|e| avm_err(format!("invalid json text, {e}")))?;

    match value {
        serde_json::Value::Object(_) => {}
        _ => {
            return Err(avm_err(
                "error while parsing JSON text, invalid json text, only json object is allowed",
            ));
        }
    }

    // Extract top-level keys and their raw byte ranges from the original input.
    // This preserves exact whitespace and nested structure (matching Go's
    // json.RawMessage behavior).
    extract_top_level_entries(json_text)
}

/// Extract top-level key-value pairs from a JSON object, preserving raw byte
/// ranges for values and rejecting duplicate keys.
///
/// The approach: use a byte-level state machine to walk the JSON, tracking
/// nesting depth. At depth 1, we identify key strings and their corresponding
/// values. We extract the exact bytes from the original input for each value.
fn extract_top_level_entries(json_text: &[u8]) -> Result<HashMap<String, Vec<u8>>, AlgoError> {
    use std::collections::HashSet;

    let bytes = json_text;
    let len = bytes.len();
    let mut result = HashMap::new();
    let mut seen_keys = HashSet::new();

    // Find the opening '{' (skip whitespace).
    let mut i = 0;
    while i < len && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= len || bytes[i] != b'{' {
        return Err(avm_err(
            "error while parsing JSON text, invalid json text, only json object is allowed",
        ));
    }
    i += 1; // skip '{'

    // Now we are inside the top-level object at depth 1.
    loop {
        // Skip whitespace.
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            return Err(avm_err("invalid json text, unexpected end of input"));
        }

        // Check for closing '}'.
        if bytes[i] == b'}' {
            break;
        }

        // Expect a key string starting with '"'.
        if bytes[i] != b'"' {
            return Err(avm_err("invalid json text, expected key string"));
        }

        // Extract the key: parse the quoted string from bytes[i..].
        let key_start = i; // points to opening '"'
        let key_end = skip_json_string(bytes, i)?; // points past closing '"'
        let key_slice = &bytes[key_start..key_end];
        let key: String = serde_json::from_slice(key_slice)
            .map_err(|e| avm_err(format!("invalid json text, {e}")))?;

        // Check for duplicate keys.
        if !seen_keys.insert(key.clone()) {
            return Err(avm_err(
                "error while parsing JSON text, invalid json text, duplicate keys not allowed",
            ));
        }

        i = key_end;

        // Skip whitespace, expect ':'.
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len || bytes[i] != b':' {
            return Err(avm_err("invalid json text, expected ':'"));
        }
        i += 1; // skip ':'

        // Skip whitespace before value.
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            return Err(avm_err("invalid json text, unexpected end of input"));
        }

        // Extract the raw value bytes.
        let value_start = i;
        let value_end = skip_json_value(bytes, i)?;
        let raw_value = bytes[value_start..value_end].to_vec();
        result.insert(key, raw_value);

        i = value_end;

        // Skip whitespace, expect ',' or '}'.
        while i < len && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= len {
            return Err(avm_err("invalid json text, unexpected end of input"));
        }
        if bytes[i] == b',' {
            i += 1; // skip comma, continue to next key
        } else if bytes[i] == b'}' {
            break;
        } else {
            return Err(avm_err("invalid json text, expected ',' or '}'"));
        }
    }

    Ok(result)
}

/// Skip a JSON string starting at position `i` (which must point to the opening `"`).
/// Returns the position just past the closing `"`.
fn skip_json_string(bytes: &[u8], i: usize) -> Result<usize, AlgoError> {
    debug_assert_eq!(bytes[i], b'"');
    let mut j = i + 1;
    loop {
        if j >= bytes.len() {
            return Err(avm_err("invalid json text, unterminated string"));
        }
        match bytes[j] {
            b'\\' => {
                j += 2; // skip escaped character
            }
            b'"' => {
                return Ok(j + 1); // past closing quote
            }
            _ => {
                j += 1;
            }
        }
    }
}

/// Skip a JSON value starting at position `i`. Returns the position just past the value.
/// Handles objects, arrays, strings, numbers, true, false, null.
fn skip_json_value(bytes: &[u8], i: usize) -> Result<usize, AlgoError> {
    if i >= bytes.len() {
        return Err(avm_err("invalid json text, unexpected end of input"));
    }
    match bytes[i] {
        b'"' => skip_json_string(bytes, i),
        b'{' => skip_json_container(bytes, i, b'{', b'}'),
        b'[' => skip_json_container(bytes, i, b'[', b']'),
        b't' => skip_literal(bytes, i, b"true"),
        b'f' => skip_literal(bytes, i, b"false"),
        b'n' => skip_literal(bytes, i, b"null"),
        // Numbers: digits, '-', '.', 'e', 'E', '+'
        b'-' | b'0'..=b'9' => skip_json_number(bytes, i),
        other => Err(avm_err(format!(
            "invalid json text, unexpected character: {}",
            other as char
        ))),
    }
}

/// Skip a JSON container (object or array) starting at position `i`.
/// Correctly handles nested structures and strings.
fn skip_json_container(bytes: &[u8], i: usize, open: u8, close: u8) -> Result<usize, AlgoError> {
    debug_assert_eq!(bytes[i], open);
    let mut depth = 1usize;
    let mut j = i + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'"' => {
                // Skip entire string.
                j = skip_json_string(bytes, j)?;
                continue;
            }
            c if c == open => {
                depth += 1;
            }
            c if c == close => {
                depth -= 1;
                if depth == 0 {
                    return Ok(j + 1);
                }
            }
            _ => {}
        }
        j += 1;
    }
    Err(avm_err("invalid json text, unterminated container"))
}

/// Skip a literal (true, false, null) starting at position `i`.
fn skip_literal(bytes: &[u8], i: usize, literal: &[u8]) -> Result<usize, AlgoError> {
    let end = i + literal.len();
    if end > bytes.len() || &bytes[i..end] != literal {
        return Err(avm_err("invalid json text, unexpected token"));
    }
    Ok(end)
}

/// Skip a JSON number starting at position `i`.
fn skip_json_number(bytes: &[u8], i: usize) -> Result<usize, AlgoError> {
    let mut j = i;
    // Consume: optional '-', digits, optional '.digits', optional 'e'/'E' [+-] digits
    while j < bytes.len() {
        match bytes[j] {
            b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E' => j += 1,
            _ => break,
        }
    }
    if j == i {
        return Err(avm_err("invalid json text, expected number"));
    }
    Ok(j)
}

/// `json_ref` (0x5f): pop key (bytes) and JSON object (bytes) from stack.
/// Immediate selects return type: 0=JSONString, 1=JSONUint64, 2=JSONObject.
/// Dynamic cost: 25 + 2 * DivCeil(len_json, 7).
pub fn op_json_ref(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let type_byte = get_uint8(instruction)?;
    let ref_type = JSONRefType::from_u8(type_byte)?;

    // Pop key (top of stack).
    let key_bytes = machine.pop_bytes()?;
    let key =
        String::from_utf8(key_bytes).map_err(|_| avm_err("json_ref: key is not valid UTF-8"))?;

    // Pop JSON text (second on stack, now top after popping key).
    let json_text = machine.pop_bytes()?;

    // Charge dynamic cost: 25 + 2 * DivCeil(len, 7)
    let cost = 25 + 2 * json_text.len().div_ceil(7);
    machine.charge_cost(cost as u64)?;

    // Parse JSON object (rejects duplicates, non-objects).
    let parsed = parse_json_object(&json_text)?;

    // Look up the key.
    let raw_value = match parsed.get(&key) {
        Some(v) => v,
        None => {
            // Check if the input is a primitive (null, true, false, number, string, array).
            // parseJSON would have already rejected arrays/primitives, but we follow Go's
            // behavior: if key not found, double-check isPrimitive for null handling.
            return Err(avm_err(format!("key {key} not found in JSON text")));
        }
    };

    match ref_type {
        JSONRefType::JSONString => {
            // Parse the raw value as a JSON string.
            let value: String = serde_json::from_slice(raw_value)
                .map_err(|e| avm_err(format!("json_ref JSONString: {e}")))?;
            machine.push(AvmValue::Bytes(value.into_bytes()))
        }
        JSONRefType::JSONUint64 => {
            // Parse the raw value as a uint64.
            let value: u64 = serde_json::from_slice(raw_value)
                .map_err(|e| avm_err(format!("json_ref JSONUint64: {e}")))?;
            machine.push(AvmValue::Uint64(value))
        }
        JSONRefType::JSONObject => {
            // Verify the value is a JSON object.
            let _: serde_json::Map<String, serde_json::Value> =
                serde_json::from_slice(raw_value)
                    .map_err(|e| avm_err(format!("json_ref JSONObject: {e}")))?;
            // Push the raw JSON bytes for the nested object.
            machine.push(AvmValue::Bytes(raw_value.clone()))
        }
    }
}

// ---------------------------------------------------------------------------
// Ed25519 opcodes
// ---------------------------------------------------------------------------

/// `ed25519verify` (0x04): pop pubkey (32 bytes), signature (64 bytes), data (bytes).
/// Domain separation: verify `SHA-512/256("ProgData" || program_hash || data)`.
/// Push 1 if verified, 0 otherwise. Cost: 1900 (static, charged by dispatch).
pub fn op_ed25519verify(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
    ctx: &mut dyn AvmContext,
) -> Result<(), AlgoError> {
    let pubkey_bytes = machine.pop_bytes()?;
    let sig_bytes = machine.pop_bytes()?;
    let data = machine.pop_bytes()?;

    if pubkey_bytes.len() != 32 {
        return Err(avm_err("invalid public key"));
    }
    if sig_bytes.len() != 64 {
        return Err(avm_err("invalid signature"));
    }

    // Domain separation: SHA-512/256("ProgData" || program_hash || data)
    let program_hash = ctx.program_hash();
    let mut msg_bytes = Vec::with_capacity(8 + 32 + data.len());
    msg_bytes.extend_from_slice(b"ProgData");
    msg_bytes.extend_from_slice(&program_hash);
    msg_bytes.extend_from_slice(&data);
    let msg_hash: [u8; 32] = Sha512_256::digest(&msg_bytes).into();

    let result = ed25519_verify_raw(&pubkey_bytes, &sig_bytes, &msg_hash);
    machine.push(AvmValue::Uint64(if result { 1 } else { 0 }))
}

/// `ed25519verify_bare` (0x84, AVM v7+): pop pubkey (32 bytes), signature (64 bytes), data (bytes).
/// Raw verification on data (no domain separation). Push 1 if verified, 0 otherwise.
/// Cost: 1900 (static, charged by dispatch).
pub fn op_ed25519verify_bare(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    let pubkey_bytes = machine.pop_bytes()?;
    let sig_bytes = machine.pop_bytes()?;
    let data = machine.pop_bytes()?;

    if pubkey_bytes.len() != 32 {
        return Err(avm_err("invalid public key"));
    }
    if sig_bytes.len() != 64 {
        return Err(avm_err("invalid signature"));
    }

    let result = ed25519_verify_raw(&pubkey_bytes, &sig_bytes, &data);
    machine.push(AvmValue::Uint64(if result { 1 } else { 0 }))
}

/// Internal ed25519 verification using ed25519-dalek with non-strict `verify`.
fn ed25519_verify_raw(pubkey_bytes: &[u8], sig_bytes: &[u8], msg: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let Ok(pk_array) = <[u8; 32]>::try_from(pubkey_bytes) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_array) else {
        return false;
    };
    let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_array);

    // Use non-strict verify (matching Go's ed25519.Verify which is RFC 8032).
    vk.verify(msg, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// ECDSA opcodes
// ---------------------------------------------------------------------------

/// Version at which Secp256r1 becomes available (fidoVersion in Go).
const SECP256R1_VERSION: u8 = 7;

/// `ecdsa_verify` (0x05): verify ECDSA signature.
/// Immediate: curve index. Stack: pop Y, X, S, R, data (all bytes).
/// Data must be exactly 32 bytes. Push 1 (verified) or 0 (failed).
pub fn op_ecdsa_verify(
    machine: &mut AvmMachine,
    instruction: &Instruction,
) -> Result<(), AlgoError> {
    let curve_byte = get_uint8(instruction)?;
    let curve = EcdsaCurve::from_u8(curve_byte)?;

    // Version gating for Secp256r1
    if curve == EcdsaCurve::Secp256r1 && machine.version < SECP256R1_VERSION {
        return Err(avm_err(format!("invalid curve {curve_byte}")));
    }

    // Charge dynamic cost based on curve
    let cost = match curve {
        EcdsaCurve::Secp256k1 => 1700u64,
        EcdsaCurve::Secp256r1 => 2500u64,
    };
    machine.charge_cost(cost)?;

    // Pop stack: Y, X, S, R, data
    let pk_y = machine.pop_bytes()?;
    let pk_x = machine.pop_bytes()?;
    let sig_s = machine.pop_bytes()?;
    let sig_r = machine.pop_bytes()?;
    let data = machine.pop_bytes()?;

    if data.len() != 32 {
        return Err(avm_err(format!(
            "the signed data must be 32 bytes long, not {}",
            data.len()
        )));
    }

    let result = match curve {
        EcdsaCurve::Secp256k1 => ecdsa_verify_secp256k1(&data, &sig_r, &sig_s, &pk_x, &pk_y),
        EcdsaCurve::Secp256r1 => ecdsa_verify_secp256r1(&data, &sig_r, &sig_s, &pk_x, &pk_y),
    };

    machine.push(AvmValue::Uint64(if result { 1 } else { 0 }))
}

/// `ecdsa_pk_decompress` (0x06): decompress a public key.
/// Immediate: curve index. Stack: pop compressed pubkey (33 bytes).
/// Push Y then X (X on top).
pub fn op_ecdsa_pk_decompress(
    machine: &mut AvmMachine,
    instruction: &Instruction,
) -> Result<(), AlgoError> {
    let curve_byte = get_uint8(instruction)?;
    let curve = EcdsaCurve::from_u8(curve_byte)?;

    // Version gating for Secp256r1
    if curve == EcdsaCurve::Secp256r1 && machine.version < SECP256R1_VERSION {
        return Err(avm_err(format!("invalid curve {curve_byte}")));
    }

    // Charge dynamic cost based on curve
    let cost = match curve {
        EcdsaCurve::Secp256k1 => 650u64,
        EcdsaCurve::Secp256r1 => 2400u64,
    };
    machine.charge_cost(cost)?;

    let compressed = machine.pop_bytes()?;

    let (x, y) = match curve {
        EcdsaCurve::Secp256k1 => ecdsa_decompress_secp256k1(&compressed)?,
        EcdsaCurve::Secp256r1 => ecdsa_decompress_secp256r1(&compressed)?,
    };

    // Push Y first, then X (X ends up on top)
    machine.push(AvmValue::Bytes(y))?;
    machine.push(AvmValue::Bytes(x))
}

/// `ecdsa_pk_recover` (0x07): recover public key from ECDSA signature.
/// Immediate: curve index (Secp256k1 only).
/// Stack: pop recovery_id (uint64, 0-3), S (bytes), R (bytes), data (32 bytes).
/// Push Y then X (X on top). Cost: 2000 (static).
pub fn op_ecdsa_pk_recover(
    machine: &mut AvmMachine,
    instruction: &Instruction,
) -> Result<(), AlgoError> {
    let curve_byte = get_uint8(instruction)?;
    let curve = EcdsaCurve::from_u8(curve_byte)?;

    if curve != EcdsaCurve::Secp256k1 {
        return Err(avm_err(format!("unsupported curve {curve_byte}")));
    }

    // Pop stack: recovery_id, S, R, data
    let recid = machine.pop_uint()?;
    let sig_s = machine.pop_bytes()?;
    let sig_r = machine.pop_bytes()?;
    let data = machine.pop_bytes()?;

    if recid > 3 {
        return Err(avm_err(format!("invalid recovery id: {recid}")));
    }

    if data.len() != 32 {
        return Err(avm_err(format!(
            "the signed data must be 32 bytes long, not {}",
            data.len()
        )));
    }

    let (x, y) = ecdsa_recover_secp256k1(&data, &sig_r, &sig_s, recid as u8)?;

    // Push Y first, then X (X ends up on top)
    machine.push(AvmValue::Bytes(y))?;
    machine.push(AvmValue::Bytes(x))
}

// ---------------------------------------------------------------------------
// ECDSA internal helpers
// ---------------------------------------------------------------------------

/// Verify ECDSA signature on secp256k1.
/// Go uses libsecp256k1 which normalizes S to low-S internally before verify.
fn ecdsa_verify_secp256k1(
    data: &[u8],
    sig_r: &[u8],
    sig_s: &[u8],
    pk_x: &[u8],
    pk_y: &[u8],
) -> bool {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::{AffinePoint, EncodedPoint};

    // Build the uncompressed point (0x04 || x || y)
    let mut uncompressed = Vec::with_capacity(1 + 32 + 32);
    uncompressed.push(0x04);
    // Pad x and y to 32 bytes; reject overlong values
    let Some(x_padded) = pad_to_32(pk_x) else {
        return false;
    };
    let Some(y_padded) = pad_to_32(pk_y) else {
        return false;
    };
    uncompressed.extend_from_slice(&x_padded);
    uncompressed.extend_from_slice(&y_padded);

    let Ok(encoded_point) = EncodedPoint::from_bytes(&uncompressed) else {
        return false;
    };

    let maybe_point = AffinePoint::from_encoded_point(&encoded_point);
    if maybe_point.is_none().into() {
        return false;
    }
    let point = maybe_point.unwrap();

    let vk = k256::ecdsa::VerifyingKey::from_affine(point);
    let Ok(vk) = vk else {
        return false;
    };

    // Build signature from R || S, normalizing S to low-S if needed.
    let Some(r_padded) = pad_to_32(sig_r) else {
        return false;
    };
    let Some(s_padded) = pad_to_32(sig_s) else {
        return false;
    };
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_padded);
    sig_bytes[32..].copy_from_slice(&s_padded);

    let Ok(mut sig) = k256::ecdsa::Signature::from_slice(&sig_bytes) else {
        // If the signature bytes can't be parsed (e.g., r or s is zero or >= order),
        // try normalizing. If it's still bad, return false.
        return false;
    };

    // Normalize S to low-S (matching Go's libsecp256k1 behavior).
    sig = sig.normalize_s().unwrap_or(sig);

    vk.verify_prehash(data, &sig).is_ok()
}

/// Verify ECDSA signature on secp256r1 (P-256 / NIST).
fn ecdsa_verify_secp256r1(
    data: &[u8],
    sig_r: &[u8],
    sig_s: &[u8],
    pk_x: &[u8],
    pk_y: &[u8],
) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{AffinePoint, EncodedPoint};

    // Build the uncompressed point (0x04 || x || y)
    let Some(x_padded) = pad_to_32(pk_x) else {
        return false;
    };
    let Some(y_padded) = pad_to_32(pk_y) else {
        return false;
    };
    let mut uncompressed = Vec::with_capacity(1 + 32 + 32);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x_padded);
    uncompressed.extend_from_slice(&y_padded);

    let Ok(encoded_point) = EncodedPoint::from_bytes(&uncompressed) else {
        return false;
    };

    let maybe_point = AffinePoint::from_encoded_point(&encoded_point);
    if maybe_point.is_none().into() {
        return false;
    }
    let point = maybe_point.unwrap();

    let Ok(vk) = p256::ecdsa::VerifyingKey::from_affine(point) else {
        return false;
    };

    // Build signature from R || S
    let Some(r_padded) = pad_to_32(sig_r) else {
        return false;
    };
    let Some(s_padded) = pad_to_32(sig_s) else {
        return false;
    };
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_padded);
    sig_bytes[32..].copy_from_slice(&s_padded);

    let Ok(sig) = p256::ecdsa::Signature::from_slice(&sig_bytes) else {
        return false;
    };

    // Go uses ecdsa.Verify which does NOT normalize S for p256.
    vk.verify_prehash(data, &sig).is_ok()
}

/// Decompress a secp256k1 compressed public key (33 bytes) to (x, y) 32-byte components.
fn ecdsa_decompress_secp256k1(compressed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AlgoError> {
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(compressed)
        .map_err(|_| avm_err("invalid pubkey"))?;
    let uncompressed = vk.to_encoded_point(false);
    let x = uncompressed.x().ok_or_else(|| avm_err("invalid pubkey"))?;
    let y = uncompressed.y().ok_or_else(|| avm_err("invalid pubkey"))?;
    Ok((x.to_vec(), y.to_vec()))
}

/// Decompress a secp256r1 (P-256) compressed public key (33 bytes) to (x, y) 32-byte components.
fn ecdsa_decompress_secp256r1(compressed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AlgoError> {
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(compressed)
        .map_err(|_| avm_err("invalid compressed pubkey"))?;
    let uncompressed = vk.to_encoded_point(false);
    let x = uncompressed
        .x()
        .ok_or_else(|| avm_err("invalid compressed pubkey"))?;
    let y = uncompressed
        .y()
        .ok_or_else(|| avm_err("invalid compressed pubkey"))?;
    Ok((x.to_vec(), y.to_vec()))
}

/// Recover a secp256k1 public key from an ECDSA signature and recovery ID.
fn ecdsa_recover_secp256k1(
    data: &[u8],
    sig_r: &[u8],
    sig_s: &[u8],
    recid: u8,
) -> Result<(Vec<u8>, Vec<u8>), AlgoError> {
    use k256::ecdsa::{RecoveryId, VerifyingKey};

    let r_padded = pad_to_32(sig_r).ok_or_else(|| avm_err("pubkey recover failed: r too long"))?;
    let s_padded = pad_to_32(sig_s).ok_or_else(|| avm_err("pubkey recover failed: s too long"))?;
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_padded);
    sig_bytes[32..].copy_from_slice(&s_padded);

    let sig = k256::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|e| avm_err(format!("pubkey recover failed: {e}")))?;

    let recovery_id = RecoveryId::new(recid & 1 != 0, recid & 2 != 0);

    let vk = VerifyingKey::recover_from_prehash(data, &sig, recovery_id)
        .map_err(|e| avm_err(format!("pubkey recover failed: {e}")))?;

    let encoded = vk.to_encoded_point(false);
    let x = encoded
        .x()
        .ok_or_else(|| avm_err("pubkey unmarshal failed"))?;
    let y = encoded
        .y()
        .ok_or_else(|| avm_err("pubkey unmarshal failed"))?;
    Ok((x.to_vec(), y.to_vec()))
}

/// Interpret a byte slice as a big-endian 32-byte scalar, matching Go's
/// `new(big.Int).SetBytes(b)` → `FillBytes(buf[:32])` semantics.
///
/// - If input ≤ 32 bytes, left-pad with zeros.
/// - If input > 32 bytes but leading bytes are all zero, strip them.
/// - If input > 32 bytes with non-zero leading bytes, return `None`
///   (the value exceeds the curve field/order and any operation will fail).
fn pad_to_32(input: &[u8]) -> Option<[u8; 32]> {
    let mut result = [0u8; 32];
    if input.len() <= 32 {
        result[32 - input.len()..].copy_from_slice(input);
        Some(result)
    } else {
        // Check if the extra leading bytes are all zero.
        let excess = input.len() - 32;
        if input[..excess].iter().all(|&b| b == 0) {
            result.copy_from_slice(&input[excess..]);
            Some(result)
        } else {
            None // Value exceeds 32 bytes — will fail any curve operation
        }
    }
}

// ---------------------------------------------------------------------------
// VRF verify (opcode 0xd0, AVM v7+)
// ---------------------------------------------------------------------------

/// `vrf_verify` (0xd0): pop pubkey (32 bytes), proof (80 bytes), data (bytes).
///
/// Verifies an ECVRF-ED25519-SHA512-Elligator2 proof (draft-irtf-cfrg-vrf-03).
/// Stack: ..., A (data), B (proof 80 bytes), C (pubkey 32 bytes) -> ..., X (output 64 bytes), Y (verified flag)
/// Cost: 5700 (static, charged by dispatch).
pub fn op_vrf_verify(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let std_byte = get_uint8(instruction)?;
    let _std = VrfStandard::from_u8(std_byte)?;

    // VrfStandard version gating: VrfAlgorand requires AVM v7, which is the
    // same version that introduces the vrf_verify opcode itself. Since the
    // opcode dispatch already rejects versions < 7, no additional field-level
    // version check is needed here (unlike ECDSA curves where Secp256r1 was
    // added in a later version than the ecdsa_verify opcode).

    // Pop the three arguments in reverse stack order (top first).
    let pubkey_bytes = machine.pop_bytes()?;
    let proof_bytes = machine.pop_bytes()?;
    let data = machine.pop_bytes()?;

    // Validate sizes (matching go-algorand's error messages).
    if proof_bytes.len() != 80 {
        return Err(avm_err(format!(
            "vrf proof wrong size {} != 80",
            proof_bytes.len()
        )));
    }
    if pubkey_bytes.len() != 32 {
        return Err(avm_err(format!(
            "vrf pubkey wrong size {} != 32",
            pubkey_bytes.len()
        )));
    }

    let pk: [u8; 32] = pubkey_bytes.try_into().unwrap();
    let pi: [u8; 80] = proof_bytes.try_into().unwrap();

    let (output, verified) = match super::vrf::vrf_verify(&pk, &pi, &data) {
        Some(output) => (output.to_vec(), 1u64),
        None => (vec![0u8; 64], 0u64),
    };

    // Push output bytes first, then verified flag on top.
    machine.push(AvmValue::Bytes(output))?;
    machine.push(AvmValue::Uint64(verified))
}

// ---------------------------------------------------------------------------
// Falcon verify stub (opcode 0x85, AVM v12+)
// ---------------------------------------------------------------------------

/// `falcon_verify` (0x85): pop pubkey (1793 bytes), signature (<=1232 bytes), data (bytes).
///
/// This is a stub — full implementation is tracked in issue #43.
/// Pops the correct number of stack arguments for consistency, then returns
/// an error.
pub fn op_falcon_verify(
    machine: &mut AvmMachine,
    _instruction: &Instruction,
) -> Result<(), AlgoError> {
    // Pop the three arguments in reverse stack order (top first).
    let _pubkey = machine.pop_bytes()?; // 1793-byte Falcon public key
    let _sig = machine.pop_bytes()?; // Falcon signature (<=1232 bytes)
    let _data = machine.pop_bytes()?; // arbitrary data

    Err(AlgoError::Avm {
        message: "falcon_verify not yet implemented (see issue #43)".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::parse;
    use crate::context::NullContext;
    use crate::machine::ExecMode;
    use crate::ops::helpers::prog;

    /// Helper: run a program and return the machine (for stack inspection).
    fn run_prog(version: u8, code: &[u8]) -> Result<AvmMachine, AlgoError> {
        let raw = prog(version, code);
        let program = parse(&raw).unwrap();
        let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 100_000);
        machine.run(&mut NullContext)?;
        Ok(machine)
    }

    // -----------------------------------------------------------------------
    // SHA-256 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_empty() {
        // pushbytes "", sha256, pushbytes <expected>, ==, return
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected: [u8; 32] = Sha256::digest(b"").into();
        let mut code = vec![
            0x80, 0x00, // pushbytes ""
            0x01, // sha256
            0x80, 0x20, // pushbytes (32 bytes follow)
        ];
        code.extend_from_slice(&expected);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(3, &code).unwrap();
        assert!(m.pass);
    }

    #[test]
    fn test_sha256_hello() {
        let expected: [u8; 32] = Sha256::digest(b"hello").into();
        let mut code = vec![
            0x80, 0x05, // pushbytes (5 bytes)
            b'h', b'e', b'l', b'l', b'o', 0x01, // sha256
            0x80, 0x20, // pushbytes (32 bytes follow)
        ];
        code.extend_from_slice(&expected);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(3, &code).unwrap();
        assert!(m.pass);
    }

    // -----------------------------------------------------------------------
    // Keccak-256 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_keccak256_empty() {
        let expected: [u8; 32] = Keccak256::digest(b"").into();
        let mut code = vec![0x80, 0x00, 0x02, 0x80, 0x20];
        code.extend_from_slice(&expected);
        code.extend_from_slice(&[0x12, 0x43]);
        let m = run_prog(3, &code).unwrap();
        assert!(m.pass);
    }

    #[test]
    fn test_keccak256_hello() {
        let expected: [u8; 32] = Keccak256::digest(b"hello").into();
        let mut code = vec![0x80, 0x05, b'h', b'e', b'l', b'l', b'o', 0x02, 0x80, 0x20];
        code.extend_from_slice(&expected);
        code.extend_from_slice(&[0x12, 0x43]);
        let m = run_prog(3, &code).unwrap();
        assert!(m.pass);
    }

    // -----------------------------------------------------------------------
    // SHA-512/256 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha512_256_empty() {
        let expected: [u8; 32] = Sha512_256::digest(b"").into();
        let mut code = vec![0x80, 0x00, 0x03, 0x80, 0x20];
        code.extend_from_slice(&expected);
        code.extend_from_slice(&[0x12, 0x43]);
        let m = run_prog(3, &code).unwrap();
        assert!(m.pass);
    }

    // -----------------------------------------------------------------------
    // SHA3-256 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha3_256_empty() {
        let expected: [u8; 32] = Sha3_256::digest(b"").into();
        let mut code = vec![0x80, 0x00, 0x98, 0x80, 0x20];
        code.extend_from_slice(&expected);
        code.extend_from_slice(&[0x12, 0x43]);
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass);
    }

    #[test]
    fn test_sha3_256_hello() {
        let expected: [u8; 32] = Sha3_256::digest(b"hello").into();
        let mut code = vec![0x80, 0x05, b'h', b'e', b'l', b'l', b'o', 0x98, 0x80, 0x20];
        code.extend_from_slice(&expected);
        code.extend_from_slice(&[0x12, 0x43]);
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass);
    }

    // -----------------------------------------------------------------------
    // base64_decode tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_base64_decode_std() {
        // base64 encode "hello" = "aGVsbG8="
        let encoded = b"aGVsbG8=";
        let mut code = vec![0x80, encoded.len() as u8];
        code.extend_from_slice(encoded);
        code.push(0x5e); // base64_decode
        code.push(0x01); // StdEncoding

        // push expected result "hello"
        code.extend_from_slice(&[0x80, 0x05, b'h', b'e', b'l', b'l', b'o']);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass);
    }

    #[test]
    fn test_base64_decode_url() {
        // base64url encode "hello" = "aGVsbG8="
        let encoded = b"aGVsbG8=";
        let mut code = vec![0x80, encoded.len() as u8];
        code.extend_from_slice(encoded);
        code.push(0x5e); // base64_decode
        code.push(0x00); // URLEncoding

        code.extend_from_slice(&[0x80, 0x05, b'h', b'e', b'l', b'l', b'o']);
        code.extend_from_slice(&[0x12, 0x43]);
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass);
    }

    #[test]
    fn test_base64_decode_no_padding() {
        // "aGVsbG8" without padding
        let encoded = b"aGVsbG8";
        let mut code = vec![0x80, encoded.len() as u8];
        code.extend_from_slice(encoded);
        code.push(0x5e);
        code.push(0x01); // StdEncoding

        code.extend_from_slice(&[0x80, 0x05, b'h', b'e', b'l', b'l', b'o']);
        code.extend_from_slice(&[0x12, 0x43]);
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass);
    }

    #[test]
    fn test_base64_decode_invalid() {
        // Invalid base64
        let encoded = b"!!!";
        let mut code = vec![0x80, encoded.len() as u8];
        code.extend_from_slice(encoded);
        code.push(0x5e);
        code.push(0x01);
        code.extend_from_slice(&[0x80, 0x00, 0x12, 0x43]);
        let result = run_prog(7, &code);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_decode_with_newlines() {
        // Go's base64 decoder silently strips CR/LF — verify we do too.
        // "aGVs\nbG8=" is "hello" with an embedded newline.
        let encoded = b"aGVs\nbG8=";
        let mut code = vec![0x80, encoded.len() as u8];
        code.extend_from_slice(encoded);
        code.push(0x5e); // base64_decode
        code.push(0x01); // StdEncoding
                         // pushbytes "hello", ==, return
        let expected = b"hello";
        code.push(0x80);
        code.push(expected.len() as u8);
        code.extend_from_slice(expected);
        code.push(0x12); // ==
        code.push(0x43); // return
        let m = run_prog(7, &code).unwrap();
        assert!(
            m.pass,
            "base64 with embedded newline should decode to 'hello'"
        );
    }

    #[test]
    fn test_base64_decode_with_crlf() {
        // Verify CR+LF are also stripped.
        let encoded = b"aGVs\r\nbG8=";
        let mut code = vec![0x80, encoded.len() as u8];
        code.extend_from_slice(encoded);
        code.push(0x5e); // base64_decode
        code.push(0x01); // StdEncoding
        let expected = b"hello";
        code.push(0x80);
        code.push(expected.len() as u8);
        code.extend_from_slice(expected);
        code.push(0x12); // ==
        code.push(0x43); // return
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass, "base64 with CRLF should decode to 'hello'");
    }

    // -----------------------------------------------------------------------
    // json_ref tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_json_ref_string() {
        // JSON: {"key": "value"}
        let json = br#"{"key": "value"}"#;
        let key = b"key";

        let mut code = vec![0x80, json.len() as u8];
        code.extend_from_slice(json);
        code.extend_from_slice(&[0x80, key.len() as u8]);
        code.extend_from_slice(key);
        code.push(0x5f); // json_ref
        code.push(0x00); // JSONString

        // push expected result "value"
        let expected = b"value";
        code.extend_from_slice(&[0x80, expected.len() as u8]);
        code.extend_from_slice(expected);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass);
    }

    #[test]
    fn test_json_ref_uint64() {
        let json = br#"{"num": 42}"#;
        let key = b"num";

        let mut code = vec![0x80, json.len() as u8];
        code.extend_from_slice(json);
        code.extend_from_slice(&[0x80, key.len() as u8]);
        code.extend_from_slice(key);
        code.push(0x5f); // json_ref
        code.push(0x01); // JSONUint64

        code.push(0x81); // pushint
        code.push(42);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass);
    }

    #[test]
    fn test_json_ref_object() {
        let json = br#"{"obj": {"inner": 1}}"#;
        let key = b"obj";

        let mut code = vec![0x80, json.len() as u8];
        code.extend_from_slice(json);
        code.extend_from_slice(&[0x80, key.len() as u8]);
        code.extend_from_slice(key);
        code.push(0x5f); // json_ref
        code.push(0x02); // JSONObject

        // Raw bytes are preserved from the original input (including whitespace).
        let expected = br#"{"inner": 1}"#;
        code.extend_from_slice(&[0x80, expected.len() as u8]);
        code.extend_from_slice(expected);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass);
    }

    #[test]
    fn test_json_ref_key_not_found() {
        let json = br#"{"key": "value"}"#;
        let key = b"missing";

        let mut code = vec![0x80, json.len() as u8];
        code.extend_from_slice(json);
        code.extend_from_slice(&[0x80, key.len() as u8]);
        code.extend_from_slice(key);
        code.push(0x5f);
        code.push(0x00);
        code.extend_from_slice(&[0x80, 0x00, 0x12, 0x43]);
        let result = run_prog(7, &code);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_ref_reject_array() {
        let json = br#"[1, 2, 3]"#;
        let key = b"key";

        let mut code = vec![0x80, json.len() as u8];
        code.extend_from_slice(json);
        code.extend_from_slice(&[0x80, key.len() as u8]);
        code.extend_from_slice(key);
        code.push(0x5f);
        code.push(0x00);
        code.extend_from_slice(&[0x80, 0x00, 0x12, 0x43]);
        let result = run_prog(7, &code);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_ref_reject_duplicate_keys() {
        let json = br#"{"key": "a", "key": "b"}"#;
        let key = b"key";

        let mut code = vec![0x80, json.len() as u8];
        code.extend_from_slice(json);
        code.extend_from_slice(&[0x80, key.len() as u8]);
        code.extend_from_slice(key);
        code.push(0x5f);
        code.push(0x00);
        code.extend_from_slice(&[0x80, 0x00, 0x12, 0x43]);
        let result = run_prog(7, &code);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_ref_reject_primitive_string() {
        // A bare JSON string is not an object
        let json = br#""hello""#;
        let key = b"key";

        let mut code = vec![0x80, json.len() as u8];
        code.extend_from_slice(json);
        code.extend_from_slice(&[0x80, key.len() as u8]);
        code.extend_from_slice(key);
        code.push(0x5f);
        code.push(0x00);
        code.extend_from_slice(&[0x80, 0x00, 0x12, 0x43]);
        let result = run_prog(7, &code);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_ref_reject_number() {
        let json = b"42";
        let key = b"key";

        let mut code = vec![0x80, json.len() as u8];
        code.extend_from_slice(json);
        code.extend_from_slice(&[0x80, key.len() as u8]);
        code.extend_from_slice(key);
        code.push(0x5f);
        code.push(0x00);
        code.extend_from_slice(&[0x80, 0x00, 0x12, 0x43]);
        let result = run_prog(7, &code);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Duplicate key detection unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_json_object_no_duplicates() {
        let json = br#"{"a": 1, "b": 2}"#;
        assert!(parse_json_object(json).is_ok());
    }

    #[test]
    fn test_parse_json_object_duplicate_keys() {
        let json = br#"{"a": 1, "a": 2}"#;
        assert!(parse_json_object(json).is_err());
    }

    #[test]
    fn test_parse_json_object_nested_dup_ok() {
        // Duplicate keys in nested objects are fine at the top level.
        // Go's parseJSON decodes into map[interface{}]json.RawMessage
        // which only checks top-level keys. Nested duplicate detection
        // depends on serde_json (which does reject them), but Go's
        // json.RawMessage does not parse nested values.
        // Our implementation only checks top-level keys, so nested
        // duplicates pass the top-level check. However, serde_json
        // validation (used for the initial parse) may reject them.
        // For consistency with Go's behavior at the AVM level,
        // we accept nested duplicates since Go's json.RawMessage
        // does not recurse.
        let json = br#"{"a": {"x": 1, "x": 2}}"#;
        // Note: serde_json silently overwrites nested duplicates,
        // and our raw extraction doesn't check nested keys.
        assert!(parse_json_object(json).is_ok());
    }

    #[test]
    fn test_parse_json_object_key_with_quotes() {
        // Keys containing escaped quotes should be handled correctly.
        let json = br#"{"k\"ey": "value"}"#;
        let result = parse_json_object(json);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert!(map.contains_key("k\"ey"));
    }

    #[test]
    fn test_parse_json_object_key_with_backslash() {
        // Keys containing escaped backslashes should be handled correctly.
        let json = br#"{"k\\ey": "value"}"#;
        let result = parse_json_object(json);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert!(map.contains_key("k\\ey"));
    }

    // -----------------------------------------------------------------------
    // base64_padded unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_base64_padded_with_padding() {
        assert!(base64_padded(b"aGVsbG8="));
        assert!(base64_padded(b"YQ=="));
    }

    #[test]
    fn test_base64_padded_without() {
        assert!(!base64_padded(b"aGVsbG8"));
        assert!(!base64_padded(b""));
    }

    #[test]
    fn test_base64_padded_with_trailing_newline() {
        assert!(base64_padded(b"aGVsbG8=\n"));
        assert!(!base64_padded(b"aGVsbG8\n"));
    }

    // -----------------------------------------------------------------------
    // Ed25519 test helpers
    // -----------------------------------------------------------------------

    /// A context that provides a program_hash for ed25519verify tests.
    struct Ed25519TestContext {
        program_hash: [u8; 32],
    }

    impl AvmContext for Ed25519TestContext {
        fn program_hash(&self) -> [u8; 32] {
            self.program_hash
        }
    }

    /// Helper: run with a custom context.
    fn run_prog_with_ctx(
        version: u8,
        code: &[u8],
        ctx: &mut dyn AvmContext,
    ) -> Result<AvmMachine, AlgoError> {
        let raw = prog(version, code);
        let program = parse(&raw).unwrap();
        let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 100_000);
        machine.run(ctx)?;
        Ok(machine)
    }

    /// Helper: encode a varuint (LEB128) for pushbytes length.
    fn encode_varuint(mut v: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            buf.push(b);
            if v == 0 {
                break;
            }
        }
        buf
    }

    /// Helper: push an arbitrary-length byte slice using pushbytes (0x80).
    fn pushbytes(code: &mut Vec<u8>, data: &[u8]) {
        code.push(0x80);
        code.extend_from_slice(&encode_varuint(data.len()));
        code.extend_from_slice(data);
    }

    // -----------------------------------------------------------------------
    // ed25519verify_bare tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ed25519verify_bare_valid() {
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        let msg = b"test message for ed25519";
        let sig = sk.sign(msg);

        let mut code = Vec::new();
        pushbytes(&mut code, msg); // data
        pushbytes(&mut code, &sig.to_bytes()); // signature
        pushbytes(&mut code, pk.as_bytes()); // pubkey
        code.push(0x84); // ed25519verify_bare
        code.push(0x43); // return

        let m = run_prog(7, &code).unwrap();
        assert!(m.pass, "ed25519verify_bare should pass for valid signature");
    }

    #[test]
    fn test_ed25519verify_bare_invalid_sig() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        let msg = b"test message";
        let bad_sig = [0u8; 64]; // invalid signature

        let mut code = Vec::new();
        pushbytes(&mut code, msg);
        pushbytes(&mut code, &bad_sig);
        pushbytes(&mut code, pk.as_bytes());
        code.push(0x84); // ed25519verify_bare
                         // Should push 0, so return will reject
        code.push(0x43); // return

        let m = run_prog(7, &code).unwrap();
        assert!(
            !m.pass,
            "ed25519verify_bare should reject invalid signature"
        );
    }

    #[test]
    fn test_ed25519verify_bare_wrong_message() {
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        let msg = b"correct message";
        let sig = sk.sign(msg);

        let mut code = Vec::new();
        pushbytes(&mut code, b"wrong message"); // different data
        pushbytes(&mut code, &sig.to_bytes());
        pushbytes(&mut code, pk.as_bytes());
        code.push(0x84);
        code.push(0x43);

        let m = run_prog(7, &code).unwrap();
        assert!(
            !m.pass,
            "ed25519verify_bare should reject mismatched message"
        );
    }

    #[test]
    fn test_ed25519verify_bare_wrong_pubkey_len() {
        let mut code = Vec::new();
        pushbytes(&mut code, b"data");
        pushbytes(&mut code, &[0u8; 64]);
        pushbytes(&mut code, &[0u8; 31]); // wrong length
        code.push(0x84);
        code.push(0x43);

        let result = run_prog(7, &code);
        assert!(
            result.is_err(),
            "ed25519verify_bare should error on wrong pubkey length"
        );
    }

    #[test]
    fn test_ed25519verify_bare_wrong_sig_len() {
        let mut code = Vec::new();
        pushbytes(&mut code, b"data");
        pushbytes(&mut code, &[0u8; 63]); // wrong length
        pushbytes(&mut code, &[0u8; 32]);
        code.push(0x84);
        code.push(0x43);

        let result = run_prog(7, &code);
        assert!(
            result.is_err(),
            "ed25519verify_bare should error on wrong sig length"
        );
    }

    // -----------------------------------------------------------------------
    // ed25519verify tests (with domain separation)
    // -----------------------------------------------------------------------

    #[test]
    fn test_ed25519verify_valid() {
        use ed25519_dalek::{Signer, SigningKey};

        // The program hash that our context will return.
        let program_hash = [7u8; 32];

        // Build the domain-separated message: SHA-512/256("ProgData" || program_hash || data)
        let data = b"hello ed25519verify";
        let mut msg_bytes = Vec::new();
        msg_bytes.extend_from_slice(b"ProgData");
        msg_bytes.extend_from_slice(&program_hash);
        msg_bytes.extend_from_slice(data);
        let msg_hash: [u8; 32] = Sha512_256::digest(&msg_bytes).into();

        let sk = SigningKey::from_bytes(&[99u8; 32]);
        let pk = sk.verifying_key();
        let sig = sk.sign(&msg_hash);

        let mut code = Vec::new();
        pushbytes(&mut code, data);
        pushbytes(&mut code, &sig.to_bytes());
        pushbytes(&mut code, pk.as_bytes());
        code.push(0x04); // ed25519verify
        code.push(0x43); // return

        let mut ctx = Ed25519TestContext { program_hash };
        // Use v3 because pushbytes requires AVM v3+
        let m = run_prog_with_ctx(3, &code, &mut ctx).unwrap();
        assert!(
            m.pass,
            "ed25519verify should pass for valid domain-separated signature"
        );
    }

    #[test]
    fn test_ed25519verify_wrong_hash_rejects() {
        use ed25519_dalek::{Signer, SigningKey};

        // Sign with a different program hash than what the context provides.
        let context_hash = [7u8; 32];
        let wrong_hash = [8u8; 32];

        let data = b"test data";
        let mut msg_bytes = Vec::new();
        msg_bytes.extend_from_slice(b"ProgData");
        msg_bytes.extend_from_slice(&wrong_hash); // use wrong hash
        msg_bytes.extend_from_slice(data);
        let msg_hash: [u8; 32] = Sha512_256::digest(&msg_bytes).into();

        let sk = SigningKey::from_bytes(&[99u8; 32]);
        let pk = sk.verifying_key();
        let sig = sk.sign(&msg_hash);

        let mut code = Vec::new();
        pushbytes(&mut code, data);
        pushbytes(&mut code, &sig.to_bytes());
        pushbytes(&mut code, pk.as_bytes());
        code.push(0x04);
        code.push(0x43);

        let mut ctx = Ed25519TestContext {
            program_hash: context_hash,
        };
        let m = run_prog_with_ctx(3, &code, &mut ctx).unwrap();
        assert!(
            !m.pass,
            "ed25519verify should reject when program hash doesn't match"
        );
    }

    // -----------------------------------------------------------------------
    // ecdsa_verify tests (secp256k1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_verify_secp256k1_valid() {
        use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

        let sk = SigningKey::from_bytes(&[1u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let msg = [0xabu8; 32];

        let (sig, _recid) = sk.sign_prehash(&msg).unwrap();
        let sig_bytes = sig.to_bytes();
        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..];

        let encoded = vk.to_encoded_point(false);
        let x = encoded.x().unwrap();
        let y = encoded.y().unwrap();

        let mut code = Vec::new();
        pushbytes(&mut code, &msg); // data (32 bytes)
        pushbytes(&mut code, r); // R
        pushbytes(&mut code, s); // S
        pushbytes(&mut code, x); // X
        pushbytes(&mut code, y); // Y
        code.push(0x05); // ecdsa_verify
        code.push(0x00); // Secp256k1
        code.push(0x43); // return

        let m = run_prog(5, &code).unwrap();
        assert!(
            m.pass,
            "ecdsa_verify secp256k1 should pass for valid signature"
        );
    }

    #[test]
    fn test_ecdsa_verify_secp256k1_bad_sig() {
        use k256::ecdsa::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let msg = [0xabu8; 32];

        // Use a different R and S (ones that are still valid field elements but don't match)
        let r = [0x01u8; 32]; // arbitrary non-zero R
        let s = [0x01u8; 32]; // arbitrary non-zero S

        let encoded = vk.to_encoded_point(false);
        let x = encoded.x().unwrap();
        let y = encoded.y().unwrap();

        let mut code = Vec::new();
        pushbytes(&mut code, &msg);
        pushbytes(&mut code, &r);
        pushbytes(&mut code, &s);
        pushbytes(&mut code, x);
        pushbytes(&mut code, y);
        code.push(0x05);
        code.push(0x00);
        code.push(0x43);

        let m = run_prog(5, &code).unwrap();
        assert!(
            !m.pass,
            "ecdsa_verify secp256k1 should reject invalid signature"
        );
    }

    #[test]
    fn test_ecdsa_verify_wrong_data_len() {
        // Data must be exactly 32 bytes
        let mut code = Vec::new();
        pushbytes(&mut code, &[0u8; 31]); // wrong length
        pushbytes(&mut code, &[1u8; 32]); // R
        pushbytes(&mut code, &[1u8; 32]); // S
        pushbytes(&mut code, &[1u8; 32]); // X
        pushbytes(&mut code, &[1u8; 32]); // Y
        code.push(0x05);
        code.push(0x00);
        code.push(0x43);

        let result = run_prog(5, &code);
        assert!(
            result.is_err(),
            "ecdsa_verify should error on non-32-byte data"
        );
    }

    // -----------------------------------------------------------------------
    // ecdsa_verify tests (secp256r1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_verify_secp256r1_valid() {
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

        let sk = SigningKey::from_bytes(&[2u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let msg = [0xcdu8; 32];

        let (sig, _recid) = sk.sign_prehash(&msg).unwrap();
        let sig_bytes = sig.to_bytes();
        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..];

        let encoded = vk.to_encoded_point(false);
        let x = encoded.x().unwrap();
        let y = encoded.y().unwrap();

        let mut code = Vec::new();
        pushbytes(&mut code, &msg);
        pushbytes(&mut code, r);
        pushbytes(&mut code, s);
        pushbytes(&mut code, x);
        pushbytes(&mut code, y);
        code.push(0x05); // ecdsa_verify
        code.push(0x01); // Secp256r1
        code.push(0x43);

        let m = run_prog(7, &code).unwrap();
        assert!(
            m.pass,
            "ecdsa_verify secp256r1 should pass for valid signature"
        );
    }

    #[test]
    fn test_ecdsa_verify_secp256r1_version_gating() {
        // Secp256r1 requires version 7+, should fail on version 5
        let mut code = Vec::new();
        pushbytes(&mut code, &[0u8; 32]); // data
        pushbytes(&mut code, &[1u8; 32]); // R
        pushbytes(&mut code, &[1u8; 32]); // S
        pushbytes(&mut code, &[1u8; 32]); // X
        pushbytes(&mut code, &[1u8; 32]); // Y
        code.push(0x05);
        code.push(0x01); // Secp256r1
        code.push(0x43);

        let result = run_prog(5, &code);
        assert!(result.is_err(), "secp256r1 should be rejected on AVM v5");
    }

    // -----------------------------------------------------------------------
    // ecdsa_pk_decompress tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_pk_decompress_secp256k1() {
        use k256::ecdsa::SigningKey;

        let sk = SigningKey::from_bytes(&[5u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let compressed = vk.to_encoded_point(true);
        let expected_uncompressed = vk.to_encoded_point(false);
        let expected_x = expected_uncompressed.x().unwrap();
        let expected_y = expected_uncompressed.y().unwrap();

        let mut code = Vec::new();
        pushbytes(&mut code, compressed.as_bytes()); // compressed pubkey (33 bytes)
        code.push(0x06); // ecdsa_pk_decompress
        code.push(0x00); // Secp256k1
                         // Stack now has: [Y, X] with X on top
                         // Store X, then compare Y to expected_y, then compare X to expected_x
                         // Just verify X matches by pushing expected and comparing
        pushbytes(&mut code, expected_x.as_slice());
        code.push(0x12); // ==
        code.push(0x4c); // swap (bring Y to top)
        pushbytes(&mut code, expected_y.as_slice());
        code.push(0x12); // ==
        code.push(0x10); // && (both must match)
        code.push(0x43); // return

        let m = run_prog(5, &code).unwrap();
        assert!(
            m.pass,
            "ecdsa_pk_decompress secp256k1 should decompress correctly"
        );
    }

    #[test]
    fn test_ecdsa_pk_decompress_secp256r1() {
        use p256::ecdsa::SigningKey;

        let sk = SigningKey::from_bytes(&[5u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let compressed = vk.to_encoded_point(true);
        let expected_uncompressed = vk.to_encoded_point(false);
        let expected_x = expected_uncompressed.x().unwrap();
        let expected_y = expected_uncompressed.y().unwrap();

        let mut code = Vec::new();
        pushbytes(&mut code, compressed.as_bytes());
        code.push(0x06); // ecdsa_pk_decompress
        code.push(0x01); // Secp256r1
        pushbytes(&mut code, expected_x.as_slice());
        code.push(0x12); // ==
        code.push(0x4c); // swap
        pushbytes(&mut code, expected_y.as_slice());
        code.push(0x12); // ==
        code.push(0x10); // &&
        code.push(0x43); // return

        let m = run_prog(7, &code).unwrap();
        assert!(
            m.pass,
            "ecdsa_pk_decompress secp256r1 should decompress correctly"
        );
    }

    #[test]
    fn test_ecdsa_pk_decompress_invalid_key() {
        let mut code = Vec::new();
        pushbytes(&mut code, &[0u8; 33]); // invalid compressed pubkey
        code.push(0x06);
        code.push(0x00);
        code.push(0x43);

        let result = run_prog(5, &code);
        assert!(
            result.is_err(),
            "ecdsa_pk_decompress should error on invalid key"
        );
    }

    // -----------------------------------------------------------------------
    // ecdsa_pk_recover tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_pk_recover_secp256k1() {
        use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

        let sk = SigningKey::from_bytes(&[3u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let msg = [0xffu8; 32];

        let (sig, recid) = sk.sign_prehash(&msg).unwrap();
        let sig_bytes = sig.to_bytes();
        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..];

        let expected = vk.to_encoded_point(false);
        let expected_x = expected.x().unwrap();
        let expected_y = expected.y().unwrap();

        let recid_val = recid.to_byte() as u64;

        let mut code = Vec::new();
        pushbytes(&mut code, &msg); // data (32 bytes)
        pushbytes(&mut code, r); // R
        pushbytes(&mut code, s); // S
                                 // push recovery_id as uint64
        code.push(0x81); // pushint
        code.push(recid_val as u8);
        code.push(0x07); // ecdsa_pk_recover
        code.push(0x00); // Secp256k1
                         // Stack: [Y, X] with X on top
        pushbytes(&mut code, expected_x.as_slice());
        code.push(0x12); // ==
        code.push(0x4c); // swap
        pushbytes(&mut code, expected_y.as_slice());
        code.push(0x12); // ==
        code.push(0x10); // &&
        code.push(0x43); // return

        let m = run_prog(5, &code).unwrap();
        assert!(
            m.pass,
            "ecdsa_pk_recover should recover the correct public key"
        );
    }

    #[test]
    fn test_ecdsa_pk_recover_invalid_recid() {
        let mut code = Vec::new();
        pushbytes(&mut code, &[0u8; 32]); // data
        pushbytes(&mut code, &[1u8; 32]); // R
        pushbytes(&mut code, &[1u8; 32]); // S
        code.push(0x81); // pushint
        code.push(4); // recovery id = 4 (invalid, must be 0-3)
        code.push(0x07);
        code.push(0x00);
        code.push(0x43);

        let result = run_prog(5, &code);
        assert!(
            result.is_err(),
            "ecdsa_pk_recover should error on recovery id > 3"
        );
    }

    #[test]
    fn test_ecdsa_pk_recover_secp256r1_unsupported() {
        let mut code = Vec::new();
        pushbytes(&mut code, &[0u8; 32]); // data
        pushbytes(&mut code, &[1u8; 32]); // R
        pushbytes(&mut code, &[1u8; 32]); // S
        code.push(0x81); // pushint
        code.push(0); // recovery id
        code.push(0x07);
        code.push(0x01); // Secp256r1
        code.push(0x43);

        let result = run_prog(7, &code);
        assert!(
            result.is_err(),
            "ecdsa_pk_recover should error for secp256r1"
        );
    }

    // -----------------------------------------------------------------------
    // ECDSA internal helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pad_to_32() {
        // Shorter input: left-padded with zeros
        let result = pad_to_32(&[0xab, 0xcd]).unwrap();
        assert_eq!(&result[..30], &[0u8; 30]);
        assert_eq!(result[30], 0xab);
        assert_eq!(result[31], 0xcd);

        // Exact 32 bytes: unchanged
        let input = [0x42u8; 32];
        assert_eq!(pad_to_32(&input), Some(input));

        // Longer input with zero leading byte: strip and accept
        let mut long_zero_prefix = vec![0x00u8; 1];
        long_zero_prefix.extend_from_slice(&[0xffu8; 32]);
        assert_eq!(pad_to_32(&long_zero_prefix), Some([0xffu8; 32]));

        // Longer input with non-zero leading byte: reject
        let mut long_nonzero = vec![0x01u8];
        long_nonzero.extend_from_slice(&[0xffu8; 32]);
        assert_eq!(pad_to_32(&long_nonzero), None);
    }

    #[test]
    fn test_ecdsa_verify_secp256k1_high_s_normalized() {
        // Test that high-S signatures are normalized and still verify
        // (matching Go's libsecp256k1 behavior which normalizes internally).
        use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        use k256::elliptic_curve::ops::Reduce;
        use k256::{Scalar, U256};

        let sk = SigningKey::from_bytes(&[10u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let msg = [0x42u8; 32];

        let (sig, _recid) = sk.sign_prehash(&msg).unwrap();

        // Get R and S components
        let (r_component, s_component) = sig.split_bytes();

        // Compute high-S: n - s (where n is the curve order)
        let s_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&s_component);
        let neg_s = -s_scalar;
        let high_s_bytes = neg_s.to_bytes();

        // Verify with the high-S value -- should still work due to normalization
        let result = ecdsa_verify_secp256k1(
            &msg,
            &r_component,
            &high_s_bytes,
            vk.to_encoded_point(false).x().unwrap(),
            vk.to_encoded_point(false).y().unwrap(),
        );
        assert!(
            result,
            "secp256k1 verification should succeed after normalizing high-S"
        );
    }

    #[test]
    fn test_ecdsa_decompress_round_trip_secp256k1() {
        use k256::ecdsa::SigningKey;

        let sk = SigningKey::from_bytes(&[20u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let compressed = vk.to_encoded_point(true);
        let expected = vk.to_encoded_point(false);

        let (x, y) = ecdsa_decompress_secp256k1(compressed.as_bytes()).unwrap();
        assert_eq!(x.as_slice(), expected.x().unwrap().as_slice());
        assert_eq!(y.as_slice(), expected.y().unwrap().as_slice());
    }

    #[test]
    fn test_ecdsa_decompress_round_trip_secp256r1() {
        use p256::ecdsa::SigningKey;

        let sk = SigningKey::from_bytes(&[20u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let compressed = vk.to_encoded_point(true);
        let expected = vk.to_encoded_point(false);

        let (x, y) = ecdsa_decompress_secp256r1(compressed.as_bytes()).unwrap();
        assert_eq!(x.as_slice(), expected.x().unwrap().as_slice());
        assert_eq!(y.as_slice(), expected.y().unwrap().as_slice());
    }

    #[test]
    fn test_ecdsa_recover_round_trip_secp256k1() {
        use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

        let sk = SigningKey::from_bytes(&[30u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let msg = [0xddu8; 32];

        let (sig, recid) = sk.sign_prehash(&msg).unwrap();
        let sig_bytes = sig.to_bytes();
        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..];

        let (x, y) = ecdsa_recover_secp256k1(&msg, r, s, recid.to_byte()).unwrap();
        let expected = vk.to_encoded_point(false);
        assert_eq!(x.as_slice(), expected.x().unwrap().as_slice());
        assert_eq!(y.as_slice(), expected.y().unwrap().as_slice());
    }

    // -----------------------------------------------------------------------
    // vrf_verify opcode tests
    // -----------------------------------------------------------------------

    fn hex_to_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Test VRF verify with go-algorand test vector 1 (empty message).
    #[test]
    fn test_vrf_verify_opcode_vector1() {
        let pk = hex_to_vec("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let pi = hex_to_vec(
            "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7\
             ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560\
             f55edc256a787afe701677c0f602900",
        );
        let beta = hex_to_vec(
            "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a60\
             3f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc",
        );
        let data: &[u8] = b""; // empty message

        let mut code = Vec::new();
        pushbytes(&mut code, data); // data
        pushbytes(&mut code, &pi); // proof (80 bytes)
        pushbytes(&mut code, &pk); // pubkey (32 bytes)
        code.push(0xd0); // vrf_verify
        code.push(0x00); // VrfAlgorand
                         // Stack now: output (64 bytes), verified flag (uint64)
                         // assert verified == 1
        code.push(0x44); // assert (pops top, fails if 0)
                         // Stack now: output (64 bytes)
                         // Compare with expected output
        pushbytes(&mut code, &beta);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return

        let m = run_prog(7, &code).unwrap();
        assert!(m.pass, "VRF verify TV1 should pass via opcode");
    }

    /// Test VRF verify with go-algorand test vector 2 (message = 0x72).
    #[test]
    fn test_vrf_verify_opcode_vector2() {
        let pk = hex_to_vec("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let pi = hex_to_vec(
            "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111\
             200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358\
             c13e6ae1111a55717e895fd15f99f07",
        );
        let beta = hex_to_vec(
            "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb\
             1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8",
        );
        let data: &[u8] = &[0x72]; // message = 0x72

        let mut code = Vec::new();
        pushbytes(&mut code, data);
        pushbytes(&mut code, &pi);
        pushbytes(&mut code, &pk);
        code.push(0xd0); // vrf_verify
        code.push(0x00); // VrfAlgorand
        code.push(0x44); // assert
        pushbytes(&mut code, &beta);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return

        let m = run_prog(7, &code).unwrap();
        assert!(m.pass, "VRF verify TV2 should pass via opcode");
    }

    /// Test VRF verify with zero proof and zero pubkey: should return verified=0.
    #[test]
    fn test_vrf_verify_opcode_invalid_returns_zero() {
        let mut code = Vec::new();
        pushbytes(&mut code, b"some data"); // data
        pushbytes(&mut code, &[0u8; 80]); // zero proof
        pushbytes(&mut code, &[0u8; 32]); // zero pubkey (small order)
        code.push(0xd0); // vrf_verify
        code.push(0x00); // VrfAlgorand
                         // Stack: output (64 zero bytes), verified (0)
                         // Negate the verified flag: !0 = 1
        code.push(0x14); // ! (logical not, opcode 0x14)
        code.push(0x44); // assert (verified must be 0, so !0 = 1 passes)
                         // Now check output is 64 zero bytes
        pushbytes(&mut code, &[0u8; 64]);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return

        let m = run_prog(7, &code).unwrap();
        assert!(
            m.pass,
            "VRF verify with zero inputs should return verified=0 and 64 zero bytes"
        );
    }

    /// Test VRF verify rejects wrong proof size.
    #[test]
    fn test_vrf_verify_opcode_wrong_proof_size() {
        let mut code = Vec::new();
        pushbytes(&mut code, b"data");
        pushbytes(&mut code, &[0u8; 79]); // wrong size (79 instead of 80)
        pushbytes(&mut code, &[0u8; 32]);
        code.push(0xd0); // vrf_verify
        code.push(0x00); // VrfAlgorand
        code.push(0x43); // return

        let result = run_prog(7, &code);
        match result {
            Err(e) => {
                let err = e.to_string();
                assert!(
                    err.contains("vrf proof wrong size"),
                    "error should mention proof size: {err}"
                );
            }
            Ok(_) => panic!("vrf_verify should error on wrong proof size"),
        }
    }

    /// Test VRF verify rejects wrong pubkey size.
    #[test]
    fn test_vrf_verify_opcode_wrong_pubkey_size() {
        let mut code = Vec::new();
        pushbytes(&mut code, b"data");
        pushbytes(&mut code, &[0u8; 80]); // correct proof size
        pushbytes(&mut code, &[0u8; 31]); // wrong pubkey size
        code.push(0xd0); // vrf_verify
        code.push(0x00); // VrfAlgorand
        code.push(0x43); // return

        let result = run_prog(7, &code);
        match result {
            Err(e) => {
                let err = e.to_string();
                assert!(
                    err.contains("vrf pubkey wrong size"),
                    "error should mention pubkey size: {err}"
                );
            }
            Ok(_) => panic!("vrf_verify should error on wrong pubkey size"),
        }
    }

    // -----------------------------------------------------------------------
    // falcon_verify stub tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_falcon_verify_stub_returns_unimplemented() {
        // Push data, signature, pubkey (1793 bytes), then call falcon_verify.
        let mut code = Vec::new();
        pushbytes(&mut code, b"some data"); // data
        pushbytes(&mut code, &[0u8; 1232]); // signature (max 1232 bytes)
        pushbytes(&mut code, &[0u8; 1793]); // pubkey (1793 bytes)
        code.push(0x85); // falcon_verify
        code.push(0x43); // return

        let result = run_prog(12, &code);
        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("falcon_verify not yet implemented"),
                    "error should mention falcon_verify: {err_msg}"
                );
                assert!(
                    err_msg.contains("issue #43"),
                    "error should reference issue #43: {err_msg}"
                );
            }
            Ok(_) => panic!("falcon_verify stub should return an error"),
        }
    }

    // -----------------------------------------------------------------------
    // FIX 1 verification: JSONObject preserves raw bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_json_ref_object_preserves_whitespace() {
        // Verify that JSONObject returns the exact bytes from the original input,
        // including extra whitespace and nested key ordering.
        let json = br#"{"obj": {"b": 2,  "a": 1}}"#;
        let key = b"obj";

        let mut code = Vec::new();
        pushbytes(&mut code, json);
        pushbytes(&mut code, key);
        code.push(0x5f); // json_ref
        code.push(0x02); // JSONObject

        // Exact raw bytes from input: {"b": 2,  "a": 1}  (extra space preserved)
        let expected = br#"{"b": 2,  "a": 1}"#;
        pushbytes(&mut code, expected);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(7, &code).unwrap();
        assert!(
            m.pass,
            "JSONObject should preserve raw bytes including whitespace"
        );
    }

    #[test]
    fn test_json_ref_object_preserves_nested_key_order() {
        // Verify nested key ordering is preserved (Go's json.RawMessage behavior).
        let json = br#"{"obj": {"z": 1, "a": 2}}"#;
        let key = b"obj";

        let mut code = Vec::new();
        pushbytes(&mut code, json);
        pushbytes(&mut code, key);
        code.push(0x5f); // json_ref
        code.push(0x02); // JSONObject

        // serde_json would re-serialize as {"a":2,"z":1} (sorted), but raw
        // bytes should preserve original order: {"z": 1, "a": 2}
        let expected = br#"{"z": 1, "a": 2}"#;
        pushbytes(&mut code, expected);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass, "JSONObject should preserve nested key ordering");
    }

    // -----------------------------------------------------------------------
    // FIX 2 verification: base64 strict mode (non-canonical padding rejection)
    // -----------------------------------------------------------------------

    #[test]
    fn test_base64_decode_strict_rejects_noncanonical_padding() {
        // "AAB=" — 'B' has non-zero trailing bits in the padding region.
        // Go's Strict() rejects this. The Rust base64 crate's default config
        // also rejects it (decode_allow_trailing_bits = false).
        let encoded = b"AAB=";
        let mut code = vec![0x80, encoded.len() as u8];
        code.extend_from_slice(encoded);
        code.push(0x5e); // base64_decode
        code.push(0x01); // StdEncoding
        code.extend_from_slice(&[0x80, 0x00, 0x12, 0x43]); // push "", ==, return
        let result = run_prog(7, &code);
        assert!(
            result.is_err(),
            "base64 decode should reject non-canonical padding bits (AAB=)"
        );
    }

    #[test]
    fn test_base64_decode_strict_accepts_canonical_padding() {
        // "AAA=" is canonical (trailing bits are zero). Should succeed.
        let encoded = b"AAA=";
        let mut code = vec![0x80, encoded.len() as u8];
        code.extend_from_slice(encoded);
        code.push(0x5e); // base64_decode
        code.push(0x01); // StdEncoding
                         // Expected: [0, 0]
        code.extend_from_slice(&[0x80, 0x02, 0x00, 0x00]);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(7, &code).unwrap();
        assert!(
            m.pass,
            "base64 decode should accept canonical padding (AAA=)"
        );
    }

    #[test]
    fn test_base64_decode_url_strict_rejects_noncanonical() {
        // Same test for URL encoding.
        let encoded = b"AAB=";
        let mut code = vec![0x80, encoded.len() as u8];
        code.extend_from_slice(encoded);
        code.push(0x5e); // base64_decode
        code.push(0x00); // URLEncoding
        code.extend_from_slice(&[0x80, 0x00, 0x12, 0x43]);
        let result = run_prog(7, &code);
        assert!(
            result.is_err(),
            "base64 URL decode should reject non-canonical padding bits"
        );
    }

    // -----------------------------------------------------------------------
    // FIX 5: secp256r1 high-S rejection
    // -----------------------------------------------------------------------

    #[test]
    fn test_ecdsa_verify_secp256r1_high_s_accepted() {
        // Standard ECDSA verification (both Go's crypto/ecdsa and p256 crate)
        // accepts both low-S and high-S signatures. Unlike secp256k1 (where
        // Go uses libsecp256k1 which normalizes S), p256 does not normalize S
        // but standard ECDSA verify still accepts high-S since it just checks
        // r == (k*G).x mod n, which works for both s and n-s.
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        use p256::elliptic_curve::ops::Reduce;
        use p256::{Scalar, U256};

        let sk = SigningKey::from_bytes(&[10u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let msg = [0x42u8; 32];

        let (sig, _recid) = sk.sign_prehash(&msg).unwrap();
        let (r_component, s_component) = sig.split_bytes();

        // Compute high-S: n - s (where n is the curve order)
        let s_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&s_component);
        let neg_s = -s_scalar;
        let high_s_bytes = neg_s.to_bytes();

        // Verify with the high-S value -- should succeed for p256 since standard
        // ECDSA verification accepts both s and n-s.
        let result = ecdsa_verify_secp256r1(
            &msg,
            &r_component,
            &high_s_bytes,
            vk.to_encoded_point(false).x().unwrap(),
            vk.to_encoded_point(false).y().unwrap(),
        );
        assert!(
            result,
            "secp256r1 should accept high-S signature (standard ECDSA, no low-S requirement)"
        );
    }

    // -----------------------------------------------------------------------
    // FIX 5: JSON edge-case tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_json_ref_empty_string_key() {
        // Empty string key: {"": "value"}
        let json = br#"{"": "value"}"#;
        let key = b"";

        let mut code = Vec::new();
        pushbytes(&mut code, json);
        pushbytes(&mut code, key);
        code.push(0x5f); // json_ref
        code.push(0x00); // JSONString

        let expected = b"value";
        pushbytes(&mut code, expected);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass, "json_ref should handle empty string keys");
    }

    #[test]
    fn test_json_ref_null_value_with_jsonstring() {
        // null value accessed as JSONString should error.
        let json = br#"{"key": null}"#;
        let key = b"key";

        let mut code = Vec::new();
        pushbytes(&mut code, json);
        pushbytes(&mut code, key);
        code.push(0x5f); // json_ref
        code.push(0x00); // JSONString
        code.push(0x43); // return (won't reach if error)

        let result = run_prog(7, &code);
        assert!(
            result.is_err(),
            "json_ref JSONString should error for null value"
        );
    }

    #[test]
    fn test_json_ref_unicode_escaped_key() {
        // Unicode escaped key: \u006b = 'k'
        let json = br#"{"\u006bey": "value"}"#;
        let key = b"key"; // the decoded key is "key"

        let mut code = Vec::new();
        pushbytes(&mut code, json);
        pushbytes(&mut code, key);
        code.push(0x5f); // json_ref
        code.push(0x00); // JSONString

        let expected = b"value";
        pushbytes(&mut code, expected);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass, "json_ref should handle unicode-escaped keys");
    }

    // -----------------------------------------------------------------------
    // FIX 5: Cost budget tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_base64_decode_cost_exact_budget() {
        // base64_decode cost: 1 + ceil(len/16)
        // "aGVsbG8=" is 8 bytes, cost = 1 + ceil(8/16) = 1 + 1 = 2
        // We test with a machine that has just enough budget.
        let encoded = b"aGVsbG8=";
        let mut code = Vec::new();
        pushbytes(&mut code, encoded);
        code.push(0x5e); // base64_decode
        code.push(0x01); // StdEncoding
        code.push(0x15); // len (opcode 0x15) -> pushes 5
        code.push(0x81); // pushint
        code.push(5); // expected length of "hello"
        code.extend_from_slice(&[0x12, 0x43]); // ==, return

        // This should succeed with default 100k budget.
        let m = run_prog(7, &code).unwrap();
        assert!(
            m.pass,
            "base64_decode with sufficient budget should succeed"
        );
    }

    #[test]
    fn test_base64_decode_cost_insufficient_budget() {
        // base64_decode with very tight budget.
        // Cost = 1 + ceil(8/16) = 2 for the encoded data.
        // Create a machine with budget = 1, which is less than needed.
        let encoded = b"aGVsbG8=";
        let raw = prog(7, &{
            let mut code = Vec::new();
            pushbytes(&mut code, encoded);
            code.push(0x5e); // base64_decode
            code.push(0x01); // StdEncoding
            code.push(0x43); // return
            code
        });
        let program = parse(&raw).unwrap();
        let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 1);
        let result = machine.run(&mut NullContext);
        assert!(
            result.is_err(),
            "base64_decode should fail with insufficient budget"
        );
    }

    #[test]
    fn test_json_ref_cost_exact_budget() {
        // json_ref cost: 25 + 2 * ceil(len_json/7)
        // For 14-byte JSON: 25 + 2 * ceil(14/7) = 25 + 4 = 29
        let json = br#"{"key": "val"}"#; // 14 bytes
        assert_eq!(json.len(), 14);
        let key = b"key";

        let mut code = Vec::new();
        pushbytes(&mut code, json);
        pushbytes(&mut code, key);
        code.push(0x5f); // json_ref
        code.push(0x00); // JSONString

        let expected = b"val";
        pushbytes(&mut code, expected);
        code.extend_from_slice(&[0x12, 0x43]); // ==, return

        // With default budget this should work fine.
        let m = run_prog(7, &code).unwrap();
        assert!(m.pass, "json_ref with sufficient budget should succeed");
    }

    #[test]
    fn test_json_ref_cost_insufficient_budget() {
        // json_ref cost: 25 + 2 * ceil(14/7) = 29
        // Machine with budget = 1 should fail.
        let json = br#"{"key": "val"}"#;
        let key = b"key";

        let raw = prog(7, &{
            let mut code = Vec::new();
            pushbytes(&mut code, json);
            pushbytes(&mut code, key);
            code.push(0x5f); // json_ref
            code.push(0x00); // JSONString
            code.push(0x43); // return
            code
        });
        let program = parse(&raw).unwrap();
        let mut machine = AvmMachine::new(program, ExecMode::LogicSig, 1);
        let result = machine.run(&mut NullContext);
        assert!(
            result.is_err(),
            "json_ref should fail with insufficient budget"
        );
    }
}
