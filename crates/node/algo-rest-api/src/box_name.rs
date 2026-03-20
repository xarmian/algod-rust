//! Box name encoding parser matching go-algorand's `apps.NewAppCallBytes`.
//!
//! Parses goal-style box name encodings of the form `encoding:value`:
//!
//! - `str:hello` — raw bytes of "hello"
//! - `int:42` — 8-byte big-endian encoding of 42
//! - `addr:AAAA...` — 32-byte decoded Algorand address
//! - `b64:AQID` — base64-decoded bytes
//! - `b32:MFRGG...` — base32-decoded bytes (RFC 4648, standard alphabet, with padding)
//! - `abi:(uint64)42` — ABI-encoded value based on type descriptor
//!
//! Reference: `github.com/algorand/avm-abi/apps/parsing.go`

use algo_types::Address;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use data_encoding::BASE32;

/// Parse a goal-style box name encoding string into raw bytes.
///
/// The input must be of the form `encoding:value` where `encoding` is one of
/// `str`, `string`, `int`, `integer`, `addr`, `address`, `b64`, `base64`,
/// `byte base64`, `b32`, `base32`, `byte base32`, or `abi`.
///
/// # Errors
///
/// Returns an error if the input is malformed or contains invalid data for the
/// specified encoding.
pub fn parse_box_name(arg: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let (encoding, value) = arg
        .split_once(':')
        .ok_or("all arguments and box names should be of the form 'encoding:value'")?;

    let decoded = match encoding {
        "str" | "string" => value.as_bytes().to_vec(),

        "int" | "integer" => {
            let num: u64 = value
                .parse()
                .map_err(|e| format!("Could not parse uint64 from string ({value}): {e}"))?;
            num.to_be_bytes().to_vec()
        }

        "addr" | "address" => {
            let addr = Address::from_algorand_string(value).map_err(|e| {
                format!("Could not unmarshal checksummed address from string ({value}): {e}")
            })?;
            addr.0.to_vec()
        }

        "b32" | "base32" | "byte base32" => BASE32
            .decode(value.as_bytes())
            .map_err(|e| format!("Could not decode base32-encoded string ({value}): {e}"))?,

        "b64" | "base64" | "byte base64" => BASE64_STANDARD
            .decode(value)
            .map_err(|e| format!("Could not decode base64-encoded string ({value}): {e}"))?,

        "abi" => {
            let (abi_type_str, abi_value_str) = value.split_once(':').ok_or(format!(
                "Could not decode abi string ({value}): should split abi-type and abi-value with colon"
            ))?;
            parse_abi_encoded(abi_type_str, abi_value_str)?
        }

        _ => return Err(format!("Unknown encoding: {encoding}").into()),
    };

    Ok(decoded)
}

/// Parse and ABI-encode a value given a type descriptor and a JSON value string.
///
/// Supports the subset of ABI types commonly used with box names:
/// - `uint<N>` (uint8 through uint512, in increments of 8)
/// - `bool`
/// - `address`
/// - `byte` (alias for uint8)
///
/// More complex ABI types (tuples, arrays, strings) are not yet implemented;
/// they can be added as needed.
fn parse_abi_encoded(
    abi_type_str: &str,
    abi_value_str: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Remove surrounding parentheses if present: (uint64) -> uint64
    let abi_type_str = abi_type_str
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(abi_type_str);

    if abi_type_str == "bool" {
        let val: bool = abi_value_str
            .parse()
            .map_err(|e| format!("Could not decode abi value string ({abi_value_str}): {e}"))?;
        // ABI bool is encoded as a single byte
        return Ok(vec![if val { 1 } else { 0 }]);
    }

    if abi_type_str == "address" {
        let addr = Address::from_algorand_string(abi_value_str.trim_matches('"'))
            .map_err(|e| format!("Could not decode abi value string ({abi_value_str}): {e}"))?;
        return Ok(addr.0.to_vec());
    }

    if abi_type_str == "byte" {
        let num: u8 = abi_value_str
            .parse()
            .map_err(|e| format!("Could not decode abi value string ({abi_value_str}): {e}"))?;
        return Ok(vec![num]);
    }

    // uint<N> types
    if let Some(bits_str) = abi_type_str.strip_prefix("uint") {
        let bits: usize = bits_str
            .parse()
            .map_err(|e| format!("Could not decode abi type string ({abi_type_str}): {e}"))?;
        if bits == 0 || bits > 512 || bits % 8 != 0 {
            return Err(
                format!("Could not decode abi type string ({abi_type_str}): bit size must be between 8 and 512 and a multiple of 8").into(),
            );
        }
        let byte_len = bits / 8;

        // Parse the value as a u128 (covers up to uint128). For larger types
        // we would need a big-int library, but uint64 covers the vast majority
        // of real-world box name use cases.
        let num: u128 = abi_value_str
            .parse()
            .map_err(|e| format!("Could not decode abi value string ({abi_value_str}): {e}"))?;

        // Encode as big-endian with the correct byte length
        let full_bytes = num.to_be_bytes(); // 16 bytes
        if byte_len <= 16 {
            // Take the last `byte_len` bytes from the 16-byte big-endian
            let start = 16 - byte_len;
            // Verify no overflow: the leading bytes we're discarding must be zero
            if full_bytes[..start].iter().any(|&b| b != 0) {
                return Err(format!(
                    "Could not decode abi value string ({abi_value_str}): value too large for {abi_type_str}"
                )
                .into());
            }
            Ok(full_bytes[start..].to_vec())
        } else {
            // For types larger than 128 bits, left-pad with zeros
            let mut result = vec![0u8; byte_len];
            let start = byte_len - 16;
            result[start..].copy_from_slice(&full_bytes);
            Ok(result)
        }
    } else {
        Err(
            format!("Could not decode abi type string ({abi_type_str}): unsupported ABI type")
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_str_encoding() {
        let result = parse_box_name("str:hello").unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_string_encoding() {
        let result = parse_box_name("string:world").unwrap();
        assert_eq!(result, b"world");
    }

    #[test]
    fn test_str_empty() {
        let result = parse_box_name("str:").unwrap();
        assert_eq!(result, b"");
    }

    #[test]
    fn test_str_with_colon() {
        // "str:hello:world" should parse as encoding=str, value=hello:world
        let result = parse_box_name("str:hello:world").unwrap();
        assert_eq!(result, b"hello:world");
    }

    #[test]
    fn test_int_encoding() {
        let result = parse_box_name("int:3").unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0, 0, 0, 3]);
    }

    #[test]
    fn test_int_zero() {
        let result = parse_box_name("int:0").unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_int_max() {
        let result = parse_box_name("int:18446744073709551615").unwrap();
        assert_eq!(result, vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_int_invalid() {
        assert!(parse_box_name("int:abc").is_err());
        assert!(parse_box_name("int:-1").is_err());
    }

    #[test]
    fn test_addr_encoding() {
        // Zero address
        let result =
            parse_box_name("addr:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
                .unwrap();
        assert_eq!(result, vec![0u8; 32]);
    }

    #[test]
    fn test_addr_invalid() {
        assert!(parse_box_name("addr:INVALID").is_err());
    }

    #[test]
    fn test_b64_encoding() {
        let result = parse_box_name("b64:AQID").unwrap();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_b64_empty() {
        let result = parse_box_name("b64:").unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_b64_invalid() {
        assert!(parse_box_name("b64:!!!").is_err());
    }

    #[test]
    fn test_b32_encoding() {
        // "MFRA====" in base32 standard with padding decodes to [0x61, 0x62]
        // which is "ab"
        let result = parse_box_name("b32:MFRA====").unwrap();
        assert_eq!(result, b"ab");
    }

    #[test]
    fn test_unknown_encoding() {
        assert!(parse_box_name("unknown:value").is_err());
    }

    #[test]
    fn test_no_colon() {
        assert!(parse_box_name("noencoding").is_err());
    }

    #[test]
    fn test_abi_uint64() {
        // Format: abi:(uint64):42 — two colons total
        let result = parse_box_name("abi:(uint64):42").unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0, 0, 0, 42]);
    }

    #[test]
    fn test_abi_uint8() {
        let result = parse_box_name("abi:(uint8):255").unwrap();
        assert_eq!(result, vec![255]);
    }

    #[test]
    fn test_abi_uint16() {
        let result = parse_box_name("abi:(uint16):256").unwrap();
        assert_eq!(result, vec![1, 0]);
    }

    #[test]
    fn test_abi_bool_true() {
        let result = parse_box_name("abi:(bool):true").unwrap();
        assert_eq!(result, vec![1]);
    }

    #[test]
    fn test_abi_bool_false() {
        let result = parse_box_name("abi:(bool):false").unwrap();
        assert_eq!(result, vec![0]);
    }

    #[test]
    fn test_abi_invalid_type() {
        assert!(parse_box_name("abi:(uint7):42").is_err());
        assert!(parse_box_name("abi:(uint0):42").is_err());
    }

    #[test]
    fn test_abi_no_colon() {
        // Missing the second colon separating type from value
        assert!(parse_box_name("abi:uint64").is_err());
    }

    #[test]
    fn test_abi_overflow() {
        assert!(parse_box_name("abi:(uint8):256").is_err());
    }
}
