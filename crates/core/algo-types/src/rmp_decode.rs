//! Low-level msgpack decode helpers using `rmp` directly.
//! Avoids serde overhead for hot-path block/transaction decoding.

use algo_error::{AlgoError, Result};
use serde_bytes::ByteBuf;

use crate::Address;

/// Create a codec error with the given message.
fn codec_err(msg: impl Into<String>) -> AlgoError {
    AlgoError::Codec {
        source: msg.into().into(),
        context: "rmp_decode".into(),
    }
}

// ── Map / key reading ──────────────────────────────────────────

/// Read a msgpack map header, returning the number of key-value pairs.
#[inline]
pub fn read_map_len(rd: &mut &[u8]) -> Result<u32> {
    rmp::decode::read_map_len(rd).map_err(|e| codec_err(format!("read_map_len: {e}")))
}

/// Read a msgpack string key as raw bytes without allocation.
///
/// Reads the string header to get the length, then returns a borrowed
/// slice of the raw key bytes. No UTF-8 validation is performed.
///
/// Uses direct byte dispatch to avoid rmp::decode::read_str_len overhead.
/// Most Algorand keys are short (fixstr: len 0-31), so the common path is
/// a single byte read.
#[inline]
pub fn read_key_bytes<'a>(rd: &mut &'a [u8]) -> Result<&'a [u8]> {
    if rd.is_empty() {
        return Err(codec_err("read_key_bytes: unexpected EOF"));
    }
    let b = rd[0];
    let len: usize;
    // fixstr: 0xa0..=0xbf encodes length 0..31 in the marker itself
    if (0xa0..=0xbf).contains(&b) {
        len = (b & 0x1f) as usize;
        *rd = &rd[1..];
    } else if b == 0xd9 {
        // str8
        if rd.len() < 2 {
            return Err(codec_err("read_key_bytes: str8 unexpected EOF"));
        }
        len = rd[1] as usize;
        *rd = &rd[2..];
    } else if b == 0xda {
        // str16
        if rd.len() < 3 {
            return Err(codec_err("read_key_bytes: str16 unexpected EOF"));
        }
        len = u16::from_be_bytes([rd[1], rd[2]]) as usize;
        *rd = &rd[3..];
    } else {
        return Err(codec_err(format!(
            "read_key_bytes: expected string marker, got 0x{b:02x}"
        )));
    }
    if rd.len() < len {
        return Err(codec_err(format!(
            "read_key_bytes: need {len} bytes, have {}",
            rd.len()
        )));
    }
    let (key, rest) = rd.split_at(len);
    *rd = rest;
    Ok(key)
}

// ── Skip value ─────────────────────────────────────────────────

/// Matches go-algorand v4.7.2-stable's `msgp.DefaultUnmarshalState.AllowableDepth`
/// (`protocol/codec.go`), an anti-DoS bound on decode nesting depth.
pub(crate) const MAX_MSGPACK_DECODE_DEPTH: usize = 255;

/// Reject `bytes` if its (first) msgpack value nests containers deeper
/// than [`MAX_MSGPACK_DECODE_DEPTH`] levels, without otherwise decoding
/// or validating it.
///
/// Exposed for decoders that don't go through this module's own
/// `decode_from_reader` family — namely `algo-codec`'s `rmp_serde`/`rmpv`
/// entry points, whose decoders have no depth cap of their own. Run this
/// as a pre-scan before handing the bytes to them.
pub fn check_msgpack_depth(bytes: &[u8]) -> Result<()> {
    let mut rd = bytes;
    skip_value(&mut rd)
}

/// Skip any msgpack value (handles all types, including arbitrarily
/// nested containers).
///
/// Iterative, not recursive: `remaining` holds, for each currently open
/// container, how many more values inside it still need skipping, so
/// nesting depth is `remaining.len()`. This is deliberate — a naive
/// recursive skip lets a maliciously deep/nested payload (this function
/// is reached for every *unrecognized* field a decoder skips, so an
/// attacker controls its shape freely) overflow the Rust call stack,
/// which aborts the process rather than returning an error. Bounding
/// `remaining.len()` at [`MAX_MSGPACK_DECODE_DEPTH`] mirrors go-algorand's
/// own bound and rejects the same maliciously deep payloads with a
/// catchable error instead.
#[inline]
pub fn skip_value(rd: &mut &[u8]) -> Result<()> {
    let mut remaining: Vec<u32> = vec![1];
    while let Some(count) = remaining.last_mut() {
        if *count == 0 {
            remaining.pop();
            continue;
        }
        *count -= 1;
        if remaining.len() > MAX_MSGPACK_DECODE_DEPTH {
            return Err(codec_err(format!(
                "skip_value: nesting depth exceeds {MAX_MSGPACK_DECODE_DEPTH}"
            )));
        }
        if rd.is_empty() {
            return Err(codec_err("skip_value: unexpected EOF"));
        }
        let b = rd[0];
        *rd = &rd[1..];
        match b {
            // positive fixint (0x00..=0x7f) — no data bytes
            0x00..=0x7f => {}
            // fixmap (0x80..=0x8f) — len 0..15 key-value pairs
            0x80..=0x8f => remaining.push(((b & 0x0f) as u32) * 2),
            // fixarray (0x90..=0x9f) — len 0..15 elements
            0x90..=0x9f => remaining.push((b & 0x0f) as u32),
            // fixstr (0xa0..=0xbf) — len 0..31
            0xa0..=0xbf => skip_bytes(rd, (b & 0x1f) as usize)?,
            // nil, false, true
            0xc0 | 0xc2 | 0xc3 => {}
            // reserved
            0xc1 => return Err(codec_err("skip_value: reserved marker 0xc1")),
            // bin8
            0xc4 => {
                let len = read_data_u8(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // bin16
            0xc5 => {
                let len = read_data_u16(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // bin32
            0xc6 => {
                let len = read_data_u32_raw(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // ext8
            0xc7 => {
                let len = read_data_u8(rd)? as usize;
                skip_bytes(rd, 1 + len)?;
            }
            // ext16
            0xc8 => {
                let len = read_data_u16(rd)? as usize;
                skip_bytes(rd, 1 + len)?;
            }
            // ext32
            0xc9 => {
                let len = read_data_u32_raw(rd)? as usize;
                skip_bytes(rd, 1 + len)?;
            }
            // f32
            0xca => skip_bytes(rd, 4)?,
            // f64
            0xcb => skip_bytes(rd, 8)?,
            // u8
            0xcc => skip_bytes(rd, 1)?,
            // u16
            0xcd => skip_bytes(rd, 2)?,
            // u32
            0xce => skip_bytes(rd, 4)?,
            // u64
            0xcf => skip_bytes(rd, 8)?,
            // i8
            0xd0 => skip_bytes(rd, 1)?,
            // i16
            0xd1 => skip_bytes(rd, 2)?,
            // i32
            0xd2 => skip_bytes(rd, 4)?,
            // i64
            0xd3 => skip_bytes(rd, 8)?,
            // fixext1
            0xd4 => skip_bytes(rd, 2)?,
            // fixext2
            0xd5 => skip_bytes(rd, 3)?,
            // fixext4
            0xd6 => skip_bytes(rd, 5)?,
            // fixext8
            0xd7 => skip_bytes(rd, 9)?,
            // fixext16
            0xd8 => skip_bytes(rd, 17)?,
            // str8
            0xd9 => {
                let len = read_data_u8(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // str16
            0xda => {
                let len = read_data_u16(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // str32
            0xdb => {
                let len = read_data_u32_raw(rd)? as usize;
                skip_bytes(rd, len)?;
            }
            // array16
            0xdc => {
                let len = read_data_u16(rd)? as u32;
                remaining.push(len);
            }
            // array32
            0xdd => {
                let len = read_data_u32_raw(rd)?;
                remaining.push(len);
            }
            // map16
            0xde => {
                let len = read_data_u16(rd)? as u32;
                remaining.push(len * 2);
            }
            // map32
            0xdf => {
                let len = read_data_u32_raw(rd)?;
                remaining.push(len * 2);
            }
            // negative fixint (0xe0..=0xff) — no data bytes
            0xe0..=0xff => {}
        }
    }
    Ok(())
}

/// Skip exactly `n` bytes from the reader.
#[inline]
fn skip_bytes(rd: &mut &[u8], n: usize) -> Result<()> {
    if rd.len() < n {
        return Err(codec_err(format!(
            "skip_bytes: need {n}, have {}",
            rd.len()
        )));
    }
    *rd = &rd[n..];
    Ok(())
}

// ── Raw data reading (no marker) ───────────────────────────────

/// Read a raw u8 (data only, no marker).
#[inline]
fn read_data_u8(rd: &mut &[u8]) -> Result<u8> {
    if rd.is_empty() {
        return Err(codec_err("read_data_u8: unexpected EOF"));
    }
    let v = rd[0];
    *rd = &rd[1..];
    Ok(v)
}

/// Read a raw big-endian u16 (data only, no marker).
#[inline]
fn read_data_u16(rd: &mut &[u8]) -> Result<u16> {
    if rd.len() < 2 {
        return Err(codec_err("read_data_u16: unexpected EOF"));
    }
    let v = u16::from_be_bytes([rd[0], rd[1]]);
    *rd = &rd[2..];
    Ok(v)
}

/// Read a raw big-endian u32 (data only, no marker).
#[inline]
fn read_data_u32_raw(rd: &mut &[u8]) -> Result<u32> {
    if rd.len() < 4 {
        return Err(codec_err("read_data_u32: unexpected EOF"));
    }
    let v = u32::from_be_bytes([rd[0], rd[1], rd[2], rd[3]]);
    *rd = &rd[4..];
    Ok(v)
}

/// Read a raw big-endian u64 (data only, no marker).
#[inline]
fn read_data_u64_raw(rd: &mut &[u8]) -> Result<u64> {
    if rd.len() < 8 {
        return Err(codec_err("read_data_u64: unexpected EOF"));
    }
    let v = u64::from_be_bytes(rd[..8].try_into().unwrap());
    *rd = &rd[8..];
    Ok(v)
}

/// Read a raw big-endian i16 (data only, no marker).
#[inline]
fn read_data_i16(rd: &mut &[u8]) -> Result<i16> {
    if rd.len() < 2 {
        return Err(codec_err("read_data_i16: unexpected EOF"));
    }
    let v = i16::from_be_bytes([rd[0], rd[1]]);
    *rd = &rd[2..];
    Ok(v)
}

/// Read a raw big-endian i32 (data only, no marker).
#[inline]
fn read_data_i32(rd: &mut &[u8]) -> Result<i32> {
    if rd.len() < 4 {
        return Err(codec_err("read_data_i32: unexpected EOF"));
    }
    let v = i32::from_be_bytes([rd[0], rd[1], rd[2], rd[3]]);
    *rd = &rd[4..];
    Ok(v)
}

/// Read a raw big-endian i64 (data only, no marker).
#[inline]
fn read_data_i64_raw(rd: &mut &[u8]) -> Result<i64> {
    if rd.len() < 8 {
        return Err(codec_err("read_data_i64: unexpected EOF"));
    }
    let v = i64::from_be_bytes(rd[..8].try_into().unwrap());
    *rd = &rd[8..];
    Ok(v)
}

// ── Integer readers (polymorphic) ──────────────────────────────

/// Read any msgpack integer format and return as u64.
///
/// Handles all integer encodings: fixint, u8, u16, u32, u64, i8, i16, i32, i64.
/// Returns an error if the value is negative or not an integer type.
///
/// Uses direct byte dispatch instead of rmp::decode::read_marker to avoid
/// Marker enum construction overhead. The hot path (fixint 0-127) is a single
/// branch.
#[inline]
pub fn read_u64(rd: &mut &[u8]) -> Result<u64> {
    if rd.is_empty() {
        return Err(codec_err("read_u64: unexpected EOF"));
    }
    let b = rd[0];
    *rd = &rd[1..];
    match b {
        // positive fixint: 0x00..=0x7f
        0x00..=0x7f => Ok(b as u64),
        // u8
        0xcc => Ok(read_data_u8(rd)? as u64),
        // u16
        0xcd => Ok(read_data_u16(rd)? as u64),
        // u32
        0xce => Ok(read_data_u32_raw(rd)? as u64),
        // u64
        0xcf => read_data_u64_raw(rd),
        // negative fixint: 0xe0..=0xff
        0xe0..=0xff => Err(codec_err(format!("read_u64: negative value {}", b as i8))),
        // i8
        0xd0 => {
            let v = read_data_u8(rd)? as i8;
            if v >= 0 {
                Ok(v as u64)
            } else {
                Err(codec_err(format!("read_u64: negative i8 value {v}")))
            }
        }
        // i16
        0xd1 => {
            let v = read_data_i16(rd)?;
            if v >= 0 {
                Ok(v as u64)
            } else {
                Err(codec_err(format!("read_u64: negative i16 value {v}")))
            }
        }
        // i32
        0xd2 => {
            let v = read_data_i32(rd)?;
            if v >= 0 {
                Ok(v as u64)
            } else {
                Err(codec_err(format!("read_u64: negative i32 value {v}")))
            }
        }
        // i64
        0xd3 => {
            let v = read_data_i64_raw(rd)?;
            if v >= 0 {
                Ok(v as u64)
            } else {
                Err(codec_err(format!("read_u64: negative i64 value {v}")))
            }
        }
        other => Err(codec_err(format!(
            "read_u64: not an integer: 0x{other:02x}"
        ))),
    }
}

/// Read any msgpack integer format and return as i64.
#[inline]
pub fn read_i64(rd: &mut &[u8]) -> Result<i64> {
    if rd.is_empty() {
        return Err(codec_err("read_i64: unexpected EOF"));
    }
    let b = rd[0];
    *rd = &rd[1..];
    match b {
        // positive fixint: 0x00..=0x7f
        0x00..=0x7f => Ok(b as i64),
        // negative fixint: 0xe0..=0xff
        0xe0..=0xff => Ok(b as i8 as i64),
        // u8
        0xcc => Ok(read_data_u8(rd)? as i64),
        // u16
        0xcd => Ok(read_data_u16(rd)? as i64),
        // u32
        0xce => Ok(read_data_u32_raw(rd)? as i64),
        // u64
        0xcf => {
            let v = read_data_u64_raw(rd)?;
            i64::try_from(v)
                .map_err(|_| codec_err(format!("read_i64: u64 value {v} overflows i64")))
        }
        // i8
        0xd0 => Ok(read_data_u8(rd)? as i8 as i64),
        // i16
        0xd1 => Ok(read_data_i16(rd)? as i64),
        // i32
        0xd2 => Ok(read_data_i32(rd)? as i64),
        // i64
        0xd3 => read_data_i64_raw(rd),
        other => Err(codec_err(format!(
            "read_i64: not an integer: 0x{other:02x}"
        ))),
    }
}

/// Read any msgpack integer format and return as u32.
#[inline]
pub fn read_u32(rd: &mut &[u8]) -> Result<u32> {
    let v = read_u64(rd)?;
    u32::try_from(v).map_err(|_| codec_err(format!("read_u32: value {v} overflows u32")))
}

/// Read any msgpack integer format and return as u16.
#[inline]
pub fn read_u16(rd: &mut &[u8]) -> Result<u16> {
    let v = read_u64(rd)?;
    u16::try_from(v).map_err(|_| codec_err(format!("read_u16: value {v} overflows u16")))
}

/// Read any msgpack integer format and return as u8.
#[inline]
pub fn read_u8_val(rd: &mut &[u8]) -> Result<u8> {
    let v = read_u64(rd)?;
    u8::try_from(v).map_err(|_| codec_err(format!("read_u8_val: value {v} overflows u8")))
}

/// Read a msgpack boolean value.
#[inline]
pub fn read_bool(rd: &mut &[u8]) -> Result<bool> {
    if rd.is_empty() {
        return Err(codec_err("read_bool: unexpected EOF"));
    }
    let b = rd[0];
    *rd = &rd[1..];
    match b {
        0xc2 => Ok(false),
        0xc3 => Ok(true),
        _ => Err(codec_err(format!(
            "read_bool: expected bool marker, got 0x{b:02x}"
        ))),
    }
}

// ── String / bytes readers ─────────────────────────────────────

/// Read a msgpack string as an owned String.
#[inline]
pub fn read_string(rd: &mut &[u8]) -> Result<String> {
    let len = rmp::decode::read_str_len(rd)
        .map_err(|e| codec_err(format!("read_string str_len: {e}")))? as usize;
    if rd.len() < len {
        return Err(codec_err(format!(
            "read_string: need {len} bytes, have {}",
            rd.len()
        )));
    }
    let s = std::str::from_utf8(&rd[..len])
        .map_err(|e| codec_err(format!("read_string: invalid utf-8: {e}")))?
        .to_owned();
    *rd = &rd[len..];
    Ok(s)
}

/// Read a msgpack bin as owned Vec<u8>.
#[inline]
pub fn read_bytes(rd: &mut &[u8]) -> Result<Vec<u8>> {
    let len = rmp::decode::read_bin_len(rd)
        .map_err(|e| codec_err(format!("read_bytes bin_len: {e}")))? as usize;
    if rd.len() < len {
        return Err(codec_err(format!(
            "read_bytes: need {len} bytes, have {}",
            rd.len()
        )));
    }
    let v = rd[..len].to_vec();
    *rd = &rd[len..];
    Ok(v)
}

/// Read a msgpack bin as a `serde_bytes::ByteBuf`.
#[inline]
pub fn read_bytes_as_bytebuf(rd: &mut &[u8]) -> Result<ByteBuf> {
    read_bytes(rd).map(ByteBuf::from)
}

/// Read a msgpack bin and verify it has exactly N bytes, returning a fixed array.
#[inline]
pub fn read_fixed_bytes<const N: usize>(rd: &mut &[u8]) -> Result<[u8; N]> {
    let len = rmp::decode::read_bin_len(rd)
        .map_err(|e| codec_err(format!("read_fixed_bytes bin_len: {e}")))? as usize;
    if len != N {
        return Err(codec_err(format!(
            "read_fixed_bytes: expected {N} bytes, got {len}"
        )));
    }
    if rd.len() < N {
        return Err(codec_err(format!(
            "read_fixed_bytes: need {N} bytes, have {}",
            rd.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&rd[..N]);
    *rd = &rd[N..];
    Ok(arr)
}

/// Read a 32-byte msgpack bin as an Address.
#[inline]
pub fn read_address(rd: &mut &[u8]) -> Result<Address> {
    let bytes: [u8; 32] = read_fixed_bytes(rd)?;
    Ok(Address(bytes))
}

// ── Nil helpers ────────────────────────────────────────────────

/// Peek at the next byte to check if it is nil (0xc0) without consuming.
#[inline]
pub fn is_nil(rd: &[u8]) -> bool {
    !rd.is_empty() && rd[0] == 0xc0
}

/// Consume a nil marker. Returns error if next byte is not nil.
#[inline]
#[allow(dead_code)]
pub fn read_nil(rd: &mut &[u8]) -> Result<()> {
    rmp::decode::read_nil(rd).map_err(|e| codec_err(format!("read_nil: {e}")))
}

/// If the next byte is nil (0xc0), consume it and return true. Otherwise return false.
#[inline]
pub fn try_read_nil(rd: &mut &[u8]) -> bool {
    if is_nil(rd) {
        *rd = &rd[1..];
        true
    } else {
        false
    }
}

// ── Optional / collection readers ──────────────────────────────

/// If the next value is nil, return None. Otherwise call `decode_fn` and wrap in Some.
#[inline]
pub fn read_optional<T>(
    rd: &mut &[u8],
    decode_fn: impl FnOnce(&mut &[u8]) -> Result<T>,
) -> Result<Option<T>> {
    if try_read_nil(rd) {
        Ok(None)
    } else {
        decode_fn(rd).map(Some)
    }
}

/// Read a msgpack array header then call `decode_fn` for each element.
#[inline]
pub fn read_vec<T>(rd: &mut &[u8], decode_fn: impl Fn(&mut &[u8]) -> Result<T>) -> Result<Vec<T>> {
    let len = rmp::decode::read_array_len(rd)
        .map_err(|e| codec_err(format!("read_vec array_len: {e}")))? as usize;
    let mut v = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        v.push(decode_fn(rd)?);
    }
    Ok(v)
}

/// If nil, return None; otherwise read as a Vec<T>.
#[inline]
pub fn read_optional_vec<T>(
    rd: &mut &[u8],
    decode_fn: impl Fn(&mut &[u8]) -> Result<T>,
) -> Result<Option<Vec<T>>> {
    if try_read_nil(rd) {
        Ok(None)
    } else {
        read_vec(rd, decode_fn).map(Some)
    }
}

/// Read an rmpv::Value from the reader (for opaque passthrough fields like eval_delta).
#[inline]
pub fn read_rmpv_value(rd: &mut &[u8]) -> Result<rmpv::Value> {
    rmpv::decode::read_value(rd).map_err(|e| codec_err(format!("read_rmpv_value: {e}")))
}

/// Read an optional rmpv::Value. If nil, return None.
#[inline]
pub fn read_optional_rmpv(rd: &mut &[u8]) -> Result<Option<rmpv::Value>> {
    if try_read_nil(rd) {
        Ok(None)
    } else {
        read_rmpv_value(rd).map(Some)
    }
}

/// Read a BTreeMap<u64, T> from a msgpack map where keys are integers.
#[inline]
pub fn read_u64_map<T>(
    rd: &mut &[u8],
    decode_fn: impl Fn(&mut &[u8]) -> Result<T>,
) -> Result<std::collections::BTreeMap<u64, T>> {
    let len = read_map_len(rd)?;
    let mut map = std::collections::BTreeMap::new();
    for _ in 0..len {
        let key = read_u64(rd)?;
        let value = decode_fn(rd)?;
        map.insert(key, value);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_nil() {
        let data = [0xc0]; // nil
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_fixint() {
        let data = [0x05]; // fixint 5
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_negfixint() {
        let data = [0xff]; // fixneg -1
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_string() {
        // fixstr "hi" = 0xa2 0x68 0x69
        let data = [0xa2, 0x68, 0x69];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_map() {
        // fixmap(1) { fixstr("a"): fixint(1) } = 0x81 0xa1 0x61 0x01
        let data = [0x81, 0xa1, 0x61, 0x01];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_array() {
        // fixarray(2) [fixint 1, fixint 2] = 0x92 0x01 0x02
        let data = [0x92, 0x01, 0x02];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_read_u64_fixint() {
        let data = [42u8];
        let mut rd = &data[..];
        assert_eq!(read_u64(&mut rd).unwrap(), 42);
    }

    #[test]
    fn test_read_u64_from_u16() {
        // u16 marker=0xcd, value=0x01 0x00 = 256
        let data = [0xcd, 0x01, 0x00];
        let mut rd = &data[..];
        assert_eq!(read_u64(&mut rd).unwrap(), 256);
    }

    #[test]
    fn test_read_i64_negative() {
        // negative fixint -5 = 0xfb
        let data = [0xfb];
        let mut rd = &data[..];
        assert_eq!(read_i64(&mut rd).unwrap(), -5);
    }

    #[test]
    fn test_read_string() {
        // fixstr "pay" = 0xa3 p a y
        let data = [0xa3, b'p', b'a', b'y'];
        let mut rd = &data[..];
        assert_eq!(read_string(&mut rd).unwrap(), "pay");
    }

    #[test]
    fn test_read_key_bytes() {
        // fixstr "fee" = 0xa3 f e e
        let data = [0xa3, b'f', b'e', b'e'];
        let mut rd = &data[..];
        assert_eq!(read_key_bytes(&mut rd).unwrap(), b"fee");
    }

    #[test]
    fn test_read_bytes() {
        // bin8 with 3 bytes
        let data = [0xc4, 0x03, 0x01, 0x02, 0x03];
        let mut rd = &data[..];
        assert_eq!(read_bytes(&mut rd).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_read_fixed_bytes_32() {
        let mut data = vec![0xc4, 32]; // bin8, len=32
        data.extend_from_slice(&[0xAA; 32]);
        let mut rd = &data[..];
        let result: [u8; 32] = read_fixed_bytes(&mut rd).unwrap();
        assert_eq!(result, [0xAA; 32]);
    }

    #[test]
    fn test_read_address() {
        let mut data = vec![0xc4, 32]; // bin8, len=32
        data.extend_from_slice(&[0x42; 32]);
        let mut rd = &data[..];
        let addr = read_address(&mut rd).unwrap();
        assert_eq!(addr.0, [0x42; 32]);
    }

    #[test]
    fn test_try_read_nil() {
        let data = [0xc0, 0x05]; // nil, then fixint 5
        let mut rd = &data[..];
        assert!(try_read_nil(&mut rd));
        assert_eq!(rd.len(), 1);
        assert!(!try_read_nil(&mut rd));
        assert_eq!(rd.len(), 1); // didn't consume non-nil
    }

    #[test]
    fn test_read_optional_some() {
        let data = [42u8]; // fixint 42
        let mut rd = &data[..];
        let result = read_optional(&mut rd, read_u64).unwrap();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_read_optional_none() {
        let data = [0xc0]; // nil
        let mut rd = &data[..];
        let result = read_optional(&mut rd, read_u64).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_read_vec_u64() {
        // fixarray(3) [1, 2, 3]
        let data = [0x93, 0x01, 0x02, 0x03];
        let mut rd = &data[..];
        let result = read_vec(&mut rd, read_u64).unwrap();
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_read_bool_true() {
        let data = [0xc3]; // true
        let mut rd = &data[..];
        assert!(read_bool(&mut rd).unwrap());
    }

    #[test]
    fn test_read_bool_false() {
        let data = [0xc2]; // false
        let mut rd = &data[..];
        assert!(!read_bool(&mut rd).unwrap());
    }

    #[test]
    fn test_skip_nested_map() {
        // fixmap(1) { fixstr("k"): fixmap(1) { fixstr("n"): fixint(1) } }
        // 0x81 0xa1 0x6b 0x81 0xa1 0x6e 0x01
        let data = [0x81, 0xa1, 0x6b, 0x81, 0xa1, 0x6e, 0x01];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_bool() {
        let data = [0xc3]; // true
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_u8() {
        let data = [0xcc, 0xff]; // u8 255
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_u64() {
        // u64 marker + 8 bytes
        let data = [0xcf, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_bin8() {
        // bin8 with 4 bytes
        let data = [0xc4, 0x04, 0x01, 0x02, 0x03, 0x04];
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_f32() {
        let data = [0xca, 0x40, 0x48, 0xf5, 0xc3]; // f32 3.14
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_skip_f64() {
        let data = [0xcb, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18]; // f64 pi
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn test_read_u32_ok() {
        let data = [0xce, 0x00, 0x01, 0x00, 0x00]; // u32 65536
        let mut rd = &data[..];
        assert_eq!(read_u32(&mut rd).unwrap(), 65536);
    }

    #[test]
    fn test_read_u16_ok() {
        let data = [0xcd, 0x01, 0x00]; // u16 256
        let mut rd = &data[..];
        assert_eq!(read_u16(&mut rd).unwrap(), 256);
    }

    #[test]
    fn test_read_u8_val_ok() {
        let data = [0xcc, 0xff]; // u8 255
        let mut rd = &data[..];
        assert_eq!(read_u8_val(&mut rd).unwrap(), 255);
    }

    #[test]
    fn test_read_map_len_fixmap() {
        let data = [0x83]; // fixmap(3)
        let mut rd = &data[..];
        assert_eq!(read_map_len(&mut rd).unwrap(), 3);
    }

    #[test]
    fn test_read_optional_vec_nil() {
        let data = [0xc0]; // nil
        let mut rd = &data[..];
        let result: Option<Vec<u64>> = read_optional_vec(&mut rd, read_u64).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_read_optional_vec_some() {
        // fixarray(2) [1, 2]
        let data = [0x92, 0x01, 0x02];
        let mut rd = &data[..];
        let result: Option<Vec<u64>> = read_optional_vec(&mut rd, read_u64).unwrap();
        assert_eq!(result, Some(vec![1, 2]));
    }

    // ── go-algorand v4.7.2-stable msgpack decode nesting depth cap ─────
    //
    // Builds `wrappers` nested fixarray(1) markers (0x91) around a single
    // scalar leaf (fixint 0). The leaf value sits at nesting depth
    // `wrappers + 1`, so `wrappers = MAX_MSGPACK_DECODE_DEPTH - 1` is the
    // deepest payload that still stays within the 255-level bound, and
    // `wrappers = MAX_MSGPACK_DECODE_DEPTH` is the shallowest one that
    // exceeds it.
    fn nested_fixarray_payload(wrappers: usize) -> Vec<u8> {
        let mut buf = vec![0x91u8; wrappers];
        buf.push(0x00); // fixint 0 leaf
        buf
    }

    #[test]
    fn skip_value_accepts_payload_at_max_depth() {
        let data = nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH - 1);
        let mut rd = &data[..];
        skip_value(&mut rd).unwrap();
        assert!(rd.is_empty());
    }

    #[test]
    fn skip_value_rejects_payload_exceeding_max_depth() {
        let data = nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH);
        let mut rd = &data[..];
        let err = skip_value(&mut rd).unwrap_err();
        let msg = std::error::Error::source(&err)
            .map(|s| s.to_string())
            .unwrap_or_default();
        assert!(msg.to_lowercase().contains("depth"), "got: {msg}");
    }

    #[test]
    fn skip_value_does_not_stack_overflow_on_very_deep_payload() {
        // Two orders of magnitude past the bound — would overflow a naive
        // recursive skip; the iterative implementation must still return a
        // clean error rather than crash the test process.
        let data = nested_fixarray_payload(50_000);
        let mut rd = &data[..];
        assert!(skip_value(&mut rd).is_err());
    }

    #[test]
    fn check_msgpack_depth_matches_skip_value_at_the_boundary() {
        assert!(
            check_msgpack_depth(&nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH - 1)).is_ok()
        );
        assert!(check_msgpack_depth(&nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH)).is_err());
    }

    #[test]
    fn skip_value_via_unknown_field_rejects_deep_nesting() {
        // Integration check: an unrecognized Transaction field (the fast
        // decoder's `_ => skip_value(rd)?` arm) whose value is a
        // maliciously deep structure must be rejected, not just a
        // top-level payload passed straight to skip_value/check_msgpack_depth.
        use crate::Transaction;

        let mut buf = Vec::new();
        rmp::encode::write_map_len(&mut buf, 3).unwrap();
        rmp::encode::write_str(&mut buf, "type").unwrap();
        rmp::encode::write_str(&mut buf, "pay").unwrap();
        rmp::encode::write_str(&mut buf, "snd").unwrap();
        rmp::encode::write_bin(&mut buf, &[7u8; 32]).unwrap();
        rmp::encode::write_str(&mut buf, "zzz_unknown_field").unwrap();
        buf.extend(nested_fixarray_payload(MAX_MSGPACK_DECODE_DEPTH));

        let mut rd = &buf[..];
        let err = Transaction::decode_from_reader(&mut rd).unwrap_err();
        assert!(
            format!("{err}").to_lowercase().contains("depth")
                || std::error::Error::source(&err)
                    .map(|s| s.to_string().to_lowercase().contains("depth"))
                    .unwrap_or(false),
            "got: {err}"
        );
    }
}
