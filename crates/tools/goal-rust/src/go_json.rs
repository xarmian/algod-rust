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

//! How go's `goal` reads the genesis ID out of `<dd>/genesis.json`:
//! `libgoal` `GenesisID` → `nodecontrol` `GetGenesis` →
//! `protocol.DecodeJSON(text, &bookkeeping.Genesis{})`, i.e. go-codec's
//! (`github.com/algorand/go-codec/codec` v1.1.10) JSON decoder with
//! `protocol.JSONHandle` (`ErrorIfNoField`), issue #2449.
//!
//! The decoder below is a port of the parts of that decoder the `Genesis`
//! struct reaches (`json.go` `jsonDecDriver`, the bytes reader, `decode.go`
//! `kStruct` / `kSlice`), so a malformed file fails with go's text (`EOF`,
//! `json decode error [pos N]: ...`) and the inputs go accepts are accepted
//! too: trailing bytes after the value, a struct written as an array, numbers
//! and literals where a string field is expected, `null` fields.
//!
//! An allocation's `state` is decoded as go decodes a
//! `bookkeeping.GenesisAccountData` (issue #2455): unknown fields fail,
//! `onl` (`basics.Status`) is a `kUint8` with its overflow check, `algo`
//! (`MicroAlgos`' `CodecDecodeSelf`), `voteFst` / `voteLst` and `voteKD`
//! are `DecodeUint64`, and `vote` / `sel` (`[32]byte`) and `stprf`
//! (`[64]byte`) are `kSlice` of an array: a string is base64 (`DecodeBytes`,
//! go's `encoding/base64` errors, no length check), a JSON array or map holds
//! the bytes (`kUint8` each, `ErrorIfNoArrayExpand` past the length).

/// go-codec's `decDefMaxDepth`.
const MAX_DEPTH: usize = 1024;

/// `GenesisAccountData` fields in source order.
const ACCOUNT_FIELDS: [&str; 8] = [
    "onl", "algo", "vote", "stprf", "sel", "voteFst", "voteLst", "voteKD",
];

/// `Genesis` fields in source order (`kStruct` array form), by codec name.
const GENESIS_FIELDS: [&str; 9] = [
    "id",
    "network",
    "proto",
    "alloc",
    "rwd",
    "fees",
    "timestamp",
    "comment",
    "devmode",
];

/// `GenesisAllocation` fields in source order.
const ALLOC_FIELDS: [&str; 3] = ["addr", "comment", "state"];

/// A go-codec panic: `io.EOF` bubbles up bare, everything else is wrapped
/// with the read position as `json decode error [pos N]: <msg>`.
#[derive(Debug)]
enum Fail {
    Eof,
    Msg(String),
}

type R<T> = Result<T, Fail>;

/// go-codec's `containerState` (only equality with these matters).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctr {
    None,
    MapStart,
    MapKey,
    MapValue,
    MapEnd,
    ArrayStart,
    ArrayElem,
    ArrayEnd,
}

/// go-codec's `valueType`, numbered as in `helper.go`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueType {
    Unset = 0,
    Nil = 1,
    String = 6,
    Map = 9,
    Array = 10,
}

struct Dec<'a> {
    b: &'a [u8],
    c: usize,
    tok: u8,
    state: Ctr,
    depth: usize,
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn is_num(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'e' | b'E' | b'.' | b'+' | b'-')
}

/// go's `%c` of a byte: the rune with that code point.
fn ch(b: u8) -> char {
    char::from(b)
}

/// go's `%s` of bytes, as goal prints it (each invalid byte one U+FFFD).
fn lossy(b: &[u8]) -> String {
    algo_types::raw_text::go_lossy(b)
}

impl<'a> Dec<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self {
            b,
            c: 0,
            tok: 0,
            state: Ctr::None,
            depth: 0,
        }
    }

    fn err(&self, msg: impl Into<String>) -> Fail {
        Fail::Msg(format!(
            "json decode error [pos {}]: {}",
            self.c,
            msg.into()
        ))
    }

    fn depth_incr(&mut self) -> R<()> {
        self.depth += 1;
        if self.depth >= MAX_DEPTH {
            return Err(self.err("maximum decoding depth exceeded"));
        }
        Ok(())
    }

    fn depth_decr(&mut self) {
        self.depth -= 1;
    }

    // ---- bytesDecReader ------------------------------------------------

    fn skip_ws(&mut self) -> R<u8> {
        let mut i = self.c;
        while i < self.b.len() {
            let t = self.b[i];
            i += 1;
            if !is_ws(t) {
                self.c = i;
                return Ok(t);
            }
        }
        Err(Fail::Eof)
    }

    fn readn1(&mut self) -> R<u8> {
        if self.c == self.b.len() {
            return Err(Fail::Eof);
        }
        let v = self.b[self.c];
        self.c += 1;
        Ok(v)
    }

    fn unreadn1(&mut self) -> R<()> {
        if self.c == 0 || self.b.is_empty() {
            return Err(self.err("cannot unread last byte read"));
        }
        self.c -= 1;
        Ok(())
    }

    fn readx(&mut self, n: usize) -> R<&'a [u8]> {
        self.c += n;
        if self.c > self.b.len() {
            self.c = self.b.len();
            return Err(Fail::Eof);
        }
        Ok(&self.b[self.c - n..self.c])
    }

    /// The bytes up to and including `stop`; returns the start offset too, so
    /// the caller can see the bytes behind the slice as go's slicing can.
    fn read_until(&mut self, stop: u8) -> R<(usize, &'a [u8])> {
        let start = self.c;
        match self.b[start..].iter().position(|&x| x == stop) {
            Some(off) => {
                self.c = start + off + 1;
                Ok((start, &self.b[start..self.c]))
            }
            None => Err(Fail::Eof),
        }
    }

    fn read_to_num(&mut self) -> R<&'a [u8]> {
        let start = self.c;
        if start == self.b.len() {
            return Err(Fail::Eof);
        }
        let mut i = start;
        while i < self.b.len() && is_num(self.b[i]) {
            i += 1;
        }
        self.c = i;
        Ok(&self.b[start..i])
    }

    // ---- jsonDecDriver -------------------------------------------------

    fn ensure_tok(&mut self) -> R<()> {
        if self.tok == 0 {
            self.tok = self.skip_ws()?;
        }
        Ok(())
    }

    fn expect(&mut self, what: &str, xc: u8, next: Ctr) -> R<()> {
        self.ensure_tok()?;
        if self.tok != xc {
            return Err(self.err(format!(
                "{what} - expect char '{}' but got char '{}'",
                ch(xc),
                ch(self.tok)
            )));
        }
        self.tok = 0;
        self.state = next;
        Ok(())
    }

    fn read_map_start(&mut self) -> R<()> {
        self.expect("read map", b'{', Ctr::MapStart)
    }

    fn read_array_start(&mut self) -> R<()> {
        self.expect("read array", b'[', Ctr::ArrayStart)
    }

    fn read_map_end(&mut self) -> R<()> {
        self.expect("read map end", b'}', Ctr::MapEnd)
    }

    fn read_array_end(&mut self) -> R<()> {
        self.expect("read array end", b']', Ctr::ArrayEnd)
    }

    fn read_map_elem_value(&mut self) -> R<()> {
        self.expect("read map value", b':', Ctr::MapValue)
    }

    fn read_array_elem(&mut self) -> R<()> {
        self.ensure_tok()?;
        if self.state != Ctr::ArrayStart {
            if self.tok != b',' {
                return Err(self.err(format!(
                    "read array element - expect char ',' but got char '{}'",
                    ch(self.tok)
                )));
            }
            self.tok = 0;
        }
        self.state = Ctr::ArrayElem;
        Ok(())
    }

    fn read_map_elem_key(&mut self) -> R<()> {
        self.ensure_tok()?;
        if self.state != Ctr::MapStart {
            if self.tok != b',' {
                return Err(self.err(format!(
                    "read map key - expect char ',' but got char '{}'",
                    ch(self.tok)
                )));
            }
            self.tok = 0;
        }
        self.state = Ctr::MapKey;
        Ok(())
    }

    fn check_break(&mut self) -> R<bool> {
        self.ensure_tok()?;
        Ok(self.tok == b'}' || self.tok == b']')
    }

    /// `readLit4True` / `readLit4False` / `readLit4Null`: the rest of the
    /// literal after its first byte.
    fn read_lit(&mut self, rest: &[u8]) -> R<()> {
        let bs = self.readx(rest.len())?;
        self.tok = 0;
        if bs != rest {
            return Err(self.err(format!("expecting {}: got {}", lossy(rest), lossy(bs))));
        }
        Ok(())
    }

    fn try_decode_as_nil(&mut self) -> R<bool> {
        self.ensure_tok()?;
        if self.tok == b'n' {
            self.read_lit(b"ull")?;
            return Ok(true);
        }
        Ok(false)
    }

    fn container_type(&mut self) -> R<ValueType> {
        self.ensure_tok()?;
        Ok(match self.tok {
            b'{' => ValueType::Map,
            b'[' => ValueType::Array,
            b'n' => ValueType::Nil,
            b'"' => ValueType::String,
            _ => ValueType::Unset,
        })
    }

    fn decode_bool(&mut self) -> R<bool> {
        self.ensure_tok()?;
        let fquot = self.state == Ctr::MapKey && self.tok == b'"';
        if fquot {
            self.tok = self.readn1()?;
        }
        let v = match self.tok {
            b'f' => {
                self.read_lit(b"alse")?;
                false
            }
            b't' => {
                self.read_lit(b"rue")?;
                true
            }
            t => return Err(self.err(format!("decode bool: got first char {}", ch(t)))),
        };
        if fquot {
            self.readn1()?;
        }
        Ok(v)
    }

    fn dec_num_bytes(&mut self) -> R<&'a [u8]> {
        self.ensure_tok()?;
        let bs = if self.tok == b'"' {
            let (_, bs) = self.read_until(b'"')?;
            &bs[..bs.len() - 1]
        } else {
            self.unreadn1()?;
            self.read_to_num()?
        };
        self.tok = 0;
        Ok(bs)
    }

    fn dec_u64_via_float(&self, s: &[u8]) -> R<u64> {
        if s.is_empty() {
            return Ok(0);
        }
        let text = lossy(s);
        let Ok(f) = go_parse_float(s) else {
            return Err(self.err(format!("invalid syntax for integer: {text}")));
        };
        // `math.Modf`: `fract` of an infinity is NaN, like go's.
        let (fi, ff) = (f.trunc(), f.fract());
        if ff > 0.0 {
            return Err(self.err(format!("fractional part found parsing integer: {text}")));
        } else if fi > u64::MAX as f64 {
            return Err(self.err(format!("overflow parsing integer: {text}")));
        }
        Ok(go_f64_to_u64(fi))
    }

    /// `DecodeUint64`.
    fn decode_uint64(&mut self) -> R<u64> {
        let bs = self.dec_num_bytes()?;
        if bs.is_empty() {
            return Ok(0);
        }
        let (n, neg, bad, overflow) = parse_integer(bs);
        if overflow {
            Err(self.err(format!("overflow parsing unsigned integer: {}", lossy(bs))))
        } else if neg {
            Err(self.err(format!(
                "minus found parsing unsigned integer: {}",
                lossy(bs)
            )))
        } else if bad {
            self.dec_u64_via_float(bs)
        } else {
            Ok(n)
        }
    }

    /// `kUint8`: `DecodeUint64` and `chkOvf.UintV(v, 8)`.
    fn decode_uint8(&mut self) -> R<()> {
        let v = self.decode_uint64()?;
        if v > u64::from(u8::MAX) {
            return Err(self.err(format!("uint64 overflow: {v}")));
        }
        Ok(())
    }

    fn decode_int64(&mut self) -> R<i64> {
        const CUTOFF: u64 = 1 << 63;
        let bs = self.dec_num_bytes()?;
        if bs.is_empty() {
            return Ok(0);
        }
        let shown = lossy(bs);
        let (mut n, neg, bad, overflow) = parse_integer(bs);
        if overflow {
            return Err(self.err(format!("overflow parsing integer: {shown}")));
        } else if bad {
            n = self.dec_u64_via_float(if neg { &bs[1..] } else { bs })?;
        }
        if neg {
            if n > CUTOFF {
                return Err(self.err(format!("overflow parsing integer: {shown}")));
            }
            Ok((n as i64).wrapping_neg())
        } else {
            if n >= CUTOFF {
                return Err(self.err(format!("overflow parsing integer: {shown}")));
            }
            Ok(n as i64)
        }
    }

    /// `appendStringAsBytes`.
    fn decode_string(&mut self) -> R<Vec<u8>> {
        self.ensure_tok()?;
        if self.tok != b'"' {
            return match self.tok {
                b'n' => {
                    self.read_lit(b"ull")?;
                    Ok(Vec::new())
                }
                b'f' => {
                    self.read_lit(b"alse")?;
                    Ok(b"false".to_vec())
                }
                b't' => {
                    self.read_lit(b"rue")?;
                    Ok(b"true".to_vec())
                }
                _ => Ok(self.dec_num_bytes()?.to_vec()),
            };
        }
        self.tok = 0;
        let (mut start, mut cs) = self.read_until(b'"')?;
        let mut v = Vec::new();
        let (mut i, mut cursor) = (0usize, 0usize);
        loop {
            if i == cs.len() {
                v.extend_from_slice(&cs[cursor..]);
                (start, cs) = self.read_until(b'"')?;
                i = 0;
                cursor = 0;
            }
            // A `\u` escape cut short by the closing quote steps past the
            // chunk, where go's `cs[i]` panics.
            if i > cs.len() {
                return Err(self.err(format!(
                    "runtime error: index out of range [{i}] with length {}",
                    cs.len()
                )));
            }
            let c = cs[i];
            if c == b'"' {
                v.extend_from_slice(&cs[cursor..i]);
                break;
            }
            if c != b'\\' {
                i += 1;
                continue;
            }
            v.extend_from_slice(&cs[cursor..i]);
            i += 1;
            let c = cs[i];
            match c {
                b'"' | b'\\' | b'/' | b'\'' => v.push(c),
                b'b' => v.push(0x08),
                b'f' => v.push(0x0c),
                b'n' => v.push(b'\n'),
                b'r' => v.push(b'\r'),
                b't' => v.push(b'\t'),
                b'u' => {
                    let r = self.unicode_escape(start, cs.len(), &mut i)?;
                    let mut buf = [0u8; 4];
                    v.extend_from_slice(r.encode_utf8(&mut buf).as_bytes());
                }
                _ => return Err(self.err(format!("unsupported escaped value: {}", ch(c)))),
            }
            i += 1;
            cursor = i;
        }
        Ok(v)
    }

    /// The `case 'u'` branch of `appendStringAsBytes`, `i` at the `u`. go
    /// slices the string chunk past its end, into the rest of the input and
    /// then the zeroed spare capacity `os.ReadFile` leaves behind the file
    /// (at least one byte, which is all these slices can reach), so this
    /// reads the whole input and zeros after it.
    fn unicode_escape(&self, start: usize, cslen: usize, i: &mut usize) -> R<char> {
        let at = |k: usize| self.b.get(start + k).copied().unwrap_or(0);
        if cslen < *i + 4 {
            return Err(self.err("need at least 4 more bytes for unicode sequence"));
        }
        let mut rr: u32 = 0;
        for k in *i + 1..*i + 5 {
            match hex(at(k)) {
                Some(h) => rr = rr * 16 + h,
                None => {
                    *i += 4;
                    return Ok(char::REPLACEMENT_CHARACTER);
                }
            }
        }
        *i += 4;
        if (0xd800..0xe000).contains(&rr) {
            if cslen >= *i + 6 {
                // `cs[i+1:][:6:6]`
                let base = *i + 1;
                if at(base) == b'\\' && at(base + 1) == b'u' {
                    *i += 2;
                    for j in 2..6 {
                        if hex(at(base + j)).is_none() {
                            *i += 4;
                            return Ok(char::REPLACEMENT_CHARACTER);
                        }
                    }
                    // go accumulates the second half into the wrong variable,
                    // so `utf16.DecodeRune(r, 0)` is always U+FFFD.
                    *i += 4;
                    return Ok(char::REPLACEMENT_CHARACTER);
                }
            }
            return Ok(char::REPLACEMENT_CHARACTER);
        }
        Ok(char::from_u32(rr).unwrap_or(char::REPLACEMENT_CHARACTER))
    }

    /// `kStruct` for a struct whose fields are `fields`; `field` decodes the
    /// value of field `k` (the `TryDecodeAsNil` check is done here).
    fn decode_struct(
        &mut self,
        fields: &[&str],
        field: &mut dyn FnMut(&mut Self, usize) -> R<()>,
    ) -> R<()> {
        match self.container_type()? {
            ValueType::Map => {
                self.read_map_start()?;
                self.depth_incr()?;
                while !self.check_break()? {
                    self.read_map_elem_key()?;
                    let key = self.decode_string()?;
                    self.read_map_elem_value()?;
                    match fields.iter().position(|f| f.as_bytes() == key.as_slice()) {
                        Some(k) => {
                            if !self.try_decode_as_nil()? {
                                field(self, k)?;
                            }
                        }
                        None => {
                            return Err(self.err(format!(
                            "no matching struct field found when decoding stream map with key {}",
                            lossy(&key)
                        )))
                        }
                    }
                }
                self.read_map_end()?;
                self.depth_decr();
            }
            ValueType::Array => {
                self.read_array_start()?;
                self.depth_incr()?;
                let mut broke = false;
                for k in 0..fields.len() {
                    if self.check_break()? {
                        broke = true;
                        break;
                    }
                    self.read_array_elem()?;
                    if !self.try_decode_as_nil()? {
                        field(self, k)?;
                    }
                }
                // Values past the last field: the first one fails (`ErrorIfNoField`).
                if !broke && !self.check_break()? {
                    self.read_array_elem()?;
                    return Err(self.err(format!(
                        "no matching struct field found when decoding stream array at index {}",
                        fields.len()
                    )));
                }
                self.read_array_end()?;
                self.depth_decr();
            }
            _ => {
                return Err(self.err("only encoded map or array can be decoded into a struct"));
            }
        }
        Ok(())
    }

    /// The container part of `kSlice` (`decSliceHelperStart` on): a JSON
    /// array or map (keys and values alternate, `ElemContainerState(j)`),
    /// `elem` decoding element `j` once `TryDecodeAsNil` is false. A fixed
    /// array of `len` elements fails past it (`ErrorIfNoArrayExpand`).
    fn decode_seq(
        &mut self,
        ctyp: ValueType,
        len: Option<usize>,
        elem: &mut dyn FnMut(&mut Self) -> R<()>,
    ) -> R<()> {
        let array = match ctyp {
            ValueType::Array => {
                self.read_array_start()?;
                true
            }
            ValueType::Map => {
                self.read_map_start()?;
                false
            }
            other => {
                return Err(self.err(format!(
                    "only encoded map or array can be decoded into a slice ({})",
                    other as u8
                )))
            }
        };
        self.depth_incr()?;
        let mut j = 0usize;
        while !self.check_break()? {
            if array {
                self.read_array_elem()?;
            } else if j.is_multiple_of(2) {
                self.read_map_elem_key()?;
            } else {
                self.read_map_elem_value()?;
            }
            let nil = self.try_decode_as_nil()?;
            if let Some(len) = len {
                if j >= len {
                    return Err(self.err(format!(
                        "cannot expand array len during decode from {len} to {}",
                        j + 1
                    )));
                }
            }
            if !nil {
                elem(self)?;
            }
            j += 1;
        }
        if array {
            self.read_array_end()?;
        } else {
            self.read_map_end()?;
        }
        self.depth_decr();
        Ok(())
    }

    /// `kSlice` for `[]GenesisAllocation`.
    fn decode_alloc(&mut self) -> R<()> {
        let ctyp = self.container_type()?;
        if ctyp == ValueType::String {
            return Err(self.err(
                "bytes/string in stream must decode into slice/array of bytes, not []bookkeeping.GenesisAllocation",
            ));
        }
        self.decode_seq(ctyp, None, &mut |d| {
            d.decode_struct(&ALLOC_FIELDS, &mut |d, k| match k {
                2 => d.decode_account_data(),
                _ => d.decode_string().map(|_| ()),
            })
        })
    }

    /// `kStruct` for `GenesisAccountData`.
    fn decode_account_data(&mut self) -> R<()> {
        self.decode_struct(&ACCOUNT_FIELDS, &mut |d, k| match k {
            0 => d.decode_uint8(),
            2 | 4 => d.decode_byte_array(32),
            3 => d.decode_byte_array(64),
            _ => d.decode_uint64().map(|_| ()),
        })
    }

    /// `kSlice` for a `[len]byte` (the array's `codecFnInfo`, `seqTypeArray`):
    /// a string is base64 (`DecodeBytes`; a short or long value is copied
    /// as far as it goes, no error), an array or map holds `kUint8` elements.
    fn decode_byte_array(&mut self, len: usize) -> R<()> {
        let ctyp = self.container_type()?;
        if ctyp == ValueType::String {
            let bs = self.decode_string()?;
            if !bs.is_empty() {
                if let Err(at) = go_base64_check(&bs) {
                    return Err(self.err(format!(
                        "error decoding base64 binary '{}': illegal base64 data at input byte {at}",
                        lossy(&bs)
                    )));
                }
            }
            return Ok(());
        }
        self.decode_seq(ctyp, Some(len), &mut |d| d.decode_uint8())
    }
}

/// go's `base64.StdEncoding.Decode` of `src`, only for its error: the
/// `CorruptInputError` offset. `\r` and `\n` are skipped; the fast paths of
/// `Decode` only take whole valid quanta, so `decodeQuantum` alone decides.
pub(crate) fn go_base64_check(src: &[u8]) -> Result<(), usize> {
    let valid = |c: u8| c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
    let skip_nl = |mut si: usize| {
        while si < src.len() && (src[si] == b'\n' || src[si] == b'\r') {
            si += 1;
        }
        si
    };
    let mut si = 0;
    while si < src.len() {
        // `decodeQuantum`
        let mut j = 0usize;
        while j < 4 {
            if si == src.len() {
                if j == 0 {
                    break;
                }
                return Err(si - j);
            }
            let c = src[si];
            si += 1;
            if valid(c) {
                j += 1;
                continue;
            }
            if c == b'\n' || c == b'\r' {
                continue;
            }
            if c != b'=' {
                return Err(si - 1);
            }
            match j {
                0 | 1 => return Err(si - 1),
                2 => {
                    si = skip_nl(si);
                    if si == src.len() {
                        return Err(src.len());
                    }
                    if src[si] != b'=' {
                        return Err(si - 1);
                    }
                    si += 1;
                }
                _ => {}
            }
            si = skip_nl(si);
            if si < src.len() {
                return Err(si);
            }
            break;
        }
    }
    Ok(())
}

/// go's `uint64(f)` on amd64: below 2^63 `CVTTSD2SQ`, else `CVTTSD2SQ(f -
/// 2^63) | 1<<63`; an out-of-range or NaN conversion gives `1<<63`.
fn go_f64_to_u64(f: f64) -> u64 {
    const TWO63: f64 = 9_223_372_036_854_775_808.0;
    let cvtt = |x: f64| -> u64 {
        if x.is_nan() || !(-TWO63..TWO63).contains(&x) {
            1 << 63
        } else {
            x as i64 as u64
        }
    };
    if f < TWO63 {
        cvtt(f)
    } else {
        cvtt(f - TWO63) | (1 << 63)
    }
}

/// go's `strconv.ParseFloat(s, 64)`: `Err` is `"invalid syntax"` or
/// `"value out of range"`. Decimal and hex (`0x...p...`) forms, `_` digit
/// separators (`underscoreOK`), `inf` / `infinity` with a sign and `nan`
/// without one, in any case.
fn go_parse_float(s: &[u8]) -> Result<f64, &'static str> {
    if let Some((f, n)) = go_float_special(s) {
        return if n == s.len() {
            Ok(f)
        } else {
            Err("invalid syntax")
        };
    }
    let Some(r) = go_read_float(s) else {
        return Err("invalid syntax");
    };
    if r.n != s.len() {
        return Err("invalid syntax");
    }
    let f = if r.hex {
        // `atofHex`; a truncated mantissa (16 hex digits read) keeps a
        // sticky low bit so the rounding to 53 bits is go's.
        let mut m = r.mantissa;
        if r.trunc {
            m |= 1;
        }
        let mut f = m as f64;
        let mut e = r.exp;
        while e != 0 && f != 0.0 && f.is_finite() {
            let step: i32 = e.clamp(-1000, 1000).try_into().unwrap_or(0);
            f *= 2f64.powi(step);
            e -= i64::from(step);
        }
        if r.neg {
            -f
        } else {
            f
        }
    } else {
        let text: String = s[..r.n]
            .iter()
            .filter(|&&c| c != b'_')
            .map(|&c| char::from(c))
            .collect();
        text.parse::<f64>().map_err(|_| "invalid syntax")?
    };
    if f.is_infinite() {
        return Err("value out of range");
    }
    Ok(f)
}

/// strconv's `special`: (value, bytes consumed).
fn go_float_special(s: &[u8]) -> Option<(f64, usize)> {
    let prefix = |s: &[u8], word: &[u8]| {
        s.iter()
            .zip(word)
            .take_while(|(a, b)| a.to_ascii_lowercase() == **b)
            .count()
    };
    let (sign, nsign, rest) = match s.first()? {
        b'+' => (1.0, 1, &s[1..]),
        b'-' => (-1.0, 1, &s[1..]),
        b'i' | b'I' => (1.0, 0, s),
        b'n' | b'N' => {
            return (prefix(s, b"nan") == 3).then_some((f64::NAN, 3));
        }
        _ => return None,
    };
    let mut n = prefix(rest, b"infinity");
    if 3 < n && n < 8 {
        n = 3;
    }
    (n == 3 || n == 8).then_some((sign * f64::INFINITY, nsign + n))
}

/// What strconv's `readFloat` read.
struct ReadFloat {
    mantissa: u64,
    exp: i64,
    neg: bool,
    trunc: bool,
    hex: bool,
    n: usize,
}

/// strconv's `readFloat`; `None` is its `ok == false`.
fn go_read_float(s: &[u8]) -> Option<ReadFloat> {
    let lower = |c: u8| c | 0x20;
    let mut underscores = false;
    let mut i = 0;
    let mut neg = false;
    match s.first()? {
        b'+' => i += 1,
        b'-' => {
            i += 1;
            neg = true;
        }
        _ => {}
    }
    let mut base: u64 = 10;
    let mut max_mant_digits = 19;
    let mut exp_char = b'e';
    let mut hex = false;
    if i + 2 < s.len() && s[i] == b'0' && lower(s[i + 1]) == b'x' {
        base = 16;
        max_mant_digits = 16;
        i += 2;
        exp_char = b'p';
        hex = true;
    }
    let (mut sawdot, mut sawdigits) = (false, false);
    let (mut nd, mut nd_mant, mut dp) = (0i64, 0i64, 0i64);
    let mut mantissa: u64 = 0;
    let mut trunc = false;
    while i < s.len() {
        let c = s[i];
        if c == b'_' {
            underscores = true;
        } else if c == b'.' {
            if sawdot {
                break;
            }
            sawdot = true;
            dp = nd;
        } else if c.is_ascii_digit() {
            sawdigits = true;
            if c == b'0' && nd == 0 {
                dp -= 1;
            } else {
                nd += 1;
                if nd_mant < max_mant_digits {
                    mantissa = mantissa * base + u64::from(c - b'0');
                    nd_mant += 1;
                } else if c != b'0' {
                    trunc = true;
                }
            }
        } else if base == 16 && (b'a'..=b'f').contains(&lower(c)) {
            sawdigits = true;
            nd += 1;
            if nd_mant < max_mant_digits {
                mantissa = mantissa * 16 + u64::from(lower(c) - b'a' + 10);
                nd_mant += 1;
            } else {
                trunc = true;
            }
        } else {
            break;
        }
        i += 1;
    }
    if !sawdigits {
        return None;
    }
    if !sawdot {
        dp = nd;
    }
    if base == 16 {
        dp *= 4;
        nd_mant *= 4;
    }
    if i < s.len() && lower(s[i]) == exp_char {
        i += 1;
        if i >= s.len() {
            return None;
        }
        let mut esign = 1;
        match s[i] {
            b'+' => i += 1,
            b'-' => {
                i += 1;
                esign = -1;
            }
            _ => {}
        }
        if i >= s.len() || !s[i].is_ascii_digit() {
            return None;
        }
        let mut e = 0i64;
        while i < s.len() && (s[i].is_ascii_digit() || s[i] == b'_') {
            if s[i] == b'_' {
                underscores = true;
            } else if e < 10000 {
                e = e * 10 + i64::from(s[i] - b'0');
            }
            i += 1;
        }
        dp += e * esign;
    } else if base == 16 {
        return None;
    }
    let exp = if mantissa != 0 { dp - nd_mant } else { 0 };
    if underscores && !go_underscore_ok(&s[..i]) {
        return None;
    }
    Some(ReadFloat {
        mantissa,
        exp,
        neg,
        trunc,
        hex,
        n: i,
    })
}

/// strconv's `underscoreOK`.
fn go_underscore_ok(s: &[u8]) -> bool {
    let lower = |c: u8| c | 0x20;
    let mut s = s;
    if let Some(b'-' | b'+') = s.first() {
        s = &s[1..];
    }
    let mut saw = b'^';
    let mut i = 0;
    let mut hex = false;
    if s.len() >= 2 && s[0] == b'0' && matches!(lower(s[1]), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = lower(s[1]) == b'x';
    }
    while i < s.len() {
        let c = s[i];
        if c.is_ascii_digit() || hex && (b'a'..=b'f').contains(&lower(c)) {
            saw = b'0';
        } else if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            if saw == b'_' {
                return false;
            }
            saw = b'!';
        }
        i += 1;
    }
    saw != b'_'
}

fn hex(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some(u32::from(c - b'0')),
        b'a'..=b'f' => Some(u32::from(c - b'a' + 10)),
        b'A'..=b'F' => Some(u32::from(c - b'A' + 10)),
        _ => None,
    }
}

/// `jsonParseInteger`: (n, neg, badSyntax, overflow).
fn parse_integer(s: &[u8]) -> (u64, bool, bool, bool) {
    const CUTOFF: u64 = u64::MAX / 10 + 1;
    let mut s = s;
    let mut neg = false;
    match s.first() {
        None => return (0, false, false, false),
        Some(b'+') => s = &s[1..],
        Some(b'-') => {
            s = &s[1..];
            neg = true;
        }
        _ => {}
    }
    let mut n: u64 = 0;
    for &c in s {
        if !c.is_ascii_digit() {
            return (n, neg, true, false);
        }
        if n >= CUTOFF {
            return (n, neg, false, true);
        }
        n *= 10;
        match n.checked_add(u64::from(c - b'0')) {
            Some(n1) => n = n1,
            None => return (n, neg, false, true),
        }
    }
    (n, neg, false, false)
}

/// The genesis ID (`<network>-<id>`) go's `goal` reads from a `genesis.json`
/// holding `text`, or go's error text.
pub fn decode_genesis_id(text: &[u8]) -> Result<String, String> {
    let mut d = Dec::new(text);
    let mut id = Vec::new();
    let mut network = Vec::new();
    let mut run = |d: &mut Dec<'_>| -> R<()> {
        if d.try_decode_as_nil()? {
            return Ok(());
        }
        d.decode_struct(&GENESIS_FIELDS, &mut |d, k| match k {
            0 => d.decode_string().map(|s| id = s),
            1 => d.decode_string().map(|s| network = s),
            3 => d.decode_alloc(),
            6 => d.decode_int64().map(|_| ()),
            8 => d.decode_bool().map(|_| ()),
            _ => d.decode_string().map(|_| ()),
        })
    };
    match run(&mut d) {
        Ok(()) => {}
        Err(Fail::Eof) => return Err("EOF".to_string()),
        Err(Fail::Msg(m)) => return Err(m),
    }
    Ok(format!(
        "{}-{}",
        String::from_utf8_lossy(&network),
        String::from_utf8_lossy(&id)
    ))
}

#[cfg(test)]
mod tests {
    use super::decode_genesis_id as gid;

    #[test]
    fn well_formed_genesis_gives_network_dash_id() {
        assert_eq!(
            gid(br#"{"id":"v1","network":"testnet","alloc":[{"addr":"A","comment":"c","state":{"algo":1}}],"timestamp":5,"devmode":true}"#),
            Ok("testnet-v1".to_string())
        );
    }

    #[test]
    fn go_leniencies_are_kept() {
        assert_eq!(gid(b"[]"), Ok("-".to_string()));
        assert_eq!(gid(br#"["v1","net"]"#), Ok("net-v1".to_string()));
        assert_eq!(gid(br#"{"network":1}"#), Ok("1-".to_string()));
        assert_eq!(
            gid(br#"{"id":"v1","network":"t"}x"#),
            Ok("t-v1".to_string())
        );
        assert_eq!(gid(b"null"), Ok("-".to_string()));
        assert_eq!(
            gid(br#"{"id":null,"network":true}"#),
            Ok("true-".to_string())
        );
    }

    #[test]
    fn syntax_errors_have_gos_text() {
        assert_eq!(gid(b""), Err("EOF".to_string()));
        assert_eq!(gid(b"{"), Err("EOF".to_string()));
        assert_eq!(
            gid(b"not json"),
            Err("json decode error [pos 4]: expecting ull: got ot ".to_string())
        );
        assert_eq!(
            gid(br#"{"x":1}"#),
            Err("json decode error [pos 5]: no matching struct field found when decoding stream map with key x".to_string())
        );
    }

    /// `state` is a `GenesisAccountData`; texts and positions from go goal
    /// v5.0.5-stable (`tests/fixtures/genesis_id_fail.jsonl`, issue #2455).
    #[test]
    fn alloc_state_decodes_like_go() {
        let state = |s: &str| gid(format!(r#"{{"alloc":[{{"state":{s}}}]}}"#).as_bytes());
        let err = |pos: usize, m: &str| Err(format!("json decode error [pos {pos}]: {m}"));
        for ok in [
            r#"{"onl":"255","algo":"5","voteLst":1e3,"voteKD":10000}"#,
            r#"{"onl":"0x1p4","voteFst":"1_0"}"#,
            r#"{"voteLst":1.8446744073709552e19}"#,
            r#"[1,2,"AAAA",null,[1,2],3,4,5]"#,
            r#"{"vote":"AAAA","sel":"","stprf":{"1":2}}"#,
            "null",
        ] {
            assert_eq!(state(ok), Ok("-".to_string()), "{ok}");
        }
        assert_eq!(
            state(r#"{"onl":1,"x":1}"#),
            err(
                32,
                "no matching struct field found when decoding stream map with key x"
            )
        );
        assert_eq!(
            state("[1,2,null,null,null,3,4,5,6]"),
            err(
                45,
                "no matching struct field found when decoding stream array at index 8"
            )
        );
        assert_eq!(state(r#"{"onl":256}"#), err(29, "uint64 overflow: 256"));
        assert_eq!(
            state(r#"{"onl":"NaN"}"#),
            err(31, "uint64 overflow: 9223372036854775808")
        );
        assert_eq!(state(r#"{"onl":"0x1p8"}"#), err(33, "uint64 overflow: 256"));
        assert_eq!(
            state(r#"{"algo":-1}"#),
            err(29, "minus found parsing unsigned integer: -1")
        );
        assert_eq!(
            state(r#"{"algo":"1e400"}"#),
            err(34, "invalid syntax for integer: 1e400")
        );
        assert_eq!(
            state(r#"{"algo":"Inf"}"#),
            err(32, "overflow parsing integer: Inf")
        );
        assert_eq!(
            state(r#"{"vote":"AA==AA"}"#),
            err(
                35,
                "error decoding base64 binary 'AA==AA': illegal base64 data at input byte 4"
            )
        );
        assert_eq!(
            state(r#"{"vote":1}"#),
            err(
                28,
                "only encoded map or array can be decoded into a slice (0)"
            )
        );
        let long = format!(r#"{{"vote":[{}null]}}"#, "0,".repeat(32));
        assert_eq!(
            state(&long),
            err(96, "cannot expand array len during decode from 32 to 33")
        );
    }

    #[test]
    fn go_parse_float_matches_strconv() {
        use super::go_parse_float as pf;
        assert_eq!(pf(b"1_0"), Ok(10.0));
        assert_eq!(pf(b"1_000.5"), Ok(1000.5));
        assert_eq!(pf(b"0x_1p4"), Ok(16.0));
        assert_eq!(pf(b"0x1.8p1"), Ok(3.0));
        assert_eq!(pf(b"+Inf"), Ok(f64::INFINITY));
        assert!(pf(b"nan").unwrap().is_nan());
        for bad in [&b"0x1"[..], b"-nan", b"infin", b"1__0", b"_1", b"1_", b""] {
            assert_eq!(pf(bad), Err("invalid syntax"), "{bad:?}");
        }
        assert_eq!(pf(b"1e400"), Err("value out of range"));
        assert_eq!(pf(b"1e-400"), Ok(0.0));
        assert_eq!(super::go_f64_to_u64(-5.0), 18446744073709551611);
        assert_eq!(super::go_f64_to_u64(18446744073709551616.0), 1 << 63);
        assert_eq!(super::go_f64_to_u64(f64::NAN), 1 << 63);
    }

    #[test]
    fn base64_errors_are_gos_offsets() {
        use super::go_base64_check as b;
        assert_eq!(b(b"AAAA"), Ok(()));
        assert_eq!(b(b"AAAA\r\nAA=\n="), Ok(()));
        assert_eq!(b(b"!!!!"), Err(0));
        assert_eq!(b(b"AAA"), Err(0));
        assert_eq!(b(b"A==="), Err(1));
        assert_eq!(b(b"AA="), Err(3));
        assert_eq!(b(b"AA\nAA\r\n=="), Err(7));
        assert_eq!(b(b"AAAAAAAA*AAA"), Err(8));
    }
}
