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
//! `kStruct` / `kSlice` / `swallow`), so a malformed file fails with go's text
//! (`EOF`, `json decode error [pos N]: ...`) and the inputs go accepts are
//! accepted too: trailing bytes after the value, a struct written as an array,
//! numbers and literals where a string field is expected, `null` fields.
//!
//! Not ported: the field types inside an allocation's `state`
//! (`GenesisAccountData`), which is only checked for being well formed
//! (issue #2455).

/// go-codec's `decDefMaxDepth`.
const MAX_DEPTH: usize = 1024;

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
            return Err(self.err(format!(
                "expecting {}: got {}",
                String::from_utf8_lossy(rest),
                String::from_utf8_lossy(bs)
            )));
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
        let text = String::from_utf8_lossy(s);
        let f = match text.parse::<f64>() {
            Ok(f) if f.is_finite() => f,
            _ => return Err(self.err(format!("invalid syntax for integer: {text}"))),
        };
        let (fi, ff) = (f.trunc(), f.fract());
        if ff > 0.0 {
            return Err(self.err(format!("fractional part found parsing integer: {text}")));
        } else if fi > u64::MAX as f64 {
            return Err(self.err(format!("overflow parsing integer: {text}")));
        }
        Ok(fi as u64)
    }

    fn decode_int64(&mut self) -> R<i64> {
        const CUTOFF: u64 = 1 << 63;
        let bs = self.dec_num_bytes()?;
        if bs.is_empty() {
            return Ok(0);
        }
        let shown = String::from_utf8_lossy(bs).into_owned();
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

    /// `DecodeNaked` of a scalar (the `default` branch of `swallow`).
    fn decode_naked_scalar(&mut self) -> R<()> {
        self.ensure_tok()?;
        match self.tok {
            b'n' => self.read_lit(b"ull"),
            b'f' => self.read_lit(b"alse"),
            b't' => self.read_lit(b"rue"),
            b'{' | b'[' => Ok(()),
            b'"' => self.decode_string().map(|_| ()),
            _ => {
                let bs = self.dec_num_bytes()?;
                if bs.is_empty() {
                    return Err(self.err("decode number from empty string"));
                }
                let (_, _, bad, overflow) = parse_integer(bs);
                if bad || overflow {
                    let text = String::from_utf8_lossy(bs);
                    let why = match text.parse::<f64>() {
                        Ok(f) if f.is_finite() => return Ok(()),
                        Ok(_) => "value out of range",
                        Err(_) => "invalid syntax",
                    };
                    return Err(self.err(format!(
                        "decode number from {text}: strconv.ParseFloat: parsing {text:?}: {why}"
                    )));
                }
                Ok(())
            }
        }
    }

    /// `Decoder.swallow`.
    fn swallow(&mut self) -> R<()> {
        if self.try_decode_as_nil()? {
            return Ok(());
        }
        match self.container_type()? {
            ValueType::Map => {
                self.read_map_start()?;
                self.depth_incr()?;
                while !self.check_break()? {
                    self.read_map_elem_key()?;
                    self.swallow()?;
                    self.read_map_elem_value()?;
                    self.swallow()?;
                }
                self.read_map_end()?;
                self.depth_decr();
            }
            ValueType::Array => {
                self.read_array_start()?;
                self.depth_incr()?;
                while !self.check_break()? {
                    self.read_array_elem()?;
                    self.swallow()?;
                }
                self.read_array_end()?;
                self.depth_decr();
            }
            ValueType::String => {
                self.decode_string()?;
            }
            _ => self.decode_naked_scalar()?,
        }
        Ok(())
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
                            String::from_utf8_lossy(&key)
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

    /// `kSlice` for `[]GenesisAllocation`.
    fn decode_alloc(&mut self) -> R<()> {
        let ctyp = self.container_type()?;
        if ctyp == ValueType::String {
            return Err(self.err(
                "bytes/string in stream must decode into slice/array of bytes, not []bookkeeping.GenesisAllocation",
            ));
        }
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
        // A map's keys and values alternate (`ElemContainerState(j)`).
        let mut at_key = true;
        while !self.check_break()? {
            if array {
                self.read_array_elem()?;
            } else if at_key {
                self.read_map_elem_key()?;
            } else {
                self.read_map_elem_value()?;
            }
            if !self.try_decode_as_nil()? {
                self.decode_struct(&ALLOC_FIELDS, &mut |d, k| match k {
                    2 => d.decode_account_data(),
                    _ => d.decode_string().map(|_| ()),
                })?;
            }
            at_key = !at_key;
        }
        if array {
            self.read_array_end()?;
        } else {
            self.read_map_end()?;
        }
        self.depth_decr();
        Ok(())
    }

    /// `GenesisAccountData`: a struct, its fields only checked to be well
    /// formed.
    fn decode_account_data(&mut self) -> R<()> {
        match self.container_type()? {
            ValueType::Map | ValueType::Array => self.swallow(),
            _ => Err(self.err("only encoded map or array can be decoded into a struct")),
        }
    }
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

    #[test]
    fn deep_nesting_is_bounded() {
        let mut s = String::from(r#"{"alloc":[{"state":"#);
        s.push_str(&"[".repeat(5000));
        let err = gid(s.as_bytes()).unwrap_err();
        assert!(err.ends_with("maximum decoding depth exceeded"), "{err}");
    }
}
