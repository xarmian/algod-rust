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

//! The consensus table every go `libgoal.Client` loads (`Client.init` →
//! `nc.GetConsensus()` → `config.PreloadConfigurableConsensusProtocols`),
//! issue #2454: a `<dd>/consensus.json` is optional, but one go's
//! `encoding/json` `Decoder` rejects fails the client.
//!
//! go decodes the file into a `config.ConsensusProtocols`
//! (`map[protocol.ConsensusVersion]config.ConsensusParams`) with
//! `json.NewDecoder(file).Decode`, so:
//! - only the first JSON value is read, whatever follows it is ignored;
//! - an empty file is `EOF`, a value cut short `unexpected EOF`, a syntax
//!   error the scanner's `invalid character ...` (`encoding/json/scanner.go`,
//!   ported below);
//! - a value of the wrong type does not stop the decoder, the first one is
//!   the error (`json: cannot unmarshal <what> into Go struct field
//!   <Struct>.<field path> of type <type>`, `decode.go` `literalStore`,
//!   `object`, `array`, `addErrorContext`); unknown fields are ignored and
//!   field names match case-insensitively.
//!
//! goal-rust does not use the table itself, only whether go's decoder
//! accepts the file.

use std::path::Path;

/// go: `config.ConfigurableConsensusProtocolsFilename`.
const CONSENSUS_FILE: &str = "consensus.json";

/// go: `encoding/json` `maxNestingDepth`.
const MAX_NESTING_DEPTH: usize = 10000;

/// go: `config.PreloadConfigurableConsensusProtocols(dataDir)`: `Err` is
/// go's error text when the file cannot be read or decoded.
pub fn preload_configurable_consensus_protocols(data_dir: &Path) -> Result<(), String> {
    let path = data_dir.join(CONSENSUS_FILE);
    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "open {}: {}",
                path.display(),
                crate::data_dir::go_os_error(&e)
            ))
        }
    };
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes).map_err(|e| {
        format!(
            "read {}: {}",
            path.display(),
            crate::data_dir::go_os_error(&e)
        )
    })?;
    decode(&bytes)
}

/// go: `json.NewDecoder(r).Decode(&config.ConsensusProtocols{})`.
pub fn decode(data: &[u8]) -> Result<(), String> {
    let n = read_value(data)?;
    let mut d = Decoder {
        data: &data[..n],
        off: 0,
        saved: None,
        ctx_struct: None,
        stack: Vec::new(),
    };
    d.value(Ty::Protocols);
    match d.saved {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

// ── the scanner (encoding/json/scanner.go) ─────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Continue,
    BeginLiteral,
    BeginObject,
    ObjectKey,
    ObjectValue,
    EndObject,
    BeginArray,
    ArrayValue,
    EndArray,
    SkipSpace,
    End,
    Error,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Parse {
    ObjectKey,
    ObjectValue,
    ArrayValue,
}

#[derive(Clone, Copy)]
enum State {
    BeginValue,
    BeginValueOrEmpty,
    BeginStringOrEmpty,
    BeginString,
    EndValue,
    EndTop,
    InString,
    InStringEsc,
    /// After `\u` and this many hex digits.
    InStringEscU(u8),
    Neg,
    One,
    Zero,
    Dot,
    Dot0,
    E,
    ESign,
    E0,
    /// Inside `true` / `false` / `null`: the bytes still expected, the name.
    Lit(&'static [u8], &'static str),
    Error,
}

struct Scanner {
    step: State,
    parse: Vec<Parse>,
    err: Option<String>,
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

/// go: `quoteChar` -- `strconv.Quote(string(c))`, the byte as a rune.
fn quote_char(c: u8) -> String {
    let q = match c {
        b'\'' => return r"'\''".to_string(),
        b'"' => return "'\"'".to_string(),
        0x07 => r"\a".to_string(),
        0x08 => r"\b".to_string(),
        0x0c => r"\f".to_string(),
        b'\n' => r"\n".to_string(),
        b'\r' => r"\r".to_string(),
        b'\t' => r"\t".to_string(),
        0x0b => r"\v".to_string(),
        b'\\' => r"\\".to_string(),
        0x00..=0x1f | 0x7f => format!(r"\x{c:02x}"),
        // go's `strconv.IsPrint`: U+0080..U+00A0 and U+00AD are not printable
        0x80..=0xa0 | 0xad => format!(r"\u{c:04x}"),
        _ => char::from(c).to_string(),
    };
    format!("'{q}'")
}

impl Scanner {
    fn new() -> Self {
        Self {
            step: State::BeginValue,
            parse: Vec::new(),
            err: None,
        }
    }

    fn error(&mut self, c: u8, context: &str) -> Op {
        self.step = State::Error;
        self.err = Some(format!("invalid character {} {context}", quote_char(c)));
        Op::Error
    }

    fn push(&mut self, c: u8, p: Parse, op: Op) -> Op {
        self.parse.push(p);
        if self.parse.len() <= MAX_NESTING_DEPTH {
            op
        } else {
            self.error(c, "exceeded max depth")
        }
    }

    fn step(&mut self, c: u8) -> Op {
        match self.step {
            State::BeginValueOrEmpty => {
                if is_space(c) {
                    return Op::SkipSpace;
                }
                if c == b']' {
                    return self.end_value(c);
                }
                self.begin_value(c)
            }
            State::BeginValue => self.begin_value(c),
            State::BeginStringOrEmpty => {
                if is_space(c) {
                    return Op::SkipSpace;
                }
                if c == b'}' {
                    let n = self.parse.len();
                    self.parse[n - 1] = Parse::ObjectValue;
                    return self.end_value(c);
                }
                self.begin_string(c)
            }
            State::BeginString => self.begin_string(c),
            State::EndValue => self.end_value(c),
            State::EndTop => self.end_top(c),
            State::InString => {
                if c == b'"' {
                    self.step = State::EndValue;
                    return Op::Continue;
                }
                if c == b'\\' {
                    self.step = State::InStringEsc;
                    return Op::Continue;
                }
                if c < 0x20 {
                    return self.error(c, "in string literal");
                }
                Op::Continue
            }
            State::InStringEsc => match c {
                b'b' | b'f' | b'n' | b'r' | b't' | b'\\' | b'/' | b'"' => {
                    self.step = State::InString;
                    Op::Continue
                }
                b'u' => {
                    self.step = State::InStringEscU(0);
                    Op::Continue
                }
                _ => self.error(c, "in string escape code"),
            },
            State::InStringEscU(n) => {
                if c.is_ascii_hexdigit() {
                    self.step = if n == 3 {
                        State::InString
                    } else {
                        State::InStringEscU(n + 1)
                    };
                    return Op::Continue;
                }
                self.error(c, r"in \u hexadecimal character escape")
            }
            State::Neg => {
                if c == b'0' {
                    self.step = State::Zero;
                    return Op::Continue;
                }
                if (b'1'..=b'9').contains(&c) {
                    self.step = State::One;
                    return Op::Continue;
                }
                self.error(c, "in numeric literal")
            }
            State::One => {
                if c.is_ascii_digit() {
                    return Op::Continue;
                }
                self.zero(c)
            }
            State::Zero => self.zero(c),
            State::Dot => {
                if c.is_ascii_digit() {
                    self.step = State::Dot0;
                    return Op::Continue;
                }
                self.error(c, "after decimal point in numeric literal")
            }
            State::Dot0 => {
                if c.is_ascii_digit() {
                    return Op::Continue;
                }
                if c == b'e' || c == b'E' {
                    self.step = State::E;
                    return Op::Continue;
                }
                self.end_value(c)
            }
            State::E => {
                if c == b'+' || c == b'-' {
                    self.step = State::ESign;
                    return Op::Continue;
                }
                self.e_sign(c)
            }
            State::ESign => self.e_sign(c),
            State::E0 => {
                if c.is_ascii_digit() {
                    return Op::Continue;
                }
                self.end_value(c)
            }
            State::Lit(rest, name) => {
                if c == rest[0] {
                    self.step = if rest.len() == 1 {
                        State::EndValue
                    } else {
                        State::Lit(&rest[1..], name)
                    };
                    return Op::Continue;
                }
                let context = format!("in literal {name} (expecting '{}')", char::from(rest[0]));
                self.error(c, &context)
            }
            State::Error => Op::Error,
        }
    }

    fn begin_value(&mut self, c: u8) -> Op {
        if is_space(c) {
            return Op::SkipSpace;
        }
        let (step, op) = match c {
            b'{' => {
                self.step = State::BeginStringOrEmpty;
                return self.push(c, Parse::ObjectKey, Op::BeginObject);
            }
            b'[' => {
                self.step = State::BeginValueOrEmpty;
                return self.push(c, Parse::ArrayValue, Op::BeginArray);
            }
            b'"' => (State::InString, Op::BeginLiteral),
            b'-' => (State::Neg, Op::BeginLiteral),
            b'0' => (State::Zero, Op::BeginLiteral),
            b't' => (State::Lit(b"rue", "true"), Op::BeginLiteral),
            b'f' => (State::Lit(b"alse", "false"), Op::BeginLiteral),
            b'n' => (State::Lit(b"ull", "null"), Op::BeginLiteral),
            b'1'..=b'9' => (State::One, Op::BeginLiteral),
            _ => return self.error(c, "looking for beginning of value"),
        };
        self.step = step;
        op
    }

    fn begin_string(&mut self, c: u8) -> Op {
        if is_space(c) {
            return Op::SkipSpace;
        }
        if c == b'"' {
            self.step = State::InString;
            return Op::BeginLiteral;
        }
        self.error(c, "looking for beginning of object key string")
    }

    fn end_value(&mut self, c: u8) -> Op {
        let n = self.parse.len();
        if n == 0 {
            self.step = State::EndTop;
            return self.end_top(c);
        }
        if is_space(c) {
            self.step = State::EndValue;
            return Op::SkipSpace;
        }
        match self.parse[n - 1] {
            Parse::ObjectKey => {
                if c == b':' {
                    self.parse[n - 1] = Parse::ObjectValue;
                    self.step = State::BeginValue;
                    return Op::ObjectKey;
                }
                self.error(c, "after object key")
            }
            Parse::ObjectValue => {
                if c == b',' {
                    self.parse[n - 1] = Parse::ObjectKey;
                    self.step = State::BeginString;
                    return Op::ObjectValue;
                }
                if c == b'}' {
                    self.pop();
                    return Op::EndObject;
                }
                self.error(c, "after object key:value pair")
            }
            Parse::ArrayValue => {
                if c == b',' {
                    self.step = State::BeginValue;
                    return Op::ArrayValue;
                }
                if c == b']' {
                    self.pop();
                    return Op::EndArray;
                }
                self.error(c, "after array element")
            }
        }
    }

    /// go: `popParseState`.
    fn pop(&mut self) {
        self.parse.pop();
        self.step = if self.parse.is_empty() {
            State::EndTop
        } else {
            State::EndValue
        };
    }

    fn end_top(&mut self, c: u8) -> Op {
        if !is_space(c) {
            // go complains about this byte on the next call only
            self.error(c, "after top-level value");
        }
        Op::End
    }

    fn zero(&mut self, c: u8) -> Op {
        if c == b'.' {
            self.step = State::Dot;
            return Op::Continue;
        }
        if c == b'e' || c == b'E' {
            self.step = State::E;
            return Op::Continue;
        }
        self.end_value(c)
    }

    fn e_sign(&mut self, c: u8) -> Op {
        if c.is_ascii_digit() {
            self.step = State::E0;
            return Op::Continue;
        }
        self.error(c, "in exponent of numeric literal")
    }
}

/// go: `Decoder.readValue` -- the length of the first JSON value, or the
/// decoder's error.
fn read_value(data: &[u8]) -> Result<usize, String> {
    let mut s = Scanner::new();
    for (i, &c) in data.iter().enumerate() {
        match s.step(c) {
            Op::End => return Ok(i),
            Op::EndObject | Op::EndArray if s.parse.is_empty() => return Ok(i + 1),
            Op::Error => return Err(s.err.take().unwrap_or_default()),
            _ => {}
        }
    }
    if s.step(b' ') == Op::End {
        return Ok(data.len());
    }
    if data.iter().any(|&c| !is_space(c)) {
        Err("unexpected EOF".to_string())
    } else {
        Err("EOF".to_string())
    }
}

// ── the typed decode (encoding/json/decode.go) ─────────────────────────

/// The Go type of a field, as far as decoding it goes.
#[derive(Clone, Copy)]
enum Kind {
    Bool,
    /// An unsigned integer of this many bits, and its Go type name.
    Uint(u32, &'static str),
    /// A 64-bit signed integer, and its Go type name.
    Int(&'static str),
    /// `map[protocol.ConsensusVersion]uint64`.
    Upgrades,
    Struct(&'static StructType),
}

struct StructType {
    /// `reflect.Type.Name()`.
    name: &'static str,
    /// `reflect.Type.String()`.
    type_name: &'static str,
    fields: &'static [(&'static str, Kind)],
}

/// What a JSON value is decoded into.
#[derive(Clone, Copy)]
enum Ty {
    /// `config.ConsensusProtocols`.
    Protocols,
    Field(Kind),
    /// Not a field: the value is skipped.
    Skip,
}

impl Ty {
    fn type_name(self) -> &'static str {
        match self {
            Ty::Protocols => "config.ConsensusProtocols",
            Ty::Field(Kind::Bool) => "bool",
            Ty::Field(Kind::Uint(_, n) | Kind::Int(n)) => n,
            Ty::Field(Kind::Upgrades) => "map[protocol.ConsensusVersion]uint64",
            Ty::Field(Kind::Struct(st)) => st.type_name,
            Ty::Skip => "",
        }
    }
}

struct Decoder<'a> {
    /// One value the scanner accepted.
    data: &'a [u8],
    off: usize,
    /// go: `decodeState.savedError` -- the first type error.
    saved: Option<String>,
    /// go: `errorContext.Struct` / `errorContext.FieldStack`.
    ctx_struct: Option<&'static str>,
    stack: Vec<&'static str>,
}

impl Decoder<'_> {
    fn skip_space(&mut self) {
        while self.off < self.data.len() && is_space(self.data[self.off]) {
            self.off += 1;
        }
    }

    /// go: `saveError(&UnmarshalTypeError{...})` through `addErrorContext`.
    fn type_error(&mut self, what: &str, ty: Ty) {
        if self.saved.is_some() {
            return;
        }
        let ty_name = ty.type_name();
        self.saved = Some(if self.ctx_struct.is_some() || !self.stack.is_empty() {
            format!(
                "json: cannot unmarshal {what} into Go struct field {}.{} of type {ty_name}",
                self.ctx_struct.unwrap_or(""),
                self.stack.join(".")
            )
        } else {
            format!("json: cannot unmarshal {what} into Go value of type {ty_name}")
        });
    }

    fn value(&mut self, ty: Ty) {
        self.skip_space();
        match self.data[self.off] {
            b'{' => {
                self.off += 1;
                self.object(ty);
            }
            b'[' => {
                self.off += 1;
                if !matches!(ty, Ty::Skip) {
                    self.type_error("array", ty);
                }
                self.skip_space();
                if self.data[self.off] == b']' {
                    self.off += 1;
                    return;
                }
                loop {
                    self.value(Ty::Skip);
                    self.skip_space();
                    let c = self.data[self.off];
                    self.off += 1;
                    if c == b']' {
                        return;
                    }
                }
            }
            b'"' => {
                self.string();
                if !matches!(ty, Ty::Skip) {
                    self.type_error("string", ty);
                }
            }
            b't' | b'f' => {
                self.off += if self.data[self.off] == b't' { 4 } else { 5 };
                if !matches!(ty, Ty::Skip | Ty::Field(Kind::Bool)) {
                    self.type_error("bool", ty);
                }
            }
            // null leaves every Go value as it is
            b'n' => self.off += 4,
            _ => {
                let start = self.off;
                while self.off < self.data.len()
                    && matches!(
                        self.data[self.off],
                        b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'
                    )
                {
                    self.off += 1;
                }
                let item = std::str::from_utf8(&self.data[start..self.off]).unwrap_or("");
                self.number(item, ty);
            }
        }
    }

    fn number(&mut self, item: &str, ty: Ty) {
        let ok = match ty {
            Ty::Skip => true,
            // go: `strconv.ParseUint(item, 10, 64)` and `OverflowUint`
            Ty::Field(Kind::Uint(bits, _)) => item
                .parse::<u64>()
                .is_ok_and(|n| bits == 64 || n >> bits == 0),
            Ty::Field(Kind::Int(_)) => item.parse::<i64>().is_ok(),
            _ => {
                self.type_error("number", ty);
                return;
            }
        };
        if !ok {
            self.type_error(&format!("number {item}"), ty);
        }
    }

    /// The string at `off` (its opening quote), unquoted.
    fn string(&mut self) -> String {
        self.off += 1;
        let start = self.off;
        while self.data[self.off] != b'"' {
            self.off += if self.data[self.off] == b'\\' { 2 } else { 1 };
        }
        let raw = &self.data[start..self.off];
        self.off += 1;
        unquote(raw)
    }

    /// The object whose `{` was just read.
    fn object(&mut self, ty: Ty) {
        let (fields, elem) = match ty {
            Ty::Field(Kind::Struct(st)) => (Some(st), Ty::Skip),
            Ty::Protocols => (None, Ty::Field(Kind::Struct(&CONSENSUS_PARAMS))),
            Ty::Field(Kind::Upgrades) => (None, Ty::Field(Kind::Uint(64, "uint64"))),
            Ty::Skip => (None, Ty::Skip),
            Ty::Field(_) => {
                self.type_error("object", ty);
                self.off -= 1;
                self.value(Ty::Skip);
                return;
            }
        };
        let orig_struct = self.ctx_struct;
        let orig_len = self.stack.len();
        self.skip_space();
        if self.data[self.off] == b'}' {
            self.off += 1;
            return;
        }
        loop {
            self.skip_space();
            let key = self.string();
            self.skip_space();
            self.off += 1; // ':'
            let sub = match fields {
                Some(st) => match lookup(st, &key) {
                    Some((name, kind)) => {
                        self.ctx_struct = Some(st.name);
                        self.stack.push(name);
                        Ty::Field(kind)
                    }
                    None => Ty::Skip,
                },
                None => elem,
            };
            self.value(sub);
            self.stack.truncate(orig_len);
            self.ctx_struct = orig_struct;
            self.skip_space();
            let c = self.data[self.off];
            self.off += 1;
            if c == b'}' {
                return;
            }
        }
    }
}

/// go: `fields.byExactName`, then `fields.byFoldedName` (`foldName`).
fn lookup(st: &StructType, key: &str) -> Option<(&'static str, Kind)> {
    if let Some(&(name, kind)) = st.fields.iter().find(|(n, _)| *n == key) {
        return Some((name, kind));
    }
    let folded = fold_name(key);
    st.fields
        .iter()
        .find(|(n, _)| fold_name(n) == folded)
        .map(|&(name, kind)| (name, kind))
}

/// go: `foldName` -- every rune as `unicode.ToUpper(unicode.ToLower(r))`.
fn fold_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            let lower = c.to_lowercase().next().unwrap_or(c);
            lower.to_uppercase().next().unwrap_or(lower)
        })
        .collect()
}

/// go: `unquoteBytes` of a string the scanner accepted.
fn unquote(raw: &[u8]) -> String {
    fn hex4(b: &[u8]) -> Option<u32> {
        let s = std::str::from_utf8(b.get(..4)?).ok()?;
        u32::from_str_radix(s, 16).ok()
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != b'\\' {
            out.push(raw[i]);
            i += 1;
            continue;
        }
        let c = raw[i + 1];
        i += 2;
        let ch = match c {
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let r = hex4(&raw[i..]).unwrap_or(0xfffd);
                i += 4;
                if (0xd800..0xe000).contains(&r) {
                    // a surrogate pair, else U+FFFD
                    let low = (raw.get(i..i + 2) == Some(b"\\u"))
                        .then(|| hex4(&raw[i + 2..]))
                        .flatten()
                        .filter(|lo| r < 0xdc00 && (0xdc00..0xe000).contains(lo));
                    match low {
                        Some(lo) => {
                            i += 6;
                            char::from_u32(0x10000 + ((r - 0xd800) << 10) + (lo - 0xdc00))
                                .unwrap_or('\u{fffd}')
                        }
                        None => '\u{fffd}',
                    }
                } else {
                    char::from_u32(r).unwrap_or('\u{fffd}')
                }
            }
            other => char::from(other),
        };
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }
    String::from_utf8_lossy(&out).into_owned()
}

static CONSENSUS_PARAMS: StructType = StructType {
    name: "ConsensusParams",
    type_name: "config.ConsensusParams",
    fields: &CONSENSUS_PARAMS_FIELDS,
};

static PAYOUTS: StructType = StructType {
    name: "ProposerPayoutRules",
    type_name: "config.ProposerPayoutRules",
    fields: &PAYOUTS_FIELDS,
};

static BONUS: StructType = StructType {
    name: "BonusPlan",
    type_name: "config.BonusPlan",
    fields: &BONUS_FIELDS,
};

// The fields of go's `config.ConsensusParams`, `ProposerPayoutRules` and
// `BonusPlan` (`config/consensus.go` at v5.0.5-stable) and their types.
static CONSENSUS_PARAMS_FIELDS: [(&str, Kind); 148] = [
    ("UpgradeVoteRounds", Kind::Uint(64, "uint64")),
    ("UpgradeThreshold", Kind::Uint(64, "uint64")),
    ("DefaultUpgradeWaitRounds", Kind::Uint(64, "uint64")),
    ("MinUpgradeWaitRounds", Kind::Uint(64, "uint64")),
    ("MaxUpgradeWaitRounds", Kind::Uint(64, "uint64")),
    ("MaxVersionStringLen", Kind::Int("int")),
    ("MaxTxnBytesPerBlock", Kind::Int("int")),
    ("MaxTxnNoteBytes", Kind::Int("int")),
    ("MaxAbsoluteTxnNoteBytes", Kind::Int("int")),
    ("MaxTxnLife", Kind::Uint(64, "uint64")),
    ("ApprovedUpgrades", Kind::Upgrades),
    ("SupportGenesisHash", Kind::Bool),
    ("RequireGenesisHash", Kind::Bool),
    ("DefaultKeyDilution", Kind::Uint(64, "uint64")),
    ("MinBalance", Kind::Uint(64, "uint64")),
    ("MinTxnFee", Kind::Uint(64, "uint64")),
    ("EnableAppCostPooling", Kind::Bool),
    ("EnableLogicSigCostPooling", Kind::Bool),
    ("RewardUnit", Kind::Uint(64, "uint64")),
    ("RewardsRateRefreshInterval", Kind::Uint(64, "uint64")),
    ("SeedLookback", Kind::Uint(64, "uint64")),
    ("SeedRefreshInterval", Kind::Uint(64, "uint64")),
    ("MaxBalLookback", Kind::Uint(64, "uint64")),
    ("NumProposers", Kind::Uint(64, "uint64")),
    ("SoftCommitteeSize", Kind::Uint(64, "uint64")),
    ("SoftCommitteeThreshold", Kind::Uint(64, "uint64")),
    ("CertCommitteeSize", Kind::Uint(64, "uint64")),
    ("CertCommitteeThreshold", Kind::Uint(64, "uint64")),
    ("NextCommitteeSize", Kind::Uint(64, "uint64")),
    ("NextCommitteeThreshold", Kind::Uint(64, "uint64")),
    ("LateCommitteeSize", Kind::Uint(64, "uint64")),
    ("LateCommitteeThreshold", Kind::Uint(64, "uint64")),
    ("RedoCommitteeSize", Kind::Uint(64, "uint64")),
    ("RedoCommitteeThreshold", Kind::Uint(64, "uint64")),
    ("DownCommitteeSize", Kind::Uint(64, "uint64")),
    ("DownCommitteeThreshold", Kind::Uint(64, "uint64")),
    ("AgreementFilterTimeout", Kind::Int("time.Duration")),
    ("AgreementFilterTimeoutPeriod0", Kind::Int("time.Duration")),
    (
        "AgreementDeadlineTimeoutPeriod0",
        Kind::Int("time.Duration"),
    ),
    ("FastRecoveryLambda", Kind::Int("time.Duration")),
    ("PaysetCommit", Kind::Int("config.PaysetCommitType")),
    ("MaxTimestampIncrement", Kind::Int("int64")),
    ("SupportSignedTxnInBlock", Kind::Bool),
    ("ForceNonParticipatingFeeSink", Kind::Bool),
    ("ApplyData", Kind::Bool),
    ("RewardsInApplyData", Kind::Bool),
    ("CredentialDomainSeparationEnabled", Kind::Bool),
    ("SupportBecomeNonParticipatingTransactions", Kind::Bool),
    ("PendingResidueRewards", Kind::Bool),
    ("Asset", Kind::Bool),
    ("MaxAssetsPerAccount", Kind::Int("int")),
    ("MaxAssetNameBytes", Kind::Int("int")),
    ("MaxAssetUnitNameBytes", Kind::Int("int")),
    ("MaxAssetURLBytes", Kind::Int("int")),
    ("TxnCounter", Kind::Bool),
    ("SupportTxGroups", Kind::Bool),
    ("MaxTxGroupSize", Kind::Int("int")),
    ("SupportTransactionLeases", Kind::Bool),
    ("FixTransactionLeases", Kind::Bool),
    ("LogicSigVersion", Kind::Uint(64, "uint64")),
    ("LogicSigMaxSize", Kind::Uint(64, "uint64")),
    ("MaxAbsoluteLogicSigProgramSize", Kind::Uint(64, "uint64")),
    ("LogicSigMaxCost", Kind::Uint(64, "uint64")),
    ("LogicSigMsig", Kind::Bool),
    ("LogicSigLMsig", Kind::Bool),
    ("MaxAssetDecimals", Kind::Uint(32, "uint32")),
    ("SupportRekeying", Kind::Bool),
    ("EnforceAuthAddrSenderDiff", Kind::Bool),
    ("Application", Kind::Bool),
    ("MaxAppArgs", Kind::Int("int")),
    ("MaxAppTotalArgLen", Kind::Int("int")),
    ("MaxAbsoluteTotalArgLen", Kind::Int("int")),
    ("MaxAppProgramLen", Kind::Int("int")),
    ("MaxAppTotalProgramLen", Kind::Int("int")),
    ("MaxExtraAppProgramPages", Kind::Int("int")),
    ("MaxAbsoluteExtraProgramPages", Kind::Int("int")),
    ("MaxAppTxnAccounts", Kind::Int("int")),
    ("MaxAppTxnForeignApps", Kind::Int("int")),
    ("MaxAppTxnForeignAssets", Kind::Int("int")),
    ("MaxAppTotalTxnReferences", Kind::Int("int")),
    ("MaxAppProgramCost", Kind::Int("int")),
    ("MaxAppKeyLen", Kind::Int("int")),
    ("MaxAppBytesValueLen", Kind::Int("int")),
    ("MaxAppSumKeyValueLens", Kind::Int("int")),
    ("MaxInnerTransactions", Kind::Int("int")),
    ("EnableInnerTransactionPooling", Kind::Bool),
    ("IsolateClearState", Kind::Bool),
    ("MinInnerApplVersion", Kind::Uint(64, "uint64")),
    ("MaxAppsCreated", Kind::Int("int")),
    ("MaxAppsOptedIn", Kind::Int("int")),
    ("AppFlatParamsMinBalance", Kind::Uint(64, "uint64")),
    ("AppFlatOptInMinBalance", Kind::Uint(64, "uint64")),
    ("SchemaMinBalancePerEntry", Kind::Uint(64, "uint64")),
    ("SchemaUintMinBalance", Kind::Uint(64, "uint64")),
    ("SchemaBytesMinBalance", Kind::Uint(64, "uint64")),
    ("MaxBoxSize", Kind::Uint(64, "uint64")),
    ("BoxFlatMinBalance", Kind::Uint(64, "uint64")),
    ("BoxByteMinBalance", Kind::Uint(64, "uint64")),
    ("MaxAppBoxReferences", Kind::Int("int")),
    ("MaxAppAccess", Kind::Int("int")),
    ("BytesPerBoxReference", Kind::Uint(64, "uint64")),
    ("MaxLocalSchemaEntries", Kind::Uint(64, "uint64")),
    ("MaxGlobalSchemaEntries", Kind::Uint(64, "uint64")),
    ("MaximumMinimumBalance", Kind::Uint(64, "uint64")),
    ("StateProofInterval", Kind::Uint(64, "uint64")),
    ("StateProofTopVoters", Kind::Uint(64, "uint64")),
    ("StateProofVotersLookback", Kind::Uint(64, "uint64")),
    ("StateProofWeightThreshold", Kind::Uint(32, "uint32")),
    ("StateProofStrengthTarget", Kind::Uint(64, "uint64")),
    ("StateProofMaxRecoveryIntervals", Kind::Uint(64, "uint64")),
    ("StateProofExcludeTotalWeightWithRewards", Kind::Bool),
    ("StateProofBlockHashInLightHeader", Kind::Bool),
    ("EnableAssetCloseAmount", Kind::Bool),
    ("InitialRewardsRateCalculation", Kind::Bool),
    ("NoEmptyLocalDeltas", Kind::Bool),
    ("EnableKeyregCoherencyCheck", Kind::Bool),
    ("EnableProperExtraPageAccounting", Kind::Bool),
    ("EnableAppVersioning", Kind::Bool),
    ("MaxProposedExpiredOnlineAccounts", Kind::Int("int")),
    ("EnableLedgerDataUpdateRound", Kind::Bool),
    ("RewardsCalculationFix", Kind::Bool),
    ("EnableStateProofKeyregCheck", Kind::Bool),
    ("MaxKeyregValidPeriod", Kind::Uint(64, "uint64")),
    ("UnifyInnerTxIDs", Kind::Bool),
    ("EnableSHA256TxnCommitmentHeader", Kind::Bool),
    ("CatchpointLookback", Kind::Uint(64, "uint64")),
    ("DeeperBlockHeaderHistory", Kind::Uint(64, "uint64")),
    ("UnfundedSenders", Kind::Bool),
    ("EnablePrecheckECDSACurve", Kind::Bool),
    ("EnableBareBudgetError", Kind::Bool),
    ("StateProofUseTrackerVerification", Kind::Bool),
    ("EnableCatchpointsWithSPContexts", Kind::Bool),
    ("EnableCatchpointsWithOnlineAccounts", Kind::Bool),
    ("AppForbidLowResources", Kind::Bool),
    ("EnableBoxRefNameError", Kind::Bool),
    ("ExcludeExpiredCirculation", Kind::Bool),
    ("DynamicFilterTimeout", Kind::Bool),
    ("Payouts", Kind::Struct(&PAYOUTS)),
    ("Bonus", Kind::Struct(&BONUS)),
    ("Heartbeat", Kind::Bool),
    ("EnableSha512BlockHash", Kind::Bool),
    ("AppSizeUpdates", Kind::Bool),
    ("AllowZeroLocalAppRef", Kind::Bool),
    ("LoadTracking", Kind::Bool),
    ("PerByteTxnSurcharge", Kind::Uint(64, "basics.Micros")),
    ("EnablePQSchemeFalcon1024", Kind::Bool),
    ("EnableSelectF128", Kind::Bool),
    ("CloseRequiresBaseMinBalance", Kind::Bool),
];
static PAYOUTS_FIELDS: [(&str, Kind); 9] = [
    ("Enabled", Kind::Bool),
    ("GoOnlineFee", Kind::Uint(64, "uint64")),
    ("Percent", Kind::Uint(64, "uint64")),
    ("MinBalance", Kind::Uint(64, "uint64")),
    ("MaxBalance", Kind::Uint(64, "uint64")),
    ("MaxMarkAbsent", Kind::Int("int")),
    ("ChallengeInterval", Kind::Uint(64, "uint64")),
    ("ChallengeGracePeriod", Kind::Uint(64, "uint64")),
    ("ChallengeBits", Kind::Int("int")),
];
static BONUS_FIELDS: [(&str, Kind); 3] = [
    ("BaseRound", Kind::Uint(64, "uint64")),
    ("BaseAmount", Kind::Uint(64, "uint64")),
    ("DecayInterval", Kind::Uint(64, "uint64")),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn err(s: &str) -> String {
        decode(s.as_bytes()).unwrap_err()
    }

    #[test]
    fn the_scanner_reports_gos_syntax_errors() {
        assert_eq!(err(""), "EOF");
        assert_eq!(err(" \n"), "EOF");
        assert_eq!(err("{"), "unexpected EOF");
        assert_eq!(err("-"), "unexpected EOF");
        assert_eq!(err("[[[[1]]]"), "unexpected EOF");
        assert_eq!(
            err("not json"),
            "invalid character 'o' in literal null (expecting 'u')"
        );
        assert_eq!(
            err("\u{feff}{}"),
            "invalid character 'ï' looking for beginning of value"
        );
        assert_eq!(
            err(r#"{"a":1,}"#),
            "invalid character '}' looking for beginning of object key string"
        );
        assert_eq!(
            err("{\"a\":\u{7f}}"),
            r"invalid character '\x7f' looking for beginning of value"
        );
        assert_eq!(
            err("{\"a\":\u{a0}}"),
            "invalid character 'Â' looking for beginning of value"
        );
        assert_eq!(
            err("[1,]"),
            "invalid character ']' looking for beginning of value"
        );
        let deep = "[".repeat(MAX_NESTING_DEPTH + 1);
        assert_eq!(err(&deep), "invalid character '[' exceeded max depth");
    }

    #[test]
    fn only_the_first_value_is_read() {
        assert_eq!(decode(b"{} {"), Ok(()));
        assert_eq!(decode(b"null"), Ok(()));
        assert_eq!(decode(br#"{"v":{}}xyz"#), Ok(()));
        assert_eq!(decode(br#"{"v":{"x":[[1,{"a":[]}],"s"]}}"#), Ok(()));
    }

    #[test]
    fn type_errors_name_gos_field_path() {
        assert_eq!(
            err("12"),
            "json: cannot unmarshal number into Go value of type config.ConsensusProtocols"
        );
        assert_eq!(
            err(r#"{"v":"x"}"#),
            "json: cannot unmarshal string into Go value of type config.ConsensusParams"
        );
        assert_eq!(
            err(r#"{"v":{"mintxnfee":1.5}}"#),
            "json: cannot unmarshal number 1.5 into Go struct field ConsensusParams.MinTxnFee of type uint64"
        );
        assert_eq!(
            err(r#"{"v":{"Bonus":{"BaseRound":true}}}"#),
            "json: cannot unmarshal bool into Go struct field BonusPlan.Bonus.BaseRound of type uint64"
        );
        assert_eq!(
            err(r#"{"v":{"ApprovedUpgrades":{"w":"x"}}}"#),
            "json: cannot unmarshal string into Go struct field ConsensusParams.ApprovedUpgrades of type uint64"
        );
        assert_eq!(
            err(r#"{"v":{"MaxAssetDecimals":4294967296}}"#),
            "json: cannot unmarshal number 4294967296 into Go struct field ConsensusParams.MaxAssetDecimals of type uint32"
        );
        // the first error wins; unknown fields and nulls are fine
        assert_eq!(
            err(r#"{"v":{"Nope":"a","MinTxnFee":null,"MaxTxnLife":"a"},"w":{"MinTxnFee":"b"}}"#),
            "json: cannot unmarshal string into Go struct field ConsensusParams.MaxTxnLife of type uint64"
        );
        assert_eq!(
            decode(br#"{"v":{"MaxAppProgramLen":-5,"MinTxnFee":7}}"#),
            Ok(())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_file_is_fine_a_directory_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(preload_configurable_consensus_protocols(tmp.path()), Ok(()));
        std::fs::create_dir(tmp.path().join(CONSENSUS_FILE)).unwrap();
        assert_eq!(
            preload_configurable_consensus_protocols(tmp.path()),
            Err(format!(
                "read {}: is a directory",
                tmp.path().join(CONSENSUS_FILE).display()
            ))
        );
    }
}
