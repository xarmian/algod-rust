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

//! An order-preserving JSON parser that remembers where each object key is
//! (issue #1971).
//!
//! go-algorand reports an unknown key of a JSON request as
//! `json decode error [pos N]: no matching struct field found when decoding
//! stream map with key K`, where `N` is the byte offset **just after the
//! colon that follows the key** and `K` is the key with its escapes decoded
//! (verified against a go-algorand v5.0.3-stable node on 22 bodies: varying
//! key length, whitespace, nesting, escapes, arrays of transactions). The
//! first such key in stream order wins, so the object members must keep their
//! order, which `serde_json::Value` does not.

/// A parsed JSON value; object members keep their text order and position.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    Str(String),
    Array(Vec<Node>),
    Object(Vec<Member>),
}

/// One `"key": value` member of an object.
#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    /// The key, escapes decoded.
    pub key: String,
    /// Byte offset just after the `:` that follows the key.
    pub after_colon: usize,
    pub value: Node,
}

/// Nesting limit; the request model is a handful of levels deep.
const MAX_DEPTH: usize = 64;

/// Parse a complete JSON document (surrounding whitespace allowed, nothing
/// else after the value). `None` for anything that is not valid JSON.
pub fn parse_ordered(text: &str) -> Option<Node> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let node = p.value(0)?;
    p.ws();
    (p.i == p.b.len()).then_some(node)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Option<()> {
        (self.b.get(self.i) == Some(&c)).then(|| self.i += 1)
    }

    fn value(&mut self, depth: usize) -> Option<Node> {
        if depth > MAX_DEPTH {
            return None;
        }
        match *self.b.get(self.i)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(Node::Str),
            b't' => self.literal("true", Node::Bool(true)),
            b'f' => self.literal("false", Node::Bool(false)),
            b'n' => self.literal("null", Node::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn literal(&mut self, word: &str, node: Node) -> Option<Node> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Some(node)
        } else {
            None
        }
    }

    fn number(&mut self) -> Option<Node> {
        let start = self.i;
        while matches!(
            self.b.get(self.i),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.i += 1;
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).ok()?;
        serde_json::from_str::<serde_json::Number>(text)
            .ok()
            .map(Node::Number)
    }

    fn array(&mut self, depth: usize) -> Option<Node> {
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.ws();
        if self.eat(b']').is_some() {
            return Some(Node::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            if self.eat(b',').is_some() {
                continue;
            }
            self.eat(b']')?;
            return Some(Node::Array(items));
        }
    }

    fn object(&mut self, depth: usize) -> Option<Node> {
        self.eat(b'{')?;
        let mut members = Vec::new();
        self.ws();
        if self.eat(b'}').is_some() {
            return Some(Node::Object(members));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            self.eat(b':')?;
            let after_colon = self.i;
            self.ws();
            let value = self.value(depth + 1)?;
            members.push(Member {
                key,
                after_colon,
                value,
            });
            self.ws();
            if self.eat(b',').is_some() {
                continue;
            }
            self.eat(b'}')?;
            return Some(Node::Object(members));
        }
    }

    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let c = *self.b.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let e = *self.b.get(self.i)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return None,
                    }
                }
                0x00..=0x1f => return None,
                _ => {
                    // copy one whole UTF-8 sequence
                    let start = self.i - 1;
                    let len = match c {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    let end = start + len;
                    let chunk = std::str::from_utf8(self.b.get(start..end)?).ok()?;
                    out.push_str(chunk);
                    self.i = end;
                }
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let s = std::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?;
        self.i += 4;
        u32::from_str_radix(s, 16).ok()
    }

    fn unicode_escape(&mut self) -> Option<char> {
        let first = self.hex4()?;
        if (0xd800..0xdc00).contains(&first) {
            // a high surrogate must be followed by \uXXXX low surrogate
            self.eat(b'\\')?;
            self.eat(b'u')?;
            let second = self.hex4()?;
            if !(0xdc00..0xe000).contains(&second) {
                return None;
            }
            char::from_u32(0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00))
        } else {
            char::from_u32(first)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(n: &Node) -> &Vec<Member> {
        match n {
            Node::Object(m) => m,
            other => panic!("not an object: {other:?}"),
        }
    }

    #[test]
    fn members_keep_order_and_the_offset_after_the_colon() {
        let text = r#"{"b":1,"a" : "x" ,"c":[true,null,{"d":2}]}"#;
        let n = parse_ordered(text).expect("valid");
        let m = obj(&n);
        assert_eq!(
            m.iter().map(|x| x.key.as_str()).collect::<Vec<_>>(),
            ["b", "a", "c"]
        );
        // offset just after each key's colon
        assert_eq!(m[0].after_colon, text.find(r#""b":"#).unwrap() + 4);
        assert_eq!(m[1].after_colon, text.find(r#""a" :"#).unwrap() + 5);
        assert_eq!(m[2].after_colon, text.find(r#""c":"#).unwrap() + 4);
        assert_eq!(m[1].value, Node::Str("x".into()));
        let Node::Array(items) = &m[2].value else {
            panic!()
        };
        assert_eq!(items[0], Node::Bool(true));
        assert_eq!(items[1], Node::Null);
        assert_eq!(obj(&items[2])[0].after_colon, text.find(r#""d":"#).unwrap() + 4);
    }

    #[test]
    fn escapes_are_decoded_in_keys_and_strings() {
        let n = parse_ordered(r#"{"zAz":"a\n\"b\"\\\/","😀":1}"#).unwrap();
        let m = obj(&n);
        assert_eq!(m[0].key, "zAz");
        assert_eq!(m[0].value, Node::Str("a\n\"b\"\\/".into()));
        assert_eq!(m[1].key, "\u{1F600}");
    }

    #[test]
    fn numbers_keep_their_integer_form() {
        let n = parse_ordered(r#"[0, 18446744073709551615, -5, 1.5, 1e3]"#).unwrap();
        let Node::Array(v) = n else { panic!() };
        let nums: Vec<_> = v
            .iter()
            .map(|x| match x {
                Node::Number(n) => (n.as_u64(), n.as_i64(), n.as_f64()),
                _ => panic!(),
            })
            .collect();
        assert_eq!(nums[0].0, Some(0));
        assert_eq!(nums[1].0, Some(u64::MAX));
        assert_eq!(nums[2].1, Some(-5));
        assert_eq!(nums[3].0, None);
        assert_eq!(nums[4].0, None);
    }

    #[test]
    fn invalid_json_is_none() {
        for bad in [
            "", "{", "[1,]", r#"{"a":1,}"#, r#"{"a" 1}"#, r#"{a:1}"#, "tru", "01x", r#""abc"#,
            r#"{"a":1} x"#, r#""\x""#, "\"\u{1}\"", r#""\ud83d""#,
        ] {
            assert!(parse_ordered(bad).is_none(), "{bad:?}");
        }
        // depth limit
        let deep = format!("{}{}", "[".repeat(100), "]".repeat(100));
        assert!(parse_ordered(&deep).is_none());
        assert!(parse_ordered(&format!("{}{}", "[".repeat(60), "]".repeat(60))).is_some());
    }

    #[test]
    fn surrounding_whitespace_is_allowed() {
        assert!(parse_ordered(" \n {\"a\":[ ] } \t").is_some());
    }
}
