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

//! go's `encoding/json` HTML escaping (issue #2370).

/// Escape serialized JSON the way go's `encoding/json` does by default
/// (`json.Marshal` and `Encoder` with `SetEscapeHTML(true)`, which Echo's
/// `ctx.JSON` and goal's source-map writer use): `<`, `>` and `&` become
/// `<`, `>` and `&`, and U+2028/U+2029 become ` `/` `.
/// These characters only occur inside JSON strings, so replacing them in the
/// whole text is safe. It keeps the body byte-identical to go's:
/// `/v2/teal/disassemble` results and error messages carry `&&`, `<=` and `>`,
/// and a source map names its source `<body>` / `<stdin>`.
pub fn escape_json_like_go(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::escape_json_like_go;

    #[test]
    fn escapes_what_go_escapes() {
        assert_eq!(
            escape_json_like_go("{\"a\":\"<b> && \u{2028}\u{2029}é\"}"),
            "{\"a\":\"\\u003cb\\u003e \\u0026\\u0026 \\u2028\\u2029é\"}"
        );
    }
}
