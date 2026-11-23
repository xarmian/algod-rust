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

//! go-algorand v5.1 `limitedBytes` (`data/transactions/logic/eval.go`): how an
//! error message shows a program-supplied byte string.

/// Most bytes of a program-supplied value an error shows (`maxQuotedLen`).
pub const MAX_QUOTED_LEN: usize = 16;

/// `limitedBytes.String()`: the first [`MAX_QUOTED_LEN`] bytes, as text when
/// every shown byte is printable ASCII (`0x20..=0x7e`) and `0x<hex>` otherwise,
/// followed by `... (<len> bytes)` when truncated.
pub fn limited_bytes(b: &[u8]) -> String {
    let shown = &b[..b.len().min(MAX_QUOTED_LEN)];
    let mut s = if shown.iter().all(|c| (0x20..=0x7e).contains(c)) {
        String::from_utf8_lossy(shown).into_owned()
    } else {
        format!("0x{}", data_encoding::HEXLOWER.encode(shown))
    };
    if shown.len() < b.len() {
        s.push_str(&format!("... ({} bytes)", b.len()));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_short_value_is_shown_as_text() {
        assert_eq!(limited_bytes(b"x"), "x");
        assert_eq!(limited_bytes(b""), "");
    }

    #[test]
    fn non_printable_value_is_shown_as_hex() {
        assert_eq!(limited_bytes(&[0, 0x7f]), "0x007f");
        assert_eq!(limited_bytes(&[0x19]), "0x19");
    }

    #[test]
    fn long_value_is_cut_to_sixteen_bytes_with_its_length() {
        let v = vec![b'a'; 20];
        assert_eq!(limited_bytes(&v), format!("{}... (20 bytes)", "a".repeat(16)));
        let v = vec![1u8; 17];
        assert_eq!(limited_bytes(&v), format!("0x{}... (17 bytes)", "01".repeat(16)));
    }
}
