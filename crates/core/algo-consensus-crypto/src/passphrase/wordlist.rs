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

//! The 2,048-word Algorand mnemonic wordlist.
//!
//! Sourced verbatim from `../go-algorand/crypto/passphrase/wordlist.go`
//! (v4.6.0-stable). The raw text — `"abandon\nability\n...\nzoo\n"` — is
//! preserved byte-for-byte so the SHA-512/256 wordlist checksum matches Go
//! (`venue`). See `passphrase_test.go::TestZeroVector` for the canonical
//! cross-reference.

use std::sync::OnceLock;

/// Raw wordlist text — exactly the bytes between Go's backticks in
/// `wordlistRaw`. Hashed by [`super::wordlist_checksum`] at startup.
pub(crate) const WORDLIST_RAW: &str = include_str!("wordlist.txt");

/// 2,048 words, indexed 0..2047. Computed once and cached.
pub(crate) fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        // Match Go: `strings.Split(wordlistRaw, "\n")` yields 2049 entries —
        // the trailing empty string is preserved so index math (e.g. the
        // checksum lookup of position [2047]) lines up with Go exactly.
        // We only ever look up 0..2047 in normal operation, but expose the
        // full split so any future divergence vs Go is byte-identical.
        let mut split: Vec<&'static str> = WORDLIST_RAW.split('\n').collect();
        // Trim the trailing empty entry caused by the terminating '\n' so
        // callers can iterate `wordlist()` without seeing an empty string.
        // Index-based lookups (0..2047) are unaffected.
        if split.last().is_some_and(|w| w.is_empty()) {
            split.pop();
        }
        debug_assert_eq!(split.len(), 2048, "Algorand wordlist must be 2048 words");
        split
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_has_2048_entries() {
        assert_eq!(wordlist().len(), 2048);
        assert_eq!(wordlist()[0], "abandon");
        assert_eq!(wordlist()[2047], "zoo");
    }
}
