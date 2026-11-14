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

//! SHA-512/256 for the hot paths (issue #2321).
//!
//! go-algorand hashes with `crypto/sha512`'s hand-written AVX2 assembly. The
//! `sha2` crate's own x86-64 backend (AVX2 intrinsics, selected at run time) is
//! about 11% slower on inputs of 1 KiB and more (1,342 ns vs 1,205 ns for 1 KiB,
//! 75.3 us vs 66.8 us for 64 KiB, same host). `ring`'s SHA-512/256 is
//! BoringSSL's assembly: faster than `sha2`, and ahead of go on the same
//! inputs. `ring` is already linked into the node binary (`hickory-resolver`),
//! so this adds no code to it, only a direct dependency of this crate.
//!
//! Every function here equals `sha2::Sha512_256` and go's `sha512.Sum512_256`
//! on every input: `tests/sha512_256_test.rs` pins the NIST vectors (generated
//! with go's standard library) and compares against `sha2` over every length
//! up to 4,500 bytes and the block boundaries of larger inputs.

use ring::digest::{Context, SHA512_256};

/// SHA-512/256 of the concatenation of `parts`, without concatenating them.
///
/// ```
/// let digest = algo_codec::hash::sha512_256(&[b"a", b"bc"]);
/// assert_eq!(digest, algo_codec::hash::sha512_256(&[b"abc"]));
/// ```
#[inline]
pub fn sha512_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = Context::new(&SHA512_256);
    for part in parts {
        ctx.update(part);
    }
    finish(ctx)
}

/// Incremental SHA-512/256, for callers that feed data as they produce it.
#[derive(Clone)]
pub struct Sha512_256Hasher(Context);

impl Default for Sha512_256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512_256Hasher {
    /// A hasher over the empty input.
    #[inline]
    pub fn new() -> Self {
        Self(Context::new(&SHA512_256))
    }

    /// Append `data`.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything appended so far.
    #[inline]
    pub fn finalize(self) -> [u8; 32] {
        finish(self.0)
    }
}

#[inline]
fn finish(ctx: Context) -> [u8; 32] {
    let digest = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}
