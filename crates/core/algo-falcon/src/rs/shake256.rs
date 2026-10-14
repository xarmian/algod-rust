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

//! SHAKE256 with Falcon's incremental context semantics (`shake.c`,
//! `inner_shake256_context`).
//!
//! Ported from the Falcon reference implementation, `falcon-c/shake.c`
//! (Copyright (c) 2017-2019 Falcon Project, MIT License, author Thomas
//! Pornin), vendored verbatim under `crates/core/algo-falcon/falcon-c/` as
//! part of github.com/algorand/falcon v0.1.0; the MIT notice is preserved in
//! `falcon-c/LICENSE`. MIT's only obligation is keeping that notice, which
//! this attribution and the vendored file do.
//!
//! Falcon uses SHAKE256 in three places: as the seed-derived keygen RNG, as
//! the sampler RNG during deterministic signing, and to hash the (salt ||
//! message) into a point. All three go through this exact
//! inject / flip / extract state machine, so the port keeps it byte for byte:
//!
//! - `inject` XORs input bytes into the 136-byte rate region, permuting
//!   whenever the region fills;
//! - `flip` applies the SHAKE padding (`0x1F` at the current position, `0x80`
//!   in the last rate byte) and sets the pointer to the end so that the first
//!   `extract` permutes;
//! - `extract` copies bytes out of the rate region, permuting whenever it is
//!   exhausted. Extraction can be interleaved with further extraction only
//!   (never with injection), exactly like the C.
//!
//! The Keccak-f[1600] permutation in the C is a lane-complemented, unrolled
//! variant for speed; since the permutation is fully specified by FIPS 202
//! and the output is checked against the C and NIST vectors, this port uses
//! the plain θ-ρ-π-χ-ι formulation.

/// SHAKE256 rate in bytes (1600 - 2·256 bits).
const RATE: usize = 136;

/// Round constants of Keccak-f[1600] (`RC[]` in `shake.c`).
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// ρ rotation offsets, indexed by lane `x + 5*y`.
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Keccak-f[1600] on the 25-lane state (`process_block` in `shake.c`).
fn process_block(a: &mut [u64; 25]) {
    for rc in RC {
        // θ
        let mut c = [0u64; 5];
        for (x, cx) in c.iter_mut().enumerate() {
            *cx = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // ρ and π
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let src = x + 5 * y;
                let dst = y + 5 * ((2 * x + 3 * y) % 5);
                b[dst] = a[src].rotate_left(RHO[src]);
            }
        }
        // χ
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // ι
        a[0] ^= rc;
    }
}

/// Falcon's `inner_shake256_context`: the Keccak state plus the byte
/// position inside the rate region.
#[derive(Clone)]
pub(crate) struct Shake256 {
    a: [u64; 25],
    dptr: usize,
}

impl Shake256 {
    /// `inner_shake256_init`.
    pub(crate) fn new() -> Self {
        Shake256 {
            a: [0u64; 25],
            dptr: 0,
        }
    }

    /// `shake256_init_prng_from_seed` (`falcon.c`): init, inject the seed,
    /// flip.
    pub(crate) fn prng_from_seed(seed: &[u8]) -> Self {
        let mut sc = Shake256::new();
        sc.inject(seed);
        sc.flip();
        sc
    }

    #[inline]
    fn xor_byte(&mut self, pos: usize, v: u8) {
        // Little-endian lane layout: byte `pos` is byte `pos & 7` of lane `pos >> 3`.
        self.a[pos >> 3] ^= u64::from(v) << ((pos & 7) << 3);
    }

    #[inline]
    fn byte_at(&self, pos: usize) -> u8 {
        (self.a[pos >> 3] >> ((pos & 7) << 3)) as u8
    }

    /// `inner_shake256_inject`.
    pub(crate) fn inject(&mut self, mut input: &[u8]) {
        let mut dptr = self.dptr;
        while !input.is_empty() {
            let clen = (RATE - dptr).min(input.len());
            let (chunk, rest) = input.split_at(clen);
            for (u, &b) in chunk.iter().enumerate() {
                self.xor_byte(dptr + u, b);
            }
            dptr += clen;
            input = rest;
            if dptr == RATE {
                process_block(&mut self.a);
                dptr = 0;
            }
        }
        self.dptr = dptr;
    }

    /// `inner_shake256_flip`: pad and switch to output mode.
    pub(crate) fn flip(&mut self) {
        let dptr = self.dptr;
        self.xor_byte(dptr, 0x1F);
        self.xor_byte(RATE - 1, 0x80);
        self.dptr = RATE;
    }

    /// `inner_shake256_extract`.
    pub(crate) fn extract(&mut self, mut out: &mut [u8]) {
        let mut dptr = self.dptr;
        while !out.is_empty() {
            if dptr == RATE {
                process_block(&mut self.a);
                dptr = 0;
            }
            let clen = (RATE - dptr).min(out.len());
            let (chunk, rest) = out.split_at_mut(clen);
            for (u, o) in chunk.iter_mut().enumerate() {
                *o = self.byte_at(dptr + u);
            }
            dptr += clen;
            out = rest;
        }
        self.dptr = dptr;
    }

    /// Convenience: extract `n` bytes into a fresh vector.
    pub(crate) fn extract_vec(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.extract(&mut v);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn shake(msg: &[u8], n: usize) -> Vec<u8> {
        let mut sc = Shake256::new();
        sc.inject(msg);
        sc.flip();
        sc.extract_vec(n)
    }

    /// FIPS 202 / NIST SHAKE256 known answers.
    #[test]
    fn nist_known_answers() {
        assert_eq!(
            hex(&shake(b"", 32)),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
        assert_eq!(
            hex(&shake(b"abc", 32)),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        );
        // 512 bytes of output for the empty message: last 32 bytes, from the
        // NIST SHAKE256 ShortMsg/VariableOut vectors.
        let out = shake(b"", 512);
        assert_eq!(
            hex(&out[480..]),
            "ab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a"
        );
    }

    /// Injecting the same bytes in different chunkings, and extracting in
    /// different chunkings, never changes the output.
    #[test]
    fn chunking_is_transparent() {
        let msg: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        let want = shake(&msg, 700);
        for chunk in [1usize, 7, 135, 136, 137, 300] {
            let mut sc = Shake256::new();
            for c in msg.chunks(chunk) {
                sc.inject(c);
            }
            sc.flip();
            let mut got = Vec::new();
            while got.len() < 700 {
                let n = chunk.min(700 - got.len());
                got.extend(sc.extract_vec(n));
            }
            assert_eq!(got, want, "chunk size {chunk}");
        }
    }

    #[test]
    fn prng_from_seed_is_init_inject_flip() {
        let seed = [0x5au8; 32];
        let mut a = Shake256::prng_from_seed(&seed);
        let mut b = Shake256::new();
        b.inject(&seed);
        b.flip();
        assert_eq!(a.extract_vec(300), b.extract_vec(300));
    }
}

/// Differential tests against the vendored C (`falcon_inner_i_shake256_*`
/// and the public `shake256_init_prng_from_seed`).
#[cfg(all(test, feature = "c-backend"))]
mod c_diff {
    use super::*;
    use crate::c_internals::{self, CInnerShake256};

    /// Tiny deterministic PRNG for test input shapes (xorshift64*).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> usize {
            (self.next() % n) as usize
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    #[test]
    fn random_inject_flip_extract_sequences_match_c() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for case in 0..200 {
            let mut rs = Shake256::new();
            let mut c = CInnerShake256::new();
            // 0..8 injections of 0..400 bytes each (crossing the 136-byte rate
            // boundary in every way).
            for _ in 0..rng.below(9) {
                let n = rng.below(401);
                let data = rng.bytes(n);
                rs.inject(&data);
                c.inject(&data);
            }
            rs.flip();
            c.flip();
            // 1..6 extractions of 0..500 bytes each.
            for _ in 0..1 + rng.below(6) {
                let n = rng.below(501);
                let got = rs.extract_vec(n);
                let want = c.extract_vec(n);
                assert_eq!(got, want, "case {case}: extract {n} bytes differs from C");
            }
        }
    }

    #[test]
    fn prng_from_seed_matches_c_public_api() {
        for seed_len in [0usize, 1, 31, 32, 48, 135, 136, 137, 500] {
            let seed: Vec<u8> = (0..seed_len).map(|i| (i * 13 + 1) as u8).collect();
            let mut rs = Shake256::prng_from_seed(&seed);
            let got = rs.extract_vec(1024);
            let want = c_internals::shake256_prng_from_seed_extract(&seed, 1024);
            assert_eq!(got, want, "seed length {seed_len}");
        }
    }
}
