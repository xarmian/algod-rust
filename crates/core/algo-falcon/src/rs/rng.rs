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

//! The ChaCha20-based PRNG that the Gaussian sampler (signing) draws from
//! (`rng.c`, `prng` in `inner.h`). Key generation does *not* use it in the
//! vendored build (`FALCON_KG_CHACHA20` is commented out in `config.h`);
//! it samples from SHAKE256 directly.
//!
//! Ported from the Falcon reference implementation, `falcon-c/rng.c` and
//! `falcon-c/inner.h` (Copyright (c) 2017-2019 Falcon Project, MIT License,
//! author Thomas Pornin), vendored verbatim under
//! `crates/core/algo-falcon/falcon-c/` as part of github.com/algorand/falcon
//! v0.1.0; the MIT notice is preserved in `falcon-c/LICENSE`.
//!
//! The PRNG is seeded with 56 bytes from a SHAKE256 context (a 48-byte key
//! half plus an 8-byte little-endian block counter) and refills a 512-byte
//! buffer with 8 ChaCha20 blocks at a time, interleaved exactly as the C's
//! little-endian build lays them out (`buf[u + (v << 3)]` as 32-bit words),
//! because consumers read the buffer by position.

use super::shake256::Shake256;

/// The ChaCha20 constant words ("expand 32-byte k").
const CW: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// `prng` (`inner.h`): a 512-byte output buffer, the read position, and the
/// 56 bytes of ChaCha20 key/counter state (stored as the C stores them, as
/// bytes; only the first 56 of the C's 256 state bytes are ever used).
#[derive(Clone)]
pub(crate) struct Prng {
    buf: [u8; 512],
    ptr: usize,
    state: [u8; 56],
}

impl Prng {
    /// `prng_init`: seed from `src` (56 bytes) and fill the buffer.
    pub(crate) fn init(src: &mut Shake256) -> Self {
        let mut p = Prng {
            buf: [0u8; 512],
            ptr: 0,
            state: [0u8; 56],
        };
        src.extract(&mut p.state);
        p.refill();
        p
    }

    #[inline(always)]
    fn state_word(&self, i: usize) -> u32 {
        u32::from_le_bytes([
            self.state[i * 4],
            self.state[i * 4 + 1],
            self.state[i * 4 + 2],
            self.state[i * 4 + 3],
        ])
    }

    /// `prng_refill`: generate 8 ChaCha20 blocks into the buffer.
    pub(crate) fn refill(&mut self) {
        let mut cc: u64 = u64::from_le_bytes(self.state[48..56].try_into().unwrap());
        for u in 0..8usize {
            let mut state = [0u32; 16];
            state[..4].copy_from_slice(&CW);
            for (v, w) in state.iter_mut().enumerate().skip(4) {
                *w = self.state_word(v - 4);
            }
            state[14] ^= cc as u32;
            state[15] ^= (cc >> 32) as u32;
            for _ in 0..10 {
                macro_rules! qround {
                    ($a:expr, $b:expr, $c:expr, $d:expr) => {{
                        state[$a] = state[$a].wrapping_add(state[$b]);
                        state[$d] ^= state[$a];
                        state[$d] = state[$d].rotate_left(16);
                        state[$c] = state[$c].wrapping_add(state[$d]);
                        state[$b] ^= state[$c];
                        state[$b] = state[$b].rotate_left(12);
                        state[$a] = state[$a].wrapping_add(state[$b]);
                        state[$d] ^= state[$a];
                        state[$d] = state[$d].rotate_left(8);
                        state[$c] = state[$c].wrapping_add(state[$d]);
                        state[$b] ^= state[$c];
                        state[$b] = state[$b].rotate_left(7);
                    }};
                }
                qround!(0, 4, 8, 12);
                qround!(1, 5, 9, 13);
                qround!(2, 6, 10, 14);
                qround!(3, 7, 11, 15);
                qround!(0, 5, 10, 15);
                qround!(1, 6, 11, 12);
                qround!(2, 7, 8, 13);
                qround!(3, 4, 9, 14);
            }
            for v in 0..4 {
                state[v] = state[v].wrapping_add(CW[v]);
            }
            for (v, w) in state.iter_mut().enumerate().take(14).skip(4) {
                *w = w.wrapping_add(self.state_word(v - 4));
            }
            state[14] = state[14].wrapping_add(self.state_word(10) ^ (cc as u32));
            state[15] = state[15].wrapping_add(self.state_word(11) ^ ((cc >> 32) as u32));
            cc = cc.wrapping_add(1);
            for (v, w) in state.iter().enumerate() {
                let off = (u + (v << 3)) * 4;
                self.buf[off..off + 4].copy_from_slice(&w.to_le_bytes());
            }
        }
        self.state[48..56].copy_from_slice(&cc.to_le_bytes());
        self.ptr = 0;
    }

    /// `prng_get_bytes`, verbatim: note the C copies from the *start* of
    /// the buffer regardless of `ptr` (it is not used by the signing or
    /// key-generation paths; kept only for parity).
    pub(crate) fn get_bytes(&mut self, dst: &mut [u8]) {
        let mut dst = dst;
        while !dst.is_empty() {
            let clen = (512 - self.ptr).min(dst.len());
            let (head, rest) = dst.split_at_mut(clen);
            head.copy_from_slice(&self.buf[..clen]);
            dst = rest;
            self.ptr += clen;
            if self.ptr == 512 {
                self.refill();
            }
        }
    }

    /// `prng_get_u64`: next 8 bytes as a little-endian `u64` (refilling when
    /// fewer than 9 bytes remain, exactly as the C).
    #[inline]
    pub(crate) fn get_u64(&mut self) -> u64 {
        let mut u = self.ptr;
        if u >= 512 - 9 {
            self.refill();
            u = 0;
        }
        self.ptr = u + 8;
        u64::from_le_bytes(self.buf[u..u + 8].try_into().unwrap())
    }

    /// `prng_get_u8`: next byte.
    #[inline]
    pub(crate) fn get_u8(&mut self) -> u32 {
        let v = self.buf[self.ptr];
        self.ptr += 1;
        if self.ptr == 512 {
            self.refill();
        }
        u32::from(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_deterministic_and_u64_reads_are_byte_aligned() {
        let seed = [3u8; 32];
        let mut a = Prng::init(&mut Shake256::prng_from_seed(&seed));
        let mut b = Prng::init(&mut Shake256::prng_from_seed(&seed));
        for _ in 0..2000 {
            assert_eq!(a.get_u64(), b.get_u64());
        }
        for _ in 0..3000 {
            assert_eq!(a.get_u8(), b.get_u8());
        }
    }
}

/// Differential tests against the vendored C (`falcon_inner_prng_*` and
/// the shimmed inline `prng_get_u64` / `prng_get_u8`).
#[cfg(all(test, feature = "c-backend"))]
mod c_diff {
    use super::*;
    use crate::c_internals::{self as c, CInnerShake256, CPrng};

    #[test]
    fn refill_stream_matches_c() {
        for seed_len in [0usize, 1, 32, 55, 56, 57, 200] {
            let seed: Vec<u8> = (0..seed_len).map(|i| (i * 31 + 7) as u8).collect();
            let mut rs_src = Shake256::prng_from_seed(&seed);
            let mut c_src = CInnerShake256::new();
            c_src.inject(&seed);
            c_src.flip();
            let mut rs = Prng::init(&mut rs_src);
            let mut cp = CPrng::init(&mut c_src);
            // Compare the initial buffer + state, then 20 successive refills.
            for round in 0..20 {
                assert_eq!(
                    rs.buf[..],
                    cp.buf()[..],
                    "seed_len {seed_len} round {round}: buffer"
                );
                assert_eq!(
                    rs.state[..],
                    cp.state()[..56],
                    "seed_len {seed_len} round {round}: state"
                );
                rs.refill();
                unsafe { c::falcon_inner_prng_refill(&mut cp) };
            }
            // The SHAKE sources must have consumed the same amount.
            assert_eq!(rs_src.extract_vec(32), c_src.extract_vec(32));
        }
    }

    #[cfg(feature = "c-internals-test")]
    #[test]
    fn get_u64_and_get_u8_match_c_including_refill_boundaries() {
        use crate::c_internals::shim as sh;
        let seed = [0x5au8; 32];
        let mut rs = Prng::init(&mut Shake256::prng_from_seed(&seed));
        let mut c_src = CInnerShake256::new();
        c_src.inject(&seed);
        c_src.flip();
        let mut cp = CPrng::init(&mut c_src);
        let mut pattern = 0x9E37_79B9_7F4A_7C15u64;
        for i in 0..20_000 {
            pattern ^= pattern << 13;
            pattern ^= pattern >> 7;
            pattern ^= pattern << 17;
            match pattern % 3 {
                0 => assert_eq!(
                    rs.get_u64(),
                    unsafe { sh::falcon_shim_x_prng_get_u64(&mut cp) },
                    "step {i}: u64"
                ),
                _ => assert_eq!(
                    rs.get_u8(),
                    unsafe { sh::falcon_shim_x_prng_get_u8(&mut cp) },
                    "step {i}: u8"
                ),
            }
        }
        let mut a = vec![0u8; 700];
        let mut b = vec![0u8; 700];
        rs.get_bytes(&mut a);
        unsafe { c::falcon_inner_prng_get_bytes(&mut cp, b.as_mut_ptr(), 700) };
        assert_eq!(a, b, "get_bytes");
    }
}
