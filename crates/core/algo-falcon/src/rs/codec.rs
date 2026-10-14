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

//! Key and signature encodings (`codec.c`): public keys as 14-bit values
//! mod q, private keys as trimmed signed integers, signatures either as
//! trimmed signed integers ("CT" form) or Golomb-Rice-like compressed form.
//!
//! Ported from the Falcon reference implementation, `falcon-c/codec.c`
//! (Copyright (c) 2017-2019 Falcon Project, MIT License, author Thomas
//! Pornin), vendored verbatim under `crates/core/algo-falcon/falcon-c/` as
//! part of github.com/algorand/falcon v0.1.0; the MIT notice is preserved in
//! `falcon-c/LICENSE`.
//!
//! Every function keeps the C contract exactly: the return value is the
//! number of bytes produced/consumed, and `0` means "error" (out-of-range
//! value, buffer too small, non-canonical encoding, non-zero padding bits).
//! An encoder called with `out = None` only computes the output length, like
//! the C's `out == NULL`. These reject-paths are consensus-visible (they are
//! how malformed public keys and signatures are refused), so the
//! differential tests feed random and adversarial bytes through both.

/// `max_fg_bits[logn]`: bit width of the f/g private-key coefficients.
pub(crate) const MAX_FG_BITS: [u8; 11] = [0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5];

/// `max_FG_bits[logn]`: bit width of the F/G private-key coefficients.
pub(crate) const MAX_FG_BITS_BIG: [u8; 11] = [0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8];

/// `max_sig_bits[logn]`: bit width of a CT-form signature coefficient.
pub(crate) const MAX_SIG_BITS: [u8; 11] = [0, 10, 11, 11, 12, 12, 12, 12, 12, 12, 12];

/// `modq_encode`: `n = 2^logn` values in `[0, 12289)` packed as 14-bit
/// big-endian fields.
pub(crate) fn modq_encode(out: Option<&mut [u8]>, x: &[u16], logn: u32) -> usize {
    let n = 1usize << logn;
    if x[..n].iter().any(|&v| v >= 12289) {
        return 0;
    }
    let out_len = ((n * 14) + 7) >> 3;
    let Some(buf) = out else {
        return out_len;
    };
    if out_len > buf.len() {
        return 0;
    }
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut v = 0usize;
    for &xu in &x[..n] {
        acc = (acc << 14) | u32::from(xu);
        acc_len += 14;
        while acc_len >= 8 {
            acc_len -= 8;
            buf[v] = (acc >> acc_len) as u8;
            v += 1;
        }
    }
    if acc_len > 0 {
        buf[v] = (acc << (8 - acc_len)) as u8;
    }
    out_len
}

/// `modq_decode`: inverse of [`modq_encode`]; rejects values `>= 12289` and
/// non-zero padding bits.
pub(crate) fn modq_decode(x: &mut [u16], logn: u32, input: &[u8]) -> usize {
    let n = 1usize << logn;
    let in_len = ((n * 14) + 7) >> 3;
    if in_len > input.len() {
        return 0;
    }
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut u = 0usize;
    let mut v = 0usize;
    while u < n {
        acc = (acc << 8) | u32::from(input[v]);
        v += 1;
        acc_len += 8;
        if acc_len >= 14 {
            acc_len -= 14;
            let w = (acc >> acc_len) & 0x3FFF;
            if w >= 12289 {
                return 0;
            }
            x[u] = w as u16;
            u += 1;
        }
    }
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return 0;
    }
    in_len
}

/// `trim_i16_encode`: `n` signed values, each in `[-(2^(bits-1)-1),
/// 2^(bits-1)-1]`, packed as `bits`-wide two's-complement fields.
pub(crate) fn trim_i16_encode(out: Option<&mut [u8]>, x: &[i16], logn: u32, bits: u32) -> usize {
    let n = 1usize << logn;
    let maxv: i32 = (1i32 << (bits - 1)) - 1;
    let minv: i32 = -maxv;
    if x[..n]
        .iter()
        .any(|&v| i32::from(v) < minv || i32::from(v) > maxv)
    {
        return 0;
    }
    let out_len = ((n * bits as usize) + 7) >> 3;
    let Some(buf) = out else {
        return out_len;
    };
    if out_len > buf.len() {
        return 0;
    }
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mask: u32 = (1u32 << bits) - 1;
    let mut v = 0usize;
    for &xu in &x[..n] {
        acc = (acc << bits) | (u32::from(xu as u16) & mask);
        acc_len += bits;
        while acc_len >= 8 {
            acc_len -= 8;
            buf[v] = (acc >> acc_len) as u8;
            v += 1;
        }
    }
    if acc_len > 0 {
        buf[v] = (acc << (8 - acc_len)) as u8;
    }
    out_len
}

/// `trim_i16_decode`: inverse of [`trim_i16_encode`]; rejects the
/// `-2^(bits-1)` encoding and non-zero padding bits.
pub(crate) fn trim_i16_decode(x: &mut [i16], logn: u32, bits: u32, input: &[u8]) -> usize {
    let n = 1usize << logn;
    let in_len = ((n * bits as usize) + 7) >> 3;
    if in_len > input.len() {
        return 0;
    }
    let mut u = 0usize;
    let mut v = 0usize;
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mask1: u32 = (1u32 << bits) - 1;
    let mask2: u32 = 1u32 << (bits - 1);
    while u < n {
        acc = (acc << 8) | u32::from(input[v]);
        v += 1;
        acc_len += 8;
        while acc_len >= bits && u < n {
            acc_len -= bits;
            let mut w = (acc >> acc_len) & mask1;
            w |= (w & mask2).wrapping_neg();
            if w == mask2.wrapping_neg() {
                return 0;
            }
            w |= (w & mask2).wrapping_neg();
            x[u] = (w as i32) as i16;
            u += 1;
        }
    }
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return 0;
    }
    in_len
}

/// `trim_i8_encode`: as [`trim_i16_encode`] for 8-bit coefficients.
pub(crate) fn trim_i8_encode(out: Option<&mut [u8]>, x: &[i8], logn: u32, bits: u32) -> usize {
    let n = 1usize << logn;
    let maxv: i32 = (1i32 << (bits - 1)) - 1;
    let minv: i32 = -maxv;
    if x[..n]
        .iter()
        .any(|&v| i32::from(v) < minv || i32::from(v) > maxv)
    {
        return 0;
    }
    let out_len = ((n * bits as usize) + 7) >> 3;
    let Some(buf) = out else {
        return out_len;
    };
    if out_len > buf.len() {
        return 0;
    }
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mask: u32 = (1u32 << bits) - 1;
    let mut v = 0usize;
    for &xu in &x[..n] {
        acc = (acc << bits) | (u32::from(xu as u8) & mask);
        acc_len += bits;
        while acc_len >= 8 {
            acc_len -= 8;
            buf[v] = (acc >> acc_len) as u8;
            v += 1;
        }
    }
    if acc_len > 0 {
        buf[v] = (acc << (8 - acc_len)) as u8;
    }
    out_len
}

/// `trim_i8_decode`: as [`trim_i16_decode`] for 8-bit coefficients.
pub(crate) fn trim_i8_decode(x: &mut [i8], logn: u32, bits: u32, input: &[u8]) -> usize {
    let n = 1usize << logn;
    let in_len = ((n * bits as usize) + 7) >> 3;
    if in_len > input.len() {
        return 0;
    }
    let mut u = 0usize;
    let mut v = 0usize;
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mask1: u32 = (1u32 << bits) - 1;
    let mask2: u32 = 1u32 << (bits - 1);
    while u < n {
        acc = (acc << 8) | u32::from(input[v]);
        v += 1;
        acc_len += 8;
        while acc_len >= bits && u < n {
            acc_len -= bits;
            let mut w = (acc >> acc_len) & mask1;
            w |= (w & mask2).wrapping_neg();
            if w == mask2.wrapping_neg() {
                return 0;
            }
            x[u] = (w as i32) as i8;
            u += 1;
        }
    }
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return 0;
    }
    in_len
}

/// `comp_encode`: compressed signature encoding. Each coefficient in
/// `[-2047, 2047]` becomes a sign bit, its 7 low bits, then its high part
/// in unary (`w` zeros and a terminating one). Returns the byte count, or 0
/// on an out-of-range value or a too-small buffer.
pub(crate) fn comp_encode(out: Option<&mut [u8]>, x: &[i16], logn: u32) -> usize {
    let n = 1usize << logn;
    if x[..n].iter().any(|&t| !(-2047..=2047).contains(&t)) {
        return 0;
    }
    let mut buf = out;
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut v = 0usize;
    for &xu in &x[..n] {
        let mut t = i32::from(xu);
        acc <<= 1;
        if t < 0 {
            t = -t;
            acc |= 1;
        }
        let mut w = t as u32;
        acc <<= 7;
        acc |= w & 127;
        w >>= 7;
        acc_len += 8;
        acc <<= w + 1;
        acc |= 1;
        acc_len += w + 1;
        while acc_len >= 8 {
            acc_len -= 8;
            if let Some(b) = &mut buf {
                if v >= b.len() {
                    return 0;
                }
                b[v] = (acc >> acc_len) as u8;
            }
            v += 1;
        }
    }
    if acc_len > 0 {
        if let Some(b) = &mut buf {
            if v >= b.len() {
                return 0;
            }
            b[v] = (acc << (8 - acc_len)) as u8;
        }
        v += 1;
    }
    v
}

/// `comp_decode`: inverse of [`comp_encode`]. Returns the number of bytes
/// consumed, or 0 on truncation, a value above 2047, a "negative zero", or
/// non-zero padding bits.
pub(crate) fn comp_decode(x: &mut [i16], logn: u32, input: &[u8]) -> usize {
    let n = 1usize << logn;
    let max_in_len = input.len();
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut v = 0usize;
    for xu in x[..n].iter_mut() {
        if v >= max_in_len {
            return 0;
        }
        acc = (acc << 8) | u32::from(input[v]);
        v += 1;
        let b = acc >> acc_len;
        let s = b & 128;
        let mut m = b & 127;
        loop {
            if acc_len == 0 {
                if v >= max_in_len {
                    return 0;
                }
                acc = (acc << 8) | u32::from(input[v]);
                v += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 128;
            if m > 2047 {
                return 0;
            }
        }
        if s != 0 && m == 0 {
            return 0;
        }
        *xu = if s != 0 { -(m as i32) } else { m as i32 } as i16;
    }
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return 0;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modq_round_trips_and_rejects_out_of_range() {
        let logn = 10;
        let x: Vec<u16> = (0..1024u32)
            .map(|i| ((i * 12_007) % 12289) as u16)
            .collect();
        let len = modq_encode(None, &x, logn);
        assert_eq!(len, 1792);
        let mut buf = vec![0u8; len];
        assert_eq!(modq_encode(Some(&mut buf), &x, logn), len);
        let mut y = vec![0u16; 1024];
        assert_eq!(modq_decode(&mut y, logn, &buf), len);
        assert_eq!(x, y);
        let mut bad = x.clone();
        bad[5] = 12289;
        assert_eq!(modq_encode(None, &bad, logn), 0);
        assert_eq!(modq_decode(&mut y, logn, &buf[..len - 1]), 0);
    }

    #[test]
    fn trim_i16_round_trips_and_rejects_minimum() {
        let logn = 10;
        let bits = 12;
        let x: Vec<i16> = (0..1024i32)
            .map(|i| ((i * 37) % 4095 - 2047) as i16)
            .collect();
        let len = trim_i16_encode(None, &x, logn, bits);
        assert_eq!(len, 1536);
        let mut buf = vec![0u8; len];
        assert_eq!(trim_i16_encode(Some(&mut buf), &x, logn, bits), len);
        let mut y = vec![0i16; 1024];
        assert_eq!(trim_i16_decode(&mut y, logn, bits, &buf), len);
        assert_eq!(x, y);
        let mut bad = x.clone();
        bad[0] = -2048;
        assert_eq!(trim_i16_encode(None, &bad, logn, bits), 0);
        // The all-ones-then-zero pattern decodes a -2048 and is rejected.
        let mut enc = buf.clone();
        enc[0] = 0x80;
        enc[1] &= 0x0F;
        assert_eq!(trim_i16_decode(&mut y, logn, bits, &enc), 0);
    }

    #[test]
    fn trim_i8_round_trips() {
        let logn = 10;
        let bits = 5;
        let x: Vec<i8> = (0..1024i32).map(|i| ((i * 7) % 31 - 15) as i8).collect();
        let len = trim_i8_encode(None, &x, logn, bits);
        assert_eq!(len, 640);
        let mut buf = vec![0u8; len];
        assert_eq!(trim_i8_encode(Some(&mut buf), &x, logn, bits), len);
        let mut y = vec![0i8; 1024];
        assert_eq!(trim_i8_decode(&mut y, logn, bits, &buf), len);
        assert_eq!(x, y);
    }

    #[test]
    fn comp_round_trips_and_rejects_negative_zero_and_padding() {
        let logn = 10;
        let x: Vec<i16> = (0..1024i32)
            .map(|i| ((i * 101) % 4095 - 2047) as i16)
            .collect();
        let len = comp_encode(None, &x, logn);
        assert!(len > 0);
        let mut buf = vec![0u8; len];
        assert_eq!(comp_encode(Some(&mut buf), &x, logn), len);
        let mut y = vec![0i16; 1024];
        assert_eq!(comp_decode(&mut y, logn, &buf), len);
        assert_eq!(x, y);
        assert_eq!(comp_encode(Some(&mut buf[..len - 1]), &x, logn), 0);
        assert_eq!(comp_decode(&mut y, logn, &buf[..len - 1]), 0);
        // "-0": sign bit set, 7 zero bits, terminator.
        let neg_zero = [0x80, 0x80];
        assert_eq!(comp_decode(&mut y, 1, &neg_zero), 0);
        // Trailing padding bits must be zero: a single coefficient 0 encodes
        // as 0x00 0x80 (8 bits + terminator); a set padding bit is rejected.
        assert_eq!(comp_decode(&mut y, 0, &[0x00, 0x80]), 2);
        assert_eq!(comp_decode(&mut y, 0, &[0x00, 0x81]), 0);
    }
}

/// Differential tests against the vendored C (`falcon_inner_*` in codec.c).
#[cfg(all(test, feature = "c-backend"))]
mod c_diff {
    use super::*;
    use crate::c_internals as c;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    #[test]
    fn tables_match_c() {
        unsafe {
            assert_eq!(MAX_FG_BITS, c::falcon_inner_max_fg_bits);
            assert_eq!(MAX_FG_BITS_BIG, c::falcon_inner_max_FG_bits);
            assert_eq!(MAX_SIG_BITS, c::falcon_inner_max_sig_bits);
        }
    }

    #[test]
    fn modq_encode_decode_match_c_on_random_and_adversarial_inputs() {
        let mut rng = Rng(0x1234_5678_9ABC_DEF1);
        for case in 0..300 {
            let logn = 1 + (case % 10) as u32;
            let n = 1usize << logn;
            // Mostly in-range values; occasionally one out of range.
            let mut x: Vec<u16> = (0..n).map(|_| rng.below(12289) as u16).collect();
            if case % 7 == 0 {
                x[rng.below(n as u64) as usize] = 12289 + rng.below(100) as u16;
            }
            let want_len =
                unsafe { c::falcon_inner_modq_encode(std::ptr::null_mut(), 0, x.as_ptr(), logn) };
            assert_eq!(
                modq_encode(None, &x, logn),
                want_len,
                "case {case}: length query"
            );
            let cap = ((n * 14) + 7) >> 3;
            let mut a = vec![0u8; cap];
            let mut b = vec![0u8; cap];
            let ra = modq_encode(Some(&mut a), &x, logn);
            let rb = unsafe { c::falcon_inner_modq_encode(b.as_mut_ptr(), cap, x.as_ptr(), logn) };
            assert_eq!((ra, &a), (rb, &b), "case {case}: encode");
            // Decode the encoding, a truncated copy, a bit-flipped copy, and random bytes.
            let mut inputs = vec![a.clone(), a[..cap.saturating_sub(1)].to_vec()];
            let mut flipped = a.clone();
            if !flipped.is_empty() {
                let i = rng.below(cap as u64) as usize;
                flipped[i] ^= 1u8 << rng.below(8);
            }
            inputs.push(flipped);
            inputs.push((0..cap + 3).map(|_| rng.next() as u8).collect());
            for input in inputs {
                let mut ya = vec![0u16; n];
                let mut yb = vec![0u16; n];
                let da = modq_decode(&mut ya, logn, &input);
                let db = unsafe {
                    c::falcon_inner_modq_decode(yb.as_mut_ptr(), logn, input.as_ptr(), input.len())
                };
                assert_eq!(da, db, "case {case}: decode return");
                if da != 0 {
                    assert_eq!(ya, yb, "case {case}: decoded values");
                }
            }
        }
    }

    #[test]
    fn trim_i16_i8_encode_decode_match_c() {
        let mut rng = Rng(0x0F0F_1234_5678_0001);
        for case in 0..300 {
            let logn = 1 + (case % 10) as u32;
            let n = 1usize << logn;
            let bits = 2 + (rng.below(11) as u32); // 2..=12
            let maxv = (1i32 << (bits - 1)) - 1;
            let mut x16: Vec<i16> = (0..n)
                .map(|_| (rng.below((2 * maxv + 1) as u64) as i32 - maxv) as i16)
                .collect();
            if case % 5 == 0 {
                x16[rng.below(n as u64) as usize] = (-maxv - 1) as i16;
            }
            let cap = ((n * bits as usize) + 7) >> 3;
            let mut a = vec![0u8; cap];
            let mut b = vec![0u8; cap];
            let ra = trim_i16_encode(Some(&mut a), &x16, logn, bits);
            let rb = unsafe {
                c::falcon_inner_trim_i16_encode(b.as_mut_ptr(), cap, x16.as_ptr(), logn, bits)
            };
            assert_eq!((ra, &a), (rb, &b), "case {case}: i16 encode bits={bits}");
            for input in [
                a.clone(),
                (0..cap).map(|_| rng.next() as u8).collect::<Vec<u8>>(),
            ] {
                let mut ya = vec![0i16; n];
                let mut yb = vec![0i16; n];
                let da = trim_i16_decode(&mut ya, logn, bits, &input);
                let db = unsafe {
                    c::falcon_inner_trim_i16_decode(
                        yb.as_mut_ptr(),
                        logn,
                        bits,
                        input.as_ptr(),
                        input.len(),
                    )
                };
                assert_eq!(da, db, "case {case}: i16 decode return bits={bits}");
                if da != 0 {
                    assert_eq!(ya, yb);
                }
            }
            if bits <= 8 {
                let mut x8: Vec<i8> = x16.iter().map(|&v| v.clamp(-127, 127) as i8).collect();
                if case % 5 == 0 {
                    x8[rng.below(n as u64) as usize] = (-maxv - 1) as i8;
                }
                let mut a = vec![0u8; cap];
                let mut b = vec![0u8; cap];
                let ra = trim_i8_encode(Some(&mut a), &x8, logn, bits);
                let rb = unsafe {
                    c::falcon_inner_trim_i8_encode(b.as_mut_ptr(), cap, x8.as_ptr(), logn, bits)
                };
                assert_eq!((ra, &a), (rb, &b), "case {case}: i8 encode bits={bits}");
                for input in [
                    a.clone(),
                    (0..cap).map(|_| rng.next() as u8).collect::<Vec<u8>>(),
                ] {
                    let mut ya = vec![0i8; n];
                    let mut yb = vec![0i8; n];
                    let da = trim_i8_decode(&mut ya, logn, bits, &input);
                    let db = unsafe {
                        c::falcon_inner_trim_i8_decode(
                            yb.as_mut_ptr(),
                            logn,
                            bits,
                            input.as_ptr(),
                            input.len(),
                        )
                    };
                    assert_eq!(da, db, "case {case}: i8 decode return bits={bits}");
                    if da != 0 {
                        assert_eq!(ya, yb);
                    }
                }
            }
        }
    }

    #[test]
    fn comp_encode_decode_match_c_on_random_and_adversarial_inputs() {
        let mut rng = Rng(0xDEAD_BEEF_0BAD_F00D);
        for case in 0..400 {
            let logn = 1 + (case % 10) as u32;
            let n = 1usize << logn;
            // Gaussian-ish small values most of the time, full range sometimes.
            let spread: i32 = if case % 3 == 0 { 2047 } else { 300 };
            let mut x: Vec<i16> = (0..n)
                .map(|_| (rng.below((2 * spread + 1) as u64) as i32 - spread) as i16)
                .collect();
            if case % 11 == 0 {
                x[rng.below(n as u64) as usize] = 2048;
            }
            let want_len =
                unsafe { c::falcon_inner_comp_encode(std::ptr::null_mut(), 0, x.as_ptr(), logn) };
            assert_eq!(
                comp_encode(None, &x, logn),
                want_len,
                "case {case}: length query"
            );
            let cap = if want_len == 0 {
                8
            } else {
                want_len + rng.below(3) as usize
            };
            let mut a = vec![0u8; cap];
            let mut b = vec![0u8; cap];
            let ra = comp_encode(Some(&mut a), &x, logn);
            let rb = unsafe { c::falcon_inner_comp_encode(b.as_mut_ptr(), cap, x.as_ptr(), logn) };
            assert_eq!((ra, &a), (rb, &b), "case {case}: encode");
            if want_len > 0 {
                // Too-small buffer.
                let small = want_len - 1;
                let mut a2 = vec![0u8; small];
                let mut b2 = vec![0u8; small];
                assert_eq!(comp_encode(Some(&mut a2), &x, logn), unsafe {
                    c::falcon_inner_comp_encode(b2.as_mut_ptr(), small, x.as_ptr(), logn)
                });
            }
            let mut inputs = vec![a.clone(), a[..cap.saturating_sub(1)].to_vec(), vec![]];
            let mut flipped = a.clone();
            if !flipped.is_empty() {
                let i = rng.below(cap as u64) as usize;
                flipped[i] ^= 1u8 << rng.below(8);
            }
            inputs.push(flipped);
            inputs.push((0..cap + 5).map(|_| rng.next() as u8).collect());
            inputs.push(vec![0u8; cap + 5]);
            inputs.push(vec![0xffu8; cap + 5]);
            for input in inputs {
                let mut ya = vec![0i16; n];
                let mut yb = vec![0i16; n];
                let da = comp_decode(&mut ya, logn, &input);
                let db = unsafe {
                    c::falcon_inner_comp_decode(yb.as_mut_ptr(), logn, input.as_ptr(), input.len())
                };
                assert_eq!(da, db, "case {case}: decode return (len {})", input.len());
                if da != 0 {
                    assert_eq!(ya, yb, "case {case}: decoded values");
                }
            }
        }
    }
}
