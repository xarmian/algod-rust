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

//! Hash-to-point and the signature norm bound (`common.c`).
//!
//! Ported from the Falcon reference implementation, `falcon-c/common.c`
//! (Copyright (c) 2017-2019 Falcon Project, MIT License, author Thomas
//! Pornin), vendored verbatim under `crates/core/algo-falcon/falcon-c/` as
//! part of github.com/algorand/falcon v0.1.0; the MIT notice is preserved in
//! `falcon-c/LICENSE`.

use super::shake256::Shake256;

/// `hash_to_point_vartime`: squeeze 16-bit words, rejection-sample them
/// into `[0, q)`, variable time. Not used by `det1024` (which takes the
/// constant-time variant everywhere) but kept for parity with the C.
pub(crate) fn hash_to_point_vartime(sc: &mut Shake256, x: &mut [u16], logn: u32) {
    let mut n = 1usize << logn;
    let mut i = 0usize;
    while n > 0 {
        let mut buf = [0u8; 2];
        sc.extract(&mut buf);
        let mut w = (u32::from(buf[0]) << 8) | u32::from(buf[1]);
        if w < 61445 {
            while w >= 12289 {
                w -= 12289;
            }
            x[i] = w as u16;
            i += 1;
            n -= 1;
        }
    }
}

/// Bulk-extraction form of [`hash_to_point_vartime`], used by verification
/// and signing (Phase 21 optimisation pass, #1938).
///
/// It produces exactly the same output vector: the SHAKE256 output stream is
/// consumed in the same order, two bytes per candidate word, rejecting
/// `w >= 61445` and reducing the rest mod q. The only difference is *how*
/// the bytes are pulled from the context — one `extract` of every word
/// still needed instead of one per word — which removes the per-word call
/// overhead (about half of this function's cost). It therefore leaves the
/// SHAKE context positioned past the last accepted word by up to the size
/// of the final over-read, which no caller uses (verification discards the
/// context and signing restores it from a saved copy before each attempt);
/// the faithful function above is what the stream-position test compares.
pub(crate) fn hash_to_point_vartime_bulk(sc: &mut Shake256, x: &mut [u16], logn: u32) {
    let n = 1usize << logn;
    let mut i = 0usize;
    let mut buf = [0u8; 2048];
    while i < n {
        let need = n - i;
        let bytes = &mut buf[..2 * need];
        sc.extract(bytes);
        for pair in bytes.as_chunks::<2>().0 {
            let mut w = (u32::from(pair[0]) << 8) | u32::from(pair[1]);
            if w < 61445 {
                while w >= 12289 {
                    w -= 12289;
                }
                x[i] = w as u16;
                i += 1;
            }
        }
    }
}

/// `hash_to_point_ct`: constant-time hash-to-point. Squeezes `n + over`
/// words, reduces each to `[0, q)` or marks it rejected (`0xFFFF`), then
/// compacts the accepted ones to the front with a data-oblivious network.
pub(crate) fn hash_to_point_ct(sc: &mut Shake256, x: &mut [u16], logn: u32) {
    const OVERTAB: [u32; 11] = [0, 65, 67, 71, 77, 86, 100, 122, 154, 205, 287];
    let n = 1u32 << logn;
    let n2 = n << 1;
    let over = OVERTAB[logn as usize];
    let m = n + over;
    let mut tt1 = vec![0u16; n as usize];
    let mut tt2 = [0u16; 63];
    for u in 0..m {
        let mut buf = [0u8; 2];
        sc.extract(&mut buf);
        let w = (u32::from(buf[0]) << 8) | u32::from(buf[1]);
        let mut wr = w.wrapping_sub(24578 & (w.wrapping_sub(24578) >> 31).wrapping_sub(1));
        wr = wr.wrapping_sub(24578 & (wr.wrapping_sub(24578) >> 31).wrapping_sub(1));
        wr = wr.wrapping_sub(12289 & (wr.wrapping_sub(12289) >> 31).wrapping_sub(1));
        wr |= (w.wrapping_sub(61445) >> 31).wrapping_sub(1);
        if u < n {
            x[u as usize] = wr as u16;
        } else if u < n2 {
            tt1[(u - n) as usize] = wr as u16;
        } else {
            tt2[(u - n2) as usize] = wr as u16;
        }
    }
    // Access the three regions as one virtual array.
    fn get(x: &[u16], tt1: &[u16], tt2: &[u16], n: u32, n2: u32, i: u32) -> u16 {
        if i < n {
            x[i as usize]
        } else if i < n2 {
            tt1[(i - n) as usize]
        } else {
            tt2[(i - n2) as usize]
        }
    }
    fn set(x: &mut [u16], tt1: &mut [u16], tt2: &mut [u16], n: u32, n2: u32, i: u32, v: u16) {
        if i < n {
            x[i as usize] = v;
        } else if i < n2 {
            tt1[(i - n) as usize] = v;
        } else {
            tt2[(i - n2) as usize] = v;
        }
    }
    let mut p = 1u32;
    while p <= over {
        let mut v = 0u32;
        for u in 0..m {
            let sv = u32::from(get(x, &tt1, &tt2, n, n2, u));
            let j = u.wrapping_sub(v);
            let mut mk = (sv >> 15).wrapping_sub(1);
            v = v.wrapping_sub(mk);
            if u < p {
                continue;
            }
            let dv = u32::from(get(x, &tt1, &tt2, n, n2, u - p));
            mk &= (((j & p).wrapping_add(0x1FF)) >> 9).wrapping_neg();
            set(
                x,
                &mut tt1,
                &mut tt2,
                n,
                n2,
                u,
                (sv ^ (mk & (sv ^ dv))) as u16,
            );
            set(
                x,
                &mut tt1,
                &mut tt2,
                n,
                n2,
                u - p,
                (dv ^ (mk & (sv ^ dv))) as u16,
            );
        }
        p <<= 1;
    }
}

/// `l2bound[logn]`: maximum squared norm of a valid signature.
const L2BOUND: [u32; 11] = [
    0, 101498, 208714, 428865, 892039, 1852696, 3842630, 7959734, 16468416, 34034726, 70265242,
];

/// `is_short`: whether `||(s1, s2)||^2 <= l2bound[logn]`, with the sum
/// saturating (via the `ng` sign accumulator) exactly like the C.
pub(crate) fn is_short(s1: &[i16], s2: &[i16], logn: u32) -> bool {
    let n = 1usize << logn;
    let mut s: u32 = 0;
    let mut ng: u32 = 0;
    for u in 0..n {
        let z = i32::from(s1[u]);
        s = s.wrapping_add((z * z) as u32);
        ng |= s;
        let z = i32::from(s2[u]);
        s = s.wrapping_add((z * z) as u32);
        ng |= s;
    }
    s |= (ng >> 31).wrapping_neg();
    s <= L2BOUND[logn as usize]
}

/// `is_short_half`: as [`is_short`] with `||s1||^2` already given as `sqn`.
pub(crate) fn is_short_half(mut sqn: u32, s2: &[i16], logn: u32) -> bool {
    let n = 1usize << logn;
    let mut ng: u32 = (sqn >> 31).wrapping_neg();
    for &v in &s2[..n] {
        let z = i32::from(v);
        sqn = sqn.wrapping_add((z * z) as u32);
        ng |= sqn;
    }
    sqn |= (ng >> 31).wrapping_neg();
    sqn <= L2BOUND[logn as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_short_accepts_small_and_rejects_large_and_overflowing() {
        let logn = 10u32;
        let s1 = vec![10i16; 1024];
        let s2 = vec![-10i16; 1024];
        assert!(is_short(&s1, &s2, logn)); // 2*1024*100 = 204800
        let big = vec![200i16; 1024];
        assert!(!is_short(&big, &big, logn)); // 2*1024*40000 = 81,920,000 > bound
        let huge = vec![-32768i16; 1024];
        assert!(!is_short(&huge, &huge, logn)); // overflows u32: must reject
        assert!(is_short_half(0, &s2, logn));
        assert!(!is_short_half(1u32 << 31, &s2, logn));
    }

    #[test]
    fn bulk_hash_to_point_equals_the_faithful_one() {
        for logn in 1..=10u32 {
            let n = 1usize << logn;
            for msg_len in [0usize, 1, 40, 72, 1000] {
                let msg: Vec<u8> = (0..msg_len)
                    .map(|i| (i * 13 + logn as usize) as u8)
                    .collect();
                let mut a = Shake256::new();
                a.inject(&msg);
                a.flip();
                let mut b = a.clone();
                let mut x = vec![0u16; n];
                let mut y = vec![0u16; n];
                hash_to_point_vartime(&mut a, &mut x, logn);
                hash_to_point_vartime_bulk(&mut b, &mut y, logn);
                assert_eq!(x, y, "logn={logn} msg_len={msg_len}");
            }
        }
    }

    #[test]
    fn hash_to_point_ct_and_vartime_agree_on_accepted_words() {
        // Both produce values in [0, q) and, for the same stream, the same
        // sequence of accepted words.
        for logn in 1..=10u32 {
            let n = 1usize << logn;
            let mut a = Shake256::new();
            a.inject(b"message");
            a.flip();
            let mut b = a.clone();
            let mut x = vec![0u16; n];
            let mut y = vec![0u16; n];
            hash_to_point_vartime(&mut a, &mut x, logn);
            hash_to_point_ct(&mut b, &mut y, logn);
            assert!(x.iter().all(|&v| v < 12289));
            assert_eq!(x, y, "logn={logn}");
        }
    }
}

/// Differential tests against the vendored C (`falcon_inner_*` in common.c).
#[cfg(all(test, feature = "c-backend"))]
mod c_diff {
    use super::*;
    use crate::c_internals::{self as c, CInnerShake256};

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    #[test]
    fn hash_to_point_matches_c() {
        let mut rng = Rng(0x4A54_0000_0000_0006);
        for case in 0..100 {
            let logn = 1 + (case % 10) as u32;
            let n = 1usize << logn;
            let msg: Vec<u8> = (0..(rng.next() % 300) as usize)
                .map(|_| rng.next() as u8)
                .collect();
            let mut rs = Shake256::new();
            rs.inject(&msg);
            rs.flip();
            let mut cc = CInnerShake256::new();
            cc.inject(&msg);
            cc.flip();
            let mut x = vec![0u16; n];
            let mut y = vec![0u16; n];
            let mut tmp = vec![0u8; 2 * n + 8];
            if case % 2 == 0 {
                hash_to_point_ct(&mut rs, &mut x, logn);
                unsafe {
                    c::falcon_inner_hash_to_point_ct(
                        &mut cc,
                        y.as_mut_ptr(),
                        logn,
                        tmp.as_mut_ptr(),
                    )
                };
                assert_eq!(x, y, "case {case}: hash_to_point_ct");
            } else {
                hash_to_point_vartime(&mut rs, &mut x, logn);
                unsafe { c::falcon_inner_hash_to_point_vartime(&mut cc, y.as_mut_ptr(), logn) };
                assert_eq!(x, y, "case {case}: hash_to_point_vartime");
            }
            // The SHAKE state must have advanced identically.
            assert_eq!(
                rs.extract_vec(64),
                cc.extract_vec(64),
                "case {case}: stream position"
            );
        }
    }

    #[test]
    fn is_short_matches_c() {
        let mut rng = Rng(0x1550_0000_0000_0007);
        for case in 0..400 {
            let logn = 1 + (case % 10) as u32;
            let n = 1usize << logn;
            let spread: i64 = match case % 4 {
                0 => 30,
                1 => 300,
                2 => 2047,
                _ => 32767,
            };
            let gen = |rng: &mut Rng| -> Vec<i16> {
                (0..n)
                    .map(|_| ((rng.next() % (2 * spread as u64 + 1)) as i64 - spread) as i16)
                    .collect()
            };
            let s1 = gen(&mut rng);
            let s2 = gen(&mut rng);
            let rs = is_short(&s1, &s2, logn);
            let cc = unsafe { c::falcon_inner_is_short(s1.as_ptr(), s2.as_ptr(), logn) };
            assert_eq!(i32::from(rs), cc, "case {case}: is_short");
            let sqn = rng.next() as u32;
            let rs = is_short_half(sqn, &s2, logn);
            let cc = unsafe { c::falcon_inner_is_short_half(sqn, s2.as_ptr(), logn) };
            assert_eq!(i32::from(rs), cc, "case {case}: is_short_half");
        }
    }
}
