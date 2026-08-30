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
//
// This file ports two third-party algorithms embedded (vendored, in the Go
// sense of "imported dependency") inside go-algorand rather than authored by
// the Algorand Foundation:
//
//   - The Bloom filter construction/sizing/(un)marshaling (`Filter`, `New`,
//     `Optimal`, `Set`/`Test`, `MarshalBinary`/`UnmarshalBinary`) ports
//     `go-algorand/util/bloom/bloom.go`, Copyright (c) 2016 David Lazar,
//     licensed under a BSD-style license (see that file's own header). Only
//     the algorithm/structure is ported here (in Rust, from scratch); no
//     original source text is copied.
//   - The SipHash-2-4 128-bit hash primitive (`hash128`) ports the portable
//     reference implementation from `github.com/dchest/siphash`
//     (`hash128.go`), written 2012-2014 by Dmitry Chestnykh, with 2014
//     128-bit-output modifications by Damian Gryski, dedicated to the public
//     domain (CC0). Both attributions are preserved here per this repo's
//     licensing policy (`CLAUDE.md`'s Licensing section) for files that port
//     third-party (non-go-algorand-authored) source.

//! Bloom filter wire format for the tx-sync pull protocol (issue #792).
//!
//! Byte-for-byte port of go-algorand's `util/bloom.Filter`: same
//! `Optimal()` sizing formula, same SipHash-2-4-keyed hash function, same
//! `MarshalBinary`/`UnmarshalBinary` layout (`numHashes` u32 BE ++ `prefix`
//! u32 BE ++ raw bit-data). This is what lets algod-rust's `TxSyncService`
//! (server) and `HttpTxSyncClient` (client) interoperate with a real
//! go-algorand node's `/v1/{genesisID}/txsync` endpoint — see
//! `crate::tx_sync_service` and `crate::tx_sync_client`.
//!
//! Golden-fixture parity is asserted in this module's tests against bytes
//! captured by running a small Go program against the real
//! `github.com/algorand/go-algorand/util/bloom` package (this repo's
//! established "golden fixtures" culture — see `CLAUDE.md`).

use std::fmt;

/// Upper bound on the number of hash probes per element, matching go's
/// `const maxHashes = uint32(32)`. A filter claiming more than this via
/// `unmarshal_binary` is rejected — mirrors go's own defense against a
/// peer-supplied filter driving unbounded per-element hashing work.
const MAX_HASHES: u32 = 32;

/// Errors decoding a wire-format Bloom filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BloomDecodeError {
    /// Fewer than 9 bytes (the 8-byte header alone, with zero data bytes,
    /// is rejected too — mirrors go's `len(data) <= 8` check). This also
    /// guards [`Filter::test`]/[`Filter::set`] against a divide-by-zero on
    /// `data.len() * 8`, since a valid decode always yields `data.len() >=
    /// 1`.
    ShortData,
    /// `numHashes` exceeds [`MAX_HASHES`].
    TooManyHashes,
}

impl fmt::Display for BloomDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortData => write!(f, "bloom filter: short data"),
            Self::TooManyHashes => write!(f, "bloom filter: too many hashes"),
        }
    }
}

impl std::error::Error for BloomDecodeError {}

/// A Bloom filter, wire-compatible with go-algorand's `util/bloom.Filter`.
#[derive(Debug, Clone)]
pub struct Filter {
    num_hashes: u32,
    data: Vec<u8>,
    prefix: [u8; 4],
}

impl Filter {
    /// Create a new filter with `size_bits` bits of storage (rounded up to
    /// the nearest byte, matching go's `(sizeBits + 7) / 8`), `num_hashes`
    /// probes per element, and a `prefix` mixed into every hash (go's
    /// `TxSyncer.counter`, incremented once per sync round so successive
    /// filters from the same client don't share hash collisions).
    #[must_use]
    pub fn new(size_bits: usize, num_hashes: u32, prefix: u32) -> Self {
        let m = size_bits.div_ceil(8);
        Self {
            num_hashes,
            data: vec![0u8; m],
            prefix: prefix.to_be_bytes(),
        }
    }

    /// Compute optimal `(size_bits, num_hashes)` for `num_elements` elements
    /// at `false_positive_rate`, matching go's `bloom.Optimal` (itself
    /// citing <https://web.stanford.edu/~ashishg/papers/inverted.pdf> §4.1).
    #[must_use]
    pub fn optimal(num_elements: usize, false_positive_rate: f64) -> (usize, u32) {
        let n = num_elements as f64;
        let p = false_positive_rate;
        let m = -(n + 0.5) * p.ln() / std::f64::consts::LN_2.powi(2) + 1.0;
        let k = -p.ln() / std::f64::consts::LN_2;
        let num_hashes = (k.ceil() as u32).min(MAX_HASHES);
        (m.ceil() as usize, num_hashes)
    }

    /// Mark `x` as present in the filter.
    pub fn set(&mut self, x: &[u8]) {
        let hashes = self.hash(x);
        let n = (self.data.len() as u32) * 8;
        for h in hashes {
            let bit = h % n;
            self.data[(bit / 8) as usize] |= 1 << (bit % 8);
        }
    }

    /// Test whether `x` may be present in the filter. Like any Bloom
    /// filter, a `true` result can be a false positive; `false` is always
    /// exact.
    #[must_use]
    pub fn test(&self, x: &[u8]) -> bool {
        let hashes = self.hash(x);
        let n = (self.data.len() as u32) * 8;
        hashes.into_iter().all(|h| {
            let bit = h % n;
            self.data[(bit / 8) as usize] & (1 << (bit % 8)) != 0
        })
    }

    /// Number of hash probes configured for this filter.
    #[must_use]
    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    /// Size of the filter's bit-data in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the filter's bit-data is empty (only possible via
    /// [`Filter::new`] with `size_bits == 0`; a filter obtained through
    /// [`Filter::unmarshal_binary`] always has at least one data byte).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Encode to go's wire format: 4-byte BE `numHashes` ++ 4-byte `prefix`
    /// ++ raw bit-data.
    #[must_use]
    pub fn marshal_binary(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.data.len());
        out.extend_from_slice(&self.num_hashes.to_be_bytes());
        out.extend_from_slice(&self.prefix);
        out.extend_from_slice(&self.data);
        out
    }

    /// Decode go's wire format. Rejects a `numHashes` above [`MAX_HASHES`]
    /// (a peer could otherwise force unbounded per-`Test`/`Set` hashing
    /// work) and any input with no data bytes at all (which would make
    /// every later `Set`/`Test` divide by zero).
    pub fn unmarshal_binary(data: &[u8]) -> Result<Self, BloomDecodeError> {
        if data.len() <= 8 {
            return Err(BloomDecodeError::ShortData);
        }
        let num_hashes = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if num_hashes > MAX_HASHES {
            return Err(BloomDecodeError::TooManyHashes);
        }
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&data[4..8]);
        Ok(Self {
            num_hashes,
            prefix,
            data: data[8..].to_vec(),
        })
    }

    /// go's `Filter.hash`: hash `prefix ++ x` with SipHash-2-4-128, four
    /// `u32`s per probe (`h1`'s two halves, `h2`'s two halves), truncated
    /// to `num_hashes` entries. `i` (the probe-group index) is folded in
    /// as SipHash's first key half so probe groups don't collide.
    fn hash(&self, x: &[u8]) -> Vec<u32> {
        let mut preimage = Vec::with_capacity(4 + x.len());
        preimage.extend_from_slice(&self.prefix);
        preimage.extend_from_slice(x);

        let n = self.num_hashes as usize;
        let groups = n.div_ceil(4);
        let mut out = vec![0u32; groups * 4];
        for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
            let (h1, h2) = siphash_hash128(i as u64, 666_666, &preimage);
            chunk[0] = h1 as u32;
            chunk[1] = (h1 >> 32) as u32;
            chunk[2] = h2 as u32;
            chunk[3] = (h2 >> 32) as u32;
        }
        out.truncate(n);
        out
    }
}

/// Length (in bytes) of a filter's `MarshalBinary` output for the optimal
/// sizing of `num_elements` at `false_positive_rate`, matching go's
/// `bloom.BinaryMarshalLength`. Used to size an upper-bound request body
/// cap without having to construct a filter first.
#[must_use]
pub fn binary_marshal_length(num_elements: usize, false_positive_rate: f64) -> usize {
    let (size_bits, _) = Filter::optimal(num_elements, false_positive_rate);
    size_bits.div_ceil(8) + 8
}

/// SipHash-2-4 with 128-bit output, keyed by `(k0, k1)`, over `p`. Ported
/// from `github.com/dchest/siphash`'s portable `hash128.go` reference
/// implementation (see this module's top-of-file attribution) — public
/// domain, no crate dependency required for ~100 lines of fully-specified
/// arithmetic.
fn siphash_hash128(k0: u64, k1: u64, p: &[u8]) -> (u64, u64) {
    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;
    let t = (p.len() as u64) << 56;

    v1 ^= 0xee;

    #[inline]
    fn round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
        *v0 = v0.wrapping_add(*v1);
        *v1 = v1.rotate_left(13);
        *v1 ^= *v0;
        *v0 = v0.rotate_left(32);

        *v2 = v2.wrapping_add(*v3);
        *v3 = v3.rotate_left(16);
        *v3 ^= *v2;

        *v0 = v0.wrapping_add(*v3);
        *v3 = v3.rotate_left(21);
        *v3 ^= *v0;

        *v2 = v2.wrapping_add(*v1);
        *v1 = v1.rotate_left(17);
        *v1 ^= *v2;
        *v2 = v2.rotate_left(32);
    }

    let mut chunks = p.chunks_exact(8);
    for block in &mut chunks {
        let m = u64::from_le_bytes(block.try_into().expect("chunks_exact(8) yields 8 bytes"));
        v3 ^= m;
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    let remainder = chunks.remainder();
    let mut last = t;
    for (i, &b) in remainder.iter().enumerate() {
        last |= (b as u64) << (8 * i);
    }
    v3 ^= last;
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xee;
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    let r0 = v0 ^ v1 ^ v2 ^ v3;

    v1 ^= 0xdd;
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    round(&mut v0, &mut v1, &mut v2, &mut v3);
    let r1 = v0 ^ v1 ^ v2 ^ v3;

    (r0, r1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Golden fixtures captured by running a small Go program against the
    /// real `github.com/algorand/go-algorand/util/bloom` package
    /// (`bloom.New`/`Set`/`MarshalBinary`/`Optimal`, go-algorand pinned at
    /// v5.0.0-stable) — see the PR description for the generator source.
    /// Byte-for-byte parity here is what guarantees a real go-algorand
    /// node can decode a filter algod-rust produces, and vice versa.
    #[test]
    fn golden_case1_small_ascii_elements() {
        let mut f = Filter::new(64, 3, 0);
        f.set(b"hello");
        f.set(b"world");
        assert_eq!(f.marshal_binary(), hex("00000003000000000049010000000004"));
        assert!(f.test(b"hello"));
        assert!(f.test(b"world"));
        assert!(!f.test(b"not-a-member-xyz"));
    }

    #[test]
    fn golden_case2_nonzero_prefix_more_elements() {
        let mut f = Filter::new(256, 5, 42);
        f.set(&[0x01, 0x02, 0x03]);
        f.set(&[0xff, 0xfe, 0xfd]);
        f.set(&[0x00]);
        assert_eq!(
            f.marshal_binary(),
            hex("000000050000002a0000000c02000008200000002002800000800000400000000010020080000020")
        );
        assert!(f.test(&[0x01, 0x02, 0x03]));
        assert!(f.test(&[0xff, 0xfe, 0xfd]));
        assert!(f.test(&[0x00]));
        assert!(!f.test(b"not-a-member-xyz"));
    }

    #[test]
    fn golden_optimal_matches_go_for_ten_elements_one_percent() {
        // go: bloom.Optimal(10, 0.01) == (sizeBits=102, numHashes=7).
        assert_eq!(Filter::optimal(10, 0.01), (102, 7));
    }

    #[test]
    fn golden_case3_optimal_sized_filter_txid_like_elements() {
        let (size_bits, num_hashes) = Filter::optimal(10, 0.01);
        let mut f = Filter::new(size_bits, num_hashes, 7);
        let elems: Vec<Vec<u8>> = (0..10)
            .map(|i| format!("txid-{i:02}-aaaaaaaaaaaaaaaaaaaaaaaaaaaa").into_bytes())
            .collect();
        for e in &elems {
            f.set(e);
        }
        assert_eq!(
            f.marshal_binary(),
            hex("0000000700000007d998bcafe89a16baeaf6e098b9")
        );
        for e in &elems {
            assert!(f.test(e));
        }
        assert!(!f.test(b"not-a-member-xyz"));
    }

    #[test]
    fn golden_optimal_matches_go_for_zero_elements() {
        // go: bloom.Optimal(0, 0.01) == (sizeBits=6, numHashes=7).
        assert_eq!(Filter::optimal(0, 0.01), (6, 7));
    }

    #[test]
    fn golden_case4_empty_filter() {
        let (size_bits, num_hashes) = Filter::optimal(0, 0.01);
        let f = Filter::new(size_bits, num_hashes, 0);
        assert_eq!(f.marshal_binary(), hex("000000070000000000"));
        assert!(!f.test(b"not-a-member-xyz"));
    }

    #[test]
    fn golden_case5_digest_sized_elements() {
        let mut f = Filter::new(128, 4, 999_999);
        let a = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let b = hex("ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544332211");
        f.set(&a);
        f.set(&b);
        assert_eq!(
            f.marshal_binary(),
            hex("00000004000f423f00041000010800040010000800000040")
        );
        assert!(f.test(&a));
        assert!(f.test(&b));
        assert!(!f.test(b"not-a-member-xyz"));
    }

    #[test]
    fn round_trips_through_marshal_unmarshal() {
        let mut f = Filter::new(256, 6, 12345);
        f.set(b"round-trip-me");
        let bytes = f.marshal_binary();
        let decoded = Filter::unmarshal_binary(&bytes).expect("valid filter decodes");
        assert_eq!(decoded.num_hashes(), f.num_hashes());
        assert_eq!(decoded.len(), f.len());
        assert!(decoded.test(b"round-trip-me"));
        assert_eq!(decoded.marshal_binary(), bytes);
    }

    #[test]
    fn unmarshal_rejects_short_data() {
        // Exactly 8 bytes (header only, zero data bytes) must be rejected
        // -- go's `len(data) <= 8` check -- since it would otherwise leave
        // `data.len() * 8 == 0`, a divide-by-zero in `set`/`test`.
        let header_only = vec![0u8; 8];
        assert_eq!(
            Filter::unmarshal_binary(&header_only).unwrap_err(),
            BloomDecodeError::ShortData
        );
        assert_eq!(
            Filter::unmarshal_binary(&[0u8; 3]).unwrap_err(),
            BloomDecodeError::ShortData
        );
    }

    #[test]
    fn unmarshal_rejects_too_many_hashes() {
        let mut data = vec![0u8; 9];
        data[0..4].copy_from_slice(&(MAX_HASHES + 1).to_be_bytes());
        assert_eq!(
            Filter::unmarshal_binary(&data).unwrap_err(),
            BloomDecodeError::TooManyHashes
        );

        // Exactly MAX_HASHES is still accepted.
        let mut ok = vec![0u8; 9];
        ok[0..4].copy_from_slice(&MAX_HASHES.to_be_bytes());
        assert!(Filter::unmarshal_binary(&ok).is_ok());
    }

    #[test]
    fn binary_marshal_length_matches_optimal_sizing() {
        let (size_bits, _) = Filter::optimal(10, 0.01);
        let expected = size_bits.div_ceil(8) + 8;
        assert_eq!(binary_marshal_length(10, 0.01), expected);
    }
}
