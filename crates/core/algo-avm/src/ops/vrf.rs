//! VRF verify implementation: ECVRF-ED25519-SHA512-Elligator2 (draft-irtf-cfrg-vrf-03).
//!
//! This implements the Algorand VRF construction matching go-algorand's
//! libsodium-fork. The key components are:
//! - Elligator2 map from field element to Edwards point (with cofactor clearing)
//! - Hash-to-curve: SHA-512 based hashing to Ed25519 point
//! - VRF proof verification per draft-irtf-cfrg-vrf-03 section 5.3
//!
//! Field arithmetic is implemented in pure Rust using the "unsaturated radix-2^51"
//! representation (5 limbs of 51 bits each), matching libsodium's fe25519 approach.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Suite byte for ECVRF-ED25519-SHA512-Elligator2 (draft-irtf-cfrg-vrf-03).
const SUITE: u8 = 0x04;

// ============================================================================
// Field element arithmetic mod p = 2^255 - 19
// ============================================================================

/// A field element in GF(2^255 - 19), represented as 5 limbs of 51 bits each.
/// This is the "unsaturated radix-2^51" representation used by libsodium ref10.
#[derive(Clone, Copy, Debug)]
struct Fe25519([u64; 5]);

impl Fe25519 {
    const ZERO: Fe25519 = Fe25519([0, 0, 0, 0, 0]);
    const ONE: Fe25519 = Fe25519([1, 0, 0, 0, 0]);

    /// Curve25519 Montgomery parameter A = 486662.
    const A: Fe25519 = Fe25519([486662, 0, 0, 0, 0]);

    /// Load a field element from 32 bytes (little-endian).
    fn from_bytes(s: &[u8; 32]) -> Self {
        let mut h = [0u64; 5];
        let load8 = |buf: &[u8]| -> u64 {
            let mut out = 0u64;
            for (i, &b) in buf.iter().enumerate().take(8) {
                out |= (b as u64) << (8 * i);
            }
            out
        };
        h[0] = load8(&s[0..]) & 0x7ffffffffffff;
        h[1] = (load8(&s[6..]) >> 3) & 0x7ffffffffffff;
        h[2] = (load8(&s[12..]) >> 6) & 0x7ffffffffffff;
        h[3] = (load8(&s[19..]) >> 1) & 0x7ffffffffffff;
        h[4] = (load8(&s[24..]) >> 12) & 0x7ffffffffffff;
        Fe25519(h)
    }

    /// Serialize a field element to 32 bytes (little-endian), fully reduced mod p.
    fn to_bytes(self) -> [u8; 32] {
        // First, carry and reduce.
        let mut h = self.0;

        // Propagate carries
        let mut carry: i64;
        for i in 0..5 {
            carry = (h[i] as i64) >> 51;
            h[i] &= 0x7ffffffffffff;
            if i < 4 {
                h[i + 1] = (h[i + 1] as i64 + carry) as u64;
            } else {
                h[0] = (h[0] as i64 + 19 * carry) as u64;
            }
        }
        // Second pass
        for i in 0..5 {
            carry = (h[i] as i64) >> 51;
            h[i] &= 0x7ffffffffffff;
            if i < 4 {
                h[i + 1] = (h[i + 1] as i64 + carry) as u64;
            } else {
                h[0] = (h[0] as i64 + 19 * carry) as u64;
            }
        }

        // Now reduce mod p = 2^255 - 19.
        // If h >= p, subtract p.
        let mut q = (h[0] + 19) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;

        h[0] += 19 * q;
        carry = (h[0] as i64) >> 51;
        h[0] &= 0x7ffffffffffff;
        for hi in h.iter_mut().skip(1) {
            *hi = (*hi as i64 + carry) as u64;
            carry = (*hi as i64) >> 51;
            *hi &= 0x7ffffffffffff;
        }

        let mut s = [0u8; 32];
        s[0] = h[0] as u8;
        s[1] = (h[0] >> 8) as u8;
        s[2] = (h[0] >> 16) as u8;
        s[3] = (h[0] >> 24) as u8;
        s[4] = (h[0] >> 32) as u8;
        s[5] = (h[0] >> 40) as u8;
        s[6] = ((h[0] >> 48) | (h[1] << 3)) as u8;
        s[7] = (h[1] >> 5) as u8;
        s[8] = (h[1] >> 13) as u8;
        s[9] = (h[1] >> 21) as u8;
        s[10] = (h[1] >> 29) as u8;
        s[11] = (h[1] >> 37) as u8;
        s[12] = ((h[1] >> 45) | (h[2] << 6)) as u8;
        s[13] = (h[2] >> 2) as u8;
        s[14] = (h[2] >> 10) as u8;
        s[15] = (h[2] >> 18) as u8;
        s[16] = (h[2] >> 26) as u8;
        s[17] = (h[2] >> 34) as u8;
        s[18] = (h[2] >> 42) as u8;
        s[19] = ((h[2] >> 50) | (h[3] << 1)) as u8;
        s[20] = (h[3] >> 7) as u8;
        s[21] = (h[3] >> 15) as u8;
        s[22] = (h[3] >> 23) as u8;
        s[23] = (h[3] >> 31) as u8;
        s[24] = (h[3] >> 39) as u8;
        s[25] = ((h[3] >> 47) | (h[4] << 4)) as u8;
        s[26] = (h[4] >> 4) as u8;
        s[27] = (h[4] >> 12) as u8;
        s[28] = (h[4] >> 20) as u8;
        s[29] = (h[4] >> 28) as u8;
        s[30] = (h[4] >> 36) as u8;
        s[31] = (h[4] >> 44) as u8;
        s
    }

    fn add(&self, rhs: &Fe25519) -> Fe25519 {
        Fe25519([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }

    fn sub(&self, rhs: &Fe25519) -> Fe25519 {
        // Add 4*p (limb-wise) to avoid underflow, then subtract.
        // p in radix-2^51: limb0 = 2^51 - 19, limbs 1-4 = 2^51 - 1
        // 4p limbs: limb0 = 4*(2^51 - 19) = 2^53 - 76, limbs 1-4 = 4*(2^51 - 1) = 2^53 - 4
        // Each bias > 2^51 so subtraction of any reduced limb won't underflow.
        Fe25519([
            (self.0[0] + 9007199254740916) - rhs.0[0], // 4 * (2^51 - 19)
            (self.0[1] + 9007199254740988) - rhs.0[1], // 4 * (2^51 - 1)
            (self.0[2] + 9007199254740988) - rhs.0[2],
            (self.0[3] + 9007199254740988) - rhs.0[3],
            (self.0[4] + 9007199254740988) - rhs.0[4],
        ])
    }

    fn neg(&self) -> Fe25519 {
        Fe25519::ZERO.sub(self)
    }

    fn mul(&self, rhs: &Fe25519) -> Fe25519 {
        let f = &self.0;
        let g = &rhs.0;

        let f0 = f[0] as u128;
        let f1 = f[1] as u128;
        let f2 = f[2] as u128;
        let f3 = f[3] as u128;
        let f4 = f[4] as u128;

        let g0 = g[0] as u128;
        let g1 = g[1] as u128;
        let g2 = g[2] as u128;
        let g3 = g[3] as u128;
        let g4 = g[4] as u128;

        let g1_19 = 19 * g1;
        let g2_19 = 19 * g2;
        let g3_19 = 19 * g3;
        let g4_19 = 19 * g4;

        let h0 = f0 * g0 + f1 * g4_19 + f2 * g3_19 + f3 * g2_19 + f4 * g1_19;
        let h1 = f0 * g1 + f1 * g0 + f2 * g4_19 + f3 * g3_19 + f4 * g2_19;
        let h2 = f0 * g2 + f1 * g1 + f2 * g0 + f3 * g4_19 + f4 * g3_19;
        let h3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + f4 * g4_19;
        let h4 = f0 * g4 + f1 * g3 + f2 * g2 + f3 * g1 + f4 * g0;

        let mut r = [0u64; 5];
        let mut carry: u128;

        carry = h0 >> 51;
        r[0] = (h0 & 0x7ffffffffffff) as u64;
        let h1 = h1 + carry;

        carry = h1 >> 51;
        r[1] = (h1 & 0x7ffffffffffff) as u64;
        let h2 = h2 + carry;

        carry = h2 >> 51;
        r[2] = (h2 & 0x7ffffffffffff) as u64;
        let h3 = h3 + carry;

        carry = h3 >> 51;
        r[3] = (h3 & 0x7ffffffffffff) as u64;
        let h4 = h4 + carry;

        carry = h4 >> 51;
        r[4] = (h4 & 0x7ffffffffffff) as u64;
        r[0] += (carry as u64) * 19;
        // One more carry from r[0]
        r[1] += r[0] >> 51;
        r[0] &= 0x7ffffffffffff;

        Fe25519(r)
    }

    fn sq(&self) -> Fe25519 {
        self.mul(self)
    }

    /// Compute 2 * self^2 (fe25519_sq2 in libsodium).
    fn sq2(&self) -> Fe25519 {
        let r = self.sq();
        r.add(&r)
    }

    /// Compute self^((p-5)/8) which is used in square root computation.
    /// This is the same exponentiation chain used for inversion but with
    /// a different final step.
    fn pow_p_minus_5_over_8(&self) -> Fe25519 {
        // (p-5)/8 = (2^255 - 24) / 8 = 2^252 - 3
        // Standard addition chain following ref10's pow2523.
        let z2 = self.sq();
        let z8 = (0..2).fold(z2, |acc, _| acc.sq());
        let z9 = self.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.sq();
        let z_5_0 = z22.mul(&z9); // z^(2^5 - 2^0) = z^31

        let mut t0 = z_5_0;
        for _ in 0..5 {
            t0 = t0.sq();
        }
        let z_10_0 = t0.mul(&z_5_0);

        let mut t0 = z_10_0;
        for _ in 0..10 {
            t0 = t0.sq();
        }
        let z_20_0 = t0.mul(&z_10_0);

        let mut t0 = z_20_0;
        for _ in 0..20 {
            t0 = t0.sq();
        }
        let z_40_0 = t0.mul(&z_20_0);

        let mut t0 = z_40_0;
        for _ in 0..10 {
            t0 = t0.sq();
        }
        let z_50_0 = t0.mul(&z_10_0);

        let mut t0 = z_50_0;
        for _ in 0..50 {
            t0 = t0.sq();
        }
        let z_100_0 = t0.mul(&z_50_0);

        let mut t0 = z_100_0;
        for _ in 0..100 {
            t0 = t0.sq();
        }
        let z_200_0 = t0.mul(&z_100_0);

        let mut t0 = z_200_0;
        for _ in 0..50 {
            t0 = t0.sq();
        }
        let z_250_0 = t0.mul(&z_50_0);

        let mut t0 = z_250_0;
        t0 = t0.sq();
        t0 = t0.sq();
        t0.mul(self) // z^(2^252 - 3)
    }

    /// Compute the modular inverse: self^(p-2) mod p.
    fn invert(&self) -> Fe25519 {
        // p - 2 = 2^255 - 21
        // We compute z^(2^255 - 21) using z^(2^252 - 3):
        // z^(2^255 - 21) = (z^(2^252 - 3))^8 * z^3
        // Because (2^252 - 3) * 8 = 2^255 - 24, and 2^255 - 24 + 3 = 2^255 - 21.
        let t = self.pow_p_minus_5_over_8();
        let t = t.sq().sq().sq(); // t^8 = z^(2^255 - 24)
        t.mul(&self.sq().mul(self)) // * z^3 = z^(2^255 - 21) = z^(p-2)
    }

    /// Compute the Euler criterion / Legendre symbol: self^((p-1)/2) mod p.
    /// Returns 0 if self == 0, 1 if self is a QR, p-1 if self is a QNR.
    /// This matches libsodium's chi25519.
    fn chi(&self) -> Fe25519 {
        // (p-1)/2 = (2^255 - 20) / 2 = 2^254 - 10
        // We follow the exact same addition chain as libsodium's chi25519.
        let z = *self;

        // Follow libsodium exactly:
        let t0 = z.sq(); // z^2
        let t1 = t0.mul(&z); // z^3
        let t0 = t1.sq(); // z^6
        let t2 = t0.sq(); // z^12
        let t2 = t2.sq(); // z^24
        let t2 = t2.mul(&t0); // z^30
        let t1 = t2.mul(&z); // z^31
        let mut t2 = t1.sq(); // z^62

        for _ in 1..5 {
            t2 = t2.sq();
        }
        let t1 = t2.mul(&t1); // z^(2^10 - 1)
        let mut t2 = t1.sq();
        for _ in 1..10 {
            t2 = t2.sq();
        }
        let t2 = t2.mul(&t1); // z^(2^20 - 1)
        let mut t3 = t2.sq();
        for _ in 1..20 {
            t3 = t3.sq();
        }
        let t2 = t3.mul(&t2); // z^(2^40 - 1)
        let mut t2 = t2.sq();
        for _ in 1..10 {
            t2 = t2.sq();
        }
        let t1 = t2.mul(&t1); // z^(2^50 - 1)
        let mut t2 = t1.sq();
        for _ in 1..50 {
            t2 = t2.sq();
        }
        let t2 = t2.mul(&t1); // z^(2^100 - 1)
        let mut t3 = t2.sq();
        for _ in 1..100 {
            t3 = t3.sq();
        }
        let t2 = t3.mul(&t2); // z^(2^200 - 1)
        let mut t2 = t2.sq();
        for _ in 1..50 {
            t2 = t2.sq();
        }
        let t1 = t2.mul(&t1); // z^(2^250 - 1)
        let mut t1 = t1.sq();
        for _ in 1..4 {
            t1 = t1.sq();
        }
        t1.mul(&t0) // z^(2^254 - 10) = z^((p-1)/2)
    }

    /// Conditional move: if flag != 0, replace self with other.
    fn cmov(&mut self, other: &Fe25519, flag: u64) {
        // Mask is all-ones (0xFFFF...) if flag != 0, all-zeros if flag == 0.
        let mask = 0u64.wrapping_sub(flag);
        for i in 0..5 {
            self.0[i] ^= (self.0[i] ^ other.0[i]) & mask;
        }
    }
}

// ============================================================================
// Elligator2 map (matching libsodium's ge25519_from_uniform)
// ============================================================================

/// Perform the Elligator2 map from 32 uniform bytes to a compressed Edwards
/// point (as 32-byte encoding), matching libsodium's `ge25519_from_uniform`.
///
/// The input `r` is 32 bytes. The function:
/// 1. Extracts the sign bit from r[31]
/// 2. Interprets the remaining bits as a field element
/// 3. Applies the Elligator2 map to get a Montgomery x-coordinate
/// 4. Converts to Edwards y-coordinate
/// 5. Sets the sign bit
/// 6. Decodes to Edwards point and multiplies by cofactor (8)
/// 7. Returns the compressed point encoding
fn elligator2_ed25519(r: &[u8; 32]) -> [u8; 32] {
    let mut s = *r;
    let x_sign = s[31] & 0x80;
    s[31] &= 0x7f;

    let mut rr2 = Fe25519::from_bytes(&s);

    // Elligator2 map on Curve25519 (Montgomery): y^2 = x^3 + Ax^2 + x, A = 486662
    // r = 2 * input^2
    rr2 = rr2.sq2();
    // r = r + 1
    rr2.0[0] += 1;
    // r = 1 / (2*input^2 + 1)
    rr2 = rr2.invert();
    // x = -A / (1 + 2*r^2) = -A * r
    let mut x = Fe25519::A.mul(&rr2);
    x = x.neg();

    // e = x^3 + A*x^2 + x (Montgomery curve equation)
    let x2 = x.sq();
    let x3 = x.mul(&x2);
    let mut e = x3.add(&x);
    let ax2 = x2.mul(&Fe25519::A);
    e = ax2.add(&e);

    // chi = e^((p-1)/2) = Legendre symbol
    e = e.chi();

    // If e == -1 (not a QR), use -x - A instead of x
    let e_bytes = e.to_bytes();
    let e_is_minus_1 = (e_bytes[1] & 1) as u64;

    let negx = x.neg();
    x.cmov(&negx, e_is_minus_1);
    let mut x2 = Fe25519::ZERO;
    x2.cmov(&Fe25519::A, e_is_minus_1);
    x = x.sub(&x2);

    // Convert Montgomery x to Edwards y: yed = (x-1)/(x+1)
    let x_plus_one = x.add(&Fe25519::ONE);
    let x_minus_one = x.sub(&Fe25519::ONE);
    let x_plus_one_inv = x_plus_one.invert();
    let yed = x_minus_one.mul(&x_plus_one_inv);
    s = yed.to_bytes();

    // Set the sign bit
    s[31] |= x_sign;

    // Decode to Edwards point, multiply by cofactor (8), encode back
    let compressed = CompressedEdwardsY(s);
    let point = compressed.decompress();
    match point {
        Some(p) => {
            // Multiply by cofactor 8
            p.mul_by_cofactor().compress().to_bytes()
        }
        None => {
            unreachable!("Elligator2 output must be a valid curve point")
        }
    }
}

// ============================================================================
// VRF helper functions
// ============================================================================

/// Hash-to-curve using Elligator2, per VRF draft spec section 5.4.1.2.
///
/// Computes: H = elligator2(SHA-512(suite || 0x01 || pk_bytes || alpha)[0..32] with bit 255 cleared)
fn hash_to_curve(pk_bytes: &[u8; 32], alpha: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update([SUITE]);
    hasher.update([0x01u8]);
    hasher.update(pk_bytes);
    hasher.update(alpha);
    let hash = hasher.finalize();

    let mut r_string = [0u8; 32];
    r_string.copy_from_slice(&hash[..32]);
    r_string[31] &= 0x7f; // clear sign bit

    elligator2_ed25519(&r_string)
}

/// Hash four points to a 16-byte challenge scalar, per VRF draft spec section 5.4.3.
///
/// c = SHA-512(suite || 0x02 || P1 || P2 || P3 || P4)[0..16]
fn hash_points(
    p1: &EdwardsPoint,
    p2: &EdwardsPoint,
    p3: &EdwardsPoint,
    p4: &EdwardsPoint,
) -> [u8; 16] {
    let mut buf = [0u8; 2 + 32 * 4];
    buf[0] = SUITE;
    buf[1] = 0x02;
    buf[2..34].copy_from_slice(&p1.compress().to_bytes());
    buf[34..66].copy_from_slice(&p2.compress().to_bytes());
    buf[66..98].copy_from_slice(&p3.compress().to_bytes());
    buf[98..130].copy_from_slice(&p4.compress().to_bytes());

    let hash = Sha512::digest(buf);
    let mut c = [0u8; 16];
    c.copy_from_slice(&hash[..16]);
    c
}

/// Decode a VRF proof (80 bytes) into its components:
/// - Gamma point (first 32 bytes, compressed Edwards Y)
/// - c scalar (next 16 bytes, little-endian)
/// - s scalar (next 32 bytes, little-endian)
///
/// Returns None if the Gamma point cannot be decompressed.
fn decode_proof(pi: &[u8; 80]) -> Option<(EdwardsPoint, [u8; 16], [u8; 32])> {
    let mut gamma_bytes = [0u8; 32];
    gamma_bytes.copy_from_slice(&pi[0..32]);

    // Check canonical encoding
    if !is_canonical_point_encoding(&gamma_bytes) {
        return None;
    }

    let compressed = CompressedEdwardsY(gamma_bytes);
    let gamma = compressed.decompress()?;

    let mut c = [0u8; 16];
    c.copy_from_slice(&pi[32..48]);

    let mut s = [0u8; 32];
    s.copy_from_slice(&pi[48..80]);

    Some((gamma, c, s))
}

/// Check if a 32-byte encoding is canonical (y < p).
/// Matches libsodium's `ge25519_is_canonical`.
fn is_canonical_point_encoding(s: &[u8; 32]) -> bool {
    let mut c = (s[31] & 0x7f) ^ 0x7f;
    for i in (1..31).rev() {
        c |= s[i] ^ 0xff;
    }
    let c = ((c as u32).wrapping_sub(1)) >> 8;
    let d = ((0xedu32).wrapping_sub(1).wrapping_sub(s[0] as u32)) >> 8;
    // canonical iff NOT (c == 1 AND d == 1)
    (c & d & 1) == 0
}

/// Check if a point encoding represents a small-order point.
/// Matches libsodium's `ge25519_has_small_order`.
fn has_small_order(s: &[u8; 32]) -> bool {
    // The 7 blacklisted points (with sign bit masked)
    const BLACKLIST: [[u8; 32]; 7] = [
        // 0 (order 4)
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // 1 (order 1)
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // order 8
        [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ],
        // order 8
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ],
        // p-1 (order 2)
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // p (=0, order 4)
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // p+1 (=1, order 1)
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];

    let mut c = [0u8; 7];
    for j in 0..31 {
        for (i, bl) in BLACKLIST.iter().enumerate() {
            c[i] |= s[j] ^ bl[j];
        }
    }
    for (i, bl) in BLACKLIST.iter().enumerate() {
        c[i] |= (s[31] & 0x7f) ^ bl[31];
    }

    let mut k = 0u32;
    for ci in &c {
        k |= (*ci as u32).wrapping_sub(1);
    }
    ((k >> 8) & 1) != 0
}

/// Validate a VRF public key: must be canonical, not small-order, and decompressible.
fn validate_vrf_key(pk: &[u8; 32]) -> Option<EdwardsPoint> {
    if has_small_order(pk) || !is_canonical_point_encoding(pk) {
        return None;
    }
    CompressedEdwardsY(*pk).decompress()
}

/// Convert a VRF proof to its output hash (without verification).
/// output = SHA-512(suite || 0x03 || point_to_string(8 * Gamma))
fn proof_to_hash(gamma: &EdwardsPoint) -> [u8; 64] {
    // Multiply Gamma by cofactor 8
    let gamma_bytes = gamma.mul_by_cofactor().compress().to_bytes();

    let mut hash_input = [0u8; 2 + 32];
    hash_input[0] = SUITE;
    hash_input[1] = 0x03;
    hash_input[2..34].copy_from_slice(&gamma_bytes);

    let hash = Sha512::digest(hash_input);
    let mut output = [0u8; 64];
    output.copy_from_slice(&hash);
    output
}

// ============================================================================
// VRF verification (draft-irtf-cfrg-vrf-03 section 5.3)
// ============================================================================

/// Verify a VRF proof and return the output if valid.
///
/// Arguments:
/// - `pk_bytes`: 32-byte VRF public key (compressed Edwards Y)
/// - `pi_bytes`: 80-byte VRF proof (Gamma || c || s)
/// - `alpha`: message bytes
///
/// Returns `Some(output)` with the 64-byte VRF output if verification succeeds,
/// or `None` if verification fails.
pub fn vrf_verify(pk_bytes: &[u8; 32], pi_bytes: &[u8; 80], alpha: &[u8]) -> Option<[u8; 64]> {
    // 1. Validate the public key
    let y_point = validate_vrf_key(pk_bytes)?;

    // 2. Decode the proof
    let (gamma, c_bytes, s_bytes) = decode_proof(pi_bytes)?;

    // 3. Prepare c as a 32-byte scalar (pad with zeros)
    let mut c_scalar_bytes = [0u8; 32];
    c_scalar_bytes[..16].copy_from_slice(&c_bytes);
    // Note: c fits in 16 bytes, no reduction needed for the scalar multiply
    // BUT we need to construct a Scalar. curve25519-dalek Scalar::from_bytes_mod_order
    // will handle this.
    let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);

    // 4. Prepare s as a reduced scalar
    // In libsodium: s is 32 bytes, padded to 64 bytes with zeros, then sc25519_reduce'd
    let mut s_wide = [0u8; 64];
    s_wide[..32].copy_from_slice(&s_bytes);
    let s_scalar = Scalar::from_bytes_mod_order_wide(&s_wide);

    // 5. Hash to curve: H = hash_to_curve(pk, alpha)
    let h_bytes = hash_to_curve(pk_bytes, alpha);
    let h_compressed = CompressedEdwardsY(h_bytes);
    let h_point = h_compressed.decompress()?;

    // 6. Compute U = s*B - c*Y
    let c_y = c_scalar * y_point;
    let s_b = EdwardsPoint::mul_base(&s_scalar);
    let u_point = s_b - c_y;

    // 7. Compute V = s*H - c*Gamma
    let c_gamma = c_scalar * gamma;
    let s_h = s_scalar * h_point;
    let v_point = s_h - c_gamma;

    // 8. Compute c' = hash_points(H, Gamma, U, V)
    let c_prime = hash_points(&h_point, &gamma, &u_point, &v_point);

    // 9. Verify c == c'
    if !eq_16(&c_bytes, &c_prime) {
        return None;
    }

    // 10. Compute output hash
    Some(proof_to_hash(&gamma))
}

/// Branch-free comparison of two 16-byte arrays.
///
/// Note: While implemented without branches, the Rust compiler does not
/// guarantee constant-time execution. This is acceptable here because all
/// VRF inputs (proof, public key, message) are on-chain and public.
fn eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Test vectors from draft-irtf-cfrg-vrf-03 appendix A.4 / go-algorand vrf_test.go.
    // Note: the "sk" in the test vectors is the 32-byte seed, not the 64-byte expanded key.
    // We only need pk, alpha, pi, and beta for verification.

    // Test vector 1: empty message
    const TV1_PK: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const TV1_ALPHA: &str = "";
    const TV1_PI: &str = "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900";
    const TV1_BETA: &str = "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc";

    // Test vector 2: message = 0x72
    const TV2_PK: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const TV2_ALPHA: &str = "72";
    const TV2_PI: &str = "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07";
    const TV2_BETA: &str = "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8";

    #[test]
    fn test_field_element_roundtrip() {
        let bytes = [0u8; 32];
        let fe = Fe25519::from_bytes(&bytes);
        assert_eq!(fe.to_bytes(), bytes);

        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        let fe = Fe25519::from_bytes(&bytes);
        assert_eq!(fe.to_bytes(), bytes);
    }

    #[test]
    fn test_field_element_mul_identity() {
        let mut bytes = [0u8; 32];
        bytes[0] = 7;
        let fe = Fe25519::from_bytes(&bytes);
        let one = Fe25519::ONE;
        let result = fe.mul(&one);
        assert_eq!(result.to_bytes(), bytes);
    }

    #[test]
    fn test_field_element_invert() {
        let mut bytes = [0u8; 32];
        bytes[0] = 42;
        let fe = Fe25519::from_bytes(&bytes);
        let inv = fe.invert();
        let product = fe.mul(&inv);
        assert_eq!(product.to_bytes(), Fe25519::ONE.to_bytes());
    }

    #[test]
    fn test_is_canonical_valid() {
        // Identity point (0, 1)
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        assert!(is_canonical_point_encoding(&bytes));
    }

    #[test]
    fn test_is_canonical_invalid() {
        // p itself (not canonical)
        let bytes: [u8; 32] = [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(!is_canonical_point_encoding(&bytes));
    }

    #[test]
    fn test_has_small_order_identity() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        assert!(has_small_order(&bytes));
    }

    #[test]
    fn test_has_small_order_normal_point() {
        // Ed25519 base point
        let basepoint = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
        assert!(!has_small_order(&basepoint.to_bytes()));
    }

    #[test]
    fn test_vrf_verify_vector1() {
        let pk = hex_to_bytes(TV1_PK);
        let alpha = hex_to_bytes(TV1_ALPHA);
        let pi = hex_to_bytes(TV1_PI);
        let expected_beta = hex_to_bytes(TV1_BETA);

        let pk_arr: [u8; 32] = pk.try_into().unwrap();
        let pi_arr: [u8; 80] = pi.try_into().unwrap();

        let result = vrf_verify(&pk_arr, &pi_arr, &alpha);
        assert!(
            result.is_some(),
            "VRF verify should succeed for test vector 1"
        );
        let output = result.unwrap();
        assert_eq!(
            output.to_vec(),
            expected_beta,
            "VRF output should match expected beta for test vector 1"
        );
    }

    #[test]
    fn test_vrf_verify_vector2() {
        let pk = hex_to_bytes(TV2_PK);
        let alpha = hex_to_bytes(TV2_ALPHA);
        let pi = hex_to_bytes(TV2_PI);
        let expected_beta = hex_to_bytes(TV2_BETA);

        let pk_arr: [u8; 32] = pk.try_into().unwrap();
        let pi_arr: [u8; 80] = pi.try_into().unwrap();

        let result = vrf_verify(&pk_arr, &pi_arr, &alpha);
        assert!(
            result.is_some(),
            "VRF verify should succeed for test vector 2"
        );
        let output = result.unwrap();
        assert_eq!(
            output.to_vec(),
            expected_beta,
            "VRF output should match expected beta for test vector 2"
        );
    }

    #[test]
    fn test_vrf_verify_invalid_proof() {
        let pk = hex_to_bytes(TV1_PK);
        let alpha = hex_to_bytes(TV1_ALPHA);
        let mut pi = hex_to_bytes(TV1_PI);
        // Corrupt the proof
        pi[0] ^= 0xff;
        // The corrupted gamma may not even decompress, which is fine (returns None)

        let pk_arr: [u8; 32] = pk.try_into().unwrap();
        let pi_arr: [u8; 80] = pi.try_into().unwrap();

        let result = vrf_verify(&pk_arr, &pi_arr, &alpha);
        assert!(
            result.is_none(),
            "VRF verify should fail for corrupted proof"
        );
    }

    #[test]
    fn test_vrf_verify_wrong_pubkey() {
        let alpha = hex_to_bytes(TV1_ALPHA);
        let pi = hex_to_bytes(TV1_PI);
        // Use TV2's pubkey with TV1's proof
        let wrong_pk = hex_to_bytes(TV2_PK);

        let pk_arr: [u8; 32] = wrong_pk.try_into().unwrap();
        let pi_arr: [u8; 80] = pi.try_into().unwrap();

        let result = vrf_verify(&pk_arr, &pi_arr, &alpha);
        assert!(
            result.is_none(),
            "VRF verify should fail with wrong public key"
        );
    }

    #[test]
    fn test_vrf_verify_wrong_message() {
        let pk = hex_to_bytes(TV2_PK);
        let pi = hex_to_bytes(TV2_PI);
        // Use wrong message (empty instead of 0x72)
        let wrong_alpha = b"";

        let pk_arr: [u8; 32] = pk.try_into().unwrap();
        let pi_arr: [u8; 80] = pi.try_into().unwrap();

        let result = vrf_verify(&pk_arr, &pi_arr, wrong_alpha);
        assert!(
            result.is_none(),
            "VRF verify should fail with wrong message"
        );
    }

    #[test]
    fn test_vrf_verify_zero_pubkey_rejected() {
        let pi = [0u8; 80];
        let pk = [0u8; 32]; // all zeros = small order
        let result = vrf_verify(&pk, &pi, b"test");
        assert!(
            result.is_none(),
            "VRF verify should reject zero public key (small order)"
        );
    }

    #[test]
    fn test_vrf_verify_zero_proof_zero_key_rejected() {
        // All-zero proof with valid-looking but non-matching key
        let pi = [0u8; 80];
        let pk = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
        let result = vrf_verify(&pk, &pi, b"test");
        assert!(result.is_none(), "VRF verify should fail with zero proof");
    }

    #[test]
    fn test_elligator2_deterministic() {
        // Same input should always produce same output
        let input = [42u8; 32];
        let out1 = elligator2_ed25519(&input);
        let out2 = elligator2_ed25519(&input);
        assert_eq!(out1, out2, "Elligator2 should be deterministic");
    }

    #[test]
    fn test_elligator2_output_is_valid_point() {
        let input = [42u8; 32];
        let out = elligator2_ed25519(&input);
        let compressed = CompressedEdwardsY(out);
        assert!(
            compressed.decompress().is_some(),
            "Elligator2 output should be a valid Edwards point"
        );
    }
}
