//! VRF prove implementation: ECVRF-ED25519-SHA512-Elligator2 (draft-irtf-cfrg-vrf-03).
//!
//! This implements the VRF prove side matching go-algorand's libsodium-fork.
//! The verify side lives in `algo-avm::ops::vrf` and is reused for cross-validation.
//!
//! # Algorithm (prove)
//!
//! 1. Expand 32-byte seed via SHA-512 + clamping to get (x_scalar, truncated_hash)
//! 2. Derive public key: Y = x * B (base-point multiplication)
//! 3. Hash-to-curve: H = elligator2(SHA-512(suite || 0x01 || pk || alpha))
//! 4. Gamma = x * H
//! 5. Nonce: k = SHA-512(truncated_hash || H_string) mod q
//! 6. U = k * B, V = k * H
//! 7. c = hash_points(H, Gamma, U, V)[0..16]
//! 8. s = c * x + k (mod q)
//! 9. proof = Gamma_bytes || c_bytes(16) || s_bytes(32)
//! 10. output = SHA-512(suite || 0x03 || cofactor_Gamma)

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Suite byte for ECVRF-ED25519-SHA512-Elligator2 (draft-irtf-cfrg-vrf-03).
const SUITE: u8 = 0x04;

/// A 32-byte VRF seed (secret entropy).
#[derive(Clone)]
pub struct VrfPrivkey([u8; 32]);

impl Drop for VrfPrivkey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A 32-byte compressed Edwards Y public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrfPubkey(pub [u8; 32]);

/// An 80-byte VRF proof: Gamma(32) || c(16) || s(32).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrfProof(pub [u8; 80]);

/// A 64-byte VRF output hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrfOutput(pub [u8; 64]);

/// A VRF keypair (seed + precomputed public key).
#[derive(Clone)]
pub struct VrfKeypair {
    pub pk: VrfPubkey,
    pub sk: VrfPrivkey,
}

// ============================================================================
// Field element arithmetic mod p = 2^255 - 19
// ============================================================================

/// A field element in GF(2^255 - 19), represented as 5 limbs of 51 bits each.
/// This is the "unsaturated radix-2^51" representation used by libsodium ref10.
#[derive(Clone, Copy, Debug)]
pub struct Fe25519(pub(crate) [u64; 5]);

impl Fe25519 {
    /// The zero element.
    pub const ZERO: Fe25519 = Fe25519([0, 0, 0, 0, 0]);
    /// The multiplicative identity.
    pub const ONE: Fe25519 = Fe25519([1, 0, 0, 0, 0]);
    /// Curve25519 Montgomery parameter A = 486662.
    pub const A: Fe25519 = Fe25519([486662, 0, 0, 0, 0]);

    /// Load a field element from 32 bytes (little-endian).
    pub fn from_bytes(s: &[u8; 32]) -> Self {
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
    pub fn to_bytes(self) -> [u8; 32] {
        let mut h = self.0;
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
        for i in 0..5 {
            carry = (h[i] as i64) >> 51;
            h[i] &= 0x7ffffffffffff;
            if i < 4 {
                h[i + 1] = (h[i + 1] as i64 + carry) as u64;
            } else {
                h[0] = (h[0] as i64 + 19 * carry) as u64;
            }
        }
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

    pub fn add(&self, rhs: &Fe25519) -> Fe25519 {
        Fe25519([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
        ])
    }

    pub fn sub(&self, rhs: &Fe25519) -> Fe25519 {
        Fe25519([
            (self.0[0] + 9007199254740916) - rhs.0[0],
            (self.0[1] + 9007199254740988) - rhs.0[1],
            (self.0[2] + 9007199254740988) - rhs.0[2],
            (self.0[3] + 9007199254740988) - rhs.0[3],
            (self.0[4] + 9007199254740988) - rhs.0[4],
        ])
    }

    pub fn neg(&self) -> Fe25519 {
        Fe25519::ZERO.sub(self)
    }

    pub fn mul(&self, rhs: &Fe25519) -> Fe25519 {
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
        r[1] += r[0] >> 51;
        r[0] &= 0x7ffffffffffff;
        Fe25519(r)
    }

    pub fn sq(&self) -> Fe25519 {
        self.mul(self)
    }

    pub fn sq2(&self) -> Fe25519 {
        let r = self.sq();
        r.add(&r)
    }

    pub fn pow_p_minus_5_over_8(&self) -> Fe25519 {
        let z2 = self.sq();
        let z8 = (0..2).fold(z2, |acc, _| acc.sq());
        let z9 = self.mul(&z8);
        let z11 = z2.mul(&z9);
        let z22 = z11.sq();
        let z_5_0 = z22.mul(&z9);
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
        t0.mul(self)
    }

    pub fn invert(&self) -> Fe25519 {
        let t = self.pow_p_minus_5_over_8();
        let t = t.sq().sq().sq();
        t.mul(&self.sq().mul(self))
    }

    pub fn chi(&self) -> Fe25519 {
        let z = *self;
        let t0 = z.sq();
        let t1 = t0.mul(&z);
        let t0 = t1.sq();
        let t2 = t0.sq();
        let t2 = t2.sq();
        let t2 = t2.mul(&t0);
        let t1 = t2.mul(&z);
        let mut t2 = t1.sq();
        for _ in 1..5 {
            t2 = t2.sq();
        }
        let t1 = t2.mul(&t1);
        let mut t2 = t1.sq();
        for _ in 1..10 {
            t2 = t2.sq();
        }
        let t2 = t2.mul(&t1);
        let mut t3 = t2.sq();
        for _ in 1..20 {
            t3 = t3.sq();
        }
        let t2 = t3.mul(&t2);
        let mut t2 = t2.sq();
        for _ in 1..10 {
            t2 = t2.sq();
        }
        let t1 = t2.mul(&t1);
        let mut t2 = t1.sq();
        for _ in 1..50 {
            t2 = t2.sq();
        }
        let t2 = t2.mul(&t1);
        let mut t3 = t2.sq();
        for _ in 1..100 {
            t3 = t3.sq();
        }
        let t2 = t3.mul(&t2);
        let mut t2 = t2.sq();
        for _ in 1..50 {
            t2 = t2.sq();
        }
        let t1 = t2.mul(&t1);
        let mut t1 = t1.sq();
        for _ in 1..4 {
            t1 = t1.sq();
        }
        t1.mul(&t0)
    }

    pub fn cmov(&mut self, other: &Fe25519, flag: u64) {
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
pub fn elligator2_ed25519(r: &[u8; 32]) -> [u8; 32] {
    let mut s = *r;
    let x_sign = s[31] & 0x80;
    s[31] &= 0x7f;

    let mut rr2 = Fe25519::from_bytes(&s);
    rr2 = rr2.sq2();
    rr2.0[0] += 1;
    rr2 = rr2.invert();
    let mut x = Fe25519::A.mul(&rr2);
    x = x.neg();

    let x2 = x.sq();
    let x3 = x.mul(&x2);
    let mut e = x3.add(&x);
    let ax2 = x2.mul(&Fe25519::A);
    e = ax2.add(&e);

    e = e.chi();

    let e_bytes = e.to_bytes();
    let e_is_minus_1 = (e_bytes[1] & 1) as u64;

    let negx = x.neg();
    x.cmov(&negx, e_is_minus_1);
    let mut x2 = Fe25519::ZERO;
    x2.cmov(&Fe25519::A, e_is_minus_1);
    x = x.sub(&x2);

    let x_plus_one = x.add(&Fe25519::ONE);
    let x_minus_one = x.sub(&Fe25519::ONE);
    let x_plus_one_inv = x_plus_one.invert();
    let yed = x_minus_one.mul(&x_plus_one_inv);
    s = yed.to_bytes();
    s[31] |= x_sign;

    let compressed = CompressedEdwardsY(s);
    match compressed.decompress() {
        Some(p) => p.mul_by_cofactor().compress().to_bytes(),
        None => unreachable!("Elligator2 output must be a valid curve point"),
    }
}

// ============================================================================
// VRF helper functions
// ============================================================================

/// Hash-to-curve using Elligator2, per VRF draft spec section 5.4.1.2.
///
/// Computes: H = elligator2(SHA-512(suite || 0x01 || pk_bytes || alpha)[0..32] with bit 255 cleared)
pub fn hash_to_curve(pk_bytes: &[u8; 32], alpha: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update([SUITE]);
    hasher.update([0x01u8]);
    hasher.update(pk_bytes);
    hasher.update(alpha);
    let hash = hasher.finalize();

    let mut r_string = [0u8; 32];
    r_string.copy_from_slice(&hash[..32]);
    r_string[31] &= 0x7f;

    elligator2_ed25519(&r_string)
}

/// Hash four points to a 16-byte challenge scalar, per VRF draft spec section 5.4.3.
///
/// c = SHA-512(suite || 0x02 || P1 || P2 || P3 || P4)[0..16]
pub fn hash_points(
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

/// Convert a VRF proof's Gamma to the output hash.
/// output = SHA-512(suite || 0x03 || compress(8 * Gamma))
pub fn proof_to_hash(gamma: &EdwardsPoint) -> [u8; 64] {
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
// Key expansion (matching libsodium's vrf_expand_sk)
// ============================================================================

/// Expand a 32-byte seed into (x_scalar, truncated_hashed_sk, pk_bytes).
///
/// Follows the same algorithm as libsodium:
/// 1. h = SHA-512(seed)
/// 2. x_scalar = h[0..32] with clamping (h[0] &= 248, h[31] &= 127, h[31] |= 64)
/// 3. truncated_hashed_sk = h[32..64]
/// 4. pk = compress(x_scalar * B)
fn expand_sk(seed: &[u8; 32]) -> (Scalar, Zeroizing<[u8; 32]>, [u8; 32]) {
    let h = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(seed)));

    // Clamp the scalar (ed25519 style)
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&h[0..32]);
    x_bytes[0] &= 248;
    x_bytes[31] &= 127;
    x_bytes[31] |= 64;

    let mut truncated = Zeroizing::new([0u8; 32]);
    truncated.copy_from_slice(&h[32..64]);

    // The clamped scalar is in [2^254, 2^255), which exceeds L (~2^252.6).
    // We reduce mod L here. This is safe because all VRF points (H, B) lie
    // in the prime-order subgroup (H has cofactor cleared), so x*P = (x mod L)*P.
    let x_scalar = Scalar::from_bytes_mod_order(x_bytes);

    // Derive public key: Y = x * B
    let y_point = EdwardsPoint::mul_base(&x_scalar);
    let pk_bytes = y_point.compress().to_bytes();

    (x_scalar, truncated, pk_bytes)
}

// ============================================================================
// Nonce generation (matching libsodium's vrf_nonce_generation)
// ============================================================================

/// Generate deterministic nonce k from truncated hash and H point encoding.
/// k = SHA-512(truncated_hashed_sk || h_string) mod q
fn nonce_generation(truncated_hashed_sk: &[u8; 32], h_string: &[u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(truncated_hashed_sk);
    hasher.update(h_string);
    let k_string = hasher.finalize();

    // sc25519_reduce: reduce 64-byte value mod q (the ed25519 group order)
    let mut k_wide = [0u8; 64];
    k_wide.copy_from_slice(&k_string);
    Scalar::from_bytes_mod_order_wide(&k_wide)
}

// ============================================================================
// VRF verify (for self-check; same algorithm as algo-avm::ops::vrf)
// ============================================================================

/// Check if a 32-byte encoding is canonical (y < p).
/// Matches libsodium's `ge25519_is_canonical`.
pub fn is_canonical_point_encoding(s: &[u8; 32]) -> bool {
    let mut c = (s[31] & 0x7f) ^ 0x7f;
    for i in (1..31).rev() {
        c |= s[i] ^ 0xff;
    }
    let c = ((c as u32).wrapping_sub(1)) >> 8;
    let d = ((0xedu32).wrapping_sub(1).wrapping_sub(s[0] as u32)) >> 8;
    (c & d & 1) == 0
}

/// Check if a point encoding represents a small-order point.
/// Matches libsodium's `ge25519_has_small_order`.
pub fn has_small_order(s: &[u8; 32]) -> bool {
    const BLACKLIST: [[u8; 32]; 7] = [
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ],
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ],
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
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

/// Verify a VRF proof and return the output if valid.
pub fn vrf_verify(pk_bytes: &[u8; 32], pi_bytes: &[u8; 80], alpha: &[u8]) -> Option<[u8; 64]> {
    // Validate key
    if has_small_order(pk_bytes) || !is_canonical_point_encoding(pk_bytes) {
        return None;
    }
    let y_point = CompressedEdwardsY(*pk_bytes).decompress()?;

    // Decode proof
    let mut gamma_bytes = [0u8; 32];
    gamma_bytes.copy_from_slice(&pi_bytes[0..32]);
    if !is_canonical_point_encoding(&gamma_bytes) {
        return None;
    }
    let gamma = CompressedEdwardsY(gamma_bytes).decompress()?;
    let mut c_bytes = [0u8; 16];
    c_bytes.copy_from_slice(&pi_bytes[32..48]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&pi_bytes[48..80]);

    // Scalars
    let mut c_scalar_bytes = [0u8; 32];
    c_scalar_bytes[..16].copy_from_slice(&c_bytes);
    let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);
    let mut s_wide = [0u8; 64];
    s_wide[..32].copy_from_slice(&s_bytes);
    let s_scalar = Scalar::from_bytes_mod_order_wide(&s_wide);

    // Hash to curve
    let h_bytes = hash_to_curve(pk_bytes, alpha);
    let h_point = CompressedEdwardsY(h_bytes).decompress()?;

    // U = s*B - c*Y
    let u_point = EdwardsPoint::mul_base(&s_scalar) - c_scalar * y_point;
    // V = s*H - c*Gamma
    let v_point = s_scalar * h_point - c_scalar * gamma;

    // c' = hash_points(H, Gamma, U, V)
    let c_prime = hash_points(&h_point, &gamma, &u_point, &v_point);

    // Check c == c'
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= c_bytes[i] ^ c_prime[i];
    }
    if diff != 0 {
        return None;
    }

    Some(proof_to_hash(&gamma))
}

// ============================================================================
// Public API
// ============================================================================

impl VrfPrivkey {
    /// Create a VRF private key from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        VrfPrivkey(seed)
    }

    /// Return the raw 32-byte seed.
    pub fn seed(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the corresponding public key.
    pub fn pubkey(&self) -> VrfPubkey {
        let (_, _, pk_bytes) = expand_sk(&self.0);
        VrfPubkey(pk_bytes)
    }

    /// Produce a VRF proof and output for the given message.
    ///
    /// This follows ECVRF-IETF-draft-03 section 5.1 exactly:
    /// 1. Expand seed to (x, truncated_hash, pk)
    /// 2. H = hash_to_curve(pk, alpha)
    /// 3. Gamma = x * H
    /// 4. k = nonce_gen(truncated_hash, H_compressed)
    /// 5. U = k*B, V = k*H
    /// 6. c = hash_points(H, Gamma, U, V)[0..16]
    /// 7. s = c*x + k (mod q)
    /// 8. proof = Gamma || c || s
    /// 9. output = SHA-512(suite || 0x03 || 8*Gamma)
    #[must_use]
    pub fn prove(&self, alpha: &[u8]) -> (VrfProof, VrfOutput) {
        let (x_scalar, truncated_hash, pk_bytes) = expand_sk(&self.0);

        // Hash to curve: H = elligator2(SHA-512(suite || 0x01 || pk || alpha))
        let h_bytes = hash_to_curve(&pk_bytes, alpha);
        let h_point = CompressedEdwardsY(h_bytes)
            .decompress()
            .expect("hash_to_curve must produce valid point");

        // Gamma = x * H
        let gamma_point = x_scalar * h_point;

        // Deterministic nonce
        let k_scalar = nonce_generation(&truncated_hash, &h_bytes);

        // k*B and k*H
        let kb_point = EdwardsPoint::mul_base(&k_scalar);
        let kh_point = k_scalar * h_point;

        // Challenge c (16 bytes)
        let c_bytes = hash_points(&h_point, &gamma_point, &kb_point, &kh_point);

        // c as a scalar (padded to 32 bytes)
        let mut c_scalar_bytes = [0u8; 32];
        c_scalar_bytes[..16].copy_from_slice(&c_bytes);
        let c_scalar = Scalar::from_bytes_mod_order(c_scalar_bytes);

        // s = c * x + k (mod q)  -- equivalent to libsodium's sc25519_muladd
        let s_scalar = c_scalar * x_scalar + k_scalar;

        // Encode proof: Gamma(32) || c(16) || s(32)
        let mut pi = [0u8; 80];
        pi[0..32].copy_from_slice(&gamma_point.compress().to_bytes());
        pi[32..48].copy_from_slice(&c_bytes);
        pi[48..80].copy_from_slice(&s_scalar.to_bytes());

        // Output hash
        let output = proof_to_hash(&gamma_point);

        (VrfProof(pi), VrfOutput(output))
    }
}

impl VrfPubkey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        VrfPubkey(bytes)
    }

    /// Verify a VRF proof against this public key and message.
    /// Returns the VRF output if verification succeeds.
    pub fn verify(&self, proof: &VrfProof, alpha: &[u8]) -> Option<VrfOutput> {
        vrf_verify(&self.0, &proof.0, alpha).map(VrfOutput)
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Check if this key is all zeros.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl VrfProof {
    /// Return the raw 80-byte proof.
    pub fn as_bytes(&self) -> &[u8; 80] {
        &self.0
    }

    /// Convert proof to output hash without verifying.
    pub fn to_hash(&self) -> Option<VrfOutput> {
        // Decode gamma
        let mut gamma_bytes = [0u8; 32];
        gamma_bytes.copy_from_slice(&self.0[0..32]);
        if !is_canonical_point_encoding(&gamma_bytes) {
            return None;
        }
        let gamma = CompressedEdwardsY(gamma_bytes).decompress()?;
        Some(VrfOutput(proof_to_hash(&gamma)))
    }
}

impl VrfOutput {
    /// Return the raw 64-byte output.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Interpret the first 8 bytes as a little-endian u64.
    /// Used as the sortition hash input in Algorand consensus.
    pub fn hash_to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[0..8].try_into().unwrap())
    }
}

impl VrfKeypair {
    /// Generate a keypair from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sk = VrfPrivkey::from_seed(seed);
        let pk = sk.pubkey();
        VrfKeypair { pk, sk }
    }

    /// Generate a random keypair using the OS RNG.
    ///
    /// Matches go-algorand's `crypto.GenerateVRFSecrets` (which reads from
    /// `crypto/rand` — equivalent to Rust's `OsRng` via `thread_rng`).
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand::thread_rng())
    }

    /// Generate a random keypair using the supplied RNG.
    ///
    /// Equivalent to go-algorand's RNG-injected keygen path
    /// (`ed25519GenerateKeyRNG` with an explicit `crypto.RNG`). Use for
    /// deterministic testing or to plumb a `crypto.PRNG`-equivalent through.
    #[must_use]
    pub fn generate_with_rng<R: RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn bytes_to_hex(b: &[u8]) -> String {
        hex::encode(b)
    }

    // IETF draft-irtf-cfrg-vrf-03 test vectors (same as in algo-avm vrf.rs)
    const TV1_SK_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const TV1_PK: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const TV1_ALPHA: &str = "";
    const TV1_PI: &str = "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900";
    const TV1_BETA: &str = "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc";

    const TV2_SK_SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const TV2_PK: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const TV2_ALPHA: &str = "72";
    const TV2_PI: &str = "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07";
    const TV2_BETA: &str = "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8";

    #[test]
    fn test_keypair_from_seed_tv1() {
        let seed: [u8; 32] = hex_to_bytes(TV1_SK_SEED).try_into().unwrap();
        let kp = VrfKeypair::from_seed(seed);
        assert_eq!(
            bytes_to_hex(&kp.pk.0),
            TV1_PK,
            "Public key should match test vector 1"
        );
    }

    #[test]
    fn test_keypair_from_seed_tv2() {
        let seed: [u8; 32] = hex_to_bytes(TV2_SK_SEED).try_into().unwrap();
        let kp = VrfKeypair::from_seed(seed);
        assert_eq!(
            bytes_to_hex(&kp.pk.0),
            TV2_PK,
            "Public key should match test vector 2"
        );
    }

    #[test]
    fn test_prove_tv1() {
        let seed: [u8; 32] = hex_to_bytes(TV1_SK_SEED).try_into().unwrap();
        let sk = VrfPrivkey::from_seed(seed);
        let alpha = hex_to_bytes(TV1_ALPHA);
        let (proof, output) = sk.prove(&alpha);

        assert_eq!(
            bytes_to_hex(&proof.0),
            TV1_PI,
            "Proof should match test vector 1"
        );
        assert_eq!(
            bytes_to_hex(&output.0),
            TV1_BETA,
            "Output should match test vector 1"
        );
    }

    #[test]
    fn test_prove_tv2() {
        let seed: [u8; 32] = hex_to_bytes(TV2_SK_SEED).try_into().unwrap();
        let sk = VrfPrivkey::from_seed(seed);
        let alpha = hex_to_bytes(TV2_ALPHA);
        let (proof, output) = sk.prove(&alpha);

        assert_eq!(
            bytes_to_hex(&proof.0),
            TV2_PI,
            "Proof should match test vector 2"
        );
        assert_eq!(
            bytes_to_hex(&output.0),
            TV2_BETA,
            "Output should match test vector 2"
        );
    }

    #[test]
    fn test_prove_then_verify_tv1() {
        let seed: [u8; 32] = hex_to_bytes(TV1_SK_SEED).try_into().unwrap();
        let kp = VrfKeypair::from_seed(seed);
        let alpha = hex_to_bytes(TV1_ALPHA);
        let (proof, output) = kp.sk.prove(&alpha);

        let verified = kp.pk.verify(&proof, &alpha);
        assert!(verified.is_some(), "Proof should verify against own pubkey");
        assert_eq!(
            verified.unwrap().0,
            output.0,
            "Verified output should match prove output"
        );
    }

    #[test]
    fn test_prove_then_verify_tv2() {
        let seed: [u8; 32] = hex_to_bytes(TV2_SK_SEED).try_into().unwrap();
        let kp = VrfKeypair::from_seed(seed);
        let alpha = hex_to_bytes(TV2_ALPHA);
        let (proof, output) = kp.sk.prove(&alpha);

        let verified = kp.pk.verify(&proof, &alpha);
        assert!(verified.is_some(), "Proof should verify against own pubkey");
        assert_eq!(
            verified.unwrap().0,
            output.0,
            "Verified output should match prove output"
        );
    }

    #[test]
    fn test_prove_verify_random_seeds() {
        // Test with several arbitrary seeds
        let seeds: Vec<[u8; 32]> = (0..5)
            .map(|i| {
                let mut s = [0u8; 32];
                s[0] = i;
                s[31] = 0xff - i;
                s
            })
            .collect();

        for (idx, seed) in seeds.iter().enumerate() {
            let kp = VrfKeypair::from_seed(*seed);
            let msg = format!("test message {}", idx);
            let (proof, output) = kp.sk.prove(msg.as_bytes());

            let verified = kp.pk.verify(&proof, msg.as_bytes());
            assert!(
                verified.is_some(),
                "Proof {} should verify against own pubkey",
                idx
            );
            assert_eq!(
                verified.unwrap().0,
                output.0,
                "Verified output {} should match prove output",
                idx
            );

            // Wrong message should fail
            let wrong = kp.pk.verify(&proof, b"wrong message");
            assert!(
                wrong.is_none(),
                "Proof {} should fail with wrong message",
                idx
            );

            // Wrong key should fail
            let other_kp = VrfKeypair::from_seed([idx as u8 + 100; 32]);
            let wrong_key = other_kp.pk.verify(&proof, msg.as_bytes());
            assert!(
                wrong_key.is_none(),
                "Proof {} should fail with wrong key",
                idx
            );
        }
    }

    #[test]
    fn test_prove_deterministic() {
        let seed = [42u8; 32];
        let sk = VrfPrivkey::from_seed(seed);
        let (proof1, output1) = sk.prove(b"hello");
        let (proof2, output2) = sk.prove(b"hello");
        assert_eq!(proof1.0, proof2.0, "Prove should be deterministic");
        assert_eq!(output1.0, output2.0, "Output should be deterministic");
    }

    #[test]
    fn test_proof_to_hash_matches_output() {
        let seed = [7u8; 32];
        let sk = VrfPrivkey::from_seed(seed);
        let (proof, output) = sk.prove(b"test");
        let hash = proof.to_hash();
        assert!(hash.is_some(), "to_hash should succeed");
        assert_eq!(
            hash.unwrap().0,
            output.0,
            "proof.to_hash should match prove output"
        );
    }

    #[test]
    fn test_hash_to_u64() {
        let seed = [1u8; 32];
        let sk = VrfPrivkey::from_seed(seed);
        let (_, output) = sk.prove(b"sortition");
        let h = output.hash_to_u64();
        // Just check it's the first 8 bytes as LE u64
        let expected = u64::from_le_bytes(output.0[0..8].try_into().unwrap());
        assert_eq!(h, expected);
    }

    #[test]
    fn test_zero_pubkey_is_zero() {
        let pk = VrfPubkey([0u8; 32]);
        assert!(pk.is_zero());
        let kp = VrfKeypair::from_seed([1u8; 32]);
        assert!(!kp.pk.is_zero());
    }

    #[test]
    fn test_verify_rejects_corrupted_proof() {
        let seed = [99u8; 32];
        let kp = VrfKeypair::from_seed(seed);
        let (mut proof, _) = kp.sk.prove(b"msg");
        proof.0[10] ^= 0xff; // corrupt
        let result = kp.pk.verify(&proof, b"msg");
        assert!(result.is_none(), "Corrupted proof should fail verification");
    }
}
