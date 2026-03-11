//! Elliptic curve opcodes: ec_add, ec_scalar_mul, ec_pairing_check,
//! ec_multi_scalar_mul, ec_subgroup_check, ec_map_to.
//!
//! Supports four groups: BN254g1, BN254g2, BLS12-381g1, BLS12-381g2.
//! Matches go-algorand's gnark-crypto-based implementation.

use algo_error::AlgoError;
use num_bigint::BigUint;

use ark_bls12_381::{
    Bls12_381, Fq as BLS12Fq, Fq2 as BLS12Fq2, G1Affine as BLS12G1Affine, G1Projective as BLS12G1,
    G2Affine as BLS12G2Affine, G2Projective as BLS12G2,
};
use ark_bn254::{
    Bn254, Fq as BN254Fq, Fq2 as BN254Fq2, G1Affine as BN254G1Affine, G1Projective as BN254G1,
    G2Affine as BN254G2Affine, G2Projective as BN254G2,
};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurve},
    pairing::Pairing,
    AffineRepr, CurveGroup, PrimeGroup,
};
use ark_ff::{BigInteger, One, PrimeField, Zero};

use crate::bytecode::Instruction;
use crate::fields::EcGroup;
use crate::machine::{AvmMachine, AvmValue};
use crate::ops::helpers::get_uint8;

fn avm_err(msg: impl Into<String>) -> AlgoError {
    AlgoError::Avm {
        message: msg.into(),
    }
}

/// Integer ceiling division, matching Go's `basics.DivCeil`.
fn div_ceil(a: usize, b: usize) -> usize {
    if b == 0 {
        return 0;
    }
    a.div_ceil(b)
}

// ---------------------------------------------------------------------------
// Size constants (matching go-algorand)
// ---------------------------------------------------------------------------

const BN254_FP_SIZE: usize = 32;
const BN254_G1_SIZE: usize = 2 * BN254_FP_SIZE; // 64
const BN254_FP2_SIZE: usize = 2 * BN254_FP_SIZE; // 64
const BN254_G2_SIZE: usize = 2 * BN254_FP2_SIZE; // 128

const BLS12_FP_SIZE: usize = 48;
const BLS12_G1_SIZE: usize = 2 * BLS12_FP_SIZE; // 96
const BLS12_FP2_SIZE: usize = 2 * BLS12_FP_SIZE; // 96
const BLS12_G2_SIZE: usize = 2 * BLS12_FP2_SIZE; // 192

const SCALAR_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// BN254 encoding/decoding
// ---------------------------------------------------------------------------

/// Decode a big-endian byte slice into a BN254 base field element.
/// Verifies the value is less than the field modulus.
fn bytes_to_bn254_field(b: &[u8]) -> Result<BN254Fq, AlgoError> {
    let v = BigUint::from_bytes_be(b);
    let modulus = BigUint::from_bytes_be(&BN254Fq::MODULUS.to_bytes_be());
    if v >= modulus {
        return Err(avm_err(format!(
            "field element {} larger than modulus {}",
            v, modulus
        )));
    }
    Ok(BN254Fq::from(v))
}

/// Decode 64 bytes (big-endian x || y) into a BN254 G1 affine point.
fn bytes_to_bn254_g1(b: &[u8]) -> Result<BN254G1Affine, AlgoError> {
    if b.len() != BN254_G1_SIZE {
        return Err(avm_err(format!(
            "bad length {}. Expected {}",
            b.len(),
            BN254_G1_SIZE
        )));
    }
    let x = bytes_to_bn254_field(&b[..BN254_FP_SIZE])?;
    let y = bytes_to_bn254_field(&b[BN254_FP_SIZE..BN254_G1_SIZE])?;
    // Check for point at infinity (both coords zero)
    if x.is_zero() && y.is_zero() {
        return Ok(BN254G1Affine::zero());
    }
    let point = BN254G1Affine::new_unchecked(x, y);
    if !point.is_on_curve() {
        return Err(avm_err("point not on curve"));
    }
    Ok(point)
}

/// Decode multiple concatenated G1 points.
fn bytes_to_bn254_g1s(b: &[u8], check_subgroup: bool) -> Result<Vec<BN254G1Affine>, AlgoError> {
    if b.len() % BN254_G1_SIZE != 0 {
        return Err(avm_err(format!(
            "bad length {}. Expected {} multiple",
            b.len(),
            BN254_G1_SIZE
        )));
    }
    if b.is_empty() {
        return Err(avm_err("empty input"));
    }
    let n = b.len() / BN254_G1_SIZE;
    let mut points = Vec::with_capacity(n);
    for i in 0..n {
        let p = bytes_to_bn254_g1(&b[i * BN254_G1_SIZE..(i + 1) * BN254_G1_SIZE])?;
        if check_subgroup && !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(avm_err("wrong subgroup"));
        }
        points.push(p);
    }
    Ok(points)
}

/// Encode a BN254 G1 affine point as 64 big-endian bytes (x || y).
fn bn254_g1_to_bytes(p: &BN254G1Affine) -> Vec<u8> {
    let mut out = vec![0u8; BN254_G1_SIZE];
    if p.is_zero() {
        return out;
    }
    let x_bytes = p.x.into_bigint().to_bytes_be();
    let y_bytes = p.y.into_bigint().to_bytes_be();
    copy_right_aligned(&x_bytes, &mut out[..BN254_FP_SIZE]);
    copy_right_aligned(&y_bytes, &mut out[BN254_FP_SIZE..BN254_G1_SIZE]);
    out
}

/// Decode 128 bytes into a BN254 G2 affine point.
/// Layout: X.A0 || X.A1 || Y.A0 || Y.A1 (each 32 bytes, big-endian)
fn bytes_to_bn254_g2(b: &[u8]) -> Result<BN254G2Affine, AlgoError> {
    if b.len() != BN254_G2_SIZE {
        return Err(avm_err(format!(
            "bad length {}. Expected {}",
            b.len(),
            BN254_G2_SIZE
        )));
    }
    let x_a0 = bytes_to_bn254_field(&b[..BN254_FP_SIZE])?;
    let x_a1 = bytes_to_bn254_field(&b[BN254_FP_SIZE..2 * BN254_FP_SIZE])?;
    let y_a0 = bytes_to_bn254_field(&b[2 * BN254_FP_SIZE..3 * BN254_FP_SIZE])?;
    let y_a1 = bytes_to_bn254_field(&b[3 * BN254_FP_SIZE..4 * BN254_FP_SIZE])?;

    let x = BN254Fq2::new(x_a0, x_a1);
    let y = BN254Fq2::new(y_a0, y_a1);

    if x.is_zero() && y.is_zero() {
        return Ok(BN254G2Affine::zero());
    }
    let point = BN254G2Affine::new_unchecked(x, y);
    if !point.is_on_curve() {
        return Err(avm_err("point not on curve"));
    }
    Ok(point)
}

/// Decode multiple concatenated G2 points.
fn bytes_to_bn254_g2s(b: &[u8], check_subgroup: bool) -> Result<Vec<BN254G2Affine>, AlgoError> {
    if b.len() % BN254_G2_SIZE != 0 {
        return Err(avm_err(format!(
            "bad length {}. Expected {} multiple",
            b.len(),
            BN254_G2_SIZE
        )));
    }
    if b.is_empty() {
        return Err(avm_err("empty input"));
    }
    let n = b.len() / BN254_G2_SIZE;
    let mut points = Vec::with_capacity(n);
    for i in 0..n {
        let p = bytes_to_bn254_g2(&b[i * BN254_G2_SIZE..(i + 1) * BN254_G2_SIZE])?;
        if check_subgroup && !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(avm_err("wrong subgroup"));
        }
        points.push(p);
    }
    Ok(points)
}

/// Encode a BN254 G2 affine point as 128 big-endian bytes.
fn bn254_g2_to_bytes(p: &BN254G2Affine) -> Vec<u8> {
    let mut out = vec![0u8; BN254_G2_SIZE];
    if p.is_zero() {
        return out;
    }
    let x_a0 = p.x.c0.into_bigint().to_bytes_be();
    let x_a1 = p.x.c1.into_bigint().to_bytes_be();
    let y_a0 = p.y.c0.into_bigint().to_bytes_be();
    let y_a1 = p.y.c1.into_bigint().to_bytes_be();
    copy_right_aligned(&x_a0, &mut out[..BN254_FP_SIZE]);
    copy_right_aligned(&x_a1, &mut out[BN254_FP_SIZE..2 * BN254_FP_SIZE]);
    copy_right_aligned(&y_a0, &mut out[2 * BN254_FP_SIZE..3 * BN254_FP_SIZE]);
    copy_right_aligned(&y_a1, &mut out[3 * BN254_FP_SIZE..4 * BN254_FP_SIZE]);
    out
}

// ---------------------------------------------------------------------------
// BLS12-381 encoding/decoding
// ---------------------------------------------------------------------------

fn bytes_to_bls12_field(b: &[u8]) -> Result<BLS12Fq, AlgoError> {
    let v = BigUint::from_bytes_be(b);
    let modulus = BigUint::from_bytes_be(&BLS12Fq::MODULUS.to_bytes_be());
    if v >= modulus {
        return Err(avm_err(format!(
            "field element {} larger than modulus {}",
            v, modulus
        )));
    }
    Ok(BLS12Fq::from(v))
}

fn bytes_to_bls12_g1(b: &[u8]) -> Result<BLS12G1Affine, AlgoError> {
    if b.len() != BLS12_G1_SIZE {
        return Err(avm_err(format!(
            "bad length {}. Expected {}",
            b.len(),
            BLS12_G1_SIZE
        )));
    }
    let x = bytes_to_bls12_field(&b[..BLS12_FP_SIZE])?;
    let y = bytes_to_bls12_field(&b[BLS12_FP_SIZE..BLS12_G1_SIZE])?;
    if x.is_zero() && y.is_zero() {
        return Ok(BLS12G1Affine::zero());
    }
    let point = BLS12G1Affine::new_unchecked(x, y);
    if !point.is_on_curve() {
        return Err(avm_err("point not on curve"));
    }
    Ok(point)
}

fn bytes_to_bls12_g1s(b: &[u8], check_subgroup: bool) -> Result<Vec<BLS12G1Affine>, AlgoError> {
    if b.len() % BLS12_G1_SIZE != 0 {
        return Err(avm_err(format!(
            "bad length {}. Expected {} multiple",
            b.len(),
            BLS12_G1_SIZE
        )));
    }
    if b.is_empty() {
        return Err(avm_err("empty input"));
    }
    let n = b.len() / BLS12_G1_SIZE;
    let mut points = Vec::with_capacity(n);
    for i in 0..n {
        let p = bytes_to_bls12_g1(&b[i * BLS12_G1_SIZE..(i + 1) * BLS12_G1_SIZE])?;
        if check_subgroup && !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(avm_err("wrong subgroup"));
        }
        points.push(p);
    }
    Ok(points)
}

fn bls12_g1_to_bytes(p: &BLS12G1Affine) -> Vec<u8> {
    let mut out = vec![0u8; BLS12_G1_SIZE];
    if p.is_zero() {
        return out;
    }
    let x_bytes = p.x.into_bigint().to_bytes_be();
    let y_bytes = p.y.into_bigint().to_bytes_be();
    copy_right_aligned(&x_bytes, &mut out[..BLS12_FP_SIZE]);
    copy_right_aligned(&y_bytes, &mut out[BLS12_FP_SIZE..BLS12_G1_SIZE]);
    out
}

fn bytes_to_bls12_g2(b: &[u8]) -> Result<BLS12G2Affine, AlgoError> {
    if b.len() != BLS12_G2_SIZE {
        return Err(avm_err(format!(
            "bad length {}. Expected {}",
            b.len(),
            BLS12_G2_SIZE
        )));
    }
    let x_a0 = bytes_to_bls12_field(&b[..BLS12_FP_SIZE])?;
    let x_a1 = bytes_to_bls12_field(&b[BLS12_FP_SIZE..2 * BLS12_FP_SIZE])?;
    let y_a0 = bytes_to_bls12_field(&b[2 * BLS12_FP_SIZE..3 * BLS12_FP_SIZE])?;
    let y_a1 = bytes_to_bls12_field(&b[3 * BLS12_FP_SIZE..4 * BLS12_FP_SIZE])?;

    let x = BLS12Fq2::new(x_a0, x_a1);
    let y = BLS12Fq2::new(y_a0, y_a1);

    if x.is_zero() && y.is_zero() {
        return Ok(BLS12G2Affine::zero());
    }
    let point = BLS12G2Affine::new_unchecked(x, y);
    if !point.is_on_curve() {
        return Err(avm_err("point not on curve"));
    }
    Ok(point)
}

fn bytes_to_bls12_g2s(b: &[u8], check_subgroup: bool) -> Result<Vec<BLS12G2Affine>, AlgoError> {
    if b.len() % BLS12_G2_SIZE != 0 {
        return Err(avm_err(format!(
            "bad length {}. Expected {} multiple",
            b.len(),
            BLS12_G2_SIZE
        )));
    }
    if b.is_empty() {
        return Err(avm_err("empty input"));
    }
    let n = b.len() / BLS12_G2_SIZE;
    let mut points = Vec::with_capacity(n);
    for i in 0..n {
        let p = bytes_to_bls12_g2(&b[i * BLS12_G2_SIZE..(i + 1) * BLS12_G2_SIZE])?;
        if check_subgroup && !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(avm_err("wrong subgroup"));
        }
        points.push(p);
    }
    Ok(points)
}

fn bls12_g2_to_bytes(p: &BLS12G2Affine) -> Vec<u8> {
    let mut out = vec![0u8; BLS12_G2_SIZE];
    if p.is_zero() {
        return out;
    }
    let x_a0 = p.x.c0.into_bigint().to_bytes_be();
    let x_a1 = p.x.c1.into_bigint().to_bytes_be();
    let y_a0 = p.y.c0.into_bigint().to_bytes_be();
    let y_a1 = p.y.c1.into_bigint().to_bytes_be();
    copy_right_aligned(&x_a0, &mut out[..BLS12_FP_SIZE]);
    copy_right_aligned(&x_a1, &mut out[BLS12_FP_SIZE..2 * BLS12_FP_SIZE]);
    copy_right_aligned(&y_a0, &mut out[2 * BLS12_FP_SIZE..3 * BLS12_FP_SIZE]);
    copy_right_aligned(&y_a1, &mut out[3 * BLS12_FP_SIZE..4 * BLS12_FP_SIZE]);
    out
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Copy src into the right side of dst, zero-padding on the left.
fn copy_right_aligned(src: &[u8], dst: &mut [u8]) {
    let n = src.len().min(dst.len());
    let offset = dst.len() - n;
    dst[..offset].fill(0);
    dst[offset..].copy_from_slice(&src[src.len() - n..]);
}

/// Parse the EcGroup immediate from the instruction.
fn get_ec_group(instruction: &Instruction) -> Result<EcGroup, AlgoError> {
    let g = get_uint8(instruction)?;
    EcGroup::from_u8(g).map_err(|_| avm_err(format!("invalid ec group {g}")))
}

/// Convert a BigUint to little-endian u64 limbs for `mul_bigint`.
fn to_le_u64_limbs(k: &BigUint) -> Vec<u64> {
    let bytes = k.to_bytes_le();
    let n_limbs = bytes.len().div_ceil(8);
    let mut limbs = vec![0u64; n_limbs];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        limbs[i] = u64::from_le_bytes(buf);
    }
    limbs
}

// ---------------------------------------------------------------------------
// ec_add (0xe0)
// ---------------------------------------------------------------------------

/// `ec_add` (0xe0): pop two points, push their sum.
pub fn op_ec_add(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let group = get_ec_group(instruction)?;

    // Charge cost per curve group (from go-algorand opcodes.go).
    let cost = match group {
        EcGroup::BN254g1 => 125,
        EcGroup::BN254g2 => 170,
        EcGroup::BLS12_381g1 => 205,
        EcGroup::BLS12_381g2 => 290,
    };
    machine.charge_cost(cost)?;

    let b_bytes = machine.pop_bytes()?;
    let a_bytes = machine.pop_bytes()?;

    let res = match group {
        EcGroup::BN254g1 => {
            let a = bytes_to_bn254_g1(&a_bytes)?;
            let b = bytes_to_bn254_g1(&b_bytes)?;
            let sum: BN254G1Affine = (a + b).into_affine();
            bn254_g1_to_bytes(&sum)
        }
        EcGroup::BN254g2 => {
            let a = bytes_to_bn254_g2(&a_bytes)?;
            let b = bytes_to_bn254_g2(&b_bytes)?;
            let sum: BN254G2Affine = (a + b).into_affine();
            bn254_g2_to_bytes(&sum)
        }
        EcGroup::BLS12_381g1 => {
            let a = bytes_to_bls12_g1(&a_bytes)?;
            let b = bytes_to_bls12_g1(&b_bytes)?;
            let sum: BLS12G1Affine = (a + b).into_affine();
            bls12_g1_to_bytes(&sum)
        }
        EcGroup::BLS12_381g2 => {
            let a = bytes_to_bls12_g2(&a_bytes)?;
            let b = bytes_to_bls12_g2(&b_bytes)?;
            let sum: BLS12G2Affine = (a + b).into_affine();
            bls12_g2_to_bytes(&sum)
        }
    };
    machine.push(AvmValue::Bytes(res))
}

// ---------------------------------------------------------------------------
// ec_scalar_mul (0xe1)
// ---------------------------------------------------------------------------

/// `ec_scalar_mul` (0xe1): pop scalar (bytes) and point (bytes), push product.
pub fn op_ec_scalar_mul(
    machine: &mut AvmMachine,
    instruction: &Instruction,
) -> Result<(), AlgoError> {
    let group = get_ec_group(instruction)?;

    // Charge cost per curve group (from go-algorand opcodes.go).
    let cost = match group {
        EcGroup::BN254g1 => 1810,
        EcGroup::BN254g2 => 3430,
        EcGroup::BLS12_381g1 => 2950,
        EcGroup::BLS12_381g2 => 6530,
    };
    machine.charge_cost(cost)?;

    let k_bytes = machine.pop_bytes()?;
    let a_bytes = machine.pop_bytes()?;

    if k_bytes.len() > SCALAR_SIZE {
        return Err(avm_err(format!(
            "ec_scalar_mul scalar len is {}, exceeds {}",
            k_bytes.len(),
            SCALAR_SIZE
        )));
    }

    let k = BigUint::from_bytes_be(&k_bytes);
    let k_limbs = to_le_u64_limbs(&k);

    let res = match group {
        EcGroup::BN254g1 => {
            let a = bytes_to_bn254_g1(&a_bytes)?;
            let proj: BN254G1 = a.into();
            bn254_g1_to_bytes(&proj.mul_bigint(&k_limbs).into_affine())
        }
        EcGroup::BN254g2 => {
            let a = bytes_to_bn254_g2(&a_bytes)?;
            let proj: BN254G2 = a.into();
            bn254_g2_to_bytes(&proj.mul_bigint(&k_limbs).into_affine())
        }
        EcGroup::BLS12_381g1 => {
            let a = bytes_to_bls12_g1(&a_bytes)?;
            let proj: BLS12G1 = a.into();
            bls12_g1_to_bytes(&proj.mul_bigint(&k_limbs).into_affine())
        }
        EcGroup::BLS12_381g2 => {
            let a = bytes_to_bls12_g2(&a_bytes)?;
            let proj: BLS12G2 = a.into();
            bls12_g2_to_bytes(&proj.mul_bigint(&k_limbs).into_affine())
        }
    };
    machine.push(AvmValue::Bytes(res))
}

// ---------------------------------------------------------------------------
// ec_pairing_check (0xe2)
// ---------------------------------------------------------------------------

/// `ec_pairing_check` (0xe2): pop two byte arrays, push 0 or 1.
/// For BN254g1/BLS12_381g1: stack[prev] = G1 points, stack[last] = G2 points
/// For BN254g2/BLS12_381g2: stack[prev] = G2 points, stack[last] = G1 points (swapped)
pub fn op_ec_pairing_check(
    machine: &mut AvmMachine,
    instruction: &Instruction,
) -> Result<(), AlgoError> {
    let group = get_ec_group(instruction)?;

    // Charge linear cost based on top-of-stack length before popping.
    // Go uses linearCost.compute() with depth=0, i.e. len(stack[last].Bytes).
    // The chunk sizes per group come from the Go opcode table directly.
    // For g1 groups: TOS = "associated" G2 bytes, chunkSize = g1 point size.
    // For g2 groups: TOS = "associated" G1 bytes, chunkSize = g2 point size.
    // This matches go-algorand exactly (see opcodes.go costByFieldAndLength).
    let top_len = match machine.stack.last() {
        Some(AvmValue::Bytes(b)) => b.len(),
        _ => 0,
    };
    let (base, chunk_cost, chunk_size) = match group {
        EcGroup::BN254g1 => (8000u64, 7400u64, BN254_G1_SIZE),
        EcGroup::BN254g2 => (8000, 7400, BN254_G2_SIZE),
        EcGroup::BLS12_381g1 => (13000, 10000, BLS12_G1_SIZE),
        EcGroup::BLS12_381g2 => (13000, 10000, BLS12_G2_SIZE),
    };
    let cost = base + chunk_cost * div_ceil(top_len, chunk_size) as u64;
    machine.charge_cost(cost)?;

    let last_bytes = machine.pop_bytes()?;
    let prev_bytes = machine.pop_bytes()?;

    let ok = match group {
        EcGroup::BN254g1 => bn254_pairing_check(&prev_bytes, &last_bytes)?,
        EcGroup::BN254g2 => bn254_pairing_check(&last_bytes, &prev_bytes)?,
        EcGroup::BLS12_381g1 => bls12_pairing_check(&prev_bytes, &last_bytes)?,
        EcGroup::BLS12_381g2 => bls12_pairing_check(&last_bytes, &prev_bytes)?,
    };

    machine.push(AvmValue::Uint64(u64::from(ok)))
}

fn bn254_pairing_check(g1_bytes: &[u8], g2_bytes: &[u8]) -> Result<bool, AlgoError> {
    let g1 = bytes_to_bn254_g1s(g1_bytes, true)?;
    let g2 = bytes_to_bn254_g2s(g2_bytes, true)?;
    if g1.len() != g2.len() {
        return Err(avm_err(format!(
            "pairing: mismatched point counts: {} g1 vs {} g2",
            g1.len(),
            g2.len()
        )));
    }

    let result = Bn254::multi_pairing(&g1, &g2);
    Ok(result.0.is_one())
}

fn bls12_pairing_check(g1_bytes: &[u8], g2_bytes: &[u8]) -> Result<bool, AlgoError> {
    let g1 = bytes_to_bls12_g1s(g1_bytes, true)?;
    let g2 = bytes_to_bls12_g2s(g2_bytes, true)?;
    if g1.len() != g2.len() {
        return Err(avm_err(format!(
            "pairing: mismatched point counts: {} g1 vs {} g2",
            g1.len(),
            g2.len()
        )));
    }

    let result = Bls12_381::multi_pairing(&g1, &g2);
    Ok(result.0.is_one())
}

// ---------------------------------------------------------------------------
// ec_multi_scalar_mul (0xe3)
// ---------------------------------------------------------------------------

/// `ec_multi_scalar_mul` (0xe3): pop scalars and points, push result.
pub fn op_ec_multi_scalar_mul(
    machine: &mut AvmMachine,
    instruction: &Instruction,
) -> Result<(), AlgoError> {
    let group = get_ec_group(instruction)?;

    // Charge linear cost based on top-of-stack (scalars) length before popping.
    // Go: baseCost + chunkCost * DivCeil(len(top), scalarSize)
    let top_len = match machine.stack.last() {
        Some(AvmValue::Bytes(b)) => b.len(),
        _ => 0,
    };
    let (base, chunk_cost) = match group {
        EcGroup::BN254g1 => (3600u64, 90u64),
        EcGroup::BN254g2 => (7200, 270),
        EcGroup::BLS12_381g1 => (6500, 95),
        EcGroup::BLS12_381g2 => (14850, 485),
    };
    let cost = base + chunk_cost * div_ceil(top_len, SCALAR_SIZE) as u64;
    machine.charge_cost(cost)?;

    let scalar_bytes = machine.pop_bytes()?;
    let point_bytes = machine.pop_bytes()?;

    let res = match group {
        EcGroup::BN254g1 => bn254_g1_multi_mul(&point_bytes, &scalar_bytes)?,
        EcGroup::BN254g2 => bn254_g2_multi_mul(&point_bytes, &scalar_bytes)?,
        EcGroup::BLS12_381g1 => bls12_g1_multi_mul(&point_bytes, &scalar_bytes)?,
        EcGroup::BLS12_381g2 => bls12_g2_multi_mul(&point_bytes, &scalar_bytes)?,
    };
    machine.push(AvmValue::Bytes(res))
}

fn bn254_g1_multi_mul(point_bytes: &[u8], scalar_bytes: &[u8]) -> Result<Vec<u8>, AlgoError> {
    let points = bytes_to_bn254_g1s(point_bytes, false)?;
    if scalar_bytes.len() != SCALAR_SIZE * points.len() {
        return Err(avm_err(format!(
            "bad scalars length {}. Expected {}",
            scalar_bytes.len(),
            SCALAR_SIZE * points.len()
        )));
    }
    let mut sum = BN254G1::zero();
    for (i, pt) in points.iter().enumerate() {
        let k = BigUint::from_bytes_be(&scalar_bytes[i * SCALAR_SIZE..(i + 1) * SCALAR_SIZE]);
        let k_limbs = to_le_u64_limbs(&k);
        let proj: BN254G1 = (*pt).into();
        sum += proj.mul_bigint(&k_limbs);
    }
    Ok(bn254_g1_to_bytes(&sum.into_affine()))
}

fn bn254_g2_multi_mul(point_bytes: &[u8], scalar_bytes: &[u8]) -> Result<Vec<u8>, AlgoError> {
    let points = bytes_to_bn254_g2s(point_bytes, false)?;
    if scalar_bytes.len() != SCALAR_SIZE * points.len() {
        return Err(avm_err(format!(
            "bad scalars length {}. Expected {}",
            scalar_bytes.len(),
            SCALAR_SIZE * points.len()
        )));
    }
    let mut sum = BN254G2::zero();
    for (i, pt) in points.iter().enumerate() {
        let k = BigUint::from_bytes_be(&scalar_bytes[i * SCALAR_SIZE..(i + 1) * SCALAR_SIZE]);
        let k_limbs = to_le_u64_limbs(&k);
        let proj: BN254G2 = (*pt).into();
        sum += proj.mul_bigint(&k_limbs);
    }
    Ok(bn254_g2_to_bytes(&sum.into_affine()))
}

fn bls12_g1_multi_mul(point_bytes: &[u8], scalar_bytes: &[u8]) -> Result<Vec<u8>, AlgoError> {
    let points = bytes_to_bls12_g1s(point_bytes, false)?;
    if scalar_bytes.len() != SCALAR_SIZE * points.len() {
        return Err(avm_err(format!(
            "bad scalars length {}. Expected {}",
            scalar_bytes.len(),
            SCALAR_SIZE * points.len()
        )));
    }
    let mut sum = BLS12G1::zero();
    for (i, pt) in points.iter().enumerate() {
        let k = BigUint::from_bytes_be(&scalar_bytes[i * SCALAR_SIZE..(i + 1) * SCALAR_SIZE]);
        let k_limbs = to_le_u64_limbs(&k);
        let proj: BLS12G1 = (*pt).into();
        sum += proj.mul_bigint(&k_limbs);
    }
    Ok(bls12_g1_to_bytes(&sum.into_affine()))
}

fn bls12_g2_multi_mul(point_bytes: &[u8], scalar_bytes: &[u8]) -> Result<Vec<u8>, AlgoError> {
    let points = bytes_to_bls12_g2s(point_bytes, false)?;
    if scalar_bytes.len() != SCALAR_SIZE * points.len() {
        return Err(avm_err(format!(
            "bad scalars length {}. Expected {}",
            scalar_bytes.len(),
            SCALAR_SIZE * points.len()
        )));
    }
    let mut sum = BLS12G2::zero();
    for (i, pt) in points.iter().enumerate() {
        let k = BigUint::from_bytes_be(&scalar_bytes[i * SCALAR_SIZE..(i + 1) * SCALAR_SIZE]);
        let k_limbs = to_le_u64_limbs(&k);
        let proj: BLS12G2 = (*pt).into();
        sum += proj.mul_bigint(&k_limbs);
    }
    Ok(bls12_g2_to_bytes(&sum.into_affine()))
}

// ---------------------------------------------------------------------------
// ec_subgroup_check (0xe4)
// ---------------------------------------------------------------------------

/// `ec_subgroup_check` (0xe4): pop a point, push 0 or 1.
pub fn op_ec_subgroup_check(
    machine: &mut AvmMachine,
    instruction: &Instruction,
) -> Result<(), AlgoError> {
    let group = get_ec_group(instruction)?;

    // Charge cost per curve group (from go-algorand opcodes.go).
    let cost = match group {
        EcGroup::BN254g1 => 20,
        EcGroup::BN254g2 => 3100,
        EcGroup::BLS12_381g1 => 1850,
        EcGroup::BLS12_381g2 => 2340,
    };
    machine.charge_cost(cost)?;

    let point_bytes = machine.pop_bytes()?;

    let ok = match group {
        EcGroup::BN254g1 => {
            let p = bytes_to_bn254_g1(&point_bytes)?;
            p.is_in_correct_subgroup_assuming_on_curve()
        }
        EcGroup::BN254g2 => {
            let p = bytes_to_bn254_g2(&point_bytes)?;
            p.is_in_correct_subgroup_assuming_on_curve()
        }
        EcGroup::BLS12_381g1 => {
            let p = bytes_to_bls12_g1(&point_bytes)?;
            p.is_in_correct_subgroup_assuming_on_curve()
        }
        EcGroup::BLS12_381g2 => {
            let p = bytes_to_bls12_g2(&point_bytes)?;
            p.is_in_correct_subgroup_assuming_on_curve()
        }
    };

    machine.push(AvmValue::Uint64(u64::from(ok)))
}

// ---------------------------------------------------------------------------
// ec_map_to (0xe5)
// ---------------------------------------------------------------------------

/// `ec_map_to` (0xe5): pop field element bytes, push point on curve.
///
/// Uses the WB (Wahby-Boneh) map for BLS12-381, matching gnark-crypto's
/// implementation. For BN254, uses the SWU map.
/// For G1: input is a single field element.
/// For G2: input is two field elements (representing Fp2).
pub fn op_ec_map_to(machine: &mut AvmMachine, instruction: &Instruction) -> Result<(), AlgoError> {
    let group = get_ec_group(instruction)?;

    // Charge cost per curve group (from go-algorand opcodes.go).
    let cost = match group {
        EcGroup::BN254g1 => 630,
        EcGroup::BN254g2 => 3300,
        EcGroup::BLS12_381g1 => 1950,
        EcGroup::BLS12_381g2 => 8150,
    };
    machine.charge_cost(cost)?;

    let fp_bytes = machine.pop_bytes()?;

    let res = match group {
        EcGroup::BN254g1 => bn254_map_to_g1(&fp_bytes)?,
        EcGroup::BN254g2 => bn254_map_to_g2(&fp_bytes)?,
        EcGroup::BLS12_381g1 => bls12_map_to_g1(&fp_bytes)?,
        EcGroup::BLS12_381g2 => bls12_map_to_g2(&fp_bytes)?,
    };
    machine.push(AvmValue::Bytes(res))
}

/// Map a field element to BLS12-381 G1 using the WB map.
fn bls12_map_to_g1(fp_bytes: &[u8]) -> Result<Vec<u8>, AlgoError> {
    let fp = bytes_to_bls12_field(fp_bytes)?;
    let point = WBMap::<ark_bls12_381::g1::Config>::map_to_curve(fp)
        .map_err(|e| avm_err(format!("map_to_curve: {e}")))?;
    Ok(bls12_g1_to_bytes(&point))
}

/// Map an Fp2 element to BLS12-381 G2 using the WB map.
fn bls12_map_to_g2(fp_bytes: &[u8]) -> Result<Vec<u8>, AlgoError> {
    if fp_bytes.len() != BLS12_FP2_SIZE {
        return Err(avm_err(format!(
            "bad encoded element length: {}",
            fp_bytes.len()
        )));
    }
    let a0 = bytes_to_bls12_field(&fp_bytes[..BLS12_FP_SIZE])?;
    let a1 = bytes_to_bls12_field(&fp_bytes[BLS12_FP_SIZE..])?;
    let fp2 = BLS12Fq2::new(a0, a1);
    let point = WBMap::<ark_bls12_381::g2::Config>::map_to_curve(fp2)
        .map_err(|e| avm_err(format!("map_to_curve: {e}")))?;
    Ok(bls12_g2_to_bytes(&point))
}

/// Map a field element to BN254 G1 using the SWU map.
///
/// BN254 does not have a WB isogeny map in arkworks, so we implement
/// the simplified SWU map matching gnark-crypto's `bn254.MapToG1`.
///
/// gnark-crypto uses the Shallue-van de Woestijne (SVdW) method for BN254.
/// Since arkworks doesn't have a built-in SWU config for BN254, we implement
/// the SVdW map directly.
fn bn254_map_to_g1(fp_bytes: &[u8]) -> Result<Vec<u8>, AlgoError> {
    let u = bytes_to_bn254_field(fp_bytes)?;
    let point = svdw_map_bn254_g1(u)?;
    Ok(bn254_g1_to_bytes(&point))
}

fn bn254_map_to_g2(fp_bytes: &[u8]) -> Result<Vec<u8>, AlgoError> {
    if fp_bytes.len() != BN254_FP2_SIZE {
        return Err(avm_err(format!(
            "bad encoded element length: {}",
            fp_bytes.len()
        )));
    }
    let a0 = bytes_to_bn254_field(&fp_bytes[..BN254_FP_SIZE])?;
    let a1 = bytes_to_bn254_field(&fp_bytes[BN254_FP_SIZE..])?;
    let u = BN254Fq2::new(a0, a1);
    let point = svdw_map_bn254_g2(u)?;
    // gnark-crypto's MapToG2 calls ClearCofactor after MapToCurve2.
    // We use gnark-crypto's endomorphism-based clearing (not simple scalar mul)
    // to produce byte-identical results.
    let cleared = bn254_g2_clear_cofactor(&point);
    Ok(bn254_g2_to_bytes(&cleared))
}

/// Shallue-van de Woestijne (SVdW) map for BN254 G1 (y^2 = x^3 + 3).
///
/// Exactly matches gnark-crypto v0.18.1's `MapToCurve1` in
/// `ecc/bn254/hash_to_g1.go`, following RFC 9380 straightline SVdW.
///
/// Constants are computed at runtime to match gnark-crypto's precomputed values:
///   Z = 1, c1 = g(Z) = 4, c2 = -Z/2, c3 = sqrt(-g(Z)*(3Z²+4A)), c4 = -4g(Z)/(3Z²+4A)
/// with sgn0(c3) == 0 enforced per RFC 9380.
fn svdw_map_bn254_g1(u: BN254Fq) -> Result<BN254G1Affine, AlgoError> {
    use ark_ff::Field;

    // BN254 G1: y^2 = x^3 + b, b = 3, a = 0
    let b = BN254Fq::from(3u64);
    let one = BN254Fq::one();

    // Precomputed constants matching gnark-crypto
    let z = BN254Fq::from(1u64);
    let c1 = z * z * z + b; // g(Z) = 4
    let c2 = -(z * BN254Fq::from(2u64).inverse().unwrap()); // -Z/2
    let three_z_sq = BN254Fq::from(3u64) * z * z;
    let mut c3 = (-(c1 * three_z_sq))
        .sqrt()
        .ok_or_else(|| avm_err("svdw: c3 sqrt failed"))?;
    // RFC 9380: sgn0(c3) MUST equal 0
    if sgn0(c3) != 0 {
        c3 = -c3;
    }
    let c4 = -(BN254Fq::from(4u64) * c1) * three_z_sq.inverse().unwrap();

    //  1. tv1 = u²
    let tv1 = u * u;
    //  2. tv1 = tv1 * c1
    let tv1 = tv1 * c1;
    //  3. tv2 = 1 + tv1
    let tv2 = one + tv1;
    //  4. tv1 = 1 - tv1
    let tv1 = one - tv1;
    //  5. tv3 = tv1 * tv2
    let tv3 = tv1 * tv2;
    //  6. tv3 = inv0(tv3)   [0 if input was 0]
    let tv3 = if tv3.is_zero() {
        BN254Fq::zero()
    } else {
        tv3.inverse().unwrap()
    };
    //  7. tv4 = u * tv1
    let tv4 = u * tv1;
    //  8. tv4 = tv4 * tv3
    let tv4 = tv4 * tv3;
    //  9. tv4 = tv4 * c3
    let tv4 = tv4 * c3;
    // 10. x1 = c2 - tv4
    let x1 = c2 - tv4;
    // 11. gx1 = x1²
    let gx1 = x1 * x1;
    // 12. gx1 = gx1 + A  (A=0)
    // 13. gx1 = gx1 * x1
    let gx1 = gx1 * x1;
    // 14. gx1 = gx1 + B
    let gx1 = gx1 + b;
    // 15. e1 = is_square(gx1)  — Legendre: 0 if square, -1 if not
    let gx1_not_square = legendre_negative(gx1);
    // 16. x2 = c2 + tv4
    let x2 = c2 + tv4;
    // 17. gx2 = x2²
    let gx2 = x2 * x2;
    // 18. gx2 = gx2 + A  (A=0)
    // 19. gx2 = gx2 * x2
    let gx2 = gx2 * x2;
    // 20. gx2 = gx2 + B
    let gx2 = gx2 + b;
    // 21. e2 = is_square(gx2) AND NOT e1
    let gx2_not_square = legendre_negative(gx2);
    let gx1_square_or_gx2_not = gx2_not_square | !gx1_not_square;
    // 22. x3 = tv2²
    let x3 = tv2 * tv2;
    // 23. x3 = x3 * tv3
    let x3 = x3 * tv3;
    // 24. x3 = x3²
    let x3 = x3 * x3;
    // 25. x3 = x3 * c4
    let x3 = x3 * c4;
    // 26. x3 = x3 + Z
    let x3 = x3 + z;
    // 27. x = CMOV(x3, x1, e1)  — select x1 if gx1 is square
    let x = if !gx1_not_square { x1 } else { x3 };
    // 28. x = CMOV(x, x2, e2)   — select x2 if gx2 is square and gx1 is not
    let x = if !gx1_square_or_gx2_not { x2 } else { x };
    // 29. gx = x²
    let gx = x * x;
    // 30. gx = gx + A  (A=0)
    // 31. gx = gx * x
    let gx = gx * x;
    // 32. gx = gx + B
    let gx = gx + b;
    // 33. y = sqrt(gx)
    let y = gx.sqrt().ok_or_else(|| avm_err("svdw: sqrt(gx) failed"))?;
    // 34. e3 = sgn0(u) == sgn0(y)
    let signs_not_equal = sgn0(u) ^ sgn0(y);
    // 35. y = CMOV(-y, y, e3)
    let y = if signs_not_equal != 0 { -y } else { y };
    Ok(BN254G1Affine::new(x, y))
}

/// SVdW map for BN254 G2 (twist curve: y^2 = x^3 + b').
///
/// Exactly matches gnark-crypto v0.18.1's `MapToCurve2` in
/// `ecc/bn254/hash_to_g2.go`. Does NOT include cofactor clearing —
/// the caller (`bn254_map_to_g2`) handles that separately.
fn svdw_map_bn254_g2(u: BN254Fq2) -> Result<BN254G2Affine, AlgoError> {
    use ark_ff::Field;

    // BN254 G2 twist: y^2 = x^3 + b/xi where xi = 9 + i (the twist parameter)
    let xi = BN254Fq2::new(BN254Fq::from(9u64), BN254Fq::from(1u64));
    let b_fq2 = BN254Fq2::new(BN254Fq::from(3u64), BN254Fq::zero());
    let b_twist = b_fq2 * xi.inverse().unwrap();
    let one = BN254Fq2::one();

    // Constants hardcoded from gnark-crypto v0.18.1 hash_to_g2.go.
    // These are the non-Montgomery (canonical) integer values.
    let z = BN254Fq2::new(BN254Fq::from(1u64), BN254Fq::zero());
    let c1 = z * z * z + b_twist; // g(Z)
    let c2 = -(z * BN254Fq2::new(BN254Fq::from(2u64), BN254Fq::zero())
        .inverse()
        .unwrap());
    // c3 and c4 are hardcoded from gnark-crypto to ensure exact sign match
    let c3 = fq2_from_strs(
        "18992192239972082890849143911285057164064277369389217330423471574879236301292",
        "21819008332247140148575583693947636719449476128975323941588917397607662637108",
    );
    let c4 = fq2_from_strs(
        "10499238450719652342378357227399831140106360636427411350395554762472100376473",
        "6940174569119770192419592065569379906172001098655407502803841283667998553941",
    );

    //  1. tv1 = u²
    let tv1 = u * u;
    //  2. tv1 = tv1 * c1
    let tv1 = tv1 * c1;
    //  3. tv2 = 1 + tv1
    let tv2 = one + tv1;
    //  4. tv1 = 1 - tv1
    let tv1 = one - tv1;
    //  5. tv3 = tv1 * tv2
    let tv3 = tv1 * tv2;
    //  6. tv3 = inv0(tv3)
    let tv3 = if tv3.is_zero() {
        BN254Fq2::zero()
    } else {
        tv3.inverse().unwrap()
    };
    //  7. tv4 = u * tv1
    let tv4 = u * tv1;
    //  8. tv4 = tv4 * tv3
    let tv4 = tv4 * tv3;
    //  9. tv4 = tv4 * c3
    let tv4 = tv4 * c3;
    // 10. x1 = c2 - tv4
    let x1 = c2 - tv4;
    // 11-14. gx1 = x1³ + b_twist
    let gx1 = x1 * x1 * x1 + b_twist;
    // 15. e1 = is_square(gx1)
    let gx1_not_square = legendre_negative_fq2(gx1);
    // 16. x2 = c2 + tv4
    let x2 = c2 + tv4;
    // 17-20. gx2 = x2³ + b_twist
    let gx2 = x2 * x2 * x2 + b_twist;
    // 21. e2 = is_square(gx2) AND NOT e1
    let gx2_not_square = legendre_negative_fq2(gx2);
    let gx1_square_or_gx2_not = gx2_not_square | !gx1_not_square;
    // 22. x3 = tv2²
    let x3 = tv2 * tv2;
    // 23. x3 = x3 * tv3
    let x3 = x3 * tv3;
    // 24. x3 = x3²
    let x3 = x3 * x3;
    // 25. x3 = x3 * c4
    let x3 = x3 * c4;
    // 26. x3 = x3 + Z
    let x3 = x3 + z;
    // 27-28. Select x
    let x = if !gx1_not_square { x1 } else { x3 };
    let x = if !gx1_square_or_gx2_not { x2 } else { x };
    // 29-32. gx = x³ + b_twist
    let gx = x * x * x + b_twist;
    // 33. y = sqrt(gx)
    let y = gx
        .sqrt()
        .ok_or_else(|| avm_err("svdw: sqrt(gx) failed for G2"))?;
    // 34-35. Fix sign
    let signs_not_equal = sgn0_fq2(u) ^ sgn0_fq2(y);
    let y = if signs_not_equal != 0 { -y } else { y };
    Ok(BN254G2Affine::new_unchecked(x, y))
}

/// BN254 curve seed (x₀) used in cofactor clearing.
const BN254_SEED: u64 = 4965661367192848881;

/// Frobenius endomorphism on BN254 G2 (the p-power endomorphism on the twist).
/// Maps (x, y) -> (x^p * PSI_X, y^p * PSI_Y)
/// where PSI_X = (u+9)^((p-1)/3) and PSI_Y = (u+9)^((p-1)/2).
fn bn254_g2_psi(p: &BN254G2) -> BN254G2 {
    use ark_ff::Field;
    // Constants from arkworks: TWIST_MUL_BY_Q_X and TWIST_MUL_BY_Q_Y
    let psi_x = BN254Fq2::new(
        BN254Fq::from(
            BigUint::parse_bytes(
                b"21575463638280843010398324269430826099269044274347216827212613867836435027261",
                10,
            )
            .unwrap(),
        ),
        BN254Fq::from(
            BigUint::parse_bytes(
                b"10307601595873709700152284273816112264069230130616436755625194854815875713954",
                10,
            )
            .unwrap(),
        ),
    );
    let psi_y = BN254Fq2::new(
        BN254Fq::from(
            BigUint::parse_bytes(
                b"2821565182194536844548159561693502659359617185244120367078079554186484126554",
                10,
            )
            .unwrap(),
        ),
        BN254Fq::from(
            BigUint::parse_bytes(
                b"3505843767911556378687030309984248845540243509899259641013678093033130930403",
                10,
            )
            .unwrap(),
        ),
    );

    let aff: BN254G2Affine = (*p).into();
    if aff.is_zero() {
        return BN254G2::zero();
    }
    let mut new_x = aff.x;
    new_x.frobenius_map_in_place(1);
    new_x *= psi_x;

    let mut new_y = aff.y;
    new_y.frobenius_map_in_place(1);
    new_y *= psi_y;

    BN254G2Affine::new_unchecked(new_x, new_y).into()
}

/// Cofactor clearing for BN254 G2, matching gnark-crypto's ClearCofactor.
/// Uses the endomorphism-based method from:
///   http://cacr.uwaterloo.ca/techreports/2011/cacr2011-26.pdf, section 6.1
fn bn254_g2_clear_cofactor(q: &BN254G2Affine) -> BN254G2Affine {
    let proj: BN254G2 = (*q).into();

    // points[0] = [x]q  (multiply by seed)
    let p0 = proj.mul_bigint(&[BN254_SEED]);

    // points[1] = psi([3x]q)
    let p1 = {
        let three_x_q = p0 + p0 + p0; // [3x]q
        bn254_g2_psi(&three_x_q)
    };

    // points[2] = psi(psi([x]q))
    let p2 = bn254_g2_psi(&bn254_g2_psi(&p0));

    // points[3] = psi(psi(psi(q)))
    let p3 = bn254_g2_psi(&bn254_g2_psi(&bn254_g2_psi(&proj)));

    // result = p0 + p1 + p2 + p3
    let result: BN254G2 = p0 + p1 + p2 + p3;
    result.into_affine()
}

/// Construct a BN254 Fq2 element from two decimal strings.
fn fq2_from_strs(a0: &str, a1: &str) -> BN254Fq2 {
    let v0 = BigUint::parse_bytes(a0.as_bytes(), 10).unwrap();
    let v1 = BigUint::parse_bytes(a1.as_bytes(), 10).unwrap();
    let f0 = BN254Fq::from(v0);
    let f1 = BN254Fq::from(v1);
    BN254Fq2::new(f0, f1)
}

/// sgn0 for BN254 Fq: returns the parity bit of the non-Montgomery representation.
/// Matches gnark-crypto's `G1Sgn0`: `z.Bits()[0] % 2`.
fn sgn0(x: BN254Fq) -> u64 {
    let repr = x.into_bigint();
    let limbs = repr.as_ref(); // &[u64] in little-endian limb order
    limbs[0] % 2
}

/// sgn0 for BN254 Fq2: matches gnark-crypto's `G2Sgn0` (RFC 9380 for extension fields).
/// sign = sign_0 if c0 != 0, else sign_1
fn sgn0_fq2(x: BN254Fq2) -> u64 {
    let sign_0 = sgn0(x.c0);
    let c0_zero = if x.c0.is_zero() { 1u64 } else { 0u64 };
    let sign_1 = sgn0(x.c1);
    // sign = sign_0 if c0 != 0, else sign_1
    // Using the RFC 9380 formula: sign = sign | (zero & sign_i)
    let mut sign = 0u64;
    let mut zero = 1u64;
    // i=1: c0
    sign |= zero & sign_0;
    zero &= c0_zero;
    // i=2: c1
    sign |= zero & sign_1;
    sign
}

/// Legendre symbol check: returns true if x is NOT a quadratic residue.
/// Matches gnark-crypto's `Legendre() >> 1` which gives 0 for squares, -1 (all bits set) for non-squares.
fn legendre_negative(x: BN254Fq) -> bool {
    use ark_ff::Field;
    // Euler criterion: x^((p-1)/2) = 1 if square, -1 if not, 0 if zero
    // Legendre symbol
    let exp = {
        let mut p_minus_1 = <BN254Fq as PrimeField>::MODULUS;
        p_minus_1.div2();
        p_minus_1
    };
    let result = x.pow(exp.as_ref());
    // result is 0, 1, or p-1 (which is -1)
    result != BN254Fq::zero() && result != BN254Fq::one()
}

/// Legendre symbol check for Fq2: returns true if x is NOT a quadratic residue.
fn legendre_negative_fq2(x: BN254Fq2) -> bool {
    use ark_ff::Field;
    // For Fq2, we check if sqrt exists
    x.sqrt().is_none()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode;
    use crate::context::NullContext;
    use crate::machine::{AvmMachine, AvmValue, ExecMode};
    use crate::ops::helpers::prog;
    use crate::ops::hex_decode;

    /// Helper: step machine through N instructions.
    fn step_n(
        m: &mut AvmMachine,
        ctx: &mut dyn crate::context::AvmContext,
        n: usize,
    ) -> Result<(), AlgoError> {
        for _ in 0..n {
            m.step(ctx)?;
        }
        Ok(())
    }

    // BN254 G1 generator
    fn bn254_g1_generator() -> Vec<u8> {
        let g = BN254G1Affine::generator();
        bn254_g1_to_bytes(&g)
    }

    // BN254 G2 generator
    fn bn254_g2_generator() -> Vec<u8> {
        let g = BN254G2Affine::generator();
        bn254_g2_to_bytes(&g)
    }

    // BLS12-381 G1 generator
    fn bls12_g1_generator() -> Vec<u8> {
        let g = BLS12G1Affine::generator();
        bls12_g1_to_bytes(&g)
    }

    // BLS12-381 G2 generator
    fn bls12_g2_generator() -> Vec<u8> {
        let g = BLS12G2Affine::generator();
        bls12_g2_to_bytes(&g)
    }

    #[test]
    fn test_bn254_g1_roundtrip() {
        let g = BN254G1Affine::generator();
        let bytes = bn254_g1_to_bytes(&g);
        assert_eq!(bytes.len(), BN254_G1_SIZE);
        let decoded = bytes_to_bn254_g1(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_bn254_g2_roundtrip() {
        let g = BN254G2Affine::generator();
        let bytes = bn254_g2_to_bytes(&g);
        assert_eq!(bytes.len(), BN254_G2_SIZE);
        let decoded = bytes_to_bn254_g2(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_bls12_g1_roundtrip() {
        let g = BLS12G1Affine::generator();
        let bytes = bls12_g1_to_bytes(&g);
        assert_eq!(bytes.len(), BLS12_G1_SIZE);
        let decoded = bytes_to_bls12_g1(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_bls12_g2_roundtrip() {
        let g = BLS12G2Affine::generator();
        let bytes = bls12_g2_to_bytes(&g);
        assert_eq!(bytes.len(), BLS12_G2_SIZE);
        let decoded = bytes_to_bls12_g2(&bytes).unwrap();
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_ec_add_bn254_g1() {
        // G + G = 2G
        let g = bn254_g1_generator();
        let expected = {
            let gen = BN254G1Affine::generator();
            let sum: BN254G1Affine = (gen + gen).into_affine();
            bn254_g1_to_bytes(&sum)
        };

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &g);
        code.extend_from_slice(&[0xe0, 0x00]); // ec_add BN254g1

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 3).unwrap();

        assert_eq!(m.stack.len(), 1);
        if let AvmValue::Bytes(result) = &m.stack[0] {
            assert_eq!(result, &expected, "G + G should equal 2G");
        } else {
            panic!("expected bytes on stack");
        }
    }

    #[test]
    fn test_ec_scalar_mul_bn254_g1() {
        // 3 * G
        let g = bn254_g1_generator();
        let scalar = {
            let mut s = vec![0u8; 32];
            s[31] = 3;
            s
        };
        let expected = {
            let gen = BN254G1Affine::generator();
            let three_g: BN254G1Affine = (gen + gen + gen).into_affine();
            bn254_g1_to_bytes(&three_g)
        };

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &scalar);
        code.extend_from_slice(&[0xe1, 0x00]); // ec_scalar_mul BN254g1

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 3).unwrap();

        assert_eq!(m.stack.len(), 1);
        if let AvmValue::Bytes(result) = &m.stack[0] {
            assert_eq!(result, &expected, "3*G should match");
        } else {
            panic!("expected bytes on stack");
        }
    }

    #[test]
    fn test_ec_subgroup_check_bn254_g1() {
        let g = bn254_g1_generator();

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        code.extend_from_slice(&[0xe4, 0x00]); // ec_subgroup_check BN254g1

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 2).unwrap();

        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(1), "generator is in subgroup");
    }

    #[test]
    fn test_ec_add_bn254_g2() {
        let g = bn254_g2_generator();
        let expected = {
            let gen = BN254G2Affine::generator();
            let sum: BN254G2Affine = (gen + gen).into_affine();
            bn254_g2_to_bytes(&sum)
        };

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &g);
        code.extend_from_slice(&[0xe0, 0x01]); // ec_add BN254g2

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 3).unwrap();

        assert_eq!(m.stack.len(), 1);
        if let AvmValue::Bytes(result) = &m.stack[0] {
            assert_eq!(result, &expected);
        } else {
            panic!("expected bytes on stack");
        }
    }

    #[test]
    fn test_ec_multi_scalar_mul_bn254_g1() {
        // 2*G + 3*G = 5*G
        let g = BN254G1Affine::generator();
        let two_points = {
            let mut v = bn254_g1_to_bytes(&g);
            v.extend_from_slice(&bn254_g1_to_bytes(&g));
            v
        };
        let scalars = {
            let mut v = vec![0u8; 32];
            v[31] = 2;
            let mut v2 = vec![0u8; 32];
            v2[31] = 3;
            v.extend_from_slice(&v2);
            v
        };
        let expected = {
            let five_g: BN254G1Affine = (g + g + g + g + g).into_affine();
            bn254_g1_to_bytes(&five_g)
        };

        let mut code = Vec::new();
        push_bytes(&mut code, &two_points);
        push_bytes(&mut code, &scalars);
        code.extend_from_slice(&[0xe3, 0x00]); // ec_multi_scalar_mul BN254g1

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 3).unwrap();

        assert_eq!(m.stack.len(), 1);
        if let AvmValue::Bytes(result) = &m.stack[0] {
            assert_eq!(result, &expected, "2*G + 3*G should equal 5*G");
        } else {
            panic!("expected bytes on stack");
        }
    }

    #[test]
    fn test_ec_add_bls12_g1() {
        let g = bls12_g1_generator();
        let expected = {
            let gen = BLS12G1Affine::generator();
            let sum: BLS12G1Affine = (gen + gen).into_affine();
            bls12_g1_to_bytes(&sum)
        };

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &g);
        code.extend_from_slice(&[0xe0, 0x02]); // ec_add BLS12_381g1

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 3).unwrap();

        assert_eq!(m.stack.len(), 1);
        if let AvmValue::Bytes(result) = &m.stack[0] {
            assert_eq!(result, &expected);
        } else {
            panic!("expected bytes on stack");
        }
    }

    #[test]
    fn test_ec_add_bls12_g2() {
        let g = bls12_g2_generator();
        let expected = {
            let gen = BLS12G2Affine::generator();
            let sum: BLS12G2Affine = (gen + gen).into_affine();
            bls12_g2_to_bytes(&sum)
        };

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &g);
        code.extend_from_slice(&[0xe0, 0x03]); // ec_add BLS12_381g2

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 3).unwrap();

        assert_eq!(m.stack.len(), 1);
        if let AvmValue::Bytes(result) = &m.stack[0] {
            assert_eq!(result, &expected);
        } else {
            panic!("expected bytes on stack");
        }
    }

    #[test]
    fn test_ec_scalar_mul_zero() {
        // 0 * G = identity
        let g = bn254_g1_generator();
        let scalar = vec![0u8; 32];
        let expected = vec![0u8; BN254_G1_SIZE]; // identity is all zeros

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &scalar);
        code.extend_from_slice(&[0xe1, 0x00]);

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 3).unwrap();

        assert_eq!(m.stack.len(), 1);
        if let AvmValue::Bytes(result) = &m.stack[0] {
            assert_eq!(result, &expected, "0*G should be identity");
        } else {
            panic!("expected bytes on stack");
        }
    }

    #[test]
    fn test_ec_add_identity_bn254_g1() {
        // G + 0 = G
        let g = bn254_g1_generator();
        let zero = vec![0u8; BN254_G1_SIZE];

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &zero);
        code.extend_from_slice(&[0xe0, 0x00]);

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 3).unwrap();

        assert_eq!(m.stack.len(), 1);
        if let AvmValue::Bytes(result) = &m.stack[0] {
            assert_eq!(result, &g, "G + 0 should be G");
        } else {
            panic!("expected bytes on stack");
        }
    }

    #[test]
    fn test_ec_bad_length_errors() {
        let bad = vec![0u8; 63];
        assert!(bytes_to_bn254_g1(&bad).is_err());

        let bad2 = vec![0u8; 95];
        assert!(bytes_to_bls12_g1(&bad2).is_err());
    }

    #[test]
    fn test_ec_not_on_curve_errors() {
        // (1, 1) is not on BN254 G1
        let mut bad_point = vec![0u8; BN254_G1_SIZE];
        bad_point[31] = 1; // x = 1
        bad_point[63] = 1; // y = 1
        assert!(bytes_to_bn254_g1(&bad_point).is_err());
    }

    #[test]
    fn test_ec_scalar_mul_too_long_scalar() {
        let g = bn254_g1_generator();
        let scalar = vec![1u8; 33]; // 33 bytes, exceeds 32

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &scalar);
        code.extend_from_slice(&[0xe1, 0x00]);

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        let result = step_n(&mut m, &mut NullContext, 3);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("exceeds 32"), "got: {msg}");
    }

    #[test]
    fn test_ec_pairing_check_bn254_trivial() {
        // Trivial pairing check: e(G1, G2) * e(-G1, G2) = 1
        // This should return true since the product of pairings is identity.
        let g1 = BN254G1Affine::generator();
        let neg_g1: BN254G1Affine = -g1;
        let g2 = BN254G2Affine::generator();

        let mut g1_bytes = bn254_g1_to_bytes(&g1);
        g1_bytes.extend_from_slice(&bn254_g1_to_bytes(&neg_g1));

        let mut g2_bytes = bn254_g2_to_bytes(&g2);
        g2_bytes.extend_from_slice(&bn254_g2_to_bytes(&g2));

        let mut code = Vec::new();
        push_bytes(&mut code, &g1_bytes);
        push_bytes(&mut code, &g2_bytes);
        code.extend_from_slice(&[0xe2, 0x00]); // ec_pairing_check BN254g1

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 3).unwrap();

        assert_eq!(m.stack.len(), 1);
        assert_eq!(
            m.stack[0],
            AvmValue::Uint64(1),
            "e(G1,G2)*e(-G1,G2) should be identity"
        );
    }

    #[test]
    fn test_ec_scalar_mul_bls12_g1() {
        let g = bls12_g1_generator();
        let scalar = {
            let mut s = vec![0u8; 32];
            s[31] = 5;
            s
        };
        let expected = {
            let gen = BLS12G1Affine::generator();
            let five_g: BLS12G1Affine = (gen + gen + gen + gen + gen).into_affine();
            bls12_g1_to_bytes(&five_g)
        };

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &scalar);
        code.extend_from_slice(&[0xe1, 0x02]); // ec_scalar_mul BLS12_381g1

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 3).unwrap();

        assert_eq!(m.stack.len(), 1);
        if let AvmValue::Bytes(result) = &m.stack[0] {
            assert_eq!(result, &expected, "5*G should match");
        } else {
            panic!("expected bytes on stack");
        }
    }

    #[test]
    fn test_ec_subgroup_check_bls12_g1() {
        let g = bls12_g1_generator();

        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        code.extend_from_slice(&[0xe4, 0x02]); // ec_subgroup_check BLS12_381g1

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 700_000);
        step_n(&mut m, &mut NullContext, 2).unwrap();

        assert_eq!(m.stack.len(), 1);
        assert_eq!(m.stack[0], AvmValue::Uint64(1), "generator is in subgroup");
    }

    #[test]
    fn test_bn254_g1_map_to_gnark_vector_27() {
        // Test vector from gnark-crypto v0.18.1: MapToG1(27)
        let input = hex_decode("000000000000000000000000000000000000000000000000000000000000001b");
        let expected = hex_decode(
            "25e1dfaeb54a2c118d2d3dba2a5463c423b9d87ff65d6b455c525bc24bc6aec0\
             041307cf4bb647d5f1aaf90c796e8874b30b9096562b1ec6ad75d57872f9be59",
        );
        let result = bn254_map_to_g1(&input).unwrap();
        assert_eq!(
            result, expected,
            "BN254 G1 MapTo(27) mismatch with gnark-crypto"
        );
    }

    #[test]
    fn test_bn254_g1_map_to_gnark_vector_42() {
        // Test vector from gnark-crypto v0.18.1: MapToG1(42)
        let input = hex_decode("000000000000000000000000000000000000000000000000000000000000002a");
        let expected = hex_decode(
            "0b9ce0a7eb90ea3c2308f9cfdea1c76c7dbb912c28bccf3d50a36497f2bc8542\
             1f45bb52352c9cb30c05b4c0a6e571b10c3c91ba6170bb9858675c3765ed7ee0",
        );
        let result = bn254_map_to_g1(&input).unwrap();
        assert_eq!(
            result, expected,
            "BN254 G1 MapTo(42) mismatch with gnark-crypto"
        );
    }

    #[test]
    fn test_bn254_g1_map_to_gnark_vector_1() {
        // Test vector from gnark-crypto v0.18.1: MapToG1(1)
        let input = hex_decode("0000000000000000000000000000000000000000000000000000000000000001");
        let expected = hex_decode(
            "2b8d79cdcaaca9beddf982188d7d92fd2acc298e53b6ec72d69aab86960a1727\
             16de5b0e1c87130160106734a03a0e2a4a78ed715dba060f06235c2abdb920e5",
        );
        let result = bn254_map_to_g1(&input).unwrap();
        assert_eq!(
            result, expected,
            "BN254 G1 MapTo(1) mismatch with gnark-crypto"
        );
    }

    #[test]
    fn test_bn254_g2_map_to_gnark_vector() {
        // Test vector from gnark-crypto v0.18.1: MapToG2((2783, 0))
        // MapToG2 includes cofactor clearing.
        // Encoded in AVM format (A0||A1 ordering), matching go-algorand's bn254G2ToBytes.
        let input = hex_decode(
            "0000000000000000000000000000000000000000000000000000000000000adf\
             0000000000000000000000000000000000000000000000000000000000000000",
        );
        let expected = hex_decode(
            "1b4445ad7c32d88dc1c0a75a11cf33800d2840e592fbcb9f72740c9db4f6073c\
             2b39f56c6f1c1ddd108e554bd3da9766d1c361648b6645f37766edabd3531a59\
             1d11be07a05fe2bedf9319c19c0dbc7095a4dd59936de66dda87da58ce62f239\
             091fa85e298e5800ab3ecc1a6f12fdee94d0b43cc0d80b0aece86e13ce481984",
        );
        let result = bn254_map_to_g2(&input).unwrap();
        assert_eq!(
            result, expected,
            "BN254 G2 MapTo((2783, 0)) mismatch with gnark-crypto"
        );
    }

    #[test]
    fn test_bn254_g1_map_to_gnark_vector_big() {
        // Test vector from gnark-crypto v0.18.1: MapToG1(123456789012345678901234567890)
        let input = hex_decode("00000000000000000000000000000000000000018ee90ff6c373e0ee4e3f0ad2");
        let expected = hex_decode(
            "106871567f4ccca36251ec478bdc044825e88a281bc0b5390c0c268f27560a00\
             0d1f0a2f95760181e5d31f826af6769b8113c21cba9bc61a55369b0d36e46a48",
        );
        let result = bn254_map_to_g1(&input).unwrap();
        assert_eq!(
            result, expected,
            "BN254 G1 MapTo(big) mismatch with gnark-crypto"
        );
    }

    #[test]
    fn test_ec_identity_roundtrip() {
        // Identity (zero point) should encode as all zeros and decode back
        let zero_bytes = vec![0u8; BN254_G1_SIZE];
        let p = bytes_to_bn254_g1(&zero_bytes).unwrap();
        assert!(p.is_zero());
        let re_encoded = bn254_g1_to_bytes(&p);
        assert_eq!(re_encoded, zero_bytes);
    }

    /// Encode a pushbytes instruction for arbitrary-length data.
    fn push_bytes(code: &mut Vec<u8>, data: &[u8]) {
        code.push(0x80); // pushbytes
        push_varuint(code, data.len() as u64);
        code.extend_from_slice(data);
    }

    /// Encode a varuint (same as TEAL/protobuf varint encoding).
    fn push_varuint(code: &mut Vec<u8>, mut val: u64) {
        loop {
            let mut byte = (val & 0x7f) as u8;
            val >>= 7;
            if val != 0 {
                byte |= 0x80;
            }
            code.push(byte);
            if val == 0 {
                break;
            }
        }
    }

    // -----------------------------------------------------------------------
    // EC cost charging tests
    // -----------------------------------------------------------------------

    /// ec_add BN254g1 costs 125. With a budget of 124, it should fail.
    #[test]
    fn test_ec_add_bn254g1_cost_charged() {
        let g = bn254_g1_generator();
        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &g);
        code.extend_from_slice(&[0xe0, 0x00]); // ec_add BN254g1

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();

        // Budget just below the ec_add BN254g1 cost of 125.
        // The two pushbytes each cost 1, so we need 2 + 125 = 127.
        let mut m = AvmMachine::new(program, ExecMode::Application, 126);
        let result = step_n(&mut m, &mut NullContext, 3);
        assert!(result.is_err(), "should exceed budget");
        assert!(
            result.unwrap_err().to_string().contains("cost budget"),
            "error should mention cost budget"
        );
    }

    /// ec_add BN254g1 costs 125. With a budget of 127 (2 pushbytes + 125), it should succeed.
    #[test]
    fn test_ec_add_bn254g1_cost_sufficient() {
        let g = bn254_g1_generator();
        let mut code = Vec::new();
        push_bytes(&mut code, &g);
        push_bytes(&mut code, &g);
        code.extend_from_slice(&[0xe0, 0x00]); // ec_add BN254g1

        let raw = prog(10, &code);
        let program = bytecode::parse(&raw).unwrap();
        let mut m = AvmMachine::new(program, ExecMode::Application, 127);
        let result = step_n(&mut m, &mut NullContext, 3);
        assert!(
            result.is_ok(),
            "should have enough budget: {:?}",
            result.err()
        );
        assert_eq!(
            m.budget, 0,
            "budget should be exactly exhausted (127 - 2 - 125)"
        );
    }

    /// ec_subgroup_check BN254g1 costs 20, BN254g2 costs 3100.
    #[test]
    fn test_ec_subgroup_check_cost_varies_by_group() {
        // BN254g1 — cost 20
        let g1 = bn254_g1_generator();
        let mut code1 = Vec::new();
        push_bytes(&mut code1, &g1);
        code1.extend_from_slice(&[0xe4, 0x00]); // ec_subgroup_check BN254g1

        let raw1 = prog(10, &code1);
        let program1 = bytecode::parse(&raw1).unwrap();
        let mut m1 = AvmMachine::new(program1, ExecMode::Application, 700_000);
        step_n(&mut m1, &mut NullContext, 2).unwrap();
        // 1 (pushbytes) + 20 (subgroup_check) = 21
        assert_eq!(m1.budget, 700_000 - 21);

        // BN254g2 — cost 3100
        let g2 = bn254_g2_generator();
        let mut code2 = Vec::new();
        push_bytes(&mut code2, &g2);
        code2.extend_from_slice(&[0xe4, 0x01]); // ec_subgroup_check BN254g2

        let raw2 = prog(10, &code2);
        let program2 = bytecode::parse(&raw2).unwrap();
        let mut m2 = AvmMachine::new(program2, ExecMode::Application, 700_000);
        step_n(&mut m2, &mut NullContext, 2).unwrap();
        // 1 (pushbytes) + 3100 (subgroup_check) = 3101
        assert_eq!(m2.budget, 700_000 - 3101);
    }
}
