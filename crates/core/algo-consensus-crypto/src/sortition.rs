//! Algorand sortition — cryptographic committee member selection.
//!
//! Implements the `sortition.Select()` function from
//! `github.com/algorand/sortition` (Go / Boost 1.65.1 C++ backend).
//!
//! Given a participant's stake (`money`), the total stake (`total_money`),
//! the expected committee size (`expected_size`), and a 32-byte VRF output,
//! this returns the number of times the participant was selected (their
//! *weight* on the committee).
//!
//! The algorithm has two parts:
//! 1. Convert the 32-byte VRF output to a ratio in \[0, 1\] by interpreting
//!    it as a big-endian 256-bit unsigned integer and dividing by `2^256 - 1`.
//! 2. Walk the binomial CDF `B(n=money, p=expected_size/total_money)` to find
//!    the smallest `j` such that `CDF(j) >= ratio`.

use num_bigint::BigUint;
use statrs::distribution::{Binomial, DiscreteCDF};

/// Convert a 32-byte VRF output to a ratio in \[0, 1\].
///
/// Interprets `vrf_output` as a big-endian unsigned 256-bit integer,
/// divides by `2^256 - 1` (the maximum 256-bit value), and truncates
/// the result to `f64`.
///
/// This matches the Go implementation which uses `big.Float` with
/// 264-bit precision (`8 * (32 + 1)`) and then calls `.Float64()`.
fn vrf_output_to_ratio(vrf_output: [u8; 32]) -> f64 {
    let numerator = BigUint::from_bytes_be(&vrf_output);
    let denominator = BigUint::from_bytes_be(&[0xFF_u8; 32]);

    // Convert BigUint to f64 by accumulating little-endian u32 digits.
    // This gives the same result as Go's `big.Float.Float64()` since f64
    // only has 53 bits of mantissa precision and the accumulation is exact
    // for the significant bits.
    let num_f64 = biguint_to_f64(&numerator);
    let den_f64 = biguint_to_f64(&denominator);
    num_f64 / den_f64
}

/// Convert a `BigUint` to `f64`, accumulating little-endian u32 digits.
fn biguint_to_f64(n: &BigUint) -> f64 {
    let digits = n.to_u32_digits(); // little-endian u32 chunks
    if digits.is_empty() {
        return 0.0;
    }
    let mut result = 0.0_f64;
    let mut base = 1.0_f64;
    for &d in &digits {
        result += d as f64 * base;
        base *= 4_294_967_296.0; // 2^32
    }
    result
}

/// Run the Algorand sortition algorithm.
///
/// Returns the number of sub-committee seats won (the *weight*).
///
/// # Arguments
///
/// * `money` — the participant's stake (in microAlgos).
/// * `total_money` — the total online stake.
/// * `expected_size` — the expected committee size (e.g. 2990 for soft
///   committee, 20 for block proposer selection).
/// * `vrf_output` — the 32-byte VRF hash output (SHA-512/256 of the
///   credential, with address mixed in).
///
/// # Performance
///
/// The `for j in 0..money` loop matches Go's C++ implementation exactly
/// (`sortition_binomial_cdf_walk` in `github.com/algorand/sortition`,
/// using Boost 1.65.1's `boost::math::binomial_distribution`). The loop
/// bound is `money` (raw microAlgos), but it terminates as soon as the
/// binomial CDF exceeds the VRF-derived ratio — which happens at `j`
/// equal to the selected *weight*.
///
/// In practice, the expected weight is `expected_size * money / total_money`.
/// Committee sizes range from 9 (proposers) to 10000 (next-vote), and a
/// single account's stake fraction is small, so the expected weight is
/// typically 0 to ~30. The CDF rises rapidly around the mean, so the
/// loop almost always terminates within a few standard deviations of the
/// expected weight — far below the `money` bound. Go's own benchmark
/// uses `money = 1_000_000` (1 Algo) against `total_money = 1e12` and
/// runs comfortably because `p = 2.5e-9` gives an expected weight of
/// ~0.0025, meaning the loop exits at j=0 for >99.7% of VRF outputs.
///
/// # Panics
///
/// Does not panic. Returns 0 for degenerate inputs (zero money or
/// total money).
pub fn select(money: u64, total_money: u64, expected_size: f64, vrf_output: [u8; 32]) -> u64 {
    if money == 0 || total_money == 0 {
        return 0;
    }

    // Clamp expected_size so p does not exceed 1.0.
    let clamped_expected = if expected_size > total_money as f64 {
        total_money as f64
    } else {
        expected_size
    };

    let p = clamped_expected / total_money as f64;
    let ratio = vrf_output_to_ratio(vrf_output);

    // statrs::Binomial::new(p, n) — p is success probability, n is number of trials.
    let dist = match Binomial::new(p, money) {
        Ok(d) => d,
        Err(_) => return 0,
    };

    // Walk the CDF: find the smallest j where CDF(j) >= ratio.
    for j in 0..money {
        let boundary = dist.cdf(j);
        if ratio <= boundary {
            return j;
        }
    }
    money
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helper -----

    fn make_vrf(first_byte: u8) -> [u8; 32] {
        let mut d = [0u8; 32];
        d[0] = first_byte;
        d
    }

    // ----- VRF-to-ratio unit tests -----

    #[test]
    fn test_vrf_ratio_zero() {
        assert_eq!(vrf_output_to_ratio([0u8; 32]), 0.0);
    }

    #[test]
    fn test_vrf_ratio_max() {
        assert!((vrf_output_to_ratio([0xFF; 32]) - 1.0).abs() < 1e-15);
    }

    #[test]
    fn test_vrf_ratio_half() {
        let ratio = vrf_output_to_ratio(make_vrf(0x80));
        assert!((ratio - 0.5).abs() < 1e-15, "expected 0.5, got {ratio}");
    }

    #[test]
    fn test_vrf_ratio_quarter() {
        let ratio = vrf_output_to_ratio(make_vrf(0x40));
        assert!((ratio - 0.25).abs() < 1e-15, "expected 0.25, got {ratio}");
    }

    #[test]
    fn test_vrf_ratio_three_quarters() {
        let ratio = vrf_output_to_ratio(make_vrf(0xC0));
        assert!((ratio - 0.75).abs() < 1e-15, "expected 0.75, got {ratio}");
    }

    // ----- Go-verified test vectors -----
    //
    // These vectors were generated by running the Go sortition.Select()
    // function (github.com/algorand/sortition v1.0.0) against the same
    // inputs and recording the output weight.

    #[test]
    fn test_select_zeros() {
        assert_eq!(select(1000, 10000, 20.0, [0x00; 32]), 0);
    }

    #[test]
    fn test_select_max() {
        assert_eq!(select(1000, 10000, 20.0, [0xFF; 32]), 22);
    }

    #[test]
    fn test_select_half() {
        assert_eq!(select(1000, 10000, 20.0, make_vrf(0x80)), 2);
    }

    #[test]
    fn test_select_all_half() {
        assert_eq!(select(10000, 10000, 20.0, make_vrf(0x80)), 20);
    }

    #[test]
    fn test_select_all_low() {
        assert_eq!(select(10000, 10000, 20.0, make_vrf(0x10)), 13);
    }

    #[test]
    fn test_select_all_high() {
        assert_eq!(select(10000, 10000, 20.0, make_vrf(0xF0)), 27);
    }

    #[test]
    fn test_select_soft_low() {
        assert_eq!(select(1500, 3000, 2990.0, make_vrf(0x40)), 1494);
    }

    #[test]
    fn test_select_soft_mid() {
        assert_eq!(select(1500, 3000, 2990.0, make_vrf(0x80)), 1495);
    }

    #[test]
    fn test_select_soft_high() {
        assert_eq!(select(1500, 3000, 2990.0, make_vrf(0xC0)), 1497);
    }

    #[test]
    fn test_select_tiny_low() {
        assert_eq!(select(1, 10000, 20.0, make_vrf(0x01)), 0);
    }

    #[test]
    fn test_select_tiny_half() {
        assert_eq!(select(1, 10000, 20.0, make_vrf(0x80)), 0);
    }

    // ----- Edge cases -----

    #[test]
    fn test_select_zero_money() {
        assert_eq!(select(0, 10000, 20.0, make_vrf(0x80)), 0);
    }

    #[test]
    fn test_select_zero_total_money() {
        assert_eq!(select(1000, 0, 20.0, make_vrf(0x80)), 0);
    }

    #[test]
    fn test_select_both_zero() {
        assert_eq!(select(0, 0, 20.0, make_vrf(0x80)), 0);
    }

    #[test]
    fn test_select_expected_exceeds_total() {
        // expected_size > total_money should be clamped (p ≤ 1.0)
        // With p=1.0, every trial succeeds, so weight = money
        let w = select(100, 100, 200.0, make_vrf(0x80));
        // With p=1.0 and ratio=0.5, CDF(j) for binomial(1.0, 100) is
        // 0 for j < 100, and 1.0 for j = 100. So ratio 0.5 > 0 for
        // all j < 100, meaning we return money = 100.
        assert_eq!(w, 100);
    }

    #[test]
    fn test_select_money_equals_one() {
        // money=1, p=0.002, ratio=0.5
        // CDF(0) = (1-p)^1 ≈ 0.998, so 0.5 <= 0.998 → weight=0
        assert_eq!(select(1, 10000, 20.0, make_vrf(0x80)), 0);
    }

    #[test]
    fn test_select_money_equals_one_high_vrf() {
        // money=1, p=0.002, ratio≈0.9375
        // CDF(0) = (1-p)^1 ≈ 0.998, so 0.9375 <= 0.998 → weight=0
        assert_eq!(select(1, 10000, 20.0, make_vrf(0xF0)), 0);
    }

    #[test]
    fn test_select_money_equals_one_nearly_max_vrf() {
        // money=1, p=0.002, ratio≈1.0
        // CDF(0) = 1-p ≈ 0.998
        // ratio = 0xFF..FF / 0xFF..FF = 1.0
        // 1.0 > 0.998, so we don't select j=0, and return money=1
        assert_eq!(select(1, 10000, 20.0, [0xFF; 32]), 1);
    }

    #[test]
    fn test_select_full_stake_zero_vrf() {
        // money == total, expected=20, vrf=0 → ratio=0.0
        // CDF(0) for B(20/10000, 10000) is (1-0.002)^10000 ≈ 2e-9
        // 0.0 <= anything → weight=0
        assert_eq!(select(10000, 10000, 20.0, [0x00; 32]), 0);
    }

    // ----- Statistical sanity check -----

    #[test]
    fn test_select_statistical_average() {
        // Similar to Go's TestSortitionBasic:
        // Run many selections with pseudorandom VRF outputs and check
        // the average weight is close to expected_size * money/total_money.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        const N: u64 = 1000;
        const EXPECTED_SIZE: f64 = 20.0;
        const MY_MONEY: u64 = 100;
        const TOTAL_MONEY: u64 = 200;

        let mut total_weight: u64 = 0;
        for i in 0..N {
            let mut hasher = DefaultHasher::new();
            i.hash(&mut hasher);
            let hash = hasher.finish();

            let mut vrf = [0u8; 32];
            vrf[0..8].copy_from_slice(&hash.to_le_bytes());
            // Fill the rest with a second hash to get more entropy
            (i + 0x12345).hash(&mut hasher);
            let hash2 = hasher.finish();
            vrf[8..16].copy_from_slice(&hash2.to_le_bytes());
            (i + 0x6789A).hash(&mut hasher);
            let hash3 = hasher.finish();
            vrf[16..24].copy_from_slice(&hash3.to_le_bytes());
            (i + 0xBCDEF).hash(&mut hasher);
            let hash4 = hasher.finish();
            vrf[24..32].copy_from_slice(&hash4.to_le_bytes());

            total_weight += select(MY_MONEY, TOTAL_MONEY, EXPECTED_SIZE, vrf);
        }

        // Expected: N * EXPECTED_SIZE * MY_MONEY / TOTAL_MONEY = 1000 * 20 * 0.5 = 10000
        let expected = (N as f64 * EXPECTED_SIZE * MY_MONEY as f64 / TOTAL_MONEY as f64) as u64;
        let diff = total_weight.abs_diff(expected);
        // Allow 5% tolerance
        let max_diff = expected / 20;
        assert!(
            diff <= max_diff,
            "statistical test: expected ~{expected}, got {total_weight}, diff={diff}, max_diff={max_diff}"
        );
    }
}
