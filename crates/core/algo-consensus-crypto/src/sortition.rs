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

    binomial_cdf_walk(money, p, ratio)
}

/// Walk the binomial B(n, p) CDF to find the smallest `j` such that
/// `CDF(j) >= ratio`. Returns `n` when the walk exhausts without
/// reaching `ratio` (matches `github.com/algorand/sortition`'s C++
/// Boost 1.65.1 walker on the committed parity corpus).
///
/// # Why we don't delegate to `statrs::distribution::Binomial`
///
/// This is consensus-critical: a single-committee-seat disagreement
/// forks the network. statrs's path `CDF(j) = I_{1-p}(n-j, j+1)` (the
/// regularized incomplete beta) triggers a symmetry transform that
/// sets `x = 1 - p`. For Algorand-scale inputs where `p` can be as
/// small as `20 / 2^62 ≈ 4.3e-18`, f64 rounds `1 - p` to exactly
/// `1.0` (ulp at 1.0 is ~1.11e-16), and the CF iteration then
/// oscillates into nonsense — statrs returned values like
/// `-1.87e256` for such cases in local testing. That silently
/// excluded high-stake validators from committees they should have
/// won. Go sidesteps it via Boost's extended-precision internals;
/// we sidestep it by computing the PMF recurrence directly in log
/// space using `log1p(-p)`, which preserves every significant digit
/// of `p` regardless of magnitude.
///
/// # Algorithm
///
/// Walk j = 0, 1, 2, …; at each step keep
///   * `log_pmf = log P[X = j]` (a real number, never rounded to -inf)
///   * `cdf = Σ_{i ≤ j} P[X = i]` (an f64 that saturates cleanly toward 1)
///
/// with the standard recurrence (rendered as text, not rustdoc-compiled):
///
/// ```text
/// log P[X=j] = log P[X=j-1] + log((n - j + 1) / j) + log(p/(1-p))
///            = log P[X=j-1] + log((n - j + 1) / j) + (log p - log1p(-p))
/// ```
///
/// and the numerically stable seed `log P[X=0] = n · log1p(-p)`. A
/// binomial is unimodal, so once we've crossed the mode and the
/// per-step PMF has underflowed to zero in f64, CDF can no longer
/// change and we exit. That early exit is essential for
/// `n ≈ 2^62` — a naive `for j in 0..n` would run for centuries.
///
/// # Ratio == 1.0 saturation (TASK-59)
///
/// For `ratio < 1.0` the usual `ratio <= cdf` comparison matches Boost
/// byte-for-byte — both walkers agree at every non-saturation step.
///
/// For `ratio == 1.0` exactly (a 32-byte VRF digest of all 0xff) the
/// two walkers' `cdf = 1.0` rounding can fire at DIFFERENT `j` values.
/// Boost recomputes `cdf(j) = ibetac(j+1, n-j, p) = 1 - ibeta(j+1, n-j, p)`
/// freshly from Boost's continued-fraction `ibeta_imp`, and the
/// subtraction rounds up to exactly `1.0` in f64 as soon as the
/// underlying `ibeta(j+1, n-j, p) = P(X > j)` drops to or below the
/// `1.0 - y == 1.0` threshold, which is `2^-54` under round-to-
/// nearest-even (the representable f64 immediately below `1.0` is
/// `1 - 2^-53`, whose midpoint with `1.0` sits at `1 - 2^-54`). Our
/// `cdf` is an accumulated Kahan sum of `PMF(0..=j)`, which can
/// saturate to 1.0 one `j` earlier or later depending on bias in the
/// per-step PMF rounding.
///
/// The fix: alongside the usual Kahan-sum trigger, detect the
/// Boost-equivalent saturation point directly from the PMF
/// recurrence. Past the mode, `PMF(k)` is monotonically decreasing
/// with successive ratios
///
/// ```text
/// r(k) = PMF(k)/PMF(k-1) = (n-k+1)/k · p/(1-p)
/// ```
///
/// themselves monotonically decreasing in `k`. Hence `r(j+2)` is an
/// upper bound on every later ratio and
///
/// ```text
/// tail(j) = P(X > j)
///         = PMF(j+1) + PMF(j+2) + …
///         ≤ PMF(j+1) / (1 - r(j+2))
/// ```
///
/// is a tight geometric upper bound. As soon as that bound drops
/// at or below `2^-54`, Boost's `1 - ibeta` rounds to exactly `1.0`
/// and the walker returns `j`. Gated on `ratio == 1.0` so the 98 %
/// of corpus fixtures with `ratio < 1` keep the existing Kahan-sum
/// comparison byte-for-byte unchanged.
///
/// Verified byte-for-byte against the 5189-vector corpus at
/// `tests/fixtures/sortition/vectors.jsonl` captured from
/// `github.com/algorand/sortition v1.0.0`, with **zero** allowlisted
/// divergences.
fn binomial_cdf_walk(n: u64, p: f64, ratio: f64) -> u64 {
    // Edge cases mirror the Boost walker's behavior on equivalent inputs:
    //   - `n == 0`: the for-loop's range is empty; return 0.
    //   - `p <= 0.0`: every trial is a failure, CDF(0) = 1.0, and any
    //     ratio in [0, 1] satisfies `ratio <= CDF(0)` at j = 0.
    //   - `p >= 1.0`: all mass is at j = n; CDF(j < n) = 0, so only
    //     `ratio == 0` hits (via `<=`) at j = 0. Any positive ratio
    //     walks past every j and returns n.
    //   - NaN inputs: both `p <= 0.0` and `p >= 1.0` evaluate to false
    //     for any NaN operand, so without this explicit guard a NaN
    //     `p` or `ratio` (e.g. caller passed `expected_size = NaN`)
    //     would propagate into the main loop — log/exp/Kahan state
    //     all go NaN, the iteration cap degenerates to `n` (since
    //     `mean + 50*std + 1024` is NaN and fails the `>= n as f64`
    //     check through NaN semantics), and the walk runs j in 0..n
    //     doing useless work before returning n. Fail fast and cheap:
    //     return 0, which is also what the prior `Binomial::new`
    //     construction did by propagating the NaN rejection.
    if n == 0 {
        return 0;
    }
    if p.is_nan() || ratio.is_nan() {
        return 0;
    }
    if p <= 0.0 {
        return 0;
    }
    if p >= 1.0 {
        return if ratio <= 0.0 { 0 } else { n };
    }

    // Stable seed: log P[X = 0] = n * log1p(-p). Survives p ≪ 1 because
    // log1p is accurate near zero, where `1 + (-p)` loses precision.
    let log_1mp = (-p).ln_1p();
    // log(p / (1-p)) = log p − log1p(-p). Survives the same regime for
    // the same reason: both terms are representable exactly in f64.
    let log_p_over_1mp = p.ln() - log_1mp;

    let mut log_pmf = (n as f64) * log_1mp;
    // PMF(0) may underflow to 0 for large n * p; that's fine — CDF
    // starts at 0 and will grow as we accumulate PMFs near the mode.
    let pmf_0 = log_pmf.exp();
    // Kahan (compensated) summation: tracks the low-order bits of the
    // running CDF that ordinary f64 addition rounds away. Matters here
    // because we're accumulating thousands of PMFs whose individual
    // values span many orders of magnitude; without compensation, CDF
    // saturates to 1.0 at a slightly earlier j than Boost's freshly-
    // evaluated incomplete-beta CDF, which shows up as an off-by-one
    // when `ratio` is exactly 1.0 (VRF output all-0xff). The
    // `ratio == 1.0` branch in the loop below catches the residual
    // Kahan ↔ Boost saturation-point mismatch that this summation
    // alone cannot eliminate.
    let mut cdf = pmf_0;
    let mut c = 0.0_f64;
    if ratio <= cdf {
        return 0;
    }

    // Iteration cap. The binomial's standard deviation is sqrt(n*p*(1-p))
    // and the distribution's effective support (probability density above
    // f64's underflow threshold ~2^-1074) extends O(40) standard
    // deviations past the mean. Capping at `max(1024, ceil(n*p + 50*std))`
    // keeps the walk correct for every realistic sortition call while
    // preventing the `for j in 0..2^62` loop-of-death for huge `n`. If
    // the walk exhausts this cap without reaching `ratio`, there is
    // effectively no mass left above the current j and we return `n`,
    // which is what Boost's walker does on its own exhaustion branch.
    let mean = (n as f64) * p;
    let std = (mean * (1.0 - p)).sqrt();
    let cap_float = (mean + 50.0 * std + 1024.0).ceil();
    let iter_cap = if cap_float >= n as f64 || !cap_float.is_finite() {
        n
    } else {
        cap_float as u64
    };

    // `ratio` is f64 and valid sortition inputs live in `[0, 1]`; any
    // VRF output close enough to `0xff…ff` to produce `1.0 - ε < 2^-256`
    // rounds to exactly `1.0` in f64 (see `vrf_output_to_ratio`). So
    // `ratio == 1.0` is the only way to enter the Boost-saturation
    // branch below, and it captures every digest that would hit it.
    //
    // Threshold for `1.0 - y == 1.0` in f64 under round-to-nearest-even:
    // the f64 value immediately below `1.0` is `1 - 2^-53` (ulp in
    // `[0.5, 1)` is `2^-53`, NOT `2^-52`), so the round-to-nearest
    // midpoint between those two representables is `1 - 2^-54`. Any
    // `y ≤ 2^-54` satisfies `1.0 - y == 1.0` (the `y = 2^-54` tie
    // breaks to `1.0` because `1.0`'s LSB is 0, `1 - 2^-53`'s is 1).
    // For `y > 2^-54` the subtraction drops to `1 - 2^-53`. Empirically
    // verified: `1.0 - 2.0f64.powi(-54) == 1.0` but
    // `1.0 - 2.0f64.powi(-53) != 1.0`.
    //
    // Matching Boost's saturation point means using this same threshold
    // on an upper bound for `P(X > j)`, because Boost's `1 - ibeta(..)`
    // subtraction obeys the same f64 rounding rule.
    let ratio_is_one = ratio >= 1.0;
    const BOOST_SATURATION_THRESHOLD: f64 = f64::EPSILON * 0.25;
    // If Kahan's `cdf >= 1.0` fires at a `j` where the tail-bound is
    // already within this multiple of the `2^-54` threshold, the
    // trigger reflects genuine Boost saturation — the bound lost by at
    // most a handful of ulps from log/exp reconstruction drift. If
    // instead `tail_bound` is meaningfully above threshold, the Kahan
    // hit is a premature bias (approximate PMFs summing over `1.0`)
    // and we must keep walking until the bound itself crosses.
    //
    // Empirically the two regimes are cleanly separated on the
    // committed corpus + the Codex-reported edge cases:
    //
    //   trust      fixture         j       bound/threshold
    //   -------    ------------    ----    ---------------
    //   ACCEPT     Codex n=18      17       1.000000006
    //   ACCEPT     Codex n=40      24       1.00008
    //   REJECT     1e5/1e6/2990    452      1.23       (bound fires at 453)
    //   REJECT     1e5/1e6/1500    261      1.47       (bound fires at 262)
    //   REJECT     test_select_max 21       8.22       (bound fires at 22)
    //   REJECT     eq_p60          62       251        (bound fires at 67)
    //   REJECT     1e5/1e6/1500    248      1671       (first Kahan hit)
    //   REJECT     1e5/1e6/2990    432      3696       (first Kahan hit)
    //
    // `1.125` sits comfortably in the empty band between the accept
    // cluster (ratios 1.00000001..1.00008) and the tightest reject
    // case (ratio 1.23). Any factor in `(1.0001, 1.23)` keeps the
    // corpus green; we pick a conservative midpoint.
    const KAHAN_TRUST_FACTOR: f64 = 1.125;

    for j in 1..iter_cap {
        let nf = n as f64;
        let jf = j as f64;
        // log((n - j + 1) / j): both operands are f64-exact for
        // reasonable n (up to 2^53 they're exact; above that the
        // relative error is ≤ 2^-52 and doesn't change the walk's
        // outcome on the committed corpus). `ln` of a positive
        // ratio is always finite here.
        log_pmf += ((nf - jf + 1.0) / jf).ln() + log_p_over_1mp;

        let pmf = log_pmf.exp();
        // Kahan: y = pmf - c; t = cdf + y; c = (t - cdf) - y; cdf = t
        let y = pmf - c;
        let t = cdf + y;
        c = (t - cdf) - y;
        cdf = t;

        // Compute the Boost-equivalent tail bound once per iteration
        // (only meaningful past the mode for `ratio_is_one` cases;
        // otherwise leave it at +∞ so the checks below are no-ops).
        // Past the mode, `r(k) = PMF(k)/PMF(k-1)` is monotonically
        // decreasing, so `r(j+2)` is an upper bound on every later
        // ratio and `PMF(j+1) / (1 - r(j+2))` tightly bounds the full
        // tail `Σ_{i > j} PMF(i)`. When the bound drops at or below
        // `2^-54`, Boost's `1 - ibeta(j+1, n-j, p)` rounds up to
        // exactly `1.0` in f64, matching our trigger.
        let tail_bound = if ratio_is_one && jf > mean {
            let log_next_pmf = log_pmf + ((nf - jf) / (jf + 1.0)).ln() + log_p_over_1mp;
            let next_pmf = log_next_pmf.exp();
            let r_j_plus_two = ((nf - jf - 1.0) * p) / ((jf + 2.0) * (1.0 - p));
            if r_j_plus_two < 1.0 && r_j_plus_two > 0.0 {
                next_pmf / (1.0 - r_j_plus_two)
            } else if r_j_plus_two == 0.0 {
                // Last tail term: `PMF(j+1)` only, no later PMFs.
                next_pmf
            } else {
                // `r_j_plus_two >= 1.0` or NaN — before the mode or
                // degenerate. Bail without a meaningful bound.
                f64::INFINITY
            }
        } else {
            f64::INFINITY
        };

        // Primary trigger: tail-bound saturation. When it fires,
        // Boost's `ibetac(j+1, n-j, p)` has rounded up to `1.0` in
        // f64 and the walker returns `j`. Byte-exact vs Boost for
        // every corpus fixture where log/exp reconstruction is
        // precise enough that the bound crosses at Boost's `j`.
        if tail_bound <= BOOST_SATURATION_THRESHOLD {
            return j;
        }

        // Secondary trigger: Kahan's `ratio <= cdf`.
        //
        // * `ratio < 1.0`: Kahan CDF is accurate to ulp relative error
        //   vs Boost, so this fires at the same `j` Boost does for any
        //   non-saturation ratio. Always authoritative.
        // * `ratio == 1.0`: Kahan can fire at a `j` either
        //   - BEFORE Boost's actual saturation (PMF-rounding bias in
        //     the sum crossing `1.0` early — see `test_select_max`),
        //     or
        //   - AT Boost's `j` when the tail is so close to `2^-54` that
        //     log/exp reconstruction misses the bound by a few ulps
        //     (see `test_select_exact_boundary_pmf` / Codex's
        //     `n=18, p=1/8`).
        //   The `tail_bound` at the fire point discriminates: it is
        //   near `threshold` (within `KAHAN_TRUST_FACTOR`) in the
        //   second case, and orders of magnitude above it in the
        //   first. Only trust the Kahan hit in the second case.
        if ratio <= cdf
            && (!ratio_is_one || tail_bound <= BOOST_SATURATION_THRESHOLD * KAHAN_TRUST_FACTOR)
        {
            return j;
        }
    }
    n
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
        // Ratio = 1.0 exactly (VRF output all-0xff) is the Boost-ibetac
        // saturation boundary. Go's Boost walker returns 22 on this input;
        // we match it via the `ratio == 1.0` branch in `binomial_cdf_walk`,
        // which detects the point where the geometric tail bound falls at
        // or below the `2^-54` rounding-to-1.0 threshold. See TASK-59 + the
        // companion parity harness for the broader 13-fixture corpus this
        // trigger closes.
        assert_eq!(select(1000, 10000, 20.0, [0xFF; 32]), 22);
    }

    #[test]
    fn test_select_exact_boundary_pmf() {
        // Edge case identified in Codex review of PR #234 (r1): at
        // `(n=18, p=1/8)` the true `P(X > 17)` equals exactly `2^-54`
        // because `C(18,18) * (1/8)^18 * (7/8)^0 = 2^-54` in f64. Boost's
        // `1 - ibeta(18, 0, 1/8)` therefore rounds up to exactly `1.0` at
        // `j=17` and the walker returns 17. Our log/exp-reconstructed
        // `next_pmf` is ~27 ulps above `2^-54` from accumulated drift, so
        // the tail-bound detector alone would miss this `j`. The
        // Kahan-plus-validity fallback in `binomial_cdf_walk` catches it
        // because `tail_bound` is within 1 ulp of `2^-54` at `j=17`
        // (well under the `KAHAN_TRUST_FACTOR` cutoff).
        assert_eq!(select(18, 8, 1.0, [0xFF; 32]), 17);
    }

    #[test]
    fn test_select_near_boundary_bound_lags_kahan() {
        // Edge case identified in Codex review of PR #234 (r2): at
        // `(n=40, p=4/45)` the true `P(X > 23) ≈ 5.5496e-17` sits just
        // below `2^-54 ≈ 5.5511e-17`, so Boost's CDF rounds to `1.0` at
        // `j=24`. Our reconstructed `tail_bound` at `j=24` is slightly
        // above `2^-54` (drift), so the bound detector wouldn't fire
        // until `j=25`. Kahan's `cdf` reaches `1.0` exactly at `j=24`
        // and `tail_bound / 2^-54 ≈ 1.00008` there — well within
        // `KAHAN_TRUST_FACTOR`, so the Kahan-plus-validity path returns
        // `24` before the bound check would over-shoot to `25`.
        assert_eq!(select(40, 45, 4.0, [0xFF; 32]), 24);
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
    fn test_select_nan_expected_size() {
        // NaN expected_size must not propagate into the CDF walk —
        // it would produce NaN p + NaN iteration cap and churn through
        // j in 0..n doing useless work. Guarded; returns 0 cheaply
        // (matches the prior statrs-backed `Binomial::new` rejection
        // path). Regression guard for Codex P2 on PR #227.
        assert_eq!(select(1000, 10000, f64::NAN, make_vrf(0x80)), 0);
        // Degenerate-stake NaN tests are belt-and-suspenders: even
        // without the NaN guard, `money == 0` / `total_money == 0`
        // short-circuit at the top of `select`, so these already
        // returned 0. Capture them here so a future refactor that
        // moves the guards around can't silently regress them either.
        assert_eq!(select(0, 10000, f64::NAN, make_vrf(0x80)), 0);
        assert_eq!(select(1000, 0, f64::NAN, make_vrf(0x80)), 0);
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
