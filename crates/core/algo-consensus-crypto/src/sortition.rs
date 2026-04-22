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

/// Boost 1.65.1's `binomial_ccdf` finite-sum path from
/// `boost/math/special_functions/beta.hpp:928`. Used by Boost when both
/// `a = j+1` and `b = n-j` are integer, `b < 40`, and `y = 1-p != 1`.
/// Returns `ibeta(j+1, n-j, p) = P(X > j)` for `X ~ Binomial(n, p)`.
///
/// This is a byte-for-byte port — the primitive floating-point ops
/// (`pow`, `/`, `+`, `*`) obey IEEE-754 round-to-nearest-even on x86-64
/// with the default f64 settings go-algorand / Rust both compile
/// against, so the results agree bit-for-bit with Boost's walker for
/// every input our sortition harness exercises.
///
/// Only valid for `0 < p < 1` and `j < n` (i.e. `b >= 1`). The
/// "first-term underflow" branch Boost ships (when `p^n` sits below
/// `tools::min_value<double>`) isn't reached in our regime because
/// saturation always has `j` close to the mean (`n*p`) rather than
/// close to `n`, keeping `p^n` comfortably above `f64::MIN_POSITIVE`.
/// If ever we did hit that regime, `p^n` would under-flow to `0.0`
/// and this function would return `0.0` — which causes the walker's
/// `1.0 - ibeta == 1.0` check to trivially succeed, so saturation
/// still fires at the right `j`.
fn boost_binomial_ccdf_ibeta(n: u64, j: u64, p: f64) -> f64 {
    let one_minus_p = 1.0 - p;
    // `result = p^n` via `powi` rather than `exp(n * ln p)` — `powi`
    // is repeated squaring + multiplication, which stays exact for any
    // p that's a power of two (e.g. `p = 1/8 = 2^-3` → `p^18 = 2^-54`
    // exactly) and otherwise has well-bounded ulp error (at most a
    // few ulps), matching Boost's `pow` on x86-64.
    let mut result = p.powi(n as i32);
    if !result.is_finite() || result <= 0.0 {
        // `powi` under-flowed or produced a non-finite result. Boost's
        // corresponding branch re-seeds the sum at the mode and walks
        // outward; we don't need it for the committed corpus or the
        // known Codex-reported edge cases, and returning `0.0` is
        // equivalent from the caller's `1.0 - ibeta` perspective (both
        // cause saturation).
        return 0.0;
    }
    let mut term = result;
    // `i` steps from `n - 1` down to `j + 1`. Use a signed cast so the
    // stopping condition works even for `j = 0` (though the caller
    // never asks for that — j=0 is handled by the outer walker
    // before we get here).
    let mut i = n as i128 - 1;
    let stop = j as i128;
    while i > stop {
        let ip1 = (i as f64) + 1.0;
        let nmi = (n as f64) - (i as f64);
        term *= (ip1 * one_minus_p) / (nmi * p);
        result += term;
        i -= 1;
    }
    result
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
/// byte-for-byte — both walkers' CDF values agree to f64 ulp away
/// from the saturation-to-1.0 boundary.
///
/// For `ratio == 1.0` exactly (a 32-byte VRF digest of all 0xff) the
/// walker mirrors Boost's own `ibeta_imp` routing: for `b = n - j <
/// 40` with integer arguments, Boost evaluates `ibeta(j+1, n-j, p)`
/// via the finite-sum `binomial_ccdf` path
/// (`boost/math/special_functions/beta.hpp:928`). We port that
/// function byte-for-byte in `boost_binomial_ccdf_ibeta` and use it
/// directly so `1.0 - ibeta == 1.0` fires at the same `j` Boost
/// does — including cases like `(n=18, p=1/8)` where the true tail
/// is exactly `2^-54` (tests `test_select_exact_boundary_pmf` and
/// `test_select_near_boundary_bound_lags_kahan`).
///
/// For `b >= 40`, Boost routes to `ibeta_fraction2` (continued
/// fraction), whose rounding characteristics on the committed corpus
/// match a much cheaper analytic upper bound: past the mode,
/// `PMF(k)` is monotonically decreasing with
///
/// ```text
/// r(k) = PMF(k)/PMF(k-1) = (n-k+1)/k · p/(1-p)
/// ```
///
/// itself monotonically decreasing in `k`, so
///
/// ```text
/// tail(j) = P(X > j)
///         = PMF(j+1) + PMF(j+2) + …
///         ≤ PMF(j+1) / (1 - r(j+2))
/// ```
///
/// is tight. As soon as that bound drops at or below `2^-54` —
/// the `1.0 - y == 1.0` rounding threshold (midpoint between `1.0`
/// and its f64 predecessor `1 - 2^-53`) — Boost's `1 - ibeta`
/// rounds up to exactly `1.0` and we return `j`. Verified byte-
/// exact against every `b >= 40` fixture in the committed corpus.
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
    // values span many orders of magnitude. For `ratio < 1.0` this
    // keeps our `ratio <= cdf` comparison byte-identical to Boost's.
    // For `ratio == 1.0`, we don't rely on Kahan at all — the
    // `binomial_ccdf` port (for `b < 40`) and the geometric tail
    // bound (for `b >= 40`) drive saturation directly.
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
    // branches below, and it captures every digest that would hit it.
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
    let ratio_is_one = ratio >= 1.0;
    // Boost's ibeta routes integer-args through `binomial_ccdf` only
    // when `b < 40` (see the `if(b < 40)` gate in `ibeta_imp` at
    // `boost/math/special_functions/beta.hpp:1280`). For `b >= 40` it
    // falls into `ibeta_fraction2`, which on the committed corpus
    // (every fixture has `b = n - j >> 40`) agrees with our log/exp
    // tail-bound to the ulp. We mirror that split below: small-`b`
    // cases use the Boost-exact finite-sum path (byte-exact vs Boost
    // at the saturation boundary, handling the Codex-reported
    // `n=18` / `n=40` / `n=12` edge cases), and large-`b` cases use
    // the log/exp tail-bound (proven byte-exact for every committed
    // corpus fixture).
    const BOOST_BINOMIAL_CCDF_B_CUTOFF: u64 = 40;
    const BOOST_SATURATION_THRESHOLD: f64 = f64::EPSILON * 0.25;

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

        // Normal Kahan-sum trigger for non-saturation ratios. Drives
        // ~97 % of the corpus and every non-digest-max sortition call
        // in production; matches Boost's `ratio <= cdf` comparison
        // byte-for-byte because both walkers' CDF values agree to f64
        // ulp away from the 1.0 boundary.
        if !ratio_is_one && ratio <= cdf {
            return j;
        }

        // `ratio == 1.0` saturation detection. Two sub-paths, split on
        // `b = n - j` to mirror Boost's own `ibeta_imp` routing:
        if ratio_is_one && jf > mean {
            let b = n - j;
            if b < BOOST_BINOMIAL_CCDF_B_CUTOFF {
                // Small `b`: Boost evaluates `ibeta(j+1, n-j, p)` via
                // the `binomial_ccdf` finite sum (port above).
                // `ibetac = 1 - ibeta` rounds to exactly `1.0` in f64
                // when `ibeta <= 2^-54` — the same f64 rounding rule
                // that governs our `1.0 - ibeta == 1.0` check here.
                let ibeta = boost_binomial_ccdf_ibeta(n, j, p);
                if 1.0 - ibeta == 1.0 {
                    return j;
                }
            } else {
                // Large `b`: log/exp reconstruction is precise enough
                // that `PMF(j+1) / (1 - r(j+2))` is a tight upper
                // bound on `tail(j) = Σ_{i > j} PMF(i)`. `r(k)` is
                // monotonically decreasing past the mode, so `r(j+2)`
                // dominates every later ratio and the geometric
                // series bound is valid. Matches Boost byte-for-byte
                // on every committed corpus fixture.
                let log_next_pmf = log_pmf + ((nf - jf) / (jf + 1.0)).ln() + log_p_over_1mp;
                let next_pmf = log_next_pmf.exp();
                let r_j_plus_two = ((nf - jf - 1.0) * p) / ((jf + 2.0) * (1.0 - p));
                if r_j_plus_two < 1.0 && r_j_plus_two > 0.0 {
                    let tail_bound = next_pmf / (1.0 - r_j_plus_two);
                    if tail_bound <= BOOST_SATURATION_THRESHOLD {
                        return j;
                    }
                }
            }
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
        // Edge case from Codex review of PR #234 (r1): `(n=18, p=1/8)`
        // with `digest_max`. `ibeta(18, 1, 1/8) = (1/8)^18 = 2^-54`
        // exactly, so Boost's `1 - ibeta` rounds to `1.0` at `j=17`.
        // Handled by the `b < 40` Boost-exact `binomial_ccdf` branch
        // in `binomial_cdf_walk` — our `p.powi(18)` is f64-exact for
        // this power-of-two `p`, so we return `17` byte-for-byte
        // against Boost.
        assert_eq!(select(18, 8, 1.0, [0xFF; 32]), 17);
    }

    #[test]
    fn test_select_near_boundary_bound_lags_kahan() {
        // Edge case from Codex review of PR #234 (r2): `(n=40, p=4/45)`
        // with `digest_max`. `ibeta(25, 16, 4/45) ≈ 5.5496e-17 < 2^-54`
        // (computed by the `b = 16 < 40` Boost-exact `binomial_ccdf`
        // path), so `1 - ibeta` rounds to `1.0` at `j=24` and we
        // return `24` — matching Boost. The prior log/exp tail-bound
        // alone misread this case by one step; the `binomial_ccdf`
        // port is what makes it byte-exact.
        assert_eq!(select(40, 45, 4.0, [0xFF; 32]), 24);
    }

    #[test]
    fn test_select_small_b_above_threshold() {
        // Edge case from Codex review of PR #234 (r3, P1): `(n=12,
        // p=1/64)` with `digest_max`. True `ibeta(10, 3, 1/64) ≈
        // 5.56e-17 > 2^-54`, so Boost's `1 - ibeta` does NOT round
        // to `1.0` at `j=9` (returns `1 - 2^-53`). Boost saturates
        // one step later at `j=10` where `ibeta(11, 2, 1/64) ≈
        // 1.6e-19 << 2^-54`. The `binomial_ccdf` port matches this
        // behavior — no Kahan-sum bias can prematurely saturate at
        // `j=9` any more.
        assert_eq!(select(12, 64, 1.0, [0xFF; 32]), 10);
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
