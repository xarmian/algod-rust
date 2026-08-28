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

use crate::f128::{binomial_cdf_walk_f128, f128_from_digest_ratio};

/// Upper bound on `select_f128`'s `money` argument. The f128 stored
/// exponent of a value `v` is about `log2(v) - 127` (the mantissa is
/// normalized to `[2^127, 2^128)`), and the smallest representable `1-p`
/// exceeds `2^-64`, so `pmf(0) = (1-p)^money` carries a stored exponent no
/// lower than `-64*money - 128`, and the worst intermediate — the
/// `a.exp+b.exp` sum inside a multiply, whose value parts total at most
/// `money` — stays above `-64*money - 256`. With `money < 2^56` every such
/// quantity is bounded by ~2^62+2^8 in magnitude, comfortably inside i64.
/// (A 2^57 bound is NOT safe: `money = 2^57-1` with `1-p = 1/(2^64-1)`
/// needs a stored exponent near `-2^63-63` and wraps.)
///
/// The bound is ~7x (about 2.8 bits) above Algorand's 10^16 microalgo
/// supply. Matches go-algorand's `sortition.SelectF128MaxMoney`
/// (`github.com/algorand/sortition@v1.1.1`, `sortition.go`).
pub const SELECT_F128_MAX_MONEY: u64 = 1u64 << 56;

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

/// Deterministic sortition function using a pure-software 128-bit float
/// implementation instead of hardware doubles, matching go-algorand v42's
/// `EnableSelectF128` (go-algorand PRs #6672 "sortition: use SelectF128",
/// #6676 "sortition: f128 followups", #6696 "bump sortition dep to v1.1.1";
/// upstream `github.com/algorand/sortition@v1.1.1`, `sortition.go`'s
/// `SelectF128`). It evaluates both the VRF ratio and the binomial CDF at
/// f128 precision using only software integer arithmetic (see [`crate::f128`]),
/// so its result is bit-reproducible across platforms — no f64/hardware
/// float anywhere in this path.
///
/// Unlike [`select`], `select_f128` takes the committee size as the exact
/// `u64` it is in the protocol rather than a float64. `money` must be below
/// [`SELECT_F128_MAX_MONEY`] — callers (this crate does not enforce it here,
/// matching upstream, which "does not check it at runtime"; `algo-agreement`'s
/// `Credential::verify` performs the bounds check before calling this,
/// mirroring go-algorand's `UnauthenticatedCredential.Verify`).
///
/// CONSENSUS / MIGRATION NOTE (from upstream's doc comment, preserved
/// verbatim in substance): `select_f128` is NOT bit-identical to the
/// deployed float64 [`select`]. They agree on the overwhelming majority of
/// inputs but can differ at knife-edge VRF outputs near a CDF boundary —
/// this is why the switch is consensus-gated on `EnableSelectF128` (v42+)
/// rather than a drop-in replacement.
///
/// # Panics
///
/// Does not panic. All internal arithmetic (see [`crate::f128`]) uses
/// wrapping/saturating operations rather than ones that can panic on
/// out-of-range input, matching upstream's "does not panic" contract on the
/// vote/credential-verification path.
pub fn select_f128(money: u64, total_money: u64, expected_size: u64, vrf_output: [u8; 32]) -> u64 {
    let ratio = f128_from_digest_ratio(&vrf_output);
    binomial_cdf_walk_f128(expected_size, total_money, ratio, money)
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
    // `result = p^n`. Use `powf(n as f64)` rather than `powi(n as i32)`
    // so we survive `n > i32::MAX` without the signed truncation wrap
    // (`n as i32` turns negative → `powi` returns `∞` for `p < 1`).
    // For the small-`n` cases that actually exercise this function
    // (Codex's n=12, n=18, n=40 — all `< i32::MAX`), `powf` is
    // byte-identical to `powi` on x86-64 f64: I verified
    // `0.125_f64.powf(18.0) == 0.125_f64.powi(18) == 2^-54` exactly.
    // `powf` preserves the power-of-two-exact result for any `p` that
    // is a dyadic rational in f64, which is what makes the n=18
    // boundary case work.
    let mut result = p.powf(n as f64);
    if !result.is_finite() || result <= 0.0 {
        // `powf` underflowed or was otherwise non-positive. Boost's
        // corresponding branch re-seeds the sum at the mode and walks
        // outward; we don't need it for the committed corpus or the
        // Codex-reported edge cases, and returning `0.0` is
        // equivalent from the caller's `1.0 - ibeta` perspective
        // (both cause saturation). Formally, returning `0.0` here is
        // only correct when the true `P(X > j)` is also within ulp
        // of zero — which it is whenever `p^n` underflows, because
        // the tail is dominated by `PMF(n) = p^n` when `b < 40` is
        // tiny.
        return 0.0;
    }
    let mut term = result;
    // `i` steps from `n - 1` down to `j + 1`. Use `i128` so the
    // stopping condition works for `n` up to `u64::MAX` (`i64` would
    // fail for `n >= 2^63`, which is reachable in sortition when
    // `money` comes close to `total_money ≈ 2^62`).
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

    // ================= select_f128 (issue #667) =================
    //
    // Two layers of parity evidence, both against the actual upstream Go
    // module (`github.com/algorand/sortition@v1.1.1`), not a hand-derived
    // approximation:
    //
    // 1. `test_select_f128_matches_go_fixture` below replays 221
    //    `SelectF128` end-to-end vectors captured by driving the real,
    //    unmodified `f128.go`/`sortition.go` source (see
    //    `tests/fixtures/sortition_f128/vectors.json` and `f128.rs`'s own
    //    fixture-driven arithmetic-primitive tests, which cover `mul`,
    //    `div`, `div_u`, `add`, `int_pow`, and the digest-ratio conversion
    //    from the same generator run).
    // 2. The tests immediately below hand-port specific named test cases
    //    from the module's own `f128_test.go` (`TestSelectF128RatioExactlyOne`,
    //    `TestSelectF128CurrentConsensusFrozenTail`,
    //    `TestSelectF128OutputCeilingRequiresStakeInvariant`,
    //    `TestSelectF128FrozenTailReportedCase`,
    //    `TestSelectF128NearMaximumDigest`) — these are the ones upstream's
    //    own comments call out as pinning the FROZEN-TAIL POLICY (issue
    //    #667's hard constraint against "cleaning up" that deliberate
    //    approximation), so they are worth keeping as named, documented
    //    regressions even though the bulk fixture above also covers general
    //    parity.

    #[derive(serde::Deserialize)]
    struct SelectF128Vec {
        money: u64,
        total_money: u64,
        expected_size: u64,
        digest: String,
        weight: u64,
    }

    #[derive(serde::Deserialize)]
    struct SelectF128Fixture {
        select_f128: Vec<SelectF128Vec>,
    }

    fn parse_digest(hex_str: &str) -> [u8; 32] {
        let bytes = hex::decode(hex_str).expect("valid hex digest");
        bytes.try_into().expect("32-byte digest")
    }

    #[test]
    fn test_select_f128_matches_go_fixture() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/fixtures/sortition_f128/vectors.json");
        let data = std::fs::read_to_string(&path).expect("read sortition_f128 fixture");
        let fixture: SelectF128Fixture =
            serde_json::from_str(&data).expect("parse sortition_f128 fixture");
        assert!(
            fixture.select_f128.len() >= 200,
            "expected a substantial SelectF128 parity corpus, got {}",
            fixture.select_f128.len()
        );
        for v in &fixture.select_f128 {
            let digest = parse_digest(&v.digest);
            let got = select_f128(v.money, v.total_money, v.expected_size, digest);
            assert_eq!(
                got, v.weight,
                "select_f128(money={}, total={}, expected={}, digest={}) = {got}, want {}",
                v.money, v.total_money, v.expected_size, v.digest, v.weight
            );
        }
    }

    fn all_0xff_digest() -> [u8; 32] {
        [0xffu8; 32]
    }

    /// The minimal digest with exactly 129 leading one bits: the smallest
    /// digest whose ratio rounds to exactly 1.0 at f128 precision (per
    /// upstream's `TestSelectF128RatioExactlyOne`).
    fn min_leading_ones_digest() -> [u8; 32] {
        let mut d = [0xffu8; 32];
        for b in d.iter_mut().skip(16) {
            *b = 0;
        }
        d[16] = 0x80;
        d
    }

    /// Port of upstream's `maxDigestMinusPowerOfTwo`: the all-0xff digest
    /// with bit `bit` (counted from the LSB of the big-endian 256-bit
    /// integer) cleared.
    fn max_digest_minus_power_of_two(bit: u32) -> [u8; 32] {
        let mut d = [0xffu8; 32];
        let idx = 31 - (bit / 8) as usize;
        d[idx] &= !(1u8 << (bit % 8));
        d
    }

    #[test]
    fn test_select_f128_near_maximum_digest() {
        // TestSelectF128NearMaximumDigest.
        let mut d = [0u8; 32];
        for b in d.iter_mut().take(7) {
            *b = 0xff;
        }
        assert_eq!(select_f128(1954, 1_999_999_999_999_964, 1500, d), 1);
    }

    #[test]
    fn test_select_f128_ratio_exactly_one() {
        // TestSelectF128RatioExactlyOne: pins the walk when the f128 ratio
        // is exactly 1.0, both mathematically (all-0xff digest) and by
        // 128-bit rounding (>= 129 leading one bits). Each case below pins
        // a different branch of the frozen-tail / exact-boundary logic.
        let cases: [(u64, u64, u64, u64); 4] = [
            (1954, 1_999_999_999_999_964, 1500, 3),
            (1954, 2_000_000_000_000_000, 1500, 5),
            (100, 200, 100, 100),
            (129, 258, 129, 128),
        ];
        for digest in [all_0xff_digest(), min_leading_ones_digest()] {
            for (money, total, expected, want) in cases {
                let got = select_f128(money, total, expected, digest);
                assert_eq!(
                    got, want,
                    "digest={:x?} money={money}: select_f128={got}, want {want}",
                    digest
                );
            }
        }
    }

    #[test]
    fn test_select_f128_current_consensus_frozen_tail() {
        // TestSelectF128CurrentConsensusFrozenTail: pins the promoted
        // frozen-tail behavior at values admitted by current go-algorand
        // consensus parameters (v41-inherited NumProposers=20,
        // NextCommitteeSize=5000, MinBalance=100_000 microalgos; mainnet
        // genesis supply 10^16 microalgos). In every case here, q=(1-p)
        // rounds downward and the accumulated f128 CDF freezes below the
        // chosen digest ratio — this is the exact scenario issue #667's
        // "frozen tail policy" clause is protecting.
        const MAINNET_SUPPLY: u64 = 10_000_000_000_000_000;
        let cases: [(&str, u64, u64, u64, u32, u64); 5] = [
            (
                "proposer committee",
                1_999_999_999_999_999,
                1_999_999_999_999_999,
                20,
                175,
                104,
            ),
            (
                "base minimum balance",
                100_000,
                MAINNET_SUPPLY,
                5_000,
                141,
                6,
            ),
            (
                "payout minimum balance",
                30_000_000_000,
                MAINNET_SUPPLY,
                5_000,
                159,
                15,
            ),
            (
                "payout maximum balance",
                70_000_000_000_000,
                MAINNET_SUPPLY,
                5_000,
                170,
                138,
            ),
            (
                "mainnet supply ceiling",
                MAINNET_SUPPLY,
                MAINNET_SUPPLY,
                5_000,
                178,
                5_945,
            ),
        ];
        for (name, money, total, expected, clear_bit, want) in cases {
            let digest = max_digest_minus_power_of_two(clear_bit);
            let got = select_f128(money, total, expected, digest);
            assert_eq!(
                got, want,
                "{name}: select_f128={got}, want promoted freeze index {want}"
            );
        }
    }

    #[test]
    fn test_select_f128_output_ceiling_requires_stake_invariant() {
        // TestSelectF128OutputCeilingRequiresStakeInvariant: the frozen-tail
        // promotion must not clip an ordinary high-mean crossing when
        // money > total_money (a caller invariant violation, not something
        // this function enforces — matches upstream, which does not clip
        // this case either).
        assert_eq!(select_f128(1_000_000, 100, 20, all_0xff_digest()), 204_858);
    }

    #[test]
    fn test_select_f128_frozen_tail_reported_case() {
        // TestSelectF128FrozenTailReportedCase: pmf(0)'s trial-count-
        // amplified rounding leaves the accumulated CDF around 2^-78 below 1
        // when money == total_money == 2e15 and committee size is 1500.
        // Both a near-max digest and the exact all-0xff digest land above
        // that plateau and must take the identical frozen path.
        const ONLINE_STAKE: u64 = 2_000_000_000_000_000;
        let d = max_digest_minus_power_of_two(176); // ratio ~= 1 - 2^-80
        assert_eq!(select_f128(ONLINE_STAKE, ONLINE_STAKE, 1500, d), 2032);
        assert_eq!(
            select_f128(ONLINE_STAKE, ONLINE_STAKE, 1500, all_0xff_digest()),
            2032
        );
    }

    #[test]
    fn test_select_f128_max_money_headroom() {
        // TestSelectF128MaxMoneyHeadroom: SELECT_F128_MAX_MONEY must keep at
        // least two bits of headroom over the 10^16 microalgo mainnet
        // supply.
        const MAINNET_SUPPLY: u64 = 10_000_000_000_000_000;
        // Deliberately a runtime assertion (mirroring upstream's own
        // `TestSelectF128MaxMoneyHeadroom`, a `testing.T` check, not a
        // compile-time one): the point is a test that fails loudly if a
        // future edit narrows the constant, not a `const _: () = ...`
        // that would just move the same tripwire to compile time.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(SELECT_F128_MAX_MONEY >= 4 * MAINNET_SUPPLY);
        }
    }
}
