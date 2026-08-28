//! Big-transaction size pricing: `feeFactor`/`FeeContribution`/`feeContribution`
//! and the `FeeForUsage` residue-tracking fee-rounding primitive.
//!
//! Mirrors go-algorand v5.0.0-stable:
//! - `data/basics/units.go` (`Micros.MulInt`)
//! - `data/basics/overflow.go` (`MicroAlgos.FeeForUsage`, PR #6650)
//! - `data/transactions/transaction.go` (`Transaction.feeFactor`, `Header.FeeContribution`)
//! - `data/transactions/application.go` (`LargeProgramExtraBytes`, `ApplicationCallTxnFields.feeContribution`)
//! - `data/transactions/signedtxn.go` (`SignedTxn.FeeFactor`, `logicSigProgramFeeContribution`, `SummarizeFees`)
//!
//! All "Micros" values here (`usage`, `feeFactor`, fee contributions) are
//! fixed-point integers with 6 digits of precision, exactly like go-algorand's
//! `basics.Micros`: `1_000_000` represents one whole unit (one `MinTxnFee`).
//!
//! # Scope
//!
//! This module implements the `FeeForUsage`/fee-contribution *primitives* and
//! the outer/top-level transaction-group fee check. Threading `FeeForUsage`'s
//! residue through `EvalParams`/`opItxnSubmit`/inner-transaction evaluation
//! (go: `ledger/eval` and `data/transactions/logic/eval.go`'s `feeResidue`) is
//! out of scope here — see the companion AVM inner-txn fee-residue-threading
//! issue. Likewise, the post-quantum-signature fee contribution
//! (`proto.PQSchemeFeeContribution`) is not yet modeled in `algo-types`, so
//! `txn_fee_factor` treats it as zero/absent — see the companion PQ-signature
//! issue.

use algo_types::consensus::ConsensusParams;
use algo_types::{SignedTransaction, Transaction};

/// The denominator of a fee residue: residues are fractional microAlgos held
/// to 1e-12 precision, so they always live in `[0, FEE_RESIDUE_SCALE)`.
/// Mirrors go's `basics.feeResidueScale` (`data/basics/overflow.go`).
pub const FEE_RESIDUE_SCALE: u128 = 1_000_000_000_000;

/// One whole "Micros" unit (fixed-point 1e6 scale). A `feeFactor`/`usage` of
/// this value represents exactly one `MinTxnFee`.
pub const ONE_MICROS: u64 = 1_000_000;

/// Mirrors go's `basics.Micros.MulInt(i int) (Micros, bool)`
/// (`data/basics/units.go`): multiplies a `Micros` fixed-point value `m` by a
/// plain integer `i` (not another `Micros` value, so no division by 1e6).
/// A negative `i` clamps the result to zero (and reports overflow, matching
/// Go's `return 0, true`) rather than going negative — this is what lets
/// callers write `surcharge, _ := proto.PerByteTxnSurcharge.MulInt(len(x) - cap)`
/// without a separate `max(0, ...)` guard: bytes under the free cap simply
/// contribute a zero surcharge.
pub fn micros_mul_int(m: u64, i: i64) -> (u64, bool) {
    if i < 0 {
        return (0, true);
    }
    match m.checked_mul(i as u64) {
        Some(v) => (v, false),
        None => (u64::MAX, true),
    }
}

/// Widening 64x64->128 multiply, split into (hi, lo) 64-bit halves. Mirrors
/// go's `bits.Mul64`. Always exact: the true 128-bit product of two u64
/// values never exceeds `u128::MAX`.
fn mul64(a: u64, b: u64) -> (u64, u64) {
    let full = (a as u128) * (b as u128);
    ((full >> 64) as u64, full as u64)
}

/// Mirrors go's `basics.Mul2div(a, b, c, d) (quotient, remainder, overflow)`
/// (`data/basics/overflow.go`): computes `a*b*c/d` and `a*b*c%d`.
///
/// The three-factor product `a*b*c` can need up to 192 bits (three u64
/// factors), which does **not** always fit in a `u128`: naively computing
/// `(a as u128) * (b as u128) * (c as u128)` overflows `u128` (and panics in
/// debug builds / silently wraps in release) whenever all three factors are
/// large -- e.g. `a == b == c == u64::MAX` -- which would corrupt the fee
/// arithmetic below with a wrong, too-small result. So this mirrors go's own
/// carry-safe construction (`bits.Mul64`/`bits.Div64`, three widening
/// 64x64->128 multiplies combined via carries) instead, using `u128` in place
/// of go's `uint64` at each step (Rust's native 128-bit widening multiply
/// exactly plays the role `bits.Mul64` plays in go): this catches genuine
/// overflow (the product needs more than ~192 bits of quotient, or the
/// quotient itself does not fit in a u64) at the same boundary go does,
/// without ever overflowing an intermediate.
fn mul2div_u64(a: u64, b: u64, c: u64, d: u128) -> (u64, u128, bool) {
    let (x, y) = mul64(a, b); // a*b == x*2^64 + y, exact
    let (j, k) = mul64(y, c); // y*c == j*2^64 + k, exact
    let (l, m) = mul64(x, c); // x*c == l*2^64 + m, exact
    if l > 0 {
        // a*b*c needs more than ~192 bits' worth of quotient room: no
        // divisor gets this back down to a single u64 "digit".
        return (u64::MAX, 0, true);
    }
    // j_plus_m is the high 64 bits of (a*b*c) once combined with k as the
    // low 64 bits, saturated to u64 exactly like go's `AddSaturate(J, M)`.
    let j_plus_m_wide = (j as u128) + (m as u128);
    let j_plus_m = if j_plus_m_wide > u64::MAX as u128 {
        u64::MAX
    } else {
        j_plus_m_wide as u64
    };
    if d <= j_plus_m as u128 {
        // Even ignoring the low 64 bits (k), the quotient already needs more
        // than a u64 can hold.
        return (u64::MAX, 0, true);
    }
    // The exact 128-bit value (j_plus_m : k), safely representable in u128.
    let numerator = ((j_plus_m as u128) << 64) | (k as u128);
    let quo = numerator / d;
    let rem = numerator % d;
    if quo > u64::MAX as u128 {
        (u64::MAX, rem, true)
    } else {
        (quo as u64, rem, false)
    }
}

/// Mirrors go's `MicroAlgos.FeeForUsage(usage, multiplier Micros, residue uint64)
/// (fee MicroAlgos, newResidue uint64, overflow bool)` (`data/basics/overflow.go`,
/// PR #6650 "Fees: Handle rounding of fees with non-integral usage better").
///
/// Returns the fee to charge for `usage` (a `Micros`-scaled multiple of `base`)
/// further scaled by `multiplier` (another `Micros` value, e.g. an AVM cost
/// multiplier), given the running `residue` (fractional microAlgos, scaled by
/// [`FEE_RESIDUE_SCALE`], already paid by earlier round-ups). It rounds up only
/// when the residue cannot absorb the fraction, so a sequence of (possibly
/// nested) fee charges rounds up just once in aggregate rather than once per
/// charge. Saturates and reports overflow on genuine overflow of the fee
/// itself; the residue is left unchanged when the fee overflows.
pub fn fee_for_usage(base: u64, usage: u64, multiplier: u64, residue: u64) -> (u64, u64, bool) {
    let (quo, rem, overflowed) = mul2div_u64(base, usage, multiplier, FEE_RESIDUE_SCALE);
    if overflowed {
        return (u64::MAX, residue, true);
    }
    let residue = residue as u128;
    // A round-up that would carry quo past u64::MAX is itself an overflow.
    if quo == u64::MAX && rem > residue {
        return (quo, residue as u64, true);
    }
    if rem == 0 {
        return (quo, residue as u64, false); // exact; residue untouched
    }
    if rem <= residue {
        return (quo, (residue - rem) as u64, false); // prior round-up already paid for this fraction
    }
    // Must round up. The overpayment becomes the residue available to later charges.
    (quo + 1, (FEE_RESIDUE_SCALE - (rem - residue)) as u64, false)
}

/// The hard cap on `Note` byte length used by well-formedness checks. Mirrors
/// the *effective* value of go's `MaxAbsoluteTxnNoteBytes`: go's
/// `checkSetMax(p.MaxAbsoluteTxnNoteBytes, &bounds.MaxTxnNoteBytes)`
/// (`config/consensus.go`) clamps the absolute cap to at least the free/soft
/// cap (`MaxTxnNoteBytes`) at config-load time for every protocol version, so
/// upstream's `WellFormed` check (`len(tx.Note) > proto.MaxAbsoluteTxnNoteBytes`)
/// is unconditional and always at least as strict as the old soft cap.
/// `ConsensusParams::max_absolute_txn_note_bytes` is left `0` ("unset") for
/// protocol versions at/before v41 (matching how the field was introduced in
/// `algo-types`), so this falls back to the soft cap in that case, exactly
/// reproducing `checkSetMax`'s effect without hand-copying `1_024` into every
/// pre-v42 version definition.
pub fn effective_max_note_bytes(params: &ConsensusParams) -> usize {
    if params.max_absolute_txn_note_bytes > 0 {
        params.max_absolute_txn_note_bytes
    } else {
        params.max_txn_note_bytes
    }
}

/// The hard cap on the summed length of `ApplicationArgs` used by
/// well-formedness checks. Mirrors the *effective* value of go's
/// `MaxAbsoluteTotalArgLen`, analogous to [`effective_max_note_bytes`]: go's
/// `checkSetMax(p.MaxAbsoluteTotalArgLen, &bounds.MaxAppTotalArgLen)` clamps it
/// to at least the free/soft cap (`MaxAppTotalArgLen`) at config-load time, so
/// this falls back to the soft cap for protocol versions where
/// `max_absolute_total_arg_len` is left `0` ("unset", at/before v41).
pub fn effective_max_total_arg_len(params: &ConsensusParams) -> usize {
    if params.max_absolute_total_arg_len > 0 {
        params.max_absolute_total_arg_len
    } else {
        params.max_app_total_arg_len
    }
}

/// Mirrors go's `Header.FeeContribution(proto)` (`data/transactions/transaction.go`):
/// the fee-factor surcharge (in `Micros`) for `Note` bytes beyond the old
/// free/soft cap (`MaxTxnNoteBytes`), saturating.
pub fn header_fee_contribution(note_len: usize, params: &ConsensusParams) -> u64 {
    let over = note_len as i64 - params.max_txn_note_bytes as i64;
    let (surcharge, _) = micros_mul_int(params.per_byte_txn_surcharge, over);
    surcharge
}

/// Mirrors go's `LargeProgramExtraBytes(proto, totalProgramSize)`
/// (`data/transactions/application.go`): the number of app-program bytes by
/// which `totalProgramSize` exceeds the free size available without paying
/// extra, i.e. `max(0, totalProgramSize - MaxAppTotalProgramLen*(1+MaxExtraAppProgramPages))`.
pub fn large_program_extra_bytes(params: &ConsensusParams, total_program_size: usize) -> usize {
    let basic_limit =
        params.max_app_total_program_len * (1 + params.max_extra_app_program_pages as usize);
    total_program_size.saturating_sub(basic_limit)
}

/// Mirrors go's `ApplicationCallTxnFields.feeContribution(proto)`
/// (`data/transactions/application.go`): the fee-factor surcharge (in
/// `Micros`) for app-program bytes beyond [`large_program_extra_bytes`]'s free
/// allowance, plus app-arg bytes beyond the old free/soft cap
/// (`MaxAppTotalArgLen`), saturating.
pub fn app_call_fee_contribution(
    params: &ConsensusParams,
    approval_len: usize,
    clear_len: usize,
    total_arg_bytes: usize,
) -> u64 {
    let total_program_bytes = approval_len + clear_len;
    let (program_surcharge, _) = micros_mul_int(
        params.per_byte_txn_surcharge,
        large_program_extra_bytes(params, total_program_bytes) as i64,
    );

    let over_args = total_arg_bytes as i64 - params.max_app_total_arg_len as i64;
    let (arg_surcharge, _) = micros_mul_int(params.per_byte_txn_surcharge, over_args);

    program_surcharge.saturating_add(arg_surcharge)
}

/// Sums the byte lengths of a transaction's `ApplicationArgs`.
fn total_arg_bytes(txn: &Transaction) -> usize {
    txn.app_arguments
        .as_ref()
        .map(|args| {
            args.iter()
                .map(|a| a.as_ref().map(|b| b.len()).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0)
}

/// Mirrors go's `Transaction.feeFactor(proto)` (`data/transactions/transaction.go`,
/// unexported upstream because callers should use `SignedTxn.FeeFactor`, which
/// adds any signature-scheme surcharge on top — see [`summarize_fees`]).
///
/// Returns the transaction's base-fee multiplier in `Micros`: `1_000_000` for
/// an ordinary transaction, more for one that uses billable oversized
/// features, `0` for a state-proof transaction, and reduced by one `MinTxnFee`
/// for a heartbeat that claims (and, syntactically, is entitled to claim) the
/// challenge fee discount.
///
/// # Heartbeat discount
///
/// Mirrors go's `Transaction.feeFactor` (`data/transactions/transaction.go`):
/// once transaction-size pricing is enabled
/// (`ConsensusParams::txn_size_pricing_enabled`, v42+), the discount is
/// claimed explicitly via `HeartbeatTxnFields::hb_challenge_discount` — grouping
/// no longer matters. Before that, the discount is inferred from "is this an
/// ungrouped (singleton) heartbeat", unconditionally (not from whether the fee
/// paid is actually low — that inference lives in well-formedness/apply, which
/// use this same discount to decide the required fee and then compare it
/// against the fee actually paid).
///
/// Either way, this only computes the *required* fee assuming the discount
/// claim is syntactically valid; verifying the claiming account is actually
/// under challenge happens at apply time
/// (`algo_ledger::apply::apply_heartbeat`), not here.
pub fn txn_fee_factor(txn: &Transaction, params: &ConsensusParams) -> u64 {
    if txn.txn_type == "stpf" {
        return 0;
    }

    let mut factor = ONE_MICROS.saturating_add(header_fee_contribution(txn.note.len(), params));

    if txn.txn_type == "appl" {
        let approval_len = txn.approval_program.as_ref().map(|p| p.len()).unwrap_or(0);
        let clear_len = txn
            .clear_state_program
            .as_ref()
            .map(|p| p.len())
            .unwrap_or(0);
        factor = factor.saturating_add(app_call_fee_contribution(
            params,
            approval_len,
            clear_len,
            total_arg_bytes(txn),
        ));
    } else if txn.txn_type == "hb" {
        let discounted = if params.txn_size_pricing_enabled() {
            // Post-v42: the discount is claimed explicitly, regardless of
            // grouping.
            txn.heartbeat
                .as_ref()
                .is_some_and(|hb| hb.hb_challenge_discount)
        } else {
            // Pre-v42: any ungrouped (singleton) heartbeat is discounted,
            // unconditionally (matches go's `isSingletonHeartbeat`).
            txn.group == [0u8; 32]
        };
        if discounted {
            factor = factor.saturating_sub(ONE_MICROS);
        }
    }

    factor
}

/// Mirrors go's `logicSigProgramFeeContribution(txgroup, proto)`
/// (`data/transactions/signedtxn.go`): the group-pooled fee-factor surcharge
/// (in `Micros`) for LogicSig program bytes beyond the group's free allowance
/// (`len(txgroup) * LogicSigMaxSize` bytes, pooled across the whole group).
/// LogicSig *args* are intentionally excluded, matching upstream.
pub fn logic_sig_program_fee_contribution(
    group: &[&SignedTransaction],
    params: &ConsensusParams,
) -> u64 {
    let program_bytes: usize = group
        .iter()
        .map(|stx| stx.lsig.as_ref().map(|l| l.logic.len()).unwrap_or(0))
        .sum();
    let free_program_bytes = group.len() * params.logic_sig_max_size as usize;
    let (surcharge, _) = micros_mul_int(
        params.per_byte_txn_surcharge,
        program_bytes as i64 - free_program_bytes as i64,
    );
    surcharge
}

/// Mirrors go's `SummarizeFees(txgroup, proto) (usage basics.Micros, paid
/// basics.MicroAlgos)` (`data/transactions/signedtxn.go`): sums each member's
/// `feeFactor` (`Micros` usage) and actual paid fee (`MicroAlgos`) across the
/// group, plus the group's pooled LogicSig program-byte surcharge.
///
/// Note: go's `SignedTxn.FeeFactor` also adds a post-quantum-signature
/// contribution (`signatureFeeContribution`) on top of `Transaction.feeFactor`;
/// that is not yet modeled here (see the module doc comment), so this treats
/// it as zero, matching non-PQ-signed transactions exactly.
pub fn summarize_fees(group: &[&SignedTransaction], params: &ConsensusParams) -> (u64, u64) {
    let mut usage: u64 = 0;
    let mut paid: u64 = 0;
    for stx in group {
        usage = usage.saturating_add(txn_fee_factor(&stx.txn, params));
        paid = paid.saturating_add(stx.txn.fee);
    }
    usage = usage.saturating_add(logic_sig_program_fee_contribution(group, params));
    (usage, paid)
}

/// The fee (in microAlgos) required for a given `usage` (in `Micros`, as
/// returned by [`summarize_fees`] or [`txn_fee_factor`]) at the protocol's
/// minimum fee. Mirrors go's `minFee.FeeForUsage(usage, 1e6, 0)` call sites
/// (e.g. `ledger/eval.CheckGroupFees`, `data/txntest/txn.go`): no cost
/// multiplier and no prior residue, since this is always the top-level
/// group's charge.
pub fn required_fee_for_usage(usage: u64, params: &ConsensusParams) -> (u64, bool) {
    let (fee, _residue, overflow) = fee_for_usage(params.min_txn_fee, usage, ONE_MICROS, 0);
    (fee, overflow)
}

/// The fee (in microAlgos) required for a single transaction on its own
/// (an ungrouped group of size one), i.e. `required_fee_for_usage(txn_fee_factor(txn, params), params)`.
pub fn required_fee_for_txn(txn: &Transaction, params: &ConsensusParams) -> (u64, bool) {
    required_fee_for_usage(txn_fee_factor(txn, params), params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V41, CONSENSUS_V42};

    // ── micros_mul_int ──────────────────────────────────────────

    #[test]
    fn mul_int_negative_clamps_to_zero() {
        let (v, overflow) = micros_mul_int(100, -5);
        assert_eq!(v, 0);
        assert!(overflow);
    }

    #[test]
    fn mul_int_zero_is_zero() {
        let (v, overflow) = micros_mul_int(100, 0);
        assert_eq!(v, 0);
        assert!(!overflow);
    }

    #[test]
    fn mul_int_positive_multiplies() {
        let (v, overflow) = micros_mul_int(100, 4096);
        assert_eq!(v, 409_600);
        assert!(!overflow);
    }

    #[test]
    fn mul_int_saturates_on_overflow() {
        let (v, overflow) = micros_mul_int(u64::MAX, 2);
        assert_eq!(v, u64::MAX);
        assert!(overflow);
    }

    // ── fee_for_usage ────────────────────────────────────────────
    // Ported directly from go's TestFeeForUsage (data/basics/units_test.go).

    #[test]
    fn fee_for_usage_no_residue_is_ceiling() {
        let min_fee = 1000u64;
        // usage = 1e6 + 1000 (i.e. 0.1% over one min fee): exact multiple of
        // min_fee (1000 * (1e6+1000)/1e6 = 1001), no rounding needed.
        let (fee, residue, overflow) = fee_for_usage(min_fee, 1_000_000 + 1000, 1_000_000, 0);
        assert!(!overflow);
        assert_eq!(fee, 1001);
        assert_eq!(residue, 0);
    }

    #[test]
    fn fee_for_usage_rounds_up_and_returns_residue() {
        let min_fee = 1000u64;
        let (fee, residue, overflow) = fee_for_usage(min_fee, 1_000_000 + 1001, 1_000_000, 0);
        assert!(!overflow);
        assert_eq!(fee, 1002); // rounded up from 1001.001
        assert_eq!(residue, (FEE_RESIDUE_SCALE - 1_000_000_000) as u64);
    }

    #[test]
    fn fee_for_usage_residue_absorbs_next_fraction() {
        let min_fee = 1000u64;
        let (_, residue, _) = fee_for_usage(min_fee, 1_000_000 + 1001, 1_000_000, 0);
        // The next charge's fractional part is covered by the prior residue.
        let (fee, _residue2, overflow) = fee_for_usage(min_fee, 1_000_000 + 1, 1_000_000, residue);
        assert!(!overflow);
        assert_eq!(fee, 1000); // no extra round-up needed
    }

    #[test]
    fn fee_for_usage_zero_base_is_zero() {
        let (fee, residue, overflow) = fee_for_usage(0, 1_000_000 + 1001, 1_000_000, 0);
        assert!(!overflow);
        assert_eq!(fee, 0);
        assert_eq!(residue, 0);
    }

    #[test]
    fn fee_for_usage_zero_usage_is_zero() {
        let (fee, residue, overflow) = fee_for_usage(1000, 0, 1_000_000, 0);
        assert!(!overflow);
        assert_eq!(fee, 0);
        assert_eq!(residue, 0);
    }

    #[test]
    fn fee_for_usage_extreme_inputs_do_not_panic_and_report_overflow() {
        // Regression test: a naive `(a as u128) * (b as u128) * (c as u128)`
        // implementation of the underlying three-factor multiply overflows
        // `u128` itself (not just `u64`) when all three factors are large,
        // which panics in debug builds and silently wraps in release --
        // exactly the "wrong fee accepted" failure mode this primitive must
        // never produce. u64::MAX cubed is nowhere near representable, so
        // this must cleanly report overflow rather than panicking or wrapping
        // to a small, wrong fee.
        let (fee, _residue, overflow) = fee_for_usage(u64::MAX, u64::MAX, u64::MAX, 0);
        assert!(overflow);
        assert_eq!(fee, u64::MAX);
    }

    #[test]
    fn fee_for_usage_overflow_saturates() {
        // (u64::MAX/2) * 3_000_000 * 1_000_000 / 1e12 is far beyond u64::MAX.
        let (fee, _residue, overflow) = fee_for_usage(u64::MAX / 2, 3_000_000, 1_000_000, 0);
        assert!(overflow);
        assert_eq!(fee, u64::MAX);
    }

    #[test]
    fn fee_for_usage_precise_never_overpays_by_more_than_one_unit() {
        // A simplified version of go's TestFeeForUsagePrecise: repeatedly
        // charging small usages against a running residue should track the
        // exact fractional total, rounding up by less than 1 microAlgo of
        // slack at any point (never accumulating drift).
        let min_fee = 1000u64;
        let mut residue = 0u64;
        let mut total_fee = 0u128;
        let mut exact_num = 0u128; // Σ min_fee*usage*multiplier, over FEE_RESIDUE_SCALE
        let usage = 333_333u64; // an awkward, non-round usage
        let multiplier = 1_000_000u64;
        for _ in 0..50 {
            let (fee, new_residue, overflow) = fee_for_usage(min_fee, usage, multiplier, residue);
            assert!(!overflow);
            assert!((new_residue as u128) < FEE_RESIDUE_SCALE);
            total_fee += fee as u128;
            exact_num += (min_fee as u128) * (usage as u128) * (multiplier as u128);
            residue = new_residue;
        }
        // total_fee must be the ceiling of the exact running total, i.e.
        // within [exact, exact+1) scaled up to whole microAlgos.
        let exact_total_scaled = exact_num / FEE_RESIDUE_SCALE;
        let remainder = exact_num % FEE_RESIDUE_SCALE;
        let expected = if remainder == 0 {
            exact_total_scaled
        } else {
            exact_total_scaled + 1
        };
        assert_eq!(total_fee, expected);
    }

    // ── header_fee_contribution / large_program_extra_bytes / app_call_fee_contribution ──

    fn v42() -> ConsensusParams {
        consensus_params_for_version(CONSENSUS_V42).unwrap()
    }

    #[test]
    fn header_fee_contribution_under_cap_is_zero() {
        let p = v42();
        assert_eq!(header_fee_contribution(100, &p), 0);
        assert_eq!(header_fee_contribution(p.max_txn_note_bytes, &p), 0);
    }

    #[test]
    fn header_fee_contribution_over_cap_charges_surcharge() {
        let p = v42();
        // 10 bytes over the free cap, 100 micros/byte surcharge.
        let over = p.max_txn_note_bytes + 10;
        assert_eq!(header_fee_contribution(over, &p), 1000);
    }

    #[test]
    fn header_fee_contribution_zero_when_size_pricing_disabled() {
        let p41 = consensus_params_for_version(CONSENSUS_V41).unwrap();
        // v41 has per_byte_txn_surcharge == 0, so any (theoretical) overage
        // contributes nothing -- and in practice can't occur since WellFormed
        // rejects it outright.
        assert_eq!(
            header_fee_contribution(p41.max_txn_note_bytes + 1000, &p41),
            0
        );
    }

    #[test]
    fn large_program_extra_bytes_under_limit_is_zero() {
        let p = v42();
        let limit = p.max_app_total_program_len * (1 + p.max_extra_app_program_pages as usize);
        assert_eq!(large_program_extra_bytes(&p, limit), 0);
        assert_eq!(large_program_extra_bytes(&p, limit - 1), 0);
    }

    #[test]
    fn large_program_extra_bytes_over_limit() {
        let p = v42();
        let limit = p.max_app_total_program_len * (1 + p.max_extra_app_program_pages as usize);
        assert_eq!(large_program_extra_bytes(&p, limit + 50), 50);
    }

    #[test]
    fn app_call_fee_contribution_charges_program_and_arg_overage() {
        let p = v42();
        let limit = p.max_app_total_program_len * (1 + p.max_extra_app_program_pages as usize);
        // 20 bytes of program overage + 5 bytes of arg overage.
        let approval_len = limit + 20;
        let clear_len = 0;
        let total_args = p.max_app_total_arg_len + 5;
        let fee = app_call_fee_contribution(&p, approval_len, clear_len, total_args);
        assert_eq!(fee, 100 * 20 + 100 * 5);
    }

    #[test]
    fn app_call_fee_contribution_zero_within_free_caps() {
        let p = v42();
        let fee = app_call_fee_contribution(&p, 100, 100, 50);
        assert_eq!(fee, 0);
    }

    // ── txn_fee_factor ───────────────────────────────────────────

    fn base_txn(txn_type: &str) -> Transaction {
        Transaction {
            txn_type: txn_type.into(),
            ..Default::default()
        }
    }

    #[test]
    fn txn_fee_factor_state_proof_is_zero() {
        let p = v42();
        let txn = base_txn("stpf");
        assert_eq!(txn_fee_factor(&txn, &p), 0);
    }

    #[test]
    fn txn_fee_factor_ordinary_payment_is_one_unit() {
        let p = v42();
        let txn = base_txn("pay");
        assert_eq!(txn_fee_factor(&txn, &p), ONE_MICROS);
    }

    #[test]
    fn txn_fee_factor_oversized_note_charges_surcharge() {
        let p = v42();
        let mut txn = base_txn("pay");
        txn.note = serde_bytes::ByteBuf::from(vec![0u8; p.max_txn_note_bytes + 10]);
        assert_eq!(txn_fee_factor(&txn, &p), ONE_MICROS + 1000);
    }

    #[test]
    fn txn_fee_factor_singleton_heartbeat_is_discounted_to_zero() {
        // Pre-v42: any ungrouped (singleton) heartbeat is unconditionally
        // discounted, regardless of an (unavailable) explicit flag.
        let p = consensus_params_for_version(CONSENSUS_V41).unwrap();
        let mut txn = base_txn("hb");
        txn.group = [0u8; 32];
        assert_eq!(txn_fee_factor(&txn, &p), 0);
    }

    #[test]
    fn txn_fee_factor_grouped_heartbeat_is_not_discounted() {
        let p = v42();
        let mut txn = base_txn("hb");
        txn.group = [0xAA; 32];
        assert_eq!(txn_fee_factor(&txn, &p), ONE_MICROS);
    }

    // ── txn_fee_factor: post-v42 explicit HbChallengeDiscount ────

    fn heartbeat_txn(discount: bool) -> Transaction {
        let mut txn = base_txn("hb");
        txn.heartbeat = Some(algo_types::HeartbeatTxnFields {
            hb_challenge_discount: discount,
            ..Default::default()
        });
        txn
    }

    #[test]
    fn txn_fee_factor_v42_singleton_heartbeat_without_flag_is_not_discounted() {
        // Post-v42, grouping alone no longer implies a discount -- unlike
        // pre-v42, an *ungrouped* heartbeat that does not set the explicit
        // flag is NOT discounted. This is the core behavior this issue adds:
        // before the fix, `txn_fee_factor` always used the pre-v42
        // grouping-only inference regardless of protocol version.
        let p = v42();
        let mut txn = heartbeat_txn(false);
        txn.group = [0u8; 32];
        assert_eq!(txn_fee_factor(&txn, &p), ONE_MICROS);
    }

    #[test]
    fn txn_fee_factor_v42_singleton_heartbeat_with_flag_is_discounted() {
        let p = v42();
        let mut txn = heartbeat_txn(true);
        txn.group = [0u8; 32];
        assert_eq!(txn_fee_factor(&txn, &p), 0);
    }

    #[test]
    fn txn_fee_factor_v42_grouped_heartbeat_with_flag_is_discounted() {
        // Post-v42, the explicit flag grants the discount even when grouped
        // (unlike the pre-v42 inference, which required a singleton).
        let p = v42();
        let mut txn = heartbeat_txn(true);
        txn.group = [0xAA; 32];
        assert_eq!(txn_fee_factor(&txn, &p), 0);
    }

    #[test]
    fn txn_fee_factor_pre_v42_ignores_explicit_flag() {
        // Pre-v42, `HbChallengeDiscount` is meaningless to feeFactor (it is
        // rejected outright at well-formedness instead) -- the pre-v42
        // inference is grouping-only, matching go's `isSingletonHeartbeat`.
        let p41 = consensus_params_for_version(CONSENSUS_V41).unwrap();
        let mut txn = heartbeat_txn(true);
        txn.group = [0xAA; 32]; // grouped: not a singleton, so not discounted.
        assert_eq!(txn_fee_factor(&txn, &p41), ONE_MICROS);
    }

    // ── logic_sig_program_fee_contribution / summarize_fees ──────

    fn make_stxn(txn_type: &str, fee: u64) -> SignedTransaction {
        SignedTransaction {
            txn: Transaction {
                txn_type: txn_type.into(),
                fee,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn summarize_fees_ordinary_group() {
        let p = v42();
        let a = make_stxn("pay", 1000);
        let b = make_stxn("pay", 1000);
        let group = vec![&a, &b];
        let (usage, paid) = summarize_fees(&group, &p);
        assert_eq!(usage, 2 * ONE_MICROS);
        assert_eq!(paid, 2000);
    }

    #[test]
    fn logic_sig_program_fee_contribution_within_free_pool_is_zero() {
        let p = v42();
        let mut a = make_stxn("pay", 1000);
        a.lsig = Some(algo_types::LogicSig {
            logic: serde_bytes::ByteBuf::from(vec![0x06; p.logic_sig_max_size as usize]),
            ..Default::default()
        });
        let group = vec![&a];
        assert_eq!(logic_sig_program_fee_contribution(&group, &p), 0);
    }

    #[test]
    fn logic_sig_program_fee_contribution_over_pool_charges_surcharge() {
        let p = v42();
        let mut a = make_stxn("pay", 1000);
        a.lsig = Some(algo_types::LogicSig {
            logic: serde_bytes::ByteBuf::from(vec![0x06; p.logic_sig_max_size as usize + 30]),
            ..Default::default()
        });
        let group = vec![&a];
        assert_eq!(logic_sig_program_fee_contribution(&group, &p), 100 * 30);
    }

    // ── required_fee_for_usage / required_fee_for_txn ────────────

    #[test]
    fn required_fee_for_txn_ordinary_is_min_fee() {
        let p = v42();
        let txn = base_txn("pay");
        let (fee, overflow) = required_fee_for_txn(&txn, &p);
        assert!(!overflow);
        assert_eq!(fee, p.min_txn_fee);
    }

    #[test]
    fn required_fee_for_txn_oversized_note_scales_up() {
        let p = v42();
        let mut txn = base_txn("pay");
        txn.note = serde_bytes::ByteBuf::from(vec![0u8; p.max_txn_note_bytes + 10]);
        let (fee, overflow) = required_fee_for_txn(&txn, &p);
        assert!(!overflow);
        // usage = 1e6 + 1000 micros -> exactly 1.001x min fee.
        assert_eq!(fee, p.min_txn_fee + 1);
    }

    #[test]
    fn required_fee_for_txn_singleton_heartbeat_is_free() {
        // Pre-v42: any ungrouped (singleton) heartbeat requires no fee.
        let p = consensus_params_for_version(CONSENSUS_V41).unwrap();
        let mut txn = base_txn("hb");
        txn.group = [0u8; 32];
        let (fee, overflow) = required_fee_for_txn(&txn, &p);
        assert!(!overflow);
        assert_eq!(fee, 0);
    }

    #[test]
    fn required_fee_for_txn_v42_singleton_heartbeat_without_flag_requires_full_fee() {
        // Post-v42: without the explicit flag, an ungrouped heartbeat is an
        // ordinary transaction -- no discount is inferred from grouping.
        let p = v42();
        let mut txn = heartbeat_txn(false);
        txn.group = [0u8; 32];
        let (fee, overflow) = required_fee_for_txn(&txn, &p);
        assert!(!overflow);
        assert_eq!(fee, p.min_txn_fee);
    }

    #[test]
    fn required_fee_for_txn_v42_singleton_heartbeat_with_flag_is_free() {
        let p = v42();
        let mut txn = heartbeat_txn(true);
        txn.group = [0u8; 32];
        let (fee, overflow) = required_fee_for_txn(&txn, &p);
        assert!(!overflow);
        assert_eq!(fee, 0);
    }
}
