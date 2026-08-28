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
//! (`proto.PQSchemeFeeContribution`) and the heartbeat challenge-discount flag
//! (`HbChallengeDiscount`) are not yet modeled in `algo-types`, so
//! `txn_fee_factor` treats both as zero/absent — see the companion PQ-signature
//! and heartbeat-challenge-discount issues.

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

/// Mirrors go's `basics.Mul2div(a, b, c, d) (quotient, remainder, overflow)`
/// (`data/basics/overflow.go`): computes `a*b*c/d` and `a*b*c%d` using a wide
/// intermediate so the three-factor product never truncates before the
/// division. Go hand-rolls this with `bits.Mul64`/`bits.Div64` because it
/// lacks a native 128-bit integer type; Rust's `u128` does this directly.
/// `overflow` is true only when the quotient itself does not fit in a u64
/// (the *fee*, not the residue, saturates in that case).
fn mul2div_u64(a: u64, b: u64, c: u64, d: u128) -> (u64, u128, bool) {
    let numerator = (a as u128) * (b as u128) * (c as u128);
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
/// for a singleton (ungrouped) heartbeat.
///
/// # Heartbeat discount caveat
///
/// Go's v42+ behavior reads an explicit `HbChallengeDiscount` flag on the
/// transaction instead of inferring the discount from "is this an ungrouped
/// heartbeat". `algo-types::HeartbeatTxnFields` does not yet carry that flag
/// (tracked by a companion heartbeat-challenge-discount issue), so this
/// function always falls back to the pre-v42 `isSingletonHeartbeat` inference,
/// which go's own comment confirms is the historical stand-in for the same
/// discount. This must be revisited when the discount flag lands.
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
        // Singleton (ungrouped) heartbeat: one MinTxnFee discount. See the
        // doc comment above re: the not-yet-modeled HbChallengeDiscount flag.
        let is_singleton_heartbeat = txn.group == [0u8; 32];
        if is_singleton_heartbeat {
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
        let p = v42();
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
        let p = v42();
        let mut txn = base_txn("hb");
        txn.group = [0u8; 32];
        let (fee, overflow) = required_fee_for_txn(&txn, &p);
        assert!(!overflow);
        assert_eq!(fee, 0);
    }
}
