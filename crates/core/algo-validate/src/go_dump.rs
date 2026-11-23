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
//! go's `transaction <summary> invalid : <err>` frame (issues #2451, #2551).
//!
//! `verify.TxnGroup` (`data/transactions/verify/txn.go`, `txnGroupBatchPrep`)
//! reports a member that is not well formed, or whose signature format or
//! LogicSig fails, as `fmt.Errorf("transaction %s invalid : %w",
//! stxn.Summary(), err)`. Through go v5.0.5 the frame was the `%+v` dump of the
//! whole `SignedTxn`; go v5.1 prints `SignedTxn.Summary()`
//! (`data/transactions/signedtxn.go`) instead -- a one-line description with
//! counts and sizes in place of variable-length fields. That text reaches
//! clients through `POST /v2/transactions` and, for the signature-stage
//! failures, simulate's `failure-message`.

use algo_types::SignedTransaction;

/// go's `fmt.Errorf("transaction %s invalid : %w", stxn.Summary(), err)` text.
pub fn frame_invalid_txn(stx: &SignedTransaction, reason: &str) -> String {
    format!("transaction {} invalid : {reason}", signed_txn_summary(stx))
}

/// go's `SignedTxn.Summary()`: `<txid> <type, 8 chars> from <sender> live
/// <first>-<last>`, then ` group <id>`, ` auth <addr>`, ` sig`, ` msig(<n>)`,
/// ` lsig(<n> bytes[, msig(<n>)][, lmsig(<n>)])` and ` sksig` for each that is
/// present.
pub fn signed_txn_summary(stx: &SignedTransaction) -> String {
    let t = &stx.txn;
    // `%.8s` of the type string: at most eight characters.
    let ty: String = t.txn_type.as_str().chars().take(8).collect();
    let mut s = format!(
        "{} {ty} from {} live {}-{}",
        algo_codec::compute_txn_id(t),
        t.sender,
        t.first_valid.0,
        t.last_valid.0
    );
    if t.group.iter().any(|b| *b != 0) {
        s.push_str(&format!(" group {}", algo_types::Digest(t.group)));
    }
    if let Some(a) = stx.auth_addr.filter(|a| *a != algo_types::Address::ZERO) {
        s.push_str(&format!(" auth {a}"));
    }
    if stx.sig.iter().any(|b| *b != 0) {
        s.push_str(" sig");
    }
    if let Some(m) = stx.msig.as_ref().filter(|m| !m.blank()) {
        s.push_str(&format!(" msig({})", m.subsigs.len()));
    }
    if let Some(l) = stx.lsig.as_ref().filter(|l| !l.is_blank()) {
        s.push_str(&format!(" lsig({} bytes", l.logic.len()));
        if let Some(m) = l.msig.as_ref().filter(|m| !m.blank()) {
            s.push_str(&format!(", msig({})", m.subsigs.len()));
        }
        if let Some(m) = l.lmsig.as_ref().filter(|m| !m.blank()) {
            s.push_str(&format!(", lmsig({})", m.subsigs.len()));
        }
        s.push(')');
    }
    if stx.pqsig.as_ref().is_some_and(|p| !p.blank()) {
        s.push_str(" sksig");
    }
    s
}

/// go's reason for a member's `txnBatchPrep` failure, the `<err>` of its
/// frame: the error's own text (never `AlgoError::Validation`'s `validation
/// error: ` prefix), and for a LogicSig program that errors, `logicSigVerify`'s
/// `transaction <txid>: %w` of the program's `EvalError` (`rejected by logic
/// err=<err>. Details: pc=<pc>`).
pub fn verify_member_reason(stx: &SignedTransaction, e: &algo_error::AlgoError) -> String {
    member_reason(stx, e, false)
}

/// [`verify_member_reason`] as simulate prints it: simulate's tracer asks
/// for detailed eval errors (`DetailedEvalErrors`), so a LogicSig program's
/// error carries the failing instructions too, `Details: pc=<pc>,
/// opcodes=<pcDetails>` (`logic.(*EvalContext).evalError`).
pub fn simulate_member_reason(stx: &SignedTransaction, e: &algo_error::AlgoError) -> String {
    member_reason(stx, e, true)
}

fn member_reason(stx: &SignedTransaction, e: &algo_error::AlgoError, detailed: bool) -> String {
    match e {
        algo_error::AlgoError::Validation { message } => message.clone(),
        algo_error::AlgoError::AvmLogicSig {
            message,
            pc,
            app_index: None,
            ..
        } => {
            let opcodes = match (detailed, stx.lsig.as_ref()) {
                (true, Some(lsig)) => format!(
                    ", opcodes={}",
                    algo_avm::disassembler::pc_details(&lsig.logic, *pc)
                ),
                _ => String::new(),
            };
            format!(
                "transaction {}: rejected by logic err={}. Details: pc={pc}{opcodes}",
                algo_codec::compute_txn_id(&stx.txn),
                message.strip_prefix("AVM: ").unwrap_or(message),
            )
        }
        other => other.to_string(),
    }
}

/// Whether go reports `e`, a member's signature verdict, with the member's
/// frame. Every `txnBatchPrep` failure is framed; the batch verifier's own
/// failure is bare, except a delegated LogicSig's: `logicSigVerify` checks
/// that signature with a batch of its own, inside the framed prep
/// (`LogicSigSanityCheck`).
pub fn verify_failure_is_framed(stx: &SignedTransaction, e: &algo_error::AlgoError) -> bool {
    !e.is_batch_sig_failure() || stx.lsig.as_ref().is_some_and(|l| l.has_program())
}
