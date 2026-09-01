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

//! Post-quantum (PQ) authorizer and on-curve LogicSig compliance checks for
//! the `raw_transaction`/`raw_transaction_async`/simulate REST boundary.
//!
//! Mirrors go-algorand's `daemon/algod/api/server/v2/handlers.go`:
//! `shouldSkipPqAddressCheck`, `isEscrowLogicSig`,
//! `rejectOnCurveLogicSigPrograms`, `enforcePQAuthorizerCompliance`.

use algo_types::{Address, SignedTransaction};
use sha2::{Digest, Sha512_256};

/// The query-parameter name go-algorand uses in its error message
/// (`skip-pq-address-check`), referenced when telling the caller how to
/// bypass this check if they understand the risk.
pub const SKIP_PQ_ADDRESS_CHECK_PARAM: &str = "skip-pq-address-check";

/// AVM version at which stateless (non-app) programs are auto-salted so
/// their program hash cannot be a valid Edwards25519 curve point. Matches
/// go-algorand's `logic.LogicSigOffCurveVersion`
/// (`data/transactions/logic/opcodes.go`).
const LOGIC_SIG_OFF_CURVE_VERSION: u8 = 13;

/// Domain-separation prefix used when hashing program bytes into a LogicSig
/// contract-account address. Matches go-algorand's `protocol.Program`.
const PROGRAM_PREFIX: &[u8] = b"Program";

/// Mirrors go-algorand's `shouldSkipPqAddressCheck`: the check runs by
/// default and is skipped only when the caller explicitly passes
/// `skip-pq-address-check=true`.
pub fn should_skip_pq_address_check(skip: Option<bool>) -> bool {
    skip.unwrap_or(false)
}

/// Compute the contract-account address a LogicSig program would authorize
/// for (`SHA512/256("Program" || logic)`), matching go-algorand's
/// `logic.HashProgram`.
fn hash_program(logic: &[u8]) -> Address {
    let mut hasher = Sha512_256::new();
    hasher.update(PROGRAM_PREFIX);
    hasher.update(logic);
    let hash: [u8; 32] = hasher.finalize().into();
    Address(hash)
}

/// Mirrors go-algorand's `isEscrowLogicSig`: true when the LogicSig carries
/// no delegated signature of any kind (ed25519, multisig, logic-multisig, or
/// PQ) and its authorizer address equals its own program hash — i.e. it's a
/// genuine contract-account LogicSig, not a delegated one.
fn is_escrow_logic_sig(stxn: &SignedTransaction) -> bool {
    let Some(lsig) = &stxn.lsig else {
        return false;
    };
    let authorizer = stxn.auth_addr.as_ref().unwrap_or(&stxn.txn.sender);
    lsig.sig == [0u8; 64]
        && lsig.msig.is_none()
        && lsig.lmsig.is_none()
        && lsig.pqsig.as_ref().map(|s| s.blank()).unwrap_or(true)
        && *authorizer == hash_program(&lsig.logic)
}

/// Reports whether `program`'s hash decodes as a valid Edwards25519 curve
/// point (i.e. is "on-curve") -- the same check `Address::is_pq_compliant`
/// applies to account addresses, applied to a LogicSig's program hash.
fn program_hash_is_edwards25519_point(program: &[u8]) -> bool {
    !hash_program(program).is_pq_compliant()
}

/// Mirrors go-algorand's `rejectOnCurveLogicSigPrograms`: for every escrow
/// LogicSig in the group running a v13+ program whose hash happens to land
/// on the Edwards25519 curve (and could therefore double as a spendable
/// on-curve address), reject the group -- unless the caller opted out via
/// `skip-pq-address-check`.
pub fn reject_on_curve_logic_sig_programs(txgroup: &[SignedTransaction]) -> Result<(), String> {
    for (i, stxn) in txgroup.iter().enumerate() {
        let Some(lsig) = &stxn.lsig else {
            continue;
        };
        if lsig.logic.is_empty() {
            continue;
        }
        let version = match algo_avm::bytecode::parse(&lsig.logic) {
            Ok(p) => p.version,
            Err(_) => continue,
        };
        if version < LOGIC_SIG_OFF_CURVE_VERSION || version > algo_avm::MAX_AVM_VERSION {
            continue;
        }
        if is_escrow_logic_sig(stxn) && program_hash_is_edwards25519_point(&lsig.logic) {
            return Err(format!(
                "transaction {i}: TEAL v{version} LogicSig program hash is an Edwards25519 point and should not be used; set {SKIP_PQ_ADDRESS_CHECK_PARAM}=true to submit anyway if you understand the risks and know what you are doing"
            ));
        }
    }
    Ok(())
}

/// Mirrors go-algorand's `enforcePQAuthorizerCompliance`: for every
/// transaction (or delegated LogicSig) carrying a non-blank `PQsig` with a
/// public key, the PQ-signature-derived authorizer address must itself be
/// PQ-compliant (off-curve) -- a PQ signature whose derived address is an
/// Edwards25519 point could be confused with, or collide with, a spendable
/// ed25519 account.
pub fn enforce_pq_authorizer_compliance(txgroup: &[SignedTransaction]) -> Result<(), String> {
    for (i, stxn) in txgroup.iter().enumerate() {
        let pq_sig = match &stxn.pqsig {
            Some(s) if !s.blank() => Some(s),
            _ => stxn
                .lsig
                .as_ref()
                .filter(|l| !l.logic.is_empty())
                .and_then(|l| l.pqsig.as_ref())
                .filter(|s| !s.blank()),
        };
        let Some(pq_sig) = pq_sig else {
            continue;
        };
        if pq_sig.public_key.is_empty() {
            continue;
        }
        let authorizer = pq_sig.address();
        if !authorizer.is_pq_compliant() {
            return Err(format!(
                "transaction {i}: pq signature authorizer address {authorizer} is an Edwards25519 curve point (non PQ-compliant)"
            ));
        }
    }
    Ok(())
}

/// Run both PQ-authorizer and on-curve-LogicSig compliance checks, matching
/// go-algorand's call order in `RawTransaction`/`RawTransactionAsync`
/// (PQ authorizer first, then on-curve LogicSig).
pub fn enforce_pq_compliance(
    txgroup: &[SignedTransaction],
    skip: Option<bool>,
) -> Result<(), String> {
    if should_skip_pq_address_check(skip) {
        return Ok(());
    }
    enforce_pq_authorizer_compliance(txgroup)?;
    reject_on_curve_logic_sig_programs(txgroup)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::pq::{PQAddressSalt, PQSig};
    use algo_types::{LogicSig, Transaction};
    use serde_bytes::ByteBuf;

    fn minimal_pay_txn(sender: Address) -> Transaction {
        Transaction {
            txn_type: algo_types::TxnType::Pay,
            sender,
            fee: 1000,
            first_valid: algo_types::Round(1),
            last_valid: algo_types::Round(1000),
            ..Default::default()
        }
    }

    #[test]
    fn should_skip_pq_address_check_defaults_false() {
        assert!(!should_skip_pq_address_check(None));
        assert!(!should_skip_pq_address_check(Some(false)));
        assert!(should_skip_pq_address_check(Some(true)));
    }

    #[test]
    fn enforce_pq_compliance_skipped_when_requested() {
        // An obviously bad PQ authorizer would normally fail, but skip=true
        // bypasses the check entirely.
        let pq_sig = PQSig {
            scheme: *b"f1",
            public_key: ByteBuf::from(vec![0u8; 1793]),
            ..Default::default()
        };
        let stxn = SignedTransaction {
            txn: minimal_pay_txn(Address([1u8; 32])),
            pqsig: Some(pq_sig),
            ..Default::default()
        };
        assert!(enforce_pq_compliance(&[stxn], Some(true)).is_ok());
    }

    #[test]
    fn enforce_pq_authorizer_compliance_ignores_blank_pqsig() {
        let stxn = SignedTransaction {
            txn: minimal_pay_txn(Address([1u8; 32])),
            ..Default::default()
        };
        assert!(enforce_pq_authorizer_compliance(&[stxn]).is_ok());
    }

    #[test]
    fn enforce_pq_authorizer_compliance_ignores_empty_public_key() {
        let stxn = SignedTransaction {
            txn: minimal_pay_txn(Address([1u8; 32])),
            pqsig: Some(PQSig {
                scheme: *b"f1",
                salt: PQAddressSalt(0),
                public_key: ByteBuf::new(),
                signature: ByteBuf::new(),
            }),
            ..Default::default()
        };
        assert!(enforce_pq_authorizer_compliance(&[stxn]).is_ok());
    }

    #[test]
    fn is_escrow_logic_sig_true_for_matching_contract_account() {
        let program = vec![0x02u8, 0x20, 0x01, 0x01, 0x22]; // v2, int 1
        let addr = hash_program(&program);
        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            ..Default::default()
        };
        let stxn = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig),
            ..Default::default()
        };
        assert!(is_escrow_logic_sig(&stxn));
    }

    #[test]
    fn is_escrow_logic_sig_false_when_delegated_sig_present() {
        let program = vec![0x02u8, 0x20, 0x01, 0x01, 0x22];
        let addr = hash_program(&program);
        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            sig: [1u8; 64],
            ..Default::default()
        };
        let stxn = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig),
            ..Default::default()
        };
        assert!(!is_escrow_logic_sig(&stxn));
    }

    #[test]
    fn reject_on_curve_logic_sig_programs_ignores_non_lsig_txns() {
        let stxn = SignedTransaction {
            txn: minimal_pay_txn(Address([1u8; 32])),
            ..Default::default()
        };
        assert!(reject_on_curve_logic_sig_programs(&[stxn]).is_ok());
    }

    #[test]
    fn reject_on_curve_logic_sig_programs_ignores_pre_v13_programs() {
        // v2 program: even if it happened to hash on-curve, pre-v13
        // programs predate the off-curve-salting requirement.
        let program = vec![0x02u8, 0x20, 0x01, 0x01, 0x22];
        let addr = hash_program(&program);
        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            ..Default::default()
        };
        let stxn = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig),
            ..Default::default()
        };
        assert!(reject_on_curve_logic_sig_programs(&[stxn]).is_ok());
    }

    #[test]
    fn reject_on_curve_logic_sig_programs_accepts_off_curve_v13_program() {
        // A v13 "int 1" program salted so its hash is off-curve (the
        // assembler's default autosalt behavior); confirms the happy path
        // doesn't false-positive.
        let program = algo_avm::assemble_string("#pragma version 13\nint 1\nreturn\n")
            .expect("assembles")
            .program;
        assert!(!program_hash_is_edwards25519_point(&program));
        let addr = hash_program(&program);
        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            ..Default::default()
        };
        let stxn = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig),
            ..Default::default()
        };
        assert!(reject_on_curve_logic_sig_programs(&[stxn]).is_ok());
    }

    #[test]
    fn reject_on_curve_logic_sig_programs_rejects_on_curve_v13_program() {
        // Search for an `int v; return` v13 program (with autosalt
        // disabled) whose hash happens to land on-curve, then confirm it's
        // rejected as an escrow LogicSig. Mirrors the search pattern used
        // in algo-avm's own autosalt tests.
        let mut program = None;
        for v in 0u64..64 {
            let src =
                format!("#pragma version 13\n#pragma autosalt false\nint {v}\nint {v}\nreturn\n");
            let ops = algo_avm::assemble_string(&src).unwrap();
            if program_hash_is_edwards25519_point(&ops.program) {
                program = Some(ops.program);
                break;
            }
        }
        let program = program.expect("expected at least one on-curve program in range 0..64");
        let addr = hash_program(&program);
        let lsig = LogicSig {
            logic: ByteBuf::from(program),
            ..Default::default()
        };
        let stxn = SignedTransaction {
            txn: minimal_pay_txn(addr),
            lsig: Some(lsig),
            ..Default::default()
        };
        let result = reject_on_curve_logic_sig_programs(&[stxn]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Edwards25519 point"));
    }
}
