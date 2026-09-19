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

use algo_avm::group::GroupBudget;
use algo_avm::{EvalTracer, ProgramType};
use algo_codec::decode_block_response;
use algo_types::consensus::ConsensusParams;
use algo_types::{Address, LogicSig, Round, SignedTransaction, Transaction};
use algo_validate::signature::verify_logicsig;
use algo_validate::verify_transaction_signature;
use algo_validate::verify_transaction_signature_with_tracer;
use sha2::{Digest, Sha512_256};
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../core/algo-codec/tests/fixtures")
}

/// Load a block fixture and decode it.
/// Returns None if the fixture file doesn't exist.
fn load_block(round: u64) -> Option<algo_types::BlockResponse> {
    let path = fixture_dir().join(format!("block_{round}.msgpack"));
    if !path.exists() {
        return None;
    }
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    Some(decode_block_response(&bytes).unwrap_or_else(|e| panic!("decode block {round}: {e}")))
}

/// Skip a test if fixtures are not available, printing a message.
macro_rules! require_fixture {
    ($expr:expr, $msg:expr) => {
        match $expr {
            Some(v) => v,
            None => {
                eprintln!("SKIPPED: {} (run `make fixtures` to generate)", $msg);
                return;
            }
        }
    };
}

/// Restore genesis_id and genesis_hash on transactions that had them stripped
/// for block storage. In Algorand blocks, genesis_id is stripped when hgi=true,
/// and genesis_hash is ALWAYS stripped (it's redundant with the block header)
/// regardless of the hgh flag value.
fn restore_genesis_fields(br: &algo_types::BlockResponse) -> Vec<algo_types::SignedTransaction> {
    br.block
        .payset
        .iter()
        .map(|stx| {
            let mut full = stx.clone();
            if stx.has_genesis_id && full.txn.genesis_id.is_empty() {
                full.txn.genesis_id.clone_from(&br.block.genesis_id);
            }
            // Genesis hash is always stripped from block-stored transactions
            if full.txn.genesis_hash == [0u8; 32] {
                full.txn.genesis_hash = br.block.genesis_hash;
            }
            full
        })
        .collect()
}

/// Verify all transaction signatures in a block fixture.
macro_rules! sig_verify_test {
    ($name:ident, $round:expr) => {
        #[test]
        fn $name() {
            let br = require_fixture!(
                load_block($round),
                concat!("block ", stringify!($round), " fixture missing")
            );

            if br.block.payset.is_empty() {
                eprintln!("block {} has no transactions, skipping", $round);
                return;
            }

            let txns = restore_genesis_fields(&br);
            let mut lsig_budget = GroupBudget::for_logicsig(txns.len());
            for (i, stx) in txns.iter().enumerate() {
                verify_transaction_signature(
                    stx,
                    &txns,
                    i,
                    &mut lsig_budget,
                    &ConsensusParams::default(),
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "signature verification failed for block {} txn {}: {e}",
                        $round, i
                    )
                });
            }
        }
    };
}

sig_verify_test!(sig_verify_block_1_pay, 1);
sig_verify_test!(sig_verify_block_2_acfg, 2);
sig_verify_test!(sig_verify_block_3_axfer_optin, 3);
sig_verify_test!(sig_verify_block_4_axfer_transfer, 4);
sig_verify_test!(sig_verify_block_5_afrz, 5);
sig_verify_test!(sig_verify_block_6_appl_create, 6);
sig_verify_test!(sig_verify_block_7_appl_call, 7);
sig_verify_test!(sig_verify_block_8_keyreg, 8);
sig_verify_test!(sig_verify_block_9_pay_tail, 9);

/// Verify all blocks in a single sweep.
#[test]
fn sig_verify_all_blocks() {
    let mut verified = 0;
    for round in 1..=9 {
        let br = match load_block(round) {
            Some(br) => br,
            None => continue,
        };

        let txns = restore_genesis_fields(&br);
        let mut lsig_budget = GroupBudget::for_logicsig(txns.len());
        for (i, stx) in txns.iter().enumerate() {
            verify_transaction_signature(
                stx,
                &txns,
                i,
                &mut lsig_budget,
                &ConsensusParams::default(),
            )
            .unwrap_or_else(|e| {
                panic!("signature verification failed for block {round} txn {i}: {e}")
            });
            verified += 1;
        }
    }

    if verified == 0 {
        eprintln!("SKIPPED: no block fixtures found (run `make fixtures` to generate)");
    } else {
        eprintln!("verified {verified} transaction signatures across all block fixtures");
    }
}

/// Mirrors go-algorand's `TestTxnValidationEncodeDecode`
/// (`data/transactions/verify/txn_test.go#L351`): a signed transaction that
/// verifies must still verify after being encoded to msgpack and decoded
/// back -- the wire round-trip must not silently drop or corrupt anything
/// the signature check depends on.
#[test]
fn sig_verify_survives_msgpack_round_trip() {
    let mut checked = 0;
    for round in 1..=9 {
        let br = match load_block(round) {
            Some(br) => br,
            None => continue,
        };

        let txns = restore_genesis_fields(&br);
        let mut lsig_budget = GroupBudget::for_logicsig(txns.len());
        // Round-trip every transaction through the plain (non-in-block)
        // SignedTxn wire encoding first, building a parallel group so
        // sibling references (gtxn, group ID) stay consistent across the
        // decoded set, exactly as the original `txns` group does.
        let round_tripped: Vec<algo_types::SignedTransaction> = txns
            .iter()
            .map(|stx| {
                let encoded = algo_codec::canonical_encode_signed_transaction(stx);
                let decoded = algo_codec::decode_signed_txn_stream(&encoded)
                    .unwrap_or_else(|e| panic!("failed to decode round-tripped signed txn: {e}"));
                assert_eq!(
                    decoded.len(),
                    1,
                    "must decode exactly one signed transaction"
                );
                decoded.into_iter().next().unwrap()
            })
            .collect();
        let mut lsig_budget_rt = GroupBudget::for_logicsig(round_tripped.len());

        for (i, stx) in txns.iter().enumerate() {
            verify_transaction_signature(
                stx,
                &txns,
                i,
                &mut lsig_budget,
                &ConsensusParams::default(),
            )
            .unwrap_or_else(|e| {
                panic!("original signed transaction failed to verify (block {round} txn {i}): {e}")
            });

            verify_transaction_signature(
                &round_tripped[i],
                &round_tripped,
                i,
                &mut lsig_budget_rt,
                &ConsensusParams::default(),
            )
            .unwrap_or_else(|e| {
                panic!(
                    "round-tripped signed transaction failed to verify (block {round} txn {i}): {e}"
                )
            });
            checked += 1;
        }
    }

    if checked == 0 {
        eprintln!("SKIPPED: no block fixtures found (run `make fixtures` to generate)");
    } else {
        eprintln!("verified {checked} signed transactions survive a msgpack round-trip");
    }
}

// ===========================================================================
// LogicSig integration tests
// ===========================================================================

/// Build a raw AVM program: version byte + code bytes.
fn prog(version: u8, code: &[u8]) -> Vec<u8> {
    let mut p = vec![version];
    p.extend_from_slice(code);
    p
}

/// Compute SHA512/256("Program" || program) and return as Address.
fn program_address(program: &[u8]) -> Address {
    let mut hasher = Sha512_256::new();
    hasher.update(b"Program");
    hasher.update(program);
    let hash: [u8; 32] = hasher.finalize().into();
    Address(hash)
}

/// Build a minimal pay transaction from a contract account (sender = program hash).
fn make_contract_account_txn(program: &[u8]) -> SignedTransaction {
    let sender = program_address(program);
    SignedTransaction {
        txn: Transaction {
            txn_type: "pay".into(),
            sender,
            fee: 1_000,
            first_valid: Round(1),
            last_valid: Round(100),
            receiver: Address([0x20; 32]),
            amount: 0,
            ..Default::default()
        },
        lsig: Some(LogicSig {
            logic: serde_bytes::ByteBuf::from(program.to_vec()),
            sig: [0u8; 64],
            msig: None,
            lmsig: None,
            args: None,
            pqsig: None,
        }),
        ..Default::default()
    }
}

/// A LogicSig with `int 1` (pushint 1) should pass verification.
#[test]
fn logicsig_valid_program_approves() {
    let program = prog(6, &[0x81, 0x01]); // pushint 1
    let stx = make_contract_account_txn(&program);
    let group = vec![stx.clone()];
    let mut budget = GroupBudget::for_logicsig(1);

    let lsig = stx.lsig.as_ref().unwrap();
    let result = verify_logicsig(
        &stx,
        lsig,
        &group,
        0,
        &mut budget,
        &ConsensusParams::default(),
    );
    assert!(
        result.is_ok(),
        "LogicSig with `pushint 1` should pass: {:?}",
        result.err()
    );
}

/// A LogicSig with `int 0` (pushint 0) should fail verification (program rejects).
#[test]
fn logicsig_rejecting_program_fails() {
    let program = prog(6, &[0x81, 0x00]); // pushint 0
    let stx = make_contract_account_txn(&program);
    let group = vec![stx.clone()];
    let mut budget = GroupBudget::for_logicsig(1);

    let lsig = stx.lsig.as_ref().unwrap();
    let result = verify_logicsig(
        &stx,
        lsig,
        &group,
        0,
        &mut budget,
        &ConsensusParams::default(),
    );
    assert!(result.is_err(), "LogicSig with `pushint 0` should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("rejected"),
        "error should mention rejection: {}",
        err_msg
    );
}

/// LogicSig pooled budget: multiple transactions in a group share the budget.
/// Running a LogicSig on one transaction should reduce the budget available
/// to the next transaction in the group.
#[test]
fn logicsig_pooled_budget_shared_across_group() {
    let program = prog(6, &[0x81, 0x01]); // pushint 1

    let stx1 = make_contract_account_txn(&program);
    let stx2 = make_contract_account_txn(&program);
    let group = vec![stx1.clone(), stx2.clone()];

    // Budget for a group of 2 is 2 * 20_000 = 40_000.
    let mut budget = GroupBudget::for_logicsig(2);
    assert_eq!(budget.remaining(), 40_000);

    // Verify first transaction's LogicSig.
    let lsig1 = stx1.lsig.as_ref().unwrap();
    verify_logicsig(
        &stx1,
        lsig1,
        &group,
        0,
        &mut budget,
        &ConsensusParams::default(),
    )
    .unwrap();

    // Budget should have decreased (pushint 1 costs 1 opcode unit).
    let after_first = budget.remaining();
    assert!(
        after_first < 40_000,
        "budget should decrease after first LogicSig execution, got {}",
        after_first
    );

    // Verify second transaction's LogicSig with the same pooled budget.
    let lsig2 = stx2.lsig.as_ref().unwrap();
    verify_logicsig(
        &stx2,
        lsig2,
        &group,
        1,
        &mut budget,
        &ConsensusParams::default(),
    )
    .unwrap();

    let after_second = budget.remaining();
    assert!(
        after_second < after_first,
        "budget should decrease further after second LogicSig execution: \
         after_first={}, after_second={}",
        after_first,
        after_second
    );
}

/// A LogicSig program that uses `app_opted_in` (Application-mode only opcode)
/// should fail because LogicSig programs cannot access state.
#[test]
fn logicsig_state_access_app_opted_in_fails() {
    // Version 2, intcblock [0], intc_0, intc_0, app_opted_in, return
    // This program tries to call app_opted_in(0, 0) which is Application-mode only.
    let program = prog(2, &[0x20, 0x01, 0x00, 0x22, 0x22, 0x61, 0x43]);
    let stx = make_contract_account_txn(&program);
    let group = vec![stx.clone()];
    let mut budget = GroupBudget::for_logicsig(1);

    let lsig = stx.lsig.as_ref().unwrap();
    let result = verify_logicsig(
        &stx,
        lsig,
        &group,
        0,
        &mut budget,
        &ConsensusParams::default(),
    );
    assert!(result.is_err(), "LogicSig using app_opted_in should fail");
}

/// verify_transaction_signature dispatches to LogicSig path when lsig is set.
#[test]
fn verify_transaction_signature_dispatches_to_logicsig() {
    let program = prog(6, &[0x81, 0x01]); // pushint 1
    let stx = make_contract_account_txn(&program);
    let group = vec![stx.clone()];
    let mut budget = GroupBudget::for_logicsig(1);

    let result =
        verify_transaction_signature(&stx, &group, 0, &mut budget, &ConsensusParams::default());
    assert!(
        result.is_ok(),
        "verify_transaction_signature should dispatch to LogicSig path: {:?}",
        result.err()
    );
}

/// LogicSig size pooling: a LogicSig exceeding 1000 bytes should be rejected
/// without pooling but accepted with pooling when the group pool is large enough.
#[test]
fn logicsig_size_pooling_allows_large_lsig_in_group() {
    use algo_validate::signature::verify_group_logicsig_size;

    let consensus = ConsensusParams::default();

    // Build a program that is larger than LogicSigMaxSize (1000 bytes).
    // We'll use pushbytes with a large payload. The program needs to be valid
    // so we construct: version 6, pushbytes <large>, pop, pushint 1
    // pushbytes 0x80: opcode 0x80, then varuint length, then bytes
    // Build a program > consensus.logic_sig_max_size (1000 bytes) using pushbytes with
    // a large blob. Layout: version(1) + pushbytes(1) + varuint(2) + 3380
    // + pop(1) + pushint 1(2) = 3387 bytes.
    let blob_len = 3380usize;
    let mut program = Vec::with_capacity(3400);
    program.push(0x06); // version 6
    program.push(0x80); // pushbytes
                        // varuint encode blob_len
    let mut n = blob_len;
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n > 0 {
            byte |= 0x80;
        }
        program.push(byte);
        if n == 0 {
            break;
        }
    }
    program.extend(std::iter::repeat(0u8).take(blob_len));
    program.push(0x48); // pop
    program.push(0x81); // pushint
    program.push(0x01); // 1

    let program_len = program.len() as u64;
    assert!(
        program_len > consensus.logic_sig_max_size,
        "test program should exceed consensus.logic_sig_max_size: {} > {}",
        program_len,
        consensus.logic_sig_max_size
    );

    // Without pooling, the individual LogicSig should be rejected.
    let no_pooling = ConsensusParams {
        enable_logicsig_size_pooling: false,
        ..ConsensusParams::default()
    };
    let stx = make_contract_account_txn(&program);
    let group = vec![stx.clone()];
    let mut budget = GroupBudget::for_logicsig(1);
    let lsig = stx.lsig.as_ref().unwrap();
    let result = verify_logicsig(&stx, lsig, &group, 0, &mut budget, &no_pooling);
    assert!(
        result.is_err(),
        "should reject large LogicSig without size pooling"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("LogicSig too long"),
        "error should mention size"
    );

    // With pooling enabled, the per-txn check is skipped.
    let pooling_consensus = ConsensusParams {
        enable_logicsig_size_pooling: true,
        ..ConsensusParams::default()
    };
    let mut budget2 = GroupBudget::for_logicsig(1);
    let result2 = verify_logicsig(&stx, lsig, &group, 0, &mut budget2, &pooling_consensus);
    assert!(
        result2.is_ok(),
        "should accept large LogicSig with size pooling (per-txn check skipped): {:?}",
        result2.err()
    );

    // Group-level check with 8 members: pool = 8 * 1000 = 8000.
    // Our program is ~3387 bytes < 8000, so it should pass.
    let mut group_of_8: Vec<SignedTransaction> = Vec::new();
    group_of_8.push(stx.clone());
    for _ in 1..8 {
        // Other 7 are plain pay txns (no LogicSig, contribute 0 to pool).
        let plain = SignedTransaction {
            txn: Transaction {
                txn_type: "pay".into(),
                sender: Address([0x10; 32]),
                fee: 1_000,
                first_valid: Round(1),
                last_valid: Round(100),
                receiver: Address([0x20; 32]),
                amount: 0,
                ..Default::default()
            },
            sig: [0u8; 64],
            ..Default::default()
        };
        group_of_8.push(plain);
    }
    let pooled_result = verify_group_logicsig_size(&group_of_8, &consensus);
    assert!(
        pooled_result.is_ok(),
        "group of 8 should have enough pool for one 3387-byte LogicSig: {:?}",
        pooled_result.err()
    );

    // Group-level check with 1 member: pool = 1 * 1000 = 1000.
    // Our program is ~3387 bytes > 1000, so it should fail.
    let small_group = vec![stx.clone()];
    let pooled_fail = verify_group_logicsig_size(&small_group, &consensus);
    assert!(
        pooled_fail.is_err(),
        "group of 1 should reject a 3387-byte LogicSig"
    );
}

/// Build a syntactically valid, executable AVM **v1** program of exactly
/// `total_len` bytes -- v1 is used (rather than a later version's more
/// compact `pushbytes`/`pushint`) because this helper backs the
/// `TestLogicSigSizeBeforePooling`-equivalent test, which specifically
/// exercises go's v18 nettemplate (`LogicSigVersion == 1`, `pragma 1`, per
/// go's own `GenerateUnsaltedProgramOfSize(size, pragma=1)` call).
///
/// Layout: `version(1) bytecblock-op(1) numconsts(1)=1 varuint-len(2) <blob>
/// bytec_0(1) pop(1) intcblock-op(1) numconsts(1)=1 intc-val(1)=1
/// intc_0(1)` -- 11 bytes of fixed overhead plus `blob_len` bytes of
/// payload (a 2-byte varuint length prefix, valid for `blob_len` in
/// `128..=16383`, which covers this test's 1000-2001-byte range). Final
/// stack value is the int 1, so the LogicSig evaluates to approve.
fn valid_program_of_size(total_len: usize) -> Vec<u8> {
    let blob_len = total_len - 11;
    assert!(
        (128..=16383).contains(&blob_len),
        "blob_len {blob_len} out of the 2-byte-varuint range this helper assumes"
    );
    let mut program = Vec::with_capacity(total_len);
    program.push(0x01); // version 1
    program.push(0x26); // bytecblock
    program.push(0x01); // num constants = 1
    program.push(((blob_len & 0x7f) | 0x80) as u8);
    program.push((blob_len >> 7) as u8);
    program.extend(std::iter::repeat(0u8).take(blob_len));
    program.push(0x28); // bytec_0
    program.push(0x48); // pop
    program.push(0x20); // intcblock
    program.push(0x01); // num constants = 1
    program.push(0x01); // value = 1
    program.push(0x22); // intc_0
    assert_eq!(program.len(), total_len);
    program
}

/// Build a 2-txn group mirroring go-algorand's `testLogicSize` helper
/// (`test/e2e-go/features/transactions/logicsig_test.go`): the first txn is
/// signed by a LogicSig program of exactly `program_len` bytes, the second
/// is a vanilla payment with no LogicSig.
fn two_txn_group_with_logicsig(program_len: usize) -> Vec<SignedTransaction> {
    let program = valid_program_of_size(program_len);
    let lsig_txn = make_contract_account_txn(&program);
    let plain_txn = SignedTransaction {
        txn: Transaction {
            txn_type: "pay".into(),
            sender: Address([0x30; 32]),
            fee: 1_000,
            first_valid: Round(1),
            last_valid: Round(100),
            receiver: Address([0x40; 32]),
            amount: 0,
            ..Default::default()
        },
        sig: [0u8; 64],
        ..Default::default()
    };
    vec![lsig_txn, plain_txn]
}

/// Mirrors go-algorand's `TestLogicSigSizeBeforePooling`
/// (`test/e2e-go/features/transactions/logicsig_test.go#L31`): on the v18
/// protocol (`MaxAbsoluteLogicSigProgramSize == LogicSigMaxSize == 1000`,
/// go's pre-pooling nettemplate), a LogicSig program of exactly 1000 bytes
/// is accepted and one byte over is rejected.
///
/// The rejection here comes from `verify_logicsig`'s per-transaction size
/// checks (its `!enable_logicsig_size_pooling` gate and/or its *absolute*
/// `max_absolute_logic_sig_program_size` cap, mirroring go's
/// `logicSigSanityCheckBatchPrep`, `data/transactions/verify/txn.go#L441`),
/// not the group-pool check (`logic_sig_group_size_check`): at v18 the
/// group pool for this 2-txn group is already `2 * 1000 = 2000` bytes (the
/// pool formula is unconditional in the pinned go-algorand source -- see
/// `logicSigGroupSizeCheck`), so a 1001-byte program would *pass* the pool
/// check on its own. It is v18's per-txn caps (`LogicSigMaxSize` and
/// `MaxAbsoluteLogicSigProgramSize`, both 1000, i.e. no room for pooling to
/// help) that actually gate it, exactly mirroring the live node's per-txn
/// rejection go's test observes.
#[test]
fn logicsig_before_pooling_absolute_cap_boundary() {
    let consensus =
        algo_types::consensus::consensus_params_for_version(algo_types::consensus::CONSENSUS_V18)
            .expect("v18 must be a known protocol version");
    assert_eq!(
        consensus.max_absolute_logic_sig_program_size, 1000,
        "test assumes go's v18 MaxAbsoluteLogicSigProgramSize of 1000 bytes"
    );
    assert_eq!(consensus.logic_sig_max_size, 1000);

    let group_ok = two_txn_group_with_logicsig(1000);
    let lsig_ok = group_ok[0].lsig.as_ref().unwrap();
    let mut budget_ok = GroupBudget::for_logicsig(group_ok.len());
    assert!(
        verify_logicsig(
            &group_ok[0],
            lsig_ok,
            &group_ok,
            0,
            &mut budget_ok,
            &consensus
        )
        .is_ok(),
        "a 1000-byte LogicSig must be accepted before pooling"
    );
    // The group-level pool check must also pass (it's not what's being pinned here).
    assert!(algo_validate::signature::logic_sig_group_size_check(&group_ok, &consensus).is_ok());

    let group_too_long = two_txn_group_with_logicsig(1001);
    let lsig_too_long = group_too_long[0].lsig.as_ref().unwrap();
    let mut budget_fail = GroupBudget::for_logicsig(group_too_long.len());
    let err = verify_logicsig(
        &group_too_long[0],
        lsig_too_long,
        &group_too_long,
        0,
        &mut budget_fail,
        &consensus,
    )
    .expect_err("a 1001-byte LogicSig must be rejected before pooling (absolute cap)");
    assert!(err.to_string().contains("too long"), "{err}");
    // Confirm the group-pool check alone would NOT have caught this at v18
    // (pool = 2 * 1000 = 2000, unconditionally) -- it's genuinely the
    // absolute per-txn cap doing the rejecting, matching go's actual code path.
    assert!(
        algo_validate::signature::logic_sig_group_size_check(&group_too_long, &consensus).is_ok(),
        "the pooled group check alone does not gate this at v18; the absolute cap does"
    );
}

/// Mirrors go-algorand's `TestLogicSigSizeAfterPooling`
/// (`test/e2e-go/features/transactions/logicsig_test.go#L46`): once
/// `EnableLogicSigSizePooling` is true, the group's total LogicSig budget is
/// `len(group) * LogicSigMaxSize` (2 * 1000 = 2000 for the 2-txn group
/// go's `testLogicSize` submits, since the companion payment contributes no
/// LogicSig bytes of its own) -- a single LogicSig may consume the whole
/// pooled budget: 2000 bytes accepted, 2001 rejected.
#[test]
fn logicsig_group_size_check_after_pooling_boundary() {
    // v41: pooling is on (introduced at v40) but the per-byte txn surcharge
    // (introduced at v42) is still zero, matching go's pre-size-pricing
    // "after pooling" nettemplate -- program bytes are pool-capped, not fee-priced.
    let consensus =
        algo_types::consensus::consensus_params_for_version(algo_types::consensus::CONSENSUS_V41)
            .expect("v41 must be a known protocol version");
    assert!(consensus.enable_logicsig_size_pooling);
    assert_eq!(consensus.per_byte_txn_surcharge, 0);
    assert_eq!(consensus.logic_sig_max_size, 1000);

    let group_ok = two_txn_group_with_logicsig(2000);
    assert!(
        algo_validate::signature::logic_sig_group_size_check(&group_ok, &consensus).is_ok(),
        "a 2000-byte LogicSig must fit the pooled 2-txn-group budget"
    );

    let group_too_long = two_txn_group_with_logicsig(2001);
    let err = algo_validate::signature::logic_sig_group_size_check(&group_too_long, &consensus)
        .expect_err("a 2001-byte LogicSig must exceed the pooled 2-txn-group budget");
    assert!(
        err.to_string().contains("more than the available pool"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// verify_transaction_signature_with_tracer (go: TestTxnGroupWithTracer,
// data/transactions/verify/txn_test.go)
// ---------------------------------------------------------------------------
//
// go's TestTxnGroupWithTracer verifies a 3-txn group (LogicSig payment,
// normal app call, LogicSig app call) through TxnGroup's tracer-threading
// path and asserts BeforeProgram/BeforeOpcode/AfterOpcode/AfterProgram fire
// for the two LogicSig-signed members and *not* for the plain-signed one.
// algod-rust's tracer-threading entry point is
// `verify_transaction_signature_with_tracer`; this test exercises it
// directly (not just the non-tracer `verify_transaction_signature` alias)
// over a simplified 2-txn group -- one LogicSig-signed, one plain-signed --
// and checks the same "events fire for the LogicSig member only" property.

/// A minimal [`EvalTracer`] that records `before_program`/`after_program`
/// calls, enough to check which group members triggered LogicSig execution.
#[derive(Default)]
struct RecordingTracer {
    programs: Vec<(ProgramType, bool /* pass */)>,
}

impl EvalTracer for RecordingTracer {
    fn before_program(&mut self, _program_type: ProgramType, _program_hash: [u8; 32]) {}

    fn after_program(&mut self, program_type: ProgramType, pass: bool, _error: Option<&str>) {
        self.programs.push((program_type, pass));
    }
}

fn signing_key_from_seed(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

/// A validly single-sig-signed pay transaction (sender's key really signs
/// the canonical "TX"-prefixed encoding), so real ed25519 verification
/// passes without going through the LogicSig path at all.
fn plain_signed_txn(note: u64) -> SignedTransaction {
    use ed25519_dalek::Signer;
    let key = signing_key_from_seed(0x55);
    let sender = Address(key.verifying_key().to_bytes());
    let txn = Transaction {
        txn_type: "pay".into(),
        sender,
        fee: 1_000,
        first_valid: Round(1),
        last_valid: Round(1000),
        receiver: Address([0x42; 32]),
        amount: 1,
        note: serde_bytes::ByteBuf::from(note.to_be_bytes().to_vec()),
        ..Default::default()
    };
    let canonical = algo_codec::canonical_encode_transaction(&txn);
    let mut msg = Vec::with_capacity(2 + canonical.len());
    msg.extend_from_slice(b"TX");
    msg.extend_from_slice(&canonical);
    let sig = key.sign(&msg);
    SignedTransaction {
        txn,
        sig: sig.to_bytes(),
        ..Default::default()
    }
}

#[test]
fn verify_transaction_signature_with_tracer_fires_only_for_logicsig_member() {
    // Member 0: LogicSig-signed (int 1 approves unconditionally).
    let lsig_program = prog(6, &[0x81, 0x01]); // pushint 1
    let lsig_stxn = make_contract_account_txn(&lsig_program);

    // Member 1: plain single-sig, no LogicSig at all.
    let plain_stxn = plain_signed_txn(1);

    let group = vec![lsig_stxn, plain_stxn];
    let mut budget = GroupBudget::for_logicsig(group.len());
    let mut tracer = RecordingTracer::default();
    let consensus = ConsensusParams::default();

    for (i, stx) in group.iter().enumerate() {
        let result = verify_transaction_signature_with_tracer(
            stx,
            &group,
            i,
            &mut budget,
            &consensus,
            Some(&mut tracer),
            None,
        );
        assert!(
            result.is_ok(),
            "member {i} must verify successfully: {:?}",
            result.err()
        );
    }

    assert_eq!(
        tracer.programs,
        vec![(ProgramType::LogicSig, true)],
        "the tracer must record exactly one LogicSig program run (for member 0, \
         approving), and nothing for member 1 (plain-signed, no LogicSig program)"
    );
}
