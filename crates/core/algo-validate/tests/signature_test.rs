use algo_avm::group::GroupBudget;
use algo_codec::decode_block_response;
use algo_types::consensus::ConsensusParams;
use algo_types::{Address, LogicSig, Round, SignedTransaction, Transaction};
use algo_validate::signature::verify_logicsig;
use algo_validate::verify_transaction_signature;
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
