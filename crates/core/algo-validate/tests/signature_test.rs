use algo_codec::decode_block_response;
use algo_validate::verify_transaction_signature;
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
            if full.txn.genesis_hash.is_empty() {
                full.txn.genesis_hash = br.block.genesis_hash.clone();
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
            for (i, stx) in txns.iter().enumerate() {
                verify_transaction_signature(stx).unwrap_or_else(|e| {
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
        for (i, stx) in txns.iter().enumerate() {
            verify_transaction_signature(stx).unwrap_or_else(|e| {
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
