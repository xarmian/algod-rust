#![no_main]

use libfuzzer_sys::fuzz_target;

use algo_ledger::{apply_transaction, ApplyContext, LedgerState};
use algo_types::{Address, SignedTransaction};

fuzz_target!(|data: &[u8]| {
    // Try to deserialize arbitrary bytes as a SignedTransaction via msgpack.
    // Most byte sequences will fail — that's fine, we just return early.
    let stx: SignedTransaction = match rmp_serde::from_slice(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Build a minimal LedgerState with the sender funded so we can exercise
    // the apply path. Fee sink gets a large balance too.
    let mut state = LedgerState::default();

    let sender = stx.txn.sender;
    let fee_sink = Address([0xFFu8; 32]);

    // Fund sender generously
    let mut sender_acct = algo_types::AccountData::default();
    sender_acct.micro_algos = 10_000_000_000; // 10k Algos
    state.accounts.insert(sender, sender_acct);

    // Fund fee sink
    let mut fee_sink_acct = algo_types::AccountData::default();
    fee_sink_acct.micro_algos = 10_000_000_000;
    state.accounts.insert(fee_sink, fee_sink_acct);

    // Also fund receiver if it is a payment
    if !stx.txn.receiver.is_zero() {
        state
            .accounts
            .entry(stx.txn.receiver)
            .or_insert_with(|| {
                let mut a = algo_types::AccountData::default();
                a.micro_algos = 1_000_000;
                a
            });
    }

    let ctx = ApplyContext::new_replay(0, fee_sink, 1000);

    // Run the transaction. Errors are expected and fine — we only care about panics.
    let _ = apply_transaction(&mut state, &stx, &ctx, 0);
});
