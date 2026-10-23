# PoC Artefacts — `AUDIT-20261023-105644-claude-opus-4-8` (`ba9c86e5`)

This directory contains standalone reproduction tests and byte-vector PoCs for the findings in `audits/reports/2026-10-23_105644_claude-opus-4-8_ba9c86e5.md`.

---

## 1. `[FIND-ba9c86e5-01]` — Program-less (`orphan`) `LogicSig` + `Sig`/`Msig`/`PQsig` Divergence & Pre-v42 Size-Pool Bypass

### 1a. Dual-signature acceptance via empty `LogicSig` (`has_lsig` vs `s.Lsig.HasProgram()`)

In `go-algorand` (`../go-algorand/data/transactions/verify/txn.go:322-357`), `checkTxnSigTypeCounts` counts `s.Lsig` as a signature category **only** when `s.Lsig.HasProgram()` (`len(s.Lsig.Logic) != 0`).
In `algod-rust` (`crates/core/algo-validate/src/signature.rs:1168-1172`), `verify_transaction_signature_with_tracer` counts `let has_lsig = stx.lsig.is_some();`.

```rust
// Reproducer test (can be run in `crates/core/algo-validate/tests/signature_test.rs`)
#[test]
fn poc_find_ba9c86e5_01a_valid_sig_with_empty_lsig_and_args_pre_v42() {
    use algo_avm::group::GroupBudget;
    use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V41};
    use algo_types::{Address, LogicSig, Round, SignedTransaction, Transaction};
    use algo_validate::{logic_sig_group_size_check, verify_transaction_signature};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_bytes::ByteBuf;

    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let sender = Address(signing_key.verifying_key().to_bytes());

    let txn = Transaction {
        txn_type: "pay".into(),
        sender,
        fee: 1000,
        first_valid: Round(1),
        last_valid: Round(100),
        receiver: Address([0x11; 32]),
        amount: 1000,
        ..Default::default()
    };

    let canonical = algo_codec::canonical_encode_transaction(&txn);
    let mut msg = b"TX".to_vec();
    msg.extend_from_slice(&canonical);
    let sig = signing_key.sign(&msg).to_bytes();

    // Attach an orphan LogicSig with empty `logic` (`HasProgram() == false`)
    // and 2,000 bytes of args (> v41's 1,000-byte LogicSigMaxSize!).
    let stx = SignedTransaction {
        txn,
        sig,
        lsig: Some(LogicSig {
            logic: ByteBuf::new(),
            args: Some(vec![ByteBuf::from(vec![0xAA; 2000])]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let v41 = consensus_params_for_version(CONSENSUS_V41).unwrap();
    let group = vec![stx.clone()];

    // 1. Go's `logicSigGroupSizeCheck` at v41 (where MaxAbsoluteLogicSigProgramSize == 0 <= LogicSigMaxSize)
    //    skips `!lsig.HasProgram()` (`if !poolOrphanLSigArgs { continue }`), so it returns Ok(()).
    assert!(logic_sig_group_size_check(&group, &v41).is_ok());

    // 2. Go's `checkTxnSigTypeCounts` sees `!s.Sig.Blank()` (1) and `s.Lsig.HasProgram() == false` (0),
    //    so `numSigCategories == 1` (regularSig) and Go ACCEPTS the transaction!
    //    In algod-rust, `has_sig = true` (1) and `has_lsig = stx.lsig.is_some()` (1) -> count == 2 -> REJECTED!
    let mut budget = GroupBudget::for_logicsig(1);
    let rust_res = verify_transaction_signature(&stx, &group, 0, &mut budget, &v41);
    assert!(
        rust_res.unwrap_err().to_string().contains("signedtxn should have only one type of signature, found 2"),
        "algod-rust rejects a transaction that go-algorand accepts at v40/v41"
    );
}
```

### 1b. Gossip & Pool Admission Missing `logic_sig_group_size_check`

In `bin/algod-rust/src/commands/participate.rs:1693-1848` (`SimpleBlockEvaluator::validate_group_stateless_inner`) and `crates/core/algo-validate/src/verified_txn_cache.rs:412-462` (`verify_transaction_group_cached`), `logic_sig_group_size_check` is **never called**.

```rust
#[test]
fn poc_find_ba9c86e5_01b_pool_admission_misses_logicsig_group_size_check() {
    use algo_types::consensus::{consensus_params_for_version, CONSENSUS_V42};
    use algo_types::{Address, LogicSig, Round, SignedTransaction, Transaction};
    use algo_validate::{
        logic_sig_group_size_check, verify_transaction_group_cached, SpecialAddresses,
        VerificationContext, VerifiedTransactionCache,
    };
    use serde_bytes::ByteBuf;

    let v42 = consensus_params_for_version(CONSENSUS_V42).unwrap();
    // Single LogicSig program `int 1` (bytes: [0x01, 0x20, 0x01, 0x01, 0x22])
    let logic = vec![0x01, 0x20, 0x01, 0x01, 0x22];
    let sender = algo_validate::hash_program(&logic);

    let txn = Transaction {
        txn_type: "pay".into(),
        sender,
        fee: 10_000,
        first_valid: Round(1),
        last_valid: Round(100),
        ..Default::default()
    };

    // Attach 2,000 bytes of args (each <= 4096 MaxLogicSigArgSize, but sum > 1000 LogicSigMaxSize)
    let stx = SignedTransaction {
        txn,
        lsig: Some(LogicSig {
            logic: ByteBuf::from(logic),
            args: Some(vec![ByteBuf::from(vec![0x11; 2000])]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let group = vec![stx];
    // Block validation (`logic_sig_group_size_check`) rejects this group:
    assert!(logic_sig_group_size_check(&group, &v42).is_err());

    // But `verify_transaction_group_cached` (used by BatchVerifier and SimpleBlockEvaluator) ACCEPTS and CACHES it!
    let cache = VerifiedTransactionCache::new(100);
    let ctx = VerificationContext {
        spec_addrs: SpecialAddresses::default(),
        consensus_version: "v42".into(),
    };
    assert!(
        verify_transaction_group_cached(&group, &ctx, &v42, &cache).is_ok(),
        "verify_transaction_group_cached accepts oversized LogicSig args and caches the group!"
    );
}
```

---

## 2. `[FIND-ba9c86e5-02]` — Gossip `decode_tx_message` (`rmp_serde`) Bypassing `allocbound` & `codec:",required"` Checks

In `crates/node/algo-network/src/tx_tag_handler.rs:730-776`, `decode_tx_message` uses `rmp_serde::from_read::<_, SignedTransaction>` instead of `SignedTransaction::decode_from_reader` + `check_msgpack_depth`.
1. No `check_msgpack_depth` pre-scan is run before `rmp_serde::from_read`, so a deeply nested msgpack value inside `dt` (`eval_delta`) or an unknown field can recurse on the thread stack.
2. `rmp_serde` does not enforce `go-algorand`'s `codec:",required"` checks (`Transaction.type` non-empty, `Transaction.snd` non-zero, `MultisigSig.v/thr/subsig` non-zero, `LogicSig.l` present) or `allocbound` limits at decode time, so a malformed gossip `TX` message with `"type": ""` or `"snd": [0; 32]` is NOT treated as a `TxTagError::Decode` (which disconnects the misbehaving peer per issue #1491), and instead passes `decode_tx_message` and is only dropped as `Ignore` by `pool.test()`.

---

## 3. `[FIND-ba9c86e5-03]` — ARC-4 Static Array Length Overflow & Exponential Allocation in `algo-abi`

In `crates/core/algo-abi/src/lib.rs:144-169` (`AbiType::byte_len`) and `crates/core/algo-abi/src/lib.rs:885-897` (`decode` / `encode_array_as_tuple`):
- `parse_static_array` allows static array lengths up to `u16::MAX` (`65535`) and nesting depth up to `MAX_ABI_DEPTH` (`64`).
- A short 40-byte type string such as `"uint8[65535][65535][65535]"` parses in $O(1)$ time, but calling `decode` on `AbiType::ArrayStatic` constructs `vec![(**elem).clone(); *len]` at each level ($65535^3$ elements) or overflows `usize` in `elem.byte_len()? * len` (`crates/core/algo-abi/src/lib.rs:154`).
- This is reachable from `GET /v2/applications/{id}/box?name=abi:...` and `GET /v2/applications/{id}/boxes?prefix=abi:...` (`crates/node/algo-rest-api/src/box_name.rs:73-78`).
