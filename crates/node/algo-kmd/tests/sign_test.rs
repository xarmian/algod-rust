//! Integration tests for wallet signing operations (TASK-210).
//!
//! End-to-end coverage:
//! - Create wallet → generate key → sign payment txn → verify the
//!   resulting `SignedTransaction` under `algo_validate::verify_single_sig`.
//! - Sign raw program bytes → verify the 64-byte Ed25519 signature
//!   against `"Program" || data` directly.
//! - Multisig: import 3 known keys, register their 2-of-3 multisig
//!   preimage, sign with two members, assemble → verify under
//!   `algo_validate::verify_multisig`.
//!
//! These tests prove the signing logic produces signatures other parts
//! of the system accept. The on-the-wire byte-equality vs go-algorand
//! is covered separately at the REST integration layer (TASK-216 / B8).

use algo_codec::canonical_encode_signed_transaction;
use algo_consensus_crypto::multisig::multisig_addr_gen;
use algo_kmd::{
    config::ScryptParams, Error, WalletDriver, WalletDriverConfig, ADDRESS_LEN, SECRET_KEY_LEN,
};
use algo_types::{
    Address, MultisigSig as AtMultisigSig, Round, SignedTransaction, Transaction, TxnType,
};
use algo_validate::signature::{verify_multisig, verify_single_sig};
use ed25519_dalek::SigningKey;
use tempfile::TempDir;

fn weak_cfg(dir: &std::path::Path) -> WalletDriverConfig {
    WalletDriverConfig {
        wallets_dir: dir.to_path_buf(),
        scrypt_params: ScryptParams {
            scrypt_n: 1024,
            scrypt_r: 1,
            scrypt_p: 1,
        },
        allow_unsafe_scrypt: true,
    }
}

/// Build a deterministic 64-byte expanded ed25519 SK for use with
/// `Wallet::import_key`. `seed_byte` lets each call produce a
/// distinct key.
fn expanded_sk_for_seed(seed_byte: u8) -> [u8; SECRET_KEY_LEN] {
    let seed = [seed_byte; 32];
    let signing = SigningKey::from_bytes(&seed);
    let pk: [u8; 32] = signing.verifying_key().to_bytes();
    let mut sk = [0u8; SECRET_KEY_LEN];
    sk[..32].copy_from_slice(&seed);
    sk[32..].copy_from_slice(&pk);
    sk
}

fn imported_addr(seed_byte: u8) -> [u8; ADDRESS_LEN] {
    let seed = [seed_byte; 32];
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

fn payment_txn(sender: [u8; ADDRESS_LEN], receiver: [u8; ADDRESS_LEN]) -> Transaction {
    Transaction {
        txn_type: TxnType::Pay,
        sender: Address(sender),
        fee: 1000,
        first_valid: Round(1),
        last_valid: Round(1000),
        amount: 42,
        receiver: Address(receiver),
        genesis_id: "test-v1".into(),
        genesis_hash: [9u8; 32],
        ..Default::default()
    }
}

#[test]
fn sign_transaction_round_trips_through_verify() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver
        .create_wallet(b"sign", b"id-s", b"pw", Some([7u8; 32]))
        .unwrap();
    let mut wallet = driver.fetch_wallet(b"id-s").unwrap();
    wallet.init(b"pw").unwrap();

    // Generate the signing key. The wallet derives it from the MDK,
    // returning the address.
    let sender = wallet.generate_key().unwrap();
    let receiver: [u8; 32] = [0x55u8; 32];

    let txn = payment_txn(sender, receiver);
    let encoded = wallet.sign_transaction(&txn, None, b"pw").unwrap();

    // Decode + verify the SignedTransaction.
    let stx: SignedTransaction = rmp_serde::from_slice(&encoded).expect("decode SignedTransaction");
    verify_single_sig(&stx).expect("Rust-signed txn must verify under algo-validate");
    assert_eq!(stx.txn.sender, Address(sender));
    assert_eq!(stx.txn.amount, 42);
}

#[test]
fn sign_transaction_with_explicit_public_key() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver
        .create_wallet(b"sign-pk", b"id-spk", b"pw", Some([8u8; 32]))
        .unwrap();
    let mut wallet = driver.fetch_wallet(b"id-spk").unwrap();
    wallet.init(b"pw").unwrap();

    let signer = wallet.generate_key().unwrap();
    let txn = payment_txn(signer, [0x11u8; 32]);

    // Explicit public_key matches the sender → still verifies.
    let encoded = wallet.sign_transaction(&txn, Some(signer), b"pw").unwrap();
    let stx: SignedTransaction = rmp_serde::from_slice(&encoded).unwrap();
    verify_single_sig(&stx).expect("explicit-pk path must verify");
}

#[test]
fn sign_transaction_rejects_wrong_password() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"wp", b"id-wp", b"pw", None).unwrap();
    let mut wallet = driver.fetch_wallet(b"id-wp").unwrap();
    wallet.init(b"pw").unwrap();
    let addr = wallet.generate_key().unwrap();
    let txn = payment_txn(addr, [0u8; 32]);
    let err = wallet.sign_transaction(&txn, None, b"wrong").unwrap_err();
    assert!(matches!(err, Error::Decrypt), "got {err:?}");
}

#[test]
fn sign_program_produces_verifiable_ed25519_signature() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver
        .create_wallet(b"prog", b"id-pr", b"pw", None)
        .unwrap();
    let mut wallet = driver.fetch_wallet(b"id-pr").unwrap();
    wallet.init(b"pw").unwrap();

    let addr = wallet.generate_key().unwrap();
    let program: Vec<u8> = vec![0x02, 0x20, 0x01, 0x01, 0x22, 0x43]; // arbitrary TEAL-ish bytes
    let sig = wallet.sign_program(&program, addr, b"pw").unwrap();

    // Verify the signature directly: "Program" || program signed by addr.
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let mut msg = Vec::with_capacity(7 + program.len());
    msg.extend_from_slice(b"Program");
    msg.extend_from_slice(&program);
    let vk = VerifyingKey::from_bytes(&addr).unwrap();
    let sig_obj = Signature::from_bytes(&sig);
    vk.verify(&msg, &sig_obj)
        .expect("sign_program output must verify");
}

#[test]
fn sign_multisig_transaction_assembles_and_verifies() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"ms", b"id-ms", b"pw", None).unwrap();
    let mut wallet = driver.fetch_wallet(b"id-ms").unwrap();
    wallet.init(b"pw").unwrap();

    // Import three known keys.
    let pk_a = imported_addr(0x21);
    let pk_b = imported_addr(0x22);
    let pk_c = imported_addr(0x23);
    wallet.import_key(&expanded_sk_for_seed(0x21)).unwrap();
    wallet.import_key(&expanded_sk_for_seed(0x22)).unwrap();
    wallet.import_key(&expanded_sk_for_seed(0x23)).unwrap();

    // Register a 2-of-3 multisig with those keys.
    let pks = vec![pk_a, pk_b, pk_c];
    let msig_addr = wallet.import_multisig(1, 2, &pks).unwrap();
    // Cross-check the address derivation matches the standalone primitive.
    assert_eq!(msig_addr, multisig_addr_gen(1, 2, &pks).unwrap().0);

    // Build a payment transaction where the sender IS the multisig.
    let txn = payment_txn(msig_addr, [0x33u8; 32]);

    // Signer A goes first — empty `partial` triggers the "create new
    // multisig" path that reads the preimage from the wallet.
    let empty_partial = AtMultisigSig::default();
    let part_a = wallet
        .sign_multisig_transaction(&txn, &empty_partial, pk_a, b"pw", None)
        .unwrap();
    assert_eq!(part_a.version, 1);
    assert_eq!(part_a.threshold, 2);
    assert_eq!(part_a.subsigs.len(), 3);

    // Signer B extends part_a — partial path validates the derived
    // address matches and the signer's pk is in the subsigs list.
    let part_ab = wallet
        .sign_multisig_transaction(&txn, &part_a, pk_b, b"pw", None)
        .unwrap();
    assert_eq!(part_ab.subsigs.len(), 3);
    // Both A and B subsigs must now be non-zero.
    assert!(part_ab.subsigs[0].signature != [0u8; 64]);
    assert!(part_ab.subsigs[1].signature != [0u8; 64]);

    // Verify under algo-validate by attaching the multisig to the
    // SignedTransaction.
    let stx = SignedTransaction {
        txn: txn.clone(),
        sig: [0u8; 64],
        msig: Some(part_ab.clone()),
        lsig: None,
        auth_addr: None,
        ..SignedTransaction::default()
    };
    verify_multisig(&stx, &part_ab).expect("2-of-3 multisig must verify");

    // Sanity: the canonical encode round-trips so the response payload
    // a REST handler would return (msgpack-encoded MultisigSig) is
    // well-formed.
    let _ = canonical_encode_signed_transaction(&stx);
}

#[test]
fn sign_multisig_transaction_rejects_outside_signer() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"os", b"id-os", b"pw", None).unwrap();
    let mut wallet = driver.fetch_wallet(b"id-os").unwrap();
    wallet.init(b"pw").unwrap();

    let pk_a = imported_addr(0x31);
    let pk_b = imported_addr(0x32);
    let pk_outside = imported_addr(0x99);
    wallet.import_key(&expanded_sk_for_seed(0x31)).unwrap();
    wallet.import_key(&expanded_sk_for_seed(0x32)).unwrap();
    wallet.import_key(&expanded_sk_for_seed(0x99)).unwrap();

    let pks = vec![pk_a, pk_b];
    let msig_addr = wallet.import_multisig(1, 2, &pks).unwrap();
    let txn = payment_txn(msig_addr, [0x77u8; 32]);

    // Signer A produces the initial partial.
    let part_a = wallet
        .sign_multisig_transaction(&txn, &AtMultisigSig::default(), pk_a, b"pw", None)
        .unwrap();

    // A key that isn't in the preimage must be rejected (Go's
    // errMsigWrongKey at sqlite.go:1230).
    let err = wallet
        .sign_multisig_transaction(&txn, &part_a, pk_outside, b"pw", None)
        .unwrap_err();
    assert!(matches!(err, Error::MultisigInvalid), "got {err:?}");
}

#[test]
fn sign_multisig_transaction_accepts_auth_signer_for_rekey() {
    // Regression for Codex PR #353 round 1: Go accepts a partial
    // multisig whose derived address matches EITHER tx.Src() OR the
    // auth-signer (rekey'd accounts). We reject otherwise. This
    // simulates that rekey case: the txn's sender is a non-multisig
    // address; the multisig that actually holds signing authority
    // is the auth_signer.
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"rk", b"id-rk", b"pw", None).unwrap();
    let mut wallet = driver.fetch_wallet(b"id-rk").unwrap();
    wallet.init(b"pw").unwrap();

    let pk_a = imported_addr(0x61);
    let pk_b = imported_addr(0x62);
    wallet.import_key(&expanded_sk_for_seed(0x61)).unwrap();
    wallet.import_key(&expanded_sk_for_seed(0x62)).unwrap();

    let pks = vec![pk_a, pk_b];
    let msig_addr = wallet.import_multisig(1, 2, &pks).unwrap();

    // Sender is a standalone address; the multisig is the auth-signer.
    let other_sender = [0xEEu8; 32];
    let txn = payment_txn(other_sender, [0x77u8; 32]);

    // Bootstrap a partial directly via the standalone primitive
    // (the fresh-sign path can't reach this configuration via
    // sign_multisig_transaction because it looks up by txn.sender).
    let signing_a = SigningKey::from_bytes(&[0x61u8; 32]);
    let signing_msg = {
        let canonical = algo_codec::canonical_encode_transaction(&txn);
        let mut m = Vec::with_capacity(2 + canonical.len());
        m.extend_from_slice(b"TX");
        m.extend_from_slice(&canonical);
        m
    };
    let part_a =
        algo_consensus_crypto::multisig::multisig_sign(&signing_msg, 1, 2, &pks, &signing_a)
            .unwrap();

    // Without auth_signer, the partial's address differs from
    // txn.sender so we must reject.
    let err = wallet
        .sign_multisig_transaction(&txn, &part_a, pk_b, b"pw", None)
        .unwrap_err();
    assert!(matches!(err, Error::MultisigInvalid), "got {err:?}");

    // With the right auth_signer the partial is accepted and B
    // extends it cleanly.
    let part_ab = wallet
        .sign_multisig_transaction(&txn, &part_a, pk_b, b"pw", Some(msig_addr))
        .unwrap();
    assert_eq!(part_ab.subsigs.len(), 2);
    assert!(part_ab.subsigs[0].signature != [0u8; 64]);
    assert!(part_ab.subsigs[1].signature != [0u8; 64]);
}

#[test]
fn sign_multisig_program_produces_verifiable_signature() {
    let dir = TempDir::new().unwrap();
    let driver = WalletDriver::new(weak_cfg(dir.path())).unwrap();
    driver.create_wallet(b"mp", b"id-mp", b"pw", None).unwrap();
    let mut wallet = driver.fetch_wallet(b"id-mp").unwrap();
    wallet.init(b"pw").unwrap();

    let pk_a = imported_addr(0x41);
    let pk_b = imported_addr(0x42);
    wallet.import_key(&expanded_sk_for_seed(0x41)).unwrap();
    wallet.import_key(&expanded_sk_for_seed(0x42)).unwrap();

    let pks = vec![pk_a, pk_b];
    let msig_addr = wallet.import_multisig(1, 2, &pks).unwrap();

    let program: Vec<u8> = vec![0x02, 0x20, 0x01, 0x01, 0x22, 0x43];
    let part_a = wallet
        .sign_multisig_program(&program, msig_addr, &AtMultisigSig::default(), pk_a, b"pw")
        .unwrap();
    let part_ab = wallet
        .sign_multisig_program(&program, msig_addr, &part_a, pk_b, b"pw")
        .unwrap();
    assert!(part_ab.subsigs[0].signature != [0u8; 64]);
    assert!(part_ab.subsigs[1].signature != [0u8; 64]);

    // Direct subsig verification: each non-empty subsig must validate
    // against "MsigProgram" || addr || program for its public key.
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let mut msg = Vec::with_capacity(11 + 32 + program.len());
    msg.extend_from_slice(b"MsigProgram");
    msg.extend_from_slice(&msig_addr);
    msg.extend_from_slice(&program);
    for subsig in &part_ab.subsigs {
        if subsig.signature == [0u8; 64] {
            continue;
        }
        let vk = VerifyingKey::from_bytes(&subsig.public_key).unwrap();
        let sig = Signature::from_bytes(&subsig.signature);
        vk.verify(&msg, &sig)
            .expect("each non-empty multisig subsig must verify");
    }
}
