//! Wallet signing operations — `sign_transaction`, `sign_program`,
//! `sign_multisig_transaction`, `sign_multisig_program`.
//!
//! Ported from `daemon/kmd/wallet/driver/sqlite.go` (v4.6.0-stable):
//! `SignTransaction` (sqlite.go:1113), `SignProgram` (sqlite.go:1145),
//! `MultisigSignTransaction` (sqlite.go:1175), `MultisigSignProgram`
//! (sqlite.go:1266).
//!
//! Domain separators (`protocol/hash.go`):
//! - Transactions: `"TX" || canonical_encode(txn)` → Ed25519
//! - Programs: `"Program" || program_bytes` → Ed25519
//! - Multisig programs (modern path): `"MsigProgram" || addr || program`
//!   → multisig
//!
//! TASK-210 ships the four-method shape called out in the plan; the
//! optional `auth_addr` (rekey'd accounts) and `use_legacy_msig`
//! switches Go's API carries land alongside the REST handler that
//! actually exposes them (TASK-216).

use algo_consensus_crypto::multisig::{
    multisig_addr_gen, multisig_assemble, multisig_sign, Error as MultisigError,
};
use algo_types::{Address, MultisigSig, SignedTransaction, Transaction};
use ed25519_dalek::SigningKey;

use crate::error::{Error, Result};
use crate::keys::{ADDRESS_LEN, SECRET_KEY_LEN};
use crate::wallet::Wallet;

/// Domain-separator prefix for transaction signing
/// (`protocol/hash.go: "TX"`).
const TX_TAG: &[u8] = b"TX";

/// Domain-separator prefix for raw program signing
/// (`protocol/hash.go: "Program"`).
const PROGRAM_TAG: &[u8] = b"Program";

/// Domain-separator prefix for the modern multisig-program path
/// (`protocol/hash.go: "MsigProgram"`, used by
/// `logic.MultisigProgram.ToBeHashed` at
/// `data/transactions/logic/program.go:39`).
const MSIG_PROGRAM_TAG: &[u8] = b"MsigProgram";

/// Compute the canonical bytes Ed25519 signs over a transaction:
/// `"TX" || canonical_encode(txn)`. Mirrors what Go's
/// `transactions.Transaction.Sign` produces (see also the existing
/// `algo-validate::signature::verify_signed_txn` consumer at
/// `crates/core/algo-validate/src/block.rs:710-714`).
fn txn_signing_message(txn: &Transaction) -> Vec<u8> {
    let canonical = algo_codec::canonical_encode_transaction(txn);
    let mut msg = Vec::with_capacity(TX_TAG.len() + canonical.len());
    msg.extend_from_slice(TX_TAG);
    msg.extend_from_slice(&canonical);
    msg
}

fn program_signing_message(program: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(PROGRAM_TAG.len() + program.len());
    msg.extend_from_slice(PROGRAM_TAG);
    msg.extend_from_slice(program);
    msg
}

fn msig_program_signing_message(addr: &[u8; ADDRESS_LEN], program: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(MSIG_PROGRAM_TAG.len() + ADDRESS_LEN + program.len());
    msg.extend_from_slice(MSIG_PROGRAM_TAG);
    msg.extend_from_slice(addr);
    msg.extend_from_slice(program);
    msg
}

/// Recover the 32-byte Ed25519 signing seed from an on-disk expanded
/// secret key (`seed || pubkey`).
fn signing_key_from_expanded(expanded: &[u8; SECRET_KEY_LEN]) -> SigningKey {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&expanded[..32]);
    SigningKey::from_bytes(&seed)
}

/// Map a multisig-primitive error onto the wallet's coarse `Error`
/// surface. We don't currently expose the multisig variant — Go's
/// REST handlers map to generic 400/500 codes, and TASK-216 will pick
/// a consistent mapping at the HTTP layer.
fn map_multisig_err(_e: MultisigError) -> Error {
    Error::MultisigInvalid
}

impl Wallet {
    /// Sign a transaction. Mirrors `SignTransaction` (sqlite.go:1113).
    ///
    /// When `public_key` is `None`, the signer is inferred from the
    /// transaction's `sender` field — matches Go's "if pk == zero,
    /// use tx.Src()" branch (sqlite.go:1122).
    ///
    /// Returns the **msgpack-encoded `SignedTransaction`** that the
    /// SDK is expected to submit to algod.
    pub fn sign_transaction(
        &self,
        txn: &Transaction,
        public_key: Option<[u8; ADDRESS_LEN]>,
        password: &[u8],
    ) -> Result<Vec<u8>> {
        self.check_password(password)?;
        let signer_addr = public_key.unwrap_or_else(|| address_to_bytes(&txn.sender));

        let expanded = self.export_key(&signer_addr, password)?;
        let signing = signing_key_from_expanded(&expanded);

        use ed25519_dalek::Signer;
        let msg = txn_signing_message(txn);
        let sig = signing.sign(&msg).to_bytes();

        let stx = SignedTransaction {
            txn: txn.clone(),
            sig,
            msig: None,
            lsig: None,
            // auth_addr is None unless the caller passed a rekey override
            // — Go exposes that on the REST surface only (TASK-216).
            auth_addr: None,
            ..SignedTransaction::default()
        };
        Ok(algo_codec::canonical_encode_signed_transaction(&stx))
    }

    /// Sign raw program bytes for `address`. Mirrors `SignProgram`
    /// (sqlite.go:1145). Returns the raw 64-byte Ed25519 signature
    /// over `"Program" || program`.
    pub fn sign_program(
        &self,
        program: &[u8],
        address: [u8; ADDRESS_LEN],
        password: &[u8],
    ) -> Result<[u8; 64]> {
        self.check_password(password)?;
        let expanded = self.export_key(&address, password)?;
        let signing = signing_key_from_expanded(&expanded);
        use ed25519_dalek::Signer;
        let msg = program_signing_message(program);
        Ok(signing.sign(&msg).to_bytes())
    }

    /// Produce or extend a multisig transaction signature. Mirrors
    /// `MultisigSignTransaction` (sqlite.go:1175).
    ///
    /// - If `partial` is empty (`version == 0 && threshold == 0 &&
    ///   subsigs.is_empty()`), look up the preimage from the wallet's
    ///   `msig_addrs` table using the transaction's sender as the
    ///   multisig address and produce a fresh single-signer multisig.
    /// - Otherwise, validate that `public_key` is one of the subsig
    ///   keys in `partial`, sign with that key, and merge into
    ///   `partial`.
    ///
    /// `auth_signer` carries the rekey/auth-address override from
    /// Go's `signer` argument (sqlite.go:1175). When present, the
    /// partial's derived multisig address is allowed to match
    /// **either** `txn.sender` **or** `auth_signer` — Go's check at
    /// sqlite.go:1224. Pass `None` for the common non-rekeyed case
    /// (the multisig IS the sender).
    pub fn sign_multisig_transaction(
        &self,
        txn: &Transaction,
        partial: &MultisigSig,
        public_key: [u8; ADDRESS_LEN],
        password: &[u8],
        auth_signer: Option<[u8; ADDRESS_LEN]>,
    ) -> Result<MultisigSig> {
        self.check_password(password)?;

        let msg = txn_signing_message(txn);
        let sender = address_to_bytes(&txn.sender);

        // Fresh-sign path looks up the preimage by the txn sender;
        // the rekey override is irrelevant when no partial exists
        // because the wallet only stores preimages under one address.
        //
        // Partial-extend path: derived multisig address must match
        // either the sender or the auth-signer (Go: sqlite.go:1224
        // — `addr != tx.Src() && addr != signer`).
        let mut allowed: Vec<[u8; ADDRESS_LEN]> = vec![sender];
        if let Some(s) = auth_signer {
            if s != sender {
                allowed.push(s);
            }
        }

        self.sign_multisig_inner(&msg, &allowed, partial, public_key, password)
    }

    /// Produce or extend a multisig program signature. Mirrors
    /// `MultisigSignProgram` (sqlite.go:1266). When
    /// `use_legacy_msig=true`, signs the **legacy** `"Program" ||
    /// raw_program` message (`logic.Program(data)` in Go); when
    /// `false`, signs the **modern** `"MultisigProgram" || addr ||
    /// program` message (`logic.MultisigProgram{Addr, Program}`).
    /// The legacy path is what older SDKs (and existing
    /// already-signed partial multisigs) expect.
    pub fn sign_multisig_program(
        &self,
        program: &[u8],
        msig_address: [u8; ADDRESS_LEN],
        partial: &MultisigSig,
        public_key: [u8; ADDRESS_LEN],
        password: &[u8],
        use_legacy_msig: bool,
    ) -> Result<MultisigSig> {
        self.check_password(password)?;
        let msg = if use_legacy_msig {
            // Go: `crypto.MultisigSign(logic.Program(data), ...)`
            // (sqlite.go:1302).  `logic.Program` prepends the same
            // `"Program"` tag as the non-multisig program sign path.
            program_signing_message(program)
        } else {
            msig_program_signing_message(&msig_address, program)
        };
        // The program path has no rekey concept — only one allowed
        // address (sqlite.go:1317).
        self.sign_multisig_inner(&msg, &[msig_address], partial, public_key, password)
    }

    /// Shared body for the multisig sign-or-extend flow. `allowed_addrs`
    /// is the set of multisig addresses the partial may resolve to —
    /// the txn-sign path passes `{sender, auth_signer?}` per Go's
    /// check at sqlite.go:1224; the program-sign path passes just the
    /// msig address. The fresh path looks up the preimage by
    /// `allowed_addrs[0]` (the sender / msig address).
    fn sign_multisig_inner(
        &self,
        msg: &[u8],
        allowed_addrs: &[[u8; ADDRESS_LEN]],
        partial: &MultisigSig,
        signer_pk: [u8; ADDRESS_LEN],
        password: &[u8],
    ) -> Result<MultisigSig> {
        let expanded = self.export_key(&signer_pk, password)?;
        let signing = signing_key_from_expanded(&expanded);

        let partial_is_empty =
            partial.version == 0 && partial.threshold == 0 && partial.subsigs.is_empty();

        let (version, threshold, pks) = if partial_is_empty {
            // No partial — look up the preimage by the primary
            // allowed address (sender for txns, msig_address for
            // programs).
            let lookup_addr = allowed_addrs[0];
            let pre = self.lookup_multisig(&lookup_addr)?;
            (pre.version, pre.threshold, pre.pks)
        } else {
            // Validate: derived address from partial must equal one
            // of the allowed addresses. Matches Go's sqlite.go:1224
            // (sender OR signer) and sqlite.go:1317 (just src) —
            // passed in as a single- or two-element slice.
            let derived = multisig_addr_gen_from_partial(partial).map_err(map_multisig_err)?;
            if !allowed_addrs.contains(&derived.0) {
                return Err(Error::MultisigInvalid);
            }
            // Signer's pk must appear in the preimage (Go: errMsigWrongKey
            // at sqlite.go:1230/1322).
            if !partial.subsigs.iter().any(|s| s.public_key == signer_pk) {
                return Err(Error::MultisigInvalid);
            }
            let pks: Vec<[u8; 32]> = partial.subsigs.iter().map(|s| s.public_key).collect();
            (partial.version, partial.threshold, pks)
        };

        let fresh =
            multisig_sign(msg, version, threshold, &pks, &signing).map_err(map_multisig_err)?;

        if partial_is_empty {
            Ok(fresh)
        } else {
            // Merge via the consensus-crypto primitive — both
            // `partial` and `fresh` are `algo_types::MultisigSig`,
            // which is what `multisig_assemble` accepts. No
            // conversion needed.
            let assembled =
                multisig_assemble(&[partial.clone(), fresh]).map_err(map_multisig_err)?;
            Ok(assembled)
        }
    }
}

// ---- Helpers ---------------------------------------------------------------

fn address_to_bytes(addr: &Address) -> [u8; ADDRESS_LEN] {
    addr.0
}

/// Derive the multisig address from a partial `MultisigSig` — uses
/// the public keys embedded in each subsig. Mirrors Go's
/// `crypto.MultisigAddrGenWithSubsigs`.
fn multisig_addr_gen_from_partial(
    partial: &MultisigSig,
) -> std::result::Result<Address, MultisigError> {
    let pks: Vec<[u8; 32]> = partial.subsigs.iter().map(|s| s.public_key).collect();
    multisig_addr_gen(partial.version, partial.threshold, &pks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txn_signing_message_starts_with_tx_tag() {
        let txn = Transaction::default();
        let msg = txn_signing_message(&txn);
        assert!(msg.starts_with(b"TX"));
        let canonical = algo_codec::canonical_encode_transaction(&txn);
        assert_eq!(&msg[2..], canonical.as_slice());
    }

    #[test]
    fn program_signing_message_starts_with_program_tag() {
        let prog = b"\x01\x02\x03\x04";
        let msg = program_signing_message(prog);
        assert_eq!(&msg[..7], b"Program");
        assert_eq!(&msg[7..], prog);
    }

    #[test]
    fn msig_program_signing_message_layout() {
        let addr = [0x55u8; 32];
        let prog = b"hello";
        let msg = msig_program_signing_message(&addr, prog);
        assert_eq!(&msg[..11], b"MsigProgram");
        assert_eq!(&msg[11..43], &addr);
        assert_eq!(&msg[43..], prog);
    }

    #[test]
    fn signing_key_from_expanded_round_trips() {
        let seed = [0x42u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let pk = signing.verifying_key().to_bytes();
        let mut expanded = [0u8; SECRET_KEY_LEN];
        expanded[..32].copy_from_slice(&seed);
        expanded[32..].copy_from_slice(&pk);
        let recovered = signing_key_from_expanded(&expanded);
        assert_eq!(recovered.to_bytes(), seed);
    }
}
