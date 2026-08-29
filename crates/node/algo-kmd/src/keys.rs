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

//! Per-wallet key operations — derive, import, export, list, lookup,
//! delete. Layered on top of the wallet handle from [`crate::wallet`].
//!
//! Ported from `daemon/kmd/wallet/driver/sqlite.go` (v4.6.0-stable):
//! `GenerateKey` / `generateKeyTxLocked` (sqlite.go:839, 884),
//! `ImportKey` (sqlite.go:736), `ExportKey` / `fetchSecretKey`
//! (sqlite.go:774, 786), `ListKeys` (sqlite.go:694), `DeleteKey`
//! (sqlite.go:978). The `LookupKey` shape in TASK-205 is a thin
//! existence probe over the `keys` table; it has no single Go
//! counterpart because Go inlines the `SELECT COUNT(1)` check at the
//! one call-site that needs it (sqlite.go:934).

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha512_256;

use crate::crypto::{
    decrypt_blob_with_password, encrypt_blob_with_key, PlaintextType, MASTER_KEY_LEN,
};
use crate::error::{Error, Result};
use crate::sqlite::WalletDb;
use crate::wallet::Wallet;

/// Length of an Algorand address — the raw Ed25519 public key. Aligned
/// with `crypto.Digest` (32 bytes) in the Go reference.
pub const ADDRESS_LEN: usize = 32;

/// Length of the on-disk Ed25519 secret key blob — Go stores the full
/// 64-byte "expanded" key (seed || pubkey), produced by
/// `crypto.GenerateSignatureSecrets` and encoded via `msgpackEncode`.
/// kmd-rust mirrors that shape so a key inserted by either
/// implementation round-trips through the other.
pub const SECRET_KEY_LEN: usize = 64;

/// `hkdfInfoFormat` (sqlite_crypto.go:40) — the `info` byte string fed
/// to HKDF-Expand for each derived key. Mirrors Go's
/// `fmt.Sprintf("AlgorandDeterministicKey-%d", index)` exactly.
fn hkdf_info(index: u64) -> Vec<u8> {
    format!("AlgorandDeterministicKey-{index}").into_bytes()
}

/// Deterministically derive the 32-byte Ed25519 seed for `index` from
/// the master derivation key. Mirrors `extractKeyWithIndex`
/// (sqlite_crypto.go:234). Go skips HKDF-Extract ("our key is long and
/// uniformly random" — sqlite_crypto.go:238) and feeds the MDK directly
/// as the PRK; we use [`Hkdf::from_prk`] for the same effect.
pub fn extract_seed_with_index(mdk: &[u8; MASTER_KEY_LEN], index: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha512_256>::from_prk(mdk).expect("32-byte MDK is a valid PRK length");
    let mut seed = [0u8; 32];
    hk.expand(&hkdf_info(index), &mut seed)
        .expect("expanding 32 bytes from SHA-512/256 HKDF cannot fail");
    seed
}

/// Convert a 32-byte Ed25519 seed into the (address, expanded-secret)
/// pair stored on disk. The expanded secret matches Go's
/// `crypto.PrivateKey` byte layout: 32-byte seed concatenated with the
/// 32-byte public key, total 64 bytes (`SignatureSecrets.SK` produced
/// by `GenerateSignatureSecrets`, sqlite_crypto.go:252).
fn keypair_from_seed(seed: &[u8; 32]) -> ([u8; ADDRESS_LEN], [u8; SECRET_KEY_LEN]) {
    let signing = SigningKey::from_bytes(seed);
    let address: [u8; ADDRESS_LEN] = signing.verifying_key().to_bytes();
    let mut expanded = [0u8; SECRET_KEY_LEN];
    expanded[..32].copy_from_slice(seed);
    expanded[32..].copy_from_slice(&address);
    (address, expanded)
}

/// Recover the address and seed from an on-disk expanded secret key.
/// The seed is bytes 0..32; the asserted address (bytes 32..64) must
/// equal the public key re-derived from the seed — otherwise return
/// [`Error::Tampering`], matching Go's `fetchSecretKey` consistency
/// check (sqlite.go:828–830).
fn keypair_from_expanded(expanded: &[u8; SECRET_KEY_LEN]) -> Result<([u8; ADDRESS_LEN], [u8; 32])> {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&expanded[..32]);
    let signing = SigningKey::from_bytes(&seed);
    let derived_addr: [u8; ADDRESS_LEN] = signing.verifying_key().to_bytes();
    if derived_addr != expanded[32..] {
        return Err(Error::Tampering);
    }
    Ok((derived_addr, seed))
}

/// Encode a `max_key_idx` value as canonical msgpack `uint`. Mirrors
/// `msgpackEncode(uint64(n))` for the same field
/// (sqlite.go:962).
fn encode_index_blob(n: u64) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(9);
    rmp::encode::write_uint(&mut buf, n).map_err(|_| Error::Crypto)?;
    Ok(buf)
}

fn decode_index_blob(bytes: &[u8]) -> Result<u64> {
    let mut cursor = bytes;
    rmp::decode::read_int::<u64, _>(&mut cursor).map_err(|_| Error::Crypto)
}

/// Encode an expanded Ed25519 secret key as canonical msgpack `bin`.
/// Go uses `msgpackEncode(sk)` where `sk` is `crypto.PrivateKey
/// ([]byte)`. go-codec writes a `[]byte` as msgpack bin; we use
/// `rmp::encode::write_bin` for the same on-wire bytes.
fn encode_secret_key_blob(sk: &[u8; SECRET_KEY_LEN]) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(SECRET_KEY_LEN + 3);
    rmp::encode::write_bin(&mut buf, sk).map_err(|_| Error::Crypto)?;
    Ok(buf)
}

fn decode_secret_key_blob(bytes: &[u8]) -> Result<[u8; SECRET_KEY_LEN]> {
    let mut cursor = bytes;
    let len = rmp::decode::read_bin_len(&mut cursor).map_err(|_| Error::Crypto)?;
    if len as usize != SECRET_KEY_LEN {
        return Err(Error::Crypto);
    }
    let mut out = [0u8; SECRET_KEY_LEN];
    use std::io::Read;
    cursor.read_exact(&mut out).map_err(|_| Error::Crypto)?;
    Ok(out)
}

// ---- Wallet impl extensions ------------------------------------------------

impl Wallet {
    /// Generate the next Ed25519 keypair from the wallet's MDK. Mirrors
    /// `GenerateKey` (sqlite.go:839) and its inner
    /// `generateKeyTxLocked` (sqlite.go:884) — decrypt the current
    /// `max_key_idx`, find the next index whose derived address isn't
    /// already in `keys` (skipping any pre-imported collisions),
    /// encrypt the SK under MEP, INSERT it, and persist the new
    /// `max_key_idx`.
    ///
    /// Wraps the index search + two writes in a single SQLite
    /// transaction so a partial failure can't leave the on-disk
    /// max_key_idx out of sync with the inserted row. The Go reference
    /// uses `db.Beginx()` with `_txlock=exclusive`; rusqlite's
    /// `transaction()` defers to a deferred lock, which still gives us
    /// the all-or-nothing guarantee we need at this layer (single-
    /// writer kmd has no concurrent-writer contention).
    pub fn generate_key(&self) -> Result<[u8; ADDRESS_LEN]> {
        let mep = self
            .master_encryption_key()
            .ok_or(Error::WalletNotInitialized)?;
        let mdk = self
            .master_derivation_key()
            .ok_or(Error::WalletNotInitialized)?;

        let db = WalletDb::open(self.db_path())?;

        db.with_transaction(|db| {
            // Read + decrypt current highest index inside the tx so the
            // probe and write are atomic.
            let blob = db.read_max_key_idx_encrypted()?;
            let decrypted = decrypt_blob_with_password(&blob, PlaintextType::MaxKeyIdx, mep)?;
            let highest = decode_index_blob(&decrypted)?;
            let mut next_index = highest.checked_add(1).ok_or(Error::TooManyKeys)?;

            // Loop until we find a non-colliding derived key. Imports
            // may have manually claimed addresses we would otherwise
            // derive (sqlite.go:916–947).
            let (addr, expanded) = loop {
                // sqliteIntOverflow (sqlite.go:49) — 1 << 63
                if next_index >= 1u64 << 63 {
                    return Err(Error::TooManyKeys);
                }
                let seed = extract_seed_with_index(mdk, next_index);
                let (addr, expanded) = keypair_from_seed(&seed);
                if !db.key_exists(&addr)? {
                    break (addr, expanded);
                }
                next_index = next_index.checked_add(1).ok_or(Error::TooManyKeys)?;
            };

            // Encrypt SK under MEP, INSERT key row, UPDATE max_key_idx.
            let sk_blob = encode_secret_key_blob(&expanded)?;
            let sk_encrypted = encrypt_blob_with_key(&sk_blob, PlaintextType::SecretKey, mep)?;
            db.insert_key(&addr, &sk_encrypted, Some(next_index))?;

            let new_idx_blob = encode_index_blob(next_index)?;
            let new_idx_encrypted =
                encrypt_blob_with_key(&new_idx_blob, PlaintextType::MaxKeyIdx, mep)?;
            db.update_max_key_idx_encrypted(&new_idx_encrypted)?;
            Ok(addr)
        })
    }

    /// Import an externally-generated Ed25519 secret key. `secret`
    /// follows Go's `crypto.PrivateKey` layout — 64 bytes of
    /// `seed || pubkey`. The caller-supplied `pubkey` half is **not
    /// trusted**: we re-derive it from the seed and store the
    /// re-derived expansion, matching `ImportKey` (sqlite.go:738–746).
    ///
    /// Returns the (re-derived) address. Imported keys have `key_idx
    /// = NULL` in the `keys` table per Go (sqlite.go:764).
    pub fn import_key(&self, secret: &[u8; SECRET_KEY_LEN]) -> Result<[u8; ADDRESS_LEN]> {
        let mep = self
            .master_encryption_key()
            .ok_or(Error::WalletNotInitialized)?;

        // Trust only the seed half; re-derive the pubkey.
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&secret[..32]);
        let (addr, expanded) = keypair_from_seed(&seed);

        let sk_blob = encode_secret_key_blob(&expanded)?;
        let sk_encrypted = encrypt_blob_with_key(&sk_blob, PlaintextType::SecretKey, mep)?;

        let db = WalletDb::open(self.db_path())?;
        db.insert_key(&addr, &sk_encrypted, None)?;
        Ok(addr)
    }

    /// Export the on-disk 64-byte expanded secret key for `addr`.
    /// Mirrors `ExportKey` (sqlite.go:774) + `fetchSecretKey`
    /// (sqlite.go:786): password-check, decrypt under MEP, msgpack-
    /// decode the SK, re-derive the public key, assert it matches
    /// `addr` (or surface [`Error::Tampering`]).
    pub fn export_key(
        &self,
        addr: &[u8; ADDRESS_LEN],
        password: &[u8],
    ) -> Result<[u8; SECRET_KEY_LEN]> {
        self.check_password(password)?;
        let mep = self
            .master_encryption_key()
            .ok_or(Error::WalletNotInitialized)?;
        let db = WalletDb::open(self.db_path())?;
        let encrypted = db.read_secret_key_encrypted(addr)?;
        let sk_blob = decrypt_blob_with_password(&encrypted, PlaintextType::SecretKey, mep)?;
        let expanded = decode_secret_key_blob(&sk_blob)?;
        let (derived_addr, _seed) = keypair_from_expanded(&expanded)?;
        if &derived_addr != addr {
            return Err(Error::Tampering);
        }
        Ok(expanded)
    }

    /// List all addresses in the wallet. Mirrors `ListKeys`
    /// (sqlite.go:694). No password check — Go doesn't require one
    /// either (addresses are public information).
    pub fn list_keys(&self) -> Result<Vec<[u8; ADDRESS_LEN]>> {
        let db = WalletDb::open(self.db_path())?;
        let raw = db.list_key_addresses()?;
        let mut out = Vec::with_capacity(raw.len());
        for bytes in raw {
            if bytes.len() != ADDRESS_LEN {
                return Err(Error::Tampering);
            }
            let mut a = [0u8; ADDRESS_LEN];
            a.copy_from_slice(&bytes);
            out.push(a);
        }
        Ok(out)
    }

    /// Existence probe — true iff `addr` is in the `keys` table. The
    /// Go reference inlines this check inside `generateKeyTxLocked`
    /// (sqlite.go:934); we surface it as a callable so external
    /// consumers (REST handlers, TASK-205 acceptance) can use the same
    /// primitive.
    pub fn lookup_key(&self, addr: &[u8; ADDRESS_LEN]) -> Result<bool> {
        let db = WalletDb::open(self.db_path())?;
        db.key_exists(addr)
    }

    /// Delete a key. Mirrors `DeleteKey` (sqlite.go:978): password
    /// check, then `DELETE FROM keys WHERE address=?`. The DELETE is
    /// silent on no-match — Go's behavior.
    pub fn delete_key(&self, addr: &[u8; ADDRESS_LEN], password: &[u8]) -> Result<()> {
        self.check_password(password)?;
        let db = WalletDb::open(self.db_path())?;
        db.delete_key(addr)
    }

    /// Public alias for the cached MDK, scoped to the keys module so
    /// `generate_key` can reach it without re-exporting state.
    fn master_derivation_key(&self) -> Option<&[u8; MASTER_KEY_LEN]> {
        self.master_derivation_key_internal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_seed_matches_hkdf_fixture_vector() {
        // Use the HKDF vectors shipped in TASK-203's fixture so this
        // test trips if Go's extractKeyWithIndex semantics ever drift.
        let mdk = [0x11u8; 32];
        let seed0 = extract_seed_with_index(&mdk, 0);
        let seed42 = extract_seed_with_index(&mdk, 42);

        let expected_0 =
            hex::decode("8188e7595eb5c3306e1de5aa255dbedf1fae9a19c51fa3dc743a2a7fd0fda940")
                .unwrap();
        let expected_42 =
            hex::decode("3a6b378bad339b239de8e58a46b44ee463523dfdc7d25bef76e91b4333e65548")
                .unwrap();
        assert_eq!(seed0.as_slice(), expected_0.as_slice());
        assert_eq!(seed42.as_slice(), expected_42.as_slice());
    }

    #[test]
    fn secret_key_blob_round_trips_through_msgpack() {
        let sk: [u8; SECRET_KEY_LEN] = std::array::from_fn(|i| i as u8);
        let encoded = encode_secret_key_blob(&sk).unwrap();
        let decoded = decode_secret_key_blob(&encoded).unwrap();
        assert_eq!(decoded, sk);
    }

    #[test]
    fn index_blob_round_trips() {
        for n in [0u64, 1, 42, 1 << 32, u64::MAX] {
            let encoded = encode_index_blob(n).unwrap();
            let decoded = decode_index_blob(&encoded).unwrap();
            assert_eq!(decoded, n);
        }
    }

    #[test]
    fn keypair_from_expanded_detects_tampered_pubkey() {
        let seed = [0x42u8; 32];
        let (_addr, mut expanded) = keypair_from_seed(&seed);
        // Flip a bit in the embedded public-key half.
        expanded[40] ^= 0x01;
        assert!(matches!(
            keypair_from_expanded(&expanded),
            Err(Error::Tampering)
        ));
    }
}
