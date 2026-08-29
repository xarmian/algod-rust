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

//! Wallet encryption primitives — scrypt KDF + NaCl secretbox AEAD +
//! canonical msgpack envelopes.
//!
//! Ported from `../go-algorand/daemon/kmd/wallet/driver/sqlite_crypto.go`
//! (v4.6.0-stable). All constants and field names match Go byte-for-byte
//! so a blob produced by either implementation round-trips through the
//! other.
//!
//! The msgpack encoding mirrors go-codec's settings used by kmd
//! (`sqlite.go:111–119`): `Canonical=true` (map keys sorted lexically)
//! and `PositiveIntUnsigned=true` (positive ints encode as msgpack uint).
//! Note: `RecursiveEmptyCheck=true` is also set on the Go handle, but
//! the `encryptedDBBlob` struct has no `omitempty` tags, so go-codec
//! writes every field unconditionally — including a 32-byte zero salt
//! and zero scrypt params on the raw-key path. We mirror that to keep
//! the bytes identical (see [`EncryptedDbBlobWire`]).
//!
//! TASK-203 scope: scrypt + secretbox + the two msgpack envelopes
//! (`typedPlaintext`, `encryptedDBBlob`). HKDF-based key derivation
//! (`extractKeyWithIndex`, sqlite_crypto.go:234) belongs to TASK-205.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use xsalsa20poly1305::{
    aead::{Aead, KeyInit},
    Key, Nonce, XSalsa20Poly1305,
};

use crate::config::ScryptParams;
use crate::error::{Error, Result};

/// `saltLen` (sqlite_crypto.go:34) — scrypt salt length.
pub const SALT_LEN: usize = 32;

/// `nonceLen` (sqlite_crypto.go:35) — secretbox (XSalsa20-Poly1305) nonce
/// length.
pub const NONCE_LEN: usize = 24;

/// `masterKeyLen` (sqlite_crypto.go:36) — secretbox key length.
pub const MASTER_KEY_LEN: usize = 32;

/// Minimum acceptable scrypt cost parameters. Mirror `minScryptN`,
/// `minScryptR`, `minScryptP` (sqlite_crypto.go:37–39). Wallets created
/// with `allow_unsafe_scrypt=false` reject anything weaker.
pub const MIN_SCRYPT_N: u32 = 32768;
pub const MIN_SCRYPT_R: u32 = 1;
pub const MIN_SCRYPT_P: u32 = 32;

/// Type-tag attached to each plaintext to prevent cross-type decryption
/// confusion (e.g. decrypting a stored secret key under the
/// master-derivation-key code path). Mirrors `plaintextType`
/// (sqlite_crypto.go:43–54).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaintextType {
    /// `PTMasterKey` (sqlite_crypto.go:47).
    MasterKey,
    /// `PTSecretKey` (sqlite_crypto.go:49).
    SecretKey,
    /// `PTMasterDerivationKey` (sqlite_crypto.go:51).
    MasterDerivationKey,
    /// `PTMaxKeyIdx` (sqlite_crypto.go:53).
    MaxKeyIdx,
}

impl PlaintextType {
    /// The string written into the `plaintext_type` field of a
    /// `typedPlaintext` envelope. These strings are the wire format —
    /// changing them breaks every existing wallet.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MasterKey => "master_key",
            Self::SecretKey => "secret_key",
            Self::MasterDerivationKey => "master_derivation_key",
            Self::MaxKeyIdx => "max_key_idx",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        Some(match s {
            "master_key" => Self::MasterKey,
            "secret_key" => Self::SecretKey,
            "master_derivation_key" => Self::MasterDerivationKey,
            "max_key_idx" => Self::MaxKeyIdx,
            _ => return None,
        })
    }
}

// ---- typedPlaintext envelope -----------------------------------------------

/// Wire shape of `typedPlaintext` (sqlite_crypto.go:58–61). Fields are
/// in alphabetical order so `rmp_serde::to_vec_named` produces canonical
/// output without further sorting. Both fields are always populated, so
/// no `skip_serializing_if` is needed.
#[derive(Serialize, Deserialize)]
struct TypedPlaintextWire {
    #[serde(rename = "plaintext", with = "serde_bytes")]
    plaintext: Vec<u8>,
    #[serde(rename = "plaintext_type")]
    plaintext_type: String,
}

fn encode_typed_plaintext(plaintext: &[u8], pt_type: PlaintextType) -> Result<Vec<u8>> {
    let wire = TypedPlaintextWire {
        plaintext: plaintext.to_vec(),
        plaintext_type: pt_type.as_str().to_string(),
    };
    rmp_serde::to_vec_named(&wire).map_err(|_| Error::Crypto)
}

fn decode_typed_plaintext(bytes: &[u8]) -> Result<(Vec<u8>, PlaintextType)> {
    let wire: TypedPlaintextWire = rmp_serde::from_slice(bytes).map_err(|_| Error::Crypto)?;
    let pt_type = PlaintextType::from_wire(&wire.plaintext_type).ok_or(Error::TypeMismatch)?;
    Ok((wire.plaintext, pt_type))
}

// ---- encryptedDBBlob envelope ----------------------------------------------

/// Wire shape of `encryptedDBBlob` (sqlite_crypto.go:65–71). Fields are
/// in alphabetical order so `rmp_serde::to_vec_named` produces a
/// Canonical (sorted-key) msgpack map, matching go-codec's
/// `Canonical=true` setting.
///
/// **All seven fields are always serialized**, including zero-valued
/// ones (an empty 32-byte salt, `do_scrypt: false`, zero scrypt params
/// on the raw-key path). The Go struct uses plain `codec:"..."` tags
/// with no `,omitempty`, so go-codec writes every field unconditionally.
/// We mirror that — a fixture test asserts byte-equality against
/// `tests/fixtures/kmd_crypto_vectors.json`, generated from
/// `tools/kmd-crypto-vector-capture`, and a raw-key blob comes in as a
/// fixmap-7 with the empty-state values present.
///
/// `nonce` and `salt` are length-checked at the boundary so the size
/// constants live in one place.
#[derive(Default, Serialize, Deserialize)]
struct EncryptedDbBlobWire {
    #[serde(rename = "ciphertext", default, with = "serde_bytes")]
    ciphertext: Vec<u8>,

    #[serde(rename = "do_scrypt", default)]
    do_scrypt: bool,

    #[serde(rename = "nonce", default)]
    nonce: serde_bytes::ByteBuf,

    #[serde(rename = "salt", default)]
    salt: serde_bytes::ByteBuf,

    #[serde(rename = "scrypt_n", default)]
    scrypt_n: u64,

    #[serde(rename = "scrypt_p", default)]
    scrypt_p: u64,

    #[serde(rename = "scrypt_r", default)]
    scrypt_r: u64,
}

fn encode_db_blob(wire: &EncryptedDbBlobWire) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(wire).map_err(|_| Error::Crypto)
}

fn decode_db_blob(bytes: &[u8]) -> Result<EncryptedDbBlobWire> {
    rmp_serde::from_slice(bytes).map_err(|_| Error::Crypto)
}

// ---- Key derivation --------------------------------------------------------

fn derive_encryption_key_with_salt(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    cfg: &ScryptParams,
) -> Result<[u8; MASTER_KEY_LEN]> {
    let key_bytes = algo_consensus_crypto::scrypt_key(
        password,
        salt,
        u32::try_from(cfg.scrypt_n).map_err(|_| Error::DeriveKey)?,
        u32::try_from(cfg.scrypt_r).map_err(|_| Error::DeriveKey)?,
        u32::try_from(cfg.scrypt_p).map_err(|_| Error::DeriveKey)?,
        MASTER_KEY_LEN,
    )
    .map_err(|_| Error::DeriveKey)?;

    let mut key = [0u8; MASTER_KEY_LEN];
    if key_bytes.len() != MASTER_KEY_LEN {
        return Err(Error::DeriveKey);
    }
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

fn fill_random(out: &mut [u8]) -> Result<()> {
    rand::rngs::OsRng
        .try_fill_bytes(out)
        .map_err(|_| Error::RandBytes)
}

// ---- Public API ------------------------------------------------------------

/// Options controlling whether key material is derived from `password`
/// via scrypt, or whether `password` is itself the raw 32-byte key
/// (matching Go's `encryptBlobWithKey` shortcut, sqlite_crypto.go:124).
pub enum Kdf<'a> {
    /// Apply scrypt with the supplied parameters; a fresh salt is
    /// generated.
    Scrypt(&'a ScryptParams),
    /// Treat `password` as the raw 32-byte key. The slice must be
    /// exactly `MASTER_KEY_LEN` bytes; otherwise [`Error::DeriveKey`]
    /// is returned.
    RawKey,
}

/// Encrypt `plaintext` (tagged with `pt_type`) under `password` and
/// return a canonically-msgpack-encoded `encryptedDBBlob`. Mirrors
/// `encryptBlobWithPasswordBlankOK` (sqlite_crypto.go:131).
///
/// A fresh nonce (and salt, when `kdf == Scrypt`) is generated from the
/// OS RNG. Use [`encrypt_blob_with_nonce_and_salt`] when a test needs
/// deterministic output.
pub fn encrypt_blob_with_password(
    plaintext: &[u8],
    pt_type: PlaintextType,
    password: &[u8],
    kdf: Kdf<'_>,
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let mut salt = [0u8; SALT_LEN];
    if matches!(kdf, Kdf::Scrypt(_)) {
        fill_random(&mut salt)?;
    }
    encrypt_blob_with_nonce_and_salt(plaintext, pt_type, password, kdf, &nonce, &salt)
}

/// Same as [`encrypt_blob_with_password`] but the caller supplies the
/// nonce (and, for the scrypt path, the salt). Used by deterministic
/// tests and the Go-interop fixture; not part of the production surface.
pub fn encrypt_blob_with_nonce_and_salt(
    plaintext: &[u8],
    pt_type: PlaintextType,
    password: &[u8],
    kdf: Kdf<'_>,
    nonce: &[u8; NONCE_LEN],
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>> {
    // Derive the secretbox key.
    let key = match kdf {
        Kdf::Scrypt(cfg) => derive_encryption_key_with_salt(password, salt, cfg)?,
        Kdf::RawKey => {
            if password.len() != MASTER_KEY_LEN {
                return Err(Error::DeriveKey);
            }
            let mut k = [0u8; MASTER_KEY_LEN];
            k.copy_from_slice(password);
            k
        }
    };

    // Encode + seal the typed plaintext.
    let encoded_plaintext = encode_typed_plaintext(plaintext, pt_type)?;
    let cipher = XSalsa20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), encoded_plaintext.as_slice())
        .map_err(|_| Error::Crypto)?;

    // Build the wire blob. All seven fields are always serialized;
    // the raw-key path writes zeros into salt + scrypt params and
    // `do_scrypt: false`. See EncryptedDbBlobWire docs for the
    // rationale (Go struct has no `omitempty`).
    let mut wire = EncryptedDbBlobWire {
        ciphertext,
        do_scrypt: false,
        nonce: serde_bytes::ByteBuf::from(nonce.to_vec()),
        salt: serde_bytes::ByteBuf::from(vec![0u8; SALT_LEN]),
        scrypt_n: 0,
        scrypt_p: 0,
        scrypt_r: 0,
    };
    if let Kdf::Scrypt(cfg) = kdf {
        wire.do_scrypt = true;
        wire.salt = serde_bytes::ByteBuf::from(salt.to_vec());
        wire.scrypt_n = u64::try_from(cfg.scrypt_n).map_err(|_| Error::DeriveKey)?;
        wire.scrypt_p = u64::try_from(cfg.scrypt_p).map_err(|_| Error::DeriveKey)?;
        wire.scrypt_r = u64::try_from(cfg.scrypt_r).map_err(|_| Error::DeriveKey)?;
    }
    encode_db_blob(&wire)
}

/// Wrap raw key material into a blob without applying scrypt. Mirrors
/// `encryptBlobWithKey` (sqlite_crypto.go:124).
///
/// `key` must be exactly `MASTER_KEY_LEN` bytes — typically the master
/// encryption password (MEP) that was itself just derived from the
/// user's password via the scrypt path.
pub fn encrypt_blob_with_key(
    plaintext: &[u8],
    pt_type: PlaintextType,
    key: &[u8],
) -> Result<Vec<u8>> {
    encrypt_blob_with_password(plaintext, pt_type, key, Kdf::RawKey)
}

/// Decrypt a `encryptedDBBlob` produced by [`encrypt_blob_with_password`]
/// or by Go's `encryptBlobWithPasswordBlankOK` (sqlite_crypto.go:131).
/// Mirrors `decryptBlobWithPassword` (sqlite_crypto.go:186).
///
/// `password` is interpreted per the blob's `do_scrypt` flag: when
/// `do_scrypt=true` it is run through scrypt with the embedded salt and
/// params; when `do_scrypt=false` it is used as the raw 32-byte key
/// (and must be exactly that length).
///
/// Fails with [`Error::Decrypt`] on AEAD failure (wrong key, corrupted
/// ciphertext, tampered nonce) and with [`Error::TypeMismatch`] when the
/// envelope's `plaintext_type` does not match the caller's `pt_type` —
/// this is the same guard Go applies (sqlite_crypto.go:224).
pub fn decrypt_blob_with_password(
    blob_bytes: &[u8],
    pt_type: PlaintextType,
    password: &[u8],
) -> Result<Vec<u8>> {
    let wire = decode_db_blob(blob_bytes)?;

    let key = if wire.do_scrypt {
        if wire.salt.len() != SALT_LEN {
            return Err(Error::Crypto);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&wire.salt);
        let cfg = ScryptParams {
            scrypt_n: i64::try_from(wire.scrypt_n).map_err(|_| Error::DeriveKey)?,
            scrypt_r: i64::try_from(wire.scrypt_r).map_err(|_| Error::DeriveKey)?,
            scrypt_p: i64::try_from(wire.scrypt_p).map_err(|_| Error::DeriveKey)?,
        };
        derive_encryption_key_with_salt(password, &salt, &cfg)?
    } else {
        if password.len() != MASTER_KEY_LEN {
            return Err(Error::DeriveKey);
        }
        let mut k = [0u8; MASTER_KEY_LEN];
        k.copy_from_slice(password);
        k
    };

    if wire.nonce.len() != NONCE_LEN {
        return Err(Error::Crypto);
    }
    let cipher = XSalsa20Poly1305::new(Key::from_slice(&key));
    let encoded_plaintext = cipher
        .decrypt(Nonce::from_slice(&wire.nonce), wire.ciphertext.as_slice())
        .map_err(|_| Error::Decrypt)?;

    let (plaintext, decoded_type) = decode_typed_plaintext(&encoded_plaintext)?;
    if decoded_type != pt_type {
        return Err(Error::TypeMismatch);
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weak_params() -> ScryptParams {
        // Use weak scrypt params so tests stay fast. These are below
        // the production minimum (allow_unsafe_scrypt=true would be
        // required to *create* a wallet with them, but the crypto
        // primitive itself doesn't care).
        ScryptParams {
            scrypt_n: 1024,
            scrypt_r: 1,
            scrypt_p: 1,
        }
    }

    #[test]
    fn raw_key_round_trip() {
        let key = [7u8; MASTER_KEY_LEN];
        let blob = encrypt_blob_with_key(b"hello", PlaintextType::SecretKey, &key).unwrap();
        let out = decrypt_blob_with_password(&blob, PlaintextType::SecretKey, &key).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn scrypt_round_trip() {
        let cfg = weak_params();
        let blob = encrypt_blob_with_password(
            b"my secret payload",
            PlaintextType::MasterKey,
            b"correct horse battery staple",
            Kdf::Scrypt(&cfg),
        )
        .unwrap();
        let out = decrypt_blob_with_password(
            &blob,
            PlaintextType::MasterKey,
            b"correct horse battery staple",
        )
        .unwrap();
        assert_eq!(out, b"my secret payload");
    }

    #[test]
    fn wrong_password_returns_decrypt_error() {
        let cfg = weak_params();
        let blob =
            encrypt_blob_with_password(b"x", PlaintextType::MaxKeyIdx, b"good", Kdf::Scrypt(&cfg))
                .unwrap();
        let err = decrypt_blob_with_password(&blob, PlaintextType::MaxKeyIdx, b"bad").unwrap_err();
        assert!(matches!(err, Error::Decrypt), "got {err:?}");
    }

    #[test]
    fn type_mismatch_is_rejected() {
        let key = [3u8; MASTER_KEY_LEN];
        let blob = encrypt_blob_with_key(b"x", PlaintextType::SecretKey, &key).unwrap();
        let err = decrypt_blob_with_password(&blob, PlaintextType::MasterKey, &key).unwrap_err();
        assert!(matches!(err, Error::TypeMismatch));
    }

    #[test]
    fn raw_key_rejects_wrong_length_password() {
        let blob =
            encrypt_blob_with_key(b"x", PlaintextType::SecretKey, &[0u8; MASTER_KEY_LEN]).unwrap();
        let err =
            decrypt_blob_with_password(&blob, PlaintextType::SecretKey, b"too short").unwrap_err();
        assert!(matches!(err, Error::DeriveKey));
    }

    #[test]
    fn key_blob_writes_all_seven_fields() {
        // The Go `encryptedDBBlob` struct has no `omitempty` tags, so
        // go-codec writes every field — even zero-valued salt and
        // scrypt params on the raw-key path. This test pins that
        // behavior on the Rust side; the on-wire equality vs the Go
        // fixture is asserted by tests/crypto_test.rs.
        let key = [0u8; MASTER_KEY_LEN];
        let blob = encrypt_blob_with_key(b"x", PlaintextType::SecretKey, &key).unwrap();
        let decoded: EncryptedDbBlobWire = rmp_serde::from_slice(&blob).unwrap();
        assert!(!decoded.do_scrypt);
        assert_eq!(decoded.scrypt_n, 0);
        assert_eq!(decoded.scrypt_r, 0);
        assert_eq!(decoded.scrypt_p, 0);
        assert_eq!(decoded.salt.len(), SALT_LEN);
        assert!(decoded.salt.iter().all(|&b| b == 0));
        assert_eq!(decoded.nonce.len(), NONCE_LEN);

        // Re-encoding the decoded shape must be byte-stable.
        let reencoded = encode_db_blob(&decoded).unwrap();
        assert_eq!(reencoded, blob);
    }

    #[test]
    fn fixed_nonce_round_trip_byte_stable() {
        // The same plaintext encrypted twice with the same nonce + key
        // must produce identical bytes — sanity check that nothing
        // non-deterministic leaks in (e.g. unstable msgpack ordering).
        let cfg = weak_params();
        let nonce = [9u8; NONCE_LEN];
        let salt = [5u8; SALT_LEN];
        let blob1 = encrypt_blob_with_nonce_and_salt(
            b"pt",
            PlaintextType::MasterDerivationKey,
            b"pw",
            Kdf::Scrypt(&cfg),
            &nonce,
            &salt,
        )
        .unwrap();
        let blob2 = encrypt_blob_with_nonce_and_salt(
            b"pt",
            PlaintextType::MasterDerivationKey,
            b"pw",
            Kdf::Scrypt(&cfg),
            &nonce,
            &salt,
        )
        .unwrap();
        assert_eq!(blob1, blob2);
    }
}
