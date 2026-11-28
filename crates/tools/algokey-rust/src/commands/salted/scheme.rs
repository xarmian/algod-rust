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

//! The signature-scheme table of `algokey salted` — go v5.1.1-stable's
//! `cmd/algokey/salted_scheme.go` (`sigSchemeOps`, `sigSchemeOpsByScheme`,
//! `parseSigScheme`, `formatSigScheme`, the entropy -> seed -> key derivation).

use algo_types::{
    canonical_address_salt, SIG_SCHEME_ED25519, SIG_SCHEME_FALCON1024, SIG_SCHEME_FALCON512,
};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512, Sha512_256};

use super::key::{SaltedPublicMaterial, SaltedSigningMaterial};
use super::{go_quote_bytes, ERR_SALTED_KEY_MALFORMED, ERR_SIG_SCHEME_NOT_SUPPORTED};

pub const SIG_SCHEME_FALCON1024_NAME: &str = "falcon-1024";
pub const SIG_SCHEME_FALCON512_NAME: &str = "falcon-512";
pub const SIG_SCHEME_ED25519_NAME: &str = "ed25519";

/// `protocol.PostQuantumKey` — the domain prefix of the key-seed hash.
const POST_QUANTUM_KEY: &[u8] = b"PQK";

/// Every scheme in go's `sigSchemeOpsByScheme`.
#[cfg(test)]
pub const REGISTERED_SCHEMES: [[u8; 2]; 3] = [
    SIG_SCHEME_FALCON1024,
    SIG_SCHEME_FALCON512,
    SIG_SCHEME_ED25519,
];

/// go's `sigSchemeOps` implementations (`falcon1024Ops`, `falcon512Ops`,
/// `ed25519Ops`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigSchemeOps {
    Falcon1024,
    Falcon512,
    Ed25519,
}

/// `sigSchemeOpsByScheme[scheme]`.
pub fn ops_for(scheme: [u8; 2]) -> Option<SigSchemeOps> {
    match scheme {
        SIG_SCHEME_FALCON1024 => Some(SigSchemeOps::Falcon1024),
        SIG_SCHEME_FALCON512 => Some(SigSchemeOps::Falcon512),
        SIG_SCHEME_ED25519 => Some(SigSchemeOps::Ed25519),
        _ => None,
    }
}

/// `fmt.Errorf("%w: %q", transactions.ErrSigSchemeNotSupported, scheme)`.
pub fn scheme_not_supported(scheme: &[u8]) -> String {
    format!("{ERR_SIG_SCHEME_NOT_SUPPORTED}: {}", go_quote_bytes(scheme))
}

/// go's `parseSigScheme`: the trimmed value is matched against the three
/// names case-insensitively, otherwise it must be the raw two-byte tag.
pub fn parse_sig_scheme(value: &str) -> Result<[u8; 2], String> {
    // strings.TrimSpace: Unicode White_Space.
    let value = value.trim();
    for (name, scheme) in [
        (SIG_SCHEME_FALCON1024_NAME, SIG_SCHEME_FALCON1024),
        (SIG_SCHEME_FALCON512_NAME, SIG_SCHEME_FALCON512),
        (SIG_SCHEME_ED25519_NAME, SIG_SCHEME_ED25519),
    ] {
        if value.eq_ignore_ascii_case(name) {
            return Ok(scheme);
        }
    }
    let bytes = value.as_bytes();
    if bytes.len() != 2 {
        return Err(scheme_not_supported(bytes));
    }
    Ok([bytes[0], bytes[1]])
}

/// go's `formatSigScheme`: the registered name, else the raw tag.
pub fn format_sig_scheme(scheme: &[u8; 2]) -> String {
    match *scheme {
        SIG_SCHEME_FALCON1024 => SIG_SCHEME_FALCON1024_NAME.to_string(),
        SIG_SCHEME_FALCON512 => SIG_SCHEME_FALCON512_NAME.to_string(),
        SIG_SCHEME_ED25519 => SIG_SCHEME_ED25519_NAME.to_string(),
        _ => String::from_utf8_lossy(scheme).to_string(),
    }
}

/// go's `deriveSigSchemeKeySeed`: `Hash(PostQuantumKey || scheme || entropy)`
/// (SHA-512/256).
pub fn derive_sig_scheme_key_seed(scheme: [u8; 2], entropy: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(POST_QUANTUM_KEY);
    hasher.update(scheme);
    hasher.update(entropy);
    hasher.finalize().into()
}

/// go's `deriveSaltedSigningMaterialFromEntropy`.
pub fn derive_salted_signing_material_from_entropy(
    scheme: [u8; 2],
    entropy: &[u8; 32],
) -> Result<SaltedSigningMaterial, String> {
    let ops = ops_for(scheme).ok_or_else(|| scheme_not_supported(&scheme))?;
    ops.derive_signing(derive_sig_scheme_key_seed(scheme, entropy))
}

/// go's `generateSaltedSigningMaterial`, with the entropy source injected
/// (go's `crypto.RNG`): `rng` is called once to fill 32 bytes.
pub fn generate_salted_signing_material_with(
    scheme: [u8; 2],
    rng: impl FnOnce(&mut [u8]),
) -> Result<([u8; 32], SaltedSigningMaterial), String> {
    let mut entropy = [0u8; 32];
    rng(&mut entropy);
    let signing = derive_salted_signing_material_from_entropy(scheme, &entropy)?;
    Ok((entropy, signing))
}

/// go's `generateSaltedSigningMaterial(scheme, crypto.SystemRNG)`.
pub fn generate_salted_signing_material(
    scheme: [u8; 2],
) -> Result<([u8; 32], SaltedSigningMaterial), String> {
    use rand::TryRng;
    generate_salted_signing_material_with(scheme, |buf| {
        rand::rngs::SysRng
            .try_fill_bytes(buf)
            .expect("system entropy")
    })
}

fn derive_material(
    scheme: [u8; 2],
    public_key: Vec<u8>,
    private_key: Vec<u8>,
) -> Result<SaltedSigningMaterial, String> {
    let (salt, _addr) = canonical_address_salt(scheme, &public_key)
        .ok_or_else(|| "no canonical address salt exists for this public key".to_string())?;
    Ok(SaltedSigningMaterial {
        public: SaltedPublicMaterial {
            scheme,
            salt,
            public_key,
        },
        private_key,
    })
}

fn wrong_private_key_size(got: usize, want: usize) -> String {
    format!("{ERR_SALTED_KEY_MALFORMED}: got private key size {got}, want {want}")
}

impl SigSchemeOps {
    /// `deriveSigning(seed)`.
    pub fn derive_signing(self, seed: [u8; 32]) -> Result<SaltedSigningMaterial, String> {
        match self {
            SigSchemeOps::Falcon1024 => {
                let (public_key, private_key) =
                    algo_falcon::falcon_keygen(&seed).map_err(|e| e.to_string())?;
                derive_material(SIG_SCHEME_FALCON1024, public_key, private_key)
            }
            SigSchemeOps::Falcon512 => {
                let (public_key, private_key) =
                    algo_falcon::falcon512_keygen(&seed).map_err(|e| e.to_string())?;
                derive_material(SIG_SCHEME_FALCON512, public_key, private_key)
            }
            SigSchemeOps::Ed25519 => {
                // libsodium's crypto_sign_seed_keypair: sk = seed || pk.
                let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
                let public_key = signing.verifying_key().to_bytes().to_vec();
                let mut private_key = seed.to_vec();
                private_key.extend_from_slice(&public_key);
                derive_material(SIG_SCHEME_ED25519, public_key, private_key)
            }
        }
    }

    /// `publicKeySize()`.
    pub fn public_key_size(self) -> usize {
        match self {
            SigSchemeOps::Falcon1024 => algo_falcon::FALCON_DET1024_PUBKEY_SIZE,
            SigSchemeOps::Falcon512 => algo_falcon::FALCON_DET512_PUBKEY_SIZE,
            SigSchemeOps::Ed25519 => 32,
        }
    }

    /// `privateKeySize()`.
    pub fn private_key_size(self) -> usize {
        match self {
            SigSchemeOps::Falcon1024 => algo_falcon::FALCON_DET1024_PRIVKEY_SIZE,
            SigSchemeOps::Falcon512 => algo_falcon::FALCON_DET512_PRIVKEY_SIZE,
            SigSchemeOps::Ed25519 => 64,
        }
    }

    /// `sign(privateKey, message)`; `message` is the hash representation
    /// (`HashRep(message)`: domain prefix followed by the encoding).
    pub fn sign(self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
        if private_key.len() != self.private_key_size() {
            return Err(wrong_private_key_size(
                private_key.len(),
                self.private_key_size(),
            ));
        }
        match self {
            SigSchemeOps::Falcon1024 => {
                algo_falcon::falcon_sign(private_key, message).map_err(|e| e.to_string())
            }
            SigSchemeOps::Falcon512 => {
                algo_falcon::falcon512_sign(private_key, message).map_err(|e| e.to_string())
            }
            SigSchemeOps::Ed25519 => {
                let sk: [u8; 64] = private_key.try_into().expect("size checked");
                Ok(libsodium_ed25519_sign(&sk, message).to_vec())
            }
        }
    }
}

/// libsodium's `crypto_sign_ed25519_detached`, which go's
/// `crypto.SecretKeyToSignatureSecrets(sk).Sign` calls with the whole 64-byte
/// secret key: the scalar and nonce prefix come from `sk[..32]`, but the
/// public key hashed into the challenge is `sk[32..]` as stored, not derived.
/// For a consistent key this is plain Ed25519; a key file whose tail does not
/// match its seed signs differently from a dalek signer, as it does in go.
fn libsodium_ed25519_sign(sk: &[u8; 64], message: &[u8]) -> [u8; 64] {
    let az = Sha512::digest(&sk[..32]);
    let mut a_bytes = [0u8; 32];
    a_bytes.copy_from_slice(&az[..32]);
    a_bytes[0] &= 248;
    a_bytes[31] &= 127;
    a_bytes[31] |= 64;
    let a = Scalar::from_bytes_mod_order(a_bytes);

    let mut h = Sha512::new();
    h.update(&az[32..]);
    h.update(message);
    let r = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let big_r = (ED25519_BASEPOINT_POINT * r).compress();

    let mut h = Sha512::new();
    h.update(big_r.as_bytes());
    h.update(&sk[32..]);
    h.update(message);
    let hram = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
    let s = hram * a + r;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(big_r.as_bytes());
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}
