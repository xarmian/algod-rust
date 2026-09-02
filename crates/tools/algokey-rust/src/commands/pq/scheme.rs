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

//! PQ scheme parsing and key derivation, mirroring
//! `../go-algorand/cmd/algokey/pq_scheme.go`.
//!
//! Only Falcon-1024 is registered in `pqSchemeOpsByScheme` upstream — a
//! well-formed-but-unregistered 2-byte scheme tag (e.g. the reserved
//! Falcon-512 `"f2"`) parses successfully via [`parse_pq_scheme`] but is
//! rejected later by [`derive_pq_signing_material_from_entropy`], exactly
//! matching Go's two-stage `parsePQScheme` (format only) /
//! `pqSchemeOpsByScheme` lookup (registration) split.

use algo_types::{canonical_pq_address_salt, PQ_SCHEME_FALCON1024};
use sha2::{Digest, Sha512_256};

use crate::cli::PQ_SCHEME_FALCON1024_NAME;
use crate::commands::pq::key::{PqPublicMaterial, PqSigningMaterial};

/// Domain separation prefix for PQ key-seed derivation
/// (`protocol.PostQuantumKey = "PQK"`).
const PQK_PREFIX: &[u8] = b"PQK";

/// Mirrors `parsePQScheme` (`pq_scheme.go:48-60`): accepts the case
/// insensitive name `"falcon-1024"`, or any raw 2-byte scheme tag.
pub fn parse_pq_scheme(value: &str) -> Result<[u8; 2], String> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case(PQ_SCHEME_FALCON1024_NAME) {
        return Ok(PQ_SCHEME_FALCON1024);
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() != 2 {
        return Err(format!("pq scheme not supported: {value:?}"));
    }
    Ok([bytes[0], bytes[1]])
}

/// Mirrors `formatPQScheme` (`pq_scheme.go:62-67`).
pub fn format_pq_scheme(scheme: &[u8; 2]) -> String {
    if *scheme == PQ_SCHEME_FALCON1024 {
        PQ_SCHEME_FALCON1024_NAME.to_string()
    } else {
        String::from_utf8_lossy(scheme).to_string()
    }
}

/// Mirrors `derivePQKeySeed` (`pq_scheme.go:87-96`):
/// `SHA512_256("PQK" || scheme[2] || entropy[32])`.
pub fn derive_pq_key_seed(scheme: [u8; 2], entropy: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(PQK_PREFIX);
    hasher.update(scheme);
    hasher.update(entropy);
    hasher.finalize().into()
}

/// Mirrors `derivePQSigningMaterialFromEntropy` (`pq_scheme.go:77-85`) +
/// `falcon1024Ops.deriveSigning` (`pq_scheme.go:98-119`). Only Falcon-1024
/// is registered; any other (even well-formed) scheme tag is rejected here.
pub fn derive_pq_signing_material_from_entropy(
    scheme: [u8; 2],
    entropy: &[u8; 32],
) -> Result<PqSigningMaterial, String> {
    if scheme != PQ_SCHEME_FALCON1024 {
        return Err(format!(
            "pq scheme not supported: {:?}",
            String::from_utf8_lossy(&scheme)
        ));
    }
    let seed = derive_pq_key_seed(scheme, entropy);
    let (public_key, private_key) =
        algo_falcon::falcon_keygen(&seed).map_err(|e| format!("cannot generate PQ key: {e}"))?;
    let (salt, _addr) = canonical_pq_address_salt(scheme, &public_key)
        .ok_or_else(|| "cannot generate PQ key: no compliant PQ address salt found".to_string())?;
    Ok(PqSigningMaterial {
        public: PqPublicMaterial {
            scheme,
            salt,
            public_key,
        },
        private_key,
    })
}

/// Mirrors `generatePQSigningMaterial` (`pq_scheme.go:69-75`): fresh 32-byte
/// entropy (mnemonic seed) plus the signing material derived from it.
pub fn generate_pq_signing_material(
    scheme: [u8; 2],
) -> Result<([u8; 32], PqSigningMaterial), String> {
    use rand::RngCore;
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);
    let signing = derive_pq_signing_material_from_entropy(scheme, &entropy)?;
    Ok((entropy, signing))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pq_scheme_accepts_named_falcon1024_case_insensitively() {
        assert_eq!(
            parse_pq_scheme("falcon-1024").unwrap(),
            PQ_SCHEME_FALCON1024
        );
        assert_eq!(
            parse_pq_scheme("FALCON-1024").unwrap(),
            PQ_SCHEME_FALCON1024
        );
        assert_eq!(
            parse_pq_scheme("  falcon-1024  ").unwrap(),
            PQ_SCHEME_FALCON1024
        );
    }

    #[test]
    fn parse_pq_scheme_accepts_raw_two_byte_tag() {
        assert_eq!(parse_pq_scheme("f2").unwrap(), *b"f2");
    }

    #[test]
    fn parse_pq_scheme_rejects_wrong_length() {
        assert!(parse_pq_scheme("f").is_err());
        assert!(parse_pq_scheme("falcon").is_err());
    }

    #[test]
    fn format_pq_scheme_round_trips_falcon1024_name() {
        assert_eq!(format_pq_scheme(&PQ_SCHEME_FALCON1024), "falcon-1024");
    }

    #[test]
    fn format_pq_scheme_shows_raw_tag_for_unregistered_scheme() {
        assert_eq!(format_pq_scheme(b"f2"), "f2");
    }

    #[test]
    fn derive_pq_key_seed_is_deterministic_and_scheme_and_entropy_sensitive() {
        let entropy = [7u8; 32];
        let a = derive_pq_key_seed(PQ_SCHEME_FALCON1024, &entropy);
        let b = derive_pq_key_seed(PQ_SCHEME_FALCON1024, &entropy);
        assert_eq!(a, b);
        let c = derive_pq_key_seed(*b"f2", &entropy);
        assert_ne!(a, c);
        let d = derive_pq_key_seed(PQ_SCHEME_FALCON1024, &[8u8; 32]);
        assert_ne!(a, d);
    }

    #[test]
    fn derive_pq_signing_material_from_entropy_is_deterministic() {
        let entropy = [3u8; 32];
        let a = derive_pq_signing_material_from_entropy(PQ_SCHEME_FALCON1024, &entropy).unwrap();
        let b = derive_pq_signing_material_from_entropy(PQ_SCHEME_FALCON1024, &entropy).unwrap();
        assert_eq!(a, b);
        a.validate().expect("derived key must validate");
    }

    #[test]
    fn derive_pq_signing_material_rejects_unregistered_scheme() {
        let entropy = [3u8; 32];
        let err = derive_pq_signing_material_from_entropy(*b"f2", &entropy).unwrap_err();
        assert!(err.contains("not supported"), "{err}");
    }

    #[test]
    fn generate_pq_signing_material_produces_valid_material_each_call() {
        let (entropy1, m1) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let (entropy2, m2) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        assert_ne!(entropy1, entropy2, "OS RNG must not repeat");
        assert_ne!(m1.public.public_key, m2.public.public_key);
        m1.validate().unwrap();
        m2.validate().unwrap();
    }
}
