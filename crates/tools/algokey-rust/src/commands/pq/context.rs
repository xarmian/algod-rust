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

//! Shared `--keyfile`/`--mnemonic` resolution and signing for `pq sign` and
//! `pq sign-program`, mirroring `resolvePQSigningContext`/`signPQ`
//! (`pq.go:311-362`).

use std::path::Path;

use algo_consensus_crypto::mnemonic_to_key;
use algo_types::{PQSig, PQ_SCHEME_FALCON1024};
use serde_bytes::ByteBuf;

use super::key::{read_pq_signing_material, PqSigningMaterial};
use super::scheme::{derive_pq_signing_material_from_entropy, parse_pq_scheme};

/// Holds the resolved PQ signing material for one `pq sign`/`pq
/// sign-program` invocation.
#[derive(Debug)]
pub struct PqSigningContext {
    pub signing: PqSigningMaterial,
}

/// Mirrors `resolvePQSigningContext` (`pq.go:311-348`): exactly one of
/// `keyfile`/`mnemonic` must be given; `--scheme` only applies to the
/// `--mnemonic` path (a keyfile already carries its own scheme).
pub fn resolve_pq_signing_context(
    keyfile: Option<&Path>,
    mnemonic: Option<&str>,
    scheme_name: &str,
) -> Result<PqSigningContext, String> {
    let signing = match (keyfile, mnemonic) {
        (Some(_), Some(_)) => {
            return Err("cannot specify both --keyfile and --mnemonic".to_string())
        }
        (None, Some(m)) => {
            let entropy = mnemonic_to_key(m)
                .map_err(|e| format!("cannot recover PQ key entropy from mnemonic: {e}"))?;
            let scheme = if scheme_name.is_empty() {
                PQ_SCHEME_FALCON1024
            } else {
                parse_pq_scheme(scheme_name)?
            };
            derive_pq_signing_material_from_entropy(scheme, &entropy)?
        }
        (Some(path), None) => read_pq_signing_material(path)?,
        (None, None) => return Err("must specify --keyfile or --mnemonic".to_string()),
    };

    Ok(PqSigningContext { signing })
}

/// Mirrors `signPQ` (`pq.go:350-362`): sign `message` (the raw
/// domain-tag-prefixed bytes — `"TX" || canonical_encode(txn)` for `pq
/// sign`, `PQDelegatedProgram::to_be_signed()` for `pq sign-program`) with
/// the context's Falcon-1024 private key and wrap the result as a `PQSig`
/// authorization envelope.
pub fn sign_pq(ctx: &PqSigningContext, message: &[u8]) -> Result<PQSig, String> {
    let signature = algo_falcon::falcon_sign(&ctx.signing.private_key, message)
        .map_err(|e| format!("cannot sign: {e}"))?;
    Ok(PQSig {
        scheme: ctx.signing.public.scheme,
        salt: ctx.signing.public.salt,
        public_key: ByteBuf::from(ctx.signing.public.public_key.clone()),
        signature: ByteBuf::from(signature),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::pq::scheme::generate_pq_signing_material;
    use algo_consensus_crypto::key_to_mnemonic;

    #[test]
    fn resolve_rejects_both_keyfile_and_mnemonic() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        std::fs::write(&kf, [0u8; 8]).unwrap();
        let err = resolve_pq_signing_context(Some(&kf), Some("m"), "falcon-1024").unwrap_err();
        assert!(err.contains("cannot specify both"), "{err}");
    }

    #[test]
    fn resolve_rejects_neither_keyfile_nor_mnemonic() {
        let err = resolve_pq_signing_context(None, None, "falcon-1024").unwrap_err();
        assert!(err.contains("must specify"), "{err}");
    }

    #[test]
    fn resolve_from_mnemonic_matches_generate() {
        let (entropy, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let mnemonic = key_to_mnemonic(&entropy).unwrap();
        let ctx = resolve_pq_signing_context(None, Some(&mnemonic), "falcon-1024").unwrap();
        assert_eq!(ctx.signing, signing);
    }

    #[test]
    fn resolve_from_keyfile_reads_back_written_material() {
        let (_, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        super::super::key::write_pq_private_key_file(&kf, &signing).unwrap();
        let ctx = resolve_pq_signing_context(Some(&kf), None, "falcon-1024").unwrap();
        assert_eq!(ctx.signing, signing);
    }

    #[test]
    fn sign_pq_produces_falcon_signature_that_verifies() {
        let (_, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let ctx = PqSigningContext { signing };
        let message = b"hello pq";
        let pqsig = sign_pq(&ctx, message).unwrap();
        assert!(algo_falcon::falcon_verify(&pqsig.public_key, &pqsig.signature, message).unwrap());
        // Tampered message must fail verification.
        assert!(
            !algo_falcon::falcon_verify(&pqsig.public_key, &pqsig.signature, b"tampered").unwrap()
        );
    }
}
