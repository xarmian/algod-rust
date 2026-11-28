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

//! go's `saltedSigningContext`, `resolveSaltedSigningContext` and `signSalted`
//! (`salted.go`): which key a command signs with, and the `SaltedKeySig` it
//! produces.

use std::path::Path;

use algo_types::SaltedKeySig;
use serde_bytes::ByteBuf;

use super::key::{read_salted_signing_material, SaltedSigningMaterial};
use super::scheme::{
    derive_salted_signing_material_from_entropy, ops_for, parse_sig_scheme, scheme_not_supported,
    SigSchemeOps,
};
use super::{seed_from_mnemonic, ERR_SCHEME_REQUIRED, ERR_SCHEME_WITH_KEYFILE};

/// go's `saltedSigningContext`.
#[derive(Debug)]
pub struct SaltedSigningContext {
    pub ops: SigSchemeOps,
    pub signing: SaltedSigningMaterial,
}

/// go's `resolveSaltedSigningContext(keyfile, mnemonic, schemeName)`; an
/// empty `keyfile`/`mnemonic`/`scheme_name` is "not given".
pub fn resolve_salted_signing_context(
    keyfile: Option<&Path>,
    mnemonic: Option<&str>,
    scheme_name: &str,
) -> Result<SaltedSigningContext, String> {
    let signing = match (keyfile, mnemonic) {
        (Some(_), Some(_)) => {
            return Err("cannot specify both --keyfile and --mnemonic".to_string())
        }
        (None, Some(m)) => {
            if scheme_name.is_empty() {
                return Err(ERR_SCHEME_REQUIRED.to_string());
            }
            let entropy = seed_from_mnemonic(m)
                .map_err(|e| format!("cannot recover key entropy from mnemonic: {e}"))?;
            let scheme = parse_sig_scheme(scheme_name)?;
            derive_salted_signing_material_from_entropy(scheme, &entropy)?
        }
        (Some(path), None) => {
            if !scheme_name.is_empty() {
                return Err(ERR_SCHEME_WITH_KEYFILE.to_string());
            }
            read_salted_signing_material(path)?
        }
        (None, None) => return Err("must specify --keyfile or --mnemonic".to_string()),
    };

    let ops = ops_for(signing.public.scheme)
        .ok_or_else(|| scheme_not_supported(&signing.public.scheme))?;
    Ok(SaltedSigningContext { ops, signing })
}

/// go's `signSalted(hctx, message)`; `message` is `HashRep(message)`.
pub fn sign_salted(ctx: &SaltedSigningContext, message: &[u8]) -> Result<SaltedKeySig, String> {
    let signature = ctx.ops.sign(&ctx.signing.private_key, message)?;
    Ok(SaltedKeySig {
        scheme: ctx.signing.public.scheme,
        salt: ctx.signing.public.salt,
        public_key: ByteBuf::from(ctx.signing.public.public_key.clone()),
        signature: ByteBuf::from(signature),
    })
}
