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

//! `algokey salted sign` — mirrors `runSaltedSignWithOptions` (`salted.go`).

use std::path::PathBuf;
use std::process::ExitCode;

use algo_codec::{canonical_encode_signed_transaction, canonical_encode_transaction};
use algo_types::SignedTransaction;

use crate::cli::SaltedSignArgs;

use super::context::{resolve_salted_signing_context, sign_salted};
use super::{
    exit_on_error, non_empty, non_empty_path, read_file, write_file, ERR_TXN_ALREADY_SIGNED,
};

const TX_PREFIX: &[u8] = b"TX";

/// go's `saltedSignOptions`.
#[derive(Debug, Clone, Default)]
pub struct SaltedSignOptions {
    pub keyfile: Option<PathBuf>,
    pub mnemonic: Option<String>,
    pub scheme: String,
    pub txfile: PathBuf,
    pub outfile: PathBuf,
    pub overwrite: bool,
}

/// go's `clearSignedTxnAuthorization`.
fn clear_signed_txn_authorization(stxn: &mut SignedTransaction) {
    stxn.sig = [0u8; 64];
    stxn.msig = None;
    stxn.lsig = None;
    stxn.pqsig = None;
    stxn.auth_addr = None;
}

pub fn run(args: SaltedSignArgs) -> ExitCode {
    exit_on_error(
        run_salted_sign_with_options(&SaltedSignOptions {
            keyfile: args.keyfile,
            mnemonic: args.mnemonic,
            scheme: args.scheme.unwrap_or_default(),
            txfile: args.txfile,
            outfile: args.outfile,
            overwrite: args.overwrite,
        }),
        &mut std::io::stderr(),
    )
}

/// go's `runSaltedSignWithOptions`.
pub fn run_salted_sign_with_options(opts: &SaltedSignOptions) -> Result<(), String> {
    let ctx = resolve_salted_signing_context(
        non_empty_path(&opts.keyfile),
        non_empty(&opts.mnemonic),
        &opts.scheme,
    )?;
    let public = ctx.signing.public.clone();

    let txdata = read_file(&opts.txfile).map_err(|e| {
        format!(
            "cannot read transactions from {}: {e}",
            opts.txfile.display()
        )
    })?;

    let mut out_bytes: Vec<u8> = Vec::with_capacity(txdata.len() + 256);
    let mut pos: usize = 0;
    let mut decoded_txns: usize = 0;
    while pos < txdata.len() {
        let (mut stxn, advance) = decode_signed_txn_like_go(&txdata[pos..])
            .map_err(|e| format!("cannot decode transaction: {e}"))?;
        decoded_txns += 1;

        if stxn.has_signature() {
            if !opts.overwrite {
                return Err(ERR_TXN_ALREADY_SIGNED.to_string());
            }
            clear_signed_txn_authorization(&mut stxn);
        }

        let canonical = canonical_encode_transaction(&stxn.txn);
        let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
        msg.extend_from_slice(TX_PREFIX);
        msg.extend_from_slice(&canonical);

        let sksig = sign_salted(&ctx, &msg).map_err(|e| format!("cannot sign transaction: {e}"))?;
        stxn.pqsig = Some(sksig);
        if stxn.txn.sender != public.address() {
            stxn.auth_addr = Some(public.address());
        }

        out_bytes.extend_from_slice(&canonical_encode_signed_transaction(&stxn));
        pos += advance;
    }

    if decoded_txns == 0 {
        return Err(format!(
            "no transactions found in {}",
            opts.txfile.display()
        ));
    }
    write_file(&opts.outfile, &out_bytes).map_err(|e| {
        format!(
            "cannot write signed transactions to {}: {e}",
            opts.outfile.display()
        )
    })
}

/// One `SignedTxn` from the front of `bytes` as go's `Decode` reads it: the
/// msgp-generated decoder's verdict and text (`algo_codec::decode_signed_txn_go`,
/// issue #2555), then the value read by algod-rust's strict reader, which
/// takes exactly the bytes go's decoder takes. Returns the value and the
/// number of bytes it took.
pub(super) fn decode_signed_txn_like_go(
    bytes: &[u8],
) -> Result<(SignedTransaction, usize), String> {
    let used = algo_codec::decode_signed_txn_go(bytes)
        .map_err(|e| String::from_utf8_lossy(&e.text()).into_owned())?;
    let stxn = read_accepted_signed_txn(&bytes[..used])?;
    Ok((stxn, used))
}

/// Read one `SignedTxn` that go's generated decoder accepted. go's
/// `ReadMapKeyZC` also takes a key spelled as an array of uint8; the strict
/// reader takes the string spellings (`str`, `bin`, `nil`) only, so a value it
/// refuses is read again with its keys rewritten as strings.
fn read_accepted_signed_txn(bytes: &[u8]) -> Result<SignedTransaction, String> {
    let read = |bytes: &[u8]| {
        let _strict = algo_types::strict_unknown_fields(bytes);
        let mut cursor = bytes;
        SignedTransaction::decode_from_reader(&mut cursor).map_err(|e| e.to_string())
    };
    read(bytes).or_else(|first| {
        let mut cursor = bytes;
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| first.clone())?;
        let mut rewritten = Vec::with_capacity(bytes.len());
        rmpv::encode::write_value(&mut rewritten, &string_keys(value)).map_err(|_| first)?;
        read(&rewritten)
    })
}

/// `value` with every map key that is an array of uint8 spelled as a string.
fn string_keys(value: rmpv::Value) -> rmpv::Value {
    use rmpv::Value;
    match value {
        Value::Map(pairs) => Value::Map(
            pairs
                .into_iter()
                .map(|(k, v)| {
                    let key = match k {
                        Value::Array(items) => {
                            let bytes: Option<Vec<u8>> = items
                                .iter()
                                .map(|i| i.as_u64().and_then(|n| u8::try_from(n).ok()))
                                .collect();
                            match bytes {
                                Some(b) => {
                                    Value::String(String::from_utf8_lossy(&b).into_owned().into())
                                }
                                None => Value::Array(items),
                            }
                        }
                        other => other,
                    };
                    (key, string_keys(v))
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(string_keys).collect()),
        other => other,
    }
}
