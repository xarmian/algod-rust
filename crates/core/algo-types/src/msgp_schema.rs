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

//! Key-set validation of the msgpack values algod-rust keeps as raw
//! `rmpv::Value`s (issue #2394).
//!
//! A block's `spt` (state proof tracking), a transaction's `dt` (eval delta)
//! and a block response's `cert` are carried opaque. go decodes each of them
//! with a generated msgp decoder, which fails with `msgp.ErrNoField` on a key
//! the struct lacks, so a block with an unknown key anywhere inside is dropped
//! at decode. [`validate`] walks the value alongside go's struct layout (the
//! key names of `data/bookkeeping/block.go`, `data/transactions/teal.go`,
//! `agreement/bundle.go`, ...) and fails on the first such key; it checks the
//! shape (map / array / nil) and the key set, not the leaf values.

use algo_error::{AlgoError, Result};

use crate::rmp_decode::{
    is_nil, no_matching_field_error, read_bytes_go_compat, read_fixed_bytes_go_compat,
    read_key_bytes, read_map_len, read_u64,
};
use crate::SignedTransaction;

/// go's struct layout of a msgp value.
pub(crate) enum Sch {
    /// An unsigned integer (go's `uint64`, `Round`, `MicroAlgos`, ...).
    Uint,
    /// A byte string or Go string (`[]byte`, `string`).
    Bytes,
    /// A byte array of exactly this many bytes (`[32]byte`, ...).
    Fixed(usize),
    /// A fixed-size array of exactly this many elements.
    ArrN(usize, &'static Sch),
    /// A struct: exactly these keys.
    Struct(&'static [(&'static str, Sch)]),
    /// `map[string]T`: any string key.
    DictStr(&'static Sch),
    /// `map[uint64]T` (`StateProofType`, the local-delta account offset).
    DictU64(&'static Sch),
    /// A slice or fixed array.
    Arr(&'static Sch),
    /// Another schema, by reference (statics cannot embed each other by value).
    Ref(&'static Sch),
    /// `transactions.SignedTxnWithAD`, an inner transaction of an eval delta.
    InnerTxn,
}

fn err(msg: &str) -> AlgoError {
    AlgoError::Codec {
        source: msg.to_string().into(),
        context: "msgp_schema".into(),
    }
}

/// Validate the value at the front of `rd` against `sch`, advancing past it.
pub(crate) fn validate(rd: &mut &[u8], sch: &Sch) -> Result<()> {
    match sch {
        Sch::Uint => read_u64(rd).map(|_| ()),
        Sch::Bytes => read_bytes_go_compat(rd).map(|_| ()),
        Sch::Fixed(32) => read_fixed_bytes_go_compat::<32>(rd).map(|_| ()),
        Sch::Fixed(64) => read_fixed_bytes_go_compat::<64>(rd).map(|_| ()),
        Sch::Fixed(80) => read_fixed_bytes_go_compat::<80>(rd).map(|_| ()),
        Sch::Fixed(n) => Err(err(&format!("unsupported fixed size {n}"))),
        Sch::ArrN(want, v) => {
            let n = rmp::decode::read_array_len(rd).map_err(|e| err(&format!("array: {e}")))?;
            if n as usize != *want {
                return Err(err(&format!("array of {n}, want {want}")));
            }
            for _ in 0..n {
                validate(rd, v)?;
            }
            Ok(())
        }
        Sch::Struct(fields) => {
            let n = read_map_len(rd)?;
            for _ in 0..n {
                let key = read_key_bytes(rd)?;
                match fields.iter().find(|(k, _)| k.as_bytes() == key) {
                    Some((_, s)) => validate(rd, s)?,
                    None => return Err(no_matching_field_error(key)),
                }
            }
            Ok(())
        }
        Sch::DictStr(v) | Sch::DictU64(v) => {
            let by_str = matches!(sch, Sch::DictStr(_));
            let n = read_map_len(rd)?;
            for _ in 0..n {
                if by_str {
                    read_key_bytes(rd)?;
                } else {
                    read_u64(rd)?;
                }
                validate(rd, v)?;
            }
            Ok(())
        }
        Sch::Arr(v) => {
            if is_nil(rd) {
                *rd = &rd[1..];
                return Ok(());
            }
            let n = rmp::decode::read_array_len(rd).map_err(|e| err(&format!("array: {e}")))?;
            for _ in 0..n {
                validate(rd, v)?;
            }
            Ok(())
        }
        Sch::Ref(s) => validate(rd, s),
        Sch::InnerTxn => SignedTransaction::decode_inner_from_reader(rd).map(|_| ()),
    }
}

static VALUE_DELTA: Sch = Sch::Struct(&[("at", Sch::Uint), ("bs", Sch::Bytes), ("ui", Sch::Uint)]);
static STATE_DELTA: Sch = Sch::DictStr(&VALUE_DELTA);
static INNER_TXN: Sch = Sch::InnerTxn;

/// `transactions.EvalDelta`.
pub(crate) static EVAL_DELTA: Sch = Sch::Struct(&[
    ("gd", Sch::DictStr(&VALUE_DELTA)),
    ("ld", Sch::DictU64(&STATE_DELTA)),
    ("sa", Sch::Arr(&Sch::Fixed(32))),
    ("lg", Sch::Arr(&Sch::Bytes)),
    ("itx", Sch::Arr(&INNER_TXN)),
]);

/// `bookkeeping.BlockHeader.StateProofTracking`:
/// `map[protocol.StateProofType]StateProofTrackingData`.
pub(crate) static STATE_PROOF_TRACKING: Sch = Sch::DictU64(&Sch::Struct(&[
    ("v", Sch::Bytes),
    ("t", Sch::Uint),
    ("n", Sch::Uint),
]));

static PROPOSAL_VALUE: Sch = Sch::Struct(&[
    ("dig", Sch::Fixed(32)),
    ("encdig", Sch::Fixed(32)),
    ("oper", Sch::Uint),
    ("oprop", Sch::Fixed(32)),
]);
static CREDENTIAL: Sch = Sch::Struct(&[("pf", Sch::Fixed(80))]);
static ONE_TIME_SIG: Sch = Sch::Struct(&[
    ("p", Sch::Fixed(32)),
    ("p1s", Sch::Fixed(64)),
    ("p2", Sch::Fixed(32)),
    ("p2s", Sch::Fixed(64)),
    ("ps", Sch::Fixed(64)),
    ("s", Sch::Fixed(64)),
]);
static VOTE_AUTH: Sch = Sch::Struct(&[
    ("snd", Sch::Fixed(32)),
    ("cred", Sch::Ref(&CREDENTIAL)),
    ("sig", Sch::Ref(&ONE_TIME_SIG)),
]);
static EQV_AUTH: Sch = Sch::Struct(&[
    ("snd", Sch::Fixed(32)),
    ("cred", Sch::Ref(&CREDENTIAL)),
    ("sig", Sch::ArrN(2, &ONE_TIME_SIG)),
    ("props", Sch::ArrN(2, &PROPOSAL_VALUE)),
]);

/// `agreement.Certificate` (= `unauthenticatedBundle`).
pub(crate) static CERTIFICATE: Sch = Sch::Struct(&[
    ("rnd", Sch::Uint),
    ("per", Sch::Uint),
    ("step", Sch::Uint),
    ("prop", Sch::Ref(&PROPOSAL_VALUE)),
    ("vote", Sch::Arr(&VOTE_AUTH)),
    ("eqv", Sch::Arr(&EQV_AUTH)),
]);
