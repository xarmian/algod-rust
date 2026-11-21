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

//! Key-set validation of a block response's `cert`, which algod-rust keeps as
//! a raw `rmpv::Value` (issue #2394).
//!
//! go decodes it with a generated msgp decoder, which fails with
//! `msgp.ErrNoField` on a key the struct lacks, so a response with an unknown
//! key anywhere inside is dropped at decode. [`validate`] walks the value
//! alongside go's struct layout (`agreement/bundle.go`) and fails on the
//! first such key; it checks the shape (map / array / nil) and the key set,
//! not the leaf values. The value itself is read later, the way go reads it,
//! by `algo_agreement::codec::decode_bundle`. (`dt` and `spt`, the other two
//! opaque values, are decoded and re-encoded the way go does by
//! `go_eval_delta`, issue #2424.)

use algo_error::{AlgoError, Result};

use crate::rmp_decode::bounds::{self, AllocBound};
use crate::rmp_decode::{
    alloc_bounds_checked, no_matching_field_error, read_fixed_bytes_go_compat,
    read_go_array_header, read_u64, struct_keys,
};

/// go's struct layout of a msgp value.
pub(crate) enum Sch {
    /// An unsigned integer (go's `uint64`, `Round`, `MicroAlgos`, ...).
    Uint,
    /// A byte array of exactly this many bytes (`[32]byte`, ...).
    Fixed(usize),
    /// A fixed-size array `[N]T`: at most this many elements (go decodes
    /// fewer into the leading elements).
    ArrN(usize, &'static Sch),
    /// A struct of this go type (its positional order for the array form,
    /// issue #2426): exactly these keys.
    Struct(&'static str, &'static [(&'static str, Sch)]),
    /// A slice of at most this many elements (its `allocbound`, issue #2427).
    Arr(&'static AllocBound, &'static Sch),
    /// Another schema, by reference (statics cannot embed each other by value).
    Ref(&'static Sch),
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
        Sch::Fixed(32) => read_fixed_bytes_go_compat::<32>(rd).map(|_| ()),
        Sch::Fixed(64) => read_fixed_bytes_go_compat::<64>(rd).map(|_| ()),
        Sch::Fixed(80) => read_fixed_bytes_go_compat::<80>(rd).map(|_| ()),
        Sch::Fixed(n) => Err(err(&format!("unsupported fixed size {n}"))),
        // go `msgp.ReadArrayHeaderBytes`: nil and a fixmap (as an
        // interleaved key/value array) too
        Sch::ArrN(want, v) => {
            let (n, _) = read_go_array_header(rd)?;
            if n > *want {
                return Err(err(&format!("array of {n}, want at most {want}")));
            }
            for _ in 0..n {
                validate(rd, v)?;
            }
            Ok(())
        }
        Sch::Struct(go_type, fields) => {
            let mut keys = struct_keys(rd, &mut (), go_type)?;
            while let Some(key) = keys.next(rd)? {
                match fields.iter().find(|(k, _)| k.as_bytes() == key) {
                    Some((_, s)) => validate(rd, s)?,
                    None => return Err(no_matching_field_error(key)),
                }
            }
            Ok(())
        }
        Sch::Arr(bound, v) => {
            let bound = bound.get();
            let (n, _) = read_go_array_header(rd)?;
            // go's `msgp.ErrOverflow`, before reading an element
            if n > bound && alloc_bounds_checked() {
                return Err(err(&format!(
                    "array of {n} exceeds the allocation bound {bound}"
                )));
            }
            for _ in 0..n {
                validate(rd, v)?;
            }
            Ok(())
        }
        Sch::Ref(s) => validate(rd, s),
    }
}

static PROPOSAL_VALUE: Sch = Sch::Struct(
    "agreement.proposalValue",
    &[
        ("dig", Sch::Fixed(32)),
        ("encdig", Sch::Fixed(32)),
        ("oper", Sch::Uint),
        ("oprop", Sch::Fixed(32)),
    ],
);
static CREDENTIAL: Sch = Sch::Struct(
    "committee.UnauthenticatedCredential",
    &[("pf", Sch::Fixed(80))],
);
static ONE_TIME_SIG: Sch = Sch::Struct(
    "crypto.OneTimeSignature",
    &[
        ("p", Sch::Fixed(32)),
        ("p1s", Sch::Fixed(64)),
        ("p2", Sch::Fixed(32)),
        ("p2s", Sch::Fixed(64)),
        ("ps", Sch::Fixed(64)),
        ("s", Sch::Fixed(64)),
    ],
);
static VOTE_AUTH: Sch = Sch::Struct(
    "agreement.voteAuthenticator",
    &[
        ("snd", Sch::Fixed(32)),
        ("cred", Sch::Ref(&CREDENTIAL)),
        ("sig", Sch::Ref(&ONE_TIME_SIG)),
    ],
);
static EQV_AUTH: Sch = Sch::Struct(
    "agreement.equivocationVoteAuthenticator",
    &[
        ("snd", Sch::Fixed(32)),
        ("cred", Sch::Ref(&CREDENTIAL)),
        ("sig", Sch::ArrN(2, &ONE_TIME_SIG)),
        ("props", Sch::ArrN(2, &PROPOSAL_VALUE)),
    ],
);

/// `agreement.Certificate` (= `unauthenticatedBundle`).
pub(crate) static CERTIFICATE: Sch = Sch::Struct(
    "agreement.Certificate",
    &[
        ("rnd", Sch::Uint),
        ("per", Sch::Uint),
        ("step", Sch::Uint),
        ("prop", Sch::Ref(&PROPOSAL_VALUE)),
        ("vote", Sch::Arr(&bounds::MAX_VOTE_THRESHOLD, &VOTE_AUTH)),
        ("eqv", Sch::Arr(&bounds::MAX_VOTE_THRESHOLD, &EQV_AUTH)),
    ],
);
