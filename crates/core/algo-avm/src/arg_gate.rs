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

//! go's argument gate (`EvalContext.step`, `data/transactions/logic/eval.go`):
//! before an opcode runs, and before its cost is charged, go checks the stack
//! height (`stack underflow in <op>`) and then every argument from argument 0
//! upward (`<op> arg <i> wanted <T> but got <U>`), from the opcode's `proto`
//! argument types (`opcodes.go`).
//!
//! algod-rust's opcode handlers pop lazily from the top, which reports the
//! wrong argument (the top one) and charges the cost first. This table lets
//! `AvmMachine::step` run go's gate for the opcodes listed here. It lists only
//! opcodes whose `proto` is known with certainty (each row is go's
//! `proto("...")` argument half); every other opcode keeps the lazy behaviour,
//! so a table row can only ever make an error exact, never create one go would
//! not raise: a row is checked against the value types the handler would have
//! popped anyway. Issue #2200 (the rest of the table: #2225).

/// An argument type of go's `proto`: `i` (uint64), `b` (bytes), `a` (any).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ArgType {
    Uint,
    Bytes,
    Any,
}

impl ArgType {
    /// go's `StackType.String()` for the type an argument wants.
    pub(crate) fn name(self) -> &'static str {
        match self {
            ArgType::Uint => "uint64",
            ArgType::Bytes => "[]byte",
            ArgType::Any => "any",
        }
    }
}

use ArgType::{Any, Bytes, Uint};

const U1: &[ArgType] = &[Uint];
const U2: &[ArgType] = &[Uint, Uint];
const U3: &[ArgType] = &[Uint, Uint, Uint];
const U4: &[ArgType] = &[Uint, Uint, Uint, Uint];
const B1: &[ArgType] = &[Bytes];
const B2: &[ArgType] = &[Bytes, Bytes];
const B3: &[ArgType] = &[Bytes, Bytes, Bytes];
const BUU: &[ArgType] = &[Bytes, Uint, Uint];
const BU: &[ArgType] = &[Bytes, Uint];
const A1: &[ArgType] = &[Any];

/// go's `proto` argument types by opcode byte (`opcodes.go`).
static GATE: [Option<&[ArgType]>; 256] = {
    let mut t: [Option<&[ArgType]>; 256] = [None; 256];
    // sha256, keccak256, sha512_256: "b:b{32}"
    t[0x01] = Some(B1);
    t[0x02] = Some(B1);
    t[0x03] = Some(B1);
    // ed25519verify: "bb{64}b{32}:T"
    t[0x04] = Some(B3);
    // + - / * < > <= >= && ||: "ii:i" / "ii:T"
    let mut b = 0x08;
    while b <= 0x11 {
        t[b] = Some(U2);
        b += 1;
    }
    t[0x14] = Some(U1); // !
    t[0x15] = Some(B1); // len
    t[0x16] = Some(U1); // itob
    t[0x17] = Some(B1); // btoi
    t[0x18] = Some(U2); // %
    t[0x19] = Some(U2); // |
    t[0x1a] = Some(U2); // &
    t[0x1b] = Some(U2); // ^
    t[0x1c] = Some(U1); // ~
    t[0x1d] = Some(U2); // mulw
    t[0x1e] = Some(U2); // addw
    t[0x1f] = Some(U4); // divmodw
    t[0x40] = Some(U1); // bnz
    t[0x41] = Some(U1); // bz
    t[0x43] = Some(U1); // return
    t[0x44] = Some(U1); // assert
    t[0x48] = Some(A1); // pop
    t[0x50] = Some(B2); // concat
    t[0x51] = Some(B1); // substring
    t[0x52] = Some(BUU); // substring3
    t[0x55] = Some(BU); // getbyte
    t[0x58] = Some(BUU); // extract3
    t[0x90] = Some(U2); // shl
    t[0x91] = Some(U2); // shr
    t[0x92] = Some(U1); // sqrt
    t[0x93] = Some(A1); // bitlen
    t[0x94] = Some(U2); // exp
    t[0x95] = Some(U2); // expw
    t[0x96] = Some(B1); // bsqrt
    t[0x97] = Some(U3); // divw
                        // b+ b- b/ b* b< b> b<= b>= b== b!= b%: "II:.."
    let mut b = 0xa0;
    while b <= 0xaa {
        t[b] = Some(B2);
        b += 1;
    }
    t[0xaf] = Some(U1); // bzero
    t
};

/// Whether `value` satisfies go's `opCompat` for an argument of type `want`.
#[inline(always)]
pub(crate) fn accepts(want: ArgType, value: &crate::machine::AvmValue) -> bool {
    use crate::machine::AvmValue;
    match want {
        ArgType::Any => true,
        ArgType::Uint => matches!(value, AvmValue::Uint64(_)),
        ArgType::Bytes => matches!(value, AvmValue::Bytes(_)),
    }
}

/// go's argument types for the single-byte opcode `opcode`, if this table
/// lists it.
#[inline]
pub(crate) fn arg_types(opcode: u8) -> Option<&'static [ArgType]> {
    GATE[opcode as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table agrees with the opcode table on how many values each listed
    /// opcode pops (where that table says), so a wrong row shows up here.
    #[test]
    fn rows_match_the_opcode_tables_pop_counts() {
        for byte in 0..=255u8 {
            let Some(types) = arg_types(byte) else {
                continue;
            };
            let spec = crate::opcode::lookup(byte)
                .unwrap_or_else(|| panic!("gate row for undefined opcode 0x{byte:02x}"));
            if spec.stack_pops >= 0 {
                assert_eq!(
                    types.len(),
                    spec.stack_pops as usize,
                    "0x{byte:02x} {}",
                    spec.name
                );
            }
        }
    }
}
