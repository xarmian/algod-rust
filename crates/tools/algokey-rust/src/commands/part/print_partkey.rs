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

//! Shared `printPartkey` formatter for `part info`, `part generate`, and
//! `part reparent`.
//!
//! Output byte-equal to `../go-algorand/cmd/algokey/part.go::printPartkey`
//! (lines 166-179, v4.6.0-stable). Base64 uses the standard alphabet
//! with padding (Go `base64.StdEncoding`).

use std::io::Write;

use algo_ledger::participation::Participation;

const B64: data_encoding::Encoding = data_encoding::BASE64;

/// Write the canonical `printPartkey` output to `out`.
///
/// Match Go exactly, including column alignment (note the extra spaces
/// before the state-proof lifetime value to match Go's wider label).
pub fn print_partkey<W: Write>(out: &mut W, partkey: &Participation) -> std::io::Result<()> {
    writeln!(out, "Parent address:    {}", partkey.parent)?;
    writeln!(out, "VRF public key:    {}", B64.encode(&partkey.vrf.pk.0))?;
    writeln!(
        out,
        "Voting public key: {}",
        B64.encode(&partkey.voting.verifier())
    )?;
    if let Some(ref sp) = partkey.state_proof_secrets {
        let v = sp.signer_context.get_verifier();
        // Mirror Go's `MsgIsZero()` check: omit the lines when the
        // verifier carries no meaningful data (zero commitment AND zero
        // key_lifetime).
        let commitment_zero = v.commitment.iter().all(|&b| b == 0);
        if !(commitment_zero && v.key_lifetime == 0) {
            writeln!(out, "State proof key:   {}", B64.encode(&v.commitment))?;
            writeln!(out, "State proof key lifetime:   {}", v.key_lifetime)?;
        }
    }
    writeln!(out, "First round:       {}", partkey.first_valid.0)?;
    writeln!(out, "Last round:        {}", partkey.last_valid.0)?;
    writeln!(out, "Key dilution:      {}", partkey.key_dilution)?;
    writeln!(out, "First batch:       {}", partkey.voting.first_batch())?;
    writeln!(out, "First offset:      {}", partkey.voting.first_offset())?;
    Ok(())
}
