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

//! `algokey salted check-address` — mirrors `runSaltedCheckAddress`
//! (`salted.go`).

use std::io::Write;
use std::process::ExitCode;

use crate::cli::SaltedCheckAddressArgs;

use super::exit_on_error;

pub fn run(args: SaltedCheckAddressArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: SaltedCheckAddressArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    exit_on_error(run_salted_check_address(&args.address, stdout), stderr)
}

/// go's `runSaltedCheckAddress`: `basics.UnmarshalChecksumAddress`, then the
/// off-curve test.
pub fn run_salted_check_address<O: Write>(address: &str, stdout: &mut O) -> Result<(), String> {
    let bytes = algo_avm::assembler::unmarshal_checksum_address(address)
        .map_err(|e| format!("cannot parse address: {e}"))?;
    let addr = algo_types::Address(bytes.try_into().expect("32 bytes"));
    if !addr.is_off_ed25519_curve() {
        return Err(format!("address {addr} is on the Ed25519 curve"));
    }
    writeln!(stdout, "address {addr} is off the Ed25519 curve").map_err(|e| e.to_string())
}
