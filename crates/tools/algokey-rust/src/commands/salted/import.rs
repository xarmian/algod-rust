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

//! `algokey salted import` — mirrors `runSaltedImportWithOptions`
//! (`salted.go`). Unlike ed25519 `algokey import`, go does NOT echo the
//! mnemonic back: only the derived key info is printed.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::SaltedImportArgs;

use super::key::write_salted_private_key_file;
use super::scheme::{derive_salted_signing_material_from_entropy, parse_sig_scheme};
use super::{exit_on_error, print_salted_key_info, seed_from_mnemonic, ERR_SCHEME_REQUIRED};

pub fn run(args: SaltedImportArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: SaltedImportArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    exit_on_error(
        run_salted_import_with_options(&args.mnemonic, &args.scheme, &args.keyfile, stdout),
        stderr,
    )
}

/// go's `runSaltedImportWithOptions(mnemonic, schemeName, keyfile)`: the scheme
/// must be given, then the mnemonic is decoded, then the scheme parsed.
pub fn run_salted_import_with_options<O: Write>(
    mnemonic: &str,
    scheme_name: &str,
    keyfile: &Path,
    stdout: &mut O,
) -> Result<(), String> {
    if scheme_name.is_empty() {
        return Err(ERR_SCHEME_REQUIRED.to_string());
    }
    let entropy = seed_from_mnemonic(mnemonic)
        .map_err(|e| format!("cannot recover key entropy from mnemonic: {e}"))?;
    let scheme = parse_sig_scheme(scheme_name)?;
    let signing = derive_salted_signing_material_from_entropy(scheme, &entropy)?;

    write_salted_private_key_file(keyfile, &signing)?;
    print_salted_key_info(stdout, &signing.public).map_err(|e| e.to_string())
}
