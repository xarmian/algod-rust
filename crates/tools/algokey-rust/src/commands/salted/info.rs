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

//! `algokey salted info` — mirrors `runSaltedInfo` (`salted.go`).

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::SaltedInfoArgs;

use super::key::read_salted_signing_material;
use super::{exit_on_error, print_salted_key_info};

pub fn run(args: SaltedInfoArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: SaltedInfoArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    exit_on_error(run_salted_info(&args.keyfile, stdout), stderr)
}

/// go's `runSaltedInfo`.
pub fn run_salted_info<O: Write>(keyfile: &Path, stdout: &mut O) -> Result<(), String> {
    let signing = read_salted_signing_material(keyfile)?;
    print_salted_key_info(stdout, &signing.public).map_err(|e| e.to_string())
}
