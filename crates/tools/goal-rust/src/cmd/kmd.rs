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

//! `goal kmd` — port of `../go-algorand/cmd/goal/kmd.go`.

//! `goal kmd start | stop` -- port of `cmd/goal/kmd.go` (issue #1993).

use std::path::PathBuf;
use std::process::ExitCode;

use crate::data_dir;
use crate::groups::kmd::StartArgs;
use crate::kmdcontrol::KmdController;

/// `messages.go:50-55`.
const INFO_KMD_STOPPED: &str = "Stopped kmd";
const INFO_KMD_ALREADY_STARTED: &str = "kmd is already running";
const INFO_KMD_ALREADY_STOPPED: &str = "kmd doesn't appear to be running";
const INFO_KMD_STARTED: &str = "Successfully started kmd";
const ERROR_KMD_FAILED_TO_START: &str = "Failed to start kmd: ";
const ERROR_KMD_FAILED_TO_STOP: &str = "Failed to stop kmd: ";

fn kmd_dirs(cli_d: &[PathBuf], kmd_dir_flag: Option<PathBuf>) -> Result<Vec<PathBuf>, ExitCode> {
    let dirs = data_dir::resolve_data_dirs(cli_d).map_err(|e| {
        eprintln!("{e}");
        ExitCode::from(1)
    })?;
    dirs.iter()
        .map(|d| {
            data_dir::resolve_kmd_data_dir(kmd_dir_flag.as_deref(), d).map_err(|e| {
                eprintln!("{e}");
                ExitCode::from(1)
            })
        })
        .collect()
}

/// Port of `startKMDCmd` (`kmd.go:64-77`): stop a running kmd first (so an
/// updated timeout takes effect), then start it.
pub fn run_start(args: StartArgs, cli_d: Vec<PathBuf>, kmd_dir_flag: Option<PathBuf>) -> ExitCode {
    let dirs = match kmd_dirs(&cli_d, kmd_dir_flag) {
        Ok(d) => d,
        Err(code) => return code,
    };
    for kmd_dir in dirs {
        let nc = KmdController::new(&kmd_dir);
        let _ = nc.stop();
        match nc.start(args.timeout) {
            Ok(true) => println!("{INFO_KMD_ALREADY_STARTED}"),
            Ok(false) => println!("{INFO_KMD_STARTED}"),
            Err(e) => {
                eprintln!("{ERROR_KMD_FAILED_TO_START}{e}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}

/// Port of `stopKMDCmd` (`kmd.go:79-100`).
pub fn run_stop(cli_d: Vec<PathBuf>, kmd_dir_flag: Option<PathBuf>) -> ExitCode {
    let dirs = match kmd_dirs(&cli_d, kmd_dir_flag) {
        Ok(d) => d,
        Err(code) => return code,
    };
    for kmd_dir in dirs {
        match KmdController::new(&kmd_dir).stop() {
            Ok(true) => println!("{INFO_KMD_ALREADY_STOPPED}"),
            Ok(false) => println!("{INFO_KMD_STOPPED}"),
            Err(e) => {
                eprintln!("{ERROR_KMD_FAILED_TO_STOP}{e}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}
