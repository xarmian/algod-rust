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

//! `algokey part generate` — generate + persist a fresh participation key.
//!
//! Mirrors `../go-algorand/cmd/algokey/part.go::partGenerateCmd.Run`
//! (lines 49-105, v4.6.0-stable).

use std::process::ExitCode;
use std::str::FromStr;

use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::{
    default_key_dilution, fill_db_with_participation_keys, FillError,
};
use algo_types::{Address, Round};

use crate::cli::PartGenerateArgs;
use crate::commands::part::print_partkey::print_partkey;
use crate::ui::spinner::run_with_spinner;

pub fn run(args: PartGenerateArgs) -> ExitCode {
    let PartGenerateArgs {
        keyfile,
        first,
        last,
        dilution,
        parent,
    } = args;

    // 1. Range validation — Go wording.
    if last < first {
        eprintln!("Last round {last} < first round {first}");
        return ExitCode::from(1);
    }

    // 2. Default dilution.
    let dilution = if dilution == 0 {
        default_key_dilution(Round(first), Round(last))
    } else {
        dilution
    };

    // 3. Parse parent (defaults to all-zero address when absent).
    let parent_addr = match parent.as_deref() {
        None | Some("") => Address([0u8; 32]),
        Some(s) => match Address::from_str(s) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Cannot parse parent address {s}: {e}");
                return ExitCode::from(1);
            }
        },
    };

    let keyfile_display = keyfile.display().to_string();

    // 4. Open the DB.
    let mut db = match ErasableDb::open(&keyfile) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Cannot open partkey database {keyfile_display}: {e}");
            return ExitCode::from(1);
        }
    };

    // 5. Status line — Go uses `fmt.Println` so the newline is implicit.
    println!("Please stand by while generating keys. This might take a few minutes...");

    // 6. Fill the DB under the spinner. The spinner becomes a no-op when
    // stderr isn't a TTY (TASK-178), so piped logs stay clean.
    let result = run_with_spinner(|| {
        fill_db_with_participation_keys(&mut db, parent_addr, Round(first), Round(last), dilution)
    });

    // 7. Error path: report + best-effort delete of the partially-written
    // keyfile, mirroring Go's `os.Remove + Failed to cleanup` chain.
    let part = match result {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "Cannot generate partkey database {keyfile_display}: {}",
                fill_error_display(&e)
            );
            // Drop the DB handle first so the WAL/journal sidecar files
            // can be cleaned up alongside the main file.
            drop(db);
            if let Err(rm_err) = std::fs::remove_file(&keyfile) {
                eprintln!("Failed to cleanup the database file {keyfile_display}: {rm_err}");
            }
            return ExitCode::from(1);
        }
    };

    // 8. Success path: confirmation, printed info, version footer.
    drop(db);
    println!("Participation key generation successful");

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = print_partkey(&mut out, &part) {
        eprintln!("Cannot write partkey info: {e}");
        return ExitCode::from(1);
    }

    println!("\nGenerated with algokey v{}", env!("CARGO_PKG_VERSION"));
    ExitCode::SUCCESS
}

/// Render a `FillError` the way Go would format the underlying error.
///
/// All `FillError::Display` variants already match Go's wording; this
/// indirection exists so future divergence (e.g. should the
/// `InvalidRange` wording need an extra layer of message) can be
/// applied here without touching the call site.
fn fill_error_display(e: &FillError) -> String {
    format!("{e}")
}
