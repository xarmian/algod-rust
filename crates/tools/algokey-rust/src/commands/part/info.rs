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

//! `algokey part info` — open a partkey DB read-only, print its fields.
//!
//! Mirrors `../go-algorand/cmd/algokey/part.go::partInfoCmd.Run`
//! (lines 107-128, v4.6.0-stable).

use std::process::ExitCode;

use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::restore_participation;

use crate::cli::PartInfoArgs;
use crate::commands::part::print_partkey::print_partkey;

pub fn run(args: PartInfoArgs) -> ExitCode {
    let keyfile_display = args.keyfile.display().to_string();

    // Open read-write to mirror Go's `db.MakeErasableAccessor` semantics:
    // on a path that doesn't yet exist sqlite creates an empty file
    // (so the open call succeeds), and the subsequent restore fails
    // with `Cannot load partkey database …` rather than `Cannot open
    // …`. Aligning the open mode keeps both error paths byte-equal to
    // Go's `part info` wording.
    let db = match ErasableDb::open(&args.keyfile) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Cannot open partkey database {keyfile_display}: {e}");
            return ExitCode::from(1);
        }
    };

    let part = match restore_participation(&db) {
        Ok(p) => p,
        Err(e) => {
            // Drop the DB handle before printing, mirroring Go's
            // `partdb.Close()` immediately followed by the load-error
            // branch (part.go:121).
            drop(db);
            eprintln!("Cannot load partkey database {keyfile_display}: {e}");
            return ExitCode::from(1);
        }
    };
    drop(db);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = print_partkey(&mut out, &part) {
        eprintln!("Cannot write partkey info: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
