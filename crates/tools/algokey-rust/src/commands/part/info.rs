//! `algokey part info` — open a partkey DB read-only, print its fields.
//!
//! Mirrors `../go-algorand/cmd/algokey/part.go::partInfoCmd.Run`
//! (lines 107-128, v4.5.1-stable).

use std::process::ExitCode;

use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::restore_participation;

use crate::cli::PartInfoArgs;
use crate::commands::part::print_partkey::print_partkey;

pub fn run(args: PartInfoArgs) -> ExitCode {
    let keyfile_display = args.keyfile.display().to_string();

    // Match Go's two distinct error wordings (`Cannot open …` vs
    // `Cannot load …`) by separating the open + load failures.
    let db = match ErasableDb::open_read_only(&args.keyfile) {
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
