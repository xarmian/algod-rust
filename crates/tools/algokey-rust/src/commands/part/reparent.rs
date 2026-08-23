//! `algokey part reparent` — change the parent address on a partkey DB.
//!
//! Mirrors `../go-algorand/cmd/algokey/part.go::partReparentCmd.Run`
//! (lines 130-164, v4.6.0-stable):
//!
//! 1. Parse `--parent` via `Address::from_str` (Go: `UnmarshalChecksumAddress`).
//! 2. Open the partkey DB via `ErasableDb::open` (matches Go's
//!    `db.MakeErasableAccessor` — read-write).
//! 3. Restore the `Participation`.
//! 4. Mutate `parent`, persist via [[TASK-175]]'s `persist_new_parent`.
//! 5. Print the updated partkey via the shared `print_partkey` formatter.

use std::process::ExitCode;
use std::str::FromStr;

use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::{persist_new_parent, restore_participation};
use algo_types::Address;

use crate::cli::PartReparentArgs;
use crate::commands::part::print_partkey::print_partkey;

pub fn run(args: PartReparentArgs) -> ExitCode {
    let PartReparentArgs { keyfile, parent } = args;
    let keyfile_display = keyfile.display().to_string();

    // 1. Parse parent.
    let new_parent = match Address::from_str(&parent) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Cannot parse parent address {parent}: {e}");
            return ExitCode::from(1);
        }
    };

    // 2. Open DB (read-write, matching Go's MakeErasableAccessor).
    let mut db = match ErasableDb::open(&keyfile) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Cannot open partkey database {keyfile_display}: {e}");
            return ExitCode::from(1);
        }
    };

    // 3. Restore.
    let mut part = match restore_participation(&db) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Cannot load partkey database {keyfile_display}: {e}");
            return ExitCode::from(1);
        }
    };

    // 4. Mutate + persist.
    part.parent = new_parent;
    if let Err(e) = persist_new_parent(&mut db, new_parent) {
        eprintln!("Cannot persist partkey database {keyfile_display}: {e}");
        return ExitCode::from(1);
    }
    drop(db);

    // 5. Print the updated partkey.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = print_partkey(&mut out, &part) {
        eprintln!("Cannot write partkey info: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
