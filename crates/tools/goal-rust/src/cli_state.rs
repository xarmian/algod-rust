//! Thread-local snapshot of the parsed root `Cli` flags
//! (`-d/--datadir`, `-k/--kmddir`). Clap's `Subcommand` enums don't
//! receive the parent struct's `#[arg(global = true)]` fields by
//! default — leaves see only their own argv. We capture the global
//! flags in `main` immediately after `Cli::parse()` and read them
//! back from leaf handlers via [`datadirs`] / [`kmddir`].
//!
//! Single-threaded by design (the CLI does its work on the main
//! thread, then tokio handles async I/O off it).

use std::cell::RefCell;
use std::path::PathBuf;

thread_local! {
    static DATADIRS: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
    static KMDDIR: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Called once from `main` after [`Cli::parse`](crate::Cli::parse).
pub fn install(datadirs: Vec<PathBuf>, kmddir: Option<PathBuf>) {
    DATADIRS.with(|d| *d.borrow_mut() = datadirs);
    KMDDIR.with(|k| *k.borrow_mut() = kmddir);
}

/// Snapshot of `-d/--datadir` flags in argv order. Empty if none.
pub fn datadirs() -> Vec<PathBuf> {
    DATADIRS.with(|d| d.borrow().clone())
}

/// Snapshot of `-k/--kmddir` flag.
pub fn kmddir() -> Option<PathBuf> {
    KMDDIR.with(|k| k.borrow().clone())
}
