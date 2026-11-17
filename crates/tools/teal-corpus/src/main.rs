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

//! `teal-corpus` CLI (#2366): `disassemble` / `assemble` batch drivers over a
//! corpus directory and the `diff` command. Exit codes: 0 success, 1 `diff`
//! found mismatches, 2 usage or I/O error, 3 a panic or timeout was recorded.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use teal_corpus::{
    diff_files, has_robustness_failure, install_quiet_panic_hook, load_inputs, process,
    render_output, run_batch, Operation,
};

#[derive(Parser)]
#[command(name = "teal-corpus", about = "Offline TEAL corpus drivers and diff")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Args)]
struct RunArgs {
    /// Corpus directory produced by scripts/teal-corpus/extract.py.
    #[arg(long)]
    corpus: PathBuf,
    /// Override the input directory (default: <corpus>/programs or <corpus>/sources).
    #[arg(long)]
    input_dir: Option<PathBuf>,
    /// Output JSONL file (default: stdout).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Parallel workers (default: available parallelism).
    #[arg(long)]
    jobs: Option<usize>,
    /// Per-input time budget in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
}

#[derive(Subcommand)]
enum Cmd {
    /// Disassemble every programs/*.bin.
    Disassemble(RunArgs),
    /// Assemble every sources/*.teal.
    Assemble(RunArgs),
    /// Compare two driver outputs; writes mismatches.jsonl rows.
    Diff {
        left: PathBuf,
        right: PathBuf,
        /// Mismatch report file (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn write_out(path: &Option<PathBuf>, data: &[u8]) -> std::io::Result<()> {
    match path {
        Some(p) => std::fs::write(p, data),
        None => std::io::stdout().write_all(data),
    }
}

fn run(op: Operation, a: RunArgs) -> i32 {
    let dir = a
        .input_dir
        .unwrap_or_else(|| a.corpus.join(op.input_subdir()));
    let inputs = match load_inputs(&dir, op.input_ext()) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: reading {}: {e}", dir.display());
            return 2;
        }
    };
    let jobs = a.jobs.unwrap_or_else(|| {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    });
    install_quiet_panic_hook();
    let rows = run_batch(
        inputs,
        jobs,
        Duration::from_millis(a.timeout_ms),
        move |i| process(op, i),
    );
    if let Err(e) = write_out(&a.out, render_output(op, &rows).as_bytes()) {
        eprintln!("error: writing output: {e}");
        return 2;
    }
    let ok = rows.iter().filter(|r| r.ok).count();
    let panics = rows.iter().filter(|r| r.panic.is_some()).count();
    let timeouts = rows.iter().filter(|r| r.timeout == Some(true)).count();
    eprintln!(
        "{}: {} inputs, {} ok, {} error, {} panic, {} timeout",
        op.name(),
        rows.len(),
        ok,
        rows.len() - ok - panics - timeouts,
        panics,
        timeouts
    );
    if has_robustness_failure(&rows) {
        3
    } else {
        0
    }
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Cmd::Disassemble(a) => run(Operation::Disassemble, a),
        Cmd::Assemble(a) => run(Operation::Assemble, a),
        Cmd::Diff { left, right, out } => match diff_files(&left, &right) {
            Err(e) => {
                eprintln!("error: {e}");
                2
            }
            Ok(rep) => {
                let mut body = String::new();
                for m in &rep.mismatches {
                    body.push_str(&m.to_string());
                    body.push('\n');
                }
                if let Err(e) = write_out(&out, body.as_bytes()) {
                    eprintln!("error: writing report: {e}");
                    std::process::exit(2);
                }
                eprintln!(
                    "diff {}: {} rows compared, {} identical, {} both-error-identical, {} mismatches, {} panics/timeouts",
                    rep.operation,
                    rep.compared,
                    rep.identical,
                    rep.both_error_identical,
                    rep.mismatches.len(),
                    rep.robustness_failures
                );
                if rep.both_panic_identical > 0 {
                    eprintln!(
                        "diff {}: {} rows are the same panic on both sides (go's assembler panic, mirrored as a typed condition)",
                        rep.operation, rep.both_panic_identical
                    );
                }
                i32::from(!rep.mismatches.is_empty() || rep.robustness_failures > 0)
            }
        },
    };
    // Hung worker threads cannot be joined; exit without waiting for them.
    std::process::exit(code);
}
