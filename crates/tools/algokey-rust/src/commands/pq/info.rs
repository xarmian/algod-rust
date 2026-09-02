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

//! `algokey pq info` — mirrors `runPQInfo` (`pq.go:212-218`).

use std::io::Write;
use std::process::ExitCode;

use crate::cli::PqInfoArgs;

use super::key::read_pq_signing_material;
use super::print_pq_key_info;

pub fn run(args: PqInfoArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: PqInfoArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    let signing = match read_pq_signing_material(&args.keyfile) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = print_pq_key_info(stdout, &signing.public) {
        let _ = writeln!(stderr, "cannot write to stdout: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::pq::key::write_pq_private_key_file;
    use crate::commands::pq::scheme::generate_pq_signing_material;
    use algo_types::PQ_SCHEME_FALCON1024;

    #[test]
    fn info_prints_key_info_for_valid_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        let (_, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        write_pq_private_key_file(&kf, &signing).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(PqInfoArgs { keyfile: kf }, &mut out, &mut err);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(&format!("PQ address: {}", signing.public.address())));
    }

    #[test]
    fn info_fails_on_missing_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("does-not-exist");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(PqInfoArgs { keyfile: kf }, &mut out, &mut err);
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        assert!(out.is_empty());
        assert!(!err.is_empty());
    }
}
