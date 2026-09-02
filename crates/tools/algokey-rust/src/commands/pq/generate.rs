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

//! `algokey pq generate` — mirrors `runPQGenerate` (`pq.go:192-210`).

use std::io::Write;
use std::process::ExitCode;

use crate::cli::PqGenerateArgs;

use super::key::write_pq_private_key_file;
use super::scheme::{generate_pq_signing_material, parse_pq_scheme};
use super::{print_pq_key_info, print_pq_mnemonic};

pub fn run(args: PqGenerateArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: PqGenerateArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    let scheme = match parse_pq_scheme(&args.scheme) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "cannot generate PQ key: {e}");
            return ExitCode::from(1);
        }
    };
    let (entropy, signing) = match generate_pq_signing_material(scheme) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "cannot generate PQ key: {e}");
            return ExitCode::from(1);
        }
    };

    if let Err(e) = write_pq_private_key_file(&args.keyfile, &signing) {
        let _ = writeln!(
            stderr,
            "cannot write private key to {}: {e}",
            args.keyfile.display()
        );
        return ExitCode::from(1);
    }
    if let Err(e) = print_pq_mnemonic(stdout, &entropy) {
        let _ = writeln!(stderr, "cannot write to stdout: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = print_pq_key_info(stdout, &signing.public) {
        let _ = writeln!(stderr, "cannot write to stdout: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_writes_keyfile_and_prints_mnemonic_and_info() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            crate::cli::PqGenerateArgs {
                scheme: "falcon-1024".to_string(),
                keyfile: kf.clone(),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(err.is_empty(), "stderr: {}", String::from_utf8_lossy(&err));

        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("PQ private key mnemonic: "));
        assert!(text.contains("PQ scheme: falcon-1024"));
        assert!(text.contains("PQ public key: "));
        assert!(text.contains("PQ address: "));

        // Keyfile must round-trip through the reader and validate.
        let read_back = super::super::key::read_pq_signing_material(&kf).unwrap();
        read_back.validate().unwrap();
    }

    #[test]
    fn generate_with_unsupported_scheme_fails_before_writing_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            crate::cli::PqGenerateArgs {
                scheme: "bogus-scheme-name".to_string(),
                keyfile: kf.clone(),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        assert!(!kf.exists());
        assert!(out.is_empty());
    }
}
