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

//! `algokey pq import` — mirrors `runPQImportWithOptions` (`pq.go:224-243`).
//! Unlike ed25519 `algokey import`, Go does NOT echo the mnemonic back on
//! `pq import` — only the derived key info is printed.

use std::io::Write;
use std::process::ExitCode;

use algo_consensus_crypto::mnemonic_to_key;

use crate::cli::PqImportArgs;

use super::key::write_pq_private_key_file;
use super::print_pq_key_info;
use super::scheme::{derive_pq_signing_material_from_entropy, parse_pq_scheme};

pub fn run(args: PqImportArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: PqImportArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    let entropy = match mnemonic_to_key(&args.mnemonic) {
        Ok(e) => e,
        Err(e) => {
            let _ = writeln!(stderr, "cannot recover PQ key entropy from mnemonic: {e}");
            return ExitCode::from(1);
        }
    };
    let scheme = match parse_pq_scheme(&args.scheme) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return ExitCode::from(1);
        }
    };
    let signing = match derive_pq_signing_material_from_entropy(scheme, &entropy) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
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
    if let Err(e) = print_pq_key_info(stdout, &signing.public) {
        let _ = writeln!(stderr, "cannot write to stdout: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_consensus_crypto::key_to_mnemonic;
    use algo_types::PQ_SCHEME_FALCON1024;

    #[test]
    fn import_round_trips_generate_output() {
        let (entropy, signing) =
            super::super::scheme::generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let mnemonic = key_to_mnemonic(&entropy).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqImportArgs {
                mnemonic,
                scheme: "falcon-1024".to_string(),
                keyfile: kf.clone(),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(err.is_empty());
        // Does NOT echo the mnemonic (unlike ed25519 `import`).
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("mnemonic"));

        let read_back = super::super::key::read_pq_signing_material(&kf).unwrap();
        assert_eq!(read_back, signing);
    }

    #[test]
    fn import_rejects_bad_mnemonic() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("k");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqImportArgs {
                mnemonic: "not a valid mnemonic".to_string(),
                scheme: "falcon-1024".to_string(),
                keyfile: kf,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        assert!(out.is_empty());
    }
}
