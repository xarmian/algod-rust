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

//! `algokey pq sign-program` — mirrors `runPQSignProgramWithOptions`
//! (`pq.go:374-406`): sign a compiled LogicSig program with a PQ private
//! key and write the resulting `LogicSig` (program + `PQsig`).

use std::io::Write;
use std::process::ExitCode;

use algo_codec::canonical_encode_logicsig;
use algo_types::{LogicSig, PQDelegatedProgram};
use serde_bytes::ByteBuf;

use crate::cli::PqSignProgramArgs;
use crate::common::write_with_mode_0600;

use super::context::{resolve_pq_signing_context, sign_pq};
use super::looks_like_teal_source;

pub fn run(args: PqSignProgramArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: PqSignProgramArgs,
    _stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    let ctx = match resolve_pq_signing_context(
        args.keyfile.as_deref(),
        args.mnemonic.as_deref(),
        &args.scheme,
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return ExitCode::from(1);
        }
    };

    let program = match std::fs::read(&args.program) {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "cannot read program from {}: {e}",
                args.program.display()
            );
            return ExitCode::from(1);
        }
    };
    if program.is_empty() {
        let _ = writeln!(stderr, "program is empty");
        return ExitCode::from(1);
    }
    let program_path_str = args.program.to_string_lossy();
    if program_path_str.ends_with(".teal") {
        let _ = writeln!(
            stderr,
            "{program_path_str} looks like TEAL source; compile it first (e.g. goal clerk compile) and don't use the .teal extension"
        );
        return ExitCode::from(1);
    }
    if looks_like_teal_source(&program) {
        let _ = writeln!(
            stderr,
            "program is not compiled bytecode; compile it first (e.g. goal clerk compile) and don't use the .teal extension"
        );
        return ExitCode::from(1);
    }

    let dp = PQDelegatedProgram {
        addr: ctx.signing.public.address(),
        program: program.clone(),
    };
    let pqsig = match sign_pq(&ctx, &dp.to_be_signed()) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "cannot sign program: {e}");
            return ExitCode::from(1);
        }
    };

    let lsig = LogicSig {
        logic: ByteBuf::from(program),
        pqsig: Some(pqsig),
        ..LogicSig::default()
    };
    if let Err(e) = write_with_mode_0600(&args.outfile, &canonical_encode_logicsig(&lsig)) {
        let _ = writeln!(
            stderr,
            "cannot write LogicSig to {}: {e}",
            args.outfile.display()
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::pq::scheme::generate_pq_signing_material;
    use algo_types::PQ_SCHEME_FALCON1024;

    fn write_keyfile(
        dir: &std::path::Path,
    ) -> (std::path::PathBuf, super::super::key::PqSigningMaterial) {
        let (_, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let kf = dir.join("k");
        super::super::key::write_pq_private_key_file(&kf, &signing).unwrap();
        (kf, signing)
    }

    #[test]
    fn sign_program_writes_logicsig_with_valid_pqsig() {
        let dir = tempfile::tempdir().unwrap();
        let (kf, signing) = write_keyfile(dir.path());
        let program_path = dir.path().join("prog.bin");
        // Not valid TEAL bytecode semantically, but binary (non-ASCII) so it
        // doesn't trip the TEAL-source heuristic.
        std::fs::write(&program_path, [0x08u8, 0x22, 0x00, 0xffu8]).unwrap();
        let outfile = dir.path().join("out.lsig");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqSignProgramArgs {
                keyfile: Some(kf),
                mnemonic: None,
                scheme: "falcon-1024".to_string(),
                program: program_path.clone(),
                outfile: outfile.clone(),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", ExitCode::SUCCESS),
            "stderr: {}",
            String::from_utf8_lossy(&err)
        );

        let produced = std::fs::read(&outfile).unwrap();
        // Decode via rmp_serde since LogicSig implements Deserialize.
        let lsig: LogicSig = rmp_serde::from_slice(&produced).expect("decode LogicSig");
        assert_eq!(lsig.logic.as_slice(), [0x08u8, 0x22, 0x00, 0xff].as_slice());
        let pqsig = lsig.pqsig.expect("pqsig set");

        let dp = PQDelegatedProgram {
            addr: signing.public.address(),
            program: lsig.logic.to_vec(),
        };
        assert!(algo_falcon::falcon_verify(
            &pqsig.public_key,
            &pqsig.signature,
            &dp.to_be_signed()
        )
        .unwrap());
    }

    #[test]
    fn sign_program_rejects_empty_program() {
        let dir = tempfile::tempdir().unwrap();
        let (kf, _) = write_keyfile(dir.path());
        let program_path = dir.path().join("empty.bin");
        std::fs::write(&program_path, []).unwrap();
        let outfile = dir.path().join("out.lsig");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqSignProgramArgs {
                keyfile: Some(kf),
                mnemonic: None,
                scheme: "falcon-1024".to_string(),
                program: program_path,
                outfile,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        assert!(String::from_utf8(err).unwrap().contains("program is empty"));
    }

    #[test]
    fn sign_program_rejects_dot_teal_extension() {
        let dir = tempfile::tempdir().unwrap();
        let (kf, _) = write_keyfile(dir.path());
        let program_path = dir.path().join("prog.teal");
        std::fs::write(&program_path, [0x08u8, 0x22]).unwrap();
        let outfile = dir.path().join("out.lsig");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqSignProgramArgs {
                keyfile: Some(kf),
                mnemonic: None,
                scheme: "falcon-1024".to_string(),
                program: program_path,
                outfile,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("looks like TEAL source"));
    }

    #[test]
    fn sign_program_rejects_teal_source_bytes_regardless_of_extension() {
        let dir = tempfile::tempdir().unwrap();
        let (kf, _) = write_keyfile(dir.path());
        let program_path = dir.path().join("prog.bin"); // no .teal extension
        std::fs::write(&program_path, b"#pragma version 8\nint 1\nreturn\n").unwrap();
        let outfile = dir.path().join("out.lsig");

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqSignProgramArgs {
                keyfile: Some(kf),
                mnemonic: None,
                scheme: "falcon-1024".to_string(),
                program: program_path,
                outfile,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("not compiled bytecode"));
    }
}
