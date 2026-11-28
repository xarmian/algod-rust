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

//! `algokey salted sign-program` — mirrors `runSaltedSignProgramWithOptions`
//! (`salted.go`): sign a compiled LogicSig program with a salted-key
//! signature, delegating the program to the key's address.

use std::path::PathBuf;
use std::process::ExitCode;

use algo_codec::canonical_encode_logicsig;
use algo_types::{LogicSig, SKsigDelegatedProgram};
use serde_bytes::ByteBuf;

use crate::cli::SaltedSignProgramArgs;

use super::context::{resolve_salted_signing_context, sign_salted};
use super::{
    exit_on_error, looks_like_teal_source, non_empty, non_empty_path, read_file, write_file,
};

/// go's `saltedSignProgramOptions`.
#[derive(Debug, Clone, Default)]
pub struct SaltedSignProgramOptions {
    pub keyfile: Option<PathBuf>,
    pub mnemonic: Option<String>,
    pub scheme: String,
    pub program: PathBuf,
    pub outfile: PathBuf,
}

pub fn run(args: SaltedSignProgramArgs) -> ExitCode {
    exit_on_error(
        run_salted_sign_program_with_options(&SaltedSignProgramOptions {
            keyfile: args.keyfile,
            mnemonic: args.mnemonic,
            scheme: args.scheme.unwrap_or_default(),
            program: args.program,
            outfile: args.outfile,
        }),
        &mut std::io::stderr(),
    )
}

/// go's `runSaltedSignProgramWithOptions`.
pub fn run_salted_sign_program_with_options(opts: &SaltedSignProgramOptions) -> Result<(), String> {
    let ctx = resolve_salted_signing_context(
        non_empty_path(&opts.keyfile),
        non_empty(&opts.mnemonic),
        &opts.scheme,
    )?;

    let program = read_file(&opts.program)
        .map_err(|e| format!("cannot read program from {}: {e}", opts.program.display()))?;
    if program.is_empty() {
        return Err("program is empty".to_string());
    }
    let program_path = opts.program.to_string_lossy();
    if program_path.ends_with(".teal") {
        return Err(format!(
            "{program_path} looks like TEAL source; compile it first (e.g. goal clerk compile) and don't use the .teal extension"
        ));
    }
    if looks_like_teal_source(&program) {
        return Err(
            "program is not compiled bytecode; compile it first (e.g. goal clerk compile) and don't use the .teal extension"
                .to_string(),
        );
    }

    let dp = SKsigDelegatedProgram {
        addr: ctx.signing.public.address(),
        program: program.clone(),
    };
    let sksig =
        sign_salted(&ctx, &dp.to_be_signed()).map_err(|e| format!("cannot sign program: {e}"))?;

    let lsig = LogicSig {
        logic: ByteBuf::from(program),
        pqsig: Some(sksig),
        ..LogicSig::default()
    };
    write_file(&opts.outfile, &canonical_encode_logicsig(&lsig))
        .map_err(|e| format!("cannot write LogicSig to {}: {e}", opts.outfile.display()))
}
