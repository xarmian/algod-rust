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

//! `algokey pq check-address` — mirrors `runPQCheckAddress` (`pq.go:419-429`).

use std::io::Write;
use std::process::ExitCode;

use algo_types::Address;

use crate::cli::PqCheckAddressArgs;

pub fn run(args: PqCheckAddressArgs) -> ExitCode {
    run_with_io(args, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io<O: Write, E: Write>(
    args: PqCheckAddressArgs,
    stdout: &mut O,
    stderr: &mut E,
) -> ExitCode {
    let addr = match Address::from_algorand_string(&args.address) {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(stderr, "cannot parse address: {e}");
            return ExitCode::from(1);
        }
    };
    if !addr.is_pq_compliant() {
        let _ = writeln!(stderr, "address {addr} is not PQ compliant");
        return ExitCode::from(1);
    }
    if let Err(e) = writeln!(stdout, "address {addr} is PQ compliant") {
        let _ = writeln!(stderr, "cannot write to stdout: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::pq::scheme::generate_pq_signing_material;
    use algo_types::PQ_SCHEME_FALCON1024;

    #[test]
    fn check_address_accepts_pq_compliant_address() {
        let (_, signing) = generate_pq_signing_material(PQ_SCHEME_FALCON1024).unwrap();
        let addr = signing.public.address();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqCheckAddressArgs {
                address: addr.to_string(),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(String::from_utf8(out).unwrap().contains("is PQ compliant"));
    }

    #[test]
    fn check_address_rejects_ordinary_ed25519_derived_address() {
        // The zero address IS a valid ed25519 curve point (it's the
        // all-zero pubkey), so it is NOT PQ-compliant.
        let addr = Address([0u8; 32]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqCheckAddressArgs {
                address: addr.to_string(),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        assert!(String::from_utf8(err).unwrap().contains("not PQ compliant"));
        assert!(out.is_empty());
    }

    #[test]
    fn check_address_rejects_malformed_address_string() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with_io(
            PqCheckAddressArgs {
                address: "not-a-real-address".to_string(),
            },
            &mut out,
            &mut err,
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::from(1)));
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("cannot parse address"));
    }
}
