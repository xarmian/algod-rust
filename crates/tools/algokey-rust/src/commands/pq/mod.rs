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

//! `algokey pq` — standalone post-quantum (Falcon-1024) account-key CLI
//! subcommand family, mirroring `../go-algorand/cmd/algokey/pq.go`,
//! `pq_key.go`, and `pq_scheme.go`.
//!
//! Distinct from this repo's participation-key PQ material (`part
//! generate`/`part info`): these subcommands manage regular (non-
//! participation) account keys that a normal account can be rekeyed to for
//! post-quantum transaction/LogicSig authorization (`PQSig`,
//! `data/transactions/pqsig.go`).

pub mod check_address;
pub mod context;
pub mod generate;
pub mod import;
pub mod info;
pub mod key;
pub mod scheme;
pub mod sign;
pub mod sign_program;

use std::io::Write;

use self::key::PqPublicMaterial;
use self::scheme::format_pq_scheme;

/// Mirrors `printPQKeyInfo` (`pq.go:448-457`) exactly:
/// ```text
/// PQ scheme: <scheme>
/// PQ public key: <base64>
/// PQ address salt: <salt>
/// PQ address: <address>
/// ```
pub fn print_pq_key_info<W: Write>(w: &mut W, public: &PqPublicMaterial) -> std::io::Result<()> {
    use base64::Engine;
    writeln!(w, "PQ scheme: {}", format_pq_scheme(&public.scheme))?;
    writeln!(
        w,
        "PQ public key: {}",
        base64::engine::general_purpose::STANDARD.encode(&public.public_key)
    )?;
    writeln!(w, "PQ address salt: {}", public.salt.0)?;
    writeln!(w, "PQ address: {}", public.address())?;
    Ok(())
}

/// Mirrors `printPQMnemonic` (`pq.go:439-446`).
pub fn print_pq_mnemonic<W: Write>(w: &mut W, entropy: &[u8; 32]) -> std::io::Result<()> {
    let mnemonic = algo_consensus_crypto::key_to_mnemonic(entropy)
        .expect("32-byte entropy always encodes to a mnemonic");
    writeln!(
        w,
        "PQ private key mnemonic: {mnemonic}\nWrite these words down: they cannot be recovered from the key file."
    )
}

/// Mirrors `looksLikeTealSource` (`pq.go:408-417`): reports whether `data`
/// is entirely printable ASCII and whitespace, resembling TEAL source
/// rather than compiled bytecode.
pub fn looks_like_teal_source(data: &[u8]) -> bool {
    data.iter()
        .all(|&b| (b >= b' ' || b == b'\t' || b == b'\n' || b == b'\r') && b <= b'~')
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::PQAddressSalt;

    #[test]
    fn print_pq_key_info_matches_go_format() {
        let public = PqPublicMaterial {
            scheme: algo_types::PQ_SCHEME_FALCON1024,
            salt: PQAddressSalt(3),
            public_key: vec![0u8; algo_falcon::FALCON_DET1024_PUBKEY_SIZE],
        };
        let mut out = Vec::new();
        print_pq_key_info(&mut out, &public).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("PQ scheme: falcon-1024\n"));
        assert!(text.contains("PQ public key: "));
        assert!(text.contains("PQ address salt: 3\n"));
        assert!(text.contains(&format!("PQ address: {}\n", public.address())));
    }

    #[test]
    fn looks_like_teal_source_true_for_printable_ascii() {
        assert!(looks_like_teal_source(
            b"#pragma version 8\nint 1\nreturn\n"
        ));
    }

    #[test]
    fn looks_like_teal_source_false_for_compiled_bytecode() {
        // Compiled TEAL bytecode starts with the version byte (e.g. 0x08),
        // which is below printable ASCII.
        assert!(!looks_like_teal_source(&[0x08, 0x22, 0x00]));
    }
}
