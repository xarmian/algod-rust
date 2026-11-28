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

//! `algokey salted` (alias `pq`) — standalone salted-address account-key CLI
//! subcommand family for Falcon-1024, Falcon-512 and Ed25519 keys, mirroring
//! `../go-algorand/cmd/algokey/salted.go`, `salted_key.go` and
//! `salted_scheme.go` (v5.1.1-stable, where it replaced `pq`).
//!
//! Distinct from this repo's participation-key material (`part
//! generate`/`part info`): these subcommands manage regular (non-
//! participation) account keys that an account can be rekeyed to, whose
//! salted address no Ed25519 key can claim (`SaltedKeySig`,
//! `data/transactions/sksig.go`).

pub mod check_address;
pub mod context;
pub mod generate;
pub mod import;
pub mod info;
pub mod key;
mod msgp_text;
#[cfg(test)]
mod oracle_tests;
pub mod scheme;
pub mod sign;
pub mod sign_program;
#[cfg(test)]
mod tests;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use self::key::SaltedPublicMaterial;
use self::scheme::format_sig_scheme;

pub use algo_avm::assembler::go_quote_bytes;

/// go's `errSaltedKeyMalformed`.
pub const ERR_SALTED_KEY_MALFORMED: &str = "key file is malformed";
/// go's `errSaltOnCurve`.
pub const ERR_SALT_ON_CURVE: &str = "address salt puts the address on the Ed25519 curve";
/// go's `transactions.ErrSigSchemeNotSupported`.
pub const ERR_SIG_SCHEME_NOT_SUPPORTED: &str = "signature scheme not supported";
/// go's `errSaltedTxnAlreadySigned`.
pub const ERR_TXN_ALREADY_SIGNED: &str = "transaction already has a signature";
/// go's `errSaltedSchemeRequired`.
pub const ERR_SCHEME_REQUIRED: &str = "--scheme is required with --mnemonic";
/// go's `errSaltedSchemeWithKeyfile`.
pub const ERR_SCHEME_WITH_KEYFILE: &str =
    "--scheme cannot be used with --keyfile, which records its scheme";

/// go's `stdinFileNameValue` / `stdoutFilenameValue`.
const STDIO_FILENAME: &str = "-";

/// How go's `os` package words an I/O error: lower-case, without Rust's
/// `(os error N)` suffix; `op` and `path` make go's `*PathError` text
/// (`open /x/key: no such file or directory`).
fn go_path_error(op: &str, path: &Path, e: &std::io::Error) -> String {
    let text = e.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text);
    let mut chars = text.chars();
    let text = match chars.next() {
        Some(c) => c.to_lowercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    };
    format!("{op} {}: {text}", path.display())
}

/// go's `readFile` (`common.go`): `-` reads stdin. The error is go's
/// `*PathError` text.
pub fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    if path == Path::new(STDIO_FILENAME) {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        return Ok(buf);
    }
    std::fs::read(path).map_err(|e| go_path_error("open", path, &e))
}

/// go's `writeFile` (`common.go`): `-` writes stdout, anything else is a file
/// at mode 0600 (`os.WriteFile`, whose error is a `*PathError`).
pub fn write_file(path: &Path, data: &[u8]) -> Result<(), String> {
    if path == Path::new(STDIO_FILENAME) {
        return std::io::stdout().write_all(data).map_err(|e| e.to_string());
    }
    crate::common::write_with_mode_0600(path, data).map_err(|e| go_path_error("open", path, &e))
}

/// go's `exitOnError`: print the error to stderr and exit 1.
pub fn exit_on_error<E: Write>(result: Result<(), String>, stderr: &mut E) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            ExitCode::from(1)
        }
    }
}

/// An optional CLI string, where go's `""` default means "not given".
pub fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}

/// An optional CLI path, where go's `""` default means "not given".
pub fn non_empty_path(value: &Option<PathBuf>) -> Option<&Path> {
    value.as_deref().filter(|p| !p.as_os_str().is_empty())
}

/// go's `printSaltedKeyInfo`.
pub fn print_salted_key_info<W: Write>(
    w: &mut W,
    public: &SaltedPublicMaterial,
) -> std::io::Result<()> {
    use base64::Engine;
    write!(
        w,
        "Scheme: {}\nPublic key: {}\nAddress salt: {}\nAddress: {}\n",
        format_sig_scheme(&public.scheme),
        base64::engine::general_purpose::STANDARD.encode(&public.public_key),
        public.salt.0,
        public.address(),
    )
}

/// go's `printSaltedMnemonic`.
pub fn print_salted_mnemonic<W: Write>(w: &mut W, entropy: &[u8; 32]) -> Result<(), String> {
    let mnemonic = algo_consensus_crypto::key_to_mnemonic(entropy).map_err(|e| e.to_string())?;
    write!(
        w,
        "Private key mnemonic: {mnemonic}\nWrite these words down: they cannot be recovered from the key file.\n"
    )
    .map_err(|e| e.to_string())
}

/// go's `seedFromMnemonic`: `passphrase.MnemonicToKey(strings.TrimSpace(m))`.
pub fn seed_from_mnemonic(mnemonic: &str) -> Result<[u8; 32], String> {
    algo_consensus_crypto::mnemonic_to_key(mnemonic.trim()).map_err(|e| e.to_string())
}

/// go's `looksLikeTealSource`: reports whether `data` is entirely printable
/// ASCII and whitespace, resembling TEAL source rather than compiled
/// bytecode.
pub fn looks_like_teal_source(data: &[u8]) -> bool {
    data.iter()
        .all(|&b| (b >= b' ' || b == b'\t' || b == b'\n' || b == b'\r') && b <= b'~')
}
