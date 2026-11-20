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

//! `goal ledger block` (`cmd/goal/ledger.go` `blockCmd`) and `goal version`
//! (`cmd/goal/commands.go` `versionCmd`), issue #2460.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::algod_rest;
use crate::formatting::report_error_text;
use crate::goal_client::{ensure_algod_endpoint, ClientType};
use crate::groups::ledger::BlockArgs;

/// go: `stdoutFilenameValue` (`cmd/goal/common.go`).
const STDOUT_FILENAME: &str = "-";

/// go's `reportErrorf`: print to stderr, exit 1.
fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(1)
}

/// go's `strconv.ParseUint(s, 10, 64)` error text, or the number.
fn parse_uint(s: &str) -> Result<u64, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "strconv.ParseUint: parsing {}: invalid syntax",
            go_quote(s)
        ));
    }
    s.parse::<u64>().map_err(|_| {
        format!(
            "strconv.ParseUint: parsing {}: value out of range",
            go_quote(s)
        )
    })
}

/// go's `strconv.Quote`, as `ParseUint`'s errors print the input.
fn go_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\u{b}' => out.push_str("\\v"),
            c if c.is_control() => {
                let n = c as u32;
                if n < 0x10000 {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn runtime() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| fail(format!("tokio runtime: {e}")))
}

/// Port of `blockCmd`: the block of a round, as go's `transcode` JSON
/// unless `-r`, to `-o` (stdout by default).
pub fn run_block(args: BlockArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let round = match parse_uint(&args.round) {
        Ok(r) => r,
        Err(e) => return fail(format!("Error parsing round number: {e}")),
    };
    let dir = match crate::data_dir::ensure_single_data_dir(&cli_d) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let endpoint = match ensure_algod_endpoint(&dir, ClientType::Algod) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    let rt = match runtime() {
        Ok(r) => r,
        Err(code) => return code,
    };
    // go: `client.RawBlock(round)` -- `GET /v2/blocks/<round>?format=msgpack`.
    let path = format!("/v2/blocks/{round}");
    let mut response = match algod_rest::get(&rt, &endpoint, &path, &[("format", "msgpack")]) {
        Ok(b) => b,
        Err(e) => return fail(report_error_text(&format!("Error processing command: {e}"))),
    };
    if !args.raw {
        response = match crate::transcode::msgpack_to_json(&response, args.b32, args.strict) {
            Ok(j) => j,
            Err(e) => return fail(format!("Error encoding block as json: {e}")),
        };
    } else if args.b32 || args.strict {
        return fail("Cannot combine --b32=true or --strict=true with --raw");
    }
    if let Err(e) = write_file(&args.out, &response) {
        return fail(format!("Cannot write file {}: {e}", args.out));
    }
    ExitCode::SUCCESS
}

/// go's `writeFile(filename, data, 0600)`: `-` is stdout.
fn write_file(filename: &str, data: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    if filename == STDOUT_FILENAME {
        let mut out = std::io::stdout().lock();
        return out
            .write_all(data)
            .and_then(|()| out.flush())
            .map_err(|e| format!("write /dev/stdout: {}", crate::data_dir::go_os_error(&e)));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(Path::new(filename))
        .map_err(|e| format!("open {filename}: {}", crate::data_dir::go_os_error(&e)))?
        .write_all(data)
        .map_err(|e| format!("write {filename}: {}", crate::data_dir::go_os_error(&e)))
}

/// go's `common.Version` (`daemon/algod/api/spec/common/model.go`).
#[derive(serde::Deserialize, Default)]
struct Version {
    #[serde(default)]
    versions: Option<Vec<String>>,
    #[serde(default)]
    genesis_id: String,
    #[serde(default)]
    build: BuildVersion,
}

/// go's `common.BuildVersion`.
#[derive(serde::Deserialize, Default, PartialEq, Eq)]
struct BuildVersion {
    #[serde(default)]
    major: i64,
    #[serde(default)]
    minor: i64,
    #[serde(default)]
    build_number: i64,
    #[serde(default)]
    commit_hash: String,
    #[serde(default)]
    branch: String,
    #[serde(default)]
    channel: String,
}

/// Port of `versionCmd`: for each data dir (`OnDataDirs`), algod's
/// `/versions`; a failure is printed to stdout, exit 1.
pub fn run_version(verbose: bool, cli_d: Vec<PathBuf>) -> ExitCode {
    let dirs = match crate::data_dir::resolve_data_dirs(&cli_d) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let rt = match runtime() {
        Ok(r) => r,
        Err(code) => return code,
    };
    let multi = dirs.len() > 1;
    for dir in &dirs {
        if multi {
            println!("{}{}]", crate::data_dir::INFO_DATA_DIR_FMT, dir.display());
        }
        let endpoint = match ensure_algod_endpoint(dir, ClientType::Algod) {
            Ok(e) => e,
            Err(e) => return fail(e),
        };
        let response = algod_rest::get_json(
            &rt,
            &endpoint,
            "/versions",
            &[],
            &crate::go_codec_json::VERSION,
        )
        .and_then(|v| serde_json::from_value::<Version>(v).map_err(|e| e.to_string()));
        let v = match response {
            Ok(v) => v,
            Err(e) => {
                println!("{e}");
                return ExitCode::from(1);
            }
        };
        // go prints the `[]string` with `%v`: `[v1 v2]`
        let versions = format!("[{}]", v.versions.unwrap_or_default().join(" "));
        if !verbose {
            println!("{versions}");
            continue;
        }
        println!("Version: {versions} ");
        println!("GenesisID: {} ", v.genesis_id);
        let b = &v.build;
        if *b != BuildVersion::default() {
            println!(
                "Build: {}.{}.{}.{} [{}] (commit #{})",
                b.major, b.minor, b.build_number, b.channel, b.branch, b.commit_hash
            );
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uint_errors_like_go_strconv() {
        assert_eq!(parse_uint("12"), Ok(12));
        assert_eq!(parse_uint("18446744073709551615"), Ok(u64::MAX));
        assert_eq!(
            parse_uint("x"),
            Err("strconv.ParseUint: parsing \"x\": invalid syntax".to_string())
        );
        assert_eq!(
            parse_uint("+1"),
            Err("strconv.ParseUint: parsing \"+1\": invalid syntax".to_string())
        );
        assert_eq!(
            parse_uint(""),
            Err("strconv.ParseUint: parsing \"\": invalid syntax".to_string())
        );
        assert_eq!(
            parse_uint("18446744073709551616"),
            Err(
                "strconv.ParseUint: parsing \"18446744073709551616\": value out of range"
                    .to_string()
            )
        );
    }
}
