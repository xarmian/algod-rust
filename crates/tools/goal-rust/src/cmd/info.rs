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

//! go's root `goal -v`, `goal license`, `goal protocols` and `goal report`
//! (`cmd/goal/commands.go`), issue #2467.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

/// go: `config.VersionMajor` / `config.VersionMinor` of go-algorand
/// v5.0.5-stable, the release goal-rust matches.
const VERSION_MAJOR: u64 = 5;
const VERSION_MINOR: u64 = 0;

/// go: `config.GetLicenseInfo()`.
pub const LICENSE_INFO: &str = "go-algorand is licensed with AGPLv3.0\nsource code available at https://github.com/algorand/go-algorand";

/// go's build variables (`config/buildvars.go`), which go's build tools set
/// with `-ldflags -X`: here the environment of the build, unset (empty) in
/// a plain build as in a plain `go build`.
const BUILD_NUMBER: Option<&str> = option_env!("GOAL_BUILD_NUMBER");
const COMMIT_HASH: Option<&str> = option_env!("GOAL_COMMIT_HASH");
const BRANCH: Option<&str> = option_env!("GOAL_BRANCH");
const CHANNEL: Option<&str> = option_env!("GOAL_CHANNEL");

/// go's `convertToInt`: `strconv.ParseInt(val, 10, 0)`, its value kept on
/// an error (0 for a syntax error, the bound for an out-of-range one).
fn convert_to_int(val: &str) -> i64 {
    let digits = val.strip_prefix(['+', '-']).unwrap_or(val);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    val.parse::<i64>().unwrap_or(if val.starts_with('-') {
        i64::MIN
    } else {
        i64::MAX
    })
}

/// go: `config.FormatVersionAndLicense()`.
pub fn format_version_and_license() -> String {
    let build = convert_to_int(BUILD_NUMBER.unwrap_or(""));
    // `Version.AsUInt64`: major << 40 | minor << 24 | uint64(build)
    let as_u64 = (((VERSION_MAJOR << 16) | VERSION_MINOR) << 24) | build as u64;
    format!(
        "{as_u64}\n{VERSION_MAJOR}.{VERSION_MINOR}.{build}.{} [{}] (commit #{})\n{LICENSE_INFO}",
        CHANNEL.unwrap_or(""),
        BRANCH.unwrap_or(""),
        COMMIT_HASH.unwrap_or("")
    )
}

/// go: `config.GetCurrentVersion().String()` (`<major>.<minor>.<build>`).
pub fn current_version_string() -> String {
    let build = convert_to_int(BUILD_NUMBER.unwrap_or(""));
    format!("{VERSION_MAJOR}.{VERSION_MINOR}.{build}")
}

/// The root command's `-v, --version`.
pub fn run_version_check() -> ExitCode {
    println!("{}", format_version_and_license());
    ExitCode::SUCCESS
}

/// `licenseCmd`.
pub fn run_license() -> ExitCode {
    println!("{LICENSE_INFO}");
    ExitCode::SUCCESS
}

/// `protoCmd`: `os.Stdout.Write(protocol.EncodeJSON(config.Consensus))`.
pub fn run_protocols() -> ExitCode {
    let mut out = std::io::stdout().lock();
    // go ignores a failed write
    let _ = out
        .write_all(&crate::protocols_json::protocols_json())
        .and_then(|()| out.flush());
    ExitCode::SUCCESS
}

/// go's `exec.Command("uname", "-a").CombinedOutput()`.
fn uname() -> Result<Vec<u8>, String> {
    match std::process::Command::new("uname").arg("-a").output() {
        Ok(o) if o.status.success() => Ok([o.stdout, o.stderr].concat()),
        Ok(o) => Err(exit_text(&o.status)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("exec: \"uname\": executable file not found in $PATH".to_string())
        }
        Err(e) => Err(format!(
            "fork/exec uname: {}",
            crate::data_dir::go_os_error(&e)
        )),
    }
}

/// go's `*exec.ExitError` text.
fn exit_text(status: &std::process::ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return format!("signal: {}", signal_name(sig));
        }
    }
    format!("exit status {}", status.code().unwrap_or(-1))
}

/// go's `syscall.Signal.String()` for the signals a child dies of.
#[cfg(unix)]
fn signal_name(sig: i32) -> String {
    match sig {
        1 => "hangup".into(),
        2 => "interrupt".into(),
        3 => "quit".into(),
        6 => "aborted".into(),
        9 => "killed".into(),
        11 => "segmentation fault".into(),
        13 => "broken pipe".into(),
        15 => "terminated".into(),
        n => format!("signal {n}"),
    }
}

/// `reportCmd`: the version and license, `uname -a`, each data dir's
/// genesis ID, then `getStatus` of each.
pub fn run_report(cli_d: Vec<PathBuf>) -> ExitCode {
    println!("{}", format_version_and_license());
    println!();
    let data = match uname() {
        Ok(d) => d,
        Err(e) => {
            println!("{e}");
            return ExitCode::from(1);
        }
    };
    println!("{}", String::from_utf8_lossy(&data));
    let dirs = match crate::data_dir::resolve_data_dirs(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let multi = dirs.len() > 1;
    for dir in &dirs {
        if multi {
            println!("{}{}]", crate::data_dir::INFO_DATA_DIR_FMT, dir.display());
        }
        // go: `readGenesis(dir)`, its error printed to stdout
        let path = dir.join(crate::data_dir::GENESIS_JSON_FILE);
        let id = std::fs::read(&path)
            .map_err(|e| {
                format!(
                    "open {}: {}",
                    path.display(),
                    crate::data_dir::go_os_error(&e)
                )
            })
            .and_then(|text| crate::go_json::decode_genesis_id(&text));
        match id {
            Ok(id) => println!("Genesis ID from genesis.json: {id}"),
            Err(e) => {
                println!("{e}");
                return ExitCode::from(1);
            }
        }
    }
    println!();
    super::node::run_status_of(&dirs, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_numbers_convert_like_go() {
        assert_eq!(convert_to_int(""), 0);
        assert_eq!(convert_to_int("12"), 12);
        assert_eq!(convert_to_int("+7"), 7);
        assert_eq!(convert_to_int("-3"), -3);
        assert_eq!(convert_to_int("x1"), 0);
        assert_eq!(convert_to_int("99999999999999999999"), i64::MAX);
        assert_eq!(convert_to_int("-99999999999999999999"), i64::MIN);
    }

    #[test]
    fn version_and_license_of_a_plain_build() {
        if BUILD_NUMBER.is_none() && COMMIT_HASH.is_none() && BRANCH.is_none() && CHANNEL.is_none()
        {
            assert_eq!(
                format_version_and_license(),
                "5497558138880\n5.0.0. [] (commit #)\n\
                 go-algorand is licensed with AGPLv3.0\n\
                 source code available at https://github.com/algorand/go-algorand"
            );
        }
    }
}
