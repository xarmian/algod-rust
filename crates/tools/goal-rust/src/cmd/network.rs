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

//! `goal network create` / `pregen` -- port of `cmd/goal/network.go`
//! (issue #1993). The heavy lifting is `algo-netdeploy`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use algo_netdeploy::create::{create_network_from_template, CreateOptions};
use algo_netdeploy::genesis_gen::generate_genesis_files;
use algo_netdeploy::template::NetworkTemplate;
use algo_netdeploy::DEFAULT_NETWORK_TEMPLATE;

use crate::groups::network::{CreateArgs, PregenArgs};

/// `messages.go`.
const INFO_NETWORK_ALREADY_EXISTS: &str = "Network Root Directory '{}' already exists and is not empty";
const ERROR_CREATE_NETWORK: &str = "Error creating private network: ";
const INFO_NETWORK_CREATED: &str = "Network {} created under {}";

fn fail(message: impl AsRef<str>) -> ExitCode {
    eprintln!("{}", message.as_ref());
    ExitCode::from(1)
}

/// go: cobra's `MarkFlagRequired("rootdir")`.
fn require_rootdir(rootdir: Option<PathBuf>) -> Result<PathBuf, ExitCode> {
    match rootdir {
        Some(p) if !p.as_os_str().is_empty() => Ok(absolute(&p)),
        _ => Err(fail("Error: required flag(s) \"rootdir\" not set")),
    }
}

fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(p))
        .unwrap_or_else(|_| p.to_path_buf())
}

/// go: `util.FileExists(dir) && !util.IsEmpty(dir)`.
fn exists_and_not_empty(dir: &Path) -> bool {
    dir.exists()
        && std::fs::read_dir(dir).map_or(true, |mut d| d.next().is_some())
}

/// go: `util.CopyFolder`.
fn copy_folder(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_folder(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn read_template(file: Option<&Path>) -> Result<String, String> {
    match file {
        None => Ok(DEFAULT_NETWORK_TEMPLATE.to_string()),
        Some(f) => std::fs::read_to_string(absolute(f)).map_err(|e| e.to_string()),
    }
}

/// Port of `networkCreateCmd` (`network.go:118-176`).
pub fn run_create(rootdir: Option<PathBuf>, args: CreateArgs) -> ExitCode {
    let root = match require_rootdir(rootdir) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let template_text = match read_template(args.template.as_deref()) {
        Ok(t) => t,
        Err(e) => return fail(format!("{ERROR_CREATE_NETWORK}{e}")),
    };
    // make sure the target directory does not exist or is empty
    if exists_and_not_empty(&root) {
        return fail(INFO_NETWORK_ALREADY_EXISTS.replacen("{}", &root.display().to_string(), 1));
    }
    if args.start {
        return fail("--start is not supported yet: run 'goal network start' after creating the network (issue #1993)");
    }

    // pregendir: copy the pregenerated files in first
    if let Some(pregen) = &args.pregendir {
        if let Err(e) = copy_folder(&absolute(pregen), &root) {
            return fail(format!("{e}"));
        }
    }

    let opts = CreateOptions {
        name: args.network.clone().unwrap_or_default(),
        dev_mode_override: args.dev_mode,
    };
    let mut out = std::io::stdout();
    let network = match create_network_from_template(&root, &template_text, &opts, &mut out) {
        Ok(n) => n,
        Err(e) => {
            if args.noclean {
                println!(" ** failed ** - Preserving network rootdir '{}'", root.display());
            } else {
                // don't leave a partial network directory if create failed
                let _ = std::fs::remove_dir_all(&root);
            }
            return fail(format!("{ERROR_CREATE_NETWORK}{e}"));
        }
    };

    if !args.noimportkeys {
        eprintln!(
            "warning: the root keys were not imported into kmd (not implemented yet, issue #1993); use 'goal account importrootkey' once kmd is running"
        );
    }
    println!(
        "{}",
        INFO_NETWORK_CREATED
            .replacen("{}", network.name(), 1)
            .replacen("{}", &root.display().to_string(), 1)
    );
    ExitCode::SUCCESS
}

/// Port of `networkPregenCmd` (`network.go:296-347`).
pub fn run_pregen(rootdir: Option<PathBuf>, args: PregenArgs) -> ExitCode {
    if rootdir.is_some_and(|r| !r.as_os_str().is_empty()) {
        return fail("This command does not take a network directory as an argument. Use --pregendir flag instead.");
    }
    let Some(pregen) = args.pregendir.as_deref().filter(|p| !p.as_os_str().is_empty()) else {
        return fail("Error: required flag(s) \"pregendir\" not set");
    };
    let pregen = absolute(pregen);
    let template_text = match read_template(args.template.as_deref()) {
        Ok(t) => t,
        Err(e) => return fail(format!("{ERROR_CREATE_NETWORK}{e}")),
    };
    // make sure the target directory does not exist or is empty
    if exists_and_not_empty(&pregen) {
        return fail(INFO_NETWORK_ALREADY_EXISTS.replacen("{}", &pregen.display().to_string(), 1));
    }
    let template = match NetworkTemplate::from_json(&template_text) {
        Ok(t) => t,
        Err(e) => return fail(format!("Error in loading template: {e}\n")),
    };
    if let Err(e) = template.validate() {
        return fail(format!("Error in template validation: {e}\n"));
    }
    let mut out = std::io::stdout();
    if let Err(e) = generate_genesis_files(&template.genesis, &pregen, &mut out) {
        return fail(format!("Cannot write genesis files: {e}"));
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_rootdir_is_gos_required_flag_error() {
        assert!(require_rootdir(None).is_err());
        assert!(require_rootdir(Some(PathBuf::new())).is_err());
        assert!(require_rootdir(Some(PathBuf::from("net"))).is_ok());
    }

    #[test]
    fn emptiness_follows_go() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!exists_and_not_empty(&tmp.path().join("missing")));
        assert!(!exists_and_not_empty(tmp.path()));
        std::fs::write(tmp.path().join("f"), "x").unwrap();
        assert!(exists_and_not_empty(tmp.path()));
    }

    #[test]
    fn copy_folder_copies_recursively() {
        let tmp = tempfile::tempdir().unwrap();
        let from = tmp.path().join("from");
        std::fs::create_dir_all(from.join("sub")).unwrap();
        std::fs::write(from.join("a"), "1").unwrap();
        std::fs::write(from.join("sub/b"), "2").unwrap();
        let to = tmp.path().join("to");
        copy_folder(&from, &to).unwrap();
        assert_eq!(std::fs::read_to_string(to.join("sub/b")).unwrap(), "2");
        assert_eq!(std::fs::read_to_string(to.join("a")).unwrap(), "1");
    }
}
