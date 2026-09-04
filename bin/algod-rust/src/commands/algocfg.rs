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

//! `algod-rust algocfg` — a CLI wrapper around `algo_config::algocfg`'s
//! get/set/reset/profile logic, matching go-algorand's `cmd/algocfg`
//! (issue #973). The field-lookup/parse/profile-application logic lives in
//! the `algo-config` crate (testable without any filesystem I/O); this
//! module only handles loading `<data-dir>/config.json`, applying the
//! requested mutation, and writing it back — go's `datadir.OnDataDirs`
//! wrapper (`cmd/algocfg/getCommand.go:47` and siblings), collapsed to a
//! single data directory since algod-rust's CLI has no multi-`--datadir`
//! flag equivalent.

use std::io::{self, Write};
use std::path::Path;

use algo_config::{Local, CONFIG_FILENAME};

/// Load `<data_dir>/config.json`, or [`Local::default`] when the file is
/// absent — go: `config.LoadConfigFromDisk` tolerating `os.IsNotExist`
/// (`cmd/algocfg/getCommand.go:48-53`).
fn load(data_dir: &Path) -> anyhow::Result<Local> {
    Local::load_from_data_dir(data_dir)
        .map_err(|e| anyhow::anyhow!("Error loading config file from '{}' - {e}", data_dir.display()))
}

fn save(cfg: &Local, data_dir: &Path) -> anyhow::Result<()> {
    let path = data_dir.join(CONFIG_FILENAME);
    cfg.save_non_default_to_path(&path)
        .map_err(|e| anyhow::anyhow!("Error saving updated config file '{}' - {e}", path.display()))
}

/// `algod-rust algocfg get -p <parameter> [-d <data-dir>]`.
pub fn run_get(parameter: &str, data_dir: &Path) -> anyhow::Result<()> {
    let cfg = load(data_dir)?;
    let value = algo_config::algocfg::get_property(&cfg, parameter)
        .map_err(|e| anyhow::anyhow!("Error retrieving property '{parameter}' - {e}"))?;
    print!("{value}");
    Ok(())
}

/// `algod-rust algocfg string -p <parameter> [-d <data-dir>]` — algod-rust
/// addition (issue #973): same lookup as `get`, but shell-quoted so the
/// output is safe to embed directly in a shell command.
pub fn run_string(parameter: &str, data_dir: &Path) -> anyhow::Result<()> {
    let cfg = load(data_dir)?;
    let value = algo_config::algocfg::get_property(&cfg, parameter)
        .map_err(|e| anyhow::anyhow!("Error retrieving property '{parameter}' - {e}"))?;
    println!("{}", algo_config::algocfg::shell_quote(&value));
    Ok(())
}

/// `algod-rust algocfg set -p <parameter> -v <value> [-d <data-dir>]`.
pub fn run_set(parameter: &str, value: &str, data_dir: &Path) -> anyhow::Result<()> {
    let mut cfg = load(data_dir)?;
    algo_config::algocfg::set_property(&mut cfg, parameter, value)
        .map_err(|e| anyhow::anyhow!("Error setting property '{parameter}' -> '{value}' - {e}"))?;
    save(&cfg, data_dir)
}

/// `algod-rust algocfg delete -p <parameter> [-d <data-dir>]` — go's
/// `algocfg reset` (named `delete` here per issue #973's naming, since it
/// removes any override, restoring the field's default).
pub fn run_delete(parameter: &str, data_dir: &Path) -> anyhow::Result<()> {
    let mut cfg = load(data_dir)?;
    algo_config::algocfg::reset_property(&mut cfg, parameter)
        .map_err(|e| anyhow::anyhow!("Error resetting property '{parameter}' - {e}"))?;
    save(&cfg, data_dir)
}

/// `algod-rust algocfg profile list`.
pub fn run_profile_list() {
    let profiles = algo_config::algocfg::profile_names();
    let longest = profiles.keys().map(|k| k.len()).max().unwrap_or(0);
    for (name, profile) in &profiles {
        println!("{name:<longest$}  {}", profile.description);
    }
}

/// `algod-rust algocfg profile print <name>`.
pub fn run_profile_print(name: &str) -> anyhow::Result<()> {
    let cfg = algo_config::algocfg::config_for_profile(name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let json = cfg
        .to_json_minimized()
        .map_err(|e| anyhow::anyhow!("Error writing config file to stdout: {e}"))?;
    println!("{json}");
    Ok(())
}

/// `algod-rust algocfg profile set <name> [-d <data-dir>] [--yes]`. Prompts
/// before overwriting an existing `config.json` unless `--yes`/`force` is
/// set — go's same interactive confirmation (`cmd/algocfg/profileCommand.go:236-249`).
pub fn run_profile_set(name: &str, data_dir: &Path, force: bool) -> anyhow::Result<()> {
    let cfg = algo_config::algocfg::config_for_profile(name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = data_dir.join(CONFIG_FILENAME);
    if !force && path.exists() {
        print!(
            "A config.json file already exists at {}\nWould you like to overwrite it? (Y/n)",
            path.display()
        );
        io::stdout().flush().ok();
        let mut resp = String::new();
        io::stdin().read_line(&mut resp)?;
        if resp.trim().eq_ignore_ascii_case("n") {
            println!("Exiting without overwriting existing config.");
            return Ok(());
        }
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    save(&cfg, data_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "algod-rust-algocfg-cli-test-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn set_then_get_round_trips_through_disk() {
        let dir = temp_dir("set-get");
        run_set("GossipFanout", "11", &dir).unwrap();
        let cfg = load(&dir).unwrap();
        assert_eq!(cfg.gossip_fanout, 11);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn delete_restores_default_on_disk() {
        let dir = temp_dir("delete");
        run_set("GossipFanout", "11", &dir).unwrap();
        run_delete("GossipFanout", &dir).unwrap();
        let cfg = load(&dir).unwrap();
        assert_eq!(cfg.gossip_fanout, Local::default().gossip_fanout);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn profile_set_writes_config_when_no_existing_file() {
        let dir = temp_dir("profile-set");
        run_profile_set("conduit", &dir, false).unwrap();
        let cfg = load(&dir).unwrap();
        assert!(cfg.enable_follow_mode);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn profile_set_unknown_name_errors() {
        let dir = temp_dir("profile-set-unknown");
        let err = run_profile_set("not-a-real-profile", &dir, true).unwrap_err();
        assert!(err.to_string().contains("not-a-real-profile"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
