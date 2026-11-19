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

//! What go's `goal` does each time it builds a `libgoal.Client`
//! (`cmd/goal/commands.go` `getGoalClient` / `ensureGoalClient`,
//! `libgoal/libgoal.go` `Client.init`), issue #2449.
//!
//! Every client, whatever its type, first resolves the kmd data dir
//! (`resolveKmdDataDir`, which reads `genesis.json` for a shared-server data
//! dir) and creates the cache directory (`ensureCacheDir`: `<dd>/goal.cache`,
//! mode 0700, for a private data dir). That is why `goal.cache` appears in the
//! data dir of nearly every go command, also when the command then fails
//! (`accountListFileName` builds a `DynamicClient` before it reads the genesis
//! ID). A `KmdClient` / `FullClient` then starts kmd when it is not running,
//! an `AlgodClient` / `FullClient` reads the algod token and `algod.net`,
//! and every client loads `<dd>/consensus.json`; a failure there is `Cannot
//! contact Algorand node: <err>` (`errorNodeStatus`), or `kmd client init
//! error: <err>` for the client `getWalletHandleMaybePassword` builds. Every
//! go call site of `ensureKmdClient` / `ensureAlgodClient` /
//! `ensureFullClient` / `getGoalClient` goes through here (issue #2454).

use std::path::{Path, PathBuf};

use crate::data_dir;
use crate::kmdcontrol::{KmdController, DEFAULT_KMD_TIMEOUT_SECS};

/// go: `errorNodeStatus` (`cmd/goal/messages.go`).
pub const ERROR_NODE_STATUS: &str = "Cannot contact Algorand node: ";

/// go: `libgoal.ClientType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientType {
    /// `DynamicClient`: neither kmd nor algod is contacted.
    Dynamic,
    /// `KmdClient`: kmd is started when not running.
    Kmd,
    /// `AlgodClient`: the algod token and address must be readable.
    Algod,
    /// `FullClient`: both.
    Full,
}

/// The steps of go's `getGoalClient` every client type shares:
/// `resolveKmdDataDir` (`reportErrorf("could not read genesis.json: %s")` on
/// a shared-server data dir whose genesis cannot be read) and
/// `ensureCacheDir`. Returns the kmd data dir.
pub fn prepare(data_dir: &Path) -> Result<PathBuf, String> {
    let kmd_dir = data_dir::resolve_kmd_data_dir(crate::cli_state::kmddir().as_deref(), data_dir)
        .map_err(|e| format!("could not read genesis.json: {e}"))?;
    crate::wallet_token::ensure_cache_dir(data_dir)?;
    Ok(kmd_dir)
}

/// [`prepare`] for the client builders that cannot return go's error: on
/// failure print it and exit 1, as go's `reportErrorf` does.
pub fn prepare_or_exit(data_dir: &Path) {
    if let Err(e) = prepare(data_dir) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

/// Why go's `getGoalClient` failed.
#[derive(Debug, PartialEq, Eq)]
pub enum ClientError {
    /// `resolveKmdDataDir` / `ensureCacheDir` failed: go reports this text
    /// itself (`reportErrorf`) and exits 1, whatever the caller.
    Fatal(String),
    /// `libgoal.MakeClientFromConfig` failed with this error.
    Init(String),
}

impl ClientError {
    /// What go's `ensureGoalClient` prints: `Cannot contact Algorand node:
    /// <err>` (`errorNodeStatus`).
    pub fn node_status(self) -> String {
        match self {
            Self::Fatal(s) => s,
            Self::Init(e) => format!("{ERROR_NODE_STATUS}{e}"),
        }
    }

    /// What go's `getWalletHandleMaybePassword` prints when it cannot build
    /// its own `KmdClient`: `kmd client init error: <err>`.
    pub fn kmd_init(self) -> String {
        match self {
            Self::Fatal(s) => s,
            Self::Init(e) => format!("kmd client init error: {e}"),
        }
    }
}

/// go's `getGoalClient(dataDir, clientType)`: [`prepare`], then
/// `libgoal` `Client.init` -- start kmd for a `KmdClient` / `FullClient`
/// (`getKMDClient`: `StartKMD`, then `KMDClient` reads the kmd token and
/// address), read the algod token and address for an `AlgodClient` /
/// `FullClient`, and load `<dd>/consensus.json` (`nc.GetConsensus`).
/// Returns the kmd data dir.
pub fn get_goal_client(data_dir: &Path, client_type: ClientType) -> Result<PathBuf, ClientError> {
    let kmd_dir = prepare(data_dir).map_err(ClientError::Fatal)?;
    if matches!(client_type, ClientType::Kmd | ClientType::Full) {
        KmdController::new(&kmd_dir)
            .start(DEFAULT_KMD_TIMEOUT_SECS)
            .map_err(ClientError::Init)?;
        kmd_endpoint(&kmd_dir).map_err(ClientError::Init)?;
    }
    if matches!(client_type, ClientType::Algod | ClientType::Full) {
        algod_endpoint(data_dir).map_err(ClientError::Init)?;
    }
    crate::consensus_json::preload_configurable_consensus_protocols(data_dir)
        .map_err(ClientError::Init)?;
    Ok(kmd_dir)
}

/// go's `ensureGoalClient(dataDir, clientType)` up to the client: `Err` is
/// the full text go prints before it exits 1. Returns the kmd data dir.
pub fn ensure_goal_client(data_dir: &Path, client_type: ClientType) -> Result<PathBuf, String> {
    get_goal_client(data_dir, client_type).map_err(ClientError::node_status)
}

/// go's `ensureKmdClient(dataDir)`: the client of a kmd started when it is
/// not running. `Err` is the full text go prints before it exits 1.
pub fn ensure_kmd_client(data_dir: &Path) -> Result<algo_kmd_client::KmdClient, String> {
    let kmd_dir = ensure_goal_client(data_dir, ClientType::Kmd)?;
    kmd_client(&kmd_dir).map_err(|e| format!("{ERROR_NODE_STATUS}{e}"))
}

/// The kmd client of the `KmdClient` go's `getWalletHandleMaybePassword`
/// builds (`getGoalClient(dataDir, KmdClient)`): `Err` is `kmd client init
/// error: <err>`.
pub fn wallet_handle_kmd_client(data_dir: &Path) -> Result<algo_kmd_client::KmdClient, String> {
    let kmd_dir = get_goal_client(data_dir, ClientType::Kmd).map_err(ClientError::kmd_init)?;
    kmd_client(&kmd_dir).map_err(|e| ClientError::Init(e).kmd_init())
}

/// go: `KMDController.KMDClient` + `client.MakeKMDClient`.
fn kmd_client(kmd_dir: &Path) -> Result<algo_kmd_client::KmdClient, String> {
    let (net, token) = kmd_endpoint(kmd_dir)?;
    algo_kmd_client::KmdClient::new(&net, &token).map_err(|e| e.to_string())
}

/// go's `ensureAlgodClient(dataDir)` / `ensureFullClient(dataDir)`: the
/// algod base URL and token. `Err` is the full text go prints before it
/// exits 1.
pub fn ensure_algod_endpoint(
    data_dir: &Path,
    client_type: ClientType,
) -> Result<(String, String), String> {
    ensure_goal_client(data_dir, client_type)?;
    algod_endpoint(data_dir).map_err(|e| format!("{ERROR_NODE_STATUS}{e}"))
}

/// go: `KMDController.KMDClient` -- the kmd token (validated), then the
/// first line of `kmd.net`.
fn kmd_endpoint(kmd_dir: &Path) -> Result<(String, String), String> {
    let token = get_and_validate_api_token(kmd_dir, "kmd.token")?;
    let net = first_line(&kmd_dir.join("kmd.net"))?;
    Ok((net, token))
}

/// go: `tokens.GetAndValidateAPIToken`.
fn get_and_validate_api_token(data_dir: &Path, name: &str) -> Result<String, String> {
    let token = first_line(&data_dir.join(name))?;
    if token.len() < 64 {
        return Err("provided APIToken too short. Must be >= 64 characters".to_string());
    }
    if token.len() > 256 {
        return Err("provided APIToken too long. Must be <= 256 characters".to_string());
    }
    Ok(token)
}

/// go: `util.GetFirstLineFromFile`.
fn first_line(path: &Path) -> Result<String, String> {
    let text = std::fs::read(path)
        .map_err(|e| format!("open {}: {}", path.display(), data_dir::go_os_error(&e)))?;
    let text = String::from_utf8_lossy(&text);
    Ok(text.split('\n').next().unwrap_or("").to_string())
}

/// go: `NodeController.AlgodClient` -- the admin token (else the regular one,
/// whose error is the one reported), then the address in `algod.net`.
/// Returns the base URL and the token.
pub fn algod_endpoint(data_dir: &Path) -> Result<(String, String), String> {
    let token = match get_and_validate_api_token(data_dir, data_dir::ALGOD_ADMIN_TOKEN_FILE) {
        Ok(t) => t,
        Err(_) => get_and_validate_api_token(data_dir, data_dir::ALGOD_TOKEN_FILE)?,
    };
    let addr = first_line(&data_dir.join(data_dir::ALGOD_NET_FILE))?;
    let url = if addr.starts_with("http:") || addr.starts_with("https:") {
        addr
    } else {
        format!("http://{addr}")
    };
    Ok((url, token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_algod_token_is_read_before_the_address() {
        let tmp = tempfile::tempdir().unwrap();
        let dd = tmp.path();
        assert_eq!(
            algod_endpoint(dd),
            Err(format!(
                "open {}: no such file or directory",
                dd.join("algod.token").display()
            ))
        );
        std::fs::write(dd.join("algod.token"), "short\n").unwrap();
        assert_eq!(
            algod_endpoint(dd),
            Err("provided APIToken too short. Must be >= 64 characters".to_string())
        );
        let tok = "a".repeat(64);
        std::fs::write(dd.join("algod.token"), format!("{tok}\n")).unwrap();
        assert_eq!(
            algod_endpoint(dd),
            Err(format!(
                "open {}: no such file or directory",
                dd.join("algod.net").display()
            ))
        );
        std::fs::write(dd.join("algod.net"), "127.0.0.1:8080\n").unwrap();
        assert_eq!(
            algod_endpoint(dd),
            Ok(("http://127.0.0.1:8080".to_string(), tok.clone()))
        );
        let admin = "b".repeat(64);
        std::fs::write(dd.join("algod.admin.token"), &admin).unwrap();
        assert_eq!(algod_endpoint(dd).unwrap().1, admin);
    }

    #[test]
    fn a_private_data_dir_gets_goal_cache() {
        let tmp = tempfile::tempdir().unwrap();
        ensure_goal_client(tmp.path(), ClientType::Dynamic).unwrap();
        assert!(tmp.path().join("goal.cache").is_dir());
        // and again: an existing cache dir is fine
        ensure_goal_client(tmp.path(), ClientType::Dynamic).unwrap();
    }
}
