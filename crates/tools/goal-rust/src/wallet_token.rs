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

//! The wallet-handle token cache and password input of go's `goal`
//! (`cmd/goal/commands.go` `getWalletHandleMaybePassword`,
//! `libgoal/wallets.go` `GetWalletHandleTokenCached`,
//! `libgoal/walletHandles.go`), issue #2391.
//!
//! go keeps the wallet handle token of each wallet in
//! `<cacheDir>/walletHandles.json` (`{"Handles": {"<wallet id>": "<token>"}}`,
//! mode 0600, advisory-locked) so a later `goal` call reuses the token (renewed
//! with kmd) instead of initialising the wallet again. The file is shared with
//! go's `goal`: same cache directory, same name, same JSON. The password goal
//! prompts for afterwards is only handed to the operation that needs it.
//!
//! The password is read with `terminal.ReadPassword` only: a stdin that is not
//! a terminal fails with go's text, there is no line-from-a-pipe fallback.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use algo_kmd_client::{KmdClient, KmdError};

use crate::data_dir;

/// `defaultCacheDir` (`cmd/goal/commands.go`).
const DEFAULT_CACHE_DIR: &str = "goal.cache";
/// `walletHandlesJSONName` (`libgoal/walletHandles.go`).
const WALLET_HANDLES_JSON_NAME: &str = "walletHandles.json";

/// `walletHandles` of `libgoal/walletHandles.go`; go's `MarshalIndent` writes
/// map keys sorted, as a `BTreeMap` does.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct WalletHandles {
    #[serde(rename = "Handles", default)]
    handles: Option<BTreeMap<String, String>>,
}

fn kmd_msg(e: &KmdError) -> String {
    match e {
        KmdError::Api { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

/// `ensureCacheDir(dataDir)` (`cmd/goal/commands.go`).
pub(crate) fn ensure_cache_dir(data_dir: &Path) -> Result<PathBuf, String> {
    if data_dir::is_algorand_data_private(data_dir) {
        let cache_dir = data_dir.join(DEFAULT_CACHE_DIR);
        if let Err(e) = create_dir_0700(&cache_dir, false) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(mkdir_error(&cache_dir, &e));
            }
        }
        return Ok(cache_dir);
    }
    // Put the cache in the user's home directory.
    let root = data_dir::global_config_file_root()
        .ok_or_else(|| "config error $HOME is not defined".to_string())?;
    let escaped = data_dir.to_string_lossy().replace('/', "_");
    let cache_dir = root.join(escaped);
    create_dir_0700(&cache_dir, true).map_err(|e| mkdir_error(&cache_dir, &e))?;
    Ok(cache_dir)
}

/// go: `reportErrorf("could not make cachedir: %s", err)` of an
/// `os.Mkdir` / `os.MkdirAll` `*PathError` (`mkdir <path>: <errno text>`).
fn mkdir_error(path: &Path, e: &std::io::Error) -> String {
    format!(
        "could not make cachedir: mkdir {}: {}",
        path.display(),
        data_dir::go_os_error(e)
    )
}

fn create_dir_0700(path: &Path, all: bool) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(all);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}

fn cache_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(WALLET_HANDLES_JSON_NAME)
}

#[derive(Clone, Copy)]
enum LockKind {
    Read,
    Write,
    Unlock,
}

/// go's unix locker: a whole-file `fcntl` lock, `F_SETLKW`.
#[cfg(unix)]
fn lock(file: &std::fs::File, kind: LockKind) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let ty = match kind {
        LockKind::Read => libc::F_RDLCK,
        LockKind::Write => libc::F_WRLCK,
        LockKind::Unlock => libc::F_UNLCK,
    };
    // SAFETY: `flock` is plain old data; `fcntl` gets a valid fd and pointer.
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = ty as _;
    fl.l_whence = libc::SEEK_SET as _;
    fl.l_start = 0;
    fl.l_len = 0;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLKW, &fl) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn lock(_file: &std::fs::File, _kind: LockKind) -> std::io::Result<()> {
    Ok(())
}

/// `lockedFile.read`.
fn read_locked(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    lock(&f, LockKind::Read)
        .map_err(|e| format!("Can't acquire read lock for {}: {e}", path.display()))?;
    let mut buf = Vec::new();
    let res = f.read_to_end(&mut buf).map_err(|e| e.to_string());
    lock(&f, LockKind::Unlock).map_err(|e| format!("Can't unlock for {}: {e}", path.display()))?;
    res.map(|_| buf)
}

/// `lockedFile.write`: open without truncating, lock, then truncate and write.
fn write_locked(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| e.to_string())?;
    lock(&f, LockKind::Write)
        .map_err(|e| format!("Can't acquire lock for {}: {e}", path.display()))?;
    let res = f
        .set_len(0)
        .and_then(|_| f.write_all(data))
        .map_err(|e| e.to_string());
    lock(&f, LockKind::Unlock).map_err(|e| format!("Can't unlock for {}: {e}", path.display()))?;
    res
}

impl WalletHandles {
    fn load(cache_dir: &Path) -> Result<Self, String> {
        let path = cache_path(cache_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = read_locked(&path)?;
        serde_json::from_slice(&raw).map_err(|e| e.to_string())
    }

    fn dump(&self, cache_dir: &Path) -> Result<(), String> {
        let raw = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_locked(&cache_path(cache_dir), &raw)
    }
}

/// `loadWalletHandleFromDisk`.
fn load_wallet_handle_from_disk(wallet_id: &str, cache_dir: &Path) -> Result<String, String> {
    let whs = WalletHandles::load(cache_dir)?;
    Ok(whs
        .handles
        .and_then(|h| h.get(wallet_id).cloned())
        .unwrap_or_default())
}

/// `writeWalletHandleToDisk`.
fn write_wallet_handle_to_disk(
    handle: &str,
    wallet_id: &str,
    cache_dir: &Path,
) -> Result<(), String> {
    let mut whs = WalletHandles::load(cache_dir)?;
    whs.handles
        .get_or_insert_with(BTreeMap::new)
        .insert(wallet_id.to_string(), handle.to_string());
    whs.dump(cache_dir)
}

/// `checkHandleValidMaybeRenew`.
fn check_handle_valid_maybe_renew(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    handle: &str,
) -> bool {
    !handle.is_empty() && rt.block_on(client.renew_wallet_handle(handle)).is_ok()
}

/// `GetWalletHandleToken`: `InitWallet`, the handle token of the response.
fn get_wallet_handle_token(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    wallet_id: &str,
    password: &str,
) -> Result<String, String> {
    rt.block_on(client.init_wallet(wallet_id, password))
        .map(|r| r.wallet_handle_token)
        .map_err(|e| kmd_msg(&e))
}

/// `GetWalletHandleTokenCached`: a valid cached token (renewed), else a new one
/// (cached).
fn get_wallet_handle_token_cached(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    cache_dir: &Path,
    wallet_id: &str,
    password: &str,
) -> Result<String, String> {
    let wht = load_wallet_handle_from_disk(wallet_id, cache_dir)?;
    if !wht.is_empty() && check_handle_valid_maybe_renew(rt, client, &wht) {
        return Ok(wht);
    }
    let wht = get_wallet_handle_token(rt, client, wallet_id, password)?;
    write_wallet_handle_to_disk(&wht, wallet_id, cache_dir)?;
    Ok(wht)
}

/// `WalletIsUnencrypted`: whether the wallet initialises with a blank password.
pub(crate) fn wallet_is_unencrypted(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    wallet_id: &str,
) -> bool {
    match get_wallet_handle_token(rt, client, wallet_id, "") {
        Ok(wh) => {
            let _ = rt.block_on(client.release_wallet_handle(&wh));
            true
        }
        Err(_) => false,
    }
}

/// `ensurePasswordForWallet`: go's `infoPasswordPrompt`, then
/// [`ensure_password`].
pub(crate) fn read_password_for(wallet_name: &str) -> Result<String, String> {
    print!("Please enter the password for wallet '{wallet_name}': ");
    ensure_password()
}

/// `ensurePassword`: `terminal.ReadPassword(os.Stdin.Fd())`, then a newline.
/// `Err` is go's `reportErrorf(errorFailedToReadPassword, err)` text.
pub(crate) fn ensure_password() -> Result<String, String> {
    let _ = std::io::stdout().flush();
    if !std::io::stdin().is_terminal() {
        // `ReadPassword` on a non-terminal fd: the failed terminal-state ioctl.
        #[cfg(unix)]
        let why = "inappropriate ioctl for device";
        #[cfg(not(unix))]
        let why = "The handle is invalid.";
        return Err(format!("Couldn't read password: {why}"));
    }
    let pw = read_password_from_stdin().map_err(|e| format!("Couldn't read password: {e}"))?;
    println!();
    Ok(pw)
}

/// `terminal.ReadPassword(int(os.Stdin.Fd()))`: stdin itself (not
/// `/dev/tty`), echo off, one line, the line end dropped.
#[cfg(unix)]
fn read_password_from_stdin() -> Result<String, String> {
    use std::io::BufRead;
    // SAFETY: termios is plain old data; the calls get fd 0 and valid pointers.
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut old) } != 0 {
        return Err("inappropriate ioctl for device".to_string());
    }
    let mut new = old;
    new.c_lflag &= !libc::ECHO;
    new.c_lflag |= libc::ICANON | libc::ISIG;
    new.c_iflag |= libc::ICRNL;
    if unsafe { libc::tcsetattr(0, libc::TCSANOW, &new) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &old) };
    match read {
        Err(e) => Err(e.to_string()),
        Ok(0) => Err("EOF".to_string()),
        Ok(_) => {
            let line = line.strip_suffix('\n').unwrap_or(&line);
            Ok(line.strip_suffix('\r').unwrap_or(line).to_string())
        }
    }
}

#[cfg(not(unix))]
fn read_password_from_stdin() -> Result<String, String> {
    rpassword::read_password().map_err(|e| e.to_string())
}

/// The tail of `getWalletHandleMaybePassword(dataDir, walletName, true)` once
/// the wallet is resolved: the (cached) handle token and the password;
/// `get_password` is go's `getPassword` (false: the prompt only when no token
/// could be had without it).
pub(crate) fn wallet_handle_and_password(
    rt: &tokio::runtime::Runtime,
    client: &KmdClient,
    data_dir: &Path,
    wallet_id: &str,
    wallet_name: &str,
    get_password: bool,
) -> Result<(String, String), String> {
    let cache_dir = ensure_cache_dir(data_dir)?;
    // A cached token, authing with a blank password if required.
    if let Ok(token) = get_wallet_handle_token_cached(rt, client, &cache_dir, wallet_id, "") {
        if get_password && !wallet_is_unencrypted(rt, client, wallet_id) {
            return Ok((token, read_password_for(wallet_name)?));
        }
        return Ok((token, String::new()));
    }
    // Assume any errors were "wrong password" errors.
    let pw = read_password_for(wallet_name)?;
    let token =
        get_wallet_handle_token_cached(rt, client, &cache_dir, wallet_id, &pw).map_err(|e| {
            format!("Couldn't get token for wallet '{wallet_name}' (ID: {wallet_id}): {e}")
        })?;
    Ok((token, pw))
}
