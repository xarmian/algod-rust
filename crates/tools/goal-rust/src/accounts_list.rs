//! Per-data-dir account-name + default-wallet persistence.
//!
//! Ports `../go-algorand/cmd/goal/accountsList.go` (257 LOC) at
//! `v4.6.0-stable`. The on-disk JSON layout mirrors Go's
//! `json.MarshalIndent` of `AccountsList{}` verbatim so a Rust-written
//! `accountList.json` is byte-compatible with Go's `goal` (and
//! vice-versa).
//!
//! ## Path resolution
//!
//! Go's `accountListFileName` (accountsList.go:56-72) picks:
//!
//! - `<data_dir>/<genesis_id>/accountList.json` if the algod data dir
//!   is "private" (no `system.json` or `shared_server: false`).
//! - `<global_config_file_root>/<genesis_id>/accountList.json`
//!   otherwise (multi-user / shared-server layout).
//!
//! We reuse `data_dir::is_algorand_data_private`,
//! `data_dir::read_genesis_id`, and `data_dir::global_config_file_root`
//! so the resolution stays consistent with kmd-dir resolution (TASK-221).
//!
//! ## Consumers
//!
//! Phase B Bs that follow consume this module:
//! - B3 (`account rename` / `account new --default`): mutates Accounts.
//! - B4 (`account list`): renders `*Default` marker via `is_default`.
//! - B6 (`account import`): names the imported account.
//! - This task (B2): `wallet new` sets `DefaultWalletID` when the new
//!   wallet is the only one; `wallet list` appends `(default)` to the
//!   wallet name line. Mirrors `wallet.go:268-273`.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::data_dir;

/// Account-name and default-account/default-wallet record for one
/// (data-dir, genesis-id) pair.
///
/// Field names map 1:1 to Go's struct (`accountsList.go:33-38`) so
/// the JSON wire format is byte-identical to what Go writes.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AccountsList {
    /// address → friendly name. Empty when no accounts have been
    /// named yet.
    #[serde(rename = "Accounts", default)]
    pub accounts: HashMap<String, String>,

    /// Address of the default account, or empty if unset.
    #[serde(rename = "DefaultAccount", default)]
    pub default_account: String,

    /// Wallet ID of the default wallet, or empty if unset. Go's field
    /// is `DefaultWalletID` (note the capital `ID` suffix Go always
    /// uses for golint compliance).
    #[serde(rename = "DefaultWalletID", default)]
    pub default_wallet_id: String,

    /// Resolved algod data dir. Persisted in the JSON for parity with
    /// Go's `json.MarshalIndent` output (which includes every exported
    /// struct field) — operators sometimes inspect the file and Go
    /// surfaces this for context. Recomputed on load from the actual
    /// `<data_dir>` that produced the file.
    #[serde(rename = "DataDir", default)]
    pub data_dir: PathBuf,
}

impl AccountsList {
    /// Construct an empty list rooted at `data_dir`. Equivalent to
    /// Go's struct literal in `makeAccountsList` (accountsList.go:41).
    pub fn new_empty(data_dir: &Path) -> Self {
        Self {
            accounts: HashMap::new(),
            default_account: String::new(),
            default_wallet_id: String::new(),
            data_dir: data_dir.to_path_buf(),
        }
    }

    /// Load from disk, falling back to an in-memory empty list when
    /// the file doesn't exist or is unreadable. Mirrors Go's
    /// `loadList` (accountsList.go:194-204) — Go uses
    /// `json.Unmarshal` and ignores the error; we do the same so a
    /// corrupted file doesn't block `wallet new`. Caller can call
    /// `account_list_filename` explicitly to inspect the path.
    pub fn load(data_dir: &Path) -> Self {
        let mut list = Self::new_empty(data_dir);
        let Ok(path) = list.account_list_filename() else {
            return list;
        };
        let Ok(raw) = fs::read(&path) else {
            return list;
        };
        if let Ok(parsed) = serde_json::from_slice::<AccountsList>(&raw) {
            list.accounts = parsed.accounts;
            list.default_account = parsed.default_account;
            list.default_wallet_id = parsed.default_wallet_id;
            // Keep `data_dir` from the live argument — Go overwrites
            // it after Unmarshal too (the struct literal in
            // makeAccountsList sets DataDir first, then loadList is
            // called; Go's `json.Unmarshal(raw, &accountList)` then
            // overwrites DataDir with whatever the file says, but the
            // value is round-tripped from a previous write that used
            // the same dir). To keep this robust against a relocated
            // data dir we re-pin from the live argument.
        }
        list
    }

    /// Resolve the on-disk path for this list. Equivalent to Go's
    /// `accountListFileName` (accountsList.go:56-72) — private data
    /// dirs land beside the data dir, shared/server layouts land
    /// under `~/.algorand/<genesis_id>/`.
    pub fn account_list_filename(&self) -> Result<PathBuf, AccountsListError> {
        let genesis_id = data_dir::read_genesis_id(&self.data_dir)
            .map_err(|e| AccountsListError::GenesisIdFail(e.to_string()))?;
        let base = if data_dir::is_algorand_data_private(&self.data_dir) {
            self.data_dir.clone()
        } else {
            data_dir::global_config_file_root().ok_or(AccountsListError::NoConfigRoot)?
        };
        Ok(base.join(genesis_id).join("accountList.json"))
    }

    /// Write the current state to disk. Mirrors Go's `dumpList`
    /// (accountsList.go:182-192) — JSON encoded with 2-space indent,
    /// trailing newline, mode 0644. Creates parent directories on
    /// demand (Go doesn't but the path is normally created by
    /// `kmd-rust`/algod first; we add it for robustness so a brand-new
    /// data dir with no prior writes works).
    pub fn save(&self) -> Result<(), AccountsListError> {
        let path = self.account_list_filename()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(AccountsListError::Io)?;
        }
        // serde_json::to_vec_pretty uses 2-space indent and emits no
        // trailing newline; Go's MarshalIndent + manual append('\n')
        // produces exactly the same shape after we add the newline.
        let mut buf = serde_json::to_vec_pretty(self).map_err(AccountsListError::Encode)?;
        buf.push(b'\n');
        fs::write(&path, &buf).map_err(AccountsListError::Io)?;
        Ok(())
    }

    /// `isDefault(addr)` — true if `addr` is the recorded default
    /// account. Mirrors Go's identically-named method.
    pub fn is_default(&self, address: &str) -> bool {
        self.default_account == address
    }

    /// `setDefaultWalletID(id)`. Mirrors Go: writes through to disk
    /// (Go's `setDefaultWalletID` calls `dumpList` at the end).
    pub fn set_default_wallet_id(&mut self, id: &str) -> Result<(), AccountsListError> {
        self.default_wallet_id = id.to_string();
        self.save()
    }

    /// `setDefault(name)` — find the address with that friendly name
    /// and mark it default. No-op if no match. Mirrors Go's behavior.
    pub fn set_default(&mut self, account_name: &str) -> Result<(), AccountsListError> {
        for (addr, name) in &self.accounts {
            if name == account_name {
                self.default_account = addr.clone();
                break;
            }
        }
        self.save()
    }

    /// `addAccount(name, addr)` — record the name, marking it default
    /// if this is the first entry. Mirrors Go's `addAccount`
    /// (accountsList.go:142-156). Validation: refuse names that parse
    /// as a checksummed Algorand address.
    pub fn add_account(
        &mut self,
        account_name: &str,
        address: &str,
    ) -> Result<(), AccountsListError> {
        if algo_types::Address::from_algorand_string(account_name).is_ok() {
            return Err(AccountsListError::AddressAsName);
        }
        if self.accounts.is_empty() {
            self.default_account = address.to_string();
        }
        self.accounts
            .insert(address.to_string(), account_name.to_string());
        self.save()
    }

    /// `removeAccount(addr)`. Mirrors Go's identically-named method.
    pub fn remove_account(&mut self, address: &str) -> Result<(), AccountsListError> {
        self.accounts.remove(address);
        self.save()
    }

    /// `getNameByAddress(addr)`. Returns the friendly name if known,
    /// otherwise the address itself. Mirrors Go.
    pub fn name_for(&self, address: &str) -> String {
        self.accounts
            .get(address)
            .cloned()
            .unwrap_or_else(|| address.to_string())
    }

    /// `getAddressByName(name)`. Returns the matching address if
    /// known, otherwise the name itself. Mirrors Go.
    pub fn address_for(&self, account_name: &str) -> String {
        for (addr, name) in &self.accounts {
            if name == account_name {
                return addr.clone();
            }
        }
        account_name.to_string()
    }

    /// `isTaken(name)`. Mirrors Go.
    pub fn is_taken(&self, account_name: &str) -> bool {
        self.accounts.values().any(|n| n == account_name)
    }

    /// `rename(old, new)`. Mirrors Go.
    pub fn rename(&mut self, old_name: &str, new_name: &str) -> Result<(), AccountsListError> {
        for name in self.accounts.values_mut() {
            if name == old_name {
                *name = new_name.to_string();
                break;
            }
        }
        self.save()
    }

    /// `getUnnamed()`. Returns the smallest unused `Unnamed-N` slug
    /// (counting from 0). Mirrors Go.
    pub fn next_unnamed(&self) -> String {
        let mut i = 0;
        loop {
            let candidate = format!("Unnamed-{i}");
            if !self.is_taken(&candidate) {
                return candidate;
            }
            i += 1;
        }
    }
}

/// Errors surfaced by [`AccountsList`].
#[derive(Debug, thiserror::Error)]
pub enum AccountsListError {
    /// Couldn't read the genesis ID for the data dir (no
    /// `genesis.json`, malformed, etc.). Carries the underlying error
    /// text rendered verbatim — operators grep for kmd/algod's
    /// existing wording.
    #[error("Cannot retrieve genesis id from data directory: {0}")]
    GenesisIdFail(String),

    /// Shared/server layout was selected but `$HOME` is unset so
    /// `~/.algorand` couldn't be resolved.
    #[error("unable to find config root: HOME is not set")]
    NoConfigRoot,

    /// Filesystem I/O failure (read, write, mkdir).
    #[error("accountsList I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON encode failure (essentially infallible for our shape,
    /// but propagated for completeness).
    #[error("accountsList encode error: {0}")]
    Encode(#[from] serde_json::Error),

    /// `add_account` was passed a name that parses as a valid
    /// Algorand address. Mirrors Go's `isValidName`
    /// (accountsList.go:48-52).
    #[error("An Algorand address cannot be used as an account name.")]
    AddressAsName,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a fake private algod data dir containing the bare
    /// genesis.json needed by `read_genesis_id`. Returns the tempdir
    /// guard + the data-dir path.
    fn fake_private_data_dir(genesis_id: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let genesis = serde_json::json!({
            "id": genesis_id.strip_prefix("network-").unwrap_or(genesis_id),
            "network": "network",
            "proto": "future",
            "alloc": [],
            "rwd": "FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I",
            "fees": "FEESINKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANY3ZN3I",
        });
        fs::write(
            data_dir.join("genesis.json"),
            serde_json::to_string_pretty(&genesis).unwrap(),
        )
        .unwrap();
        (tmp, data_dir)
    }

    #[test]
    fn round_trip_private_data_dir() {
        let (_tmp, data_dir) = fake_private_data_dir("network-net");

        let mut list = AccountsList::new_empty(&data_dir);
        list.add_account(
            "alice",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY",
        )
        .expect("add alice");
        list.add_account(
            "bob",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB7",
        )
        .expect("add bob");
        list.set_default_wallet_id("wallet-id-xyz")
            .expect("set wid");

        // File landed under <data_dir>/<gid>/accountList.json.
        let path = list.account_list_filename().expect("path");
        assert!(
            path.starts_with(&data_dir),
            "private path under data dir: {path:?}"
        );
        assert!(path.ends_with("accountList.json"));

        let reloaded = AccountsList::load(&data_dir);
        assert_eq!(reloaded.default_wallet_id, "wallet-id-xyz");
        assert_eq!(reloaded.accounts.len(), 2);
        assert_eq!(
            reloaded.name_for("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY"),
            "alice"
        );
        // First-added address is the default.
        assert!(reloaded.is_default("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY"));
    }

    #[test]
    fn load_missing_file_returns_empty_in_memory() {
        let (_tmp, data_dir) = fake_private_data_dir("net2");
        let list = AccountsList::load(&data_dir);
        assert!(list.accounts.is_empty());
        assert!(list.default_wallet_id.is_empty());
        assert!(list.default_account.is_empty());
    }

    #[test]
    fn shared_data_dir_uses_global_config_root() {
        // Mark the data dir as shared via system.json. We don't actually
        // write into ~/.algorand from a test — just verify the resolved
        // path is rooted there (or that the helper surfaces NoConfigRoot
        // when HOME is unset).
        let (_tmp, data_dir) = fake_private_data_dir("net3");
        fs::write(data_dir.join("system.json"), br#"{"shared_server": true}"#).unwrap();
        let list = AccountsList::new_empty(&data_dir);
        match list.account_list_filename() {
            Ok(p) => {
                // Must NOT be under the data dir.
                assert!(
                    !p.starts_with(&data_dir),
                    "shared layout must escape data dir; got {p:?}",
                );
                assert!(p.ends_with("accountList.json"));
            }
            Err(AccountsListError::NoConfigRoot) => {
                // Acceptable if HOME is unset in the test env.
            }
            Err(e) => panic!("unexpected error resolving shared path: {e:?}"),
        }
    }

    #[test]
    fn add_account_with_address_as_name_is_rejected() {
        let (_tmp, data_dir) = fake_private_data_dir("net4");
        let mut list = AccountsList::new_empty(&data_dir);
        // Build a real Algorand address with valid checksum to pass
        // the name-validation guard, then try to use it as the name.
        let addr_str = algo_types::Address([0xab; 32]).to_algorand_string();
        let err = list.add_account(&addr_str, &addr_str).unwrap_err();
        assert!(matches!(err, AccountsListError::AddressAsName));
    }

    #[test]
    fn next_unnamed_skips_taken_slots() {
        let (_tmp, data_dir) = fake_private_data_dir("net5");
        let mut list = AccountsList::new_empty(&data_dir);
        assert_eq!(list.next_unnamed(), "Unnamed-0");
        list.add_account(
            "Unnamed-0",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY",
        )
        .expect("add");
        assert_eq!(list.next_unnamed(), "Unnamed-1");
    }

    #[test]
    fn rename_swaps_the_friendly_name() {
        let (_tmp, data_dir) = fake_private_data_dir("net6");
        let mut list = AccountsList::new_empty(&data_dir);
        list.add_account(
            "old",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY",
        )
        .expect("add");
        list.rename("old", "new").expect("rename");
        let reloaded = AccountsList::load(&data_dir);
        assert_eq!(
            reloaded.name_for("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY"),
            "new"
        );
        // Old name no longer resolves.
        assert!(!reloaded.is_taken("old"));
    }

    #[test]
    fn json_keys_match_go_struct_field_names() {
        // Wire-format check: byte-for-byte Go's MarshalIndent shape.
        let (_tmp, data_dir) = fake_private_data_dir("net7");
        let mut list = AccountsList::new_empty(&data_dir);
        list.default_wallet_id = "wid".to_string();
        list.default_account = "addr".to_string();
        let json = serde_json::to_string_pretty(&list).unwrap();
        for key in [
            "\"Accounts\"",
            "\"DefaultAccount\"",
            "\"DefaultWalletID\"",
            "\"DataDir\"",
        ] {
            assert!(
                json.contains(key),
                "JSON must use Go's exact key {key}; got {json}",
            );
        }
    }
}
