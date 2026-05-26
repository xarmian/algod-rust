//! `goal account` — port of `../go-algorand/cmd/goal/account.go`.
//!
//! Leaf list and `Short` text taken from cobra `Use` / `Short` fields
//! (account.go:81-109).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum AccountCmd {
    /// Generate and install participation key for the specified account.
    #[command(name = "addpartkey")]
    Addpartkey,
    /// Retrieve information about the assets belonging to the specified
    /// account inclusive of asset metadata.
    #[command(name = "assetdetails")]
    Assetdetails(AssetdetailsArgs),
    /// Retrieve the balances for the specified account.
    Balance(AddressArgs),
    /// Change online status for the specified account.
    #[command(name = "changeonlinestatus")]
    Changeonlinestatus,
    /// Delete an account.
    Delete(DeleteArgs),
    /// Delete a participation key.
    #[command(name = "deletepartkey")]
    Deletepartkey,
    /// Dump the balance record for the specified account.
    Dump(DumpArgs),
    /// Export an account key for use with account import.
    Export,
    /// Import an account key from mnemonic.
    Import,
    /// Import .rootkey files from the data directory into a kmd wallet.
    #[command(name = "importrootkey")]
    Importrootkey,
    /// Retrieve information about the assets and applications belonging
    /// to the specified account.
    Info(InfoArgs),
    /// Install a participation key.
    #[command(name = "installpartkey")]
    Installpartkey,
    /// Show the list of Algorand accounts on this machine.
    List(ListArgs),
    /// List participation keys summary.
    #[command(name = "listpartkeys")]
    Listpartkeys,
    /// Permanently mark an account as not participating (i.e. offline and
    /// earns no rewards).
    #[command(name = "marknonparticipating")]
    Marknonparticipating,
    /// Control and manage multisig accounts.
    Multisig {
        #[command(subcommand)]
        cmd: Option<MultisigCmd>,
    },
    /// Create a new account.
    New(NewArgs),
    /// Output details about all available part keys.
    #[command(name = "partkeyinfo")]
    Partkeyinfo,
    /// Change the human-friendly name of an account.
    Rename(RenameArgs),
    /// Renew all existing participation keys.
    #[command(name = "renewallpartkeys")]
    Renewallpartkeys,
    /// Renew an account's participation key.
    #[command(name = "renewpartkey")]
    Renewpartkey,
    /// Retrieve the rewards for the specified account.
    Rewards(AddressArgs),
}

// ------- TASK-235 (B3) args -------

/// `account new [name]` — generate a fresh key in the chosen wallet.
/// Mirrors `account.go:313-359` (`newCmd`).
#[derive(Args, Debug)]
pub struct NewArgs {
    /// Friendly account name. Optional positional — Go uses
    /// `cobra.RangeArgs(0, 1)` and falls back to `accountList.getUnnamed()`
    /// when omitted.
    pub name: Option<String>,

    /// Wallet to create the key in. Mirrors Go's persistent `-w` flag
    /// on the account group (`account.go:112`).
    #[arg(short = 'w', long = "wallet")]
    pub wallet: Option<String>,

    /// Wallet password (skip the prompt). Phase-A divergence: when
    /// stdin is non-TTY and `--password` is omitted, we read one line
    /// from stdin (same pattern as `wallet new`).
    #[arg(long = "password")]
    pub password: Option<String>,

    /// Mark this account as the default account in accountList.json.
    /// Mirrors Go's `-f, --default` bool (`account.go:118`).
    #[arg(short = 'f', long = "default")]
    pub set_default: bool,
}

/// `account delete -a <address>` — remove a key from the wallet AND
/// from accountList.json. Mirrors `account.go:379-398` (`deleteCmd`).
///
/// Go uses `-a` flag with `validateNoPosArgsFn` (no positionals). We
/// match for help-parity even though the task body sketched a
/// positional surface.
#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// Address of the account to delete. Mirrors Go's
    /// `-a, --address` flag (`account.go:121`).
    #[arg(short = 'a', long = "address")]
    pub address: String,

    /// Wallet that holds the key. Mirrors Go's persistent `-w` flag.
    #[arg(short = 'w', long = "wallet")]
    pub wallet: Option<String>,

    /// Wallet password (skip the prompt). Non-TTY stdin reads one
    /// line.
    #[arg(long = "password")]
    pub password: Option<String>,
}

/// `account rename <old> <new>` — local-only rename of the friendly
/// name in accountList.json. Mirrors `account.go:281-310`.
#[derive(Args, Debug)]
pub struct RenameArgs {
    /// Existing account name (or address). Go's first positional.
    pub old_name: String,
    /// New account name. Go's second positional.
    pub new_name: String,
}

/// Shared `-a <address>` flag for the read-path leaves
/// `balance` / `rewards`. `info` and `assetdetails` carry richer args
/// (see [`InfoArgs`], [`AssetdetailsArgs`]). Mirrors Go's account-group
/// persistent `-a, --address` flag (`account.go:121`).
#[derive(Args, Debug)]
pub struct AddressArgs {
    /// Algorand address to operate on. Mirrors Go's `-a, --address` flag.
    #[arg(short = 'a', long = "address")]
    pub address: String,
}

/// `account info -a <addr> [--onlyShowAssetIDs]`. Adds Go's
/// `--onlyShowAssetIDs` flag (account.go:108) to suppress per-asset
/// metadata fetch on the Held Assets section.
#[derive(Args, Debug)]
pub struct InfoArgs {
    /// Algorand address to operate on.
    #[arg(short = 'a', long = "address")]
    pub address: String,
    /// Skip the per-asset metadata fetch on Held Assets; each held
    /// asset row becomes `\tID N\n`. Mirrors Go's identically-named
    /// flag — useful against algods that throttle or when the caller
    /// just wants the asset-id catalog.
    #[arg(long = "onlyShowAssetIDs", alias = "only-show-asset-ids")]
    pub only_show_asset_ids: bool,
}

/// `account assetdetails -a <addr> [-l <n>] [-n <token>]`. Mirrors
/// Go's `--limit/-l` + `--next/-n` flags (account.go:117) and routes
/// through the paginated `/v2/accounts/{addr}/assets` endpoint.
#[derive(Args, Debug)]
pub struct AssetdetailsArgs {
    /// Algorand address to operate on.
    #[arg(short = 'a', long = "address")]
    pub address: String,
    /// Cap the number of asset entries returned. Mirrors Go's
    /// `-l, --limit` (unset ⇒ algod's default).
    #[arg(short = 'l', long = "limit")]
    pub limit: Option<u64>,
    /// Opaque continuation token from a previous response's
    /// `NextToken`. Mirrors Go's `-n, --next`.
    #[arg(short = 'n', long = "next")]
    pub next: Option<String>,
}

/// `account dump -a <address>` — pretty-print the REST
/// `/v2/accounts/{addr}` response.
///
/// **Intentional divergence from Go** (TASK-235 scope, documented in
/// PR description): Go uses `protocol.EncodeJSONStrict(&BalanceRecord)`
/// at `account.go:851` which emits the internal `basics.BalanceRecord`
/// struct with msgpack-keyed JSON fields. Per task body, we fetch the
/// REST response (`/v2/accounts/{addr}`) and pretty-print it instead —
/// more useful for operators piping into `jq`, less Go-byte-exact.
/// Porting the BalanceRecord JSON encoder is out of scope for B3.
/// `account list [-w <wallet>]` — TASK-236 / B4. Lists every address
/// kmd knows about with status flag, balance, friendly name, and the
/// `*` default-account marker.
///
/// **Divergence from Go**: Go's `listCmd` (`account.go:488-543`) takes
/// `ensureWalletHandle(dataDir, walletName)` and lists only one
/// wallet's addresses. The task body + plan prescribe multi-wallet
/// aggregation across every wallet kmd knows about, since the
/// AccountsList we ship in TASK-234 tracks wallet-level defaults. We
/// follow the plan; `-w` still narrows to a single wallet for parity
/// with Go's actual filter semantics.
#[derive(Args, Debug)]
pub struct ListArgs {
    /// Restrict to a single wallet by name. When omitted, list every
    /// address across every wallet kmd knows about.
    #[arg(short = 'w', long = "wallet")]
    pub wallet: Option<String>,

    /// Wallet password for the open-handle step. Required for each
    /// wallet's `init_wallet` call; non-TTY stdin reads one line.
    #[arg(long = "password")]
    pub password: Option<String>,
}

#[derive(Args, Debug)]
pub struct DumpArgs {
    /// Address to dump. Mirrors Go's `-a, --address` flag.
    #[arg(short = 'a', long = "address")]
    pub address: String,

    /// Write the response to this file instead of stdout. Mirrors
    /// Go's `-o, --outfile` flag (`account.go`). Go writes msgpack-
    /// encoded `BalanceRecord` to disk; since we render the REST JSON
    /// instead (see [`DumpArgs`] doc), the file gets the same raw
    /// JSON body that would otherwise hit stdout.
    #[arg(short = 'o', long = "outfile")]
    pub outfile: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum MultisigCmd {
    /// Delete a multisig account.
    Delete,
    /// Print information about a multisig account.
    Info,
    /// Create a new multisig account.
    New,
}

pub fn run(cmd: AccountCmd) -> ExitCode {
    let leaf: &str = match cmd {
        AccountCmd::Addpartkey => "addpartkey",
        AccountCmd::Assetdetails(args) => {
            return crate::cmd::account::run_assetdetails(args, crate::cli_state::datadirs());
        }
        AccountCmd::Balance(args) => {
            return crate::cmd::account::run_balance(args, crate::cli_state::datadirs());
        }
        AccountCmd::Changeonlinestatus => "changeonlinestatus",
        AccountCmd::Delete(args) => {
            return crate::cmd::account::run_delete(
                args,
                crate::cli_state::datadirs(),
                crate::cli_state::kmddir(),
            );
        }
        AccountCmd::Deletepartkey => "deletepartkey",
        AccountCmd::Dump(args) => {
            return crate::cmd::account::run_dump(args, crate::cli_state::datadirs());
        }
        AccountCmd::Export => "export",
        AccountCmd::Import => "import",
        AccountCmd::Importrootkey => "importrootkey",
        AccountCmd::Info(args) => {
            return crate::cmd::account::run_info(args, crate::cli_state::datadirs());
        }
        AccountCmd::Installpartkey => "installpartkey",
        AccountCmd::List(args) => {
            return crate::cmd::account::run_list(
                args,
                crate::cli_state::datadirs(),
                crate::cli_state::kmddir(),
            );
        }
        AccountCmd::Listpartkeys => "listpartkeys",
        AccountCmd::Marknonparticipating => "marknonparticipating",
        AccountCmd::Multisig { cmd } => {
            let Some(cmd) = cmd else {
                return crate::print_group_help(&["account", "multisig"]);
            };
            let leaf = match cmd {
                MultisigCmd::Delete => "delete",
                MultisigCmd::Info => "info",
                MultisigCmd::New => "new",
            };
            return unimplemented("account multisig", leaf);
        }
        AccountCmd::New(args) => {
            return crate::cmd::account::run_new(
                args,
                crate::cli_state::datadirs(),
                crate::cli_state::kmddir(),
            );
        }
        AccountCmd::Partkeyinfo => "partkeyinfo",
        AccountCmd::Rename(args) => {
            return crate::cmd::account::run_rename(args, crate::cli_state::datadirs());
        }
        AccountCmd::Renewallpartkeys => "renewallpartkeys",
        AccountCmd::Renewpartkey => "renewpartkey",
        AccountCmd::Rewards(args) => {
            return crate::cmd::account::run_rewards(args, crate::cli_state::datadirs());
        }
    };
    unimplemented("account", leaf)
}
