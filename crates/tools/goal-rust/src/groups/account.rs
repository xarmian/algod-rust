//! `goal account` — port of `../go-algorand/cmd/goal/account.go`.
//!
//! Leaf list and `Short` text taken from cobra `Use` / `Short` fields
//! (account.go:81-109).

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
    Assetdetails,
    /// Retrieve the balances for the specified account.
    Balance,
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
    Info,
    /// Install a participation key.
    #[command(name = "installpartkey")]
    Installpartkey,
    /// Show the list of Algorand accounts on this machine.
    List,
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
    Rewards,
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
#[derive(Args, Debug)]
pub struct DumpArgs {
    /// Address to dump. Mirrors Go's `-a, --address` flag.
    #[arg(short = 'a', long = "address")]
    pub address: String,
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
        AccountCmd::Assetdetails => "assetdetails",
        AccountCmd::Balance => "balance",
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
        AccountCmd::Info => "info",
        AccountCmd::Installpartkey => "installpartkey",
        AccountCmd::List => "list",
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
        AccountCmd::Rewards => "rewards",
    };
    unimplemented("account", leaf)
}
