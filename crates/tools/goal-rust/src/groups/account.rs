//! `goal account` — port of `../go-algorand/cmd/goal/account.go`.
//!
//! Leaf list and `Short` text taken from cobra `Use` / `Short` fields
//! (account.go:81-109).

use std::process::ExitCode;

use clap::Subcommand;

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
    Delete,
    /// Delete a participation key.
    #[command(name = "deletepartkey")]
    Deletepartkey,
    /// Dump the balance record for the specified account.
    Dump,
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
    New,
    /// Output details about all available part keys.
    #[command(name = "partkeyinfo")]
    Partkeyinfo,
    /// Change the human-friendly name of an account.
    Rename,
    /// Renew all existing participation keys.
    #[command(name = "renewallpartkeys")]
    Renewallpartkeys,
    /// Renew an account's participation key.
    #[command(name = "renewpartkey")]
    Renewpartkey,
    /// Retrieve the rewards for the specified account.
    Rewards,
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
        AccountCmd::Delete => "delete",
        AccountCmd::Deletepartkey => "deletepartkey",
        AccountCmd::Dump => "dump",
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
        AccountCmd::New => "new",
        AccountCmd::Partkeyinfo => "partkeyinfo",
        AccountCmd::Rename => "rename",
        AccountCmd::Renewallpartkeys => "renewallpartkeys",
        AccountCmd::Renewpartkey => "renewpartkey",
        AccountCmd::Rewards => "rewards",
    };
    unimplemented("account", leaf)
}
