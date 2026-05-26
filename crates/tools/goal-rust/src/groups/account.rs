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
    Addpartkey(AddpartkeyArgs),
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
    Deletepartkey(DeletepartkeyArgs),
    /// Dump the balance record for the specified account.
    Dump(DumpArgs),
    /// Export an account key for use with account import.
    Export(ExportArgs),
    /// Import an account key from mnemonic.
    Import(ImportArgs),
    /// Import .rootkey files from the data directory into a kmd wallet.
    #[command(name = "importrootkey")]
    Importrootkey(ImportRootKeyArgs),
    /// Retrieve information about the assets and applications belonging
    /// to the specified account.
    Info(InfoArgs),
    /// Install a participation key.
    #[command(name = "installpartkey")]
    Installpartkey(InstallpartkeyArgs),
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
    Renewallpartkeys(RenewallpartkeysArgs),
    /// Renew an account's participation key.
    #[command(name = "renewpartkey")]
    Renewpartkey(RenewpartkeyArgs),
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

/// `account renewpartkey --address <addr> --roundLastValid <r>
/// [--keyDilution <n>] [--register]`. Mirrors Go's
/// `renewParticipationKeyCmd` (account.go:1053-1099).
///
/// **Divergences (documented):**
/// - Same algokey-rust-no-lib limitation as addpartkey: uses B9's
///   REST generate endpoint (server-side generation + install).
/// - Go's renewpartkey ALWAYS issues a keyreg (online) transaction
///   after generating; we skip that step (lands in B12) and the
///   operator runs `goal account changeonlinestatus` themselves.
///   `--register` is wired but errors with a deferral message.
#[derive(Args, Debug)]
pub struct RenewpartkeyArgs {
    #[arg(short = 'a', long = "address")]
    pub address: String,
    /// Last round for which the new key is valid.
    #[arg(long = "roundLastValid", alias = "round-last-valid")]
    pub round_last_valid: u64,
    /// Optional key dilution.
    #[arg(long = "keyDilution", alias = "key-dilution")]
    pub key_dilution: Option<u64>,
    /// Issue a keyreg-online transaction after generation. Defers to
    /// B12 — set today exits 1 with a clear deferral message.
    #[arg(long = "register")]
    pub register: bool,
}

/// `account renewallpartkeys --roundLastValid <r> [--keyDilution <n>]
/// [--register]`. Mirrors Go's `renewAllParticipationKeyCmd`
/// (account.go:1132-1219).
#[derive(Args, Debug)]
pub struct RenewallpartkeysArgs {
    #[arg(long = "roundLastValid", alias = "round-last-valid")]
    pub round_last_valid: u64,
    #[arg(long = "keyDilution", alias = "key-dilution")]
    pub key_dilution: Option<u64>,
    #[arg(long = "register")]
    pub register: bool,
}

/// `account addpartkey --address <addr> --roundFirstValid <r> --roundLastValid <r> [--keyDilution <n>]`.
/// Mirrors Go's `addParticipationKeyCmd` (account.go:973-1011).
///
/// **Divergence from Go**: Go's addpartkey calls
/// `participation.GenParticipationKeysTo` (client-side generation to
/// disk, then upload). We use B9's `generate_participation_keys` REST
/// endpoint (server-side generation) since algokey-rust has no lib
/// facade yet. As a result, `--partkeyoutputdir` is omitted — algod
/// picks the on-disk location. Documented in PR #383.
#[derive(Args, Debug)]
pub struct AddpartkeyArgs {
    #[arg(short = 'a', long = "address")]
    pub address: String,
    /// First valid round for the new participation key.
    #[arg(long = "roundFirstValid", alias = "round-first-valid")]
    pub round_first_valid: u64,
    /// Last valid round for the new participation key.
    #[arg(long = "roundLastValid", alias = "round-last-valid")]
    pub round_last_valid: u64,
    /// Key dilution (subkeys per batch). Optional; algod picks a
    /// sensible default when omitted. Mirrors Go's `--keyDilution`.
    #[arg(long = "keyDilution", alias = "key-dilution")]
    pub key_dilution: Option<u64>,
}

/// `account installpartkey --partkey <path> --delete-input`. Mirrors
/// Go's `installParticipationKeyCmd` (account.go:1012-1052).
#[derive(Args, Debug)]
pub struct InstallpartkeyArgs {
    /// Path to the partkey file to install. Mirrors Go's
    /// `--partkey` flag.
    #[arg(long = "partkey")]
    pub partkey: std::path::PathBuf,
    /// Acknowledge forward-security deletion. Go refuses to install
    /// without this flag — forward security requires the input file
    /// to be deleted post-install (account.go:1016-1027).
    #[arg(long = "delete-input")]
    pub delete_input: bool,
}

/// `account deletepartkey <participation-id>`. Mirrors Go's
/// `deletePartKeyCmd` (account.go:361-377). Go uses
/// `--partkeyid` flag, not a positional — we follow.
#[derive(Args, Debug)]
pub struct DeletepartkeyArgs {
    /// ParticipationID to delete. Mirrors Go's `--partkeyid` flag.
    #[arg(long = "partkeyid")]
    pub partkeyid: String,
}

/// `account importrootkey [-u/--unencrypted] [-w <wallet>]` — discover
/// every `<data_dir>/<gid>/*.rootkey` SQLite file and import each into
/// the named wallet's kmd. Mirrors `importRootKeysCmd`
/// (account.go:1372-1463).
#[derive(Args, Debug)]
pub struct ImportRootKeyArgs {
    /// Use the kmd unencrypted-default-wallet (no password prompt;
    /// auto-creates if missing). Mirrors Go's `-u, --unencrypted-wallet`
    /// flag (account.go:193). Note this flag name differs from
    /// `wallet new --unencrypted` (the wallet-create leaf uses just
    /// `--unencrypted`).
    #[arg(short = 'u', long = "unencrypted-wallet")]
    pub unencrypted: bool,

    /// Wallet to import into. Mirrors Go's persistent `-w` flag.
    #[arg(short = 'w', long = "wallet")]
    pub wallet: Option<String>,

    /// Wallet password (skip the prompt). Non-TTY stdin reads one
    /// line.
    #[arg(long = "password")]
    pub password: Option<String>,
}

/// `account import [name]` — read mnemonic on stdin (or supply via
/// `--mnemonic`), import into the named wallet's kmd. Mirrors Go's
/// `importCmd` (account.go:1281-1338).
#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Friendly account name. Optional positional (Go uses
    /// `cobra.RangeArgs(0, 1)`; auto-generates via accountList
    /// `getUnnamed()` when omitted).
    pub name: Option<String>,

    /// Wallet to import into. Mirrors Go's persistent `-w` flag.
    #[arg(short = 'w', long = "wallet")]
    pub wallet: Option<String>,

    /// Wallet password (skip the prompt). Non-TTY stdin reads one
    /// line after the mnemonic.
    #[arg(long = "password")]
    pub password: Option<String>,

    /// 25-word mnemonic instead of reading from stdin. Mirrors Go's
    /// `--mnemonic` flag.
    #[arg(long = "mnemonic")]
    pub mnemonic: Option<String>,

    /// Mark the imported account as default in accountList.json.
    /// Mirrors Go's `-f, --default` flag (account.go:118 — `importDefault`).
    #[arg(short = 'f', long = "default")]
    pub set_default: bool,
}

/// `account export -a <addr>` — export the account key as a 25-word
/// mnemonic. Mirrors Go's `exportCmd` (account.go:1339-1371).
#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Address to export. Mirrors Go's `-a, --address` flag.
    #[arg(short = 'a', long = "address")]
    pub address: String,

    /// Wallet holding the key.
    #[arg(short = 'w', long = "wallet")]
    pub wallet: Option<String>,

    /// Wallet password (skip the prompt).
    #[arg(long = "password")]
    pub password: Option<String>,
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
    Delete(MsigDeleteArgs),
    /// Print information about a multisig account.
    Info(MsigInfoArgs),
    /// Create a new multisig account.
    New(MsigNewArgs),
}

// ---- TASK-240 (B8) multisig args ----

/// `account multisig new [-T <threshold>] <addr1> <addr2> ... [-w] [--password]`
/// Mirrors Go's `newMultisigCmd` (account.go:400-441).
#[derive(Args, Debug)]
pub struct MsigNewArgs {
    /// Component addresses (≥ 1 positional, Go uses `MinimumNArgs(1)`).
    pub addresses: Vec<String>,
    /// Multisig signing threshold (number of signatures required).
    /// Mirrors Go's `-T, --threshold` flag (account.go:124).
    #[arg(short = 'T', long = "threshold")]
    pub threshold: u8,
    /// Wallet to import into.
    #[arg(short = 'w', long = "wallet")]
    pub wallet: Option<String>,
    /// Wallet password (skip the prompt).
    #[arg(long = "password")]
    pub password: Option<String>,
}

/// `account multisig delete -a <addr> [-w] [--password]`. Mirrors
/// `deleteMultisigCmd` (account.go:443-462).
#[derive(Args, Debug)]
pub struct MsigDeleteArgs {
    /// Multisig address to delete.
    #[arg(short = 'a', long = "address")]
    pub address: String,
    #[arg(short = 'w', long = "wallet")]
    pub wallet: Option<String>,
    #[arg(long = "password")]
    pub password: Option<String>,
}

/// `account multisig info -a <addr> [-w] [--password]`. Mirrors
/// `infoMultisigCmd` (account.go:464-487).
#[derive(Args, Debug)]
pub struct MsigInfoArgs {
    /// Multisig address to inspect.
    #[arg(short = 'a', long = "address")]
    pub address: String,
    #[arg(short = 'w', long = "wallet")]
    pub wallet: Option<String>,
    #[arg(long = "password")]
    pub password: Option<String>,
}

pub fn run(cmd: AccountCmd) -> ExitCode {
    let leaf: &str = match cmd {
        AccountCmd::Addpartkey(args) => {
            return crate::cmd::account::run_addpartkey(args, crate::cli_state::datadirs());
        }
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
        AccountCmd::Deletepartkey(args) => {
            return crate::cmd::account::run_deletepartkey(args, crate::cli_state::datadirs());
        }
        AccountCmd::Dump(args) => {
            return crate::cmd::account::run_dump(args, crate::cli_state::datadirs());
        }
        AccountCmd::Export(args) => {
            return crate::cmd::account::run_export(
                args,
                crate::cli_state::datadirs(),
                crate::cli_state::kmddir(),
            );
        }
        AccountCmd::Import(args) => {
            return crate::cmd::account::run_import(
                args,
                crate::cli_state::datadirs(),
                crate::cli_state::kmddir(),
            );
        }
        AccountCmd::Importrootkey(args) => {
            return crate::cmd::account::run_importrootkey(
                args,
                crate::cli_state::datadirs(),
                crate::cli_state::kmddir(),
            );
        }
        AccountCmd::Info(args) => {
            return crate::cmd::account::run_info(args, crate::cli_state::datadirs());
        }
        AccountCmd::Installpartkey(args) => {
            return crate::cmd::account::run_installpartkey(args, crate::cli_state::datadirs());
        }
        AccountCmd::List(args) => {
            return crate::cmd::account::run_list(
                args,
                crate::cli_state::datadirs(),
                crate::cli_state::kmddir(),
            );
        }
        AccountCmd::Listpartkeys => {
            return crate::cmd::account::run_listpartkeys(crate::cli_state::datadirs());
        }
        AccountCmd::Marknonparticipating => "marknonparticipating",
        AccountCmd::Multisig { cmd } => {
            let Some(cmd) = cmd else {
                return crate::print_group_help(&["account", "multisig"]);
            };
            return match cmd {
                MultisigCmd::Delete(args) => crate::cmd::account::run_multisig_delete(
                    args,
                    crate::cli_state::datadirs(),
                    crate::cli_state::kmddir(),
                ),
                MultisigCmd::Info(args) => crate::cmd::account::run_multisig_info(
                    args,
                    crate::cli_state::datadirs(),
                    crate::cli_state::kmddir(),
                ),
                MultisigCmd::New(args) => crate::cmd::account::run_multisig_new(
                    args,
                    crate::cli_state::datadirs(),
                    crate::cli_state::kmddir(),
                ),
            };
        }
        AccountCmd::New(args) => {
            return crate::cmd::account::run_new(
                args,
                crate::cli_state::datadirs(),
                crate::cli_state::kmddir(),
            );
        }
        AccountCmd::Partkeyinfo => {
            return crate::cmd::account::run_partkeyinfo(crate::cli_state::datadirs());
        }
        AccountCmd::Rename(args) => {
            return crate::cmd::account::run_rename(args, crate::cli_state::datadirs());
        }
        AccountCmd::Renewallpartkeys(args) => {
            return crate::cmd::account::run_renewallpartkeys(args, crate::cli_state::datadirs());
        }
        AccountCmd::Renewpartkey(args) => {
            return crate::cmd::account::run_renewpartkey(args, crate::cli_state::datadirs());
        }
        AccountCmd::Rewards(args) => {
            return crate::cmd::account::run_rewards(args, crate::cli_state::datadirs());
        }
    };
    unimplemented("account", leaf)
}
