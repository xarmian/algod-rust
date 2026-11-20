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

//! go `goal` v5.0.5-stable's cobra usage text (`Command.UsageString()`) for
//! the `account` and `wallet` commands and every command under them, as go
//! prints it after a usage error (issue #2453). Captured from go's `goal`:
//! for `account` / `wallet` from `goal <cmd> extra`, for the others from
//! `goal <cmd> --nosuchflag`, keeping the `Usage:` block that follows the
//! `Error: ...` line (cobra prints it with `Println`, so the text here ends
//! with one newline and go's stderr with two). Regenerate it the same way
//! when go's flags or `Short` texts change; `default_flags_e2e` compares
//! the error rows against go. [`help`] adds the `Long` text above it for
//! `--help` (issue #2464), compared against go by the same test.

/// The usage text of the command `path` (`"account multisig new"`), or
/// `None` for a command not in the table.
pub(crate) fn usage(path: &str) -> Option<&'static str> {
    Some(match path {
        "account" => {
            r#"Usage:
  goal account [flags]
  goal account [command]

Available Commands:
  addpartkey           Generate and install participation key for the specified account
  applicationdetails   Retrieve information about the applications created or opted-into by the specified account, possibly including application metadata
  assetdetails         Retrieve information about the assets belonging to the specified account inclusive of asset metadata
  balance              Retrieve the balances for the specified account
  changeonlinestatus   Change online status for the specified account
  delete               Delete an account
  deletepartkey        Delete a participation key
  dump                 Dump the balance record for the specified account
  export               Export an account key for use with account import
  import               Import an account key from mnemonic
  importrootkey        Import .rootkey files from the data directory into a kmd wallet
  info                 Retrieve information about the assets and applications belonging to the specified account
  installpartkey       Install a participation key
  list                 Show the list of Algorand accounts on this machine
  listpartkeys         List participation keys summary
  marknonparticipating Permanently mark an account as not participating (i.e. offline and earns no rewards)
  multisig             Control and manage multisig accounts
  new                  Create a new account
  partkeyinfo          Output details about all available part keys
  rename               Change the human-friendly name of an account
  renewallpartkeys     Renew all existing participation keys
  renewpartkey         Renew an account's participation key
  rewards              Retrieve the rewards for the specified account

Flags:
  -f, --default string   Set the account with this name to be the default account
  -h, --help             help for account
  -w, --wallet string    Set the wallet to be used for the selected operation

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd

Use "goal account [command] --help" for more information about a command.
"#
        }
        "wallet" => {
            r#"Usage:
  goal wallet [flags]
  goal wallet [command]

Available Commands:
  list        List wallets managed by kmd
  new         Create a new wallet
  rename      Rename wallet

Flags:
  -f, --default string   Set the wallet with this name to be the default wallet
  -h, --help             help for wallet

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd

Use "goal wallet [command] --help" for more information about a command.
"#
        }
        "account addpartkey" => {
            r#"Usage:
  goal account addpartkey [flags]

Flags:
  -a, --address string         Account to associate with the generated partkey
  -h, --help                   help for addpartkey
      --keyDilution uint       Key dilution for two-level participation keys (defaults to sqrt of validity window)
  -o, --outdir string          Save participation key file to specified output directory to (for offline creation)
      --roundFirstValid uint   The first round for which the generated partkey will be valid
      --roundLastValid uint    The last round for which the generated partkey will be valid

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account applicationdetails" => {
            r#"Usage:
  goal account applicationdetails [flags]

Flags:
  -a, --address string   Account address to look up (required)
  -h, --help             help for applicationdetails
      --include-params   Include application parameters (creator, global state schema, etc.)
  -l, --limit uint       The maximum number of applications to return
  -n, --next string      The next application index to use for pagination

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account assetdetails" => {
            r#"Usage:
  goal account assetdetails [flags]

Flags:
  -a, --address string   Account address to look up (required)
  -h, --help             help for assetdetails
  -l, --limit uint       The maximum number of assets to return
  -n, --next string      The next asset index to use for pagination

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account balance" => {
            r#"Usage:
  goal account balance [flags]

Flags:
  -a, --address string   Account address to retrieve balance (required)
  -h, --help             help for balance

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account changeonlinestatus" => {
            r#"Usage:
  goal account changeonlinestatus [flags]

Flags:
  -a, --address string       Account address to change (required if no --partkeyfile)
  -f, --fee uint             The Fee to set on the status change transaction (defaults to suggested fee)
      --firstvalid uint      FirstValid for the status change transaction (0 for current)
  -h, --help                 help for changeonlinestatus
      --lastvalid uint       The last round where the transaction may be committed to the ledger
  -x, --lease string         Lease value (base64, optional): no transaction may also acquire this lease until lastvalid
  -N, --no-wait              Don't wait for transaction to commit
  -o, --online               Set this account to online or offline (default true)
      --partkeyfile string   Participation key file (required if no --address)
      --rekey-to string      Rekey account to the given spending key/address. (Future transactions from this account will need to be signed with the new key.)
  -S, --signer string        Address of key to sign with, if different due to rekeying
  -t, --txfile string        Write status change transaction to this file
  -v, --validrounds uint     The validity period for the status change transaction

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account delete" => {
            r#"Usage:
  goal account delete [flags]

Flags:
  -a, --address string   Address of account to delete
  -h, --help             help for delete

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account deletepartkey" => {
            r#"Usage:
  goal account deletepartkey [flags]

Flags:
  -h, --help               help for deletepartkey
      --partkeyid string   Participation Key ID to delete

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account dump" => {
            r#"Usage:
  goal account dump [flags]

Flags:
  -a, --address string   Account address to retrieve balance (required)
  -h, --help             help for dump
  -o, --outfile string   Save balance record to specified output file

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account export" => {
            r#"Usage:
  goal account export [flags]

Flags:
  -a, --address string   Address of account to export
  -h, --help             help for export

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account import" => {
            r#"Usage:
  goal account import [flags]

Flags:
  -f, --default           Set this account as the default one
  -h, --help              help for import
  -m, --mnemonic string   Mnemonic to import (will prompt otherwise)

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account importrootkey" => {
            r#"Usage:
  goal account importrootkey [flags]

Flags:
  -h, --help                 help for importrootkey
  -u, --unencrypted-wallet   Import into the default unencrypted wallet, potentially creating it

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account info" => {
            r#"Usage:
  goal account info [flags]

Flags:
  -a, --address string     Account address to look up (required)
  -h, --help               help for info
      --onlyShowAssetIDs   Only show ASA IDs and not pull asset metadata

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account installpartkey" => {
            r#"Usage:
  goal account installpartkey [flags]

Flags:
      --delete-input     Acknowledge that installpartkey will delete the input key file
  -h, --help             help for installpartkey
      --partkey string   Participation key file to install

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account list" => {
            r#"Usage:
  goal account list [flags]

Flags:
  -h, --help   help for list
      --info   Include additional information about each account's assets and applications

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account listpartkeys" => {
            r#"Usage:
  goal account listpartkeys [flags]

Flags:
  -h, --help   help for listpartkeys

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account marknonparticipating" => {
            r#"Usage:
  goal account marknonparticipating [flags]

Flags:
  -a, --address string     Account address to change
  -f, --fee uint           The Fee to set on the status change transaction (defaults to suggested fee)
      --firstvalid uint    FirstValid for the status change transaction (0 for current)
  -h, --help               help for marknonparticipating
      --lastvalid uint     The last round where the transaction may be committed to the ledger
  -N, --no-wait            Don't wait for transaction to commit
      --rekey-to string    Rekey account to the given spending key/address. (Future transactions from this account will need to be signed with the new key.)
  -S, --signer string      Address of key to sign with, if different from address due to rekeying
  -t, --txfile string      Write status change transaction to this file, rather than posting to network
  -v, --validrounds uint   The validity period for the status change transaction

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account multisig" => {
            r#"Usage:
  goal account multisig [flags]
  goal account multisig [command]

Available Commands:
  delete      Delete a multisig account
  info        Print information about a multisig account
  new         Create a new multisig account

Flags:
  -h, --help   help for multisig

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation

Use "goal account multisig [command] --help" for more information about a command.
"#
        }
        "account new" => {
            r#"Usage:
  goal account new [flags]

Flags:
  -f, --default   Set this account as the default one
  -h, --help      help for new

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account partkeyinfo" => {
            r#"Usage:
  goal account partkeyinfo [flags]

Flags:
  -h, --help   help for partkeyinfo

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account rename" => {
            r#"Usage:
  goal account rename [old name] [new name] [flags]

Flags:
  -h, --help   help for rename

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account renewallpartkeys" => {
            r#"Usage:
  goal account renewallpartkeys [flags]

Flags:
  -f, --fee uint              The Fee to set on the status change transactions (defaults to suggested fee)
  -h, --help                  help for renewallpartkeys
      --keyDilution uint      Key dilution for two-level participation keys
  -N, --no-wait               Don't wait for transaction to commit
      --rekey-to string       Rekey account to the given spending key/address. (Future transactions from this account will need to be signed with the new key.)
      --roundLastValid uint   The last round for which the generated partkeys will be valid

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account renewpartkey" => {
            r#"Usage:
  goal account renewpartkey [flags]

Flags:
  -a, --address string        Account address to update (required)
  -f, --fee uint              The Fee to set on the status change transaction (defaults to suggested fee)
  -h, --help                  help for renewpartkey
      --keyDilution uint      Key dilution for two-level participation keys
  -N, --no-wait               Don't wait for transaction to commit
      --rekey-to string       Rekey account to the given spending key/address. (Future transactions from this account will need to be signed with the new key.)
      --roundLastValid uint   The last round for which the generated partkey will be valid

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account rewards" => {
            r#"Usage:
  goal account rewards [flags]

Flags:
  -a, --address string   Account address to retrieve rewards (required)
  -h, --help             help for rewards

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account multisig delete" => {
            r#"Usage:
  goal account multisig delete [flags]

Flags:
  -a, --address string   Address of multisig account to delete
  -h, --help             help for delete

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account multisig info" => {
            r#"Usage:
  goal account multisig info [flags]

Flags:
  -a, --address string   Address of multisig account to look up
  -h, --help             help for info

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "account multisig new" => {
            r#"Usage:
  goal account multisig new [address 1] [address 2]... [flags]

Flags:
  -h, --help              help for new
  -T, --threshold uint8   Number of signatures required to spend from this address (default 1)

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
  -w, --wallet string         Set the wallet to be used for the selected operation
"#
        }
        "wallet list" => {
            r#"Usage:
  goal wallet list [flags]

Flags:
  -h, --help   help for list

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
"#
        }
        "wallet new" => {
            r#"Usage:
  goal wallet new [wallet name] [flags]

Flags:
  -h, --help                       help for new
      --no-display-seed            Create a new wallet without displaying the seed phrase.
  -r, --recover goal account new   Recover the wallet from the backup mnemonic provided at wallet creation (NOT the mnemonic provided by goal account export or by algokey). Regenerate accounts in the wallet with goal account new
      --unencrypted                Create a new wallet without a password.

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
"#
        }
        "wallet rename" => {
            r#"Usage:
  goal wallet rename [wallet name] [new wallet name] [flags]

Flags:
  -h, --help   help for rename

Global Flags:
  -d, --datadir stringArray   Data directory for the node
  -k, --kmddir string         Data directory for kmd
"#
        }
        _ => return None,
    })
}

/// go's text above the usage in `goal <path> --help`: the command's `Long`,
/// or its `Short` when it has none (cobra's help template trims its
/// trailing whitespace). Captured from go's `goal <path> --help`.
fn long(path: &str) -> Option<&'static str> {
    Some(match path {
        "account" => {
            r#"Collection of commands to support the creation and management of accounts / wallets tied to a specific Algorand node instance."#
        }
        "account addpartkey" => {
            r#"Generate and install participation key for the specified account. This participation key can then be used for going online and participating in consensus."#
        }
        "account applicationdetails" => {
            r#"Retrieve information about the applications created or opted-into by the specified account, possibly including application metadata"#
        }
        "account assetdetails" => {
            r#"Retrieve information about the assets the specified account has created or opted into, inclusive of asset metadata."#
        }
        "account balance" => {
            r#"Retrieve the balance record for the specified account. Algo balance is displayed in microAlgos."#
        }
        "account changeonlinestatus" => {
            r#"Change online status for the specified account. Set online should be 1 to set online, 0 to set offline. The broadcast transaction will be valid for a limited number of rounds. goal will provide the TXID of the transaction if successful. Going online requires that the given account has a valid participation key. If the participation key is specified using --partkeyfile, you must separately install the participation key from that file using "goal account installpartkey"."#
        }
        "account delete" => {
            r#"Delete the indicated account. The key management daemon will no longer know about this account, although the account will still exist on the network."#
        }
        "account deletepartkey" => r#"Delete the indicated participation key."#,
        "account dump" => {
            r#"Dump the balance record for the specified account to terminal as JSON or to a file as MessagePack."#
        }
        "account export" => {
            r#"Export an account mnemonic seed, for use with account import. This exports the seed for a single account and should NOT be confused with the wallet mnemonic."#
        }
        "account import" => {
            r#"Import an account key from a mnemonic generated by the export command or by algokey (NOT a mnemonic from the goal wallet command). The imported account will be listed alongside your wallet-generated accounts, but will not be tied to your wallet."#
        }
        "account importrootkey" => {
            r#"Import .rootkey files from the data directory into a kmd wallet. This is analogous to using the import command with an account seed mnemonic: the imported account will be displayed alongside your wallet-derived accounts, but will not be tied to your wallet mnemonic."#
        }
        "account info" => {
            r#"Retrieve information about the assets and applications the specified account has created or opted into."#
        }
        "account installpartkey" => {
            r#"Install a participation key from a partkey file. Intended for use with participation key files generated by "algokey part generate". Does not change the online status of an account or register the participation key; use "goal account changeonlinestatus" for doing so. Deletes input key file on successful install to ensure forward security."#
        }
        "account list" => {
            r#"Show the list of Algorand accounts on this machine. Indicates whether the account is [offline] or [online], and if the account is the default account for goal. Also displays account information with --info."#
        }
        "account listpartkeys" => {
            r#"List all participation keys tracked by algod along with summary of additional information. For detailed key information use 'partkeyinfo'."#
        }
        "account marknonparticipating" => {
            r#"Permanently mark an account as not participating (as opposed to Online or Offline). Once marked, the account can never go online or offline, it is forever nonparticipating, and it will never earn rewards on its balance."#
        }
        "account multisig" => r#"Control and manage multisig accounts"#,
        "account multisig delete" => {
            r#"Delete a multisig account. Like ordinary account delete, the local node will no longer know about the account, but it may still exist on the network."#
        }
        "account multisig info" => {
            r#"Print information about a multisig account, such as its Algorand multisig version, or the number of keys needed to validate a transaction from the multisig account."#
        }
        "account multisig new" => {
            r#"Create a new multisig account from a list of existing non-multisig addresses"#
        }
        "account new" => {
            r#"Coordinates the creation of a new account with KMD. The name specified here is stored in a local configuration file and is only used by goal when working against that specific node instance."#
        }
        "account partkeyinfo" => {
            r#"Output details about all available part keys in the specified data directory(ies), such as key validity period."#
        }
        "account rename" => {
            r#"Change the human-friendly name of an account. This is a local-only name, it is not stored on the network."#
        }
        "account renewallpartkeys" => {
            r#"Generate new participation keys for all existing accounts with participation keys and issue the necessary transactions to register them."#
        }
        "account renewpartkey" => {
            r#"Generate a participation key for the specified account and issue the necessary transaction to register it."#
        }
        "account rewards" => {
            r#"Retrieve the rewards for the specified account, including pending rewards. Units displayed are microAlgos."#
        }
        "wallet" => r#"Manage wallets: encrypted collections of Algorand account keys"#,
        "wallet list" => r#"List wallets managed by kmd"#,
        "wallet new" => r#"Create a new wallet"#,
        "wallet rename" => r#"Rename wallet"#,
        _ => return None,
    })
}

/// go's `goal <path> --help` (cobra's help template: the `Long` text, a
/// blank line and the usage), printed on stdout.
pub(crate) fn help(path: &str) -> Option<String> {
    Some(format!(
        "{}

{}",
        long(path)?,
        usage(path)?
    ))
}
