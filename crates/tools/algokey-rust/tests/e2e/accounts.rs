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

//! Funded-account discovery and funding helpers (TASK-184).
//!
//! Algod's REST API exposes account *addresses* and *balances*, but the
//! genesis-funded accounts' secret keys live only inside the algod-go
//! container's wallet database. We extract them by shelling out to
//! `docker exec algod-go goal account export`, then decoding the
//! 25-word mnemonic back to a 32-byte seed via
//! [`algo_consensus_crypto::mnemonic_to_key`].

use std::process::Command;

use algo_codec::canonical_encode_transaction;
use algo_consensus_crypto::mnemonic_to_key;
use algo_error::{AlgoError, Result};
use algo_rest_client::TxId;
use algo_types::{Address, Round, SignedTransaction, Transaction, TxnType};
use ed25519_dalek::{Signer, SigningKey};

use super::localnet::{Localnet, ALGOD_CONTAINER};

/// Domain separator prepended to canonical transaction bytes before signing.
/// Matches `protocol.HashID("TX")` (see `crates/tools/algokey-rust/src/commands/sign.rs`).
const TX_PREFIX: &[u8] = b"TX";

/// A genesis-funded account with the secret seed populated so the harness
/// can sign on its behalf.
#[derive(Debug, Clone)]
pub struct FundedAccount {
    pub address: Address,
    pub mnemonic: String,
    pub seed: [u8; 32],
    /// Balance in microAlgos at the time of discovery (informational —
    /// not refreshed automatically).
    pub balance: u64,
}

impl FundedAccount {
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

/// Discover the genesis-funded account with the highest balance.
///
/// Strategy (mirrors `Makefile generate-txns`):
/// 1. `docker exec algod-go goal account list -d /algod/data` — parse
///    the address column.
/// 2. For each candidate, `AlgodClient::get_account` confirms the balance.
/// 3. Pick the address with the largest balance.
/// 4. `docker exec algod-go goal account export -d /algod/data --address <addr>`
///    extracts the 25-word mnemonic.
/// 5. `mnemonic_to_key` decodes to a 32-byte seed.
pub async fn discover_faucet(net: &Localnet) -> Result<FundedAccount> {
    let listing = run_goal(&["account", "list", "-d", "/algod/data"])?;
    let addresses = parse_account_addresses(&listing);
    if addresses.is_empty() {
        return Err(AlgoError::Network {
            message: format!(
                "no accounts discovered via `goal account list`; raw output:\n{listing}"
            ),
        });
    }

    let mut best: Option<(Address, String, u64)> = None;
    for addr_str in addresses {
        let address = Address::from_algorand_string(&addr_str).map_err(|e| AlgoError::Network {
            message: format!("unparseable address {addr_str} from goal: {e}"),
        })?;
        let info = net.client().get_account(&address).await?;
        if best.as_ref().map_or(true, |(_, _, b)| info.amount > *b) {
            best = Some((address, addr_str, info.amount));
        }
    }

    let (address, addr_str, balance) = best.expect("addresses was non-empty");

    let export = run_goal(&[
        "account",
        "export",
        "-d",
        "/algod/data",
        "--address",
        &addr_str,
    ])?;
    let mnemonic = parse_mnemonic(&export).ok_or_else(|| AlgoError::Network {
        message: format!("could not parse mnemonic from `goal account export`:\n{export}"),
    })?;

    let seed = mnemonic_to_key(&mnemonic).map_err(|e| AlgoError::Network {
        message: format!("mnemonic_to_key failed for faucet account: {e}"),
    })?;

    // Sanity check: the seed must reproduce the address.
    let pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    if pk != address.0 {
        return Err(AlgoError::Network {
            message: format!(
                "discovered seed does not match address {addr_str}: derived={} expected={}",
                hex::encode(pk),
                hex::encode(address.0),
            ),
        });
    }

    Ok(FundedAccount {
        address,
        mnemonic,
        seed,
        balance,
    })
}

/// Build, sign, and submit a payment transaction from `faucet` to `target`
/// for `amount` microAlgos. Returns the txid algod assigned. Caller is
/// expected to wait for confirmation via
/// [`super::submission::wait_for_confirmation`].
pub async fn fund_address(
    net: &Localnet,
    faucet: &FundedAccount,
    target: Address,
    amount: u64,
) -> Result<TxId> {
    let params = net.client().suggested_transaction_params().await?;

    let fee = params.fee.max(params.min_fee);
    let first_valid = Round(params.last_round);
    let last_valid = Round(params.last_round + 1000);

    let txn = Transaction {
        txn_type: TxnType::Pay,
        sender: faucet.address,
        fee,
        first_valid,
        last_valid,
        genesis_hash: params.genesis_hash.0,
        genesis_id: params.genesis_id.clone(),
        receiver: target,
        amount,
        ..Transaction::default()
    };

    let signed = sign(txn, &faucet.signing_key());
    let encoded = algo_codec::canonical_encode_signed_transaction(&signed);
    net.client().send_raw_transaction(&encoded).await
}

/// Sign a `Transaction` and return a `SignedTransaction` with the ed25519
/// signature populated. The sender is also the signer (no rekey).
pub fn sign(txn: Transaction, key: &SigningKey) -> SignedTransaction {
    let canonical = canonical_encode_transaction(&txn);
    let mut msg = Vec::with_capacity(TX_PREFIX.len() + canonical.len());
    msg.extend_from_slice(TX_PREFIX);
    msg.extend_from_slice(&canonical);
    let sig = key.sign(&msg).to_bytes();
    SignedTransaction {
        txn,
        sig,
        ..SignedTransaction::default()
    }
}

/// Run `docker exec <ALGOD_CONTAINER> goal <args>` and return stdout as a
/// `String`. Non-zero exits surface as `AlgoError::Network`.
fn run_goal(args: &[&str]) -> Result<String> {
    let output = Command::new("docker")
        .arg("exec")
        .arg(ALGOD_CONTAINER)
        .arg("goal")
        .args(args)
        .output()
        .map_err(|e| AlgoError::Network {
            message: format!("failed to spawn `docker exec goal {}`: {e}", args.join(" ")),
        })?;

    if !output.status.success() {
        return Err(AlgoError::Network {
            message: format!(
                "`docker exec goal {}` exited with {}: stderr={}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse the tab-separated lines produced by `goal account list`.
///
/// Sample line:
///   `[online]\tKNALKO43...\tKNALKO43...\t4000000000000000 microAlgos`
///
/// The second tab-separated column is the address. Lines that don't look
/// like account rows are skipped.
fn parse_account_addresses(stdout: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim_end_matches(['\r']);
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 2 {
            continue;
        }
        // Algorand addresses are 58 chars, A-Z2-7 base32 alphabet. Cheap
        // sanity filter — avoids picking up header rows or "Last Round"
        // metadata if goal's output format ever shifts.
        let candidate = cols[1].trim();
        if candidate.len() == 58 && candidate.chars().all(|c| c.is_ascii_alphanumeric()) {
            out.push(candidate.to_string());
        }
    }
    out
}

/// Parse the mnemonic from `goal account export`.
///
/// Sample output:
///   `Exported key for account KNALKO...: "east mirror buzz ... life"`
///
/// We extract the contents between the first and last double-quote.
fn parse_mnemonic(stdout: &str) -> Option<String> {
    let first = stdout.find('"')?;
    let last = stdout.rfind('"')?;
    if last <= first + 1 {
        return None;
    }
    Some(stdout[first + 1..last].to_string())
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn account_list_parses_tab_separated_rows() {
        let sample = "\
[online]\tKNALKO43XAF6URKGXK35EOS3LELC2S4CUDR3IYQSG7LACUJVV74Z7GZZPE\tKNALKO43XAF6URKGXK35EOS3LELC2S4CUDR3IYQSG7LACUJVV74Z7GZZPE\t4000000000000000 microAlgos
[online]\tN3M6O5BMFZD4AWK3PQXGGHWCESZWZ5MMWGGUOKTC55BY5XEBN2ZB4IXDXU\tN3M6O5BMFZD4AWK3PQXGGHWCESZWZ5MMWGGUOKTC55BY5XEBN2ZB4IXDXU\t2000000000000000 microAlgos
";
        let addrs = parse_account_addresses(sample);
        assert_eq!(addrs.len(), 2);
        assert!(addrs[0].starts_with("KNALKO43"));
        assert!(addrs[1].starts_with("N3M6O5BM"));
    }

    #[test]
    fn account_list_skips_non_address_rows() {
        let sample = "Last committed block: 42\n[online]\tKNALKO43XAF6URKGXK35EOS3LELC2S4CUDR3IYQSG7LACUJVV74Z7GZZPE\tKNALKO43XAF6URKGXK35EOS3LELC2S4CUDR3IYQSG7LACUJVV74Z7GZZPE\t4000\n";
        let addrs = parse_account_addresses(sample);
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn mnemonic_parses_from_export_output() {
        let sample = "Exported key for account KNALKO43XAF6URKGXK35EOS3LELC2S4CUDR3IYQSG7LACUJVV74Z7GZZPE: \"east mirror buzz harbor raccoon carpet hello rack rain top dawn feel pride blast install hurry zoo witness stuff blue leave chicken obey abandon life\"\n";
        let m = parse_mnemonic(sample).expect("should parse");
        assert!(m.starts_with("east mirror"));
        assert!(m.ends_with("abandon life"));
        assert_eq!(m.split_whitespace().count(), 25);
    }

    #[test]
    fn mnemonic_returns_none_on_empty() {
        assert!(parse_mnemonic("no quotes here").is_none());
        assert!(parse_mnemonic("only one \" quote").is_none());
        assert!(parse_mnemonic("\"\"").is_none());
    }
}
