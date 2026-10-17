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

//! Genesis and wallet generation: port of `gen/generate.go`
//! (`GenerateGenesisFiles`). For every wallet of a [`GenesisData`] it creates
//! (or reuses) a `<Name>.rootkey` account file and, for online wallets, a
//! `<Name>.<first>.<last>.partkey` participation file, then writes the
//! `genesis.json` that allocates the stake to those accounts.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::{fill_db_with_participation_keys, restore::restore_participation};
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_CURRENT_VERSION};
use algo_types::{Address, ConsensusParams, Round};
use rand::TryRng;
use serde_json::{json, Map, Value};

use crate::template::GenesisData;

/// go: `gen.TotalMoney` = 10 * 1e9 * 1e6 microAlgos.
pub const TOTAL_MONEY: u64 = 10_000_000_000_000_000;
/// go: `gen.schemaID`.
pub const SCHEMA_ID: &str = "v1";

/// go: `defaultSinkAddr`.
pub const DEFAULT_SINK_ADDR: [u8; 32] = [
    0x07, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6,
    0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x09, 0xa3, 0x96, 0xb8, 0x2e,
    0xa2, 0x21,
];
/// go: `defaultPoolAddr` (all 0xff).
pub const DEFAULT_POOL_ADDR: [u8; 32] = [0xff; 32];

/// go: `genesisAllocation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub name: String,
    pub stake: u64,
    pub online: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum GenError {
    #[error("{0}")]
    Msg(String),
}

fn err<T>(m: impl Into<String>) -> Result<T, GenError> {
    Err(GenError::Msg(m.into()))
}

/// go: `config.RootKeyFilename`.
pub fn root_key_filename(wallet: &str) -> String {
    format!("{wallet}.rootkey")
}

/// go: `config.PartKeyFilename`.
pub fn part_key_filename(wallet: &str, first: u64, last: u64) -> String {
    format!("{wallet}.{first}.{last}.partkey")
}

/// go: `setupGenerateGenesisFiles` -- the protocol version, its parameters and
/// the per-wallet stake. Stakes are `TotalMoney/100 * percent`, rounded, with
/// go's round-off fixup so they add up to exactly `TotalMoney`.
pub fn setup_allocations(
    genesis: &GenesisData,
) -> Result<(String, ConsensusParams, Vec<Allocation>), GenError> {
    let proto = if genesis.consensus_protocol.is_empty() {
        CONSENSUS_CURRENT_VERSION.to_string()
    } else {
        genesis.consensus_protocol.clone()
    };
    let Some(params) = consensus_params_for_version(&proto) else {
        return err(format!("protocol {proto} not supported"));
    };

    let mut allocation: Vec<Allocation> = genesis
        .wallets
        .iter()
        .map(|w| Allocation {
            name: w.name.clone(),
            stake: (((TOTAL_MONEY / 100) as f64) * w.stake + 0.5) as u64,
            online: w.online,
        })
        .collect();

    let sum: u64 = allocation.iter().map(|a| a.stake).sum();
    if sum != TOTAL_MONEY {
        let fsum = sum as f64;
        let ftot = TOTAL_MONEY as f64;
        if ((fsum - ftot) / ftot).abs() < 0.01 && sum.abs_diff(TOTAL_MONEY) < 10_000 {
            // wallet stake is a float and round-off might happen but we are
            // close enough to do a fixup
            fixup_round_off(&mut allocation, params.min_balance, TOTAL_MONEY)?;
        } else {
            return err(format!(
                "Amounts don't add up to TotalMoney - off by {}",
                TOTAL_MONEY as i128 - sum as i128
            ));
        }
    }
    Ok((proto, params, allocation))
}

/// go's round-off fixup: nudge stakes one microAlgo at a time until they add up
/// to `target`. go loops until the sum matches, which never happens when every
/// wallet already sits at the minimum balance; this one is bounded.
fn fixup_round_off(
    allocation: &mut [Allocation],
    min_balance: u64,
    target: u64,
) -> Result<(), GenError> {
    let mut sum: u64 = allocation.iter().map(|a| a.stake).sum();
    let max_steps = (sum.abs_diff(target) + 1) * allocation.len() as u64 + 16;
    let mut steps = 0u64;
    let mut i = 0;
    while sum != target {
        if steps > max_steps {
            return err(format!(
                "Amounts don't add up to TotalMoney - off by {}",
                target as i128 - sum as i128
            ));
        }
        steps += 1;
        if sum < target {
            allocation[i].stake += 1;
            sum += 1;
        } else if allocation[i].stake > min_balance {
            allocation[i].stake -= 1;
            sum -= 1;
        }
        i = (i + 1) % allocation.len();
    }
    Ok(())
}

/// The keys of one generated wallet.
#[derive(Debug, Clone)]
struct WalletKeys {
    address: [u8; 32],
    /// `(vote id, selection id, state proof id, first, last, dilution)`
    participation: Option<PartInfo>,
}

#[derive(Debug, Clone)]
struct PartInfo {
    vote_id: [u8; 32],
    selection_id: [u8; 32],
    state_proof_id: Option<[u8; 64]>,
    first_valid: u64,
    last_valid: u64,
    key_dilution: u64,
}

/// What [`generate_genesis_files`] produced.
#[derive(Debug)]
pub struct Generated {
    /// Wallet name -> account address (including `FeeSink` and `RewardsPool`).
    pub addresses: BTreeMap<String, [u8; 32]>,
    pub genesis_path: PathBuf,
    pub root_keys_created: usize,
    pub part_keys_created: usize,
}

fn random_seed() -> Result<[u8; 32], GenError> {
    let mut seed = [0u8; 32];
    rand::rngs::SysRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| GenError::Msg(format!("system entropy: {e}")))?;
    Ok(seed)
}

/// go: `account.GenerateRoot` / `ImportRoot` -- an ed25519 account stored in a
/// sqlite file as `RootAccount(data)`, `data` being the msgpack
/// `SignatureSecrets` (`SK`, `SignatureVerifier`).
pub fn write_root_key(path: &Path, seed: &[u8; 32]) -> Result<[u8; 32], GenError> {
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    let pk = signing.verifying_key().to_bytes();
    let mut sk = Vec::with_capacity(64);
    sk.extend_from_slice(seed);
    sk.extend_from_slice(&pk);
    let blob = {
        let value = rmpv::Value::Map(vec![
            (rmpv::Value::from("SK"), rmpv::Value::Binary(sk)),
            (
                rmpv::Value::from("SignatureVerifier"),
                rmpv::Value::Binary(pk.to_vec()),
            ),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &value)
            .map_err(|e| GenError::Msg(format!("encoding the root key: {e}")))?;
        buf
    };
    let _ = std::fs::remove_file(path);
    let conn = rusqlite::Connection::open(path)
        .map_err(|e| GenError::Msg(format!("couldn't open root DB accessor {}: {e}", path.display())))?;
    conn.execute_batch("create table RootAccount (\n       data blob --*  msgpack encoding of RootAccount.secrets\n);")
        .map_err(|e| GenError::Msg(format!("ImportRoot: failed to install database: {e}")))?;
    conn.execute("insert into RootAccount values (?)", [&blob])
        .map_err(|e| GenError::Msg(format!("ImportRoot: failed to insert account: {e}")))?;
    Ok(pk)
}

/// go: `loadRootKey` -- the account address of an existing root key file.
pub fn read_root_key_address(path: &Path) -> Result<[u8; 32], GenError> {
    let conn = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| GenError::Msg(format!("couldn't load existing root file {}: {e}", path.display())))?;
    let blob: Vec<u8> = conn
        .query_row("SELECT data FROM RootAccount", [], |row| row.get(0))
        .map_err(|e| GenError::Msg(format!("could not restore existing root file {}: {e}", path.display())))?;
    let mut rd: &[u8] = &blob;
    let value = rmpv::decode::read_value(&mut rd)
        .map_err(|e| GenError::Msg(format!("could not restore existing root file {}: {e}", path.display())))?;
    let map = value
        .as_map()
        .ok_or_else(|| GenError::Msg(format!("could not restore existing root file {}", path.display())))?;
    for (k, v) in map {
        if k.as_str() == Some("SignatureVerifier") {
            if let Some(bytes) = v.as_slice() {
                if let Ok(pk) = <[u8; 32]>::try_from(bytes) {
                    return Ok(pk);
                }
            }
        }
    }
    err(format!(
        "could not restore existing root file {}: no SignatureVerifier",
        path.display()
    ))
}

fn part_info_of(part: &algo_ledger::participation::Participation) -> PartInfo {
    PartInfo {
        vote_id: part.voting.verifier(),
        selection_id: part.vrf.pk.0,
        state_proof_id: part
            .state_proof_secrets
            .as_ref()
            .map(|s| s.get_verifier().commitment),
        first_valid: part.first_valid.0,
        last_valid: part.last_valid.0,
        key_dilution: part.key_dilution,
    }
}

/// One wallet: reuse an existing key pair or generate it (go's `createWallet`
/// loop body).
fn make_wallet(
    out_dir: &Path,
    alloc: &Allocation,
    first: u64,
    last: u64,
    dilution: u64,
    counters: &(std::sync::atomic::AtomicUsize, std::sync::atomic::AtomicUsize),
    log: &std::sync::Mutex<&mut (dyn Write + Send)>,
) -> Result<WalletKeys, GenError> {
    use std::sync::atomic::Ordering;
    let say = |m: String| {
        if let Ok(mut w) = log.lock() {
            let _ = writeln!(w, "{m}");
        }
    };
    let root_path = out_dir.join(root_key_filename(&alloc.name));
    let part_path = out_dir.join(part_key_filename(&alloc.name, first, last));

    let address = if root_path.exists() {
        read_root_key_address(&root_path)?
    } else {
        let pk = write_root_key(&root_path, &random_seed()?)?;
        say(format!("Created new rootkey: {}", root_path.display()));
        counters.0.fetch_add(1, Ordering::Relaxed);
        pk
    };

    let mut participation = None;
    if alloc.online {
        let reused = if part_path.exists() {
            ErasableDb::open(&part_path)
                .ok()
                .and_then(|db| restore_participation(&db).ok())
        } else {
            None
        };
        let part = match reused {
            Some(p) if p.parent.0 != address => {
                return err(format!(
                    "participation file {} belongs to a different account than {}",
                    part_path.display(),
                    root_path.display()
                ));
            }
            Some(p) => {
                say(format!(
                    "Reusing existing wallet: {} {}",
                    root_path.display(),
                    part_path.display()
                ));
                p
            }
            None => {
                let _ = std::fs::remove_file(&part_path);
                let mut db = ErasableDb::open(&part_path).map_err(|e| {
                    GenError::Msg(format!(
                        "couldn't open participation DB accessor {}: {e}",
                        part_path.display()
                    ))
                })?;
                say(format!(
                    "Generating {}'s keys for a period of {} rounds",
                    alloc.name,
                    last.saturating_sub(first)
                ));
                let p = fill_db_with_participation_keys(
                    &mut db,
                    Address(address),
                    Round(first),
                    Round(last),
                    dilution,
                )
                .map_err(|e| {
                    let _ = std::fs::remove_file(&part_path);
                    GenError::Msg(format!(
                        "could not generate new participation file {}: {e}",
                        part_path.display()
                    ))
                })?;
                say(format!(
                    "participation key generation for {} completed successfully",
                    alloc.name
                ));
                counters.1.fetch_add(1, Ordering::Relaxed);
                p
            }
        };
        participation = Some(part_info_of(&part));
    }
    Ok(WalletKeys {
        address,
        participation,
    })
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn parse_address(text: &str, default: [u8; 32]) -> Result<[u8; 32], GenError> {
    if text.is_empty() {
        return Ok(default);
    }
    let addr = text
        .parse::<Address>()
        .map_err(|e| GenError::Msg(format!("invalid address {text}: {e}")))?;
    // go: the zero address means "unset"
    Ok(if addr.0 == [0u8; 32] { default } else { addr.0 })
}

/// go: `GenerateGenesisFiles`.
pub fn generate_genesis_files(
    genesis: &GenesisData,
    out_dir: &Path,
    log: &mut (dyn Write + Send),
) -> Result<Generated, GenError> {
    let (proto, params, mut allocation) = setup_allocations(genesis)?;
    std::fs::create_dir_all(out_dir)
        .map_err(|e| GenError::Msg(format!("couldn't make output directory '{}': {e}", out_dir.display())))?;

    let fee_sink = parse_address(&genesis.fee_sink, DEFAULT_SINK_ADDR)?;
    let rewards_pool = parse_address(&genesis.rewards_pool, DEFAULT_POOL_ADDR)?;
    let first = genesis.first_part_key_round;
    let last = genesis.last_part_key_round;
    let dilution = if genesis.part_key_dilution == 0 {
        params.default_key_dilution
    } else {
        genesis.part_key_dilution
    };

    // go: sort account names alphabetically
    allocation.sort_by(|a, b| a.name.cmp(&b.name));

    let counters = (
        std::sync::atomic::AtomicUsize::new(0),
        std::sync::atomic::AtomicUsize::new(0),
    );
    let log = std::sync::Mutex::new(log);
    let results: Vec<Result<WalletKeys, GenError>> = {
        let workers = std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(2)
            * 2;
        let next = std::sync::atomic::AtomicUsize::new(0);
        let slots: Vec<std::sync::Mutex<Option<Result<WalletKeys, GenError>>>> =
            allocation.iter().map(|_| std::sync::Mutex::new(None)).collect();
        std::thread::scope(|scope| {
            for _ in 0..workers.min(allocation.len().max(1)) {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(alloc) = allocation.get(i) else { return };
                    let r = make_wallet(out_dir, alloc, first, last, dilution, &counters, &log);
                    *slots[i].lock().expect("slot") = Some(r);
                });
            }
        });
        slots
            .into_iter()
            .map(|s| s.into_inner().expect("slot").expect("every wallet processed"))
            .collect()
    };
    let mut wallets = Vec::with_capacity(results.len());
    for r in results {
        wallets.push(r?);
    }

    // go: records + genesisAddrs, then FeeSink / RewardsPool
    let mut addresses: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    let mut alloc_json: Vec<Value> = Vec::new();

    let rewards_balance = genesis.rewards_pool_balance.max(params.min_balance);
    // go: alloc2 = [RewardsPool, FeeSink, wallets...]
    alloc_json.push(json!({
        "addr": Address(rewards_pool).to_algorand_string(),
        "comment": "RewardsPool",
        "state": {"algo": rewards_balance, "onl": 2},
    }));
    alloc_json.push(json!({
        "addr": Address(fee_sink).to_algorand_string(),
        "comment": "FeeSink",
        "state": {"algo": params.min_balance, "onl": 2},
    }));
    addresses.insert("RewardsPool".to_string(), rewards_pool);
    addresses.insert("FeeSink".to_string(), fee_sink);

    for (alloc, keys) in allocation.iter().zip(&wallets) {
        let mut state = Map::new();
        state.insert("algo".into(), json!(alloc.stake));
        if alloc.online {
            state.insert("onl".into(), json!(1));
            if let Some(p) = &keys.participation {
                state.insert("vote".into(), json!(b64(&p.vote_id)));
                state.insert("sel".into(), json!(b64(&p.selection_id)));
                state.insert("voteKD".into(), json!(p.key_dilution));
                if p.first_valid != 0 {
                    state.insert("voteFst".into(), json!(p.first_valid));
                }
                state.insert("voteLst".into(), json!(p.last_valid));
                if params.enable_state_proof_keyreg_check {
                    if let Some(sp) = &p.state_proof_id {
                        state.insert("stprf".into(), json!(b64(sp)));
                    }
                }
            }
        }
        alloc_json.push(json!({
            "addr": Address(keys.address).to_algorand_string(),
            "comment": alloc.name,
            "state": Value::Object(state),
        }));
        addresses.insert(alloc.name.clone(), keys.address);
    }

    let mut g = Map::new();
    g.insert("alloc".into(), Value::Array(alloc_json));
    if !genesis.comment.is_empty() {
        g.insert("comment".into(), json!(genesis.comment));
    }
    if genesis.dev_mode {
        g.insert("devmode".into(), json!(true));
    }
    g.insert("fees".into(), json!(Address(fee_sink).to_algorand_string()));
    g.insert(
        "id".into(),
        json!(format!("{SCHEMA_ID}{}", genesis.version_modifier)),
    );
    g.insert("network".into(), json!(genesis.network_name));
    g.insert("proto".into(), json!(proto));
    g.insert("rwd".into(), json!(Address(rewards_pool).to_algorand_string()));
    g.insert("timestamp".into(), json!(0));

    let genesis_path = out_dir.join("genesis.json");
    let mut text = serde_json::to_string_pretty(&Value::Object(g))
        .map_err(|e| GenError::Msg(e.to_string()))?;
    text.push('\n');
    std::fs::write(&genesis_path, text)
        .map_err(|e| GenError::Msg(format!("writing {}: {e}", genesis_path.display())))?;

    Ok(Generated {
        addresses,
        genesis_path,
        root_keys_created: counters.0.load(std::sync::atomic::Ordering::Relaxed),
        part_keys_created: counters.1.load(std::sync::atomic::Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{NetworkTemplate, WalletData};

    fn genesis_with(wallets: &[(&str, f64, bool)]) -> GenesisData {
        GenesisData {
            network_name: "unit".into(),
            first_part_key_round: 0,
            last_part_key_round: 100,
            rewards_pool_balance: 0,
            wallets: wallets
                .iter()
                .map(|(n, s, o)| WalletData {
                    name: (*n).into(),
                    stake: *s,
                    online: *o,
                })
                .collect(),
            ..GenesisData::default()
        }
    }

    #[test]
    fn stakes_add_up_to_total_money_with_gos_round_off_fixup() {
        let g = genesis_with(&[("A", 40.0, true), ("B", 40.0, true), ("C", 20.0, false)]);
        let (proto, _, allocs) = setup_allocations(&g).unwrap();
        assert_eq!(proto, CONSENSUS_CURRENT_VERSION);
        assert_eq!(allocs.iter().map(|a| a.stake).sum::<u64>(), TOTAL_MONEY);
        assert_eq!(allocs[0].stake, 4_000_000_000_000_000);
        assert_eq!(allocs[2].stake, 2_000_000_000_000_000);

        // thirds do not divide evenly: the fixup tops the sum up to the dust
        let g = genesis_with(&[
            ("A", 33.333333, true),
            ("B", 33.333333, true),
            ("C", 33.333334, true),
        ]);
        let (_, _, allocs) = setup_allocations(&g).unwrap();
        assert_eq!(allocs.iter().map(|a| a.stake).sum::<u64>(), TOTAL_MONEY);
    }

    #[test]
    fn a_far_off_total_is_an_error_and_an_unknown_protocol_too() {
        let g = genesis_with(&[("A", 50.0, true)]);
        assert!(setup_allocations(&g)
            .unwrap_err()
            .to_string()
            .starts_with("Amounts don't add up to TotalMoney - off by "));
        let mut g = genesis_with(&[("A", 100.0, true)]);
        g.consensus_protocol = "nonsense-v0".into();
        assert_eq!(
            setup_allocations(&g).unwrap_err().to_string(),
            "protocol nonsense-v0 not supported"
        );
    }

    #[test]
    fn go_file_names() {
        assert_eq!(root_key_filename("Wallet1"), "Wallet1.rootkey");
        assert_eq!(part_key_filename("Wallet1", 0, 30000), "Wallet1.0.30000.partkey");
    }

    #[test]
    fn root_keys_round_trip_and_match_the_stored_address() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("W.rootkey");
        let seed = [7u8; 32];
        let pk = write_root_key(&path, &seed).unwrap();
        assert_eq!(read_root_key_address(&path).unwrap(), pk);
        // writing again replaces the file (go removes the old one)
        let pk2 = write_root_key(&path, &[9u8; 32]).unwrap();
        assert_ne!(pk, pk2);
        assert_eq!(read_root_key_address(&path).unwrap(), pk2);
    }

    #[test]
    fn genesis_keys_are_standard_padded_base64() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn the_round_off_fixup_adds_and_removes_single_microalgos_and_is_bounded() {
        let mk = |stakes: &[u64]| -> Vec<Allocation> {
            stakes
                .iter()
                .enumerate()
                .map(|(i, s)| Allocation { name: format!("W{i}"), stake: *s, online: false })
                .collect()
        };
        // short by 2: first two wallets get +1
        let mut a = mk(&[10, 10, 10]);
        fixup_round_off(&mut a, 1, 32).unwrap();
        assert_eq!(a.iter().map(|x| x.stake).collect::<Vec<_>>(), vec![11, 11, 10]);
        // over by 2: removed from wallets above the minimum
        let mut a = mk(&[10, 10, 10]);
        fixup_round_off(&mut a, 1, 28).unwrap();
        assert_eq!(a.iter().map(|x| x.stake).sum::<u64>(), 28);
        // over, but every wallet is at the minimum: go spins forever, this errors
        let mut a = mk(&[5, 5]);
        let e = fixup_round_off(&mut a, 5, 8).unwrap_err();
        assert!(e.to_string().starts_with("Amounts don't add up to TotalMoney - off by "), "{e}");
    }

    #[test]
    fn a_reused_partkey_of_another_account_is_refused() {
        let mut genesis = genesis_with(&[("A", 50.0, true), ("B", 50.0, true)]);
        genesis.last_part_key_round = 30;
        let tmp = tempfile::tempdir().unwrap();
        let mut log: Vec<u8> = Vec::new();
        generate_genesis_files(&genesis, tmp.path(), &mut log).unwrap();
        // swap B's partkey in as A's
        std::fs::copy(tmp.path().join("B.0.30.partkey"), tmp.path().join("A.0.30.partkey")).unwrap();
        let e = generate_genesis_files(&genesis, tmp.path(), &mut log).unwrap_err();
        assert!(e.to_string().contains("belongs to a different account"), "{e}");
    }

    #[test]
    fn default_addresses_are_used_for_empty_and_zero() {
        assert_eq!(parse_address("", DEFAULT_SINK_ADDR).unwrap(), DEFAULT_SINK_ADDR);
        let zero = Address([0u8; 32]).to_algorand_string();
        assert_eq!(parse_address(&zero, DEFAULT_POOL_ADDR).unwrap(), DEFAULT_POOL_ADDR);
        let other = Address([5u8; 32]).to_algorand_string();
        assert_eq!(parse_address(&other, DEFAULT_POOL_ADDR).unwrap(), [5u8; 32]);
        assert!(parse_address("not an address", DEFAULT_POOL_ADDR).is_err());
    }

    #[test]
    fn the_default_template_generates_a_loadable_genesis_with_keys() {
        let tpl = NetworkTemplate::from_json(include_str!("default_template.json")).unwrap();
        let mut genesis = tpl.genesis.clone();
        genesis.network_name = "unitnet".into();
        genesis.last_part_key_round = 50; // keep key generation quick
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("net");
        let mut log: Vec<u8> = Vec::new();
        let gen = generate_genesis_files(&genesis, &out, &mut log).unwrap();
        assert_eq!(gen.root_keys_created, 3);
        assert_eq!(gen.part_keys_created, 2, "only the two online wallets get partkeys");
        for w in ["Wallet1", "Wallet2", "Wallet3"] {
            assert!(out.join(root_key_filename(w)).is_file(), "{w} rootkey");
        }
        assert!(out.join("Wallet1.0.50.partkey").is_file());
        assert!(out.join("Wallet2.0.50.partkey").is_file());
        assert!(!out.join("Wallet3.0.50.partkey").exists());

        let text = std::fs::read_to_string(&gen.genesis_path).unwrap();
        let parsed = algo_ledger::genesis::parse_genesis_json(&text).expect("the node can parse it");
        assert_eq!(parsed.network, "unitnet");
        assert_eq!(parsed.id, "v1");
        assert_eq!(parsed.alloc.len(), 5, "pool, sink, three wallets");
        let total: u64 = parsed.alloc.iter().map(|a| a.state.algo).sum();
        // the pool holds the minimum balance (RewardsPoolBalance 0) and the sink too
        let params = consensus_params_for_version(CONSENSUS_CURRENT_VERSION).unwrap();
        assert_eq!(total, TOTAL_MONEY + 2 * params.min_balance);
        let online: Vec<_> = parsed.alloc.iter().filter(|a| a.state.onl == Some(1)).collect();
        assert_eq!(online.len(), 2);
        for a in online {
            assert!(a.state.vote.is_some() && a.state.sel.is_some());
            assert_eq!(a.state.vote_lst, Some(50));
        }
        assert_eq!(gen.addresses["Wallet1"].len(), 32);
        assert!(String::from_utf8_lossy(&log).contains("Created new rootkey"));
    }

    #[test]
    fn existing_wallets_are_reused_on_a_second_run() {
        let mut genesis = genesis_with(&[("A", 100.0, true)]);
        genesis.last_part_key_round = 30;
        let tmp = tempfile::tempdir().unwrap();
        let mut log: Vec<u8> = Vec::new();
        let first = generate_genesis_files(&genesis, tmp.path(), &mut log).unwrap();
        let second = generate_genesis_files(&genesis, tmp.path(), &mut log).unwrap();
        assert_eq!(second.root_keys_created, 0);
        assert_eq!(second.part_keys_created, 0);
        assert_eq!(first.addresses["A"], second.addresses["A"]);
        assert!(String::from_utf8_lossy(&log).contains("Reusing existing wallet"));
    }
}
