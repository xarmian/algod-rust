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

//! The canonical final state of a corpus replay (issue #2105, epic #2101).
//!
//! Both replay harnesses emit this document after replaying a corpus: the
//! go-algorand one (`benchmarks/go-replay/state.go`) and algod-rust's
//! `algod-rust bench replay-corpus`. The `replay` bench tier fails unless the
//! two are equal and match the corpus's `corpus.json` `final_state`. The line
//! formats here and in `state.go` must stay identical; they are documented in
//! the "The `replay` tier" section of `docs/BENCHMARK_COMPARISON.md`. Every
//! digest is the lowercase hex sha256 of the concatenated lines.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;

use algo_ledger::genesis::GenesisJson;
use algo_ledger::{LedgerStore, SqliteLedger};
use algo_types::{AccountData, AccountStatus, Address, Block, TealValue, TxnType};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512_256};

use crate::corpus::block_hash_string;

/// KV key prefix of app boxes (go `apps.MakeBoxKey`).
pub const BOX_PREFIX: &[u8] = b"bx:";

/// One `AccountTotals` bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgoCountJson {
    pub money: u64,
    pub reward_units: u64,
}

/// The ledger's `AccountTotals` at the final round.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotalsJson {
    pub online: AlgoCountJson,
    pub offline: AlgoCountJson,
    pub not_participating: AlgoCountJson,
    pub rewards_level: u64,
}

/// A digest over a set of lines.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestJson {
    pub count: u64,
    pub microalgos: u64,
    pub sha256: String,
}

/// The canonical final state (`final_state` of a `bench-replay-run/v1`
/// result).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalState {
    pub round: u64,
    pub block_hash: String,
    pub txn_counter: u64,
    /// Online + offline money (REST `/v2/ledger/supply` `total-money`).
    pub total_money: u64,
    pub online_money: u64,
    pub totals: TotalsJson,
    /// `corpus.json`'s account set and digest: `"<address> <amount>\n"`
    /// over the sorted addresses, amount with pending rewards (REST
    /// `amount`).
    pub known_accounts: DigestJson,
    /// Every non-empty account: base record + resources (see
    /// [`account_lines`]).
    pub all_accounts: DigestJson,
    /// Every box: `"<hex key> <hex value>\n"` sorted by key.
    pub kv: DigestJson,
}

/// Rebuilds the account set `corpus.json`'s `accounts_sha256` covers
/// (`benchmarks/go-corpus` `workload.known`): every genesis allocation, every
/// receiver of a top-level payment, and the accounts of the first two apps
/// the corpus creates (its main and callee apps).
#[derive(Debug, Default)]
pub struct KnownSet {
    seen: HashSet<Address>,
    apps: usize,
    addrs: Vec<Address>,
}

impl KnownSet {
    /// Start from the genesis allocations.
    pub fn new(genesis: &GenesisJson) -> Result<Self, String> {
        let mut k = KnownSet::default();
        for a in &genesis.alloc {
            let addr = Address::from_algorand_string(&a.addr)
                .map_err(|e| format!("genesis address {}: {e}", a.addr))?;
            k.add(addr);
        }
        Ok(k)
    }

    fn add(&mut self, a: Address) {
        if self.seen.insert(a) {
            self.addrs.push(a);
        }
    }

    /// Add one block's payment receivers and created setup apps.
    pub fn add_block(&mut self, block: &Block) {
        for st in &block.payset {
            let t = &st.txn;
            match t.txn_type {
                TxnType::Pay => self.add(t.receiver),
                TxnType::Appl if t.application_id == 0 && self.apps < 2 => {
                    self.apps += 1;
                    self.add(Address(algo_ledger::avm_context::app_address(
                        st.apply_data_application_id,
                    )));
                }
                _ => {}
            }
        }
    }

    /// The collected addresses (insertion order).
    pub fn addresses(&self) -> &[Address] {
        &self.addrs
    }
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// The checksummed address, `-` for the zero / absent address.
fn addr_str(a: Option<&Address>) -> String {
    match a {
        Some(a) if !a.is_zero() => a.to_string(),
        _ => "-".to_string(),
    }
}

fn b01(b: bool) -> u8 {
    u8::from(b)
}

/// A TEAL key/value map as `<hex key>:u<uint>` / `<hex key>:b<hex bytes>`
/// entries sorted by key bytes, joined with `,` (go `state.go` `tkv`).
fn tkv(kv: &BTreeMap<Vec<u8>, TealValue>) -> String {
    kv.iter()
        .map(|(k, v)| match v {
            TealValue::Uint(u) => format!("{}:u{u}", hex::encode(k)),
            TealValue::Bytes(b) => format!("{}:b{}", hex::encode(k), hex::encode(b)),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn status_byte(s: AccountStatus) -> u8 {
    match s {
        AccountStatus::Offline => 0,
        AccountStatus::Online => 1,
        AccountStatus::NotParticipating => 2,
    }
}

/// Whether the stored record is go's zero `ledgercore.AccountData` (a
/// deleted account), which the digest leaves out.
fn is_empty_account(a: &AccountData) -> bool {
    a.micro_algos == 0
        && a.rewards_base == 0
        && a.rewarded_micro_algos == 0
        && a.status == AccountStatus::Offline
        && a.vote_id.is_none_or(|k| k == [0u8; 32])
        && a.selection_id.is_none_or(|k| k == [0u8; 32])
        && a.state_proof_id.is_none_or(|k| k == [0u8; 64])
        && a.vote_first_valid == 0
        && a.vote_last_valid == 0
        && a.vote_key_dilution == 0
        && a.auth_addr.is_none_or(|x| x.is_zero())
        && a.total_assets_opted_in == 0
        && a.total_created_assets == 0
        && a.total_apps_opted_in == 0
        && a.total_created_apps == 0
        && a.total_extra_app_pages == 0
        && a.total_box_bytes == 0
        && a.total_boxes == 0
        && a.total_app_schema.num_uint == 0
        && a.total_app_schema.num_byte_slice == 0
        && !a.incentive_eligible
        && a.last_proposed == 0
        && a.last_heartbeat == 0
}

/// One account's record in the `all_accounts` digest: the stored base
/// record (no pending rewards) and its resources, by kind then id (go
/// `state.go` `accountLines`). `resource_ids` are the account's resource
/// ids (asset or app; the getters tell which).
pub fn account_lines<L: LedgerStore>(
    store: &L,
    addr: &Address,
    a: &AccountData,
    resource_ids: &[u64],
) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{addr} st={} amt={} rb={} rwd={} auth={} ie={} sch={}/{} xp={} napp={} nls={} nasp={} nas={} bx={} bb={} lp={} lh={} vote={} sel={} sp={} vfv={} vlv={} kd={}",
        status_byte(a.status),
        a.micro_algos,
        a.rewards_base,
        a.rewarded_micro_algos,
        addr_str(a.auth_addr.as_ref()),
        b01(a.incentive_eligible),
        a.total_app_schema.num_uint,
        a.total_app_schema.num_byte_slice,
        a.total_extra_app_pages,
        a.total_created_apps,
        a.total_apps_opted_in,
        a.total_created_assets,
        a.total_assets_opted_in,
        a.total_boxes,
        a.total_box_bytes,
        a.last_proposed,
        a.last_heartbeat,
        hex::encode(a.vote_id.unwrap_or([0u8; 32])),
        hex::encode(a.selection_id.unwrap_or([0u8; 32])),
        hex::encode(a.state_proof_id.unwrap_or([0u8; 64])),
        a.vote_first_valid,
        a.vote_last_valid,
        a.vote_key_dilution,
    );
    let mut ids = resource_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    for &id in &ids {
        if let Some(h) = store.get_asset_holding(addr, id) {
            let _ = writeln!(s, " as {id} {} {}", h.amount, b01(h.frozen));
        }
    }
    for &id in &ids {
        if let Some(rec) = store.get_asset_params(id).filter(|r| r.creator == *addr) {
            let p = &rec.params;
            let _ = writeln!(
                s,
                " asp {id} t={} dc={} df={} un={} an={} url={} mh={} m={} r={} f={} c={}",
                p.total,
                p.decimals,
                b01(p.default_frozen),
                hex::encode(&p.unit_name),
                hex::encode(&p.asset_name),
                hex::encode(&p.url),
                hex::encode(p.metadata_hash.unwrap_or([0u8; 32])),
                addr_str(p.manager.as_ref()),
                addr_str(p.reserve.as_ref()),
                addr_str(p.freeze.as_ref()),
                addr_str(p.clawback.as_ref()),
            );
        }
    }
    for &id in &ids {
        if let Some(ls) = store.get_app_local_state(addr, id) {
            let _ = writeln!(
                s,
                " ls {id} {}/{} {}",
                ls.schema.num_uint,
                ls.schema.num_byte_slice,
                tkv(&ls.key_value)
            );
        }
    }
    for &id in &ids {
        if let Some(p) = store.get_app_params(id).filter(|p| p.creator == *addr) {
            let _ = writeln!(
                s,
                " app {id} ap={} cp={} gs={}/{} lsch={}/{} xp={} v={} ss={} fbr={} fba={} {}",
                sha_hex(&p.approval_program),
                sha_hex(&p.clear_state_program),
                p.global_state_schema.num_uint,
                p.global_state_schema.num_byte_slice,
                p.local_state_schema.num_uint,
                p.local_state_schema.num_byte_slice,
                p.extra_program_pages,
                p.version,
                addr_str(Some(&p.size_sponsor)),
                b01(p.foreign_box_reads),
                b01(p.family_box_access),
                tkv(&p.global_state),
            );
        }
    }
    s
}

/// Compute the canonical final state of `ledger`, enumerating accounts,
/// resources and boxes from its tracker database at `tracker_db` (read
/// through a separate read-only connection; the values come from the
/// ledger's own getters). `known` is the [`KnownSet`] of the replayed
/// rounds. With `dump`, the digested lines are also written to
/// `known_accounts.txt`, `all_accounts.txt` and `kv.txt` there (the go
/// harness's `-dump-state` writes the same files), so a divergence can be
/// diffed line by line.
pub fn compute_final_state(
    ledger: &SqliteLedger,
    tracker_db: &Path,
    known: &[Address],
    dump: Option<&Path>,
) -> Result<FinalState, String> {
    let write_dump = |name: &str, text: &str| -> Result<(), String> {
        match dump {
            Some(d) => std::fs::write(d.join(name), text).map_err(|e| format!("{name}: {e}")),
            None => Ok(()),
        }
    };
    if let Some(d) = dump {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let round = ledger.current_round().0;
    let hdr = ledger
        .get_block_header_data(round)
        .map_err(|e| format!("header of round {round}: {e}"))?
        .ok_or_else(|| format!("no header for round {round}"))?;
    let mut h = Sha512_256::new();
    h.update(b"BH");
    h.update(&hdr);
    let digest: [u8; 32] = h.finalize().into();
    let t = ledger.account_totals();
    let mut fs = FinalState {
        round,
        block_hash: block_hash_string(&digest),
        txn_counter: ledger.txn_counter(),
        total_money: t.online.money + t.offline.money,
        online_money: t.online.money,
        totals: TotalsJson {
            online: AlgoCountJson {
                money: t.online.money,
                reward_units: t.online.reward_units,
            },
            offline: AlgoCountJson {
                money: t.offline.money,
                reward_units: t.offline.reward_units,
            },
            not_participating: AlgoCountJson {
                money: t.not_participating.money,
                reward_units: t.not_participating.reward_units,
            },
            rewards_level: t.rewards_level,
        },
        ..FinalState::default()
    };

    // corpus.json's digest: REST amounts (pending rewards applied).
    let mut ks: Vec<(String, Address)> = known.iter().map(|a| (a.to_string(), *a)).collect();
    ks.sort();
    ks.dedup();
    let mut lines = String::new();
    for (s, a) in &ks {
        let amount = match ledger.get_account(a) {
            Some(mut acct) => {
                algo_ledger::rewards::apply_rewards(&mut acct, t.rewards_level)
                    .expect("replayed account at the final rewards level");
                acct.micro_algos
            }
            None => 0,
        };
        fs.known_accounts.microalgos += amount;
        let _ = writeln!(lines, "{s} {amount}");
    }
    fs.known_accounts.count = ks.len() as u64;
    fs.known_accounts.sha256 = sha_hex(lines.as_bytes());
    write_dump("known_accounts.txt", &lines)?;

    let conn = rusqlite::Connection::open_with_flags(
        tracker_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("{}: {e}", tracker_db.display()))?;
    let mut resources: BTreeMap<Vec<u8>, Vec<u64>> = BTreeMap::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT a.address, r.aidx FROM accountbase a \
                 LEFT JOIN resources r ON r.addrid = a.addrid",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<i64>>(1)?))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (addr, aidx) = row.map_err(|e| e.to_string())?;
            let ids = resources.entry(addr).or_default();
            if let Some(id) = aidx {
                ids.push(id as u64);
            }
        }
    }
    let mut accts: Vec<(String, String, u64)> = Vec::new();
    for (raw, ids) in &resources {
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| format!("accountbase address of {} bytes", raw.len()))?;
        let addr = Address(bytes);
        let Some(acct) = ledger.get_account(&addr) else {
            continue;
        };
        if is_empty_account(&acct) {
            continue;
        }
        accts.push((
            addr.to_string(),
            account_lines(ledger, &addr, &acct, ids),
            acct.micro_algos,
        ));
    }
    accts.sort();
    lines.clear();
    for (_, l, algos) in &accts {
        lines.push_str(l);
        fs.all_accounts.microalgos += algos;
    }
    fs.all_accounts.count = accts.len() as u64;
    fs.all_accounts.sha256 = sha_hex(lines.as_bytes());
    write_dump("all_accounts.txt", &lines)?;

    let (kv, kv_lines) = box_digest(&conn)?;
    fs.kv = kv;
    lines = kv_lines;
    write_dump("kv.txt", &lines)?;
    Ok(fs)
}

/// The `kv` digest: every box (`bx:` key) of the tracker DB's `kvstore`, as
/// `"<hex key> <hex value>\n"` sorted by key, with its lines.
pub fn box_digest(conn: &rusqlite::Connection) -> Result<(DigestJson, String), String> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM kvstore ORDER BY key")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
        })
        .map_err(|e| e.to_string())?;
    let mut d = DigestJson::default();
    let mut lines = String::new();
    for row in rows {
        let (k, v) = row.map_err(|e| e.to_string())?;
        // go `LookupKeyValue`: an existing key with a NULL value is an empty
        // box (`val = []byte{}`), not a missing one.
        let v = v.unwrap_or_default();
        if !k.starts_with(BOX_PREFIX) {
            continue;
        }
        d.count += 1;
        let _ = writeln!(lines, "{} {}", hex::encode(&k), hex::encode(&v));
    }
    d.sha256 = sha_hex(lines.as_bytes());
    Ok((d, lines))
}

/// Check `fs` against `corpus.json`'s `final_state` (what the generating
/// go-algorand node reported over REST). Returns one message per differing
/// field; empty when it matches. Mirrors go `state.go` `compareWithCorpus`.
pub fn compare_with_corpus(fs: &FinalState, want: &serde_json::Value) -> Vec<String> {
    let mut mm = Vec::new();
    let mut num = |name: &str, got: u64| match want[name].as_u64() {
        Some(w) if w == got => {}
        Some(w) => mm.push(format!("{name}: replay {got}, corpus.json {w}")),
        None => mm.push(format!("{name} missing from corpus.json")),
    };
    num("round", fs.round);
    num("txn_counter", fs.txn_counter);
    num("total_money", fs.total_money);
    num("online_money", fs.online_money);
    num("accounts", fs.known_accounts.count);
    num("accounts_microalgos", fs.known_accounts.microalgos);
    let mut s = |name: &str, got: &str| {
        let w = want[name].as_str().unwrap_or("");
        if w != got {
            mm.push(format!("{name}: replay {got}, corpus.json {w}"));
        }
    };
    s("block_hash", &fs.block_hash);
    s("accounts_sha256", &fs.known_accounts.sha256);
    mm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tkv_sorts_by_key_bytes_and_types_values() {
        let mut kv = BTreeMap::new();
        kv.insert(b"b".to_vec(), TealValue::Uint(7));
        kv.insert(b"a".to_vec(), TealValue::Bytes(vec![0xff, 0x00]));
        assert_eq!(tkv(&kv), "61:bff00,62:u7");
        assert_eq!(tkv(&BTreeMap::new()), "");
    }

    /// go's `LookupKeyValue` returns a NULL-valued kvstore row as an
    /// existing empty box (`val = []byte{}`), so the box digest must count
    /// and hash it as empty, not skip it.
    #[test]
    fn box_digest_counts_null_values_as_empty_boxes() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kvstore (key BLOB PRIMARY KEY, value BLOB);
             INSERT INTO kvstore VALUES (x'62783a01', NULL);
             INSERT INTO kvstore VALUES (x'62783a02', x'ff');
             INSERT INTO kvstore VALUES (x'6f746865', x'01');",
        )
        .unwrap();
        let (d, lines) = box_digest(&conn).unwrap();
        assert_eq!(d.count, 2);
        assert_eq!(lines, "62783a01 \n62783a02 ff\n");
        assert_eq!(d.sha256, sha_hex(lines.as_bytes()));
    }

    #[test]
    fn compare_with_corpus_names_each_differing_field() {
        let fs = FinalState {
            round: 5,
            block_hash: "blk-X".into(),
            txn_counter: 9,
            ..FinalState::default()
        };
        let want = serde_json::json!({
            "round": 5, "block_hash": "blk-Y", "txn_counter": 9, "total_money": 0,
            "online_money": 0, "accounts": 0, "accounts_microalgos": 0,
            "accounts_sha256": fs.known_accounts.sha256,
        });
        assert_eq!(
            compare_with_corpus(&fs, &want),
            vec!["block_hash: replay blk-X, corpus.json blk-Y".to_string()]
        );
    }
}
