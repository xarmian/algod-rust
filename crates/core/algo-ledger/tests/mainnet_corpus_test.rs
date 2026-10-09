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

//! Mainnet regression corpus (issue #1675).
//!
//! Every entry under `fixtures/mainnet_corpus/` is a real mainnet block that
//! once exposed a divergence between algod-rust and go-algorand, together
//! with the pre-state it needs and go's own post-state for the keys it wrote
//! (see `fixtures/mainnet_corpus/README.md`; regenerate with
//! `scripts/capture_mainnet_corpus.py`).
//!
//! For each entry the test builds an in-memory ledger from the recorded
//! pre-state, applies the block in `ApplyMode::Execute` and asserts that
//!
//! 1. the apply succeeds,
//! 2. the ApplyData Execute computed for every transaction equals the
//!    ApplyData go recorded in the block (the shadow-execute comparison,
//!    `compare_recorded_apply_data`), and
//! 3. every account, asset holding/params, app params/local state and box go's
//!    state delta of the round wrote has exactly go's post value afterwards,
//! 4. the converse: nothing Rust modified or created is absent from go's delta
//!    (this is what catches over-writes such as #1669 / #1729), and
//! 5. the capture's `meta` approximation counts equal the explicit per-round
//!    allow-list in the `corpus!` table, so a re-capture cannot silently
//!    become more approximate.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use algo_ledger::shadow_execute::compare_recorded_apply_data;
use algo_ledger::{apply_block_capturing_apply_data, ApplyMode, LedgerState, LedgerStore};
use algo_types::{
    AccountData, AccountStatus, Address, AppLocalState, AppParams, AssetHolding, AssetParams,
    AssetParamsRecord, Round, StateSchema, TealValue,
};
use rmpv::Value;

// ---------------------------------------------------------------------------
// rmpv helpers
// ---------------------------------------------------------------------------

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(m) => m
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
            .filter(|v| !v.is_nil()),
        _ => None,
    }
}

fn num(v: &Value, key: &str) -> u64 {
    get(v, key).and_then(Value::as_u64).unwrap_or(0)
}

fn flag(v: &Value, key: &str) -> bool {
    get(v, key).and_then(Value::as_bool).unwrap_or(false)
}

fn raw(v: &Value) -> Vec<u8> {
    match v {
        Value::Binary(b) => b.clone(),
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Nil => Vec::new(),
        other => panic!("expected bytes, got {other:?}"),
    }
}

fn bytes_of(v: &Value, key: &str) -> Vec<u8> {
    get(v, key).map(raw).unwrap_or_default()
}

fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    match get(v, key) {
        Some(Value::Array(a)) => a,
        _ => &[],
    }
}

fn addr_of(v: &Value, key: &str) -> Address {
    let b = bytes_of(v, key);
    let mut a = [0u8; 32];
    assert_eq!(b.len(), 32, "{key} must be a 32-byte address");
    a.copy_from_slice(&b);
    Address(a)
}

fn opt_addr(v: &Value, key: &str) -> Option<Address> {
    let a = get(v, key).map(|_| addr_of(v, key))?;
    (a != Address::ZERO).then_some(a)
}

fn opt_fixed<const N: usize>(v: &Value, key: &str) -> Option<[u8; N]> {
    let b = bytes_of(v, key);
    if b.len() != N || b.iter().all(|x| *x == 0) {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&b);
    Some(out)
}

fn schema(v: Option<&Value>) -> StateSchema {
    match v {
        Some(s) => StateSchema {
            num_uint: num(s, "nui"),
            num_byte_slice: num(s, "nbs"),
        },
        None => StateSchema::default(),
    }
}

fn teal_map(v: Option<&Value>) -> BTreeMap<Vec<u8>, TealValue> {
    let mut out = BTreeMap::new();
    if let Some(Value::Map(entries)) = v {
        for (k, tv) in entries {
            let val = match num(tv, "tt") {
                1 => TealValue::Bytes(bytes_of(tv, "tb")),
                2 => TealValue::Uint(num(tv, "ui")),
                other => panic!("unexpected TealValue type {other}"),
            };
            out.insert(raw(k), val);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// go record -> algo-types conversions
// ---------------------------------------------------------------------------

fn account_from(rec: &Value) -> AccountData {
    AccountData {
        micro_algos: num(rec, "MicroAlgos"),
        rewards_base: num(rec, "RewardsBase"),
        rewarded_micro_algos: num(rec, "RewardedMicroAlgos"),
        status: AccountStatus::from(num(rec, "Status") as u8),
        vote_id: opt_fixed::<32>(rec, "VoteID"),
        selection_id: opt_fixed::<32>(rec, "SelectionID"),
        state_proof_id: opt_fixed::<64>(rec, "StateProofID"),
        vote_first_valid: num(rec, "VoteFirstValid"),
        vote_last_valid: num(rec, "VoteLastValid"),
        vote_key_dilution: num(rec, "VoteKeyDilution"),
        auth_addr: opt_addr(rec, "AuthAddr"),
        total_assets_opted_in: num(rec, "TotalAssets"),
        total_created_assets: num(rec, "TotalAssetParams"),
        total_apps_opted_in: num(rec, "TotalAppLocalStates"),
        total_created_apps: num(rec, "TotalAppParams"),
        total_extra_app_pages: num(rec, "TotalExtraAppPages") as u32,
        total_box_bytes: num(rec, "TotalBoxBytes"),
        total_boxes: num(rec, "TotalBoxes"),
        total_app_schema: schema(get(rec, "TotalAppSchema")),
        incentive_eligible: flag(rec, "IncentiveEligible"),
        last_proposed: num(rec, "LastProposed"),
        last_heartbeat: num(rec, "LastHeartbeat"),
        ..AccountData::default()
    }
}

/// The consensus-relevant projection of an account (excludes the trie
/// bookkeeping field and the resource maps the store keeps separately).
fn account_proj(a: &AccountData) -> String {
    format!(
        "algos={} rewards_base={} rewarded={} status={:?} vote_id={:?} sel={:?} sp={:?} \
         vfv={} vlv={} dil={} auth={:?} assets={} created_assets={} opted_apps={} \
         created_apps={} extra_pages={} box_bytes={} boxes={} schema={:?} incentive={} \
         last_proposed={} last_hb={}",
        a.micro_algos,
        a.rewards_base,
        a.rewarded_micro_algos,
        a.status,
        a.vote_id,
        a.selection_id,
        a.state_proof_id.map(|s| s.to_vec()),
        a.vote_first_valid,
        a.vote_last_valid,
        a.vote_key_dilution,
        a.auth_addr,
        a.total_assets_opted_in,
        a.total_created_assets,
        a.total_apps_opted_in,
        a.total_created_apps,
        a.total_extra_app_pages,
        a.total_box_bytes,
        a.total_boxes,
        a.total_app_schema,
        a.incentive_eligible,
        a.last_proposed,
        a.last_heartbeat,
    )
}

fn asset_params_from(p: &Value, creator: Address) -> AssetParamsRecord {
    AssetParamsRecord {
        params: AssetParams {
            total: num(p, "t"),
            decimals: num(p, "dc") as u32,
            default_frozen: flag(p, "df"),
            unit_name: bytes_of(p, "un"),
            asset_name: bytes_of(p, "an"),
            url: bytes_of(p, "au"),
            metadata_hash: opt_fixed::<32>(p, "am"),
            manager: opt_addr(p, "m"),
            reserve: opt_addr(p, "r"),
            freeze: opt_addr(p, "f"),
            clawback: opt_addr(p, "c"),
        },
        creator,
    }
}

fn app_params_from(p: &Value, creator: Address) -> AppParams {
    AppParams {
        creator,
        approval_program: bytes_of(p, "approv"),
        clear_state_program: bytes_of(p, "clearp"),
        global_state: teal_map(get(p, "gs")),
        local_state_schema: schema(get(p, "lsch")),
        global_state_schema: schema(get(p, "gsch")),
        extra_program_pages: num(p, "epp") as u32,
        version: num(p, "v"),
        size_sponsor: opt_addr(p, "ss").unwrap_or(Address::ZERO),
        foreign_box_reads: flag(p, "fbr"),
        family_box_access: flag(p, "fba"),
    }
}

fn local_state_from(p: &Value) -> AppLocalState {
    AppLocalState {
        schema: schema(get(p, "hsch")),
        key_value: teal_map(get(p, "tkv")),
    }
}

fn holding_from(p: &Value) -> AssetHolding {
    AssetHolding {
        amount: num(p, "a"),
        frozen: flag(p, "f"),
    }
}

/// One part (`Params` / `Holding` / `State`) of a go resource record:
/// `Some(Some(payload))` = set, `Some(None)` = deleted, `None` = untouched.
fn part<'a>(rec: &'a Value, part: &str, inner: &str) -> Option<Option<&'a Value>> {
    let p = get(rec, part)?;
    if flag(p, "Deleted") {
        return Some(None);
    }
    get(p, inner).map(Some)
}

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/mainnet_corpus")
}

fn read_value(path: &PathBuf) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {path:?}: {e}"));
    rmpv::decode::read_value(&mut bytes.as_slice())
        .unwrap_or_else(|e| panic!("cannot decode {path:?}: {e}"))
}

fn build_pre_state(round: u64, state: &Value) -> LedgerState {
    let mut ls = LedgerState::new();
    let hdr = get(state, "prev_hdr").expect("prev_hdr");
    let proto = String::from_utf8(bytes_of(hdr, "proto")).expect("proto");
    ls.set_rewards_level(num(hdr, "earn"));
    ls.set_rewards_rate(num(hdr, "rate"));
    ls.set_rewards_residue(num(hdr, "frac"));
    ls.set_rewards_recalculation_round(num(hdr, "rwcalr"));
    ls.set_fee_sink(addr_of(hdr, "fees"));
    ls.set_rewards_pool(addr_of(hdr, "rwd"));
    ls.set_txn_counter(num(hdr, "tc"));
    ls.set_protocol(proto.clone());
    ls.set_genesis_id(String::from_utf8(bytes_of(hdr, "gen")).expect("gen"));
    let mut gh = [0u8; 32];
    gh.copy_from_slice(&bytes_of(hdr, "gh"));
    ls.set_genesis_hash(gh);
    ls.set_current_round(Round(round - 1));
    // The previous header gives `global LatestTimestamp`.
    let mut hdr_bytes = Vec::new();
    rmpv::encode::write_value(&mut hdr_bytes, hdr).expect("encode prev header");
    ls.put_block(round - 1, &proto, &hdr_bytes, &[])
        .expect("put prev header");
    // Earlier headers serve the `block` opcode (BlkSeed / BlkTimestamp).
    for (k, h) in arr(state, "extra_hdrs").iter().enumerate() {
        let mut b = Vec::new();
        rmpv::encode::write_value(&mut b, h).expect("encode header");
        let hp = String::from_utf8(bytes_of(h, "proto")).expect("proto");
        ls.put_block(round - 2 - k as u64, &hp, &b, &[])
            .expect("put header");
    }

    let pre = get(state, "pre").expect("pre");
    for rec in arr(pre, "Accts") {
        ls.set_account(&addr_of(rec, "Addr"), account_from(rec));
    }
    for rec in arr(pre, "AssetResources") {
        let addr = addr_of(rec, "Addr");
        let id = num(rec, "Aidx");
        if let Some(Some(p)) = part(rec, "Params", "Params") {
            ls.set_asset_params(id, asset_params_from(p, addr));
        }
        if let Some(Some(h)) = part(rec, "Holding", "Holding") {
            ls.set_asset_holding(&addr, id, holding_from(h));
        }
    }
    for rec in arr(pre, "AppResources") {
        let addr = addr_of(rec, "Addr");
        let id = num(rec, "Aidx");
        if let Some(Some(p)) = part(rec, "Params", "Params") {
            ls.set_app_params(id, app_params_from(p, addr));
        }
        if let Some(Some(s)) = part(rec, "State", "LocalState") {
            ls.set_app_local_state(&addr, id, local_state_from(s));
        }
    }
    if let Some(Value::Map(kv)) = get(pre, "KvMods") {
        for (k, v) in kv {
            let key = raw(k);
            if let Some(data) = get(v, "Data") {
                set_box_by_kv_key(&mut ls, &key, raw(data));
            }
        }
    }
    ls
}

/// go's KV key for a box is `"bx:" || appID(8, BE) || name`.
fn split_box_key(key: &[u8]) -> (u64, &[u8]) {
    assert!(
        key.len() >= 11 && &key[..3] == b"bx:",
        "unexpected KvMods key {key:?}"
    );
    let mut id = [0u8; 8];
    id.copy_from_slice(&key[3..11]);
    (u64::from_be_bytes(id), &key[11..])
}

fn set_box_by_kv_key(ls: &mut LedgerState, key: &[u8], value: Vec<u8>) {
    let (app, name) = split_box_key(key);
    ls.set_box(app, name, value);
}

// ---------------------------------------------------------------------------
// The replay + compare
// ---------------------------------------------------------------------------

fn check_post_state(ls: &LedgerState, state: &Value, diffs: &mut Vec<String>) {
    let post = get(state, "post").expect("post");
    for rec in arr(post, "Accts") {
        let addr = addr_of(rec, "Addr");
        let want = account_proj(&account_from(rec));
        let got = ls
            .get_account(&addr)
            .map(account_proj)
            .unwrap_or_else(|| "<absent>".into());
        // go keeps a fully-zero record only for accounts it did not delete;
        // an absent account and an all-zero one are equivalent here.
        let zero = account_proj(&AccountData::default());
        if want != got && !(want == zero && got == "<absent>") {
            diffs.push(format!("account {addr:?}\n  go:   {want}\n  rust: {got}"));
        }
    }
    for rec in arr(post, "AssetResources") {
        let addr = addr_of(rec, "Addr");
        let id = num(rec, "Aidx");
        match part(rec, "Params", "Params") {
            Some(Some(p)) => {
                let want = asset_params_from(p, addr);
                let got = ls.get_asset_params(id);
                if got != Some(&want) {
                    diffs.push(format!(
                        "asset params {id}\n  go:   {want:?}\n  rust: {got:?}"
                    ));
                }
            }
            Some(None) if ls.get_asset_params(id).is_some() => {
                diffs.push(format!("asset params {id}: go deleted, rust kept"));
            }
            _ => {}
        }
        match part(rec, "Holding", "Holding") {
            Some(Some(h)) => {
                let want = holding_from(h);
                let got = ls.get_asset_holding(&addr, id);
                if got != Some(&want) {
                    diffs.push(format!(
                        "holding {addr:?}/{id}\n  go:   {want:?}\n  rust: {got:?}"
                    ));
                }
            }
            Some(None) if ls.get_asset_holding(&addr, id).is_some() => {
                diffs.push(format!("holding {addr:?}/{id}: go deleted, rust kept"));
            }
            _ => {}
        }
    }
    for rec in arr(post, "AppResources") {
        let addr = addr_of(rec, "Addr");
        let id = num(rec, "Aidx");
        match part(rec, "Params", "Params") {
            Some(Some(p)) => {
                let want = app_params_from(p, addr);
                let got = ls.get_app_params(id);
                if got != Some(&want) {
                    diffs.push(format!(
                        "app params {id}\n  go:   {want:?}\n  rust: {got:?}"
                    ));
                }
            }
            Some(None) if ls.get_app_params(id).is_some() => {
                diffs.push(format!("app params {id}: go deleted, rust kept"));
            }
            _ => {}
        }
        match part(rec, "State", "LocalState") {
            Some(Some(s)) => {
                let want = local_state_from(s);
                let got = ls.get_app_local_state(&addr, id);
                if got != Some(&want) {
                    diffs.push(format!(
                        "local state {addr:?}/{id}\n  go:   {want:?}\n  rust: {got:?}"
                    ));
                }
            }
            Some(None) if ls.get_app_local_state(&addr, id).is_some() => {
                diffs.push(format!("local state {addr:?}/{id}: go deleted, rust kept"));
            }
            _ => {}
        }
    }
    if let Some(Value::Map(kv)) = get(post, "KvMods") {
        for (k, v) in kv {
            let key = raw(k);
            let (app, name) = split_box_key(&key);
            let want = get(v, "Data").map(raw);
            let got = ls.get_box(app, name);
            if want != got {
                diffs.push(format!(
                    "box app={app} name={}\n  go:   {:?}\n  rust: {:?}",
                    hex::encode(name),
                    want.as_ref().map(|w| (w.len(), hex::encode(w))),
                    got.as_ref().map(|w| (w.len(), hex::encode(w))),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Converse check: nothing Rust wrote may be absent from go's delta
// ---------------------------------------------------------------------------

struct Snapshot {
    accounts: HashMap<Address, AccountData>,
    holdings: HashMap<(Address, u64), AssetHolding>,
    local_states: HashMap<(Address, u64), AppLocalState>,
    asset_params: HashMap<u64, AssetParamsRecord>,
    app_params: HashMap<u64, AppParams>,
    boxes: HashMap<(u64, Vec<u8>), Vec<u8>>,
}

impl Snapshot {
    fn of(ls: &LedgerState) -> Self {
        Snapshot {
            accounts: ls.accounts.clone(),
            holdings: ls.asset_holdings.clone(),
            local_states: ls.app_local_states.clone(),
            asset_params: ls.asset_params.clone(),
            app_params: ls.app_params.clone(),
            boxes: ls.boxes.clone(),
        }
    }
}

/// Explicit exceptions to the converse check. Empty on purpose: go's delta
/// lists the fee sink, rewards pool and the proposer payout recipient, and the
/// corpus passes without any allowance. Add an entry (with a comment saying
/// why go does not list it) rather than loosening the check.
const UNLISTED_ACCOUNT_ALLOWANCE: &[Address] = &[];

/// Keys whose value differs between `before` and `after` (created, changed or
/// removed).
fn changed<'a, K, V>(before: &'a HashMap<K, V>, after: &'a HashMap<K, V>) -> Vec<&'a K>
where
    K: Eq + std::hash::Hash,
    V: PartialEq,
{
    let mut out: Vec<&K> = Vec::new();
    for (k, v) in after {
        if before.get(k) != Some(v) {
            out.push(k);
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            out.push(k);
        }
    }
    out
}

fn check_no_unlisted_writes(
    before: &Snapshot,
    ls: &LedgerState,
    state: &Value,
    diffs: &mut Vec<String>,
) {
    let post = get(state, "post").expect("post");
    let go_accts: HashSet<Address> = arr(post, "Accts")
        .iter()
        .map(|r| addr_of(r, "Addr"))
        .collect();
    let mut go_holdings = HashSet::new();
    let mut go_asset_params = HashSet::new();
    for rec in arr(post, "AssetResources") {
        let (addr, id) = (addr_of(rec, "Addr"), num(rec, "Aidx"));
        if part(rec, "Holding", "Holding").is_some() {
            go_holdings.insert((addr, id));
        }
        if part(rec, "Params", "Params").is_some() {
            go_asset_params.insert(id);
        }
    }
    let mut go_local = HashSet::new();
    let mut go_app_params = HashSet::new();
    for rec in arr(post, "AppResources") {
        let (addr, id) = (addr_of(rec, "Addr"), num(rec, "Aidx"));
        if part(rec, "State", "LocalState").is_some() {
            go_local.insert((addr, id));
        }
        if part(rec, "Params", "Params").is_some() {
            go_app_params.insert(id);
        }
    }
    let mut go_boxes = HashSet::new();
    if let Some(Value::Map(kv)) = get(post, "KvMods") {
        for (k, _) in kv {
            let key = raw(k);
            let (app, name) = split_box_key(&key);
            go_boxes.insert((app, name.to_vec()));
        }
    }

    // Accounts compare by consensus projection; absent == all-zero record.
    let zero = account_proj(&AccountData::default());
    let proj = |m: &HashMap<Address, AccountData>, a: &Address| {
        m.get(a).map(account_proj).unwrap_or_else(|| zero.clone())
    };
    let mut addrs: HashSet<Address> = before.accounts.keys().copied().collect();
    addrs.extend(ls.accounts.keys().copied());
    for a in addrs {
        if proj(&before.accounts, &a) != proj(&ls.accounts, &a)
            && !go_accts.contains(&a)
            && !UNLISTED_ACCOUNT_ALLOWANCE.contains(&a)
        {
            diffs.push(format!(
                "account {a:?} was modified by Rust but is not in go's delta\n  before: {}\n  after:  {}",
                proj(&before.accounts, &a),
                proj(&ls.accounts, &a)
            ));
        }
    }
    for k in changed(&before.holdings, &ls.asset_holdings) {
        if !go_holdings.contains(k) {
            diffs.push(format!(
                "holding {k:?} modified by Rust but not in go's delta"
            ));
        }
    }
    for k in changed(&before.local_states, &ls.app_local_states) {
        if !go_local.contains(k) {
            diffs.push(format!(
                "local state {k:?} modified by Rust but not in go's delta"
            ));
        }
    }
    for k in changed(&before.asset_params, &ls.asset_params) {
        if !go_asset_params.contains(k) {
            diffs.push(format!(
                "asset params {k} modified by Rust but not in go's delta"
            ));
        }
    }
    for k in changed(&before.app_params, &ls.app_params) {
        if !go_app_params.contains(k) {
            diffs.push(format!(
                "app params {k} modified by Rust but not in go's delta"
            ));
        }
    }
    for k in changed(&before.boxes, &ls.boxes) {
        if !go_boxes.contains(k) {
            diffs.push(format!(
                "box app={} name={} modified by Rust but not in go's delta",
                k.0,
                hex::encode(&k.1)
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// meta approximation allow-list
// ---------------------------------------------------------------------------

/// How approximate a captured pre-state is: counts of
/// (accounts not found in any delta, accounts taken from the chain tip,
/// resource parts taken from the chain tip, resource parts left unresolved).
type Approx = (usize, usize, usize, usize);

fn list_len(meta: &Value, key: &str) -> usize {
    match get(meta, key) {
        Some(Value::Array(a)) => a.len(),
        Some(v) => v.as_u64().unwrap_or(0) as usize,
        None => 0,
    }
}

fn check_meta(round: u64, state: &Value, allowed: Approx) -> Result<(), String> {
    let meta = get(state, "meta").expect("meta");
    let got: Approx = (
        list_len(meta, "unresolved_accounts"),
        list_len(meta, "tip_approximated_accounts"),
        list_len(meta, "tip_approximated_resource_parts"),
        list_len(meta, "unresolved_resource_parts"),
    );
    if got == allowed {
        return Ok(());
    }
    Err(format!(
        "round {round}: pre-state approximation (unresolved accounts, tip accounts, tip \
         resource parts, unresolved resource parts) is {got:?} but the allow-list says \
         {allowed:?}. Details (tip_approximated_accounts / unresolved_accounts / ...): {meta:?}"
    ))
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

fn get_mut<'a>(v: &'a mut Value, key: &str) -> Option<&'a mut Value> {
    match v {
        Value::Map(m) => m
            .iter_mut()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// Replay one corpus entry; `mutate` may tamper with an in-memory copy of the
/// state file (used by the negative tests). Returns every divergence found.
fn run_entry(round: u64, mutate: &dyn Fn(&mut Value)) -> Vec<String> {
    let dir = corpus_dir();
    let raw_block = std::fs::read(dir.join(format!("{round}.msgpack")))
        .unwrap_or_else(|e| panic!("missing corpus block {round}: {e}"));
    let block = algo_codec::decode_block_response(&raw_block)
        .unwrap_or_else(|e| panic!("cannot decode block {round}: {e}"))
        .block;
    assert_eq!(block.round, Round(round));
    let mut state = read_value(&dir.join(format!("{round}.state.msgpack")));
    mutate(&mut state);
    let mut ls = build_pre_state(round, &state);
    let before = Snapshot::of(&ls);

    let computed = match apply_block_capturing_apply_data(&mut ls, &block, ApplyMode::Execute) {
        Ok(c) => c,
        Err(e) => return vec![format!("Execute-mode apply failed: {e}")],
    };

    let mut diffs: Vec<String> = compare_recorded_apply_data(&block, &computed)
        .iter()
        .map(|d| format!("apply_data {d}"))
        .collect();
    check_post_state(&ls, &state, &mut diffs);
    check_no_unlisted_writes(&before, &ls, &state, &mut diffs);
    diffs
}

fn replay_entry(round: u64, allowed: Approx) {
    let diffs = run_entry(round, &|_| {});
    assert!(
        diffs.is_empty(),
        "round {round}: {} divergence(s) from go:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
    let state = read_value(&corpus_dir().join(format!("{round}.state.msgpack")));
    if let Err(e) = check_meta(round, &state, allowed) {
        panic!("{e}");
    }
}

/// Single source of truth for the corpus: one row per block emits its test and
/// its entry in `WIRED` / `APPROX`, so tests and the wiring check cannot diverge.
macro_rules! corpus {
    ($( $(#[$doc:meta])* $name:ident => $round:expr, approx $approx:expr; )*) => {
        const WIRED: &[u64] = &[$($round),*];
        const APPROX: &[(u64, Approx)] = &[$(($round, $approx)),*];
        $(
            $(#[$doc])*
            #[test]
            fn $name() {
                replay_entry($round, $approx);
            }
        )*
    };
}

corpus! {
    /// Listed in #1675.
    round_65549710 => 65549710, approx (0, 1, 1, 5);
    /// Listed in #1675.
    round_65549861 => 65549861, approx (0, 2, 2, 20);
    /// Listed in #1675.
    round_65560513 => 65560513, approx (4, 10, 8, 27);
    /// Listed in #1675.
    round_65561121 => 65561121, approx (4, 2, 4, 8);
    /// Listed in #1675.
    round_65582745 => 65582745, approx (2, 3, 8, 14);
    /// #1665 class: inner close-out leaving a zeroed account.
    round_65589704_inner_close_out_zeroed_account => 65589704, approx (4, 2, 11, 34);
    /// #1664: box counts/bytes of an app account after inner calls.
    round_65595332_app_account_box_totals => 65595332, approx (0, 2, 8, 22);
    /// Listed in #1675.
    round_65596480 => 65596480, approx (0, 3, 2, 0);
    /// #1669: an account go zeroes must not stay a non-empty record.
    round_65668288_zeroed_account_min_balance => 65668288, approx (4, 2, 3, 7);
    /// #1699 / #1710: inner transaction groups carry a go-compatible Group ID.
    round_65689687_inner_group_ids => 65689687, approx (4, 4, 3, 11);
    /// #1698 / #1708: DeltaAction numbering (SetBytes=1, SetUint=2).
    round_65703970_delta_action_numbering => 65703970, approx (2, 11, 23, 32);
    /// #1729 / #1730: the zero-amount close into a brand new account stamps the
    /// target's rewards_base. This block is the real #1729 guard.
    round_65723764_close_to_new_account_stamps_rewards_base => 65723764, approx (5, 6, 11, 14);
    /// Smoke replay of the first spend from that account (txn 7). It was green
    /// before the #1729 fix too (its pre-state comes from go), so it is NOT the
    /// #1729 guard; it is kept as the fixed-code spend-from-new-account check
    /// and because its inner transactions (axfer/appl with nested deltas)
    /// exercise the eval-delta/itx encoding (#1742) that older trees get wrong.
    round_65723784_smoke_replay_spend_from_new_account => 65723784, approx (2, 10, 20, 30);
}

/// Every fixture needs a test and every test a fixture (both directions).
#[test]
fn every_corpus_block_has_state_and_is_wired() {
    let dir = corpus_dir();
    let mut blocks = Vec::new();
    let mut states = Vec::new();
    for e in std::fs::read_dir(&dir).expect("corpus dir") {
        let name = e.unwrap().file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".state.msgpack") {
            states.push(stem.parse::<u64>().expect("round"));
        } else if let Some(stem) = name.strip_suffix(".msgpack") {
            blocks.push(stem.parse::<u64>().expect("round"));
        }
    }
    blocks.sort_unstable();
    states.sort_unstable();
    let mut wired = WIRED.to_vec();
    wired.sort_unstable();
    assert_eq!(
        blocks, states,
        "a block fixture and its state file must come in pairs"
    );
    assert_eq!(
        blocks, wired,
        "fixtures on disk and the `corpus!` table disagree"
    );
    assert_eq!(APPROX.len(), WIRED.len());
}

// ---------------------------------------------------------------------------
// Negative tests: prove each check can fail
// ---------------------------------------------------------------------------

fn remove_post_entry(state: &mut Value, list: &str, keep: &dyn Fn(&Value) -> bool) -> usize {
    let post = get_mut(state, "post").expect("post");
    let Some(Value::Array(a)) = get_mut(post, list) else {
        return 0;
    };
    let before = a.len();
    a.retain(|r| keep(r));
    before - a.len()
}

#[test]
fn negative_dropping_a_written_account_from_go_post_is_caught() {
    // The sender of block 65723764's close is created by Rust; erasing it from
    // go's post delta must surface as "modified by Rust but not in go's delta".
    let diffs = run_entry(65723764, &|st| {
        let removed = remove_post_entry(st, "Accts", &|r| {
            addr_of(r, "Addr").0[..4] != [0xc1, 0xac, 0xd7, 0x41]
        });
        assert_eq!(
            removed, 1,
            "fixture no longer contains the expected account"
        );
    });
    assert!(
        diffs
            .iter()
            .any(|d| d.contains("modified by Rust but is not in go's delta")),
        "converse check did not fire: {diffs:?}"
    );
}

#[test]
fn negative_dropping_a_written_box_from_go_post_is_caught() {
    let state = read_value(&corpus_dir().join("65595332.state.msgpack"));
    let keys: Vec<Vec<u8>> = match get(&state, "post").and_then(|p| get(p, "KvMods")) {
        Some(Value::Map(m)) => m.iter().map(|(k, _)| raw(k)).collect(),
        _ => Vec::new(),
    };
    assert!(!keys.is_empty(), "65595332 must record box writes");
    let mut caught = 0;
    for victim in &keys {
        let diffs = run_entry(65595332, &|st| {
            let post = get_mut(st, "post").unwrap();
            if let Some(Value::Map(m)) = get_mut(post, "KvMods") {
                m.retain(|(k, _)| &raw(k) != victim);
            }
        });
        if diffs
            .iter()
            .any(|d| d.contains("box app=") && d.contains("not in go's delta"))
        {
            caught += 1;
        }
    }
    assert!(caught >= 1, "no box removal was detected");
}

#[test]
fn negative_tampered_pre_state_is_caught() {
    let diffs = run_entry(65723764, &|st| {
        let pre = get_mut(st, "pre").unwrap();
        if let Some(Value::Array(accts)) = get_mut(pre, "Accts") {
            for r in accts.iter_mut() {
                if let Some(v) = get_mut(r, "MicroAlgos") {
                    if let Some(n) = v.as_u64() {
                        *v = Value::from(n + 1);
                    }
                }
            }
        }
    });
    assert!(!diffs.is_empty(), "tampering with pre-state went unnoticed");
}

#[test]
fn negative_meta_approximation_allow_list_rejects_drift() {
    let (round, allowed) = APPROX[0];
    let state = read_value(&corpus_dir().join(format!("{round}.state.msgpack")));
    assert!(check_meta(round, &state, allowed).is_ok());
    let looser = (allowed.0, allowed.1 + 1, allowed.2, allowed.3);
    let err = check_meta(round, &state, looser).expect_err("drift must be rejected");
    assert!(
        err.contains("tip_approximated_accounts"),
        "message must print the meta: {err}"
    );
}
