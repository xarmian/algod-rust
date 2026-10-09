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
//!    state delta of the round wrote has exactly go's post value afterwards.

use std::collections::BTreeMap;
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

fn replay_entry(round: u64) {
    let dir = corpus_dir();
    let raw_block = std::fs::read(dir.join(format!("{round}.msgpack")))
        .unwrap_or_else(|e| panic!("missing corpus block {round}: {e}"));
    let block = algo_codec::decode_block_response(&raw_block)
        .unwrap_or_else(|e| panic!("cannot decode block {round}: {e}"))
        .block;
    assert_eq!(block.round, Round(round));
    let state = read_value(&dir.join(format!("{round}.state.msgpack")));
    let mut ls = build_pre_state(round, &state);

    let computed = apply_block_capturing_apply_data(&mut ls, &block, ApplyMode::Execute)
        .unwrap_or_else(|e| panic!("round {round}: Execute-mode apply failed: {e}"));

    let mut diffs: Vec<String> = compare_recorded_apply_data(&block, &computed)
        .iter()
        .map(|d| format!("apply_data {d}"))
        .collect();
    check_post_state(&ls, &state, &mut diffs);
    assert!(
        diffs.is_empty(),
        "round {round}: {} divergence(s) from go:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

macro_rules! corpus_entry {
    ($name:ident, $round:expr) => {
        #[test]
        fn $name() {
            replay_entry($round);
        }
    };
}

// #1729: the zero-amount close into a brand new account (block 65723764) must
// stamp the target's rewards_base; its first spend is block 65723784 txn 7.
corpus_entry!(
    round_65723764_close_to_new_account_stamps_rewards_base,
    65723764
);
// #1698: DeltaAction numbering (SetBytes=1, SetUint=2) in recorded eval deltas.
corpus_entry!(round_65703970_delta_action_numbering, 65703970);
// #1669: account zeroed by go must not survive as a non-empty record.
corpus_entry!(round_65668288_zeroed_account_min_balance, 65668288);
// #1699 / #1710: inner transaction groups carry a go-compatible Group ID.
corpus_entry!(round_65689687_inner_group_ids, 65689687);
// #1664: box counts/bytes of an app account (min balance) after inner calls.
corpus_entry!(round_65595332_app_account_box_totals, 65595332);
// #1665: inner close-out leaving a zeroed account (update_round on an empty record).
corpus_entry!(round_65589704_inner_close_out_zeroed_account, 65589704);
// Divergences listed in #1675 without a dedicated issue number.
corpus_entry!(round_65549710, 65549710);
corpus_entry!(round_65549861, 65549861);
corpus_entry!(round_65560513, 65560513);
corpus_entry!(round_65561121, 65561121);
corpus_entry!(round_65582745, 65582745);
corpus_entry!(round_65596480, 65596480);
corpus_entry!(
    round_65723784_spend_from_close_to_account_sender_rewards_zero,
    65723784
);

/// Every `<round>.msgpack` in the corpus directory must have a state file and
/// a test above, so a captured-but-unwired entry cannot silently rot.
#[test]
fn every_corpus_block_has_state_and_is_wired() {
    let wired: &[u64] = &[
        65549710, 65549861, 65560513, 65561121, 65582745, 65589704, 65595332, 65596480, 65668288,
        65689687, 65703970, 65723764, 65723784,
    ];
    let dir = corpus_dir();
    let mut found = Vec::new();
    for e in std::fs::read_dir(&dir).expect("corpus dir") {
        let name = e.unwrap().file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".state.msgpack") {
            found.push(stem.parse::<u64>().expect("round"));
        } else if let Some(stem) = name.strip_suffix(".msgpack") {
            let r: u64 = stem.parse().expect("round");
            assert!(
                dir.join(format!("{r}.state.msgpack")).exists(),
                "{r}.msgpack has no state file"
            );
        }
    }
    found.sort_unstable();
    let mut w = wired.to_vec();
    w.sort_unstable();
    assert_eq!(found, w, "corpus directory and wired tests disagree");
}
