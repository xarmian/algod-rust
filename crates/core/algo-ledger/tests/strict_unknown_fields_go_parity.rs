// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict unknown-field parity of the catchpoint file readers with go-algorand
//! (issue #2396), and decoded-value parity on repeated keys (issue #2421).
//!
//! go's catchpoint restore (`ledger/catchupaccessor.go`) decodes every section
//! with `protocol.Decode` (generated msgp decoders: a key the struct lacks is
//! `msgp.ErrNoField`) and then decodes each balance record's `msgp.Raw` account
//! and resource blobs (`prepareNormalizedBalancesV6`), so a catchpoint file
//! with an unknown key anywhere in those is rejected. `tests/fixtures/
//! strict_decode/` holds sections of go-written catchpoints and go-encoded
//! random ones (`seeds.jsonl`) and mutants of them with go's verdict and, when
//! go accepts, go's decoded value (`cases.jsonl`), from
//! `scripts/strict-decode/strict_decode_fixtures.py --set ledger`
//! (tools/strict-decode-oracle/ledger_oracle_test.go.txt).

use algo_ledger::catchpoint::importer::decode_balance_record_blobs;
use algo_ledger::catchpoint::parser::{
    decode_catchpoint_chunk, decode_catchpoint_header, decode_state_proof_verification,
};
use algo_ledger::catchpoint::types::{
    AccountTotals, AlgoCount, CatchpointBaseAccountData, CatchpointFileHeader,
    CatchpointResourcesData, CatchpointSnapshotChunkV6, CatchpointStateProofVerificationWrapper,
};
use algo_ledger::catchpoint::CatchpointError;

#[path = "../../../../scripts/strict-decode/replay.rs"]
mod replay;

use replay::{valued, Verdicts};

/// A decoded chunk with every decoded account blob and its decoded resource
/// blobs (ascending creatable index).
type DecodedChunk = (
    CatchpointSnapshotChunkV6,
    Vec<(CatchpointBaseAccountData, Vec<CatchpointResourcesData>)>,
);

/// What the importer does with a chunk before writing it (go:
/// `processStagingBalances` -> `prepareNormalizedBalancesV6`): decode the chunk,
/// then every account blob and every resource blob
/// (`decode_balance_record_blobs`, which the importer runs per record).
fn import_chunk_decode(b: &[u8]) -> Result<DecodedChunk, CatchpointError> {
    let chunk = decode_catchpoint_chunk(b)?;
    let mut blobs = Vec::new();
    for bal in &chunk.balances {
        let (ba, res) = decode_balance_record_blobs(bal)?;
        blobs.push((ba, res.into_iter().map(|(_, r)| r).collect()));
    }
    Ok((chunk, blobs))
}

// ── go's msgp encoding of the decoded values (issue #2421) ────────────────
//
// What go's generated `MarshalMsg` writes for the same go value: a map of the
// non-zero fields (`omitempty`) in sorted key order, minimal uints, `[N]byte`
// and `[]byte` as `bin`, `string` as `str`, `msgp.Raw` verbatim (`nil` when
// empty). The replay compares this with go's re-encode of what go decoded.

#[derive(Default)]
struct GoMap(Vec<(&'static str, Vec<u8>)>);

impl GoMap {
    fn raw(&mut self, k: &'static str, v: Vec<u8>) {
        self.0.push((k, v));
    }
    fn uint(&mut self, k: &'static str, v: u64) {
        if v != 0 {
            self.raw(k, uint(v));
        }
    }
    fn boolean(&mut self, k: &'static str, v: bool) {
        if v {
            self.raw(k, vec![0xc3]);
        }
    }
    /// A `[N]byte` (omitted when all zero).
    fn fixed(&mut self, k: &'static str, v: &[u8]) {
        if v.iter().any(|&x| x != 0) {
            self.raw(k, bin(v));
        }
    }
    /// A `[]byte` (omitted when empty).
    fn bytes(&mut self, k: &'static str, v: &[u8]) {
        if !v.is_empty() {
            self.raw(k, bin(v));
        }
    }
    fn string(&mut self, k: &'static str, v: &[u8]) {
        if !v.is_empty() {
            self.raw(k, string(v));
        }
    }
    /// A `msgp.Raw` (omitted when empty).
    fn msgp_raw(&mut self, k: &'static str, v: &[u8]) {
        if !v.is_empty() {
            self.raw(k, v.to_vec());
        }
    }
    /// A nested struct (omitted when its encoding is the empty map).
    fn object(&mut self, k: &'static str, v: Vec<u8>) {
        if v != [0x80] {
            self.raw(k, v);
        }
    }
    fn array(&mut self, k: &'static str, items: Vec<Vec<u8>>) {
        if !items.is_empty() {
            let mut out = Vec::new();
            rmp::encode::write_array_len(&mut out, items.len() as u32).expect("vec write");
            out.extend(items.concat());
            self.raw(k, out);
        }
    }
    fn finish(mut self) -> Vec<u8> {
        self.0.sort_by(|a, b| a.0.cmp(b.0));
        let mut out = Vec::new();
        rmp::encode::write_map_len(&mut out, self.0.len() as u32).expect("vec write");
        for (k, v) in self.0 {
            out.extend(string(k.as_bytes()));
            out.extend(v);
        }
        out
    }
}

fn uint(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    rmp::encode::write_uint(&mut out, v).expect("vec write");
    out
}

fn bin(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    rmp::encode::write_bin(&mut out, v).expect("vec write");
    out
}

fn string(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    rmp::encode::write_str_len(&mut out, v.len() as u32).expect("vec write");
    out.extend_from_slice(v);
    out
}

fn algo_count(c: &AlgoCount) -> Vec<u8> {
    let mut m = GoMap::default();
    m.uint("mon", c.money);
    m.uint("rwd", c.reward_units);
    m.finish()
}

fn account_totals(t: &AccountTotals) -> Vec<u8> {
    let mut m = GoMap::default();
    m.object("notpart", algo_count(&t.not_participating));
    m.object("offline", algo_count(&t.offline));
    m.object("online", algo_count(&t.online));
    m.uint("rwdlvl", t.rewards_level);
    m.finish()
}

fn header(h: &CatchpointFileHeader) -> Vec<u8> {
    let mut m = GoMap::default();
    m.object("accountTotals", account_totals(&h.totals));
    m.uint("accountsCount", h.total_accounts);
    m.uint("balancesRound", h.balances_round);
    m.fixed("blockHeaderDigest", &h.block_header_digest);
    m.uint("blocksRound", h.blocks_round);
    m.string("catchpoint", &algo_types::raw_text::decode(&h.catchpoint));
    m.uint("chunksCount", h.total_chunks);
    m.uint("kvsCount", h.total_kvs);
    m.uint("onlineAccountsCount", h.total_online_accounts);
    m.uint("onlineRoundParamsCount", h.total_online_round_params);
    m.uint("version", h.version);
    m.finish()
}

fn chunk(c: &CatchpointSnapshotChunkV6) -> Vec<u8> {
    let mut m = GoMap::default();
    m.array(
        "bl",
        c.balances
            .iter()
            .map(|b| {
                let mut r = GoMap::default();
                r.fixed("a", &b.address);
                r.msgp_raw("b", &b.account_data);
                if !b.resources.is_empty() {
                    let mut idx: Vec<_> = b.resources.keys().copied().collect();
                    idx.sort_unstable();
                    let mut out = Vec::new();
                    rmp::encode::write_map_len(&mut out, idx.len() as u32).expect("vec write");
                    for k in idx {
                        out.extend(uint(k));
                        // `msgp.Raw.MarshalMsg`: `nil` when empty
                        match b.resources[&k].as_slice() {
                            [] => out.push(0xc0),
                            v => out.extend_from_slice(v),
                        }
                    }
                    r.raw("c", out);
                }
                r.boolean("e", b.expecting_more_entries);
                r.finish()
            })
            .collect(),
    );
    m.array(
        "kv",
        c.kvs
            .iter()
            .map(|kv| {
                let mut r = GoMap::default();
                r.bytes("k", &kv.key);
                r.bytes("v", &kv.value);
                r.finish()
            })
            .collect(),
    );
    m.array(
        "oa",
        c.online_accounts
            .iter()
            .map(|oa| {
                let mut r = GoMap::default();
                r.fixed("addr", &oa.address);
                r.msgp_raw("data", &oa.data);
                r.uint("nob", oa.normalized_online_balance);
                r.uint("upd", oa.updated_round);
                r.uint("vlv", oa.vote_last_valid);
                r.finish()
            })
            .collect(),
    );
    m.array(
        "orp",
        c.online_round_params
            .iter()
            .map(|p| {
                let mut r = GoMap::default();
                r.msgp_raw("data", &p.data);
                r.uint("rnd", p.round);
                r.finish()
            })
            .collect(),
    );
    m.finish()
}

fn base_account_data(a: &CatchpointBaseAccountData) -> Vec<u8> {
    let mut m = GoMap::default();
    m.fixed("A", &a.vote_id);
    m.fixed("B", &a.selection_id);
    m.uint("C", a.vote_first_valid);
    m.uint("D", a.vote_last_valid);
    m.uint("E", a.vote_key_dilution);
    m.fixed("F", &a.state_proof_id);
    m.uint("a", a.status as u64);
    m.uint("b", a.micro_algos);
    m.uint("c", a.rewards_base);
    m.uint("d", a.rewarded_micro_algos);
    m.fixed("e", &a.auth_addr);
    m.uint("f", a.total_app_schema_num_uint);
    m.uint("g", a.total_app_schema_num_byte_slice);
    m.uint("h", a.total_extra_app_pages as u64);
    m.uint("i", a.total_asset_params);
    m.uint("j", a.total_assets);
    m.uint("k", a.total_app_params);
    m.uint("l", a.total_app_local_states);
    m.uint("m", a.total_boxes);
    m.uint("n", a.total_box_bytes);
    m.boolean("o", a.incentive_eligible);
    m.uint("p", a.last_proposed);
    m.uint("q", a.last_heartbeat);
    m.uint("z", a.update_round);
    m.finish()
}

fn value_bytes(v: rmpv::Value) -> Vec<u8> {
    match v {
        rmpv::Value::String(s) => s.into_bytes(),
        rmpv::Value::Binary(b) => b,
        _ => Vec::new(),
    }
}

/// A `basics.TealKeyValue` the reader keeps as raw msgpack: go's re-encode of
/// the map that raw value decodes to (sorted keys, a key repeated inside the
/// map keeps its last value, `TealValue` fields `omitempty`); `None` when go
/// omits it (nil or empty).
fn teal_key_value(raw_kv: &[u8]) -> Option<Vec<u8>> {
    if raw_kv.is_empty() {
        return None;
    }
    let v = rmpv::decode::read_value(&mut &raw_kv[..]).expect("a decoded TealKeyValue");
    let rmpv::Value::Map(entries) = v else {
        return None;
    };
    let mut kv = std::collections::BTreeMap::new();
    for (k, tv) in entries {
        let key = value_bytes(k);
        let (mut tb, mut tt, mut ui) = (Vec::new(), 0, 0);
        if let rmpv::Value::Map(fields) = tv {
            for (f, fv) in fields {
                match value_bytes(f).as_slice() {
                    b"tb" => tb = value_bytes(fv),
                    b"tt" => tt = fv.as_u64().unwrap_or(0),
                    b"ui" => ui = fv.as_u64().unwrap_or(0),
                    other => panic!("TealValue key {other:?}"),
                }
            }
        }
        let mut m = GoMap::default();
        m.string("tb", &tb);
        m.uint("tt", tt);
        m.uint("ui", ui);
        kv.insert(key, m.finish());
    }
    if kv.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    rmp::encode::write_map_len(&mut out, kv.len() as u32).expect("vec write");
    for (k, v) in kv {
        out.extend(string(&k));
        out.extend(v);
    }
    Some(out)
}

fn resources_data(r: &CatchpointResourcesData) -> Vec<u8> {
    let mut m = GoMap::default();
    m.uint("A", r.version);
    m.fixed("B", &r.size_sponsor);
    m.boolean("C", r.foreign_box_reads);
    m.boolean("D", r.family_box_access);
    m.uint("a", r.total);
    m.uint("b", r.decimals as u64);
    m.boolean("c", r.default_frozen);
    m.string("d", &r.unit_name);
    m.string("e", &r.asset_name);
    m.string("f", &r.url);
    m.fixed("g", &r.metadata_hash);
    m.fixed("h", &r.manager);
    m.fixed("i", &r.reserve);
    m.fixed("j", &r.freeze);
    m.fixed("k", &r.clawback);
    m.uint("l", r.amount);
    m.boolean("m", r.frozen);
    m.uint("n", r.schema_num_uint);
    m.uint("o", r.schema_num_byte_slice);
    if let Some(kv) = teal_key_value(&r.key_value) {
        m.raw("p", kv);
    }
    m.bytes("q", &r.approval_program);
    m.bytes("r", &r.clear_state_program);
    if let Some(kv) = teal_key_value(&r.global_state) {
        m.raw("s", kv);
    }
    m.uint("t", r.local_state_schema_num_uint);
    m.uint("u", r.local_state_schema_num_byte_slice);
    m.uint("v", r.global_state_schema_num_uint);
    m.uint("w", r.global_state_schema_num_byte_slice);
    m.uint("x", r.extra_program_pages as u64);
    m.uint("y", r.resource_flags as u64);
    m.uint("z", r.update_round);
    m.finish()
}

fn sp_verification(w: &CatchpointStateProofVerificationWrapper) -> Vec<u8> {
    let mut m = GoMap::default();
    m.array(
        "spd",
        w.data
            .iter()
            .map(|c| {
                let mut r = GoMap::default();
                r.uint("pw", c.online_total_weight);
                r.uint("spround", c.last_attested_round);
                r.string("v", &algo_types::raw_text::decode(&c.version));
                r.bytes("vc", &c.voters_commitment);
                r.finish()
            })
            .collect(),
    );
    m.finish()
}

fn verdicts(kind: &str, b: &[u8]) -> Verdicts {
    match kind {
        "cpheader" => vec![(
            "decode_catchpoint_header",
            valued(decode_catchpoint_header(b), header),
        )],
        "cpchunk" => vec![(
            "decode_catchpoint_chunk + account/resource blobs",
            valued(import_chunk_decode(b), |(c, blobs)| {
                let mut out = chunk(c);
                for (ba, res) in blobs {
                    out.extend(base_account_data(ba));
                    for r in res {
                        out.extend(resources_data(r));
                    }
                }
                out
            }),
        )],
        "cpspver" => vec![(
            "decode_state_proof_verification",
            valued(decode_state_proof_verification(b), sp_verification),
        )],
        other => panic!("unknown kind {other}"),
    }
}

/// Every committed mutant (and, with `STRICT_FUZZ_FILE`, every fuzz case): go's
/// verdict and decoded value equal the catchpoint reader's.
#[test]
fn catchpoint_readers_match_go_on_every_mutated_section() {
    replay::replay_committed_and_fuzz(env!("CARGO_MANIFEST_DIR"), "ledger", verdicts);
}
