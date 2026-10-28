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

//! Reader for the deterministic workload block corpus (issue #2104, epic
//! #2101), the input of the `replay` bench tier.
//!
//! A corpus directory (`benchmarks/corpus/small/`, or the fetched `large`)
//! holds `blocks.bin`, `genesis.json`, `node-config.json`, `consensus.json`,
//! `corpus.json` and `MANIFEST.sha256`; the layout is documented in the
//! "Workload corpus" section of `docs/BENCHMARK_COMPARISON.md`.
//!
//! `blocks.bin` is the magic `ACRPBLK1` followed by one record per round
//! `0..=N`: `round: u64 BE`, `len: u32 BE`, then `len` bytes that are the
//! exact `/v2/blocks/{round}?format=msgpack` response (block + cert).
//!
//! [`Histogram`] recomputes `corpus.json`'s txn census from blocks decoded by
//! the production `algo-codec` decoder; its definitions mirror
//! `benchmarks/go-corpus/record.go` exactly.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use algo_types::genesis_restore::GenesisRestoreRule;
use algo_types::{Address, Block, SignedTransaction, Transaction, TxnType};
use sha2::{Digest as _, Sha256};

/// Magic bytes at the start of `blocks.bin`.
pub const BLOCKS_MAGIC: &[u8; 8] = b"ACRPBLK1";
/// Name of the manifest file in a corpus directory.
pub const MANIFEST: &str = "MANIFEST.sha256";

/// One `blocks.bin` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRecord<'a> {
    /// Round the record claims to hold.
    pub round: u64,
    /// The raw `/v2/blocks/{round}?format=msgpack` response body.
    pub payload: &'a [u8],
}

/// Split a `blocks.bin` stream into its records (no decoding).
pub fn parse_blocks(bytes: &[u8]) -> Result<Vec<BlockRecord<'_>>, String> {
    let rest = bytes
        .strip_prefix(BLOCKS_MAGIC.as_slice())
        .ok_or_else(|| "blocks.bin: bad magic (expected ACRPBLK1)".to_string())?;
    let mut out = Vec::new();
    let mut rest = rest;
    while !rest.is_empty() {
        if rest.len() < 12 {
            return Err(format!(
                "blocks.bin: truncated record header after {} records",
                out.len()
            ));
        }
        let round = u64::from_be_bytes(rest[0..8].try_into().expect("8 bytes"));
        let len = u32::from_be_bytes(rest[8..12].try_into().expect("4 bytes")) as usize;
        let body = &rest[12..];
        if body.len() < len {
            return Err(format!("blocks.bin: record for round {round} truncated"));
        }
        out.push(BlockRecord {
            round,
            payload: &body[..len],
        });
        rest = &body[len..];
    }
    Ok(out)
}

/// Hex sha256 of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Parse `MANIFEST.sha256` text into `name -> digest`.
///
/// Accepts exactly what `scripts/bench/corpus/corpus_tool.py`
/// `parse_manifest` accepts (shared vectors:
/// `scripts/bench/testdata/corpus/manifest_vectors.json`): blank lines are
/// skipped; every other line is a 64-char lowercase hex digest, two spaces
/// and a plain file name of the corpus directory itself. A name containing
/// `/` or `\`, the names `.` and `..`, the manifest itself and duplicate
/// entries are rejected, so verification can never read outside the corpus.
pub fn parse_manifest(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut listed = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let malformed = || format!("{MANIFEST} line {}: malformed: {line:?}", i + 1);
        let (digest, name) = line.split_once("  ").ok_or_else(malformed)?;
        let hex_ok = digest.len() == 64
            && digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
        let name_ok = !name.is_empty()
            && !name.contains('/')
            && !name.contains('\\')
            && name != "."
            && name != ".."
            && name != MANIFEST;
        if !hex_ok || !name_ok {
            return Err(malformed());
        }
        if listed
            .insert(name.to_string(), digest.to_string())
            .is_some()
        {
            return Err(format!("{MANIFEST} line {}: duplicate entry {name}", i + 1));
        }
    }
    Ok(listed)
}

/// Check every `MANIFEST.sha256` entry of `dir` and that no file is unlisted.
pub fn verify_manifest(dir: &Path) -> Result<(), String> {
    let raw = fs::read(dir.join(MANIFEST)).map_err(|e| format!("{MANIFEST}: {e}"))?;
    if raw.contains(&b'\r') {
        return Err(format!(
            "{MANIFEST} contains CR bytes: a line-ending conversion touched the corpus \
             (benchmarks/corpus/** must be -text in .gitattributes)"
        ));
    }
    let text = String::from_utf8(raw).map_err(|e| format!("{MANIFEST}: {e}"))?;
    let listed = parse_manifest(&text)?;
    let mut errors = Vec::new();
    for (name, digest) in &listed {
        let path = dir.join(name);
        if !path.is_file() {
            errors.push(format!("{name}: listed in {MANIFEST} but missing"));
            continue;
        }
        match fs::read(&path) {
            Ok(b) if &sha256_hex(&b) == digest => {}
            Ok(_) => errors.push(format!("{name}: sha256 mismatch")),
            Err(e) => errors.push(format!("{name}: {e}")),
        }
    }
    let entries = fs::read_dir(dir).map_err(|e| e.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.path().is_file() && name != MANIFEST && !listed.contains_key(&name) {
            errors.push(format!("{name}: present but not listed in {MANIFEST}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// `corpus.json`'s txn census. Keys only appear once counted (like the Go
/// maps), so two histograms compare equal exactly when the counts do.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Histogram {
    /// Top-level txn type -> count.
    pub types: BTreeMap<String, u64>,
    /// `type.subtype` -> count (see [`subtype`]).
    pub subtypes: BTreeMap<String, u64>,
    /// Inner txn type -> count (all nesting levels).
    pub inner_types: BTreeMap<String, u64>,
    /// Feature counters: groups, grouped_txns, rekey_txns, auth_addr_txns,
    /// inner_txns, app_{global,local}_delta_txns, app_box_ref_txns,
    /// empty_blocks.
    pub features: BTreeMap<String, u64>,
}

fn bump(m: &mut BTreeMap<String, u64>, k: &str) {
    *m.entry(k.to_string()).or_insert(0) += 1;
}

fn nonzero(a: &Option<Address>) -> bool {
    a.as_ref().is_some_and(|a| !a.is_zero())
}

/// The workload subtype of a top-level txn (mirrors go-corpus `subtype`).
pub fn subtype(t: &Transaction) -> &'static str {
    match t.txn_type {
        TxnType::Pay => {
            if t.close_remainder_to.is_zero() {
                "payment"
            } else {
                "close"
            }
        }
        TxnType::Axfer => {
            if nonzero(&t.asset_close_to) {
                "close"
            } else if nonzero(&t.asset_sender) {
                "clawback"
            } else if t.asset_amount == 0 && t.asset_receiver.unwrap_or(Address::ZERO) == t.sender {
                "optin"
            } else {
                "transfer"
            }
        }
        TxnType::Acfg => {
            if t.config_asset == 0 {
                "create"
            } else if t
                .asset_params
                .as_ref()
                .is_none_or(|p| *p == Default::default())
            {
                "destroy"
            } else {
                "reconfigure"
            }
        }
        TxnType::Afrz => {
            if t.asset_frozen {
                "freeze"
            } else {
                "unfreeze"
            }
        }
        TxnType::Appl => {
            if t.application_id == 0 {
                return "create";
            }
            match t.on_completion {
                0 => "call",
                1 => "optin",
                2 => "closeout",
                3 => "clear",
                4 => "update",
                5 => "delete",
                _ => "other",
            }
        }
        TxnType::Keyreg => {
            if t.non_participation {
                "nonparticipation"
            } else if t.vote_pk.is_some_and(|k| k != [0u8; 32]) {
                "online"
            } else {
                "offline"
            }
        }
        _ => "other",
    }
}

fn map_get<'a>(v: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    v.as_map()?.iter().find_map(|(k, val)| {
        let matches = match k {
            rmpv::Value::String(s) => s.as_bytes() == key.as_bytes(),
            rmpv::Value::Binary(b) => b.as_slice() == key.as_bytes(),
            _ => false,
        };
        matches.then_some(val)
    })
}

fn non_empty_map(v: Option<&rmpv::Value>) -> bool {
    v.and_then(|v| v.as_map()).is_some_and(|m| !m.is_empty())
}

impl Histogram {
    fn inner(&mut self, eval_delta: Option<&rmpv::Value>) {
        let Some(itx) = eval_delta
            .and_then(|dt| map_get(dt, "itx"))
            .and_then(|v| v.as_array())
        else {
            return;
        };
        for inner in itx {
            let ty = map_get(inner, "txn")
                .and_then(|t| map_get(t, "type"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            bump(&mut self.inner_types, &ty);
            bump(&mut self.features, "inner_txns");
            self.inner(map_get(inner, "dt"));
        }
    }

    /// Count one block's payset (mirrors go-corpus `histogram.addBlock`).
    pub fn add_block(&mut self, payset: &[SignedTransaction]) {
        if payset.is_empty() {
            bump(&mut self.features, "empty_blocks");
        }
        let mut last_group = [0u8; 32];
        for (i, st) in payset.iter().enumerate() {
            let t = &st.txn;
            let ty = t.txn_type.as_str();
            bump(&mut self.types, ty);
            bump(&mut self.subtypes, &format!("{ty}.{}", subtype(t)));
            if t.group != [0u8; 32] {
                bump(&mut self.features, "grouped_txns");
                if i == 0 || t.group != last_group {
                    bump(&mut self.features, "groups");
                }
                last_group = t.group;
            } else {
                last_group = [0u8; 32];
            }
            if nonzero(&t.rekey_to) {
                bump(&mut self.features, "rekey_txns");
            }
            if nonzero(&st.auth_addr) {
                bump(&mut self.features, "auth_addr_txns");
            }
            if t.txn_type == TxnType::Appl {
                let dt = st.eval_delta.as_ref();
                if non_empty_map(dt.and_then(|d| map_get(d, "gd"))) {
                    bump(&mut self.features, "app_global_delta_txns");
                }
                if non_empty_map(dt.and_then(|d| map_get(d, "ld"))) {
                    bump(&mut self.features, "app_local_delta_txns");
                }
                if t.boxes.as_ref().is_some_and(|b| !b.is_empty()) {
                    bump(&mut self.features, "app_box_ref_txns");
                }
            }
            self.inner(st.eval_delta.as_ref());
        }
    }
}

/// The TxIDs of a block's top-level txns, in payset order, with the stripped
/// genesis id/hash restored the way go's `DecodeSignedTxn` does.
pub fn block_txids(block: &Block) -> Vec<[u8; 32]> {
    let rule = GenesisRestoreRule::for_block(block);
    block
        .payset
        .iter()
        .map(|st| {
            let (id, hash) = rule.restored_genesis(st);
            algo_codec::compute_txn_id_with_genesis(&st.txn, id, hash).0
        })
        .collect()
}

/// go's `BlockHash.String()`: `blk-` + unpadded base32 of the digest.
pub fn block_hash_string(digest: &[u8; 32]) -> String {
    format!("blk-{}", data_encoding::BASE32_NOPAD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_blocks_round_trip_and_errors() {
        let mut b = BLOCKS_MAGIC.to_vec();
        for (r, p) in [(0u64, &b"ab"[..]), (1, &b""[..]), (2, &b"xyz"[..])] {
            b.extend_from_slice(&r.to_be_bytes());
            b.extend_from_slice(&(p.len() as u32).to_be_bytes());
            b.extend_from_slice(p);
        }
        let recs = parse_blocks(&b).unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(
            recs[2],
            BlockRecord {
                round: 2,
                payload: b"xyz"
            }
        );
        assert!(
            parse_blocks(&b[..b.len() - 1]).is_err(),
            "truncated payload"
        );
        assert!(parse_blocks(b"NOTMAGIC").is_err(), "bad magic");
    }

    /// The vectors corpus_tool.py's tests run too: both parsers must accept
    /// exactly the same manifests.
    #[test]
    fn parse_manifest_matches_the_shared_python_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/bench/testdata/corpus/manifest_vectors.json");
        let v: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let vectors = v["vectors"].as_array().unwrap();
        assert!(vectors.len() > 10);
        let hex64 = "0123456789abcdef".repeat(4);
        for vec in vectors {
            let name = vec["name"].as_str().unwrap();
            let text: String = vec["text"]
                .as_str()
                .unwrap()
                .split_inclusive('\n')
                .map(|l| match l.strip_prefix("H ") {
                    Some(rest) => format!("{hex64} {rest}"),
                    None => l.to_string(),
                })
                .collect();
            let got = parse_manifest(&text);
            if vec["valid"].as_bool().unwrap() {
                assert!(got.is_ok(), "{name}: rejected: {got:?}");
            } else {
                assert!(got.is_err(), "{name}: accepted {text:?}");
            }
        }
    }

    #[test]
    fn verify_manifest_rejects_escape_and_unlisted() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("c");
        fs::create_dir(&d).unwrap();
        fs::write(d.join("a.bin"), b"abc").unwrap();
        let line = format!("{}  a.bin\n", sha256_hex(b"abc"));
        fs::write(d.join(MANIFEST), &line).unwrap();
        assert_eq!(verify_manifest(&d), Ok(()));
        // A file outside the corpus directory must never be consulted.
        fs::write(dir.path().join("outside.bin"), b"x").unwrap();
        let esc = format!("{line}{}  ../outside.bin\n", sha256_hex(b"x"));
        fs::write(d.join(MANIFEST), esc).unwrap();
        assert!(verify_manifest(&d).unwrap_err().contains("malformed"));
        fs::write(d.join(MANIFEST), &line).unwrap();
        fs::write(d.join("extra.bin"), b"1").unwrap();
        assert!(verify_manifest(&d)
            .unwrap_err()
            .contains("extra.bin: present but not listed"));
    }

    #[test]
    fn block_hash_string_matches_go_format() {
        // go: BlockHash{}.String() == "blk-" + 52 'A's.
        assert_eq!(
            block_hash_string(&[0u8; 32]),
            format!("blk-{}", "A".repeat(52))
        );
    }
}
