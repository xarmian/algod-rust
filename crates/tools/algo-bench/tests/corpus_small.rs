// Copyright (c) 2026 Algod DAO
//
// SPDX-License-Identifier: MIT
// For the full license text, see LICENSE-MIT at the repository root.

//! The committed `small` workload corpus (issue #2104) decodes with the
//! production `algo-codec` decoder and matches its `corpus.json`:
//!
//! * `MANIFEST.sha256` verifies (and has no CR bytes: the corpus must reach
//!   the working tree byte-exact, see `.gitattributes`);
//! * `blocks.bin` holds consecutive rounds `0..=N`, each a block + cert that
//!   the serde and the fast rmp decoders both accept and agree on;
//! * the hash chain holds: every block's `prev` / `prev512` equals the
//!   SHA-512/256 / SHA-512 header digest of the previous block, computed by
//!   the production `algo-codec` code;
//! * the txn-type histogram, the txid fingerprint (TxIDs computed by
//!   `algo-codec`), the final block hash and txn counter equal `corpus.json`.

use std::fs;
use std::path::PathBuf;

use algo_bench::corpus::{self, Histogram};
use sha2::{Digest as _, Sha256, Sha512};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../benchmarks/corpus/small")
}

fn header_digest_512(block: &algo_types::Block) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"BH");
    h.update(algo_codec::canonical_encode_block_header_from_block(block));
    h.finalize().into()
}

#[test]
fn small_corpus_decodes_and_matches_corpus_json() {
    let dir = corpus_dir();
    corpus::verify_manifest(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));

    let meta: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("corpus.json")).unwrap()).unwrap();
    assert_eq!(meta["schema"], "algod-corpus/v1");
    let blocks_file = meta["files"]["blocks"].as_str().unwrap();
    let bytes = fs::read(dir.join(blocks_file)).unwrap();
    let records = corpus::parse_blocks(&bytes).unwrap();
    let last = meta["rounds"]["last"].as_u64().unwrap();
    assert_eq!(
        records.len() as u64,
        meta["rounds"]["count"].as_u64().unwrap()
    );
    assert_eq!(records.len() as u64, last + 1);

    let genesis_hash = data_encoding::BASE64
        .decode(meta["network"]["genesis_hash"].as_str().unwrap().as_bytes())
        .unwrap();
    let genesis_id = meta["network"]["genesis_id"].as_str().unwrap();
    let proto = meta["network"]["consensus_version"].as_str().unwrap();

    let mut hist = Histogram::default();
    let mut txids = Sha256::new();
    let mut txns = 0u64;
    let mut prev: Option<algo_types::Block> = None;
    for (i, rec) in records.iter().enumerate() {
        assert_eq!(
            rec.round, i as u64,
            "records must be consecutive rounds from 0"
        );
        let resp = algo_codec::decode_block_response(rec.payload)
            .unwrap_or_else(|e| panic!("round {}: {e}", rec.round));
        let fast = algo_codec::decode_block_response_fast(rec.payload)
            .unwrap_or_else(|e| panic!("round {} (fast decoder): {e}", rec.round));
        assert_eq!(
            resp.block, fast.block,
            "round {}: serde and fast decoders disagree",
            rec.round
        );
        let block = resp.block;
        assert_eq!(
            block.round.0, rec.round,
            "record {} holds block {}",
            rec.round, block.round.0
        );
        assert_eq!(block.genesis_id, genesis_id);
        assert_eq!(block.genesis_hash.as_slice(), genesis_hash.as_slice());
        assert_eq!(block.current_protocol, proto);
        let cert = resp
            .cert
            .as_ref()
            .unwrap_or_else(|| panic!("round {}: no cert", rec.round));
        let cert_round = cert
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("rnd")))
            .and_then(|(_, v)| v.as_u64())
            .unwrap_or(0);
        assert_eq!(cert_round, rec.round, "cert round");
        if let Some(p) = &prev {
            assert_eq!(
                block.branch,
                algo_codec::compute_block_digest(p).0,
                "round {}: prev != digest(block {})",
                rec.round,
                p.round.0
            );
            assert_eq!(
                block.prev512,
                header_digest_512(p),
                "round {}: prev512",
                rec.round
            );
            hist.add_block(&block.payset);
            for id in corpus::block_txids(&block) {
                txids.update(id);
                txns += 1;
            }
        } else {
            assert!(block.payset.is_empty(), "the genesis block has no txns");
        }
        prev = Some(block);
    }

    let want: Histogram = serde_json::from_value(meta["histogram"].clone()).unwrap();
    assert_eq!(
        hist, want,
        "histogram recomputed from the Rust-decoded blocks"
    );
    assert_eq!(txns, meta["txns"].as_u64().unwrap());
    assert_eq!(
        hex::encode(txids.finalize()),
        meta["txids_sha256"].as_str().unwrap(),
        "txids"
    );

    let last_block = prev.unwrap();
    let fs_ = &meta["final_state"];
    assert_eq!(last_block.round.0, fs_["round"].as_u64().unwrap());
    assert_eq!(last_block.txn_counter, fs_["txn_counter"].as_u64().unwrap());
    assert_eq!(
        corpus::block_hash_string(&algo_codec::compute_block_digest(&last_block).0),
        fs_["block_hash"].as_str().unwrap()
    );

    // Issue #2104: every workload kind is present.
    for k in [
        "pay.payment",
        "pay.close",
        "axfer.optin",
        "axfer.transfer",
        "axfer.clawback",
        "axfer.close",
        "afrz.freeze",
        "afrz.unfreeze",
        "acfg.create",
        "acfg.reconfigure",
        "acfg.destroy",
        "appl.create",
        "appl.call",
        "appl.optin",
        "appl.closeout",
        "appl.clear",
        "appl.update",
        "appl.delete",
        "keyreg.online",
        "keyreg.offline",
    ] {
        assert!(
            hist.subtypes.get(k).copied().unwrap_or(0) > 0,
            "no {k} txns"
        );
    }
    for k in [
        "groups",
        "inner_txns",
        "rekey_txns",
        "auth_addr_txns",
        "app_global_delta_txns",
        "app_local_delta_txns",
        "app_box_ref_txns",
    ] {
        assert!(
            hist.features.get(k).copied().unwrap_or(0) > 0,
            "feature {k} is zero"
        );
    }
    for k in ["pay", "axfer", "appl"] {
        assert!(
            hist.inner_types.get(k).copied().unwrap_or(0) > 0,
            "no inner {k} txns"
        );
    }
}

/// The corpus is replayable by algod-rust: its own genesis loader builds the
/// same round-0 block the go node served, and the production ledger applies
/// every block (devmode chain: no proposer, see `set_devmode_chain`) to the
/// recorded final txn counter and total money. The timed, final-state-gated
/// Go-vs-Rust replay is the `replay` tier (#2105); this is its smoke test.
#[test]
fn small_corpus_replays_through_the_rust_ledger() {
    use algo_ledger::{
        make_genesis_block, parse_genesis_json, populate_store, seed_account_totals_from_genesis,
        LedgerStore, SqliteLedger,
    };

    let dir = corpus_dir();
    let meta: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("corpus.json")).unwrap()).unwrap();
    let genesis =
        parse_genesis_json(&fs::read_to_string(dir.join("genesis.json")).unwrap()).unwrap();
    assert!(genesis.devmode);
    assert_eq!(
        data_encoding::BASE64.encode(&algo_ledger::genesis::genesis_hash(&genesis)),
        meta["network"]["genesis_hash"].as_str().unwrap(),
        "Rust genesis hash of genesis.json"
    );

    let mut l = SqliteLedger::open_in_memory().unwrap();
    l.set_devmode_chain(true);
    l.begin_block().unwrap();
    populate_store(&mut l, &genesis).unwrap();
    seed_account_totals_from_genesis(&mut l, &genesis).unwrap();
    let gblk = make_genesis_block(&genesis).unwrap();
    let hdr = algo_codec::canonical_encode_block_header_from_block(&gblk);
    let blk = algo_codec::canonical_encode_block(&gblk);
    l.put_block(0, &gblk.current_protocol, &hdr, &blk).unwrap();
    l.set_txn_counter(gblk.txn_counter);
    l.commit_block().unwrap();

    let bytes = fs::read(dir.join(meta["files"]["blocks"].as_str().unwrap())).unwrap();
    let records = corpus::parse_blocks(&bytes).unwrap();
    let served0 = algo_codec::decode_block_response(records[0].payload)
        .unwrap()
        .block;
    assert_eq!(
        algo_codec::compute_block_digest(&served0),
        algo_codec::compute_block_digest(&gblk),
        "algod-rust's genesis block differs from the round-0 block go-algorand served"
    );
    for rec in &records[1..] {
        let block = algo_codec::decode_block_response(rec.payload)
            .unwrap()
            .block;
        l.begin_block().unwrap();
        l.apply_block_caching_delta(&block)
            .unwrap_or_else(|e| panic!("round {}: {e}", rec.round));
        l.commit_block().unwrap();
    }
    let fs_ = &meta["final_state"];
    assert_eq!(
        l.txn_counter(),
        fs_["txn_counter"].as_u64().unwrap(),
        "txn counter"
    );
    let totals = l.account_totals();
    assert_eq!(
        totals.online.money + totals.offline.money,
        fs_["total_money"].as_u64().unwrap(),
        "total money (online + offline) after replay"
    );
}
