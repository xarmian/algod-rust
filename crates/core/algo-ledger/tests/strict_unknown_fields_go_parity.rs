// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict unknown-field parity of the catchpoint file readers with go-algorand
//! (issue #2396).
//!
//! go's catchpoint restore (`ledger/catchupaccessor.go`) decodes every section
//! with `protocol.Decode` (generated msgp decoders: a key the struct lacks is
//! `msgp.ErrNoField`) and then decodes each balance record's `msgp.Raw` account
//! and resource blobs (`prepareNormalizedBalancesV6`), so a catchpoint file
//! with an unknown key anywhere in those is rejected. `tests/fixtures/
//! strict_decode/` holds sections of go-written catchpoints and go-encoded
//! random ones (`seeds.jsonl`) and mutants of them with go's verdict
//! (`cases.jsonl`), from `scripts/strict-decode/strict_decode_fixtures.py
//! --set ledger` (tools/strict-decode-oracle/ledger_oracle_test.go.txt).

use algo_ledger::catchpoint::msgp_compat::{decode_base_account_data, decode_resources_data};
use algo_ledger::catchpoint::parser::{
    decode_catchpoint_chunk, decode_catchpoint_header, decode_state_proof_verification,
};
use algo_ledger::catchpoint::CatchpointError;

#[path = "../../../../scripts/strict-decode/replay.rs"]
mod replay;

use replay::{verdict, Verdicts};

/// What the importer does with a chunk before writing it (go:
/// `processStagingBalances` -> `prepareNormalizedBalancesV6`): decode the chunk,
/// then every account blob and every resource blob.
fn import_chunk_decode(b: &[u8]) -> Result<(), CatchpointError> {
    let chunk = decode_catchpoint_chunk(b)?;
    for bal in &chunk.balances {
        decode_base_account_data(&bal.account_data)?;
        for res in bal.resources.values() {
            decode_resources_data(res)?;
        }
    }
    Ok(())
}

fn verdicts(kind: &str, b: &[u8]) -> Verdicts {
    match kind {
        "cpheader" => vec![(
            "decode_catchpoint_header",
            verdict(decode_catchpoint_header(b)),
        )],
        "cpchunk" => vec![(
            "decode_catchpoint_chunk + account/resource blobs",
            verdict(import_chunk_decode(b)),
        )],
        "cpspver" => vec![(
            "decode_state_proof_verification",
            verdict(decode_state_proof_verification(b)),
        )],
        other => panic!("unknown kind {other}"),
    }
}

/// Every committed mutant (and, with `STRICT_FUZZ_FILE`, every fuzz case): go's
/// verdict equals the catchpoint reader's.
#[test]
fn catchpoint_readers_match_go_on_every_mutated_section() {
    replay::replay_committed_and_fuzz(env!("CARGO_MANIFEST_DIR"), "ledger", verdicts);
}
