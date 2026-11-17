// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict unknown-field parity of the identity-handshake and tx-sync decoders
//! with go-algorand (issue #2396).
//!
//! go decodes the three netidentity messages with `protocol.Decode` (generated
//! msgp decoders, `msgp.ErrNoField` on a key the struct lacks,
//! `network/netidentity.go`) and a tx-sync response with
//! `protocol.DecodeReflect` (`protocol.CodecHandle`, `ErrorIfNoField = true`,
//! `rpcs/httpTxSync.go`). `tests/fixtures/strict_decode/` holds valid messages
//! (`seeds.jsonl`) and mutants of them with go's verdict (`cases.jsonl`), from
//! `scripts/strict-decode/strict_decode_fixtures.py --set network`
//! (tools/strict-decode-oracle/network_oracle_test.go.txt and the `txsync`
//! kind of rpcs_oracle_test.go.txt).

use algo_network::identity::{
    decode_identity_challenge_response_signed, decode_identity_challenge_signed,
    decode_identity_verification_message_signed,
};
use algo_network::tx_sync_client::decode_tx_sync_response;

#[path = "../../../../scripts/strict-decode/replay.rs"]
mod replay;

use replay::{verdict, Verdicts};

fn verdicts(kind: &str, b: &[u8]) -> Verdicts {
    match kind {
        "idchal" => vec![(
            "decode_identity_challenge_signed",
            verdict(decode_identity_challenge_signed(b)),
        )],
        "idresp" => vec![(
            "decode_identity_challenge_response_signed",
            verdict(decode_identity_challenge_response_signed(b)),
        )],
        "idverify" => vec![(
            "decode_identity_verification_message_signed",
            verdict(decode_identity_verification_message_signed(b)),
        )],
        "txsync" => vec![(
            "decode_tx_sync_response",
            verdict(decode_tx_sync_response(b)),
        )],
        other => panic!("unknown kind {other}"),
    }
}

/// Every committed mutant (and, with `STRICT_FUZZ_FILE`, every fuzz case): go's
/// verdict equals algod-rust's.
#[test]
fn identity_and_tx_sync_decoders_match_go_on_every_mutated_message() {
    replay::replay_committed_and_fuzz(env!("CARGO_MANIFEST_DIR"), "network", verdicts);
}
