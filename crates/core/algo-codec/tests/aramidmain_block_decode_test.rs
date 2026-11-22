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

//! aramidmain block 23132701 (issue #2439): a payment whose note is 8535
//! bytes, legal under `aramidmain-v1.0/3` (`MaxTxnNoteBytes` 131072). The
//! fixtures are the `GET /v2/blocks/{r}?format=msgpack` bodies served by
//! https://algod.aramidmain.a-wallet.net (go-algorand v4.7.3), byte for byte.
//!
//! go's msgp `allocbound` of `note` is `bounds.MaxTxnNoteBytes`, the maximum
//! of `MaxAbsoluteTxnNoteBytes` over every LOADED consensus protocol
//! (`config.checkSetAllocBounds`, run again by
//! `SetConfigurableConsensusProtocols` for a `consensus.json`). The vendored
//! `consensus.json` was written for go v4.7.3 and leaves that field out (0), so
//! the bound stays 4096 and go v5.0.5-stable rejects this block, loaded or not
//! (`msgp: length overflow: 8535 > 4096 at Txn at 0 at Payset at Block`);
//! algod-rust matches go (issue #2441; before it, the bound followed
//! `MaxTxnNoteBytes`, as go v4.7.3 does, and the block decoded).
//!
//! `install_consensus_overrides` is a process-global write-once: this test
//! binary holds this one test only.

use algo_codec::{
    canonical_encode_block, compute_block_digest, decode_block, decode_block_response,
};
use algo_types::consensus::{
    built_in_consensus_protocols, install_consensus_overrides,
    preload_consensus_protocols_with_bundle,
};

const BUNDLE: &str = include_str!("../../../../bin/algod-rust/consensus/aramidmain-consensus.json");
const BLOCK_23132701: &[u8] = include_bytes!("fixtures/aramidmain/block_23132701.msgpack");
const BLOCK_23132702: &[u8] = include_bytes!("fixtures/aramidmain/block_23132702.msgpack");

/// The `block` value of a `{"block", "cert"}` response, as the served bytes.
fn block_bytes(body: &[u8]) -> &[u8] {
    let mut rd = body;
    let n = rmp::decode::read_map_len(&mut rd).expect("response map");
    for _ in 0..n {
        let klen = rmp::decode::read_str_len(&mut rd).expect("key") as usize;
        let (key, after) = rd.split_at(klen);
        let vlen = algo_types::msgpack_value_len(after).expect("value");
        if key == b"block" {
            return &after[..vlen];
        }
        rd = &after[vlen..];
    }
    panic!("no block key");
}

#[test]
fn aramidmain_block_with_a_large_note_is_refused_even_with_the_network_protocols_loaded() {
    // Built-in table only: go's verdict (bounds.MaxTxnNoteBytes = 4096).
    let err = decode_block_response(BLOCK_23132701).expect_err("4096-byte note bound");
    assert!(
        format!("{err:?}").contains("8535"),
        "the note's length header is what is refused: {err:?}"
    );

    let merged =
        preload_consensus_protocols_with_bundle(None, built_in_consensus_protocols(), Some(BUNDLE))
            .unwrap();
    install_consensus_overrides(&merged);
    // `MaxAbsoluteTxnNoteBytes` is unset (0) in the file: no bound is raised.
    assert_eq!(algo_types::go_msgp::bounds::MAX_TXN_NOTE_BYTES.get(), 4096);
    let err = decode_block_response(BLOCK_23132701).expect_err("still the 4096-byte bound");
    assert!(
        format!("{err:?}").contains("8535"),
        "the note's length header is what is refused: {err:?}"
    );

    // go wrote it canonically, and its hash is the next block's `prev`: the
    // block is fine under the bound go v4.7.3 used, which a protocol that sets
    // `MaxAbsoluteTxnNoteBytes` brings back.
    let mut p = algo_types::consensus::consensus_params_for_version("future").unwrap();
    p.max_absolute_txn_note_bytes = 131_072;
    algo_types::consensus::check_set_alloc_bounds(&p);
    let resp = decode_block_response(BLOCK_23132701).expect("aramidmain block decodes");
    assert_eq!(resp.block.round.0, 23_132_701);
    assert_eq!(resp.block.payset.len(), 1);
    assert_eq!(resp.block.payset[0].txn.note.len(), 8535);
    assert!(resp.cert.is_some());
    let raw = block_bytes(BLOCK_23132701);
    let blk = decode_block(raw).unwrap();
    assert!(canonical_encode_block(&blk) == raw, "canonical re-encode");
    let next = decode_block_response(BLOCK_23132702).unwrap().block;
    assert_eq!(compute_block_digest(&blk).0, next.branch);
}
