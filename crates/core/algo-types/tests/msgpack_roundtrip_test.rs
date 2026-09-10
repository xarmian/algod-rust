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

//! Msgpack self-roundtrip coverage for algo-types data types that go's
//! `msgp_gen_test.go`-generated `TestMarshalUnmarshal*`/
//! `TestRandomizedEncoding*` pairs exercise directly, but which algod-rust
//! previously only exercised indirectly through canonical-encoding,
//! genesis-load, or block-fixture tests (Phase 17, issue #961):
//!
//! - `StateSchema` (~ go's `basics.StateSchema` /
//!   `data/basics/msgp_gen_test.go`'s `TestMarshalUnmarshalStateSchema(s)`).
//!   algod-rust has no separate `StateSchemas` (local+global pair) wire
//!   type — go's `basics.StateSchemas{Local, Global StateSchema}` is
//!   represented here as two independent `Option<StateSchema>` fields
//!   inline on `ApplicationCallFields`
//!   (`local_state_schema`/`global_state_schema`, `transaction.rs`), so
//!   `StateSchema` itself is the type under test for both.
//! - `BlockHeader` (~ go's `bookkeeping.BlockHeader` /
//!   `data/bookkeeping/msgp_gen_test.go`'s `TestMarshalUnmarshalBlockHeader`)
//!   — a *direct* round-trip of the type, distinct from the existing
//!   canonical-encoding/genesis/block-fixture coverage elsewhere.
//! - `ParticipationUpdates` (~ go's `bookkeeping.ParticipationUpdates` /
//!   `TestMarshalUnmarshalParticipationUpdates`). Like `StateSchemas`, go's
//!   struct (`ExpiredParticipationAccounts`/`AbsentParticipationAccounts`)
//!   is flattened directly onto `BlockHeader` here
//!   (`expired_participation_accounts`/`absent_participation_accounts`)
//!   rather than nested, so its round-trip is covered as part of
//!   `BlockHeader`'s below (`block_header_participation_updates_roundtrips`
//!   exercises both fields populated, matching go's non-empty case).
//! - `StateProofMessage` (~ go's `stateproofmsg.Message` /
//!   `data/stateproofmsg/msgp_gen_test.go`'s `TestMarshalUnmarshalMessage`).
//!
//! Uses this repo's established byte-stability pattern (encode, decode,
//! re-encode, assert bytes match — see
//! `crates/node/algo-rest-api/tests/msgpack_model_roundtrip_test.rs`) plus a
//! decoded-value equality check, since every type here derives `PartialEq`.

use algo_types::{Address, BlockHeader, Round, StateProofMessage, StateSchema};
use serde_bytes::ByteBuf;

fn assert_msgpack_roundtrips<T>(value: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let encoded = rmp_serde::to_vec_named(value).expect("encode");
    let decoded: T = rmp_serde::from_slice(&encoded).expect("decode");
    assert_eq!(value, &decoded, "decoded value must equal the original");
    let re_encoded = rmp_serde::to_vec_named(&decoded).expect("re-encode");
    assert_eq!(
        encoded, re_encoded,
        "msgpack roundtrip must be byte-stable (no data loss)"
    );
}

// ---------------------------------------------------------------------------
// StateSchema (~ go's basics.StateSchema / basics.StateSchemas pair)
// ---------------------------------------------------------------------------

#[test]
fn state_schema_zero_value_roundtrips() {
    assert_msgpack_roundtrips(&StateSchema::default());
}

#[test]
fn state_schema_populated_roundtrips() {
    let v = StateSchema {
        num_uint: 12,
        num_byte_slice: 34,
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn state_schemas_pair_roundtrips() {
    // go's basics.StateSchemas{Local, Global} — algod-rust has no nested
    // pair type (see module doc), so exercise both halves of the pair
    // independently, as `ApplicationCallFields` does.
    let local = StateSchema {
        num_uint: 1,
        num_byte_slice: 2,
    };
    let global = StateSchema {
        num_uint: 3,
        num_byte_slice: 4,
    };
    assert_msgpack_roundtrips(&local);
    assert_msgpack_roundtrips(&global);
}

#[test]
fn state_schema_randomized_field_combinations_roundtrip() {
    let mut state: u64 = 0x1111_2222_3333_4444;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };
    for _ in 0..32u64 {
        let r = next();
        let v = StateSchema {
            num_uint: r % 1000,
            num_byte_slice: (r >> 16) % 1000,
        };
        assert_msgpack_roundtrips(&v);
    }
}

// ---------------------------------------------------------------------------
// StateProofMessage (~ go's stateproofmsg.Message)
// ---------------------------------------------------------------------------

#[test]
fn state_proof_message_zero_value_roundtrips() {
    assert_msgpack_roundtrips(&StateProofMessage::default());
}

#[test]
fn state_proof_message_populated_roundtrips() {
    let v = StateProofMessage {
        block_headers_commitment: ByteBuf::from(vec![0xABu8; 32]),
        voters_commitment: ByteBuf::from(vec![0xCDu8; 32]),
        ln_proven_weight: 123_456_789,
        first_attested_round: 1000,
        last_attested_round: 1256,
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn state_proof_message_randomized_field_combinations_roundtrip() {
    let mut state: u64 = 0x9999_8888_7777_6666;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };
    for i in 0..32u64 {
        let r = next();
        let v = StateProofMessage {
            block_headers_commitment: if r & 1 == 0 {
                ByteBuf::new()
            } else {
                ByteBuf::from(vec![(r % 256) as u8; 32])
            },
            voters_commitment: if r & 2 == 0 {
                ByteBuf::new()
            } else {
                ByteBuf::from(vec![((r >> 8) % 256) as u8; 32])
            },
            ln_proven_weight: r,
            first_attested_round: i * 1000,
            last_attested_round: i * 1000 + (r % 1000),
        };
        assert_msgpack_roundtrips(&v);
    }
}

// ---------------------------------------------------------------------------
// BlockHeader (direct round-trip)
// ---------------------------------------------------------------------------

#[test]
fn block_header_zero_value_roundtrips() {
    assert_msgpack_roundtrips(&BlockHeader::default());
}

#[test]
fn block_header_populated_roundtrips() {
    let v = BlockHeader {
        round: Round(42),
        branch: [1u8; 32],
        seed: [2u8; 32],
        txn_commitment: [3u8; 32],
        timestamp: 1_700_000_000,
        genesis_id: "mainnet-v1.0".to_string(),
        genesis_hash: [4u8; 32],
        proposer: Address([5u8; 32]),
        fee_sink: Address([6u8; 32]),
        rewards_pool: Address([7u8; 32]),
        rewards_level: 100,
        rewards_rate: 10,
        rewards_residue: 5,
        rewards_recalculation_round: Round(1_000_000),
        current_protocol: "https://github.com/algorandfoundation/specs/tree/abc123".to_string(),
        next_protocol: String::new(),
        next_protocol_approvals: 0,
        next_protocol_switch_on: Round::default(),
        next_protocol_vote_before: Round::default(),
        txn_counter: 999,
        fees_collected: 50,
        bonus: 25,
        proposer_payout: 12,
        prev512: [8u8; 64],
        txn256: [9u8; 32],
        txn512: [10u8; 64],
        state_proof_tracking: None,
        upgrade_propose: String::new(),
        upgrade_delay: 0,
        upgrade_approve: false,
        expired_participation_accounts: None,
        absent_participation_accounts: None,
        load: 0,
        congestion_tax: 0,
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn block_header_decodes_old_v32_wire_format() {
    // Mirrors go-algorand's TestBlockHeader_Serialization
    // (data/bookkeeping/block_test.go): decodes a real block header captured
    // from a V32 e2e test, back when BlockHeader only carried the legacy
    // SHA512/256 commitment (no txn256/txn512/prev512 fields, which were
    // added later by EnableSha512BlockHash). A correct decoder must accept
    // this older wire format and leave the newer fields at their zero value.
    let hex_blk_hdr = "8fa3737074810081a16ecd0200a466656573c42007dacb4b6d9ed141b17576bd459ae6421d486da3d4ef2247c409a396b82ea221a466726163ce1dcd64fea367656ea7746573742d7631a26768c42032cb340d569e1f9e4d9690c1ba04d77759bae6f353e13af1becf42dcd7d3bdeba470726576c420a2270bc90e3cc48d56081b3b85c15d6a10e14303a6d42ca2537954ce90beec40a570726f746fa6667574757265a472617465ce0ee6b27fa3726e6402a6727763616c72ce0007a120a3727764c420ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa473656564c420a19005a25abad1ad28ec2298baeda9a17693a9ef12127a5ff3e5fa9258c7e9eba2746306a27473ce625ed0eaa374786ec420508f9330176e6064767b0fb7eb0e8bf68ffbaf995a4c7b37ca0217c5a82b4a60";
    let bytes = hex::decode(hex_blk_hdr).expect("valid hex");
    let hdr = BlockHeader::decode_from_reader(&mut bytes.as_slice())
        .expect("must decode an old-format (pre-EnableSha512BlockHash) block header");

    // Legacy SHA512/256 commitment ("txn" tag -> txn_commitment) must be set
    // (present in the fixture, nonzero).
    assert_ne!(hdr.txn_commitment, [0u8; 32]);
    // The newer fields (added by EnableSha512BlockHash) are absent from this
    // old fixture and must decode to their zero value, not error out.
    assert_eq!(hdr.txn256, [0u8; 32]);
    assert_eq!(hdr.txn512, [0u8; 64]);
    assert_eq!(hdr.prev512, [0u8; 64]);
}

#[test]
fn block_header_participation_updates_roundtrips() {
    // Mirrors go's TestMarshalUnmarshalParticipationUpdates non-empty case:
    // both ExpiredParticipationAccounts/AbsentParticipationAccounts (here,
    // BlockHeader's inline expired_participation_accounts/
    // absent_participation_accounts fields) populated with several
    // addresses.
    let v = BlockHeader {
        round: Round(7),
        expired_participation_accounts: Some(vec![Address([1u8; 32]), Address([2u8; 32])]),
        absent_participation_accounts: Some(vec![
            Address([3u8; 32]),
            Address([4u8; 32]),
            Address([5u8; 32]),
        ]),
        ..BlockHeader::default()
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn block_header_upgrade_vote_fields_roundtrip() {
    let v = BlockHeader {
        round: Round(3),
        upgrade_propose: "https://github.com/algorandfoundation/specs/tree/def456".to_string(),
        upgrade_delay: 140_000,
        upgrade_approve: true,
        next_protocol: "https://github.com/algorandfoundation/specs/tree/def456".to_string(),
        next_protocol_approvals: 1000,
        next_protocol_switch_on: Round(500_000),
        next_protocol_vote_before: Round(499_000),
        ..BlockHeader::default()
    };
    assert_msgpack_roundtrips(&v);
}

#[test]
fn block_header_randomized_field_combinations_roundtrip() {
    // Deterministic pseudo-randomization (LCG) over field presence/values,
    // matching the spirit of go-algorand's protocol.RunEncodingTest fuzz —
    // matches the pattern established in
    // crates/node/algo-rest-api/tests/msgpack_model_roundtrip_test.rs.
    let mut state: u64 = 0x0BAD_F00D_DEAD_BEEF;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        state
    };

    for i in 0..48u64 {
        let r = next();
        let v = BlockHeader {
            round: Round(r % 10_000_000),
            branch: [(r % 256) as u8; 32],
            seed: if r & 1 == 0 {
                [0u8; 32]
            } else {
                [((r >> 8) % 256) as u8; 32]
            },
            txn_commitment: [((r >> 16) % 256) as u8; 32],
            timestamp: (r % 2_000_000_000) as i64,
            genesis_id: if r & 2 == 0 {
                String::new()
            } else {
                format!("net-{i}")
            },
            genesis_hash: [((r >> 24) % 256) as u8; 32],
            proposer: if r & 4 == 0 {
                Address::default()
            } else {
                Address([(r % 256) as u8; 32])
            },
            fee_sink: Address([1u8; 32]),
            rewards_pool: Address([2u8; 32]),
            rewards_level: r % 1_000_000,
            rewards_rate: r % 1000,
            rewards_residue: r % 100,
            rewards_recalculation_round: Round(r % 1_000_000),
            current_protocol: format!("proto-{i}"),
            next_protocol: if r & 8 == 0 {
                String::new()
            } else {
                format!("next-proto-{i}")
            },
            next_protocol_approvals: r % 5000,
            next_protocol_switch_on: Round(r % 100_000),
            next_protocol_vote_before: Round(r % 99_000),
            txn_counter: r,
            fees_collected: r % 100_000,
            bonus: r % 100,
            proposer_payout: r % 100,
            prev512: [((r >> 32) % 256) as u8; 64],
            txn256: [((r >> 40) % 256) as u8; 32],
            txn512: [((r >> 48) % 256) as u8; 64],
            state_proof_tracking: None,
            upgrade_propose: if r & 16 == 0 {
                String::new()
            } else {
                format!("upgrade-{i}")
            },
            upgrade_delay: r % 200_000,
            upgrade_approve: r & 32 != 0,
            expired_participation_accounts: if r & 64 == 0 {
                None
            } else {
                Some(vec![Address([(r % 256) as u8; 32])])
            },
            absent_participation_accounts: if r & 128 == 0 {
                None
            } else {
                Some(vec![
                    Address([((r >> 8) % 256) as u8; 32]),
                    Address([((r >> 16) % 256) as u8; 32]),
                ])
            },
            load: r % 1_000_000,
            congestion_tax: r % 1_000_000,
        };
        assert_msgpack_roundtrips(&v);
    }
}
