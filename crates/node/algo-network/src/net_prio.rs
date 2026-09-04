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

//! `NetPrio` challenge/response wire types.
//!
//! Mirrors go-algorand's `node.netPrioResponse` / `node.netPrioResponseSigned`
//! (`node/netprio.go`) — the payload carried by the `NP`-tagged message
//! (`Tag::NetPrioResponse` in `tag.rs`, already routed by `ws_peer.rs` and
//! `message_filter.rs`) that a peer sends in response to a network-priority
//! challenge, proving stake weight via a signed nonce.
//!
//! algod-rust doesn't yet drive the challenge/response handshake itself —
//! go's `NewPrioChallenge`/`MakePrioResponse`/`VerifyPrioResponse`
//! (`node/netprio.go`) are daemon-level participation-key logic out of
//! scope for issue #961, which closes msgpack round-trip test-coverage
//! gaps only — but the wire types belong next to `Tag::NetPrioResponse` so
//! that future wiring has a canonical, codec-compatible type to decode
//! into, and so the type can carry the dedicated round-trip test go's
//! `msgp_gen_test.go` gives it (`TestMarshalUnmarshalnetPrioResponse`/
//! `netPrioResponseSigned` and their randomized-encoding variants,
//! `node/msgp_gen_test.go`).

use algo_types::{Address, Round};
use serde::{Deserialize, Serialize};

use crate::block_cert::OneTimeSignature;

fn is_empty_nonce(v: &str) -> bool {
    v.is_empty()
}

fn is_zero_round(v: &Round) -> bool {
    v.0 == 0
}

fn is_zero_address(v: &Address) -> bool {
    v.is_zero()
}

fn is_default_response(v: &NetPrioResponse) -> bool {
    v.is_empty()
}

fn is_default_sig(v: &OneTimeSignature) -> bool {
    *v == OneTimeSignature::default()
}

/// The unsigned nonce/challenge response.
///
/// Mirrors Go's `node.netPrioResponse`
/// (`_struct struct{} \`codec:",omitempty,omitemptyarray"\``, field
/// `Nonce string \`codec:"Nonce,allocbound=..."\``) — the field key is the
/// literal Go field name (no short codec tag), and the field is omitted
/// from the encoding entirely when empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPrioResponse {
    /// The base64-encoded challenge nonce being echoed back.
    #[serde(rename = "Nonce", default, skip_serializing_if = "is_empty_nonce")]
    pub nonce: String,
}

impl NetPrioResponse {
    /// Mirrors Go's implicit `MsgIsZero`/`omitempty` check: true when the
    /// only field, `Nonce`, is empty.
    pub fn is_empty(&self) -> bool {
        self.nonce.is_empty()
    }
}

/// The signed challenge response sent as the `NP`-tagged network message.
///
/// Mirrors Go's `node.netPrioResponseSigned`
/// (`_struct struct{} \`codec:",omitempty,omitemptyarray"\``) — all four
/// fields use their literal Go field names as map keys and are each
/// omitted when zero-valued.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetPrioResponseSigned {
    /// The (unsigned) nonce response this signature covers.
    #[serde(
        rename = "Response",
        default,
        skip_serializing_if = "is_default_response"
    )]
    pub response: NetPrioResponse,

    /// The round the signing participation key is valid for
    /// (`voteRound = latest + 2` in go's `MakePrioResponse`).
    #[serde(rename = "Round", default, skip_serializing_if = "is_zero_round")]
    pub round: Round,

    /// The account whose participation key produced `sig`.
    #[serde(rename = "Sender", default, skip_serializing_if = "is_zero_address")]
    pub sender: Address,

    /// The one-time (ephemeral participation-key) signature over `response`.
    #[serde(rename = "Sig", default, skip_serializing_if = "is_default_sig")]
    pub sig: OneTimeSignature,
}
