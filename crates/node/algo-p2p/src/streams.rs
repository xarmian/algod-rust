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

//! Placeholder for libp2p request/response stream handling.
//!
//! Go's `network/p2p/streams.go` and `network/p2p/http.go` implement a
//! stream manager that multiplexes Algorand's WS-gossip protocol (and an
//! HTTP-over-libp2p-streams client) on top of the host built in [`crate::host`].
//! Neither is needed to satisfy this issue's acceptance criteria (dial/listen
//! foundation only, no protocol traffic yet), so this module is intentionally
//! left as a stub: it exists so later sub-issues (gossipsub wiring in #540,
//! capability/HTTP-over-stream needs in #541) have an obvious place to land
//! stream-protocol handlers without having to first invent the module.
//!
//! [`StreamProtocol`] is re-exported here (rather than requiring downstream
//! callers to reach into `libp2p` directly) since it is the type later
//! sub-issues will register handlers against.

pub use libp2p::StreamProtocol;
