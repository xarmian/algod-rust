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

//! The libp2p stream protocol identifier this crate's transport uses to
//! serve HTTP-shaped request/response traffic — algod-rust's counterpart to
//! go-algorand's `RegisterHTTPHandler`-equivalent registration point over
//! its libp2p transport (issue #1024, a follow-up to #955).
//!
//! Go: `network/p2p/http.go`'s `algorandP2pHTTPProtocol` constant
//! (`"/algorand-http/1.0.0"`), which `HTTPServer` (a thin wrapper around
//! `go-libp2p`'s `libp2phttp.Host`) registers exactly once via
//! `Host.SetHTTPHandlerAtPath(algorandP2pHTTPProtocol, "/", p2phttpMux)` —
//! every path `RegisterHTTPHandler`/`RegisterHTTPHandlerFunc` is called with
//! afterwards is added to that same `gorilla/mux` router instance, not a new
//! libp2p protocol registration. Go's `p2pHTTPRoundTripper` (the client
//! side) opens a stream on this same protocol ID and writes/reads a raw
//! HTTP/1.1 request/response directly onto it (`r.Write(s)` /
//! `http.ReadResponse(bufio.NewReader(s), r)`) — no additional framing.
//!
//! This crate is deliberately kept free of an `axum`/`hyper` dependency (see
//! this crate's `lib.rs` doc comment), so unlike [`crate::wsproto`]'s
//! tag-frame codec this module is just the protocol identifier itself; the
//! HTTP/1.1 request/response serving over a stream accepted on this
//! protocol (mirroring go's raw-HTTP-over-the-stream behavior above) is
//! implemented by `bin/algod-rust`'s `p2p_transport` module, which already
//! depends on `hyper`/`axum` for exactly this purpose on the classic
//! WS-gossip transport (`algo_network::ws_network`).
//!
//! Reference: `../go-algorand/network/p2p/http.go`,
//! `network/p2p/http_test.go`, `network/p2pNetwork.go`'s `TestLedgerServiceP2P`.

use libp2p::StreamProtocol;

/// Go: `network/p2p/http.go`'s `algorandP2pHTTPProtocol`.
pub const ALGORAND_HTTP_PROTOCOL: StreamProtocol = StreamProtocol::new("/algorand-http/1.0.0");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_matches_go_constant() {
        assert_eq!(ALGORAND_HTTP_PROTOCOL.as_ref(), "/algorand-http/1.0.0");
    }
}
