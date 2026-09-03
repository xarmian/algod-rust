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

//! Mode-derived connection-manager/resource-manager limits and raw
//! address-filtering helpers for the libp2p transport.
//!
//! Ports go-algorand's `network/p2p/p2p.go` `deriveConnLimits`,
//! `netAddressToListenAddress`, and `addressFilter` (plus the
//! `manet.IsIPUnspecified`/`manet.IsPublicAddr` helpers they call into,
//! reimplemented here directly since `rust-libp2p`'s `multiaddr` crate has
//! no equivalent of go-multiaddr's `net` ("manet") package) — the
//! remaining "connection-limit/pubsub-parameter tuning" gap from issue
//! #818. The gossipsub mesh-degree half of that gap
//! (`deriveAlgorandGossipSubParams`) lives in [`crate::pubsub`] instead,
//! mirroring go's own `p2p.go`/`pubsub.go` split.
//!
//! (Gaps 1 and 2 from #818 — the stream manager and `IdentityTracker` —
//! landed in PR #893; see `crate::streams` and `crate::identity_tracker`.)
//!
//! **This module is computation-only.** `algo_p2p::host::P2pHost::new`
//! still configures the swarm/gossipsub with library defaults, exactly as
//! before this change. Wiring [`derive_conn_limits`]'s output into a live
//! connection manager and resource manager needs:
//! - a new config surface on `P2pHost::new` (it takes only an identity
//!   config and network ID today, not the `gossip_fanout` /
//!   `incoming_connections_limit` / `is_listen_server` /
//!   `enable_dht_providers` inputs this module's functions need), and
//! - genuinely new `rust-libp2p` dependencies: go's connection manager
//!   (`go-libp2p/p2p/net/connmgr`) and resource manager
//!   (`go-libp2p/p2p/host/resource-manager`) both have `rust-libp2p`
//!   counterparts (`libp2p-connection-limits` and
//!   `libp2p::swarm::Config`'s own per-peer/per-connection limits
//!   respectively), but neither is a dependency of this crate yet, and
//!   fitting the resource manager's scope-based accounting
//!   (system/transient/peer/protocol scopes) onto `rust-libp2p`'s simpler
//!   connection-count-only limiter is a design decision of its own, not a
//!   mechanical substitution.
//!
//! This is left as a documented follow-up, consistent with how #893
//! scoped the stream manager and `IdentityTracker` (ported, unit-tested,
//! not wired into a live connection-acceptance path).

use std::net::{Ipv4Addr, Ipv6Addr};

use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;

use crate::errors::P2pError;

/// Derived connection-manager and resource-manager limits for a given
/// node mode.
///
/// Go: `network/p2p/p2p.go`'s unexported `connLimitConfig` struct — kept
/// public here since, unlike go's version (private to a single file that
/// both derives and immediately consumes it), this module is deliberately
/// consumption-agnostic (see this module's doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnLimitConfig {
    /// Connection manager "low water mark" — target connection count the
    /// manager trims down to once `conn_mgr_high` is exceeded. `0` (paired
    /// with `conn_mgr_high == 0`) means connection trimming is disabled.
    /// Go: `connMgrLow`.
    pub conn_mgr_low: i64,
    /// Connection manager "high water mark" — the connection count that
    /// triggers trimming. Go: `connMgrHigh`.
    pub conn_mgr_high: i64,
    /// Resource-manager total connection ceiling (`system.Conns`). Go:
    /// `rcmgrConns`.
    pub rcmgr_conns: i64,
    /// Resource-manager inbound-connection ceiling
    /// (`system.ConnsInbound`); `0` means "no explicit limit" (the
    /// resource manager's own scaled default applies). Go:
    /// `rcmgrConnsInbound`.
    pub rcmgr_conns_inbound: i64,
    /// Resource-manager outbound-connection ceiling
    /// (`system.ConnsOutbound`). Go: `rcmgrConnsOutbound`.
    pub rcmgr_conns_outbound: i64,
}

/// Compute connection-manager and resource-manager limits from a node's
/// mode and networking config.
///
/// Go: `network/p2p/p2p.go` `deriveConnLimits(cfg config.Local)`. Ported
/// field-for-field rather than taking a `config.Local`-shaped struct,
/// since algod-rust's `algo-config::Local` deliberately has no unified
/// `IsListenServer()`-equivalent method (see `algo-config`'s
/// `Local::gossip_fanout_for_listen_server` doc comment for why — the
/// caller, which already knows whether it is acting as a relay/listen
/// server from its own CLI-subcommand shape, is expected to compute
/// `is_listen_server` itself and pass it in).
///
/// - `gossip_fanout`: go's `cfg.GossipFanout`.
/// - `incoming_connections_limit`: go's `cfg.IncomingConnectionsLimit`;
///   only consulted when `is_listen_server` is `true` (mirrors go, which
///   only reads this field inside the `cfg.IsListenServer()` branch). A
///   negative value means "unbounded" (go: `< 0`), returned as
///   `i64::MAX`/disabled-trimming, matching go's `math.MaxInt` /
///   `high = 0, low = 0`.
/// - `is_listen_server`: go's `cfg.IsListenServer()` (`IsWsListenServer()
///   || IsP2PListenServer()`) — true for a relay/listen-server node,
///   false for a pure client (including a hybrid client with
///   `EnableP2PHybridMode` set but no listen address of either kind).
/// - `enable_dht_providers`: go's `cfg.EnableDHTProviders` — doubles the
///   outbound-connection allowance when set (DHT provider-record
///   advertisement opens its own outbound connections on top of ordinary
///   gossip-mesh fanout).
pub fn derive_conn_limits(
    gossip_fanout: i64,
    incoming_connections_limit: i64,
    is_listen_server: bool,
    enable_dht_providers: bool,
) -> ConnLimitConfig {
    let mut rcmgr_conns_outbound = gossip_fanout * 3;
    if enable_dht_providers {
        rcmgr_conns_outbound += gossip_fanout * 3;
    }

    let (low, high, rcmgr_conns, rcmgr_conns_inbound) = if is_listen_server {
        if incoming_connections_limit < 0 {
            (0, 0, i64::MAX, i64::MAX)
        } else {
            let rcmgr_conns = rcmgr_conns_outbound + incoming_connections_limit;
            let high = rcmgr_conns;
            let low = high * 96 / 100;
            (low, high, rcmgr_conns, incoming_connections_limit)
        }
    } else {
        let rcmgr_conns = rcmgr_conns_outbound + gossip_fanout * 3;
        let high = rcmgr_conns_outbound;
        let low = gossip_fanout * 2;
        (low, high, rcmgr_conns, 0)
    };

    ConnLimitConfig {
        conn_mgr_low: low,
        conn_mgr_high: high,
        rcmgr_conns,
        rcmgr_conns_inbound,
        rcmgr_conns_outbound,
    }
}

/// Convert a `NetAddress`-style `"ip:port"` string (go-algorand's
/// `config.Local.NetAddress`/`P2PHybridNetAddress` format) into a libp2p
/// listen-address multiaddr string.
///
/// Go: `network/p2p/p2p.go` `netAddressToListenAddress`. An empty `ip`
/// half (e.g. `":4160"`) defaults to `"0.0.0.0"` ("all interfaces"); an
/// empty or missing `port` half, or more/fewer than two `:`-separated
/// parts, is an error.
pub fn net_address_to_listen_address(net_address: &str) -> Result<String, P2pError> {
    let parts: Vec<&str> = net_address.split(':').collect();
    if parts.len() != 2 {
        return Err(P2pError::InvalidMultiaddr(format!(
            "invalid netAddress {net_address}; required format is \"ip:port\""
        )));
    }
    let ip = if parts[0].is_empty() {
        "0.0.0.0"
    } else {
        parts[0]
    };
    if parts[1].is_empty() {
        return Err(P2pError::InvalidMultiaddr(format!(
            "invalid netAddress {net_address}, port is required"
        )));
    }

    Ok(format!("/ip4/{ip}/tcp/{}", parts[1]))
}

/// Whether `addr`'s IP component is the "unspecified" ("all interfaces")
/// address — `0.0.0.0` for IPv4, `::` for IPv6.
///
/// Go: `manet.IsIPUnspecified`, backed by `net.IP.IsUnspecified()` — this
/// mirrors `net.IP.IsUnspecified()`'s exact semantics via
/// [`std::net::Ipv4Addr::is_unspecified`]/[`std::net::Ipv6Addr::is_unspecified`].
/// Returns `false` for a multiaddr with no IP component at all (matching
/// go's `len(head) == 0` early-return).
pub fn is_ip_unspecified(addr: &Multiaddr) -> bool {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => return ip.is_unspecified(),
            Protocol::Ip6(ip) => return ip.is_unspecified(),
            _ => continue,
        }
    }
    false
}

/// Whether the listen address a `NetAddress` string parses to needs the
/// private/unroutable-address [`address_filter`] applied to a host's
/// observed listen addresses.
///
/// Go: the `needAddressFilter` local in `MakeHost` — set when
/// `cfg.NetAddress` parses successfully AND the resulting listen address
/// is "all interfaces" (`manet.IsIPUnspecified`). Go's comment on this
/// logic: the filter is deliberately *not* enabled when `NetAddress` is
/// set to a specific address (including loopback/private ones) — an
/// operator who explicitly configured a concrete bind address is assumed
/// to know what they're doing; the filter exists only to avoid
/// advertising e.g. a Docker bridge's private address when the operator
/// asked to listen on every interface.
///
/// Returns `Ok(false)` (not an error) for a `net_address` that fails to
/// parse, matching go's `if parsedListenAddr, perr := ...; perr == nil { ...
/// } else { log a warning }` — a malformed `NetAddress` simply never
/// triggers the filter, it doesn't abort host construction.
pub fn needs_address_filter(net_address: &str) -> bool {
    match net_address_to_listen_address(net_address) {
        Ok(listen_addr) => match listen_addr.parse::<Multiaddr>() {
            Ok(ma) => is_ip_unspecified(&ma),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Private/unroutable-address classification
//
// Go: `github.com/multiformats/go-multiaddr/net` ("manet")'s
// `IsPublicAddr`/`private.go` CIDR tables. `rust-libp2p`'s `multiaddr`
// crate has no equivalent helper (or "manet"-style companion crate) at
// all, so the CIDR tables below are transcribed directly from go-multiaddr
// `v0.16.1`'s `net/private.go` (the version go-algorand's own `go.mod`
// resolves to at the `v5.0.0-stable` pin) rather than approximated via
// `std::net`'s (partially nightly-only) `Ipv4Addr`/`Ipv6Addr` classifier
// methods, to keep this a byte-for-byte parity port rather than a
// close-enough reimplementation.
// ---------------------------------------------------------------------------

/// `(network, prefix_len)` CIDR blocks go-multiaddr classifies as private
/// IPv4 space. Go: `manet.Private4` / `privateCIDR4`.
const PRIVATE4: &[(Ipv4Addr, u32)] = &[
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
];

/// `(network, prefix_len)` CIDR blocks go-multiaddr classifies as
/// unroutable (but not necessarily "private") IPv4 space. Go:
/// `manet.Unroutable4` / `unroutableCIDR4`.
const UNROUTABLE4: &[(Ipv4Addr, u32)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(192, 0, 0, 0), 26),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 88, 99, 0), 24),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
    (Ipv4Addr::new(255, 255, 255, 255), 32),
];

/// `(network, prefix_len)` CIDR blocks go-multiaddr classifies as
/// unroutable IPv6 space (multicast, and the documentation prefix — a
/// subset of the global-unicast allocation below, explicitly excluded).
/// Go: `manet.Unroutable6` / `unroutableCIDR6`.
const UNROUTABLE6: &[(Ipv6Addr, u32)] = &[
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
    (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
];

/// The IPv6 global-unicast allocation. Go: `globalUnicast` /
/// `globalUnicastCIDR6`.
const GLOBAL_UNICAST6: &[(Ipv6Addr, u32)] = &[(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)];

/// The well-known and local-use NAT64 prefixes (RFC 6052 / RFC 8215) — an
/// IPv6 address under either can only (WellKnown) or may (LocalUse)
/// reference a public IPv4 address; go-multiaddr counts both as public to
/// avoid a false negative. Go: `nat64` / `nat64CIDRs`.
const NAT64: &[(Ipv6Addr, u32)] = &[
    (Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
    (Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
];

/// go-algorand's own extra IPv6 exclusions applied on top of
/// `manet.IsPublicAddr` by [`address_filter`] — the discard-only prefix
/// (`100::/64`, RFC 6666) and the IPv6 benchmarking prefix
/// (`2001:2::/48`, RFC 5180). Only the latter actually changes
/// `address_filter`'s outcome: `2001:2::/48` falls inside
/// `GLOBAL_UNICAST6` and so reads as "public" under `manet.IsPublicAddr`
/// alone, while `100::/64` is already excluded by `manet.IsPublicAddr`
/// itself (it isn't part of `2000::/3`) — this entry is ported anyway for
/// source-level parity with go's own `private6` list. Go:
/// `network/p2p/p2p.go` `private6`.
const ALGORAND_PRIVATE6: &[(Ipv6Addr, u32)] = &[
    (Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64),
    (Ipv6Addr::new(0x2001, 2, 0, 0, 0, 0, 0, 0), 48),
];

fn ipv4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix_len: u32) -> bool {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn ipv4_in_any(ip: Ipv4Addr, cidrs: &[(Ipv4Addr, u32)]) -> bool {
    cidrs.iter().any(|&(net, len)| ipv4_in_cidr(ip, net, len))
}

fn ipv6_in_cidr(ip: Ipv6Addr, network: Ipv6Addr, prefix_len: u32) -> bool {
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    (u128::from(ip) & mask) == (u128::from(network) & mask)
}

fn ipv6_in_any(ip: Ipv6Addr, cidrs: &[(Ipv6Addr, u32)]) -> bool {
    cidrs.iter().any(|&(net, len)| ipv6_in_cidr(ip, net, len))
}

/// Whether `addr`'s IP component is a publicly routable address, per
/// go-multiaddr's classification tables. Go: `manet.IsPublicAddr`
/// (restricted here to the `ip4`/`ip6` component cases — this crate never
/// constructs `dns`/`dns4`/`dns6`/`dnsaddr` listen/observed addresses, so
/// go's additional special-use-domain handling for those has no
/// equivalent input to apply to).
fn is_public_addr(addr: &Multiaddr) -> bool {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                return !ipv4_in_any(ip, PRIVATE4) && !ipv4_in_any(ip, UNROUTABLE4);
            }
            Protocol::Ip6(ip) => {
                let is_public_unicast =
                    ipv6_in_any(ip, GLOBAL_UNICAST6) && !ipv6_in_any(ip, UNROUTABLE6);
                if is_public_unicast {
                    return true;
                }
                return ipv6_in_any(ip, NAT64);
            }
            _ => continue,
        }
    }
    false
}

/// Filter a set of observed/candidate listen addresses down to public,
/// routable ones — go-algorand's private-address filter for a host
/// listening on "all interfaces" (see [`needs_address_filter`]).
///
/// Go: `network/p2p/p2p.go` `addressFilter`, passed to `libp2p.New` as
/// `libp2p.AddrsFactory(addressFilter)` when `needAddressFilter` is set.
/// IPv4 addresses are kept whenever [`is_public_addr`] passes (go has no
/// additional IPv4 exclusion beyond `manet.IsPublicAddr` — "no rules for
/// IPv4 at the moment, accept"); IPv6 addresses additionally exclude
/// [`ALGORAND_PRIVATE6`] on top of `is_public_addr`.
pub fn address_filter(addrs: &[Multiaddr]) -> Vec<Multiaddr> {
    let mut res = Vec::with_capacity(addrs.len());
    for addr in addrs {
        if !is_public_addr(addr) {
            continue;
        }
        let mut kept = false;
        for proto in addr.iter() {
            match proto {
                Protocol::Ip4(_) => {
                    kept = true;
                    break;
                }
                Protocol::Ip6(ip) => {
                    kept = !ipv6_in_any(ip, ALGORAND_PRIVATE6);
                    break;
                }
                _ => continue,
            }
        }
        if kept {
            res.push(addr.clone());
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- derive_conn_limits (go: TestDeriveConnLimits_*) --------------------

    #[test]
    fn derive_conn_limits_server() {
        let limits = derive_conn_limits(4, 2400, true, false);
        assert_eq!(limits.rcmgr_conns, 2400 + 12);
        assert_eq!(limits.rcmgr_conns_inbound, 2400);
        assert_eq!(limits.rcmgr_conns_outbound, 12);
        assert_eq!(limits.conn_mgr_high, 2412);
        assert_eq!(limits.conn_mgr_low, 2315); // 2412 * 96 / 100
        assert!(limits.conn_mgr_high <= limits.rcmgr_conns);
    }

    #[test]
    fn derive_conn_limits_unbounded_server() {
        let limits = derive_conn_limits(4, -1, true, false);
        assert_eq!(limits.rcmgr_conns, i64::MAX);
        assert_eq!(limits.rcmgr_conns_inbound, i64::MAX);
        assert_eq!(limits.rcmgr_conns_outbound, 12);
        assert_eq!(limits.conn_mgr_high, 0);
        assert_eq!(limits.conn_mgr_low, 0);
    }

    #[test]
    fn derive_conn_limits_dht_providers() {
        let limits = derive_conn_limits(4, 2400, true, true);
        assert_eq!(limits.rcmgr_conns, 2400 + 12 + 12);
        assert_eq!(limits.rcmgr_conns_inbound, 2400);
        assert_eq!(limits.rcmgr_conns_outbound, 24);
        assert_eq!(limits.conn_mgr_high, 2424);
        assert_eq!(limits.conn_mgr_low, 2327); // 2424 * 96 / 100
    }

    #[test]
    fn derive_conn_limits_client() {
        let limits = derive_conn_limits(4, 0, false, false);
        assert_eq!(limits.rcmgr_conns, 24); // 4 * 6
        assert_eq!(limits.rcmgr_conns_inbound, 0);
        assert_eq!(limits.rcmgr_conns_outbound, 12); // 4 * 3
        assert_eq!(limits.conn_mgr_high, 12); // 4 * 3
        assert_eq!(limits.conn_mgr_low, 8); // 4 * 2
        assert!(limits.conn_mgr_high <= limits.rcmgr_conns);

        // IncomingConnectionsLimit = -1 does not affect client limits.
        let same = derive_conn_limits(4, -1, false, false);
        assert_eq!(limits, same);
    }

    /// Go's `TestDeriveConnLimits_HybridClient`: `EnableP2PHybridMode` set
    /// but no listen address — still a client for connection-limit
    /// purposes. algod-rust has no unified hybrid-mode flag to check here
    /// (see [`derive_conn_limits`]'s doc comment) — the caller determines
    /// `is_listen_server` itself, so this is exercised by simply passing
    /// `false`, identically to the plain client case.
    #[test]
    fn derive_conn_limits_hybrid_client() {
        let limits = derive_conn_limits(4, 0, false, false);
        assert_eq!(limits.rcmgr_conns, 24);
        assert_eq!(limits.rcmgr_conns_inbound, 0);
        assert_eq!(limits.rcmgr_conns_outbound, 12);
        assert_eq!(limits.conn_mgr_high, 12);
        assert_eq!(limits.conn_mgr_low, 8);
        assert!(limits.conn_mgr_high <= limits.rcmgr_conns);
    }

    /// Go's `TestDeriveConnLimits_HybridServer`: `EnableP2PHybridMode` with
    /// `P2PHybridNetAddress` set is a listen server, using default
    /// `GossipFanout` (4) since the go test never overrides it.
    #[test]
    fn derive_conn_limits_hybrid_server() {
        let limits = derive_conn_limits(4, 2400, true, false);
        assert_eq!(limits.rcmgr_conns, 2412);
        assert_eq!(limits.rcmgr_conns_inbound, 2400);
        assert_eq!(limits.rcmgr_conns_outbound, 12);
        assert_eq!(limits.conn_mgr_high, 2412);
        assert_eq!(limits.conn_mgr_low, 2315);
        assert!(limits.conn_mgr_high <= limits.rcmgr_conns);
    }

    #[test]
    fn derive_conn_limits_zero_fanout() {
        let limits = derive_conn_limits(0, 2400, false, false);
        assert!(limits.conn_mgr_low >= 0);
        assert!(limits.conn_mgr_high >= limits.conn_mgr_low);
        assert!(limits.rcmgr_conns >= limits.conn_mgr_high);
        assert_eq!(limits.rcmgr_conns_inbound, 0);
        assert_eq!(limits.rcmgr_conns_outbound, 0);
    }

    // --- net_address_to_listen_address (go: TestNetAddressToListenAddress) -

    #[test]
    fn net_address_to_listen_address_cases() {
        assert_eq!(
            net_address_to_listen_address("192.168.1.1:8080").unwrap(),
            "/ip4/192.168.1.1/tcp/8080"
        );
        assert_eq!(
            net_address_to_listen_address(":8080").unwrap(),
            "/ip4/0.0.0.0/tcp/8080"
        );
        assert!(net_address_to_listen_address("192.168.1.1:")
            .unwrap_err()
            .to_string()
            .contains("invalid netAddress"));
        assert!(net_address_to_listen_address("192.168.1.1")
            .unwrap_err()
            .to_string()
            .contains("invalid netAddress"));
        assert!(net_address_to_listen_address("192.168.1.1:8080:9090")
            .unwrap_err()
            .to_string()
            .contains("invalid netAddress"));
    }

    // --- is_ip_unspecified (go: TestP2PMaNetIsIPUnspecified) ----------------

    #[test]
    fn ip_unspecified_cases() {
        for addr in [":0", ":1234", "0.0.0.0:2345", "0.0.0.0:0"] {
            let listen = net_address_to_listen_address(addr).unwrap();
            let ma: Multiaddr = listen.parse().unwrap();
            assert!(is_ip_unspecified(&ma), "expected {addr} to be unspecified");
        }

        for addr in [
            "127.0.0.1:0",
            "127.0.0.1:1234",
            "1.2.3.4:5678",
            "1.2.3.4:0",
            "192.168.0.111:0",
            "10.0.0.1:101",
        ] {
            let listen = net_address_to_listen_address(addr).unwrap();
            let ma: Multiaddr = listen.parse().unwrap();
            assert!(!is_ip_unspecified(&ma), "expected {addr} to be specified");
        }

        // IPv6 support, mirrored from go's separate assertion.
        let ma: Multiaddr = "/ip6/::/tcp/1234".parse().unwrap();
        assert!(is_ip_unspecified(&ma));
    }

    // --- needs_address_filter (go: TestP2PMakeHostAddressFilter's ----------
    // --- needAddressFilter-gating half; the full test also spins up a ------
    // --- real host, which belongs to a higher-level integration test, not --
    // --- this computation-only module) --------------------------------------

    #[test]
    fn needs_address_filter_for_all_interfaces() {
        assert!(needs_address_filter(":0"));
        assert!(needs_address_filter("0.0.0.0:0"));
    }

    #[test]
    fn needs_address_filter_false_for_specific_address() {
        assert!(!needs_address_filter("127.0.0.1:4160"));
        assert!(!needs_address_filter("10.0.0.1:4160"));
        assert!(!needs_address_filter("1.2.3.4:4160"));
    }

    #[test]
    fn needs_address_filter_false_for_malformed_net_address() {
        // A malformed NetAddress never triggers the filter — mirrors go's
        // `perr == nil` gate (a parse failure just logs a warning and
        // leaves `needAddressFilter` at its default `false`).
        assert!(!needs_address_filter("not-a-valid-address"));
    }

    // --- address_filter / is_public_addr (go: TestP2PPrivateAddresses) -----

    fn ip4(addr: &str) -> Multiaddr {
        format!("/ip4/{addr}").parse().unwrap()
    }

    fn ip6(addr: &str) -> Multiaddr {
        format!("/ip6/{addr}").parse().unwrap()
    }

    #[test]
    fn private_and_unroutable_ipv4_addresses_are_filtered_out() {
        for addr in [
            "10.0.0.0",
            "100.64.0.0",
            "169.254.0.0",
            "172.16.0.0",
            "192.0.0.0",
            "192.0.2.0",
            "192.88.99.0",
            "192.168.0.0",
            "198.18.0.0",
            "198.51.100.0",
            "203.0.113.0",
            "224.0.0.0",
            "233.252.0.0",
            "255.255.255.255",
        ] {
            let ma = ip4(addr);
            assert!(!is_public_addr(&ma), "expected {addr} to be non-public");
            assert!(
                address_filter(std::slice::from_ref(&ma)).is_empty(),
                "expected address_filter to drop {addr}"
            );
        }
    }

    #[test]
    fn private_and_unroutable_ipv6_addresses_are_filtered_out() {
        for addr in ["fc00::", "fe80::", "2001:db8::"] {
            let ma = ip6(addr);
            assert!(
                address_filter(std::slice::from_ref(&ma)).is_empty(),
                "expected address_filter to drop {addr}"
            );
        }
    }

    /// go-algorand's own extra IPv6 exclusions, applied by `address_filter`
    /// on top of `is_public_addr`. Both addresses end up filtered out
    /// either way, but for different reasons:
    /// - `2001:2::/48` (IPv6 benchmarking, RFC 5180) *is* globally-unicast
    ///   per `manet.IsPublicAddr` alone (a strict subset of `2000::/3`,
    ///   and not the `2001:db8::/32` documentation prefix `manet` already
    ///   excludes) — this is the case go-algorand's `private6` exclusion
    ///   actually exists for.
    /// - `100::/64` (the discard-only prefix, RFC 6666) is already *not*
    ///   globally-unicast under `manet.IsPublicAddr` (its first 3 bits
    ///   are `000`, not `001` — it falls outside `2000::/3` entirely) —
    ///   go-algorand's `private6` entry for it is a redundant belt-and-
    ///   suspenders check, ported here for source-level parity with go's
    ///   `private6` list even though it can't change the outcome.
    #[test]
    fn algorand_specific_private6_ranges_are_filtered_out() {
        let benchmarking = ip6("2001:2::");
        assert!(
            is_public_addr(&benchmarking),
            "expected 2001:2:: to be public under manet.IsPublicAddr alone"
        );
        assert!(
            address_filter(std::slice::from_ref(&benchmarking)).is_empty(),
            "expected address_filter to drop 2001:2::"
        );

        let discard_only = ip6("100::");
        assert!(
            !is_public_addr(&discard_only),
            "expected 100:: to already be non-public under manet.IsPublicAddr alone"
        );
        assert!(
            address_filter(std::slice::from_ref(&discard_only)).is_empty(),
            "expected address_filter to drop 100::"
        );
    }

    #[test]
    fn public_addresses_pass_through_address_filter() {
        let addrs = vec![ip4("8.8.8.8"), ip6("2606:4700:4700::1111")];
        let filtered = address_filter(&addrs);
        assert_eq!(filtered, addrs);
    }
}
