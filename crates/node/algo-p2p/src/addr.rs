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

//! Combined "host:port, full URL, or libp2p multiaddr" bootstrap-entry
//! parser (issue #1088, Phase 17 gap).
//!
//! Mirrors go-algorand's `network/addr` package (`ParseHostOrURL`,
//! `IsMultiaddr`, `ParseHostOrURLOrMultiaddr`) at `v5.0.0-stable`. Its real
//! callers in go (`cmd/algod/main.go`, `cmd/goal/node.go`) use it to
//! validate/normalize a single `-p`/`--peer` command-line entry that may be
//! either a classic relay address (`host:port` or a full `ws://`/`http://`
//! URL) or a libp2p multiaddr (`/ip4/.../tcp/.../p2p/<peer-id>`) — algod-rust
//! supports both relay transports (`algo-network`'s WS gossip and this
//! crate's libp2p transport) from the same binary, so a mixed peer-override
//! list needs the same disambiguation.
//!
//! This module lives in `algo-p2p` (not `algo-network`) because multiaddr
//! validation needs the `multiaddr`/libp2p types already depended on here;
//! `algo-network` has no multiaddr dependency and doesn't need one — its own
//! bootstrap entries are always `host:port`.

use std::str::FromStr;

use libp2p::Multiaddr;
use url::Url;

/// Matches go's `HostColonPortPattern = regexp.MustCompile(`^[-a-zA-Z0-9.]+:\d+$`)`.
///
/// Hand-rolled rather than pulling in the `regex` crate for one fixed
/// pattern: `<host-chars>+ ':' <digits>+` with nothing else, where
/// `<host-chars>` is `[-a-zA-Z0-9.]`.
fn matches_host_colon_port(addr: &str) -> bool {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || port.is_empty() {
        return false;
    }
    let host_ok = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    let port_ok = port.bytes().all(|b| b.is_ascii_digit());
    host_ok && port_ok
}

/// Errors returned by [`parse_host_or_url`] and [`parse_host_or_url_or_multiaddr`].
///
/// Mirrors go's three sentinel errors in `network/addr/addr.go`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddrParseError {
    /// Go: `errURLNoHost = errors.New("could not parse a host from url")`.
    #[error("could not parse a host from url")]
    NoHost,
    /// Go: `errURLColonHost = errors.New("host name starts with a colon")`.
    #[error("host name starts with a colon")]
    ColonHost,
    /// Go: `errMultiaddrParse = errors.New("failed to parse multiaddr")`.
    #[error("failed to parse multiaddr: {0}")]
    MultiaddrParse(String),
    /// The input could not be parsed as a URL at all (go returns the
    /// underlying `url.Parse` error in this case; we don't have a 1:1
    /// error type for Rust's `url` crate, so this wraps its message).
    #[error("could not parse url: {0}")]
    UrlParse(String),
}

/// Parses `addr` as either a bare `host:port` pair or a full URL.
///
/// Mirrors go's `ParseHostOrURL`: Rust's `url` crate (like Go's
/// `net/url.Parse`) doesn't handle a bare `host:port` — it interprets
/// `foo.com:1234` as scheme `foo.com` with an empty path — so a `host:port`
/// shape is detected up front via [`HOST_COLON_PORT_PATTERN`] and given an
/// explicit `http://` scheme before parsing.
pub fn parse_host_or_url(addr: &str) -> Result<Url, AddrParseError> {
    if matches_host_colon_port(addr) {
        return Url::parse(&format!("http://{addr}"))
            .map_err(|e| AddrParseError::UrlParse(e.to_string()));
    }

    if let Ok(parsed) = Url::parse(addr) {
        if parsed.host_str().is_none() {
            return Err(AddrParseError::NoHost);
        }
        return Ok(parsed);
    }

    if addr.starts_with("http:")
        || addr.starts_with("https:")
        || addr.starts_with("ws:")
        || addr.starts_with("wss:")
        || addr.starts_with("://")
        || addr.starts_with("//")
    {
        // Go returns the original (parsed, err) pair here — both nil/zero
        // on this path in practice, since these prefixes are exactly the
        // ones `url.Parse` already accepts. We already know `Url::parse`
        // failed above, so surface that failure directly.
        return Err(AddrParseError::UrlParse(
            "failed to parse url with recognized scheme prefix".to_string(),
        ));
    }

    // Go's `net/url.Parse` is far more permissive than Rust's `url` crate:
    // it happily parses a bare relative-reference-shaped string like
    // "ip4/127.0.0.1/tcp/8080" (no scheme, no host) instead of erroring,
    // which is exactly how go's real `ParseHostOrURL` reaches its
    // `errURLNoHost` case for that shape — the "http://" + addr fallback
    // below is never reached in go for such inputs. Rust's `Url::parse`
    // instead returns `Err` outright for anything scheme-less that isn't a
    // recognized-prefix case above, so without this check we'd wrongly
    // fall into the "http://" fallback and mint a host out of what should
    // be a path-only, host-less reference. The fallback's real purpose
    // (per go's own comment) is narrower: turning a bracketed-IPv6-with-port
    // shape like "[::]:4601" into something the URL parser accepts — such
    // shapes always contain a ':' (the port separator), so gate the
    // fallback on that.
    if !addr.contains(':') {
        return Err(AddrParseError::NoHost);
    }

    // RFC 1123 section 2: the first character of a host is relaxed to allow
    // either a letter or a digit — but a bare leading colon (e.g. ":1234",
    // meaning a missing host with only a port) is invalid, unless it's the
    // start of an IPv6 literal ("::..."). Go detects this *after* a
    // successful (permissive) `url.Parse`, by checking `parsed.Host[0]`.
    // Rust's `url` crate instead rejects "http://:1234" outright as an
    // "empty host" parse error, so check for this shape up front.
    if addr.starts_with(':') && !addr.starts_with("::") {
        return Err(AddrParseError::ColonHost);
    }

    // This turns "[::]:4601" into "http://[::]:4601", which the url crate
    // (like Go's net/url) can parse directly.
    Url::parse(&format!("http://{addr}")).map_err(|e| AddrParseError::UrlParse(e.to_string()))
}

/// Returns `true` if `addr` looks like (and validates as) a libp2p multiaddr.
///
/// Mirrors go's `IsMultiaddr`: a multiaddr always starts with `/` but not
/// `//` (which is reserved for scheme-relative URLs, e.g. `//host/path`).
pub fn is_multiaddr(addr: &str) -> bool {
    if addr.starts_with('/') && !addr.starts_with("//") {
        Multiaddr::from_str(addr).is_ok()
    } else {
        false
    }
}

/// Parses `addr` as a `host:port`, full URL, or libp2p multiaddr, returning
/// the normalized `host:port`/URL host, or the multiaddr string unchanged.
///
/// Mirrors go's `ParseHostOrURLOrMultiaddr`.
pub fn parse_host_or_url_or_multiaddr(addr: &str) -> Result<String, AddrParseError> {
    if addr.starts_with('/') && !addr.starts_with("//") {
        return Multiaddr::from_str(addr)
            .map(|_| addr.to_string())
            .map_err(|e| AddrParseError::MultiaddrParse(e.to_string()));
    }
    let url = parse_host_or_url(addr)?;
    Ok(url
        .host_str()
        .map(|h| match url.port() {
            Some(p) => format!("{h}:{p}"),
            None => h.to_string(),
        })
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mirrors go's `TestParseHostURLOrMultiaddr` (network/addr/addr_test.go).
    #[test]
    fn valid_multiaddrs_round_trip() {
        let valid = [
            "/ip4/127.0.0.1/tcp/8080",
            "/ip6/::1/tcp/8080",
            "/ip4/192.168.1.1/udp/9999/quic",
            "/ip4/192.168.1.1/tcp/8180/p2p/Qmewz5ZHN1AAGTarRbMupNPbZRfg3p5jUGoJ3JYEatJVVk",
            "/ip4/192.255.2.8/tcp/8180/ws",
        ];
        for addr in valid {
            assert!(
                is_multiaddr(addr),
                "expected {addr} to be a valid multiaddr"
            );
            let v = parse_host_or_url_or_multiaddr(addr)
                .unwrap_or_else(|e| panic!("expected {addr} to parse, got {e:?}"));
            assert_eq!(v, addr);
        }
    }

    #[test]
    fn bad_multiaddrs_and_hosts_are_rejected() {
        let invalid_ip4 = "/ip4/256.256.256.256/tcp/8080";
        let bad_protocol = "/ip4/127.0.0.1/abc/8080";
        let bad_port = "/ip4/127.0.0.1/tcp/abc";
        let unix_no_path = "/unix";
        let tcp_no_port = "/ip4/127.0.0.1/tcp";
        let bad_peer_id = "/p2p/invalidPeerID";
        let missing_leading_slash = "ip4/127.0.0.1/tcp/8080";
        let bare_colon_port = ":1234";

        for addr in [
            invalid_ip4,
            bad_protocol,
            bad_port,
            unix_no_path,
            tcp_no_port,
            bad_peer_id,
        ] {
            assert!(!is_multiaddr(addr), "expected {addr} to be rejected");
            match parse_host_or_url_or_multiaddr(addr) {
                Err(AddrParseError::MultiaddrParse(_)) => {}
                other => panic!("expected {addr} to fail multiaddr parse, got {other:?}"),
            }
        }

        // Missing the starting '/' — parsed as a URL instead, and rejected
        // for having no host (go: errURLNoHost).
        assert!(!is_multiaddr(missing_leading_slash));
        match parse_host_or_url_or_multiaddr(missing_leading_slash) {
            Err(AddrParseError::NoHost) => {}
            other => panic!("expected {missing_leading_slash} to fail with NoHost, got {other:?}"),
        }

        // Host starts with a colon (not an IPv6 literal) — go: errURLColonHost.
        assert!(!is_multiaddr(bare_colon_port));
        match parse_host_or_url_or_multiaddr(bare_colon_port) {
            Err(AddrParseError::ColonHost) => {}
            other => panic!("expected {bare_colon_port} to fail with ColonHost, got {other:?}"),
        }
    }

    #[test]
    fn host_colon_port_parses_as_http() {
        let url = parse_host_or_url("relay.example.com:4160").unwrap();
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("relay.example.com"));
        assert_eq!(url.port(), Some(4160));
    }

    #[test]
    fn ipv6_bracket_host_port_parses() {
        let url = parse_host_or_url("[::]:4601").unwrap();
        // The `url` crate's `host_str()` keeps the IPv6 literal's brackets
        // (unlike go's `url.URL.Hostname()`, which strips them) — the
        // joined "host:port" form below is still correct either way, since
        // `format!("{h}:{p}")` reproduces the original address exactly.
        assert_eq!(url.host_str(), Some("[::]"));
        assert_eq!(url.port(), Some(4601));

        let joined = parse_host_or_url_or_multiaddr("[::]:4601").unwrap();
        assert_eq!(joined, "[::]:4601");
    }

    #[test]
    fn full_urls_pass_through() {
        let url = parse_host_or_url("ws://relay.example.com:4160/v1/net/gossip").unwrap();
        assert_eq!(url.scheme(), "ws");
        assert_eq!(url.host_str(), Some("relay.example.com"));
        assert_eq!(url.port(), Some(4160));
    }
}
