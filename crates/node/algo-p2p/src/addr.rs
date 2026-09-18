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
    parse_host_or_url_with_literal_port(addr).map(|(url, _)| url)
}

/// Like [`parse_host_or_url`], but also returns the literal, as-written port
/// from `addr` when one is present — including one that equals its scheme's
/// WHATWG default and that the returned `Url`'s own `port()`/`set_port()`
/// therefore cannot represent (see [`literal_port`]'s doc comment).
///
/// [`parse_host_or_url_or_multiaddr`] uses this (instead of `Url::port()`
/// alone) to build its returned "host:port" string, so that an explicit
/// default port survives end to end (issue #1436). `parse_host_or_url`
/// itself still returns a plain `Url` unchanged: nothing else in this crate
/// inspects `.port()` on its result for a "special"-scheme default-port
/// input, and preserving `Url`'s ordinary semantics elsewhere avoids
/// widening this fix beyond the actual bug.
fn parse_host_or_url_with_literal_port(addr: &str) -> Result<(Url, Option<u16>), AddrParseError> {
    if matches_host_colon_port(addr) {
        let joined = format!("http://{addr}");
        return Url::parse(&joined)
            .map(|parsed| {
                let port = literal_port(&joined);
                (parsed, port)
            })
            .map_err(|e| AddrParseError::UrlParse(e.to_string()));
    }

    if let Ok(parsed) = Url::parse(addr) {
        if parsed.host_str().is_none() {
            return Err(AddrParseError::NoHost);
        }
        let port = literal_port(addr);
        return Ok((parsed, port));
    }

    if addr.starts_with("http:")
        || addr.starts_with("https:")
        || addr.starts_with("ws:")
        || addr.starts_with("wss:")
        || addr.starts_with("://")
    {
        // Go returns the original (parsed, err) pair here — both nil/zero
        // on this path in practice, since these prefixes are exactly the
        // ones `url.Parse` already accepts. We already know `Url::parse`
        // failed above, so surface that failure directly.
        return Err(AddrParseError::UrlParse(
            "failed to parse url with recognized scheme prefix".to_string(),
        ));
    }

    // Protocol-relative URL ("//host[:port][/path]", e.g. "//somewhere.tld"
    // or "//somewhere.tld:4601" — two of go's `TestParseHostOrURL` valid
    // cases). Go's permissive `net/url.Parse` accepts this directly,
    // yielding `url.URL{Scheme: "", Host: "host[:port]"}`; Rust's `url`
    // crate requires an absolute URL with a non-empty scheme (and can't
    // represent an empty one at all), so give it a temporary one the same
    // way the "[::]:port" fallback below does, purely to reuse the crate's
    // authority/port parsing and validation (e.g. still rejecting
    // "//localhost:WAT" for its non-numeric port, matching go).
    if let Some(rest) = addr.strip_prefix("//") {
        let joined = format!("http://{rest}");
        return Url::parse(&joined)
            .map(|parsed| {
                let port = literal_port(&joined);
                (parsed, port)
            })
            .map_err(|e| AddrParseError::UrlParse(e.to_string()));
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
    let joined = format!("http://{addr}");
    Url::parse(&joined)
        .map(|parsed| {
            let port = literal_port(&joined);
            (parsed, port)
        })
        .map_err(|e| AddrParseError::UrlParse(e.to_string()))
}

/// Recovers the literal, as-written port from `url_str` (the exact string
/// that was fed to `Url::parse` to obtain a successful parse), even when it
/// equals the WHATWG default for the URL's "special" scheme (`ws`=80,
/// `wss`=443, `http`=80, `https`=443, `ftp`=21) — in which case `Url::port()`
/// (and even calling `Url::set_port()` again with that same value) returns
/// `None`: the WHATWG URL parsing *and* port-setter algorithms both null out
/// a special scheme's default port unconditionally, so `url::Url` has no way
/// to represent "an explicit port was written that happens to equal the
/// default" — that information is only recoverable from the original text.
///
/// Go's `net/url.Parse` has no such normalization at all — `url.URL.Host`
/// always contains the literal parsed authority, port included — so
/// `ParseHostOrURL("wss://localhost:443")` keeps `:443` (issue #1436).
///
/// Implementation: re-parses the same `scheme://host[:port]...` authority
/// under a synthetic non-"special" scheme name, which the `url` crate never
/// elides a port for regardless of value, and reads the port back off that.
fn literal_port(url_str: &str) -> Option<u16> {
    let scheme_end = url_str.find("://")?;
    let rest = &url_str[scheme_end..];
    let probe = format!("x-algod-rust-literal-port{rest}");
    Url::parse(&probe).ok()?.port()
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
    let (url, literal_port) = parse_host_or_url_with_literal_port(addr)?;
    let port = literal_port.or_else(|| url.port());
    Ok(url
        .host_str()
        .map(|h| match port {
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

    // Mirrors go's `TestParseHostOrURL` (network/addr/addr_test.go:33-104),
    // porting its valid-cases table (13 of go's 14 entries — see the note
    // below) and its full bad-URL table verbatim (issue #1436). Each valid
    // case checks both `parse_host_or_url`'s `(scheme, host)` and
    // `parse_host_or_url_or_multiaddr`'s joined `host:port` string, matching
    // go's per-case `t.Run(tc.text, ...)` / `t.Run(tc.text+"-multiaddr", ...)`
    // subtests.
    #[test]
    fn parse_host_or_url_matches_go_valid_cases_table() {
        // (input, expected scheme, expected host [go's url.URL.Host, i.e.
        // including an explicit port])
        //
        // go's 14th case, `{"::11.22.33.44:123", url.URL{Scheme: "http",
        // Host: "::11.22.33.44:123"}}`, is intentionally omitted: it relies
        // on a Go net/url stdlib quirk (`parseHost` only validates the
        // *last* colon-separated host segment as a port, never checking
        // whether the rest forms a real IPv6 literal) that the WHATWG-strict
        // `url` crate has no way to replicate without bypassing its host
        // parser entirely — a separate, narrower fix tracked in issue #1437,
        // unrelated to this issue's port-preservation bug.
        let cases: &[(&str, &str, &str)] = &[
            ("localhost:123", "http", "localhost:123"),
            ("http://localhost:123", "http", "localhost:123"),
            ("ws://localhost:9999", "ws", "localhost:9999"),
            ("wss://localhost:443", "wss", "localhost:443"),
            ("https://localhost:123", "https", "localhost:123"),
            ("https://somewhere.tld", "https", "somewhere.tld"),
            ("http://127.0.0.1:123", "http", "127.0.0.1:123"),
            ("//somewhere.tld", "", "somewhere.tld"),
            ("//somewhere.tld:4601", "", "somewhere.tld:4601"),
            ("http://[::]:123", "http", "[::]:123"),
            ("1.2.3.4:123", "http", "1.2.3.4:123"),
            ("[::]:123", "http", "[::]:123"),
            (
                "r2-devnet.devnet.algodev.network:4560",
                "http",
                "r2-devnet.devnet.algodev.network:4560",
            ),
        ];

        for (input, expected_scheme, expected_host) in cases {
            // `parse_host_or_url` itself is unavoidably lossy for a URL like
            // "wss://localhost:443": `url::Url` implements WHATWG default-port
            // elision on *both* parsing and `set_port()`, so a special
            // scheme's (ws/wss/http/https/ftp) explicit-but-default port can
            // never be represented on the `Url` object itself — only the
            // original text carries that information (see `literal_port`'s
            // doc comment). So this checks scheme/host (sans port) against
            // the bare `Url`, and checks the full "host:port" string — the
            // part go's real callers, and this module's own
            // `parse_host_or_url_or_multiaddr`, actually consume — via the
            // literal-port-aware helper, matching go's `url.URL.Host` exactly.
            let (url, literal_port) = parse_host_or_url_with_literal_port(input)
                .unwrap_or_else(|e| panic!("expected {input:?} to parse, got {e:?}"));
            if !expected_scheme.is_empty() {
                // Go's protocol-relative "//host" cases parse to an empty
                // `url.URL.Scheme`; `url::Url` cannot represent an empty
                // scheme at all (see `parse_host_or_url_with_literal_port`'s
                // "//"-prefix branch), so those two cases are exempted here
                // and instead validated purely on their host:port string
                // below, which is what this module's real callers consume.
                assert_eq!(
                    url.scheme(),
                    *expected_scheme,
                    "scheme mismatch for {input:?}"
                );
            }
            let port = literal_port.or_else(|| url.port());
            let host = url
                .host_str()
                .map(|h| match port {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_string(),
                })
                .unwrap_or_default();
            assert_eq!(host, *expected_host, "host mismatch for {input:?}");

            let joined = parse_host_or_url_or_multiaddr(input).unwrap_or_else(|e| {
                panic!("expected {input:?} to parse (multiaddr path), got {e:?}")
            });
            assert_eq!(joined, *expected_host, "joined host mismatch for {input:?}");
        }
    }

    #[test]
    fn parse_host_or_url_rejects_go_bad_url_table() {
        let bad_urls = [
            "justahost",
            "localhost:WAT",
            "http://localhost:WAT",
            "https://localhost:WAT",
            "ws://localhost:WAT",
            "wss://localhost:WAT",
            "//localhost:WAT",
            "://badaddress",
            "://localhost:1234",
            ":xxx",
            ":xxx:1234",
            "::11.22.33.44",
            ":a:1",
            ":a:",
            ":1",
            ":a",
            ":",
            "",
        ];
        for addr in bad_urls {
            assert!(
                parse_host_or_url(addr).is_err(),
                "expected {addr:?} to fail to parse"
            );
            assert!(
                !is_multiaddr(addr),
                "expected {addr:?} to not be a multiaddr"
            );
            assert!(
                parse_host_or_url_or_multiaddr(addr).is_err(),
                "expected {addr:?} to fail to parse (multiaddr path)"
            );
        }
    }

    #[test]
    fn full_urls_pass_through() {
        let url = parse_host_or_url("ws://relay.example.com:4160/v1/net/gossip").unwrap();
        assert_eq!(url.scheme(), "ws");
        assert_eq!(url.host_str(), Some("relay.example.com"));
        assert_eq!(url.port(), Some(4160));
    }

    // -------------------------------------------------------------------
    // Go: `TestPeerInfoFromAddr` / `TestPeerInfoFromAddrs`
    // (`network/p2p/peerstore/utils_test.go`) and
    // `TestP2PMultiaddrConversionToFrom` (`network/p2pNetwork_test.go`).
    //
    // go-libp2p needs an explicit `peer.AddrInfoFromP2pAddr`/
    // `AddrInfoToP2pAddrs` step to split a `/.../p2p/<id>` multiaddr into
    // a dialable `peer.AddrInfo` (and back) before its `host.Connect` will
    // accept it. rust-libp2p has no equivalent split step: `Swarm::dial`
    // (this crate's `P2pHost::dial`, `host.rs`) takes the *whole*
    // multiaddr — including a trailing `/p2p/<peer-id>` component — and
    // resolves the target `PeerId` internally
    // (`DialOpts::unknown_peer_id().address(addr)`), so there is no
    // isolated conversion function to port 1:1 (this row's own note
    // already says as much). What both go tests actually pin down is
    // parse validity/error-shape for the same table of multiaddr strings,
    // and that a valid multiaddr with a `/p2p/<id>` suffix round-trips
    // through parsing unchanged — both of which map directly onto
    // `Multiaddr::from_str` (the primitive `is_multiaddr` above already
    // wraps), so this ports that behavior instead of a function that
    // doesn't exist here.
    // -------------------------------------------------------------------

    /// Go: `TestPeerInfoFromAddr`. Same table of valid/invalid multiaddr
    /// strings; asserts parse success/failure exactly like go's
    /// `PeerInfoFromAddr` (which itself starts with `ma.NewMultiaddr`).
    #[test]
    fn multiaddr_from_str_matches_peer_info_from_addr_table() {
        let cases: &[(&str, bool)] = &[
            ("/ip4/", false),
            ("/ip4/1.2.3.4/tcp/AAAAAAA", false),
            ("/ip4/1.2.3.4/tcp/443/AAAAAAA", false),
            (
                "/badprotocol/1.2.3.4/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
                false,
            ),
            ("/ip4/1.2.3.4/tcp/4041/p2p/AAAAAAA", false),
            (
                "/ip4/ams-2.bootstrap.libp2p.io/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
                false,
            ),
            (
                "/dns4/ams-2.bootstrap.libp2p.io/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
                true,
            ),
            (
                "/ip4/147.75.83.83/tcp/4001/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Na",
                true,
            ),
        ];

        for (addr, should_parse) in cases {
            let result = Multiaddr::from_str(addr);
            assert_eq!(
                result.is_ok(),
                *should_parse,
                "{addr}: expected parse success = {should_parse}, got {result:?}"
            );
        }
    }

    /// Go: `TestPeerInfoFromAddrs` — given a mixed batch of valid and
    /// malformed multiaddr strings, exactly the valid ones parse and the
    /// malformed ones are individually reported.
    #[test]
    fn multiaddr_from_str_partitions_a_batch_like_peer_info_from_addrs() {
        let addrs = [
            "/ip4/1.2.3.4/tcp/4041/p2p/AAAAAAA",
            "/ip4/1.2.3.4/tcp/AAAAAAA",
            "/dns4/ams-2.bootstrap.libp2p.io/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
            "/ip4/147.75.83.83/tcp/4001/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Na",
        ];

        let (parsed, malformed): (Vec<_>, Vec<_>) =
            addrs.iter().partition(|a| Multiaddr::from_str(a).is_ok());

        assert_eq!(parsed.len(), 2, "expected exactly 2 valid multiaddrs");
        assert_eq!(
            malformed.len(),
            2,
            "expected exactly 2 malformed multiaddrs"
        );
        assert!(malformed.contains(&&"/ip4/1.2.3.4/tcp/4041/p2p/AAAAAAA"));
        assert!(malformed.contains(&&"/ip4/1.2.3.4/tcp/AAAAAAA"));
    }

    /// Go: `TestP2PMultiaddrConversionToFrom` — a multiaddr carrying a
    /// `/p2p/<peer-id>` suffix round-trips through parsing unchanged
    /// (`ma.String() == a`), and the peer ID embedded in it is
    /// extractable. In go this requires the explicit
    /// `AddrInfoFromP2pAddr`/`AddrInfoToP2pAddrs` round trip (which drops
    /// and restores the p2p component); here `Multiaddr` keeps the whole
    /// address as one value and `iter()` finds the embedded `PeerId`
    /// directly, without ever needing to split it off.
    #[test]
    fn multiaddr_with_peer_id_round_trips_and_extracts_peer_id() {
        let a = "/ip4/192.168.1.1/tcp/8180/p2p/Qmewz5ZHN1AAGTarRbMupNPbZRfg3p5jUGoJ3JYEatJVVk";
        let ma = Multiaddr::from_str(a).expect("valid multiaddr");
        assert_eq!(
            ma.to_string(),
            a,
            "round trip through parsing must be lossless"
        );

        let peer_id = ma.iter().find_map(|proto| match proto {
            libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
            _ => None,
        });
        assert_eq!(
            peer_id.map(|p| p.to_string()),
            Some("Qmewz5ZHN1AAGTarRbMupNPbZRfg3p5jUGoJ3JYEatJVVk".to_string()),
            "the /p2p/<id> suffix must yield the same PeerId go's AddrInfoFromP2pAddr extracts"
        );
    }
}
