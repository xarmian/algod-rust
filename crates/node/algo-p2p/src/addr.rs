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
//! `IsMultiaddr`, `ParseHostOrURLOrMultiaddr`) at `v5.0.1-stable`. Its real
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
    /// The `url.Parse` error go returns, with go's text
    /// (`parse "<url>": <reason>`).
    #[error("{0}")]
    UrlParse(String),
}

/// The two fields of go's `*url.URL` that `ParseHostOrURL` callers use:
/// `Scheme` (lower-cased) and `Host` (including any port, as go keeps it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoUrl {
    /// `url.URL.Scheme`.
    pub scheme: String,
    /// `url.URL.Host`.
    pub host: String,
}

/// Parses `addr` as either a bare `host:port` pair or a full URL.
///
/// A port of go's `ParseHostOrURL` (`network/addr/addr.go`) on top of a port of
/// the part of go 1.27's `net/url.Parse` it depends on ([`go_url_parse`]); the
/// `url` crate is WHATWG-strict and differs from go on host shapes, default
/// ports and error texts, so it is not used. Pinned to go by
/// `tests/addr_oracle.rs`.
pub fn parse_host_or_url(addr: &str) -> Result<GoUrl, AddrParseError> {
    // If the entire addr is "host:port" grab that right away.
    if matches_host_colon_port(addr) {
        return Ok(GoUrl {
            scheme: "http".to_string(),
            host: addr.to_string(),
        });
    }
    let first_err = match go_url_parse(addr) {
        Ok(parsed) => {
            if parsed.host.is_empty() {
                return Err(AddrParseError::NoHost);
            }
            return Ok(parsed);
        }
        Err(e) => e,
    };
    if ["http:", "https:", "ws:", "wss:", "://", "//"]
        .iter()
        .any(|p| addr.starts_with(p))
    {
        return Err(AddrParseError::UrlParse(first_err));
    }
    // This turns "[::]:4601" into "http://[::]:4601" which url.Parse can do
    match go_url_parse(&format!("http://{addr}")) {
        Ok(parsed) => {
            // https://datatracker.ietf.org/doc/html/rfc1123#section-2
            // first character is relaxed to allow either a letter or a digit
            let h = parsed.host.as_bytes();
            if h.first() == Some(&b':') && (h.len() < 2 || h[1] != b':') {
                return Err(AddrParseError::ColonHost);
            }
            Ok(parsed)
        }
        // return original err, not our prefix altered try
        Err(_) => Err(AddrParseError::UrlParse(first_err)),
    }
}

// --- go 1.27 net/url.Parse, the part ParseHostOrURL depends on ---------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Enc {
    Host,
    Zone,
    Path,
    UserPassword,
    Fragment,
}

/// go's `shouldEscape` (reference implementation of its encoding table).
fn should_escape(c: u8, mode: Enc) -> bool {
    if c.is_ascii_alphanumeric() {
        return false;
    }
    if matches!(mode, Enc::Host | Enc::Zone)
        && matches!(
            c,
            b'!' | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
    {
        return false;
    }
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            Enc::Path => return c == b'?',
            Enc::UserPassword => return matches!(c, b'@' | b'/' | b'?' | b':'),
            Enc::Fragment => return false,
            _ => {}
        },
        _ => {}
    }
    if mode == Enc::Fragment && matches!(c, b'!' | b'(' | b')' | b'*') {
        return false;
    }
    true
}

fn unhex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// go's `unescape`: validates `%XX` escapes (and, for host/zone, characters)
/// and returns the unescaped bytes.
fn go_unescape(s: &[u8], mode: Enc) -> Result<Vec<u8>, String> {
    let quote = |b: &[u8]| go_quote(&String::from_utf8_lossy(b));
    let mut i = 0;
    let mut out = Vec::with_capacity(s.len());
    while i < s.len() {
        match s[i] {
            b'%' => {
                if i + 2 >= s.len()
                    || !s[i + 1].is_ascii_hexdigit()
                    || !s[i + 2].is_ascii_hexdigit()
                {
                    let end = (i + 3).min(s.len());
                    return Err(format!("invalid URL escape {}", quote(&s[i..end])));
                }
                if mode == Enc::Host && unhex(s[i + 1]) < 8 && &s[i..i + 3] != b"%25" {
                    return Err(format!("invalid URL escape {}", quote(&s[i..i + 3])));
                }
                let v = unhex(s[i + 1]) << 4 | unhex(s[i + 2]);
                if mode == Enc::Zone
                    && &s[i..i + 3] != b"%25"
                    && v != b' '
                    && should_escape(v, Enc::Host)
                {
                    return Err(format!("invalid URL escape {}", quote(&s[i..i + 3])));
                }
                out.push(v);
                i += 3;
            }
            c => {
                if matches!(mode, Enc::Host | Enc::Zone) && c < 0x80 && should_escape(c, mode) {
                    return Err(format!(
                        "invalid character {} in host name",
                        quote(&s[i..i + 1])
                    ));
                }
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// go's `strconv.Quote` (`%q`): printable runes as they are, the usual escapes,
/// `\xNN` for other ASCII control bytes and `\uNNNN` / `\UNNNNNNNN` for
/// non-printable runes. Go's `IsPrint` is approximated for non-ASCII: controls,
/// spaces other than ASCII space and the common format characters are not
/// printable.
fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            ' '..='~' => out.push(c),
            c if (c as u32) < 0x80 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if go_is_print(c) => out.push(c),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

fn go_is_print(c: char) -> bool {
    !(c.is_control()
        || c.is_whitespace()
        || matches!(
            c as u32,
            0xad | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x2064 | 0xfeff | 0xfff9..=0xfffb
        ))
}

/// go's `getScheme`: `Ok((scheme, rest))`.
fn go_get_scheme(raw: &str) -> Result<(&str, &str), String> {
    for (i, c) in raw.bytes().enumerate() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' => {
                if i == 0 {
                    return Ok(("", raw));
                }
            }
            b':' => {
                if i == 0 {
                    return Err("missing protocol scheme".to_string());
                }
                return Ok((&raw[..i], &raw[i + 1..]));
            }
            _ => return Ok(("", raw)),
        }
    }
    Ok(("", raw))
}

/// go's `validOptionalPort`.
fn valid_optional_port(port: &str) -> bool {
    match port.as_bytes().split_first() {
        None => true,
        Some((b':', digits)) => digits.iter().all(u8::is_ascii_digit),
        Some(_) => false,
    }
}

/// go's `validUserinfo`.
fn valid_userinfo(s: &str) -> bool {
    s.chars().all(|r| {
        r.is_ascii_alphanumeric()
            || matches!(
                r,
                '-' | '.'
                    | '_'
                    | ':'
                    | '~'
                    | '!'
                    | '$'
                    | '&'
                    | '\''
                    | '('
                    | ')'
                    | '*'
                    | '+'
                    | ','
                    | ';'
                    | '='
                    | '%'
                    | '@'
            )
    })
}

/// go's `netip.ParseAddr` for the IPv6 shapes `parseHost` can hand it: the
/// address is accepted only when its first `.`, `:` or `%` is a `:` and
/// `parseIPv6` succeeds (anything else is an IPv4 address or an error, which
/// `parseHost` rejects either way).
fn go_ip_literal_is_ipv6(s: &str) -> Result<(), String> {
    match s.bytes().find(|b| matches!(b, b'.' | b':' | b'%')) {
        Some(b':') => go_parse_ipv6(s),
        _ => Err(format!("ParseAddr({s:?}): unable to parse IP")),
    }
}

/// go's `netip` `parseIPv6`.
fn go_parse_ipv6(input: &str) -> Result<(), String> {
    let err = |msg: &str| Err(format!("ParseAddr({input:?}): {msg}"));
    let mut s = input.as_bytes();
    if let Some(i) = s.iter().position(|&b| b == b'%') {
        if i + 1 == s.len() {
            return err("zone must be a non-empty string");
        }
        s = &s[..i];
    }
    let mut ellipsis: i32 = -1;
    if s.len() >= 2 && s[0] == b':' && s[1] == b':' {
        ellipsis = 0;
        s = &s[2..];
        if s.is_empty() {
            return Ok(());
        }
    }
    let mut i: i32 = 0;
    while i < 16 {
        let mut off = 0usize;
        let mut acc: u32 = 0;
        while off < s.len() && s[off].is_ascii_hexdigit() {
            acc = (acc << 4) + u32::from(unhex(s[off]));
            if off > 3 {
                return err("each group must have 4 or less digits");
            }
            if acc > 0xffff {
                return err("IPv6 field has value >=2^16");
            }
            off += 1;
        }
        if off == 0 {
            return err("each colon-separated field must have at least one digit");
        }
        if off < s.len() && s[off] == b'.' {
            if ellipsis < 0 && i != 12 {
                return err("embedded IPv4 address must replace the final 2 fields of the address");
            }
            if i + 4 > 16 {
                return err(
                    "too many hex fields to fit an embedded IPv4 at the end of the address",
                );
            }
            let v4 = std::str::from_utf8(s).unwrap_or("");
            go_parse_ipv4_fields(v4).map_err(|m| format!("ParseAddr({input:?}): {m}"))?;
            s = &[];
            i += 4;
            break;
        }
        i += 2;
        s = &s[off..];
        if s.is_empty() {
            break;
        }
        if s[0] != b':' {
            return err("unexpected character, want colon");
        } else if s.len() == 1 {
            return err("colon must be followed by more characters");
        }
        s = &s[1..];
        if s[0] == b':' {
            if ellipsis >= 0 {
                return err("multiple :: in address");
            }
            ellipsis = i;
            s = &s[1..];
            if s.is_empty() {
                break;
            }
        }
    }
    if !s.is_empty() {
        return err("trailing garbage after address");
    }
    if i < 16 {
        if ellipsis < 0 {
            return err("address string too short");
        }
    } else if ellipsis >= 0 {
        return err("the :: must expand to at least one field of zeros");
    }
    Ok(())
}

/// go's `parseIPv4Fields`: four dot-separated decimal fields, each at most 255
/// without a leading zero.
fn go_parse_ipv4_fields(s: &str) -> Result<(), String> {
    let fields: Vec<&str> = s.split('.').collect();
    if fields.len() != 4 {
        return Err("IPv4 address too short or too long".to_string());
    }
    for f in fields {
        if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
            return Err("unexpected character in IPv4 field".to_string());
        }
        if f.len() > 1 && f.starts_with('0') {
            return Err("IPv4 field has octet with leading zero".to_string());
        }
        if f.parse::<u32>().map_or(true, |v| v > 255) {
            return Err("IPv4 field has value >255".to_string());
        }
    }
    Ok(())
}

/// go's `parseHost` (go 1.27: colons in an `http`/`https` host are strict, the
/// default for a module with `go 1.27`).
fn go_parse_host(scheme: &str, host: &str) -> Result<String, String> {
    let lossy = |b: Vec<u8>| String::from_utf8_lossy(&b).into_owned();
    let open = host.rfind('[');
    if matches!(open, Some(i) if i > 0) {
        return Err("invalid IP-literal".to_string());
    }
    if open == Some(0) {
        // an IP-Literal, e.g. "[fe80::1]", "[fe80::1%25en0]", "[fe80::1]:80"
        let Some(close) = host.rfind(']') else {
            return Err("missing ']' in host".to_string());
        };
        let colon_port = &host[close + 1..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {colon_port:?} after host"));
        }
        let unescaped_colon_port = go_unescape(colon_port.as_bytes(), Enc::Host)?;
        let hostname = &host[1..close];
        let unescaped_hostname = if let Some(z) = hostname.find("%25") {
            let hb = hostname.as_bytes();
            let mut h = go_unescape(&hb[..z], Enc::Host)?;
            h.extend(go_unescape(&hb[z..], Enc::Zone)?);
            h
        } else {
            go_unescape(hostname.as_bytes(), Enc::Host)?
        };
        let unescaped_hostname = lossy(unescaped_hostname);
        go_ip_literal_is_ipv6(&unescaped_hostname).map_err(|e| format!("invalid host: {e}"))?;
        return Ok(format!(
            "[{unescaped_hostname}]{}",
            lossy(unescaped_colon_port)
        ));
    }
    if let Some(first) = host.find(':') {
        let last = host.rfind(':').unwrap_or(first);
        let i = if last != first && !(scheme == "http" || scheme == "https") {
            last
        } else {
            first
        };
        let colon_port = &host[i..];
        if !valid_optional_port(colon_port) {
            return Err(format!("invalid port {colon_port:?} after host"));
        }
    }
    go_unescape(host.as_bytes(), Enc::Host).map(lossy)
}

/// go's `parseAuthority`, returning the host.
fn go_parse_authority(scheme: &str, authority: &str) -> Result<String, String> {
    let (userinfo, host) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };
    let host = go_parse_host(scheme, host)?;
    if let Some(userinfo) = userinfo {
        if !valid_userinfo(userinfo) {
            return Err("net/url: invalid userinfo".to_string());
        }
        let (user, pass) = match userinfo.split_once(':') {
            Some((u, p)) => (u, Some(p)),
            None => (userinfo, None),
        };
        go_unescape(user.as_bytes(), Enc::UserPassword)?;
        if let Some(p) = pass {
            go_unescape(p.as_bytes(), Enc::UserPassword)?;
        }
    }
    Ok(host)
}

/// go 1.27 `net/url.Parse` as far as `ParseHostOrURL` uses it: the lower-cased
/// scheme and the host, with go's validation (control characters, scheme,
/// first path segment, authority, `%` escapes in the path and fragment) and go's
/// error text (`parse "<url>": <reason>`).
fn go_url_parse(raw: &str) -> Result<GoUrl, String> {
    // Cut off #frag
    let (u, frag) = match raw.split_once('#') {
        Some((u, f)) => (u, f),
        None => (raw, ""),
    };
    let url = go_url_parse_no_frag(u).map_err(|e| format!("parse {}: {e}", go_quote(u)))?;
    if !frag.is_empty() {
        go_unescape(frag.as_bytes(), Enc::Fragment).map_err(|e| format!("parse {}: {e}", go_quote(raw)))?;
    }
    Ok(url)
}

fn go_url_parse_no_frag(raw: &str) -> Result<GoUrl, String> {
    if raw.bytes().any(|b| b < b' ' || b == 0x7f) {
        return Err("net/url: invalid control character in URL".to_string());
    }
    if raw == "*" {
        return Ok(GoUrl {
            scheme: String::new(),
            host: String::new(),
        });
    }
    let (scheme, rest) = go_get_scheme(raw)?;
    let scheme = scheme.to_ascii_lowercase();
    // the query is not validated
    let rest = rest.split('?').next().unwrap_or("");
    if !rest.starts_with('/') {
        if !scheme.is_empty() {
            // rootless paths per RFC 3986 are opaque
            return Ok(GoUrl {
                scheme,
                host: String::new(),
            });
        }
        // Avoid confusion with malformed schemes, like cache_object:foo/bar.
        if rest.split('/').next().is_some_and(|seg| seg.contains(':')) {
            return Err("first path segment in URL cannot contain colon".to_string());
        }
    }
    let mut host = String::new();
    let mut path = rest;
    if (!scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let authority = &rest[2..];
        let (authority, p) = match authority.find('/') {
            Some(i) => (&authority[..i], &authority[i..]),
            None => (authority, ""),
        };
        path = p;
        host = go_parse_authority(&scheme, authority)?;
    }
    go_unescape(path.as_bytes(), Enc::Path)?;
    Ok(GoUrl { scheme, host })
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
    Ok(parse_host_or_url(addr)?.host)
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
        assert_eq!(url.scheme, "http");
        assert_eq!(url.host, "relay.example.com:4160");
    }

    #[test]
    fn ipv6_bracket_host_port_parses() {
        let url = parse_host_or_url("[::]:4601").unwrap();
        assert_eq!(url.scheme, "http");
        assert_eq!(url.host, "[::]:4601");
        assert_eq!(
            parse_host_or_url_or_multiaddr("[::]:4601").unwrap(),
            "[::]:4601"
        );
    }

    // go's `TestParseHostOrURL` (network/addr/addr_test.go, v5.1.1) valid
    // table: `(text, Scheme, Host)`. v5.1.1 replaced the unbracketed
    // `::11.22.33.44:123` case by `[::11.22.33.44]:123`.
    #[test]
    fn parse_host_or_url_matches_go_valid_cases_table() {
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
            ("[::11.22.33.44]:123", "http", "[::11.22.33.44]:123"),
        ];
        for (input, scheme, host) in cases {
            let url = parse_host_or_url(input).unwrap_or_else(|e| panic!("{input:?}: {e:?}"));
            assert_eq!(
                (url.scheme.as_str(), url.host.as_str()),
                (*scheme, *host),
                "{input:?}"
            );
            assert_eq!(
                parse_host_or_url_or_multiaddr(input).unwrap(),
                *host,
                "{input:?}"
            );
        }
    }

    // go's bad-URL table with the error text v5.1.1 asserts (`ErrorContains`).
    #[test]
    fn parse_host_or_url_rejects_go_bad_url_table() {
        const BAD_PORT: &str = "invalid port";
        const NO_SCHEME: &str = "missing protocol scheme";
        const NO_HOST: &str = "could not parse a host from url";
        const COLON_HOST: &str = "host name starts with a colon";
        let bad: &[(&str, &str)] = &[
            ("justahost", NO_HOST),
            ("localhost:WAT", NO_HOST),
            ("http://localhost:WAT", BAD_PORT),
            ("https://localhost:WAT", BAD_PORT),
            ("ws://localhost:WAT", BAD_PORT),
            ("wss://localhost:WAT", BAD_PORT),
            ("//localhost:WAT", BAD_PORT),
            ("://badaddress", NO_SCHEME),
            ("://localhost:1234", NO_SCHEME),
            (":xxx", NO_SCHEME),
            (":xxx:1234", NO_SCHEME),
            ("::11.22.33.44", NO_SCHEME),
            ("::11.22.33.44:123", NO_SCHEME),
            (":a:1", NO_SCHEME),
            (":a:", NO_SCHEME),
            (":1", COLON_HOST),
            (":a", NO_SCHEME),
            (":", COLON_HOST),
            ("", NO_HOST),
        ];
        for (addr, want) in bad {
            let e = parse_host_or_url(addr).expect_err(addr);
            assert!(e.to_string().contains(want), "{addr:?}: {e}");
            assert!(!is_multiaddr(addr), "{addr:?}");
            let e = parse_host_or_url_or_multiaddr(addr).expect_err(addr);
            assert!(e.to_string().contains(want), "{addr:?}: {e}");
        }
    }

    #[test]
    fn full_urls_pass_through() {
        let url = parse_host_or_url("ws://relay.example.com:4160/v1/net/gossip").unwrap();
        assert_eq!(url.scheme, "ws");
        assert_eq!(url.host, "relay.example.com:4160");
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
