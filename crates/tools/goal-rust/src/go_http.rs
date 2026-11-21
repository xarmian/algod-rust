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

//! The part of go's `net/http` client goal's `RestClient.submitForm` runs
//! for an `http://` algod (`&http.Client{}` over `http.DefaultTransport`,
//! issue #2476), so a request that fails says what go says:
//!
//! - the URL go prints (`url.URL.String()`: `EscapedPath`, `Values.Encode`);
//! - the dial: an IP literal, `/etc/hosts`, then DNS (`dial tcp: lookup
//!   <host> on <nameserver>: no such host`), each address tried in turn
//!   within the dialer's 30 s (`dial tcp <addr>: connect: connection
//!   refused`, `dial tcp <addr>: i/o timeout`), `HTTP_PROXY` /
//!   `NO_PROXY` (`proxyconnect tcp: ...`);
//! - the answer: `ReadResponse`'s status line (`resp.Status` is the
//!   server's own reason phrase, byte for byte), its MIME header and
//!   transfer errors (`net/http: HTTP/1.x transport connection broken:
//!   malformed HTTP response "<line>"`, ...), an answer-less close (`EOF`),
//!   1xx answers skipped, the body by `Content-Length`, chunked or up to
//!   the close;
//! - `Client.Do`'s redirects (301, 302, 303, 307, 308; `stopped after 10
//!   redirects`);
//! - for an `https://` algod (issue #2489), the TLS handshake's failures as
//!   go's transport reports them: a server that answers in plain HTTP
//!   (`http: server gave HTTP response to HTTPS client`), one that answers
//!   neither HTTP nor TLS (`tls: first record does not look like a TLS
//!   handshake`), a certificate no root vouches for (`tls: failed to verify
//!   certificate: x509: certificate signed by unknown authority`); since
//!   issue #2507 also go's validity-period and host-name errors, which go
//!   reports before it looks for a chain (`x509: certificate has expired or
//!   is not yet valid: current time T is after T`, `x509: certificate is
//!   valid for A, B, not C`, [`crate::x509_leaf`]), an unfit key usage, the
//!   server's alerts (`remote error: tls: handshake failure`), a close
//!   between records (`EOF`) or inside one (`unexpected EOF`), an oversized
//!   record, the transport's 10 s handshake timeout, and `HTTPS_PROXY`
//!   (`CONNECT host:port` with `Proxy-Authorization`, a non-200 answer is
//!   its status text, `proxyconnect tcp: ...`).
//!
//! Not ported, and why (issue #2507): go offers ALPN `h2` and speaks HTTP/2
//! when the server picks it. go-algorand's algod does not terminate TLS for
//! its REST API (`TLSCertFile` / `TLSKeyFile` are the websocket network's), so
//! an `https:` algod is a TLS-terminating front end, and whether it picks h2
//! depends on that software; HTTP/1.1 is what a plain algod behind it speaks
//! and what goal-rust negotiates. A certificate authority used as the leaf is
//! accepted by go and refused by webpki (`CaUsedAsEndEntity`); goal-rust keeps
//! the stricter verdict.
//!
//! Every error is `<Op> "<url>": <err>` (`*url.Error`). Texts are in the
//! lossless form of [`algo_types::raw_text`]: a reason phrase that is not
//! UTF-8 keeps its bytes.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// `http.DefaultTransport`'s dialer timeout.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// go: `saneMinimum` of `partialDeadline`.
const DIAL_SANE_MINIMUM: Duration = Duration::from_secs(2);

/// go: `Client.Do`'s redirect limit (`defaultCheckRedirect`).
const MAX_REDIRECTS: usize = 10;

/// A request URL the way go's `url.URL` holds and prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoUrl {
    pub scheme: String,
    /// `User` + `Host` as written (`user@host:port`).
    pub authority: String,
    /// The path as sent (`EscapedPath`).
    pub escaped_path: String,
    pub raw_query: String,
    pub fragment: String,
}

impl GoUrl {
    /// go: `queryURL := client.serverURL; queryURL.Path = path;
    /// queryURL.RawQuery = mergeRawQueries(queryURL.RawQuery, v.Encode())`,
    /// `base` being the server URL (`http://<algod.net>`, or `algod.net`'s
    /// own `http:` / `https:` URL).
    pub fn for_request(base: &str, path: &str, query: &[(&str, &str)]) -> GoUrl {
        let mut url = GoUrl::parse(base);
        url.escaped_path = escape_path(path);
        url.raw_query = merge_raw_queries(&url.raw_query, &values_encode(query));
        url
    }

    /// A URL split into its parts (go's `url.Parse` for the forms algod
    /// URLs take: `scheme://authority/path?query#fragment`).
    pub fn parse(s: &str) -> GoUrl {
        let (s, fragment) = match s.split_once('#') {
            Some((a, f)) => (a, f.to_string()),
            None => (s, String::new()),
        };
        let (s, raw_query) = match s.split_once('?') {
            Some((a, q)) => (a, q.to_string()),
            None => (s, String::new()),
        };
        let (scheme, rest) = match s.split_once("://") {
            Some((sc, r)) => (sc.to_ascii_lowercase(), r),
            None => (String::new(), s),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        GoUrl {
            scheme,
            authority: authority.to_string(),
            escaped_path: path.to_string(),
            raw_query,
            fragment,
        }
    }

    /// `Host` (the authority without the user info).
    pub fn host(&self) -> &str {
        match self.authority.rfind('@') {
            Some(i) => &self.authority[i + 1..],
            None => &self.authority,
        }
    }

    /// go: `RequestURI()`.
    fn request_uri(&self) -> String {
        let mut s = if self.escaped_path.is_empty() {
            "/".to_string()
        } else {
            self.escaped_path.clone()
        };
        if !self.raw_query.is_empty() {
            s.push('?');
            s.push_str(&self.raw_query);
        }
        s
    }

    /// go: `u.Parse(ref)` of a `Location` header.
    fn resolve(&self, loc: &str) -> GoUrl {
        if loc.contains("://") {
            return GoUrl::parse(loc);
        }
        if let Some(rest) = loc.strip_prefix("//") {
            return GoUrl::parse(&format!("{}://{rest}", self.scheme));
        }
        let mut target = GoUrl::parse(&format!("{}://{}", self.scheme, self.authority));
        let rel = GoUrl::parse(loc);
        target.raw_query = rel.raw_query;
        target.fragment = rel.fragment;
        target.escaped_path = if rel.escaped_path.starts_with('/') {
            rel.escaped_path
        } else if rel.escaped_path.is_empty() {
            target.raw_query = if loc.contains('?') {
                target.raw_query
            } else {
                self.raw_query.clone()
            };
            self.escaped_path.clone()
        } else {
            let dir = match self.escaped_path.rfind('/') {
                Some(i) => &self.escaped_path[..=i],
                None => "/",
            };
            format!("{dir}{}", rel.escaped_path)
        };
        target
    }
}

impl std::fmt::Display for GoUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.scheme.is_empty() {
            write!(f, "{}://", self.scheme)?;
        }
        f.write_str(&self.authority)?;
        if !self.escaped_path.is_empty()
            && !self.escaped_path.starts_with('/')
            && !self.authority.is_empty()
        {
            f.write_str("/")?;
        }
        f.write_str(&self.escaped_path)?;
        if !self.raw_query.is_empty() {
            write!(f, "?{}", self.raw_query)?;
        }
        if !self.fragment.is_empty() {
            write!(f, "#{}", self.fragment)?;
        }
        Ok(())
    }
}

/// go: `mergeRawQueries`.
fn merge_raw_queries(q1: &str, q2: &str) -> String {
    if q1.is_empty() || q2.is_empty() {
        format!("{q1}{q2}")
    } else {
        format!("{q1}&{q2}")
    }
}

/// go: `url.Values.Encode()`: sorted by key, `QueryEscape`d.
pub fn values_encode(query: &[(&str, &str)]) -> String {
    let mut sorted = query.to_vec();
    sorted.sort_by_key(|(k, _)| *k);
    sorted
        .iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// go: `url.QueryEscape`.
pub fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b' ' => out.push('+'),
            b if unreserved(b) => out.push(char::from(b)),
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// go: `escape(path, encodePath)` (`URL.EscapedPath` of a `Path` set in
/// code).
pub fn escape_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if unreserved(b)
            || matches!(
                b,
                b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'@'
            )
        {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// What the server answered.
#[derive(Debug)]
pub struct Response {
    /// `resp.StatusCode`.
    pub status_code: u16,
    /// `resp.Status`: the status line after the protocol, as sent (raw
    /// bytes in [`algo_types::raw_text`] form).
    pub status: String,
    /// `resp.ContentLength` (`-1`: unknown).
    pub content_length: i64,
    /// The body bytes read.
    pub body: Vec<u8>,
    /// The error reading the body ended with (`unexpected EOF`, ...).
    pub body_err: Option<String>,
    /// `resp.Request.URL`: the URL of the request that got this answer.
    pub url: GoUrl,
}

/// `<method> <url>` as `http.Client.Do` (`headers` added to the request,
/// `body` sent with its `Content-Length`): the final answer (redirects
/// followed), or go's `*url.Error` text.
pub fn request(
    method: &str,
    url: &GoUrl,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<Response, String> {
    let op = url_error_op(method);
    let mut method = method.to_string();
    let mut body = body;
    let mut url = url.clone();
    let mut redirects = 0usize;
    loop {
        let resp =
            round_trip(&method, &url, headers, body).map_err(|e| format!("{op} \"{url}\": {e}"))?;
        let redirect = matches!(resp.response.status_code, 301 | 302 | 303 | 307 | 308);
        let location = resp.location.clone().filter(|l| !l.is_empty());
        let (Some(loc), true) = (location, redirect) else {
            return Ok(resp.response);
        };
        let next = url.resolve(&loc);
        if redirects >= MAX_REDIRECTS {
            // go: the `*url.Error` of a failed redirect check names the
            // `Location` as sent
            return Err(format!(
                "{op} \"{loc}\": stopped after {MAX_REDIRECTS} redirects"
            ));
        }
        redirects += 1;
        if matches!(resp.response.status_code, 301..=303) && method != "HEAD" {
            method = "GET".to_string();
            body = None;
        }
        url = next;
    }
}

/// go: `urlErrorOp`: the method with only its first letter upper case.
fn url_error_op(method: &str) -> String {
    let mut chars = method.chars();
    match chars.next() {
        Some(c) => format!("{}{}", c, chars.as_str().to_ascii_lowercase()),
        None => String::new(),
    }
}

struct RoundTrip {
    response: Response,
    location: Option<String>,
}

/// One request on a fresh connection: the answer, or the transport's error
/// text (without the `*url.Error` decoration).
fn round_trip(
    method: &str,
    url: &GoUrl,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<RoundTrip, String> {
    let https = url.scheme == "https";
    if url.scheme != "http" && !https {
        return Err(format!("unsupported protocol scheme {:?}", url.scheme));
    }
    let host = url.host().to_string();
    let proxy = proxy_for(&host, https);
    let mut stream = match &proxy {
        Some(p) => dial(&p.addr).map_err(|e| format!("proxyconnect tcp: {e}"))?,
        None if https && !has_port(&host) => dial(&format!("{host}:443"))?,
        None => dial(&host)?,
    };
    // an `https:` request through a proxy is tunnelled (`CONNECT host:port`)
    if let (true, Some(p)) = (https, &proxy) {
        let addr = if has_port(&host) {
            host.clone()
        } else {
            format!("{host}:443")
        };
        connect_tunnel(&mut stream, &addr, p.auth.as_deref())?;
    }
    let target = match proxy {
        Some(_) if !https => url.to_string(),
        _ => url.request_uri(),
    };
    let mut req =
        format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Go-http-client/1.1\r\n");
    match body {
        Some(b) => req.push_str(&format!("Content-Length: {}\r\n", b.len())),
        // go sends a zero length for a body-less POST, PUT and PATCH
        None if matches!(method, "POST" | "PUT" | "PATCH") => req.push_str("Content-Length: 0\r\n"),
        None => {}
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    let mut bytes = req.into_bytes();
    if let Some(b) = body {
        bytes.extend_from_slice(b);
    }
    let local = stream.local_addr().ok();
    let peer = stream.peer_addr().ok();
    if https {
        let mut tls = tls_connect(stream, &host)?;
        let _ = tls.write_all(&bytes);
        let _ = tls.flush();
        return read_response(tls, local, peer, method, url);
    }
    // A failed write shows as the read error below, as in go's transport.
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
    read_response(stream, local, peer, method, url)
}

/// go's `CONNECT` through a proxy (`Transport.dialConn`): the request, then
/// the proxy's answer; anything but a 200 is its status text as the error
/// (`unknown status code` when it has none).
fn connect_tunnel(stream: &mut TcpStream, addr: &str, auth: Option<&str>) -> Result<(), String> {
    let local = stream.local_addr().ok();
    let peer = stream.peer_addr().ok();
    let mut req =
        format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: Go-http-client/1.1\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    let _ = stream.write_all(req.as_bytes());
    let _ = stream.flush();
    let read_err = |e: &std::io::Error| match (local, peer) {
        (Some(l), Some(p)) => format!("read tcp {l}->{p}: read: {}", errno_text(e)),
        _ => errno_text(e),
    };
    let mut r = BufReader::new(&*stream);
    let line = match read_line(&mut r) {
        Ok(Some(l)) => l,
        // `ReadResponse` turns the `io.EOF` of an empty answer into this
        Ok(None) => return Err("unexpected EOF".to_string()),
        Err(e) => return Err(read_err(&e)),
    };
    let (proto, status) = match line.iter().position(|&b| b == b' ') {
        Some(i) => (&line[..i], &line[i + 1..]),
        None => return Err(bad_string("malformed HTTP response", &line)),
    };
    let status_start = status
        .iter()
        .position(|&b| b != b' ')
        .unwrap_or(status.len());
    let status = &status[status_start..];
    let code_text = match status.iter().position(|&b| b == b' ') {
        Some(i) => &status[..i],
        None => status,
    };
    if code_text.len() != 3 {
        return Err(bad_string("malformed HTTP status code", code_text));
    }
    let code = std::str::from_utf8(code_text)
        .ok()
        .and_then(go_atoi)
        .filter(|c| *c >= 0)
        .ok_or_else(|| bad_string("malformed HTTP status code", code_text))?;
    if parse_http_version(proto).is_none() {
        return Err(bad_string("malformed HTTP version", proto));
    }
    read_mime_header(&mut r).map_err(|e| match e {
        HeaderError::Io(e) => read_err(&e),
        HeaderError::Text(t) => t,
    })?;
    if code != 200 {
        return Err(match status.iter().position(|&b| b == b' ') {
            Some(i) => algo_types::raw_text::encode(&status[i + 1..]).into_owned(),
            None => "unknown status code".to_string(),
        });
    }
    Ok(())
}

/// Whether a `host[:port]` names its port.
fn has_port(hostport: &str) -> bool {
    match hostport.strip_prefix('[') {
        Some(rest) => rest
            .split_once(']')
            .is_some_and(|(_, a)| a.starts_with(':')),
        None => hostport
            .rsplit_once(':')
            .is_some_and(|(h, _)| !h.contains(':')),
    }
}

/// A connection that keeps what go's TLS record layer knows of it: the first
/// bytes (a `tls.RecordHeaderError` holds them), where the record being read
/// stands (an EOF inside one is `unexpected EOF`, between two a bare `EOF`)
/// and the length field of the latest record header.
struct Recording {
    inner: TcpStream,
    first: Vec<u8>,
    /// Header bytes of the record being read.
    hdr: Vec<u8>,
    /// Payload bytes of that record still to come.
    remaining: usize,
    /// The length field of the latest record header.
    last_len: usize,
}

impl Recording {
    fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            first: Vec::new(),
            hdr: Vec::new(),
            remaining: 0,
            last_len: 0,
        }
    }

    /// Whether the bytes read so far stop inside a record.
    fn mid_record(&self) -> bool {
        self.remaining > 0 || !self.hdr.is_empty()
    }
}

impl Read for Recording {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        let keep = (5 - self.first.len().min(5)).min(n);
        self.first.extend_from_slice(&buf[..keep]);
        for &b in &buf[..n] {
            if self.remaining > 0 {
                self.remaining -= 1;
            } else {
                self.hdr.push(b);
                if self.hdr.len() == 5 {
                    self.last_len = usize::from(u16::from_be_bytes([self.hdr[3], self.hdr[4]]));
                    self.remaining = self.last_len;
                    self.hdr.clear();
                }
            }
        }
        Ok(n)
    }
}

impl Write for Recording {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// go's `Transport.TLSHandshakeTimeout`.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The checks of go's `x509.Certificate.Verify` that come before the chain
/// (the validity period, then the host name), then the platform's verdict on
/// the chain: what go reports for an untrusted certificate that is also
/// expired, or for another name, is that and not the unknown authority.
#[derive(Debug)]
struct GoVerifier {
    inner: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>,
    host: String,
}

impl rustls::client::danger::ServerCertVerifier for GoVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(leaf) = crate::x509_leaf::parse_leaf(end_entity.as_ref()) {
            let unix = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
            if let Some(e) = crate::x509_leaf::validity_error(&leaf, unix) {
                return Err(rustls::Error::General(e));
            }
            if let Some(e) = crate::x509_leaf::name_error(&leaf, &self.host) {
                return Err(rustls::Error::General(e));
            }
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// go's `tls.Client(conn, cfg).Handshake()` as the transport runs it (the
/// system roots, the URL's host as the server name, a 10 s timeout): the TLS
/// stream, or go's error text.
fn tls_connect(
    stream: TcpStream,
    host: &str,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, Recording>, String> {
    let local = stream.local_addr().ok();
    let peer = stream.peer_addr().ok();
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let platform = rustls_platform_verifier::Verifier::new(provider.clone())
        .map_err(|e| format!("tls: {e}"))?;
    let (name, _) = split_host_port(host);
    let verifier = GoVerifier {
        inner: std::sync::Arc::new(platform),
        host: name.clone(),
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(name.clone())
        .map_err(|_| format!("tls: invalid server name {name:?}"))?;
    let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), server_name)
        .map_err(|e| format!("tls: {e}"))?;
    let mut sock = Recording::new(stream);
    let started = Instant::now();
    while conn.is_handshaking() {
        let left = TLS_HANDSHAKE_TIMEOUT.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err("net/http: TLS handshake timeout".to_string());
        }
        let _ = sock.inner.set_read_timeout(Some(left));
        if let Err(e) = conn.complete_io(&mut sock) {
            return Err(tls_error(&e, &sock, local, peer));
        }
    }
    let _ = sock.inner.set_read_timeout(None);
    Ok(rustls::StreamOwned::new(conn, sock))
}

/// go's names of the TLS alerts (`crypto/tls/alert.go`).
fn go_alert(code: u8) -> String {
    let name = match code {
        0 => "close notify",
        10 => "unexpected message",
        20 => "bad record MAC",
        21 => "decryption failed",
        22 => "record overflow",
        30 => "decompression failure",
        40 => "handshake failure",
        42 => "bad certificate",
        43 => "unsupported certificate",
        44 => "revoked certificate",
        45 => "expired certificate",
        46 => "unknown certificate",
        47 => "illegal parameter",
        48 => "unknown certificate authority",
        49 => "access denied",
        50 => "error decoding message",
        51 => "error decrypting message",
        60 => "export restriction",
        70 => "protocol version not supported",
        71 => "insufficient security level",
        80 => "internal error",
        86 => "inappropriate fallback",
        90 => "user canceled",
        100 => "no renegotiation",
        109 => "missing extension",
        110 => "unsupported extension",
        111 => "certificate unobtainable",
        112 => "unrecognized name",
        113 => "bad certificate status response",
        114 => "bad certificate hash value",
        115 => "unknown PSK identity",
        116 => "certificate required",
        120 => "no application protocol",
        _ => return format!("alert({code})"),
    };
    name.to_string()
}

/// go's text of a failed TLS handshake.
fn tls_error(
    e: &std::io::Error,
    sock: &Recording,
    local: Option<SocketAddr>,
    peer: Option<SocketAddr>,
) -> String {
    use rustls::{CertificateError, Error as TlsError};
    let first = sock.first.as_slice();
    let tls = e.get_ref().and_then(|i| i.downcast_ref::<TlsError>());
    // go's first record check: `typ` an alert or a handshake, `vers` below
    // 0x1000, else `tls.RecordHeaderError`
    let first_record_bad = first.len() == 5
        && ((first[0] != 21 && first[0] != 22)
            || u16::from_be_bytes([first[1], first[2]]) >= 0x1000);
    match tls {
        Some(TlsError::General(t)) if t.starts_with("x509: ") => {
            format!("tls: failed to verify certificate: {t}")
        }
        Some(TlsError::InvalidCertificate(CertificateError::UnknownIssuer)) => {
            "tls: failed to verify certificate: x509: certificate signed by unknown authority"
                .to_string()
        }
        Some(TlsError::InvalidCertificate(
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. },
        )) => "tls: failed to verify certificate: x509: certificate specifies an incompatible key usage"
            .to_string(),
        Some(TlsError::InvalidCertificate(CertificateError::Other(o)))
            if format!("{o:?}").contains("EkuError") =>
        {
            "tls: failed to verify certificate: x509: certificate specifies an incompatible key usage"
                .to_string()
        }
        Some(TlsError::InvalidCertificate(c)) => {
            format!("tls: failed to verify certificate: {c:?}")
        }
        // a `close_notify` is go's `io.EOF`
        Some(TlsError::AlertReceived(d)) if u8::from(*d) == 0 => "EOF".to_string(),
        Some(TlsError::AlertReceived(d)) => {
            format!("remote error: tls: {}", go_alert(u8::from(*d)))
        }
        // go's transport: a `RecordHeaderError` whose bytes read like HTTP
        Some(_) if first.starts_with(b"HTTP/") => {
            "http: server gave HTTP response to HTTPS client".to_string()
        }
        Some(_) if first_record_bad => {
            "tls: first record does not look like a TLS handshake".to_string()
        }
        Some(_) if sock.last_len > 16384 + 2048 => {
            format!("tls: oversized record received with length {}", sock.last_len)
        }
        Some(other) => format!("tls: {other}"),
        None if matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ) =>
        {
            "net/http: TLS handshake timeout".to_string()
        }
        None if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            if sock.mid_record() {
                "unexpected EOF".to_string()
            } else {
                "EOF".to_string()
            }
        }
        None => match (local, peer) {
            (Some(l), Some(p)) => format!("read tcp {l}->{p}: read: {}", errno_text(e)),
            _ => errno_text(e),
        },
    }
}

/// go: `net/http: HTTP/1.x transport connection broken: <err>`.
fn broken(e: impl std::fmt::Display) -> String {
    format!("net/http: HTTP/1.x transport connection broken: {e}")
}

fn read_response(
    stream: impl Read,
    local: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    method: &str,
    url: &GoUrl,
) -> Result<RoundTrip, String> {
    let read_err = |e: &std::io::Error| match (local, peer) {
        (Some(l), Some(p)) => format!("read tcp {l}->{p}: read: {}", errno_text(e)),
        _ => errno_text(e),
    };
    let mut r = BufReader::new(stream);
    // go's readLoop peeks the first byte: nothing before the close is a
    // bare `EOF`
    match r.fill_buf() {
        Ok([]) => return Err("EOF".to_string()),
        Ok(_) => {}
        Err(e) => return Err(read_err(&e)),
    }
    loop {
        let line = read_line(&mut r)
            .map_err(|e| broken(read_err(&e)))?
            .ok_or_else(|| broken("unexpected EOF"))?;
        let (proto, status) = match line.iter().position(|&b| b == b' ') {
            Some(i) => (&line[..i], &line[i + 1..]),
            None => return Err(broken(bad_string("malformed HTTP response", &line))),
        };
        let status_start = status
            .iter()
            .position(|&b| b != b' ')
            .unwrap_or(status.len());
        let status = &status[status_start..];
        let code_text = match status.iter().position(|&b| b == b' ') {
            Some(i) => &status[..i],
            None => status,
        };
        if code_text.len() != 3 {
            return Err(broken(bad_string("malformed HTTP status code", code_text)));
        }
        let status_code = std::str::from_utf8(code_text)
            .ok()
            .and_then(go_atoi)
            .filter(|c| *c >= 0)
            .ok_or_else(|| broken(bad_string("malformed HTTP status code", code_text)))?;
        let Some((major, minor)) = parse_http_version(proto) else {
            return Err(broken(bad_string("malformed HTTP version", proto)));
        };
        let header = read_mime_header(&mut r).map_err(|e| match e {
            HeaderError::Io(e) => broken(read_err(&e)),
            HeaderError::Text(t) => broken(t),
        })?;
        let status_code = u16::try_from(status_code).unwrap_or(u16::MAX);
        if (100..=199).contains(&status_code) && status_code != 101 {
            continue;
        }
        let chunked = transfer_chunked(&header, (major, minor)).map_err(broken)?;
        let content_length = fix_length(status_code, method, &header, chunked).map_err(broken)?;
        let mut body = Vec::new();
        let mut body_err = None;
        if chunked {
            if let Err(e) = read_chunked(&mut r, &mut body) {
                body_err = Some(match e {
                    HeaderError::Io(e) => read_err(&e),
                    HeaderError::Text(t) => t,
                });
            }
        } else if content_length > 0 {
            let want = content_length as u64;
            if let Err(e) = (&mut r).take(want).read_to_end(&mut body) {
                body_err = Some(read_err(&e));
            } else if (body.len() as u64) < want {
                body_err = Some("unexpected EOF".to_string());
            }
        } else if content_length < 0 {
            if let Err(e) = r.read_to_end(&mut body) {
                body_err = Some(read_err(&e));
            }
        }
        let location = header
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(b"location"))
            .map(|(_, v)| algo_types::raw_text::go_lossy(v));
        return Ok(RoundTrip {
            response: Response {
                status_code,
                status: algo_types::raw_text::encode(status).into_owned(),
                content_length,
                body,
                body_err,
                url: url.clone(),
            },
            location,
        });
    }
}

/// go: `badStringError(what, val)`: `<what> %q`.
fn bad_string(what: &str, val: &[u8]) -> String {
    format!("{what} {}", algo_avm::assembler::go_quote_bytes(val))
}

/// go: `strconv.Atoi` of a 3-byte status code.
fn go_atoi(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// go: `ParseHTTPVersion`.
fn parse_http_version(v: &[u8]) -> Option<(u8, u8)> {
    match v {
        b"HTTP/1.1" => return Some((1, 1)),
        b"HTTP/1.0" => return Some((1, 0)),
        _ => {}
    }
    if v.len() != 8 || !v.starts_with(b"HTTP/") || v[6] != b'.' {
        return None;
    }
    let digit = |b: u8| b.is_ascii_digit().then(|| b - b'0');
    Some((digit(v[5])?, digit(v[7])?))
}

/// A line without its `\n` / `\r\n` (go's `bufio.Reader.ReadLine`); `None`
/// at the end of the stream.
fn read_line(r: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    if r.read_until(b'\n', &mut line)? == 0 {
        return Ok(None);
    }
    if line.ends_with(b"\n") {
        line.pop();
        if line.ends_with(b"\r") {
            line.pop();
        }
    }
    Ok(Some(line))
}

enum HeaderError {
    Io(std::io::Error),
    Text(String),
}

impl From<std::io::Error> for HeaderError {
    fn from(e: std::io::Error) -> Self {
        HeaderError::Io(e)
    }
}

fn eof() -> HeaderError {
    HeaderError::Text("unexpected EOF".to_string())
}

/// go: `textproto.Reader.ReadMIMEHeader`, the keys as sent.
/// A MIME header: `(key, value)` pairs as sent.
type Header = Vec<(Vec<u8>, Vec<u8>)>;

fn read_mime_header(r: &mut impl BufRead) -> Result<Header, HeaderError> {
    let mut out = Vec::new();
    if matches!(r.fill_buf()?.first(), Some(b' ' | b'\t')) {
        let line = read_line(r)?.ok_or_else(eof)?;
        if line.len() > 80 {
            return Err(HeaderError::Text("message too large".to_string()));
        }
        return Err(HeaderError::Text(format!(
            "malformed MIME header initial line: {}",
            algo_types::raw_text::encode(&line)
        )));
    }
    loop {
        let Some(line) = read_line(r)? else {
            return Err(eof());
        };
        if line.is_empty() {
            return Ok(out);
        }
        if !line.contains(&b':') {
            return Err(HeaderError::Text(format!(
                "malformed MIME header: missing colon: {}",
                algo_avm::assembler::go_quote_bytes(&line)
            )));
        }
        // continuation lines, folded with one space
        let mut kv = trim(&line).to_vec();
        while matches!(r.fill_buf()?.first(), Some(b' ' | b'\t')) {
            let Some(next) = read_line(r)? else {
                return Err(eof());
            };
            kv.push(b' ');
            kv.extend_from_slice(trim(&next));
        }
        let malformed = || {
            HeaderError::Text(format!(
                "malformed MIME header line: {}",
                algo_types::raw_text::encode(&kv)
            ))
        };
        let colon = kv.iter().position(|&b| b == b':').ok_or_else(malformed)?;
        let (k, v) = (&kv[..colon], &kv[colon + 1..]);
        if k.is_empty() || !k.iter().all(|&b| token_byte(b)) {
            return Err(malformed());
        }
        if !v
            .iter()
            .all(|&b| b >= 0x80 || (b >= 0x20 && b != 0x7f) || b == b'\t')
        {
            return Err(malformed());
        }
        let start = v
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .unwrap_or(v.len());
        out.push((k.to_vec(), v[start..].to_vec()));
    }
}

/// go: `textproto.trim` (ASCII spaces and tabs at both ends).
fn trim(s: &[u8]) -> &[u8] {
    let is_space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r');
    let start = s.iter().position(|b| !is_space(b)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|b| !is_space(b))
        .map_or(start, |i| i + 1);
    &s[start..end]
}

/// go: `validHeaderFieldByte` (an RFC 7230 token character).
fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn header_values<'a>(header: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Vec<&'a [u8]> {
    header
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| v.as_slice())
        .collect()
}

/// go's `%q` of a `[]string`: `["a" "b"]`.
fn quote_list(values: &[&[u8]]) -> String {
    let quoted: Vec<String> = values
        .iter()
        .map(|v| algo_avm::assembler::go_quote_bytes(v))
        .collect();
    format!("[{}]", quoted.join(" "))
}

/// go: `transferReader.parseTransferEncoding`: whether the body is chunked.
fn transfer_chunked(header: &[(Vec<u8>, Vec<u8>)], proto: (u8, u8)) -> Result<bool, String> {
    let raw = header_values(header, "Transfer-Encoding");
    if raw.is_empty() || proto < (1, 1) {
        return Ok(false);
    }
    if raw.len() != 1 {
        return Err(format!("too many transfer encodings: {}", quote_list(&raw)));
    }
    if !raw[0].eq_ignore_ascii_case(b"chunked") {
        return Err(format!(
            "unsupported transfer encoding: {}",
            algo_avm::assembler::go_quote_bytes(raw[0])
        ));
    }
    Ok(true)
}

/// go: `fixLength` of a response: the body length, `-1` when unknown.
fn fix_length(
    status: u16,
    method: &str,
    header: &[(Vec<u8>, Vec<u8>)],
    chunked: bool,
) -> Result<i64, String> {
    let lens = header_values(header, "Content-Length");
    if lens.len() > 1 {
        let first = trim(lens[0]);
        if lens[1..].iter().any(|l| trim(l) != first) {
            return Err(format!(
                "http: message cannot contain multiple Content-Length headers; got {}",
                quote_list(&lens)
            ));
        }
    }
    let mut n = -1i64;
    if let Some(cl) = lens.first() {
        let cl = trim(cl);
        if cl.is_empty() {
            return Err(bad_string("invalid empty Content-Length", cl));
        }
        n = std::str::from_utf8(cl)
            .ok()
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|v| *v < 1 << 63)
            .map(|v| v as i64)
            .ok_or_else(|| bad_string("bad Content-Length", cl))?;
    }
    if method == "HEAD" || status / 100 == 1 || status == 204 || status == 304 {
        return Ok(0);
    }
    if chunked {
        return Ok(-1);
    }
    Ok(n)
}

/// go: `internal.chunkedReader`, into `out`.
fn read_chunked(r: &mut impl BufRead, out: &mut Vec<u8>) -> Result<(), HeaderError> {
    loop {
        let line = read_line(r)?.ok_or_else(eof)?;
        let line = trim(&line);
        let size_text = match line.iter().position(|&b| b == b';') {
            Some(i) => trim(&line[..i]),
            None => line,
        };
        if size_text.is_empty() {
            return Err(HeaderError::Text(
                "empty hex number for chunk length".to_string(),
            ));
        }
        let mut size = 0u64;
        for (i, &b) in size_text.iter().enumerate() {
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => {
                    return Err(HeaderError::Text(
                        "invalid byte in chunk length".to_string(),
                    ))
                }
            };
            if i == 16 {
                return Err(HeaderError::Text("http chunk length too large".to_string()));
            }
            size = size << 4 | u64::from(d);
        }
        if size == 0 {
            // the trailer, up to the empty line
            while let Some(l) = read_line(r)? {
                if l.is_empty() {
                    break;
                }
            }
            return Ok(());
        }
        let got = r.take(size).read_to_end(out)?;
        if (got as u64) < size {
            return Err(eof());
        }
        let mut crlf = [0u8; 2];
        match r.read_exact(&mut crlf) {
            Ok(()) if crlf == *b"\r\n" => {}
            Ok(()) => {
                return Err(HeaderError::Text("malformed chunked encoding".to_string()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(eof()),
            Err(e) => return Err(HeaderError::Io(e)),
        }
    }
}

// ---- the dialer ---------------------------------------------------------------

/// The text of a socket error as go's `syscall.Errno` prints it
/// (`connection refused`, `network is unreachable`, ...).
fn errno_text(e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        return "i/o timeout".to_string();
    }
    let text = match e.raw_os_error() {
        Some(code) => {
            let full = std::io::Error::from_raw_os_error(code).to_string();
            match full.rfind(" (os error") {
                Some(i) => full[..i].to_string(),
                None => full,
            }
        }
        None => e.to_string(),
    };
    let mut chars = text.chars();
    match chars.next() {
        Some(c) => format!("{}{}", c.to_lowercase(), chars.as_str()),
        None => text,
    }
}

/// `host:port` split like go's `net.SplitHostPort` (the port defaulting to
/// HTTP's).
fn split_host_port(hostport: &str) -> (String, String) {
    if let Some(rest) = hostport.strip_prefix('[') {
        if let Some((h, after)) = rest.split_once(']') {
            let port = after.strip_prefix(':').unwrap_or("");
            let port = if port.is_empty() { "80" } else { port };
            return (h.to_string(), port.to_string());
        }
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let p = if p.is_empty() { "80" } else { p };
            (h.to_string(), p.to_string())
        }
        _ => (hostport.to_string(), "80".to_string()),
    }
}

/// go: `Dialer.DialContext("tcp", hostport)`.
fn dial(hostport: &str) -> Result<TcpStream, String> {
    let (host, port_text) = split_host_port(hostport);
    // go: `parsePort`: a number beyond 65535 is invalid, a name is looked up
    // as a service
    let port = if !port_text.is_empty() && port_text.bytes().all(|b| b.is_ascii_digit()) {
        match port_text.parse::<u16>() {
            Ok(p) => p,
            Err(_) => return Err(format!("dial tcp: address {port_text}: invalid port")),
        }
    } else {
        return Err(format!("dial tcp: lookup tcp/{port_text}: unknown port"));
    };
    let ips = resolve(&host).map_err(|e| format!("dial tcp: {e}"))?;
    let deadline = Instant::now() + DIAL_TIMEOUT;
    let mut first_err = None;
    let n = ips.len();
    for (i, ip) in ips.into_iter().enumerate() {
        let addr = SocketAddr::new(ip, port);
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            first_err.get_or_insert_with(|| format!("dial tcp {addr}: i/o timeout"));
            break;
        }
        // go: `partialDeadline`
        let mut timeout = remaining / (n - i) as u32;
        if timeout < DIAL_SANE_MINIMUM {
            timeout = remaining.min(DIAL_SANE_MINIMUM);
        }
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => {
                let text = if e.kind() == std::io::ErrorKind::TimedOut {
                    format!("dial tcp {addr}: i/o timeout")
                } else {
                    format!("dial tcp {addr}: connect: {}", errno_text(&e))
                };
                first_err.get_or_insert(text);
            }
        }
    }
    Err(first_err.unwrap_or_else(|| format!("dial tcp: lookup {host}: no such host")))
}

/// The addresses go's resolver returns for `host`, or its `*net.DNSError`
/// text.
fn resolve(host: &str) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let hosts = hosts_file_lookup(host);
    if !hosts.is_empty() {
        return Ok(hosts);
    }
    if !is_domain_name(host) {
        return Err(format!("lookup {host}: no such host"));
    }
    use std::net::ToSocketAddrs as _;
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let mut ips: Vec<IpAddr> = Vec::new();
            for a in addrs {
                if !ips.contains(&a.ip()) {
                    ips.push(a.ip());
                }
            }
            if ips.is_empty() {
                return Err(format!("lookup {host} on {}: no such host", nameserver()));
            }
            Ok(ips)
        }
        Err(e) => {
            let text = e.to_string();
            let what = if text.contains("Temporary failure") {
                "server misbehaving"
            } else {
                "no such host"
            };
            Err(format!("lookup {host} on {}: {what}", nameserver()))
        }
    }
}

/// The DNS server go's resolver asks first: the first `nameserver` of
/// `/etc/resolv.conf`, else `127.0.0.1:53`.
fn nameserver() -> String {
    let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    for line in conf.lines() {
        let mut f = line.split_whitespace();
        if f.next() == Some("nameserver") {
            if let Some(ip) = f.next().and_then(|s| s.parse::<IpAddr>().ok()) {
                return SocketAddr::new(ip, 53).to_string();
            }
        }
    }
    "127.0.0.1:53".to_string()
}

/// go: `lookupStaticHost`: the addresses `/etc/hosts` names `host` with,
/// in file order.
fn hosts_file_lookup(host: &str) -> Vec<IpAddr> {
    if !cfg!(unix) {
        return Vec::new();
    }
    let want = host.trim_end_matches('.').to_ascii_lowercase();
    let text = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut f = line.split_whitespace();
        let Some(ip) = f.next().and_then(|s| s.parse::<IpAddr>().ok()) else {
            continue;
        };
        if f.any(|name| name.trim_end_matches('.').to_ascii_lowercase() == want) {
            out.push(ip);
        }
    }
    out
}

/// go: `isDomainName`.
fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }
    let b = s.as_bytes();
    let l = b.len();
    if l == 0 || l > 254 || l == 254 && b[l - 1] != b'.' {
        return false;
    }
    let mut last = b'.';
    let mut non_numeric = false;
    let mut partlen = 0;
    for &c in b {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                partlen += 1;
            }
            b'0'..=b'9' => partlen += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                partlen += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' || partlen > 63 || partlen == 0 {
                    return false;
                }
                partlen = 0;
            }
            _ => return false,
        }
        last = c;
    }
    if last == b'-' || partlen > 63 {
        return false;
    }
    non_numeric
}

/// go: `http.ProxyFromEnvironment` for an `http` request to `host`: the
/// proxy's `host:port`, or `None` to dial directly.
fn proxy_for(host: &str, https: bool) -> Option<Proxy> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    // go ignores HTTP_PROXY when run as a CGI script
    if env("REQUEST_METHOD").is_some() {
        return None;
    }
    let proxy = if https {
        env("HTTPS_PROXY").or_else(|| env("https_proxy"))?
    } else {
        env("HTTP_PROXY").or_else(|| env("http_proxy"))?
    };
    let (name, _) = split_host_port(host);
    let name = name.to_ascii_lowercase();
    if name == "localhost" || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
        return None;
    }
    let no_proxy = env("NO_PROXY")
        .or_else(|| env("no_proxy"))
        .unwrap_or_default();
    for entry in no_proxy.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if entry == "*" {
            return None;
        }
        let (entry_host, _) = split_host_port(entry);
        let entry_host = entry_host.to_ascii_lowercase();
        let suffix = entry_host.trim_start_matches('.');
        if name == suffix || name.ends_with(&format!(".{suffix}")) {
            return None;
        }
    }
    let url = if proxy.contains("://") {
        GoUrl::parse(&proxy)
    } else {
        GoUrl::parse(&format!("http://{proxy}"))
    };
    // go's `Proxy-Authorization: Basic` of the proxy URL's user info
    let auth = url.authority.rfind('@').map(|i| {
        let info = &url.authority[..i];
        let (user, pass) = info.split_once(':').unwrap_or((info, ""));
        let credentials = format!("{}:{}", percent_decode(user), percent_decode(pass));
        format!(
            "Basic {}",
            data_encoding::BASE64.encode(credentials.as_bytes())
        )
    });
    Some(Proxy {
        addr: url.host().to_string(),
        auth,
    })
}

/// The proxy of a request: where to dial and the `Proxy-Authorization` value.
#[derive(Debug, PartialEq, Eq)]
struct Proxy {
    addr: String,
    auth: Option<String>,
}

/// go's `url.PathUnescape` of user info, `%XX` only.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_print_like_go() {
        let u = GoUrl::for_request(
            "http://127.0.0.1:8080",
            "/v2/catchup/1#AB c",
            &[("min", "5"), ("next", "a b*~")],
        );
        assert_eq!(
            u.to_string(),
            "http://127.0.0.1:8080/v2/catchup/1%23AB%20c?min=5&next=a+b%2A~"
        );
        assert_eq!(u.request_uri(), "/v2/catchup/1%23AB%20c?min=5&next=a+b%2A~");
        let u = GoUrl::for_request("http://h:80/x?a=1", "/versions", &[("b", "2")]);
        assert_eq!(u.to_string(), "http://h:80/versions?a=1&b=2");
    }

    #[test]
    fn domain_names_like_go() {
        assert!(is_domain_name("algod.invalid"));
        assert!(!is_domain_name("256.1.1.1"));
        assert!(!is_domain_name("a..b"));
        assert!(!is_domain_name("a-"));
    }

    fn serve(answer: &'static [u8]) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let _ = s.write_all(answer);
            }
        });
        format!("http://{addr}")
    }

    fn get(answer: &'static [u8]) -> Result<Response, String> {
        let base = serve(answer);
        request("GET", &GoUrl::for_request(&base, "/x", &[]), &[], None)
            .map_err(|e| e.replacen(&format!("Get \"{base}/x\": "), "", 1))
    }

    #[test]
    fn answers_read_like_go() {
        let r = get(b"HTTP/1.1 500 Boom Town\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((r.status_code, r.status.as_str()), (500, "500 Boom Town"));
        assert_eq!(r.body, b"{}");
        let r = get(b"HTTP/1.1 599\r\n\r\n").unwrap();
        assert_eq!(r.status, "599");
        let r = get(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1;x\r\nc\r\n0\r\n\r\n").unwrap();
        assert_eq!((r.body.as_slice(), r.content_length), (&b"abc"[..], -1));
        let r = get(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab").unwrap();
        assert_eq!(r.body_err.as_deref(), Some("unexpected EOF"));
        let r = get(b"HTTP/1.1 500 B\xffad\r\n\r\n").unwrap();
        assert_eq!(
            algo_types::raw_text::decode(&r.status).as_ref(),
            b"500 B\xffad"
        );
    }

    #[test]
    fn malformed_answers_read_like_go() {
        let b = "net/http: HTTP/1.x transport connection broken: ";
        for (answer, want) in [
            (&b""[..], "EOF".to_string()),
            (
                b"garbage\r\n\r\n",
                format!("{b}malformed HTTP response \"garbage\""),
            ),
            (
                b"\x15\x03\x01\x00\x02\x02P",
                format!("{b}malformed HTTP response \"\\x15\\x03\\x01\\x00\\x02\\x02P\""),
            ),
            (
                b"HTTP/1.1 20 OK\r\n\r\n",
                format!("{b}malformed HTTP status code \"20\""),
            ),
            (
                b"HTTP/1.1 2x0 OK\r\n\r\n",
                format!("{b}malformed HTTP status code \"2x0\""),
            ),
            (
                b"HTTX/1.1 200 OK\r\n\r\n",
                format!("{b}malformed HTTP version \"HTTX/1.1\""),
            ),
            (b"HTTP/1.1 200 OK\r\n", format!("{b}unexpected EOF")),
            (
                b"HTTP/1.1 200 OK\r\nbad\r\n\r\n",
                format!("{b}malformed MIME header: missing colon: \"bad\""),
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
                format!("{b}bad Content-Length \"x\""),
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
                format!("{b}unsupported transfer encoding: \"gzip\""),
            ),
        ] {
            let answer: &'static [u8] = Box::leak(answer.to_vec().into_boxed_slice());
            assert_eq!(get(answer).unwrap_err(), want);
        }
    }

    #[test]
    fn redirects_are_followed() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for (i, s) in l.incoming().enumerate() {
                let Ok(mut s) = s else { continue };
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let answer = if i == 0 {
                    "HTTP/1.1 302 Found\r\nLocation: /y?z=1\r\nContent-Length: 0\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                };
                let _ = s.write_all(answer.as_bytes());
            }
        });
        let r = request(
            "GET",
            &GoUrl::for_request(&format!("http://{addr}"), "/x", &[]),
            &[],
            None,
        )
        .unwrap();
        assert_eq!(r.body, b"ok");
        assert_eq!(r.url.to_string(), format!("http://{addr}/y?z=1"));
    }

    #[test]
    fn a_refused_dial_reads_like_go() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_eq!(
            dial(&format!("127.0.0.1:{port}")).unwrap_err(),
            format!("dial tcp 127.0.0.1:{port}: connect: connection refused")
        );
        assert_eq!(
            dial("256.1.1.1:80").unwrap_err(),
            "dial tcp: lookup 256.1.1.1: no such host"
        );
    }
}
