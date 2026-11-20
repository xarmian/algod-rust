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

//! go's algod REST client GET (`daemon/algod/api/client/restClient.go`
//! `RestClient.submitForm`), issue #2466: the request URL, the errors go's
//! `net/http` reports for a request that gets no answer (`Get "<url>":
//! dial tcp <addr>: connect: connection refused`, `Get "<url>": EOF`), the
//! `extractError` of an answer that is not 200 / 201 (`HTTP <status>:
//! <message>`, `Unauthorized request to `<url>` when using token `<token>`
//! : <message>`) and go-codec's decode of a JSON answer
//! ([`crate::go_codec_json`]).

use crate::go_codec_json::{self, Ty};

/// go: `authHeader`.
const AUTH_HEADER: &str = "X-Algo-API-Token";

/// `GET <path>?<query>` against algod (`(base URL, token)`, as
/// [`crate::goal_client::algod_endpoint`] returns it), as go's
/// `RestClient.submitForm`: the answer's body, or go's error text. `query`
/// is go's `url.Values` (`query.Values` of the params struct): encoded
/// sorted by key.
pub fn get(
    rt: &tokio::runtime::Runtime,
    (base, token): &(String, String),
    path: &str,
    query: &[(&str, &str)],
) -> Result<Vec<u8>, String> {
    let url = request_url(base, path, query)?;
    rt.block_on(async {
        let mut req = reqwest::Client::new().get(url.clone());
        // go: every path but `/health` carries the token
        let sent_token = if path == "/health" {
            ""
        } else {
            token.as_str()
        };
        if path != "/health" {
            req = req.header(AUTH_HEADER, token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| transport_error("Get", url.as_str(), &e))?;
        answer("Get", url.as_str(), resp, sent_token).await
    })
}

/// `POST <path>` of `body` (`content_type`) against algod, as go's
/// `RestClient.submitForm` (e.g. `AddParticipationKey`): the answer's body,
/// or go's error text.
pub fn post(
    rt: &tokio::runtime::Runtime,
    (base, token): &(String, String),
    path: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let url = request_url(base, path, &[])?;
    rt.block_on(async {
        let resp = reqwest::Client::new()
            .post(url.clone())
            .header(AUTH_HEADER, token)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body)
            .send()
            .await
            .map_err(|e| transport_error("Post", url.as_str(), &e))?;
        answer("Post", url.as_str(), resp, token).await
    })
}

/// go's `submitForm` once an answer arrived: the body of a 200 / 201, else
/// go's `extractError` text.
async fn answer(
    op: &str,
    url: &str,
    resp: reqwest::Response,
    sent_token: &str,
) -> Result<Vec<u8>, String> {
    let status = resp.status();
    let final_url = resp.url().to_string();
    let body = resp
        .bytes()
        .await
        .map_err(|e| transport_error(op, url, &e))?;
    if status == 200 || status == 201 {
        return Ok(body.to_vec());
    }
    let message = error_message(&String::from_utf8_lossy(&body));
    if status == 401 {
        return Err(format!(
            "Unauthorized request to `{final_url}` when using token `{sent_token}` : {message}"
        ));
    }
    Err(format!("HTTP {status}: {message}"))
}

/// [`get`], then go-codec's decode of the body into `ty`
/// (`protocol.NewJSONDecoder(resp.Body).Decode(&response)`).
pub fn get_json(
    rt: &tokio::runtime::Runtime,
    endpoint: &(String, String),
    path: &str,
    query: &[(&str, &str)],
    ty: &'static Ty,
) -> Result<serde_json::Value, String> {
    let body = get(rt, endpoint, path, query)?;
    go_codec_json::decode(&body, ty).map_err(|e| e.to_string())
}

/// go: `queryURL := client.serverURL; queryURL.Path = path;
/// queryURL.RawQuery = v.Encode()`.
fn request_url(base: &str, path: &str, query: &[(&str, &str)]) -> Result<reqwest::Url, String> {
    let mut url = reqwest::Url::parse(base).map_err(|e| e.to_string())?;
    url.set_path(path);
    let mut sorted = query.to_vec();
    sorted.sort_by_key(|(k, _)| *k);
    if sorted.is_empty() {
        url.set_query(None);
    } else {
        url.query_pairs_mut().clear().extend_pairs(sorted);
    }
    Ok(url)
}

/// go's `*url.Error` of a request that got no answer: `<Op> "<url>":
/// <err>`, the error text that of go's `net` / `net/http` where it is
/// known.
fn transport_error(op: &str, url: &str, e: &reqwest::Error) -> String {
    use std::error::Error as _;
    let mut source = e.source();
    while let Some(s) = source {
        if let Some(io) = s.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::ConnectionRefused {
                if let Some(addr) = dial_addr(url) {
                    return format!("{op} \"{url}\": dial tcp {addr}: connect: connection refused");
                }
            }
        }
        if let Some(h) = s.downcast_ref::<hyper::Error>() {
            // the server closed the connection without an answer
            if h.is_incomplete_message() {
                return format!("{op} \"{url}\": EOF");
            }
        }
        source = s.source();
    }
    format!("{op} \"{url}\": {e}")
}

/// The `ip:port` go's dialer names: the first address the URL's host
/// resolves to.
fn dial_addr(url: &str) -> Option<std::net::SocketAddr> {
    use std::net::ToSocketAddrs as _;
    let url = reqwest::Url::parse(url).ok()?;
    let port = url.port_or_known_default()?;
    let host = url.host_str()?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Some((ip, port).into()),
        Err(_) => (host, port).to_socket_addrs().ok()?.next(),
    }
}

/// go's `extractError` message: the body decoded as a `model.ErrorResponse`
/// (its `message`, matched case-insensitively like `encoding/json`), else
/// the raw body, keeping only printable ASCII (`filterASCII`).
pub fn error_message(body: &str) -> String {
    let decoded = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Null) => Some(String::new()),
        Ok(serde_json::Value::Object(m)) => {
            let field = |name: &str| {
                m.iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v)
                    .next_back()
            };
            let message = match field("message") {
                None | Some(serde_json::Value::Null) => Some(String::new()),
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                Some(_) => None,
            };
            let data_ok = matches!(
                field("data"),
                None | Some(serde_json::Value::Null) | Some(serde_json::Value::Object(_))
            );
            message.filter(|_| data_ok)
        }
        _ => None,
    };
    decoded
        .unwrap_or_else(|| body.to_string())
        .chars()
        .filter(|c| (' '..='~').contains(c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_query_is_encoded_sorted_like_url_values() {
        let url = request_url(
            "http://127.0.0.1:8080",
            "/v2/accounts/X",
            &[("format", "json"), ("exclude", "all")],
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:8080/v2/accounts/X?exclude=all&format=json"
        );
        let url = request_url("http://127.0.0.1:8080/", "/versions", &[]).unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:8080/versions");
    }

    #[test]
    fn a_refused_connection_reads_like_go_net_http() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // bind then drop: nothing listens on the port
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let ep = (format!("http://127.0.0.1:{port}"), "t".repeat(64));
        assert_eq!(
            get(&rt, &ep, "/versions", &[]),
            Err(format!(
                "Get \"http://127.0.0.1:{port}/versions\": dial tcp 127.0.0.1:{port}: connect: connection refused"
            ))
        );
    }
}
