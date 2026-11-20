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

//! go's algod REST client (`daemon/algod/api/client/restClient.go`
//! `RestClient.submitForm`), issues #2466 / #2476: the request (go's URL,
//! the `rawRequestPaths` bodies), the errors of a request that gets no
//! answer ([`crate::go_http`]: go's `net/http` texts), the `extractError`
//! of an answer that is not 200 / 201 (`HTTP <resp.Status>: <message>`,
//! `Unauthorized request to `<url>` when using token `<token>` :
//! <message>`), `expectNoContent`, and go-codec's decode of a JSON answer
//! ([`crate::go_codec_json`]).
//!
//! Error texts are in the lossless form of [`algo_types::raw_text`]: the
//! server's reason phrase keeps its bytes. [`print_raw`] writes them as go
//! does where go prints the error unfiltered; `reportErrorf` sites filter
//! them through [`crate::formatting::report_error_text`].

use crate::go_codec_json::{self, Ty};
use crate::go_http::{self, GoUrl};

/// go: `authHeader`.
const AUTH_HEADER: &str = "X-Algo-API-Token";

/// go: `maxRawResponseBytes`.
const MAX_RAW_RESPONSE_BYTES: usize = 50_000_000;

/// The `(base URL, token)` of an algod, as
/// [`crate::goal_client::algod_endpoint`] returns it.
pub type Endpoint = (String, String);

/// A 200 / 201 answer.
pub struct Answer {
    /// The body bytes read.
    pub body: Vec<u8>,
    /// The error the body read ended with.
    pub body_err: Option<String>,
    /// `resp.ContentLength`.
    pub content_length: i64,
}

/// `<method> <path>?<query>` against algod as go's
/// `RestClient.submitForm`: the 200 / 201 answer, or go's error text.
/// `query` is go's `url.Values` (`query.Values` of the params struct,
/// encoded sorted by key); `body` the raw request body of a
/// `rawRequestPaths` POST.
pub fn submit(
    rt: &tokio::runtime::Runtime,
    (base, token): &Endpoint,
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<Answer, String> {
    let url = GoUrl::for_request(base, path, query);
    // go: every path but `/health` carries the token
    let sent_token = if path == "/health" {
        ""
    } else {
        token.as_str()
    };
    let headers: Vec<(&str, &str)> = if path == "/health" {
        Vec::new()
    } else {
        vec![(AUTH_HEADER, token.as_str())]
    };
    let resp = if url.scheme == "https" {
        tls_request(rt, method, &url, &headers, body)?
    } else {
        go_http::request(method, &url, &headers, body)?
    };
    if resp.status_code != 200 && resp.status_code != 201 {
        let message = error_message(&String::from_utf8_lossy(&resp.body));
        if resp.status_code == 401 {
            return Err(format!(
                "Unauthorized request to `{}` when using token `{sent_token}` : {message}",
                resp.url
            ));
        }
        return Err(format!("HTTP {}: {message}", resp.status));
    }
    let mut body = resp.body;
    let mut body_err = resp.body_err;
    // go: `http.MaxBytesReader(nil, resp.Body, maxRawResponseBytes)`
    if body.len() > MAX_RAW_RESPONSE_BYTES {
        body.truncate(MAX_RAW_RESPONSE_BYTES);
        body_err = Some("http: request body too large".to_string());
    }
    Ok(Answer {
        body,
        body_err,
        content_length: resp.content_length,
    })
}

/// go: `client.getRaw`: the body of a GET.
pub fn get(
    rt: &tokio::runtime::Runtime,
    endpoint: &Endpoint,
    path: &str,
    query: &[(&str, &str)],
) -> Result<Vec<u8>, String> {
    raw(submit(rt, endpoint, "GET", path, query, None)?)
}

/// go: `client.get`: a GET decoded into `ty`.
pub fn get_json(
    rt: &tokio::runtime::Runtime,
    endpoint: &Endpoint,
    path: &str,
    query: &[(&str, &str)],
    ty: &'static Ty,
) -> Result<serde_json::Value, String> {
    json(submit(rt, endpoint, "GET", path, query, None)?, ty)
}

/// go: `client.post` of a `rawRequestPaths` body (`PostParticipationKey`,
/// ...), or `submitForm(..., "POST", false, true, false)` without one
/// (`Catchup`): the answer decoded into `ty`.
pub fn post_json(
    rt: &tokio::runtime::Runtime,
    endpoint: &Endpoint,
    path: &str,
    query: &[(&str, &str)],
    body: Option<&[u8]>,
    ty: &'static Ty,
) -> Result<serde_json::Value, String> {
    json(submit(rt, endpoint, "POST", path, query, body)?, ty)
}

/// go: `client.delete(response, path, nil, expectNoContent)`: the answer
/// decoded into `ty`, or nothing when `expect_no_content`.
pub fn delete(
    rt: &tokio::runtime::Runtime,
    endpoint: &Endpoint,
    path: &str,
    ty: &'static Ty,
    expect_no_content: bool,
) -> Result<Option<serde_json::Value>, String> {
    let answer = submit(rt, endpoint, "DELETE", path, &[], None)?;
    if expect_no_content {
        if answer.content_length == 0 {
            return Ok(None);
        }
        return Err(format!(
            "expected empty response but got response of {} bytes",
            answer.content_length
        ));
    }
    json(answer, ty).map(Some)
}

/// The status code of go's `HTTPError` text (`HTTP <resp.Status>: ...`):
/// what `errors.As(err, &httpError)` then `httpError.StatusCode` reads.
pub fn http_error_status(err: &str) -> Option<u16> {
    let status = err.strip_prefix("HTTP ")?;
    let code = status.get(..3)?;
    let digits = code.trim_start_matches(['+', '-']);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    code.parse::<u16>().ok()
}

/// go: `libgoal.Client.AssetInformation`: `GET /v2/assets/<index>` into a
/// `model.Asset`, then a non-empty `name-b64` / `unit-name-b64` / `url-b64`
/// replaces `name` / `unit-name` / `url` (`string(bytes)`).
pub fn asset_information(
    rt: &tokio::runtime::Runtime,
    endpoint: &Endpoint,
    index: u64,
) -> Result<serde_json::Value, String> {
    use base64::Engine as _;
    let mut asset = get_json(
        rt,
        endpoint,
        &format!("/v2/assets/{index}"),
        &[],
        &go_codec_json::ASSET,
    )?;
    if let Some(params) = asset.get_mut("params").and_then(|p| p.as_object_mut()) {
        for (field, b64) in [
            ("name", "name-b64"),
            ("unit-name", "unit-name-b64"),
            ("url", "url-b64"),
        ] {
            let bytes = params
                .get(b64)
                .and_then(|v| v.as_str())
                .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                .unwrap_or_default();
            if !bytes.is_empty() {
                params.insert(
                    field.to_string(),
                    serde_json::Value::String(algo_types::raw_text::go_lossy(&bytes)),
                );
            }
        }
    }
    Ok(asset)
}

/// go: `io.ReadAll(resp.Body)` of a raw answer.
fn raw(answer: Answer) -> Result<Vec<u8>, String> {
    match answer.body_err {
        Some(e) => Err(e),
        None => Ok(answer.body),
    }
}

/// go: `protocol.NewJSONDecoder(resp.Body).Decode(&response)`.
fn json(answer: Answer, ty: &'static Ty) -> Result<serde_json::Value, String> {
    let (decoded, hit_end) = go_codec_json::decode_reading(&answer.body, ty);
    match (decoded, answer.body_err) {
        // go-codec read on where the body broke off: the read's error
        (_, Some(e)) if hit_end => Err(e),
        (Ok(v), _) => Ok(v),
        (Err(e), _) => Err(e.to_string()),
    }
}

/// Write `text` (the lossless form) to stderr as its bytes, then a newline:
/// go's `fmt.Fprintln(os.Stderr, err)`.
pub fn print_raw(text: &str) {
    eprint_raw(&format!("{text}\n"));
}

/// Write `text` (the lossless form) to stderr as its bytes: go's
/// `fmt.Fprint(os.Stderr, s)`.
pub fn eprint_raw(text: &str) {
    use std::io::Write as _;
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(&algo_types::raw_text::decode(text));
}

/// An `https:` algod: the request through reqwest's TLS client.
fn tls_request(
    rt: &tokio::runtime::Runtime,
    method: &str,
    url: &GoUrl,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<go_http::Response, String> {
    let op = {
        let mut c = method.chars();
        match c.next() {
            Some(f) => format!("{f}{}", c.as_str().to_ascii_lowercase()),
            None => String::new(),
        }
    };
    let text = url.to_string();
    let wrap = |e: &reqwest::Error| format!("{op} \"{text}\": {}", transport_error(e));
    rt.block_on(async {
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
        let mut req = reqwest::Client::new().request(method, text.as_str());
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        if let Some(b) = body {
            req = req.body(b.to_vec());
        }
        let resp = req.send().await.map_err(|e| wrap(&e))?;
        let status = resp.status();
        let final_url = GoUrl::parse(resp.url().as_str());
        let content_length = resp.content_length().map_or(-1, |n| n as i64);
        let (body, body_err) = match resp.bytes().await {
            Ok(b) => (b.to_vec(), None),
            Err(e) => (Vec::new(), Some(transport_error(&e))),
        };
        Ok(go_http::Response {
            status_code: status.as_u16(),
            status: status.to_string(),
            content_length,
            body,
            body_err,
            url: final_url,
        })
    })
}

/// The error text of a request reqwest sent that got no answer.
fn transport_error(e: &reqwest::Error) -> String {
    use std::error::Error as _;
    let mut source = e.source();
    while let Some(s) = source {
        if let Some(h) = s.downcast_ref::<hyper::Error>() {
            if h.is_incomplete_message() {
                return "EOF".to_string();
            }
        }
        source = s.source();
    }
    e.to_string()
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
            get(&rt, &ep, "/v2/accounts/X", &[("format", "json"), ("exclude", "all")]),
            Err(format!(
                "Get \"http://127.0.0.1:{port}/v2/accounts/X?exclude=all&format=json\": dial tcp 127.0.0.1:{port}: connect: connection refused"
            ))
        );
    }
}
