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

//! `algod-rust catchupsrv`: a Rust port of go-algorand's standalone
//! `cmd/catchupsrv` tool (issue #969, epic #830/Phase 17).
//!
//! go-algorand's `catchupsrv` serves individual block files over HTTP at
//! `rpcs.BlockServiceBlockPath` (`/v{version}/{genesisID}/block/{round}`),
//! reading them from `<dir>/v<version>/<genesisID>/block/<blockToPath(round)>`
//! on disk (`../go-algorand/cmd/catchupsrv/download.go`,
//! `../go-algorand/cmd/catchupsrv/main.go`). It is used to let an airgapped
//! `algod` fast-catch-up from a locally staged directory of block files
//! instead of the live gossip network — see
//! `../go-algorand/cmd/catchupsrv/README.md`.
//!
//! This module ports the exact round-number <-> file-path/name/URL-string
//! mapping (`block_to_path`/`block_to_file_name`/`block_to_string`,
//! matching go's `blockToPath`/`blockToFileName`/`blockToString`
//! byte-for-byte — see `TestBlockToPath`/`TestBlockToFileName`/
//! `TestBlockToString` in `download_test.go`) plus a minimal axum HTTP
//! server that serves files from that same on-disk layout, so a Go
//! catchup client pointed at `algod-rust catchupsrv` sees identical
//! URLs/paths/content-type to what it expects from a Go `catchupsrv`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::extract::{Path as AxumPath, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tracing::info;

/// Minimum length of a block filename (after zero-padding) when sharding
/// into subfolders. Matches go's `minLenBlockStr` in `download.go`.
const MIN_LEN_BLOCK_STR: usize = 6;

const BASE36_DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Converts a block number into its base-36 string representation.
/// Matches go's `blockToString` (`strconv.FormatUint(blk, 36)`).
pub fn block_to_string(blk: u64) -> String {
    if blk == 0 {
        return "0".to_string();
    }
    let mut digits = Vec::new();
    let mut n = blk;
    while n > 0 {
        digits.push(BASE36_DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    digits.reverse();
    // SAFETY: every pushed byte comes from BASE36_DIGITS, which is ASCII.
    String::from_utf8(digits).expect("base36 digits are always valid ASCII/UTF-8")
}

/// Converts a block number into the filename it will be stored/served as:
/// the base-36 representation, left-padded with zeros to at least
/// `MIN_LEN_BLOCK_STR` characters. Matches go's `blockToFileName`.
pub fn block_to_file_name(blk: u64) -> String {
    let s = block_to_string(blk);
    if s.len() < MIN_LEN_BLOCK_STR {
        format!("{}{}", "0".repeat(MIN_LEN_BLOCK_STR - s.len()), s)
    } else {
        s
    }
}

/// Converts a block number into the sharded relative path it will be
/// stored/served at, e.g. for block `bcdef` the path is `0b/cd/0bcdef`, and
/// for block `abcdefg` the path is `abc/de/abcdefg`. Matches go's
/// `blockToPath`, which splits the (zero-padded) filename into a
/// `len-4`/`2`/`len` three-way split so the first two path components stay
/// exactly two characters wide regardless of the block number's magnitude.
pub fn block_to_path(blk: u64) -> String {
    let s = block_to_file_name(blk);
    let len = s.len();
    // `s` is always at least MIN_LEN_BLOCK_STR long (zero-padded above), so
    // these subtractions never underflow.
    let part1_end = len + 2 - MIN_LEN_BLOCK_STR;
    let part2_end = len + 4 - MIN_LEN_BLOCK_STR;
    format!("{}/{}/{}", &s[..part1_end], &s[part1_end..part2_end], s)
}

/// Parses a base-36 block-number string back into a round number. Matches
/// go's `stringToBlock`.
pub fn string_to_block(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s, 36).map_err(|e| format!("invalid block string \"{s}\": {e}"))
}

/// Content-Type go-algorand's block-service handler sets on a served block
/// (`rpcs.blockService.go`'s `ServeBlockPath`, via `network.BlockResponseContentType`).
const BLOCK_CONTENT_TYPE: &str = "application/x-algorand-block-v1";

#[derive(Clone)]
struct ServerState {
    dir: PathBuf,
}

/// go's `filepath.Clean` for `/`-separated paths.
fn go_clean(path: &str) -> String {
    let rooted = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if matches!(out.last(), Some(l) if *l != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            p => out.push(p),
        }
    }
    let joined = out.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_string(),
        (false, false) => joined,
    }
}

/// go 1.27 `filepath.IsLocal` (unix flavour; on Windows the backslash is a
/// separator too and a drive colon is not local): the path is relative, not
/// empty and does not escape its root lexically.
fn is_local(path: &str) -> bool {
    #[cfg(windows)]
    let owned = path.replace('\\', "/");
    #[cfg(windows)]
    let path = owned.as_str();
    #[cfg(windows)]
    if path.contains(':') {
        return false;
    }
    if path.is_empty() || path.starts_with('/') {
        return false;
    }
    let has_dots = path.split('/').any(|p| p == "." || p == "..");
    let cleaned = if has_dots {
        go_clean(path)
    } else {
        path.to_string()
    };
    !(cleaned == ".." || cleaned.starts_with("../"))
}

/// go v5.1.1 `readBlockFile` (`cmd/catchupsrv/main.go`): reads
/// `<dir>/v<version>/<genesis_id>/block/<block_to_path(round)>`, refusing (as
/// "not found") a relative path that lexically escapes `dir` (`filepath.IsLocal`).
/// Symlinks under `dir` are followed (they are trusted), like go's `os.ReadFile`.
fn read_block_file(
    dir: &Path,
    version: &str,
    genesis_id: &str,
    round: u64,
) -> std::io::Result<Vec<u8>> {
    // `filepath.Join` cleans the joined path
    let rel = go_clean(&format!(
        "v{version}/{genesis_id}/block/{}",
        block_to_path(round)
    ));
    if !is_local(&rel) {
        return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
    }
    std::fs::read(dir.join(rel))
}

/// Byte-identical response to Go's `net/http` `http.NotFound(w, r)` — status
/// 404, body `"404 page not found\n"`, `Content-Type: text/plain;
/// charset=utf-8` — which go-algorand's `cmd/catchupsrv/main.go` uses for
/// both a missing block file and an unparseable round string.
fn go_http_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "404 page not found\n",
    )
        .into_response()
}

async fn serve_block(
    State(state): State<ServerState>,
    AxumPath((genesis_id, round_str)): AxumPath<(String, String)>,
) -> Response {
    let round = match string_to_block(&round_str) {
        Ok(r) => r,
        Err(_) => return go_http_not_found(),
    };

    // `BlockServiceBlockPath` only matches version 1
    let dir = state.dir.clone();
    let read = tokio::task::spawn_blocking(move || read_block_file(&dir, "1", &genesis_id, round))
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)));
    match read {
        Ok(data) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, BLOCK_CONTENT_TYPE)],
            data,
        )
            .into_response(),
        Err(_) => go_http_not_found(),
    }
}

/// Builds the axum router serving go-algorand's `rpcs.BlockServiceBlockPath`
/// route (`/v1/{genesisID}/block/{round}`) from `dir`.
pub fn router(dir: PathBuf) -> Router {
    Router::new()
        .route("/v1/{genesis_id}/block/{round}", get(serve_block))
        .with_state(ServerState { dir })
}

/// Runs the catchupsrv HTTP daemon, serving block files from `dir` on
/// `addr` until the process is terminated. Mirrors go's `catchupsrv -dir
/// <dir> -addr <addr>` (the download/gossip-relay pieces of go's tool are
/// out of scope here — see issue #969's acceptance criteria).
pub async fn run(dir: PathBuf, addr: SocketAddr) -> anyhow::Result<()> {
    let app = router(dir);
    info!(%addr, "serving catchupsrv");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures ported verbatim from
    // `../go-algorand/cmd/catchupsrv/download_test.go`'s
    // TestBlockToPath/TestBlockToFileName/TestBlockToString.

    #[test]
    fn block_to_path_matches_go_fixtures() {
        assert_eq!(block_to_path(0), "00/00/000000");
        assert_eq!(block_to_path(1000), "00/00/0000rs");
        assert_eq!(block_to_path(10000500), "05/yc/05ycfo");
        assert_eq!(block_to_path(10012300500), "4ll/2c/4ll2cic");
    }

    #[test]
    fn block_to_file_name_matches_go_fixtures() {
        assert_eq!(block_to_file_name(0), "000000");
        assert_eq!(block_to_file_name(1000), "0000rs");
        assert_eq!(block_to_file_name(10000500), "05ycfo");
        assert_eq!(block_to_file_name(10012300500), "4ll2cic");
    }

    #[test]
    fn block_to_string_matches_go_fixtures() {
        assert_eq!(block_to_string(0), "0");
        assert_eq!(block_to_string(1000), "rs");
        assert_eq!(block_to_string(10000500), "5ycfo");
        assert_eq!(block_to_string(10012300500), "4ll2cic");
    }

    #[test]
    fn string_to_block_round_trips() {
        for blk in [0u64, 1000, 10000500, 10012300500] {
            let s = block_to_string(blk);
            assert_eq!(string_to_block(&s), Ok(blk));
        }
    }

    #[test]
    fn string_to_block_rejects_invalid_input() {
        assert!(string_to_block("not-base36!").is_err());
    }

    #[tokio::test]
    async fn serves_block_with_expected_content_type() {
        let tmp = tempfile::tempdir().unwrap();
        let round: u64 = 12345;
        let block_dir = tmp
            .path()
            .join("v1")
            .join("test-genesis-v1")
            .join("block")
            .join(block_to_path(round));
        tokio::fs::create_dir_all(block_dir.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&block_dir, b"fake-block-bytes")
            .await
            .unwrap();

        let app = router(tmp.path().to_path_buf());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!(
            "http://{addr}/v1/test-genesis-v1/block/{}",
            block_to_string(round)
        );
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            resp.headers().get(reqwest::header::CONTENT_TYPE).unwrap(),
            BLOCK_CONTENT_TYPE
        );
        let body = resp.bytes().await.unwrap();
        assert_eq!(&body[..], b"fake-block-bytes");
    }

    #[tokio::test]
    async fn returns_404_for_missing_block() {
        let tmp = tempfile::tempdir().unwrap();
        let app = router(tmp.path().to_path_buf());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!(
            "http://{addr}/v1/test-genesis-v1/block/{}",
            block_to_string(999)
        );
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get(reqwest::header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        let body = resp.bytes().await.unwrap();
        assert_eq!(&body[..], b"404 page not found\n");
    }

    #[tokio::test]
    async fn returns_404_for_non_base36_round() {
        let tmp = tempfile::tempdir().unwrap();
        let app = router(tmp.path().to_path_buf());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/v1/test-genesis-v1/block/not-a-round");
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get(reqwest::header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        let body = resp.bytes().await.unwrap();
        assert_eq!(&body[..], b"404 page not found\n");
    }

    // go v5.1.1 `TestReadBlockFile` (cmd/catchupsrv/main_test.go): a genesis ID
    // taken from the URL must not lead outside the served directory.
    #[test]
    fn read_block_file_stays_inside_the_directory() {
        use std::fs;
        let dir = tempfile::tempdir().unwrap();
        let block = b"block data".to_vec();
        let block_path = dir
            .path()
            .join("v1")
            .join("test-v1")
            .join("block")
            .join(block_to_path(1000));
        fs::create_dir_all(block_path.parent().unwrap()).unwrap();
        fs::write(&block_path, &block).unwrap();
        assert_eq!(
            read_block_file(dir.path(), "1", "test-v1", 1000).unwrap(),
            block
        );

        let outside = tempfile::tempdir().unwrap();
        let outside_block_dir = outside.path().join("block");
        let outside_block_path = outside_block_dir.join(block_to_path(1000));
        fs::create_dir_all(outside_block_path.parent().unwrap()).unwrap();
        fs::write(&outside_block_path, b"outside data").unwrap();

        let outside_name = outside.path().file_name().unwrap().to_str().unwrap();
        let err =
            read_block_file(dir.path(), "1", &format!("../../{outside_name}"), 1000).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        // the version is part of the path too
        assert!(read_block_file(dir.path(), "../..", "x", 1000).is_err());
        assert!(read_block_file(dir.path(), "1", "/etc", 1000).is_err());

        // `filepath.IsLocal` on its own
        assert!(is_local("a/b"));
        assert!(is_local("a/../b"));
        assert!(!is_local(""));
        assert!(!is_local("/a"));
        assert!(!is_local(".."));
        assert!(!is_local("../a"));
        assert!(!is_local("a/../../b"));

        // Backslashes are literal filename characters on unix: mux accepts them
        // within one genesisID segment and go reads that literal directory.
        #[cfg(unix)]
        {
            let genesis_id = format!("..\\..\\{outside_name}");
            let literal = dir
                .path()
                .join("v1")
                .join(&genesis_id)
                .join("block")
                .join(block_to_path(1000));
            fs::create_dir_all(literal.parent().unwrap()).unwrap();
            fs::write(&literal, &block).unwrap();
            assert_eq!(
                read_block_file(dir.path(), "1", &genesis_id, 1000).unwrap(),
                block
            );

            // symlinks under the directory are trusted and followed
            use std::os::unix::fs::symlink;
            let inside_block_dir = dir.path().join("v1").join("test-v1").join("block");
            for (name, target, want) in [
                (
                    "relative",
                    outside_block_dir.clone(),
                    b"outside data".to_vec(),
                ),
                (
                    "absolute",
                    outside_block_dir.clone(),
                    b"outside data".to_vec(),
                ),
                ("absolute-inside", inside_block_dir, block.clone()),
            ] {
                let link_dir = dir.path().join("v1").join(name);
                fs::create_dir_all(&link_dir).unwrap();
                let target = if name == "relative" {
                    // relative to the link's directory
                    let mut rel = std::path::PathBuf::new();
                    for _ in link_dir.strip_prefix("/").unwrap().components() {
                        rel.push("..");
                    }
                    rel.join(target.strip_prefix("/").unwrap())
                } else {
                    target
                };
                symlink(&target, link_dir.join("block")).unwrap();
                assert_eq!(
                    read_block_file(dir.path(), "1", name, 1000).unwrap(),
                    want,
                    "{name}"
                );
            }
        }
    }

    /// The route only matches version 1 (go: `BlockServiceBlockPath`), so a
    /// request for another version is not served from `<dir>/v<other>`.
    #[tokio::test]
    async fn only_version_one_is_routed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp
            .path()
            .join("v2")
            .join("g")
            .join("block")
            .join(block_to_path(7));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"v2 block").unwrap();
        let app = router(tmp.path().to_path_buf());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let resp = reqwest::get(format!("http://{addr}/v2/g/block/{}", block_to_string(7)))
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    }

    /// A percent-encoded `..` in the genesis ID (axum decodes it) cannot leave
    /// the served directory.
    #[tokio::test]
    async fn percent_encoded_traversal_in_the_genesis_id_is_not_found() {
        let parent = tempfile::tempdir().unwrap();
        let served = parent.path().join("served");
        std::fs::create_dir_all(&served).unwrap();
        let secret = parent.path().join("block").join(block_to_path(7));
        std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
        std::fs::write(&secret, b"secret").unwrap();
        let app = router(served);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        // <served>/v1/../block/<path> would be <served>/block/..., and
        // `%2e%2e%2f..` climbs further: served/v1/../../block/<path> is the secret
        let resp = reqwest::get(format!(
            "http://{addr}/v1/%2e%2e%2f%2e%2e/block/{}",
            block_to_string(7)
        ))
        .await
        .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    }
}
