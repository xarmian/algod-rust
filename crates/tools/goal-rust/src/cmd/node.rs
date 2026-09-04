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

//! `goal-rust node status` — port of `../go-algorand/cmd/goal/node.go:
//! 412-517` (`statusCmd`, `getStatus`, `makeStatusString`).
//!
//! Output text is byte-identical to Go's `goal node status` for the
//! three branches the format strings expose (steady-state,
//! catchpoint-catchup, consensus-upgrade voting).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use algo_rest_client::{AlgodClient, BlockSource, NodeStatus};

#[cfg(test)]
use algo_rest_client::AlgodVersions;

use crate::data_dir::{read_algod_admin_token, read_algod_net, read_algod_token};
use crate::groups::node::StatusArgs;

/// Mirrors `messages.go:64` (`infoNodeStatus`).
const INFO_NODE_STATUS: &str = "Last committed block: {}\nTime since last block: {}\nSync Time: {}\nLast consensus protocol: {}\nNext consensus protocol: {}\nRound for next consensus protocol: {}\nNext consensus protocol supported: {}";

/// Mirrors `messages.go:65`.
const INFO_NODE_STATUS_UPGRADE_VOTING: &str = "Consensus upgrade state: Voting\nYes votes: {}\nNo votes: {}\nVotes remaining: {}\nYes votes required: {}\nVote window close round: {}";

/// Mirrors `messages.go:66`.
const INFO_NODE_STATUS_UPGRADE_SCHEDULED: &str = "Consensus upgrade state: Scheduled";

/// Mirrors `messages.go:67`.
const CATCHUP_STOPPED_ON_UNSUPPORTED: &str =
    "Last supported block ({}) is committed. The next block consensus protocol is not supported. Catchup service is stopped.";

/// Mirrors `messages.go:68`.
const INFO_NODE_CATCHPOINT_CATCHUP_STATUS: &str =
    "Last committed block: {}\nSync Time: {}\nCatchpoint: {}";

/// Mirrors `messages.go:69`.
const INFO_NODE_CATCHPOINT_CATCHUP_ACCOUNTS: &str = "Catchpoint total accounts: {}\nCatchpoint accounts processed: {}\nCatchpoint accounts verified: {}\nCatchpoint total KVs: {}\nCatchpoint KVs processed: {}\nCatchpoint KVs verified: {}";

/// Mirrors `messages.go:70`.
const INFO_NODE_CATCHPOINT_CATCHUP_BLOCKS: &str =
    "Catchpoint total blocks: {}\nCatchpoint downloaded blocks: {}";

/// Mirrors `messages.go:71`.
const NODE_LAST_CATCHPOINT: &str = "Last Catchpoint: {}";

/// Mirrors `messages.go:76` (`errorNodeStatus`).
const ERROR_NODE_STATUS: &str = "Cannot contact Algorand node: {}";

/// Mirrors `messages.go:78`.
const ERROR_NODE_RUNNING: &str = "Node must be stopped before writing APIToken";

/// Mirrors `messages.go:79`.
const ERROR_NODE_FAIL_GEN_TOKEN: &str = "Cannot generate API token: {}";

/// Mirrors `messages.go:85`.
const INFO_NODE_WROTE_TOKEN: &str = "Successfully wrote new API token: {}";

/// Token filename rotated by `goal node generatetoken`. Tracks Go's
/// `tokens.AlgodTokenFilename` — `node.go:402` passes this filename
/// to `tokens.GenerateAPIToken`. Note: this is `algod.token`, NOT
/// `algod.admin.token`; the original TASK-224 spec named the admin
/// variant but Go's source rotates the public token. We mirror Go.
const ALGOD_TOKEN_ROTATE_FILE: &str = "algod.token";

/// Top-level entry point invoked from `groups::node::run`. Maps
/// resolved data dirs onto algod connections and prints status for
/// each, mirroring Go's `datadir.OnDataDirs(getStatus)`.
pub fn run_status(args: StatusArgs, cli_d: Vec<PathBuf>) -> ExitCode {
    let dirs = match crate::data_dir::resolve_data_dirs(&cli_d) {
        Ok(dirs) => dirs,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let multi = dirs.len() > 1;
    let mut exit = ExitCode::SUCCESS;
    for dir in &dirs {
        if multi {
            // Mirrors `cmd/util/datadir/messages.go:infoDataDir`.
            println!("[Data Directory: {}]", dir.display());
        }
        if let Err(()) = runtime.block_on(get_status(dir, args.watch)) {
            exit = ExitCode::from(1);
        }
    }
    exit
}

/// Port of `getStatus(dataDir string)`. Loops printing status (with
/// `--watch`'s ANSI cleanup between frames) until single-shot mode
/// breaks out.
async fn get_status(data_dir: &Path, watch_ms: u64) -> Result<(), ()> {
    /// ANSI cursor-up + delete-line. Same constants Go uses
    /// (`node.go:425-426`).
    const CUU: &str = "\x1b[A";
    const DL: &str = "\x1b[M";

    let client = build_client(data_dir)?;

    let mut cleanup_fmt = String::new();
    loop {
        let stat = match client.get_status().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{}", format_message(ERROR_NODE_STATUS, &[&e.to_string()]));
                return Err(());
            }
        };
        let vers = match client.get_versions().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", format_message(ERROR_NODE_STATUS, &[&e.to_string()]));
                return Err(());
            }
        };

        let mut status_str = format!("{cleanup_fmt}{}\n", make_status_string(&stat));
        if !vers.genesis_id.is_empty() {
            status_str = format!("{status_str}Genesis ID: {}\n", vers.genesis_id);
        }
        status_str = format!("{status_str}Genesis hash: {}", vers.genesis_hash_b64);
        println!("{status_str}");

        if watch_ms == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(watch_ms)).await;
        cleanup_fmt = String::new();
        let lines = status_str.split('\n').count();
        for _ in 0..lines {
            cleanup_fmt.push_str(CUU);
            cleanup_fmt.push_str(DL);
        }
    }
    Ok(())
}

/// Phase-A advisory: `goal-rust node start` delegates process
/// supervision to the host's supervisor. Prints guidance to stderr
/// and exits 0 (advisory, not an error).
///
/// Go's `startCmd` (node.go:235-289) forks `algod`, writes
/// `algod.pid`, and runs as a supervisor — that's a heavy port we've
/// scoped out of Phase A. A follow-up Idea tracks the full port.
pub fn run_start(cli_d: Vec<PathBuf>) -> ExitCode {
    advisory_supervision(
        &cli_d,
        "goal-rust does not yet manage the algod process directly. \
        Start algod via your supervisor (systemd, supervisord, or \
        'algod -d {dir}' as a child of your shell).",
    )
}

/// Phase-A advisory: `goal-rust node stop`. Counterpart to
/// [`run_start`] — guidance + exit 0.
pub fn run_stop(cli_d: Vec<PathBuf>) -> ExitCode {
    advisory_supervision(
        &cli_d,
        "goal-rust does not manage the algod process. Stop algod via \
        your supervisor or SIGTERM the PID in {dir}/algod.pid.",
    )
}

/// Phase-A advisory: `goal-rust node restart`. Combined stop/start
/// guidance.
pub fn run_restart(cli_d: Vec<PathBuf>) -> ExitCode {
    advisory_supervision(
        &cli_d,
        "goal-rust does not manage the algod process. Restart algod \
        via your supervisor: stop the PID in {dir}/algod.pid, then \
        start a fresh 'algod -d {dir}'.",
    )
}

/// Shared advisory printer. Substitutes `{dir}` with each resolved
/// data dir and emits one line per dir to stderr. Returns exit 0
/// because invoking the command isn't a usage error — the operator
/// can read the message and act.
fn advisory_supervision(cli_d: &[PathBuf], template: &str) -> ExitCode {
    // We don't *require* a data dir to be set (the message is still
    // useful without one), but if `-d` / `$ALGORAND_DATA` resolves to
    // a real path, embed it in the message for copy-paste convenience.
    let dirs = crate::data_dir::resolve_data_dirs(cli_d)
        .unwrap_or_else(|_| vec![PathBuf::from("<data-dir>")]);
    for dir in &dirs {
        let dir_str = dir.display().to_string();
        let msg = template.replace("{dir}", &dir_str);
        eprintln!("{msg}");
    }
    ExitCode::SUCCESS
}

/// Port of `lastroundCmd` (`node.go:519-534`). Per-data-dir, calls
/// `client.CurrentRound()` and prints `{round}\n`.
pub fn run_lastround(cli_d: Vec<PathBuf>) -> ExitCode {
    let dirs = match crate::data_dir::resolve_data_dirs(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let multi = dirs.len() > 1;
    let mut exit = ExitCode::SUCCESS;
    for dir in &dirs {
        if multi {
            println!("[Data Directory: {}]", dir.display());
        }
        let client = match build_client(dir) {
            Ok(c) => c,
            Err(()) => {
                exit = ExitCode::from(1);
                continue;
            }
        };
        match rt.block_on(client.get_status()) {
            Ok(stat) => println!("{}", stat.last_round),
            Err(e) => {
                eprintln!("{}", format_message(ERROR_NODE_STATUS, &[&e.to_string()]));
                exit = ExitCode::from(1);
            }
        }
    }
    exit
}

/// Port of `generateTokenCmd` (`node.go:380-410`). For each data dir:
///
/// 1. Try to contact algod's `/health`. If reachable → print
///    `ERROR_NODE_RUNNING` and exit 1 (matches Go's `client.HealthCheck()`
///    success ⇒ `reportErrorln(errorNodeRunning)`).
/// 2. Generate a fresh 64-hex-char token (32 random bytes encoded).
/// 3. Write it to `<data_dir>/algod.token` with `0600` mode.
/// 4. Print `Successfully wrote new API token: <token>`.
pub fn run_generate_token(cli_d: Vec<PathBuf>) -> ExitCode {
    let dirs = match crate::data_dir::resolve_data_dirs(&cli_d) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let multi = dirs.len() > 1;
    let mut exit = ExitCode::SUCCESS;
    for dir in &dirs {
        if multi {
            println!("[Data Directory: {}]", dir.display());
        }
        if rt.block_on(algod_is_running(dir)) {
            eprintln!("{ERROR_NODE_RUNNING}");
            exit = ExitCode::from(1);
            continue;
        }
        let token = generate_api_token_hex();
        match write_token(&dir.join(ALGOD_TOKEN_ROTATE_FILE), &token) {
            Ok(()) => println!("{}", format_message(INFO_NODE_WROTE_TOKEN, &[&token])),
            Err(e) => {
                eprintln!(
                    "{}",
                    format_message(ERROR_NODE_FAIL_GEN_TOKEN, &[&e.to_string()]),
                );
                exit = ExitCode::from(1);
            }
        }
    }
    exit
}

/// Liveness probe used by `generatetoken`'s safety guard.
///
/// Returns true iff we can prove algod is reachable on this data
/// dir's `algod.net`:
///
/// - missing `algod.net` ⇒ false (fresh data dir; rotation can
///   proceed, matching Go where HealthCheck would also fail)
/// - TCP connect to `host:port` refused (ECONNREFUSED) ⇒ false
///   (definitely no listener — safe to rotate)
/// - anything else (TCP connect succeeds; or any other connect
///   error like DNS failure, timeout, TLS, route unreachable) ⇒
///   true (conservatively refuse rotation — Codex review TASK-224
///   round 1: a slow-but-running node must not slip past)
///
/// The TCP-first design avoids ambiguity in reqwest's
/// `Error::is_connect`, which lumps DNS failures together with
/// genuine connection refusals.
async fn algod_is_running(data_dir: &Path) -> bool {
    // Distinguish "the file doesn't exist" from other read errors
    // (permission denied, mid-write, etc.). Only the genuinely-
    // missing case is safe to treat as "fresh data dir, no node" —
    // anything else is ambiguous and we refuse rotation (Codex
    // review TASK-224 round 2).
    let net = match std::fs::read_to_string(data_dir.join("algod.net")) {
        Ok(s) => s.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    // Empty algod.net is ambiguous (partial / truncated write,
    // corrupted data dir). Be conservative — refuse rotation
    // (Codex review TASK-224 round 3).
    if net.is_empty() {
        return true;
    }
    // Strip any scheme prefix so we can hand a bare `host:port` to
    // tokio's TcpStream::connect — that's the form `algod.net`
    // contains in practice.
    let host_port = net
        .strip_prefix("http://")
        .or_else(|| net.strip_prefix("https://"))
        .unwrap_or(&net);
    let host_port = host_port.trim_end_matches('/').to_string();

    let connect = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(&host_port),
    )
    .await;

    match connect {
        // Connected → something is listening → refuse rotation.
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            // ECONNREFUSED is the one firm "down" signal. Anything
            // else (DNS, route, permission, …) → conservatively
            // treat as running and refuse rotation.
            e.kind() != std::io::ErrorKind::ConnectionRefused
        }
        // Timeout reaching the host: conservative — refuse rotation.
        Err(_) => true,
    }
}

fn generate_api_token_hex() -> String {
    use rand::RngCore;
    // 32 bytes → 64 hex chars. Mirrors Go's
    // `util/tokens/tokens.go:GenerateAPIToken` (entropyLen =
    // (minimumAPITokenLength + 1) / 2 = 32).
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut s = String::with_capacity(64);
    for b in buf {
        use std::fmt::Write;
        // {:02x} matches Go's fmt.Sprintf("%x", tokenBytes) exactly.
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn write_token(path: &Path, token: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // OpenOptions::mode only sets the mode at *creation* time; an
        // existing token file with looser permissions would keep its
        // old mode after a rewrite. We follow up with set_permissions
        // below to ensure 0o600 either way (Codex review TASK-224 r2).
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(token.as_bytes())?;
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Fetch and validate a catchpoint label from a plain-text URL, mirroring
/// Go's `getMissingCatchpointLabel` (`cmd/goal/node.go:131-153`). Used by
/// `goal node catchup` when no catchpoint argument is given: it looks up
/// the latest catchpoint label for the network from a well-known URL
/// (e.g. `https://algorand-catchpoints.s3.us-east-2.amazonaws.com/...`).
///
/// Returns the label (trailing newline trimmed, matching Go's
/// `strings.TrimSuffix(label, "\n")`) on a `200 OK` response whose body
/// parses as a valid catchpoint label (`{round}#{base32_hash}`, matching
/// `ledgercore.ParseCatchpointLabel` — see
/// `algo_ledger::catchpoint::parse_catchpoint_label`, which we mirror
/// locally here rather than pulling the (sqlite/ledger-heavy) `algo-ledger`
/// crate into `goal-rust` for one small validation helper). Any non-200
/// status is reported as Go's `resp.Status` string (`"404 Not Found"`), and
/// a well-formed-but-invalid body is reported as a parse error.
///
/// `#[allow(dead_code)]`: `goal node catchup` itself is still an
/// `unimplemented` stub (`crate::groups::node::NodeCmd::Catchup`) — a full
/// port needs the catchpoint-download progress loop too, which is out of
/// scope here. Ported ahead of that work so `TestGetMissingCatchpointLabel`
/// parity is pinned now; the future `catchup` port should call this
/// directly rather than re-deriving it.
#[allow(dead_code)]
pub(crate) async fn get_missing_catchpoint_label(url: &str) -> Result<String, String> {
    let resp = reqwest::get(url).await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if status.as_u16() != 200 {
        // Mirrors Go's `resp.Status` format: "404 Not Found".
        let reason = status.canonical_reason().unwrap_or("");
        return Err(format!("{} {reason}", status.as_u16())
            .trim_end()
            .to_string());
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    let label = body.strip_suffix('\n').unwrap_or(&body).to_string();
    if !is_valid_catchpoint_label(&label) {
        return Err(format!("'{label}' is not a valid catchpoint label"));
    }
    Ok(label)
}

/// Mirrors go-algorand's `ledgercore.ParseCatchpointLabel` validation
/// (round `#` base32-hash, hash decoding to at most 32 bytes) — just the
/// well-formedness check `get_missing_catchpoint_label` needs, without
/// pulling in `algo-ledger`.
fn is_valid_catchpoint_label(label: &str) -> bool {
    let mut parts = label.split('#');
    let (Some(round), Some(hash), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if round.parse::<u64>().is_err() {
        return false;
    }
    data_encoding::BASE32_NOPAD
        .decode(hash.as_bytes())
        .is_ok_and(|bytes| bytes.len() <= 32)
}

fn build_client(data_dir: &Path) -> Result<AlgodClient, ()> {
    let net = match read_algod_net(data_dir) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{}", format_message(ERROR_NODE_STATUS, &[&e.to_string()]));
            return Err(());
        }
    };
    let url = if net.starts_with("http://") || net.starts_with("https://") {
        net
    } else {
        format!("http://{net}")
    };
    let token = match read_algod_admin_token(data_dir) {
        Ok(t) if !t.is_empty() => t,
        _ => match read_algod_token(data_dir) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{}", format_message(ERROR_NODE_STATUS, &[&e.to_string()]));
                return Err(());
            }
        },
    };
    Ok(AlgodClient::new(url, token))
}

/// Pure formatter — covers the three Go branches at `node.go:455-516`.
/// Marked `pub` so unit tests in this module + integration tests can
/// drive it against synthetic [`NodeStatus`] fixtures.
pub fn make_status_string(stat: &NodeStatus) -> String {
    let last_round_time = format_secs(stat.time_since_last_round);
    let catchup_time = format_secs(stat.catchup_time);

    let catchpointing = stat.catchpoint.as_deref().is_some_and(|s| !s.is_empty());

    if !catchpointing {
        let mut s = format_message(
            INFO_NODE_STATUS,
            &[
                &stat.last_round.to_string(),
                &last_round_time,
                &catchup_time,
                &stat.last_version,
                &stat.next_version,
                &stat.next_version_round.to_string(),
                &fmt_bool(stat.next_version_supported),
            ],
        );

        if let Some(lc) = &stat.last_catchpoint {
            s.push('\n');
            s.push_str(&format_message(NODE_LAST_CATCHPOINT, &[lc]));
        }

        if stat.stopped_at_unsupported_round {
            s.push('\n');
            s.push_str(&format_message(
                CATCHUP_STOPPED_ON_UNSUPPORTED,
                &[&stat.last_round.to_string()],
            ));
        }

        let upgrade_next_before = stat.upgrade_next_protocol_vote_before.unwrap_or(0);
        if upgrade_next_before > stat.last_round {
            let votes_required = stat.upgrade_votes_required.unwrap_or(0);
            let no_votes = stat.upgrade_no_votes.unwrap_or(0);
            let yes_votes = stat.upgrade_yes_votes.unwrap_or(0);
            let vote_rounds = stat.upgrade_vote_rounds.unwrap_or(0);
            // Go subtracts as u64; if the response is malformed and
            // `yes+no > rounds`, Go would underflow. We saturate to
            // 0 to avoid panicking on a malformed payload but still
            // produce a printable number.
            let remaining = vote_rounds
                .saturating_sub(yes_votes)
                .saturating_sub(no_votes);
            s.push('\n');
            s.push_str(&format_message(
                INFO_NODE_STATUS_UPGRADE_VOTING,
                &[
                    &yes_votes.to_string(),
                    &no_votes.to_string(),
                    &remaining.to_string(),
                    &votes_required.to_string(),
                    &upgrade_next_before.to_string(),
                ],
            ));
        } else if upgrade_next_before > 0 {
            s.push('\n');
            s.push_str(INFO_NODE_STATUS_UPGRADE_SCHEDULED);
        }

        s
    } else {
        let catchpoint = stat.catchpoint.as_deref().unwrap_or("");
        let mut s = format_message(
            INFO_NODE_CATCHPOINT_CATCHUP_STATUS,
            &[&stat.last_round.to_string(), &catchup_time, catchpoint],
        );
        if let (Some(total), Some(proc), Some(ver), Some(t_kvs), Some(p_kvs), Some(v_kvs)) = (
            stat.catchpoint_total_accounts,
            stat.catchpoint_processed_accounts,
            stat.catchpoint_verified_accounts,
            stat.catchpoint_total_kvs,
            stat.catchpoint_processed_kvs,
            stat.catchpoint_verified_kvs,
        ) {
            if total > 0 {
                s.push('\n');
                s.push_str(&format_message(
                    INFO_NODE_CATCHPOINT_CATCHUP_ACCOUNTS,
                    &[
                        &total.to_string(),
                        &proc.to_string(),
                        &ver.to_string(),
                        &t_kvs.to_string(),
                        &p_kvs.to_string(),
                        &v_kvs.to_string(),
                    ],
                ));
            }
        }
        if let (Some(acq), Some(total)) = (
            stat.catchpoint_acquired_blocks,
            stat.catchpoint_total_blocks,
        ) {
            if acq + total > 0 {
                s.push('\n');
                s.push_str(&format_message(
                    INFO_NODE_CATCHPOINT_CATCHUP_BLOCKS,
                    &[&total.to_string(), &acq.to_string()],
                ));
            }
        }
        s
    }
}

/// Format a duration in nanoseconds like Go's
/// `fmt.Sprintf("%.1fs", time.Duration(ns).Seconds())`.
fn format_secs(ns: u64) -> String {
    let secs = ns as f64 / 1_000_000_000.0;
    format!("{secs:.1}s")
}

/// Mirror Go's `%v` for `bool`: lowercase `true` / `false`.
fn fmt_bool(b: bool) -> String {
    if b { "true" } else { "false" }.to_string()
}

/// Trivial template formatter: replaces consecutive `{}` placeholders
/// with the supplied args, left-to-right. We use this so the format
/// constants above stay byte-identical to Go's `messages.go` —
/// `fmt.Sprintf` substitutes `%d/%s/%v` positionally, and this does
/// the same with `{}`. Args are stringified by the caller so we can
/// keep the formatter type-erased.
fn format_message(template: &str, args: &[&str]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    let mut i = 0;
    while let Some(idx) = rest.find("{}") {
        out.push_str(&rest[..idx]);
        if i < args.len() {
            out.push_str(args[i]);
            i += 1;
        }
        rest = &rest[idx + 2..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_status() -> NodeStatus {
        NodeStatus {
            last_round: 42,
            time_since_last_round: 3_500_000_000, // 3.5s
            catchup_time: 0,                      // 0.0s
            last_version: "future".into(),
            next_version: "future".into(),
            next_version_round: 100,
            next_version_supported: true,
            stopped_at_unsupported_round: false,
            last_catchpoint: None,
            ..NodeStatus::default()
        }
    }

    #[test]
    fn format_secs_matches_go_one_decimal() {
        assert_eq!(format_secs(0), "0.0s");
        assert_eq!(format_secs(1_500_000_000), "1.5s");
        assert_eq!(format_secs(3_500_000_000), "3.5s");
    }

    #[test]
    fn steady_state_matches_info_node_status_template() {
        // Direct port of Go's expected output for a synced node, no
        // catchpoint, no pending upgrade.
        let stat = base_status();
        let expected = "Last committed block: 42\n\
            Time since last block: 3.5s\n\
            Sync Time: 0.0s\n\
            Last consensus protocol: future\n\
            Next consensus protocol: future\n\
            Round for next consensus protocol: 100\n\
            Next consensus protocol supported: true";
        assert_eq!(make_status_string(&stat), expected);
    }

    #[test]
    fn steady_state_with_last_catchpoint_appends_line() {
        let mut stat = base_status();
        stat.last_catchpoint = Some("1234#abc".into());
        let s = make_status_string(&stat);
        assert!(
            s.ends_with("\nLast Catchpoint: 1234#abc"),
            "missing Last Catchpoint suffix: {s:?}",
        );
    }

    #[test]
    fn steady_state_with_upgrade_voting_appends_voting_block() {
        let mut stat = base_status();
        stat.upgrade_next_protocol_vote_before = Some(1000);
        stat.upgrade_votes_required = Some(10000);
        stat.upgrade_yes_votes = Some(3000);
        stat.upgrade_no_votes = Some(500);
        stat.upgrade_vote_rounds = Some(10000);
        let s = make_status_string(&stat);
        assert!(
            s.ends_with(
                "\nConsensus upgrade state: Voting\n\
                Yes votes: 3000\n\
                No votes: 500\n\
                Votes remaining: 6500\n\
                Yes votes required: 10000\n\
                Vote window close round: 1000",
            ),
            "voting block missing or wrong: {s:?}",
        );
    }

    #[test]
    fn steady_state_with_scheduled_upgrade_after_round_falls_through_to_scheduled() {
        // upgrade_next_protocol_vote_before > 0 but <= last_round
        // selects the "Scheduled" branch (no vote-count detail).
        let mut stat = base_status();
        stat.last_round = 2000;
        stat.upgrade_next_protocol_vote_before = Some(1000);
        let s = make_status_string(&stat);
        assert!(
            s.ends_with("\nConsensus upgrade state: Scheduled"),
            "scheduled suffix missing: {s:?}",
        );
    }

    #[test]
    fn stopped_at_unsupported_round_appends_message() {
        let mut stat = base_status();
        stat.stopped_at_unsupported_round = true;
        let s = make_status_string(&stat);
        assert!(
            s.contains(
                "\nLast supported block (42) is committed. The next block consensus protocol is not supported. Catchup service is stopped.",
            ),
            "unsupported message missing: {s:?}",
        );
    }

    #[test]
    fn catchpoint_branch_uses_catchpoint_template() {
        let stat = NodeStatus {
            last_round: 1234,
            catchup_time: 12_300_000_000, // 12.3s
            catchpoint: Some("1234#abc".into()),
            ..NodeStatus::default()
        };
        let expected = "Last committed block: 1234\n\
            Sync Time: 12.3s\n\
            Catchpoint: 1234#abc";
        assert_eq!(make_status_string(&stat), expected);
    }

    #[test]
    fn catchpoint_progress_lines_appear_when_accounts_total_positive() {
        let stat = NodeStatus {
            last_round: 1234,
            catchpoint: Some("1234#abc".into()),
            catchpoint_total_accounts: Some(100),
            catchpoint_processed_accounts: Some(50),
            catchpoint_verified_accounts: Some(40),
            catchpoint_total_kvs: Some(200),
            catchpoint_processed_kvs: Some(150),
            catchpoint_verified_kvs: Some(140),
            catchpoint_acquired_blocks: Some(10),
            catchpoint_total_blocks: Some(20),
            ..NodeStatus::default()
        };
        let s = make_status_string(&stat);
        assert!(s.contains("Catchpoint total accounts: 100"));
        assert!(s.contains("Catchpoint accounts processed: 50"));
        assert!(s.contains("Catchpoint accounts verified: 40"));
        assert!(s.contains("Catchpoint total KVs: 200"));
        assert!(s.contains("Catchpoint KVs processed: 150"));
        assert!(s.contains("Catchpoint KVs verified: 140"));
        assert!(s.contains("Catchpoint total blocks: 20"));
        assert!(s.contains("Catchpoint downloaded blocks: 10"));
    }

    #[test]
    fn empty_catchpoint_string_is_steady_state_not_catchpoint() {
        // Mirrors Go's `*stat.Catchpoint == ""` check at node.go:459.
        let stat = NodeStatus {
            last_round: 5,
            catchpoint: Some(String::new()),
            ..NodeStatus::default()
        };
        let s = make_status_string(&stat);
        assert!(s.starts_with("Last committed block: 5"));
        assert!(!s.contains("Catchpoint:"));
    }

    // Reference shape — keeps the AlgodVersions import live for
    // doctests/clippy.
    #[allow(dead_code)]
    fn _ensure_versions_compiles() -> AlgodVersions {
        AlgodVersions::default()
    }

    #[test]
    fn generate_api_token_hex_is_64_lowercase_hex_chars() {
        // Mirrors Go's util/tokens/tokens.go:GenerateAPIToken: 32
        // random bytes hex-encoded ⇒ 64 chars [0-9a-f].
        let t1 = generate_api_token_hex();
        let t2 = generate_api_token_hex();
        assert_eq!(t1.len(), 64, "token must be 64 hex chars; got {t1:?}");
        assert!(
            t1.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "token must be lowercase hex; got {t1:?}",
        );
        assert_ne!(t1, t2, "two consecutive calls must differ (random)");
    }

    #[test]
    fn write_token_creates_file_with_token_contents() {
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("algod.token");
        write_token(&p, "deadbeef".repeat(8).as_str()).expect("write");
        let got = std::fs::read_to_string(&p).expect("read");
        assert_eq!(got, "deadbeef".repeat(8));
    }

    #[cfg(unix)]
    #[test]
    fn write_token_tightens_existing_file_to_0600() {
        // Regression guard (Codex review TASK-224 round 2):
        // OpenOptions::mode only applies at creation time. If
        // algod.token already exists with looser perms (e.g. 0644
        // from a previous bug or manual edit), the rotation must
        // still leave it at 0600.
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("algod.token");
        std::fs::write(&p, "old-token").expect("seed");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("loosen");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644,
            "fixture must start at 0644",
        );
        write_token(&p, "new-token").expect("rotate");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rotation must tighten to 0600; got {mode:o}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new-token");
    }

    #[cfg(unix)]
    #[test]
    fn write_token_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().expect("tempdir");
        let p = d.path().join("algod.token");
        write_token(&p, "x").expect("write");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token file mode must be 0600; got {mode:o}");
    }

    // ---- is_valid_catchpoint_label -------------------------------------

    #[test]
    fn is_valid_catchpoint_label_accepts_well_formed_labels() {
        assert!(is_valid_catchpoint_label(
            "6500000#JZOMXYAWFXKZ6X3TVIF5NIHXP3JQU5FUMKY7BOULCMT7BQV6QGVQ"
        ));
    }

    #[test]
    fn is_valid_catchpoint_label_rejects_malformed_labels() {
        assert!(!is_valid_catchpoint_label("no-hash-separator"));
        assert!(!is_valid_catchpoint_label("6500000#abc#def"));
        assert!(!is_valid_catchpoint_label("not-a-round#JZOMXYAW"));
        assert!(!is_valid_catchpoint_label("6500000#not!valid!base32"));
    }

    // ---- get_missing_catchpoint_label -----------------------------------
    // Ports go's `TestGetMissingCatchpointLabel` HTTP-status branches
    // (`cmd/goal/node_test.go:35-...`) against a hand-rolled TCP mock (this
    // crate's established pattern — see `tests/node_status_e2e.rs`) instead
    // of hitting the real S3 URLs the go test also covers.

    /// Spawn a single-response mock HTTP server on `127.0.0.1` returning
    /// the given status line and body, and return its base URL.
    fn spawn_mock_http(status_line: &'static str, body: &'static str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "{status_line}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        });
        format!("http://127.0.0.1:{port}/")
    }

    #[tokio::test]
    async fn get_missing_catchpoint_label_valid_label_ok() {
        let label = "6500000#JZOMXYAWFXKZ6X3TVIF5NIHXP3JQU5FUMKY7BOULCMT7BQV6QGVQ";
        let url = spawn_mock_http("HTTP/1.1 200 OK", label);
        let got = get_missing_catchpoint_label(&url).await.unwrap();
        assert_eq!(got, label);
    }

    #[tokio::test]
    async fn get_missing_catchpoint_label_trims_trailing_newline() {
        let label = "6500000#JZOMXYAWFXKZ6X3TVIF5NIHXP3JQU5FUMKY7BOULCMT7BQV6QGVQ";
        let url = spawn_mock_http(
            "HTTP/1.1 200 OK",
            "6500000#JZOMXYAWFXKZ6X3TVIF5NIHXP3JQU5FUMKY7BOULCMT7BQV6QGVQ\n",
        );
        let got = get_missing_catchpoint_label(&url).await.unwrap();
        assert_eq!(got, label);
    }

    #[tokio::test]
    async fn get_missing_catchpoint_label_bad_request_errors() {
        let url = spawn_mock_http("HTTP/1.1 400 Bad Request", "");
        let err = get_missing_catchpoint_label(&url).await.unwrap_err();
        assert_eq!(err, "400 Bad Request");
    }

    #[tokio::test]
    async fn get_missing_catchpoint_label_forbidden_errors() {
        let url = spawn_mock_http("HTTP/1.1 403 Forbidden", "");
        let err = get_missing_catchpoint_label(&url).await.unwrap_err();
        assert_eq!(err, "403 Forbidden");
    }

    #[tokio::test]
    async fn get_missing_catchpoint_label_not_found_errors() {
        let url = spawn_mock_http("HTTP/1.1 404 Not Found", "");
        let err = get_missing_catchpoint_label(&url).await.unwrap_err();
        assert_eq!(err, "404 Not Found");
    }

    #[tokio::test]
    async fn get_missing_catchpoint_label_malformed_body_errors() {
        let url = spawn_mock_http("HTTP/1.1 200 OK", "not a catchpoint label");
        let err = get_missing_catchpoint_label(&url).await.unwrap_err();
        assert!(err.contains("not a valid catchpoint label"), "got: {err}");
    }
}
