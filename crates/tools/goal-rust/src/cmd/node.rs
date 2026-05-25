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
    // Mirrors Go's `nodecontrol/algodControl.go:72-75`: prefer
    // `algod.admin.token`, fall back to `algod.token`.
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
    let client = AlgodClient::new(url, token);

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
}
