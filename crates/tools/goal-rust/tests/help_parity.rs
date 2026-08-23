//! Help-parity test: every group / leaf that Go's `goal` exposes must
//! also appear in `goal-rust`'s `--help`.
//!
//! Fixture mode (default): parse the committed
//! `tests/fixtures/goal_help_*.txt` files captured from Go's
//! `v4.6.0-stable` binary. Live mode (`MIXED_CLUSTER=1`): regenerate
//! the fixtures from a `goal` binary on PATH before diffing — same
//! assertions either way.
//!
//! Acceptance bar (PLAN-152 / TASK-220): every command name Go's help
//! lists in "Available Commands" appears in the corresponding Rust help
//! output. Order, surrounding text, and per-leaf flags are out of scope
//! for Phase A — A2..A11 land the bodies and per-leaf flag parity.

use std::path::PathBuf;
use std::process::Command;

const GOAL_RUST_BIN: &str = env!("CARGO_BIN_EXE_goal-rust");

/// Groups that have their own `--help` to inspect. The string is the
/// argv we pass to *both* binaries when capturing help, and (with `_`
/// replaced by space and joined by `_`) the fixture-file stem.
const GROUPS: &[&str] = &[
    "root",
    "account",
    "account_multisig",
    "app",
    "asset",
    "clerk",
    "completion",
    "kmd",
    "ledger",
    "network",
    "node",
    "wallet",
];

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Extract command names from a cobra `--help` capture. Cobra's format
/// is:
///
/// ```text
/// Available Commands:
///   foo         Description
///   bar         Description
///
/// Flags:
/// ```
///
/// We collect lines between those two markers, strip the leading
/// whitespace, and take the first whitespace-delimited token of each.
fn extract_available_commands(help: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in help.lines() {
        let trimmed = line.trim_start();
        // Cobra emits "Available Commands:"; clap emits "Commands:".
        // Both mark the start of the subcommand list.
        if trimmed.starts_with("Available Commands:") || trimmed == "Commands:" {
            in_block = true;
            continue;
        }
        if in_block {
            if line.trim().is_empty() {
                break;
            }
            if let Some(name) = line.split_whitespace().next() {
                // cobra always autogenerates "help" — clap does too but
                // names it differently. Skip it.
                if name == "help" {
                    continue;
                }
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn load_fixture(group: &str) -> String {
    let path = fixtures_dir().join(format!("{group}.txt"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing fixture {}: {e}", path.display()))
}

fn rust_help(group: &str) -> String {
    let argv: Vec<&str> = if group == "root" {
        vec!["--help"]
    } else {
        // "account_multisig" → ["account", "multisig", "--help"]
        let mut v: Vec<&str> = group.split('_').collect();
        v.push("--help");
        v
    };
    let out = Command::new(GOAL_RUST_BIN)
        .args(&argv)
        .output()
        .expect("run goal-rust --help");
    String::from_utf8(out.stdout).expect("utf8")
}

#[test]
fn every_group_help_lists_all_go_subcommands() {
    let mut failures = Vec::new();
    for group in GROUPS {
        let go_help = load_fixture(group);
        let rust_help = rust_help(group);
        let go_cmds = extract_available_commands(&go_help);
        let rust_cmds = extract_available_commands(&rust_help);
        for cmd in &go_cmds {
            if !rust_cmds.contains(cmd) {
                failures.push(format!("[{group}] Rust --help missing `{cmd}`"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "help-parity failures ({}):\n{}",
        failures.len(),
        failures.join("\n"),
    );
}

#[test]
fn root_help_lists_every_top_level_group() {
    let go_cmds = extract_available_commands(&load_fixture("root"));
    let rust_cmds = extract_available_commands(&rust_help("root"));
    // Sanity: Go ships at least the 14 commands the task scopes
    // (account, app, asset, clerk, completion, kmd, ledger, license,
    // network, node, protocols, report, version, wallet).
    assert!(
        go_cmds.len() >= 14,
        "fixture sanity: expected ≥ 14 top-level commands, got {} — {:?}",
        go_cmds.len(),
        go_cmds,
    );
    for cmd in &go_cmds {
        assert!(
            rust_cmds.contains(cmd),
            "root --help missing top-level command `{cmd}` — got {:?}",
            rust_cmds,
        );
    }
}

#[test]
fn root_version_flag_is_lowercase_v_not_uppercase_v() {
    // Regression guard (Codex review of TASK-220): Go's `goal` binds
    // `-v, --version` as the root flag; clap's default emits `-V`.
    // Verify the lowercase short is accepted and the uppercase one is
    // rejected, so we'd notice if clap's default ever leaks back in.
    let ok = Command::new(GOAL_RUST_BIN)
        .arg("-v")
        .output()
        .expect("run goal-rust -v");
    let stderr = String::from_utf8_lossy(&ok.stderr);
    assert!(
        stderr.contains("goal-rust:  version is not yet implemented"),
        "expected `-v` to hit the version stub; stderr={stderr:?}",
    );

    let nope = Command::new(GOAL_RUST_BIN)
        .arg("-V")
        .output()
        .expect("run goal-rust -V");
    assert!(
        !nope.status.success(),
        "expected `-V` to be rejected (Go's `goal` only binds lowercase -v)",
    );
}

#[test]
fn group_without_leaf_falls_back_to_help_and_exits_zero() {
    // Regression guard (Codex review of TASK-220 round 3): Go's cobra
    // treats `goal app` (group, no leaf) as a help fallback — prints
    // group help on stdout and exits 0. Our scaffold previously
    // rejected with a clap parse error.
    let cases: &[&[&str]] = &[
        &["account"],
        &["app"],
        &["app", "box"],
        &["account", "multisig"],
        &["clerk"],
        &["clerk", "multisig"],
        &["wallet"],
    ];
    for argv in cases {
        let out = Command::new(GOAL_RUST_BIN)
            .args(*argv)
            .output()
            .expect("run goal-rust group");
        assert!(
            out.status.success(),
            "argv={argv:?} expected exit 0 (help fallback), got {:?}\n  stdout={:?}\n  stderr={:?}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("Commands:") || stdout.contains("Available Commands:"),
            "argv={argv:?} expected help on stdout, got {stdout:?}",
        );
        // Regression guard (Codex review round 4): the fallback help
        // must include the binary name in the Usage line, not just
        // the leaf subcommand name — otherwise it diverges from
        // `goal-rust <group> --help` and loses the global flag list.
        assert!(
            stdout.contains("goal-rust"),
            "argv={argv:?} fallback help missing bin name; got {stdout:?}",
        );
        let datadir_mentioned = stdout.contains("--datadir") || stdout.contains("-d, --datadir");
        assert!(
            datadir_mentioned,
            "argv={argv:?} fallback help missing global --datadir flag; got {stdout:?}",
        );
    }
}

#[test]
fn unimplemented_leaf_exits_with_code_two_and_message() {
    // Spot-check a handful of leaves across different groups, including
    // hyphenated names and nested subgroups.
    let cases: &[(&[&str], &str)] = &[
        // Every `account` leaf is implemented (through TASK-244 / B12:
        // changeonlinestatus, marknonparticipating), and the whole `clerk`
        // group is now complete (TASK-292: simulate + multisig). Spot-check
        // still-stubbed leaves in other groups.
        (&["node", "generate-p2pid"], "node generate-p2pid"),
        // All `wallet` leaves are implemented (TASK-226/227/228);
        // use a still-stubbed `node` leaf as the spot check.
        (&["node", "catchup"], "node catchup"),
    ];
    for (argv, expected) in cases {
        let out = Command::new(GOAL_RUST_BIN)
            .args(*argv)
            .output()
            .expect("run goal-rust stub");
        let code = out.status.code().expect("got exit code");
        assert_eq!(
            code,
            2,
            "argv={argv:?} expected exit 2, got {code} (stdout={:?}, stderr={:?})",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        let wanted = format!("goal-rust: {expected} is not yet implemented");
        assert!(
            stderr.contains(&wanted),
            "argv={argv:?} stderr missing `{wanted}`: {stderr:?}",
        );
    }
}
