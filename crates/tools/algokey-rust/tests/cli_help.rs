//! Snapshot-style help-text assertions.
//!
//! Each subcommand's --help output must mention every flag documented in
//! `../go-algorand/cmd/algokey/`. We assert flag names and short letters
//! are present so a future cobra → clap drift surfaces immediately. We do
//! NOT assert byte-exact help text — clap's formatter diverges from
//! cobra's, which is acceptable per TASK-155 ("Byte-exact help-text
//! parity with Go ... is acceptable as long as flag names + descriptions
//! are present").

use std::process::Command;

fn algokey() -> Command {
    Command::new(env!("CARGO_BIN_EXE_algokey-rust"))
}

fn help(args: &[&str]) -> String {
    let mut cmd = algokey();
    for a in args {
        cmd.arg(a);
    }
    cmd.arg("--help");
    let out = cmd.output().expect("run algokey-rust");
    assert!(out.status.success(), "--help should exit 0");
    String::from_utf8(out.stdout).expect("utf8 help")
}

#[test]
fn root_help_lists_all_six_top_level_commands() {
    // Top-level subcommand order matches main.go:45-51 — generate, import,
    // export, sign, multisig, part. `keyreg` is intentionally nested
    // under `part` to mirror Go (`part.go:185`).
    let h = help(&[]);
    for cmd in ["generate", "import", "export", "sign", "multisig", "part"] {
        assert!(h.contains(cmd), "root --help missing `{cmd}`:\n{h}");
    }
    assert!(
        !h.lines().any(|line| line.starts_with("  keyreg")),
        "keyreg must NOT be a top-level command (lives under `part`):\n{h}"
    );
}

#[test]
fn generate_help_has_keyfile_and_pubkeyfile() {
    let h = help(&["generate"]);
    assert!(h.contains("-f, --keyfile"), "missing -f, --keyfile:\n{h}");
    assert!(
        h.contains("-p, --pubkeyfile"),
        "missing -p, --pubkeyfile:\n{h}"
    );
}

#[test]
fn import_help_has_mnemonic_and_keyfile() {
    let h = help(&["import"]);
    assert!(h.contains("-m, --mnemonic"), "missing -m, --mnemonic:\n{h}");
    assert!(h.contains("-f, --keyfile"), "missing -f, --keyfile:\n{h}");
}

#[test]
fn export_help_has_keyfile_and_pubkeyfile() {
    let h = help(&["export"]);
    assert!(h.contains("-f, --keyfile"), "missing -f, --keyfile:\n{h}");
    assert!(
        h.contains("-p, --pubkeyfile"),
        "missing -p, --pubkeyfile:\n{h}"
    );
}

#[test]
fn sign_help_has_all_four_flags() {
    let h = help(&["sign"]);
    for flag in [
        "-k, --keyfile",
        "-m, --mnemonic",
        "-t, --txfile",
        "-o, --outfile",
    ] {
        assert!(h.contains(flag), "sign missing `{flag}`:\n{h}");
    }
}

#[test]
fn multisig_help_has_signing_flags_and_subcommand() {
    let h = help(&["multisig"]);
    for flag in [
        "-k, --keyfile",
        "-m, --mnemonic",
        "-t, --txfile",
        "-o, --outfile",
    ] {
        assert!(h.contains(flag), "multisig missing `{flag}`:\n{h}");
    }
    assert!(
        h.contains("append-auth-addr"),
        "multisig missing append-auth-addr subcommand:\n{h}"
    );
}

#[test]
fn multisig_append_auth_addr_help_has_required_flags() {
    let h = help(&["multisig", "append-auth-addr"]);
    for flag in ["-p, --params", "-t, --txfile", "-o, --outfile"] {
        assert!(h.contains(flag), "append-auth-addr missing `{flag}`:\n{h}");
    }
}

/// Mirrors Go's `partCmd.Run` (part.go:43-46): invoking `part` with no
/// subcommand falls back to printing the help text and exits 0.
#[test]
fn part_with_no_subcommand_prints_help_and_exits_zero() {
    let out = algokey().arg("part").output().expect("run algokey-rust");
    assert!(
        out.status.success(),
        "expected `part` (no subcommand) to succeed; got {:?}, stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["generate", "info", "reparent", "keyreg"] {
        assert!(
            stdout.contains(sub),
            "`part` help should list subcommand `{sub}`:\n{stdout}"
        );
    }
}

#[test]
fn part_help_has_subcommands_including_keyreg() {
    let h = help(&["part"]);
    for sub in ["generate", "info", "reparent", "keyreg"] {
        assert!(h.contains(sub), "part missing subcommand `{sub}`:\n{h}");
    }
}

#[test]
fn part_generate_help_has_required_flags() {
    let h = help(&["part", "generate"]);
    for flag in ["--keyfile", "--first", "--last", "--dilution", "--parent"] {
        assert!(h.contains(flag), "part generate missing `{flag}`:\n{h}");
    }
}

#[test]
fn part_keyreg_help_has_required_flags() {
    let h = help(&["part", "keyreg"]);
    for flag in [
        "--fee",
        "--firstvalid",
        "--lastvalid",
        "--network",
        "--offline",
        "--outputFile",
        "--keyfile",
        "--account",
    ] {
        assert!(h.contains(flag), "part keyreg missing `{flag}`:\n{h}");
    }
}

#[test]
fn required_flags_are_enforced() {
    // Each pair: (argv, why this should fail). clap exits with code 2 for
    // usage errors and our stubs exit with code 2 for "not implemented" —
    // distinguish via stderr content (clap writes a usage line).
    let cases: &[&[&str]] = &[
        &["import"],                              // missing --mnemonic
        &["export"],                              // missing --keyfile
        &["sign"],                                // missing --txfile/--outfile
        &["multisig"],                            // missing --txfile/--outfile
        &["multisig", "append-auth-addr"],        // missing --params/--txfile
        &["part", "generate"],                    // missing --first/--last/--keyfile
        &["part", "info"],                        // missing --keyfile
        &["part", "reparent"],                    // missing --keyfile/--parent
        &["part", "keyreg"],                      // missing --firstvalid AND --network
        &["part", "keyreg", "--firstvalid", "1"], // missing --network (mirrors Go's MarkFlagRequired)
    ];
    for argv in cases {
        let out = algokey().args(*argv).output().expect("run algokey-rust");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success(),
            "expected `{argv:?}` to fail; got success with stderr: {stderr}"
        );
        assert!(
            stderr.contains("required") || stderr.contains("Usage:"),
            "expected `{argv:?}` to print a clap usage error; got: {stderr}"
        );
    }
}

#[test]
fn fully_specified_subcommands_stub_to_not_implemented() {
    // When all required flags are present, the command body should fire
    // and exit 2 with "not implemented" on stderr.
    let cases: &[&[&str]] = &[
        // `generate` is no longer stubbed (TASK-157); it lives in
        // tests/generate_smoke.rs.
        // `import` is no longer stubbed (TASK-158); it lives in
        // tests/import_smoke.rs.
        // `export` is no longer stubbed (TASK-159); it lives in
        // tests/export_smoke.rs.
        // `sign` is no longer stubbed (TASK-167); it has its own unit
        // tests in src/commands/sign.rs.
        &["multisig", "-t", "/tmp/in", "-o", "/tmp/out"],
        &[
            "multisig",
            "append-auth-addr",
            "-p",
            "1 A B",
            "-t",
            "/tmp/in",
        ],
        &[
            "part",
            "generate",
            "--keyfile",
            "/tmp/k",
            "--first",
            "1",
            "--last",
            "1000",
        ],
        &["part", "info", "--keyfile", "/tmp/k"],
        &["part", "reparent", "--keyfile", "/tmp/k", "--parent", "A"],
        &[
            "part",
            "keyreg",
            "--firstvalid",
            "1",
            "--network",
            "mainnet",
        ],
    ];
    for argv in cases {
        let out = algokey().args(*argv).output().expect("run algokey-rust");
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected `{argv:?}` to exit 2 (not implemented); got {:?}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("not implemented"),
            "expected `{argv:?}` stderr to contain 'not implemented'; got: {stderr}"
        );
    }
}
