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

//! cobra's command lookup for `goal account` and `goal wallet`, ahead of
//! clap (issue #2453).
//!
//! go's `accountCmd` and `walletCmd` (`cmd/goal/account.go`, `wallet.go`)
//! take no positional arguments (`Args: validateNoPosArgsFn`, i.e.
//! `cobra.NoArgs`) and declare `-f, --default` with `Flags()`, a local flag.
//! cobra (v1.8.1, `Command.Find`) first walks the arguments down to the
//! deepest subcommand named in them, skipping flags with `stripFlags`, and
//! that one command then parses every remaining argument with its own flag
//! set. So:
//!
//! - `goal account -f x extra` (or `goal account extra`) is
//!   `unknown command "extra" for "goal account"` plus the usage of
//!   `account`;
//! - in `goal account -f x list` the `-f` belongs to `list`, which has no
//!   such flag: `unknown shorthand flag: 'f' in -f` (`unknown flag:
//!   --default` for the long name) plus the usage of `account list`;
//! - in `goal account -f x new` it is `new`'s own (bool) `-f`, the same as
//!   `goal account new -f x`.
//!
//! goal's `main` prints the error once more on stdout (`fmt.Println(err)`)
//! and exits 1. clap would instead reject the extra argument with its own
//! text, and take a `-f` before a subcommand as `account`'s and ignore it,
//! so [`preflight`] settles these cases on the raw arguments first. Anything
//! it does not recognise (an unknown flag, a help flag, a missing flag
//! value) is left to clap unchanged.

use std::ffi::OsString;
use std::process::ExitCode;

use crate::cobra_usage::usage;

/// What [`preflight`] decided.
pub enum Preflight {
    /// Parse these arguments with clap.
    Run(Vec<OsString>),
    /// go's usage error was printed; exit with this code.
    Exit(ExitCode),
}

/// Applies cobra's command lookup for `account` / `wallet` to the process
/// arguments (`args[0]` is the program name).
pub fn preflight(args: Vec<OsString>) -> Preflight {
    let Some(strs) = args
        .iter()
        .map(|a| a.to_str().map(str::to_string))
        .collect::<Option<Vec<String>>>()
    else {
        return Preflight::Run(args);
    };
    match decide(&strs) {
        Outcome::Unchanged => Preflight::Run(args),
        Outcome::Reordered(v) => Preflight::Run(v.into_iter().map(OsString::from).collect()),
        Outcome::Fail { msg, usage_path } => {
            let usage = usage(&usage_path).unwrap_or_default();
            // cobra: `c.PrintErrln("Error:", err.Error())` and
            // `c.PrintErrln(cmd.UsageString())`; goal's main: `fmt.Println(err)`.
            eprintln!("Error: {msg}\n{usage}");
            println!("{msg}");
            Preflight::Exit(ExitCode::from(1))
        }
    }
}

/// The decision on the argument strings.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Leave the arguments to clap as they are.
    Unchanged,
    /// The arguments with the subcommand names moved right after the
    /// group name, so clap hands the flags before them to the subcommand
    /// as cobra does.
    Reordered(Vec<String>),
    /// cobra's usage error: `msg`, then the usage of the command `usage_path`.
    Fail { msg: String, usage_path: String },
}

/// The flags one command knows while cobra looks for a subcommand, short
/// and long names alike; all of them take a value. (cobra adds the help
/// flag only to the command it finds, and a help flag is left to clap.)
type Level = &'static [&'static str];

/// The root's persistent `-d/--datadir` and `-k/--kmddir`. Its local
/// `-v/--version` is not one of `account`'s flags, so a call with it is left
/// to clap.
const ROOT: Level = &["d", "datadir", "k", "kmddir"];

/// `account`: its local `-f/--default`, its persistent `-w/--wallet` and the
/// root's persistent flags.
const ACCOUNT: Level = &["d", "datadir", "k", "kmddir", "w", "wallet", "f", "default"];

/// `wallet`: its local `-f/--default` and the root's persistent flags.
const WALLET: Level = &["d", "datadir", "k", "kmddir", "f", "default"];

/// `account multisig`: the persistent flags it inherits.
const MULTISIG: Level = &["d", "datadir", "k", "kmddir", "w", "wallet"];

const ACCOUNT_SUBCOMMANDS: &[&str] = &[
    "addpartkey",
    "applicationdetails",
    "assetdetails",
    "balance",
    "changeonlinestatus",
    "delete",
    "deletepartkey",
    "dump",
    "export",
    "import",
    "importrootkey",
    "info",
    "installpartkey",
    "list",
    "listpartkeys",
    "marknonparticipating",
    "multisig",
    "new",
    "partkeyinfo",
    "rename",
    "renewallpartkeys",
    "renewpartkey",
    "rewards",
];

const MULTISIG_SUBCOMMANDS: &[&str] = &["delete", "info", "new"];

const WALLET_SUBCOMMANDS: &[&str] = &["list", "new", "rename"];

/// The commands under `account` / `wallet` with a `-f` of their own
/// (`--default` on `new` and `import`, `--fee` on the others).
const OWN_SHORT_F: &[&str] = &[
    "account changeonlinestatus",
    "account import",
    "account marknonparticipating",
    "account new",
    "account renewallpartkeys",
    "account renewpartkey",
];

/// The commands under `account` / `wallet` with a `--default` of their own.
const OWN_LONG_DEFAULT: &[&str] = &["account import", "account new"];

/// One argument, seen by cobra's `stripFlags` at a given command.
enum Token {
    /// `--`: the end of the flags.
    End,
    /// A positional argument (a subcommand name or an argument).
    Positional,
    /// A flag the command knows; `takes_next` when its value is the next
    /// argument (`-f x`, `--default x`).
    Known { takes_next: bool, default: bool },
    /// A help flag, a flag the command does not know, a bare `-`, or
    /// grouped shorthands: left to clap.
    Other,
}

fn token(s: &str, level: Level) -> Token {
    if s == "--" {
        return Token::End;
    }
    if let Some(long) = s.strip_prefix("--") {
        let (name, has_value) = match long.split_once('=') {
            Some((n, _)) => (n, true),
            None => (long, false),
        };
        return if level.contains(&name) {
            Token::Known {
                takes_next: !has_value,
                default: name == "default",
            }
        } else {
            Token::Other
        };
    }
    let Some(short) = s.strip_prefix('-') else {
        return Token::Positional;
    };
    let mut chars = short.chars();
    let Some(c) = chars.next() else {
        return Token::Other;
    };
    if level.contains(&c.to_string().as_str()) {
        // `-fx` and `-f=x` carry their value.
        Token::Known {
            takes_next: chars.as_str().is_empty(),
            default: c == 'f',
        }
    } else {
        Token::Other
    }
}

/// cobra's `stripFlags` skip rule for a flag the command does not know:
/// `-x` and `--name` without `=` take the next argument as their value.
fn unknown_takes_next(s: &str) -> bool {
    !s.contains('=') && (s.starts_with("--") || (s.starts_with('-') && s.chars().count() == 2))
}

/// go's `%q` of a string (`strconv.Quote`), for the argument names in
/// cobra's errors.
fn go_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{07}' => out.push_str("\\a"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0b}' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// pflag's error for `-f` / `--default` given to a command without it.
fn unknown_flag_msg(s: &str) -> String {
    match s.strip_prefix("--") {
        Some(long) => format!(
            "unknown flag: --{}",
            long.split_once('=').map_or(long, |(n, _)| n)
        ),
        None => format!("unknown shorthand flag: 'f' in {s}"),
    }
}

pub(crate) fn decide(args: &[String]) -> Outcome {
    // The group name: the first positional after the root's flags.
    let mut i = 1;
    let group = loop {
        let Some(s) = args.get(i) else {
            return Outcome::Unchanged;
        };
        match token(s, ROOT) {
            Token::Positional => break i,
            Token::Known { takes_next, .. } => i += if takes_next { 2 } else { 1 },
            Token::End | Token::Other => return Outcome::Unchanged,
        }
    };
    let (level, subcommands) = match args[group].as_str() {
        "account" => (ACCOUNT, ACCOUNT_SUBCOMMANDS),
        "wallet" => (WALLET, WALLET_SUBCOMMANDS),
        _ => return Outcome::Unchanged,
    };
    let group_name = args[group].as_str();

    // The group's flags up to the first positional; `defaults` are the
    // `-f` / `--default` arguments among them.
    let mut defaults = Vec::new();
    let mut i = group + 1;
    let first = loop {
        let Some(s) = args.get(i) else {
            return Outcome::Unchanged;
        };
        match token(s, level) {
            Token::Positional => break i,
            Token::Known {
                takes_next,
                default,
            } => {
                if default {
                    defaults.push(i);
                }
                i += if takes_next { 2 } else { 1 };
            }
            // After `--` every argument is positional: the first one is the
            // unknown command, even a subcommand's name.
            Token::End => {
                return match args.get(i + 1) {
                    Some(arg) => Outcome::Fail {
                        msg: format!(
                            "unknown command {} for \"goal {group_name}\"",
                            go_quote(arg)
                        ),
                        usage_path: group_name.to_string(),
                    },
                    None => Outcome::Unchanged,
                };
            }
            Token::Other => return Outcome::Unchanged,
        }
    };

    if !subcommands.contains(&args[first].as_str()) {
        // `cobra.NoArgs`, once the group's flags parsed (an unknown or help
        // flag after the argument wins, left to clap).
        let mut j = first + 1;
        while let Some(s) = args.get(j) {
            match token(s, level) {
                Token::Positional => j += 1,
                Token::Known { takes_next, .. } => j += if takes_next { 2 } else { 1 },
                Token::End => break,
                Token::Other => return Outcome::Unchanged,
            }
        }
        return Outcome::Fail {
            msg: format!(
                "unknown command {} for \"goal {group_name}\"",
                go_quote(&args[first])
            ),
            usage_path: group_name.to_string(),
        };
    }
    if defaults.is_empty() {
        return Outcome::Unchanged;
    }

    // The subcommand path, one level further under `account multisig`.
    let mut names = vec![first];
    if group_name == "account" && args[first] == "multisig" {
        let mut j = first + 1;
        while let Some(s) = args.get(j) {
            match token(s, MULTISIG) {
                Token::Positional => {
                    if MULTISIG_SUBCOMMANDS.contains(&s.as_str()) {
                        names.push(j);
                    }
                    break;
                }
                Token::Known { takes_next, .. } => j += if takes_next { 2 } else { 1 },
                Token::End => break,
                Token::Other => j += if unknown_takes_next(s) { 2 } else { 1 },
            }
        }
    }
    let path = std::iter::once(group)
        .chain(names.iter().copied())
        .map(|k| args[k].as_str())
        .collect::<Vec<_>>()
        .join(" ");

    // The subcommand parses the group's `-f` / `--default` arguments in
    // order: the first one it does not have is pflag's error.
    for &k in &defaults {
        let s = args[k].as_str();
        let own = if s.starts_with("--") {
            OWN_LONG_DEFAULT
        } else {
            OWN_SHORT_F
        };
        if !own.contains(&path.as_str()) {
            return Outcome::Fail {
                msg: unknown_flag_msg(s),
                usage_path: path,
            };
        }
    }

    // All of them are the subcommand's own: hand them to it.
    let mut out: Vec<String> = args[..=group].to_vec();
    out.extend(names.iter().map(|&k| args[k].clone()));
    out.extend(
        args.iter()
            .enumerate()
            .skip(group + 1)
            .filter(|(k, _)| !names.contains(k))
            .map(|(_, s)| s.clone()),
    );
    Outcome::Reordered(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(args: &[&str]) -> Outcome {
        let mut v = vec!["goal".to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        decide(&v)
    }

    fn fail(msg: &str, usage_path: &str) -> Outcome {
        Outcome::Fail {
            msg: msg.to_string(),
            usage_path: usage_path.to_string(),
        }
    }

    fn reordered(args: &[&str]) -> Outcome {
        let mut v = vec!["goal".to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        Outcome::Reordered(v)
    }

    #[test]
    fn extra_arguments_are_cobras_unknown_command() {
        let acct = r#"unknown command "extra" for "goal account""#;
        assert_eq!(d(&["account", "-f", "x", "extra"]), fail(acct, "account"));
        assert_eq!(d(&["account", "extra", "more"]), fail(acct, "account"));
        assert_eq!(
            d(&["-d", "dd", "account", "-w", "w", "extra", "-d", "e"]),
            fail(acct, "account")
        );
        assert_eq!(
            d(&["wallet", "--default=x", "extra"]),
            fail(r#"unknown command "extra" for "goal wallet""#, "wallet")
        );
        // `-w` is not a `wallet` flag, `-f`'s value is not a command.
        assert_eq!(d(&["wallet", "-w", "x", "extra"]), Outcome::Unchanged);
        assert_eq!(d(&["account", "-f", "list"]), Outcome::Unchanged);
        // After `--` even a subcommand's name is an argument.
        assert_eq!(
            d(&["account", "-f", "x", "--", "list"]),
            fail(r#"unknown command "list" for "goal account""#, "account")
        );
        assert_eq!(
            d(&["account", r#"ex"tr\a"#]),
            fail(
                r#"unknown command "ex\"tr\\a" for "goal account""#,
                "account"
            )
        );
    }

    #[test]
    fn help_and_unknown_flags_are_left_to_clap() {
        assert_eq!(d(&["account", "extra", "-h"]), Outcome::Unchanged);
        assert_eq!(d(&["account", "extra", "-z"]), Outcome::Unchanged);
        assert_eq!(d(&["account", "-h", "-f", "x", "list"]), Outcome::Unchanged);
        assert_eq!(d(&["account", "-f"]), Outcome::Unchanged);
        assert_eq!(d(&["account", "-f", "x"]), Outcome::Unchanged);
        assert_eq!(d(&["account", "list", "-f", "x"]), Outcome::Unchanged);
        assert_eq!(d(&["clerk", "extra"]), Outcome::Unchanged);
        assert_eq!(d(&["-v", "account", "extra"]), Outcome::Unchanged);
        assert_eq!(d(&[]), Outcome::Unchanged);
    }

    #[test]
    fn root_default_before_a_subcommand_is_the_subcommands_flag() {
        let short = "unknown shorthand flag: 'f' in -f";
        assert_eq!(
            d(&["account", "-f", "x", "list"]),
            fail(short, "account list")
        );
        assert_eq!(
            d(&["account", "-fx", "list", "--info"]),
            fail("unknown shorthand flag: 'f' in -fx", "account list")
        );
        assert_eq!(
            d(&["account", "--default=x", "multisig", "-w", "w", "info"]),
            fail("unknown flag: --default", "account multisig info")
        );
        assert_eq!(
            d(&["account", "-f", "x", "multisig", "bogus"]),
            fail(short, "account multisig")
        );
        assert_eq!(
            d(&["account", "--default", "5", "changeonlinestatus"]),
            fail("unknown flag: --default", "account changeonlinestatus")
        );
        assert_eq!(
            d(&["account", "-f", "5", "--default", "x", "changeonlinestatus"]),
            fail("unknown flag: --default", "account changeonlinestatus")
        );
        assert_eq!(
            d(&["wallet", "-f", "w", "rename", "a", "b"]),
            fail(short, "wallet rename")
        );
        // The subcommand's own `-f`.
        assert_eq!(
            d(&["-d", "dd", "account", "-f", "x", "-w", "w", "new"]),
            reordered(&["-d", "dd", "account", "new", "-f", "x", "-w", "w"])
        );
        assert_eq!(
            d(&["account", "-f", "5", "changeonlinestatus", "-a", "A"]),
            reordered(&["account", "changeonlinestatus", "-f", "5", "-a", "A"])
        );
        assert_eq!(
            d(&["account", "--default", "imp", "import"]),
            reordered(&["account", "import", "--default", "imp"])
        );
    }

    #[test]
    fn every_command_has_a_usage_and_the_own_flag_lists_match_it() {
        let mut paths = vec!["account".to_string(), "wallet".to_string()];
        paths.extend(ACCOUNT_SUBCOMMANDS.iter().map(|s| format!("account {s}")));
        paths.extend(
            MULTISIG_SUBCOMMANDS
                .iter()
                .map(|s| format!("account multisig {s}")),
        );
        paths.extend(WALLET_SUBCOMMANDS.iter().map(|s| format!("wallet {s}")));
        for p in &paths {
            let u = usage(p).unwrap_or_else(|| panic!("no usage for {p}"));
            assert!(u.starts_with(&format!("Usage:\n  goal {p} ")), "{p}");
            // The command's own flags, before "Global Flags:".
            let own = u
                .split("\nFlags:\n")
                .nth(1)
                .and_then(|f| f.split("\nGlobal Flags:\n").next())
                .unwrap_or("");
            if p == "account" || p == "wallet" {
                continue;
            }
            assert_eq!(
                own.contains("\n  -f, --") || own.starts_with("  -f, --"),
                OWN_SHORT_F.contains(&p.as_str()),
                "{p}: -f"
            );
            assert_eq!(
                own.contains(" --default "),
                OWN_LONG_DEFAULT.contains(&p.as_str()),
                "{p}: --default"
            );
        }
    }
}
