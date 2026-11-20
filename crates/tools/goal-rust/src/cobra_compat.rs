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

//! cobra's command lookup and flag parsing for the `goal account` and
//! `goal wallet` trees, ahead of clap (issues #2453, #2464).
//!
//! go's `goal` (cobra v1.8.1, pflag v1.0.6) runs a command line in these
//! steps, each of which can end it:
//!
//! 1. `Command.Find` walks the arguments down to the deepest subcommand
//!    named in them, skipping flags with `stripFlags` (a flag the command
//!    does not know, and every non-bool one written without `=`, takes the
//!    next argument as its value; the help flag is not known yet);
//! 2. that command parses all remaining arguments with its flag set (its
//!    own flags, the persistent flags of it and its parents, and `-h,
//!    --help`), left to right: the first unknown flag, missing value or bad
//!    value is the error;
//! 3. `-h/--help` prints the command's help on stdout and exits 0;
//! 4. the command's `Args` rule checks the positional arguments;
//! 5. its required flags must all be set.
//!
//! An error in 2, 4 or 5 is printed as `Error: <err>` and the command's
//! usage on stderr, then once more by goal's `main` on stdout
//! (`fmt.Println(err)`), and exits 1. [`preflight`] runs these steps on the
//! raw arguments for a command under `account` or `wallet`; a command line
//! that passes them all goes to clap, with the subcommand names moved right
//! after the group name so that every flag reaches the command cobra found
//! (`goal account -f x new` is `goal account new -f x`).

use std::ffi::OsString;
use std::process::ExitCode;

use crate::cobra_usage::{help, usage};

/// What [`preflight`] decided.
pub enum Preflight {
    /// Parse these arguments with clap.
    Run(Vec<OsString>),
    /// go's help or usage error was printed; exit with this code.
    Exit(ExitCode),
}

/// Applies cobra's lookup and flag parsing for `account` / `wallet` to the
/// process arguments (`args[0]` is the program name).
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
        Outcome::Help(path) => {
            // cobra's default help function writes to `OutOrStdout()`.
            print!("{}", help(&path).unwrap_or_default());
            Preflight::Exit(ExitCode::SUCCESS)
        }
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
    /// The arguments with the subcommand names moved right after the group
    /// name, so clap hands the flags before them to the subcommand as cobra
    /// does.
    Reordered(Vec<String>),
    /// `-h/--help`: go's help of the command `path`.
    Help(String),
    /// cobra's usage error: `msg`, then the usage of the command `usage_path`.
    Fail { msg: String, usage_path: String },
}

/// A pflag value type, as far as parsing tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// `Bool`: takes no value unless written `--name=v` / `-n=v`
    /// (`NoOptDefVal` is `"true"`).
    Bool,
    /// `String`, `StringArray`: any value.
    Str,
    /// `Uint8`: `strconv.ParseUint(s, 0, 8)`.
    U8,
    /// `Uint64`: `strconv.ParseUint(s, 0, 64)`.
    U64,
}

#[derive(Clone, Copy, Debug)]
struct Flag {
    long: &'static str,
    /// The shorthand letter, `0` for none.
    short: u8,
    kind: Kind,
    /// `MarkFlagRequired`.
    required: bool,
}

const fn opt(long: &'static str, short: u8, kind: Kind) -> Flag {
    Flag {
        long,
        short,
        kind,
        required: false,
    }
}

const fn req(long: &'static str, short: u8, kind: Kind) -> Flag {
    Flag {
        long,
        short,
        kind,
        required: true,
    }
}

/// cobra's `InitDefaultHelpFlag`, added to the command it found.
const HELP: Flag = opt("help", b'h', Kind::Bool);

/// A command's `Args` rule.
#[derive(Clone, Copy, Debug)]
enum ArgsRule {
    /// `Args` unset on a command without subcommands: anything goes.
    Arbitrary,
    /// `cobra.NoArgs` (goal's `validateNoPosArgsFn`).
    No,
    Exact(usize),
    Range(usize, usize),
    Min(usize),
}

struct Cmd {
    /// The command path without `goal`; `""` is the root.
    path: &'static str,
    /// `Flags()`.
    local: &'static [Flag],
    /// `PersistentFlags()`, inherited by every command below.
    persistent: &'static [Flag],
    args: ArgsRule,
}

use Kind::{Bool, Str, U64, U8};

/// go's `cmd/goal` `account.go`, `wallet.go` and the root's flags in
/// `commands.go`.
const COMMANDS: &[Cmd] = &[
    Cmd {
        path: "",
        local: &[opt("version", b'v', Bool)],
        persistent: &[opt("datadir", b'd', Str), opt("kmddir", b'k', Str)],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account",
        local: &[opt("default", b'f', Str)],
        persistent: &[opt("wallet", b'w', Str)],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account addpartkey",
        local: &[
            req("address", b'a', Str),
            req("roundFirstValid", 0, U64),
            req("roundLastValid", 0, U64),
            opt("outdir", b'o', Str),
            opt("keyDilution", 0, U64),
        ],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account applicationdetails",
        local: &[
            req("address", b'a', Str),
            opt("next", b'n', Str),
            opt("limit", b'l', U64),
            opt("include-params", 0, Bool),
        ],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account assetdetails",
        local: &[
            req("address", b'a', Str),
            opt("next", b'n', Str),
            opt("limit", b'l', U64),
        ],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account balance",
        local: &[req("address", b'a', Str)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account changeonlinestatus",
        local: &[
            opt("address", b'a', Str),
            opt("partkeyfile", 0, Str),
            opt("signer", b'S', Str),
            opt("online", b'o', Bool),
            opt("fee", b'f', U64),
            opt("firstvalid", 0, U64),
            opt("validrounds", b'v', U64),
            opt("lastvalid", 0, U64),
            opt("lease", b'x', Str),
            opt("txfile", b't', Str),
            opt("no-wait", b'N', Bool),
            opt("rekey-to", 0, Str),
        ],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account delete",
        local: &[req("address", b'a', Str)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account deletepartkey",
        local: &[opt("partkeyid", 0, Str)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        // go marks `balanceCmd`'s `address` required a second time instead.
        path: "account dump",
        local: &[opt("outfile", b'o', Str), opt("address", b'a', Str)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account export",
        local: &[req("address", b'a', Str)],
        persistent: &[],
        args: ArgsRule::Arbitrary,
    },
    Cmd {
        path: "account import",
        local: &[opt("default", b'f', Bool), opt("mnemonic", b'm', Str)],
        persistent: &[],
        args: ArgsRule::Arbitrary,
    },
    Cmd {
        path: "account importrootkey",
        local: &[opt("unencrypted-wallet", b'u', Bool)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account info",
        local: &[req("address", b'a', Str), opt("onlyShowAssetIDs", 0, Bool)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account installpartkey",
        local: &[req("partkey", 0, Str), opt("delete-input", 0, Bool)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account list",
        local: &[opt("info", 0, Bool)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account listpartkeys",
        local: &[],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account marknonparticipating",
        local: &[
            req("address", b'a', Str),
            opt("signer", b'S', Str),
            opt("fee", b'f', U64),
            opt("firstvalid", 0, U64),
            opt("validrounds", b'v', U64),
            opt("lastvalid", 0, U64),
            opt("txfile", b't', Str),
            opt("no-wait", b'N', Bool),
            opt("rekey-to", 0, Str),
        ],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account multisig",
        local: &[],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account multisig delete",
        local: &[req("address", b'a', Str)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account multisig info",
        local: &[req("address", b'a', Str)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account multisig new",
        local: &[req("threshold", b'T', U8)],
        persistent: &[],
        args: ArgsRule::Min(1),
    },
    Cmd {
        path: "account new",
        local: &[opt("default", b'f', Bool)],
        persistent: &[],
        args: ArgsRule::Range(0, 1),
    },
    Cmd {
        path: "account partkeyinfo",
        local: &[],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account rename",
        local: &[],
        persistent: &[],
        args: ArgsRule::Exact(2),
    },
    Cmd {
        path: "account renewallpartkeys",
        local: &[
            opt("fee", b'f', U64),
            req("roundLastValid", 0, U64),
            opt("keyDilution", 0, U64),
            opt("no-wait", b'N', Bool),
            opt("rekey-to", 0, Str),
        ],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "account renewpartkey",
        local: &[
            req("address", b'a', Str),
            opt("fee", b'f', U64),
            req("roundLastValid", 0, U64),
            opt("keyDilution", 0, U64),
            opt("no-wait", b'N', Bool),
            opt("rekey-to", 0, Str),
        ],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        // go marks a `partkeyid` flag required here, which `rewards` does
        // not have (`MarkFlagRequired` fails and is ignored).
        path: "account rewards",
        local: &[req("address", b'a', Str)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "wallet",
        local: &[opt("default", b'f', Str)],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "wallet list",
        local: &[],
        persistent: &[],
        args: ArgsRule::No,
    },
    Cmd {
        path: "wallet new",
        local: &[
            opt("recover", b'r', Bool),
            opt("unencrypted", 0, Bool),
            opt("no-display-seed", 0, Bool),
        ],
        persistent: &[],
        args: ArgsRule::Exact(1),
    },
    Cmd {
        path: "wallet rename",
        local: &[],
        persistent: &[],
        args: ArgsRule::Exact(2),
    },
];

fn command(path: &str) -> Option<&'static Cmd> {
    COMMANDS.iter().find(|c| c.path == path)
}

/// `findNext`: the subcommand `name` of `parent`. Of the root's commands
/// only `account` and `wallet` are known here; any other one is left to
/// clap.
fn child(parent: &Cmd, name: &str) -> Option<&'static Cmd> {
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    let path = if parent.path.is_empty() {
        name.to_string()
    } else {
        format!("{} {name}", parent.path)
    };
    command(&path)
}

/// The flags of `cmd` after `mergePersistentFlags`: its own, then the
/// persistent ones of it and its parents (a parent's flag never shadows one
/// of the same name); `with_help` adds cobra's help flag.
fn flags_of(cmd: &Cmd, with_help: bool) -> Vec<Flag> {
    let mut out: Vec<Flag> = cmd.local.to_vec();
    let mut path = Some(cmd.path);
    while let Some(p) = path {
        let c = command(p).expect("a parent of a known command is known");
        for f in c.persistent {
            if !out.iter().any(|o| o.long == f.long) {
                out.push(*f);
            }
        }
        path = if p.is_empty() {
            None
        } else {
            Some(p.rsplit_once(' ').map_or("", |(parent, _)| parent))
        };
    }
    if with_help {
        out.push(HELP);
    }
    out
}

fn by_long<'a>(flags: &'a [Flag], name: &str) -> Option<&'a Flag> {
    flags.iter().find(|f| f.long == name)
}

fn by_short(flags: &[Flag], c: u8) -> Option<&Flag> {
    flags.iter().find(|f| f.short != 0 && f.short == c)
}

/// cobra's `hasNoOptDefVal` (`--name`): only bool flags have one here.
fn has_no_opt_def_val(name: &str, flags: &[Flag]) -> bool {
    by_long(flags, name).is_some_and(|f| f.kind == Kind::Bool)
}

/// cobra's `shortHasNoOptDefVal` (`-n`).
fn short_has_no_opt_def_val(name: &str, flags: &[Flag]) -> bool {
    name.bytes()
        .next()
        .and_then(|c| by_short(flags, c))
        .is_some_and(|f| f.kind == Kind::Bool)
}

/// The argument `s` takes the next one as its value while cobra looks for
/// commands (`stripFlags`, `argsMinusFirstX`).
fn skips_next(s: &str, flags: &[Flag]) -> bool {
    if s.contains('=') {
        return false;
    }
    if let Some(long) = s.strip_prefix("--") {
        if !has_no_opt_def_val(long, flags) {
            return true;
        }
    }
    s.starts_with('-') && s.len() == 2 && !short_has_no_opt_def_val(&s[1..], flags)
}

/// cobra's `stripFlags`: the positions in `idx` of the non-flag arguments.
fn strip_flags(args: &[String], idx: &[usize], flags: &[Flag]) -> Vec<usize> {
    let mut commands = Vec::new();
    let mut i = 0;
    while i < idx.len() {
        let s = args[idx[i]].as_str();
        i += 1;
        if s == "--" {
            break;
        }
        if skips_next(s, flags) {
            // '-f arg': skip arg, or stop when it is the last one.
            if idx.len() - i <= 1 {
                break;
            }
            i += 1;
            continue;
        }
        if !s.is_empty() && !s.starts_with('-') {
            commands.push(idx[i - 1]);
        }
    }
    commands
}

/// cobra's `argsMinusFirstX`: `idx` without the first argument equal to
/// `x` that is not a flag value.
fn args_minus_first_x(args: &[String], idx: &[usize], x: &str, flags: &[Flag]) -> Vec<usize> {
    let mut pos = 0;
    while pos < idx.len() {
        let s = args[idx[pos]].as_str();
        if s == "--" {
            break;
        }
        if skips_next(s, flags) {
            pos += 2;
            continue;
        }
        if !s.starts_with('-') && s == x {
            let mut out = idx.to_vec();
            out.remove(pos);
            return out;
        }
        pos += 1;
    }
    idx.to_vec()
}

/// go's `%q` of a string (`strconv.Quote`), for the arguments in cobra's
/// and pflag's errors.
fn go_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => push_escaped(&mut out, c),
        }
    }
    out.push('"');
    out
}

/// go's `%q` of a byte (`strconv.QuoteRune(rune(b))`): pflag's
/// `unknown shorthand flag: %q` names the first byte of the shorthands.
fn go_quote_byte(b: u8) -> String {
    let c = char::from(b);
    let mut out = String::from("'");
    match c {
        '\'' => out.push_str("\\'"),
        '\\' => out.push_str("\\\\"),
        c => push_escaped(&mut out, c),
    }
    out.push('\'');
    out
}

/// strconv's escaping of one rune that is not the quote character.
fn push_escaped(out: &mut String, c: char) {
    match c {
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
        // Latin-1's non-printing runes (C1 controls, no-break space, soft
        // hyphen); other non-ASCII runes are printed as they are.
        c if (0x80..=0xa0).contains(&(c as u32)) || c == '\u{ad}' => {
            out.push_str(&format!("\\u{:04x}", c as u32));
        }
        c => out.push(c),
    }
}

/// go's `strconv.ParseBool`.
fn parse_bool(s: &str) -> Result<bool, String> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!(
            "strconv.ParseBool: parsing {}: invalid syntax",
            go_quote(s)
        )),
    }
}

/// go's `strconv.ParseUint(s, 0, bits)`, for the error it returns.
fn parse_uint(s0: &str, bits: u32) -> Result<u64, String> {
    let syntax = || {
        format!(
            "strconv.ParseUint: parsing {}: invalid syntax",
            go_quote(s0)
        )
    };
    let range = || {
        format!(
            "strconv.ParseUint: parsing {}: value out of range",
            go_quote(s0)
        )
    };
    let b = s0.as_bytes();
    if b.is_empty() {
        return Err(syntax());
    }
    let (base, digits): (u64, &[u8]) = if b[0] == b'0' {
        match b.get(1).map(u8::to_ascii_lowercase) {
            Some(b'b') if b.len() >= 3 => (2, &b[2..]),
            Some(b'o') if b.len() >= 3 => (8, &b[2..]),
            Some(b'x') if b.len() >= 3 => (16, &b[2..]),
            _ => (8, &b[1..]),
        }
    } else {
        (10, b)
    };
    let max_val: u64 = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let cutoff = u64::MAX / base + 1;
    let mut underscores = false;
    let mut n: u64 = 0;
    for &c in digits {
        let lower = c.to_ascii_lowercase();
        let d = match c {
            b'_' => {
                underscores = true;
                continue;
            }
            b'0'..=b'9' => u64::from(c - b'0'),
            _ if lower.is_ascii_lowercase() => u64::from(lower - b'a' + 10),
            _ => return Err(syntax()),
        };
        if d >= base {
            return Err(syntax());
        }
        if n >= cutoff {
            return Err(range());
        }
        n *= base;
        let n1 = n.wrapping_add(d);
        if n1 < n || n1 > max_val {
            return Err(range());
        }
        n = n1;
    }
    if underscores && !underscore_ok(b) {
        return Err(syntax());
    }
    Ok(n)
}

/// go's `strconv.underscoreOK`: underscores only between digits (or after
/// the base prefix).
fn underscore_ok(s: &[u8]) -> bool {
    let mut saw = b'^';
    let s = match s.first() {
        Some(b'-' | b'+') => &s[1..],
        _ => s,
    };
    let mut i = 0;
    let mut hex = false;
    if s.len() >= 2 && s[0] == b'0' && matches!(s[1].to_ascii_lowercase(), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0';
        hex = s[1].to_ascii_lowercase() == b'x';
    }
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c.is_ascii_digit() || (hex && matches!(c.to_ascii_lowercase(), b'a'..=b'f')) {
            saw = b'0';
            continue;
        }
        if c == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
    }
    saw != b'_'
}

/// What the found command's flag parsing left.
struct Parsed {
    /// `Flags().Args()`.
    positional: Vec<String>,
    /// The long names of the flags set.
    changed: Vec<&'static str>,
    help: bool,
}

impl Parsed {
    /// pflag's `FlagSet.Set`.
    fn set(&mut self, flag: &Flag, value: &str) -> Result<(), String> {
        let checked = match flag.kind {
            Kind::Bool => parse_bool(value).map(|v| {
                if flag.long == HELP.long {
                    self.help = v;
                }
            }),
            Kind::Str => Ok(()),
            Kind::U8 => parse_uint(value, 8).map(drop),
            Kind::U64 => parse_uint(value, 64).map(drop),
        };
        if let Err(e) = checked {
            let name = if flag.short != 0 {
                format!("-{}, --{}", char::from(flag.short), flag.long)
            } else {
                format!("--{}", flag.long)
            };
            return Err(format!(
                "invalid argument {} for {} flag: {e}",
                go_quote(value),
                go_quote(&name)
            ));
        }
        if !self.changed.contains(&flag.long) {
            self.changed.push(flag.long);
        }
        Ok(())
    }
}

/// pflag's `FlagSet.Parse` (interspersed, `ContinueOnError`).
fn parse(args: &[&str], flags: &[Flag]) -> Result<Parsed, String> {
    let mut p = Parsed {
        positional: Vec::new(),
        changed: Vec::new(),
        help: false,
    };
    let mut i = 0;
    while i < args.len() {
        let s = args[i];
        i += 1;
        if s.len() < 2 || !s.starts_with('-') {
            p.positional.push(s.to_string());
            continue;
        }
        if s == "--" {
            p.positional
                .extend(args[i..].iter().map(|a| (*a).to_string()));
            break;
        }
        if let Some(name) = s.strip_prefix("--") {
            // parseLongArg
            if name.starts_with(['-', '=']) {
                return Err(format!("bad flag syntax: {s}"));
            }
            let (name, inline) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (name, None),
            };
            let Some(flag) = by_long(flags, name) else {
                return Err(format!("unknown flag: --{name}"));
            };
            let value = match inline {
                Some(v) => v,
                None if flag.kind == Kind::Bool => "true",
                None if i < args.len() => {
                    i += 1;
                    args[i - 1]
                }
                None => return Err(format!("flag needs an argument: {s}")),
            };
            p.set(flag, value)?;
            continue;
        }
        // parseShortArg: one shorthand letter at a time.
        let mut shorthands = &s.as_bytes()[1..];
        while !shorthands.is_empty() {
            if shorthands.starts_with(b"test.") {
                break;
            }
            let c = shorthands[0];
            let rest = String::from_utf8_lossy(shorthands);
            let Some(flag) = by_short(flags, c) else {
                return Err(format!(
                    "unknown shorthand flag: {} in -{rest}",
                    go_quote_byte(c)
                ));
            };
            let value: String;
            if shorthands.len() > 2 && shorthands[1] == b'=' {
                value = String::from_utf8_lossy(&shorthands[2..]).into_owned();
                shorthands = &[];
            } else if flag.kind == Kind::Bool {
                value = "true".to_string();
                shorthands = &shorthands[1..];
            } else if shorthands.len() > 1 {
                value = String::from_utf8_lossy(&shorthands[1..]).into_owned();
                shorthands = &[];
            } else if i < args.len() {
                value = args[i].to_string();
                i += 1;
                shorthands = &[];
            } else {
                return Err(format!(
                    "flag needs an argument: {} in -{rest}",
                    go_quote_byte(c)
                ));
            }
            p.set(flag, &value)?;
        }
    }
    Ok(p)
}

/// The command's `Args` rule on its positional arguments.
fn validate_args(cmd: &Cmd, args: &[String]) -> Result<(), String> {
    let n = args.len();
    match cmd.args {
        ArgsRule::Arbitrary => Ok(()),
        ArgsRule::No if n > 0 => Err(format!(
            "unknown command {} for \"goal {}\"",
            go_quote(&args[0]),
            cmd.path
        )),
        ArgsRule::No => Ok(()),
        ArgsRule::Exact(k) if n != k => Err(format!("accepts {k} arg(s), received {n}")),
        ArgsRule::Range(lo, hi) if n < lo || n > hi => Err(format!(
            "accepts between {lo} and {hi} arg(s), received {n}"
        )),
        ArgsRule::Min(k) if n < k => {
            Err(format!("requires at least {k} arg(s), only received {n}"))
        }
        ArgsRule::Exact(_) | ArgsRule::Range(..) | ArgsRule::Min(_) => Ok(()),
    }
}

/// cobra's `ValidateRequiredFlags`: the unset required flags, in pflag's
/// (sorted) order.
fn validate_required(flags: &[Flag], changed: &[&str]) -> Result<(), String> {
    let mut missing: Vec<&str> = flags
        .iter()
        .filter(|f| f.required && !changed.contains(&f.long))
        .map(|f| f.long)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    missing.sort_unstable();
    Err(format!(
        "required flag(s) \"{}\" not set",
        missing.join("\", \"")
    ))
}

pub(crate) fn decide(args: &[String]) -> Outcome {
    // Find: walk down from the root.
    let mut cmd = command("").expect("the root is in the table");
    let mut idx: Vec<usize> = (1..args.len()).collect();
    let mut names = Vec::new();
    loop {
        let flags = flags_of(cmd, false);
        let Some(&next) = strip_flags(args, &idx, &flags).first() else {
            break;
        };
        let Some(sub) = child(cmd, &args[next]) else {
            break;
        };
        idx = args_minus_first_x(args, &idx, &args[next], &flags);
        names.push(next);
        cmd = sub;
    }
    if cmd.path.is_empty() {
        return Outcome::Unchanged;
    }

    // execute: flags, help, `Args`, required flags.
    let flags = flags_of(cmd, true);
    let rest: Vec<&str> = idx.iter().map(|&k| args[k].as_str()).collect();
    let fail = |msg: String| Outcome::Fail {
        msg,
        usage_path: cmd.path.to_string(),
    };
    let parsed = match parse(&rest, &flags) {
        Ok(p) => p,
        Err(msg) => return fail(msg),
    };
    if parsed.help {
        return Outcome::Help(cmd.path.to_string());
    }
    if let Err(msg) = validate_args(cmd, &parsed.positional) {
        return fail(msg);
    }
    if let Err(msg) = validate_required(&flags, &parsed.changed) {
        return fail(msg);
    }

    // Hand every argument after the command names to the found command.
    let group = names[0];
    let mut out: Vec<String> = args[..=group].to_vec();
    out.extend(names[1..].iter().map(|&k| args[k].clone()));
    out.extend(
        args.iter()
            .enumerate()
            .skip(group + 1)
            .filter(|(k, _)| !names.contains(k))
            .map(|(_, s)| s.clone()),
    );
    if out == args {
        Outcome::Unchanged
    } else {
        Outcome::Reordered(out)
    }
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

    fn help(path: &str) -> Outcome {
        Outcome::Help(path.to_string())
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
        // `-w` is not a `wallet` flag; `-f`'s value is not a command.
        assert_eq!(
            d(&["wallet", "-w", "x", "extra"]),
            fail("unknown shorthand flag: 'w' in -w", "wallet")
        );
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
        assert_eq!(
            d(&["account", "list", "--", "x"]),
            fail(
                r#"unknown command "x" for "goal account list""#,
                "account list"
            )
        );
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
        assert_eq!(
            d(&["account", "-w", "w", "multisig", "info", "-a", "A"]),
            reordered(&["account", "multisig", "info", "-w", "w", "-a", "A"])
        );
        assert_eq!(d(&["account", "list", "--info"]), Outcome::Unchanged);
        assert_eq!(d(&["clerk", "extra"]), Outcome::Unchanged);
        assert_eq!(d(&["-v"]), Outcome::Unchanged);
        assert_eq!(d(&[]), Outcome::Unchanged);
    }

    #[test]
    fn help_is_the_found_commands() {
        assert_eq!(d(&["account", "-h"]), help("account"));
        assert_eq!(d(&["wallet", "--help"]), help("wallet"));
        // The help flag is unknown while cobra looks for the command: it
        // takes the next argument as its value.
        assert_eq!(d(&["account", "-h", "list"]), help("account"));
        assert_eq!(d(&["account", "--help", "list"]), help("account"));
        assert_eq!(d(&["account", "-f", "x", "-h"]), help("account"));
        assert_eq!(
            d(&["account", "multisig", "new", "-h"]),
            help("account multisig new")
        );
        // Help wins over the arguments and the required flags...
        assert_eq!(d(&["account", "info", "-h", "extra"]), help("account info"));
        // ... but not over a flag error, wherever it stands.
        assert_eq!(
            d(&["account", "list", "-h", "-z"]),
            fail("unknown shorthand flag: 'z' in -z", "account list")
        );
        assert_eq!(
            d(&["wallet", "-h", "-f"]),
            fail("flag needs an argument: 'f' in -f", "wallet")
        );
        assert_eq!(
            d(&["account", "list", "-h=x"]),
            fail(
                r#"invalid argument "x" for "-h, --help" flag: strconv.ParseBool: parsing "x": invalid syntax"#,
                "account list"
            )
        );
        assert_eq!(d(&["account", "list", "--help=false"]), Outcome::Unchanged);
    }

    #[test]
    fn flag_errors_are_pflags_first_from_the_left() {
        let cos = "account changeonlinestatus";
        assert_eq!(
            d(&["account", "-f"]),
            fail("flag needs an argument: 'f' in -f", "account")
        );
        assert_eq!(
            d(&["account", "--default"]),
            fail("flag needs an argument: --default", "account")
        );
        assert_eq!(
            d(&["account", "list", "-w"]),
            fail("flag needs an argument: 'w' in -w", "account list")
        );
        assert_eq!(
            d(&["account", "-z", "list"]),
            fail("unknown shorthand flag: 'z' in -z", "account")
        );
        assert_eq!(
            d(&["-v", "account", "list"]),
            fail("unknown shorthand flag: 'v' in -v", "account")
        );
        assert_eq!(
            d(&["account", "list", "--nosuch=1"]),
            fail("unknown flag: --nosuch", "account list")
        );
        assert_eq!(
            d(&["account", "list", "---x"]),
            fail("bad flag syntax: ---x", "account list")
        );
        assert_eq!(
            d(&["account", "list", "-é"]),
            fail("unknown shorthand flag: 'Ã' in -é", "account list")
        );
        assert_eq!(
            d(&["account", "changeonlinestatus", "-Nz"]),
            fail("unknown shorthand flag: 'z' in -z", cos)
        );
        assert_eq!(
            d(&["account", "changeonlinestatus", "-f", "x", "-z"]),
            fail(
                r#"invalid argument "x" for "-f, --fee" flag: strconv.ParseUint: parsing "x": invalid syntax"#,
                cos
            )
        );
        assert_eq!(
            d(&["account", "changeonlinestatus", "-z", "-f", "x"]),
            fail("unknown shorthand flag: 'z' in -z", cos)
        );
        assert_eq!(
            d(&["account", "changeonlinestatus", "-ofalse"]),
            fail(
                r#"invalid argument "alse" for "-f, --fee" flag: strconv.ParseUint: parsing "alse": invalid syntax"#,
                cos
            )
        );
        assert_eq!(
            d(&["account", "changeonlinestatus", "--lastvalid", "1_0"]),
            Outcome::Unchanged
        );
        assert_eq!(
            d(&["account", "renewallpartkeys", "--roundLastValid=-1"]),
            fail(
                r#"invalid argument "-1" for "--roundLastValid" flag: strconv.ParseUint: parsing "-1": invalid syntax"#,
                "account renewallpartkeys"
            )
        );
    }

    #[test]
    fn arguments_then_required_flags() {
        assert_eq!(
            d(&["wallet", "new"]),
            fail("accepts 1 arg(s), received 0", "wallet new")
        );
        assert_eq!(
            d(&["account", "new", "a", "b"]),
            fail("accepts between 0 and 1 arg(s), received 2", "account new")
        );
        assert_eq!(
            d(&["account", "multisig", "new"]),
            fail(
                "requires at least 1 arg(s), only received 0",
                "account multisig new"
            )
        );
        assert_eq!(
            d(&["account", "balance", "extra"]),
            fail(
                r#"unknown command "extra" for "goal account balance""#,
                "account balance"
            )
        );
        assert_eq!(
            d(&["account", "addpartkey", "--roundLastValid", "5"]),
            fail(
                r#"required flag(s) "address", "roundFirstValid" not set"#,
                "account addpartkey"
            )
        );
        assert_eq!(
            d(&["account", "export", "extra"]),
            fail(r#"required flag(s) "address" not set"#, "account export")
        );
        assert_eq!(d(&["account", "dump"]), Outcome::Unchanged);
        assert_eq!(d(&["account", "rewards", "-a", "A"]), Outcome::Unchanged);
    }

    #[test]
    fn parse_uint_matches_strconv() {
        let ok = |s: &str, bits: u32| parse_uint(s, bits).ok();
        assert_eq!(ok("0", 64), Some(0));
        assert_eq!(ok("0x_1F", 64), Some(31));
        assert_eq!(ok("0b101", 64), Some(5));
        assert_eq!(ok("0o17", 64), Some(15));
        assert_eq!(ok("017", 64), Some(15));
        assert_eq!(ok("1_000", 64), Some(1000));
        assert_eq!(ok("255", 8), Some(255));
        assert_eq!(ok("18446744073709551615", 64), Some(u64::MAX));
        for bad in ["", "0x", "08", "1__0", "_1", "1_", "-1", "+1", "x", "0x_"] {
            assert_eq!(
                parse_uint(bad, 64),
                Err(format!(
                    "strconv.ParseUint: parsing {}: invalid syntax",
                    go_quote(bad)
                )),
                "{bad}"
            );
        }
        for big in [
            ("256", 8),
            ("18446744073709551616", 64),
            ("0x1_0000_0000_0000_0000", 64),
        ] {
            assert_eq!(
                parse_uint(big.0, big.1),
                Err(format!(
                    "strconv.ParseUint: parsing \"{}\": value out of range",
                    big.0
                ))
            );
        }
    }

    #[test]
    fn go_quotes() {
        assert_eq!(go_quote_byte(b'f'), "'f'");
        assert_eq!(go_quote_byte(b'\''), r"'\''");
        assert_eq!(go_quote_byte(1), r"'\x01'");
        assert_eq!(go_quote_byte(0xc3), "'Ã'");
        assert_eq!(go_quote_byte(0x85), r"'\u0085'");
        assert_eq!(go_quote("a\"b\n"), r#""a\"b\n""#);
    }

    /// The flag table against go's usage text: each command's flags,
    /// shorthands and value-taking (a bool flag shows no type) and its
    /// inherited ones.
    #[test]
    fn the_flag_table_matches_gos_usage() {
        for cmd in COMMANDS.iter().filter(|c| !c.path.is_empty()) {
            let u = usage(cmd.path).unwrap_or_else(|| panic!("no usage for {}", cmd.path));
            assert!(help_text_of(cmd.path).is_some(), "{}: no help", cmd.path);
            let mut want: Vec<String> = Vec::new();
            let mut section = "";
            for line in u.lines() {
                if line.ends_with(':') && !line.starts_with(' ') {
                    section = line;
                    continue;
                }
                if section != "Flags:" && section != "Global Flags:"
                    || !line.trim_start().starts_with('-')
                {
                    continue;
                }
                let spec = line.trim_start();
                let (short, rest) = match spec.strip_prefix('-').filter(|_| !spec.starts_with("--"))
                {
                    Some(r) => (r.as_bytes()[0], &r[3..]),
                    None => (0, spec),
                };
                let rest = rest.strip_prefix("--").expect("a long name");
                let head = rest.split("  ").next().unwrap_or("");
                let (long, typ) = head.split_once(' ').unwrap_or((head, ""));
                // `--recover` is a bool with a backquoted name in its usage.
                let bool_flag = typ.is_empty() || long == "recover";
                want.push(format!(
                    "{long}/{}/{bool_flag}",
                    char::from(short.max(b' '))
                ));
            }
            let mut got: Vec<String> = flags_of(cmd, true)
                .iter()
                .map(|f| {
                    format!(
                        "{}/{}/{}",
                        f.long,
                        char::from(f.short.max(b' ')),
                        f.kind == Kind::Bool
                    )
                })
                .collect();
            want.sort();
            got.sort();
            assert_eq!(got, want, "{}", cmd.path);
        }
    }

    fn help_text_of(path: &str) -> Option<String> {
        crate::cobra_usage::help(path)
    }
}
