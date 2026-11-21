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

//! cobra's command lookup and flag parsing, ahead of clap (issues #2453,
//! #2464, #2472).
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
//! (`fmt.Println(err)`), and exits 1.
//!
//! The command table is go's own: `cobra_tree.json`, which
//! `tools/goal-cobra-oracle` dumps from go `goal` v5.0.5-stable's cobra tree
//! (every command's flags, `Args` rule, usage and help texts, and the runes
//! `strconv.IsPrint` rejects). [`preflight`] runs the steps above on the raw
//! arguments, for every command line but the two goal's `main` handles
//! before cobra (`goal helptest`, `goal generate-docs <dir>`); one that
//! passes them all goes to clap rewritten
//! into one canonical form: the command names, then each flag cobra set as
//! `--<long>=<value>` (numbers as go parsed them, a bool flag as clap's
//! switch), then the positional arguments. So every flag reaches the
//! command cobra found (`goal account -f x new` is `goal account new -f
//! x`), and clap sees the values go would use (`--fee 0x10` is 16).

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::OnceLock;

use serde::Deserialize;

/// What [`preflight`] decided.
pub enum Preflight {
    /// Parse these arguments with clap.
    Run(Vec<OsString>),
    /// go's help or usage error was printed; exit with this code.
    Exit(ExitCode),
}

/// Applies cobra's lookup and flag parsing to the process arguments
/// (`args[0]` is the program name).
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
        Outcome::Run(v) if v == strs => Preflight::Run(args),
        Outcome::Run(v) => Preflight::Run(v.into_iter().map(OsString::from).collect()),
        Outcome::Help(path) => {
            // cobra's default help function writes to `OutOrStdout()`.
            print!("{}", help(&path).unwrap_or_default());
            Preflight::Exit(ExitCode::SUCCESS)
        }
        Outcome::Print(text) => {
            print!("{text}");
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

/// go's usage text of the command `path` (`"account multisig new"`;
/// `Command.UsageString()`), or `None` for a command go does not have.
pub(crate) fn usage(path: &str) -> Option<&'static str> {
    command(path).map(|c| c.usage.as_str())
}

/// go's `goal <path> --help` (cobra's help template: the `Long` text, or
/// the `Short` one, a blank line and the usage), printed on stdout.
pub(crate) fn help(path: &str) -> Option<&'static str> {
    command(path).map(|c| c.help_text.as_str())
}

/// The decision on the argument strings.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Leave the arguments to clap as they are.
    Unchanged,
    /// The canonical form of the command line for clap.
    Run(Vec<String>),
    /// `-h/--help`: go's help of the command `path`.
    Help(String),
    /// Print this on stdout and exit 0 (`goal helptest`).
    Print(String),
    /// cobra's usage error: `msg`, then the usage of the command `usage_path`.
    Fail { msg: String, usage_path: String },
}

// ---- go's command tree ------------------------------------------------------

/// `cobra_tree.json` as `tools/goal-cobra-oracle` writes it.
#[derive(Deserialize)]
struct TreeFile {
    commands: Vec<CmdData>,
    /// `strconv.IsPrint`'s false runes: hex `lo-hi` ranges, comma-separated.
    not_printable: String,
}

// The fields only the tests read state what this port assumes of the tree.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Deserialize)]
struct CmdData {
    path: String,
    name: String,
    aliases: Vec<String>,
    hidden: bool,
    deprecated: String,
    runnable: bool,
    disable_flag_parsing: bool,
    traverse_children: bool,
    silence_usage: bool,
    silence_errors: bool,
    args_nil: bool,
    args_probe: Option<Vec<Option<String>>>,
    local: Vec<FlagData>,
    persistent: Vec<FlagData>,
    help_flag: FlagData,
    usage: String,
    help: String,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Deserialize)]
struct FlagData {
    name: String,
    shorthand: String,
    #[serde(rename = "type")]
    ty: String,
    no_opt_def_val: String,
    def_value: String,
    required: bool,
    hidden: bool,
    deprecated: String,
    shorthand_deprecated: String,
}

/// A pflag value type, as far as parsing tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Bool,
    /// `String`: any value.
    Str,
    /// `StringArray`: any value, every one kept.
    StrArray,
    /// `StringSlice`: each value read as one CSV record, every one kept.
    StrSlice,
    /// `Uint*`: `strconv.ParseUint(s, 0, bits)`.
    Uint(u32),
    /// `Int*`: `strconv.ParseInt(s, 0, bits)`.
    Int(u32),
    /// A type this port does not parse (none in go goal v5.0.5-stable).
    Other,
}

impl Kind {
    fn of(ty: &str) -> Kind {
        match ty {
            "bool" => Kind::Bool,
            "string" => Kind::Str,
            "stringArray" => Kind::StrArray,
            "stringSlice" => Kind::StrSlice,
            "uint64" | "uint" => Kind::Uint(64),
            "uint32" => Kind::Uint(32),
            "uint16" => Kind::Uint(16),
            "uint8" => Kind::Uint(8),
            "int64" | "int" => Kind::Int(64),
            "int32" => Kind::Int(32),
            "int16" => Kind::Int(16),
            "int8" => Kind::Int(8),
            _ => Kind::Other,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
struct Flag {
    long: String,
    /// The shorthand letter, `0` for none.
    short: u8,
    kind: Kind,
    /// pflag's `NoOptDefVal`: the value of `--name` / `-n` without one.
    no_opt: Option<String>,
    /// `MarkFlagRequired`.
    required: bool,
    /// The pflag type name.
    ty: String,
    /// `DefValue`.
    def: String,
}

impl Flag {
    fn from(d: &FlagData) -> Flag {
        Flag {
            long: d.name.clone(),
            short: d.shorthand.bytes().next().unwrap_or(0),
            kind: Kind::of(&d.ty),
            no_opt: (!d.no_opt_def_val.is_empty()).then(|| d.no_opt_def_val.clone()),
            required: d.required,
            ty: d.ty.clone(),
            def: d.def_value.clone(),
        }
    }
}

/// A command's `Args` rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArgsRule {
    /// `Args` unset (a command without subcommands takes anything) or
    /// `cobra.ArbitraryArgs`.
    Arbitrary,
    /// `cobra.NoArgs` (goal's `validateNoPosArgsFn`).
    No,
    Exact(usize),
    Range(usize, usize),
    Min(usize),
    /// A validator of goal's own: `node catchup`'s `catchpointCmdArgument`,
    /// ported in [`validate_args`].
    Custom,
}

struct Cmd {
    /// The command path without `goal`; `""` is the root.
    path: String,
    name: String,
    aliases: Vec<String>,
    /// `Flags()`.
    local: Vec<Flag>,
    /// `PersistentFlags()`, inherited by every command below.
    persistent: Vec<Flag>,
    /// cobra's `InitDefaultHelpFlag`, added to the command it found.
    help: Flag,
    args: ArgsRule,
    runnable: bool,
    usage: String,
    help_text: String,
}

fn tree_file() -> &'static TreeFile {
    static FILE: OnceLock<TreeFile> = OnceLock::new();
    FILE.get_or_init(|| {
        serde_json::from_str(include_str!("cobra_tree.json"))
            .expect("cobra_tree.json is go goal's cobra tree")
    })
}

fn tree() -> &'static [Cmd] {
    static TREE: OnceLock<Vec<Cmd>> = OnceLock::new();
    TREE.get_or_init(|| {
        // `args_rule` quotes arguments, which asks `is_print` for the ranges:
        // they live in their own cell, not in this one.
        tree_file()
            .commands
            .iter()
            .map(|d| Cmd {
                path: d.path.clone(),
                name: d.name.clone(),
                aliases: d.aliases.clone(),
                local: d.local.iter().map(Flag::from).collect(),
                persistent: d.persistent.iter().map(Flag::from).collect(),
                help: Flag::from(&d.help_flag),
                args: args_rule(d),
                runnable: d.runnable,
                usage: d.usage.clone(),
                help_text: d.help.clone(),
            })
            .collect()
    })
}

/// `strconv.IsPrint`'s false ranges, sorted.
fn not_printable() -> &'static [(u32, u32)] {
    static RANGES: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    RANGES.get_or_init(|| {
        tree_file()
            .not_printable
            .split(',')
            .filter_map(|r| {
                let (lo, hi) = r.split_once('-')?;
                Some((
                    u32::from_str_radix(lo, 16).ok()?,
                    u32::from_str_radix(hi, 16).ok()?,
                ))
            })
            .collect()
    })
}

/// go's `strconv.IsPrint`.
fn is_print(c: char) -> bool {
    let c = c as u32;
    let ranges = not_printable();
    let i = ranges.partition_point(|&(_, hi)| hi < c);
    !ranges.get(i).is_some_and(|&(lo, _)| lo <= c)
}

/// `goal` and the command path.
fn command_path(path: &str) -> String {
    if path.is_empty() {
        "goal".to_string()
    } else {
        format!("goal {path}")
    }
}

/// The `Args` rule whose errors are the ones go's validator gave for 0 to
/// 6 arguments `a1`..`a6`.
fn args_rule(d: &CmdData) -> ArgsRule {
    let Some(probe) = &d.args_probe else {
        // cobra's `legacyArgs` for a command that is not the root.
        return ArgsRule::Arbitrary;
    };
    let mut candidates = vec![ArgsRule::Arbitrary, ArgsRule::No];
    for k in 0..=6 {
        candidates.push(ArgsRule::Exact(k));
        candidates.push(ArgsRule::Min(k));
        for hi in k..=5 {
            candidates.push(ArgsRule::Range(k, hi));
        }
    }
    let args: Vec<String> = (1..=6).map(|i| format!("a{i}")).collect();
    candidates
        .into_iter()
        .find(|rule| {
            (0..=6).all(|n| {
                probe.get(n).cloned().flatten() == validate_args(&d.path, *rule, &args[..n]).err()
            })
        })
        .unwrap_or(ArgsRule::Custom)
}

fn command(path: &str) -> Option<&'static Cmd> {
    tree().iter().find(|c| c.path == path)
}

/// `findNext`: the subcommand `name` (or alias) of `parent`.
fn child(parent: &Cmd, name: &str) -> Option<&'static Cmd> {
    if name.is_empty() {
        return None;
    }
    tree().iter().find(|c| {
        !c.path.is_empty()
            && c.path.rsplit_once(' ').map_or("", |(p, _)| p) == parent.path
            && (c.name == name || c.aliases.iter().any(|a| a == name))
    })
}

/// The flags of `cmd` after `mergePersistentFlags`: its own, then the
/// persistent ones of it and its parents (a parent's flag never shadows one
/// of the same name); `with_help` adds cobra's help flag.
fn flags_of(cmd: &'static Cmd, with_help: bool) -> Vec<&'static Flag> {
    let mut out: Vec<&'static Flag> = cmd.local.iter().collect();
    let mut path = Some(cmd.path.as_str());
    while let Some(p) = path {
        let c = command(p).expect("a parent of a known command is known");
        for f in &c.persistent {
            if !out.iter().any(|o| o.long == f.long) {
                out.push(f);
            }
        }
        path = if p.is_empty() {
            None
        } else {
            Some(p.rsplit_once(' ').map_or("", |(parent, _)| parent))
        };
    }
    if with_help && !out.iter().any(|o| o.long == cmd.help.long) {
        out.push(&cmd.help);
    }
    out
}

fn by_long(flags: &[&'static Flag], name: &str) -> Option<&'static Flag> {
    flags.iter().copied().find(|f| f.long == name)
}

fn by_short(flags: &[&'static Flag], c: u8) -> Option<&'static Flag> {
    flags.iter().copied().find(|f| f.short != 0 && f.short == c)
}

/// cobra's `hasNoOptDefVal` (`--name`).
fn has_no_opt_def_val(name: &str, flags: &[&'static Flag]) -> bool {
    by_long(flags, name).is_some_and(|f| f.no_opt.is_some())
}

/// cobra's `shortHasNoOptDefVal` (`-n`).
fn short_has_no_opt_def_val(name: &str, flags: &[&'static Flag]) -> bool {
    name.bytes()
        .next()
        .and_then(|c| by_short(flags, c))
        .is_some_and(|f| f.no_opt.is_some())
}

/// The argument `s` takes the next one as its value while cobra looks for
/// commands (`stripFlags`, `argsMinusFirstX`).
fn skips_next(s: &str, flags: &[&'static Flag]) -> bool {
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
fn strip_flags(args: &[String], idx: &[usize], flags: &[&'static Flag]) -> Vec<usize> {
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
fn args_minus_first_x(
    args: &[String],
    idx: &[usize],
    x: &str,
    flags: &[&'static Flag],
) -> Vec<usize> {
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

// ---- go's value parsing -------------------------------------------------------

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

/// strconv's `appendEscapedRune` for a rune that is not the quote
/// character or a backslash: a printable one as it is, else its escape.
fn push_escaped(out: &mut String, c: char) {
    if is_print(c) {
        out.push(c);
        return;
    }
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
        c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
        c => out.push_str(&format!("\\U{:08x}", c as u32)),
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

/// Why `strconv.Parse{Uint,Int}` failed.
#[derive(Debug, PartialEq, Eq)]
enum NumErr {
    Syntax,
    Range,
}

/// go's `strconv.ParseUint(s, 0, bits)`.
fn parse_uint_raw(s0: &str, bits: u32) -> Result<u64, NumErr> {
    let b = s0.as_bytes();
    if b.is_empty() {
        return Err(NumErr::Syntax);
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
            _ => return Err(NumErr::Syntax),
        };
        if d >= base {
            return Err(NumErr::Syntax);
        }
        if n >= cutoff {
            return Err(NumErr::Range);
        }
        n *= base;
        let n1 = n.wrapping_add(d);
        if n1 < n || n1 > max_val {
            return Err(NumErr::Range);
        }
        n = n1;
    }
    if underscores && !underscore_ok(b) {
        return Err(NumErr::Syntax);
    }
    Ok(n)
}

fn num_err(func: &str, s0: &str, e: NumErr) -> String {
    let why = match e {
        NumErr::Syntax => "invalid syntax",
        NumErr::Range => "value out of range",
    };
    format!("strconv.{func}: parsing {}: {why}", go_quote(s0))
}

/// go's `strconv.ParseUint(s, 0, bits)`, for the error it returns.
fn parse_uint(s0: &str, bits: u32) -> Result<u64, String> {
    parse_uint_raw(s0, bits).map_err(|e| num_err("ParseUint", s0, e))
}

/// go's `strconv.ParseInt(s, 0, bits)`.
fn parse_int(s0: &str, bits: u32) -> Result<i64, String> {
    let err = |e| num_err("ParseInt", s0, e);
    let (neg, s) = match s0.as_bytes().first() {
        Some(b'+') => (false, &s0[1..]),
        Some(b'-') => (true, &s0[1..]),
        _ => (false, s0),
    };
    let un = match parse_uint_raw(s, bits) {
        Ok(v) => v,
        Err(NumErr::Range) => return Err(err(NumErr::Range)),
        Err(e) => return Err(err(e)),
    };
    let cutoff = 1u64 << (bits - 1);
    if !neg && un >= cutoff {
        return Err(err(NumErr::Range));
    }
    if neg && un > cutoff {
        return Err(err(NumErr::Range));
    }
    Ok(if neg {
        (un as i64).wrapping_neg()
    } else {
        un as i64
    })
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
        hex = s[1].eq_ignore_ascii_case(&b'x');
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

/// Lines of a string as go's `csv.Reader.readLine` reads them.
struct CsvLines<'a> {
    rest: &'a [u8],
    num_line: usize,
}

impl<'a> CsvLines<'a> {
    /// The next line (`\r\n` as `\n`, a last `\r` dropped) and whether the
    /// input had ended (`io.EOF` with nothing read).
    fn read_line(&mut self) -> (Vec<u8>, bool) {
        let (mut line, eof) = match self.rest.iter().position(|&b| b == b'\n') {
            Some(i) => {
                let l = self.rest[..=i].to_vec();
                self.rest = &self.rest[i + 1..];
                (l, false)
            }
            None => {
                let l = self.rest.to_vec();
                self.rest = &[];
                let empty = l.is_empty();
                (l, empty)
            }
        };
        if !eof && !line.ends_with(b"\n") && line.last() == Some(&b'\r') {
            line.pop();
        }
        self.num_line += 1;
        let n = line.len();
        if n >= 2 && line[n - 2] == b'\r' && line[n - 1] == b'\n' {
            line[n - 2] = b'\n';
            line.pop();
        }
        (line, eof)
    }
}

fn length_nl(b: &[u8]) -> usize {
    usize::from(b.last() == Some(&b'\n'))
}

/// pflag's `readAsCSV`: go's `csv.NewReader(strings.NewReader(val)).Read()`
/// (comma `,`, no lazy quotes), the values of one `StringSlice` flag.
fn read_as_csv(val: &str) -> Result<Vec<String>, String> {
    const BARE: &str = "bare \" in non-quoted-field";
    const QUOTE: &str = "extraneous or missing \" in quoted-field";
    if val.is_empty() {
        return Ok(Vec::new());
    }
    let mut r = CsvLines {
        rest: val.as_bytes(),
        num_line: 0,
    };
    let mut line;
    loop {
        let (l, eof) = r.read_line();
        if eof {
            return Err("EOF".to_string());
        }
        line = l;
        if line.len() == length_nl(&line) {
            continue;
        }
        break;
    }
    let rec_line = r.num_line;
    let perr = |line_no: usize, col: usize, what: &str| {
        if rec_line != line_no {
            format!(
                "record on line {rec_line}; parse error on line {line_no}, column {col}: {what}"
            )
        } else {
            format!("parse error on line {line_no}, column {col}: {what}")
        }
    };
    let mut fields: Vec<Vec<u8>> = Vec::new();
    let (mut pos_line, mut pos_col) = (r.num_line, 1usize);
    let mut line: &[u8] = &line;
    let mut owned: Vec<u8>;
    'field: loop {
        if line.first() != Some(&b'"') {
            let i = line.iter().position(|&b| b == b',');
            let field = match i {
                Some(i) => &line[..i],
                None => &line[..line.len() - length_nl(line)],
            };
            if let Some(j) = field.iter().position(|&b| b == b'"') {
                return Err(perr(r.num_line, pos_col + j, BARE));
            }
            fields.push(field.to_vec());
            match i {
                Some(i) => {
                    line = &line[i + 1..];
                    pos_col += i + 1;
                    continue 'field;
                }
                None => break 'field,
            }
        }
        let mut field = Vec::new();
        line = &line[1..];
        pos_col += 1;
        loop {
            if let Some(i) = line.iter().position(|&b| b == b'"') {
                field.extend_from_slice(&line[..i]);
                line = &line[i + 1..];
                pos_col += i + 1;
                match line.first() {
                    Some(b'"') => {
                        field.push(b'"');
                        line = &line[1..];
                        pos_col += 1;
                    }
                    Some(b',') => {
                        line = &line[1..];
                        pos_col += 1;
                        fields.push(field);
                        continue 'field;
                    }
                    _ if length_nl(line) == line.len() => {
                        fields.push(field);
                        break 'field;
                    }
                    _ => return Err(perr(r.num_line, pos_col - 1, QUOTE)),
                }
            } else if !line.is_empty() {
                field.extend_from_slice(line);
                pos_col += line.len();
                let (l, _) = r.read_line();
                owned = l;
                line = &owned;
                if !line.is_empty() {
                    pos_line += 1;
                    pos_col = 1;
                }
            } else {
                return Err(perr(pos_line, pos_col, QUOTE));
            }
        }
    }
    Ok(fields
        .into_iter()
        .map(|f| String::from_utf8_lossy(&f).into_owned())
        .collect())
}

// ---- pflag's parse --------------------------------------------------------------

/// A flag value as go parsed it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Val {
    Bool(bool),
    Str(String),
    Uint(u64),
    Int(i64),
    /// The values of one `StringSlice` occurrence.
    Slice(Vec<String>),
}

/// What the found command's flag parsing left.
struct Parsed {
    /// `Flags().Args()`.
    positional: Vec<String>,
    /// Every flag set, in command-line order, with its value.
    sets: Vec<(&'static Flag, Val)>,
    help: bool,
}

impl Parsed {
    /// pflag's `FlagSet.Set`.
    fn set(&mut self, flag: &'static Flag, value: &str) -> Result<(), String> {
        let checked = match flag.kind {
            Kind::Bool => parse_bool(value).map(Val::Bool),
            Kind::Str | Kind::StrArray | Kind::Other => Ok(Val::Str(value.to_string())),
            Kind::StrSlice => read_as_csv(value).map(Val::Slice),
            Kind::Uint(bits) => parse_uint(value, bits).map(Val::Uint),
            Kind::Int(bits) => parse_int(value, bits).map(Val::Int),
        };
        let v = match checked {
            Ok(v) => v,
            Err(e) => {
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
        };
        if flag.long == "help" {
            self.help = v == Val::Bool(true);
        }
        self.sets.push((flag, v));
        Ok(())
    }

    fn changed(&self, long: &str) -> bool {
        self.sets.iter().any(|(f, _)| f.long == long)
    }
}

/// pflag's `FlagSet.Parse` (interspersed, `ContinueOnError`).
fn parse(args: &[&str], flags: &[&'static Flag]) -> Result<Parsed, String> {
    let mut p = Parsed {
        positional: Vec::new(),
        sets: Vec::new(),
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
            let value = match (inline, &flag.no_opt) {
                (Some(v), _) => v,
                (None, Some(d)) => d.as_str(),
                (None, None) if i < args.len() => {
                    i += 1;
                    args[i - 1]
                }
                (None, None) => return Err(format!("flag needs an argument: {s}")),
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
            } else if let Some(d) = &flag.no_opt {
                value = d.clone();
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
fn validate_args(path: &str, rule: ArgsRule, args: &[String]) -> Result<(), String> {
    let n = args.len();
    match rule {
        ArgsRule::Arbitrary => Ok(()),
        // `node catchup`'s `catchpointCmdArgument` (`cmd/goal/node.go`).
        ArgsRule::Custom if path == "node catchup" => {
            crate::cmd::node::validate_catchpoint_args(args).map(drop)
        }
        ArgsRule::Custom => Ok(()),
        ArgsRule::No if n > 0 => Err(format!(
            "unknown command {} for {}",
            go_quote(&args[0]),
            go_quote(&command_path(path))
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
fn validate_required(flags: &[&'static Flag], parsed: &Parsed) -> Result<(), String> {
    let mut missing: Vec<&str> = flags
        .iter()
        .filter(|f| f.required && !parsed.changed(&f.long))
        .map(|f| f.long.as_str())
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

// ---- the command line for clap ------------------------------------------------

/// How goal-rust's clap command `path` takes the flag `long`: clap's own
/// long name for it and whether it is a switch (`SetTrue` / `SetFalse`),
/// looked up in the command and the global flags of its parents.
fn clap_arg(path: &str, long: &str) -> Option<(String, Option<bool>)> {
    let mut chain = vec![<crate::Cli as clap::CommandFactory>::command()];
    for name in path.split(' ').filter(|n| !n.is_empty()) {
        let next = chain.last()?.find_subcommand(name)?.clone();
        chain.push(next);
    }
    let deepest = chain.len() - 1;
    for (level, c) in chain.iter().enumerate().rev() {
        let found = c.get_arguments().find(|a| {
            !a.is_positional()
                && (level == deepest || a.is_global_set())
                && (a.get_long() == Some(long)
                    || a.get_all_aliases().is_some_and(|al| al.contains(&long)))
        });
        if let Some(a) = found {
            // A switch takes no value, unless it is declared to (`-o=false`).
            let takes_value = a.get_num_args().is_some_and(|r| r.takes_values());
            let switch = match a.get_action() {
                clap::ArgAction::SetTrue if !takes_value => Some(true),
                clap::ArgAction::SetFalse if !takes_value => Some(false),
                _ => None,
            };
            return Some((a.get_long().unwrap_or(long).to_string(), switch));
        }
    }
    None
}

/// Flags go's command accepts (inherited from its parent) but never reads,
/// which goal-rust's clap command does not declare: cobra parses them and
/// clap gets nothing.
///
/// - `account`'s persistent `-w/--wallet` is read only by `new`, `delete`,
///   `list`, `import`, `export`, `importrootkey`, `changeonlinestatus`,
///   `marknonparticipating`, `renewpartkey`, `renewallpartkeys` and
///   `multisig new/delete/info` (`cmd/goal/account.go`).
/// - `app`'s persistent transaction inputs (`--app-arg`, the reference
///   flags, `--access`, `--empty-refs`) are read through `getAppInputs` by
///   `create`, `update`, `optin`, `closeout`, `clear`, `call`, `delete` and
///   `method`, its program files through `mustParseProgArgs` by `create`,
///   `update` and `method`, and `--reject-version` by all of those but
///   `create` (`cmd/goal/application.go`); `app box`'s persistent
///   `--app-id` by `box info` and `box list` (`cmd/goal/box.go`).
const UNREAD: &[(&str, &[&str])] = &[
    ("account", &["wallet"]),
    ("account addpartkey", &["wallet"]),
    ("account assetdetails", &["wallet"]),
    ("account balance", &["wallet"]),
    ("account deletepartkey", &["wallet"]),
    ("account dump", &["wallet"]),
    ("account info", &["wallet"]),
    ("account installpartkey", &["wallet"]),
    ("account listpartkeys", &["wallet"]),
    ("account multisig", &["wallet"]),
    ("account partkeyinfo", &["wallet"]),
    ("account rename", &["wallet"]),
    ("account rewards", &["wallet"]),
    ("app", APP_INPUTS),
    ("app box", APP_BOX_GROUP),
    ("app box info", APP_INPUTS),
    ("app box list", APP_INPUTS),
    ("app info", APP_INPUTS),
    // `app read`'s own `--local` (a bool) shadows the inherited one.
    ("app read", APP_INPUTS_BUT_LOCAL),
    ("app call", APP_PROGRAMS),
    ("app clear", APP_PROGRAMS),
    ("app closeout", APP_PROGRAMS),
    ("app delete", APP_PROGRAMS),
    ("app optin", APP_PROGRAMS),
    ("app create", &["reject-version"]),
];

/// `app`'s persistent flags but `-w/--wallet`.
const APP_INPUTS: &[&str] = &[
    "access",
    "app-account",
    "app-arg",
    "approval-prog",
    "approval-prog-raw",
    "box",
    "clear-prog",
    "clear-prog-raw",
    "empty-refs",
    "foreign-app",
    "foreign-asset",
    "holding",
    "local",
    "reject-version",
];

const APP_INPUTS_BUT_LOCAL: &[&str] = &[
    "access",
    "app-account",
    "app-arg",
    "approval-prog",
    "approval-prog-raw",
    "box",
    "clear-prog",
    "clear-prog-raw",
    "empty-refs",
    "foreign-app",
    "foreign-asset",
    "holding",
    "reject-version",
];

/// `app box` itself: `app`'s inputs and its own `--app-id`.
const APP_BOX_GROUP: &[&str] = &[
    "access",
    "app-account",
    "app-arg",
    "app-id",
    "approval-prog",
    "approval-prog-raw",
    "box",
    "clear-prog",
    "clear-prog-raw",
    "empty-refs",
    "foreign-app",
    "foreign-asset",
    "holding",
    "local",
    "reject-version",
];

const APP_PROGRAMS: &[&str] = &[
    "approval-prog",
    "approval-prog-raw",
    "clear-prog",
    "clear-prog-raw",
];

/// Whether go's command `path` never reads its flag `long` ([`UNREAD`]).
fn unread(path: &str, long: &str) -> bool {
    UNREAD
        .iter()
        .any(|(p, flags)| *p == path && flags.contains(&long))
}

fn val_text(v: &Val) -> Vec<String> {
    match v {
        Val::Bool(b) => vec![b.to_string()],
        Val::Str(s) => vec![s.clone()],
        Val::Uint(n) => vec![n.to_string()],
        Val::Int(n) => vec![n.to_string()],
        Val::Slice(v) => v.clone(),
    }
}

/// The command line clap parses for what cobra found: the command names,
/// each flag set (in the order first set; the last value of a scalar flag,
/// every value of an array one; `--help=false` dropped), then the
/// positional arguments, after `--` when one of them starts with `-`.
fn canonical(argv0: &str, cmd: &Cmd, parsed: &Parsed) -> Vec<String> {
    let mut out = vec![argv0.to_string()];
    out.extend(
        cmd.path
            .split(' ')
            .filter(|w| !w.is_empty())
            .map(str::to_string),
    );
    let mut order: Vec<&'static Flag> = Vec::new();
    for (f, _) in &parsed.sets {
        if !order.iter().any(|o| std::ptr::eq(*o, *f)) && f.long != "help" {
            order.push(f);
        }
    }
    for f in order {
        let values: Vec<&Val> = parsed
            .sets
            .iter()
            .filter(|(g, _)| std::ptr::eq(*g, f))
            .map(|(_, v)| v)
            .collect();
        let values: Vec<&Val> = match f.kind {
            Kind::StrArray | Kind::StrSlice => values,
            _ => values.last().copied().into_iter().collect(),
        };
        if unread(&cmd.path, &f.long) {
            continue;
        }
        match clap_arg(&cmd.path, &f.long) {
            Some((long, Some(on))) if f.kind == Kind::Bool => {
                if values.last().is_some_and(|v| **v == Val::Bool(on)) {
                    out.push(format!("--{long}"));
                }
            }
            Some((long, _)) => {
                for v in values {
                    out.extend(val_text(v).into_iter().map(|t| format!("--{long}={t}")));
                }
            }
            // A flag of go's that goal-rust's command lacks: clap's error.
            None => {
                for v in values {
                    out.extend(val_text(v).into_iter().map(|t| format!("--{}={t}", f.long)));
                }
            }
        }
    }
    if parsed
        .positional
        .iter()
        .any(|p| p.starts_with('-') && p.len() > 1)
    {
        out.push("--".to_string());
    }
    out.extend(parsed.positional.iter().cloned());
    out
}

/// cobra's `Find` from the root: the deepest command `args` (after the
/// program name, at the positions `idx`) name, and the positions left.
fn find(args: &[String], mut idx: Vec<usize>) -> (&'static Cmd, Vec<usize>) {
    let mut cmd = command("").expect("the root is in the table");
    loop {
        let flags = flags_of(cmd, false);
        let Some(&next) = strip_flags(args, &idx, &flags).first() else {
            break;
        };
        let Some(sub) = child(cmd, &args[next]) else {
            break;
        };
        idx = args_minus_first_x(args, &idx, &args[next], &flags);
        cmd = sub;
    }
    (cmd, idx)
}

/// goal's `helptest` (`runAllHelps`): `<path> -h` for every runnable
/// command, in cobra's (sorted) order. It runs before cobra's `Execute`
/// adds the `help` command, which is not listed.
fn help_test() -> String {
    let mut paths: Vec<&str> = tree()
        .iter()
        .filter(|c| c.runnable && c.path != "help")
        .map(|c| c.path.as_str())
        .collect();
    paths.sort_unstable();
    paths
        .iter()
        .map(|p| format!("{} -h\n", command_path(p)))
        .collect()
}

pub(crate) fn decide(args: &[String]) -> Outcome {
    // goal's `main`, before cobra.
    if args.len() == 3 && args[1] == "generate-docs" {
        return Outcome::Unchanged;
    }
    if args.len() == 2 && args[1] == "helptest" {
        return Outcome::Print(help_test());
    }
    let (cmd, idx) = find(args, (1..args.len()).collect());

    // execute: flags, help, `Args`, required flags.
    let flags = flags_of(cmd, true);
    let rest: Vec<&str> = idx.iter().map(|&k| args[k].as_str()).collect();
    let fail = |msg: String| Outcome::Fail {
        msg,
        usage_path: cmd.path.clone(),
    };
    let parsed = match parse(&rest, &flags) {
        Ok(p) => p,
        Err(msg) => return fail(msg),
    };
    if parsed.help || !cmd.runnable {
        return Outcome::Help(cmd.path.clone());
    }
    if let Err(msg) = validate_args(&cmd.path, cmd.args, &parsed.positional) {
        return fail(msg);
    }
    if let Err(msg) = validate_required(&flags, &parsed) {
        return fail(msg);
    }
    if cmd.path == "help" {
        // cobra's help command: `c.Root().Find(args)` and that command's
        // help (the root's for a name it does not know).
        let mut words = vec![args[0].clone()];
        words.extend(parsed.positional.iter().cloned());
        let (topic, _) = find(&words, (1..words.len()).collect());
        return Outcome::Help(topic.path.clone());
    }
    Outcome::Run(canonical(&args[0], cmd, &parsed))
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

    fn run(args: &[&str]) -> Outcome {
        let mut v = vec!["goal".to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        Outcome::Run(v)
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
        assert_eq!(
            d(&["clerk", "extra"]),
            fail(r#"unknown command "extra" for "goal clerk""#, "clerk")
        );
        // `-w` is not a `wallet` flag; `-f`'s value is not a command.
        assert_eq!(
            d(&["wallet", "-w", "x", "extra"]),
            fail("unknown shorthand flag: 'w' in -w", "wallet")
        );
        assert_eq!(
            d(&["account", "-f", "list"]),
            run(&["account", "--default=list"])
        );
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
        // The subcommand's own `-f`: a bool for `account new`, whose name
        // is then the positional `x`.
        assert_eq!(
            d(&["-d", "dd", "account", "-f", "x", "-w", "w", "new"]),
            run(&[
                "account",
                "new",
                "--datadir=dd",
                "--default",
                "--wallet=w",
                "x"
            ])
        );
        assert_eq!(
            d(&["account", "-f", "5", "changeonlinestatus", "-a", "A"]),
            run(&["account", "changeonlinestatus", "--fee=5", "--address=A"])
        );
        assert_eq!(
            d(&["account", "--default", "imp", "import"]),
            run(&["account", "import", "--default", "imp"])
        );
        assert_eq!(
            d(&["account", "-w", "w", "multisig", "info", "-a", "A"]),
            run(&["account", "multisig", "info", "--wallet=w", "--address=A"])
        );
        assert_eq!(
            d(&["account", "list", "--info"]),
            run(&["account", "list", "--info"])
        );
        assert_eq!(d(&["-v"]), run(&["--version"]));
        assert_eq!(d(&[]), run(&[]));
    }

    #[test]
    fn the_root_is_a_command_too() {
        assert_eq!(
            d(&["extra"]),
            fail(r#"unknown command "extra" for "goal""#, "")
        );
        assert_eq!(
            d(&["lsit", "-d", "x"]),
            fail(r#"unknown command "lsit" for "goal""#, "")
        );
        assert_eq!(d(&["--help"]), help(""));
        assert_eq!(d(&["-h", "clerk"]), help(""));
        assert_eq!(d(&["-z"]), fail("unknown shorthand flag: 'z' in -z", ""));
        assert_eq!(
            d(&["-d", "x", "-k", "y", "-v"]),
            run(&["--datadir=x", "--kmddir=y", "--version"])
        );
        assert_eq!(
            d(&["kmd", "extra"]),
            fail(r#"unknown command "extra" for "goal kmd""#, "kmd")
        );
        assert_eq!(d(&["version", "-v"]), run(&["version", "--verbose"]));
        // goal's `main` handles these two before cobra.
        assert_eq!(d(&["generate-docs", "x"]), Outcome::Unchanged);
        let Outcome::Print(text) = d(&["helptest"]) else {
            panic!("helptest");
        };
        assert!(text.starts_with("goal -h\ngoal account -h\n"), "{text}");
        assert!(!text.contains("goal help"), "{text}");
        assert!(text.ends_with("goal wallet rename -h\n"), "{text}");
        assert_eq!(
            d(&["helptest", "x"]),
            fail(r#"unknown command "helptest" for "goal""#, "")
        );
    }

    #[test]
    fn the_help_command_is_cobras() {
        assert_eq!(d(&["help"]), help(""));
        assert_eq!(d(&["help", "clerk", "send"]), help("clerk send"));
        assert_eq!(d(&["help", "clerk", "nosuch"]), help("clerk"));
        assert_eq!(d(&["help", "nosuch"]), help(""));
        assert_eq!(d(&["help", "help"]), help("help"));
        assert_eq!(d(&["help", "-h"]), help("help"));
        assert_eq!(d(&["-d", "x", "help", "app", "box"]), help("app box"));
        assert_eq!(
            d(&["help", "-z"]),
            fail("unknown shorthand flag: 'z' in -z", "help")
        );
        assert_eq!(d(&["help", "--", "-x"]), help(""));
    }

    #[test]
    fn the_canonical_command_line_holds_gos_values() {
        // go's numbers, the last value of a scalar flag, every one of an
        // array flag, a bool flag's `=false`, and `--` before a positional
        // that starts with `-`.
        assert_eq!(
            d(&[
                "clerk",
                "send",
                "-a",
                "0x10",
                "--fee=1_000",
                "--fee",
                "010",
                "-f",
                "F",
                "-t",
                "T",
                "-N",
                "--no-wait=false"
            ]),
            run(&[
                "clerk",
                "send",
                "--amount=16",
                "--fee=8",
                "--from=F",
                "--to=T"
            ])
        );
        assert_eq!(
            d(&[
                "-d",
                "a",
                "clerk",
                "-w",
                "w",
                "send",
                "--argb64",
                "x,y",
                "--argb64=z",
                "-a",
                "1",
                "-f",
                "F",
                "-t",
                "T",
                "-d",
                "b"
            ]),
            run(&[
                "clerk",
                "send",
                "--datadir=a",
                "--datadir=b",
                "--wallet=w",
                "--argb64=x",
                "--argb64=y",
                "--argb64=z",
                "--amount=1",
                "--from=F",
                "--to=T"
            ])
        );
        assert_eq!(
            d(&["clerk", "compile", "--", "-x.teal"]),
            run(&["clerk", "compile", "--", "-x.teal"])
        );
        assert_eq!(
            d(&["account", "changeonlinestatus", "-a", "A", "-o=false"]),
            run(&[
                "account",
                "changeonlinestatus",
                "--address=A",
                "--online=false"
            ])
        );
        assert_eq!(
            d(&["clerk", "tealsign", "--set-lsig-arg-idx", "-0x2"]),
            run(&["clerk", "tealsign", "--set-lsig-arg-idx=-2"])
        );
    }

    #[test]
    fn help_is_the_found_commands() {
        assert_eq!(d(&["account", "-h"]), help("account"));
        assert_eq!(d(&["wallet", "--help"]), help("wallet"));
        assert_eq!(d(&["clerk", "send", "-h"]), help("clerk send"));
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
        assert_eq!(
            d(&["account", "list", "--help=false"]),
            run(&["account", "list"])
        );
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
            run(&["account", "changeonlinestatus", "--lastvalid=10"])
        );
        assert_eq!(
            d(&["account", "renewallpartkeys", "--roundLastValid=-1"]),
            fail(
                r#"invalid argument "-1" for "--roundLastValid" flag: strconv.ParseUint: parsing "-1": invalid syntax"#,
                "account renewallpartkeys"
            )
        );
        assert_eq!(
            d(&[
                "clerk",
                "simulate",
                "--extra-opcode-budget",
                "9223372036854775808"
            ]),
            fail(
                r#"invalid argument "9223372036854775808" for "--extra-opcode-budget" flag: strconv.ParseInt: parsing "9223372036854775808": value out of range"#,
                "clerk simulate"
            )
        );
        assert_eq!(
            d(&["clerk", "send", "--argb64", "a\"b"]),
            fail(
                r#"invalid argument "a\"b" for "--argb64" flag: parse error on line 1, column 2: bare " in non-quoted-field"#,
                "clerk send"
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
        assert_eq!(
            d(&["clerk", "send"]),
            fail(r#"required flag(s) "amount", "to" not set"#, "clerk send")
        );
        assert_eq!(d(&["account", "dump"]), run(&["account", "dump"]));
        assert_eq!(
            d(&["account", "rewards", "-a", "A"]),
            run(&["account", "rewards", "--address=A"])
        );
    }

    #[test]
    fn flags_go_does_not_define_are_cobras_unknown_flag() {
        // goal-rust once had its own `--password`, `wallet new -w/--driver`,
        // `changeonlinestatus --offline` and `renew*partkey(s) --register`
        // (issue #2407): go's goal knows none of them.
        assert_eq!(
            d(&["wallet", "new", "w", "-w", "pw", "--no-display-seed"]),
            fail("unknown shorthand flag: 'w' in -w", "wallet new")
        );
        assert_eq!(
            d(&["account", "import", "x", "-m", "m", "--password", "pw"]),
            fail("unknown flag: --password", "account import")
        );
        assert_eq!(
            d(&["account", "changeonlinestatus", "-a", "A", "--offline"]),
            fail("unknown flag: --offline", "account changeonlinestatus")
        );
        assert_eq!(
            d(&["wallet", "new", "w", "-f", "x"]),
            fail("unknown shorthand flag: 'f' in -f", "wallet new")
        );
        assert_eq!(
            d(&["clerk", "send", "-a", "1", "-t", "T", "--password", "pw"]),
            fail("unknown flag: --password", "clerk send")
        );
    }

    /// The goal-rust clap command of every go command (cobra's `help`
    /// command has none: the preflight answers it).
    fn clap_commands() -> Vec<(&'static Cmd, clap::Command)> {
        let mut out = Vec::new();
        for cmd in tree() {
            let mut c = <crate::Cli as clap::CommandFactory>::command();
            let mut found = cmd.path != "help";
            for name in cmd.path.split(' ').filter(|n| !n.is_empty()) {
                match c.find_subcommand(name) {
                    Some(sub) => c = sub.clone(),
                    None => found = false,
                }
            }
            if found {
                out.push((cmd, c));
            }
        }
        out
    }

    /// Every flag goal-rust's clap command declares is one of go's: nothing
    /// cobra rejects as unknown is ever needed by goal-rust.
    #[test]
    fn clap_declares_no_flag_beyond_gos() {
        for (cmd, c) in clap_commands() {
            let go = flags_of(cmd, true);
            for a in c.get_arguments().filter(|a| !a.is_positional()) {
                let long = a.get_long().unwrap_or("");
                assert!(
                    go.iter().any(|f| f.long == long),
                    "goal {}: --{long} is not one of go's flags",
                    cmd.path
                );
            }
        }
    }

    /// Every flag of go's in the trees parsed here reaches goal-rust's clap
    /// command, a bool flag as a switch only where go's default is false
    /// (else `--x=false` could not be told apart).
    #[test]
    fn clap_takes_every_flag_of_gos() {
        // Flags go's command reads that goal-rust's does not have yet.
        const GAPS: &[&str] = &[
            // issue #2513
            "goal app method --app-arg",
            // issue #2512
            "goal node clone --noledger",
            "goal node clone --targetdir",
            "goal node create --api",
            "goal node create --archival",
            "goal node create --destination",
            "goal node create --full-config",
            "goal node create --hosted",
            "goal node create --network",
            "goal node create --relay",
        ];
        let mut missing = Vec::new();
        for (cmd, _) in clap_commands() {
            for f in flags_of(cmd, false) {
                if unread(&cmd.path, &f.long) {
                    assert!(
                        clap_arg(&cmd.path, &f.long).is_none(),
                        "goal-rust's goal {} declares --{} now: drop it from UNREAD",
                        cmd.path,
                        f.long
                    );
                    continue;
                }
                match clap_arg(&cmd.path, &f.long) {
                    None => missing.push(format!("goal {} --{}", cmd.path, f.long)),
                    Some((_, Some(_))) => assert!(
                        f.kind == Kind::Bool && f.def == "false",
                        "goal {}: --{} ({}, default {:?}) is a clap switch",
                        cmd.path,
                        f.long,
                        f.ty,
                        f.def
                    ),
                    Some(_) => {}
                }
            }
        }
        assert_eq!(missing, GAPS, "go's flags not in goal-rust's clap");
    }

    /// What this port assumes of go's tree: every flag type parsed, no
    /// command aliased, hidden, deprecated or parsing flags its own way, no
    /// flag hidden or deprecated, and the `Args` rules a known shape (only
    /// `node catchup`'s is goal's own).
    #[test]
    fn the_tree_is_what_this_port_parses() {
        let file: TreeFile = serde_json::from_str(include_str!("cobra_tree.json")).unwrap();
        for d in &file.commands {
            assert!(
                !d.hidden
                    && d.deprecated.is_empty()
                    && !d.disable_flag_parsing
                    && !d.traverse_children
                    && !d.silence_usage
                    && !d.silence_errors
                    && d.aliases.is_empty(),
                "{}",
                d.path
            );
            for f in d.local.iter().chain(&d.persistent).chain([&d.help_flag]) {
                assert!(
                    Kind::of(&f.ty) != Kind::Other
                        && !f.hidden
                        && f.deprecated.is_empty()
                        && f.shorthand_deprecated.is_empty()
                        && f.shorthand.len() <= 1
                        && (f.no_opt_def_val.is_empty() || f.ty == "bool"),
                    "{} --{}",
                    d.path,
                    f.name
                );
            }
        }
        // The root's `Args` is set, so cobra's `legacyArgs` (and its
        // suggestions) never runs.
        assert!(file
            .commands
            .iter()
            .any(|d| d.path.is_empty() && !d.args_nil));
        let custom: Vec<&str> = tree()
            .iter()
            .filter(|c| c.args == ArgsRule::Custom)
            .map(|c| c.path.as_str())
            .collect();
        assert_eq!(custom, ["node catchup"]);
        // The port of its validator gives go's errors for the probe's
        // arguments.
        let catchup = file
            .commands
            .iter()
            .find(|d| d.path == "node catchup")
            .unwrap();
        let args: Vec<String> = (1..=6).map(|i| format!("a{i}")).collect();
        for (n, want) in catchup.args_probe.as_ref().unwrap().iter().enumerate() {
            assert_eq!(
                validate_args("node catchup", ArgsRule::Custom, &args[..n]).err(),
                *want,
                "{n} arguments"
            );
        }
        assert_eq!(command("wallet new").unwrap().args, ArgsRule::Exact(1));
        assert_eq!(command("account new").unwrap().args, ArgsRule::Range(0, 1));
        assert_eq!(
            command("account multisig new").unwrap().args,
            ArgsRule::Min(1)
        );
        assert_eq!(command("clerk compile").unwrap().args, ArgsRule::Arbitrary);
        assert_eq!(command("clerk send").unwrap().args, ArgsRule::No);
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
        assert_eq!(ok("4294967295", 32), Some(u64::from(u32::MAX)));
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
            ("4294967296", 32),
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
    fn parse_int_matches_strconv() {
        assert_eq!(parse_int("-1", 64), Ok(-1));
        assert_eq!(parse_int("+0x10", 64), Ok(16));
        assert_eq!(parse_int("-9223372036854775808", 64), Ok(i64::MIN));
        assert_eq!(parse_int("9223372036854775807", 64), Ok(i64::MAX));
        for (s, why) in [
            ("9223372036854775808", "value out of range"),
            ("-9223372036854775809", "value out of range"),
            ("99999999999999999999", "value out of range"),
            ("-", "invalid syntax"),
            ("", "invalid syntax"),
            ("--1", "invalid syntax"),
            ("1.5", "invalid syntax"),
            ("-_1", "invalid syntax"),
        ] {
            assert_eq!(
                parse_int(s, 64),
                Err(format!("strconv.ParseInt: parsing {}: {why}", go_quote(s))),
                "{s}"
            );
        }
    }

    #[test]
    fn read_as_csv_matches_gos_reader() {
        let ok = |s: &str| read_as_csv(s).unwrap();
        assert_eq!(ok(""), Vec::<String>::new());
        assert_eq!(ok("a,b"), ["a", "b"]);
        assert_eq!(ok("a,"), ["a", ""]);
        assert_eq!(ok(r#""a,b",c"#), ["a,b", "c"]);
        assert_eq!(ok(r#""a""b""#), [r#"a"b"#]);
        assert_eq!(ok("a\nb"), ["a"]);
        assert_eq!(ok("\n\na\r\n"), ["a"]);
        assert_eq!(ok("a\r"), ["a"]);
        assert_eq!(ok("\"a\nb\""), ["a\nb"]);
        assert_eq!(read_as_csv("\n").unwrap_err(), "EOF");
        assert_eq!(
            read_as_csv("ab\"c").unwrap_err(),
            "parse error on line 1, column 3: bare \" in non-quoted-field"
        );
        assert_eq!(
            read_as_csv("x,\"a\"b").unwrap_err(),
            "parse error on line 1, column 5: extraneous or missing \" in quoted-field"
        );
        assert_eq!(
            read_as_csv("\"abc").unwrap_err(),
            "parse error on line 1, column 5: extraneous or missing \" in quoted-field"
        );
        assert_eq!(
            read_as_csv("\"a\nbc").unwrap_err(),
            "record on line 1; parse error on line 2, column 3: extraneous or missing \" in quoted-field"
        );
    }

    #[test]
    fn go_quotes() {
        assert_eq!(go_quote_byte(b'f'), "'f'");
        assert_eq!(go_quote_byte(b'\''), r"'\''");
        assert_eq!(go_quote_byte(1), r"'\x01'");
        assert_eq!(go_quote_byte(0xc3), "'Ã'");
        assert_eq!(go_quote_byte(0x85), r"'\u0085'");
        assert_eq!(go_quote("a\"b\n"), r#""a\"b\n""#);
        // strconv.IsPrint: every rune go does not print is escaped, a
        // printable one (letters, marks, numbers, punctuation, symbols,
        // ASCII space) is not.
        assert_eq!(go_quote("\u{200b}"), "\"\\u200b\"");
        assert_eq!(go_quote("\u{2028}\u{2029}"), "\"\\u2028\\u2029\"");
        assert_eq!(go_quote("\u{feff}"), "\"\\ufeff\"");
        assert_eq!(go_quote("\u{a0}\u{ad}\u{85}"), "\"\\u00a0\\u00ad\\u0085\"");
        assert_eq!(go_quote("\u{e000}"), "\"\\ue000\"");
        assert_eq!(
            go_quote("\u{e0001}\u{10ffff}"),
            "\"\\U000e0001\\U0010ffff\""
        );
        assert_eq!(go_quote("\u{3000}"), "\"\\u3000\"");
        assert_eq!(go_quote("é日本😀 ~"), "\"é日本😀 ~\"");
        assert_eq!(go_quote("\u{301}"), "\"\u{301}\"");
        assert!(is_print(' ') && !is_print('\u{2000}') && !is_print('\u{10fffd}'));
    }

    /// The help of every command is its `Long` (or `Short`) text above its
    /// usage, as cobra's template prints it (`network pregen`'s help
    /// function hides the `rootdir` flag first).
    #[test]
    fn help_is_the_text_above_the_usage() {
        for c in tree() {
            if c.path == "network pregen" {
                assert!(!c.help_text.contains("--rootdir"));
                assert!(c.usage.contains("--rootdir"));
                continue;
            }
            assert!(
                c.help_text.ends_with(&format!("\n\n{}", c.usage)),
                "{}",
                c.path
            );
            assert!(c.usage.starts_with("Usage:\n"), "{}", c.path);
        }
    }
}
