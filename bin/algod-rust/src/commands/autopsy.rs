//! `autopsy` subcommand — read cadaver binary trace logs produced by the
//! agreement service and render a human-readable round-by-round timeline.
//!
//! Mirrors go-algorand v4.5.1-stable `agreement/autopsy.go` (which streams
//! `.cdv.archive` first, then the active `.cdv`, into a per-run analyzer).
//! This Rust version reuses `algo_agreement::trace::CadaverReader` so the
//! reader/writer pair stays in sync — see TASK-63 for the writer.
//!
//! The acceptance criteria for TASK-64 are:
//!
//! 1. Reads a cadaver file produced by the cadaver writer.
//! 2. Outputs round/period/step timeline in human-readable form, with an
//!    optional `--json` flag for machine-readable output.
//! 3. Smoke test: run autopsy against a fixture cadaver and verify the
//!    rendered output. (See `mod tests` below.)

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use algo_agreement::trace::{CadaverReader, CadaverRecord, PlayerSnapshot};
use anyhow::Context;
use serde::Serialize;

/// Output format for the rendered timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutopsyFormat {
    /// Human-readable plain-text timeline (default).
    Text,
    /// JSON array of records, suitable for scripting / further analysis.
    Json,
}

/// Run the `autopsy` command.
///
/// `cadaver_path` may point at the active `.cdv` file; if a sibling
/// `.cdv.archive` exists it is read first (matching Go's
/// `PrepareAutopsy` precedence). When `cadaver_path` ends in
/// `.cdv.archive` we read just that file (assumes the user explicitly
/// asked for the archive).
pub fn run(cadaver_path: &Path, format: AutopsyFormat) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    render_to(cadaver_path, format, &mut out)
}

/// Same as [`run`] but writes to a caller-provided sink. Exposed so the
/// smoke tests can capture the rendered output without going through
/// `stdout`.
pub fn render_to(
    cadaver_path: &Path,
    format: AutopsyFormat,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let inputs = resolve_inputs(cadaver_path)?;
    if inputs.is_empty() {
        anyhow::bail!("no cadaver files found for path {}", cadaver_path.display(),);
    }
    let reader = open_chained_reader(&inputs)?;
    let cadaver = CadaverReader::new(reader);
    let records = cadaver
        .read_all()
        .with_context(|| format!("reading cadaver records from {inputs:?}"))?;

    match format {
        AutopsyFormat::Text => write_text(&records, out)?,
        AutopsyFormat::Json => write_json(&records, out)?,
    }
    Ok(())
}

/// Resolve a user-supplied path into the ordered list of files to
/// stream. If `<base>.cdv.archive` exists alongside the requested
/// active `.cdv`, it precedes the active file. Mirrors Go's
/// `PrepareAutopsy` behavior.
fn resolve_inputs(cadaver_path: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let path_str = cadaver_path.to_string_lossy();
    if path_str.ends_with(".cdv.archive") {
        // Explicitly an archive file — read just that.
        if !cadaver_path.exists() {
            anyhow::bail!("cadaver archive not found: {}", cadaver_path.display());
        }
        return Ok(vec![cadaver_path.to_path_buf()]);
    }

    let mut inputs = Vec::new();
    let archive = PathBuf::from(format!("{path_str}.archive"));
    if archive.exists() {
        inputs.push(archive);
    }
    if cadaver_path.exists() {
        inputs.push(cadaver_path.to_path_buf());
    }
    Ok(inputs)
}

/// Chain readers for every file in `inputs` so a single pass through
/// `CadaverReader` consumes archive + active back-to-back.
fn open_chained_reader(inputs: &[PathBuf]) -> anyhow::Result<Box<dyn Read>> {
    let mut readers: Vec<Box<dyn Read>> = Vec::with_capacity(inputs.len());
    for path in inputs {
        let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        readers.push(Box::new(BufReader::new(f)));
    }
    Ok(readers
        .into_iter()
        .reduce(|acc, next| Box::new(acc.chain(next)))
        .expect("inputs is non-empty"))
}

// ---------------------------------------------------------------------------
// Text renderer
// ---------------------------------------------------------------------------

fn write_text(records: &[CadaverRecord], out: &mut dyn Write) -> io::Result<()> {
    let mut current_scope: Option<PlayerSnapshot> = None;
    let mut run_index: u32 = 0;

    for rec in records {
        match rec {
            CadaverRecord::Meta(meta) => {
                if run_index > 0 {
                    writeln!(out)?;
                }
                writeln!(
                    out,
                    "== run #{} (num_opened={}, version={}) ==",
                    run_index, meta.num_opened, meta.version_commit_hash,
                )?;
                run_index += 1;
                current_scope = None;
            }
            CadaverRecord::Player(scope) => {
                writeln!(
                    out,
                    "[ R{} P{} S{} ] player",
                    scope.round.0, scope.period.0, scope.step,
                )?;
                current_scope = Some(*scope);
            }
            CadaverRecord::Event(payload) => {
                writeln!(
                    out,
                    "{} event: {} bytes",
                    fmt_scope(current_scope.as_ref()),
                    payload.len(),
                )?;
            }
            CadaverRecord::Action(payload) => {
                writeln!(
                    out,
                    "{} action: {} bytes",
                    fmt_scope(current_scope.as_ref()),
                    payload.len(),
                )?;
            }
            CadaverRecord::EndOfSequence => {
                writeln!(out, "-- end of sequence --")?;
                current_scope = None;
            }
        }
    }
    Ok(())
}

fn fmt_scope(scope: Option<&PlayerSnapshot>) -> String {
    match scope {
        Some(s) => format!("[ R{} P{} S{} ]", s.round.0, s.period.0, s.step),
        None => "[      ]".to_string(),
    }
}

// ---------------------------------------------------------------------------
// JSON renderer
// ---------------------------------------------------------------------------

/// Wire shape used by `--json`. Kept lean: events/actions report their
/// payload byte length rather than the raw bytes (autopsy is a triage
/// tool, not a deserializer for arbitrary user types).
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JsonRecord<'a> {
    Meta {
        num_opened: u32,
        version_commit_hash: &'a str,
    },
    Player {
        round: u64,
        period: u64,
        step: u64,
    },
    Event {
        round: Option<u64>,
        period: Option<u64>,
        step: Option<u64>,
        payload_bytes: usize,
    },
    Action {
        round: Option<u64>,
        period: Option<u64>,
        step: Option<u64>,
        payload_bytes: usize,
    },
    EndOfSequence,
}

fn write_json(records: &[CadaverRecord], out: &mut dyn Write) -> io::Result<()> {
    let mut current_scope: Option<PlayerSnapshot> = None;
    let mapped: Vec<JsonRecord> = records
        .iter()
        .map(|rec| match rec {
            CadaverRecord::Meta(meta) => {
                current_scope = None;
                JsonRecord::Meta {
                    num_opened: meta.num_opened,
                    version_commit_hash: &meta.version_commit_hash,
                }
            }
            CadaverRecord::Player(scope) => {
                current_scope = Some(*scope);
                JsonRecord::Player {
                    round: scope.round.0,
                    period: scope.period.0,
                    step: scope.step,
                }
            }
            CadaverRecord::Event(payload) => JsonRecord::Event {
                round: current_scope.map(|s| s.round.0),
                period: current_scope.map(|s| s.period.0),
                step: current_scope.map(|s| s.step),
                payload_bytes: payload.len(),
            },
            CadaverRecord::Action(payload) => JsonRecord::Action {
                round: current_scope.map(|s| s.round.0),
                period: current_scope.map(|s| s.period.0),
                step: current_scope.map(|s| s.step),
                payload_bytes: payload.len(),
            },
            CadaverRecord::EndOfSequence => {
                current_scope = None;
                JsonRecord::EndOfSequence
            }
        })
        .collect();

    serde_json::to_writer_pretty(&mut *out, &mapped)
        .map_err(|e| io::Error::other(e.to_string()))?;
    writeln!(out)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use algo_agreement::trace::{Cadaver, CadaverConfig, CADAVER_SIZE_MINIMUM};
    use algo_agreement::Period;
    use algo_types::Round;
    use serde::{Deserialize, Serialize};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Serialize, Deserialize)]
    struct FixtureEvent {
        kind: String,
        value: i64,
    }

    fn unique_dir(label: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("algo-autopsy-test-{label}-{pid}-{nanos}"));
        fs::create_dir_all(&dir).expect("create tmp dir");
        dir
    }

    /// Write a small fixture cadaver: Meta + two scopes, each with an
    /// event and an action. Returns the path and the temp dir for cleanup.
    fn write_fixture(label: &str) -> (PathBuf, PathBuf) {
        let dir = unique_dir(label);
        let cfg = CadaverConfig {
            base_directory: dir.clone(),
            base_filename: "node".into(),
            file_size_target: CADAVER_SIZE_MINIMUM,
            version_commit_hash: "fixture-commit".into(),
        };
        let active = cfg.active_path();
        {
            let mut cad = Cadaver::open(cfg).expect("open cadaver");
            let scope1 = PlayerSnapshot {
                round: Round(7),
                period: Period(0),
                step: 0,
            };
            let scope2 = PlayerSnapshot {
                round: Round(7),
                period: Period(1),
                step: 3,
            };
            cad.trace_event(
                scope1,
                &FixtureEvent {
                    kind: "vote".into(),
                    value: 1,
                },
            )
            .expect("write event 1");
            cad.trace_actions(
                scope1,
                &[FixtureEvent {
                    kind: "broadcast".into(),
                    value: 0,
                }],
            )
            .expect("write actions");
            cad.trace_event(
                scope2,
                &FixtureEvent {
                    kind: "cert".into(),
                    value: 2,
                },
            )
            .expect("write event 2");
        }
        (active, dir)
    }

    /// Acceptance-criterion smoke test: render a fixture cadaver and
    /// diff the plain-text output against a golden string. The exact
    /// payload byte counts depend on rmp_serde's encoding of
    /// `FixtureEvent` and the cadaver Meta (which include the version
    /// hash), so we assert on the structural skeleton (run header,
    /// player markers, expected entry count + types) rather than
    /// byte-counted lines that would be brittle to codec changes.
    #[test]
    fn render_text_against_fixture_cadaver() {
        let (cdv_path, dir) = write_fixture("text");

        let mut sink: Vec<u8> = Vec::new();
        render_to(&cdv_path, AutopsyFormat::Text, &mut sink).expect("render text");
        let output = String::from_utf8(sink).expect("utf-8 output");

        // Run header is present with the fixture's commit hash.
        assert!(
            output.contains("== run #0"),
            "missing run header in:\n{output}",
        );
        assert!(
            output.contains("version=fixture-commit"),
            "missing commit hash in:\n{output}",
        );

        // Both scopes show up as Player lines in the right order.
        let r7p0 = output.find("[ R7 P0 S0 ] player").expect("scope1 player");
        let r7p1 = output.find("[ R7 P1 S3 ] player").expect("scope2 player");
        assert!(r7p0 < r7p1, "scope1 must precede scope2 in:\n{output}");

        // Event + action lines reference the correct scope. Two events,
        // one action: that ordering matches the fixture write sequence.
        let event_lines: Vec<&str> = output.lines().filter(|l| l.contains("event:")).collect();
        assert_eq!(event_lines.len(), 2, "events: {event_lines:?}");
        assert!(event_lines[0].starts_with("[ R7 P0 S0 ]"));
        assert!(event_lines[1].starts_with("[ R7 P1 S3 ]"));

        let action_lines: Vec<&str> = output.lines().filter(|l| l.contains("action:")).collect();
        assert_eq!(action_lines.len(), 1, "actions: {action_lines:?}");
        assert!(action_lines[0].starts_with("[ R7 P0 S0 ]"));

        let _ = fs::remove_dir_all(&dir);
    }

    /// JSON output is parseable, structurally sound, and carries the
    /// scope info on every event/action.
    #[test]
    fn render_json_against_fixture_cadaver() {
        let (cdv_path, dir) = write_fixture("json");

        let mut sink: Vec<u8> = Vec::new();
        render_to(&cdv_path, AutopsyFormat::Json, &mut sink).expect("render json");

        let value: serde_json::Value = serde_json::from_slice(&sink).expect("output is valid JSON");
        let arr = value.as_array().expect("top-level array");

        // Expect: Meta, Player(scope1), Event, Action, Player(scope2), Event.
        assert_eq!(arr.len(), 6, "unexpected record count, got: {value:#?}");
        assert_eq!(arr[0]["kind"], "meta");
        assert_eq!(arr[0]["version_commit_hash"], "fixture-commit");
        assert_eq!(arr[1]["kind"], "player");
        assert_eq!(arr[1]["round"], 7);
        assert_eq!(arr[1]["period"], 0);
        assert_eq!(arr[2]["kind"], "event");
        assert_eq!(arr[2]["round"], 7);
        assert_eq!(arr[2]["period"], 0);
        assert_eq!(arr[3]["kind"], "action");
        assert_eq!(arr[3]["round"], 7);
        assert_eq!(arr[4]["kind"], "player");
        assert_eq!(arr[4]["period"], 1);
        assert_eq!(arr[4]["step"], 3);
        assert_eq!(arr[5]["kind"], "event");
        assert_eq!(arr[5]["period"], 1);

        let _ = fs::remove_dir_all(&dir);
    }

    /// `EndOfSequence` is emitted in plain text when reopening a populated
    /// cadaver file (cadaver writer behavior). Confirm the renderer
    /// surfaces it as a delimiter line.
    #[test]
    fn render_text_marks_end_of_sequence_between_runs() {
        let dir = unique_dir("eos");
        let cfg = CadaverConfig {
            base_directory: dir.clone(),
            base_filename: "node".into(),
            file_size_target: CADAVER_SIZE_MINIMUM,
            version_commit_hash: "fixture-commit".into(),
        };
        let active = cfg.active_path();

        // Two consecutive sessions on the same file → second open emits
        // an EndOfSequence boundary plus a fresh Meta.
        for run in 0..2 {
            let mut cad = Cadaver::open(cfg.clone()).expect("open cadaver");
            cad.trace_event(
                PlayerSnapshot {
                    round: Round(1 + run),
                    period: Period(0),
                    step: 0,
                },
                &FixtureEvent {
                    kind: format!("run-{run}"),
                    value: run as i64,
                },
            )
            .expect("write event");
        }

        let mut sink: Vec<u8> = Vec::new();
        render_to(&active, AutopsyFormat::Text, &mut sink).expect("render text");
        let output = String::from_utf8(sink).expect("utf-8 output");

        assert!(
            output.contains("-- end of sequence --"),
            "EOS marker missing in:\n{output}",
        );
        assert!(output.contains("== run #0"));
        assert!(output.contains("== run #1"));

        let _ = fs::remove_dir_all(&dir);
    }

    /// `resolve_inputs` returns the archive first when both files exist
    /// (matches Go's `PrepareAutopsy` ordering).
    #[test]
    fn resolve_inputs_archive_first_then_active() {
        let dir = unique_dir("resolve");
        let active = dir.join("node.cdv");
        let archive = dir.join("node.cdv.archive");
        fs::write(&active, b"x").unwrap();
        fs::write(&archive, b"x").unwrap();

        let inputs = resolve_inputs(&active).expect("resolve");
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0], archive);
        assert_eq!(inputs[1], active);

        let _ = fs::remove_dir_all(&dir);
    }

    /// Pointing directly at a `.cdv.archive` file reads just that file.
    #[test]
    fn resolve_inputs_archive_path_returns_archive_only() {
        let dir = unique_dir("archive-only");
        let archive = dir.join("node.cdv.archive");
        fs::write(&archive, b"x").unwrap();

        let inputs = resolve_inputs(&archive).expect("resolve");
        assert_eq!(inputs, vec![archive]);

        let _ = fs::remove_dir_all(&dir);
    }

    /// Missing file is reported as an error rather than silently
    /// producing empty output.
    #[test]
    fn missing_cadaver_file_produces_error() {
        let dir = unique_dir("missing");
        let nonexistent = dir.join("does-not-exist.cdv");

        let mut sink: Vec<u8> = Vec::new();
        let err = render_to(&nonexistent, AutopsyFormat::Text, &mut sink)
            .expect_err("missing file must surface an error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no cadaver files found") || msg.contains("does-not-exist"),
            "unhelpful error: {msg}",
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
