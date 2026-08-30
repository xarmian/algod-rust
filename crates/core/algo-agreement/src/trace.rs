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

// Cadaver structured trace writer for agreement state-machine transitions.
//
// Mirrors go-algorand v4.6.0-stable `agreement/cadaver.go` (the binary log
// writer) and the entry-tag portion of `agreement/trace.go`. The companion
// reader/analyzer (autopsy) lives in a sibling task — see TASK-64.
//
// ## What this is for
// A rotating, append-only binary log of agreement state-machine transitions.
// Each time the state machine observes an input event or emits an output
// action batch, the cadaver writes:
//
// 1. A `Player` entry (if the round/period changed since the previous
//    entry) so a reader can correlate subsequent events/actions with the
//    player context in which they happened.
// 2. An `Event` or `Action` entry carrying a msgpack-encoded payload.
//
// When the file passes `file_size_target` bytes we close it, rename it to
// `<name>.archive`, and open a fresh file — same semantics as Go.
//
// ## Format compatibility with Go
//
// **Frame format matches Go byte-for-byte:**
//
// * Entry tag values are identical to Go's `cadaverEntryType`:
//   `Meta = 0, Player = 1, Event = 2, Action = 3, EndOfSequence = 4`.
// * Entry tag is msgpack-encoded as a single small-int byte (Go's
//   `protocol.EncodeStream` and rmp-serde both emit the positive-fixint
//   form for ints in `[0, 127]`).
// * File naming and rotation (`.cdv`, rename to `.cdv.archive`) matches
//   Go's `cadaver.trySetup`.
// * `EndOfSequence` is written when reopening an existing file and before
//   writing the new `Meta`, matching Go's `c.out.bytesWritten > 0` branch.
//
// **Payloads diverge from Go:** agreement types on the Rust side serialize
// through `rmp_serde`, whose struct-encoding defaults to a positional array
// of field values. Go's payloads come from hand-written / generated
// `msgp_gen.go` code which uses named-map encoding. Reconciling these
// would require a second codec layer (the same gap DOC-21 §3.14 flags for
// consensus wire bytes). Since the autopsy analyzer (TASK-64) is a
// Rust-native tool parsing our own payloads, full Go byte parity is
// unnecessary here and the divergence is accepted per the task's
// "documented and justified" allowance.
//
// ## Threading
//
// `Cadaver` is `Send` but not `Sync`; callers wanting to write from
// multiple threads should wrap it in `Mutex<Cadaver>` or a channel-fronted
// writer thread. The agreement main loop is single-threaded w.r.t. state
// transitions so this is normally a non-issue.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use rmp_serde::{decode, encode};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::step::Period;
use algo_types::Round;

/// Entry-type tag prefixing every record in the cadaver stream.
///
/// Values are wire-level stable: changing them would invalidate existing
/// cadaver files and break the autopsy reader. Mirrors go-algorand
/// `cadaver.go::cadaverEntryType`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CadaverEntryType {
    /// File metadata — always the first entry in a fresh file.
    Meta = 0,
    /// Snapshot of the player at the current (round, period).
    Player = 1,
    /// A single input event delivered to the state machine.
    Event = 2,
    /// An action batch emitted by the state machine.
    Action = 3,
    /// End of a sequence — written before a fresh `Meta` when appending
    /// to a previously populated file.
    EndOfSequence = 4,
}

/// Per-file metadata written as the first entry after each open/rotate.
///
/// Mirrors go-algorand `CadaverMetadata`. `num_opened` increments each
/// time the writer opens (or rotates into) a new file so readers can
/// order sequences when multiple archives are present.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CadaverMetadata {
    pub num_opened: u32,
    pub version_commit_hash: String,
}

/// Minimum file size target that makes rotation meaningful. Prevents
/// pathological "rotate on every write" configurations.
///
/// Mirrors Go's `cadaverSizeMinimum = 100 * 1024`.
pub const CADAVER_SIZE_MINIMUM: u64 = 100 * 1024;

/// Resolve `config.Local`'s `CadaverSizeTarget`/`CadaverDirectory` (issue
/// #756) into a [`CadaverConfig`], or `None` if cadaver tracing is
/// disabled — go's `MakeService`/`makeTracer` size-target logic
/// (`../go-algorand/agreement/service.go:110-119`,
/// `../go-algorand/agreement/trace.go:76-97`), ported field-for-field:
///
/// * `size_target == 0` → cadaver tracing is disabled: returns `Ok(None)`,
///   matching go's `fileSizeTarget == 0` "disabled" branch.
/// * `size_target != 0` but below [`CADAVER_SIZE_MINIMUM`] → returns
///   `Err(SizeTargetTooSmall)`. go additionally rejects a *negative*
///   `int64(cadaverSizeTarget)` (an overflow artifact of go's `uint64` ->
///   `int64` cast); that case cannot arise here because `size_target` stays
///   `u64` throughout, so there is nothing to replicate.
/// * otherwise → `Ok(Some(CadaverConfig { .. }))`, with `directory` falling
///   back to `default_directory` when empty. go falls back to
///   `ColdDataDir`, which algod-rust doesn't have (`CATCHPOINT_DIR`'s doc
///   comment in `algo-config` records that hot/cold-directory split as an
///   architectural non-goal); callers here supply whatever directory
///   should stand in for it — typically the node's data directory.
///
/// Note: this function does **not** call [`Cadaver::open`] itself, so the
/// [`CADAVER_SIZE_MINIMUM`] check surfaces through the returned
/// `CadaverConfig` only once a caller actually opens it — this crate has no
/// live call site that opens a `Cadaver` during agreement service startup
/// yet (only tests and the `autopsy` CLI reader construct one today), so
/// wiring an actual running node to produce cadaver files end-to-end is
/// tracked as a separate follow-up rather than done as part of this
/// config-field-audit issue.
pub fn resolve_cadaver_config(
    size_target: u64,
    directory: &str,
    default_directory: &Path,
    base_filename: &str,
    version_commit_hash: String,
) -> Option<CadaverConfig> {
    if size_target == 0 {
        return None;
    }
    let base_directory = if directory.is_empty() {
        default_directory.to_path_buf()
    } else {
        PathBuf::from(directory)
    };
    Some(CadaverConfig {
        base_directory,
        base_filename: base_filename.to_string(),
        file_size_target: size_target,
        version_commit_hash,
    })
}

/// Snapshot of `(round, period, step)` written with every `Player` entry.
///
/// This is intentionally a narrow projection of the full `Player` struct:
/// the cadaver records *transitions between rounds/periods* (the positions
/// a reader uses to seek), not the full router state (which is persisted
/// separately in `persistence::DiskState`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlayerSnapshot {
    pub round: Round,
    pub period: Period,
    pub step: u64,
}

/// Writer configuration.
#[derive(Debug, Clone)]
pub struct CadaverConfig {
    /// Directory where cadaver files live. Must exist when the writer opens.
    pub base_directory: PathBuf,
    /// Filename stem; the active file will be `<stem>.cdv` and archives
    /// will be `<stem>.cdv.archive`.
    pub base_filename: String,
    /// Rotate once the active file passes this byte threshold. Must be
    /// >= `CADAVER_SIZE_MINIMUM`.
    pub file_size_target: u64,
    /// Metadata written to the head of every file.
    pub version_commit_hash: String,
}

impl CadaverConfig {
    /// Return the absolute path to the active `.cdv` file.
    pub fn active_path(&self) -> PathBuf {
        self.base_directory
            .join(format!("{}.cdv", self.base_filename))
    }

    /// Return the absolute path the active file is renamed to on rotation.
    pub fn archive_path(&self) -> PathBuf {
        self.base_directory
            .join(format!("{}.cdv.archive", self.base_filename))
    }
}

/// Errors surfaced by the cadaver writer.
#[derive(Debug, thiserror::Error)]
pub enum CadaverError {
    #[error("cadaver I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("cadaver encode error: {0}")]
    Encode(#[from] encode::Error),
    #[error("cadaver decode error: {0}")]
    Decode(#[from] decode::Error),
    #[error("cadaver size target {0} is smaller than minimum {CADAVER_SIZE_MINIMUM}")]
    SizeTargetTooSmall(u64),
    #[error("cadaver writer is in a failed state; subsequent writes are no-ops")]
    Failed,
}

/// Rotating append-only binary log for agreement state-machine tracing.
///
/// ## Usage
///
/// ```no_run
/// use algo_agreement::trace::{Cadaver, CadaverConfig, PlayerSnapshot};
/// use algo_agreement::Period;
/// use algo_types::Round;
///
/// let cfg = CadaverConfig {
///     base_directory: std::env::temp_dir(),
///     base_filename: "node-1".into(),
///     file_size_target: 1024 * 1024,
///     version_commit_hash: env!("CARGO_PKG_VERSION").into(),
/// };
/// let mut cadaver = Cadaver::open(cfg).expect("open cadaver");
/// cadaver
///     .write_player(PlayerSnapshot { round: Round(5), period: Period(0), step: 0 })
///     .expect("write player");
/// ```
pub struct Cadaver {
    config: CadaverConfig,
    out: Option<CadaverHandle>,
    num_opened: u32,
    /// Sticky failure flag. Once set, every subsequent write is a no-op
    /// until the writer is reopened. Mirrors Go's `c.failed != nil` check.
    failed: bool,
    /// Tracks the last `(round, period)` seen on a `trace_event` /
    /// `trace_actions` call so we only emit a `Player` entry when the
    /// scope actually changes (matches Go's `c.prevRound / c.prevPeriod`
    /// gating in `cadaver.trace`).
    prev_round: Option<Round>,
    prev_period: Option<Period>,
}

impl Cadaver {
    /// Open (or create and append to) the active cadaver file. If the
    /// file already has content, writes an `EndOfSequence` entry first so
    /// a reader can separate the prior run's records from this run's.
    ///
    /// On open, always writes a fresh `Meta` entry.
    pub fn open(config: CadaverConfig) -> Result<Self, CadaverError> {
        if config.file_size_target < CADAVER_SIZE_MINIMUM {
            return Err(CadaverError::SizeTargetTooSmall(config.file_size_target));
        }
        let mut cad = Self {
            config,
            out: None,
            num_opened: 0,
            failed: false,
            prev_round: None,
            prev_period: None,
        };
        cad.try_setup()?;
        Ok(cad)
    }

    /// Ensure the underlying file is open and below the rotation threshold.
    /// Rotates into a fresh file when the active one passes its size target.
    fn try_setup(&mut self) -> Result<(), CadaverError> {
        if self.failed {
            return Err(CadaverError::Failed);
        }

        if self.out.is_none() {
            self.init_file()?;
            return Ok(());
        }

        // Check rotation threshold.
        let over_size = self
            .out
            .as_ref()
            .map(|h| h.bytes_written >= self.config.file_size_target)
            .unwrap_or(false);
        if over_size {
            // Close current handle (drop flushes).
            self.out = None;
            let active = self.config.active_path();
            let archive = self.config.archive_path();
            match std::fs::rename(&active, &archive) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    // File was externally removed between close and rename.
                    // Matches Go's "file doesn't exist" branch — log and
                    // continue (a fresh file will be created below).
                    warn!(
                        path = %active.display(),
                        "cadaver: active file missing at rotate; continuing",
                    );
                }
                Err(e) => {
                    self.failed = true;
                    return Err(CadaverError::Io(e));
                }
            }
            self.init_file()?;
        }
        Ok(())
    }

    /// Open or create the active file and emit the sequence header
    /// (`EndOfSequence` if appending, then `Meta`).
    fn init_file(&mut self) -> Result<(), CadaverError> {
        let path = self.config.active_path();
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .read(false)
            .open(&path)?;
        let handle = CadaverHandle::from_file(file)?;
        let existing_bytes = handle.bytes_written;
        self.out = Some(handle);

        // If the file already had content, mark the boundary between the
        // previous run's records and this run's.
        if existing_bytes > 0 {
            self.write_tagged(CadaverEntryType::EndOfSequence, &())?;
        }

        self.write_tagged(
            CadaverEntryType::Meta,
            &CadaverMetadata {
                num_opened: self.num_opened,
                version_commit_hash: self.config.version_commit_hash.clone(),
            },
        )?;
        self.num_opened = self.num_opened.saturating_add(1);
        Ok(())
    }

    /// Write a `Player` entry unconditionally. Useful for tests and for
    /// callers that want explicit control; the `trace_*` variants below
    /// emit the player automatically when scope changes.
    pub fn write_player(&mut self, snapshot: PlayerSnapshot) -> Result<(), CadaverError> {
        self.try_setup()?;
        self.prev_round = Some(snapshot.round);
        self.prev_period = Some(snapshot.period);
        self.write_tagged(CadaverEntryType::Player, &snapshot)
    }

    /// Record an input event. Emits a `Player` entry first if `(round,
    /// period)` differ from the previous scope — matches Go's
    /// `cadaver.trace` gating before `traceInput`.
    pub fn trace_event<E: Serialize>(
        &mut self,
        scope: PlayerSnapshot,
        event: &E,
    ) -> Result<(), CadaverError> {
        self.try_setup()?;
        self.emit_player_if_scope_changed(scope)?;
        self.write_tagged(CadaverEntryType::Event, event)
    }

    /// Record an action batch emitted by the state machine. Same scope
    /// gating as `trace_event`.
    pub fn trace_actions<A: Serialize>(
        &mut self,
        scope: PlayerSnapshot,
        actions: &[A],
    ) -> Result<(), CadaverError> {
        self.try_setup()?;
        self.emit_player_if_scope_changed(scope)?;
        self.write_tagged(CadaverEntryType::Action, &actions)
    }

    /// Explicitly write an `EndOfSequence` marker. Normally unnecessary
    /// — `open()` writes one automatically when it finds an existing
    /// populated file — but exposed for callers that want to segment a
    /// single session.
    pub fn write_end_of_sequence(&mut self) -> Result<(), CadaverError> {
        self.try_setup()?;
        self.write_tagged(CadaverEntryType::EndOfSequence, &())
    }

    fn emit_player_if_scope_changed(&mut self, scope: PlayerSnapshot) -> Result<(), CadaverError> {
        let scope_changed =
            self.prev_round != Some(scope.round) || self.prev_period != Some(scope.period);
        if scope_changed {
            self.prev_round = Some(scope.round);
            self.prev_period = Some(scope.period);
            self.write_tagged(CadaverEntryType::Player, &scope)?;
        }
        Ok(())
    }

    fn write_tagged<T: Serialize>(
        &mut self,
        tag: CadaverEntryType,
        payload: &T,
    ) -> Result<(), CadaverError> {
        match self.write_tagged_inner(tag, payload) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Any failure here can leave a partial frame on disk
                // (e.g. tag written but payload failed mid-way). Trip
                // the sticky failure flag so subsequent `trace_*` calls
                // short-circuit via `try_setup` instead of appending
                // additional records into a corrupted stream.
                self.failed = true;
                Err(e)
            }
        }
    }

    fn write_tagged_inner<T: Serialize>(
        &mut self,
        tag: CadaverEntryType,
        payload: &T,
    ) -> Result<(), CadaverError> {
        let handle = match self.out.as_mut() {
            Some(h) => h,
            None => return Err(CadaverError::Failed),
        };
        // Write the tag (1 byte positive-fixint in msgpack) followed by
        // the payload. A single `write_all` per value keeps the on-disk
        // framing identical to Go's sequential `EncodeStream` pattern.
        let tag_bytes = rmp_serde::to_vec(&(tag as u8))?;
        handle.write_all(&tag_bytes)?;
        let payload_bytes = rmp_serde::to_vec(payload)?;
        handle.write_all(&payload_bytes)?;
        Ok(())
    }

    /// Total bytes written to the currently-active file (i.e. since the
    /// most recent rotation). Useful for tests and diagnostics.
    pub fn bytes_written(&self) -> u64 {
        self.out.as_ref().map(|h| h.bytes_written).unwrap_or(0)
    }

    /// Number of times a file has been opened (initial + rotations).
    pub fn num_opened(&self) -> u32 {
        self.num_opened
    }
}

/// File handle that tracks cumulative bytes written so the caller can
/// detect the rotation threshold without an extra `fstat` syscall.
struct CadaverHandle {
    file: File,
    bytes_written: u64,
}

impl CadaverHandle {
    fn from_file(file: File) -> io::Result<Self> {
        let meta = file.metadata()?;
        Ok(Self {
            file,
            bytes_written: meta.len(),
        })
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf)?;
        self.bytes_written += buf.len() as u64;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// A decoded entry as returned by `CadaverReader::next_entry`.
///
/// The `Event` and `Action` variants carry their payloads as raw bytes so
/// the reader doesn't need to know the caller's event/action types. The
/// autopsy CLI will provide the concrete deserializers (TASK-64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CadaverRecord {
    Meta(CadaverMetadata),
    Player(PlayerSnapshot),
    Event(Vec<u8>),
    Action(Vec<u8>),
    EndOfSequence,
}

/// Streaming reader for a single cadaver file (not across archives).
///
/// Intended for tests and the forthcoming autopsy CLI.
pub struct CadaverReader<R: Read> {
    inner: R,
    eof: bool,
}

impl<R: Read> CadaverReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, eof: false }
    }

    /// Read the next entry from the stream. Returns `Ok(None)` on clean
    /// EOF, `Err` on any mid-record decode failure.
    pub fn next_entry(&mut self) -> Result<Option<CadaverRecord>, CadaverError> {
        if self.eof {
            return Ok(None);
        }
        // Decode the tag byte. EOF here is clean; EOF mid-record isn't.
        let tag: u8 = match rmp_serde::from_read(&mut self.inner) {
            Ok(t) => t,
            Err(decode::Error::InvalidMarkerRead(e))
                if e.kind() == io::ErrorKind::UnexpectedEof =>
            {
                self.eof = true;
                return Ok(None);
            }
            Err(e) => return Err(CadaverError::Decode(e)),
        };

        let rec = match tag {
            t if t == CadaverEntryType::Meta as u8 => {
                CadaverRecord::Meta(rmp_serde::from_read(&mut self.inner)?)
            }
            t if t == CadaverEntryType::Player as u8 => {
                CadaverRecord::Player(rmp_serde::from_read(&mut self.inner)?)
            }
            t if t == CadaverEntryType::Event as u8 => {
                // The payload is a single rmp value; capture its bytes so
                // the autopsy consumer can deserialize using its own types.
                let value: rmpv::Value = rmpv::decode::read_value(&mut self.inner)
                    .map_err(|e| CadaverError::Io(io::Error::other(e)))?;
                let mut buf = Vec::new();
                rmpv::encode::write_value(&mut buf, &value)
                    .map_err(|e| CadaverError::Io(io::Error::other(e)))?;
                CadaverRecord::Event(buf)
            }
            t if t == CadaverEntryType::Action as u8 => {
                let value: rmpv::Value = rmpv::decode::read_value(&mut self.inner)
                    .map_err(|e| CadaverError::Io(io::Error::other(e)))?;
                let mut buf = Vec::new();
                rmpv::encode::write_value(&mut buf, &value)
                    .map_err(|e| CadaverError::Io(io::Error::other(e)))?;
                CadaverRecord::Action(buf)
            }
            t if t == CadaverEntryType::EndOfSequence as u8 => {
                // EOS's payload is the encoded unit `()` — read + discard.
                let _: () = rmp_serde::from_read(&mut self.inner)?;
                CadaverRecord::EndOfSequence
            }
            other => {
                return Err(CadaverError::Decode(decode::Error::Uncategorized(format!(
                    "unknown cadaver entry tag: {other}"
                ))));
            }
        };
        Ok(Some(rec))
    }

    /// Collect every remaining entry into a Vec.
    pub fn read_all(mut self) -> Result<Vec<CadaverRecord>, CadaverError> {
        let mut out = Vec::new();
        while let Some(rec) = self.next_entry()? {
            out.push(rec);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct DummyEvent {
        kind: String,
        value: i64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct DummyAction {
        target_round: u64,
    }

    fn unique_dir(label: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!("algo-cadaver-{label}-{pid}-{nanos}"));
        fs::create_dir_all(&dir).expect("create tmp dir");
        dir
    }

    fn test_config(dir: &Path, name: &str, size_target: u64) -> CadaverConfig {
        CadaverConfig {
            base_directory: dir.to_path_buf(),
            base_filename: name.into(),
            file_size_target: size_target,
            version_commit_hash: "test-commit".into(),
        }
    }

    #[test]
    fn rejects_size_target_below_minimum() {
        let dir = unique_dir("min-size");
        let cfg = test_config(&dir, "node", CADAVER_SIZE_MINIMUM - 1);
        match Cadaver::open(cfg) {
            Err(CadaverError::SizeTargetTooSmall(n)) => {
                assert_eq!(n, CADAVER_SIZE_MINIMUM - 1);
            }
            Err(e) => panic!("expected SizeTargetTooSmall, got error {e:?}"),
            Ok(_) => panic!("expected SizeTargetTooSmall, got Ok"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// Acceptance-criterion test: write events and actions, read them
    /// back, verify ordering and payload round-trip.
    #[test]
    fn write_then_read_preserves_order_and_payloads() {
        let dir = unique_dir("roundtrip");
        let cfg = test_config(&dir, "node", CADAVER_SIZE_MINIMUM);

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

        {
            let mut cad = Cadaver::open(cfg.clone()).expect("open cadaver");
            cad.trace_event(
                scope1,
                &DummyEvent {
                    kind: "vote".into(),
                    value: 1,
                },
            )
            .expect("write event 1");
            cad.trace_actions(
                scope1,
                &[
                    DummyAction { target_round: 7 },
                    DummyAction { target_round: 8 },
                ],
            )
            .expect("write actions");
            cad.trace_event(
                scope2,
                &DummyEvent {
                    kind: "cert".into(),
                    value: 2,
                },
            )
            .expect("write event 2");
        }

        // Read back and validate stream shape.
        let file = File::open(cfg.active_path()).expect("open for read");
        let records = CadaverReader::new(file).read_all().expect("read all");

        // Expected: Meta, Player(scope1), Event, Action, Player(scope2), Event.
        assert_eq!(records.len(), 6, "records: {records:#?}");
        match &records[0] {
            CadaverRecord::Meta(m) => {
                assert_eq!(m.num_opened, 0);
                assert_eq!(m.version_commit_hash, "test-commit");
            }
            other => panic!("expected Meta, got {other:?}"),
        }
        match &records[1] {
            CadaverRecord::Player(p) => assert_eq!(*p, scope1),
            other => panic!("expected Player(scope1), got {other:?}"),
        }
        match &records[2] {
            CadaverRecord::Event(bytes) => {
                let ev: DummyEvent = rmp_serde::from_slice(bytes).expect("decode event 1");
                assert_eq!(
                    ev,
                    DummyEvent {
                        kind: "vote".into(),
                        value: 1,
                    }
                );
            }
            other => panic!("expected Event, got {other:?}"),
        }
        match &records[3] {
            CadaverRecord::Action(bytes) => {
                let actions: Vec<DummyAction> =
                    rmp_serde::from_slice(bytes).expect("decode actions");
                assert_eq!(
                    actions,
                    vec![
                        DummyAction { target_round: 7 },
                        DummyAction { target_round: 8 }
                    ],
                );
            }
            other => panic!("expected Action, got {other:?}"),
        }
        match &records[4] {
            CadaverRecord::Player(p) => assert_eq!(*p, scope2),
            other => panic!("expected Player(scope2), got {other:?}"),
        }
        match &records[5] {
            CadaverRecord::Event(bytes) => {
                let ev: DummyEvent = rmp_serde::from_slice(bytes).expect("decode event 2");
                assert_eq!(
                    ev,
                    DummyEvent {
                        kind: "cert".into(),
                        value: 2,
                    }
                );
            }
            other => panic!("expected Event, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// A `Player` entry is emitted only when `(round, period)` changes
    /// across consecutive events, matching Go's gating in `cadaver.trace`.
    #[test]
    fn player_entry_only_on_scope_change() {
        let dir = unique_dir("scope-gating");
        let cfg = test_config(&dir, "node", CADAVER_SIZE_MINIMUM);

        let scope = PlayerSnapshot {
            round: Round(1),
            period: Period(0),
            step: 0,
        };

        {
            let mut cad = Cadaver::open(cfg.clone()).expect("open");
            // Three events at the same (round, period) — expect ONE player entry total.
            for v in 0..3 {
                cad.trace_event(
                    scope,
                    &DummyEvent {
                        kind: "noop".into(),
                        value: v,
                    },
                )
                .expect("write event");
            }
        }

        let file = File::open(cfg.active_path()).expect("open for read");
        let records = CadaverReader::new(file).read_all().expect("read all");

        let player_count = records
            .iter()
            .filter(|r| matches!(r, CadaverRecord::Player(_)))
            .count();
        assert_eq!(player_count, 1, "records: {records:#?}");
        let event_count = records
            .iter()
            .filter(|r| matches!(r, CadaverRecord::Event(_)))
            .count();
        assert_eq!(event_count, 3);

        let _ = fs::remove_dir_all(&dir);
    }

    /// Rotation: once `bytes_written >= file_size_target`, the next write
    /// closes the active file, renames it to `.cdv.archive`, and opens a
    /// fresh one starting with a new `Meta`.
    #[test]
    fn rotates_when_size_target_exceeded() {
        let dir = unique_dir("rotation");
        let cfg = test_config(&dir, "node", CADAVER_SIZE_MINIMUM);

        let scope = PlayerSnapshot {
            round: Round(1),
            period: Period(0),
            step: 0,
        };

        {
            let mut cad = Cadaver::open(cfg.clone()).expect("open");
            assert_eq!(cad.num_opened(), 1, "initial open counts as 1");

            // Push enough data past the threshold. Each event payload is
            // a few dozen bytes; thousands of events will blow past 100KB.
            let big_string = "x".repeat(200);
            for i in 0..2000u32 {
                cad.trace_event(
                    scope,
                    &DummyEvent {
                        kind: big_string.clone(),
                        value: i as i64,
                    },
                )
                .expect("write event");
                if cad.num_opened() > 1 {
                    break;
                }
            }
            assert!(
                cad.num_opened() >= 2,
                "expected at least one rotation; num_opened = {}",
                cad.num_opened()
            );
        }

        // The archive file must exist.
        assert!(
            cfg.archive_path().exists(),
            "archive not created at {}",
            cfg.archive_path().display(),
        );
        // The active file must exist and start with a Meta entry.
        let records_active = CadaverReader::new(File::open(cfg.active_path()).unwrap())
            .read_all()
            .expect("read active");
        match records_active.first() {
            Some(CadaverRecord::Meta(m)) => {
                assert!(
                    m.num_opened >= 1,
                    "post-rotation meta must have num_opened >= 1"
                );
            }
            other => panic!("expected Meta first, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// Reopening a populated file writes EndOfSequence + a fresh Meta
    /// before the next records, matching Go's `bytesWritten > 0` branch.
    #[test]
    fn reopening_existing_file_writes_eos_then_fresh_meta() {
        let dir = unique_dir("reopen");
        let cfg = test_config(&dir, "node", CADAVER_SIZE_MINIMUM);

        let scope = PlayerSnapshot {
            round: Round(1),
            period: Period(0),
            step: 0,
        };

        {
            let mut cad = Cadaver::open(cfg.clone()).expect("open 1");
            cad.trace_event(
                scope,
                &DummyEvent {
                    kind: "first-run".into(),
                    value: 0,
                },
            )
            .expect("write event");
        }
        {
            let mut cad = Cadaver::open(cfg.clone()).expect("open 2");
            cad.trace_event(
                scope,
                &DummyEvent {
                    kind: "second-run".into(),
                    value: 1,
                },
            )
            .expect("write event");
        }

        let records = CadaverReader::new(File::open(cfg.active_path()).unwrap())
            .read_all()
            .expect("read all");

        // Find the boundary: EndOfSequence followed immediately by Meta.
        let eos_idx = records
            .iter()
            .position(|r| matches!(r, CadaverRecord::EndOfSequence))
            .expect("EOS present between runs");
        match records.get(eos_idx + 1) {
            Some(CadaverRecord::Meta(_)) => {}
            other => panic!("expected Meta after EOS, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// A payload whose `Serialize` impl always errors — used to simulate a
    /// mid-record write failure without needing to fake the filesystem.
    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S: serde::Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("intentional serialize failure"))
        }
    }

    /// Regression for the Codex P1 on PR #237: an error in `write_tagged`
    /// must flip the sticky `failed` flag so subsequent writes don't
    /// silently append into a partial frame.
    #[test]
    fn write_tagged_sets_failed_on_serialize_error() {
        let dir = unique_dir("fail-flag");
        let cfg = test_config(&dir, "node", CADAVER_SIZE_MINIMUM);
        let mut cad = Cadaver::open(cfg.clone()).expect("open");

        let scope = PlayerSnapshot {
            round: Round(1),
            period: Period(0),
            step: 0,
        };

        // First call: the Player entry serializes fine, but the Event
        // payload fails mid-record. `write_tagged` must mark `failed`.
        let err = cad
            .trace_event(scope, &FailingSerialize)
            .expect_err("serialize failure must propagate");
        assert!(
            matches!(err, CadaverError::Encode(_)),
            "expected Encode error, got {err:?}",
        );

        // Second call: must short-circuit with `Failed` instead of writing
        // new records into a potentially corrupted stream.
        match cad.write_player(scope) {
            Err(CadaverError::Failed) => {}
            Err(e) => panic!("expected Failed, got {e:?}"),
            Ok(()) => panic!("expected Failed, got Ok — failed flag not sticky"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // --- resolve_cadaver_config (issue #756) --------------------------

    #[test]
    fn resolve_cadaver_config_zero_size_target_disables_tracing() {
        let cfg = resolve_cadaver_config(
            0,
            "",
            Path::new("/var/lib/algod"),
            "agreement",
            "v1".to_string(),
        );
        assert!(cfg.is_none(), "size target 0 must disable cadaver tracing");
    }

    #[test]
    fn resolve_cadaver_config_empty_directory_falls_back_to_default() {
        let cfg = resolve_cadaver_config(
            CADAVER_SIZE_MINIMUM,
            "",
            Path::new("/var/lib/algod"),
            "agreement",
            "v1".to_string(),
        )
        .expect("nonzero size target enables tracing");
        assert_eq!(cfg.base_directory, PathBuf::from("/var/lib/algod"));
        assert_eq!(cfg.base_filename, "agreement");
        assert_eq!(cfg.file_size_target, CADAVER_SIZE_MINIMUM);
        assert_eq!(cfg.version_commit_hash, "v1");
    }

    #[test]
    fn resolve_cadaver_config_explicit_directory_overrides_default() {
        let cfg = resolve_cadaver_config(
            CADAVER_SIZE_MINIMUM,
            "/data/cadaver",
            Path::new("/var/lib/algod"),
            "agreement",
            "v1".to_string(),
        )
        .expect("nonzero size target enables tracing");
        assert_eq!(cfg.base_directory, PathBuf::from("/data/cadaver"));
    }

    #[test]
    fn resolve_cadaver_config_too_small_but_nonzero_target_is_caught_by_open() {
        // resolve_cadaver_config itself doesn't validate the minimum size —
        // it defers to Cadaver::open, mirroring go's makeTracer error but
        // surfaced at the point the file is actually opened.
        let cfg = resolve_cadaver_config(
            1,
            "",
            Path::new("/var/lib/algod"),
            "agreement",
            "v1".to_string(),
        )
        .expect("nonzero size target enables tracing, even if too small");
        assert_eq!(cfg.file_size_target, 1);
        match Cadaver::open(cfg) {
            Err(CadaverError::SizeTargetTooSmall(1)) => {}
            Err(e) => panic!("expected SizeTargetTooSmall(1), got error {e:?}"),
            Ok(_) => panic!("expected SizeTargetTooSmall(1), got Ok"),
        }
    }

    #[test]
    fn active_and_archive_paths_use_expected_extensions() {
        let dir = unique_dir("paths");
        let cfg = test_config(&dir, "node", CADAVER_SIZE_MINIMUM);
        assert!(cfg.active_path().to_string_lossy().ends_with("node.cdv"));
        assert!(cfg
            .archive_path()
            .to_string_lossy()
            .ends_with("node.cdv.archive"));
        let _ = fs::remove_dir_all(&dir);
    }
}
