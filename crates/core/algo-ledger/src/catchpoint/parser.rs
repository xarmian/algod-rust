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

//! Streaming catchpoint file parser.
//!
//! Catchpoint files are tar archives (optionally gzip- or Snappy-compressed at
//! the outer level) containing:
//!
//! 1. `content.msgpack` — the [`CatchpointFileHeader`], plain msgpack.
//! 2. `stateProofVerificationContext.msgpack` — optional state proof data.
//! 3. `balances.N.msgpack` — chunk entries; each may be Snappy-frame-compressed,
//!    then msgpack-decoded as [`CatchpointSnapshotChunkV6`].
//!
//! This module provides [`CatchpointReader`] for generic `Read` sources and
//! [`open`] for file-based auto-detection of compression.
//!
//! **Streaming semantics:** entries are processed one at a time via callback
//! ([`CatchpointReader::for_each`], [`CatchpointReaderFile::for_each`]), so the
//! full tar archive is never buffered in memory. However, individual entries
//! (chunks) are read entirely into memory for msgpack decoding.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use flate2::read::GzDecoder;

use super::types::{
    CatchpointError, CatchpointFileHeader, CatchpointSnapshotChunkV6, CATCHPOINT_FILE_VERSION_V6,
    CATCHPOINT_FILE_VERSION_V7, CATCHPOINT_FILE_VERSION_V8,
};

// ---------------------------------------------------------------------------
// Tar entry filename constants (matching go-algorand)
// ---------------------------------------------------------------------------

/// Filename of the header entry inside the catchpoint tar archive.
const CONTENT_FILENAME: &str = "content.msgpack";

/// Filename of the state proof verification context entry.
const SP_VERIFICATION_FILENAME: &str = "stateProofVerificationContext.msgpack";

/// Prefix for balance chunk entries (`balances.N.msgpack`).
const BALANCES_PREFIX: &str = "balances.";

/// Name of the algod-rust-only tar entry that records the round the embedded
/// account state actually reflects (issue #1654). Written by
/// [`super::writer::export_catchpoint_file`] only when
/// [`super::writer::ExportOptions::state_round`] is set; go-algorand's
/// catchpoint accessor ignores unknown sections, so go-produced files never
/// contain it and go consumers are unaffected by it.
pub const STATE_ROUND_MARKER_FILENAME: &str = "algod-rust.state-round";

/// Suffix for balance chunk entries.
const BALANCES_SUFFIX: &str = ".msgpack";

// ---------------------------------------------------------------------------
// CatchpointEntry
// ---------------------------------------------------------------------------

/// A single decoded entry from a catchpoint tar archive.
#[derive(Debug)]
pub enum CatchpointEntry {
    /// The file header from `content.msgpack`.
    Header(CatchpointFileHeader),

    /// Raw bytes of the state proof verification context entry.
    StateProofVerification(Vec<u8>),

    /// A decoded balance/KV/online-account chunk from `balances.N.msgpack`.
    Chunk(CatchpointSnapshotChunkV6),
}

// ---------------------------------------------------------------------------
// CatchpointReader<R>
// ---------------------------------------------------------------------------

/// Streaming reader for catchpoint tar archives over a generic [`Read`] source.
///
/// Because `tar::Entries` borrows the archive, this reader uses a callback-based
/// API ([`for_each`](Self::for_each)) rather than implementing `Iterator`
/// directly. For an `Iterator`-based API with file auto-detection, see
/// [`open`] and [`CatchpointReaderFile`].
pub struct CatchpointReader<R: Read> {
    archive: tar::Archive<R>,
    cached_header: Option<CatchpointFileHeader>,
}

impl<R: Read> CatchpointReader<R> {
    /// Create a reader over a raw (uncompressed) tar stream.
    pub fn new(reader: R) -> Result<Self, CatchpointError> {
        Ok(Self {
            archive: tar::Archive::new(reader),
            cached_header: None,
        })
    }

    /// Returns the cached header if `content.msgpack` has already been read.
    pub fn header(&self) -> Option<&CatchpointFileHeader> {
        self.cached_header.as_ref()
    }

    /// Iterate entries by calling `f` for each decoded [`CatchpointEntry`].
    ///
    /// This is the primary streaming method. For large catchpoint files
    /// (500 MB+), this avoids buffering the entire archive in memory.
    /// Individual entries are fully read into memory for msgpack decoding.
    ///
    /// Returns [`CatchpointError::MissingHeader`] if the archive does not
    /// contain a `content.msgpack` entry.
    pub fn for_each<F>(mut self, mut f: F) -> Result<(), CatchpointError>
    where
        F: FnMut(CatchpointEntry) -> Result<(), CatchpointError>,
    {
        let entries = self.archive.entries().map_err(CatchpointError::Io)?;

        let mut found_header = false;
        for entry_result in entries {
            let mut entry = entry_result.map_err(CatchpointError::Io)?;

            if let Some(catchpoint_entry) = process_entry(&mut entry, &mut self.cached_header)? {
                if matches!(catchpoint_entry, CatchpointEntry::Header(_)) {
                    found_header = true;
                }
                f(catchpoint_entry)?;
            }
        }

        if !found_header {
            return Err(CatchpointError::MissingHeader);
        }

        Ok(())
    }

    /// Collect all entries into a `Vec`.
    ///
    /// Convenient for testing and small files. For large catchpoint files,
    /// prefer [`for_each`](Self::for_each).
    pub fn collect_entries(self) -> Result<Vec<CatchpointEntry>, CatchpointError> {
        let mut entries = Vec::new();
        self.for_each(|entry| {
            entries.push(entry);
            Ok(())
        })?;
        Ok(entries)
    }
}

// Convenience constructors for specific compression wrappers.

impl CatchpointReader<GzDecoder<BufReader<File>>> {
    /// Create a reader that wraps a buffered file in a gzip decompressor.
    pub fn from_gzip(reader: BufReader<File>) -> Result<Self, CatchpointError> {
        Self::new(GzDecoder::new(reader))
    }
}

impl CatchpointReader<snap::read::FrameDecoder<BufReader<File>>> {
    /// Create a reader that wraps a buffered file in a Snappy frame decompressor.
    pub fn from_snappy(reader: BufReader<File>) -> Result<Self, CatchpointError> {
        Self::new(snap::read::FrameDecoder::new(reader))
    }
}

// ---------------------------------------------------------------------------
// CatchpointReaderFile — file-based reader with auto-detection
// ---------------------------------------------------------------------------

/// Compression-aware inner archive (type-erased over compression variant).
enum FileInner {
    Raw(tar::Archive<BufReader<File>>),
    Gzip(tar::Archive<GzDecoder<BufReader<File>>>),
    Snappy(tar::Archive<snap::read::FrameDecoder<BufReader<File>>>),
}

/// A catchpoint reader opened from a file, with auto-detected compression.
///
/// Supports gzip, Snappy framing, and raw tar formats. Use [`open`] to
/// construct.
pub struct CatchpointReaderFile {
    inner: FileInner,
    cached_header: Option<CatchpointFileHeader>,
}

impl CatchpointReaderFile {
    /// Read the [`STATE_ROUND_MARKER_FILENAME`] entry, if the file has one.
    ///
    /// The writer places the marker directly after `content.msgpack`, ahead
    /// of every `balances.N.msgpack` chunk, so the scan stops at the first
    /// chunk and never streams the bulk of the file.
    pub fn state_round_marker(mut self) -> Result<Option<u64>, CatchpointError> {
        match &mut self.inner {
            FileInner::Raw(archive) => scan_state_round_marker(archive),
            FileInner::Gzip(archive) => scan_state_round_marker(archive),
            FileInner::Snappy(archive) => scan_state_round_marker(archive),
        }
    }

    /// Returns the cached header if `content.msgpack` has already been read.
    pub fn header(&self) -> Option<&CatchpointFileHeader> {
        self.cached_header.as_ref()
    }

    /// Iterate entries by calling `f` for each decoded [`CatchpointEntry`].
    ///
    /// Entries are processed one at a time (the archive is not fully buffered),
    /// but individual chunks are read entirely into memory for decoding.
    ///
    /// Returns [`CatchpointError::MissingHeader`] if the archive does not
    /// contain a `content.msgpack` entry.
    pub fn for_each<F>(mut self, mut f: F) -> Result<(), CatchpointError>
    where
        F: FnMut(CatchpointEntry) -> Result<(), CatchpointError>,
    {
        match &mut self.inner {
            FileInner::Raw(archive) => iterate_archive(archive, &mut self.cached_header, &mut f),
            FileInner::Gzip(archive) => iterate_archive(archive, &mut self.cached_header, &mut f),
            FileInner::Snappy(archive) => iterate_archive(archive, &mut self.cached_header, &mut f),
        }
    }

    /// Collect all entries into a `Vec`.
    pub fn collect_entries(self) -> Result<Vec<CatchpointEntry>, CatchpointError> {
        let mut entries = Vec::new();
        self.for_each(|entry| {
            entries.push(entry);
            Ok(())
        })?;
        Ok(entries)
    }
}

/// Open a catchpoint file from disk, auto-detecting the compression format.
///
/// Peeks at the first bytes to distinguish gzip (`1f 8b`), Snappy framing
/// (`ff 06 00 00 73 4e 61 50 70 59`), or raw tar.
pub fn open(path: impl AsRef<Path>) -> Result<CatchpointReaderFile, CatchpointError> {
    let file = File::open(path.as_ref())?;
    let mut buf_reader = BufReader::new(file);

    let peeked = peek_bytes(&mut buf_reader, 10)?;

    if peeked.len() >= 2 && peeked[0] == 0x1f && peeked[1] == 0x8b {
        Ok(CatchpointReaderFile {
            inner: FileInner::Gzip(tar::Archive::new(GzDecoder::new(buf_reader))),
            cached_header: None,
        })
    } else if peeked.len() >= 10 && peeked[0] == 0xff && &peeked[1..10] == b"\x06\x00\x00sNaPpY" {
        Ok(CatchpointReaderFile {
            inner: FileInner::Snappy(tar::Archive::new(snap::read::FrameDecoder::new(buf_reader))),
            cached_header: None,
        })
    } else {
        Ok(CatchpointReaderFile {
            inner: FileInner::Raw(tar::Archive::new(buf_reader)),
            cached_header: None,
        })
    }
}

/// Peek at up to `n` bytes from a `BufReader` without consuming them.
fn peek_bytes<R: Read>(reader: &mut BufReader<R>, n: usize) -> Result<Vec<u8>, CatchpointError> {
    let buf = reader.fill_buf()?;
    let available = buf.len().min(n);
    Ok(buf[..available].to_vec())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Iterate over tar entries in an archive, calling `f` for each recognized
/// [`CatchpointEntry`].
///
/// Returns [`CatchpointError::MissingHeader`] if the archive does not contain
/// a `content.msgpack` entry.
fn iterate_archive<R: Read, F>(
    archive: &mut tar::Archive<R>,
    cached_header: &mut Option<CatchpointFileHeader>,
    f: &mut F,
) -> Result<(), CatchpointError>
where
    F: FnMut(CatchpointEntry) -> Result<(), CatchpointError>,
{
    let entries = archive.entries().map_err(CatchpointError::Io)?;

    let mut found_header = false;
    for entry_result in entries {
        let mut entry = entry_result.map_err(CatchpointError::Io)?;

        if let Some(catchpoint_entry) = process_entry(&mut entry, cached_header)? {
            if matches!(catchpoint_entry, CatchpointEntry::Header(_)) {
                found_header = true;
            }
            f(catchpoint_entry)?;
        }
    }

    if !found_header {
        return Err(CatchpointError::MissingHeader);
    }

    Ok(())
}

/// Scan the leading tar entries for [`STATE_ROUND_MARKER_FILENAME`].
fn scan_state_round_marker<R: Read>(
    archive: &mut tar::Archive<R>,
) -> Result<Option<u64>, CatchpointError> {
    for entry_result in archive.entries().map_err(CatchpointError::Io)? {
        let mut entry = entry_result.map_err(CatchpointError::Io)?;
        let path = entry
            .path()
            .map_err(CatchpointError::Io)?
            .to_string_lossy()
            .into_owned();
        if path == STATE_ROUND_MARKER_FILENAME {
            let data = read_entry_bytes(&mut entry)?;
            let text = std::str::from_utf8(&data).map_err(|e| {
                CatchpointError::DecodeError(format!("state-round marker is not UTF-8: {e}"))
            })?;
            let round = text.trim().parse::<u64>().map_err(|e| {
                CatchpointError::DecodeError(format!("state-round marker {text:?}: {e}"))
            })?;
            return Ok(Some(round));
        }
        if path.starts_with(BALANCES_PREFIX) {
            return Ok(None);
        }
    }
    Ok(None)
}

/// Maximum allowed size for a single tar entry (2 GiB).
///
/// go-algorand's V8 writer allows `balances.N.msgpack` chunks to grow to
/// roughly 2 GiB when a chunk contains many large app resources, so 256 MiB
/// is too low. We match Go's practical upper bound here.
const MAX_ENTRY_SIZE: usize = 2 * 1024 * 1024 * 1024;

/// Maximum allowed size for decompressed Snappy output (2 GiB).
///
/// Without this bound, a crafted or corrupted Snappy stream could expand a
/// small compressed payload into many gigabytes, exhausting memory.
const MAX_DECOMPRESSED_SIZE: usize = 2 * 1024 * 1024 * 1024;

/// Read the full contents of a tar entry into a `Vec<u8>`.
fn read_entry_bytes<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<Vec<u8>, CatchpointError> {
    let size = entry.header().size().map_err(CatchpointError::Io)? as usize;
    if size > MAX_ENTRY_SIZE {
        return Err(CatchpointError::IntegrityError(format!(
            "tar entry too large: {} bytes",
            size
        )));
    }
    let mut buf = vec![0u8; size];
    entry.read_exact(&mut buf)?;
    Ok(buf)
}

/// Process a single tar entry, returning a [`CatchpointEntry`] if recognized.
fn process_entry<R: Read>(
    entry: &mut tar::Entry<'_, R>,
    cached_header: &mut Option<CatchpointFileHeader>,
) -> Result<Option<CatchpointEntry>, CatchpointError> {
    let path = entry
        .path()
        .map_err(CatchpointError::Io)?
        .to_string_lossy()
        .into_owned();

    if path == CONTENT_FILENAME {
        let data = read_entry_bytes(entry)?;
        let header: CatchpointFileHeader = rmp_serde::from_slice(&data)
            .map_err(|e| CatchpointError::DecodeError(format!("header msgpack: {e}")))?;

        // V6, V7, and V8 (issues #752, #766) are supported: this crate's
        // chunk/SP-verification handling is driven entirely by which tar
        // entries are actually present, not by the header version field, so
        // a V6 file (no SP-verification entry, no online-accounts entries)
        // parses the same way a V8 file with both features disabled already
        // does. V5 (predating the accounts/resources schema split) is out
        // of scope -- see issue #766's "V5 support" acceptance criterion.
        if header.version != CATCHPOINT_FILE_VERSION_V6
            && header.version != CATCHPOINT_FILE_VERSION_V7
            && header.version != CATCHPOINT_FILE_VERSION_V8
        {
            return Err(CatchpointError::UnsupportedVersion(header.version));
        }

        *cached_header = Some(header.clone());
        Ok(Some(CatchpointEntry::Header(header)))
    } else if path == SP_VERIFICATION_FILENAME {
        let data = read_entry_bytes(entry)?;
        Ok(Some(CatchpointEntry::StateProofVerification(data)))
    } else if path.starts_with(BALANCES_PREFIX) && path.ends_with(BALANCES_SUFFIX) {
        let raw_data = read_entry_bytes(entry)?;

        // Chunk data may be Snappy-frame-compressed. Detect and decompress if so.
        let decoded_data = snappy_decompress_if_needed(raw_data)?;

        let mut chunk: CatchpointSnapshotChunkV6 = rmp_serde::from_slice(&decoded_data)
            .map_err(|e| CatchpointError::DecodeError(format!("chunk msgpack: {e}")))?;

        patch_msgp_raw_fields_for_non_utf8_strings(&decoded_data, &mut chunk)?;

        Ok(Some(CatchpointEntry::Chunk(chunk)))
    } else {
        tracing::debug!("catchpoint: skipping unknown tar entry: {}", path);
        Ok(None)
    }
}

/// Issue #1636 (seventh investigation round): fix up any `msgp.Raw`-typed
/// field (`BalanceRecordV6.account_data`/`.resources[*]`,
/// `OnlineAccountRecordV6.data`, `OnlineRoundParamsRecordV6.data`) whose
/// raw bytes the primary `rmp_serde::from_slice::<CatchpointSnapshotChunkV6>`
/// decode above got wrong for a msgpack `str` field containing non-UTF8
/// bytes (real Algorand app local-state/box keys are arbitrary
/// smart-contract-chosen bytes with no UTF-8 guarantee).
///
/// Root cause: `rmp_serde`'s `Deserializer` (`rmp-serde-1.3.1/src/decode.rs`
/// `read_str_data`), when it hits a `str` marker whose payload fails UTF-8
/// validation, calls `visitor.visit_bytes(buf)` as a fallback — the exact
/// same visitor method it would call for a genuine `bin` field. By the time
/// this reaches `rmpv::Value`'s own `Deserialize` impl (used by
/// `types::deserialize_msgp_raw`/`deserialize_msgp_raw_map`), the two cases
/// are indistinguishable and both become `Value::Binary`, which re-encodes
/// using the `bin` type marker — silently rewriting the original `str8`
/// (`0xd9`)/`str16`/`str32` marker byte to `bin8` (`0xc4`)/`bin16`/`bin32`,
/// changing the raw bytes go-algorand's `AccountHashBuilderV6`/
/// `ResourcesHashBuilderV6`/`KvHashBuilderV6` hash over (go's own encoder
/// always uses `str` for a Go `string` field regardless of UTF-8 validity,
/// and never re-decodes+re-encodes these fields at all — it hashes the
/// original wire bytes directly). This is NOT specific to `rmpv::Value`'s
/// re-encoder (already hardened by `types::write_value_str_preserving`) —
/// the corruption happens one step earlier, during `rmp_serde`'s decode
/// itself, before any of this crate's re-encoding logic ever runs, so no
/// amount of fixing the re-encoder alone can recover the lost type-marker
/// information.
///
/// The fix: `rmpv::decode::read_value` (used directly on the same
/// `decoded_data` bytes, bypassing `rmp_serde`/serde's `Deserializer`
/// abstraction entirely) does NOT have this hazard — it reads the msgpack
/// `str`/`bin` markers directly and faithfully preserves an invalid-UTF8
/// `str` as `Value::String` with its raw bytes recoverable via
/// `Utf8String::as_bytes()` (see `types::write_value_str_preserving`'s doc
/// comment and the issue #1636 seventh-round unit tests for the byte-level
/// proof). So: decode the identical `decoded_data` a second time via
/// `rmpv::decode::read_value` into a faithful `Value` tree, walk it to find
/// each `msgp.Raw` field's *already-correct* sub-`Value` by direct map/array
/// navigation (never through another `Deserializer`/`Visitor` round trip,
/// which would reintroduce the exact same ambiguity — `rmpv::Value`'s own
/// `impl Deserializer for Value` has the identical `visit_byte_buf`
/// collapse), re-encode each one with `write_value_str_preserving`, and
/// overwrite the (possibly-wrong) bytes the primary decode produced.
///
/// A second full decode of every chunk is a real cost, but this runs once
/// per catchpoint import (not a hot per-round path), and correctness of the
/// hashed bytes is non-negotiable for a consensus-critical catchpoint
/// label — see issue #1636's seventh investigation round for the
/// cross-implementation evidence (against go-algorand's own reference
/// import code, on identical real mainnet catchpoint bytes) that pinned
/// this down as the actual root cause of a deterministic wrong-label bug.
fn patch_msgp_raw_fields_for_non_utf8_strings(
    decoded_data: &[u8],
    chunk: &mut CatchpointSnapshotChunkV6,
) -> Result<(), CatchpointError> {
    let native = rmpv::decode::read_value(&mut &decoded_data[..])
        .map_err(|e| CatchpointError::DecodeError(format!("chunk msgpack (native pass): {e}")))?;
    let Some(map) = native.as_map() else {
        return Ok(());
    };

    let reencode = |v: &rmpv::Value| -> Result<Vec<u8>, CatchpointError> {
        let mut buf = Vec::new();
        super::types::write_value_str_preserving(&mut buf, v).map_err(|e| {
            CatchpointError::DecodeError(format!("re-encode msgp.Raw field (native pass): {e}"))
        })?;
        Ok(buf)
    };

    if let Some(bl) = map_get(map, "bl").and_then(|v| v.as_array()) {
        for (i, native_balance) in bl.iter().enumerate() {
            let Some(balance) = chunk.balances.get_mut(i) else {
                break;
            };
            let Some(bmap) = native_balance.as_map() else {
                continue;
            };
            if let Some(b) = map_get(bmap, "b") {
                balance.account_data = serde_bytes::ByteBuf::from(reencode(b)?);
            }
            if let Some(c) = map_get(bmap, "c").and_then(|v| v.as_map()) {
                for (k, v) in c {
                    if let Some(aidx) = k.as_u64() {
                        if let Some(existing) = balance.resources.get_mut(&aidx) {
                            *existing = serde_bytes::ByteBuf::from(reencode(v)?);
                        }
                    }
                }
            }
        }
    }

    if let Some(oa) = map_get(map, "oa").and_then(|v| v.as_array()) {
        for (i, native_oa) in oa.iter().enumerate() {
            let Some(rec) = chunk.online_accounts.get_mut(i) else {
                break;
            };
            if let Some(data) = native_oa.as_map().and_then(|m| map_get(m, "data")) {
                rec.data = serde_bytes::ByteBuf::from(reencode(data)?);
            }
        }
    }

    if let Some(orp) = map_get(map, "orp").and_then(|v| v.as_array()) {
        for (i, native_orp) in orp.iter().enumerate() {
            let Some(rec) = chunk.online_round_params.get_mut(i) else {
                break;
            };
            if let Some(data) = native_orp.as_map().and_then(|m| map_get(m, "data")) {
                rec.data = serde_bytes::ByteBuf::from(reencode(data)?);
            }
        }
    }

    Ok(())
}

/// Look up a string key in a decoded `rmpv::Value::Map`'s entry list.
fn map_get<'a>(map: &'a [(rmpv::Value, rmpv::Value)], key: &str) -> Option<&'a rmpv::Value> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
}

/// If `data` starts with a Snappy framing stream identifier, decompress it.
/// Otherwise return the data as-is (plain msgpack).
///
/// Takes ownership of `data` to avoid an unnecessary copy in the common
/// (non-Snappy) path.
fn snappy_decompress_if_needed(data: Vec<u8>) -> Result<Vec<u8>, CatchpointError> {
    if data.is_empty() {
        return Ok(data);
    }

    // Snappy framing format starts with stream identifier chunk:
    // byte 0xff + 3-byte LE length (0x06, 0x00, 0x00) + "sNaPpY"
    if data.len() >= 10 && data[0] == 0xff && &data[1..10] == b"\x06\x00\x00sNaPpY" {
        let decoder = snap::read::FrameDecoder::new(data.as_slice());
        // Bound the decompressed output to prevent memory exhaustion from
        // crafted or corrupted Snappy streams.
        let mut limited = decoder.take(MAX_DECOMPRESSED_SIZE as u64 + 1);
        let mut decompressed = Vec::new();
        limited
            .read_to_end(&mut decompressed)
            .map_err(|e| CatchpointError::SnappyError(e.to_string()))?;
        if decompressed.len() > MAX_DECOMPRESSED_SIZE {
            return Err(CatchpointError::IntegrityError(format!(
                "Snappy decompressed output too large: exceeded {} bytes",
                MAX_DECOMPRESSED_SIZE
            )));
        }
        Ok(decompressed)
    } else {
        // Not Snappy-compressed; already plain msgpack. Return owned vec directly.
        Ok(data)
    }
}
