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
    CatchpointError, CatchpointFileHeader, CatchpointSnapshotChunkV6, CATCHPOINT_FILE_VERSION_V8,
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

/// Maximum allowed size for a single tar entry (256 MB).
const MAX_ENTRY_SIZE: usize = 256 * 1024 * 1024;

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

        // Intentionally only V8 (current go-algorand format) is supported.
        // V6/V7 support could be added later if needed for historical catchpoints.
        if header.version != CATCHPOINT_FILE_VERSION_V8 {
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

        let chunk: CatchpointSnapshotChunkV6 = rmp_serde::from_slice(&decoded_data)
            .map_err(|e| CatchpointError::DecodeError(format!("chunk msgpack: {e}")))?;

        Ok(Some(CatchpointEntry::Chunk(chunk)))
    } else {
        tracing::debug!("catchpoint: skipping unknown tar entry: {}", path);
        Ok(None)
    }
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
        let mut decoder = snap::read::FrameDecoder::new(data.as_slice());
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| CatchpointError::SnappyError(e.to_string()))?;
        Ok(decompressed)
    } else {
        // Not Snappy-compressed; already plain msgpack. Return owned vec directly.
        Ok(data)
    }
}
