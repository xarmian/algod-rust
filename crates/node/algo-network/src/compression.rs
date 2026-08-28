//! Zstd compression and decompression for network payloads.
//!
//! Mirrors the zstd compression used by go-algorand's `network/msgCompressor.go`.
//! Proposals (PP tag) are compressed with zstd; this module provides the
//! primitives for compressing and decompressing arbitrary payloads.

use std::io::{self, Read};
use thiserror::Error;

/// Zstd frame magic bytes (RFC 8878 §3.1.1).
/// Also defined in go-algorand as `zstdCompressionMagic`.
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

/// Maximum decompressed message size. Protects against zip bombs. Matches
/// go-algorand v4.7.4-stable's `MaxDecompressedMessageSize`
/// (`network/msgCompressor.go`), which is `protocol.ProposalPayloadTagMaxSize`
/// (`protocol/tags.go`: `const ProposalPayloadTagMaxSize = 0x501e3a`) — the
/// actual maximum size a legitimate compressed gossip message (a proposal
/// payload) can decompress to, tightened from a flat 20 MiB "some large
/// enough value" in earlier go-algorand versions.
pub const MAX_DECOMPRESSED_MESSAGE_SIZE: usize = 0x501e3a;

/// Compression level matching go-algorand's `zstd.BestSpeed` (level 1).
const ZSTD_COMPRESSION_LEVEL: i32 = 1;

/// Errors that can occur during compression or decompression.
#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("zstd compression failed: {0}")]
    CompressFailed(io::Error),

    #[error("zstd decompression failed: {0}")]
    DecompressFailed(io::Error),

    #[error("decompressed data exceeds maximum size of {max_size} bytes")]
    DecompressedTooLarge { max_size: usize },
}

/// Returns `true` if `data` begins with the zstd frame magic bytes.
pub fn is_zstd_compressed(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == ZSTD_MAGIC
}

/// Compress `data` using zstd at the same level as go-algorand (BestSpeed = 1).
pub fn zstd_compress(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    zstd::stream::encode_all(data, ZSTD_COMPRESSION_LEVEL).map_err(CompressionError::CompressFailed)
}

/// Decompress zstd-compressed `data` with a maximum output size guard.
///
/// If the decompressed output would exceed `max_size` bytes, returns
/// [`CompressionError::DecompressedTooLarge`] to protect against zip bombs.
pub fn zstd_decompress(data: &[u8], max_size: usize) -> Result<Vec<u8>, CompressionError> {
    let mut decoder =
        zstd::stream::read::Decoder::new(data).map_err(CompressionError::DecompressFailed)?;

    // Read in chunks, enforcing the size limit.
    let mut output = Vec::with_capacity(data.len().min(max_size));
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(CompressionError::DecompressFailed)?;
        if n == 0 {
            break;
        }
        if output.len() + n > max_size {
            return Err(CompressionError::DecompressedTooLarge { max_size });
        }
        output.extend_from_slice(&buf[..n]);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes_match_zstd_standard() {
        // RFC 8878 §3.1.1 defines the magic number as 0xFD2FB528 (little-endian).
        assert_eq!(ZSTD_MAGIC, [0x28, 0xb5, 0x2f, 0xfd]);
    }

    #[test]
    fn round_trip() {
        let original = b"hello world, this is some data to compress and decompress!";
        let compressed = zstd_compress(original).expect("compress");
        let decompressed =
            zstd_decompress(&compressed, MAX_DECOMPRESSED_MESSAGE_SIZE).expect("decompress");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn round_trip_empty() {
        let original = b"";
        let compressed = zstd_compress(original).expect("compress");
        let decompressed =
            zstd_decompress(&compressed, MAX_DECOMPRESSED_MESSAGE_SIZE).expect("decompress");
        assert_eq!(decompressed, original.as_slice());
    }

    #[test]
    fn is_zstd_compressed_positive() {
        let data = b"some payload data";
        let compressed = zstd_compress(data).expect("compress");
        assert!(is_zstd_compressed(&compressed));
    }

    #[test]
    fn is_zstd_compressed_negative() {
        assert!(!is_zstd_compressed(b"not compressed"));
        assert!(!is_zstd_compressed(b"abc"));
        assert!(!is_zstd_compressed(b""));
        // Wrong magic
        assert!(!is_zstd_compressed(&[0x00, 0xb5, 0x2f, 0xfd]));
    }

    #[test]
    fn decompress_non_zstd_data_fails() {
        let result = zstd_decompress(b"this is not zstd data", MAX_DECOMPRESSED_MESSAGE_SIZE);
        assert!(matches!(result, Err(CompressionError::DecompressFailed(_))));
    }

    #[test]
    fn decompress_too_large_rejected() {
        // Create a payload that compresses well but decompresses to more than our tiny limit.
        let original = vec![0u8; 1024];
        let compressed = zstd_compress(&original).expect("compress");
        // Try to decompress with a very small max_size.
        let result = zstd_decompress(&compressed, 100);
        assert!(matches!(
            result,
            Err(CompressionError::DecompressedTooLarge { max_size: 100 })
        ));
    }

    #[test]
    fn max_decompressed_message_size_matches_go() {
        // go-algorand v4.7.4-stable: MaxDecompressedMessageSize =
        // protocol.ProposalPayloadTagMaxSize (protocol/tags.go: `const
        // ProposalPayloadTagMaxSize = 0x501e3a`), tightened from a flat
        // 20 MiB "some large enough value" to the actual maximum size a
        // legitimate compressed gossip message (a proposal payload) can
        // decompress to.
        assert_eq!(MAX_DECOMPRESSED_MESSAGE_SIZE, 0x501e3a);
        assert_eq!(MAX_DECOMPRESSED_MESSAGE_SIZE, 5_250_618);
    }

    #[test]
    fn decompress_between_old_and_new_bound_now_rejected() {
        // A payload between the old 20 MiB bound and the new ~5 MiB bound
        // must now be rejected as too large, where it previously succeeded.
        let original = vec![0u8; 6 * 1024 * 1024]; // 6 MiB: below old bound, above new bound
        let compressed = zstd_compress(&original).expect("compress");
        let result = zstd_decompress(&compressed, MAX_DECOMPRESSED_MESSAGE_SIZE);
        assert!(matches!(
            result,
            Err(CompressionError::DecompressedTooLarge { max_size }) if max_size == MAX_DECOMPRESSED_MESSAGE_SIZE
        ));
    }

    #[test]
    fn compressed_data_starts_with_magic() {
        let compressed = zstd_compress(b"test data").expect("compress");
        assert_eq!(&compressed[..4], &ZSTD_MAGIC);
    }

    #[test]
    fn large_payload_round_trip() {
        // ~1 MiB of data with a pattern.
        let original: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
        let compressed = zstd_compress(&original).expect("compress");
        // Compressed should be smaller for patterned data.
        assert!(compressed.len() < original.len());
        let decompressed =
            zstd_decompress(&compressed, MAX_DECOMPRESSED_MESSAGE_SIZE).expect("decompress");
        assert_eq!(decompressed, original);
    }
}
