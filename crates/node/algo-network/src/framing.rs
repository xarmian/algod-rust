//! WebSocket message framing.
//!
//! go-algorand's wire format is simple: each WebSocket binary message starts
//! with a 2-byte ASCII tag followed by the payload bytes.  The WebSocket
//! layer already provides message boundaries, so no length prefix is needed.
//!
//! Reference: `go-algorand/network/wsPeer.go` readLoop / writeLoop.

use crate::tag::{Tag, TAG_LENGTH};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur when encoding or decoding a framed network message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    /// The frame is shorter than the minimum tag length.
    FrameTooShort { len: usize },
    /// The 2-byte tag prefix does not match any known tag.
    InvalidTag { bytes: [u8; 2] },
    /// The payload exceeds the per-tag maximum message size.
    PayloadTooLarge { tag: Tag, size: usize, max: usize },
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::FrameTooShort { len } => {
                write!(
                    f,
                    "frame too short: need at least {} bytes, got {}",
                    TAG_LENGTH, len
                )
            }
            NetworkError::InvalidTag { bytes } => {
                write!(
                    f,
                    "unknown tag bytes: [{:#04x}, {:#04x}]",
                    bytes[0], bytes[1]
                )
            }
            NetworkError::PayloadTooLarge { tag, size, max } => {
                write!(
                    f,
                    "payload too large for tag {}: {} bytes exceeds max {}",
                    tag, size, max
                )
            }
        }
    }
}

impl std::error::Error for NetworkError {}

// ---------------------------------------------------------------------------
// Encode / Decode
// ---------------------------------------------------------------------------

/// Encode a tagged message into a frame suitable for sending over a WebSocket.
///
/// The returned `Vec<u8>` contains the 2-byte tag followed by `payload`.
/// Returns an error if the payload exceeds the tag's maximum message size.
pub fn encode_frame(tag: &Tag, payload: &[u8]) -> Result<Vec<u8>, NetworkError> {
    let max = tag.max_message_size();
    if payload.len() > max {
        return Err(NetworkError::PayloadTooLarge {
            tag: *tag,
            size: payload.len(),
            max,
        });
    }

    let tag_bytes = tag.as_bytes();
    let mut frame = Vec::with_capacity(TAG_LENGTH + payload.len());
    frame.extend_from_slice(&tag_bytes);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Decode a raw WebSocket binary message into a `(Tag, payload)` pair.
///
/// The first 2 bytes are interpreted as a tag; the remainder is the payload.
/// Returns an error if the frame is too short, the tag is unrecognised, or
/// the payload exceeds the tag's per-message size limit.
pub fn decode_frame(data: &[u8]) -> Result<(Tag, &[u8]), NetworkError> {
    if data.len() < TAG_LENGTH {
        return Err(NetworkError::FrameTooShort { len: data.len() });
    }

    let tag_bytes: [u8; 2] = [data[0], data[1]];
    let tag = Tag::from_bytes(&tag_bytes).ok_or(NetworkError::InvalidTag { bytes: tag_bytes })?;

    let payload = &data[TAG_LENGTH..];
    let max = tag.max_message_size();
    if payload.len() > max {
        return Err(NetworkError::PayloadTooLarge {
            tag,
            size: payload.len(),
            max,
        });
    }

    Ok((tag, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let payload = b"hello world";
        let frame = encode_frame(&Tag::Transaction, payload).unwrap();
        assert_eq!(&frame[..2], b"TX");
        assert_eq!(&frame[2..], payload);

        let (tag, decoded_payload) = decode_frame(&frame).unwrap();
        assert_eq!(tag, Tag::Transaction);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn encode_empty_payload() {
        let frame = encode_frame(&Tag::MsgOfInterest, b"").unwrap();
        assert_eq!(frame, b"MI");

        let (tag, payload) = decode_frame(&frame).unwrap();
        assert_eq!(tag, Tag::MsgOfInterest);
        assert!(payload.is_empty());
    }

    #[test]
    fn decode_frame_too_short() {
        assert_eq!(
            decode_frame(b""),
            Err(NetworkError::FrameTooShort { len: 0 })
        );
        assert_eq!(
            decode_frame(b"A"),
            Err(NetworkError::FrameTooShort { len: 1 })
        );
    }

    #[test]
    fn decode_unknown_tag() {
        let data = b"ZZhello";
        assert_eq!(
            decode_frame(data),
            Err(NetworkError::InvalidTag { bytes: *b"ZZ" })
        );
    }

    #[test]
    fn encode_payload_too_large() {
        // MsgOfInterest max is 48 bytes
        let payload = vec![0u8; 49];
        let result = encode_frame(&Tag::MsgOfInterest, &payload);
        assert_eq!(
            result,
            Err(NetworkError::PayloadTooLarge {
                tag: Tag::MsgOfInterest,
                size: 49,
                max: 48,
            })
        );
    }

    #[test]
    fn decode_payload_too_large() {
        // Build a frame with tag MI but 49 bytes of payload
        let mut frame = Vec::new();
        frame.extend_from_slice(b"MI");
        frame.extend_from_slice(&[0u8; 49]);

        let result = decode_frame(&frame);
        assert_eq!(
            result,
            Err(NetworkError::PayloadTooLarge {
                tag: Tag::MsgOfInterest,
                size: 49,
                max: 48,
            })
        );
    }

    #[test]
    fn encode_at_max_boundary() {
        // UniEnsBlockReq max is 67 bytes -- encoding exactly 67 should succeed
        let payload = vec![0u8; 67];
        assert!(encode_frame(&Tag::UniEnsBlockReq, &payload).is_ok());

        // One byte over should fail
        let payload_over = vec![0u8; 68];
        assert!(encode_frame(&Tag::UniEnsBlockReq, &payload_over).is_err());
    }

    #[test]
    fn tag_only_frame_decodes() {
        // A frame with just the 2-byte tag and no payload is valid
        let (tag, payload) = decode_frame(b"AV").unwrap();
        assert_eq!(tag, Tag::AgreementVote);
        assert!(payload.is_empty());
    }

    #[test]
    fn network_error_display() {
        let e = NetworkError::FrameTooShort { len: 1 };
        assert!(e.to_string().contains("too short"));

        let e = NetworkError::InvalidTag { bytes: *b"ZZ" };
        assert!(e.to_string().contains("unknown tag"));

        let e = NetworkError::PayloadTooLarge {
            tag: Tag::Transaction,
            size: 100,
            max: 50,
        };
        assert!(e.to_string().contains("too large"));
    }
}
