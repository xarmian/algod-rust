//! Peer identity challenge-response protocol.
//!
//! Implements the 3-message identity challenge exchange from
//! go-algorand `network/netidentity.go`. This protocol identifies
//! redundant connections between peers and prevents them.
//!
//! ## Protocol Flow
//!
//! 1. **Identity Challenge** (HTTP request header `X-Algorand-IdentityChallenge`):
//!    the initiator sends a signed `identityChallengeSigned` containing:
//!    - its ed25519 public key (`pk`)
//!    - a random 32-byte challenge (`c`)
//!    - the intended recipient's public address (`a`)
//!
//! 2. **Identity Challenge Response** (HTTP response header):
//!    the responder sends a signed `identityChallengeResponseSigned` containing:
//!    - its ed25519 public key (`pk`)
//!    - the original challenge echoed back (`c`)
//!    - a new 32-byte response challenge (`rc`)
//!
//! 3. **Identity Verification** (websocket message with `NI` tag):
//!    the initiator sends a signed `identityVerificationMessageSigned` containing:
//!    - the response challenge from Message 2 (`rc`)
//!
//! ## Signing Protocol (Go conformance)
//!
//! Go's `SignatureSecrets.Sign(message Hashable)` calls:
//!   `SignBytes(HashRep(message))`
//! where `HashRep(h)` = `hashid || protocol.Encode(h)` (raw concatenation, NOT hashed).
//! `SignBytes` calls raw `ed25519Sign` which applies SHA-512 internally.
//!
//! So the signed payload is: `ed25519_sign(sk, prefix || msgpack_canonical(msg))`
//!
//! Reference: `../go-algorand/crypto/curve25519.go` lines 224-227,
//!            `../go-algorand/crypto/util.go` lines 38-41.
//!
//! ## Canonical Encoding (Go conformance)
//!
//! Go uses code-generated msgp serialization with sorted map keys and
//! `omitempty` semantics. Our canonical encoding functions produce
//! byte-identical output to Go's `MarshalMsg` methods.
//!
//! Reference: `../go-algorand/network/msgp_gen.go`

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::errors::IdentityError;

// ---------------------------------------------------------------------------
// Constants — sourced directly from go-algorand
// ---------------------------------------------------------------------------

// Re-export from handshake module for backward compatibility.
pub use crate::handshake::IDENTITY_CHALLENGE_HEADER;

/// Hash domain prefix for identity challenges.
/// Go: `protocol.NetIdentityChallenge` = `"NIC"` in `protocol/hash.go` line 52.
const HASH_ID_CHALLENGE: &[u8] = b"NIC";

/// Hash domain prefix for identity challenge responses.
/// Go: `protocol.NetIdentityChallengeResponse` = `"NIR"` in `protocol/hash.go` line 53.
const HASH_ID_CHALLENGE_RESPONSE: &[u8] = b"NIR";

/// Hash domain prefix for identity verification messages.
/// Go: `protocol.NetIdentityVerificationMessage` = `"NIV"` in `protocol/hash.go` line 54.
const HASH_ID_VERIFICATION: &[u8] = b"NIV";

/// Network tag prefix for identity verification messages sent over websocket.
/// Go: `protocol.NetIDVerificationTag` = `"NI"` in `protocol/tags.go` line 35.
const NET_ID_VERIFICATION_TAG: &[u8] = b"NI";

/// Size of a challenge value in bytes.
/// Go: `identityChallengeValue` = `[32]byte` in `network/netidentity.go` line 84.
const CHALLENGE_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Wire types (msgpack-serializable, field names from Go codec tags)
// ---------------------------------------------------------------------------

/// A 32-byte random challenge value used in the identity exchange.
/// Go: `identityChallengeValue [32]byte` in `network/netidentity.go` line 84.
pub type IdentityChallengeValue = [u8; CHALLENGE_SIZE];

/// The initial challenge message (Message 1).
///
/// Go struct (netidentity.go lines 306-312):
/// ```go
/// type identityChallenge struct {
///     _struct       struct{}              `codec:",omitempty,omitemptyarray"`
///     Key           crypto.PublicKey       `codec:"pk"`
///     Challenge     identityChallengeValue `codec:"c"`
///     PublicAddress []byte                 `codec:"a,allocbound=maxAddressLen"`
/// }
/// ```
///
/// Canonical field order (sorted): `a`, `c`, `pk`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityChallenge {
    /// Sender's ed25519 public key (32 bytes). Go codec tag: `pk`.
    #[serde(rename = "pk", with = "serde_bytes")]
    pub key: Vec<u8>,

    /// 32-byte random challenge. Go codec tag: `c`.
    #[serde(rename = "c", with = "serde_bytes")]
    pub challenge: Vec<u8>,

    /// Public address of the intended recipient. Go codec tag: `a`.
    /// Omitted when empty (omitempty).
    #[serde(
        rename = "a",
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "serde_bytes"
    )]
    pub public_address: Vec<u8>,
}

/// A signed identity challenge (Message 1 wire format).
///
/// Go struct (netidentity.go lines 316-321):
/// ```go
/// type identityChallengeSigned struct {
///     _struct   struct{}           `codec:",omitempty,omitemptyarray"`
///     Msg       identityChallenge  `codec:"ic"`
///     Signature crypto.Signature   `codec:"sig"`
/// }
/// ```
///
/// Canonical field order (sorted): `ic`, `sig`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityChallengeSigned {
    /// The unsigned challenge message. Go codec tag: `ic`.
    #[serde(rename = "ic")]
    pub msg: IdentityChallenge,

    /// Ed25519 signature over `"NIC" || canonical_encode(msg)`. Go codec tag: `sig`.
    #[serde(rename = "sig", with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// The challenge response message (Message 2).
///
/// Go struct (netidentity.go lines 325-331):
/// ```go
/// type identityChallengeResponse struct {
///     _struct           struct{}              `codec:",omitempty,omitemptyarray"`
///     Key               crypto.PublicKey       `codec:"pk"`
///     Challenge         identityChallengeValue `codec:"c"`
///     ResponseChallenge identityChallengeValue `codec:"rc"`
/// }
/// ```
///
/// Canonical field order (sorted): `c`, `pk`, `rc`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityChallengeResponse {
    /// Responder's ed25519 public key (32 bytes). Go codec tag: `pk`.
    #[serde(rename = "pk", with = "serde_bytes")]
    pub key: Vec<u8>,

    /// Original challenge echoed back. Go codec tag: `c`.
    #[serde(rename = "c", with = "serde_bytes")]
    pub challenge: Vec<u8>,

    /// New 32-byte response challenge. Go codec tag: `rc`.
    #[serde(rename = "rc", with = "serde_bytes")]
    pub response_challenge: Vec<u8>,
}

/// A signed identity challenge response (Message 2 wire format).
///
/// Go struct (netidentity.go lines 333-338):
/// ```go
/// type identityChallengeResponseSigned struct {
///     _struct   struct{}                   `codec:",omitempty,omitemptyarray"`
///     Msg       identityChallengeResponse  `codec:"icr"`
///     Signature crypto.Signature           `codec:"sig"`
/// }
/// ```
///
/// Canonical field order (sorted): `icr`, `sig`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityChallengeResponseSigned {
    /// The unsigned response message. Go codec tag: `icr`.
    #[serde(rename = "icr")]
    pub msg: IdentityChallengeResponse,

    /// Ed25519 signature over `"NIR" || canonical_encode(msg)`. Go codec tag: `sig`.
    #[serde(rename = "sig", with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// The verification message (Message 3).
///
/// Go struct (netidentity.go lines 340-344):
/// ```go
/// type identityVerificationMessage struct {
///     _struct           struct{}              `codec:",omitempty,omitemptyarray"`
///     ResponseChallenge identityChallengeValue `codec:"rc"`
/// }
/// ```
///
/// Canonical field order: `rc`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityVerificationMessage {
    /// Response challenge from Message 2. Go codec tag: `rc`.
    #[serde(rename = "rc", with = "serde_bytes")]
    pub response_challenge: Vec<u8>,
}

/// A signed identity verification message (Message 3 wire format).
///
/// Go struct (netidentity.go lines 346-351):
/// ```go
/// type identityVerificationMessageSigned struct {
///     _struct   struct{}                      `codec:",omitempty,omitemptyarray"`
///     Msg       identityVerificationMessage   `codec:"ivm"`
///     Signature crypto.Signature              `codec:"sig"`
/// }
/// ```
///
/// Canonical field order (sorted): `ivm`, `sig`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityVerificationMessageSigned {
    /// The unsigned verification message. Go codec tag: `ivm`.
    #[serde(rename = "ivm")]
    pub msg: IdentityVerificationMessage,

    /// Ed25519 signature over `"NIV" || canonical_encode(msg)`. Go codec tag: `sig`.
    #[serde(rename = "sig", with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Identity information extracted after a successful challenge exchange.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// The peer's verified ed25519 public key.
    pub public_key: VerifyingKey,

    /// The peer's declared public address, if provided in the initial challenge.
    pub public_address: Option<String>,
}

// ---------------------------------------------------------------------------
// Canonical msgpack encoding — matches Go's msgp-generated MarshalMsg
// ---------------------------------------------------------------------------
//
// Go's algorand msgp encoding uses:
// - Map with string keys, sorted lexicographically
// - `omitempty`: zero-valued fields are omitted
//   - PublicKey [32]byte: omitted if all zeros (MsgIsZero checks == PublicKey{})
//   - Signature [64]byte: omitted if all zeros (MsgIsZero checks == Signature{})
//   - identityChallengeValue [32]byte: omitted if == identityChallengeValue{}
//   - []byte: omitted if len == 0
// - Binary fields ([32]byte, [64]byte, []byte) encoded via msgp.AppendBytes = msgpack bin format
//
// Reference: ../go-algorand/network/msgp_gen.go, ../go-algorand/crypto/msgp_gen.go

/// Encode an `IdentityChallenge` in Go-canonical msgpack format.
///
/// Go field order (sorted): `a`, `c`, `pk`
/// Reference: Go `identityChallenge.MarshalMsg` (msgp_gen.go lines 175-212)
fn canonical_encode_challenge(c: &IdentityChallenge) -> Vec<u8> {
    let mut fields: Vec<(&str, Vec<u8>)> = Vec::new();

    // "a" - PublicAddress (omit if len == 0)
    if !c.public_address.is_empty() {
        let mut buf = Vec::new();
        rmp::encode::write_bin(&mut buf, &c.public_address).unwrap();
        fields.push(("a", buf));
    }

    // "c" - Challenge (omit if all zeros: identityChallengeValue{})
    if c.challenge.iter().any(|&b| b != 0) {
        let mut buf = Vec::new();
        rmp::encode::write_bin(&mut buf, &c.challenge).unwrap();
        fields.push(("c", buf));
    }

    // "pk" - Key (omit if all zeros: PublicKey.MsgIsZero())
    if c.key.iter().any(|&b| b != 0) {
        let mut buf = Vec::new();
        rmp::encode::write_bin(&mut buf, &c.key).unwrap();
        fields.push(("pk", buf));
    }

    // Keys are already in sorted order: "a" < "c" < "pk"
    encode_map(&fields)
}

/// Encode an `IdentityChallengeSigned` in Go-canonical msgpack format.
///
/// Go field order (sorted): `ic`, `sig`
/// Reference: Go `identityChallengeSigned.MarshalMsg` (msgp_gen.go lines 678-706)
fn canonical_encode_challenge_signed(cs: &IdentityChallengeSigned) -> Vec<u8> {
    let mut fields: Vec<(&str, Vec<u8>)> = Vec::new();

    // "ic" - Msg (omit if MsgIsZero: all subfields zero/empty)
    let msg_bytes = canonical_encode_challenge(&cs.msg);
    if !is_zero_map(&msg_bytes) {
        fields.push(("ic", msg_bytes));
    }

    // "sig" - Signature (omit if all zeros: Signature.MsgIsZero())
    if cs.signature.iter().any(|&b| b != 0) {
        let mut buf = Vec::new();
        rmp::encode::write_bin(&mut buf, &cs.signature).unwrap();
        fields.push(("sig", buf));
    }

    encode_map(&fields)
}

/// Encode an `IdentityChallengeResponse` in Go-canonical msgpack format.
///
/// Go field order (sorted): `c`, `pk`, `rc`
/// Reference: Go `identityChallengeResponse.MarshalMsg` (msgp_gen.go lines 364-401)
fn canonical_encode_challenge_response(r: &IdentityChallengeResponse) -> Vec<u8> {
    let mut fields: Vec<(&str, Vec<u8>)> = Vec::new();

    // "c" - Challenge (omit if all zeros)
    if r.challenge.iter().any(|&b| b != 0) {
        let mut buf = Vec::new();
        rmp::encode::write_bin(&mut buf, &r.challenge).unwrap();
        fields.push(("c", buf));
    }

    // "pk" - Key (omit if all zeros)
    if r.key.iter().any(|&b| b != 0) {
        let mut buf = Vec::new();
        rmp::encode::write_bin(&mut buf, &r.key).unwrap();
        fields.push(("pk", buf));
    }

    // "rc" - ResponseChallenge (omit if all zeros)
    if r.response_challenge.iter().any(|&b| b != 0) {
        let mut buf = Vec::new();
        rmp::encode::write_bin(&mut buf, &r.response_challenge).unwrap();
        fields.push(("rc", buf));
    }

    encode_map(&fields)
}

/// Encode an `IdentityChallengeResponseSigned` in Go-canonical msgpack format.
///
/// Go field order (sorted): `icr`, `sig`
/// Reference: Go `identityChallengeResponseSigned.MarshalMsg` (msgp_gen.go lines 535-563)
fn canonical_encode_challenge_response_signed(rs: &IdentityChallengeResponseSigned) -> Vec<u8> {
    let mut fields: Vec<(&str, Vec<u8>)> = Vec::new();

    // "icr" - Msg (omit if MsgIsZero)
    let msg_bytes = canonical_encode_challenge_response(&rs.msg);
    if !is_zero_map(&msg_bytes) {
        fields.push(("icr", msg_bytes));
    }

    // "sig" - Signature (omit if all zeros)
    if rs.signature.iter().any(|&b| b != 0) {
        let mut buf = Vec::new();
        rmp::encode::write_bin(&mut buf, &rs.signature).unwrap();
        fields.push(("sig", buf));
    }

    encode_map(&fields)
}

/// Encode an `IdentityVerificationMessage` in Go-canonical msgpack format.
///
/// Go field order: `rc`
/// Reference: Go `identityVerificationMessage.MarshalMsg` (msgp_gen.go lines 875-894)
fn canonical_encode_verification_message(v: &IdentityVerificationMessage) -> Vec<u8> {
    let mut fields: Vec<(&str, Vec<u8>)> = Vec::new();

    // "rc" - ResponseChallenge (omit if all zeros)
    if v.response_challenge.iter().any(|&b| b != 0) {
        let mut buf = Vec::new();
        rmp::encode::write_bin(&mut buf, &v.response_challenge).unwrap();
        fields.push(("rc", buf));
    }

    encode_map(&fields)
}

/// Encode an `IdentityVerificationMessageSigned` in Go-canonical msgpack format.
///
/// Go field order (sorted): `ivm`, `sig`
/// Reference: Go `identityVerificationMessageSigned.MarshalMsg` (msgp_gen.go lines 997-1038)
///
/// Note: Go inlines the inner identityVerificationMessage encoding within
/// the outer MarshalMsg. The outer checks `Msg.ResponseChallenge == zero`
/// to decide whether to include the `ivm` field, and if included, encodes
/// the inner struct directly. Our approach of encoding the inner struct
/// separately then embedding is byte-equivalent.
fn canonical_encode_verification_message_signed(vs: &IdentityVerificationMessageSigned) -> Vec<u8> {
    let mut fields: Vec<(&str, Vec<u8>)> = Vec::new();

    // "ivm" - Msg (omit if inner message is zero)
    let msg_bytes = canonical_encode_verification_message(&vs.msg);
    if !is_zero_map(&msg_bytes) {
        fields.push(("ivm", msg_bytes));
    }

    // "sig" - Signature (omit if all zeros)
    if vs.signature.iter().any(|&b| b != 0) {
        let mut buf = Vec::new();
        rmp::encode::write_bin(&mut buf, &vs.signature).unwrap();
        fields.push(("sig", buf));
    }

    encode_map(&fields)
}

/// Encode a sorted list of (key, encoded_value) pairs as a msgpack fixmap.
///
/// Go uses `0x80 | n` for up to 15 entries (fixmap format).
fn encode_map(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let len = fields.len() as u32;

    // Use fixmap (0x80 | n) for up to 15 entries, matching Go's encoding
    if len <= 15 {
        out.push(0x80 | len as u8);
    } else {
        rmp::encode::write_map_len(&mut out, len).unwrap();
    }

    for (key, value) in fields {
        rmp::encode::write_str(&mut out, key).unwrap();
        out.extend_from_slice(value);
    }

    out
}

/// Check if an encoded msgpack map is the empty map (0x80 = fixmap with 0 entries).
fn is_zero_map(bytes: &[u8]) -> bool {
    bytes.len() == 1 && bytes[0] == 0x80
}

// ---------------------------------------------------------------------------
// Signing and verification
// ---------------------------------------------------------------------------

/// Construct the bytes-to-sign: `prefix || canonical_encode(msg)`.
///
/// This matches Go's `HashRep(message)` = `hashid || protocol.Encode(msg)`.
/// Ed25519 then signs these bytes directly (ed25519 internally applies SHA-512).
///
/// Reference: Go `crypto.HashRep` in `crypto/util.go` lines 38-41.
fn sign_payload(prefix: &[u8], canonical_msg: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(prefix.len() + canonical_msg.len());
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(canonical_msg);
    payload
}

/// Sign a message with domain-separated ed25519.
///
/// Returns the 64-byte signature over `prefix || canonical_encode(msg)`.
fn sign_message(prefix: &[u8], canonical_msg: &[u8], key: &SigningKey) -> Signature {
    let payload = sign_payload(prefix, canonical_msg);
    key.sign(&payload)
}

/// Verify a message with domain-separated ed25519.
///
/// Returns `true` if the signature is valid over `prefix || canonical_encode(msg)`.
fn verify_message(
    prefix: &[u8],
    canonical_msg: &[u8],
    signature: &Signature,
    public_key: &VerifyingKey,
) -> bool {
    let payload = sign_payload(prefix, canonical_msg);
    public_key.verify(&payload, signature).is_ok()
}

// ---------------------------------------------------------------------------
// Challenge flow functions
// ---------------------------------------------------------------------------

/// Generate a new identity challenge (Message 1).
///
/// Creates a random 32-byte challenge, signs it with our key, and returns both
/// the signed challenge and the raw challenge value (needed to verify the
/// response later).
///
/// Matches Go's `identityChallengePublicKeyScheme.AttachChallenge`.
pub fn generate_challenge(
    our_key: &SigningKey,
    public_address: &str,
) -> (IdentityChallengeSigned, IdentityChallengeValue) {
    let mut challenge = [0u8; CHALLENGE_SIZE];
    rand::thread_rng().fill_bytes(&mut challenge);

    let msg = IdentityChallenge {
        key: our_key.verifying_key().to_bytes().to_vec(),
        challenge: challenge.to_vec(),
        public_address: public_address.as_bytes().to_vec(),
    };

    let canonical = canonical_encode_challenge(&msg);
    let signature = sign_message(HASH_ID_CHALLENGE, &canonical, our_key);

    let signed = IdentityChallengeSigned {
        msg,
        signature: signature.to_bytes().to_vec(),
    };

    (signed, challenge)
}

/// Encode a signed identity challenge as a base64 string for an HTTP header.
///
/// The result is `base64(canonical_msgpack(signed_challenge))`.
/// Matches Go's `identityChallenge.signAndEncodeB64`.
pub fn attach_challenge_header(challenge_signed: &IdentityChallengeSigned) -> String {
    let encoded = canonical_encode_challenge_signed(challenge_signed);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encoded)
}

/// Decode, verify, and respond to an identity challenge from an HTTP header.
///
/// Given a base64-encoded signed challenge from the request, this function:
/// 1. Decodes and deserializes the challenge
/// 2. Verifies the signature
/// 3. Checks the public address matches one of our addresses
/// 4. Creates and signs a response with a new challenge
///
/// Returns the signed response, the response challenge value (for later
/// verification of Message 3), and the peer's public key.
///
/// Matches Go's `identityChallengePublicKeyScheme.VerifyRequestAndAttachResponse`.
///
/// ## Go error semantics:
/// - If the address doesn't match: Go returns `(empty, empty, nil)` (no error).
///   We return `Err(IdentityError::AddressNotMatched)` so the caller can
///   distinguish "proceed without identity" from a real error.
/// - If the signature is bad: Go returns error. We return `Err(IdentityError::BadSignature)`.
pub fn verify_challenge_and_respond(
    header_value: &str,
    our_key: &SigningKey,
    our_addresses: &[&str],
) -> Result<
    (
        IdentityChallengeResponseSigned,
        IdentityChallengeValue,
        VerifyingKey,
    ),
    IdentityError,
> {
    // Decode base64
    let msg_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, header_value)?;

    // Decode msgpack
    let signed: IdentityChallengeSigned = rmp_serde::from_slice(&msg_bytes)?;

    // Extract and verify the public key
    let peer_pk_bytes: [u8; 32] = signed.msg.key[..]
        .try_into()
        .map_err(|_| IdentityError::InvalidPublicKey("expected 32 bytes".into()))?;
    let peer_pk = VerifyingKey::from_bytes(&peer_pk_bytes)
        .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;

    // Verify signature: re-encode the inner message canonically and verify
    let sig_bytes: [u8; 64] = signed.signature[..]
        .try_into()
        .map_err(|_| IdentityError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let canonical = canonical_encode_challenge(&signed.msg);
    if !verify_message(HASH_ID_CHALLENGE, &canonical, &signature, &peer_pk) {
        return Err(IdentityError::BadSignature);
    }

    // Check public address matches one of ours.
    // Go (netidentity.go lines 250-252): if address doesn't match, return
    // (empty, empty, nil) -- not an error, but identity exchange is skipped.
    if !signed.msg.public_address.is_empty() {
        let addr_str = String::from_utf8_lossy(&signed.msg.public_address);
        if !our_addresses.iter().any(|a| *a == addr_str.as_ref()) {
            return Err(IdentityError::AddressNotMatched);
        }
    }

    // Generate response challenge
    let mut response_challenge = [0u8; CHALLENGE_SIZE];
    rand::thread_rng().fill_bytes(&mut response_challenge);

    let resp_msg = IdentityChallengeResponse {
        key: our_key.verifying_key().to_bytes().to_vec(),
        challenge: signed.msg.challenge.clone(),
        response_challenge: response_challenge.to_vec(),
    };

    let canonical_resp = canonical_encode_challenge_response(&resp_msg);
    let resp_signature = sign_message(HASH_ID_CHALLENGE_RESPONSE, &canonical_resp, our_key);

    let resp_signed = IdentityChallengeResponseSigned {
        msg: resp_msg,
        signature: resp_signature.to_bytes().to_vec(),
    };

    Ok((resp_signed, response_challenge, peer_pk))
}

/// Encode a signed challenge response as a base64 string for an HTTP header.
///
/// Matches Go's `identityChallengeResponse.signAndEncodeB64`.
pub fn attach_response_header(response_signed: &IdentityChallengeResponseSigned) -> String {
    let encoded = canonical_encode_challenge_response_signed(response_signed);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encoded)
}

/// Verify a challenge response from the responder (Message 2).
///
/// Given a base64-encoded signed response from the HTTP response header and the
/// original challenge value we sent, this function:
/// 1. Decodes and deserializes the response
/// 2. Checks the original challenge matches
/// 3. Verifies the responder's signature
/// 4. Builds the verification message (Message 3) to send back
///
/// Returns the peer's identity and the signed verification message.
///
/// Matches Go's `identityChallengePublicKeyScheme.VerifyResponse`.
pub fn verify_challenge_response(
    response_header: &str,
    expected_challenge: &IdentityChallengeValue,
    our_key: &SigningKey,
) -> Result<(PeerIdentity, IdentityVerificationMessageSigned), IdentityError> {
    // Decode base64
    let msg_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, response_header)?;

    // Decode msgpack
    let signed: IdentityChallengeResponseSigned = rmp_serde::from_slice(&msg_bytes)?;

    // Check original challenge matches (Go: netidentity.go line 287)
    if signed.msg.challenge.as_slice() != expected_challenge.as_slice() {
        return Err(IdentityError::ChallengeMismatch);
    }

    // Extract and verify the responder's public key
    let peer_pk_bytes: [u8; 32] = signed.msg.key[..]
        .try_into()
        .map_err(|_| IdentityError::InvalidPublicKey("expected 32 bytes".into()))?;
    let peer_pk = VerifyingKey::from_bytes(&peer_pk_bytes)
        .map_err(|e| IdentityError::InvalidPublicKey(e.to_string()))?;

    // Verify the responder's signature
    let sig_bytes: [u8; 64] = signed.signature[..]
        .try_into()
        .map_err(|_| IdentityError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let canonical = canonical_encode_challenge_response(&signed.msg);
    if !verify_message(HASH_ID_CHALLENGE_RESPONSE, &canonical, &signature, &peer_pk) {
        return Err(IdentityError::BadSignature);
    }

    // Build verification message (Message 3)
    // Go: identityChallengePublicKeyScheme.identityVerificationMessage (line 299-302)
    let ver_msg = IdentityVerificationMessage {
        response_challenge: signed.msg.response_challenge.clone(),
    };
    let canonical_ver = canonical_encode_verification_message(&ver_msg);
    let ver_signature = sign_message(HASH_ID_VERIFICATION, &canonical_ver, our_key);

    let ver_signed = IdentityVerificationMessageSigned {
        msg: ver_msg,
        signature: ver_signature.to_bytes().to_vec(),
    };

    let identity = PeerIdentity {
        public_key: peer_pk,
        public_address: None,
    };

    Ok((identity, ver_signed))
}

/// Serialize a signed verification message for sending over websocket.
///
/// Returns the wire bytes: `"NI" || canonical_msgpack(signed_verification)`.
/// Matches Go's `identityVerificationMessage` (line 300-301):
/// `append([]byte(protocol.NetIDVerificationTag), protocol.Encode(&signedMsg)...)`
pub fn build_identity_verification(verification: &IdentityVerificationMessageSigned) -> Vec<u8> {
    let encoded = canonical_encode_verification_message_signed(verification);
    let mut out = Vec::with_capacity(NET_ID_VERIFICATION_TAG.len() + encoded.len());
    out.extend_from_slice(NET_ID_VERIFICATION_TAG);
    out.extend_from_slice(&encoded);
    out
}

/// Verify a received identity verification message (Message 3).
///
/// Given the raw websocket payload (without the tag prefix) and the expected
/// response challenge, verifies the signature against the peer's public key.
///
/// Matches Go's `identityVerificationHandler` (netidentity.go lines 405-441).
pub fn verify_identity_verification(
    payload: &[u8],
    expected_challenge: &IdentityChallengeValue,
    peer_key: &VerifyingKey,
) -> Result<(), IdentityError> {
    // Decode msgpack
    let signed: IdentityVerificationMessageSigned = rmp_serde::from_slice(payload)?;

    // Check challenge matches (Go: line 421)
    if signed.msg.response_challenge.as_slice() != expected_challenge.as_slice() {
        return Err(IdentityError::ChallengeMismatch);
    }

    // Verify signature (Go: line 426)
    let sig_bytes: [u8; 64] = signed.signature[..]
        .try_into()
        .map_err(|_| IdentityError::BadSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let canonical = canonical_encode_verification_message(&signed.msg);
    if !verify_message(HASH_ID_VERIFICATION, &canonical, &signature, peer_key) {
        return Err(IdentityError::BadSignature);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Create a deterministic signing key from a seed byte.
    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    // -----------------------------------------------------------------------
    // Full protocol flow tests
    // -----------------------------------------------------------------------

    #[test]
    fn full_3_message_roundtrip() {
        let initiator_key = test_key(1);
        let responder_key = test_key(2);

        // Step 1: Initiator generates challenge
        let (challenge_signed, orig_challenge) =
            generate_challenge(&initiator_key, "responder.example.com:4160");

        // Encode for HTTP header
        let header_value = attach_challenge_header(&challenge_signed);
        assert!(!header_value.is_empty());

        // Step 2: Responder verifies and responds
        let (response_signed, response_challenge, peer_pk) = verify_challenge_and_respond(
            &header_value,
            &responder_key,
            &["responder.example.com:4160"],
        )
        .expect("challenge verification should succeed");

        assert_eq!(peer_pk, initiator_key.verifying_key());

        // Encode response for HTTP header
        let response_header = attach_response_header(&response_signed);
        assert!(!response_header.is_empty());

        // Step 3: Initiator verifies response and builds verification message
        let (identity, verification_signed) =
            verify_challenge_response(&response_header, &orig_challenge, &initiator_key)
                .expect("response verification should succeed");

        assert_eq!(identity.public_key, responder_key.verifying_key());

        // Build and verify the verification message
        let wire_bytes = build_identity_verification(&verification_signed);
        assert!(wire_bytes.starts_with(NET_ID_VERIFICATION_TAG));

        // Responder verifies Message 3
        let payload = &wire_bytes[NET_ID_VERIFICATION_TAG.len()..];
        verify_identity_verification(payload, &response_challenge, &initiator_key.verifying_key())
            .expect("verification message should be valid");
    }

    #[test]
    fn self_challenge_response_loop() {
        // Test where the same node challenges itself (mirrors Go test pattern)
        let key = test_key(5);
        let addr = "self-addr:4160";

        // Step 1: Generate challenge
        let (challenge_signed, orig_challenge) = generate_challenge(&key, addr);
        let header = attach_challenge_header(&challenge_signed);

        // Step 2: Same node responds
        let (response_signed, response_challenge, peer_pk) =
            verify_challenge_and_respond(&header, &key, &[addr])
                .expect("self-challenge should succeed");

        // Since we challenged ourselves, the peer key should be our own
        assert_eq!(peer_pk, key.verifying_key());

        let response_header = attach_response_header(&response_signed);

        // Step 3: Verify response
        let (identity, verification) =
            verify_challenge_response(&response_header, &orig_challenge, &key)
                .expect("self-response should verify");

        // Because we responded to ourselves, identity key should also be ours
        assert_eq!(identity.public_key, key.verifying_key());

        // Verify Message 3
        let wire = build_identity_verification(&verification);
        let payload = &wire[NET_ID_VERIFICATION_TAG.len()..];
        verify_identity_verification(payload, &response_challenge, &key.verifying_key())
            .expect("self-verification should succeed");
    }

    // -----------------------------------------------------------------------
    // Domain separation
    // -----------------------------------------------------------------------

    #[test]
    fn domain_separation_different_prefixes_different_signatures() {
        let key = test_key(42);

        let msg = IdentityChallenge {
            key: key.verifying_key().to_bytes().to_vec(),
            challenge: [0xAA; 32].to_vec(),
            public_address: b"test".to_vec(),
        };

        let canonical = canonical_encode_challenge(&msg);

        // Sign with different prefixes
        let sig_nic = sign_message(HASH_ID_CHALLENGE, &canonical, &key);
        let sig_nir = sign_message(HASH_ID_CHALLENGE_RESPONSE, &canonical, &key);
        let sig_niv = sign_message(HASH_ID_VERIFICATION, &canonical, &key);

        // All signatures should be different
        assert_ne!(sig_nic.to_bytes(), sig_nir.to_bytes());
        assert_ne!(sig_nic.to_bytes(), sig_niv.to_bytes());
        assert_ne!(sig_nir.to_bytes(), sig_niv.to_bytes());

        // Each should only verify with its own prefix
        let vk = key.verifying_key();
        assert!(verify_message(HASH_ID_CHALLENGE, &canonical, &sig_nic, &vk));
        assert!(!verify_message(
            HASH_ID_CHALLENGE_RESPONSE,
            &canonical,
            &sig_nic,
            &vk
        ));
        assert!(!verify_message(
            HASH_ID_VERIFICATION,
            &canonical,
            &sig_nic,
            &vk
        ));
    }

    #[test]
    fn hash_id_constants_match_go() {
        // Verify our HashID constants match Go's protocol/hash.go exactly
        assert_eq!(HASH_ID_CHALLENGE, b"NIC");
        assert_eq!(HASH_ID_CHALLENGE_RESPONSE, b"NIR");
        assert_eq!(HASH_ID_VERIFICATION, b"NIV");
        assert_eq!(NET_ID_VERIFICATION_TAG, b"NI");
        assert_eq!(IDENTITY_CHALLENGE_HEADER, "X-Algorand-IdentityChallenge");
    }

    // -----------------------------------------------------------------------
    // Signature verification failures
    // -----------------------------------------------------------------------

    #[test]
    fn bad_signature_rejected() {
        let initiator_key = test_key(1);
        let responder_key = test_key(2);
        let wrong_key = test_key(3);

        // Generate a challenge but sign with the WRONG key
        let msg = IdentityChallenge {
            key: initiator_key.verifying_key().to_bytes().to_vec(),
            challenge: [0xBB; 32].to_vec(),
            public_address: b"responder:4160".to_vec(),
        };

        let canonical = canonical_encode_challenge(&msg);
        let bad_sig = sign_message(HASH_ID_CHALLENGE, &canonical, &wrong_key);

        let bad_signed = IdentityChallengeSigned {
            msg,
            signature: bad_sig.to_bytes().to_vec(),
        };

        let header = attach_challenge_header(&bad_signed);

        let result = verify_challenge_and_respond(&header, &responder_key, &["responder:4160"]);
        assert!(matches!(result, Err(IdentityError::BadSignature)));
    }

    #[test]
    fn bad_response_signature_rejected() {
        let initiator_key = test_key(1);
        let responder_key = test_key(2);
        let wrong_key = test_key(3);

        let (challenge_signed, orig_challenge) =
            generate_challenge(&initiator_key, "responder:4160");
        let header_value = attach_challenge_header(&challenge_signed);

        let (response_signed, _response_challenge, _peer_pk) =
            verify_challenge_and_respond(&header_value, &responder_key, &["responder:4160"])
                .expect("should succeed");

        // Replace signature with one from wrong key
        let canonical = canonical_encode_challenge_response(&response_signed.msg);
        let bad_sig = sign_message(HASH_ID_CHALLENGE_RESPONSE, &canonical, &wrong_key);

        let tampered = IdentityChallengeResponseSigned {
            msg: response_signed.msg,
            signature: bad_sig.to_bytes().to_vec(),
        };

        let response_header = attach_response_header(&tampered);

        let result = verify_challenge_response(&response_header, &orig_challenge, &initiator_key);
        assert!(matches!(result, Err(IdentityError::BadSignature)));
    }

    #[test]
    fn verification_message_bad_signature_rejected() {
        let initiator_key = test_key(1);
        let wrong_key = test_key(99);

        let challenge = [0xCC; 32];

        // Create verification message signed by wrong key
        let ver_msg = IdentityVerificationMessage {
            response_challenge: challenge.to_vec(),
        };
        let canonical = canonical_encode_verification_message(&ver_msg);
        let sig = sign_message(HASH_ID_VERIFICATION, &canonical, &wrong_key);

        let ver_signed = IdentityVerificationMessageSigned {
            msg: ver_msg,
            signature: sig.to_bytes().to_vec(),
        };

        let wire = build_identity_verification(&ver_signed);
        let payload = &wire[NET_ID_VERIFICATION_TAG.len()..];

        let result =
            verify_identity_verification(payload, &challenge, &initiator_key.verifying_key());
        assert!(matches!(result, Err(IdentityError::BadSignature)));
    }

    // -----------------------------------------------------------------------
    // Challenge mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn challenge_mismatch_rejected() {
        let initiator_key = test_key(1);
        let responder_key = test_key(2);

        let (challenge_signed, _orig_challenge) =
            generate_challenge(&initiator_key, "responder:4160");
        let header_value = attach_challenge_header(&challenge_signed);

        let (response_signed, _response_challenge, _peer_pk) =
            verify_challenge_and_respond(&header_value, &responder_key, &["responder:4160"])
                .expect("should succeed");

        let response_header = attach_response_header(&response_signed);

        // Verify with WRONG expected challenge
        let wrong_challenge = [0xFF; 32];
        let result = verify_challenge_response(&response_header, &wrong_challenge, &initiator_key);
        assert!(matches!(result, Err(IdentityError::ChallengeMismatch)));
    }

    #[test]
    fn verification_message_bad_challenge_rejected() {
        let initiator_key = test_key(1);

        let ver_msg = IdentityVerificationMessage {
            response_challenge: [0xAA; 32].to_vec(),
        };
        let canonical = canonical_encode_verification_message(&ver_msg);
        let sig = sign_message(HASH_ID_VERIFICATION, &canonical, &initiator_key);

        let ver_signed = IdentityVerificationMessageSigned {
            msg: ver_msg,
            signature: sig.to_bytes().to_vec(),
        };

        let wire = build_identity_verification(&ver_signed);
        let payload = &wire[NET_ID_VERIFICATION_TAG.len()..];

        // Verify with wrong expected challenge
        let wrong_challenge = [0xBB; 32];
        let result =
            verify_identity_verification(payload, &wrong_challenge, &initiator_key.verifying_key());
        assert!(matches!(result, Err(IdentityError::ChallengeMismatch)));
    }

    // -----------------------------------------------------------------------
    // Address matching
    // -----------------------------------------------------------------------

    #[test]
    fn address_not_matched_returns_specific_error() {
        // Mirrors Go's behavior: if address doesn't match, return without
        // attaching response (no error in Go, AddressNotMatched in Rust).
        let initiator_key = test_key(1);
        let responder_key = test_key(2);

        let (challenge_signed, _orig_challenge) =
            generate_challenge(&initiator_key, "wrong-address:4160");
        let header_value = attach_challenge_header(&challenge_signed);

        let result =
            verify_challenge_and_respond(&header_value, &responder_key, &["correct-address:4160"]);
        assert!(matches!(result, Err(IdentityError::AddressNotMatched)));
    }

    #[test]
    fn empty_address_in_challenge_skips_address_check() {
        // When public_address is empty in the challenge, the responder should
        // not check against our_addresses at all (proceed with identity exchange).
        let initiator_key = test_key(1);
        let responder_key = test_key(2);

        // Generate a challenge with empty address
        let msg = IdentityChallenge {
            key: initiator_key.verifying_key().to_bytes().to_vec(),
            challenge: [0xAA; 32].to_vec(),
            public_address: vec![], // empty
        };
        let canonical = canonical_encode_challenge(&msg);
        let sig = sign_message(HASH_ID_CHALLENGE, &canonical, &initiator_key);
        let signed = IdentityChallengeSigned {
            msg,
            signature: sig.to_bytes().to_vec(),
        };

        let header = attach_challenge_header(&signed);

        // Should succeed even though addresses don't match
        let result = verify_challenge_and_respond(&header, &responder_key, &["anything:4160"]);
        assert!(result.is_ok());
    }

    #[test]
    fn multiple_our_addresses_matches_any() {
        // Verify that if we have multiple addresses, any match suffices.
        let initiator_key = test_key(1);
        let responder_key = test_key(2);

        let (challenge_signed, _) = generate_challenge(&initiator_key, "addr2:4160");
        let header = attach_challenge_header(&challenge_signed);

        let result = verify_challenge_and_respond(
            &header,
            &responder_key,
            &["addr1:4160", "addr2:4160", "addr3:4160"],
        );
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Base64 encoding/decoding
    // -----------------------------------------------------------------------

    #[test]
    fn base64_encode_decode_roundtrip() {
        let key = test_key(10);
        let (challenge_signed, _) = generate_challenge(&key, "test-addr:4160");

        // Encode to base64
        let b64 = attach_challenge_header(&challenge_signed);

        // Decode back
        let decoded_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
                .expect("base64 decode should succeed");

        // Should decode to valid msgpack
        let decoded: IdentityChallengeSigned =
            rmp_serde::from_slice(&decoded_bytes).expect("msgpack decode should succeed");

        assert_eq!(decoded.msg.key, challenge_signed.msg.key);
        assert_eq!(decoded.msg.challenge, challenge_signed.msg.challenge);
        assert_eq!(
            decoded.msg.public_address,
            challenge_signed.msg.public_address
        );
    }

    #[test]
    fn bad_base64_header_rejected() {
        let key = test_key(1);

        let result = verify_challenge_and_respond("NOT VALID BASE 64! :)", &key, &["addr"]);
        assert!(result.is_err());
    }

    #[test]
    fn bad_msgpack_payload_rejected() {
        // Valid base64 but not valid msgpack
        let bad_payload = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"not-msgpack-data!!",
        );

        let key = test_key(1);
        let result = verify_challenge_and_respond(&bad_payload, &key, &["addr"]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Msgpack structure verification -- field names must match Go codec tags
    // -----------------------------------------------------------------------

    #[test]
    fn msgpack_field_names_match_go_codec_tags() {
        // Verify the exact field names in our canonical encoding match
        // Go's codec tags from netidentity.go

        let challenge = IdentityChallenge {
            key: vec![1; 32],
            challenge: vec![2; 32],
            public_address: b"addr".to_vec(),
        };
        let encoded = canonical_encode_challenge(&challenge);
        let value: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).expect("should parse");

        if let rmpv::Value::Map(entries) = value {
            let keys: Vec<String> = entries
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();
            // Go codec tags: a, c, pk (sorted)
            assert_eq!(keys, vec!["a", "c", "pk"]);
        } else {
            panic!("expected map");
        }

        // identityChallengeResponse: Go codec tags c, pk, rc (sorted)
        let resp = IdentityChallengeResponse {
            key: vec![1; 32],
            challenge: vec![2; 32],
            response_challenge: vec![3; 32],
        };
        let encoded = canonical_encode_challenge_response(&resp);
        let value: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).expect("should parse");
        if let rmpv::Value::Map(entries) = value {
            let keys: Vec<String> = entries
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();
            assert_eq!(keys, vec!["c", "pk", "rc"]);
        } else {
            panic!("expected map");
        }

        // identityVerificationMessage: Go codec tag rc
        let ver = IdentityVerificationMessage {
            response_challenge: vec![4; 32],
        };
        let encoded = canonical_encode_verification_message(&ver);
        let value: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).expect("should parse");
        if let rmpv::Value::Map(entries) = value {
            let keys: Vec<String> = entries
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();
            assert_eq!(keys, vec!["rc"]);
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn signed_wrapper_field_names_match_go() {
        let key = test_key(7);

        // identityChallengeSigned: Go codec tags ic, sig (sorted)
        let msg = IdentityChallenge {
            key: key.verifying_key().to_bytes().to_vec(),
            challenge: [0x42; 32].to_vec(),
            public_address: b"node.example.com:4160".to_vec(),
        };
        let canonical = canonical_encode_challenge(&msg);
        let sig = sign_message(HASH_ID_CHALLENGE, &canonical, &key);
        let signed = IdentityChallengeSigned {
            msg,
            signature: sig.to_bytes().to_vec(),
        };
        let signed_bytes = canonical_encode_challenge_signed(&signed);
        let value: rmpv::Value =
            rmpv::decode::read_value(&mut &signed_bytes[..]).expect("should parse");
        if let rmpv::Value::Map(entries) = value {
            let keys: Vec<String> = entries
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();
            assert_eq!(keys, vec!["ic", "sig"]);
        } else {
            panic!("expected map");
        }

        // identityChallengeResponseSigned: Go codec tags icr, sig (sorted)
        let resp_msg = IdentityChallengeResponse {
            key: key.verifying_key().to_bytes().to_vec(),
            challenge: [0x11; 32].to_vec(),
            response_challenge: [0x22; 32].to_vec(),
        };
        let canonical_resp = canonical_encode_challenge_response(&resp_msg);
        let resp_sig = sign_message(HASH_ID_CHALLENGE_RESPONSE, &canonical_resp, &key);
        let resp_signed = IdentityChallengeResponseSigned {
            msg: resp_msg,
            signature: resp_sig.to_bytes().to_vec(),
        };
        let resp_signed_bytes = canonical_encode_challenge_response_signed(&resp_signed);
        let value: rmpv::Value =
            rmpv::decode::read_value(&mut &resp_signed_bytes[..]).expect("should parse");
        if let rmpv::Value::Map(entries) = value {
            let keys: Vec<String> = entries
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();
            assert_eq!(keys, vec!["icr", "sig"]);
        } else {
            panic!("expected map");
        }

        // identityVerificationMessageSigned: Go codec tags ivm, sig (sorted)
        let ver_msg = IdentityVerificationMessage {
            response_challenge: [0x33; 32].to_vec(),
        };
        let canonical_ver = canonical_encode_verification_message(&ver_msg);
        let ver_sig = sign_message(HASH_ID_VERIFICATION, &canonical_ver, &key);
        let ver_signed = IdentityVerificationMessageSigned {
            msg: ver_msg,
            signature: ver_sig.to_bytes().to_vec(),
        };
        let ver_signed_bytes = canonical_encode_verification_message_signed(&ver_signed);
        let value: rmpv::Value =
            rmpv::decode::read_value(&mut &ver_signed_bytes[..]).expect("should parse");
        if let rmpv::Value::Map(entries) = value {
            let keys: Vec<String> = entries
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();
            assert_eq!(keys, vec!["ivm", "sig"]);
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // Omitempty semantics
    // -----------------------------------------------------------------------

    #[test]
    fn omitempty_fields_omitted() {
        // When public_address is empty, it should be omitted
        let challenge = IdentityChallenge {
            key: vec![1; 32],
            challenge: vec![2; 32],
            public_address: vec![],
        };

        let encoded = canonical_encode_challenge(&challenge);

        // Should be fixmap with 2 entries (no "a" field)
        assert_eq!(encoded[0], 0x82, "should be fixmap with 2 entries");

        let value: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).expect("should parse");
        if let rmpv::Value::Map(entries) = value {
            assert_eq!(entries.len(), 2);
            let keys: Vec<String> = entries
                .iter()
                .map(|(k, _)| k.as_str().unwrap().to_string())
                .collect();
            assert_eq!(keys, vec!["c", "pk"]);
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn all_zero_challenge_omitted() {
        // When challenge is all zeros, it should be omitted (omitempty)
        // Go: identityChallengeValue{} comparison in MarshalMsg
        let challenge = IdentityChallenge {
            key: vec![1; 32],
            challenge: vec![0; 32],
            public_address: vec![],
        };

        let encoded = canonical_encode_challenge(&challenge);

        // Should be fixmap with 1 entry (only "pk")
        assert_eq!(encoded[0], 0x81, "should be fixmap with 1 entry");
    }

    #[test]
    fn all_zero_key_omitted() {
        // When key is all zeros, it should be omitted (MsgIsZero)
        let challenge = IdentityChallenge {
            key: vec![0; 32],
            challenge: vec![1; 32],
            public_address: vec![],
        };

        let encoded = canonical_encode_challenge(&challenge);
        assert_eq!(encoded[0], 0x81, "should be fixmap with 1 entry");

        let value: rmpv::Value = rmpv::decode::read_value(&mut &encoded[..]).expect("should parse");
        if let rmpv::Value::Map(entries) = value {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].0.as_str().unwrap(), "c");
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn completely_zero_struct_produces_empty_map() {
        // All-zero struct should produce an empty fixmap (0x80)
        let challenge = IdentityChallenge {
            key: vec![0; 32],
            challenge: vec![0; 32],
            public_address: vec![],
        };

        let encoded = canonical_encode_challenge(&challenge);
        assert_eq!(encoded, vec![0x80], "all-zero struct should be empty map");
    }

    // -----------------------------------------------------------------------
    // Byte-level canonical encoding conformance
    // -----------------------------------------------------------------------

    /// Helper: build expected msgpack bytes from a sequence of raw byte slices.
    fn build_expected(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in parts {
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn canonical_encoding_byte_level_challenge() {
        // Verify byte-level encoding of a known challenge matches what
        // Go's msgp MarshalMsg would produce.
        //
        // Go encoding for identityChallenge with:
        //   Key = [0x01; 32], Challenge = [0x02; 32], PublicAddress = b"test"
        //
        // Expected msgpack (from Go's MarshalMsg):
        //   0x83                       - fixmap, 3 entries
        //   0xa1 0x61                  - fixstr "a"
        //   0xc4 0x04 "test"           - bin8, 4 bytes, "test"
        //   0xa1 0x63                  - fixstr "c"
        //   0xc4 0x20 [0x02; 32]       - bin8, 32 bytes
        //   0xa2 0x70 0x6b             - fixstr "pk"
        //   0xc4 0x20 [0x01; 32]       - bin8, 32 bytes

        let challenge = IdentityChallenge {
            key: vec![0x01; 32],
            challenge: vec![0x02; 32],
            public_address: b"test".to_vec(),
        };

        let encoded = canonical_encode_challenge(&challenge);

        let expected = build_expected(&[
            &[0x83],             // fixmap, 3 entries
            &[0xa1, 0x61],       // fixstr "a"
            &[0xc4, 0x04],       // bin8, len=4
            b"test",             // "test"
            &[0xa1, 0x63],       // fixstr "c"
            &[0xc4, 0x20],       // bin8, len=32
            &[0x02; 32],         // challenge bytes
            &[0xa2, 0x70, 0x6b], // fixstr "pk"
            &[0xc4, 0x20],       // bin8, len=32
            &[0x01; 32],         // key bytes
        ]);

        assert_eq!(
            encoded, expected,
            "canonical encoding must match Go's msgp output byte-for-byte"
        );
    }

    #[test]
    fn canonical_encoding_byte_level_challenge_response() {
        // identityChallengeResponse with:
        //   Key = [0x01; 32], Challenge = [0x02; 32], ResponseChallenge = [0x03; 32]
        //
        // Expected (sorted: c, pk, rc):
        //   0x83
        //   0xa1 0x63  0xc4 0x20 [0x02; 32]   - "c" -> Challenge
        //   0xa2 0x70 0x6b  0xc4 0x20 [0x01; 32]  - "pk" -> Key
        //   0xa2 0x72 0x63  0xc4 0x20 [0x03; 32]  - "rc" -> ResponseChallenge

        let resp = IdentityChallengeResponse {
            key: vec![0x01; 32],
            challenge: vec![0x02; 32],
            response_challenge: vec![0x03; 32],
        };

        let encoded = canonical_encode_challenge_response(&resp);

        let expected = build_expected(&[
            &[0x83],             // fixmap, 3 entries
            &[0xa1, 0x63],       // fixstr "c"
            &[0xc4, 0x20],       // bin8, len=32
            &[0x02; 32],         // challenge bytes
            &[0xa2, 0x70, 0x6b], // fixstr "pk"
            &[0xc4, 0x20],       // bin8, len=32
            &[0x01; 32],         // key bytes
            &[0xa2, 0x72, 0x63], // fixstr "rc"
            &[0xc4, 0x20],       // bin8, len=32
            &[0x03; 32],         // response challenge bytes
        ]);

        assert_eq!(
            encoded, expected,
            "canonical encoding must match Go's msgp output byte-for-byte"
        );
    }

    #[test]
    fn canonical_encoding_byte_level_verification_message() {
        // identityVerificationMessage with ResponseChallenge = [0x04; 32]
        //
        // Expected:
        //   0x81                       - fixmap, 1 entry
        //   0xa2 0x72 0x63             - fixstr "rc"
        //   0xc4 0x20 [0x04; 32]       - bin8, 32 bytes

        let ver = IdentityVerificationMessage {
            response_challenge: vec![0x04; 32],
        };

        let encoded = canonical_encode_verification_message(&ver);

        let expected = build_expected(&[
            &[0x81],             // fixmap, 1 entry
            &[0xa2, 0x72, 0x63], // fixstr "rc"
            &[0xc4, 0x20],       // bin8, len=32
            &[0x04; 32],         // response challenge bytes
        ]);

        assert_eq!(
            encoded, expected,
            "canonical encoding must match Go's msgp output byte-for-byte"
        );
    }

    #[test]
    fn canonical_encoding_signed_wrapper_structure() {
        // Verify the signed wrapper encoding has the right structure.

        let key = test_key(7);
        let msg = IdentityChallenge {
            key: key.verifying_key().to_bytes().to_vec(),
            challenge: [0x42; 32].to_vec(),
            public_address: b"addr".to_vec(),
        };

        let canonical = canonical_encode_challenge(&msg);
        let sig = sign_message(HASH_ID_CHALLENGE, &canonical, &key);

        let signed = IdentityChallengeSigned {
            msg,
            signature: sig.to_bytes().to_vec(),
        };

        let signed_bytes = canonical_encode_challenge_signed(&signed);

        // First byte: fixmap with 2 entries
        assert_eq!(signed_bytes[0], 0x82);

        // Verify the structure is parseable
        let value: rmpv::Value =
            rmpv::decode::read_value(&mut &signed_bytes[..]).expect("should parse");
        if let rmpv::Value::Map(entries) = &value {
            assert_eq!(entries.len(), 2);

            // "ic" key
            assert_eq!(entries[0].0.as_str().unwrap(), "ic");
            // Inner value should be a map
            assert!(entries[0].1.is_map(), "inner 'ic' value should be a map");

            // "sig" key
            assert_eq!(entries[1].0.as_str().unwrap(), "sig");
            // Signature should be binary
            assert!(entries[1].1.is_bin(), "signature should be binary");
            assert_eq!(
                entries[1].1.as_slice().unwrap().len(),
                64,
                "signature should be 64 bytes"
            );
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // Signing protocol verification
    // -----------------------------------------------------------------------

    #[test]
    fn signing_protocol_matches_go_hashrep() {
        // Verify that our signing produces the same result as Go's:
        // Sign(Hashable) -> SignBytes(HashRep(msg))
        // where HashRep(msg) = hashid || Encode(msg)
        // and SignBytes does raw ed25519 sign

        let key = test_key(42);
        let msg = IdentityChallenge {
            key: key.verifying_key().to_bytes().to_vec(),
            challenge: [0xAB; 32].to_vec(),
            public_address: b"test:4160".to_vec(),
        };

        let canonical = canonical_encode_challenge(&msg);

        // Our sign_message does: ed25519_sign(key, prefix || canonical)
        let sig = sign_message(HASH_ID_CHALLENGE, &canonical, &key);

        // Manually construct what Go would sign:
        // HashRep(msg) = "NIC" || protocol.Encode(&msg)
        let mut hashrep = Vec::new();
        hashrep.extend_from_slice(b"NIC");
        hashrep.extend_from_slice(&canonical);

        // Verify directly against the hashrep
        let vk = key.verifying_key();
        assert!(vk.verify(&hashrep, &sig).is_ok());

        // Also verify our verify_message function works
        assert!(verify_message(HASH_ID_CHALLENGE, &canonical, &sig, &vk));
    }

    #[test]
    fn wire_verification_message_format() {
        // Verify the wire format of Message 3 starts with "NI" tag
        // then canonical msgpack of the signed verification message.
        // Go: append([]byte(protocol.NetIDVerificationTag), protocol.Encode(&signedMsg)...)

        let key = test_key(1);
        let ver_msg = IdentityVerificationMessage {
            response_challenge: [0xDD; 32].to_vec(),
        };
        let canonical = canonical_encode_verification_message(&ver_msg);
        let sig = sign_message(HASH_ID_VERIFICATION, &canonical, &key);

        let ver_signed = IdentityVerificationMessageSigned {
            msg: ver_msg,
            signature: sig.to_bytes().to_vec(),
        };

        let wire = build_identity_verification(&ver_signed);

        // Should start with "NI"
        assert_eq!(&wire[..2], b"NI");

        // The rest should be valid msgpack
        let payload = &wire[2..];
        let value: rmpv::Value =
            rmpv::decode::read_value(&mut &payload[..]).expect("should parse as msgpack");
        assert!(value.is_map());
    }

    // -----------------------------------------------------------------------
    // Go conformance: byte-identical msgpack encoding vectors
    // -----------------------------------------------------------------------
    //
    // These test vectors were generated by running protocol.Encode() on the
    // exact same structs in go-algorand (network package, v4.5.1-stable).
    // Every test asserts byte-for-byte identity between Rust and Go output.

    /// Helper: decode hex string to bytes.
    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn go_conformance_identity_challenge_full() {
        // Go test1: identityChallenge with Key=[0x01;32], Challenge=[0x02;32],
        // PublicAddress=b"r-aa.algorand-mainnet.network:4160"
        let c = IdentityChallenge {
            key: vec![0x01; 32],
            challenge: vec![0x02; 32],
            public_address: b"r-aa.algorand-mainnet.network:4160".to_vec(),
        };
        let encoded = canonical_encode_challenge(&c);
        let expected = hex_bytes(
            "83a161c422722d61612e616c676f72616e642d6d61696e6e65742e6e6574776f726b3a34313630a163c4200202020202020202020202020202020202020202020202020202020202020202a2706bc4200101010101010101010101010101010101010101010101010101010101010101"
        );
        assert_eq!(
            encoded, expected,
            "test1_identityChallenge_full: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_challenge_no_addr() {
        // Go test2: identityChallenge with Key=[0x01;32], Challenge=[0x02;32], no address
        let c = IdentityChallenge {
            key: vec![0x01; 32],
            challenge: vec![0x02; 32],
            public_address: vec![],
        };
        let encoded = canonical_encode_challenge(&c);
        let expected = hex_bytes(
            "82a163c4200202020202020202020202020202020202020202020202020202020202020202a2706bc4200101010101010101010101010101010101010101010101010101010101010101"
        );
        assert_eq!(
            encoded, expected,
            "test2_identityChallenge_no_addr: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_challenge_all_zero() {
        // Go test3: identityChallenge all zeros -> empty fixmap 0x80
        let c = IdentityChallenge {
            key: vec![0x00; 32],
            challenge: vec![0x00; 32],
            public_address: vec![],
        };
        let encoded = canonical_encode_challenge(&c);
        let expected = hex_bytes("80");
        assert_eq!(
            encoded, expected,
            "test3_identityChallenge_all_zero: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_challenge_key_only() {
        // Go test4: identityChallenge with only Key=[0x01;32] set
        let c = IdentityChallenge {
            key: vec![0x01; 32],
            challenge: vec![0x00; 32],
            public_address: vec![],
        };
        let encoded = canonical_encode_challenge(&c);
        let expected = hex_bytes(
            "81a2706bc4200101010101010101010101010101010101010101010101010101010101010101",
        );
        assert_eq!(
            encoded, expected,
            "test4_identityChallenge_key_only: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_challenge_signed_full() {
        // Go test5: identityChallengeSigned with full challenge + sig=[0xAA;64]
        let cs = IdentityChallengeSigned {
            msg: IdentityChallenge {
                key: vec![0x01; 32],
                challenge: vec![0x02; 32],
                public_address: b"r-aa.algorand-mainnet.network:4160".to_vec(),
            },
            signature: vec![0xAA; 64],
        };
        let encoded = canonical_encode_challenge_signed(&cs);
        let expected = hex_bytes(
            "82a2696383a161c422722d61612e616c676f72616e642d6d61696e6e65742e6e6574776f726b3a34313630a163c4200202020202020202020202020202020202020202020202020202020202020202a2706bc4200101010101010101010101010101010101010101010101010101010101010101a3736967c440aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            encoded, expected,
            "test5_identityChallengeSigned_full: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_challenge_signed_zero_msg() {
        // Go test6: identityChallengeSigned with zero inner message, sig=[0xAA;64]
        let cs = IdentityChallengeSigned {
            msg: IdentityChallenge {
                key: vec![0x00; 32],
                challenge: vec![0x00; 32],
                public_address: vec![],
            },
            signature: vec![0xAA; 64],
        };
        let encoded = canonical_encode_challenge_signed(&cs);
        let expected = hex_bytes(
            "81a3736967c440aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            encoded, expected,
            "test6_identityChallengeSigned_zero_msg: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_challenge_response_full() {
        // Go test7: identityChallengeResponse with Key=[0x03;32], Challenge=[0x04;32], RC=[0x05;32]
        let r = IdentityChallengeResponse {
            key: vec![0x03; 32],
            challenge: vec![0x04; 32],
            response_challenge: vec![0x05; 32],
        };
        let encoded = canonical_encode_challenge_response(&r);
        let expected = hex_bytes(
            "83a163c4200404040404040404040404040404040404040404040404040404040404040404a2706bc4200303030303030303030303030303030303030303030303030303030303030303a27263c4200505050505050505050505050505050505050505050505050505050505050505"
        );
        assert_eq!(
            encoded, expected,
            "test7_identityChallengeResponse_full: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_challenge_response_signed_full() {
        // Go test8: identityChallengeResponseSigned with full response + sig=[0xBB;64]
        let rs = IdentityChallengeResponseSigned {
            msg: IdentityChallengeResponse {
                key: vec![0x03; 32],
                challenge: vec![0x04; 32],
                response_challenge: vec![0x05; 32],
            },
            signature: vec![0xBB; 64],
        };
        let encoded = canonical_encode_challenge_response_signed(&rs);
        let expected = hex_bytes(
            "82a369637283a163c4200404040404040404040404040404040404040404040404040404040404040404a2706bc4200303030303030303030303030303030303030303030303030303030303030303a27263c4200505050505050505050505050505050505050505050505050505050505050505a3736967c440bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            encoded, expected,
            "test8_identityChallengeResponseSigned_full: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_verification_message_full() {
        // Go test9: identityVerificationMessage with RC=[0x06;32]
        let v = IdentityVerificationMessage {
            response_challenge: vec![0x06; 32],
        };
        let encoded = canonical_encode_verification_message(&v);
        let expected = hex_bytes(
            "81a27263c4200606060606060606060606060606060606060606060606060606060606060606",
        );
        assert_eq!(
            encoded, expected,
            "test9_identityVerificationMessage_full: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_verification_message_zero() {
        // Go test10: identityVerificationMessage all zeros -> empty fixmap
        let v = IdentityVerificationMessage {
            response_challenge: vec![0x00; 32],
        };
        let encoded = canonical_encode_verification_message(&v);
        let expected = hex_bytes("80");
        assert_eq!(
            encoded, expected,
            "test10_identityVerificationMessage_zero: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_verification_message_signed_full() {
        // Go test11: identityVerificationMessageSigned with RC=[0x06;32], sig=[0xCC;64]
        let vs = IdentityVerificationMessageSigned {
            msg: IdentityVerificationMessage {
                response_challenge: vec![0x06; 32],
            },
            signature: vec![0xCC; 64],
        };
        let encoded = canonical_encode_verification_message_signed(&vs);
        let expected = hex_bytes(
            "82a369766d81a27263c4200606060606060606060606060606060606060606060606060606060606060606a3736967c440cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(
            encoded, expected,
            "test11_identityVerificationMessageSigned_full: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_verification_message_signed_zero_msg() {
        // Go test12: identityVerificationMessageSigned with zero inner, sig=[0xCC;64]
        let vs = IdentityVerificationMessageSigned {
            msg: IdentityVerificationMessage {
                response_challenge: vec![0x00; 32],
            },
            signature: vec![0xCC; 64],
        };
        let encoded = canonical_encode_verification_message_signed(&vs);
        let expected = hex_bytes(
            "81a3736967c440cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(
            encoded, expected,
            "test12_identityVerificationMessageSigned_zero_msg: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_challenge_response_challenge_only() {
        // Go test13: identityChallengeResponse with only Challenge=[0x04;32]
        let r = IdentityChallengeResponse {
            key: vec![0x00; 32],
            challenge: vec![0x04; 32],
            response_challenge: vec![0x00; 32],
        };
        let encoded = canonical_encode_challenge_response(&r);
        let expected =
            hex_bytes("81a163c4200404040404040404040404040404040404040404040404040404040404040404");
        assert_eq!(
            encoded, expected,
            "test13_identityChallengeResponse_challenge_only: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_challenge_response_signed_all_zero() {
        // Go test14: identityChallengeResponseSigned all zeros -> empty fixmap
        let rs = IdentityChallengeResponseSigned {
            msg: IdentityChallengeResponse {
                key: vec![0x00; 32],
                challenge: vec![0x00; 32],
                response_challenge: vec![0x00; 32],
            },
            signature: vec![0x00; 64],
        };
        let encoded = canonical_encode_challenge_response_signed(&rs);
        let expected = hex_bytes("80");
        assert_eq!(
            encoded, expected,
            "test14_identityChallengeResponseSigned_all_zero: Rust encoding must be byte-identical to Go"
        );
    }

    #[test]
    fn go_conformance_identity_challenge_signed_all_zero() {
        // Go test15: identityChallengeSigned all zeros -> empty fixmap
        let cs = IdentityChallengeSigned {
            msg: IdentityChallenge {
                key: vec![0x00; 32],
                challenge: vec![0x00; 32],
                public_address: vec![],
            },
            signature: vec![0x00; 64],
        };
        let encoded = canonical_encode_challenge_signed(&cs);
        let expected = hex_bytes("80");
        assert_eq!(
            encoded, expected,
            "test15_identityChallengeSigned_all_zero: Rust encoding must be byte-identical to Go"
        );
    }
}
