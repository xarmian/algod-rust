//! Outbound WebSocket connection establishment.
//!
//! Builds an HTTP upgrade request with the correct Algorand headers, opens a
//! `tokio-tungstenite` connection to the target relay, and drives the
//! handshake + identity exchange to completion.  Returns a fully negotiated
//! `WsPeer` on success.
//!
//! # Go reference
//!
//! - `network/wsNetwork.go` — `tryConnect`, `setHeaders`, `checkServerResponseVariables`
//! - `network/netidentity.go` — identity challenge exchange
//! - `network/wsPeer.go` — peer initialization after handshake

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use http::header::HeaderName;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_util::sync::CancellationToken;

use crate::errors::WsConnectError;
use crate::handshake::{
    check_server_response_variables, gossip_path, set_headers, OutgoingHeaderParams,
    SUPPORTED_PROTOCOL_VERSIONS, TOO_MANY_REQUESTS_RETRY_AFTER_HEADER,
};
use crate::identity::{
    attach_challenge_header, build_identity_verification, generate_challenge,
    verify_challenge_response, IdentityChallengeValue,
};
use crate::message::OutgoingMessage;
use crate::msg_of_interest::marshal_msg_of_interest;
use crate::peer_features::{decode_peer_features, encode_peer_features, PeerFeatureFlags};
use crate::request_response::RequestTracker;
use crate::tag::Tag;
use crate::ws_peer::{PeerHandle, WsPeer, WsPeerConfig};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default handshake timeout — matches Go's `websocket.Dialer.HandshakeTimeout`
/// of 45 seconds in `tryConnect`.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(45);

/// User-Agent header value identifying this client.
const USER_AGENT: &str = "algod-rust/0.1.0";

// ---------------------------------------------------------------------------
// ConnectConfig
// ---------------------------------------------------------------------------

/// Configuration for an outbound WebSocket connection attempt.
///
/// Contains all the parameters needed to build the HTTP upgrade request,
/// run the identity challenge exchange, and initialize the resulting peer.
pub struct ConnectConfig {
    /// Genesis ID of the network we are connecting to (e.g. "mainnet-v1.0").
    pub genesis_id: String,

    /// Per-node random value for self-loop detection.
    pub node_random: u64,

    /// Our ed25519 signing key for the identity challenge exchange.
    /// When `None`, identity challenge exchange is skipped.
    pub our_identity_key: Option<SigningKey>,

    /// Our public address (e.g. "relay.example.com:4160") for identity exchange.
    /// If `None`, the identity challenge will use an empty address.
    pub our_address: Option<String>,

    /// Instance name, used to distinguish multiple nodes on the same machine.
    pub instance_name: String,

    /// Our address for incoming connections (can be empty).
    pub location: String,

    /// Telemetry identifier for logging (can be empty).
    pub telemetry_id: String,

    /// Our advertised peer feature flags.
    pub our_features: PeerFeatureFlags,

    /// Maximum time allowed for the full connect + handshake sequence.
    /// Defaults to 45 seconds if not specified (matching Go).
    pub handshake_timeout: Duration,

    /// Optional per-peer configuration (filters, request timeout, etc.).
    /// When `None`, uses `WsPeerConfig::default()`.
    pub peer_config: Option<WsPeerConfig>,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            genesis_id: String::new(),
            node_random: 0,
            our_identity_key: None,
            our_address: None,
            instance_name: String::new(),
            location: String::new(),
            telemetry_id: String::new(),
            our_features: PeerFeatureFlags::COMPRESSED_PROPOSAL,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            peer_config: None,
        }
    }
}

// ---------------------------------------------------------------------------
// URL building
// ---------------------------------------------------------------------------

/// Build the full WebSocket gossip URL for a given address and genesis ID.
///
/// Returns a URL like `ws://relay.example.com:4161/v1/mainnet-v1.0/gossip`.
///
/// If the address already contains a scheme (`ws://` or `wss://`), it is used
/// as-is. Otherwise, `ws://` is prepended.
pub fn build_gossip_url(addr: &str, genesis_id: &str) -> String {
    let base = if addr.contains("://") {
        addr.to_string()
    } else {
        format!("ws://{}", addr)
    };

    let path = gossip_path(genesis_id);
    // Ensure no double slashes between base and path
    if base.ends_with('/') {
        format!("{}{}", base, &path[1..])
    } else {
        format!("{}{}", base, path)
    }
}

// ---------------------------------------------------------------------------
// try_connect
// ---------------------------------------------------------------------------

/// Establish an outbound WebSocket connection to an Algorand relay peer.
///
/// This is the Rust equivalent of Go's `WebsocketNetwork.tryConnect`. It:
///
/// 1. Builds the gossip URL from the address and genesis ID
/// 2. Generates an identity challenge
/// 3. Sets all Algorand handshake headers
/// 4. Opens a WebSocket connection with a handshake timeout
/// 5. Validates the server's response headers
/// 6. Extracts peer features from the response
/// 7. Verifies the identity challenge response (if present)
/// 8. Creates and starts a `WsPeer`
/// 9. Sends the MsgOfInterest and identity verification messages
///
/// Returns a [`PeerHandle`] on success, or a [`WsConnectError`] on failure.
pub async fn try_connect(addr: &str, config: &ConnectConfig) -> Result<PeerHandle, WsConnectError> {
    // Step 1: Build gossip URL
    let gossip_url = build_gossip_url(addr, &config.genesis_id);
    tracing::debug!(url = %gossip_url, "connecting to peer");

    // Step 2: Generate identity challenge (only if we have a signing key)
    // Strip the URL scheme from the address before using it for the identity
    // challenge — the peer advertises itself as "host:port" without a scheme.
    let their_addr = strip_scheme(addr).to_lowercase();
    let identity_data = config.our_identity_key.as_ref().map(|key| {
        let (challenge_signed, challenge_value) = generate_challenge(key, &their_addr);
        let challenge_header = attach_challenge_header(&challenge_signed);
        (challenge_header, challenge_value)
    });
    let challenge_header_str = identity_data.as_ref().map(|(h, _)| h.as_str());

    // Step 3: Build request headers
    let node_random_str = config.node_random.to_string();
    let features_str = encode_peer_features(&config.our_features);
    let params = OutgoingHeaderParams {
        genesis_id: &config.genesis_id,
        node_random: &node_random_str,
        location: if config.location.is_empty() {
            None
        } else {
            Some(config.location.as_str())
        },
        instance_name: &config.instance_name,
        telemetry_id: Some(config.telemetry_id.as_str()),
        identity_challenge: challenge_header_str,
        peer_features: Some(&features_str),
    };
    let headers = set_headers(&params);

    // Step 4: Build HTTP request
    let mut request = gossip_url
        .into_client_request()
        .map_err(|e| WsConnectError::UpgradeRejected(e.to_string()))?;

    // Copy all Algorand headers into the request
    for (name, value) in headers.iter() {
        request.headers_mut().insert(name.clone(), value.clone());
    }

    // Set User-Agent header (matches Go's SetUserAgentHeader)
    request.headers_mut().insert(
        HeaderName::from_static("user-agent"),
        USER_AGENT.parse().expect("valid header value"),
    );

    // Steps 5 & 6: Dial WebSocket with handshake timeout
    let connect_result = tokio::time::timeout(
        config.handshake_timeout,
        tokio_tungstenite::connect_async(request),
    )
    .await;

    let (ws_stream, response) = match connect_result {
        Ok(Ok((stream, resp))) => (stream, resp),
        Ok(Err(e)) => {
            return Err(map_tungstenite_error(e));
        }
        Err(_elapsed) => {
            tracing::warn!(addr = %addr, "connection timed out");
            return Err(WsConnectError::Timeout);
        }
    };

    tracing::debug!(
        addr = %addr,
        status = %response.status(),
        "WebSocket connection established"
    );

    // Step 7: Validate server response headers
    let response_headers = response.headers();
    let server_info = check_server_response_variables(
        response_headers,
        SUPPORTED_PROTOCOL_VERSIONS,
        &node_random_str,
        &config.genesis_id,
    )
    .map_err(|e| WsConnectError::Handshake(Box::new(e)))?;

    tracing::debug!(
        addr = %addr,
        version = %server_info.protocol_version,
        node_random = %server_info.node_random,
        "server response validated"
    );

    // Step 8: Extract peer features
    let peer_features_header = response_headers
        .get(HeaderName::from_static("x-algorand-peer-features"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let remote_features = decode_peer_features(&server_info.protocol_version, peer_features_header);
    // The effective feature set is the intersection of the server's advertised
    // capabilities and our local configuration.  Without this, the write_loop
    // would zstd-compress outbound PP payloads even when the caller has
    // deliberately disabled COMPRESSED_PROPOSAL in `ConnectConfig::our_features`.
    let peer_features = remote_features.intersection(config.our_features);
    tracing::debug!(
        addr = %addr,
        features_raw = %peer_features_header,
        features_remote = ?remote_features,
        features_negotiated = ?peer_features,
        "negotiated peer features"
    );

    // Step 9: Check for priority challenge header (NP)
    // Go sends a PriorityChallengeHeader; for now we just log it.
    // TODO: implement priority challenge response when priority scheduling is added.
    if let Some(priority_challenge) = response_headers
        .get(HeaderName::from_static("x-algorand-prioritychallenge"))
        .and_then(|v| v.to_str().ok())
    {
        tracing::debug!(
            addr = %addr,
            challenge = %priority_challenge,
            "received priority challenge from server (not responding — no priority scheme configured)"
        );
    }

    // Step 10: Verify identity response (if present and we have a key)
    let (identity_key, id_verification_bytes) = if let (Some(key), Some((_, ref challenge_value))) =
        (&config.our_identity_key, &identity_data)
    {
        let identity_result = extract_and_verify_identity(response_headers, challenge_value, key);

        match identity_result {
            Ok((peer_key, verification_msg)) => {
                tracing::debug!(
                    addr = %addr,
                    peer_key = ?peer_key,
                    "identity challenge exchange succeeded"
                );
                (Some(peer_key), Some(verification_msg))
            }
            Err(ref e) if is_identity_exchange_skipped(e) => {
                // No identity challenge response from server — not an error
                tracing::debug!(
                    addr = %addr,
                    "identity exchange not performed (no response header)"
                );
                (None, None)
            }
            Err(e) => {
                tracing::warn!(
                    addr = %addr,
                    error = %e,
                    "identity verification failed, abandoning peering"
                );
                return Err(WsConnectError::Identity(e));
            }
        }
    } else {
        tracing::debug!(
            addr = %addr,
            "identity exchange skipped (no signing key configured)"
        );
        (None, None)
    };

    let identity_verified = id_verification_bytes.is_some();

    // Step 11: Create and start WsPeer
    let closing = CancellationToken::new();
    let mut peer_cfg = config.peer_config.clone().unwrap_or_default();
    if peer_cfg.request_tracker.is_none() {
        peer_cfg.request_tracker = Some(Arc::new(RequestTracker::new()));
    }
    let peer = WsPeer::with_config(
        ws_stream,
        addr.to_string(),
        server_info.protocol_version,
        peer_features,
        identity_key,
        identity_verified,
        closing,
        peer_cfg,
    );
    let handle = peer.start();

    // Step 12: Send identity verification (if exchange succeeded)
    // The identity protocol requires the NI verification message (Message 3)
    // to be sent before any gossip traffic. Go relays that enforce identity
    // flow ordering will drop the connection otherwise.
    if let Some(verification_bytes) = id_verification_bytes {
        let ni_msg = OutgoingMessage::new(Tag::NetIDVerification, verification_bytes);
        if let Err(e) = handle.send_priority(ni_msg) {
            tracing::warn!(
                addr = %addr,
                error = %e,
                "could not send identity verification"
            );
        }
    }

    // Step 13: Send MsgOfInterest
    let mi_tags = Tag::active_tags();
    let mi_payload = marshal_msg_of_interest(&mi_tags);
    let mi_msg = OutgoingMessage::new(Tag::MsgOfInterest, mi_payload);
    if let Err(e) = handle.send_priority(mi_msg) {
        tracing::warn!(
            addr = %addr,
            error = %e,
            "could not send MsgOfInterest"
        );
    }

    tracing::info!(
        addr = %addr,
        version = %handle.version(),
        features = ?handle.features(),
        identity_verified = identity_verified,
        "outbound connection established"
    );

    // Step 14: Return PeerHandle
    Ok(handle)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the identity challenge response header from the server's HTTP
/// response and verify it against our original challenge.
///
/// Returns the peer's public key and the serialized NI-tagged verification
/// message bytes to send back.
fn extract_and_verify_identity(
    response_headers: &http::HeaderMap,
    challenge_value: &IdentityChallengeValue,
    our_key: &SigningKey,
) -> Result<(ed25519_dalek::VerifyingKey, Vec<u8>), crate::errors::IdentityError> {
    let header_value = response_headers
        .get(HeaderName::from_static("x-algorand-identitychallenge"))
        .and_then(|v| v.to_str().ok())
        .ok_or(crate::errors::IdentityError::HeaderMissing)?;

    if header_value.is_empty() {
        return Err(crate::errors::IdentityError::HeaderMissing);
    }

    let (peer_identity, verification_signed) =
        verify_challenge_response(header_value, challenge_value, our_key)?;

    // Build the wire bytes for the NI verification message
    // build_identity_verification already prepends the "NI" tag bytes
    let wire_bytes = build_identity_verification(&verification_signed);
    // Strip the tag prefix — the OutgoingMessage framing will re-add it
    let payload = wire_bytes[2..].to_vec();

    Ok((peer_identity.public_key, payload))
}

/// Returns `true` if the identity error indicates that the server simply
/// did not participate in the identity exchange (not a fatal error).
///
/// Only a genuinely missing or empty header is non-fatal.  Any other
/// identity error (bad signature, challenge mismatch, invalid key,
/// address not matched) means the server *attempted* the exchange but
/// the result is malformed — that must abort the connection.
fn is_identity_exchange_skipped(err: &crate::errors::IdentityError) -> bool {
    matches!(err, crate::errors::IdentityError::HeaderMissing)
}

/// Map a tungstenite error to our `WsConnectError`, handling HTTP status
/// codes from failed WebSocket upgrades.
fn map_tungstenite_error(err: tokio_tungstenite::tungstenite::Error) -> WsConnectError {
    use tokio_tungstenite::tungstenite::Error as TungError;

    match err {
        TungError::Http(response) => {
            let status = response.status().as_u16();
            let body = response
                .body()
                .as_ref()
                .map(|b| {
                    let s = String::from_utf8_lossy(b);
                    filter_ascii(&s, 128)
                })
                .unwrap_or_default();

            match status {
                412 => WsConnectError::GenesisMismatch,
                429 => {
                    let retry_after = response
                        .headers()
                        .get(TOO_MANY_REQUESTS_RETRY_AFTER_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());
                    WsConnectError::TooManyRequests {
                        retry_after_secs: retry_after,
                    }
                }
                508 => WsConnectError::SelfLoop,
                _ => WsConnectError::HttpStatus { status, body },
            }
        }
        other => WsConnectError::Tungstenite(other),
    }
}

/// Strip a URL scheme prefix (`ws://`, `wss://`, `http://`, `https://`)
/// from an address string, returning just the `host:port` portion.
///
/// If no recognised scheme is present the input is returned unchanged.
/// This is used to normalise addresses before identity challenge signing,
/// because the peer advertises itself as `host:port` without a scheme.
fn strip_scheme(addr: &str) -> &str {
    for prefix in &["wss://", "ws://", "https://", "http://"] {
        if let Some(rest) = addr.strip_prefix(prefix) {
            return rest;
        }
    }
    addr
}

/// Filter a string to contain only printable ASCII characters, truncating
/// to `max_len`. Mirrors Go's `filterASCII` in `wsNetwork.go`.
fn filter_ascii(s: &str, max_len: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(max_len)
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // URL building tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_gossip_url_basic() {
        let url = build_gossip_url("relay.example.com:4161", "testnet-v1.0");
        assert_eq!(url, "ws://relay.example.com:4161/v1/testnet-v1.0/gossip");
    }

    #[test]
    fn build_gossip_url_mainnet() {
        let url = build_gossip_url("1.2.3.4:4161", "mainnet-v1.0");
        assert_eq!(url, "ws://1.2.3.4:4161/v1/mainnet-v1.0/gossip");
    }

    #[test]
    fn build_gossip_url_with_scheme() {
        let url = build_gossip_url("ws://relay.example.com:4161", "testnet-v1.0");
        assert_eq!(url, "ws://relay.example.com:4161/v1/testnet-v1.0/gossip");
    }

    #[test]
    fn build_gossip_url_wss_scheme() {
        let url = build_gossip_url("wss://relay.example.com:4161", "testnet-v1.0");
        assert_eq!(url, "wss://relay.example.com:4161/v1/testnet-v1.0/gossip");
    }

    #[test]
    fn build_gossip_url_trailing_slash() {
        let url = build_gossip_url("relay.example.com:4161/", "testnet-v1.0");
        assert_eq!(url, "ws://relay.example.com:4161/v1/testnet-v1.0/gossip");
    }

    #[test]
    fn build_gossip_url_empty_genesis() {
        let url = build_gossip_url("relay.example.com:4161", "");
        assert_eq!(url, "ws://relay.example.com:4161/v1//gossip");
    }

    #[test]
    fn build_gossip_url_ipv6() {
        let url = build_gossip_url("[::1]:4161", "betanet-v1.0");
        assert_eq!(url, "ws://[::1]:4161/v1/betanet-v1.0/gossip");
    }

    // -----------------------------------------------------------------------
    // Error mapping tests
    // -----------------------------------------------------------------------

    #[test]
    fn map_http_412_to_genesis_mismatch() {
        use tokio_tungstenite::tungstenite::Error as TungError;

        let response = http::Response::builder()
            .status(412)
            .body(Some(b"genesis mismatch".to_vec()))
            .unwrap();
        let err = map_tungstenite_error(TungError::Http(response));
        assert!(matches!(err, WsConnectError::GenesisMismatch));
    }

    #[test]
    fn map_http_429_with_retry_after() {
        use tokio_tungstenite::tungstenite::Error as TungError;

        let response = http::Response::builder()
            .status(429)
            .header("Retry-After", "60")
            .body(Some(b"too many requests".to_vec()))
            .unwrap();
        let err = map_tungstenite_error(TungError::Http(response));
        match err {
            WsConnectError::TooManyRequests { retry_after_secs } => {
                assert_eq!(retry_after_secs, Some(60));
            }
            other => panic!("expected TooManyRequests, got: {other:?}"),
        }
    }

    #[test]
    fn map_http_429_without_retry_after() {
        use tokio_tungstenite::tungstenite::Error as TungError;

        let response = http::Response::builder()
            .status(429)
            .body(Some(b"too many requests".to_vec()))
            .unwrap();
        let err = map_tungstenite_error(TungError::Http(response));
        match err {
            WsConnectError::TooManyRequests { retry_after_secs } => {
                assert_eq!(retry_after_secs, None);
            }
            other => panic!("expected TooManyRequests, got: {other:?}"),
        }
    }

    #[test]
    fn map_http_508_to_self_loop() {
        use tokio_tungstenite::tungstenite::Error as TungError;

        let response = http::Response::builder()
            .status(508)
            .body(Some(b"loop detected".to_vec()))
            .unwrap();
        let err = map_tungstenite_error(TungError::Http(response));
        assert!(matches!(err, WsConnectError::SelfLoop));
    }

    #[test]
    fn map_http_500_to_http_status() {
        use tokio_tungstenite::tungstenite::Error as TungError;

        let response = http::Response::builder()
            .status(500)
            .body(Some(b"internal error".to_vec()))
            .unwrap();
        let err = map_tungstenite_error(TungError::Http(response));
        match err {
            WsConnectError::HttpStatus { status, body } => {
                assert_eq!(status, 500);
                assert!(body.contains("internal error"));
            }
            other => panic!("expected HttpStatus, got: {other:?}"),
        }
    }

    #[test]
    fn map_http_empty_body() {
        use tokio_tungstenite::tungstenite::Error as TungError;

        let response = http::Response::builder()
            .status(403)
            .body(None::<Vec<u8>>)
            .unwrap();
        let err = map_tungstenite_error(TungError::Http(response));
        match err {
            WsConnectError::HttpStatus { status, body } => {
                assert_eq!(status, 403);
                assert!(body.is_empty());
            }
            other => panic!("expected HttpStatus, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // filter_ascii tests
    // -----------------------------------------------------------------------

    #[test]
    fn filter_ascii_basic() {
        assert_eq!(filter_ascii("hello world", 128), "hello world");
    }

    #[test]
    fn filter_ascii_strips_non_printable() {
        assert_eq!(filter_ascii("hello\x00world\x01!", 128), "helloworld!");
    }

    #[test]
    fn filter_ascii_truncates() {
        let long = "a".repeat(200);
        let filtered = filter_ascii(&long, 128);
        assert_eq!(filtered.len(), 128);
    }

    #[test]
    fn filter_ascii_empty() {
        assert_eq!(filter_ascii("", 128), "");
    }

    // -----------------------------------------------------------------------
    // strip_scheme tests
    // -----------------------------------------------------------------------

    #[test]
    fn strip_scheme_ws() {
        assert_eq!(
            strip_scheme("ws://relay.example.com:4161"),
            "relay.example.com:4161"
        );
    }

    #[test]
    fn strip_scheme_wss() {
        assert_eq!(
            strip_scheme("wss://relay.example.com:4161"),
            "relay.example.com:4161"
        );
    }

    #[test]
    fn strip_scheme_no_scheme() {
        assert_eq!(
            strip_scheme("relay.example.com:4161"),
            "relay.example.com:4161"
        );
    }

    #[test]
    fn strip_scheme_http() {
        assert_eq!(
            strip_scheme("http://relay.example.com"),
            "relay.example.com"
        );
    }

    #[test]
    fn strip_scheme_https() {
        assert_eq!(
            strip_scheme("https://relay.example.com"),
            "relay.example.com"
        );
    }

    // -----------------------------------------------------------------------
    // ConnectConfig default test
    // -----------------------------------------------------------------------

    #[test]
    fn connect_config_default_timeout() {
        let config = ConnectConfig::default();
        assert_eq!(config.handshake_timeout, DEFAULT_HANDSHAKE_TIMEOUT);
        assert_eq!(config.handshake_timeout.as_secs(), 45);
    }

    // -----------------------------------------------------------------------
    // Identity exchange skip detection
    // -----------------------------------------------------------------------

    #[test]
    fn identity_exchange_skipped_on_header_missing() {
        assert!(is_identity_exchange_skipped(
            &crate::errors::IdentityError::HeaderMissing
        ));
    }

    #[test]
    fn identity_exchange_not_skipped_on_challenge_mismatch() {
        // ChallengeMismatch means the server sent a response but the echoed
        // challenge did not match — this is a malformed response, not a skip.
        assert!(!is_identity_exchange_skipped(
            &crate::errors::IdentityError::ChallengeMismatch
        ));
    }

    #[test]
    fn identity_exchange_not_skipped_on_address_not_matched() {
        // AddressNotMatched means the server responded but addresses don't
        // line up — this should abort the connection.
        assert!(!is_identity_exchange_skipped(
            &crate::errors::IdentityError::AddressNotMatched
        ));
    }

    #[test]
    fn identity_exchange_not_skipped_on_bad_signature() {
        assert!(!is_identity_exchange_skipped(
            &crate::errors::IdentityError::BadSignature
        ));
    }

    #[test]
    fn identity_exchange_not_skipped_on_invalid_public_key() {
        assert!(!is_identity_exchange_skipped(
            &crate::errors::IdentityError::InvalidPublicKey("bad key".into())
        ));
    }
}
