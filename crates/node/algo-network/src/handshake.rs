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

//! Algorand WebSocket handshake protocol.
//!
//! After the raw WebSocket upgrade succeeds, peers exchange Algorand-specific
//! HTTP headers (genesis ID, protocol version, node random, instance name,
//! peer features, etc.) to negotiate compatibility.  This module implements
//! header construction and validation, mirroring Go's `setHeaders`,
//! `checkProtocolVersionMatch`, and `checkServerResponseVariables` functions
//! from `network/wsNetwork.go`.
//!
//! # Go reference
//!
//! - `network/wsNetwork.go` — header constants, `setHeaders`, protocol version
//!   checking, server response validation, `GossipNetworkPath`

use http::header::HeaderName;
use http::HeaderMap;

use super::errors::HandshakeError;

// ---------------------------------------------------------------------------
// Header name constants (must match go-algorand exactly)
// ---------------------------------------------------------------------------

/// HTTP header for the network protocol version.
///
/// Go: `ProtocolVersionHeader = "X-Algorand-Version"`.
pub const PROTOCOL_VERSION_HEADER: &str = "X-Algorand-Version";

/// HTTP header for accepted network protocol versions.  Clients use this to
/// advertise all protocol versions they support (one `Add` per version).
///
/// Go: `ProtocolAcceptVersionHeader = "X-Algorand-Accept-Version"`.
pub const PROTOCOL_ACCEPT_VERSION_HEADER: &str = "X-Algorand-Accept-Version";

/// HTTP header for telemetry ID used for logging.
///
/// Go: `TelemetryIDHeader = "X-Algorand-TelId"`.
pub const TELEMETRY_ID_HEADER: &str = "X-Algorand-TelId";

/// HTTP header for the genesis ID — ensures both peers are on the same chain.
///
/// Go: `GenesisHeader = "X-Algorand-Genesis"`.
pub const GENESIS_HEADER: &str = "X-Algorand-Genesis";

/// HTTP header containing a per-node random string used to detect self-loops.
///
/// Go: `NodeRandomHeader = "X-Algorand-NodeRandom"`.
pub const NODE_RANDOM_HEADER: &str = "X-Algorand-NodeRandom";

/// HTTP header by which an inbound connection reports its public address.
///
/// Go: `AddressHeader = "X-Algorand-Location"`.
pub const ADDRESS_HEADER: &str = "X-Algorand-Location";

/// HTTP header identifying a local node instance (disambiguates multiple nodes
/// running on the same machine).
///
/// Go: `InstanceNameHeader = "X-Algorand-InstanceName"`.
pub const INSTANCE_NAME_HEADER: &str = "X-Algorand-InstanceName";

/// HTTP header that informs a client about a priority challenge it should sign
/// to increase network priority.
///
/// Go: `PriorityChallengeHeader = "X-Algorand-PriorityChallenge"`.
pub const PRIORITY_CHALLENGE_HEADER: &str = "X-Algorand-PriorityChallenge";

/// HTTP header used to exchange identity challenges during the handshake.
///
/// Go: `IdentityChallengeHeader = "X-Algorand-IdentityChallenge"`.
pub const IDENTITY_CHALLENGE_HEADER: &str = "X-Algorand-IdentityChallenge";

/// HTTP header listing peer features as a comma-separated string.
///
/// Go: `PeerFeaturesHeader = "X-Algorand-Peer-Features"`.
pub const PEER_FEATURES_HEADER: &str = "X-Algorand-Peer-Features";

/// HTTP header for retry-after on `429 Too Many Requests` responses.
///
/// Go: `TooManyRequestsRetryAfterHeader = "Retry-After"`.
pub const TOO_MANY_REQUESTS_RETRY_AFTER_HEADER: &str = "Retry-After";

/// HTTP header identifying the user agent.
///
/// Go: `UserAgentHeader = "User-Agent"`.
pub const USER_AGENT_HEADER: &str = "User-Agent";

// ---------------------------------------------------------------------------
// Protocol version constants
// ---------------------------------------------------------------------------

/// The current network protocol version.
///
/// Go: `ProtocolVersion = "2.2"`.
///
/// Version history:
/// - `1`   — Catchup service over websocket with unicast messages
/// - `2.1` — Topic key/data pairs; services over gossip connections
/// - `2.2` — Peer features
pub const PROTOCOL_VERSION: &str = "2.2";

/// Supported network protocol versions, in order of preference.
///
/// Go: `SupportedProtocolVersions = []string{"2.2"}`.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2.2"];

// ---------------------------------------------------------------------------
// Gossip network path
// ---------------------------------------------------------------------------

/// URL path template for the WebSocket gossip endpoint.
///
/// The `{genesisID}` placeholder must be replaced with the actual genesis ID
/// before use.
///
/// Go: `GossipNetworkPath = "/v1/{genesisID}/gossip"`.
pub const GOSSIP_NETWORK_PATH: &str = "/v1/{genesisID}/gossip";

/// Build the concrete gossip URL path for a given genesis ID.
///
/// Replaces the `{genesisID}` placeholder in [`GOSSIP_NETWORK_PATH`].
pub fn gossip_path(genesis_id: &str) -> String {
    GOSSIP_NETWORK_PATH.replace("{genesisID}", genesis_id)
}

// ---------------------------------------------------------------------------
// Outgoing request header builder
// ---------------------------------------------------------------------------

/// Parameters for building outgoing WebSocket upgrade request headers.
///
/// This is the Rust equivalent of Go's `peerMetadataProvider` interface fields
/// consumed by `setHeaders`.
pub struct OutgoingHeaderParams<'a> {
    /// Genesis ID of the network we are connecting to.
    pub genesis_id: &'a str,
    /// Per-node random string for self-loop detection.
    pub node_random: &'a str,
    /// Optional public address (e.g. `"relay.example.com:4160"`).
    pub location: Option<&'a str>,
    /// Instance name, used to distinguish multiple local nodes.
    pub instance_name: &'a str,
    /// Optional telemetry GUID for logging.
    pub telemetry_id: Option<&'a str>,
    /// Optional base64-encoded identity challenge header value.
    pub identity_challenge: Option<&'a str>,
    /// Optional comma-separated peer features string.
    pub peer_features: Option<&'a str>,
}

/// Builds the HTTP headers for an outgoing WebSocket upgrade request.
///
/// Mirrors Go's `setHeaders` function: sets protocol version, accept-version
/// list, genesis ID, node random, location, instance name, telemetry ID,
/// peer features, and optionally the identity challenge header.
pub fn set_headers(params: &OutgoingHeaderParams<'_>) -> HeaderMap {
    let mut headers = HeaderMap::new();

    // Telemetry ID — always set, even if empty (matches Go's setHeaders).
    let tel_id = params.telemetry_id.unwrap_or("");
    headers.insert(
        HeaderName::from_static("x-algorand-telid"),
        tel_id.parse().expect("valid header value"),
    );

    // Instance name
    headers.insert(
        HeaderName::from_static("x-algorand-instancename"),
        params.instance_name.parse().expect("valid header value"),
    );

    // Location (public address) — only set if non-empty
    if let Some(location) = params.location {
        if !location.is_empty() {
            headers.insert(
                HeaderName::from_static("x-algorand-location"),
                location.parse().expect("valid header value"),
            );
        }
    }

    // Node random — only set if non-empty
    if !params.node_random.is_empty() {
        headers.insert(
            HeaderName::from_static("x-algorand-noderandom"),
            params.node_random.parse().expect("valid header value"),
        );
    }

    // Genesis ID
    headers.insert(
        HeaderName::from_static("x-algorand-genesis"),
        params.genesis_id.parse().expect("valid header value"),
    );

    // Peer features — always include (Go always announces ppzstd at minimum).
    let features = params.peer_features.unwrap_or("");
    headers.insert(
        HeaderName::from_static("x-algorand-peer-features"),
        features.parse().expect("valid header value"),
    );

    // Protocol version (for backward compatibility)
    headers.insert(
        HeaderName::from_static("x-algorand-version"),
        PROTOCOL_VERSION.parse().expect("valid header value"),
    );

    // Accept-version list — one entry per supported version
    for v in SUPPORTED_PROTOCOL_VERSIONS {
        headers.append(
            HeaderName::from_static("x-algorand-accept-version"),
            v.parse().expect("valid header value"),
        );
    }

    // Identity challenge (optional)
    if let Some(challenge) = params.identity_challenge {
        if !challenge.is_empty() {
            headers.insert(
                HeaderName::from_static("x-algorand-identitychallenge"),
                challenge.parse().expect("valid header value"),
            );
        }
    }

    headers
}

// ---------------------------------------------------------------------------
// Protocol version matching
// ---------------------------------------------------------------------------

/// Result of a protocol version match attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionMatch {
    /// A matching version was found.
    Matched(String),
    /// No matching version found; `other_version` is what the remote advertised
    /// in the `X-Algorand-Version` header (may be empty).
    NoMatch { other_version: String },
}

/// Check protocol version compatibility against the remote peer's headers.
///
/// Mirrors Go's `checkProtocolVersionMatch`:
/// 1. First checks all values of `X-Algorand-Accept-Version` against our
///    supported versions.
/// 2. Falls back to `X-Algorand-Version` if no accept-version matched.
/// 3. Returns [`VersionMatch::NoMatch`] if neither header contains a
///    compatible version.
pub fn check_protocol_version_match(
    other_headers: &HeaderMap,
    our_supported_versions: &[&str],
) -> VersionMatch {
    // First: check accept-version headers (there can be multiple)
    let accept_key = HeaderName::from_static("x-algorand-accept-version");
    for value in other_headers.get_all(&accept_key) {
        if let Ok(v) = value.to_str() {
            if our_supported_versions.contains(&v) {
                return VersionMatch::Matched(v.to_string());
            }
        }
    }

    // Fallback: check the single protocol version header
    let version_key = HeaderName::from_static("x-algorand-version");
    if let Some(value) = other_headers.get(&version_key) {
        if let Ok(v) = value.to_str() {
            if our_supported_versions.contains(&v) {
                return VersionMatch::Matched(v.to_string());
            } else {
                return VersionMatch::NoMatch {
                    other_version: v.to_string(),
                };
            }
        }
    }

    VersionMatch::NoMatch {
        other_version: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Server response info
// ---------------------------------------------------------------------------

/// Information extracted from a server's WebSocket upgrade response headers.
///
/// Returned by [`check_server_response_variables`] on success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerResponseInfo {
    /// The negotiated network protocol version (e.g. `"2.2"`).
    pub protocol_version: String,
    /// The server's per-node random identifier.
    pub node_random: String,
    /// The server's genesis ID.
    pub genesis_id: String,
    /// The server's telemetry GUID (may be empty).
    pub telemetry_id: String,
    /// The server's instance name (may be empty).
    pub instance_name: String,
    /// The server's public address (may be empty).
    pub public_address: String,
}

// ---------------------------------------------------------------------------
// Full server response validation
// ---------------------------------------------------------------------------

/// Validate the server's WebSocket upgrade response headers.
///
/// Mirrors Go's `checkServerResponseVariables`:
///
/// 1. **Protocol version match** — at least one supported version must appear
///    in the server's `X-Algorand-Accept-Version` or `X-Algorand-Version`
///    headers.
/// 2. **NodeRandom not empty** — the server must provide a non-empty
///    `X-Algorand-NodeRandom` header.
/// 3. **NodeRandom not equal to ours** — detects self-connections.
/// 4. **GenesisID matches** — the server's `X-Algorand-Genesis` must match
///    our expected genesis ID.
///
/// On success returns [`ServerResponseInfo`] containing the parsed header
/// values.
#[allow(clippy::result_large_err)]
pub fn check_server_response_variables(
    response_headers: &HeaderMap,
    our_supported_versions: &[&str],
    our_node_random: &str,
    expected_genesis_id: &str,
) -> Result<ServerResponseInfo, HandshakeError> {
    // 1. Protocol version
    let protocol_version =
        match check_protocol_version_match(response_headers, our_supported_versions) {
            VersionMatch::Matched(v) => v,
            VersionMatch::NoMatch { other_version } => {
                return Err(HandshakeError::VersionMismatch {
                    local: our_supported_versions.join(","),
                    remote: other_version,
                });
            }
        };

    // 2 & 3. NodeRandom: must be present, non-empty, and different from ours
    let other_random = response_headers
        .get(HeaderName::from_static("x-algorand-noderandom"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if other_random.is_empty() {
        return Err(HandshakeError::MissingHeader(
            NODE_RANDOM_HEADER.to_string(),
        ));
    }
    if other_random == our_node_random {
        return Err(HandshakeError::SelfLoop);
    }

    // 4. Genesis ID
    let other_genesis = response_headers
        .get(HeaderName::from_static("x-algorand-genesis"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if other_genesis != expected_genesis_id {
        return Err(HandshakeError::GenesisMismatch {
            expected: expected_genesis_id.to_string(),
            actual: other_genesis.to_string(),
        });
    }

    // Extract optional common headers
    let telemetry_id = response_headers
        .get(HeaderName::from_static("x-algorand-telid"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let instance_name = response_headers
        .get(HeaderName::from_static("x-algorand-instancename"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let public_address = response_headers
        .get(HeaderName::from_static("x-algorand-location"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    Ok(ServerResponseInfo {
        protocol_version,
        node_random: other_random.to_string(),
        genesis_id: other_genesis.to_string(),
        telemetry_id,
        instance_name,
        public_address,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Helper: build a minimal valid server response header map ----------

    fn valid_server_headers(node_random: &str, genesis_id: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-algorand-version"),
            "2.2".parse().unwrap(),
        );
        h.append(
            HeaderName::from_static("x-algorand-accept-version"),
            "2.2".parse().unwrap(),
        );
        h.insert(
            HeaderName::from_static("x-algorand-noderandom"),
            node_random.parse().unwrap(),
        );
        h.insert(
            HeaderName::from_static("x-algorand-genesis"),
            genesis_id.parse().unwrap(),
        );
        h.insert(
            HeaderName::from_static("x-algorand-telid"),
            "tel-abc".parse().unwrap(),
        );
        h.insert(
            HeaderName::from_static("x-algorand-instancename"),
            "test-node".parse().unwrap(),
        );
        h.insert(
            HeaderName::from_static("x-algorand-location"),
            "1.2.3.4:4160".parse().unwrap(),
        );
        h
    }

    // =====================================================================
    // set_headers tests
    // =====================================================================

    #[test]
    fn set_headers_includes_all_expected() {
        let params = OutgoingHeaderParams {
            genesis_id: "testnet-v1.0",
            node_random: "abc123",
            location: Some("relay.example.com:4160"),
            instance_name: "my-node",
            telemetry_id: Some("tel-xyz"),
            identity_challenge: Some("base64challenge"),
            peer_features: Some("ppzstd,avvpack"),
        };

        let headers = set_headers(&params);

        // Protocol version
        assert_eq!(
            headers.get("x-algorand-version").unwrap().to_str().unwrap(),
            "2.2"
        );

        // Accept version
        let accept_values: Vec<&str> = headers
            .get_all("x-algorand-accept-version")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert!(accept_values.contains(&"2.2"));

        // Genesis
        assert_eq!(
            headers.get("x-algorand-genesis").unwrap().to_str().unwrap(),
            "testnet-v1.0"
        );

        // Node random
        assert_eq!(
            headers
                .get("x-algorand-noderandom")
                .unwrap()
                .to_str()
                .unwrap(),
            "abc123"
        );

        // Location
        assert_eq!(
            headers
                .get("x-algorand-location")
                .unwrap()
                .to_str()
                .unwrap(),
            "relay.example.com:4160"
        );

        // Instance name
        assert_eq!(
            headers
                .get("x-algorand-instancename")
                .unwrap()
                .to_str()
                .unwrap(),
            "my-node"
        );

        // Telemetry ID
        assert_eq!(
            headers.get("x-algorand-telid").unwrap().to_str().unwrap(),
            "tel-xyz"
        );

        // Identity challenge
        assert_eq!(
            headers
                .get("x-algorand-identitychallenge")
                .unwrap()
                .to_str()
                .unwrap(),
            "base64challenge"
        );

        // Peer features
        assert_eq!(
            headers
                .get("x-algorand-peer-features")
                .unwrap()
                .to_str()
                .unwrap(),
            "ppzstd,avvpack"
        );
    }

    #[test]
    fn set_headers_optional_fields_omitted() {
        let params = OutgoingHeaderParams {
            genesis_id: "mainnet-v1.0",
            node_random: "random123",
            location: None,
            instance_name: "node-0",
            telemetry_id: None,
            identity_challenge: None,
            peer_features: None,
        };

        let headers = set_headers(&params);

        // Required headers present
        assert!(headers.get("x-algorand-version").is_some());
        assert!(headers.get("x-algorand-genesis").is_some());
        assert!(headers.get("x-algorand-noderandom").is_some());
        assert!(headers.get("x-algorand-instancename").is_some());

        // Optional headers absent (except telemetry ID and peer features
        // which are always set, matching Go's behavior).
        assert!(headers.get("x-algorand-location").is_none());
        assert_eq!(
            headers.get("x-algorand-telid").unwrap().to_str().unwrap(),
            ""
        );
        assert!(headers.get("x-algorand-identitychallenge").is_none());
        assert_eq!(
            headers
                .get("x-algorand-peer-features")
                .unwrap()
                .to_str()
                .unwrap(),
            ""
        );
    }

    #[test]
    fn set_headers_empty_location_omitted() {
        let params = OutgoingHeaderParams {
            genesis_id: "testnet-v1.0",
            node_random: "rand",
            location: Some(""),
            instance_name: "node",
            telemetry_id: Some(""),
            identity_challenge: Some(""),
            peer_features: Some(""),
        };

        let headers = set_headers(&params);

        // Empty strings should be treated as absent (except telemetry ID
        // and peer features which are always included).
        assert!(headers.get("x-algorand-location").is_none());
        assert_eq!(
            headers.get("x-algorand-telid").unwrap().to_str().unwrap(),
            ""
        );
        assert!(headers.get("x-algorand-identitychallenge").is_none());
        assert_eq!(
            headers
                .get("x-algorand-peer-features")
                .unwrap()
                .to_str()
                .unwrap(),
            ""
        );
    }

    #[test]
    fn set_headers_empty_node_random_omitted() {
        let params = OutgoingHeaderParams {
            genesis_id: "testnet-v1.0",
            node_random: "",
            location: None,
            instance_name: "node",
            telemetry_id: None,
            identity_challenge: None,
            peer_features: None,
        };

        let headers = set_headers(&params);
        assert!(headers.get("x-algorand-noderandom").is_none());
    }

    // =====================================================================
    // check_protocol_version_match tests
    // =====================================================================

    #[test]
    fn version_match_exact_accept_version() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_static("x-algorand-accept-version"),
            "2.2".parse().unwrap(),
        );

        let result = check_protocol_version_match(&headers, SUPPORTED_PROTOCOL_VERSIONS);
        assert_eq!(result, VersionMatch::Matched("2.2".to_string()));
    }

    #[test]
    fn version_match_multiple_accept_versions() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_static("x-algorand-accept-version"),
            "2.1".parse().unwrap(),
        );
        headers.append(
            HeaderName::from_static("x-algorand-accept-version"),
            "2.2".parse().unwrap(),
        );
        headers.append(
            HeaderName::from_static("x-algorand-accept-version"),
            "2.3".parse().unwrap(),
        );

        let result = check_protocol_version_match(&headers, SUPPORTED_PROTOCOL_VERSIONS);
        assert_eq!(result, VersionMatch::Matched("2.2".to_string()));
    }

    #[test]
    fn version_match_fallback_to_protocol_version() {
        let mut headers = HeaderMap::new();
        // No accept-version, only the version header
        headers.insert(
            HeaderName::from_static("x-algorand-version"),
            "2.2".parse().unwrap(),
        );

        let result = check_protocol_version_match(&headers, SUPPORTED_PROTOCOL_VERSIONS);
        assert_eq!(result, VersionMatch::Matched("2.2".to_string()));
    }

    #[test]
    fn version_match_accept_takes_priority_over_version() {
        let mut headers = HeaderMap::new();
        // Version header has a non-matching version
        headers.insert(
            HeaderName::from_static("x-algorand-version"),
            "1.0".parse().unwrap(),
        );
        // But accept-version has a match
        headers.append(
            HeaderName::from_static("x-algorand-accept-version"),
            "2.2".parse().unwrap(),
        );

        let result = check_protocol_version_match(&headers, SUPPORTED_PROTOCOL_VERSIONS);
        assert_eq!(result, VersionMatch::Matched("2.2".to_string()));
    }

    #[test]
    fn version_mismatch_no_compatible_version() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-algorand-version"),
            "1.0".parse().unwrap(),
        );
        headers.append(
            HeaderName::from_static("x-algorand-accept-version"),
            "1.0".parse().unwrap(),
        );

        let result = check_protocol_version_match(&headers, SUPPORTED_PROTOCOL_VERSIONS);
        assert_eq!(
            result,
            VersionMatch::NoMatch {
                other_version: "1.0".to_string()
            }
        );
    }

    #[test]
    fn version_mismatch_no_headers_at_all() {
        let headers = HeaderMap::new();

        let result = check_protocol_version_match(&headers, SUPPORTED_PROTOCOL_VERSIONS);
        assert_eq!(
            result,
            VersionMatch::NoMatch {
                other_version: String::new()
            }
        );
    }

    #[test]
    fn version_mismatch_only_incompatible_accept() {
        let mut headers = HeaderMap::new();
        headers.append(
            HeaderName::from_static("x-algorand-accept-version"),
            "3.0".parse().unwrap(),
        );
        // No x-algorand-version header at all
        let result = check_protocol_version_match(&headers, SUPPORTED_PROTOCOL_VERSIONS);
        assert_eq!(
            result,
            VersionMatch::NoMatch {
                other_version: String::new()
            }
        );
    }

    // =====================================================================
    // check_server_response_variables tests
    // =====================================================================

    #[test]
    fn valid_server_response() {
        let headers = valid_server_headers("server-random-42", "testnet-v1.0");

        let info = check_server_response_variables(
            &headers,
            SUPPORTED_PROTOCOL_VERSIONS,
            "my-random-99",
            "testnet-v1.0",
        )
        .expect("should succeed");

        assert_eq!(info.protocol_version, "2.2");
        assert_eq!(info.node_random, "server-random-42");
        assert_eq!(info.genesis_id, "testnet-v1.0");
        assert_eq!(info.telemetry_id, "tel-abc");
        assert_eq!(info.instance_name, "test-node");
        assert_eq!(info.public_address, "1.2.3.4:4160");
    }

    #[test]
    fn version_mismatch_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-algorand-version"),
            "1.0".parse().unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-algorand-noderandom"),
            "other".parse().unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-algorand-genesis"),
            "testnet-v1.0".parse().unwrap(),
        );

        let result = check_server_response_variables(
            &headers,
            SUPPORTED_PROTOCOL_VERSIONS,
            "mine",
            "testnet-v1.0",
        );

        assert!(result.is_err());
        assert!(
            matches!(result, Err(HandshakeError::VersionMismatch { .. })),
            "expected VersionMismatch, got: {result:?}"
        );
    }

    #[test]
    fn self_loop_detected_same_node_random() {
        let headers = valid_server_headers("same-random", "testnet-v1.0");

        let result = check_server_response_variables(
            &headers,
            SUPPORTED_PROTOCOL_VERSIONS,
            "same-random", // same as server
            "testnet-v1.0",
        );

        assert!(result.is_err());
        assert!(
            matches!(result, Err(HandshakeError::SelfLoop)),
            "expected SelfLoop, got: {result:?}"
        );
    }

    #[test]
    fn empty_node_random_rejected() {
        let mut headers = valid_server_headers("", "testnet-v1.0");
        // Remove the node random since empty string won't be stored
        headers.remove(HeaderName::from_static("x-algorand-noderandom"));

        let result = check_server_response_variables(
            &headers,
            SUPPORTED_PROTOCOL_VERSIONS,
            "my-random",
            "testnet-v1.0",
        );

        assert!(result.is_err());
        assert!(
            matches!(result, Err(HandshakeError::MissingHeader(_))),
            "expected MissingHeader, got: {result:?}"
        );
    }

    #[test]
    fn missing_node_random_header_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-algorand-version"),
            "2.2".parse().unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-algorand-genesis"),
            "testnet-v1.0".parse().unwrap(),
        );
        // No x-algorand-noderandom header

        let result = check_server_response_variables(
            &headers,
            SUPPORTED_PROTOCOL_VERSIONS,
            "my-random",
            "testnet-v1.0",
        );

        assert!(result.is_err());
        assert!(
            matches!(result, Err(HandshakeError::MissingHeader(_))),
            "expected MissingHeader, got: {result:?}"
        );
    }

    #[test]
    fn genesis_id_mismatch_rejected() {
        let headers = valid_server_headers("server-rand", "mainnet-v1.0");

        let result = check_server_response_variables(
            &headers,
            SUPPORTED_PROTOCOL_VERSIONS,
            "my-rand",
            "testnet-v1.0", // expecting testnet, server says mainnet
        );

        assert!(result.is_err());
        assert!(
            matches!(result, Err(HandshakeError::GenesisMismatch { .. })),
            "expected GenesisMismatch, got: {result:?}"
        );
    }

    #[test]
    fn missing_genesis_header_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-algorand-version"),
            "2.2".parse().unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-algorand-noderandom"),
            "server-rand".parse().unwrap(),
        );
        // No genesis header

        let result = check_server_response_variables(
            &headers,
            SUPPORTED_PROTOCOL_VERSIONS,
            "my-rand",
            "testnet-v1.0",
        );

        assert!(result.is_err());
        assert!(
            matches!(result, Err(HandshakeError::GenesisMismatch { .. })),
            "expected GenesisMismatch, got: {result:?}"
        );
    }

    #[test]
    fn empty_genesis_header_rejected() {
        let mut headers = valid_server_headers("server-rand", "");
        // Empty genesis value — should still reject because it doesn't match
        headers.insert(
            HeaderName::from_static("x-algorand-genesis"),
            "".parse().unwrap(),
        );

        let result = check_server_response_variables(
            &headers,
            SUPPORTED_PROTOCOL_VERSIONS,
            "my-rand",
            "testnet-v1.0",
        );

        assert!(result.is_err());
        assert!(
            matches!(result, Err(HandshakeError::GenesisMismatch { .. })),
            "expected GenesisMismatch, got: {result:?}"
        );
    }

    #[test]
    fn optional_fields_may_be_absent() {
        // Minimal valid headers — only the three required fields
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-algorand-version"),
            "2.2".parse().unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-algorand-noderandom"),
            "server-rand".parse().unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-algorand-genesis"),
            "testnet-v1.0".parse().unwrap(),
        );

        let info = check_server_response_variables(
            &headers,
            SUPPORTED_PROTOCOL_VERSIONS,
            "my-rand",
            "testnet-v1.0",
        )
        .expect("should succeed with minimal headers");

        assert_eq!(info.protocol_version, "2.2");
        assert_eq!(info.node_random, "server-rand");
        assert_eq!(info.genesis_id, "testnet-v1.0");
        assert!(info.telemetry_id.is_empty());
        assert!(info.instance_name.is_empty());
        assert!(info.public_address.is_empty());
    }

    // =====================================================================
    // gossip_path tests
    // =====================================================================

    #[test]
    fn gossip_path_substitution() {
        assert_eq!(gossip_path("testnet-v1.0"), "/v1/testnet-v1.0/gossip");
        assert_eq!(gossip_path("mainnet-v1.0"), "/v1/mainnet-v1.0/gossip");
    }

    // =====================================================================
    // Header constant value tests
    // =====================================================================

    #[test]
    fn header_constant_values_match_go() {
        assert_eq!(PROTOCOL_VERSION_HEADER, "X-Algorand-Version");
        assert_eq!(PROTOCOL_ACCEPT_VERSION_HEADER, "X-Algorand-Accept-Version");
        assert_eq!(TELEMETRY_ID_HEADER, "X-Algorand-TelId");
        assert_eq!(GENESIS_HEADER, "X-Algorand-Genesis");
        assert_eq!(NODE_RANDOM_HEADER, "X-Algorand-NodeRandom");
        assert_eq!(ADDRESS_HEADER, "X-Algorand-Location");
        assert_eq!(INSTANCE_NAME_HEADER, "X-Algorand-InstanceName");
        assert_eq!(PRIORITY_CHALLENGE_HEADER, "X-Algorand-PriorityChallenge");
        assert_eq!(IDENTITY_CHALLENGE_HEADER, "X-Algorand-IdentityChallenge");
        assert_eq!(PEER_FEATURES_HEADER, "X-Algorand-Peer-Features");
        assert_eq!(TOO_MANY_REQUESTS_RETRY_AFTER_HEADER, "Retry-After");
        assert_eq!(USER_AGENT_HEADER, "User-Agent");
    }

    #[test]
    fn protocol_version_constants_match_go() {
        assert_eq!(PROTOCOL_VERSION, "2.2");
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS, &["2.2"]);
    }

    #[test]
    fn gossip_network_path_constant_matches_go() {
        assert_eq!(GOSSIP_NETWORK_PATH, "/v1/{genesisID}/gossip");
    }
}
