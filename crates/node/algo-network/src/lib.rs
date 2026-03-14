pub mod block_cert;
pub mod compression;
pub mod connect;
pub mod errors;
pub mod forwarding_policy;
pub mod framing;
pub mod handler;
pub mod handshake;
pub mod identity;
pub mod message;
pub mod msg_of_interest;
pub mod peer_features;
pub mod reconnect;
pub mod tag;
pub mod topics;
pub mod ws_peer;

pub mod discovery;
pub mod dns_bootstrap;
pub mod gossip_node;
pub mod message_filter;
pub mod peer_role;
pub mod phonebook;
pub mod request_response;
pub mod srv_resolver;

// ---------------------------------------------------------------------------
// Re-exports: gossip wire format (Epic 30)
// ---------------------------------------------------------------------------

// Block certificates
pub use block_cert::{
    Certificate, EncodedBlockCert, EquivocationVoteAuthenticator, OneTimeSignature, ProposalValue,
    UnauthenticatedCredential, VoteAuthenticator,
};

// Compression
pub use compression::{
    is_zstd_compressed, zstd_compress, zstd_decompress, CompressionError,
    MAX_DECOMPRESSED_MESSAGE_SIZE, ZSTD_MAGIC,
};

// Framing
pub use framing::{decode_frame, encode_frame, NetworkError};

// Forwarding policy
pub use forwarding_policy::ForwardingPolicy;

// Messages
pub use message::{IncomingMessage, OutgoingMessage};

// Message-of-interest filtering
pub use msg_of_interest::{marshal_msg_of_interest, unmarshal_msg_of_interest, MsgOfInterestError};

// Tags
pub use tag::{Tag, MAX_MESSAGE_LENGTH, TAG_LENGTH};

// Topics (request/response key-value pairs)
pub use topics::{
    Topic, Topics, TopicsError, BLOCK_AND_CERT_VALUE, BLOCK_DATA_KEY, CERT_DATA_KEY, ERROR_KEY,
    LATEST_ROUND_KEY, REQUEST_DATA_TYPE_KEY, REQUEST_HASH_KEY, ROUND_KEY,
};

// ---------------------------------------------------------------------------
// Re-exports: WebSocket peer connectivity (Epic 31)
// ---------------------------------------------------------------------------

// Error taxonomy
pub use errors::{HandshakeError, IdentityError, PeerError, PhonebookError, WsConnectError};

// Handshake: header building, protocol version negotiation, server response
// validation, gossip path construction
pub use handshake::{
    check_protocol_version_match, check_server_response_variables, gossip_path, set_headers,
    OutgoingHeaderParams, ServerResponseInfo, VersionMatch, GOSSIP_NETWORK_PATH, PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};

// Identity: challenge-response protocol types and flow functions
pub use identity::{
    attach_challenge_header, attach_response_header, build_identity_verification,
    generate_challenge, verify_challenge_and_respond, verify_challenge_response,
    verify_identity_verification, IdentityChallengeResponseSigned, IdentityChallengeSigned,
    IdentityVerificationMessageSigned, PeerIdentity,
};

// Peer feature negotiation
pub use peer_features::{decode_peer_features, encode_peer_features, PeerFeatureFlags};

// WebSocket peer abstraction
pub use ws_peer::{PeerHandle, PeerSender, WsPeer, WsPeerConfig};

// Reconnection supervisor with exponential backoff
pub use reconnect::{
    classify_connect_error, classify_handshake_error, classify_peer_error, ConnectionFailure,
    ExponentialBackoff, ReconnectEvent, ReconnectPolicy, ReconnectSupervisor, SupervisorError,
    TerminalAction,
};

// ---------------------------------------------------------------------------
// Re-exports: Peer Discovery and Phonebook (Epic 32)
// ---------------------------------------------------------------------------

// Peer roles
pub use peer_role::{Role, RoleSet, ARCHIVAL_ROLE, RELAY_ROLE};

// DNS bootstrap
pub use dns_bootstrap::{DnsBootstrap, DnsBootstrapError};

// SRV resolver
pub use srv_resolver::{
    resolve_addresses, HickorySrvResolver, SrvRecord, SrvResolveError, SrvResolver,
};

// Phonebook
pub use phonebook::Phonebook;

// Discovery
pub use discovery::Discovery;

// ---------------------------------------------------------------------------
// Re-exports: Message Handler Framework (Epic 33a)
// ---------------------------------------------------------------------------

// Handler traits and dispatch
pub use handler::{
    MessageHandler, MessageValidatorHandler, Multiplexer, TaggedMessageHandler,
    TaggedMessageValidatorHandler, ValidatedMessage,
};

// ---------------------------------------------------------------------------
// Re-exports: Message deduplication filter (Epic 33a)
// ---------------------------------------------------------------------------

// Digest-based seen-message cache
pub use message_filter::{
    dedup_safe_tag, generate_message_digest, MessageFilter, MESSAGE_FILTER_SIZE,
};

// ---------------------------------------------------------------------------
// Re-exports: GossipNode trait and Peer abstraction (Epic 33a)
// ---------------------------------------------------------------------------

// GossipNode network abstraction
pub use gossip_node::{substitute_genesis_id, GossipNode, Peer, PeerOption};

// ---------------------------------------------------------------------------
// Re-exports: Request/Response correlation (Epic 33a)
// ---------------------------------------------------------------------------

// Request/response tracker and constants
pub use request_response::{
    hash_topics, RequestResponseError, RequestTracker, DEFAULT_REQUEST_TIMEOUT,
    REQUEST_NONCE_FIELD, RESPONSE_HASH_FIELD,
};

// ---------------------------------------------------------------------------
// Message filtering helpers
// ---------------------------------------------------------------------------

/// Returns `true` if this tag represents a message type that the node needs to
/// process during block sync.
///
/// For the initial networking pass the node only needs:
/// - `TS` (TopicMsgResp) -- block-service responses carrying block+cert data
/// - `MI` (MsgOfInterest) -- peer interest negotiation
/// - `UE` (UniEnsBlockReq) -- block-service requests (catchup protocol)
///
/// All other message families (agreement votes, proposals, transactions, state
/// proofs, etc.) are decoded at the framing layer but can be safely discarded
/// until those subsystems are implemented.
pub fn is_block_sync_related(tag: &Tag) -> bool {
    matches!(
        tag,
        Tag::TopicMsgResp | Tag::MsgOfInterest | Tag::UniEnsBlockReq
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_sync_related_tags() {
        assert!(is_block_sync_related(&Tag::TopicMsgResp));
        assert!(is_block_sync_related(&Tag::MsgOfInterest));
        assert!(is_block_sync_related(&Tag::UniEnsBlockReq));
    }

    #[test]
    fn non_block_sync_tags_ignored() {
        let ignored = [
            Tag::AgreementVote,
            Tag::VotePacked,
            Tag::VoteBundle,
            Tag::ProposalPayload,
            Tag::Transaction,
            Tag::StateProofSig,
            Tag::NetPrioResponse,
            Tag::NetIDVerification,
            Tag::MsgDigestSkip,
        ];
        for tag in &ignored {
            assert!(
                !is_block_sync_related(tag),
                "{tag} should not be block-sync related"
            );
        }
    }

    #[test]
    fn deprecated_tags_not_block_sync_related() {
        assert!(!is_block_sync_related(&Tag::PingDeprecated));
        assert!(!is_block_sync_related(&Tag::PingReplyDeprecated));
    }
}
