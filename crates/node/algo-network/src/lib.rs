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

pub mod agreement_network;
pub mod block_cert;
pub mod block_fetcher;
pub mod block_service;
pub mod bloom;
pub mod broadcast;
pub mod compression;
pub mod connect;
pub mod errors;
pub mod forwarding_policy;
pub mod framing;
pub mod handler;
pub mod handshake;
pub mod health_service;
pub mod identity;
pub mod listener;
pub mod message;
pub mod msg_of_interest;
pub mod peer_features;
pub mod peer_ranker;
pub mod reconnect;
pub mod tag;
pub mod topics;
pub mod ws_peer;

pub mod discovery;
pub mod dns_bootstrap;
pub mod gossip_node;
pub mod local_tx_broadcast;
pub mod mesh;
pub mod message_filter;
pub mod peer_role;
pub mod phonebook;
pub mod request_response;
pub mod request_tracker;
pub mod srv_resolver;
pub mod tx_sync_client;
pub mod tx_sync_pool_adapter;
pub mod tx_sync_service;
pub mod tx_syncer;
pub mod tx_tag_handler;
pub mod vpack;
pub mod ws_network;

// ---------------------------------------------------------------------------
// Re-exports: gossip wire format (Epic 30)
// ---------------------------------------------------------------------------

// Block certificates
pub use block_cert::{
    Certificate, EncodedBlockCert, EquivocationVoteAuthenticator, OneTimeSignature, ProposalValue,
    UnauthenticatedCredential, VoteAuthenticator,
};

// Block fetch primitives (WS unicast catchup protocol)
pub use block_fetcher::{
    decode_round_from_uvarint, format_round_base36, make_block_request_topics,
    parse_block_response, BlockFetchError, BlockResponseData,
};

// Block service (HTTP and WebSocket block serving)
pub use block_service::{
    BlockService, BlockServiceError, LedgerForBlockService, MemoryGuard,
    BLOCK_RESPONSE_CONTENT_TYPE, DEFAULT_BLOCK_SERVICE_MEM_CAP,
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
pub use ws_peer::{PeerHandle, PeerSender, UnicastPeerRef, WsPeer, WsPeerConfig};

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

// GossipNode network abstraction and unicast peer interface
pub use gossip_node::{substitute_genesis_id, GossipNode, Peer, PeerOption, Router, UnicastPeer};

// ---------------------------------------------------------------------------
// Re-exports: Request/Response correlation (Epic 33a)
// ---------------------------------------------------------------------------

// Request/response tracker and constants
pub use request_response::{
    encode_uvarint, hash_topics, RequestResponseError, RequestTracker, DEFAULT_REQUEST_TIMEOUT,
    REQUEST_NONCE_FIELD, RESPONSE_HASH_FIELD,
};

// ---------------------------------------------------------------------------
// Re-exports: Per-IP connection tracking and rate limiting
// ---------------------------------------------------------------------------

// Connection-level tracking (per-IP connection counts + sliding-window rate limit)
pub use request_tracker::ConnectionTracker;

// ---------------------------------------------------------------------------
// Re-exports: Health service (HTTP /status endpoint)
// ---------------------------------------------------------------------------

pub use health_service::{health_check, health_router, HealthResponse, HEALTH_SERVICE_STATUS_PATH};

// ---------------------------------------------------------------------------
// Re-exports: Rejecting limit listener (Epic 34)
// ---------------------------------------------------------------------------

// Semaphore-based TCP connection limiter
pub use listener::{ConnectionGuard, RejectingLimitListener, RESERVED_HEALTH_SERVICE_CONNECTIONS};

// ---------------------------------------------------------------------------
// Re-exports: WebsocketNetwork coordinator (Epic 33b)
// ---------------------------------------------------------------------------

// WebSocket network coordinator implementing GossipNode
pub use ws_network::{
    PeerDirection, WebsocketNetwork, WebsocketNetworkConfig, UNBOUNDED_BROADCAST_CONNECTIONS_LIMIT,
};

// Mesh connectivity thread — maintains target outgoing connection count
pub use mesh::{
    ConnectFn, MeshRequest, MeshThread, PeerCounter, DEFAULT_GOSSIP_FANOUT, DEFAULT_MESH_INTERVAL,
};

// ---------------------------------------------------------------------------
// Re-exports: Broadcast thread (priority queues, stale dropping)
// ---------------------------------------------------------------------------

// Background broadcast with priority queues and connection limit
pub use broadcast::{
    is_high_priority_tag, BroadcastError, BroadcastHandle, BroadcastPeer, BroadcastThread,
    PeerSendRef, MAX_MESSAGE_QUEUE_DURATION,
};

// ---------------------------------------------------------------------------
// Re-exports: Agreement network bridge (GossipNode -> AgreementNetwork)
// ---------------------------------------------------------------------------

// Bridge adapting GossipNode to algo-agreement's AgreementNetwork trait
pub use agreement_network::{
    agreement_tag_to_network_tag, network_tag_to_agreement_tag, AgreementNetworkBridge,
    AgreementNetworkConfig, DEFAULT_BUNDLE_QUEUE_LEN, DEFAULT_PROPOSAL_QUEUE_LEN,
    DEFAULT_VOTE_QUEUE_LEN,
};

// ---------------------------------------------------------------------------
// Re-exports: Transaction synchronizer (Plan 33, gap G1 — skeleton)
// ---------------------------------------------------------------------------

// TxSyncer state machine, peer / pool / handler abstractions, seen-hash LRU
pub use tx_syncer::{
    sync_round, NoOpSolicitedTxHandler, PeerSource, PendingTxAggregate, SeenTxCache,
    SolicitedTxHandler, TxSyncError, TxSyncPeerClient, TxSyncer, TxSyncerConfig,
};

// ---------------------------------------------------------------------------
// Re-exports: TxSyncer production pool adapters (issue #774)
// ---------------------------------------------------------------------------

// PendingTxAggregate / SolicitedTxHandler backed by a real TransactionPool
pub use tx_sync_pool_adapter::{PoolPendingTxAggregate, PoolSolicitedTxHandler};

// ---------------------------------------------------------------------------
// Re-exports: Transaction-sync HTTP service (issue #774)
// ---------------------------------------------------------------------------

// Server side of the TxSyncer pull protocol
pub use tx_sync_service::{
    PendingTxGroupsSource, TxSyncPeerLimiter, TxSyncService, TX_SYNC_REQUEST_CONTENT_TYPE,
    TX_SYNC_RESPONSE_CONTENT_TYPE,
};

// go-algorand-wire-compatible Bloom filter (issue #792)
pub use bloom::{BloomDecodeError, Filter as BloomFilter};

// Client (peer) side of the TxSyncer pull protocol
pub use tx_sync_client::{GossipTxSyncPeerSource, HttpTxSyncClient};

// ---------------------------------------------------------------------------
// Re-exports: TX-tag inbound handler (Plan 33, gap G1 — inbound half)
// ---------------------------------------------------------------------------

// Decoder + MessageHandler for inbound TX-tagged gossip messages
pub use tx_tag_handler::{decode_tx_message, TxTagError, TxTagHandler, MAX_TX_GROUP_SIZE};

// ---------------------------------------------------------------------------
// Re-exports: Local txn broadcast (Plan 33, gap G1 — outbound half)
// ---------------------------------------------------------------------------

// Pool ingest trait, adapter, and local-txn broadcast orchestrator
pub use local_tx_broadcast::{
    encode_tx_group, LocalTxBroadcaster, LocalTxError, PoolIngest, PoolIngestAdapter,
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
