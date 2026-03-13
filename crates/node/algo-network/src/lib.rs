pub mod block_cert;
pub mod compression;
pub mod framing;
pub mod message;
pub mod msg_of_interest;
pub mod tag;
pub mod topics;

// Re-exports: primary types and functions at crate root.
pub use block_cert::{
    Certificate, EncodedBlockCert, EquivocationVoteAuthenticator, OneTimeSignature, ProposalValue,
    UnauthenticatedCredential, VoteAuthenticator,
};
pub use compression::{
    is_zstd_compressed, zstd_compress, zstd_decompress, CompressionError,
    MAX_DECOMPRESSED_MESSAGE_SIZE, ZSTD_MAGIC,
};
pub use framing::{decode_frame, encode_frame, NetworkError};
pub use message::{IncomingMessage, OutgoingMessage};
pub use msg_of_interest::{marshal_msg_of_interest, unmarshal_msg_of_interest, MsgOfInterestError};
pub use tag::{Tag, MAX_MESSAGE_LENGTH, TAG_LENGTH};
pub use topics::{
    Topic, Topics, TopicsError, BLOCK_AND_CERT_VALUE, BLOCK_DATA_KEY, CERT_DATA_KEY, ERROR_KEY,
    LATEST_ROUND_KEY, REQUEST_DATA_TYPE_KEY, REQUEST_HASH_KEY, ROUND_KEY,
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
