//! Certificate cross-verification helpers (PLAN-32 / TASK-88).
//!
//! The library holds the small amount of glue code that converts a
//! `BlockResponse` fetched over REST into the `(Block, Certificate)` pair
//! [`algo_agreement::Certificate::authenticate`] expects. The binary
//! (`src/main.rs`) wires it to the REST client, a sqlite-backed
//! `AgreementLedgerBridge`, and a CLI.
//!
//! Scope today is the **Go → Rust** verification direction only:
//!   - fetch (block, cert) from a Go algod REST node
//!   - decode cert from its msgpack-native form
//!   - call `Certificate::authenticate` against an algod-rust ledger
//!     that is caught up to the target round.
//!
//! The inverse (Rust-produced cert verified by Go) requires the Rust
//! node to be running with participation keys — tracked under PLAN-35.

use algo_agreement::{codec as agreement_codec, Certificate};
use algo_codec::compute_block_digest;
use algo_types::{Block, BlockResponse, Digest};
use anyhow::{Context, Result};

/// Certificate extracted from a [`BlockResponse`] + the block's locally
/// computed digest.
#[derive(Debug, Clone)]
pub struct VerifiablePair {
    pub block: Block,
    pub block_digest: Digest,
    pub certificate: Certificate,
}

/// Convert a [`BlockResponse`] (as returned by the REST client) into the
/// shape `Certificate::authenticate` consumes.
///
/// Fails if the response lacks a cert or the cert msgpack Value can't be
/// re-encoded / decoded into an `UnauthenticatedBundle`.
pub fn pair_from_response(resp: BlockResponse) -> Result<VerifiablePair> {
    let BlockResponse { block, cert } = resp;
    let cert_value = cert.context("response has no `cert` field — cannot verify")?;

    // Re-encode the rmpv::Value back to canonical msgpack bytes and
    // decode as an UnauthenticatedBundle via the agreement codec. This
    // keeps us on the same decode path the algod-rust gossip layer uses
    // and avoids depending on a parallel Certificate serde shape.
    let mut cert_bytes = Vec::<u8>::new();
    rmpv::encode::write_value(&mut cert_bytes, &cert_value)
        .context("re-encoding cert rmpv::Value to msgpack")?;
    let bundle = agreement_codec::decode_bundle(&cert_bytes)
        .map_err(|e| anyhow::anyhow!("decode_bundle: {e}"))?;
    let certificate = Certificate::from_bundle(&bundle);

    let block_digest = compute_block_digest(&block);
    Ok(VerifiablePair {
        block,
        block_digest,
        certificate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use algo_types::Block;

    /// Regression: `pair_from_response` rejects a response with a
    /// missing `cert` field. (We pass `?format=msgpack` so cert is
    /// usually present, but defensively guard in case a future change
    /// in Go's envelope omits it.)
    #[test]
    fn pair_from_response_requires_cert() {
        let resp = BlockResponse {
            block: Block::default(),
            cert: None,
        };
        let err = pair_from_response(resp).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no `cert`"), "unexpected error: {msg}");
    }
}
