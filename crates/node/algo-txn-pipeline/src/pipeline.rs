//! The build → sign → submit → confirm pipeline for goal-rust subcommands.

use std::time::Duration;

use algo_codec::canonical_encode_transaction;
use algo_kmd_client::KmdClient;
use algo_rest_client::{AlgodClient, BlockSource, PendingTxnInfo, SuggestedParams, TxId};
use algo_types::Transaction;

use crate::error::{PipelineError, Result};

/// How long to wait between confirmation polls.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Composes the algod REST client and (optionally) the kmd wallet client into
/// the single path goal-rust subcommands use to construct, sign, broadcast, and
/// confirm a transaction. Phase C (`clerk`) reuses this verbatim, adding pay /
/// axfer / acfg / afrz / appl builders alongside [`KeyregBuilder`].
pub struct TxnPipeline {
    algod: AlgodClient,
    kmd: Option<KmdClient>,
}

impl TxnPipeline {
    /// Create a pipeline. `kmd` may be `None` for read-only / write-to-file
    /// flows that never sign through a wallet.
    pub fn new(algod: AlgodClient, kmd: Option<KmdClient>) -> Self {
        TxnPipeline { algod, kmd }
    }

    /// Borrow the underlying algod client (for queries the pipeline doesn't wrap).
    pub fn algod(&self) -> &AlgodClient {
        &self.algod
    }

    /// Borrow the kmd client, if one was configured (for wallet-handle
    /// resolution that lives outside the pipeline).
    pub fn kmd(&self) -> Option<&KmdClient> {
        self.kmd.as_ref()
    }

    /// Fetch the network's suggested transaction parameters.
    pub async fn suggested_params(&self) -> Result<SuggestedParams> {
        Ok(self.algod.suggested_transaction_params().await?)
    }

    /// Current last-committed round (used to compute validity windows).
    pub async fn current_round(&self) -> Result<u64> {
        Ok(self.algod.get_status().await?.last_round)
    }

    /// Sign an unsigned transaction via kmd, returning the msgpack-encoded
    /// `SignedTransaction` bytes. The signer key is inferred from the
    /// transaction sender (go's `signerAddress == ""` path).
    pub async fn sign_with_kmd(
        &self,
        wallet_handle: &str,
        wallet_password: &str,
        txn: &Transaction,
    ) -> Result<Vec<u8>> {
        let kmd = self.kmd.as_ref().ok_or(PipelineError::NoKmdClient)?;
        let encoded = canonical_encode_transaction(txn);
        // `[0u8; 32]` tells kmd to infer the signer from the txn sender.
        let resp = kmd
            .sign_transaction(wallet_handle, wallet_password, encoded, [0u8; 32])
            .await?;
        Ok(resp.signed_transaction)
    }

    /// Broadcast a raw (msgpack-encoded) signed transaction, returning its txid.
    pub async fn submit(&self, raw_signed: &[u8]) -> Result<TxId> {
        Ok(self.algod.send_raw_transaction(raw_signed).await?)
    }

    /// Poll until the transaction is committed, rejected, or `max_rounds` have
    /// elapsed since the call began. Mirrors go-algorand's `waitForCommit`
    /// (`cmd/goal/clerk.go:198`): commit returns the pending info, a pool error
    /// surfaces as [`PipelineError::PoolRejected`], and exhausting the window
    /// surfaces as [`PipelineError::NotConfirmed`].
    pub async fn wait_for_confirmation(
        &self,
        txid: &TxId,
        max_rounds: u64,
    ) -> Result<PendingTxnInfo> {
        let start_round = self.current_round().await?;
        loop {
            let info = self.algod.get_pending_transaction(txid).await?;
            if info.is_committed() {
                return Ok(info);
            }
            if info.is_rejected() {
                return Err(PipelineError::PoolRejected {
                    txid: txid.to_string(),
                    pool_error: info.pool_error,
                });
            }
            let current = self.current_round().await?;
            if current.saturating_sub(start_round) >= max_rounds {
                return Err(PipelineError::NotConfirmed {
                    txid: txid.to_string(),
                    rounds: max_rounds,
                });
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
}
