use algo_codec::decode_block_response;
use algo_error::{AlgoError, Result};
use algo_types::{BlockResponse, Round};
use async_trait::async_trait;
use tracing::debug;

use crate::{BlockSource, NodeStatus};

/// REST API client for a go-algorand node.
pub struct AlgodClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl AlgodClient {
    /// Create a new client with the given base URL and API token.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http: reqwest::Client::new(),
        }
    }

    fn request(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .get(format!("{}{}", self.base_url, path))
            .header("X-Algo-API-Token", &self.token)
    }
}

#[async_trait]
impl BlockSource for AlgodClient {
    async fn get_block_raw(&self, round: Round) -> Result<Vec<u8>> {
        debug!(round = %round, "fetching block (msgpack)");

        let resp = self
            .request(&format!("/v2/blocks/{}?format=msgpack", round))
            .send()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("GET /v2/blocks/{round}"),
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AlgoError::Conformance {
                message: format!("GET /v2/blocks/{round} returned {status}: {body}"),
            });
        }

        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("reading body for block {round}"),
            })
    }

    async fn get_block(&self, round: Round) -> Result<BlockResponse> {
        let bytes = self.get_block_raw(round).await?;
        decode_block_response(&bytes)
    }

    async fn get_status(&self) -> Result<NodeStatus> {
        debug!("fetching node status");

        let resp = self
            .request("/v2/status")
            .send()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "GET /v2/status".into(),
            })?;

        resp.json::<NodeStatus>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing /v2/status response".into(),
            })
    }

    async fn wait_for_round(&self, round: Round) -> Result<NodeStatus> {
        debug!(round = %round, "waiting for round");

        let resp = self
            .request(&format!("/v2/status/wait-for-block-after/{}", round))
            .send()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("GET /v2/status/wait-for-block-after/{round}"),
            })?;

        resp.json::<NodeStatus>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("parsing wait-for-block-after/{round} response"),
            })
    }
}
