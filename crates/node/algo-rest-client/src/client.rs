use std::time::Duration;

use algo_codec::decode_block_response;
use algo_error::{AlgoError, Result};
use algo_types::{BlockResponse, Round};
use async_trait::async_trait;
use tracing::{debug, warn};

use crate::{
    AccountInfo, AlgodVersions, BlockSource, NodeStatus, ParticipationKey, ParticipationKeyAdded,
    PendingTxnInfo, PostTransactionResponse, SuggestedParams, TealCompileResult, TxId,
};

/// Configuration for the REST client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Request timeout for normal requests (default: 30s).
    pub timeout: Duration,
    /// Request timeout for long-poll requests like wait_for_round (default: 5min).
    pub long_poll_timeout: Duration,
    /// Maximum number of retry attempts (default: 3).
    pub max_retries: u32,
    /// Initial backoff duration, doubled each retry (default: 100ms).
    pub initial_backoff: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            long_poll_timeout: Duration::from_secs(300),
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
        }
    }
}

/// REST API client for a go-algorand node.
pub struct AlgodClient {
    base_url: String,
    token: String,
    http: reqwest::Client,
    long_poll_http: reqwest::Client,
    config: ClientConfig,
}

impl AlgodClient {
    /// Create a new client with default configuration.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self::with_config(base_url, token, ClientConfig::default())
    }

    /// Create a new client with custom configuration.
    pub fn with_config(
        base_url: impl Into<String>,
        token: impl Into<String>,
        config: ClientConfig,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build HTTP client");

        let long_poll_http = reqwest::Client::builder()
            .timeout(config.long_poll_timeout)
            .build()
            .expect("failed to build long-poll HTTP client");

        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http,
            long_poll_http,
            config,
        }
    }

    /// Execute a GET request with retry and exponential backoff.
    ///
    /// Retries on connection errors, timeouts, and 5xx responses.
    /// Does not retry on 4xx responses.
    async fn get_with_retry(
        &self,
        path: &str,
        client: &reqwest::Client,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);
        let mut backoff = self.config.initial_backoff;

        for attempt in 0..=self.config.max_retries {
            let mut request = client.get(&url);

            // Only add the API token header if the token is not empty
            if !self.token.is_empty() {
                request = request.header("X-Algo-API-Token", &self.token);
            }

            let result = request.send().await;

            match result {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(resp);
                    }
                    if status.is_server_error() && attempt < self.config.max_retries {
                        warn!(
                            attempt = attempt + 1,
                            max = self.config.max_retries,
                            status = %status,
                            path,
                            backoff_ms = backoff.as_millis() as u64,
                            "server error, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                    // 4xx or exhausted retries on 5xx — return the error response
                    let body = resp.text().await.unwrap_or_default();
                    if status == reqwest::StatusCode::NOT_FOUND {
                        return Err(AlgoError::NotFound(format!("GET {path}: {body}")));
                    }
                    return Err(AlgoError::Conformance {
                        message: format!("GET {path} returned {status}: {body}"),
                    });
                }
                Err(e) if is_retryable(&e) && attempt < self.config.max_retries => {
                    warn!(
                        attempt = attempt + 1,
                        max = self.config.max_retries,
                        error = %e,
                        path,
                        backoff_ms = backoff.as_millis() as u64,
                        "transient error, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
                Err(e) => {
                    return Err(AlgoError::RestClient {
                        source: Box::new(e),
                        context: format!("GET {path}"),
                    });
                }
            }
        }

        unreachable!("retry loop should always return")
    }

    /// Execute a POST request without retries.
    ///
    /// POSTs on this client today are exclusively non-idempotent transaction
    /// submission (`/v2/transactions`). Retrying after an ambiguous failure
    /// (timeout, connection drop, 5xx after the request reached algod) can
    /// silently double-submit and cause algod to reject the retry as a
    /// duplicate, even though the original submission succeeded. We propagate
    /// the original error and let the caller recover via
    /// [`AlgodClient::get_pending_transaction`] using the client-computed txid.
    ///
    /// Behavior:
    /// - 2xx → response returned to caller
    /// - 404  → [`AlgoError::NotFound`]
    /// - other non-2xx → [`AlgoError::Conformance`] with body context
    /// - transport / send error → [`AlgoError::RestClient`]
    async fn post_no_retry(
        &self,
        path: &str,
        content_type: &'static str,
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base_url, path);

        let mut request = self
            .http
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body);

        if !self.token.is_empty() {
            request = request.header("X-Algo-API-Token", &self.token);
        }

        match request.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return Ok(resp);
                }
                let body_text = resp.text().await.unwrap_or_default();
                if status == reqwest::StatusCode::NOT_FOUND {
                    return Err(AlgoError::NotFound(format!("POST {path}: {body_text}")));
                }
                Err(AlgoError::Conformance {
                    message: format!("POST {path} returned {status}: {body_text}"),
                })
            }
            Err(e) => Err(AlgoError::RestClient {
                source: Box::new(e),
                context: format!("POST {path}"),
            }),
        }
    }
}

impl AlgodClient {
    /// Fetch `/versions` (also reachable as `/v2/versions`) — returns
    /// API version list + genesis ID + base64-encoded genesis hash +
    /// build info. Mirrors Go's `algodClient.AlgodVersions()` used by
    /// `goal node status`.
    pub async fn get_versions(&self) -> algo_error::Result<AlgodVersions> {
        let resp = self.get_with_retry("/versions", &self.http).await?;
        resp.json::<AlgodVersions>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing /versions response".into(),
            })
    }

    /// Fetch account information for the given address at the latest round.
    pub async fn get_account(&self, addr: &algo_types::Address) -> algo_error::Result<AccountInfo> {
        let path = format!("/v2/accounts/{}", addr.to_algorand_string());
        let resp = self.get_with_retry(&path, &self.http).await?;
        resp.json::<AccountInfo>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("parsing account info for {}", addr.to_algorand_string()),
            })
    }

    /// Fetch account information for the given address at a specific round.
    ///
    /// Requires the node to have historical data for the requested round
    /// (i.e., an archival node or a node that hasn't pruned that round yet).
    pub async fn get_account_at_round(
        &self,
        addr: &algo_types::Address,
        round: u64,
    ) -> algo_error::Result<AccountInfo> {
        let path = format!("/v2/accounts/{}?round={}", addr.to_algorand_string(), round);
        let resp = self.get_with_retry(&path, &self.http).await?;
        resp.json::<AccountInfo>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!(
                    "parsing account info for {} at round {}",
                    addr.to_algorand_string(),
                    round
                ),
            })
    }
}

impl AlgodClient {
    /// Submit a single msgpack-encoded `SignedTxn` (or transaction group) to the
    /// node via `POST /v2/transactions`. Returns the txid the node assigns to
    /// (the first transaction of) the group.
    ///
    /// The node validates the txn against the current consensus protocol and
    /// adds it to the transaction pool synchronously. A 400 response indicates
    /// the pool rejected the transaction (bad signature, insufficient fee,
    /// stale validity window, etc.); a 503 indicates the node is currently
    /// catching up.
    ///
    /// Ported reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go:1090`
    /// (`RawTransaction`). Content-Type is `application/x-binary` per the
    /// algod OpenAPI spec.
    ///
    /// **Not retried.** Transaction submission is not idempotent — retrying
    /// after an ambiguous failure (timeout, dropped connection, 5xx after the
    /// request reached the node) can cause silent double-submission. On error,
    /// callers can recover by computing the txid locally and polling
    /// [`Self::get_pending_transaction`].
    pub async fn send_raw_transaction(&self, raw: &[u8]) -> Result<TxId> {
        debug!(bytes = raw.len(), "submitting raw transaction");

        let resp = self
            .post_no_retry("/v2/transactions", "application/x-binary", raw.to_vec())
            .await?;

        let parsed: PostTransactionResponse =
            resp.json().await.map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing POST /v2/transactions response".into(),
            })?;

        Ok(TxId(parsed.tx_id))
    }

    /// Look up a transaction by txid in the pool or in recent blocks via
    /// `GET /v2/transactions/pending/{txid}`.
    ///
    /// Distinguishes three states:
    /// - **Committed**: `confirmed_round = Some(round)`, `pool_error = ""`
    /// - **Pending**: `confirmed_round = None`, `pool_error = ""`
    /// - **Rejected**: `pool_error != ""` (rare — usually the txn drops out
    ///   of the pool before this is observable)
    ///
    /// A txid the node has never seen returns `AlgoError::NotFound`; a txid
    /// that has been evicted past `MaxTxnLife` rounds returns the same.
    ///
    /// Ported reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go:1505`
    /// (`PendingTransactionInformation`). We request the default JSON encoding
    /// (`format=json`); the msgpack form carries the same fields.
    pub async fn get_pending_transaction(&self, txid: &TxId) -> Result<PendingTxnInfo> {
        debug!(%txid, "fetching pending transaction");

        let path = format!("/v2/transactions/pending/{}", txid.as_str());
        let resp = self.get_with_retry(&path, &self.http).await?;

        resp.json::<PendingTxnInfo>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("parsing GET /v2/transactions/pending/{}", txid.as_str()),
            })
    }

    /// Fetch suggested transaction parameters via `GET /v2/transactions/params`.
    ///
    /// The returned `SuggestedParams` carries the genesis hash as a decoded
    /// `Digest` (algod returns it base64-encoded over the wire), and includes
    /// the current consensus version's `min_fee` so callers don't have to look
    /// it up separately.
    ///
    /// Ported reference: `../go-algorand/daemon/algod/api/server/v2/handlers.go:1459`
    /// (`TransactionParams`).
    pub async fn suggested_transaction_params(&self) -> Result<SuggestedParams> {
        debug!("fetching suggested transaction params");

        let resp = self
            .get_with_retry("/v2/transactions/params", &self.http)
            .await?;

        resp.json::<SuggestedParams>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing GET /v2/transactions/params response".into(),
            })
    }
}

// ---- Participation key surface (TASK-241 / B9) ----
//
// Mirrors `../go-algorand/daemon/algod/api/server/v2/handlers.go:243-330`.
// Five endpoints: list, get-by-id, add, delete-by-id,
// generate-for-address. Used by goal-rust's `account addpartkey`,
// `installpartkey`, `listpartkeys`, `partkeyinfo`, `deletepartkey`
// (B10) and `renewpartkey` / `renewallpartkeys` (B11).

impl AlgodClient {
    /// `GET /v2/participation` — list every participation key the node
    /// knows about. Go's `convertParticipationRecord` loop appends to
    /// a nil slice, so an empty list serializes as JSON `null` rather
    /// than `[]` (handlers.go:252-258 + our own server mirrors at
    /// algo-rest-api/handlers.rs:3296). Deserialize as
    /// `Option<Vec<…>>` and default `None` to an empty vec so a fresh
    /// node doesn't surface as a parse error.
    pub async fn list_participation_keys(&self) -> Result<Vec<ParticipationKey>> {
        let resp = self.get_with_retry("/v2/participation", &self.http).await?;
        let parsed: Option<Vec<ParticipationKey>> =
            resp.json().await.map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing GET /v2/participation response".into(),
            })?;
        Ok(parsed.unwrap_or_default())
    }

    /// `GET /v2/participation/{id}` — fetch one participation key by
    /// its ParticipationID. 404 ⇒ `AlgoError::NotFound`.
    pub async fn get_participation_key(&self, id: &str) -> Result<ParticipationKey> {
        let path = format!("/v2/participation/{id}");
        let resp = self.get_with_retry(&path, &self.http).await?;
        resp.json::<ParticipationKey>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("parsing GET /v2/participation/{id} response"),
            })
    }

    /// `POST /v2/participation` — install a partkey from on-disk
    /// bytes. The body is the raw partkey-file payload that algod
    /// passes through to `Node.InstallParticipationKey`. Content-Type
    /// is `application/msgpack` to match Go's handler at
    /// handlers.go:303 (the handler is content-agnostic — it just
    /// reads the body — but msgpack is what the partkey file format
    /// uses on disk).
    pub async fn add_participation_key(
        &self,
        partkey_bytes: &[u8],
    ) -> Result<ParticipationKeyAdded> {
        let resp = self
            .post_no_retry(
                "/v2/participation",
                "application/msgpack",
                partkey_bytes.to_vec(),
            )
            .await?;
        resp.json::<ParticipationKeyAdded>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing POST /v2/participation response".into(),
            })
    }

    /// `DELETE /v2/participation/{id}` — remove a partkey by id.
    pub async fn delete_participation_key(&self, id: &str) -> Result<()> {
        let url = format!("{}/v2/participation/{id}", self.base_url);
        let mut req = self.http.delete(&url);
        if !self.token.is_empty() {
            req = req.header("X-Algo-API-Token", &self.token);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return Ok(());
                }
                let body_text = resp.text().await.unwrap_or_default();
                if status == reqwest::StatusCode::NOT_FOUND {
                    return Err(AlgoError::NotFound(format!(
                        "DELETE /v2/participation/{id}: {body_text}"
                    )));
                }
                Err(AlgoError::Conformance {
                    message: format!(
                        "DELETE /v2/participation/{id} returned {status}: {body_text}"
                    ),
                })
            }
            Err(e) => Err(AlgoError::RestClient {
                source: Box::new(e),
                context: format!("DELETE /v2/participation/{id}"),
            }),
        }
    }

    /// `POST /v2/participation/generate/{address}?first=<n>&last=<n>[&dilution=<n>]`
    /// — ask the node to generate a partkey for `address` in the
    /// background, install it, and return immediately. Mirrors
    /// handlers.go:262-300 (`GenerateParticipationKeys`).
    ///
    /// Algod's response is intentionally just `"{}"` today (the
    /// handler comment notes a future field for the partkey id);
    /// we return the raw body string so callers can match Go's
    /// surface even after a server-side enrichment.
    pub async fn generate_participation_keys(
        &self,
        address: &str,
        first_valid: u64,
        last_valid: u64,
        key_dilution: Option<u64>,
    ) -> Result<String> {
        let mut path =
            format!("/v2/participation/generate/{address}?first={first_valid}&last={last_valid}");
        if let Some(d) = key_dilution {
            path.push_str(&format!("&dilution={d}"));
        }
        // Empty body — the handler does not read the request body.
        let resp = self
            .post_no_retry(&path, "application/x-binary", Vec::new())
            .await?;
        resp.text().await.map_err(|e| AlgoError::RestClient {
            source: Box::new(e),
            context: format!("reading POST {path} response body"),
        })
    }
}

// ---- TEAL tooling surface (TASK-291 / CLERK T3) ----
//
// Mirrors `../go-algorand/daemon/algod/api/server/v2/handlers.go` TealCompile
// (`/v2/teal/compile`). Used by goal-rust's `clerk compile` leaf.
//
// `TealDryrun` (`/v2/teal/dryrun`) and the raw account/application/round/block
// reads `libgoal.MakeDryrunStateGenerated` (libgoal.go:1163) performed while
// assembling a dryrun dump were removed with goal-rust's `dryrun` /
// `dryrun-remote` leaves (issue #674), matching go-algorand's removal of the
// endpoint (PR #6651, v5.0.0-beta).

impl AlgodClient {
    /// `POST /v2/teal/compile` — assemble TEAL source text to bytecode.
    ///
    /// Returns `(program_hash_address, compiled_program_bytes)`. The body is the
    /// raw source text (Content-Type `text/plain`, matching go-algorand's
    /// handler which reads the body as source). A 404 means the node has
    /// `EnableDeveloperAPI=false`; a 400 carries the assembler error text.
    ///
    /// Ported reference:
    /// `../go-algorand/daemon/algod/api/server/v2/handlers.go` (`TealCompile`).
    pub async fn teal_compile(&self, source: &[u8]) -> Result<TealCompileResult> {
        let resp = self
            .post_no_retry("/v2/teal/compile", "text/plain", source.to_vec())
            .await?;
        resp.json::<TealCompileResult>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing POST /v2/teal/compile response".into(),
            })
    }

    /// `POST /v2/transactions/simulate` — simulate a transaction group and
    /// return the raw response JSON value. The body is the JSON-encoded
    /// `model.SimulateRequest` (`txn-groups[].txns` are JSON `SignedTransaction`
    /// values, which the Rust node decodes via `serde_json::from_value`); we
    /// always request the JSON response so the CLI can pretty-print it directly.
    /// A 404 means the node has `EnableDeveloperAPI=false`.
    ///
    /// Ported reference:
    /// `../go-algorand/daemon/algod/api/server/v2/handlers.go`
    /// (`SimulateTransaction`) and `libgoal.(*Client).SimulateTransactions`
    /// (libgoal.go:1281). Go encodes the request as msgpack; the Rust node
    /// accepts either, and JSON keeps the client free of msgpack-roundtrip
    /// quirks for embedded txn bytes.
    pub async fn simulate_transactions(&self, request_json: &[u8]) -> Result<serde_json::Value> {
        let resp = self
            .post_no_retry(
                "/v2/transactions/simulate?format=json",
                "application/json",
                request_json.to_vec(),
            )
            .await?;
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing POST /v2/transactions/simulate response".into(),
            })
    }

    /// `GET /v2/deltas/{round}?format=json` — the ledger state delta for a
    /// round, as a raw JSON value (`ledgercore.StateDelta`'s wire shape).
    ///
    /// Used by `algo-fixtures`' state-delta capture (issue #573) to golden
    /// a real go-algorand node's `KvMods` output for conformance testing
    /// against algod-rust's own `StateDelta.kv_mods`.
    pub async fn get_state_delta_json(&self, round: u64) -> Result<serde_json::Value> {
        let path = format!("/v2/deltas/{round}?format=json");
        let resp = self.get_with_retry(&path, &self.http).await?;
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("parsing GET /v2/deltas/{round}?format=json response"),
            })
    }

    /// `GET /v2/deltas/{round}?format=msgpack` — the ledger state delta for
    /// a round, as raw msgpack bytes exactly as the node sent them.
    ///
    /// See [`Self::get_state_delta_json`]; kept separate (rather than a
    /// generic `format` parameter) to match this file's existing
    /// one-purpose-per-method convention (`get_account_json`,
    /// `get_application_json`).
    pub async fn get_state_delta_msgpack_raw(&self, round: u64) -> Result<Vec<u8>> {
        let path = format!("/v2/deltas/{round}?format=msgpack");
        let resp = self.get_with_retry(&path, &self.http).await?;
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("reading GET /v2/deltas/{round}?format=msgpack response body"),
            })
    }
}

/// Check if a reqwest error is transient and worth retrying.
fn is_retryable(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout() || err.is_request()
}

#[async_trait]
impl BlockSource for AlgodClient {
    async fn get_block_raw(&self, round: Round) -> Result<Vec<u8>> {
        debug!(round = %round, "fetching block (msgpack)");

        let path = format!("/v2/blocks/{}?format=msgpack", round);
        let resp = self.get_with_retry(&path, &self.http).await?;

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

        let resp = self.get_with_retry("/v2/status", &self.http).await?;

        resp.json::<NodeStatus>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: "parsing /v2/status response".into(),
            })
    }

    async fn wait_for_round(&self, round: Round) -> Result<NodeStatus> {
        debug!(round = %round, "waiting for round");

        let path = format!("/v2/status/wait-for-block-after/{}", round);
        let resp = self.get_with_retry(&path, &self.long_poll_http).await?;

        resp.json::<NodeStatus>()
            .await
            .map_err(|e| AlgoError::RestClient {
                source: Box::new(e),
                context: format!("parsing wait-for-block-after/{round} response"),
            })
    }
}
