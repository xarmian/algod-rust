use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use algo_ledger::{
    apply::apply_block, parse_genesis_json, populate_store, seed_account_totals_from_genesis,
    LedgerStore, SqliteLedger,
};
use algo_network::{
    BlockService, BlockServiceError, ForwardingPolicy, GossipNode, IncomingMessage,
    LedgerForBlockService, MessageHandler, OutgoingMessage, Phonebook, Tag, TaggedMessageHandler,
    WebsocketNetwork, WebsocketNetworkConfig, RELAY_ROLE,
};
use algo_types::Round;
use async_trait::async_trait;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use crate::commands::network_common::genesis_id_for;

// ---------------------------------------------------------------------------
// SqliteLedger-backed block service
// ---------------------------------------------------------------------------

/// Wraps a `SqliteLedger` behind a `Mutex` so it can satisfy the
/// `Send + Sync + 'static` bounds required by `LedgerForBlockService`.
///
/// Also provides write methods for block ingestion from peer gossip.
struct LedgerBlockService {
    ledger: Mutex<SqliteLedger>,
}

impl LedgerBlockService {
    /// Store a raw block + certificate fetched from a peer, and (when
    /// possible) apply the block's state transitions so the local
    /// ledger's accountbase stays current.
    ///
    /// History: before PLAN-32 / TASK-95 this function passed an empty
    /// `proto` + empty `hdrdata` to `put_block` and skipped `apply_block`
    /// entirely — fine for a pure block archive but left the
    /// `accountbase` / `accounttotals` / per-round header fields empty,
    /// which in turn broke `algo_agreement::Certificate::authenticate`
    /// for downstream consumers (the TASK-88 cert cross-verify tool).
    ///
    /// Current behavior:
    /// 1. Decode the block msgpack bytes to a typed `Block`. If decode
    ///    fails we fall back to the legacy behavior (raw blob store
    ///    without apply) so a malformed block doesn't break gossip —
    ///    downstream consumers surface the resulting gaps on their own.
    /// 2. Call `put_block` with the real `proto` (from
    ///    `Block::current_protocol`) and canonical `hdrdata` so
    ///    `LedgerReader::{consensus_version, seed, lookup_digest}` work.
    /// 3. For every round > 0, call `apply_block` to mutate `accountbase`.
    ///    Round 0 (genesis) is stored without apply since the opening
    ///    state should come from `populate_store`. If apply fails we
    ///    log + continue — still better than silently dropping the
    ///    block. Downstream verification fails visibly in that case.
    fn store_block_and_cert(
        &self,
        round: u64,
        block_data: &[u8],
        cert_data: &[u8],
    ) -> Result<(), String> {
        let mut ledger = self.ledger.lock().map_err(|e| format!("lock: {e}"))?;
        ledger.begin_block().map_err(|e| format!("begin: {e}"))?;

        // Attempt a typed decode. decode_block_fast is the rmp-direct
        // path; fall back to decode_block (serde) for shapes the fast
        // path can't yet round-trip. If BOTH fail and this is round 0,
        // fall back to a raw-bytes archive (genesis blocks have a
        // minimal shape that isn't always round-trip-decodable today);
        // for any other round, treat decode as fatal — we refuse to
        // commit a block we can't apply, to keep accountbase
        // consistent.
        let decoded = algo_codec::decode_block_fast(block_data)
            .or_else(|_| algo_codec::decode_block(block_data));
        match decoded {
            Ok(block) => {
                let proto = block.current_protocol.clone();
                let hdrdata = algo_codec::canonical_encode_block_header_from_block(&block);
                if let Err(e) = ledger.put_block(round, &proto, &hdrdata, block_data) {
                    let _ = ledger.rollback_block();
                    return Err(format!("put_block: {e}"));
                }
                if let Err(e) = ledger.put_block_cert(round, cert_data) {
                    let _ = ledger.rollback_block();
                    return Err(format!("put_block_cert: {e}"));
                }
                // Apply state transitions for non-genesis rounds. apply_block
                // on round 0 would re-run the genesis transactions (which
                // is both redundant and sometimes incorrect — the genesis
                // state has already been loaded via populate_store).
                if round > 0 {
                    if let Err(e) = apply_block(&mut *ledger, &block) {
                        // Apply failure is fatal: apply_block only rolls
                        // back rewards on error, not earlier per-txn
                        // accountbase mutations within the same block.
                        // Committing would leave corrupted state that
                        // future rounds build on. Roll the whole
                        // transaction back instead; gossip will retry
                        // fetching the block.
                        warn!(
                            round = round,
                            error = %e,
                            "apply_block failed; rolling back this round"
                        );
                        let _ = ledger.rollback_block();
                        return Err(format!("apply_block: {e}"));
                    }
                }
                ledger.set_current_round(Round(round));
                ledger.commit_block().map_err(|e| format!("commit: {e}"))?;
                Ok(())
            }
            Err(decode_err) if round == 0 => {
                // Round 0 — genesis block shape isn't always round-trip
                // decodable today. Accept the raw msgpack as `hdrdata`
                // so `seed()` extracting the "seed" codec key at the
                // top of the map still works (consumers that need
                // round 0's seed go through this path). Skip apply —
                // populate_store already supplied genesis state.
                warn!(
                    error = %decode_err,
                    "round 0 decode failed; storing raw bytes as hdrdata fallback"
                );
                ledger
                    .put_block(0, "", block_data, block_data)
                    .map_err(|e| {
                        let _ = ledger.rollback_block();
                        format!("put_block: {e}")
                    })?;
                ledger.put_block_cert(0, cert_data).map_err(|e| {
                    let _ = ledger.rollback_block();
                    format!("put_block_cert: {e}")
                })?;
                ledger.set_current_round(Round(0));
                ledger.commit_block().map_err(|e| format!("commit: {e}"))?;
                Ok(())
            }
            Err(decode_err) => {
                // Non-genesis decode failure: refuse to store. Storing
                // without apply would leave the accountbase out of
                // sync with the block history, which poisons all
                // subsequent verification. Rolling back + returning
                // err keeps the gossip fetch loop retrying — if the
                // peer really returned malformed bytes, that's visible
                // in logs.
                let _ = ledger.rollback_block();
                Err(format!(
                    "block decode failed at round {round}: {decode_err}"
                ))
            }
        }
    }

    fn latest_round_inner(&self) -> u64 {
        self.ledger.lock().map(|l| l.current_round().0).unwrap_or(0)
    }
}

impl LedgerForBlockService for LedgerBlockService {
    fn encoded_block_cert(&self, round: u64) -> Result<(Vec<u8>, Vec<u8>), BlockServiceError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| BlockServiceError::BlockNotAvailable {
                round,
                latest_round: None,
            })?;
        let latest = ledger.current_round().0;

        let block_data = ledger
            .get_block_data(round)
            .map_err(|_| BlockServiceError::BlockNotAvailable {
                round,
                latest_round: Some(latest),
            })?
            .ok_or(BlockServiceError::BlockNotAvailable {
                round,
                latest_round: Some(latest),
            })?;

        let cert_data = ledger
            .get_block_cert(round)
            .map_err(|_| BlockServiceError::BlockNotAvailable {
                round,
                latest_round: Some(latest),
            })?
            .unwrap_or_default();

        Ok((block_data, cert_data))
    }

    fn latest_round(&self) -> u64 {
        self.latest_round_inner()
    }
}

// ---------------------------------------------------------------------------
// Gossip handler: notifies the catchup loop when new blocks may be available
// ---------------------------------------------------------------------------

/// A gossip handler that signals the block catchup loop whenever
/// agreement-related messages arrive (ProposalPayload, AgreementVote).
///
/// This handler does not process the message content itself; it simply
/// triggers a wakeup so the catchup loop can fetch the new block via HTTP.
struct BlockNotifyHandler {
    notify: Arc<Notify>,
}

#[async_trait]
impl MessageHandler for BlockNotifyHandler {
    async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        // Signal the catchup loop that new consensus activity was seen.
        self.notify.notify_one();
        OutgoingMessage {
            action: ForwardingPolicy::Broadcast,
            tag: msg.tag,
            payload: msg.data,
            topics: None,
        }
    }
}

// ---------------------------------------------------------------------------
// WebSocket block request handler: serves blocks to peers via UniEnsBlockReq
// ---------------------------------------------------------------------------

/// Handles incoming `UniEnsBlockReq` WebSocket messages by delegating to the
/// [`BlockService`]'s existing `handle_ws_block_request` method.
///
/// When a Go non-relay peer asks for a block, it sends a `UniEnsBlockReq`
/// message over WebSocket.  This handler looks up the block in the local
/// ledger and returns it as a `TopicMsgResp` with block+cert Topics.
///
/// Without this handler, Go peers fall back to periodic HTTP catchup (~17s
/// intervals), causing bursty sync behaviour.
struct BlockRequestHandler {
    block_service: Arc<BlockService>,
}

#[async_trait]
impl MessageHandler for BlockRequestHandler {
    async fn handle(&self, msg: IncomingMessage) -> OutgoingMessage {
        let (response_topics, _guard) = self.block_service.handle_ws_block_request(&msg.data);
        // The read_loop's Respond path will append the RequestHash topic,
        // marshal the Topics, and send as TopicMsgResp.  We just pass the
        // topics through — the payload field is unused for Respond.
        OutgoingMessage {
            action: ForwardingPolicy::Respond,
            tag: Tag::TopicMsgResp,
            payload: Vec::new(),
            topics: Some(response_topics),
        }
    }
}

// ---------------------------------------------------------------------------
// Block catchup: fetch blocks from peers via HTTP
// ---------------------------------------------------------------------------

/// Parse a `PreEncodedBlockCert` msgpack response body into raw block bytes
/// and raw cert bytes.
///
/// The response is a msgpack map: `{"block": <raw>, "cert": <raw>}`.
/// We decode just enough to extract the two raw byte sequences.
fn parse_block_cert_response(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let value: rmpv::Value =
        rmpv::decode::read_value(&mut &body[..]).map_err(|e| format!("msgpack decode: {e}"))?;

    let map = value.as_map().ok_or("response is not a msgpack map")?;

    let mut block_data: Option<Vec<u8>> = None;
    let mut cert_data: Option<Vec<u8>> = None;

    for (key, val) in map {
        let key_str = key.as_str().unwrap_or("");
        match key_str {
            "block" => {
                // Go's PreEncodedBlockCert stores block as raw msgpack bytes
                // (protocol.EncodedBytes = []byte).  In the msgpack response
                // these appear as Binary values — extract the raw bytes directly
                // rather than re-encoding (which would double-wrap them).
                if let Some(bytes) = val.as_slice() {
                    block_data = Some(bytes.to_vec());
                } else {
                    // Fallback: re-encode non-binary values.
                    let mut buf = Vec::new();
                    rmpv::encode::write_value(&mut buf, val)
                        .map_err(|e| format!("re-encode block: {e}"))?;
                    block_data = Some(buf);
                }
            }
            "cert" => {
                if let Some(bytes) = val.as_slice() {
                    cert_data = Some(bytes.to_vec());
                } else {
                    let mut buf = Vec::new();
                    rmpv::encode::write_value(&mut buf, val)
                        .map_err(|e| format!("re-encode cert: {e}"))?;
                    cert_data = Some(buf);
                }
            }
            _ => {}
        }
    }

    let block = block_data.ok_or("response missing 'block' key")?;
    let cert = cert_data.ok_or("response missing 'cert' key")?;
    Ok((block, cert))
}

/// Convert a gossip peer address to an HTTP base URL.
///
/// Peer addresses from the CLI are typically `host:port` (e.g. `go-relay:4161`).
/// Go algod serves both WebSocket gossip and HTTP block service on the same port.
fn peer_to_http_base(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.to_string()
    } else {
        format!("http://{}", addr)
    }
}

/// Background task that fetches new blocks from peer relays via HTTP and
/// stores them in the local SQLite ledger.
///
/// The loop is woken by the `Notify` signal (from gossip handlers) or by a
/// periodic 2-second poll as a fallback.
async fn block_catchup_loop(
    ledger: Arc<LedgerBlockService>,
    peers: Vec<String>,
    genesis_id: String,
    notify: Arc<Notify>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client");

    info!(peers = peers.len(), "block catchup loop started");

    loop {
        // Wait for a gossip signal or a timeout (poll fallback).
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("block catchup loop cancelled");
                return;
            }
            _ = notify.notified() => {
                // Woken by gossip activity — try to fetch immediately.
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                // Periodic poll fallback.
            }
        }

        // Determine what round to fetch next.
        // If current is 0 and we haven't stored the genesis block yet,
        // fetch round 0 first (needed by Go nodes to bootstrap).
        let current = ledger.latest_round_inner();
        let has_genesis = current > 0
            || ledger
                .ledger
                .lock()
                .ok()
                .and_then(|l| l.get_block_data(0).ok().flatten())
                .is_some();
        let next_round = if has_genesis { current + 1 } else { 0 };

        // Try each peer until one succeeds.
        let mut fetched = false;
        for peer_addr in &peers {
            let base = peer_to_http_base(peer_addr);
            let url = format!(
                "{}/v1/{}/block/{}",
                base,
                genesis_id,
                algo_network::format_round_base36(next_round)
            );

            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                    Ok(body) => match parse_block_cert_response(&body) {
                        Ok((block_data, cert_data)) => {
                            match ledger.store_block_and_cert(next_round, &block_data, &cert_data) {
                                Ok(()) => {
                                    info!(
                                        round = next_round,
                                        peer = peer_addr.as_str(),
                                        block_bytes = block_data.len(),
                                        cert_bytes = cert_data.len(),
                                        "stored block from peer"
                                    );
                                    fetched = true;
                                }
                                Err(e) => {
                                    warn!(
                                        round = next_round,
                                        error = %e,
                                        "failed to store block"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                round = next_round,
                                peer = peer_addr.as_str(),
                                error = %e,
                                "failed to parse block response"
                            );
                        }
                    },
                    Err(e) => {
                        debug!(
                            round = next_round,
                            peer = peer_addr.as_str(),
                            error = %e,
                            "failed to read block response body"
                        );
                    }
                },
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    debug!(
                        round = next_round,
                        peer = peer_addr.as_str(),
                        status = status,
                        "block not available from peer"
                    );
                }
                Err(e) => {
                    debug!(
                        round = next_round,
                        peer = peer_addr.as_str(),
                        error = %e,
                        "failed to connect to peer for block fetch"
                    );
                }
            }

            if fetched {
                break;
            }
        }

        // If we fetched a block successfully, immediately try the next one
        // (don't wait for notify/timeout). This handles catch-up of multiple
        // rounds efficiently.
        if fetched {
            notify.notify_one();
        }
    }
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

/// Run the relay command: start a relay node that listens for inbound
/// connections and forwards gossip messages.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    bind_address: &str,
    genesis_id: &str,
    network: &str,
    peers: &[String],
    incoming_limit: u32,
    max_per_ip: u32,
    rate_limit: u32,
    broadcast_limit: u32,
    tls_cert: Option<&str>,
    tls_key: Option<&str>,
    mem_cap_mb: u64,
    ledger_path: &Path,
    genesis_json_path: Option<&Path>,
) -> anyhow::Result<()> {
    // Resolve genesis ID: use the provided value, or look it up by network name.
    let resolved_genesis_id = if genesis_id.is_empty() {
        genesis_id_for(network)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown network '{}': use --genesis-id to specify the genesis ID",
                    network
                )
            })?
            .to_string()
    } else {
        genesis_id.to_string()
    };

    let mem_cap = mem_cap_mb * 1024 * 1024;

    info!(
        bind = bind_address,
        genesis_id = %resolved_genesis_id,
        network = network,
        incoming_limit = incoming_limit,
        max_per_ip = max_per_ip,
        rate_limit = rate_limit,
        broadcast_limit = broadcast_limit,
        mem_cap_mb = mem_cap_mb,
        peers = peers.len(),
        "starting relay node"
    );

    // Build phonebook and seed with any initial peer addresses.
    let phonebook = Arc::new(Phonebook::new(rate_limit as usize, Duration::from_secs(60)));

    if !peers.is_empty() {
        phonebook.replace_peer_list(peers, "cli", RELAY_ROLE);
        info!(count = peers.len(), "added initial peer addresses");
    }

    // Build network config with relay mode enabled.
    let config = WebsocketNetworkConfig {
        genesis_id: resolved_genesis_id.clone(),
        network_id: network.to_string(),
        net_address: Some(bind_address.to_string()),
        relay_messages: true,
        incoming_connections_limit: incoming_limit,
        max_connections_per_ip: max_per_ip,
        connections_rate_limiting_count: rate_limit,
        broadcast_connections_limit: broadcast_limit,
        tls_cert_file: tls_cert.map(|s| s.to_string()),
        tls_key_file: tls_key.map(|s| s.to_string()),
        block_service_mem_cap: mem_cap,
        gossip_fanout: if peers.is_empty() {
            algo_network::DEFAULT_GOSSIP_FANOUT
        } else {
            peers.len().max(algo_network::DEFAULT_GOSSIP_FANOUT)
        },
        ..Default::default()
    };

    let net = Arc::new(WebsocketNetwork::new(config, phonebook));

    // Open the SQLite ledger and register the block service HTTP handler.
    let mut sqlite_ledger = SqliteLedger::open(ledger_path).map_err(|e| {
        anyhow::anyhow!("failed to open ledger at {}: {}", ledger_path.display(), e)
    })?;

    // Reject anything but a fully populated block archive before
    // serving blocks. A relay must be able to satisfy block requests
    // from peers; both BlockBehind (post-crash gap) and CatchpointOnly
    // (catchpoint-imported with no block download yet) leave holes.
    match sqlite_ledger
        .reconcile_cross_file()
        .map_err(|e| anyhow::anyhow!("reconcile cross-file consistency for relay ledger: {e}"))?
    {
        algo_ledger::CrossFileState::Empty | algo_ledger::CrossFileState::Consistent { .. } => {}
        algo_ledger::CrossFileState::CatchpointOnly { tracker_round } => {
            anyhow::bail!(
                "relay requires blocks on disk; the ledger is catchpoint-only at round \
                 {tracker_round}. Run `algod-rust sync` first to populate the block archive."
            );
        }
        algo_ledger::CrossFileState::BlockBehind {
            tracker_round,
            block_max_round,
        } => {
            anyhow::bail!(
                "ledger inconsistency: tracker at round {tracker_round} but blockdb.blocks max \
                 is {block_max_round}. Recover from a catchpoint or delete the DB."
            );
        }
    }

    let latest = sqlite_ledger.current_round().0;
    info!(path = %ledger_path.display(), latest_round = latest, "opened ledger database");

    // Optional: bootstrap genesis state when the ledger is fresh.
    // Without this the relay's accountbase + accounttotals stay empty
    // forever (apply_block alone doesn't populate totals — see
    // PLAN-32 / TASK-95), which breaks downstream consumers that need
    // full ledger state.
    //
    // "Already seeded" is detected by whether the `accounttotals` ROW
    // EXISTS, not whether online stake is non-zero — a network with
    // every allocation offline legitimately has online=0 after
    // seeding, and `online_stake > 0` would then re-seed every
    // restart, trampling accumulated state.
    //
    // Pre-TASK-95 archive volumes (blocks present, no accounttotals
    // row) are a genuinely ambiguous state: re-running populate_store
    // would reset `accountbase` to genesis while the blocks table
    // stays at the current tip, leaving the ledger internally
    // inconsistent (genesis state + history of later-round apply
    // writes, with nothing tying them together). Rather than paper
    // over that, fail fast and force the operator to `--purge` and
    // rebuild from scratch. This path only fires on the first
    // TASK-95 upgrade of an existing volume; `--purge` is already
    // the documented upgrade procedure.
    if let Some(genesis_path) = genesis_json_path {
        let already_seeded = sqlite_ledger.has_account_totals().unwrap_or(false);
        if !already_seeded && latest > 0 {
            anyhow::bail!(
                "ledger at {} has {} imported block(s) but no accounttotals row — \
                 likely a pre-TASK-95 archive volume. Refusing to re-seed genesis \
                 over accumulated block history (would leave accountbase at genesis \
                 while blocks table is at round {}). Run `scripts/stop.sh --purge` \
                 and restart to rebuild the ledger cleanly.",
                ledger_path.display(),
                latest,
                latest,
            );
        }
        if !already_seeded {
            let genesis_str = std::fs::read_to_string(genesis_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to read genesis.json at {}: {}",
                    genesis_path.display(),
                    e
                )
            })?;
            let genesis = parse_genesis_json(&genesis_str)
                .map_err(|e| anyhow::anyhow!("failed to parse genesis.json: {}", e))?;
            sqlite_ledger
                .begin_block()
                .map_err(|e| anyhow::anyhow!("begin_block during genesis seed: {}", e))?;
            populate_store(&mut sqlite_ledger, &genesis)
                .map_err(|e| anyhow::anyhow!("populate_store from genesis: {}", e))?;
            seed_account_totals_from_genesis(&mut sqlite_ledger, &genesis)
                .map_err(|e| anyhow::anyhow!("seed_account_totals_from_genesis: {}", e))?;
            sqlite_ledger
                .commit_block()
                .map_err(|e| anyhow::anyhow!("commit_block during genesis seed: {}", e))?;
            let online = sqlite_ledger.online_stake().unwrap_or(0);
            info!(
                genesis_path = %genesis_path.display(),
                allocations = genesis.alloc.len(),
                online_stake = online,
                "seeded ledger from genesis (accountbase + accounttotals)"
            );
        } else {
            info!(
                latest_round = latest,
                "ledger already seeded (accounttotals row present); skipping genesis bootstrap"
            );
        }
    } else {
        debug!("no --genesis-json provided; accountbase will remain empty (archive-only mode)");
    }

    let ledger = Arc::new(LedgerBlockService {
        ledger: Mutex::new(sqlite_ledger),
    });
    let block_service = Arc::new(BlockService::new(
        Arc::clone(&ledger) as Arc<dyn LedgerForBlockService>,
        resolved_genesis_id.clone(),
        mem_cap,
    ));
    net.register_http_handler("/", block_service.http_router());

    // Register gossip handlers for all relay-forwarded message types.
    // The handler returns ForwardingPolicy::Broadcast so the network layer
    // enqueues each message to the broadcast thread for delivery to all
    // connected peers (excluding the originator).  Agreement-related tags
    // (PP, AV, VB, VP) also notify the catchup loop so it can fetch the
    // committed block via HTTP from the upstream peer.
    let catchup_notify = Arc::new(Notify::new());
    let notify_handler: Arc<dyn MessageHandler> = Arc::new(BlockNotifyHandler {
        notify: Arc::clone(&catchup_notify),
    });
    // Register the block request handler for UniEnsBlockReq — this allows
    // Go peers to fetch blocks directly over WebSocket instead of falling
    // back to periodic HTTP catchup (~17s intervals).
    let block_request_handler: Arc<dyn MessageHandler> = Arc::new(BlockRequestHandler {
        block_service: Arc::clone(&block_service),
    });

    net.register_handlers(vec![
        TaggedMessageHandler {
            tag: Tag::ProposalPayload,
            handler: Arc::clone(&notify_handler),
        },
        TaggedMessageHandler {
            tag: Tag::AgreementVote,
            handler: Arc::clone(&notify_handler),
        },
        TaggedMessageHandler {
            tag: Tag::VoteBundle,
            handler: Arc::clone(&notify_handler),
        },
        TaggedMessageHandler {
            tag: Tag::VotePacked,
            handler: Arc::clone(&notify_handler),
        },
        TaggedMessageHandler {
            tag: Tag::Transaction,
            handler: Arc::clone(&notify_handler),
        },
        TaggedMessageHandler {
            tag: Tag::StateProofSig,
            handler: Arc::clone(&notify_handler),
        },
        TaggedMessageHandler {
            tag: Tag::UniEnsBlockReq,
            handler: block_request_handler,
        },
    ]);

    // Start the network (listener + mesh + monitor tasks).
    net.start_arc()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let (addr, listening) = net.address();
    if listening {
        info!(address = %addr, "relay node listening");
    } else {
        info!("relay node started (no listener)");
    }

    // Spawn the background block catchup task that fetches committed blocks
    // from peer relays via HTTP and stores them in the local SQLite ledger.
    let catchup_cancel = tokio_util::sync::CancellationToken::new();
    let catchup_task = if !peers.is_empty() {
        let cancel = catchup_cancel.clone();
        let ledger_for_catchup = Arc::clone(&ledger);
        let genesis = resolved_genesis_id.clone();
        let peer_list: Vec<String> = peers.to_vec();
        let notify = Arc::clone(&catchup_notify);
        Some(tokio::spawn(async move {
            block_catchup_loop(ledger_for_catchup, peer_list, genesis, notify, cancel).await;
        }))
    } else {
        warn!("no peers configured; block catchup is disabled");
        None
    };

    info!(
        genesis_id = %resolved_genesis_id,
        "relay node active — press Ctrl+C to stop"
    );

    // Wait for Ctrl+C.
    tokio::signal::ctrl_c().await?;

    info!("shutting down relay node...");
    catchup_cancel.cancel();
    if let Some(task) = catchup_task {
        let _ = task.await;
    }
    net.stop().await;
    info!("relay node stopped");

    Ok(())
}
