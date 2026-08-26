//! `algo-agreement-fuzz` — inject one malformed agreement message into a live
//! go-algorand node and report what it did (issue #472).
//!
//! Each run sends **exactly one** message. The message is built by
//! [`algo_agreement_fuzz`] from a real participation key and real ledger
//! parameters, so it is byte-identical to an honest message except for the one
//! injected fault named by `--case`.
//!
//! ```text
//! algo-agreement-fuzz \
//!     --node http://127.0.0.1:4001 --token <algod-token> \
//!     --gossip 127.0.0.1:4161 --genesis-id phase6net-v1 \
//!     --partkey ops/mixed-cluster/netroot/Wallet4.0.30000.partkey \
//!     --case bad-vrf-proof --out report.json
//! ```
//!
//! `--dry-run` builds and prints the message without touching the network,
//! which is how the unit-tested construction path is exercised in CI.

use std::path::PathBuf;
use std::time::Duration;

use algo_agreement::{Period, Seed, DOWN, PROPOSE};
use algo_agreement_fuzz::inject::{inject_one, InjectionOutcome, InjectorConfig};
use algo_agreement_fuzz::inject_p2p::{capture_proposal_p2p, inject_one_p2p, P2pInjectorConfig};
use algo_agreement_fuzz::{
    baseline_and_faulted, bottom, committee_weight, corrupt_proposal, encode_compound_message,
    encode_vote, synthetic_proposal_value, OtsDomain, ParticipationSecrets, ProposalFault,
    VoteContext, VoteFault, VrfCorruption,
};
use algo_ledger::erasable_db::ErasableDb;
use algo_ledger::participation::restore::restore_participation;
use algo_network::tag::Tag;
use algo_types::consensus::consensus_params_for_version;
use algo_types::{Address, BlockResponse, ConsensusParams, Round};
use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "algo-agreement-fuzz",
    about = "Inject a single malformed agreement message into a live go-algorand node"
)]
struct Cli {
    /// Which negative case to inject.
    #[arg(long, value_parser = ["bad-vrf-proof", "wrong-committee-weight", "wrong-ots-domain", "malformed-proposal"])]
    case: String,

    /// algod REST endpoint of the target Go node.
    #[arg(long, default_value = "http://127.0.0.1:4001")]
    node: String,

    /// algod API token.
    #[arg(long)]
    token: String,

    /// Which wire transport to inject the message over. `ws-gossip` speaks
    /// go-algorand's WS-gossip handshake/framing (`--gossip`); `p2p` speaks
    /// the raw `/algorand-ws/2.2.0` libp2p stream (`--p2p-multiaddr`) that a
    /// go-algorand node started with `EnableP2P=true` uses instead — see
    /// `ops/mixed-cluster-p2p/` (issue #597).
    #[arg(long, default_value = "ws-gossip", value_parser = ["ws-gossip", "p2p"])]
    transport: String,

    /// `host:port` of the target Go node's WS-gossip listener.
    /// (`--transport ws-gossip` only.)
    #[arg(long, default_value = "127.0.0.1:4161")]
    gossip: String,

    /// The target Go node's dialable P2P multiaddr, including its trailing
    /// `/p2p/<peer-id>` component (e.g. from
    /// `ops/mixed-cluster-p2p/netroot/.p2p-multiaddr-1`).
    /// (`--transport p2p` only.)
    #[arg(long)]
    p2p_multiaddr: Option<String>,

    /// Genesis ID of the network (e.g. `phase6net-v1`).
    #[arg(long)]
    genesis_id: String,

    /// Participation key (`*.partkey` SQLite file) for the injected identity.
    #[arg(long)]
    partkey: PathBuf,

    /// Build the message and print it, but do not connect to anything.
    #[arg(long)]
    dry_run: bool,

    /// Seconds to wait for Go to disconnect us after the injection.
    #[arg(long, default_value_t = 20)]
    observe_secs: u64,

    /// How many rounds to search for a zero-weight selector
    /// (`wrong-committee-weight` only).
    #[arg(long, default_value_t = 40)]
    weight_search_rounds: u64,

    /// Seconds to wait for a real proposal to capture (`malformed-proposal`).
    #[arg(long, default_value_t = 60)]
    capture_secs: u64,

    /// Which single field to corrupt for `malformed-proposal`.
    #[arg(long, default_value = "bad-payset-commitment",
          value_parser = ["bad-payset-commitment", "bad-prev-block-hash", "bad-genesis-hash", "bad-seed-proof", "proposer-mismatch"])]
    proposal_fault: String,

    /// Write a JSON report here.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Log level.
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Debug, Serialize)]
struct Report {
    case: String,
    tag: String,
    sender: String,
    round: u64,
    period: u64,
    step: u64,
    /// Sortition weight the account really has for this selector, as the
    /// verifier will recompute it.
    committee_weight: u64,
    /// Bytes of the honest baseline message (hex), when one exists.
    baseline_hex: Option<String>,
    /// Bytes actually put on the wire (hex).
    injected_hex: String,
    /// Which byte ranges differ between baseline and injected.
    differing_byte_count: Option<usize>,
    /// The go-algorand error text this case should provoke.
    expected_go_error: String,
    /// Whether Go closed our connection.
    disconnected: Option<bool>,
    elapsed_ms: Option<u128>,
    frames_received: Option<Vec<String>>,
    /// Base32 block digest of the honest payload (`PP` cases only). This is
    /// the `Hash` field go-algorand's agreement tracer prints.
    honest_block_digest: Option<String>,
    /// Base32 block digest of the corrupted payload we actually sent.
    injected_block_digest: Option<String>,
    /// Base32 block digest of the block the network really committed at that
    /// round — proof of whether Go adopted the corrupted payload.
    committed_block_digest: Option<String>,
    /// `true` only if the network committed the corrupted block. Must be
    /// `false`; `true` would be a genuine consensus-safety finding.
    corrupted_block_adopted: Option<bool>,
    dry_run: bool,
}

// ---------------------------------------------------------------------------
// algod REST helpers
// ---------------------------------------------------------------------------

struct Algod {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl Algod {
    fn new(base: &str, token: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("http client"),
        }
    }

    async fn get_json(&self, path: &str) -> Result<serde_json::Value> {
        let url = format!("{}{path}", self.base);
        let resp = self
            .http
            .get(&url)
            .header("X-Algo-API-Token", &self.token)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .with_context(|| format!("body of {url}"))?;
        if !status.is_success() {
            bail!("GET {url} -> {status}: {body}");
        }
        serde_json::from_str(&body).with_context(|| format!("decoding {url}"))
    }

    async fn last_round(&self) -> Result<Round> {
        let v = self.get_json("/v2/status").await?;
        Ok(Round(
            v["last-round"]
                .as_u64()
                .ok_or_else(|| anyhow!("/v2/status has no last-round"))?,
        ))
    }

    async fn block(&self, r: Round) -> Result<BlockResponse> {
        let url = format!("{}/v2/blocks/{}?format=msgpack", self.base, r.0);
        let resp = self
            .http
            .get(&url)
            .header("X-Algo-API-Token", &self.token)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("body of {url}"))?;
        if !status.is_success() {
            bail!("GET {url} -> {status}");
        }
        rmp_serde::from_slice(&bytes).with_context(|| format!("decoding block {}", r.0))
    }

    async fn seed(&self, r: Round) -> Result<Seed> {
        Ok(Seed(self.block(r).await?.block.seed))
    }

    /// The account's voting stake, and the network's total online stake.
    async fn stake(&self, addr: &Address) -> Result<(u64, u64)> {
        let acct = self
            .get_json(&format!("/v2/accounts/{}", addr.to_algorand_string()))
            .await?;
        let balance = acct["amount"]
            .as_u64()
            .ok_or_else(|| anyhow!("account has no amount"))?;
        let supply = self.get_json("/v2/ledger/supply").await?;
        let online = supply["online-money"]
            .as_u64()
            .ok_or_else(|| anyhow!("/v2/ledger/supply has no online-money"))?;
        Ok((balance, online))
    }

    /// Consensus params for the round currently being agreed on.
    async fn consensus_params(&self, r: Round) -> Result<ConsensusParams> {
        let version = self
            .block(algo_agreement::params_round(r))
            .await?
            .block
            .current_protocol;
        consensus_params_for_version(&version)
            .ok_or_else(|| anyhow!("unknown consensus version {version}"))
    }
}

// ---------------------------------------------------------------------------
// Transport — ws-gossip or P2P (issue #597)
// ---------------------------------------------------------------------------

/// Which wire transport to inject the single malformed message over, plus
/// its already-resolved connection config. See [`Cli::transport`]'s doc
/// comment for the go-algorand-side rationale.
enum Transport {
    /// go-algorand's WS-gossip handshake/framing — [`algo_agreement_fuzz::inject`].
    WsGossip(InjectorConfig),
    /// The raw `/algorand-ws/2.2.0` libp2p stream — [`algo_agreement_fuzz::inject_p2p`].
    P2p(P2pInjectorConfig),
}

impl Transport {
    /// Resolve `--transport` (plus `--gossip`/`--p2p-multiaddr`) into a
    /// concrete, ready-to-use config.
    fn resolve(cli: &Cli, observe_secs: u64) -> Result<Self> {
        match cli.transport.as_str() {
            "p2p" => {
                let addr = cli.p2p_multiaddr.as_deref().ok_or_else(|| {
                    anyhow!("--transport p2p requires --p2p-multiaddr <multiaddr>")
                })?;
                let multiaddr: libp2p::Multiaddr = addr
                    .parse()
                    .with_context(|| format!("parsing --p2p-multiaddr {addr}"))?;
                Ok(Transport::P2p(P2pInjectorConfig {
                    observe: Duration::from_secs(observe_secs),
                    ..P2pInjectorConfig::new(multiaddr, &cli.genesis_id)
                }))
            }
            _ => Ok(Transport::WsGossip(InjectorConfig {
                observe: Duration::from_secs(observe_secs),
                ..InjectorConfig::new(&cli.gossip, &cli.genesis_id)
            })),
        }
    }

    /// Reconfigure the observe window on an already-resolved transport (used
    /// where `run_malformed_proposal` needs a longer window for the initial
    /// capture than for the later injection).
    fn with_observe(&self, observe_secs: u64) -> Self {
        let observe = Duration::from_secs(observe_secs);
        match self {
            Transport::WsGossip(cfg) => Transport::WsGossip(InjectorConfig {
                observe,
                ..cfg.clone()
            }),
            Transport::P2p(cfg) => Transport::P2p(P2pInjectorConfig {
                observe,
                ..cfg.clone()
            }),
        }
    }

    async fn inject_one(&self, tag: Tag, payload: Vec<u8>) -> Result<InjectionOutcome> {
        match self {
            Transport::WsGossip(cfg) => inject_one(cfg, tag, payload).await,
            Transport::P2p(cfg) => inject_one_p2p(cfg, tag, payload).await,
        }
    }

    async fn capture_proposal(&self) -> Result<Vec<u8>> {
        match self {
            Transport::WsGossip(cfg) => algo_agreement_fuzz::inject::capture_proposal(cfg).await,
            Transport::P2p(cfg) => capture_proposal_p2p(cfg).await,
        }
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.clone().into()),
        )
        .init();

    let db = ErasableDb::open_read_only(&cli.partkey)
        .with_context(|| format!("opening partkey {}", cli.partkey.display()))?;
    let part = restore_participation(&db).context("restoring participation key")?;
    let sender = part.parent;
    let secrets = ParticipationSecrets {
        vrf: part.vrf,
        ots: part.voting,
    };

    let algod = Algod::new(&cli.node, &cli.token);
    let last = algod.last_round().await?;
    // The round agreement is currently running is last+1; target last+2 so the
    // message stays inside Go's freshness window (`voteFresh` accepts
    // PlayerRound and PlayerRound+1) even if a round completes mid-flight.
    let target = Round(last.0 + 2);
    let params = algod.consensus_params(target).await?;
    let (balance, total_money) = algod.stake(&sender).await?;
    let key_dilution =
        algo_agreement::effective_key_dilution(part.key_dilution, params.default_key_dilution);

    tracing::info!(
        %sender, last = last.0, target = target.0, balance, total_money, key_dilution,
        "loaded injected identity"
    );

    // Resolving a transport only builds its config (dial/gossip target,
    // timeouts) — it does not touch the network on its own, so this happens
    // unconditionally even for `--dry-run` (mirrors `run_malformed_proposal`,
    // which has always captured a real proposal off the wire regardless of
    // `--dry-run`, since a proposal has to come from *somewhere* to corrupt).
    let transport = Transport::resolve(&cli, cli.observe_secs)?;

    let report = match cli.case.as_str() {
        "malformed-proposal" => run_malformed_proposal(&cli, &algod, &transport).await?,
        _ => {
            let fault = parse_vote_fault(&cli.case)?;
            run_vote_case(
                &cli,
                &algod,
                &secrets,
                sender,
                target,
                params,
                balance,
                total_money,
                key_dilution,
                fault,
                &transport,
            )
            .await?
        }
    };

    let json = serde_json::to_string_pretty(&report)?;
    println!("{json}");
    if let Some(path) = &cli.out {
        std::fs::write(path, &json).with_context(|| format!("writing {}", path.display()))?;
    }

    // Exit non-zero when a live run did not observe the expected rejection, so
    // the shell driver can simply check the exit status.
    if report.corrupted_block_adopted == Some(true) {
        bail!(
            "go-algorand COMMITTED the corrupted block at round {} — this is a genuine              consensus-safety finding, not a harness bug",
            report.round
        );
    }
    if !cli.dry_run && report.disconnected == Some(false) && report.tag == "AV" {
        bail!(
            "go-algorand did NOT disconnect after a {} vote — this may be a real \
             conformance finding; inspect the node log",
            report.case
        );
    }
    Ok(())
}

fn parse_vote_fault(case: &str) -> Result<VoteFault> {
    Ok(match case {
        "bad-vrf-proof" => VoteFault::BadVrfProof(VrfCorruption::FlipGamma),
        "wrong-committee-weight" => VoteFault::ZeroWeightCredential,
        "wrong-ots-domain" => VoteFault::WrongOtsDomain(OtsDomain::Payload),
        other => bail!("unknown vote case {other}"),
    })
}

fn parse_proposal_fault(name: &str) -> Result<ProposalFault> {
    Ok(match name {
        "bad-payset-commitment" => ProposalFault::BadPaysetCommitment,
        "bad-prev-block-hash" => ProposalFault::BadPrevBlockHash,
        "bad-genesis-hash" => ProposalFault::BadGenesisHash,
        "bad-seed-proof" => ProposalFault::BadSeedProof,
        "proposer-mismatch" => ProposalFault::ProposerMismatch,
        other => bail!("unknown proposal fault {other}"),
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_vote_case(
    cli: &Cli,
    algod: &Algod,
    secrets: &ParticipationSecrets,
    sender: Address,
    target: Round,
    params: ConsensusParams,
    balance: u64,
    total_money: u64,
    key_dilution: u64,
    fault: VoteFault,
    transport: &Transport,
) -> Result<Report> {
    // Recovery steps are always propagated by Go's freshness rules
    // (`voteStepFresh`: `vote >= late` short-circuits) and are never emitted by
    // an honest node in a healthy cluster, so injecting at `down` cannot
    // collide with a real vote from the same account.
    //
    // The zero-weight case is the exception: the `down` committee is far too
    // large to ever miss, so it uses the small proposer committee instead.
    let step = if fault == VoteFault::ZeroWeightCredential {
        PROPOSE
    } else {
        DOWN
    };

    let mut ctx = VoteContext {
        sender,
        round: target,
        period: Period(0),
        step,
        proposal: if step == PROPOSE {
            synthetic_proposal_value(sender, target, Period(0))
        } else {
            bottom()
        },
        seed: algod
            .seed(algo_agreement::seed_round(target, &params))
            .await?,
        balance,
        total_money,
        key_dilution,
        vote_first_valid: Round(0),
        vote_last_valid: Round(0),
        params: params.clone(),
    };

    if fault == VoteFault::ZeroWeightCredential {
        // Search forward for a round where this account misses the proposer
        // committee. Only rounds within the freshness window are usable, so the
        // search polls the node until such a round becomes current.
        let mut found = None;
        for _ in 0..cli.weight_search_rounds {
            let last = algod.last_round().await?;
            let round = Round(last.0 + 2);
            let seed = algod
                .seed(algo_agreement::seed_round(round, &params))
                .await?;
            let mut probe = ctx.clone();
            probe.round = round;
            probe.seed = seed;
            probe.proposal = synthetic_proposal_value(sender, round, Period(0));
            if committee_weight(&probe, secrets) == 0 {
                found = Some(probe);
                break;
            }
            tokio::time::sleep(Duration::from_millis(900)).await;
        }
        ctx = found.ok_or_else(|| {
            anyhow!(
                "account won a proposer seat in every one of the {} rounds probed; \
                 rerun (the search is stochastic)",
                cli.weight_search_rounds
            )
        })?;
    }

    let weight = committee_weight(&ctx, secrets);
    if fault != VoteFault::ZeroWeightCredential && weight == 0 {
        bail!(
            "account is not on the step-{} committee at round {}; a rejection would be \
             attributable to the missing seat rather than to the injected fault",
            ctx.step,
            ctx.round
        );
    }

    // One honest build shared by both halves, so the reported byte diff is the
    // injected fault and not a fresh one-time subkey.
    let (baseline, injected) = baseline_and_faulted(&ctx, secrets, fault)?;
    let baseline_bytes = encode_vote(&baseline);
    let injected_bytes = encode_vote(&injected);
    let differing = count_differing_bytes(&baseline_bytes, &injected_bytes);

    tracing::info!(
        case = fault.case_name(),
        round = ctx.round.0,
        step = ctx.step.0,
        weight,
        differing_bytes = differing,
        "built injected vote"
    );

    let mut report = Report {
        case: fault.case_name().to_string(),
        tag: "AV".to_string(),
        sender: sender.to_algorand_string(),
        round: ctx.round.0,
        period: ctx.period.0,
        step: ctx.step.0,
        committee_weight: weight,
        baseline_hex: Some(hex::encode(&baseline_bytes)),
        injected_hex: hex::encode(&injected_bytes),
        differing_byte_count: Some(differing),
        expected_go_error: fault.expected_go_error().to_string(),
        disconnected: None,
        elapsed_ms: None,
        frames_received: None,
        honest_block_digest: None,
        injected_block_digest: None,
        committed_block_digest: None,
        corrupted_block_adopted: None,
        dry_run: cli.dry_run,
    };

    if cli.dry_run {
        return Ok(report);
    }

    let outcome = transport
        .inject_one(Tag::AgreementVote, injected_bytes)
        .await?;
    tracing::info!(?outcome, "injection complete");
    report.disconnected = Some(outcome.disconnected);
    report.elapsed_ms = Some(outcome.elapsed_ms);
    report.frames_received = Some(outcome.frames_received);
    Ok(report)
}

/// Case 4: capture a genuine proposal payload off the wire, corrupt exactly one
/// field, and re-inject it.
///
/// Capturing rather than assembling is deliberate: the injector has no ledger,
/// so the only way to obtain a payload that is valid in every respect *except*
/// the injected fault is to take one an honest proposer just produced.
async fn run_malformed_proposal(cli: &Cli, algod: &Algod, transport: &Transport) -> Result<Report> {
    use algo_agreement::codec;

    let fault = parse_proposal_fault(&cli.proposal_fault)?;
    let capture_transport = transport.with_observe(cli.capture_secs);

    let captured = capture_transport.capture_proposal().await?;
    tracing::debug!(
        len = captured.len(),
        first_32_hex = %hex::encode(&captured[..captured.len().min(32)]),
        "captured PP bytes before decode"
    );
    let cm = codec::decode_compound_message(&captured)
        .map_err(|e| anyhow!("captured PP did not decode: {e}"))?;
    let round = cm.proposal.round();
    tracing::info!(
        round = round.0,
        bytes = captured.len(),
        "captured a real proposal"
    );

    let corrupted = corrupt_proposal(&cm.proposal, fault)?;
    let injected_cm = algo_agreement_fuzz::build_compound_message(corrupted, cm.vote.clone());
    let injected_bytes = encode_compound_message(&injected_cm);
    let baseline_bytes = encode_compound_message(&cm);
    let differing = count_differing_bytes(&baseline_bytes, &injected_bytes);

    let last = algod.last_round().await?;
    let mut report = Report {
        case: format!("malformed-proposal/{}", fault.case_name()),
        tag: "PP".to_string(),
        sender: cm.vote.raw_vote.sender.to_algorand_string(),
        round: round.0,
        period: cm.vote.raw_vote.period.0,
        step: cm.vote.raw_vote.step.0,
        committee_weight: 0,
        baseline_hex: Some(hex::encode(&baseline_bytes)),
        injected_hex: hex::encode(&injected_bytes),
        differing_byte_count: Some(differing),
        expected_go_error: fault.expected_go_error().to_string(),
        disconnected: None,
        elapsed_ms: None,
        frames_received: None,
        honest_block_digest: Some(cm.proposal.block_digest().to_string()),
        injected_block_digest: Some(injected_cm.proposal.block_digest().to_string()),
        committed_block_digest: None,
        corrupted_block_adopted: None,
        dry_run: cli.dry_run,
    };
    tracing::info!(
        last = last.0,
        honest = %cm.proposal.block_digest(),
        injected = %injected_cm.proposal.block_digest(),
        "captured proposal is for round {}", round.0
    );

    if cli.dry_run {
        return Ok(report);
    }

    let inject_transport = transport.with_observe(cli.observe_secs);
    let injected_digest = injected_cm.proposal.block_digest();
    let outcome = inject_transport
        .inject_one(Tag::ProposalPayload, injected_bytes)
        .await?;
    tracing::info!(?outcome, "injection complete");
    report.disconnected = Some(outcome.disconnected);
    report.elapsed_ms = Some(outcome.elapsed_ms);
    report.frames_received = Some(outcome.frames_received);

    // A malformed payload is answered with `ignoreAction`, not a disconnect
    // (agreement/player.go, payloadRejected/payloadMalformed), so the decisive
    // assertion is what the network actually committed at that round.
    let committed = wait_for_block(algod, round, Duration::from_secs(120)).await?;
    let committed_digest = algo_agreement::UnauthenticatedProposal {
        block: committed,
        seed_proof: [0u8; 80],
        original_period: Period(0),
        original_proposer: Address([0u8; 32]),
    }
    .block_digest();
    report.committed_block_digest = Some(committed_digest.to_string());
    report.corrupted_block_adopted = Some(committed_digest == injected_digest);
    tracing::info!(
        committed = %committed_digest,
        adopted_corrupted = committed_digest == injected_digest,
        "round {} settled", round.0
    );
    Ok(report)
}

/// Poll until `round` is committed, then return its block.
async fn wait_for_block(
    algod: &Algod,
    round: Round,
    timeout: Duration,
) -> Result<algo_types::Block> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if algod.last_round().await?.0 >= round.0 {
            return Ok(algod.block(round).await?.block);
        }
        if std::time::Instant::now() >= deadline {
            bail!("round {} was not committed within {timeout:?}", round.0);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Number of positions at which the two encodings differ (length difference
/// counts as differing bytes).
fn count_differing_bytes(a: &[u8], b: &[u8]) -> usize {
    let common = a.len().min(b.len());
    let mut n = a.len().abs_diff(b.len());
    for i in 0..common {
        if a[i] != b[i] {
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_differing_bytes() {
        assert_eq!(count_differing_bytes(b"abc", b"abc"), 0);
        assert_eq!(count_differing_bytes(b"abc", b"abd"), 1);
        assert_eq!(count_differing_bytes(b"abc", b"ab"), 1);
        assert_eq!(count_differing_bytes(b"", b"xyz"), 3);
    }

    #[test]
    fn vote_cases_map_to_the_documented_faults() {
        assert_eq!(
            parse_vote_fault("bad-vrf-proof").unwrap().case_name(),
            "bad-vrf-proof"
        );
        assert_eq!(
            parse_vote_fault("wrong-committee-weight").unwrap(),
            VoteFault::ZeroWeightCredential
        );
        assert_eq!(
            parse_vote_fault("wrong-ots-domain").unwrap(),
            VoteFault::WrongOtsDomain(OtsDomain::Payload)
        );
        assert!(parse_vote_fault("nope").is_err());
    }

    #[test]
    fn proposal_faults_parse() {
        assert_eq!(
            parse_proposal_fault("bad-payset-commitment").unwrap(),
            ProposalFault::BadPaysetCommitment
        );
        assert_eq!(
            parse_proposal_fault("bad-seed-proof").unwrap(),
            ProposalFault::BadSeedProof
        );
        assert!(parse_proposal_fault("nope").is_err());
    }
}
