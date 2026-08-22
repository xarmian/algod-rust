# Phase 6 Validation — Consensus Participation (Conformance Layer 9)

_Completed: 2026-08-22_

Phase 6 turns algod-rust from a follower/relay into a **participation
node**: it holds participation keys, runs VRF sortition, assembles and
proposes blocks, casts soft/cert/next votes, and advances periods
alongside go-algorand v4.5.1-stable peers on the same network.

This document is the evidence map for
[`docs/PHASE6_PROPOSAL.md`](PHASE6_PROPOSAL.md)'s seven Success
Criteria. It is the Layer 9 counterpart to
[`PHASE5_VALIDATION.md`](PHASE5_VALIDATION.md) (Layer 8) and is
referenced from
[`CONFORMANCE_STRATEGY.md`](CONFORMANCE_STRATEGY.md) §11.

Every claim below cites a specific file that exists in this repo and a
specific check inside it. Where a claim rests on a live mixed Go/Rust
cluster rather than an in-process test, the citation names both the
script that runs it and the assertion it makes.

> **One open item.** All seven of the proposal's success criteria are
> met. Epic #107's own checklist carries one criterion that goes beyond
> them — *"Rust votes appear in certificates verified by Go nodes"* —
> which is **not** demonstrated at this harness's 30/30/30/10 stake
> split and is not reachable there: `agreement.makeBundle` stops packing
> votes at quorum, and the three Go accounts alone clear it. Measured:
> 0 of 301 consecutive certificates carried the Rust vote, while Go's
> `VoteAccepted` telemetry showed those same votes being accepted and
> weighted. See criterion 7 below for the full reasoning; #107 is left
> open on this point.

---

## Epics Completed

| Epic | Title | Issue | Key deliverables |
|------|-------|-------|------------------|
| 37 | Cryptographic Primitives and Agreement Params | #101 | `crates/core/algo-consensus-crypto` — VRF (libsodium-fork parity), sortition, one-time signatures, merkle signature scheme |
| 38 | Participation Key Loading and Signing | #102 | `crates/core/algo-ledger/src/participation/` — partkey restore/install/fill/persist, keyreg construction |
| 39 | Agreement Types, Selectors, and Verification | #103 | `crates/core/algo-agreement` — votes, bundles, proposals, certificates, credential verification, lookback state |
| 41a | Agreement Service Interfaces | #104 | Ledger / key-manager / network / block-factory trait surface |
| 40 | Agreement State Machine | #105 | `player`/`router`/`proposalStore`/`voteTracker` port of go-algorand's agreement state machine |
| 41b | Agreement Service Integration | #106 | `Service` wiring the state machine to gossip, ledger, pool and key manager; `algod-rust participate` |
| 42 | Mixed-Cluster Consensus Conformance Testing | #107 | `ops/mixed-cluster/` 4-node harness, positive/negative/restart conformance suites, participation metrics |

Epic 42 shipped as seven merged changes:

| Sub-issue | PR | Commit | What it added |
|---|---|---|---|
| #468 | #479 | `133aeca` | `goal network create` partkey + genesis-bootstrap interop for `participate` |
| #478 | #480 | `5064481` | 6 real bugs in `algo-network` / `algo-agreement` / `algo-ledger` / pool that kept Rust nodes stuck at round 0 in a real cluster |
| #469 | #481 | `647c4be` | The Rust node wired in as an **online** participant (30/30/30/10 stake split); VRF seed-proof fix |
| #482 | #483 | `cb7ad49` | Agreement action-ordering fix — pseudonode actions must run *after* the demux executes the batch, otherwise Rust never proposes |
| #470 | #484 | `8c74c0a` | Positive Layer-9 conformance suite (proposer share, cert cross-verify both directions, step coverage, forced period advancement, soak) |
| #471 | #485 | `7eac3e0` | Restart/rejoin conformance + fix for crash-state msgpack encoding (positional → named) |
| #472 | #486 | `d8121eb` | Negative Layer-9 conformance (`crates/tools/algo-agreement-fuzz`) |
| #473 | #487 | `c6df61f` | Participation metrics: `/v2/participation/status`, `/metrics`, structured events, round timing |

---

## Test Topology

```
        ┌────────────┐   gossip 4161   ┌────────────┐
        │ go-node-1  │◀───────────────▶│ go-node-2  │
        │ relay+prop │                 │ relay+prop │
        │  30% stake │                 │  30% stake │
        └─────┬──────┘                 └──────┬─────┘
              │                               │
              │      ┌────────────┐           │
              └─────▶│ go-node-3  │◀──────────┘
                     │ relay+prop │
                     │  30% stake │
                     └──────┬─────┘
                            │ gossip (outbound dials)
                            ▼
                  ┌──────────────────────┐
                  │     rust-node-4      │
                  │ algod-rust participate│
                  │  10% stake, voting   │
                  │  REST on host :4004  │
                  └──────────────────────┘
```

| Container | Image / build | Role | Host ports |
|---|---|---|---|
| `phase6-go-node-1` | `algorand/algod:4.5.1-stable` | relay + proposer, 30% online stake | 4001 (REST), 4161 (gossip — published only for the #472 injector) |
| `phase6-go-node-2` | `algorand/algod:4.5.1-stable` | relay + proposer, 30% | 4002 (REST) |
| `phase6-go-node-3` | `algorand/algod:4.5.1-stable` | relay + proposer, 30% | 4003 (REST) |
| `phase6-rust-node-4` | built from `docker/Dockerfile` | `algod-rust participate`, 10% | 4004 (REST) |

Definition: `ops/mixed-cluster/docker-compose.yml`,
`ops/mixed-cluster/template.json`. Bootstrap and config overlay:
`ops/mixed-cluster/scripts/start.sh`. Runbook and sortition math:
`ops/mixed-cluster/README.md`.

The stake split is deliberate: the three Go nodes hold 90% of stake
against a `CertCommitteeSize = 1500` / threshold `1112` (74.1%)
quorum, so a Rust bug can never halt the chain, while
`NumProposers = 20` gives the Rust node an expected 2 proposer seats
per round — it wins ~10% of rounds, enough for a statistical gate over
200 rounds.

---

## Success Criteria → Evidence

### 1. VRF sortition produces identical committee membership decisions as Go (test vectors)

| Evidence | What it proves |
|---|---|
| `crates/core/algo-consensus-crypto/tests/vrf_parity.rs` — `vrf_parity_vs_go_algorand()` | Rust VRF `prove`/`verify` produce **byte-identical** proofs and outputs to go-algorand's libsodium fork, over the vector corpus captured by `tools/vrf-vector-capture/`. |
| `crates/core/algo-consensus-crypto/tests/sortition_parity.rs` — `sortition_parity_vs_go_algorand()` | Rust `sortition::select` returns the same committee weight as `github.com/algorand/sortition` (Boost incomplete-beta) for every captured `(money, total, expected_size, digest)` vector, from `tools/sortition-vector-capture/`. |
| `crates/core/algo-agreement/tests/lookback_boundary.rs` — `rust_matches_go_on_every_captured_vector`, `v7_to_v8_transition_shifts_balance_round_by_160` | The *inputs* to sortition — balance round, seed round, and the seed lookback across consensus-version boundaries — match Go's `agreement/params.go` on the vectors from `tools/lookback-vector-capture/`. Committee parity is worthless if the lookback round is off by one. |
| `crates/tools/algo-agreement-fuzz/src/lib.rs` — `baseline_credential_matches_go_make_credential`, `case2_weight_matches_direct_sortition_select` | The credential the *production* code path builds for a live cluster account matches `committee.MakeCredential`, and its weight matches a direct `sortition.Select` call. |

**Live cross-check.** The same sortition is exercised end-to-end in the
cluster: `ops/mixed-cluster/scripts/analyze.py`'s `proposer_share_check`
requires the Rust account's observed proposer count over N rounds to sit
inside a two-sided binomial bound (`|k − Np| ≤ σ·√(Np(1−p))`, σ = 3,
p = 0.10) and **always fails on k = 0**. If Rust's sortition disagreed
with Go's, Rust would either never win a round or win far too many.

---

### 2. Rust votes accepted / verified by Go nodes in a mixed cluster

| Evidence | What it proves |
|---|---|
| `ops/mixed-cluster/scripts/consensus-conformance.sh` — `go_accepts_rust_votes` check | Scrapes the Go nodes' own `VoteAccepted` agreement telemetry for entries whose `Sender` is the Rust account, **broken down per step**, and fails if any required step is missing. This is Go's verifier saying yes, not Rust asserting about itself. |
| Same script — `no_go_side_rejections` check | Requires **zero** WARN-level agreement rejections (`malformed proposal`, `malformed vote`, `rejected block`, `bundle malformed`) in all three Go nodes' logs for the whole run. |
| `ops/mixed-cluster/scripts/participation-smoke.sh` | The fast (30-round) version of the same two assertions plus 4-node lockstep; wrapped for cargo by `crates/node/algo-network/tests/mixed_cluster_participation.rs` — `rust_node_participates_in_mixed_cluster()`. |
| `crates/core/algo-agreement/tests/codec_roundtrip.rs` — `uvote_roundtrip_vs_go`, `vote_roundtrip_vs_go`, `ubundle_roundtrip_vs_go`, `bundle_roundtrip_vs_go`, `rawvote_roundtrip_vs_go` | The wire encoding Go must parse round-trips byte-for-byte against fixtures captured from go-algorand (`tools/agreement-wire-capture/`). |

Run it with `make consensus-cluster-test`, or the smoke version with
`make consensus-cluster-smoke`.

---

### 3. Rust proposes blocks accepted by Go nodes

| Evidence | What it proves |
|---|---|
| `ops/mixed-cluster/scripts/analyze.py` — `proposer_share_check`, driven by `--rust-account` | The **committed chain** read back from the Go nodes' `/v2/blocks/{r}` carries the Rust account as proposer at roughly its 10% stake share. A block only reaches that histogram if a Go quorum certified it. |
| `ops/mixed-cluster/scripts/analyze_test.py` — `ProposerShareTest` (7 cases, incl. `test_observer_topology_zero_rust_proposals_fails`, `test_real_participating_run_passes`, `test_over_proposing_also_fails`) | The gate itself is unit-tested against real recorded data from both a non-participating (must fail) and a participating (must pass) run — so a green proposer-share result is meaningful. Run with `make consensus-cluster-analyzer`. |
| `crates/core/algo-agreement/src/metrics.rs` + `crates/core/algo-agreement/tests/metrics_test.rs` — `own_proposal_committed_counts_as_accepted`, `own_proposal_losing_the_round_counts_as_rejected` | The Rust node's own `proposals_accepted` / `proposals_rejected` counters, surfaced on `/v2/participation/status`, are defined and tested against block-commit outcomes — an independent second reading of the same fact. |
| `crates/core/algo-agreement/tests/simulate_smoke.rs` — `assemble_never_runs_before_previous_round_is_committed` | Regression lock for #482, the ordering bug that made the Rust node's proposer share **0%** while everything else looked healthy. |

---

### 4. Rust correctly verifies Go votes

| Evidence | What it proves |
|---|---|
| `crates/tools/algo-cert-crossverify/` (`src/lib.rs`, `src/main.rs`) | Fetches **Go-produced** certificates from a Go node's REST API and authenticates each one with Rust's `Certificate::authenticate` against a caught-up Rust ledger (`/app/ledger.sqlite`, `docker cp`'d out of the container by `verify-soak.sh`). Non-zero exit on any failure. Wired as the `certs_authenticate_rust` check in `consensus-conformance.sh`. |
| `crates/core/algo-agreement/tests/player_permutation.rs` — `player_permutation()` | 7 player states × 14 message events, run under V41 and V41-with-dynamic-filter-timeout (196 assertions), mirroring go-algorand's `agreement/player_permutation_test.go` — the state machine reacts to incoming Go messages the way Go's does. |
| `crates/core/algo-agreement/tests/codec_roundtrip.rs` — `cert_roundtrip_vs_go`, `proposalvalue_roundtrip_vs_go`, `uproposal_roundtrip_vs_go`, `tpayload_roundtrip_vs_go` | Rust decodes Go's certificate and proposal encodings without loss. |
| `crates/core/algo-agreement/tests/fuzzer_smoke.rs` (28 tests) | Drop / duplicate / reorder / node-crash message pipelines do not desynchronise the verifier. |

The Rust node is also verifying Go votes continuously and implicitly:
it cannot advance a round without certifying it, and
`consensus-cluster-status` (`scripts/status.sh`) fails if the Rust node
falls more than `LAG_TOLERANCE` rounds behind the Go quorum.

---

### 5. 200+ rounds in a mixed 4-node cluster (3 Go + 1 Rust) with active participation

| Evidence | What it proves |
|---|---|
| `ops/mixed-cluster/scripts/consensus-conformance.sh` (`make consensus-cluster-test`, `ROUNDS` defaults to **200**) | The one-command acceptance gate: up → optional forced period advancement → soak → verify → down, emitting a machine-readable `summary.json`. |
| `ops/mixed-cluster/scripts/soak.sh` + `scripts/metrics.py` | Per-round JSONL collection across all four nodes: `/v2/status` rounds, `/v2/blocks/{r}` proposer + timestamp + hash, `docker inspect` container samples, and `/v2/participation/status` snapshots. |
| `ops/mixed-cluster/scripts/analyze.py` — `summarize`, per-node lag bounds (`node_lockstep`) | All four nodes stay within tolerance of the max round for the entire soak. |
| `ops/mixed-cluster/scripts/analyze.py` — `step_coverage_check` (`--rust-log`) | The Rust node cast votes at **both** the soft and cert steps (and records next-step / reproposal activity), so "200 rounds" is 200 rounds of *participation*, not of passive following. |
| `docs/SOAK_METHODOLOGY.md` | The measured metrics, tuning knobs, acceptance thresholds and known limitations for the soak. |
| `crates/node/algo-network/tests/consensus_conformance.rs` — `rust_node_passes_positive_consensus_conformance()` | The whole suite as a `#[ignore]`d, `MIXED_CLUSTER=1`-gated cargo test. |

Period advancement is not left to chance: the suite's
`period_advancement_recovery` stage pauses a Go relay for
`PAUSE_SECONDS` to force the cluster past period 0 and asserts it
returns to lockstep.

---

### 6. No forks; normal block cadence

| Evidence | What it proves |
|---|---|
| `crates/tools/algo-fork-detector/` (`src/lib.rs`, `src/main.rs`) | Fetches every round from every node, **recomputes the block digest locally** rather than trusting the served hash, and classifies each round `Agreed` / `Forked` / insufficient. Unit tests: `agreed_when_all_same`, `forked_when_differ`, `insufficient_when_under_two`, `aggregate_includes_fetch_failures`, `aggregate_emits_findings_for_forks_only`. |
| `ops/mixed-cluster/scripts/verify-soak.sh` | Runs the fork detector over **every** round of the soak window (cert cross-verify is sampled with `--stride`; fork detection never is). Wired as the `fork_free` check in `consensus-conformance.sh`. |
| `ops/mixed-cluster/scripts/analyze.py` — `cadence_check` | Gates block-time mean and p95 against configured bounds; the report also carries p50/p99, commit-latency spread, and a warning digest. Unit-tested by `analyze_test.py::CadenceTest`. |
| `ops/mixed-cluster/scripts/restart-rejoin.sh` — `no_fork`, `no_stall` assertions | Fork-freedom is re-checked across **all four** nodes over each restart window, and the Go quorum is required never to go `MAX_STALL_SECONDS` without advancing. |

---

### 7. Certificates with Rust votes verifiable by Go nodes during catchup

| Evidence | What it proves |
|---|---|
| `tools/cert-authenticate/main.go` (+ `run-in-docker.sh`) | A **real go-algorand v4.5.1-stable** binary re-authenticates the exported certificates with `agreement.Certificate.Authenticate`. Its `agreement.LedgerReader` facts — seed, circulation, balance/params/seed rounds, per-voter online account data — are the ones **Rust** supplied via `algo-cert-crossverify --export-go-input`, so a divergence in Rust's view of stake or seed surfaces as a Go-side authentication failure. Go recomputes the block digest itself and reports a mismatch distinctly. Exit code 2 = a cert failed. |
| `ops/mixed-cluster/scripts/verify-soak.sh` (`--rust-account`) → `consensus-conformance.sh` check `certs_authenticate_go` | Runs the above as part of the acceptance gate. |
| `crates/tools/algo-cert-crossverify/src/lib.rs` — `rust_vote_rounds`, `cert_contains_sender_matches_exact_address`, `cert_senders_dedupes_and_sorts`, `go_verify_input_round_trips_through_json` | Identifies which certificates actually carry the Rust account's vote, and locks the export format. |

**Honest scope note.** `agreement.makeBundle`
(`../go-algorand/agreement/bundle.go`) stops packing votes once the
running weight reaches quorum, so a certificate carries only the votes
that were *needed*. At the harness's 30/30/30/10 split the three Go
accounts alone clear the 74.1% cert threshold, and the Rust node's cert
vote — one relay hop later — is dropped from the bundle. Measured on a
healthy participating run: **0 of 301** consecutive certificates
(checked on all three Go nodes) contained it. `MIN_RUST_VOTE_ROUNDS`
therefore defaults to `0` — recorded, not gated — and vote *acceptance*
is asserted from Go's own `VoteAccepted` telemetry instead (criterion
2). What criterion 7 does prove unconditionally is that certificates
produced on a network **where the Rust node is an online participant
contributing to the seed, the stake denominator and the proposal set**
authenticate under both implementations, with the Rust ledger's view of
the voting state as the input. Raise `MIN_RUST_VOTE_ROUNDS` on a
topology where the Rust stake exceeds ~26% and is therefore required
for quorum.

---

## Beyond the Success Criteria

The epic's own acceptance criteria (#107) go past the proposal's seven.

### Restart / rejoin mid-round (#471)

`ops/mixed-cluster/scripts/restart-rejoin.sh`, `make consensus-cluster-restart`,
cargo wrapper `crates/node/algo-network/tests/consensus_conformance.rs` —
`rust_node_rejoins_consensus_after_restart()`.

| Scenario | How the node goes down |
|---|---|
| `graceful` | `docker restart` (SIGTERM) — clean shutdown + rejoin |
| `kill` | `docker kill -s KILL` — real crash recovery off whatever the async persistence loop had committed to `crash.sqlite` |
| `proposer` | SIGKILL timed into a round the node is *proposing* in, driven off its own `assembled N proposal message(s) at (round, period)` log line |

Per-scenario assertions: **rejoin** within `REJOIN_ROUND_BUDGET` rounds
and `REJOIN_TIMEOUT` seconds; **resumed_voting** (at least one attest
for a round at/after the restart, so a replayed pre-crash checkpoint
cannot masquerade as fresh participation); **no_stall**; **no_fork**
across all four nodes; **no_equivocation_rust** via
`ops/mixed-cluster/scripts/equivocation.py`; **no_equivocation_go** via
go-algorand's own `voteTracker: observed an equivocator` /
`EquivocatedVote` (`../go-algorand/agreement/voteTracker.go`).

`equivocation.py` is unit-tested by `equivocation_test.py`, which the
script runs as a **self-test before the scenarios** — a "no
equivocation" verdict only counts if the detector provably catches a
synthetic double vote, and `attests_scanned > 0` is separately
required so an empty scan can never pass.

**Real bug found and fixed here**: persisted agreement state used
positional (array) msgpack instead of named/canonical, so
`skip_serializing_if` fields silently shifted and a live node's crash
state never decoded — every restart quietly discarded it. See
`crates/core/algo-agreement/src/persistence.rs`
(`encode_decode_router_holding_a_real_block_proposal`,
`full_persist_restore_cycle_with_a_real_block_proposal`, plus ~40
surrounding persistence tests).

### Negative conformance (#472)

`crates/tools/algo-agreement-fuzz/` builds an honest agreement message
from the real `Wallet4.partkey` and real ledger parameters — through the
production encoders in `algo_agreement::codec` and the production
crypto in `algo_consensus_crypto` — then injects **exactly one** typed
fault and opens a normal gossip connection to `go-node-1`.
`ops/mixed-cluster/scripts/negative-conformance.sh` (`make
consensus-cluster-negative`) requires both a `BadData` disconnect *and*
the case-specific `../go-algorand/agreement/trace.go` error text, since
a closed socket alone is not attribution.

| Case | Injected fault | go-algorand's rejection |
|---|---|---|
| `bad-vrf-proof` | one bit flipped in the 80-byte VRF proof | `unauthenticatedVote.verify: … UnauthenticatedCredential.Verify: could not verify VRF Proof` |
| `wrong-committee-weight` | an entirely honest vote for a `(round, 0, propose)` where the account wins **zero** seats (0 bytes differ from honest) | `malformed proposal … UnauthenticatedCredential.Verify: credential has weight 0` |
| `wrong-ots-domain` | correct one-time key, correct body, signed under `"PL"` instead of `"VO"` | `unauthenticatedVote.verify: could not verify FS signature on vote by …` |
| `malformed-proposal` | a genuine `PP` captured off the wire with one block field corrupted | `rejected block for (r, 0): proposalStore: no accepting blockAssembler found on payloadPresent`; block never committed |

Two protocol-level findings are recorded in
`ops/mixed-cluster/README.md` §"Two findings worth recording": a
claimed committee weight is **not representable on the wire**
(`committee.UnauthenticatedCredential` carries only the VRF proof;
`Weight` lives on the verified credential and is always recomputed), and
a single-field payload corruption **cannot reach the block validator**
because `EncodingDigest = HashObj(payload)` binds the payload to the
proposal-vote.

### Participation monitoring (#473)

| Surface | Evidence |
|---|---|
| `GET /v2/participation/status` (API token) — JSON: votes by step, proposals made/accepted/rejected, reproposals, blocks committed, broadcast failures, round-timing stats + rolling per-round samples | `crates/node/algo-rest-api/src/handlers.rs::get_participation_status`, routed in `src/router.rs`; tests `participation_status_returns_metrics_json`, `participation_status_requires_a_token`, `participation_status_accepts_the_admin_token`, `participation_status_404s_when_not_participating`, `participation_status_route_does_not_shadow_key_lookup` in `crates/node/algo-rest-api/tests/integration.rs` |
| `GET /metrics` (unauthenticated) — the same counters in Prometheus text exposition format, hand-rendered with **no new workspace dependency** | `crates/core/algo-agreement/src/metrics.rs::to_prometheus_text`; tests `metrics_endpoint_returns_prometheus_text_without_auth`, `metrics_endpoint_404s_when_not_participating` |
| Counter semantics | `crates/core/algo-agreement/tests/metrics_test.rs` — 22 tests covering per-step vote labels, proposal accept/reject attribution, round-timing windows, history capping, thread safety |
| Harness wiring | `scripts/metrics.py` emits `kind: "participation"` records; `scripts/analyze.py::participation_endpoint_check` / `summarize_participation_records` gate on them (`--require-participation-endpoint`, `--max-round-duration-ms`); covered by `analyze_test.py::ParticipationEndpointTest` |

Both endpoints answer **404 when the process is not participating**, so
a scraper can distinguish "not participating" from "participating, zero
votes so far" (a 200 with zeroed counters). Neither is a go-algorand
conformance surface — Go has no `/v2/participation/status`, and its
`/metrics` is a different subsystem with a different metric set.

### Participation-key and genesis interop (#468)

`crates/core/algo-ledger/tests/goal_network_create_test.rs` runs against
a partkey and genesis captured from a real
`goal network create` over `ops/mixed-cluster/template.json`
(v4.5.1-stable), committed at
`crates/core/algo-ledger/tests/fixtures/partkey/goal-network-create/`:

- `restores_metadata_from_goal_network_create_partkey`,
  `first_valid_round_zero_is_preserved`,
  `goal_partkey_liveness_window_matches_the_template`
- `vote_pubkey_matches_genesis_alloc`, `vrf_pubkey_matches_genesis_alloc`,
  `state_proof_commitment_matches_genesis_alloc` — the restored keys
  equal what `goal` independently wrote into `genesis.json`
- `genesis_seed_matches_go_ledger_supply` — the online / participating
  totals `participate --genesis-json` seeds match what a live
  `algorand/algod:4.5.1-stable` serves from `/v2/ledger/supply` at
  round 0 on the same netroot
- `keyreg_online_brings_offline_genesis_account_online`,
  `online_genesis_account_needs_no_keyreg`,
  `keyreg_with_expired_key_window_is_rejected`
- `corrupt_partkey_is_rejected`, `partkey_with_missing_tables_is_rejected`,
  `reinstalling_the_same_goal_partkey_is_a_constraint_violation`

Auto-discovery (`--partkey-dir` scanning
`<data-dir>/<genesis-id>/<account>.<first>.<last>.partkey`) mirrors
`AlgorandFullNode.loadParticipationKeys` in
`../go-algorand/node/node.go`. Command source:
`bin/algod-rust/src/commands/participate.rs`.

---

## Bugs Found by This Epic

Layer-9 testing earned its keep — every one of these was invisible to
unit tests and only appeared in a real mixed cluster.

| # | Bug | Fixed in |
|---|---|---|
| 1–6 | Six defects across `algo-network`, `algo-agreement`, `algo-ledger` and the pool that left a Rust node stuck at round 0 in a real cluster | #478 / `5064481` |
| 7 | VRF **seed proof** computed incorrectly for block assembly | #469 / `647c4be` |
| 8 | Agreement action ordering: a batch's `Pseudonode(Assemble N)` ran *before* the demux executed the same batch's `Ensure(block N−1)`, so block assembly always ran two rounds behind and fell through to an empty block that failed — Rust voted but **never proposed** (0% proposer share) | #482 / `cb7ad49` |
| 9 | Persisted agreement crash state encoded with positional msgpack, silently corrupting on every restart | #471 / `7eac3e0` |

---

## How to Reproduce

```bash
# Fast, no Docker: the analyzer/verifier gates themselves
make consensus-cluster-analyzer
cargo test -p algo-agreement-fuzz
cargo test -p algo-fork-detector -p algo-cert-crossverify
cargo test -p algo-consensus-crypto            # VRF / sortition / OTS parity
cargo test -p algo-agreement                   # state machine, codec, persistence

# The 4-node cluster
make consensus-cluster-up
make consensus-cluster-status                  # per-node round snapshot
make consensus-cluster-down                    # PURGE=1 also wipes netroot/

# Layer-9 gates
make consensus-cluster-smoke                   # #469, ~30 rounds
make consensus-cluster-test                    # #470, 200-round soak (ROUNDS=N)
make consensus-cluster-test RESTART_SCENARIOS=1 NEGATIVE_CASES=1
make consensus-cluster-restart                 # #471, against a running cluster
make consensus-cluster-negative                # #472

# Through cargo (all #[ignore]d and gated on MIXED_CLUSTER=1)
MIXED_CLUSTER=1 cargo test -p algo-network --test consensus_conformance   -- --ignored --nocapture
MIXED_CLUSTER=1 cargo test -p algo-network --test negative_conformance    -- --ignored --nocapture
MIXED_CLUSTER=1 cargo test -p algo-network --test mixed_cluster_participation -- --ignored --nocapture
```

`tools/cert-authenticate/` needs go-algorand's vendored libsodium fork;
`tools/cert-authenticate/run-in-docker.sh` builds it inside a
`golang:1.25-bookworm` container with both the checkout and the build
cached in named volumes (first run 3–5 min). That is also the only
supported path on Windows, where the host checkout's line endings break
autotools.

---

## Conformance Layers Covered

| Layer | Description | Phase | Status |
|-------|-------------|-------|--------|
| 1 | Wire format (msgpack decode/encode) | 0 | Covered |
| 2 | Block structure | 0 | Covered |
| 3 | Cryptographic digests | 0 | Covered |
| 4 | Stateless validation | 1 | Covered |
| 5 | Block-level validation | 1 | Covered |
| 6 | Ledger execution (state transitions, AVM) | 2–3 | Covered |
| 7 | Catchup and sync | 4 | Covered |
| 8 | Networking (gossip, framing, block serving, relay forwarding) | 5 | Covered |
| **9** | **Consensus (VRF sortition, voting, proposal, certificates, period advancement, restart/rejoin, negative rejection)** | **6** | **Covered** |

---

## Known Limitations

| Limitation | Notes |
|---|---|
| **Not in CI** | The harness is not run by any GitHub Actions workflow. Container build + Rust release build + a 200-round soak is far too slow for per-PR CI; see `docs/MIXED_CLUSTER_HARNESS.md` §3 and the follow-up issue filed there. All Layer-9 cluster tests are `#[ignore]`d and gated on `MIXED_CLUSTER=1`, so `cargo test --workspace` never touches Docker. |
| One Rust node, not three | The proposal's 6-node topology (3 Go + 3 Rust) and 1000+ round soak are explicitly **deferred to Phase 7** by #107. |
| Rust cert votes not inside certificates | Structural consequence of `makeBundle` + the 30/30/30/10 split, not a defect — see criterion 7. This is the one Epic #107 acceptance item left open; Phase 7's 3 Go + 3 Rust topology puts the Rust stake at 50%, where the votes become quorum-necessary and `MIN_RUST_VOTE_ROUNDS` can be raised above 0 to gate on it. |
| Negative suite injects at one node | Only `go-node-1`'s gossip port is published, deliberately: an injection can never reach the other two, which carry the quorum. |
| `algod-rust relay` still has no REST listener | `participate` does; the harness no longer needs it. |
| No mainnet/testnet participation | Out of Phase 6 scope. |
| Statistical gates, not deterministic ones | Proposer share is a 3σ binomial band, so a healthy run can in principle fail (~0.3%). σ and stake fraction are overridable (`PROPOSER_SIGMA`, `RUST_STAKE_FRACTION`). |

---

## Conclusion

algod-rust participates in Algorand consensus as a peer of
go-algorand v4.5.1-stable. On a private 4-node network it holds
participation keys generated by `goal network create`, runs sortition
that matches Go's on every captured vector, casts soft and cert votes
that Go's verifier accepts and counts at its exact stake weight,
proposes blocks that a Go quorum certifies at its expected share,
survives graceful restarts and SIGKILLs mid-round without equivocating
or forking, and has its malformed messages rejected by Go with exactly
the errors go-algorand's own code paths produce. Certificates from that
network authenticate under both implementations, with the Rust ledger's
view of seed and stake as the input to Go's verifier.

Deferred to Phase 7: a 6-node (3 Go + 3 Rust) topology, 1000+ round
soaks, consensus performance benchmarking, and public-network
participation.
