# Mixed-Cluster Consensus Harness — Design (PLAN-32 / TASK-86)

> **Status: shipped and complete.** This file records the *design
> rationale* behind the harness. For what it proves and which test
> backs each claim, read `docs/PHASE6_VALIDATION.md`; for how to drive
> it, read `ops/mixed-cluster/README.md`. Both are kept current; this
> document is not a task list.

## Why

Phase 6 acceptance (see PLAN-32) requires running the Rust node alongside
go-algorand nodes on a private network and proving consensus agrees
byte-for-byte across the cluster. TASK-86 is the foundation piece: a
docker-compose topology where we can bring up a 4-node (3 Go + 1 Rust)
private network reliably enough to hang soak tests (TASK-87) and fork-
detection tooling (TASK-88) on top.

Epic 42 (#107) then turned that foundation into the full Layer-9 suite:
the Rust node became an online participant (#469), and the harness grew
positive (#470), restart/rejoin (#471) and negative (#472) conformance
gates plus participation metrics (#473). The canonical entry points are
the `consensus-cluster-*` make targets.

## Relation to the existing `docker/docker-compose.mixed-cluster.yml`

The repo already has a mixed-cluster compose under `docker/`
(`docker-compose.mixed-cluster.yml`) but it serves a distinct purpose:

| File | Purpose | Topology |
|---|---|---|
| `docker/docker-compose.mixed-cluster.yml` | Gossip + catchup interop — can the Rust observer read Go blocks? Can a Go non-relay sync from a Rust relay? | 1 Go relay (block producer) + 1 Rust observer + 1 Rust relay + 1 Go non-relay |
| `ops/mixed-cluster/docker-compose.yml` | **Consensus agreement** — does the Rust node vote and propose on a network of 3 Go peers running real agreement, and does Go accept it? | 3 Go relay+proposers (30% stake each) + 1 `algod-rust participate` node (10%), all four online |

These intentionally coexist. A future refactor could unify them but
that's not in this task's scope. The `ops/` location is net-new and
signals "e2e / plan-level orchestration" vs `docker/` which collects
scenario-specific compose files.

## Topology decisions

### 3 Go proposers + 1 Rust participant, 30/30/30/10

`template.json` gives each Go node 30% of stake and the Rust node 10%,
**all four online and participating** (this was 33/33/33/1-offline in
the TASK-86 original; #469 flipped Wallet4 online).

Why this stake split:

- **The Rust node must never be able to halt the chain.** The three Go
  nodes hold 90% of online stake, an expected 1350 of the
  `CertCommitteeSize = 1500` cert votes against a `1112` (74.1%)
  threshold — roughly 13 sigma clear. They certify rounds with or
  without the Rust node, so a Rust bug shows up as a failed *assertion*,
  not as a dead cluster with nothing to read.
- **But its participation must still be statistically observable.**
  Under ConsensusFuture's `NumProposers = 20`, a 10% share gives an
  expected proposer-committee size of 2, so the Rust node holds at least
  one proposer credential in ~86% of rounds and wins ~10% of them. Over
  a 200-round soak that is a mean of 20 wins with sd 4.24 — a wide
  enough margin for `analyze.py`'s two-sided binomial gate to
  distinguish "healthy" from "never proposes" (see
  `ops/mixed-cluster/README.md` §"The proposer-share bound").
- A 25/25/25/25 split would have been worse on the first count: the
  cert threshold (>2/3 of online) would then need all three Go nodes in
  quorum, which stochastic sortition makes brittle.
- The flip side of the 10% share is that Rust's cert vote is not
  *needed* for quorum, so `agreement.makeBundle` drops it from the
  certificate. Vote acceptance is therefore asserted from Go's own
  `VoteAccepted` telemetry instead — see `docs/PHASE6_VALIDATION.md`
  criterion 7 for the full reasoning.

### One container per node (not `goal network start` in one container)

The vanilla algorand/algod image bootstraps a `goal network create`
tree when it doesn't find one, then calls `goal network start -r` which
runs *all nodes* inside one container. Doing it that way would mean 1
container with 3 Go algod processes + 1 separate Rust container — a
layout that's awkward for per-node observation and doesn't match how
operators run real nodes.

Instead, `start.sh` runs `goal network create` once (in a throwaway
container mounted on `./netroot`) and each of the 4 nodes mounts its
own `netroot/Node<N>/` subdirectory as `/algod/data`. The algod image's
entrypoint sees a pre-existing `genesis.json` and falls through to
`start_public_network`, running just one algod process. The Rust node
uses the custom `docker/Dockerfile` and is built from the local source.

### Config.json overlay

`goal network create` sets `NetAddress = 127.0.0.1:<port>` per node,
which is fine for single-host `goal network start` but useless across
docker containers. `start.sh` runs `algocfg` inside the algod image to
rewrite each Node's `config.json` with:

- `NetAddress = 0.0.0.0:4161` on the three Go relays — listen on all
  interfaces inside the container. `Node4Rust` gets `NetAddress = ""`:
  the Rust node is a participation node that dials out to the relays,
  matching the Go participation topology.
- `EndpointAddress = 0.0.0.0:8080` — same for REST
- `DNSBootstrapID = ""` — so private-net nodes don't try to reach
  mainnet/testnet relays and fill the logs with resolver errors

## Follow-ups (§1 and §2 resolved; §3 deferred)

### 1. Rust consensus participation — RESOLVED (#468, #469, #470–#473)

The Rust node in this compose file runs `algod-rust participate` and is
an **online voter and proposer**, holding 10% of online stake against
the three Go relays' 30% each. `template.json` marks all four wallets
`"Online": true`. Entry points: `make consensus-cluster-smoke` (30
rounds), `make consensus-cluster-test` (200-round positive suite),
`make consensus-cluster-restart`, `make consensus-cluster-negative`.
`docs/PHASE6_VALIDATION.md` maps each Phase 6 success criterion to the
test that verifies it.

Getting there took two real fixes that only a live cluster could
surface: a VRF **seed-proof** bug (#469) and an agreement
action-ordering bug (#482) that let the Rust node vote but never
propose — its `Pseudonode(Assemble N)` action ran before the demux had
executed the same batch's `Ensure(block N−1)`, so block assembly always
ran two rounds behind. Both are fixed and regression-locked
(`crates/core/algo-agreement/tests/simulate_smoke.rs`,
`assemble_never_runs_before_previous_round_is_committed`).

The key-format prerequisites that made this section an open question in
the first place were closed by issue #468:

- **Participation-key format interop — verified.** `goal network
  create` emits `*.partkey` files in Go's single-account SQLite schema.
  A partkey captured from a real `goal network create` run over
  `template.json` (v4.5.1-stable) is committed at
  `crates/core/algo-ledger/tests/fixtures/partkey/goal-network-create/`
  and proven end to end by
  `crates/core/algo-ledger/tests/goal_network_create_test.rs`: it
  restores, and its VRF / OTS / state-proof public keys match the
  values `goal` independently wrote into `genesis.json`.
- **Provisioning — no conversion step needed.** `--partkey-path` opens
  the multi-key *registry* schema, which is not the same database, so
  `participate` bridges the two at startup. Point `--data-dir` at a
  `goal`-generated node directory and it scans that node's genesis
  subdirectory (`<data-dir>/<genesis-id>/`, e.g.
  `netroot/Node4Rust/phase6net-v1/`) for `<account>.<first>.<last>.partkey`
  files and registers them — the same discovery
  `AlgorandFullNode.loadParticipationKeys` performs
  (`../go-algorand/node/node.go`). `--partkey-dir` scans an arbitrary
  directory and `--import-partkey` names individual files, for layouts
  that don't follow Go's convention.
- **Genesis interop — verified.** `participate --genesis-json` seeds
  `accountbase` + `accounttotals` from the `goal`-generated
  `genesis.json` (including the `ConsensusProtocol: "future"` pin the
  template sets). `genesis_seed_matches_go_ledger_supply` asserts the
  resulting online / participating totals against the values a live
  `algorand/algod:4.7.0-stable` node serves from `/v2/ledger/supply` at
  round 0 on the same netroot.
- **Online-stake awareness — done.** `template.json` now marks Wallet4
  `"Online": true`, so `goal network create` generates its partkey
  directly and no keyreg is needed to join the harness. The keyreg path
  remains covered by `keyreg_online_brings_offline_genesis_account_online`
  for the general case.

### 2. REST surface on the Rust relay — RESOLVED (#469, #473)

The cluster's Rust node runs `algod-rust participate --rest-listen
0.0.0.0:8080` (host port 4004) since issue #469, so `status.sh` and
`metrics.py` read its round from the same `/v2/status` endpoint as the Go
nodes'. Issue #473 added two participation-observability endpoints on top:

| Endpoint | Auth | Payload |
|---|---|---|
| `GET /v2/participation/status` | public API token | JSON snapshot: vote counts by step, proposals made/accepted/rejected, reproposals, blocks committed, broadcast failures, and round-timing stats (round start → first vote / proposal / commit) including a rolling per-round sample array |
| `GET /metrics` | none | The same counters in Prometheus text exposition format |

Both answer **404 when the process is not participating in consensus**
(`serve`, dev mode, read-only inspection) so a scraper can distinguish
"not participating" from "participating, zero votes so far" — the latter
is a 200 with zeroed counters.

Neither is a go-algorand conformance surface: go has no
`/v2/participation/status`, and its `/metrics` is served by a different
subsystem with a different metric set. These are algod-rust extensions
for this harness, deliberately implemented with **no new workspace
dependency** — the exposition text is rendered by hand in
`crates/core/algo-agreement/src/metrics.rs`.

`scripts/status.sh` prints a participation column from the JSON endpoint;
`scripts/metrics.py` writes `participation` / `participation_final` JSONL
records; `scripts/analyze.py` summarizes them and can gate on them with
`--require-participation-endpoint` / `--max-round-duration-ms`.

`algod-rust relay` still has no REST listener; that remains open, but the
cluster no longer needs it.

### 3. CI integration — SHIPPED as `.github/workflows/consensus-cluster.yml` (#488)

The harness runs nightly in GitHub Actions. The workflow is
**`Nightly Consensus Cluster`** (`.github/workflows/consensus-cluster.yml`),
triggered by `schedule` (02:41 UTC daily) and `workflow_dispatch` only —
there is deliberately **no `pull_request` and no `push` trigger**, so
per-PR CI wall time is untouched. Every cluster test also remains
`#[ignore]`d behind `MIXED_CLUSTER=1`, so `cargo test --workspace` still
never touches Docker.

| Tier | When | What it runs | Red gate |
|---|---|---|---|
| **1 — smoke** | every run | `make consensus-cluster-up` → `-status` (retried up to 5 min, so the gate measures steady state rather than boot ordering) → `SKIP_START=1 KEEP_CLUSTER=1 make consensus-cluster-smoke` (`SMOKE_ROUNDS=30`) → `make consensus-cluster-down` | lockstep loss (spread > `LAG_TOLERANCE`), a Rust node that does not advance 30 rounds, or any WARN-level Go-side agreement rejection (#469) |
| **2 — full suite** | nightly, or `workflow_dispatch` with `tier=full` (the default) | `make consensus-cluster-test RESTART_SCENARIOS=1 NEGATIVE_CASES=1` with `ROUNDS` (default 200) and a pinned `OUT_DIR` | any failed check in `summary.json` — proposer share, vote-step coverage, cadence, fork freedom, certs under Rust *and* under go-algorand's own verifier, Go-side `VoteAccepted`, restart/rejoin (#471) and negative-injection (#472) sub-checks |

Artifacts are uploaded as `consensus-cluster-<run_id>` with 30-day
retention: `summary.json`, `soak.jsonl`, `analyze.summary.json`, the
cert-crossverify JSONL and `verify-go-report-*.json` (the
`tools/cert-authenticate` output), `restart/restart-summary.json`,
`negative/negative-summary.json`, the per-node logs the analyzers read,
and — on failure — a `container-logs/` dump of all four nodes.

Cold-build cost is kept off the critical path two ways:

* the `algod-rust` node image is pre-built by `docker/build-push-action`
  with a `type=gha` buildx layer cache and tagged
  `algod-rust-phase6:local` (the tag `docker-compose.yml` now declares
  for `rust-node-4`); `start.sh` honours `PHASE6_SKIP_BUILD=1` and reuses
  it instead of running `docker compose up --build` once per tier;
* the Docker volume holding `tools/cert-authenticate`'s in-container
  go-algorand clone **and its built libsodium** is tarred into
  `actions/cache` (keyed on the pin plus `run-in-docker.sh`), so
  `run-in-docker.sh`'s 3-5 minute first run is paid once. Per CLAUDE.md
  the build itself is still go-algorand's own `make libsodium`, invoked
  by `run-in-docker.sh` — the workflow re-implements none of it.

Layer 9 evidence is recorded in `docs/PHASE6_VALIDATION.md`; the nightly
run is now the standing source of that evidence, with local runs still
available for iteration.

## Verification against TASK-86 acceptance

| Criterion | Verified how |
|---|---|
| `docker compose up -d` starts all 4 nodes | `start.sh` wraps it; compose file has 4 services |
| All 4 see each other as peers within 60s | Each Go node's `config.json` has the other 3 as peers via `NetAddress` + peer config; Rust node has `--peers=go-node-1,go-node-2,go-node-3` |
| Genesis hash matches | Single `goal network create` invocation produces one `genesis.json` distributed via `netroot/NodeN/` subdirs |
| 3 Go + 1 Rust advance to round ≥ 10 within 2 min | Validated by `status.sh` (`make consensus-cluster-status`), which fails if any node lags more than `LAG_TOLERANCE` behind the max; the 3 Go nodes hold 90% of online stake, comfortably above the 74.1% cert threshold |
| `stop.sh` cleans up volumes + networks | `docker compose down -v --remove-orphans`; `--purge` flag wipes netroot/ too |
| Runbook | `ops/mixed-cluster/README.md` |
| Design doc | This file |

The "Rust node proposes at least once every N rounds" criterion from
TASK-87 was out of scope for TASK-86 itself. It is now shipped and
gated: `analyze.py`'s `proposer_share_check` requires the Rust account
to appear in the committed-proposer histogram inside a two-sided
binomial bound and **always** fails on zero. See
`docs/PHASE6_VALIDATION.md` criterion 3.

## Where to go next

| Question | Read |
|---|---|
| What does the harness prove, and which test proves it? | `docs/PHASE6_VALIDATION.md` |
| How do I run it? | `ops/mixed-cluster/README.md`, `make help` |
| How does Layer 9 fit the overall conformance plan? | `docs/CONFORMANCE_STRATEGY.md` §11 |
| What does the soak measure and what are its thresholds? | `docs/SOAK_METHODOLOGY.md` |
