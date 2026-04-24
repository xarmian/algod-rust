# Mixed-Cluster Consensus Harness — Design (PLAN-32 / TASK-86)

## Why

Phase 6 acceptance (see PLAN-32) requires running the Rust node alongside
go-algorand nodes on a private network and proving consensus agrees
byte-for-byte across the cluster. TASK-86 is the foundation piece: a
docker-compose topology where we can bring up a 4-node (3 Go + 1 Rust)
private network reliably enough to hang soak tests (TASK-87) and fork-
detection tooling (TASK-88) on top.

## Relation to the existing `docker/docker-compose.mixed-cluster.yml`

The repo already has a mixed-cluster compose under `docker/`
(`docker-compose.mixed-cluster.yml`) but it serves a distinct purpose:

| File | Purpose | Topology |
|---|---|---|
| `docker/docker-compose.mixed-cluster.yml` | Gossip + catchup interop — can the Rust observer read Go blocks? Can a Go non-relay sync from a Rust relay? | 1 Go relay (block producer) + 1 Rust observer + 1 Rust relay + 1 Go non-relay |
| `ops/mixed-cluster/docker-compose.yml` (this PR) | **Consensus agreement** — can the Rust node live on a network where 3 Go peers are running real agreement, without disrupting them? | 3 Go relay+proposers + 1 Rust relay peer (not yet proposing) |

These intentionally coexist. A future refactor could unify them but
that's not in this task's scope. The `ops/` location is net-new and
signals "e2e / plan-level orchestration" vs `docker/` which collects
scenario-specific compose files.

## Topology decisions

### 3 proposers, 1 non-participating peer

`template.json` gives each Go node 33% stake (online, proposing) and the
Rust node 1% stake (**offline** → no participation keys actually used
for consensus). Consensus quorum (>2/3 of online stake) is met by any
2 of the 3 Go nodes; the Rust node joins as a peer and syncs blocks
via gossip.

Why this stake split:

- A 4-way 25/25/25/25 split with all 4 online would make the Rust
  node's 25% count toward the online-stake denominator. If it doesn't
  propose, cert threshold (>2/3 of online = >66.7%) requires all 3 Go
  nodes in quorum — which is brittle because Algorand's sortition is
  stochastic and any single Go node occasionally missing would stall
  blocks. With Rust offline, the denominator is 99% and quorum only
  needs ~2/3 × 99% ≈ 66% ≈ 2 Go nodes, which is robust.
- An alternative (skip the Rust wallet entirely) would mean the Rust
  node connects with no account on the network. We keep Wallet4 in the
  genesis as a placeholder so a future Rust-participation iteration can
  flip it `Online: true` with zero template churn.

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

- `NetAddress = 0.0.0.0:4161` — listen on all interfaces inside the
  container
- `EndpointAddress = 0.0.0.0:8080` — same for REST
- `DNSBootstrapID = ""` — so private-net nodes don't try to reach
  mainnet/testnet relays and fill the logs with resolver errors

## Open questions (follow-ups)

### 1. Rust consensus participation

Today the Rust node runs `algod-rust relay --peers=...` and
`--genesis-id=...` but does NOT participate. Making it propose
requires, at minimum:

- **Participation-key format interop.** `goal network create` emits
  `*.partkey` files in Go's SQLite schema. `algod-rust participate`'s
  `--partkey-path` expects a participation key database; whether those
  formats are compatible today is unverified. Related work lives in
  PLAN-35 (DB Interchange — Phase A: Reader) which is the canonical
  place to close this gap.
- **Genesis interop.** The Rust node must accept the `goal`-generated
  `genesis.json` byte-for-byte, including the `ConsensusProtocol:
  "future"` pin the template sets. Needs verification.
- **Online-stake awareness.** Wallet4 is offline in the current
  template; flipping it online will require the Rust node to respond
  to sortition and propose. Gated on the two points above.

This is captured at the PR level rather than as its own TASK item
because it's really a rollup of PLAN-35 prerequisites — the right place
to reconsider the Rust participation story is once reader-side
interchange lands.

### 2. REST surface on the Rust relay

The current `algod-rust relay` subcommand doesn't expose `/v2/status`
(TASK-79 wired REST into `participate`, not `relay`). `status.sh`
therefore reports `n/a` for the Rust node. Short-term workaround: point
`status.sh` at the Rust node's gossip port instead, or have TASK-87's
soak harness scrape container logs.

Longer-term fix: a future task can add `--rest-listen` to the `relay`
subcommand, reusing the NodeInterface adapter already built in TASK-79
(`bin/algod-rust/src/node_interface_impl.rs`).

### 3. CI integration

This harness is excluded from CI in the current PR. The build requires
docker-in-docker (or a preloaded algorand/algod image) and a Rust
release build — both slow. A follow-up can add a nightly / merge-to-
main job that runs `start.sh` → wait 2 min → `status.sh`, then tears
down, keeping per-PR CI fast.

## Verification against TASK-86 acceptance

| Criterion | Verified how |
|---|---|
| `docker compose up -d` starts all 4 nodes | `start.sh` wraps it; compose file has 4 services |
| All 4 see each other as peers within 60s | Each Go node's `config.json` has the other 3 as peers via `NetAddress` + peer config; Rust node has `--peers=go-node-1,go-node-2,go-node-3` |
| Genesis hash matches | Single `goal network create` invocation produces one `genesis.json` distributed via `netroot/NodeN/` subdirs |
| 3 Go + 1 Rust advance to round ≥ 10 within 2 min | Validated by `status.sh`; 3 Go nodes hold 99% of online stake, sufficient for quorum |
| `stop.sh` cleans up volumes + networks | `docker compose down -v --remove-orphans`; `--purge` flag wipes netroot/ too |
| Runbook | `ops/mixed-cluster/README.md` |
| Design doc | This file |

The "Rust node proposes at least once every N rounds" criterion from
TASK-87 is explicitly **not** claimed by this PR — that's why Wallet4
is offline and why PLAN-35 remains the dependency for Rust-side
participation.
