# Mixed-Cluster Consensus Harness

A 4-node docker-compose harness that runs 3 go-algorand v4.5.1-stable
nodes + 1 algod-rust node on a private network. **All four nodes hold
online stake and participate in consensus** (issue #469); the Rust node
runs `algod-rust participate`, votes, and serves the algod v2 REST API.
Foundation for:

- TASK-87 — 200-round soak test with metrics collection (shipped — see
  "Running a soak" below and `docs/SOAK_METHODOLOGY.md`)
- TASK-88 — fork detector / cert cross-verify (needs the same harness)

## Topology

```
┌────────────┐   gossip   ┌────────────┐
│ go-node-1  │◀──────────▶│ go-node-2  │
│ relay+prop │            │ relay+prop │
└─────┬──────┘            └──────┬─────┘
      │                          │
      │                          │
      │         ┌────────────┐   │
      └────────▶│ go-node-3  │◀──┘
                │ relay+prop │
                └──────┬─────┘
                       │
                       ▼
                ┌──────────────────┐
                │   rust-node-4    │
                │ participate+vote │
                └──────────────────┘
```

- **go-node-1/2/3**: algorand/algod:4.5.1-stable relays with **30%** of
  online stake each, all online, all proposing.
- **rust-node-4**: a built-from-source `algod-rust participate` node
  holding **10%** of online stake, dialing the 3 Go relays over gossip.
  It imports the `.partkey` that `goal network create` generated for
  Wallet4 straight out of `netroot/Node4Rust/<genesis-id>/` via
  `--partkey-dir` (issue #468's go-algorand key auto-discovery — no
  conversion step), seeds accountbase + accounttotals from the
  bind-mounted `netroot/genesis.json`, and serves the algod v2 REST API
  on host port **4004** so `status.sh` reads its round the same way it
  reads a Go node's.

### Stake split and sortition math

`template.json` allocates 30/30/30/10, all four wallets ONLINE.

- **Proposal** (ConsensusFuture, `NumProposers = 20`): the Rust node's
  expected proposer-committee size is `20 * 0.10 = 2`, so it holds at
  least one proposer credential in ~86% of rounds, and — because the
  round is won by the lowest credential among all selected proposers —
  it is expected to win **~10% of rounds**.
- **Certification** (`CertCommitteeSize = 1500`, threshold `1112` =
  74.1%): the three Go nodes hold 90% of stake, an expected 1350 of
  1500 cert votes and ~13 sigma clear of the threshold, so they certify
  rounds with or without the Rust node. A Rust bug therefore cannot
  halt the chain, and the Rust node's expected 150 votes are far below
  quorum on their own.

### Current status: votes and proposals both accepted

Go **accepts the Rust node's votes**: `go-node-1`'s agreement log shows
`VoteAccepted` entries whose `Sender` is the Rust node's account, with
`Weight` around 150 of 1500 — exactly its 10% share. Over a 30+ round
run the Go nodes log **zero** agreement-level rejections
(`malformed proposal|malformed vote|rejected block|bundle malformed`).

Go also **commits the Rust node's proposals**: the proposer histogram
over a 200-round soak puts the Rust account at roughly its 10% stake
share, alongside the three Go accounts at ~30% each.

Until issue #482 was fixed, that share was **0%**. The agreement main
loop executed a batch's `Pseudonode(Assemble N)` action *before* handing
the same batch — which begins with `Ensure(block N-1)` — to the demux
thread that performs it, so `TransactionPool::assemble_block` always ran
against a ledger two rounds behind and fell through to
`assemble_empty_block`, which failed with

```
cannot get prev header for N-1: ledger error: no block header data for round N-1
```

every round. The main loop now blocks on the demux thread's
acknowledgement that the batch has been executed before running that
batch's pseudonode actions, matching Go's in-order `Service.do(actions)`.
`PHASE6_RUST_LOG=info,algo_agreement=debug` still surfaces
`block assembly failed; not proposing this round`, but now only with
`error=requested round N for AssembleBlock is stale` during catchup,
which is normal operation.

## Prerequisites

- Docker + Docker Compose v2.
- Python 3 (used by `status.sh` and `participation-smoke.sh`).
- The repo root as the build context — the Rust node uses
  `docker/Dockerfile` from the repo root to compile `algod-rust` from
  source. First start takes several minutes; subsequent starts reuse
  the cached image.

## Usage

```bash
# bring up the cluster (generates netroot/ on first run)
ops/mixed-cluster/scripts/start.sh

# peek at each node's round
ops/mixed-cluster/scripts/status.sh

# tear down (keeps netroot/ so restarts reuse keys + genesis)
ops/mixed-cluster/scripts/stop.sh

# tear down and wipe keys (fresh network next start)
ops/mixed-cluster/scripts/stop.sh --purge

# same three, through the canonical make targets
make consensus-cluster-up
make consensus-cluster-status
make consensus-cluster-down          # append PURGE=1 to wipe netroot/
```

`phase6-cluster-up` / `-status` / `-down` remain as deprecated aliases.

## Participation smoke test (issue #469)

`participation-smoke.sh` brings the cluster up, waits for it to advance
`SMOKE_ROUNDS` (default 30) rounds, and asserts that all four nodes stay
in lockstep, that the Rust node's own REST `/v2/status` progresses, and
that no Go node logged an agreement-level rejection. It also reports how
many Rust votes Go accepted and how many blocks the Rust node proposed
(expected ≈10% of the rounds observed — see "Current status" above;
over a 30-round window the sortition variance is wide, so the count is
reported rather than asserted).

```bash
make consensus-cluster-smoke                       # 30 rounds, tears down after
SMOKE_ROUNDS=100 KEEP_CLUSTER=1     bash ops/mixed-cluster/scripts/participation-smoke.sh

# ...or through cargo, gated so it stays out of `cargo test --workspace`
MIXED_CLUSTER=1 cargo test -p algo-network     --test mixed_cluster_participation -- --ignored --nocapture
```

After ~30s the 3 Go nodes should be at round ≥ 3. After 2 minutes
all 3 should be at round ≥ 10 (assuming the default 4.5s block time
under the `future` consensus protocol baked into the template).

## Running a soak (TASK-87)

The soak harness layers on top of the cluster. It assumes `start.sh`
has already brought everything up and tears nothing down.

```bash
# Long acceptance soak (~10-15 minutes at ~3s block time).
ops/mixed-cluster/scripts/soak.sh --rounds 200

# Analyze a specific soak output. Pass exactly one file; merging
# records across runs silently confuses the lag + block-time checks.
ops/mixed-cluster/scripts/analyze.py ops/mixed-cluster/soak-<unix>.jsonl
```

Output goes to `ops/mixed-cluster/soak-<unix>.jsonl` by default (gitignored).
`analyze.py` prints a human report and writes a `<file>.summary.json`
sidecar.

See `docs/SOAK_METHODOLOGY.md` for the full set of tuning knobs,
measured metrics, acceptance criteria, and known limitations.

## Verifying a soak (TASK-88 + TASK-95)

After a soak, run the verifier to assert no forks occurred across the
Go REST nodes AND that the Go-produced certificates authenticate under
algod-rust's `Certificate::authenticate`:

```bash
# Build the tools once.
cargo build -p algo-fork-detector -p algo-cert-crossverify

# Fork detection + Go→Rust cert cross-verify.
ops/mixed-cluster/scripts/verify-soak.sh --from-round 1 --to-round 200
```

TASK-95 made cert cross-verify the default: the Rust relay now seeds
accountbase + accounttotals from genesis and applies each imported
block, so its `/app/ledger.sqlite` is a valid verifier input. The
wrapper `docker cp`s it out for the run and cleans up on exit.

Options:
- `--no-cert-crossverify` — skip cert verification (faster sanity
  check; fork detection still runs).
- `--cert-ledger PATH` — use an externally-prepared SQLite instead of
  the relay container's. Must be caught up past `--to-round`.
- `--stride N` — sample every N'th round for cert verification
  (fork detection always covers every round). Default 20.

The verifier writes `verify-fork-<ts>.jsonl` and `verify-cert-<ts>.jsonl`
next to the soak output (both gitignored). The underlying binaries
`algo-fork-detector` and `algo-cert-crossverify` are standalone and
scriptable outside the shell wrapper.

## Phase B writer-side acceptance (TASK-127)

The `handoff-rust-to-go.sh` script is PLAN-36's end-to-end acceptance
gate: it proves that go-algorand can boot against a tracker DB + block
DB produced exclusively by `algod-rust` and continue reading the last
Rust-written round.

```bash
# Run the full handoff (default: 20 rounds).
bash ops/mixed-cluster/scripts/handoff-rust-to-go.sh

# Longer handoff:
HANDOFF_ROUNDS=50 bash ops/mixed-cluster/scripts/handoff-rust-to-go.sh

# Keep the temp dir on success (for inspection):
KEEP_HANDOFF=1 bash ops/mixed-cluster/scripts/handoff-rust-to-go.sh

# Don't re-bootstrap the Go cluster (assume it's already up):
SKIP_CLUSTER_START=1 bash ops/mixed-cluster/scripts/handoff-rust-to-go.sh
```

What it does, in order:

1. Bring up the 3 Go nodes via `start.sh` (idempotent — reuses `netroot/`).
2. Wait until the Go cluster has produced at least `HANDOFF_ROUNDS`
   blocks.
3. Build `algod-rust` and run `algod-rust sync` against go-node-1,
   writing `<HANDOFF_DIR>/node.tracker.sqlite` and
   `<HANDOFF_DIR>/node.block.sqlite`.
4. Verify no Rust-only tables leaked into the produced tracker DB
   (`state_deltas`, `merkle_trie`, `catchpoint_import_state`,
   `algod_rust_meta` must all be absent).
5. Stage those files into a Go-shaped data dir at
   `<HANDOFF_DIR>/godata/<genesisID>/ledger.{tracker,block}.sqlite`
   alongside a minimal `config.json` + `genesis.json` + `algod.token`.
6. Boot a one-shot `algorand/algod:4.5.1-stable` container against
   that data dir on host port 7833.
7. Assert `/v2/status` responds, `last-round >= HANDOFF_ROUNDS`, and
   Go's startup logs contain no ERROR/FATAL lines.
8. Fetch `/v2/blocks/N` from the resumed Go node and confirm it
   serves the block.

On PASS the temp dir is cleaned automatically (override with
`KEEP_HANDOFF=1`). On FAIL the temp dir is preserved so the produced
SQLite files + Go container logs can be inspected.

The Rust integration test
`crates/node/algo-network/tests/rust_writer_go_resume.rs` wraps this
script for `cargo test`:

```bash
MIXED_CLUSTER=1 cargo test -p algo-network --test rust_writer_go_resume \
    -- --ignored --nocapture
```

It's `#[ignore]`'d and gated on `MIXED_CLUSTER=1` so it stays out of
the default workspace test path — handoffs take 3-5 minutes and
require Docker.

### Known scope

Go runs in single-node mode against the imported DB, so it does NOT
propose block `N+1` on its own. The acceptance gate is that Go can
mount, read, and serve the Rust-written rounds without schema errors
— **not** that Go produces fresh blocks atop them. Bidirectional
handoff (Go advances atop Rust-written state, Rust verifies, etc.)
is Phase C / PLAN-37 territory.

## Host ports

| Service       | Host port | Container port | Purpose                |
|---------------|-----------|----------------|------------------------|
| go-node-1     | `4001`    | `8080`         | REST API (token auth)  |
| go-node-2     | `4002`    | `8080`         | REST API               |
| go-node-3     | `4003`    | `8080`         | REST API               |
| rust-node-4   | `4160`    | `4160`         | Gossip (no REST today) |

Hit the Go nodes with:

```
curl -sf -H "X-Algo-API-Token: $(cat netroot/Node1/algod.token)" \
    http://localhost:4001/v2/status | jq .
```

The Rust node's `relay` subcommand does not yet expose REST — see the
design doc for the follow-up. `status.sh` reports `n/a` for it.

## What's in `netroot/`

`scripts/start.sh` runs `goal network create` on first invocation,
producing:

```
netroot/
├── network.json
├── genesis.json
├── Node1/
│   ├── config.json           (rewritten by start.sh — see below)
│   ├── genesis.json
│   ├── algod.token
│   └── <wallet>.partkey
├── Node2/
├── Node3/
└── Node4Rust/
```

`start.sh` then calls `algocfg` inside the Go image to overlay each
node's `config.json` with:

- `NetAddress = 0.0.0.0:4161`
- `EndpointAddress = 0.0.0.0:8080`
- `DNSBootstrapID = ""` (so private-net nodes don't reach public DNS)

The `netroot/` tree is `.gitignore`d — it contains private participation
keys and should never be committed.

## Platform notes

Validated on Linux with native Docker. macOS and Windows should work in
principle but some gotchas you may hit:

- **macOS (Docker Desktop, VirtioFS / gRPC-FUSE):** bind mounts like
  `./netroot/Node1:/algod/data` go through a filesystem shim. The
  uid-1001 ownership that `goal network create` writes survives the
  round trip, so `stop.sh --purge`'s in-container `rm` is still the
  correct path. The host-side fallback in `stop.sh` silently handles
  the less-common case where `rm -rf` from the host user succeeds.
- **Windows / WSL2:** native Linux rules apply inside the WSL2 distro.
  Running `scripts/start.sh` from a PowerShell shell through a Docker
  Desktop backed by WSL2 should work the same as Linux; scripts assume
  POSIX tools (`bash`, `python3`, `curl`, `mktemp`).
- **Colima / non-Docker-Desktop:** untested but should work as long as
  the runtime supports `docker compose` and bind mounts. Report back if
  you hit issues.

If you're on a platform where the in-container cleanup path can't reach
the algorand/algod image (offline, rate-limited, etc.), `stop.sh
--purge` falls back to a host-side `rm -rf` best-effort — you may see
a "root-owned files still present" warning and need to `sudo rm -rf
netroot/` manually.

## Troubleshooting

- **`docker compose up` fails with "missing netroot/Node1"**: run
  `scripts/start.sh` (not `docker compose up` directly) — it bootstraps
  the tree before invoking compose.
- **Nodes never advance past round 0**: verify each Node's `config.json`
  has `NetAddress = 0.0.0.0:4161` (not `127.0.0.1:<port>` from the
  goal-generated default). `start.sh` does this rewrite; if you poked
  at netroot/ manually, re-run `stop.sh --purge && start.sh`.
- **Rust node doesn't connect to Go nodes**: check the Rust container's
  logs with `docker logs phase6-rust-node-4`. Common cause: the
  `--genesis-id` passed in the compose file doesn't match what
  `goal network create` actually produced. `start.sh` captures the ID
  into `netroot/.phase6-genesis-id` AND exports it as the
  `PHASE6_GENESIS_ID` environment variable; `docker-compose.yml`
  interpolates that via `${PHASE6_GENESIS_ID:-phase6net-v1}` so custom
  templates / renamed networks pick up the right value automatically.
  If you invoke `docker compose up` directly (bypassing `start.sh`),
  export the id first: `PHASE6_GENESIS_ID="$(cat ops/mixed-cluster/netroot/.phase6-genesis-id)" docker compose -f ops/mixed-cluster/docker-compose.yml up`.
- **"address already in use" on host port**: another service is bound
  to 4001/4002/4003/4160. Edit the compose file's `ports:` section to
  remap.

## Scope (TASK-86)

This PR delivers the harness plus local-run scripts. It explicitly does
NOT:

- Run a long soak — TASK-87 builds on this with a metrics collector.
- Detect forks or cross-verify certificates — TASK-88.
- Exercise Rust consensus participation — gated on participation-key
  interop with Go's netgoal output (see the follow-up in the design
  doc).
- Integrate into CI — left as a follow-up so CI doesn't take a
  container-build hit on every PR.

## Design doc

See `docs/MIXED_CLUSTER_HARNESS.md` for the rationale behind the
topology choices, the open questions on Rust-side participation, and the
relationship to the existing `docker/docker-compose.mixed-cluster.yml`
harness (which serves a different purpose — gossip / catchup interop
testing, not consensus agreement).
