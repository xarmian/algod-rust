# Mixed-Cluster Consensus Harness

A 4-node docker-compose harness that runs 3 go-algorand v4.6.0-stable
nodes + 1 algod-rust node on a private network. **All four nodes hold
online stake and participate in consensus** (issue #469); the Rust node
runs `algod-rust participate`, votes, and serves the algod v2 REST API.
Foundation for (all shipped):

- TASK-87 — 200-round soak test with metrics collection (see "Running a
  soak" below and `docs/SOAK_METHODOLOGY.md`)
- TASK-88 / TASK-95 — fork detector + cert cross-verify (see "Verifying
  a soak")
- Epic 42 (#107) — the full Layer-9 conformance suite: positive (#470),
  restart/rejoin (#471), negative (#472), metrics (#473). Evidence map:
  `docs/PHASE6_VALIDATION.md`.

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

- **go-node-1/2/3**: algorand/algod:4.6.0-stable relays with **30%** of
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

Everything that drives this harness lives under one `consensus-cluster-*`
prefix:

| Target | What it does |
|---|---|
| `consensus-cluster-up` | bring the 4 nodes up (bootstraps `netroot/` on first run) |
| `consensus-cluster-status` | per-node round snapshot; non-zero exit if any node lags |
| `consensus-cluster-down` | tear down (`PURGE=1` also wipes `netroot/`) |
| `consensus-cluster-smoke` | #469 participation smoke test (`SMOKE_ROUNDS`, default 30) |
| `consensus-cluster-test` | #470 positive suite (`ROUNDS`, `RESTART_SCENARIOS`, `NEGATIVE_CASES`) |
| `consensus-cluster-restart` | #471 restart/rejoin scenarios (`RESTART_MODE`) |
| `consensus-cluster-negative` | #472 negative suite (`CASES`, `SKIP_START`, `KEEP_CLUSTER`) |
| `consensus-cluster-analyzer` | unit-test the soak analyzer — no Docker needed |

Deprecated aliases, kept working but printing a notice:
`phase6-cluster-up` / `-status` / `-down` (the TASK-86 names),
`consensus-analyzer-test` → `consensus-cluster-analyzer`, and
`consensus-negative-test` → `consensus-cluster-negative`.

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

## Positive consensus conformance (issue #470, Epic 42c)

`scripts/consensus-conformance.sh` is the one-command acceptance gate
for the Rust node's *own* participation. It runs
cluster-up → (optional) forced period advancement → soak → verify →
cluster-down and writes a machine-readable `summary.json`:

```bash
# 200 rounds, full suite, teardown at the end.
make consensus-cluster-test                 # or ROUNDS=500 make …

# Just the analyzer's unit tests (no Docker).
make consensus-cluster-analyzer

# Through cargo, gated the same way as the #469 smoke test.
MIXED_CLUSTER=1 cargo test -p algo-network --test consensus_conformance \
    -- --ignored --nocapture
```

What it asserts:

| Check | Source |
| --- | --- |
| `proposer_share` | `analyze.py --rust-account` — the Rust account must appear as block proposer, never zero, within a two-sided binomial bound |
| `vote_step_coverage` | `analyze.py --rust-log` — the Rust node cast BOTH `soft` and `cert` votes |
| `period_advancement_recovery` | a Go relay is paused for `PAUSE_SECONDS`, forcing period advancement; the cluster must return to lockstep |
| `fork_free` | `algo-fork-detector` over every round |
| `certs_authenticate_rust` | `algo-cert-crossverify` — Go-produced certs under Rust's verifier |
| `certs_authenticate_go` | `tools/cert-authenticate` — the same certs under go-algorand's own `agreement.Certificate.Authenticate` |
| `go_accepts_rust_votes` | Go's `VoteAccepted` telemetry with the Rust account as `Sender`, broken down per step |
| `no_go_side_rejections` | zero WARN-level agreement rejections in the Go logs |
| `block_cadence`, `node_lockstep` | `analyze.py` block-time and lag bounds |

### The proposer-share bound

Proposer selection over N rounds is Binomial(N, p) with p the account's
share of ONLINE stake (0.10 here). The gate accepts
`|k - Np| <= sigma * sqrt(Np(1-p))` with `sigma = 3` by default, and
**always** fails on `k = 0`.

3 sigma rather than something tighter because the real 200-round run
recorded on issue #482 saw 13/200 (mu = 20, sd = 4.24, z = -1.65) — a
2-sigma gate would have been ~0.35 sigma from failing a healthy run. At
N = 200 the 3-sigma window is k ∈ [7, 32], still nowhere near the
regression it is meant to catch (k = 0, z = -4.71). Override with
`PROPOSER_SIGMA` / `RUST_STAKE_FRACTION`.

### Why Rust votes are not required *inside* certificates

`agreement.makeBundle` (go-algorand `agreement/bundle.go`) stops packing
votes as soon as the running weight reaches the step's quorum, so a
certificate carries only the votes that were needed. With the 30/30/30/10
split the three Go accounts hold ~90% of the cert committee against a
~74% threshold, so the three Go votes alone always suffice and the Rust
node's cert vote — one relay hop later — is dropped from the bundle.
Measured on a healthy participating run: **0 of 301 consecutive
certificates** (checked on all three Go nodes) contained it, while the Go
nodes' own `VoteAccepted` telemetry showed the Rust votes being counted
at the propose, soft and cert steps.

So `MIN_RUST_VOTE_ROUNDS` defaults to `0` (recorded, not gated), and
vote *acceptance* is asserted from the Go side instead. Raise it on a
topology where the Rust stake exceeds ~26% and is therefore required for
quorum.

### The go-algorand-side authenticator

`tools/cert-authenticate` is a small Go program that re-authenticates the
exported certificates with go-algorand v4.6.0-stable's own verifier.
`algo-cert-crossverify --export-go-input` writes it the raw `(block,
cert)` msgpack plus the `agreement.LedgerReader` facts (seed,
circulation, per-voter online account data) read out of the **Rust**
ledger, so a divergence in Rust's view of stake or seed shows up as a
Go-side authentication failure. Go recomputes the block digest itself
and reports a mismatch distinctly.

Building it needs go-algorand's vendored libsodium fork, so
`tools/cert-authenticate/run-in-docker.sh` clones the pinned checkout
inside a `golang:1.25-bookworm` container, runs `make libsodium` there,
and caches both in named Docker volumes (first run ~3-5 min, later runs
seconds). That is also the only supported path on Windows, where the
host checkout's line endings break autotools.

## Restart / rejoin conformance (issue #471, Epic 42d)

`scripts/restart-rejoin.sh` takes the Rust node down **while rounds are
being produced** and asserts it comes back correctly. It does not manage
cluster lifetime — bring the cluster up first, and a failing run leaves
it up for inspection.

```bash
make consensus-cluster-up
cargo build -p algo-fork-detector

# All three scenarios (graceful, SIGKILL, restart-as-proposer):
make consensus-cluster-restart

# One scenario:
RESTART_MODE=kill make consensus-cluster-restart
bash ops/mixed-cluster/scripts/restart-rejoin.sh --mode graceful

# As an opt-in stage of the #470 suite (it will start/stop the cluster):
make consensus-cluster-test RESTART_SCENARIOS=1

# Through cargo, gated like the other cluster tests:
MIXED_CLUSTER=1 cargo test -p algo-network --test consensus_conformance \
    restart -- --ignored --nocapture
```

### Scenarios

| mode | how the node goes down | what it exercises |
| --- | --- | --- |
| `graceful` | `docker restart` (SIGTERM) | clean shutdown + rejoin |
| `kill` | `docker kill -s KILL` | real crash recovery — the node comes back off whatever the async persistence loop had committed to `crash.sqlite` at the instant it died |
| `proposer` | SIGKILL timed into a round the node is proposing in | period advancement around a lost proposer |

The proposer window is driven off the node's own log: the agreement
service emits `assembled N proposal message(s) at (round, period)`
only when sortition handed it a proposer credential, so the script waits
for that line and kills `PROPOSER_KILL_DELAY` seconds later. At the
harness's 10% stake this lands within a handful of rounds without
needing the stake split changed.

### Assertions

Per scenario:

* **rejoin** — back to within `LAG_TOLERANCE` of the Go quorum inside
  `REJOIN_ROUND_BUDGET` Go rounds and `REJOIN_TIMEOUT` seconds.
* **resumed_voting** — at least one attest for a round at/after the
  restart, so a replayed pre-crash checkpoint cannot be mistaken for
  fresh participation.
* **no_stall** — the Go quorum never goes `MAX_STALL_SECONDS` without
  advancing, during or after the outage.
* **no_fork** — `algo-fork-detector` over **all four** nodes across the
  restart window.
* **no_equivocation_rust** — `scripts/equivocation.py` groups every
  `attested to ... at (round, period, step)` line in the container's
  whole log (which spans the restart, since `docker restart`/`docker
  kill` keep the same container) by coordinate and fails if any
  coordinate carries two *different* values. Replaying the same vote is
  fine and expected; a second, different value is a double vote.
* **no_equivocation_go** — go-algorand's own detector:
  `voteTracker: observed an equivocator` / `EquivocatedVote`
  (`agreement/voteTracker.go:134,178`) naming the Rust account.

`equivocation.py` is unit-tested by `equivocation_test.py`, which the
script runs as a **self-test before the scenarios** — a green
"no equivocation" verdict is only meaningful if the detector provably
catches a synthetic double vote, and `attests_scanned > 0` is separately
required so an empty scan can never pass.

## Negative conformance (issue #472, Epic 42e)

The suites above prove a Go quorum **accepts** algod-rust's valid
agreement messages. `scripts/negative-conformance.sh` proves the
converse: go-algorand **rejects** a Rust-constructed agreement message
carrying exactly one injected fault, stays up, and keeps making rounds.

Messages are built by `crates/tools/algo-agreement-fuzz` from the real
`Wallet4.partkey` and real ledger parameters, through the production
encoders in `algo_agreement::codec` and the production crypto in
`algo_consensus_crypto` — so the only thing wrong with an injected
message is the named fault. `algo-agreement-fuzz` then opens a normal
gossip connection to `go-node-1` (its `4161` is published to
`127.0.0.1` for exactly this reason) and sends **one** message.

```bash
# Full suite (brings the cluster up and tears it down).
make consensus-cluster-negative

# One case, against an already-running cluster, keeping it up.
cargo build -p algo-agreement-fuzz
CASES=bad-vrf-proof SKIP_START=1 KEEP_CLUSTER=1 \
    bash ops/mixed-cluster/scripts/negative-conformance.sh

# As an opt-in stage of the #470 suite.
make consensus-cluster-test NEGATIVE_CASES=1

# Through cargo, gated like the other cluster tests.
MIXED_CLUSTER=1 cargo test -p algo-network --test negative_conformance \
    -- --ignored --nocapture

# Build a message without a cluster (unit-tested path, no Docker):
cargo test -p algo-agreement-fuzz
algo-agreement-fuzz --case bad-vrf-proof --dry-run ...
```

### Cases and what go-algorand actually says

| case | injected fault | Go's rejection |
| --- | --- | --- |
| `bad-vrf-proof` | one bit flipped in the 80-byte VRF proof (**1 byte** differs from the honest message) | `malformed vote for (r, 0, 255): unauthenticatedVote.verify: got a vote, but sender was not selected: UnauthenticatedCredential.Verify: could not verify VRF Proof` + `Peer … disconnected: BadData` |
| `wrong-committee-weight` | nothing on the wire — an entirely honest vote for a `(round, 0, propose)` where the account wins **zero** seats (**0 bytes** differ) | `malformed proposal for (r, 0): … UnauthenticatedCredential.Verify: credential has weight 0` + `BadData` |
| `wrong-ots-domain` | the correct one-time key signs the correct body under the `"PL"` domain instead of `"VO"` | `malformed vote for (r, 0, 255): unauthenticatedVote.verify: could not verify FS signature on vote by …` + `BadData` |
| `malformed-proposal` | a genuine `PP` captured off the wire with one block field corrupted | `rejected block for (r, 0): proposalStore: no accepting blockAssembler found on payloadPresent`, and the corrupted block is never committed |

Each vote case is answered with `disconnectAction`
(`agreement/player.go`, `voteMalformed`) → `disconnectBadData`
(`network/wsPeer.go:141`), so the injector's socket closes within a few
milliseconds. A closed socket alone is **not** attribution — an
undecodable payload would also close it — so the script additionally
requires the case-specific error text from `agreement/trace.go`.

### Two findings worth recording

**A claimed committee weight is not representable on the wire.** The
issue asked for "a credential claiming a stake weight inconsistent with
the account's online balance". No such message exists:
`committee.UnauthenticatedCredential` (`data/committee/credential.go`)
carries only the VRF proof (`codec:"pf"`); `Weight` lives on the
*verified* `committee.Credential`, which is never transmitted. The
verifier always recomputes the weight from `sortition.Select`. The
reachable weight rejection is therefore weight-zero, which is what
`wrong-committee-weight` produces — and note its wire bytes are
byte-identical to an honest vote, so the rejection comes purely from the
ledger.

**A single-field payload corruption cannot reach the block validator.**
`unauthenticatedProposal.value()` binds the payload to the proposal-vote
through `EncodingDigest = HashObj(payload)` over the *entire* payload,
so corrupting any one field breaks the binding and the payload is
dropped by `proposalStore` before `ledger` validation is attempted.
Reaching the block validator would additionally require forging the
proposal-vote for the corrupted value, i.e. the original proposer's
one-time key. `malformed-proposal` therefore asserts the property that
is actually observable and actually matters: the corrupted block is
never committed, and the node logs `rejected block for` carrying our
exact payload digest.

### Safety

The injected identity is Wallet4 — the algod-rust node's own account —
but every injected vote is **invalid**, so go-algorand discards it
inside `unauthenticatedVote.verify` before it can reach the vote
tracker, and it can never be recorded as an equivocating vote. The
harness never injects a valid vote. The two non-payload cases use step
`down` (255), which an honest node emits only in fast partition
recovery, so an injection cannot collide with a real vote from the same
account. Only `go-node-1`'s gossip port is reachable from the host.

The `malformed-proposal` case briefly raises `go-node-1`'s
`BaseLoggerDebugLevel` (payload rejections are logged at DEBUG,
`agreement/trace.go:327`) and restarts it, restoring the level
afterwards; the other two Go nodes carry the quorum meanwhile.

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
6. Boot a one-shot `algorand/algod:4.6.0-stable` container against
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

All bindings are on `127.0.0.1` — the harness never listens on a
routable interface, even though the committed API token is the trivial
`aaaa…` value.

| Service       | Host port | Container port | Purpose                                        |
|---------------|-----------|----------------|------------------------------------------------|
| go-node-1     | `4001`    | `8080`         | REST API (token auth)                          |
| go-node-1     | `4161`    | `4161`         | Gossip — published **only** for this node, so the #472 injector can reach exactly one Go peer |
| go-node-2     | `4002`    | `8080`         | REST API                                       |
| go-node-3     | `4003`    | `8080`         | REST API                                       |
| rust-node-4   | `4004`    | `8080`         | REST API — `/v2/status`, `/v2/participation/status`, `/metrics` |

go-node-2/3's gossip ports and the Rust node's outbound-only gossip are
deliberately not published.

Hit the Go nodes with:

```
curl -sf -H "X-Algo-API-Token: $(cat netroot/Node1/algod.token)" \
    http://localhost:4001/v2/status | jq .
```

and the Rust node the same way on `4004`:

```
curl -sf -H "X-Algo-API-Token: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    http://localhost:4004/v2/participation/status | jq .
curl -sf http://localhost:4004/metrics          # Prometheus text, no auth
```

(`algod-rust relay` still has no REST listener; `participate`, which is
what this harness runs, does.)

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

## Scope

Everything TASK-86 originally deferred has since shipped:

| Originally deferred | Status |
|---|---|
| Long soak with a metrics collector (TASK-87) | Shipped — `scripts/soak.sh` + `scripts/metrics.py` + `scripts/analyze.py` |
| Fork detection / cert cross-verify (TASK-88, TASK-95) | Shipped — `algo-fork-detector`, `algo-cert-crossverify`, `tools/cert-authenticate` via `scripts/verify-soak.sh` |
| Rust consensus participation | Shipped — issue #468 (key interop) + #469 (online participant); the Rust node votes and proposes |
| CI integration | Shipped — issue **#488**: `.github/workflows/consensus-cluster.yml` runs Tier 1 (`up` → `status` → `smoke` → `down`) and Tier 2 (`consensus-cluster-test RESTART_SCENARIOS=1 NEGATIVE_CASES=1`) nightly at 02:41 UTC, plus on `workflow_dispatch`. **Never per-PR** — a container build + release build + 200-round soak is far too slow for that, so there is no `pull_request`/`push` trigger and all cluster tests stay `#[ignore]`d behind `MIXED_CLUSTER=1`. Artifacts (`summary.json`, `soak.jsonl`, `analyze.summary.json`, verifier reports) are kept 30 days. See `docs/MIXED_CLUSTER_HARNESS.md` §3. |

## Related docs

| Question | Read |
|---|---|
| What does this harness prove, and which test proves it? | `docs/PHASE6_VALIDATION.md` |
| Why is the topology shaped this way? | `docs/MIXED_CLUSTER_HARNESS.md` |
| How does Layer 9 fit the overall conformance plan? | `docs/CONFORMANCE_STRATEGY.md` §11 |
| What does the soak measure, with what thresholds? | `docs/SOAK_METHODOLOGY.md` |
| All the make targets | `make help` |

Note that `docker/docker-compose.mixed-cluster.yml` is a *different*
harness serving a different purpose — gossip / catchup interop testing
(`make mixed-cluster-*`), not consensus agreement.
