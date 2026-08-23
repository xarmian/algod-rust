# 3 Go + 3 Rust Mixed-Cluster Harness (Phase 7, issue #496)

A 6-node docker-compose harness — sibling of [`../mixed-cluster/`](../mixed-cluster/README.md)
— that runs 3 go-algorand v4.6.0-stable nodes + 3 algod-rust nodes on a
private network with a **50/50** online-stake split. It exists to answer
the one question `../mixed-cluster/`'s 30/30/30/10 topology structurally
cannot: **do Rust votes ever appear *inside* a Go-produced, Go-verified
certificate?**

## Why a sibling directory, not a bigger `../mixed-cluster/`

`../mixed-cluster/` backs a **nightly CI job**
(`.github/workflows/consensus-cluster.yml`) that deliberately keeps Rust
stake at 10% so a Rust bug can never halt the chain — see its README's
"Current status" section. Retuning that harness's stake split in place
would either break the nightly low-stake invariant it exists to prove,
or require a topology-switching flag threaded through every one of its
nine scripts (`start.sh`, `stop.sh`, `status.sh`, `soak.sh`,
`verify-soak.sh`, `metrics.py`, `analyze.py`, `consensus-conformance.sh`,
`restart-rejoin.sh`, `negative-conformance.sh`, `participation-smoke.sh`)
— each of which hard-codes node counts, container names, and host
ports. A parameterized single harness was evaluated and rejected as
higher-risk: it would touch every file the nightly job depends on to
serve a topology that only needs a fraction of that surface (this
issue's acceptance criteria need `start.sh`/`stop.sh`/`status.sh`,
`soak.sh` + `metrics.py`, and `verify-soak.sh` — not the restart/negative/
proposer-share suites, which assume the low-stake "Rust can't halt the
chain" invariant that no longer holds at 50/50 by design).

This directory therefore **duplicates and specializes** exactly those
five files (`start.sh`, `stop.sh`, `status.sh`, `metrics.py`,
`verify-soak.sh`) plus `soak.sh` (copied unmodified — it is already
generic, delegating to the local `status.sh`/`metrics.py`) for a
six-node, 50/50 topology, with distinct container names (`phase7-*`),
docker network (`phase7net`) and host ports (`4101-4106` REST,
`4261` gossip) so both harnesses can run **concurrently** without
collision. `docs/PHASE6_VALIDATION.md`'s Phase 7 addendum and this
README record the measured evidence; the reusable verification
binaries (`algo-fork-detector`, `algo-cert-crossverify`,
`tools/cert-authenticate`) are unchanged and shared as-is — they were
already generic over node lists and ledger paths.

Not ported here (out of scope for issue #496, which only requires the
cert-membership evidence): `consensus-conformance.sh`'s proposer-share /
forced-period-advancement checks, `restart-rejoin.sh`, `negative-
conformance.sh`, `participation-smoke.sh`, `analyze.py`'s full report.
Those assume exactly one Rust node and a stake fraction low enough that
`k = 0` proposals is meaningful evidence of a regression — neither
holds at 50/50 across three Rust nodes. Porting them is a reasonable
follow-up if this topology becomes a second permanent nightly job (see
"Follow-ups" below) but is not needed to answer this issue's question.

## Topology

```
┌────────────┐   gossip   ┌────────────┐
│ go-node-1  │◀──────────▶│ go-node-2  │
│ ~16.7% stk │            │ ~16.7% stk │
└─────┬──────┘            └──────┬─────┘
      │                          │
      │         ┌────────────┐   │
      └────────▶│ go-node-3  │◀──┘
                │ ~16.7% stk │
                └──────┬─────┘
        ┌──────────────┼──────────────┐
        ▼               ▼              ▼
┌──────────────┐┌──────────────┐┌──────────────┐
│ rust-node-4  ││ rust-node-5  ││ rust-node-6  │
│ ~16.7% stk   ││ ~16.7% stk   ││ ~16.7% stk   │
└──────────────┘└──────────────┘└──────────────┘
```

`template.json` allocates Wallet1-3 (Go) 17/17/16 units and Wallet4-6
(Rust) 17/17/16 units — Go = 50, Rust = 50 out of 100 total, all six
wallets ONLINE. Each Rust node dials all three Go relays over gossip
(mirroring `../mixed-cluster/`'s participation topology) and serves its
own algod v2 REST API.

### Why 50/50 makes Rust votes quorum-necessary

`agreement.makeBundle` (`../../go-algorand/agreement/bundle.go` @
v4.6.0-stable) stops packing votes into a certificate the instant
running weight clears the step's quorum. For the `future` consensus
protocol this harness uses (`../../go-algorand/config/consensus.go`),
`CertCommitteeSize = 1500` and the quorum threshold is `1112` (74.1%).

- At `../mixed-cluster/`'s 30/30/30/10 split, the three Go accounts
  alone hold an expected 1350 of 1500 cert-committee votes — ~13 sigma
  clear of 1112 — so `makeBundle` never needs a Rust vote to reach
  quorum, and empirically never included one across 301 sampled
  certificates (see that harness's README).
- At this harness's 50/50 split, the three Go accounts hold an expected
  **750** of 1500 votes — well *short* of 1112. `makeBundle` cannot
  finish a certificate from the Go side alone; it must keep packing
  votes (Go or Rust) until quorum is reached, so a Rust vote becomes
  **quorum-necessary** and is expected to appear inside real
  certificates as a matter of course, not as a rare tail event.

## Prerequisites

Same as `../mixed-cluster/`: Docker + Docker Compose v2, Python 3, and
the repo root as the build context (`docker/Dockerfile`). If
`algod-rust-phase6:local` has already been built by `../mixed-cluster/`,
this harness's `algod-rust-phase7:local` build reuses Docker's layer
cache (same Dockerfile/context) even though the tag differs.

## Usage

```bash
# bring up the cluster (generates netroot/ on first run)
ops/mixed-cluster-3rust/scripts/start.sh

# peek at each node's round
ops/mixed-cluster-3rust/scripts/status.sh

# soak N rounds (default 200; ~10-15 min at ~3-4.5s block time)
ops/mixed-cluster-3rust/scripts/soak.sh --rounds 200

# verify: fork-free + Rust votes present in Go-produced/Go-verified
# certificates, BOTH directions. --rust-account is one of the three
# Rust wallets (any one demonstrates quorum-necessity; see "Evidence"
# below for why one account is sufficient here).
cargo build -p algo-fork-detector -p algo-cert-crossverify
ops/mixed-cluster-3rust/scripts/verify-soak.sh \
    --from-round 1 --to-round 200 \
    --rust-account <Wallet4's address> \
    --min-rust-vote-rounds 5

# tear down (keeps netroot/ so restarts reuse keys + genesis)
ops/mixed-cluster-3rust/scripts/stop.sh
ops/mixed-cluster-3rust/scripts/stop.sh --purge   # also wipes netroot/
```

Host ports: go-node-1/2/3 on `4101-4103`, rust-node-4/5/6 on
`4104-4106`, go-node-1's gossip listener published on `4261`.
Container names: `phase7-go-node-{1,2,3}`, `phase7-rust-node-{4,5,6}`.

### `--rust-account` and the single-address gate

`algo-cert-crossverify --rust-account ADDR` checks for **one** address's
vote per sampled certificate (see `crates/tools/algo-cert-crossverify`).
With three Rust wallets online here, any one of them appearing inside a
certificate is sufficient to demonstrate quorum-necessity — the harness
does not need to prove all three appear in the same certificate (they
often will, since `makeBundle` packs votes as they arrive in whatever
order the network delivers them, and 750 Go votes leaves 362+ needed
from a committee where Rust holds an expected 750 seats). Point
`--rust-account` at whichever Rust wallet's address `start.sh` reports,
or loop the verifier once per Rust account for stronger coverage.

## Evidence (issue #496 acceptance criteria)

**Closed.** A live soak past round 230 on an otherwise-idle host
measured: 220 consecutive rounds fork-free (`algo-fork-detector`:
`forks=0 insufficient=0 fetch_errors=0`), zero Go-side agreement
rejections, and both cert-verification directions passing — 16 sampled
certificates all authenticate under both implementations, 12 of which
carry a Rust participant's vote (`algo-cert-crossverify` Go→Rust,
`tools/cert-authenticate` against a real go-algorand v4.6.0-stable
build Rust→Go). See `docs/PHASE6_VALIDATION.md`'s Phase 7 addendum for
the full writeup, exact commands, and root-cause notes on this
topology's round-time characteristics.

Note on `soak.sh --stall-timeout`: at 50/50 stake, roughly every other
round needs one or more `next`-vote recovery escalations before
committing (typically resolving within 60-90s — see the addendum for
why this is expected, not a liveness bug). `soak.sh`'s default here is
180s (raised from the parent 10%-stake harness's 60s specifically for
this reason); lower it only if you've confirmed your run doesn't hit
this pattern.

## Follow-ups

- Port `restart-rejoin.sh` / `negative-conformance.sh` /
  `participation-smoke.sh` / full `analyze.py` reporting to this
  topology if it becomes a second permanent nightly job.
- `algo-cert-crossverify` only accepts a single `--rust-account`; a
  natural follow-up is to accept a repeated flag / comma-separated list
  so a single invocation can assert coverage across all three Rust
  wallets at once instead of one address per run.
- No negative-conformance gossip injector is wired up here (only
  go-node-1's gossip port is published, matching `../mixed-cluster/`'s
  layout, but `algo-agreement-fuzz` was not pointed at it).
