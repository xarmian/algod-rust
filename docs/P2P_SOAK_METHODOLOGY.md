# P2P Mixed-Cluster Soak Methodology (issue #594)

## Why

This is the P2P-transport sibling of `docs/SOAK_METHODOLOGY.md`
(PLAN-32 / TASK-87). Issue #591 (PR #593) fixed the P2P block/cert
catch-up fetch path and, with it, `ops/mixed-cluster-p2p/scripts/
consensus-round-trip.sh` live-verified the 4-node P2P cluster (3
go-algorand v4.7.0-stable nodes in plain P2P mode + 1 `algod-rust
participate --enable-p2p` stake-holding node) sustaining 30+ rounds in
lockstep with zero agreement rejections — the same proof
`participation-smoke.sh` gives the WS-gossip harness, but purely over
the libp2p transport (`/algorand-ws/2.2.0` raw stream + gossipsub, no
WS-gossip listener at all).

`consensus-round-trip.sh` is a single pass/fail gate over a short
(30-round) window, not a soak. This doc + the scripts it describes add
that: a >= 200-round run with the same per-round JSONL metrics shape
and `.summary.json` sidecar convention as the WS-gossip harness, so the
two are diffable and CI-consumable the same way.

**Read `docs/SOAK_METHODOLOGY.md` first** — this doc only calls out
what's different for the P2P harness. Everything not mentioned here
(record `kind`s, derived metrics, acceptance definitions, comparing
runs across baselines) is identical.

## What's different from the WS-gossip harness

| | WS-gossip (`ops/mixed-cluster/`) | P2P (`ops/mixed-cluster-p2p/`) |
| --- | --- | --- |
| Transport | WS-gossip (`ws://.../v1/{genesisID}/gossip`) | libp2p: gossipsub (TX tag only) + raw `/algorand-ws/2.2.0` stream (AV/PP/VB) |
| Container names | `phase6-go-node-{1,2,3}`, `phase6-rust-node-4` | `p2pinterop-go-node-{1,2,3}`, `p2pinterop-rust-node-4` |
| Host REST ports | 4001-4004 | 5001-5004 |
| Go node topology | all three relays fully peered | chain-bootstrapped 1 <- 2 <- 3 (go-node-3 never told go-node-1's address directly — see `ops/mixed-cluster-p2p/README.md`) |
| Rust node mode | WS-gossip `participate` | `participate --enable-p2p` (`P2pOnly`, no WS listener at all) |
| Stake split | 30/30/30/10 (`ops/mixed-cluster/template.json`) | 30/30/30/10 (`ops/mixed-cluster-p2p/template.json`) — same |
| Scripts | `scripts/{soak,metrics,analyze}.py` | `scripts/{soak,metrics}.py` (new) reusing `ops/mixed-cluster/scripts/analyze.py` directly (see below) |
| CI workflow | `.github/workflows/consensus-cluster.yml` (nightly `41 2 * * *`) | `.github/workflows/p2p-consensus-soak.yml` (nightly `50 3 * * *`, after `p2p-interop.yml`'s `5 3` and `consensus-cluster.yml`'s `41 2`) |

### `metrics.py`: rust-node-4 is a first-class REST node here

The WS-gossip `metrics.py` still samples `phase6-rust-node-4` only by
container state + best-effort log-round scrape (see that script's
module docstring and `docs/SOAK_METHODOLOGY.md`'s "Known limitations":
*"metrics.py still samples the Rust node by container state ...
extending metrics.py to do the same is a small follow-up"*) — a
historical gap from before the Rust node exposed REST at all.

The P2P harness's `rust-node-4` has served a real algod v2 REST API on
host port 5004 since issue #589 (`ops/mixed-cluster-p2p/scripts/
status.sh` and `consensus-round-trip.sh` both already poll it exactly
like a Go node), so `ops/mixed-cluster-p2p/scripts/metrics.py` includes
it directly in `NODES_REST` rather than repeating the WS-gossip
limitation. The container-state sample and `/v2/participation/status`
polling are kept too, as additional liveness/participation evidence —
this is a superset of the WS-gossip record shape, not a different one,
so `analyze.py` (below) needs no changes to consume it.

### `analyze.py` is reused unchanged — no fresh TDD pass

Issue #594's own TDD instruction: write `analyze.py`'s regression-
detection logic with a synthetic-JSONL unit test *before* wiring it
into a live workflow, unless reusing already-tested code, in which case
say why a fresh pass isn't needed.

`ops/mixed-cluster/scripts/analyze.py`'s logic operates purely on the
JSONL record shape (`kind`, `node`, `round`, timestamps, proposer
addresses, etc.) — it has no cluster-specific assumptions baked in
(the only occurrences of a WS-gossip container name in the whole file
are a `--help` string and one cosmetic print label, both of which are
harmless when run against a P2P soak file since the record `node`
values it actually reads are `"go-node-1"`/`"rust-node-4"` etc., not
container names). Its unit tests (`ops/mixed-cluster/scripts/
analyze_test.py`, run by `make consensus-cluster-analyzer`) already
cover the threshold logic with synthetic fixtures, including the
negative cases. `ops/mixed-cluster-p2p/scripts/consensus-soak.sh` (the
orchestrator described below) self-tests it (same pattern
`consensus-conformance.sh` uses) before trusting its verdict, and calls
it directly at `ops/mixed-cluster/scripts/analyze.py` rather than
duplicating 1000+ lines of already-tested logic into this directory.
`ops/mixed-cluster-p2p/scripts/metrics.py`, in contrast, IS new code —
but it is a data-collection script wired to live Docker/REST state
(container names, ports), not new threshold/regression-detection logic,
which is exactly the class of change the WS-gossip harness's own
`metrics.py` has never had a dedicated unit test for either (compare
`ops/mixed-cluster/scripts/`: only `analyze_test.py` and
`equivocation_test.py` exist there). It was verified live end-to-end
against a real 4-node P2P cluster before this issue was considered
done (see the PR description for the run's summary numbers).

## Not yet covered

Issue #596 wired three of the four WS-gossip-only Tier 2 verifiers to
this harness (all opt-in, off by default, same as
`consensus-conformance.sh`'s own gating):

- ~~**Fork detection** (`algo-fork-detector`) or **bidirectional cert
  cross-verify** (`algo-cert-crossverify` + `tools/cert-authenticate`).
  Neither tool is wired to this harness's container names/ports/SQLite
  extraction path yet.~~ Done (#596) — `VERIFY_STAGE=1` (see
  `ops/mixed-cluster-p2p/scripts/verify-soak.sh`, `make
  p2p-interop-verify`). Both tools operate on exported ledger/block
  facts over REST + SQLite, not on the gossip/P2P wire format, so
  nothing about them was WS-gossip-specific — porting was
  container-name/port plumbing only.
- ~~**Restart/rejoin scenarios** (issue #471's analogue).~~ Done (#596)
  — `RESTART_SCENARIOS=1` (see
  `ops/mixed-cluster-p2p/scripts/restart-rejoin.sh`, `make
  p2p-interop-restart`). Same reasoning: the restart/rejoin mechanics
  (docker kill/restart, REST round polling, `algo-agreement`'s own log
  lines) are transport-agnostic.
- ~~**Negative conformance** (issue #472's analogue — malformed-message
  injection) is **still open**. The existing injector,
  `crates/tools/algo-agreement-fuzz`, speaks go-algorand's WS-gossip
  handshake/framing (`algo_network::connect` + `algo_network::framing`)
  — this harness's Go nodes run `EnableP2P=true` with no WS-gossip
  listener at all, and AV/PP/VB agreement traffic travels over a raw
  `/algorand-ws/2.2.0` libp2p stream instead (issue #560). Building a
  P2P-speaking injector is genuine new engineering (a libp2p client
  capable of dialing, negotiating `/algorand-ws/2.2.0`, and sending one
  malformed message), not a porting exercise, so #596 left it out and
  filed it as #597.~~ Done (#597) — `NEGATIVE_CASES=1` (see
  `ops/mixed-cluster-p2p/scripts/negative-conformance.sh`). `algo-agreement-fuzz`
  gained a second connection backend
  (`crates/tools/algo-agreement-fuzz/src/inject_p2p.rs`, `--transport p2p`)
  that dials a peer, negotiates `/algorand-ws/2.2.0` via
  `algo_p2p::{P2pHost, wsproto}`, and sends one tagged frame on the raw
  stream — reusing the exact same fault-construction logic
  (`build_vote`/`corrupt_proposal`/`baseline_and_faulted`) the WS-gossip
  injector already had; only the transport layer is new. One deliberate
  deviation from the WS-gossip script: it does not raise go-node-1's
  `BaseLoggerDebugLevel` and restart it for the `malformed-proposal`
  case, since a restart here would churn the node's ephemeral libp2p
  PeerId (`P2PPersistPeerID` defaults to false) and fragment the
  bootstrap-chained 3-node mesh — the `not-adopted` assertion (the
  corrupted block is never committed) remains the decisive check for
  that case regardless.

What IS covered by the base soak (`p2p-interop-soak-test` with no extra
flags): proposer-share assertion, vote-step coverage (soft + cert),
block cadence bounds, node lockstep, zero Go-side agreement rejections,
and Go's own `VoteAccepted` telemetry for the Rust account — the same
five categories `docs/SOAK_METHODOLOGY.md`'s "Acceptance" section
defines for the base soak (rounds reached, no lag violation, zero
warnings, every block has ts+proposer), plus the opt-in issue #470-style
participation assertions. `VERIFY_STAGE=1 RESTART_SCENARIOS=1
NEGATIVE_CASES=1` add issue #596's fork-freedom, bidirectional cert
authentication, and restart/rejoin coverage, plus issue #597's
negative-conformance coverage, on top of that.

## Running a soak

Prereqs: docker + docker-compose v2, python 3. See
`ops/mixed-cluster-p2p/README.md` for the cluster prerequisites.

```bash
# 1. Bring the cluster up (builds the Rust image on first run).
ops/mixed-cluster-p2p/scripts/start.sh

# 2. Wait until status.sh reports healthy (all nodes at round >= 1).
ops/mixed-cluster-p2p/scripts/status.sh

# 3. Run the soak.
ops/mixed-cluster-p2p/scripts/soak.sh --rounds 200

# 4. Analyze (the SHARED WS-gossip analyzer — see "analyze.py is
#    reused unchanged" above for why).
ops/mixed-cluster/scripts/analyze.py ops/mixed-cluster-p2p/soak-<ts>.jsonl \
  --rust-account <ADDR> --rust-log <path to a `docker logs
  p2pinterop-rust-node-4` capture>

# 5. Tear down.
ops/mixed-cluster-p2p/scripts/stop.sh
```

Or the one-shot orchestrator (up -> soak -> analyze -> down, writing a
`summary.json`):

```bash
make p2p-interop-soak-test ROUNDS=200
```

The JSONL path defaults to
`ops/mixed-cluster-p2p/soak-<unix-timestamp>.jsonl` and, like the
WS-gossip harness's own soak output, is gitignored.

## CI

`.github/workflows/p2p-consensus-soak.yml` mirrors
`consensus-cluster.yml`'s `schedule` + `workflow_dispatch`-only trigger
(no `pull_request`/`push` — a 200+-round soak plus cluster boot is tens
of minutes, far too expensive per PR) and its two-tier structure:

- **Tier 1** (always): `p2p-interop-up` -> `p2p-interop-status`
  (lockstep gate, retried like `consensus-cluster.yml`'s own) ->
  `p2p-interop-consensus-test` (issue #589's 30-round smoke) ->
  `p2p-interop-down`.
- **Tier 2** (nightly / dispatch with `tier=full`):
  `p2p-interop-soak-test ROUNDS=<input, default 200> VERIFY_STAGE=1
  RESTART_SCENARIOS=1`, uploading `summary.json`, `soak.jsonl`,
  `analyze.summary.json`, `verify.log` + `verify-go-report-*.json` (the
  go-algorand cert verifier), the cert-crossverify JSONL, the
  `restart/` sub-summary, and the per-node container logs as a workflow
  artifact.

Scheduled for `50 3 * * *` UTC — after `consensus-cluster.yml`'s
`41 2` and `p2p-interop.yml`'s `5 3`, so the three nightly Docker-heavy
jobs don't contend for the same runner.
