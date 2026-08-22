# Mixed-Cluster Soak Methodology (PLAN-32 / TASK-87)

## Why

Phase 6 acceptance requires the Rust node to coexist with go-algorand
nodes on a live private network for an extended run without disrupting
consensus. TASK-86 proved the 4-node cluster boots and peers; TASK-87
(this doc) proves it stays healthy for ≥ 200 rounds and captures enough
per-round data for later fork / divergence analysis (TASK-88) and
regression detection.

The soak harness is intentionally thin:

- `scripts/start.sh` / `scripts/stop.sh` — same as TASK-86; unchanged.
- `scripts/soak.sh` — preflight + orchestrate; assumes the cluster is
  already up.
- `scripts/metrics.py` — stdlib-only Python collector that polls each
  Go node's `/v2/status`, fetches `/v2/blocks/{r}` once per new round,
  and writes one JSONL record per event.
- `scripts/analyze.py` — stdlib-only aggregator that prints a summary
  and writes a `.summary.json` sidecar for consumption by CI / future
  fork-detector tooling.

Keeping the collector and analyzer in separate processes lets you
re-analyze an older JSONL run without re-collecting and lets CI post-
process soak output without needing docker.

## What we measure

Per tick (default 500 ms):

- `/v2/status` from each of `go-node-1`, `go-node-2`, `go-node-3`:
  - `last-round` (round each node thinks is committed)
  - `time-since-last-round` (ns since that commit on this node) →
    derived `commit_ts_utc` = `now − time_since_last_round`
  - `catchup-time`
- On any detected round transition at any node, `/v2/blocks/{r}?format=json`
  from the first healthy node:
  - Block timestamp `ts` (on-chain)
  - Proposer (block header `prp` on v40+, falling back to
    `cert.prop.oprop` for older protocols)
  - Genesis hash, previous-block hash
  - `txn_count` — **per-block** transaction count (length of the
    `txns` array, or 0 when the key is omitted from an empty block)
  - `tx_counter` — **cumulative** chain-wide transaction counter
    (the block header's `tc` field). Monotonically non-decreasing
    across rounds. Captured separately because `tc` is chain-wide,
    not per-block — earlier drafts used `tc` as a fallback for
    `txn_count` and that was misleading.

Every 5 s:

- `docker inspect phase6-rust-node-4` → container state
- `docker logs phase6-rust-node-4 --tail 200` → best-effort
  `log_round` scrape (no stable structured round log exists today;
  null is normal)

Since issue #469 the Rust node holds 10% of ONLINE stake and serves the
algod v2 REST API on host port 4004, so it is sampled exactly like a Go
node. It is a fully accepted voter — Go logs `VoteAccepted` for its
votes — but it does not yet appear in the proposer histogram; see
§Known limitations.

## Output format

Each JSONL record is one event. Records have a `kind`:

| kind         | Fields                                                                                          |
|--------------|-------------------------------------------------------------------------------------------------|
| `run_meta`   | `phase` (`start` / `baseline` / `target_reached` / `stalled` / `overall_timeout` / `interrupted` / `end`), timings, baseline round |
| `node_round` | `node`, `round`, `commit_ts_utc`, `time_since_last_round_ms`, `catchup_time_ns`, `back_fill`    |
| `block`      | `round`, `block_ts_unix`, `proposer`, `gen_hash`, `prev_hash`, `txn_count` (per-block), `tx_counter` (cumulative chain-wide), `source_node` |
| `container`  | `node`, `state`, `log_round`                                                                    |
| `warning`    | `msg` (free-form), plus context fields depending on the warning                                 |

All records carry `wall_ts` (ISO 8601 UTC) as the time the collector
emitted the record.

`back_fill=true` means this `node_round` record covers a round the node
jumped over in a single observation (multi-step advance). The collector
only has an accurate `commit_ts_utc` for the latest round in such a
jump; the back-filled rounds have `commit_ts_utc=null` on purpose.

The analyzer reports back-filled rounds as their own count
(`rounds.back_filled_only_count` — rounds we witnessed via back-fill
but never sampled with an authoritative `commit_ts`). They are excluded
from the `commit_spread_ms` distribution because there is no commit
time to diff against. `partial_round_observations` is a separate
tally: rounds where we have a `commit_ts` from exactly one node (so a
single-node run would see every round as "partial", while a back-fill
gives us zero nodes).

## Derived metrics (in analyze.py)

- **Block time (s)** — `block_ts[r] − block_ts[r−1]` over consecutive
  rounds where both have a block record. Reported as mean / p50 / p95 /
  p99 / min / max.
- **Commit spread (ms)** — for each round with observations from ≥ 2
  REST nodes, `max(commit_ts) − min(commit_ts)` across nodes. A proxy
  for round convergence time. Rounds with only one observation are
  counted under `partial_round_observations` and excluded from the
  distribution.
- **Per-node max round** — last observed `last-round` per node.
  `lag_violation` is emitted if `max − min > --lag-tolerance` (default
  5).
- **Proposer histogram** — count per block-header proposer address,
  with the percent of blocks in the soak window.
- **Warning digest** — count grouped by the first `:`-delimited prefix
  of each warning message.

The full summary is written to `<soak>.jsonl.summary.json`.

## Acceptance

A soak run is **clean** if `analyze.py` reports "all criteria satisfied"
(exit 0). That requires:

1. `run_meta.end.phase == "target_reached"`. Any other phase
   (`stalled`, `overall_timeout`, `interrupted`) indicates the cluster
   didn't reach the requested round window.
2. No lag violation (`max − min ≤ --lag-tolerance`, default 5) among
   REST nodes at end-of-run.
3. Zero `warning` records in the JSONL. The collector emits warnings
   on transient fetch failures, parse errors, stalls, and any
   collector-side anomalies, so a clean run should have none.
4. Every captured block has a `block_ts_unix` and a `proposer`.

**Explicitly out of scope for TASK-87** (i.e., NOT part of acceptance):

- **Rust node proposer share.** `Wallet4` is now `Online: true` with
  10% of stake (issue #469) and the Rust node votes with keys Go
  accepts, but it still contributes 0% of proposals — see
  §Known limitations for the block-assembly ordering bug behind that.
  A proposer-share assertion stays out of scope until it is fixed.
- **Fork detection / cert cross-verify.** TASK-88. This harness'
  output feeds it but the detector itself isn't shipped here.
- **Adversarial soak (fuzzer on live cluster).** Future work.
- **CI integration.** Deliberately deferred — a full 200-round soak
  takes 15-20 minutes, too expensive for per-PR CI. A shorter (e.g. 30-
  round) version is a reasonable first CI gate; tracked as a follow-up.

## Running a soak

Prereqs: docker + docker-compose v2, python 3. See the top-level
`ops/mixed-cluster/README.md` for the cluster prerequisites.

```bash
# 1. Bring the cluster up (builds the Rust image on first run).
ops/mixed-cluster/scripts/start.sh

# 2. Wait until status.sh reports healthy (all nodes at round ≥ 1).
ops/mixed-cluster/scripts/status.sh

# 3. Run the soak.
ops/mixed-cluster/scripts/soak.sh --rounds 200

# 4. Analyze (one file at a time — see §Comparing runs for multi-run diffs).
ops/mixed-cluster/scripts/analyze.py ops/mixed-cluster/soak-<ts>.jsonl

# 5. Tear down.
ops/mixed-cluster/scripts/stop.sh
```

The JSONL path defaults to `ops/mixed-cluster/soak-<unix-timestamp>.jsonl`
and is gitignored (contains potentially-noisy per-run data; summaries
should be attached to PR / Pad comments instead).

## Tuning knobs

- `--rounds N` — how many NEW rounds past the current baseline to wait
  for. 200 is the acceptance target; 30-50 is enough for a harness
  smoke test.
- `--interval S` — poll cadence. 0.5 s is enough resolution to detect
  every round transition at ~4.5 s block time and still sample
  `time-since-last-round` usefully. Going below ~0.2 s risks throwing
  off the Go node's request budget; going above ~2 s loses the
  transition timing.
- `--stall-timeout S` — abort if no REST node has advanced in S
  seconds. Default 60 s (≈ 12 × 4.5 s expected block time).
- `--overall-timeout S` — hard wall-clock cap. Default 0 (off); useful
  if the soak is running in a CI-like environment that kills long
  jobs.

## Comparing runs

The `.summary.json` sidecar is designed for diffing across runs.
Suggested workflow for catching regressions:

```bash
# Run a soak, stash the summary as a baseline.
soak.sh --rounds 200 --out soak-baseline.jsonl
analyze.py soak-baseline.jsonl
mv soak-baseline.jsonl.summary.json baselines/soak-v0.X-main.json

# After a consensus-critical change, re-run and diff.
soak.sh --rounds 200 --out soak-candidate.jsonl
analyze.py soak-candidate.jsonl
diff <(jq -S . baselines/soak-v0.X-main.json) \
     <(jq -S . soak-candidate.jsonl.summary.json)
```

A significant delta in `block_time_s.p95`, `commit_spread_ms.p95`, or a
change in proposer distribution beyond noise is worth investigating.

## Known limitations

- **Proposer-share variance.** The Rust node both votes (Go logs
  `VoteAccepted` with `Weight` ~150/1500, matching its 10% stake) and
  proposes blocks Go commits, so all four accounts appear in the
  proposer histogram. Its share is a binomial draw around 10%, so a
  200-round soak still has a standard deviation of ~2 percentage
  points — compare shares against that band, not against exact 10%.
  (Before issue #482 was fixed the share was a hard 0%: the agreement
  main loop ran a batch's `Pseudonode(Assemble N)` before the demux
  thread executed the same batch's `Ensure(block N-1)`, so the pool's
  `assemble_empty_block` fallback failed every round with
  `cannot get prev header for N-1`.)
- **`metrics.py` still samples the Rust node by container state.** Its
  REST endpoint exists now (port 4004) and `status.sh` uses it;
  extending `metrics.py` to do the same is a small follow-up.
- **Single-machine docker.** Network latency and scheduling jitter on
  one host bias the `commit_spread_ms` distribution low relative to a
  geo-distributed production network. Use the numbers as a relative
  baseline, not as absolute SLOs.
- **Single collector process.** If the collector process dies mid-run,
  the JSONL is truncated at the last `flush()`. There's no checkpoint
  / resume. In practice the collector has minimal external deps and
  the `open(..., buffering=1)` line-buffering keeps truncation at a
  record boundary.
- **Proposer extraction** reads `block.prp` first, then
  `cert.prop.oprop` as fallback. Protocols older than v40 that may
  store it elsewhere are not handled — if we ever run this harness on
  `future = vN < v40`, revisit `extract_proposer` in `metrics.py`.

## Verifying a soak (TASK-88)

Post-soak, two tools assert the cluster held together:

- `algo-fork-detector` — polls `/v2/blocks/{r}` across every Go REST
  node, computes each block's digest locally, and fails non-zero on
  any round where the nodes disagree. Shipped as a workspace binary
  under `crates/tools/algo-fork-detector`. Fork detection covers the
  three Go nodes; the Rust node is deferred (see §Verifier scope).
- `algo-cert-crossverify` — loads the `(block, cert)` pair Go produced
  and runs it through `algo_agreement::Certificate::authenticate`
  against a SQLite-backed `AgreementLedgerBridge`. Shipped under
  `crates/tools/algo-cert-crossverify`.

`ops/mixed-cluster/scripts/verify-soak.sh` wraps both tools. As of
TASK-95 cert cross-verify runs by default — the relay maintains the
ledger state it needs — and the script extracts the SQLite via
`docker exec sqlite3 .backup` + `docker cp`.

```bash
# Default: fork detection + Go→Rust cert cross-verify.
scripts/verify-soak.sh --from-round 1 --to-round 200

# Skip cert cross-verify entirely (faster sanity check).
scripts/verify-soak.sh --from-round 1 --to-round 200 --no-cert-crossverify

# Use an externally-prepared SQLite instead of the relay container's.
scripts/verify-soak.sh \
    --from-round 1 --to-round 200 \
    --cert-ledger /path/to/external-full-sync-ledger.sqlite
```

### Verifier scope

The fork detector runs end-to-end against the current TASK-86 harness
— verified on a 30-round live soak with 41 rounds checked, 0 forks,
0 insufficient-coverage warnings, 0 fetch errors.

Cert cross-verify runs by default as of **TASK-95**. The Rust relay
seeds `accountbase` + `accounttotals` from the bind-mounted genesis
on fresh startup and applies each imported block, so its SQLite
ledger (copied out of the container by `verify-soak.sh` at verify
time) is a valid input for `Certificate::authenticate`. Verified
live on a 90-round soak: 11/11 sampled rounds authenticated cleanly.

Rust-produced cert verification (the inverse Rust → Go direction) still
needs the Rust node to actively propose; its keys are online and its
votes are accepted, but block assembly is blocked (see
§Known limitations).

## Follow-ups (out of TASK-87 scope)

- CI gate: short soak (30-50 rounds) on merge-to-main. Needs a
  runner with docker + 3-4 GB RAM headroom.
- Weekly 1000-round regression soak with summary archived under
  `ops/mixed-cluster/baselines/`.
- Extend `metrics.py` to sample `/v2/metrics` (Prometheus) for peer
  counts, memory, and txnpool stats when `EnableDeveloperAPI` is on.
- Fix the agreement/pool round-advance ordering so the Rust node can
  assemble and propose blocks; then re-enable the proposer-share
  acceptance criterion (~10% at the current 30/30/30/10 split).
