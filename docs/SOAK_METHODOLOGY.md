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

The Rust node has no REST endpoint today and is `Online: false` in the
genesis template, so we cannot — and do not — record it as a proposer
or source of block data. See §Known limitations.

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

- **Rust node proposer share.** The task description originally asked
  for "Rust proposes ≥ ~25% with ε tolerance", but that requires the
  Rust node to run on-network participation keys — which needs
  participation-key format interop with go-algorand's netgoal output.
  That work is tracked under PLAN-35 (Rust consensus participation) and
  is a strict prerequisite for flipping `Wallet4` to `Online: true` in
  `template.json`. Until then the proposer histogram will show only
  go-node-{1,2,3}.
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

- **Rust node not proposing.** See above. Tracked under PLAN-35.
- **Rust node has no REST.** We observe it via `docker inspect` /
  `docker logs`. The log scraping regex is best-effort and may return
  `null` for `log_round`; the state sample is the authoritative
  liveness signal.
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

`ops/mixed-cluster/scripts/verify-soak.sh` wraps both tools:

```bash
# Fork detection only (current default — see §Verifier scope).
scripts/verify-soak.sh --from-round 1 --to-round 200

# Opt in to cert cross-verify against a pre-built full-sync ledger.
scripts/verify-soak.sh \
    --from-round 1 --to-round 200 \
    --with-cert-crossverify /path/to/full-sync-ledger.sqlite
```

### Verifier scope

The fork detector runs end-to-end against the current TASK-86 harness
— verified on a 30-round live soak with 41 rounds checked, 0 forks,
0 insufficient-coverage warnings, 0 fetch errors.

Cert cross-verify ships the binary + library + orchestrator plumbing,
but the current harness runs the Rust node in `relay` mode, which
writes imported blocks with empty `proto` / `hdrdata` and never
updates the participation tracker. The cross-verify binary detects
this and fails fast with a clear pointer to **TASK-95** (follow-up:
enable a full-sync algod-rust ledger in the mixed cluster). Until
then, running cert cross-verify requires a full-sync ledger supplied
externally via `--with-cert-crossverify <path>`.

Rust-produced cert verification (the inverse Rust → Go direction) is
not in this PR's scope at all — it needs the Rust node to be running
online participation keys, which is gated on PLAN-35.

## Follow-ups (out of TASK-87 scope)

- CI gate: short soak (30-50 rounds) on merge-to-main. Needs a
  runner with docker + 3-4 GB RAM headroom.
- Weekly 1000-round regression soak with summary archived under
  `ops/mixed-cluster/baselines/`.
- Extend `metrics.py` to sample `/v2/metrics` (Prometheus) for peer
  counts, memory, and txnpool stats when `EnableDeveloperAPI` is on.
- Rust-node REST server (gated on node wiring work) + participation
  key interop (PLAN-35) → flip `Wallet4` online → acceptance-criterion
  #2 from the original task can then be satisfied.
