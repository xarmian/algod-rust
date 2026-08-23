---
name: algod-traffic-debug
description: Capture, decode, and diff agreement/gossip wire traffic between go-algorand and algod-rust nodes in the mixed clusters — use when debugging why one side drops, misclassifies, or never sees the other side's votes, proposals, or bundles.
---

# Debugging go-algorand ↔ algod-rust gossip traffic

Repeatable method used to root-cause issue #497 (recovery bundles verified
then silently dropped). Works against `ops/mixed-cluster/` (4 nodes) and
`ops/mixed-cluster-3rust/` (6 nodes, 50/50 stake).

## 1. Capture — the Rust node is the best tap point

Every gossip message a Rust node receives (Go-originated bytes, verbatim) or
sends (Rust-originated bytes) can be dumped as hex without tcpdump/WS-frame
reassembly. `algo-network` has permanent trace points:

- **inbound**: `HandlerMux::handle` (`crates/node/algo-network/src/handler.rs`)
  logs `dir="recv" tag=<T> peer=<addr> len=<n> hex=<payload>`
- **outbound**: `WsNetwork::broadcast_inner` (`crates/node/algo-network/src/ws_network.rs`)
  logs `dir="send" tag=<T> len=<n> hex=<payload>`

Enable them on the cluster's Rust nodes (env override, no rebuild needed):

```bash
cd ops/mixed-cluster-3rust
source netroot/.phase7-env && export PHASE7_GENESIS_ID PHASE7_GENESIS_HASH
PHASE7_RUST_LOG="info,algo_agreement=debug,algo_network::wire=trace" \
  docker compose up -d --force-recreate rust-node-4 rust-node-5 rust-node-6
docker logs phase7-rust-node-4 2>&1 | grep "wire message" > wire4.log
```

`algo_agreement=debug` additionally surfaces the *disposition* of each
message: `message_ignored` (with the voteAggregator/player filter reason,
e.g. "filtered premature vote", "failed to cause a significant state
change") and `message_disconnect` / `vote_verify_failed` (verification
errors, with sender/round/period/step).

Caveat: `--force-recreate` restarts the node mid-round; recreate the whole
cluster (`scripts/stop.sh --purge && scripts/start.sh`) when you need to
observe round 1 / period 0 from the beginning — individual gossip votes are
fire-once, and a restarted node has permanently missed them.

## 2. The Go side — structured agreement telemetry

go-algorand's nodes in these clusters already log every agreement event as
JSON. The most useful `Type` values (grep `docker logs phase7-go-node-1`):

- `VoteAccepted` — per-vote: `Sender`, `Weight`, `WeightTotal` (running tally),
  `ObjectRound/ObjectPeriod/ObjectStep` (the vote's coordinates)
- `ThresholdReached` — `Weight` vs `WeightTotal` (threshold)
- `StepTimeout` — from `logTimeout` (`msg` carries the deadline value and
  the player's current (r, p, s))
- `RoundConcluded`, `PeriodConcluded`

Timeline extractor (round 1):

```bash
docker logs phase7-go-node-1 2>&1 | python3 -c "
import sys, json
for line in sys.stdin:
    try: d = json.loads(line)
    except: continue
    if d.get('Type') in ('VoteAccepted','ThresholdReached','StepTimeout') and d.get('Round')==1:
        print(d['Type'], '(r,p,s)=', d.get('ObjectRound'), d.get('ObjectPeriod'), d.get('ObjectStep'),
              'sender', (d.get('Sender') or '')[:8], 'w', d.get('Weight'), d.get('WeightTotal'), d.get('time','')[11:19])
"
```

This is how you prove "Go counted the Rust votes and reached the threshold
at (1,0,3)" independently of anything the Rust side claims.

## 3. Decode the hex payloads (canonical msgpack)

All tags carry canonical msgpack (sorted keys, omitempty). `pip install
msgpack` and decode; a ready-made pretty-printer that parses the wire-trace
log lines and labels origin (RUST-origin for `send`, GO-origin for `recv`
from a `go-node-*` peer):

```bash
python3 decode_wire.py wire4.log AV   # or VB / PP / TX
```

(script: strip ANSI, regex `dir=… tag=… peer=… hex=…`, `msgpack.unpackb`,
print keys with `bin<N>:<base32-prefix>` for byte fields — see issue #497's
PR discussion for the full listing.)

### Wire structures per tag (Go reference files)

- **AV** — agreement vote (`agreement/vote.go` `unauthenticatedVote`):
  `{r: rawVote, cred: {pf: bin80}, sig: OneTimeSignature}`.
  `rawVote` = `{snd: bin32, rnd: uint, per: uint, step: uint, prop: proposalValue}`.
  `proposalValue` = `{oper: uint, oprop: bin32, dig: bin32, encdig: bin32}`.
  **omitempty is semantic**: a *bottom* next-vote omits `prop` entirely;
  period 0 omits `per`; step propose (0) omits `step`. A 3-account
  soft-vote is ~624 bytes; a bottom next-vote ~499 bytes.
  `sig` keys: `s`, `p`, `p2`, `p1s`, `p2s`, `ps` (old-style field, all-zero).
- **VB** — vote bundle (`agreement/bundle.go` `unauthenticatedBundle`):
  `{rnd, per, step, prop, vote: [voteAuthenticator...], eqv: [...]}` where
  `voteAuthenticator` = `{snd, cred, sig}` (round/period/step/proposal are
  hoisted to the envelope — receivers reconstruct each rawVote from it).
  A bottom bundle omits `prop` and `per` just like votes.
- **PP** — proposal payload (`agreement/proposal.go` `transmittedPayload`):
  block fields + `sdpf` (seed proof), `oper`, `oprop`, plus the pinned
  proposal-vote under `pv` in compound messages.
- Tag list: `protocol/tags.go` (`AV`, `PP`, `VB`, `TX`, `MI`, `NP`, ...).

## 4. Diff Go-origin vs Rust-origin

For each tag, compare messages of the same kind field-by-field:

- **presence**: every key present on one side and absent on the other is a
  finding (beware legitimate omitempty differences that encode *values* —
  compare like-for-like, e.g. bottom vote vs bottom vote).
- **sizes**: same-kind messages should have near-identical lengths (both
  sides' soft votes were 624 bytes in #497 — encoding parity held, which
  is what redirected the investigation inward to message *handling*).
- **coordinates**: `rnd/per/step` tell you whether the two sides are even
  in the same period/step. In #497 the freshness rule (`voteStepFresh`:
  steps ≤ next always relayed, otherwise only mine±1) plus a start-time
  offset meant neither side could see the other's escalating next-votes —
  which is exactly the situation bundle relay + fast recovery must fix.

## 5. Where messages die inside algod-rust (checklist)

When bytes provably arrive (wire trace) but nothing happens, follow the
pipeline; each stage has a distinct log signature at `algo_agreement=debug`:

1. decode (`demux.rs handle_raw_vote`) — "error decoding vote message"
2. freshness filter (`types.rs vote_fresh`) — `message_ignored` with
   "filtered stale/premature vote …"
3. crypto verify (`crypto_verifier.rs`) — `vote_verify_failed` warn with
   the exact ledger/sig/cred error
4. tracker replay — for bundles, "bundle … failed to cause a significant
   state change" means the votes never made it into the voteTracker
   (#497's root cause: `verify_bundle_impl` dropped the authenticated
   votes; the aggregator replays `message.verified_bundle_votes`)
5. threshold → player — `handle_threshold_event` / `enter_period` (player
   logs "timeout fired" with its current (r, p, s) — if period never
   advances while Go's does, stage 4 or 5 ate the threshold)

## 6. Gotchas that cost real time

- A Rust node **restarted against an already-seeded, zero-block ledger**
  loses its in-memory genesis `protocol` and fails every membership lookup
  with `unknown consensus version: ""` (it also disconnects the sending
  peer each time). Recreate the cluster instead of the node.
- `docker logs` timestamps are UTC; the tracing lines and Go's `time`
  field are directly comparable.
- Go re-broadcasts only the *freshest bundle* + pinned payload during
  partition recovery (`player.partitionPolicy`), and fast-recovery votes
  (`late`/`redo`/`down`, steps 253-255) every `FastRecoveryLambda`.
  Ordinary next-votes are sent once — capture early or you will never see
  them.
