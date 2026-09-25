<!-- mainnet-soak:round={round} -->
<!--
Copyright (c) 2026 Algod DAO
SPDX-License-Identifier: MIT
See the LICENSE-MIT file in the repository root for the full license text.
-->
## Root cause / Upstream change

- The nightly mainnet node soak (`.github/workflows/mainnet-node-soak.yml`,
  issue #1598) ran a single `algod-rust participate --network mainnet`
  process against real mainnet, bootstrapped with fast catchup from
  `{peer_url}`, and it **halted during `{phase}`** — no observable progress
  for {stalled_minutes} minutes — while the catchup peer's own `/v2/status`
  proved the network was alive and ahead the whole time.
- Round: **{round}**{catchpoint_line}
- Node `/v2/status` just before the halt: `last-round={node_last_round}`,
  `time-since-last-round={node_time_since_last_round}`
- Peer `/v2/status` just before the halt: `last-round={peer_last_round}`
- Log excerpt around the halt:

```
{log_excerpt}
```

- Run: {run_url}
- Artifacts (node log, status JSONL, `summary.json`): {artifacts_url}

## What algod-rust must do

- Affected crates: whichever of `algo-ledger`/`algo-avm`/`algo-validate`/
  `algo-agreement`/`algo-rest-api` the reproduction below implicates —
  narrow this once the actual failing operation is known.
- Reproduce offline against the pinned reference, without needing to
  re-run a live mainnet soak:

  ```
  cargo run --release --bin algod-rust -- replay --network mainnet \
      --start {repro_start} --end {round} --compare
  ```

  (or, if the halt was mid-catchup rather than a live-follow apply
  failure, re-run catchpoint import for label `{catchpoint_label}` and
  replay forward to round {round} — see `docs/MAINNET_SOAK.md`.)
- Compare against `../go-algorand` at the pin (`v5.0.2-stable`) for the
  same round/block to find the specific behavioral divergence.

## Acceptance criteria

- [ ] TDD: a failing test pinned to round {round} (a fixture-based test if
      the block/state is small enough to commit, otherwise a live
      conformance test against the reference) that reproduces the halt.
- [ ] Parity: fixture/oracle comparison against go-algorand at round
      {round}.
- [ ] `cargo fmt` / `clippy -D warnings` / full workspace suite green.
- [ ] Live verification: the next scheduled mainnet-node-soak run gets
      past round {round} without halting.
