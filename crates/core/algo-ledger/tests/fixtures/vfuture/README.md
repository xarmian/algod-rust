# vFuture golden fixtures (issue #548)

Captured from a real `algorand/algod:4.7.0-stable` node running under the
`future` consensus protocol (`docker/docker-compose.vfuture.yml`), with
`MaxTxnBytesPerBlock` shrunk via `docker/config/vfuture-consensus.json`
(see `tools/vfuture-consensus-override/`) so a small burst of payment
transactions could push a block over 50% full -- the threshold at which
`CongestionTax` becomes non-zero the following round.

- Round 45-46: idle rounds, `Load`/`CongestionTax` both zero (baseline).
- Round 47: first round with non-zero `Load` ("ld" = 951660, ~95% full)
  after a 40-transaction flood.
- Round 48: `Load` = 950927 and the first round with non-zero
  `CongestionTax` ("ct" = 90332), predicted exactly by
  `next_congestion_tax(round_47.load, round_47.congestion_tax)`.
- Round 49-50: `CongestionTax` tapering back down as `Load` drops.

Regenerate with: `docker/scripts/capture-vfuture-fixtures.sh`
(see `docs/DEV_WORKFLOW.md` -> "vFuture Fixture Capture").

Consumed by `crates/core/algo-ledger/tests/vfuture_load_fixture.rs`.
