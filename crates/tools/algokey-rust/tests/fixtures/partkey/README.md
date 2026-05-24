# Phase C partkey fixtures

Captures from `go-algorand` pinned to `v4.5.1-stable` (the
`build-phase-b-fixtures.go` script in `../../scripts/` documents the
exact tag). Used by `tests/part_info_parity.rs` and
`tests/phase_c_cross_impl.rs` to enforce byte-equal output between the
Rust port and Go's `algokey`.

## Files

| Fixture | Inputs | Size |
|---|---|---|
| `small_with_sp.db` | `--first 1 --last 512 --dilution 100 --parent 7777…JUVU` | ~32 KB |
| `part_info_outputs/small_with_sp.stdout` | `algokey part info --keyfile small_with_sp.db` | ~450 B |

The medium fixture (`--first 1 --last 100000`, ~400 KB) is not yet
captured — it's gated for the feature-on slow path; add it under
`medium_with_sp.db` when the slow-test feature lands.

## Regenerating

```bash
# Build the Go binary at the pinned tag.
cd ../go-algorand && git checkout v4.5.1-stable
go build -o /tmp/algokey-go ./cmd/algokey

# Drive the capture script.
ALGOKEY=/tmp/algokey-go bash scripts/capture-algokey-fixtures.sh
```

The script regenerates every fixture deterministically. Diffs in the
captured `.stdout` files indicate either a real Go-side change (bump the
pin) or a bug in the writer/info pipeline (fix Rust).

## Notes

- Falcon-1024 keygen is non-deterministic (system RNG), so the binary
  `*.db` files differ on each capture; only the structural fields
  inspected by `part info` are stable. The byte-equal parity test in
  `tests/part_info_parity.rs` asserts the `.stdout` matches because
  that's the surface users see. Cross-impl tests in
  `tests/phase_c_cross_impl.rs` regenerate fresh DBs via either
  binary and assert structural-field round-trips, since byte-equal DB
  files would require an HMAC-DRBG seeded keygen path on both sides
  (deferred — see notes in `algo-consensus-crypto/tests/ots_generate_test.rs`).
