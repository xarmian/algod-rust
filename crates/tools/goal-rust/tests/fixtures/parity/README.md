# Parity fixtures

Byte-exact snapshots of `goal`'s stdout for the subcommands that
`goal-rust` ships in Phase A (PLAN-152). Used by the harness in
`tests/parity_fixtures.rs` to keep our output diff-clean against
go-algorand `v4.5.1-stable`.

## Files

| Fixture | Subcommand | Go source |
|---|---|---|
| `node_status_synced.txt` | `node status` (steady, no catchpoint, no upgrade) | `cmd/goal/node.go:455-462` + `messages.go:64` |
| `node_status_catchpoint.txt` | `node status` (catchpoint catchup) | `node.go:498-516` + `messages.go:68-70` |
| `node_status_upgrade_voting.txt` | `node status` (consensus upgrade voting) | `node.go:479-494` + `messages.go:65` |
| `node_lastround.txt` | `node lastround` | `node.go:519-534` |
| `wallet_new_created.txt` | `wallet new <name>` happy path | `wallet.go:144-149` + `messages.go:172-173` |
| `wallet_list_empty.txt` | `wallet list` with no wallets | `wallet.go:261-281` + `messages.go:178` |
| `wallet_rename_ok.txt` | `wallet rename foo bar` happy path | `wallet.go:275` + `messages.go:179` |

`node generatetoken` is intentionally NOT in this set: its output
contains a non-deterministic 64-hex-char token. The parity invariant
for that subcommand is structural (prefix + 64 hex chars) and lives
in `tests/node_status_e2e.rs`.

`node start|stop|restart` are Phase-A advisory stubs (TASK-225) and
have no Go-output equivalent worth pinning.

## Refresh workflow

Fixtures here are hand-derived from Go's `messages.go` format
strings — every constant is also embedded byte-exactly in
`src/cmd/*.rs`, so renaming or rewording on the Go side is caught
both at the per-leaf assertion and the harness level.

**These fixtures may only be refreshed from a Go binary.** The
Rust assertion helper deliberately has no "rewrite from
`actual`" escape hatch — that would let a Rust regression bake
itself in as the new expected without ever comparing against Go.

To refresh from an actual `goal` binary (e.g. after a go-algorand
version bump):

```bash
MIXED_CLUSTER=1 ./crates/tools/goal-rust/tools/capture-goal-fixtures.sh
```

The script is currently a scaffold — the algod+kmd state-fixture
rig for the catchpoint / upgrade-voting branches lives outside
Phase A. Until that lands, refresh by editing the `.txt` files by
hand against the Go source line references in the table above, and
inspect the diff carefully before committing.
