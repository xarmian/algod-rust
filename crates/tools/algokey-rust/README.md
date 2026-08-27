# algokey-rust

A Rust reimplementation of go-algorand's `algokey` CLI, pinned to and
byte-compatible with **`v4.7.2-stable`** of the reference implementation
at `../go-algorand`.

`algokey-rust` is a drop-in for the Go binary: every subcommand
(`generate`, `import`, `export`, `sign`, `multisig`, `multisig
append-auth-addr`, `part generate`, `part info`, `part reparent`,
`part keyreg`) produces wire-byte-identical artifacts to the
corresponding Go invocation, including signed transactions, multisig
preimages, and partkey SQLite databases. Cross-implementation
compatibility is enforced by the bidirectional matrix in
[`tests/e2e/compat_matrix_*_test.rs`](tests/e2e/) (PLAN-183, Phase D).

---

## Building

```bash
cargo build -p algokey-rust --release
```

The compiled binary lands at `target/release/algokey-rust`.

## Running unit tests

Default `cargo test` runs the in-process unit suite — no docker, no
network, no Go binary required:

```bash
cargo test -p algokey-rust
```

## Cross-implementation tests against the Go `algokey` binary

A subset of tests cross-checks Rust outputs against the pinned Go
`algokey` binary. Install it once:

```bash
mkdir -p ~/.local/bin
cd ../go-algorand
go build -o ~/.local/bin/algokey ./cmd/algokey
~/.local/bin/algokey -v
```

Ensure `~/.local/bin` is on your `PATH` (it usually is on Debian-family
distros; on others add `export PATH="$HOME/.local/bin:$PATH"` to your
shell rc).

Then re-run `cargo test`. Tests gracefully skip-with-notice (printing
the install command above) when the Go binary isn't on `PATH`.

## End-to-end tests against a live algod-go localnet

The full Phase D suite drives a live algod-go localnet via docker
compose, signs and submits real transactions, and verifies the
bidirectional Go↔Rust compatibility matrix end-to-end. One command:

```bash
make algokey-e2e
```

This wraps:

1. `make localnet-up` — start `algod-go` in DEV_MODE on `:4001`
2. `cargo test -p algokey-rust --features e2e -- --test-threads=1` —
   runs three test binaries:
   - `e2e_smoke` — localnet bring-up + faucet discovery + self-pay
     confirmation (TASK-184)
   - `e2e_keyreg` — headline keyreg participation flow + offline +
     reparent siblings (TASK-185)
   - `compat_matrix_core` + `compat_matrix_extended` — 23 bidirectional
     Go↔Rust round-trips (TASK-199 + TASK-200), with JUnit XML written
     to `target/algokey-compat-matrix-{core,extended}.xml`
3. `make localnet-down` — always runs, even on test failure, so an
   aborted run doesn't leak containers/volumes

### Prerequisites

- **Docker + docker compose** — used by `localnet-up`
- **Go toolchain** — only needed once, to build the pinned `algokey`
  binary (compat matrix skips with a clear notice if it isn't on
  `PATH`)

### Running individual test binaries

For tighter feedback loops, you can run a single binary:

```bash
make localnet-up
cargo test -p algokey-rust --features e2e --test e2e_smoke
cargo test -p algokey-rust --features e2e --test e2e_keyreg -- --test-threads=1
cargo test -p algokey-rust --features e2e --test compat_matrix_extended -- --test-threads=1
make localnet-down
```

Once the localnet is up, `Localnet::bring_up()` in the harness detects
and reuses it across binaries — re-runs are fast.

## Pinned Go version

The repo references `go-algorand@v4.7.2-stable`. To bump:

1. Update the `../go-algorand` checkout: `cd ../go-algorand && git
   checkout v<new>-stable`
2. Update `GO_ALGORAND_REV` in `.github/workflows/algokey-e2e.yml`
3. Re-run `make algokey-e2e` — the compat matrix will catch any
   wire-byte divergences introduced by the new Go rev
4. Update the version mentions in fixture READMEs

## Refreshing fixtures

Cross-implementation fixture data lives under `tests/fixtures/`.
Regenerate via:

```bash
./scripts/capture-algokey-fixtures.sh
```

## CI

GitHub Actions: [`.github/workflows/algokey-e2e.yml`](../../../.github/workflows/algokey-e2e.yml).

The workflow is path-filtered: it runs only when a PR or push to `main`
touches `crates/tools/algokey-rust/**` or one of the dependencies the
suite actually exercises (`algo-consensus-crypto::{passphrase, multisig,
merklesig}`, `algo-ledger::participation`, `algo-ledger::erasable_db`,
`algo-types::networks`, `algo-rest-client`, the docker-compose file, or
the Makefile). Unrelated commits skip it entirely.

The job uploads the JUnit XML files (`algokey-compat-matrix-core.xml`,
`algokey-compat-matrix-extended.xml`) as a CI artifact named
`algokey-compat-matrix-<sha>`.
