# algod-rust

[![Conformance Parity](https://github.com/xarmian/algod-rust/actions/workflows/conformance-parity.yml/badge.svg)](https://github.com/xarmian/algod-rust/actions/workflows/conformance-parity.yml)
[![Coverage](https://github.com/xarmian/algod-rust/actions/workflows/coverage.yml/badge.svg)](https://github.com/xarmian/algod-rust/actions/workflows/coverage.yml)
[![codecov](https://codecov.io/gh/xarmian/algod-rust/branch/main/graph/badge.svg)](https://codecov.io/gh/xarmian/algod-rust)

A full Rust reimplementation of [go-algorand](https://github.com/algorand/go-algorand)
— a production-grade Algorand node, developed against `go-algorand v4.7.0-stable`
as the authoritative reference and verified byte-for-byte through a conformance
harness.

## Status

Phases 0–5 are complete: conformance harness, block sync, AVM (TEAL) execution,
ledger apply, transaction/block validation, and the REST API v2. Phase 6
(consensus participation) is in progress. See
[docs/PROJECT_SCOPE.md](docs/PROJECT_SCOPE.md) for the full scope and
[docs/PHASE6_PROPOSAL.md](docs/PHASE6_PROPOSAL.md) for the current phase.

The Rust node votes and proposes blocks alongside go-algorand
v4.7.0-stable nodes in a mixed 4-node cluster
(`make consensus-cluster-test`);
[docs/PHASE6_VALIDATION.md](docs/PHASE6_VALIDATION.md) maps each Phase 6
success criterion to the test or tool that verifies it.

## Quick start

```bash
cargo build --workspace
cargo test --workspace
make help          # localnet, fixtures, conformance, replay, benchmarks
```

## Documentation

- [docs/CRATE_ARCHITECTURE.md](docs/CRATE_ARCHITECTURE.md) — workspace crate design
- [docs/DEV_WORKFLOW.md](docs/DEV_WORKFLOW.md) — fixture generation, localnet, testing
- [docs/CONFORMANCE_STRATEGY.md](docs/CONFORMANCE_STRATEGY.md) — parity verification vs go-algorand
- [docs/COVERAGE.md](docs/COVERAGE.md) — test coverage reporting, thresholds, best practices
