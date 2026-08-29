# algod-rust

[![Conformance Parity](https://github.com/xarmian/algod-rust/actions/workflows/conformance-parity.yml/badge.svg)](https://github.com/xarmian/algod-rust/actions/workflows/conformance-parity.yml)
[![Coverage](https://github.com/xarmian/algod-rust/actions/workflows/coverage.yml/badge.svg)](https://github.com/xarmian/algod-rust/actions/workflows/coverage.yml)
[![codecov](https://codecov.io/gh/xarmian/algod-rust/branch/main/graph/badge.svg)](https://codecov.io/gh/xarmian/algod-rust)

A full Rust reimplementation of [go-algorand](https://github.com/algorand/go-algorand)
— a production-grade Algorand node, developed against `go-algorand v5.0.0-stable`
as the authoritative reference and verified byte-for-byte through a conformance
harness.

## Status

Phases 0–5 are complete: conformance harness, block sync, AVM (TEAL) execution,
ledger apply, transaction/block validation, and the REST API v2. Phase 6
(consensus participation) is in progress. See
[docs/PROJECT_SCOPE.md](docs/PROJECT_SCOPE.md) for the full scope and
[docs/PHASE6_PROPOSAL.md](docs/PHASE6_PROPOSAL.md) for the current phase.

The Rust node votes and proposes blocks alongside go-algorand
v5.0.0-stable nodes in a mixed 4-node cluster
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

## Licensing

algod-rust is a **modified work based on go-algorand**
(https://github.com/algorand/go-algorand), developed file-by-file against
its source as the authoritative reference. As such, algod-rust is
licensed **as a whole** under the **GNU Affero General Public License
v3.0 or later**, preserving go-algorand's own section 7e Additional Terms
(which reserve all rights in the Algorand trademarks to Algorand
Foundation Ltd. — this license grants none) as inherited additional
terms. See [`COPYING`](COPYING) for the full license text.

Individual files that are genuinely original to this project, with no
derivation from go-algorand's AGPL-licensed material, are marked MIT and
are additionally available under the terms in
[`LICENSE-MIT`](LICENSE-MIT) (Copyright (c) 2026 Algod DAO). See
[`docs/LICENSING_AUDIT.md`](docs/LICENSING_AUDIT.md) for the file-level
classification, and [`docs/LICENSING.md`](docs/LICENSING.md) for the full
rationale — why algod-rust is classified this way, the AGPL section 13
network-source obligation, trademark and patent posture, and third-party
attributions (e.g. the poseidon2 AVM opcode, ported from gnark-crypto,
Apache-2.0).
