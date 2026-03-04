
# ARCHITECTURE.md — Algod-Rust Phase 0 Technical Architecture Diagram & Explanation

## Overview (purpose)
This document describes the technical architecture for **Phase 0** of the `algod-rust` project: a deterministic **Rust follower** that consumes blocks from a Go `algod` localnet, decodes and canonicalizes them, computes digests/txids, and compares results against the Go reference implementation for conformance validation.

Phase 0 scope intentionally excludes P2P and consensus participation. The goal is to provide a durable harness and crate layout that will support incremental replacement of subsystems later (AVM, ledger apply, catchup, networking).

---

## High-level ASCII diagram (components & data flow)

```
                                 +----------------+
                                 |  Developer /   |
                                 |  CI / scripts  |
                                 +-------+--------+
                                         |
                                         | docker-compose / make validate
                                         v
        +--------------------+      +----+-----+      +--------------------+
        |                    |      |          |      |                    |
        |  go-algorand node   |<---->|  Network |<---->|  External peers    |
        |  (algod-go localnet)|      |  (local) |      |  (not in Phase 0)  |
        |  - REST API (4001)  |      +----------+      +--------------------+
        |  - genesis.json     |
        |  - data dir volume  |
        +---------+----------+
                  |
                  | (1) blocks via REST (msgpack preferred)
                  |
         +--------v---------+
         |  algod-rust      |  <-- Phase 0 follower binary (container)
         |  (bin/algod-rust)|
         |  - algo_rest_client (fetch blocks/status)
         |  - algo_codec (decode/encode canonical msgpack)
         |  - algo_types (block/txn structs)
         |  - algo_conformance (diff & reporting)
         +--------+---------+
                  |
    +-------------+-------------------------------+
    |             |                               |
    |             | (2) fixtures / golden vectors  |
    |             v                               v
+---v----+   +---+---+                       +---+---+
| fixtures|   | reports|                       | logs  |
| (./fixtures)| |(reports/) |                 |(stdout)|
+--------+   +-------+                         +-------+
```

Key flows:
1. `algod-rust` fetches raw blocks (prefer msgpack) from `go-algorand` via REST; alternately, reads block files from a mounted data dir if REST msgpack is unavailable.
2. `algod-rust` decodes blocks to `algo_types` via `algo_codec`, re-encodes canonically, computes txn IDs and block-level digests, and compares them with the expected values (from Go or golden helper).
3. Fixtures captured from Go are stored in `./fixtures` to provide deterministic regression tests; conformance reports are written to `reports/` for CI/artifact storage.

---

## Component responsibilities (crates / modules)

### `algo_types`
- Pure data models: block header, block body (payset), transaction minimal fields, accounts (if needed later).
- Purpose: central type definitions used across codec, conformance, and other crates.
- Design: derive `serde` (for debug), but canonical encoding/decoding must be implemented in `algo_codec` to avoid JSON pitfalls.

### `algo_codec`
- Canonical msgpack decoding/encoding for Algorand block and txn formats (Phase 0 subset).
- Provide `decode_block(bytes) -> Block` and `encode_block_canonical(&Block) -> Vec<u8>`.
- Provide txn canonicalization utilities and helpers to compute transaction canonical bytes used for txid hashing.
- Include golden tests exercising encode/decode round-trips against fixtures captured from Go.

### `algo_rest_client`
- Minimal client to `GET /v2/status` and `GET /v2/blocks/{round}`.
- Prefer ability to request raw msgpack blob. If REST can't return msgpack, use file mount of Go node data dir as a fallback.
- Handle token auth and configurable URL + backoff retries.

### `algo_conformance`
- Compare `Block` (Rust) with `Block` (reference) across selected invariants:
  - round number
  - protocol version
  - txn count, txids
  - computed canonical digests (txn ids / block-level digest)
- Produce structured reports: JSON summarizing pass/fail per round, first mismatch details, stack traces for decode errors, and metrics (time per round, bytes processed).
- CLI entrypoints for single-run and continuous follow mode.

### `bin/algod-rust`
- Orchestrates startup, config, connects to REST, follows rounds, captures fixtures, and calls conformance checks.
- Command-line flags: `--algod-url`, `--algod-token-file`, `--start-round`, `--follow`, `--fixtures-dir`, `--report-dir`.
- Modes: `capture`, `validate-once`, and `follow` (continuous).

---

## Data formats & assumptions

- **Preferred**: msgpack block bytes from `GET /v2/blocks/{round}` (the exact Algorand wire format). Msgpack avoids JSON reserialization issues (ordering, base64 encoding).
- **Fallback**: If msgpack cannot be fetched, mount Go node `data/` dir into the Rust container and read raw block files (ensure deterministic access and file format understanding).
- **Golden fixtures**: Keep raw bytes, parsed JSON (for debug), and computed digests recorded alongside metadata (round, timestamp, source go-algorand commit hash).

---

## Canonical encoding & hashing strategy

- Implement canonical msgpack encoding rules matching Algorand's canonicalization expectations for txns and headers. This is critical because txn ID and block digest are defined over canonical bytes.
- Compute txn ID as `sha512_256(canonical_txn_bytes)` (or exact hash Algorand uses) — check exact algorithm version to match Go reference.
- Compute block-level digest using the same algorithm Go uses; if REST does not expose it, include a tiny Go helper (in docker compose) that prints expected digests for a round range; the helper will run `algod` libraries to compute canonical digest for verification.

---

## Conformance harness & CI integration

- `make validate` should:
  1. `docker compose up -d` the go-algorand node and algod-rust
  2. Run `algod-rust capture --rounds 1..N` (optional)
  3. Run `algod-rust validate --start 1 --end N --report reports/conformance.json`
  4. Upload `reports/conformance.json` as artifact in CI or print failure logs
- CI should run this on a smaller round window (e.g., rounds 1..200) and fail fast on mismatch, but should allow recording of failures for investigation (not flaky).

---

## Testing philosophy & golden tests

- Treat the harness as the product. Tests include:
  - Unit tests: encode/decode round-trip for each type
  - Integration: decode a small sample fixture and check structural invariants
  - Golden regression: `encode(decode(bytes)) == canonical(bytes)` for captured fixtures
  - Conformance: run N rounds and assert no mismatches
- Capture fixtures from a specific go-algorand commit and include commit metadata in fixtures to ensure reproducibility.

---

## Observability & debugging aids

- Structured JSON logs for conformance runs with fields: `round`, `op`, `status`, `detail`, `duration_ms`.
- Keep `reports/` with:
  - `conformance-<timestamp>.json` (summary + per-round details)
  - `mismatch-<round>-<timestamp>.json` (full pre/post decode state)
- Provide `algod-rust dump --round N --out debug-N/` to dump canonical bytes, parsed JSON, and computed hashes for manual inspection.
- Expose a `--metrics-port` (Prometheus) with counters: rounds_processed, decode_errors, mismatch_count, avg_round_latency_ms.

---

## Deployment & containerization

- Build two containers in `docker/`:
  - `algod-go` (official go-algorand image or a small wrapper image that runs a localnet init script)
  - `algod-rust` (built from workspace; release binary for CI)
- Compose file should mount `./fixtures` and `./reports` as volumes so CI can read artifacts.
- Keep `algod-rust` single threaded initially; parallelize (rayon/tokio tasks) later once correctness is proven.

---

## Security notes & keys handling

- Never store production keys in fixtures. Phase 0 uses localnet genesis and ephemeral tokens.
- For local testing, allow passing token via file mount (`/run/algod/token`) and read it in `algo_rest_client` securely.
- Keep container networking isolated to avoid accidental exposure.

---

## Failure modes & recovery

- If `algod-rust` detects a mismatch:
  - Log full mismatch file to `reports/`
  - Optionally pause follow mode and wait for investigation (configurable)
- If REST msgpack is unavailable:
  - Fall back to mounted blocks or abort with helpful message
- If decoding fails on unknown field:
  - Log unknown field metadata and continue (or fail-fast based on CLI flag)

---

## Next-phase extension points (Phase 1+)

- Replace REST ingestion with P2P observer mode (decode gossip messages directly)
- Implement `algo-ledger` to apply transactions and compute state roots -> verify full state equivalence
- Integrate `algo-avm` (Rust AVM) into conformance tests with deterministic execution traces
- Add FFI bridge to allow Go->Rust incremental substitution (e.g., call Rust AVM from Go node)

---

## Appendix: Useful CLI prototypes

```
# Capture fixtures
algod-rust capture --algod-url http://algod-go:4001 --start 1 --end 500 --out ./fixtures

# Validate a range and write report
algod-rust validate --algod-url http://algod-go:4001 --start 1 --end 500 --report ./reports/conformance.json

# Follow mode (continuous)
algod-rust follow --algod-url http://algod-go:4001 --metrics-port 9090 --fixtures-dir ./fixtures --report-dir ./reports
```

---

_Last updated: 2026-03-03T04:20:50.173876Z
