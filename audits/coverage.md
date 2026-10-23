# Algod-Rust — Audit Coverage Ledger

**Purpose:** one row per audit area defined in `audits/instructions.md` §3. Every audit run (human or AI, any vendor) updates the rows it covered, so the next auditor can pick the areas that are stale, never audited, or changed since their last audit (`instructions.md` §5). Rows you did not audit are never touched.

**Depth legend:** `—` never audited · `skim` read-through only · `deep` line-by-line M1/M2 against go-algorand · `poc` deep plus at least one PoC, new vector, or harness run.

**Reference pin:** `go-algorand v5.0.4-stable`.

## Tier 1 — consensus-critical and cryptographic core

| Id | Area | Crate(s) | Last audited (UTC) | Commit | Auditor tag | Methodologies | Depth | Report |
|---|---|---|---|---|---|---|---|---|
| A-00 | Delta review of `crates/core/**` since previous report | all | — | — | — | — | — | — |
| A-01 | Canonical msgpack | `algo-codec` | — | — | — | — | — | — |
| A-02 | Protocol primitives, hashing, consensus tables | `algo-types` | — | — | — | — | — | — |
| A-03 | Stateless validation | `algo-validate` | — | — | — | — | — | — |
| A-04 | Ledger apply & block evaluation | `algo-ledger` | — | — | — | — | — | — |
| A-05 | Block assembly & proposal | `algo-ledger`, `algo-pool`, `algo-agreement` | — | — | — | — | — | — |
| A-06 | AVM core: parser, flow, stack, budgets | `algo-avm` | — | — | — | — | — | — |
| A-07 | AVM state, resources, boxes, inner txns | `algo-avm`, `algo-ledger` | — | — | — | — | — | — |
| A-08 | AVM arithmetic & bytes | `algo-avm` | — | — | — | — | — | — |
| A-09 | AVM cryptographic opcodes | `algo-avm`, `algo-consensus-crypto`, `algo-falcon` | — | — | — | — | — | — |
| A-10 | ARC-4 ABI | `algo-abi` | — | — | — | — | — | — |
| A-11 | Agreement `BA*` | `algo-agreement` | — | — | — | — | — | — |
| A-12 | Sortition, VRF, participation keys, state proofs | `algo-consensus-crypto` | — | — | — | — | — | — |
| A-13 | Falcon-1024 `det1024` (`DIV-001`) | `algo-falcon` | — | — | — | — | — | — |

## Tier 2 — network, mempool, runtime services, storage

| Id | Area | Crate(s) | Last audited (UTC) | Commit | Auditor tag | Methodologies | Depth | Report |
|---|---|---|---|---|---|---|---|---|
| A-14 | Transaction pool & ingestion | `algo-pool`, `algo-txn-pipeline` | — | — | — | — | — | — |
| A-15 | WebSocket gossip | `algo-network` | — | — | — | — | — | — |
| A-16 | libp2p transport | `algo-p2p` | — | — | — | — | — | — |
| A-17 | Catchup & catchpoints | `algo-ledger`, `algo-rest-client`, `algo-network` | — | — | — | — | — | — |
| A-18 | REST API v2 | `algo-rest-api` | — | — | — | — | — | — |
| A-19 | KMD & key tooling | `algo-kmd`, `bin/kmd-rust`, `algokey-rust`, `goal-rust` | — | — | — | — | — | — |
| A-20 | Configuration & protocol versions | `algo-config`, `algo-types` | — | — | — | — | — | — |
| A-21 | Persistence & crash recovery | `algo-ledger` | — | — | — | — | — | — |
| A-22 | Node runtime & concurrency | `bin/algod-rust`, async glue | — | — | — | — | — | — |

## Tier 3 — tooling, CI, supply chain

| Id | Area | Crate(s) / paths | Last audited (UTC) | Commit | Auditor tag | Methodologies | Depth | Report |
|---|---|---|---|---|---|---|---|---|
| A-23 | CLI tools | `goal-rust`, `algokey-rust`, `algo-netdeploy`, `algo-fork-detector` | — | — | — | — | — | — |
| A-24 | Dependencies & build | `Cargo.toml`, `Cargo.lock`, `deny.toml`, `build.rs`, profiles | — | — | — | — | — | — |
| A-25 | CI & release integrity | `.github/workflows/`, `docker/` | — | — | — | — | — | — |

## Smart-contract rule catalogue coverage (`instructions.md` §3.2)

Tick a rule only when a report's §5 "Verified invariants" table carries file:line evidence for it against a go-algorand oracle. Record the report that last verified it.

| # | Rule | Last verified (report) | Status |
|---|---|---|---|
| 1 | Authorization (`Sender`/`AuthAddr`/rekey/LogicSig/multisig/inner sender) | — | not verified |
| 2 | Fees and fee pooling | — | not verified |
| 3 | Minimum balance requirement incl. v43 `CloseRequiresBaseMinBalance` | — | not verified |
| 4 | Group atomicity and rollback | — | not verified |
| 5 | Opt-in / close-out / clear-state | — | not verified |
| 6 | Asset lifecycle, freeze, clawback | — | not verified |
| 7 | Application lifecycle and limits | — | not verified |
| 8 | Boxes and box budgets | — | not verified |
| 9 | Inner transactions | — | not verified |
| 10 | Global / transaction / block fields per version | — | not verified |
| 11 | Opcode budget and pooling | — | not verified |
| 12 | Determinism of program-visible data | — | not verified |
| 13 | Program versioning | — | not verified |
| 14 | Developer-tooling fidelity (`simulate`/`dryrun`) | — | not verified |
