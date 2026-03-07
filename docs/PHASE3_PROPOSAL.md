# Phase 3 — AVM Execution

_Created: 2026-03-06_

## Goal

Implement the Algorand Virtual Machine (TEAL interpreter) so that algod-rust can independently execute smart contract programs, produce EvalDelta (state changes, inner transactions, logs) without relying on recorded block data, and execute LogicSig programs. This covers Conformance Layer 6 (AVM Execution).

## Scope

**In scope:**
- Full TEAL bytecode interpreter covering all ~170 opcodes across AVM versions 1–10
- Independent EvalDelta production (global deltas, local deltas, inner transactions, logs)
- Inner transaction construction and recursive execution
- Box storage (key-value CRUD, I/O budget, min-balance, persistence)
- LogicSig program execution (replacing signature-only verification)
- Cost accounting matching go-algorand exactly
- Approval and clear-state program execution paths
- Program validation (bytecode verification, branch targets, subroutine balance)

**Out of scope:**
- `normalizedonlinebalance` (Phase 3+, affects participation weight not AVM execution)
- Catchpoint sync and mid-chain state loading (Phase 4)
- Networking / gossip (Phase 5)
- Consensus participation (Phase 6)

## Epic Issues

| Epic | Title | Issue | Effort | Dependencies |
|------|-------|-------|--------|--------------|
| 19 | AVM Core: Bytecode Parser & Stack Machine | [#21](https://github.com/xarmian/algod-rust/issues/21) | Large | — |
| 20 | AVM State Access: Ledger Queries & Transaction Fields | [#22](https://github.com/xarmian/algod-rust/issues/22) | Large | #21 |
| 21 | AVM Crypto Opcodes | [#23](https://github.com/xarmian/algod-rust/issues/23) | Medium | #21 (parallel with 20) |
| 20b | Transaction Evaluation Bridge | [#24](https://github.com/xarmian/algod-rust/issues/24) | Medium | #22 |
| 22 | Inner Transactions | [#25](https://github.com/xarmian/algod-rust/issues/25) | Large | #24 |
| 22b | Box Storage | [#26](https://github.com/xarmian/algod-rust/issues/26) | Large | #24 (parallel with 22) |
| 23 | AVM Integration: Replace Recorded EvalDelta | [#27](https://github.com/xarmian/algod-rust/issues/27) | Medium | #23, #25, #26 |
| 24 | Phase 3 Closeout: Mainnet AVM Conformance | [#28](https://github.com/xarmian/algod-rust/issues/28) | Medium | #27 |

Critical path: **19 → 20 → 20b → 22 → 23 → 24**

## New Infrastructure

### New Crate
- `crates/core/algo-avm` — TEAL interpreter, opcode implementations, program validator

### New Workspace Dependencies

| Crate | Purpose |
|-------|---------|
| `sha3` | keccak256, SHA3-256 opcodes |
| `k256` | secp256k1 ECDSA (verify, recover, decompress) |
| `p256` | secp256r1 ECDSA (AVM v7+) |
| `num-bigint` | Wide math opcodes (divmodw, expw) |

## Success Criteria

1. All ~170 AVM opcodes implemented across versions 1–10 with correct stack semantics and cost accounting
2. Application calls independently produce EvalDelta (global deltas, local deltas, inner transactions, logs)
3. Inner transactions re-executed independently through the AVM with correct rollback semantics
4. Box storage fully functional: create, read, write, delete with min-balance and I/O budget accounting
5. LogicSig TEAL programs executed (not treated as opaque blobs)
6. 1000+ mainnet blocks replayed with `--avm-execute`, producing identical EvalDelta to go-algorand
7. Opcode-level conformance tests exist for each opcode category
8. Cost accounting matches go-algorand exactly for all exercised programs
9. All existing 402+ tests continue to pass with zero regressions
10. Zero clippy warnings, code formatted, all tests green

## Risks

| Risk | Mitigation |
|------|------------|
| Opcode behavioral edge cases (overflow, type coercion) | Differential testing per-opcode against go-algorand |
| Inner txn budget pooling complexity | Mirror Go's EvalParams pooling; test with mainnet groups |
| AVM version gating (v1–v10 feature flags) | Program validator rejects opcodes above declared version |
| LogicSig vs App mode differences | Separate execution modes with compile-time constraints |
| Box I/O budget accounting | Port Go's budget formula directly; fuzz with random box patterns |
| Program validation correctness | Port Go's CheckProgram() logic; test with malformed programs |
| Rollback coverage for box + inner txn mutations | Extend snapshot/restore; integration tests for failure paths |
