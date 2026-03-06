# Phase 3 Proposal — AVM Execution

_Created: 2026-03-06_

## Goal

Implement the Algorand Virtual Machine (TEAL interpreter) so that algod-rust can independently execute smart contract programs, produce EvalDelta (state changes, inner transactions, logs) without relying on recorded block data, and execute LogicSig programs. This covers Conformance Layer 6 (AVM Execution).

## What "AVM Execution" Means

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

## Epic Breakdown

### Epic 19 — AVM Core: Bytecode Parser & Stack Machine

**Goal:** Build the TEAL bytecode decoder, program validator, and core execution engine.

**Deliverables:**
- New crate: `crates/core/algo-avm`
- TEAL bytecode parser: version byte, opcode stream, immediates (uint, byte constants, branches)
- Opcode table: cost, stack effects, min AVM version for all ~170 opcodes across v1–v10
- Program validator: branch target validation, subroutine call/return balance, stack depth limits, AVM version gating per opcode
- Stack machine: `Vec<StackValue>` where `StackValue` is `Uint(u64)` or `Bytes(Vec<u8>)`
- Scratch space: `[StackValue; 256]`
- Program counter, branching: `b`, `bz`, `bnz`, `callsub`, `retsub`, `switch`, `match`
- Cost accounting: 20,000 budget for LogicSig mode, 700 per app call pooled across group
- ~50 pure opcodes implemented:
  - Arithmetic: `+`, `-`, `*`, `/`, `%`, `exp`, `addw`, `mulw`, `divmodw`, wide math
  - Logic: `&&`, `||`, `!`, `~`, `&`, `|`, `^`
  - Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
  - Byte ops: `concat`, `substring`, `extract`, `replace`, `len`, `getbit`, `setbit`, `getbyte`, `setbyte`, `btoi`, `itob`, `bzero`
  - Constants: `int`, `byte`, `addr`, `intcblock`, `bytecblock`, `intc_*`, `bytec_*`, `pushint`, `pushbytes`
  - Stack manipulation: `dup`, `dup2`, `pop`, `swap`, `dig`, `bury`, `cover`, `uncover`, `frame_dig`, `frame_bury`
  - Flow: `err`, `return`, `assert`, `select`
- Test vectors: hand-crafted TEAL programs for each opcode category
- Fuzz target: random bytecode execution with resource limits (no panics)

**Affected crates:** New `crates/core/algo-avm/`, workspace `Cargo.toml`
**Estimated effort:** Large

---

### Epic 20 — AVM State Access: Ledger Queries & Transaction Fields

**Goal:** Wire the AVM to ledger state so TEAL programs can read/write global state, local state, and query account/asset/app parameters.

**Deliverables:**
- `AvmContext` trait providing state access methods the VM calls
- Reference-index resolution layer: resolve `accounts` array indices, foreign apps/assets indices, box references to actual addresses/IDs
- `global` opcode: ~30 global fields (`MinTxnFee`, `MinBalance`, `MaxTxnLife`, `ZeroAddress`, `GroupSize`, `LogicSigVersion`, `Round`, `LatestTimestamp`, `CurrentApplicationID`, `CreatorAddress`, `CurrentApplicationAddress`, `GroupID`, `OpcodeBudget`, `CallerApplicationID`, `CallerApplicationAddress`, etc.)
- `txn`/`gtxn`/`gtxns`/`gtxna`/`gtxnsa` opcodes: ~60 transaction fields
- `arg`/`args` opcodes for LogicSig arguments
- `log` opcode: collect into EvalDelta logs
- State read/write opcodes: `app_opted_in`, `app_local_get`, `app_local_get_ex`, `app_global_get`, `app_global_get_ex`, `app_local_put`, `app_global_put`, `app_local_del`, `app_global_del`
- Account/asset/app query opcodes: `balance`, `min_balance`, `asset_holding_get`, `asset_params_get`, `app_params_get`, `acct_params_get`
- Cost accounting for state access opcodes (varied costs per opcode)
- Integration tests using TEAL programs that read/write state against `LedgerState`

**Affected crates:** `crates/core/algo-avm/` (new src/context.rs, src/fields.rs), `crates/core/algo-ledger/` (AvmContext impl), `crates/core/algo-types/` (field enums)
**Estimated effort:** Large

---

### Epic 20b — Transaction Evaluation Bridge

**Goal:** Bridge between the AVM interpreter and the ledger's transaction application pipeline.

**Deliverables:**
- Typed execution result: `AvmResult` struct with global deltas, local deltas, inner transactions, logs, and approval/rejection status
- Approval vs clear-state execution paths: approval program runs first; for ClearState on-completion, clear-state program runs and always succeeds even on failure
- Group context: pooled opcode budget across atomic group, call-frame accounting
- LogicSig vs App execution mode: distinct constraints (no state writes in LogicSig, no inner txns, arg access only)
- Wiring `AvmResult` back to ledger state application (replacing `parse_eval_delta` from `rmpv::Value` for execute mode)

**Affected crates:** `crates/core/algo-avm/` (new src/eval.rs or bridge module), `crates/core/algo-ledger/`
**Estimated effort:** Medium

---

### Epic 21 — AVM Crypto Opcodes

**Goal:** Implement all cryptographic and encoding opcodes required by TEAL programs.

**Deliverables:**
- Hash opcodes: `sha256`, `sha512_256`, `keccak256`, `sha3_256`
- Signature opcodes: `ed25519verify`, `ed25519verify_bare`
- ECDSA opcodes: `ecdsa_verify`, `ecdsa_pk_recover`, `ecdsa_pk_decompress` for secp256k1 and secp256r1
- VRF opcode: `vrf_verify` (VrfAlgorand standard)
- Encoding opcodes: `base64_decode` (standard + URL encoding)
- JSON opcodes: `json_ref` (AVM v7+ — string, uint64, object access)
- Cost accounting (crypto ops are expensive: ed25519verify = 1900, ecdsa_verify = 1700, vrf_verify = 5700)
- New workspace dependencies: `sha3`, `k256` (secp256k1), `p256` (secp256r1)

**Affected crates:** `crates/core/algo-avm/` (new src/crypto.rs), workspace `Cargo.toml`
**Estimated effort:** Medium

---

### Epic 22 — Inner Transactions

**Goal:** Enable TEAL programs to construct and execute inner transactions, including recursive AVM invocation.

**Deliverables:**
- Construction opcodes: `itxn_begin`, `itxn_field`, `itxn_submit`, `itxn_next`
- Field access opcodes: `itxn`, `itxna`, `itxnas`, `gitxn`, `gitxna`, `gitxnas`
- Inner transaction execution: dispatch to `apply_pay`/`apply_axfer`/`apply_acfg`/`apply_afrz` for non-app types; recursive AVM invocation for inner `appl` calls
- Inner transaction grouping (AVM v6+): `itxn_next` chains multiple inner txns into a group
- Depth tracking: max depth per consensus params (practical limit ~8 on mainnet)
- Rollback semantics: inner txn failure rolls back all inner side effects but not outer txn
- Budget pooling: inner app calls share the group's pooled opcode budget

**Affected crates:** `crates/core/algo-avm/` (new src/itxn.rs), `crates/core/algo-ledger/` (apply.rs refactor for AVM-driven inner txn dispatch)
**Estimated effort:** Large

---

### Epic 22b — Box Storage

**Goal:** Implement full box key-value storage accessible from TEAL programs.

**Deliverables:**
- `LedgerStore` trait extensions: `get_box`, `set_box`, `delete_box`, `box_len`, box listing
- In-memory implementation: box key-value store on `LedgerState`
- SQLite implementation: box table, CRUD operations, indexes
- Snapshot/rollback: box mutations covered by existing rollback mechanism
- Merkle trie integration: box resources in state root (HashKind::Kv = 3)
- Min-balance accounting: box create/delete adjusts account min-balance (`total_boxes`, `total_box_bytes` counters)
- Box opcodes: `box_create`, `box_extract`, `box_replace`, `box_del`, `box_len`, `box_get`, `box_put`, `box_resize`
- Box I/O budget accounting: 700 bytes base + per-box-ref budget

**Affected crates:** `crates/core/algo-avm/` (new src/box_ops.rs), `crates/core/algo-ledger/` (store_trait.rs, state.rs, sqlite.rs, trie)
**Estimated effort:** Large

---

### Epic 23 — AVM Integration: Replace Recorded EvalDelta

**Goal:** Wire the AVM into the ledger pipeline so application calls independently execute TEAL rather than consuming recorded EvalDelta.

**Deliverables:**
- Refactor `apply_appl()` for two modes: **Replay** (use recorded EvalDelta — current behavior, preserved for backward compatibility) and **Execute** (run AVM, produce EvalDelta independently)
- Compare AVM-produced `AvmResult` against recorded `EvalDelta` for conformance validation
- LogicSig TEAL execution: wire into `verify_logicsig` in algo-validate
- Pooled opcode budget enforcement across transaction group
- Differential testing: per-program execution comparison against go-algorand results
- New CLI flag `--avm-execute` on replay command
- New Makefile targets for AVM conformance replay

**Affected crates:** `crates/core/algo-ledger/src/apply.rs`, `crates/core/algo-validate/src/signature.rs`, `bin/algod-rust/`, `Makefile`
**Estimated effort:** Medium

---

### Epic 24 — Phase 3 Closeout: Mainnet AVM Conformance

**Goal:** Validate AVM execution against mainnet blocks, fix edge cases, document results.

**Deliverables:**
- Mainnet block replay with `--avm-execute` for 1000+ consecutive blocks
- Edge case fixes driven by replay failures
- Opcode coverage report: which of ~170 opcodes were exercised by mainnet replay
- TEAL test vector suite: fixtures for each opcode category
- AVM-specific fuzz targets (random TEAL programs against random state)
- `docs/PHASE3_VALIDATION.md` document
- Update PHASE2_VALIDATION.md gaps table (close out Phase 3 items)

**Affected crates:** Various (bug fixes), `docs/`
**Estimated effort:** Medium

---

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

Existing deps already cover: `sha2` (SHA-256, SHA-512/256), `ed25519-dalek` (ed25519), `data-encoding` (base32/base64).

### New Makefile Targets
- `avm-replay` — localnet AVM conformance replay
- `avm-replay-mainnet` — mainnet AVM conformance replay

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
11. Approval and clear-state execution paths both tested
12. Program validation rejects malformed bytecode matching go-algorand's CheckProgram

## Estimated Scope

| Epic | Effort | Dependencies |
|------|--------|-------------|
| 19 — AVM Core | Large | — |
| 20 — State Access | Large | 19 |
| 20b — Eval Bridge | Medium | 20 |
| 21 — Crypto Opcodes | Medium | 19 (parallel with 20) |
| 22 — Inner Transactions | Large | 20b |
| 22b — Box Storage | Large | 20b (parallel with 22) |
| 23 — Integration | Medium | 21, 22, 22b |
| 24 — Closeout | Medium | 23 |

Critical path: **19 → 20 → 20b → 22 → 23 → 24**

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

## Relationship to Later Phases

- **Phase 4 (Catchup and Sync):** With AVM execution complete, catchpoint sync enables mid-chain state loading for large-scale mainnet replay without genesis-to-current sequential processing.
- **Phase 5 (Networking):** AVM execution is the final validation step for incoming blocks — after stateless validation (Phase 1) and ledger application (Phase 2), AVM re-execution confirms contract state changes.
- **Phase 6 (Consensus):** Full block validation (Phases 1–3) is a prerequisite for consensus participation — a node must validate blocks it votes on.
