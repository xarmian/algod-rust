# Algod-Rust — Comprehensive Security & Consensus Parity Audit Instructions

**Issued by:** Office of the CTO, Algod DAO  
**Target Repository:** `xarmian/algod-rust`  
**Reference Implementation:** `algorand/go-algorand` (pinned at `v5.0.4-stable` in `../go-algorand`)  
**Document Version:** 1.0  

---

## 1. Executive Mandate & Audit Objectives

`algod-rust` is a production-grade, full Rust reimplementation of the Algorand blockchain protocol node (`go-algorand`). In a Byzantine Fault Tolerant (BFT) Layer-1 network where nodes written in different languages (`go-algorand` and `algod-rust`) participate simultaneously in consensus, **any behavioral discrepancy, non-deterministic execution path, or wire-encoding divergence is a consensus-splitting vulnerability**.

As an independent auditor (human security researcher or autonomous AI security agent), your objective is to attempt to break `algod-rust` across five critical security properties:

1. **Consensus & State-Transition Equivalence (Zero-Fork Guarantee):** Prove or disprove that for every possible byte sequence representing a block, transaction group, or TEAL program, `algod-rust` and `go-algorand` (`v5.0.4-stable`) reach the exact same accept/reject decision and compute the exact same resulting state commitment, account deltas, EvalDeltas, and block digests.
2. **Cryptographic Soundness & Post-Quantum Integrity:** Verify that VRF sortition, Ed25519 batch/single verification, one-time ephemeral participation signatures, sumhash/state-proof Merkle trees, and the pure-Rust deterministic Falcon-1024 (`det1024`) implementation (`DIV-001`) are free of malleability, side-channel leakage, domain-separation flaws, and floating-point/fixed-point divergence.
3. **Byzantine Agreement (`BA*`) Safety & Liveness:** Verify that no sequence of adversarial votes, Equivocation/Bundle messages, malformed proposal payloads, replay attacks, or clock-skew manipulations can cause `algod-rust` to certify conflicting blocks, stall liveness permanently, or accept an invalid certificate.
4. **Asymmetric Resource Exhaustion (DoS) & Memory Safety:** Verify that no unauthenticated or peer-authenticated network packet, gossip frame, catchpoint chunk, or AVM program can trigger an unhandled panic (`unwrap`/`expect`/slice index out-of-bounds), integer overflow/underflow, unbounded memory allocation, file-descriptor exhaustion, or CPU starvation (e.g., quadratic execution cost in TEAL opcodes or transaction pool validation).
5. **Key Management, API Boundary, & Privilege Isolation:** Verify that `kmd-rust`, `algokey-rust`, and `algo-rest-api` enforce strict authentication (`X-Algo-API-Token`, `X-KMD-API-Token`), zeroize secret key material in memory, prevent path traversal or SQL injection in SQLite ledger stores, and never leak sensitive node state on public endpoints.

---

## 2. Architecture & Audit Scope Matrix

Auditors must cover the workspace crates prioritized by consensus and security criticality. Review `docs/CRATE_ARCHITECTURE.md` and `docs/DIVERGENCES.md` before beginning code inspection.

### Tier 1 — Consensus-Critical & Cryptographic Core (Highest Priority)

| Crate / Path | Security Domain | Primary Attack Surfaces & Invariants | Upstream `go-algorand` Oracle |
|---|---|---|---|
| `crates/core/algo-codec` | Canonical Msgpack | Non-canonical field ordering, duplicate map keys, zero-value omission rules, trailing bytes, recursion depth bombs, signed/unsigned integer coercion | `protocol/codec.go`, `go-codec` |
| `crates/core/algo-types` | Protocol Primitives | Domain separation prefixes (`TX`, `TG`, `BH`, `B256`, `MA`, `ProgramData`), GenesisHash binding, TxID / GroupID calculation, address checksums | `data/basics/`, `data/transactions/`, `data/bookkeeping/` |
| `crates/core/algo-falcon` | Post-Quantum Crypto (`DIV-001`) | Pure-Rust `det1024` (`src/rs/`) vs vendored C (`c-backend`), IEEE-754 binary64 vs `FALCON_FPEMU` edge cases, `fpr_expm_p63` fixed-point math, CT vs compressed signature conversion, salt-version checks | `crypto/falconWrapper.go`, `github.com/algorand/falcon` |
| `crates/core/algo-consensus-crypto` | VRF, Ephemeral Keys, Sumhash | VRF proof verification & output determinism, sortition binomial CDF math (`statrs`/float precision), ephemeral key dilution/expiration, state-proof `sumhash` Poseidon2/SHA256 Merkle verification | `crypto/`, `crypto/merklearray/`, `data/committee/` |
| `crates/core/algo-avm` | AVM / Smart Contracts & TEAL Opcodes | Opcode version/mode gating (`v1`–`v13`, `LogicSig` vs `Application`), varint branch decoding, stack/call-frame/scratch bounds (`proto`/`frame_dig`/`frame_bury`), dynamic opcode cost accounting & pooled `GroupBudget`, elliptic curve/pairing/hash/PQ opcodes (`ec_*`, `poseidon2`, `sumhash512`, `mimc`, `falcon_verify`, `vrf_verify`), wide-byte math (`b+`, `b*`, `b/`, `bsqrt`), box storage & MBR billing (`box_*`), inner transaction trees (`itxn_*`, `compute_inner_txn_id`), ClearState error-swallowing vs Approval rollback | `data/transactions/logic/` |
| `crates/core/algo-abi` | Smart Contract ARC-4 ABI | Recursive ABI type string parser (`Uint`, `Ufixed`, `Tuple`, `ArrayDynamic`), method selector computation, binary/JSON encoding and box-name decoding bounds | `github.com/algorand/avm-abi/abi/` |
| `crates/core/algo-validate` | Stateless Validation | Signature verification, multisig threshold/subsig bounds, LogicSig program size/arg limits, rekeying rules, asset/app parameter bounds, lease & validity window checks | `data/transactions/verify.go`, `ledger/eval/` |
| `crates/core/algo-ledger` | Stateful Ledger & Apply | Block header validation, reward distribution, MBR (Minimum Balance Requirement) calculation (`CloseRequiresBaseMinBalance` v43), app/asset creation & close-out, state delta rollback on group failure, simulation engine (`EvalDelta` parity), SQLite persistence & crash-snapshot zstd decode | `ledger/`, `ledger/apply/`, `ledger/simulation/` |
| `crates/core/algo-agreement` | `BA*` Consensus Engine | Proposal payload verification, soft/cert/next/late/redo/down vote thresholds, committee weight calculation, bundle assembly, equivocation filtering, fast-recovery state transitions | `agreement/` |

### Tier 2 — Network, Mempool, & Runtime Services (High Priority)

| Crate / Path | Security Domain | Primary Attack Surfaces & Invariants | Upstream `go-algorand` Oracle |
|---|---|---|---|
| `crates/core/algo-pool` | Transaction Pool | Mempool eviction under flood, replacement-by-fee rules, group atomicity in pool, lease collision handling, memory growth caps | `data/txPool.go` |
| `crates/node/algo-network` & `crates/node/algo-p2p` | Gossip & P2P Transport | WebSocket/HTTP gossip & libp2p transport, peer authentication, message size caps, vote/tx deduplication filters, slow-loris / connection slot exhaustion (`fd_limits`), eclipse attack resistance | `network/`, `rpcs/` |
| `crates/node/algo-txn-pipeline` | Ingestion Pipeline | Concurrent signature verification worker pools, channel backpressure, batch verification fallback on invalid sig | `data/txHandler.go` |
| `crates/node/algo-rest-api` | REST API v2 Server | Bearer token validation (constant-time comparison), admin vs public route separation, simulate/dryrun resource limits, pagination bounds, JSON/msgpack serialization parity | `daemon/algod/api/server/v2/` |
| `crates/node/algo-kmd` & `bin/kmd-rust` | Key Management Daemon | Wallet master derivation key encryption (`scrypt` + `crypto_secretbox`), key handle expiration, memory zeroization (`zeroize`), API token enforcement | `daemon/kmd/` |
| `crates/node/algo-config` | Configuration & Params | Consensus parameter tables per protocol version, `config.json` parsing defaults, safe fallback behavior | `config/` |

### Tier 3 — CLI Binaries & Tooling (Medium Priority)

- `bin/algod-rust`, `crates/tools/algokey-rust`, `crates/tools/goal-rust`, `crates/tools/algo-netdeploy`
- Focus on: private key file permissions (`0600`), seed/mnemonic entropy generation, CLI input sanitization, and safe handling of key material in logs/stdout.

### Deliberate Divergences (Out-of-Scope as Bugs, In-Scope for Soundness Verification)

Before flagging a difference from `go-algorand`, **always check `docs/DIVERGENCES.md`** (`DIV-001`, `DIV-002`, etc.) and grep for `DIVERGENCE DIV-`. Registered divergences are intentional architectural choices. Do **not** report the existence of a registered divergence as a defect; instead, audit whether the divergence's implementation violates its claimed `"Wire / consensus impact: none"` invariant.

---

## 3. Mandatory Audit Methodologies

Every audit engagement (and every automated `"do new audit"` run) must combine **at least three** of the following six methodologies, documenting the exact commands, harnesses, and code paths inspected.

### Methodology M1: Line-by-Line Differential Specification Analysis (Go vs. Rust)
Compare the Rust implementation directly against the pinned `../go-algorand` (`v5.0.4-stable`) source code for target subsystems.
- Verify that every conditional branch, version gate (`ConsensusParams`), early return, and error-clearing rule in Go has an exact counterpart in Rust.
- **High-risk anti-patterns to hunt:**
  - Rust using saturating arithmetic (`saturating_add`/`saturating_sub`) where Go checks for overflow and rejects the transaction, or vice versa.
  - Map iteration order affecting consensus state hashes, `EvalDelta` key ordering, or canonical msgpack output (`HashMap` vs `BTreeMap`).
  - Partial state mutations persisting when a later transaction in an atomic group or inner transaction tree fails.
  - Floating-point rounding differences in sortition (`algo-consensus-crypto`) or Falcon (`algo-falcon`).

### Methodology M2: Static Analysis, Panic Surface & Unsafe Code Audit
Perform systematic static inspection of the Rust workspace:
- **Unsafe & FFI Boundary Audit:** Locate every `unsafe` block across `crates/` and `bin/`. Verify memory alignment, pointer validity, lifetime bounds, and thread safety (`Send`/`Sync`).
- **Panic & Unwrap Audit in Production Paths:** Search non-test code in Tier 1 and Tier 2 crates for `.unwrap()`, `.expect()`, direct slice indexing `slice[i]`, integer division `/` or `%` by potentially zero denominators, and `.try_into().unwrap()`. Any reachable panic triggered by wire input, block data, or TEAL bytecode is at minimum a **High** severity DoS finding.
- **Dependency & Supply-Chain Audit:** Check `Cargo.toml` / `Cargo.lock` for unmaintained cryptographic crates, unsound transitive dependencies, or feature flags that weaken security (e.g., non-constant-time crypto paths).

### Methodology M3: Cryptographic & Invariant Property Verification
Audit cryptographic primitives against academic and protocol specifications:
- **Domain Separation:** Confirm that every signature verification and hash calculation prepends the mandatory Algorand domain separator (`"TX"`, `"TG"`, `"BH"`, `"PLD"`, `"OT1"`, `"OT2"`, `"MX"`, `"ProgramData"`, etc.) and cannot collide across types (e.g., crafting a `Transaction` whose bytes match a `BlockHeader`).
- **Malleability & Canonicality:** Verify Ed25519 signature S-value range checks (cofactorless vs small-order point rejection matching `go-algorand`), VRF proof uniqueness, and Falcon-1024 signature canonicality (both compressed `0xBA` and constant-time `0xDA` formats).
- **Constant-Time Execution & Secret Zeroization:** Verify that private key operations, KMD password checks, and REST API token comparisons (`subtle::ConstantTimeEq`) do not leak timing information, and that ephemeral/participation secret keys implement `ZeroizeOnDrop`.

### Methodology M4: Coverage-Guided & Differential Fuzzing
Review, execute, or design new fuzz targets under `fuzz/fuzz_targets/` (`fuzz_apply_transaction`, `fuzz_account_roundtrip`, `fuzz_teal_program`, `fuzz_avm_context`) and `crates/tools/algo-agreement-fuzz`:
- Identify gaps in fuzzing coverage (e.g., network message decoders, catchpoint state proof verifiers, ABI type decoders, state-delta roundtrips).
- Construct adversarial property tests (`proptest`) or unit test vectors targeting boundary values (`u64::MAX`, `i64::MIN`, empty byte slices, maximum TEAL stack depth, maximum inner-txn depth, deeply nested msgpack maps).

### Methodology M5: Adversarial Consensus & Byzantine Fault Injection
Analyze `algo-agreement`, `algo-network`, and `algo-p2p` under an active Byzantine threat model (up to $f < \frac{1}{3}$ malicious stake + arbitrary Sybil non-stake peers):
- **Equivocation & Split-Vote Attacks:** Can a proposer send different `ProposalPayload` bodies for the same `(round, period, step)` and cause honest `algod-rust` nodes to lock on one value while certifying another?
- **Future-Round / Past-Round Vote Floods:** How does `algod-rust` bound memory when flooded with votes for future rounds or periods before committee sortition can be verified?
- **Catchup & State-Proof Poisoning:** During fast catchup (`algo-ledger`), what happens if a peer serves corrupted catchpoint chunks or invalid Merkle proofs? Does the node ban the peer and recover, or wedge?

### Methodology M6: Economic, Resource-Metering & DoS Stress Analysis
Verify that every operation's computational and storage footprint is strictly bounded by protocol fees or rate limits:
- **AVM Cost vs. Wall-Clock CPU:** Check whether any TEAL opcode (e.g., `ec_pairing_check`, `ec_multi_scalar_mul`, `mimc`, `poseidon2`, `falcon_verify`, `box_extract`/`box_replace`, regex/byte ops) can be invoked with pathological inputs that consume orders of magnitude more CPU/RAM than its dynamic opcode cost charges.
- **Ledger Minimum Balance Requirement (MBR) Bypass:** Check whether any sequence of asset opt-in/close-out, app opt-in/clear-state, box creation/deletion, or account close-to (`CloseRemainderTo` / `AssetCloseTo`, including v43 `CloseRequiresBaseMinBalance`) can leave ledger records allocated without locking the required MBR, or underflow an account balance.

---

## 4. Industry-Standard Severity & Likelihood Classification

In accordance with leading blockchain security audit frameworks (**Trail of Bits**, **OpenZeppelin**, **NCC Group**, **Halborn**, and **Immunefi Blockchain/DLT Bug Bounty Standard**), every finding must be rated along two axes: **Impact** and **Likelihood / Exploitability**, combined into a deterministic **Severity** level.

### Severity Matrix

| Impact \ Likelihood | High (Trivial / Unauthenticated / Automated) | Medium (Requires Specific State / Stake / Timing) | Low (Theoretical / Extreme Preconditions) |
|---|---|---|---|
| **Critical Impact** (Consensus split, unauthorized mint/spend, key theft) | **CRITICAL** | **CRITICAL** | **HIGH** |
| **High Impact** (Remote node crash/halt, permanent liveness stall, MBR bypass) | **HIGH** | **HIGH** | **MEDIUM** |
| **Medium Impact** (Targeted resource exhaustion, API auth bypass on non-admin, single-peer wedge) | **MEDIUM** | **MEDIUM** | **LOW** |
| **Low Impact** (Minor spec deviation without consensus impact, defense-in-depth gap) | **LOW** | **LOW** | **INFORMATIONAL** |

### Severity Definitions

- **🔴 CRITICAL:**
  - Any state-transition, validation, or AVM evaluation divergence between `algod-rust` and `go-algorand` on reachable block/transaction inputs (chain split / hard fork).
  - Forgery of signatures, VRF proofs, state proofs, or `BA*` certificates; double-spending or unauthorized balance/asset creation.
  - Remote code execution (RCE), memory corruption (`unsafe` UB), or extraction of secret keys (`kmd-rust`, participation keys).
- **🟠 HIGH:**
  - Remotely triggerable panic, crash, deadlock, or OOM on a consensus node via P2P gossip, block sync, or valid transaction submission.
  - Permanent consensus stall (liveness failure) where honest nodes cannot advance rounds or recover.
  - Bypass of Minimum Balance Requirements (MBR), transaction fee accounting, or AVM opcode cost limits.
- **🟡 MEDIUM:**
  - Asymmetric CPU/disk/memory amplification (DoS) degrading node performance below block-time budget (~2.7s/round).
  - REST API or KMD boundary flaws, information disclosure, or peer-scoring flaws allowing eclipse attacks.
  - Edge-case bugs requiring compromised local configuration or privileged API access.
- **🔵 LOW:**
  - Minor behavioral mismatches in CLI tools (`goal-rust`, `algokey-rust`), non-consensus logging/metrics errors, or suboptimal error handling.
- **⚪ INFORMATIONAL / BEST PRACTICE:**
  - Code maintainability, missing defense-in-depth assertions, documentation drift, or test coverage enhancements with no direct exploit path.

---

## 5. Output Requirements: Audit Report Format & Naming Convention

### 5.1 File Location & Chronological Naming (Mandatory)

Every audit report **must** be saved as a Markdown file inside the `audits/reports/` directory.  
To guarantee strict chronological ordering when sorted lexicographically, the filename **must** follow this exact pattern:

```text
audits/reports/YYYY-MM-DD_HHMMSS_<auditor-tag>_<git-short-hash>.md
```

- `YYYY-MM-DD_HHMMSS`: UTC timestamp of the audit execution (e.g., `2026-10-23_073500`).
- `<auditor-tag>`: Lowercase kebab-case identifier of the auditor or agent team (e.g., `sec-agent-alpha`, `crypto-audit-bot`, `trail-of-bits-sim`, `claude-opus-sec`).
- `<git-short-hash>`: Output of `git rev-parse --short HEAD` (7–8 hex characters, e.g., `52322269`).

**Example filename:**
`audits/reports/2026-10-23_073500_sec-agent-alpha_52322269.md`

### 5.2 Mandatory Report Template

Every generated report in `audits/reports/` must adhere to the following industry-standard structure:

```markdown
# Algod-Rust Security Audit Report

## 1. Audit Metadata & Provenance
| Field | Value |
|---|---|
| **Report ID** | `AUDIT-YYYYMMDD-HHMMSS-<auditor-tag>` |
| **Timestamp (UTC)** | `YYYY-MM-DDTHH:MM:SSZ` |
| **Auditor Tag** | `<auditor-tag>` |
| **Target Commit (Short Hash)** | `<git-short-hash>` |
| **Target Commit (Full SHA)** | `<git-full-sha>` |
| **Branch / Worktree State** | `<branch> (clean / dirty)` |
| **Upstream Reference Pin** | `go-algorand v5.0.4-stable` |
| **Methodologies Applied** | `M1, M2, ...` |
| **Crates / Subsystems Audited** | `<list of crates>` |

## 2. Executive Summary
- High-level assessment of system posture, key strengths observed, and summary of the most critical risk areas discovered during this audit pass.
- Summary count table of findings by severity:

| Severity | Count | Open | Mitigated / Verified |
|---|---|---|---|
| 🔴 Critical | 0 | 0 | 0 |
| 🟠 High | 0 | 0 | 0 |
| 🟡 Medium | 0 | 0 | 0 |
| 🔵 Low | 0 | 0 | 0 |
| ⚪ Informational | 0 | 0 | 0 |
| **Total** | **0** | **0** | **0** |

## 3. Scope & Methodology Execution Log
- Detailed record of which files/lines were inspected, which `go-algorand` files were compared against, which static searches/tests/fuzzers were run, and what invariants were tested.

## 4. Detailed Findings
*(Repeat the subsection below for each finding, ordered from highest to lowest severity. Use IDs `FIND-<git-short-hash>-01`, `FIND-<git-short-hash>-02`, etc.)*

### [FIND-<hash>-01] <Concise Title of Vulnerability>
- **Severity:** 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low / ⚪ Informational
- **Likelihood:** High / Medium / Low
- **Impact:** Critical / High / Medium / Low
- **Category:** (e.g., Consensus Parity / Cryptography / Panic DoS / AVM Execution / Memory Safety / Network DoS)
- **Affected Component:** `crates/.../src/file.rs:line_start-line_end`
- **Upstream Reference:** `../go-algorand/path/to/file.go:line` (if applicable)
- **Risk Registry Link:** `RISK-INT-XXX` or `RISK-EXT-XXX` (must map to `audits/risks.md`)
- **Status:** Open / Acknowledged / Mitigated

#### Description & Root Cause
Precise technical explanation of the flaw, citing exact Rust functions and comparing with `go-algorand` where relevant.

#### Exploit Scenario / Proof of Concept (PoC)
Step-by-step reproduction, adversarial input construction, or unit test demonstrating how an attacker triggers the issue and what the impact is.

#### Recommended Remediation
Concrete, surgical code fix or architectural mitigation, including regression test requirements.

## 5. Invariant & Parity Verification Checklist
Table of security invariants explicitly verified as **PASS** during this audit pass (with file:line evidence), so subsequent audits can build incremental coverage.

## 6. Risk Registry Delta (`audits/risks.md` Updates)
Summary of new risks added, severity/likelihood adjustments made, or mitigations recorded in `audits/risks.md` as a result of this audit.
```

---

## 6. Automated Workflow: Executing `"do new audit"`

When the user prompts an AI agent with **"do new audit"** (or any variation such as *"run a new audit"*, *"perform security audit"*, or *"do new audit on `<subsystem>`"*), the agent **must** execute the following end-to-end workflow without skipping steps:

1. **Read Audit State & Prior Coverage:**
   - Read `audits/instructions.md` (this file) and `audits/risks.md`.
   - List existing reports in `audits/reports/` to see which subsystems and commits were audited most recently.
   - If the user did not specify a target subsystem, select the highest-priority unaudited (or least-recently-audited) Tier 1 / Tier 2 subsystem or recent `git log` changes since the last report's `<git-short-hash>`.

2. **Collect Git & Environment Provenance:**
   - Run `git rev-parse --short HEAD`, `git rev-parse HEAD`, and `git status -s`.
   - Generate the current UTC timestamp (`YYYY-MM-DD_HHMMSS`) and select a descriptive `<auditor-tag>` (e.g., `ai-sec-auditor` or subsystem-specific tag like `sec-audit-avm`, `sec-audit-consensus`).

3. **Execute Deep Multi-Methodology Audit:**
   - Apply at least **three methodologies** (`M1`–`M6` from Section 3) against the selected scope.
   - Perform real code inspection (`view`/`grep` on `crates/...` and `../go-algorand/...`), trace untrusted inputs from wire/API entrypoints into core logic, check for panics/overflows/divergences, and run targeted verification tests where appropriate.
   - Do **not** fabricate placeholder findings: every finding or verified invariant must cite real file paths and 1-based line numbers in the current tree.

4. **Write the Chronological Audit Report:**
   - Create `audits/reports/YYYY-MM-DD_HHMMSS_<auditor-tag>_<git-short-hash>.md` following the exact template in Section 5.2.

5. **Synchronize the Risk Registry (`audits/risks.md`):**
   - Update `audits/risks.md` in the same turn:
     - Add any newly discovered risks under Section 2 (**Internal / Controllable Risks**) or Section 3 (**External / Uncontrollable Risks**).
     - Update the **Last Audited Commit**, **Last Audit Report**, **Residual Risk**, and **Audit History Log** table at the bottom of `audits/risks.md` to reference the new report file.
