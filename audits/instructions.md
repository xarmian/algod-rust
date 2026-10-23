# Algod-Rust — Security, Soundness & Consensus-Parity Audit Instructions

**Issued by:** Office of the CTO, Algod DAO
**Target repository:** `xarmian/algod-rust` (public)
**Reference implementation:** `algorand/go-algorand`, pinned at `v5.0.4-stable` in `../go-algorand` (detached HEAD)
**Document version:** 2.0 (supersedes 1.0)
**Audience:** independent human security researchers and autonomous AI auditing agents of any vendor. Every auditor, whatever their tooling, follows this document end-to-end and produces a report in the same format so that reports from different auditors are directly comparable and cumulative.

---

## 0. How to use this document

| If you are… | Read… | Then do… |
|---|---|---|
| A human auditor starting an engagement | §1–§4, §6, §8 | Pick a scope with §5, run §6, write the report per §7, update `risks.md` and `coverage.md` per §9 |
| An AI agent triggered by **"do new audit"** | Everything | Execute §10 literally, in order, without skipping a step |
| A maintainer triaging a report | §4, §7, §8 | Verify the PoC, file/fix, update `risks.md` status columns |

Three files form the audit system. All live under `audits/`:

- `audits/instructions.md` — this document (methodology, scope, report contract).
- `audits/risks.md` — the living risk registry (`RISK-INT-NNN` controllable, `RISK-EXT-NNN` uncontrollable) plus the **Audit History & Synchronization Log**.
- `audits/coverage.md` — the coverage ledger: one row per audit area (`A-NN`), recording when it was last audited, at which commit, by whom, and with which methodologies. It is how many independent auditors avoid re-auditing the same 20% of the code while 80% is never looked at.
- `audits/reports/` — one immutable report per run, named `YYYY-MM-DD_HHMMSS_<auditor-tag>_<git-short-hash>.md`.

**Golden rule: evidence, not opinion.** Every finding and every "verified PASS" cites a real file path and 1-based line range in the current tree (`crates/.../file.rs:L10-L42`) and, where parity is the question, the matching `../go-algorand/...` location. Line numbers must be re-read from the working tree in the same run, never recalled from memory or from an older report. A claim without a location is not a finding; it is a note in §7.9 ("Open questions").

---

## 1. Why this audit exists: the asset we protect

`algod-rust` is a full Rust reimplementation of the Algorand node. It is a **Layer-1 blockchain client**. Its correctness is the foundation that every smart contract, every DeFi protocol, every token and every wallet built on Algorand depends on. The money is not in this repository, but this repository decides where the money goes.

Three consequences shape everything below:

1. **Determinism is consensus.** go-algorand and algod-rust run side-by-side in the same network. If the two implementations disagree on *any* reachable input — one byte of msgpack, one TEAL opcode edge case, one overflow rule, one map iteration order — the network forks. In a BFT network a fork is the worst outcome: it is a double-spend engine. A divergence that only triggers on a bizarre, "nobody would ever do that" input is still Critical, because an attacker will do that on purpose.
2. **The AVM is the trust base of every contract.** Developers reason about their contracts using the protocol's rules (MBR, fee pooling, group atomicity, rekey semantics, box billing, inner-transaction limits, opt-in/close-out rules, clear-state semantics). If algod-rust applies any of these rules differently, a contract that is secure under the protocol becomes exploitable on nodes running algod-rust, and the contract author cannot defend against it. "Funds held in smart contracts are safe" is a property of the node, not only of the contract.
3. **Developer tooling is part of the security boundary.** Teams audit and test contracts with `/v2/transactions/simulate`, `dryrun`, `/v2/teal/compile`, `/v2/teal/disassemble`, source maps, and the pending-transaction/account/box/application endpoints. If those lie — report a different `EvalDelta`, a different cost, a different error, a different final balance than consensus would produce — developers ship contracts whose real behaviour they have never seen. Fidelity of non-consensus, developer-facing paths is therefore in scope, at one severity level below the equivalent consensus defect.

### 1.1 Security properties to break (the auditor's objective)

The auditor's job is adversarial: try to break each property, then document either the break (a finding) or the evidence that it holds (a verified invariant).

| # | Property | Statement to disprove |
|---|---|---|
| P1 | **State-transition equivalence (zero-fork)** | For every byte string presented as a block, transaction group, LogicSig, or TEAL program, algod-rust and go-algorand `v5.0.4-stable` reach the same accept/reject decision and the same resulting account deltas, `ApplyData`, `EvalDelta`, block digest, state-proof roots and payset commitments. |
| P2 | **Cryptographic soundness** | Ed25519 (single and batch), VRF, one-time participation signatures, multisig, LogicSig/`ProgramData`, sumhash/SHA-512/256 Merkle trees, Poseidon2/MiMC, pairings, and pure-Rust Falcon-1024 `det1024` (`DIV-001`) accept exactly the set of inputs the reference accepts, are not malleable where the reference is not, use correct domain separation, and leak no secret through timing or memory. |
| P3 | **Agreement (`BA*`) safety and liveness** | No sequence of adversarial votes, proposals, bundles, equivocations, replays, clock manipulations or message reorderings causes algod-rust to certify two conflicting blocks for one round, accept an invalid certificate, or stall permanently while honest stake is > 2/3. |
| P4 | **Smart-contract platform integrity** | Every protocol rule a contract author may rely on (see §3.2 catalogue) is enforced identically to the reference: authorization (`Sender`/`AuthAddr`/rekey/LogicSig/multisig), MBR, fee pooling, group atomicity and rollback, resource availability, box billing, inner-transaction trees, opt-in/close-out/clear-state, asset freeze/clawback, app account funds, `OnCompletion` semantics, opcode cost budgets. |
| P5 | **Availability under adversarial load** | No unauthenticated or peer-authenticated input (gossip frame, block, catchpoint chunk, REST request, TEAL program, msgpack blob) can panic, deadlock, OOM, exhaust file descriptors or disk, or consume CPU far above its protocol-priced cost. |
| P6 | **Key, token and boundary isolation** | Participation keys, KMD wallets and mnemonics are never leaked (memory, logs, API, disk permissions); REST/KMD/admin tokens are compared constant-time and enforced on every privileged route; no path traversal, injection or deserialization gadget exists on any file/DB/API boundary. |
| P7 | **Persistence integrity** | A crash, power loss, disk-full or kill at any instruction boundary leaves the SQLite ledger, catchpoint files, participation key store and crash-snapshot in a state from which the node restarts to a consistent round, never to a silently diverged one. |
| P8 | **Developer-tooling fidelity** | `simulate`, `dryrun`, `compile`, `disassemble`, source maps, `pending`, `account`/`asset`/`application`/`box` endpoints, and `goal-rust` report exactly what consensus would do. |
| P9 | **Code soundness** | The implementation is free of undefined behaviour, data races, unsound `unsafe`, lossy casts on consensus values, swallowed errors, non-cancel-safe async, and time/locale/platform dependence that could make two nodes behave differently. |

---

## 2. Threat model

Audit against all of these adversaries. For each finding, name which adversary can trigger it; it determines Likelihood (§4).

| Adversary | Capabilities | Can reach |
|---|---|---|
| **T1 Anonymous network peer** | Connects to the node over WebSocket gossip or libp2p with no stake. Sends arbitrary bytes, arbitrary rates, slow-loris, connection churn, malformed handshakes, oversized frames, unsolicited catchup/blocks, votes for any round. | `algo-network`, `algo-p2p`, `algo-agreement` ingress, `algo-ledger` catchup, codec |
| **T2 Transaction submitter** | Any user with a few microAlgos. Submits any syntactically valid or invalid transaction/group/LogicSig to the public `POST /v2/transactions` or via gossip. | `algo-pool`, `algo-txn-pipeline`, `algo-validate`, `algo-avm`, `algo-ledger` |
| **T3 Smart-contract author** | Deploys arbitrary approval/clear-state programs and LogicSigs; controls inner-transaction trees; controls box names and sizes; can make app accounts hold funds. Goal: steal from other contracts, bypass MBR/fees, exhaust node resources below cost, or make algod-rust disagree with go-algorand. | `algo-avm`, `algo-ledger` apply, `algo-abi` |
| **T4 Byzantine stake (< 1/3)** | Holds participation keys for a minority of online stake. Can propose, vote, equivocate, withhold, replay, send bundles with any subset of its votes, time messages adversarially. | `algo-agreement`, `algo-consensus-crypto`, block assembly |
| **T5 Malicious relay / catchup server** | Controls what blocks, certificates, catchpoint labels and chunks a syncing node receives. | `algo-rest-client`, `algo-ledger` catchpoint, `algo-network` block service |
| **T6 Unprivileged REST client** | Network access to the REST port; may hold the public (non-admin) token or no token. | `algo-rest-api` |
| **T7 Local low-privilege user** | Shell on the node host without the node's user. Reads world-readable files, races filesystem operations, observes timing. | key files, data dir permissions, `kmd-rust`, `algokey-rust`, `goal-rust` |
| **T8 Supply chain** | Compromised or unsound crate, C library (bundled SQLite, optional Falcon C backend), toolchain or CI action. | `Cargo.lock`, `deny.toml`, build scripts, `.github/workflows` |
| **T9 Upstream protocol** | go-algorand has a latent bug or ships an emergency consensus change. Not controllable, but algod-rust's response to it is. | version gating, halt-on-unknown-protocol, upgrade pipeline |

Assumptions that are **out of scope** as findings (but in scope as context): > 1/3 Byzantine stake; broken Ed25519/SHA-2/lattice assumptions; a root-compromised host. These live in `risks.md` §3 as `RISK-EXT-*`.

---

## 3. Scope: audit areas

Every audit area has a stable id (`A-NN`) used by `audits/coverage.md`. Tiers set priority; within a tier pick by coverage age (§5). Read `docs/CRATE_ARCHITECTURE.md`, `docs/DIVERGENCES.md` and the relevant `docs/PHASE*_VALIDATION.md` before inspecting code: they tell you what the project already claims to have proven, which is exactly what an auditor should try to falsify.

### 3.1 Tier 1 — consensus-critical and cryptographic core

| Id | Area | Crate(s) | What to attack | go-algorand oracle |
|---|---|---|---|---|
| A-01 | Canonical msgpack | `algo-codec` | Non-canonical input accepted on a consensus path; field ordering; omit-empty rules per type; duplicate keys; trailing bytes; nesting depth; int/uint width coercion; `bin` vs `str`; map-key sort order (length-then-bytes? byte-lexicographic?) vs `go-codec`; round-trip not byte-identical | `protocol/codec.go`, `go-codec` (`msgpack.go`) |
| A-02 | Protocol primitives & hashing | `algo-types` | Domain separators (`TX`, `TG`, `BH`, `B256`, `MA`, `PLD`, `OT1`/`OT2`, `MX`, `ProgramData`, `appID`, `spc`, `STIB`, `SPC`); TxID/GroupID; address checksum; `GenesisHash`/`GenesisID` binding; consensus parameter tables vs `config/consensus.go` for **every** version incl. v40–v43 and `vFuture`; heartbeat txn fields; `Proposer`/`FeesCollected`/`Bonus`/`ProposerPayout` header fields | `protocol/hash.go`, `data/basics/`, `data/transactions/`, `data/bookkeeping/`, `config/consensus.go` |
| A-03 | Stateless validation | `algo-validate` | Signature dispatch (sig / msig / lsig; exactly one); multisig threshold, version, duplicate/zero subsigs; LogicSig size/args/version; rekey (`RekeyTo` vs `AuthAddr`); lease; `FirstValid`/`LastValid`/`MaxTxnLife`; fee min and fee pooling across group; group size and `Group` field consistency; `GenesisHash` required-ness per version; well-formedness of every txn type (pay, keyreg incl. incentive eligibility and `StateProofPK`, acfg, axfer, afrz, appl, stpf, **hb**); note size; zero-address semantics; batch verification fallback | `data/transactions/verify/`, `data/transactions/*.go` `WellFormed`, `ledger/eval/` |
| A-04 | Ledger apply & block evaluation | `algo-ledger` | Reward distribution and `RewardsLevel` rounding; `MinBalance` per account including app schema, extra pages, boxes, assets; v43 `CloseRequiresBaseMinBalance`; close-to with pending rewards; asset creator/manager/reserve/freeze/clawback transitions; default-frozen; clawback from frozen; app create/opt-in/close-out/clear-state/update/delete and the `OnCompletion` matrix; group-level rollback on any failure incl. inner; block header validation (`TimeStamp` clamp, `Seed`, `TxnCounter`, `UpgradeState`, `Proposer`, payouts, `AbsentParticipationAccounts`, `ExpiredParticipationAccounts`); `FeeSink`/`RewardsPool` special-casing; state-proof txn application; `TxnCounter` and app/asset ID assignment | `ledger/apply/`, `ledger/eval/eval.go`, `ledger/eval/prefetcher`, `data/bookkeeping/block.go`, `ledger/ledgercore/` |
| A-05 | Block assembly & proposal | `algo-ledger`, `algo-pool`, `algo-agreement` | Proposer-side: payset selection respecting `MaxTxnBytesPerBlock`, group integrity, fee ordering, `TxnCounter`, timestamp choice, payout computation, heartbeat insertion, `Seed` derivation; an algod-rust proposer must never build a block go-algorand would reject | `data/pools/transactionPool.go` `AssembleBlock`, `ledger/eval/eval.go` `BlockEvaluator`, `agreement/proposal*.go` |
| A-06 | AVM core: parser, flow, stack, budgets | `algo-avm` | Bytecode parse incl. varint branches, `switch`/`match` tables, const blocks, `pushbytess`/`pushints` limits; static `check_program` vs runtime; version/mode gating (`v1`–`v13`, LogicSig vs Application, `logic_sig_version` cap); stack depth 1000; scratch 256; `proto`/`frame_*`/`callsub`/`retsub` depth and frame maths; cost charged **before** execution; pooled `GroupBudget` across outer and inner calls; `MaxAppProgramCost`, `LOGICSIG_BUDGET`; dynamic cost formulae | `data/transactions/logic/{assembler,eval,opcodes,ledger,frames}.go` |
| A-07 | AVM state, resources, boxes, inner txns | `algo-avm`, `algo-ledger` | Resource-sharing rules (pre-v9 vs v9+), `check_pre_shared_resources_access`; box MBR `2500 + 400·(name+size)`, `box_create`/`box_resize`/`box_splice`/`box_del` billing and read/write budget; `app_global_*`/`app_local_*` schema limits and key/value sizes; `itxn_*` depth 8 / count 256, inner fee pooling, inner `Sender` must be app account or rekeyed-to it, inner rekey, inner app create and `compute_inner_txn_id`; `gaid`/`gaids`; reentrancy; rollback of inner effects on sibling failure; ClearState error swallowing (see `CLAUDE.md`) | `data/transactions/logic/{resources,box,eval}.go`, `ledger/apply/application.go`, `ledger/internal/appcow*` |
| A-08 | AVM arithmetic & bytes | `algo-avm` | `b+ b- b* b/ b% bsqrt b| b& b^ b~`, leading-zero rules, 64-byte bounds; `divmodw`, `divw`, `mulw`, `addw`, `expw`, `exp`, `sqrt`, `shl`, `shr`; `extract*`, `replace*`, `substring*`, `concat`, `setbit`/`getbit`/`setbyte`/`getbyte`, `bitlen`, `itob`/`btoi` bounds; `MAX_STRING_SIZE` 4096; `json_ref`; `base64_decode` strictness | `data/transactions/logic/eval.go` |
| A-09 | AVM cryptographic opcodes | `algo-avm`, `algo-consensus-crypto`, `algo-falcon` | `ed25519verify`/`_bare` (ProgramData prefix!), `ecdsa_verify`/`pk_decompress`/`pk_recover` for secp256k1/r1 incl. low-S, recovery id, point-at-infinity; `vrf_verify`; `ec_*` on BN254/BLS12-381 — subgroup checks, infinity encoding, non-canonical field elements, `ec_map_to` hash-to-curve, `ec_multi_scalar_mul` length mismatch; `mimc`, `poseidon2`, `sumhash512`, `sha3_256`, `keccak256`, `sha512_256`, `sha512`; `falcon_verify` format and salt-version checks | `data/transactions/logic/{crypto,pairing}.go`, `crypto/` |
| A-10 | ARC-4 ABI | `algo-abi` | Recursive type-string parser depth and allocation; `ufixed` precision bounds; dynamic-array/tuple head/tail offsets out of range; method selector; JSON↔binary; use from REST box-name decoding and `goal-rust` | `github.com/algorand/avm-abi/abi/` |
| A-11 | Agreement `BA*` | `algo-agreement` | Vote verification order (cheap checks before crypto); committee credential/sortition; soft/cert/next/late/redo/down thresholds; period/step bounds; proposal payload ↔ vote binding; equivocation detection and bundle verification; `Seed` and `Proposer` validation; fast recovery; pipelining; replay of old-round messages; memory bounds for future rounds; certificate verification for catchup | `agreement/` (`vote.go`, `proposal.go`, `bundle.go`, `player.go`, `state_machine*.go`, `cryptoVerifier.go`) |
| A-12 | Sortition, VRF, participation keys | `algo-consensus-crypto` | Binomial CDF / sortition numerics vs reference (fixed-point or big-float?); VRF proof-to-hash; one-time signature key dilution, batch index, expiry; `StateProofPK` commitment; sumhash Merkle trees; state-proof verification (`stpf`) weights and reveal rules | `data/committee/sortition/`, `crypto/vrf*.go`, `crypto/onetimesig.go`, `crypto/merklearray/`, `crypto/stateproof/` |
| A-13 | Falcon-1024 (`DIV-001`) | `algo-falcon` | Pure-Rust `det1024` vs vendored C: IEEE-754 vs `FALCON_FPEMU`, `fpr_expm_p63`, Gaussian sampler, FFT rounding, CT↔compressed conversion, salt version, signature length bounds, decode of non-canonical encodings; all `unsafe` in `src/rs/`; the C backend FFI boundary | `crypto/falconWrapper.go`, `github.com/algorand/falcon` |

### 3.2 Smart-contract platform rule catalogue (P4)

The following rules are what contract authors rely on. For whichever AVM/ledger area you audit, walk this list and record each rule as **verified PASS (file:line)**, **finding**, or **not examined**. Do not skip the list because "tests exist": your job is to check that the tests test the right thing against the right oracle.

1. **Authorization.** The authorizer of a txn is `AuthAddr` if set, else `Sender`; `RekeyTo` takes effect after this txn; rekey to self clears `AuthAddr`; LogicSig address must equal the authorizer; multisig address derived from version/threshold/pks; a LogicSig delegated by a rekeyed account is checked against the new auth-addr. Inner txns: sender must be the app account or an account rekeyed to it.
2. **Fees.** `MinTxnFee`; fee pooling across the group only, not across inner trees except via the credit rules in `itxn`; `FeeSink` exemption; inner txn fee defaults; LogicSig programs can read `txn Fee` but the fee is validated by the node, not the program.
3. **MBR.** Base MBR, per-asset, per-app (created and opted-in), per-schema entry, extra pages, boxes; checked at the end of each txn (not group) except where the protocol says otherwise; v43 `CloseRequiresBaseMinBalance`; MBR of the **app account** on `box_create`/`box_resize` inner calls; MBR not charged twice or refunded twice on delete.
4. **Group atomicity.** Any failure (including inner txn, including ClearState *not* failing) rolls back all state of the group; no partial `ApplyData`; `TxnCounter` and ID allocations rolled back; box/box-ref budget reset.
5. **Opt-in / close-out / clear-state.** `OptIn` to an app you're in; `CloseOut` requires approval; `ClearState` always succeeds in opting out even if the program errors or exceeds budget; local state deleted exactly once; asset close-to with frozen holdings; `AssetCloseTo` to a non-opted-in account; close-to to self.
6. **Assets.** Default-frozen; freeze by freeze address only; clawback by clawback address only and bypasses freeze; zero-amount transfers as opt-in; manager/reserve/freeze/clawback can be set to zero (immutable) and never re-set; total supply bounds; decimals bounds; unit/asset name/URL lengths; metadata hash length; destroy requires all units in creator.
7. **Applications.** `OnCompletion` matrix for create; `ExtraProgramPages`; `MaxAppProgramLen`; `MaxAppArgs`/`MaxAppTotalArgLen`; `MaxAppTxnAccounts`/`ForeignApps`/`ForeignAssets`/`Boxes` and the combined `MaxAppTotalTxnReferences`; app account address derivation; `global CurrentApplicationAddress`; update/delete authorization is by program, not by creator; deleted app's boxes and the MBR implications; `app_params_get`/`acct_params_get`/`asset_params_get` on deleted/nonexistent targets.
8. **Boxes.** Name length 1–64, size ≤ `MaxBoxSize`; read/write byte budget per txn and across group via box refs; box ref to app 0 meaning current app; boxes of deleted app; `box_create` existing (returns 0, no change); `box_put` size mismatch error; `box_splice`/`box_resize` v10+ gating.
9. **Inner transactions.** Depth 8, count 256; which fields are settable per type; `itxn_field` type validation; default `FirstValid`/`LastValid`; inner `appl` create returning created id via `gaid`/`itxn CreatedApplicationID`; inner rekey and its effect on later inner txns; inner `keyreg`; inner `afrz`/`acfg`; log limits (`MaxLogCalls`, `MaxLogSize`) across inner tree.
10. **Global/transaction fields.** `global` fields per version (`OpcodeBudget`, `CallerApplicationID`, `CallerApplicationAddress`, `AssetCreateMinBalance`, `AssetOptInMinBalance`, `GenesisHash`, `PayoutsEnabled` and payout params v40+); `txn`/`gtxn`/`itxn`/`gitxn` field availability per version and mode; `txnas`/`gtxnsas` bounds; `block` opcode fields incl. v11+ `BlkProposer`, `BlkFeesCollected`, `BlkBonus`, `BlkBranch`, `BlkFeeSink`, `BlkProtocol`, `BlkTxnCounter`, `BlkProposerPayout`.
11. **Budget.** 700 per app call, pooled across group app calls; inner app calls add 700 each; LogicSig `LogicSigMaxCost` 20,000, pooled across the group only from consensus v39 (`EnableLogicSigCostPooling`); dynamic costs charged before the operation; `OpcodeBudget` reads the pooled remainder.
12. **Determinism of program-visible data.** `global Round`, `LatestTimestamp`, `block` fields, `global GroupID`, `global CreatorAddress` must be identical across implementations; no wall-clock or RNG leakage into evaluation.
13. **Versioning.** A program with version > `logic_sig_version` of the current consensus rejected at validation; `MinAvmVersion` for inner txns; program version derived from the first varint; `#pragma` irrelevant to node.
14. **Developer-tooling fidelity (P8).** For each of the above, `simulate` (with `allow-more-logging`, `allow-empty-signatures`, `extra-opcode-budget`, `exec-trace-config`) and `dryrun` must report the same outcome, cost and `EvalDelta` as consensus apply, except where go-algorand itself documents a difference.

### 3.3 Tier 2 — network, mempool, runtime services, storage

| Id | Area | Crate(s) | What to attack | go-algorand oracle |
|---|---|---|---|---|
| A-14 | Transaction pool & ingestion | `algo-pool`, `algo-txn-pipeline` | Eviction and fee priority under flood; replacement rules; group atomicity in pool; lease collisions; re-validation cost per round (quadratic?); duplicate/`TxID` cache; batch verification fallback on one bad signature; backpressure vs unbounded channels; `MaxTxnLife` expiry; pool memory cap | `data/pools/transactionPool.go`, `data/txHandler.go`, `data/txDupCache.go` |
| A-15 | WebSocket gossip | `algo-network` | Handshake/version negotiation; message tag dispatch; size caps per tag; per-peer rate limits (`docs/NETWORK_RATE_LIMITING.md`); dedup filters; slow-loris; FD limits; peer scoring/banning; outgoing queue bounds; TLS/`X-Algorand-*` headers; block service request bounds; relay vs non-relay behaviour | `network/wsNetwork.go`, `network/wsPeer.go`, `network/limitlistener`, `rpcs/` |
| A-16 | libp2p transport | `algo-p2p` | Peer identity/private key storage; gossipsub topic validation and scoring; DHT/peerstore poisoning; stream limits; interop with WebSocket relays (dual-stack) | `network/p2p/`, `network/p2pNetwork.go` |
| A-17 | Catchup & catchpoints | `algo-ledger`, `algo-rest-client`, `algo-network` | Catchpoint label parsing; chunk verification against the label hash **before** any state is written; Merkle proofs; partial-download cleanup; peer banning on bad data; `rounds` ordering; certificate verification during block catchup; disk-space exhaustion; SQLite transactions spanning catchup | `catchup/`, `ledger/catchupaccessor.go`, `ledger/catchpointtracker.go` |
| A-18 | REST API v2 | `algo-rest-api` | Token comparison constant-time; admin vs public route table (shutdown, catchup, participation keys, `ready`, metrics); body size limits; `simulate`/`dryrun` CPU and memory bounds; pagination `limit`/`next` validation; msgpack vs JSON encoders producing identical semantics; `format=msgpack` path for every endpoint; error leaking internal paths; CORS; `/v2/blocks/{round}?format=msgpack` byte-exactness; `/genesis`; `/health`/`/ready` semantics; `/v2/accounts/{a}?exclude=` | `daemon/algod/api/server/v2/handlers.go`, `daemon/algod/api/algod.oas2.json` |
| A-19 | KMD & key tooling | `algo-kmd`, `bin/kmd-rust`, `algokey-rust`, `goal-rust` | Wallet encryption (`scrypt` params, `crypto_secretbox` nonce reuse), master derivation key handling, handle expiry, token enforcement, `ZeroizeOnDrop` for every secret type, `Debug`/`Display`/`tracing` leakage, file mode `0600`, mnemonic checksum, deterministic key derivation parity | `daemon/kmd/`, `cmd/algokey/`, `libgoal/` |
| A-20 | Configuration & versions | `algo-config`, `algo-types` consensus tables | `config.json` defaults vs `config/defaults.go` (**every** field, cf. `docs/PHASE16_VALIDATION.md`); unknown-field handling; consensus table per protocol string; behaviour on unknown future protocol (halt, never guess); `vFuture` never reachable on MainNet; `FalconBackend` switch | `config/`, `config/consensus.go`, `protocol/consensus.go` |
| A-21 | Persistence & crash recovery | `algo-ledger` (`sqlite.rs`, snapshot) | Transaction boundaries per round; fsync/journal mode; crash between block write and tracker write; zstd snapshot decode bounds; startup consistency check; disk-full handling; schema migration; concurrent readers (REST) vs writer | `ledger/store/`, `ledger/tracker.go`, `ledger/acctupdates.go` |
| A-22 | Node runtime & concurrency | `bin/algod-rust`, all async glue | Lock ordering across ledger/pool/agreement/network; `std::sync::Mutex` held across `.await`; `RwLock` writer starvation; `tokio::select!` cancellation safety; unbounded `mpsc`; task panics silently aborting a subsystem; shutdown ordering; signal handling; time source (monotonic vs wall) | n/a (soundness, §6 M7) |

### 3.4 Tier 3 — tooling, CI, supply chain

| Id | Area | What to attack |
|---|---|---|
| A-23 | CLI tools (`goal-rust`, `algokey-rust`, `algo-netdeploy`, `algo-fork-detector`) | Key material on stdout/logs/argv; temp files; input sanitization; default file modes; `DIV-002` claim holds |
| A-24 | Dependencies & build | `cargo deny check` (`deny.toml`), `cargo audit`, unmaintained crypto crates, `unsafe` in transitive deps on consensus paths, `build.rs` network access, pinned `Cargo.lock`, `rust-toolchain.toml`, release profile (`lto`, `codegen-units`, `overflow-checks`, `debug-assertions`), `scripts/check_debug_assertions.py` |
| A-25 | CI & release integrity | Workflow permissions, third-party actions pinned by SHA, secrets exposure, Docker image provenance, that conformance/fuzz/parity workflows actually gate merges |

### 3.5 Deliberate divergences

`docs/DIVERGENCES.md` registers every intended difference from go-algorand (`DIV-001` pure-Rust Falcon, `DIV-002` `goal node pendingtxns` output, …). Before reporting any difference, grep `DIVERGENCE DIV-` and read the entry. A registered divergence is **not a finding**. What *is* in scope: does the implementation uphold the entry's "Wire / consensus impact: none" claim, and is the evidence it cites real and sufficient? If not, that is a finding against the divergence's proof, not against its existence.

---

## 4. Severity, likelihood, confidence

### 4.1 Severity matrix

| Impact \ Likelihood | **High** — any T1/T2/T3/T6 adversary, automated, no special state | **Medium** — needs stake, specific chain state, timing or race | **Low** — theoretical, extreme preconditions |
|---|---|---|---|
| **Critical impact** — consensus split, unauthorized spend/mint, signature/certificate forgery, key extraction, RCE/memory corruption | 🔴 **CRITICAL** | 🔴 **CRITICAL** | 🟠 **HIGH** |
| **High impact** — remote crash/halt/OOM of a node, permanent liveness stall, MBR/fee/budget bypass, a contract rule (§3.2) enforced differently | 🟠 **HIGH** | 🟠 **HIGH** | 🟡 **MEDIUM** |
| **Medium impact** — asymmetric resource amplification, non-admin API auth flaw, info disclosure, single-peer wedge, developer-tooling result differing from consensus | 🟡 **MEDIUM** | 🟡 **MEDIUM** | 🔵 **LOW** |
| **Low impact** — spec deviation without consensus effect, CLI mismatch, defence-in-depth gap | 🔵 **LOW** | 🔵 **LOW** | ⚪ **INFO** |

Rules of thumb:

- **Any P1 divergence on a reachable input is Critical**, regardless of how contrived the input. "Reachable" means a T2 or T3 adversary can put it in a block.
- A divergence that only exists in `simulate`/`dryrun`/REST (P8) is one level below the consensus equivalent.
- A panic reachable from T1/T2/T3 is at least High. A panic reachable only from T6-with-admin-token or T7 is Medium.
- Missing test coverage is Informational unless you show the untested path is wrong.

### 4.2 Confidence (mandatory on every finding)

| Confidence | Meaning | Required for |
|---|---|---|
| **Confirmed** | A PoC (test, script, byte vector, or dual-node run) demonstrates the behaviour on the current commit | Any Critical; any High reported as `Open` |
| **Likely** | Code reading shows the defect unambiguously; PoC not built (explain why) | High may be reported as `Likely` only with a line-by-line trace in the report |
| **Speculative** | A suspicious pattern; could not confirm or rule out in this run | Goes to §7.9 Open questions, **not** to Findings |

A Critical without a PoC must be downgraded to `Likely`/High and marked for immediate maintainer verification. This is how we keep reports from different auditors comparable: severity is driven by evidence, not by the auditor's prose.

### 4.3 De-duplication across reports

Before writing a finding, grep every prior report in `audits/reports/` and the `Linked Audit Findings` column of `risks.md` for the same file/function. If it was already reported: reference the earlier id (`Duplicate of FIND-<hash>-NN`), state whether it is still present at the current commit, and do not count it as new in the summary table. Re-confirming an old finding still exists is valuable and goes in §7.6 (Regression check).

---

## 5. Selecting a scope for this run

Depth beats breadth. A run that fully audits two Tier-1 areas with PoCs is worth more than one that skims all 25.

1. Read `audits/coverage.md`. For each area, note `Last audited commit`, `Last audited (UTC)`, and `Methodologies`.
2. Run `git log --oneline <last-audited-commit>..HEAD -- <area paths>` for each area; areas with consensus-relevant changes since their last audit go to the top.
3. If the user named a scope (crate, PR, issue, area id, "delta since last audit"), use it.
4. Otherwise pick, in this order, until you have 2–4 areas: Tier-1 areas never audited → Tier-1 areas with changes since last audit → Tier-1 areas by oldest `Last audited` → Tier-2 by the same rules → Tier-3.
5. **Every run additionally includes a delta review**: read the full diff of every commit to `crates/core/**` since the most recent report's commit (or the last 30 commits if there is none) looking for the §6 M1/M2 anti-patterns. Record it in the report as area `A-00 Delta`.
6. State your chosen scope and the reason in §7.1 of the report before you start auditing, so that the choice is not retro-fitted to what you happened to find.

---

## 6. Methodologies

Each run applies **at least four** of M1–M8, and **always** M1 and M2 when any Tier-1 area is in scope. For every methodology record in §7.3 the exact commands run, files and line ranges read, and oracles compared. "I reviewed the AVM" is not a log entry; `Read crates/core/algo-avm/src/ops/itxn.rs:1-612 against ../go-algorand/data/transactions/logic/eval.go:5210-5610 (opItxnSubmit)` is.

### M1 — Differential specification analysis (Go ↔ Rust)

For each function on the chosen path, place the Rust and the pinned Go side-by-side and check **every** branch, early return, version gate, error string that is consensus-visible, and arithmetic operation.

Hunt list (each is a historical cause of client splits in some blockchain):

- `saturating_*`/`wrapping_*` where Go uses `basics.OAdd`/`OSub`/`OMul` and fails, or checked arithmetic where Go wraps.
- `as` casts (`u64 as usize`, `i64 as u64`, `u64 as u32`) truncating or sign-flipping consensus values; 32-bit `usize` assumptions.
- `HashMap`/`HashSet` iteration feeding any hash, delta ordering, or encoding; `BTreeMap` with a `Ord` that differs from Go's sort.
- Version gates: a check that Go performs only when `proto.X` is true, done unconditionally in Rust or vice versa; parameters read from the wrong round's consensus version (block's vs. next round's); `vFuture` leakage.
- Order of checks when both fail: which error wins matters for `simulate`, and sometimes for whether a txn is "well-formed" vs "invalid" (pool vs block).
- Partial mutation before a later check fails; state written then "undone" by a path that is not exactly inverse.
- Zero-value semantics: Go's `omitempty` zero-value, nil vs empty slice, zero address, zero `AssetID`/`AppID` meaning "current".
- Floating point anywhere near consensus (sortition, Falcon, rewards). Rust `f64` and Go `float64` both IEEE-754 but transcendental functions and FMA contraction differ.
- String/bytes handling: UTF-8 validation where Go accepts raw bytes; length in chars vs bytes.
- Time: wall clock in a consensus decision; `Duration` overflow; leap seconds.
- Error swallowing: `let _ =`, `.ok()`, `if let Ok(..)` on a consensus path where Go propagates.
- Anything not covered by a test row in `docs/PHASE17_TEST_PARITY.md` that maps to a Go test asserting a security property.

Use go-algorand's own tests as attack vectors: `data/transactions/logic/*_test.go`, `ledger/apply/*_test.go`, `data/transactions/verify/*_test.go` contain the edge cases upstream considered dangerous. Port a handful to algod-rust as PoC checks when the Phase 17 map says they are `matched` but you doubt the match is semantic.

### M2 — Static analysis, panic surface, `unsafe`, soundness lints

- `unsafe`: enumerate every block (`grep -rn "unsafe" crates bin --include=*.rs`). For each: safety comment present and *true*; alignment, bounds, lifetimes, aliasing, `Send`/`Sync` impls, FFI null/length contracts, `from_raw_parts` lengths, `transmute`, `MaybeUninit`, `static mut`. The Falcon `src/rs/` and `c.rs`, `algo-ledger/src/sqlite.rs`, `algo-network/src/fd_limits.rs`, `algo-types/src/serde_bytes_array.rs` are known hot-spots.
- Panic surface in non-test code of Tier-1/2 crates reached from T1–T6 inputs: `.unwrap()`, `.expect()`, `[i]`/`[a..b]` indexing, `/`, `%`, `<<`, `>>` with attacker-influenced operands, `unreachable!`, `assert!`, `panic!`, `.try_into().unwrap()`, `u32::try_from(..).unwrap()`, `Vec::with_capacity(attacker_len)`, recursion on attacker-shaped input. Trace at least the top five candidates to their ingress point and either prove unreachable (with the guard's file:line) or report.
- Lossy casts and overflow: `cargo clippy --workspace --all-targets -- -W clippy::cast_possible_truncation -W clippy::cast_sign_loss -W clippy::arithmetic_side_effects` restricted to consensus crates; inspect each hit on a consensus path.
- Release-profile semantics: `overflow-checks` and `debug-assertions` in `Cargo.toml [profile.release]`; `python3 scripts/check_debug_assertions.py`; any `cfg!(debug_assertions)` that changes behaviour.
- Supply chain: `cargo deny check` (see `deny.toml`), `cargo audit` if installed, `cargo tree -i <crate>` for crypto/serialization crates, `build.rs` contents, `git`/`path` dependencies, features that disable constant-time or validation code.

### M3 — Cryptographic verification

- Domain separation: every `hash(prefix || bytes)` and every signature `verify(prefix || bytes)` uses the exact prefix the reference uses; no two prefixes collide; the prefix is **not** attacker-suppliable.
- Canonicality and malleability: Ed25519 small-order / non-canonical `S` / non-canonical point handling must match go-algorand's libsodium-backed verification (`crypto/` single and batch paths) **exactly** on every input, including inputs where single and batch verification could disagree; a signature accepted by one implementation and rejected by the other is a fork; VRF proof uniqueness; multisig subsig ordering; Falcon CT/compressed canonical form; secp256k1/r1 recovery and low-S; BN254/BLS12-381 point canonicality, subgroup membership, infinity encoding.
- Constant-time and zeroization: API/KMD token compare (`subtle`), password/MDK handling, `ZeroizeOnDrop` on every secret struct, no `Debug` derive on secret types, no secret in `tracing`/`log`/error strings/panic messages, no secret in `Clone` copies that escape zeroization.
- Randomness: where the node needs randomness (participation key generation, libp2p identity, KMD) it uses an OS CSPRNG; nowhere does randomness reach consensus evaluation.
- Vectors: run `cargo test -p algo-falcon` with vectors, `digest_test`, `teal_vectors`, state-proof vectors; add adversarial vectors for any edge you find untested.

### M4 — Fuzzing and property testing

- Existing targets: `fuzz/fuzz_targets/` (`fuzz_account_roundtrip`, `fuzz_apply_transaction`, `fuzz_avm_context`, `fuzz_teal_program`), `crates/tools/algo-agreement-fuzz`, proptests in `algo-agreement`, `algo-avm`, `algo-types`, `.github/workflows/nightly-fuzz.yml`. Read each harness: what does it actually reach? Is the oracle "doesn't panic" or "equals go-algorand"? A fuzzer that never passes `check_program` tests nothing in the evaluator.
- Gaps to look for and (if you can) fill with a new harness in `audits/poc/<report-id>/` (never in the workspace during an audit run): gossip frame decoders, vote/proposal/bundle decoders, catchpoint chunk parser, ABI type parser, REST request bodies (`simulate`), msgpack-with-trailing-data, block header decoder, participation key file parser.
- Boundary vectors to try by hand where no fuzzer exists: `u64::MAX`, `0`, `-1 as u64`, empty bytes, 4096/4097 byte strings, 1000/1001 stack depth, 8/9 inner depth, 256/257 inner count, 64/65-byte bignums, `MaxTxnBytesPerBlock ± 1`, round 0 / round `u64::MAX`, `FirstValid > LastValid`, group of 16/17, 255/256 scratch slot.
- Differential fuzzing: if a go-algorand binary is available (see `docs/MIXED_CLUSTER_HARNESS.md`, `crates/tools/algo-conformance`), run the same corpus through both and diff results; this is the strongest P1 evidence an auditor can produce.

### M5 — Adversarial consensus and network fault injection

Model T1, T4, T5 explicitly:

- Equivocation: same `(round, period, step)` two proposals / two votes; does the node count the credential once? Does it propagate both? Is the equivocation bundle verified before relaying?
- Future/past flood: votes for round `r+1000`, period `p+1000`; memory per peer; eviction order; does verification of future votes happen before the committee can be known (stake for round `r+1000` unknown)?
- Replay: a valid vote from an old round re-sent; a certificate for round `r` presented during catchup at `r+1`.
- Proposal payload: payload for a vote never seen; payload whose hash ≠ the voted hash; payload > size cap; payload with invalid `Seed`/`Proposer`; payload arriving after certification.
- Timing: `MaxTimestampIncrement` and the local clock; period timeouts manipulated by clock skew; fast-recovery triggers.
- Catchup: label of a catchpoint for a different genesis; chunk count mismatch; valid label with an invalid chunk late in the stream (is earlier state already committed?); peer that stalls mid-chunk.
- Resource: connection slots, FD budget (`fd_limits.rs`), per-peer send queue, block-service request amplification (small request → large response).

Where the live harnesses exist (`docs/MIXED_CLUSTER_HARNESS.md`, `.github/workflows/agreement-multinode.yml`, `p2p-*`), use them to confirm a hypothesis rather than reason about it.

### M6 — Economic, metering and DoS analysis

- For each heavy opcode (`ec_pairing_check`, `ec_multi_scalar_mul`, `ec_map_to`, `mimc`, `poseidon2`, `falcon_verify`, `vrf_verify`, `sumhash512`, `json_ref`, `box_*`, `b*`/`b/` on 64-byte operands, `base64_decode`): measure or estimate CPU for the worst-case input against its protocol cost; compare with `algo-bench` results in `docs/BENCHMARKS.md`. The protocol cost is fixed (`RISK-EXT-008`), but an algod-rust implementation **slower than go-algorand** on a worst-case input is a liveness risk and a finding.
- MBR/fee/budget arithmetic: can any sequence (§3.2 items 2, 3, 8, 9, 11) leave state allocated without MBR, double-refund, underflow, or allow spending the budget twice?
- Pool/validation amplification: cost to the node per byte submitted by T2 for the cheapest-to-send, most-expensive-to-validate transaction (e.g. maximal multisig, maximal LogicSig, maximal group, maximal `Boxes` refs).
- Storage amplification: boxes, logs, app pages, note fields, catchpoint files, SQLite growth per block vs fee paid.

### M7 — Code soundness and robustness (new in 2.0)

Not every security bug is a parity bug. This methodology is about whether the code is *sound* as engineering:

- **Concurrency.** Every `Mutex`/`RwLock`: lock order documented and consistent; never held across `.await`; no `std` lock in async context on hot paths; `tokio::select!` arms cancellation-safe; `JoinHandle`s awaited or detached deliberately with panic handling; bounded vs unbounded channels and what happens when full; atomics with correct `Ordering`; `Arc<Mutex<_>>` cycles.
- **Error handling.** No `let _ = fallible()` on a path that matters; errors carry enough context; `?` on `std::io` in a consensus path converting to the correct outcome (fail closed); panics in spawned tasks surfaced rather than silently killing a subsystem; shutdown drains and flushes.
- **Resource lifecycle.** Files/sockets/DB statements closed on every path; temp files cleaned; disk-full and `ENOSPC` handled; memory growth proportional to protocol-bounded quantities only.
- **Determinism hygiene.** No `std::time::SystemTime`, `rand`, `HashMap` iteration, environment variables, locale, or platform-specific behaviour (`usize` width, path separators, line endings, CRLF fixtures — see `CLAUDE.md`) inside `crates/core/*` evaluation code.
- **Type safety.** Newtypes for `Round`, `MicroAlgos`, `AssetIndex`, `AppIndex` used consistently; no bare `u64` where mix-ups are possible on a consensus path; `#[must_use]` on results that guard state.
- **Persistence (P7).** Identify every write path to disk; for each, the crash window and the recovery code that handles it. SQLite journal mode, `PRAGMA synchronous`, transaction scope per round, ordering between block store and account tracker, snapshot write-then-rename.
- **API contracts.** OpenAPI (`docs/`/`validate-api`) vs implementation: every documented error code, every `required` field, every enum value.
- **Test quality.** For the audited area, read the tests the project cites as evidence (`docs/PHASE*_VALIDATION.md`, `docs/phase17/parity_*.md`). Does each assert the property, or just "no panic"? Does it use a go-algorand-derived oracle or a Rust-computed expectation (which would be circular)?

### M8 — Developer-tooling fidelity (new in 2.0)

For the audited AVM/ledger rules, construct 3–10 contract scenarios (as TEAL + txn groups) exercising the rule's edge and compare: consensus apply (`algo-ledger`), `simulate`, `dryrun`, and if available go-algorand. Specifically check: `EvalDelta` contents and ordering; `logs`; `inner-txns` tree; `budget-consumed`/`budget-added`; `failure-message` and `failed-at`; `exec-trace` stack/scratch snapshots; `unnamed-resources-accessed`; `app-budget-consumed`. A mismatch is a P8 finding. Also verify `compile` → `disassemble` → `compile` is a fixed point and that source maps point to the right PCs.

---

## 7. Report contract

### 7.1 File location and name

```text
audits/reports/YYYY-MM-DD_HHMMSS_<auditor-tag>_<git-short-hash>.md
```

- `YYYY-MM-DD_HHMMSS`: **UTC** time the run started (`date -u +%Y-%m-%d_%H%M%S`).
- `<auditor-tag>`: lowercase kebab-case, identifies the auditor *and* the model/team, so reports from different models are distinguishable: e.g. `claude-fable-5-1`, `gpt-5-sec`, `gemini-3-audit`, `trailofbits-jdoe`, `independent-asmith`. Do not use a generic `ai-sec-auditor`.
- `<git-short-hash>`: `git rev-parse --short HEAD` of the audited tree. If the tree is dirty, say so in §7.2 metadata and list the dirty paths.

PoC artefacts (test files, byte vectors, scripts, TEAL) go in `audits/poc/<report-id>/` where `report-id` is the filename stem. **Never modify files under `crates/`, `bin/`, `fuzz/` or `docs/` during an audit run.** Audits observe; fixes are separate PRs.

### 7.2 Template (mandatory, all nine sections, in this order)

```markdown
# Algod-Rust Security Audit Report

## 1. Metadata & provenance
| Field | Value |
|---|---|
| Report ID | `AUDIT-YYYYMMDD-HHMMSS-<auditor-tag>` |
| Start / end (UTC) | `YYYY-MM-DDTHH:MM:SSZ` / `YYYY-MM-DDTHH:MM:SSZ` |
| Auditor tag | `<auditor-tag>` |
| Auditor type | human / AI agent (model id and vendor) |
| Target commit | `<short>` (`<full sha>`), branch `<name>`, tree clean / dirty (`<paths>`) |
| Upstream pin | `go-algorand v5.0.4-stable` (`git -C ../go-algorand rev-parse HEAD` = `<sha>`) |
| Scope (area ids) | `A-00 Delta, A-06, A-07, …` and why (per §5) |
| Methodologies | `M1, M2, M4, M7` |
| Toolchain | `rustc --version`, `cargo --version`, OS |
| Effort | wall-clock hours or agent turns/tokens, whichever applies |

## 2. Executive summary
Five to fifteen sentences: posture of the audited areas, the most important finding, the most important verified invariant, what a maintainer should do first.

| Severity | New | Duplicate (still present) | Mitigated since last report |
|---|---|---|---|
| 🔴 Critical | 0 | 0 | 0 |
| 🟠 High | 0 | 0 | 0 |
| 🟡 Medium | 0 | 0 | 0 |
| 🔵 Low | 0 | 0 | 0 |
| ⚪ Informational | 0 | 0 | 0 |
| **Total** | **0** | **0** | **0** |

## 3. Scope & methodology execution log
Per methodology: exact commands (fenced), files and line ranges read, go-algorand files and line ranges compared, tests/fuzzers run with their output summary, harness runs. This section is what lets the next auditor avoid redoing your work and lets a maintainer reproduce your evidence.

## 4. Findings
Ordered by severity, then confidence. Ids `FIND-<git-short-hash>-01`, `-02`, …

Every finding **must** explicitly state in its metadata header (`Affected implementations`) and in its `Description & root cause` whether the issue exists:
- **`algod-rust only`** — a divergence, regression, or Rust-specific flaw where `go-algorand` (`v5.0.4-stable`) behaves safely/correctly, OR
- **`both go-algorand and algod-rust`** — a shared upstream protocol/implementation flaw present in both `go-algorand` (`v5.0.4-stable` or its Go dependencies such as `avm-abi`) and `algod-rust` (see §8.4 and `RISK-EXT-001` for handling rules: never unilaterally break consensus parity to fix a shared consensus bug).

### [FIND-<hash>-01] <Title: what breaks, in one line>
- **Severity:** 🔴/🟠/🟡/🔵/⚪ · **Impact:** … · **Likelihood:** … · **Confidence:** Confirmed / Likely
- **Affected implementations:** `algod-rust only` | `both go-algorand and algod-rust`
- **Property:** P1–P9 · **Adversary:** T1–T9 · **Area:** A-NN · **Category:** Consensus parity / Cryptography / Panic DoS / Resource DoS / Contract rule / Memory safety / Concurrency / Persistence / Auth / Tooling fidelity / Supply chain
- **Location:** `crates/.../file.rs:L10-L42` (function `name`)
- **Upstream reference:** `../go-algorand/path/file.go:L100-L130` (function `Name`)
- **Risk registry:** `RISK-INT-NNN` (existing) or `NEW → RISK-INT-NNN` (added in this run)
- **Duplicate of:** `FIND-<hash>-NN` from `<report file>` / none
- **Status:** Open / Acknowledged / Mitigated

#### Description & root cause
State clearly upfront whether this issue exists **only in `algod-rust`** or **in both `go-algorand` and `algod-rust`**. Explain what the Rust code does, what the Go reference does, and why they differ (if `algod-rust only`) or why both implementations share the vulnerability (if `both go-algorand and algod-rust`). Quote the decisive lines of both.

#### Exploit scenario / proof of concept
Concrete steps or a test in `audits/poc/<report-id>/`. For P1: the input bytes or TEAL, the go-algorand result, the algod-rust result. For DoS: the input and the observed effect (panic message, memory, time). For Likely: the line-by-line trace that stands in for a PoC and what prevented building one.

#### Impact on builders
One paragraph: what a smart-contract developer or user would experience. ("A contract that relies on X to protect funds in Y is drainable on algod-rust nodes by Z.")

#### Remediation
Surgical fix, the regression test to add, and which `docs/phase17/parity_*.md` row or `docs/PHASE*_VALIDATION.md` evidence should be updated.

## 5. Verified invariants
Table: `Property | Rule (from §3.2 or §1.1) | Evidence (file:line, test name, command) | Oracle (go-algorand file:line / vector / live run)`. Only list what you actually verified in this run. This table is what gives the project cumulative assurance; be precise.

## 6. Regression check of prior findings
For each `Open`/`Acknowledged` finding in earlier reports that touches your scope: still present at this commit (file:line) / fixed (commit) / not re-examined.

## 7. Coverage delta (`audits/coverage.md`)
Which `A-NN` rows you updated and to what.

## 8. Risk registry delta (`audits/risks.md`)
Rows added, residual-risk changes, status changes, Audit History row appended.

## 9. Open questions & not covered
Speculative observations (Confidence: Speculative), areas you intended to cover and did not, assumptions you made, anything a follow-up auditor should pick up first.
```

### 7.3 Quality bar (reports failing these are returned)

- Every location is a real path and line range at the audited commit, re-read during the run.
- Every finding explicitly states whether the issue exists **only in `algod-rust`** (`algod-rust only`) or **in both `go-algorand` and `algod-rust`** (`both go-algorand and algod-rust`), with `go-algorand` file:line evidence verifying upstream's behavior.
- No finding without a Confidence rating; no Critical without Confirmed.
- No "may", "could potentially", "it is possible that" in a finding's title or description without the concrete condition under which it happens; speculative material belongs in §9.
- No fabricated commands, outputs, or test names. If a command could not be run (e.g. no go-algorand binary on the machine), say so.
- No finding that is a registered divergence (§3.5) or a documented intended behaviour (`CLAUDE.md`, `docs/DIVERGENCES.md`) unless the documented proof is shown to be wrong.
- The verified-invariants table has at least as many rows as the findings section. An audit that finds nothing and verifies nothing has not happened.
- The report is self-contained for a reader who was not present: no "as discussed", no references to chat context.

---

## 8. Disclosure and handling of exploitable findings

`xarmian/algod-rust` is a **public** repository. Committing a report that contains a working exploit for a Critical or High finding publishes the exploit to everyone, including attackers, before operators can patch. Therefore:

1. **Critical and High findings with Confirmed confidence are embargoed.** Write the full report, but **do not commit or push** it, and do not open a public GitHub issue for it. Deliver it privately to the maintainers (the Algod DAO security contact named in `SECURITY.md` if present, otherwise the repository owner via a private channel). For an AI agent: write the file, then stop and tell the user in the final message exactly which findings are embargoed and that the report must not be committed yet. Do not commit the embargoed report or file the issue yourself.
2. Medium and below, and Likely/Speculative items, may be committed with the report and filed as GitHub issues labelled `security` with the usual team label (`algod-issue-create` skill for agents).
3. Once a fix for an embargoed finding is merged and operators have had a reasonable upgrade window (maintainers decide; default 14 days after the release containing the fix), the embargoed report is committed unchanged, with a `## 0. Disclosure note` prepended giving the fix commit and release.
4. Findings that are **also present in go-algorand** (shared protocol bugs, `RISK-EXT-001`) are reported to Algorand's security process first; algod-rust must not fix them unilaterally (a unilateral fix is a fork). The report records them as `Status: Acknowledged — upstream`.

---

## 9. Keeping the registry and ledger in sync

Every run, in the same session as the report:

- **`audits/risks.md`:** update `Last Updated` and `Last Audited Commit`; add a `RISK-INT-NNN`/`RISK-EXT-NNN` row for each new risk class (not for each finding — a finding is an instance of a risk); put `FIND-<hash>-NN` ids in the `Linked Audit Findings` column of the risk each finding instantiates; adjust `Residual Risk`/`Status` where evidence justifies it (both directions — a strong verified-invariants table can lower residual risk); append a row to the **Audit History & Synchronization Log**.
- **`audits/coverage.md`:** for each `A-NN` you audited, set `Last audited (UTC)`, `Commit`, `Auditor tag`, `Methodologies`, `Report`, and `Depth` (`skim` = read-through only, `deep` = line-by-line with M1, `poc` = deep plus at least one PoC or new vector). Do not touch rows you did not audit.
- If a finding shows a `docs/PHASE*_VALIDATION.md` or `docs/phase17/parity_*.md` claim to be wrong, say so in the finding's Remediation; do not edit those docs in the audit run.

---

## 10. Automated workflow for `"do new audit"`

When a user says **"do new audit"**, **"run a new audit"**, **"perform security audit"**, or **"do new audit on `<scope>`"**, an AI agent executes exactly this sequence. Do not skip, reorder, or summarize-instead-of-do any step. Do not delegate the whole audit to a sub-agent; the auditing agent reads the code itself.

1. **Load state.** Read `audits/instructions.md` (this file), `audits/risks.md`, `audits/coverage.md`, and list `audits/reports/`. Read the two most recent reports in full (if any) so you can de-duplicate (§4.3) and run the regression check (§7.2 section 6).
2. **Provenance.** Run and record:
   ```bash
   git rev-parse --short HEAD && git rev-parse HEAD && git branch --show-current && git status -s
   git -C ../go-algorand describe --tags --exact-match && git -C ../go-algorand rev-parse HEAD
   date -u +%Y-%m-%d_%H%M%S
   rustc --version && cargo --version
   ```
   If the go-algorand checkout is not at `v5.0.4-stable`, stop and report that; do not audit against the wrong oracle.
3. **Choose the auditor tag** per §7.1: it must identify the model (e.g. `claude-fable-5-1`). If the user supplied a tag, use it.
4. **Choose scope** per §5 and write it down (area ids + justification) before reading any code in depth. Always include `A-00 Delta`.
5. **Audit.** Apply ≥ 4 methodologies (M1 and M2 mandatory for Tier 1). Work through the §3.2 catalogue for any AVM/ledger area. Trace untrusted input from its ingress to the sink for every panic/overflow candidate. Build PoCs for anything you want to call Critical or High; place them in `audits/poc/<report-id>/`. Run existing tests relevant to the area (`cargo test -p <crate>`), and read what they assert. Record every command and every file:line range as you go, not afterwards.
6. **De-duplicate** each candidate finding against prior reports and `risks.md` (§4.3).
7. **Write the report** at `audits/reports/YYYY-MM-DD_HHMMSS_<auditor-tag>_<git-short-hash>.md` with all nine sections of §7.2. Check it against §7.3 before saving.
8. **Update `audits/risks.md` and `audits/coverage.md`** per §9.
9. **Disclosure gate (§8).** If any finding is Critical or High with Confirmed confidence: do not commit, do not open issues; end with a clear message to the user listing the embargoed finding ids. Otherwise, file one GitHub issue per Medium+ finding (agents with repo access, via the `algod-issue-create` skill; include the `FIND-` id and report path; label `security`), and record the issue numbers in the report's findings.
10. **Final message** to the user: the report path, the severity table, the embargo status, which `A-NN` rows changed, and the single most valuable next audit scope.

---

## 11. Toolbox (commands that are known to work in this repository)

```bash
# Build/lint/test (Windows: see CLAUDE.md for the MSVC environment; prefer `make` targets)
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p algo-avm            # or any crate
cargo test --test digest_test
make lint                          # fmt-check + clippy + divergence register check
make deny                          # cargo deny check per deny.toml

# Project-specific checkers
python3 scripts/check_divergences.py
python3 scripts/check_debug_assertions.py
python3 scripts/phase17_parity_delta.py check --go-algorand ../go-algorand

# Static hunts (restrict to non-test, Tier-1/2 paths when reviewing results)
grep -rn "unsafe" crates bin --include=*.rs | grep -v -E "/tests?/|_test\.rs"
grep -rnE "\.unwrap\(\)|\.expect\(|unreachable!|panic!" crates/core/*/src crates/node/*/src --include=*.rs
grep -rnE "saturating_(add|sub|mul)|wrapping_(add|sub|mul)" crates/core/*/src --include=*.rs
grep -rnE "\bas (u8|u16|u32|u64|i32|i64|usize)\b" crates/core/algo-ledger/src crates/core/algo-avm/src crates/core/algo-validate/src --include=*.rs
grep -rnE "HashMap|HashSet" crates/core/algo-ledger/src crates/core/algo-avm/src crates/core/algo-types/src crates/core/algo-codec/src --include=*.rs
grep -rnE "SystemTime|Instant::now|thread_rng|rand::" crates/core/*/src --include=*.rs
grep -rnE "let _ =|\.ok\(\);" crates/core/algo-ledger/src crates/core/algo-validate/src crates/core/algo-agreement/src --include=*.rs
grep -rn "DIVERGENCE DIV-" crates bin

# Fuzzing (nightly toolchain required)
cd fuzz && cargo +nightly fuzz list && cargo +nightly fuzz run fuzz_teal_program -- -max_total_time=600

# Falcon differential tests against the vendored C
cargo test -p algo-falcon --features c-internals-test

# go-algorand oracle lookups
grep -rn "func opItxnSubmit" ../go-algorand/data/transactions/logic/
grep -n "CloseRequiresBaseMinBalance" ../go-algorand/config/consensus.go
```

Harnesses for live differential evidence: `docs/MIXED_CLUSTER_HARNESS.md`, `docs/MIXED_CLUSTER_RUNBOOK.md`, `docs/CONFORMANCE_STRATEGY.md`, `crates/tools/algo-conformance`, `crates/tools/algo-cert-crossverify`, `crates/tools/algo-fork-detector`.

---

## 12. Change log of this document

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-10-23 | Initial framework: five properties, Tier 1–3 matrix, M1–M6, severity matrix, report template, `do new audit` workflow. |
| 2.0 | 2026-10-23 | Added: explicit threat model (T1–T9); nine security properties incl. smart-contract platform integrity, persistence, developer-tooling fidelity and code soundness; stable area ids `A-00`–`A-25` with coverage ledger `audits/coverage.md`; smart-contract rule catalogue (§3.2); confidence ratings and PoC requirement for Critical/High; de-duplication and regression-check rules; M7 code soundness and M8 tooling fidelity; scope-selection algorithm; nine-section report template with quality bar; public-repo disclosure/embargo rule; model-identifying auditor tags; toolbox of verified commands. |
