# Epic: go-algorand ↔ algod-rust test parity audit

Tracks auditing algod-rust's test suite against go-algorand's, test by
test, across the entire pinned `v5.0.0-stable` reference — independent
of any single subsystem or version delta — and closing the real gaps
found. GitHub epic issue:
[#830](https://github.com/xarmian/algod-rust/issues/830). Full scope
and audit findings: [`docs/PHASE17_PROPOSAL.md`](../PHASE17_PROPOSAL.md).
Full evidence map: [`docs/PHASE17_TEST_PARITY.md`](../PHASE17_TEST_PARITY.md).

## Why this phase exists

Phases 0–16 built and hardened algod-rust subsystem by subsystem and
version-delta by version-delta, each scoped to a specific area or a
specific upstream diff. None asked the exhaustive question this phase
asks: for every test go-algorand actually has, does algod-rust have one
proving the same behavior? A gap predating every prior phase, or
falling between two phases' scopes, would never surface any other way.

## Headline findings

Of 3,177 go-algorand tests: 472 `matched-1:1`, 443 `matched-1:many`, 200
`matched-many:1`, 721 `partial`, 430 `missing-test`, 578
`not-implemented`, 333 `out-of-scope`. **1,115 real, actionable gaps.**

The largest: **AVM transaction-group resource-availability enforcement
does not exist at all** — no cross-transaction resource sharing (v9+),
no availability check on raw addresses, no `tx.Access`-based resolution
at runtime, despite the data model being fully implemented and
statically validated.

## Sub-issues (priority-first within each group)

**Correctness bugs:**
- [x] #808 — avm: implement transaction-group resource-availability enforcement (foreign-array-style sharing + raw-address gate) — **highest priority**; holding/local-state cross-product sharing and tx.Access resolution split to #841
- [x] #809 — avm/ledger: fix app-call guard correctness bugs — merged via PR #838
- [x] #810 — avm: add per-field version gating for global/txn/gtxn/asset_params_get/acct_params_get/block — merged via PR #840; found gap in v13+ block fields split to #839
- [x] #811 — avm: implement RekeyTo/ApplicationCall minimum-AVM-version rule — merged via PR #831
- [x] #812 — validate: add per-type WellFormed() mempool validation — merged via PR #837
- [x] #813 — consensus: reconcile Falcon-512 vs Falcon-1024 parameter-set naming — resolved-by-investigation, no bug found (false alarm from audit test-name grepping)
- [x] #815 — ledger: FirstValidTime + block_field implemented via PR #834; absentee computation split to #833 (needs new block-proposal-time online-stake infrastructure)
- [x] #833 — ledger: implement block-proposal-side absentee/suspension list computation (split from #815); isAbsent pure function implemented via PR #846, block-assembly wiring split to #845 — closed as superseded by #845
- [x] #816 — rest-api: add PQ authorizer/LogicSig-curve compliance checks and stateproof-for-round polling — merged via PR #836; simulate placeholder-PQ-sig moved to #835
- [x] #822 — crypto: enforce decode-time allocation bounds in merklearray proof decoder — merged via PR #832
- [x] #839 — avm: implement missing v13+ block opcode fields (BlkBranch512, BlkSha512_256/256/512TxnCommitment) (split from #810)
- [ ] #841 — avm: implement holding/local-state cross-product resource sharing and tx.Access-list resolution (split from #808)
- [ ] #845 — ledger/pool/agreement: wire isAbsent-based absentee-account computation into block assembly (split from #833); validation-side done via PR #886 (`validate_absent_online_accounts` now checks isAbsent/challenge-failure for a received block's claimed-absent list, rejecting a falsely-claimed absentee — a real security-relevant gap); proposal-side (`assemble_block` producing its own `ParticipationUpdates.AbsentParticipationAccounts`) confirmed to need genuinely new plumbing (grep-verified: zero `ParticipationUpdates` usage in `algo-pool`/`algo-agreement` today) and remains open
- [x] #847 — avm: assembler treats ';' as a comment delimiter instead of a statement separator (found while working #823) — merged via PR #849
- [x] ledger/agreement: `detect_validation_groups` had no transaction-group-size upper bound at all (found while working #825) — merged via PR #857; filed #856 for unrelated pre-existing test failures found while verifying no regressions
- [x] #856 — bin/algod-rust: 3 stale `participate.rs` tests predating PR #837's tightened per-type wellFormed rules (afrz missing freeze_asset/freeze_account; a close-to-self test asserting acceptance of a scenario go-algorand rejects) — merged via PR #870
- [x] #866 — avm: `pre-sharedResources program cannot be invoked with tx.Access` version-gate (go's `sharedResourcesVersion`, `eval.go:1612-1621`) was entirely unimplemented (found while working #824 theme 1) — merged via PR #871
- [x] #877 — avm: `txn`/`gtxn`/`gtxns` lack go-algorand's pseudo-op multi-arity dispatch (`txna`/`gtxna`/`gtxnsa` sugar) (found while working #823 theme 4) — merged via PR #881

**Net-new subsystems:**
- [ ] #814 — stateproof: implement a signing/proving worker; core signing/proving algorithm done via PR #898 (`algo-consensus-crypto::stateproof::Prover`, `algo-ledger::stateproof_worker` — round-eligibility, per-account signing, signature gathering/persistence, proof-building; verified with a real multi-participant sign→build→verify round trip using real Falcon-1024 keys); live background daemon (gossip `StateProofSig` handling, autonomous `StateProofTx` broadcast), disk-cache persistence, and the signer-side message-construction path deliberately deferred as needing live multi-node interop testing
- [ ] #817 — networking: implement vpack vote-compression codec; stateless codec done via PR #885 (verified against 7 real byte-vector fixtures captured from go-algorand's own source), stateful codec (LRU reference tables, HPACK-style proposal window, `r.rnd` delta encoding) done via PR #895 (verified against 8 further real byte-vector fixtures using the same technique) — both codec modes complete. Live websocket/P2P wiring remains open, deliberately deferred as needing dedicated live multi-node interop testing, not a background-agent task
- [ ] #818 — networking: implement libp2p stream manager, p2pMetainfo exchange, and IdentityTracker; stream manager and IdentityTracker ported as standalone, unwired modules via PR #893 (`p2pMetainfo` found to already be ported, parity doc simply hadn't been updated); connection-limit/pubsub-parameter tuning and live wiring into `P2pHost`'s event loop remain open
- [ ] #819 — sync: implement catchup peer-selection/ranking layer; ranking algorithm (`PeerRanker`/`ClassBasedPeerSelector`) done via PR #891, closing 21 of 26 previously-not-implemented rows; wiring into live block/catchpoint fetch paths remains open, deliberately deferred as needing live multi-node testing — issue #819 notes a new follow-up issue should be filed for that wiring work
- [ ] #829 — avm: implement static stack-type-tracking pass in the TEAL assembler; slice 1 (straight-line/branch-free tracking, safe-by-construction — disables itself rather than guessing on branches/labels/arity-dependent opcodes) via PR #883, covering TestSwapTypeCheck/TestEqualsTypeCheck/TestDupTypeCheck/TestSelectTypeCheck/TestSetBitTypeCheck + TestTypeTracking's first case; slice 2 via PR #892 adds branch-merge type unification (ported go's actual `deadcode`/`bottom`/`deadens` algorithm from `assembler.go`/`opcodes.go`), covering TestBranchAssemblyTypeCheck, the rest of TestTypeTracking, and TestTypeTrackingRegression; slice 3 via PR #899 adds scratch-slot per-index type tracking (`ProgramKnowledge.scratchSpace`-equivalent, constant-index-aware `loads`/`stores`), covering TestScratchTypeCheck and TestScratchBounds's message-observable assertion; `#pragma typetrack` toggling, dynamic-/arity-dependent opcodes (match/txn/gtxn/gtxns/popn/dupn/cover/uncover/pushbytess/pushints), and bounds-refined types remain as documented follow-up work
- [ ] #821 — pool/networking: implement application-call excessive-rate-limiter (ERL) subsystem; algorithm ported via PR #890 (`crates/core/algo-pool/src/app_rate_limiter.rs`, all 11 `TestAppRateLimiter_*` cases, sharded/LRU sliding-window + client-mapper hashing bit-for-bit); wiring into the live pull-based tx-sync ingestion path deliberately deferred as an architecture decision, not attempted
- [x] #820 — tools: add algokey pq CLI, autonomous heartbeat service, and libgoal app-call resource resolution; heartbeat service done via PR #882 (also fixed a real bug: `hb` transactions were blanket-rejected from the pool, which would have silently discarded the new service's own submissions); algokey pq CLI done via PR #884 (22/30 upstream tests matched); libgoal resource-resolution algorithm done via PR #887 — closed. Full `app call`/`app method` ABI CLI subcommand split to #888 (needs a materially larger ARC-4/ABI-encoding subsystem that doesn't exist in `goal-rust` yet)
- [ ] #828 — util: consider porting db Accessor/Migration framework, pagedqueue, and rateLimit ElasticRateLimiter
- [x] #888 — tools: goal-rust `app call`/`app method` ABI CLI subcommand (split from #820); slice 1 (PR #896) adds the ARC-4 ABI encoding subsystem — new `crates/core/algo-abi` crate (extracted from `algo-rest-api`'s private `abi.rs`), method-selector computation, `Method`/Contract-JSON signature parsing, ABI value decode, JSON display formatting, and go's more-than-15-arguments tuple-bundling rule — verified against real ARC-4 vectors from go-algorand's own e2e ABI fixture and `TestParseMethodArgJSONtoByteSlice`; slice 2 (PR #900) wires it into live `goal-rust app call`/`app method` CLI subcommands — CLI-value parsing, resource resolution via #887, transaction construction/signing/submission, ARC-4 return-value decoding — closed. `app create`/`update`/`delete`/`optin`/`closeout`/`clear`/`read`/`info`/`box info`/`box list` remain unimplemented as smaller independent follow-ups
- [x] #835 — ledger/simulation: implement placeholder PQ signature validation in the simulator (split from #816)

**Test-gap sweeps:**
- [ ] #823 — testing: close AVM/assembler missing-test gaps; theme 1 partial (match opcode execution-level tests, also fixed a real op_match bug) via PR #848 — assembler-level TestAssembleMatch/TestDisassembleBad* sub-items are the only remaining scope; theme 2 (JSON parser edge cases) via PR #851; theme 3 (box budget, all scenarios) via PR #852 + PR #878; theme 4 (assembler diagnostics, all scenarios — found+fixed 2 real gaps: intc/bytec out-of-range acceptance, disassembler silently printing unresolvable field bytes; split TestAssembleTxna's real multi-arity-dispatch gap to #877) via PR #854 + PR #878; theme 5 (EC/pairing, all scenarios — found+fixed a real consensus-affecting bug: BLS12-381 ec_map_to never cleared the cofactor, producing points outside the prime-order subgroup) via PR #853 + PR #878
- [x] #824 — testing: close ledger missing-test gaps; PQ-rekeying theme's core security gap (authorizer-vs-AuthAddr check was entirely unenforced) fixed via PR #850; theme 1 (app-call lifecycle, found+fixed a real cross-product resource-availability bug for top-level group siblings) via PR #867 (also split off #866, a real tx.Access version-gate bug, fixed via PR #871); theme 2 (account/resource lookups) via PR #872; theme 3 (catchpoint/archival, found+fixed a real resource-count-mismatch validation gap in catchpoint import) via PR #875; theme 5 (msgpack edge cases, found+fixed a real AccountTotals omitempty encoding bug) via PR #864; theme 6 (tracker/commit robustness, found+fixed 2 real bugs: missing lastCatchpoint persistence, and an offline-account stake/key leak into agreement's OnlineAccountData) via PR #869 — all 6 themes done, closed
- [ ] #825 — testing: close agreement missing-test gaps; theme 4's `TestProposalCarriesOversizedTxnGroup` fixed via PR #857 (a real bug, not just a missing test), `TestProposalManagerRejectsUnknownEvent` via PR #858, `TestSampleIndexIsValid`/`TestLowerBound` constant invariants via PR #859; theme 2 DONE (all 14 credential-arrival-history scenarios) via PR #868 + PR #880 — 2 real bugs found+fixed (`Vote.validated_at` and `Proposal.received_at` were both always `Duration::ZERO`, silently defeating the dynamic-filter-timeout feature and zeroing `BlockAcceptedEvent.ReceivedAt` telemetry); theme 1 partial (6 named regressions + 2 network-hardening scenarios) via PR #876; theme 3 partial (`TestAgreementServiceStartDeadline`, no divergence found) via PR #889 — the other 9 theme-3 scenarios and theme 1's remainder are blocked on a genuinely-missing multi-node service-level test harness (go's 5-node `testingNetwork`/`testingClock`/`activityMonitor`; algod-rust's only service-level harness drives a single node over a `BlackholeNetwork`), documented per-row in `docs/phase17/parity_agreement.md` rather than left as bare gaps. `TestSortProposalValueLess`, `TestPseudonodeNonEnqueuedTasks` remain open too
- [x] #826 — testing: close crypto missing-test gaps; theme 1 (tamper vectors) via PR #855, theme 2 (KAT coverage, found real go-derived + independently cross-verified vectors) via PR #863, theme 3 (randomized-encoding property tests, shared driver) via PR #873 — closed
- [ ] #827 — testing: close REST/kmd/multi-node-cluster negative-path missing-test gaps; theme 1 (REST negative-path coverage) via PR #861; themes 2/3/5 via PR #874 (found+fixed a real msgpack decode bug: 10 `Option` fields missing `#[serde(default)]`); theme 4 (multi-node cluster, needs a node-orchestration test harness algod-rust doesn't have) remains genuinely open

## Reproducing this audit

`scripts/list_go_tests.sh` and `scripts/list_rust_tests.sh` regenerate
the raw test inventories; re-run both and rebuild
`docs/phase17/parity_*.md` after any future go-algorand version bump.
