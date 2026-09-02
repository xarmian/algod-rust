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
- [ ] #833 — ledger: implement block-proposal-side absentee/suspension list computation (split from #815); isAbsent pure function implemented via PR #846, block-assembly wiring split to #845
- [x] #816 — rest-api: add PQ authorizer/LogicSig-curve compliance checks and stateproof-for-round polling — merged via PR #836; simulate placeholder-PQ-sig moved to #835
- [x] #822 — crypto: enforce decode-time allocation bounds in merklearray proof decoder — merged via PR #832
- [x] #839 — avm: implement missing v13+ block opcode fields (BlkBranch512, BlkSha512_256/256/512TxnCommitment) (split from #810)
- [ ] #841 — avm: implement holding/local-state cross-product resource sharing and tx.Access-list resolution (split from #808)
- [ ] #845 — ledger/pool/agreement: wire isAbsent-based absentee-account computation into block assembly (split from #833)
- [x] #847 — avm: assembler treats ';' as a comment delimiter instead of a statement separator (found while working #823) — merged via PR #849
- [x] ledger/agreement: `detect_validation_groups` had no transaction-group-size upper bound at all (found while working #825) — merged via PR #857; filed #856 for unrelated pre-existing test failures found while verifying no regressions
- [x] #856 — bin/algod-rust: 3 stale `participate.rs` tests predating PR #837's tightened per-type wellFormed rules (afrz missing freeze_asset/freeze_account; a close-to-self test asserting acceptance of a scenario go-algorand rejects) — merged via PR #870
- [x] #866 — avm: `pre-sharedResources program cannot be invoked with tx.Access` version-gate (go's `sharedResourcesVersion`, `eval.go:1612-1621`) was entirely unimplemented (found while working #824 theme 1) — merged via PR #871
- [x] #877 — avm: `txn`/`gtxn`/`gtxns` lack go-algorand's pseudo-op multi-arity dispatch (`txna`/`gtxna`/`gtxnsa` sugar) (found while working #823 theme 4) — merged via PR #881

**Net-new subsystems:**
- [ ] #814 — stateproof: implement a signing/proving worker
- [ ] #817 — networking: implement vpack vote-compression codec; stateless codec done via PR #885 (verified against 7 real byte-vector fixtures captured from go-algorand's own source — genuine wire-level interop evidence); stateful mode (LRU reference table) and live websocket/P2P wiring remain open — the latter deliberately deferred as needing dedicated live multi-node interop testing, not a background-agent task
- [ ] #818 — networking: implement libp2p stream manager, p2pMetainfo exchange, and IdentityTracker
- [ ] #819 — sync: implement catchup peer-selection/ranking layer
- [ ] #829 — avm: implement static stack-type-tracking pass in the TEAL assembler; first incremental slice (straight-line/branch-free tracking, safe-by-construction — disables itself rather than guessing on branches/labels/arity-dependent opcodes) via PR #883, covering TestSwapTypeCheck/TestEqualsTypeCheck/TestDupTypeCheck/TestSelectTypeCheck/TestSetBitTypeCheck + TestTypeTracking's first case; branch-merge unification, scratch-slot tracking, and several other sub-tests remain as documented follow-up work
- [ ] #821 — pool/networking: implement application-call excessive-rate-limiter (ERL) subsystem
- [ ] #820 — tools: add algokey pq CLI, autonomous heartbeat service, and libgoal app-call resource resolution; heartbeat service done via PR #882 (also fixed a real bug: `hb` transactions were blanket-rejected from the pool, which would have silently discarded the new service's own submissions); algokey pq CLI done via PR #884 (22/30 upstream tests matched); libgoal app-call resource resolution remains open
- [ ] #828 — util: consider porting db Accessor/Migration framework, pagedqueue, and rateLimit ElasticRateLimiter
- [x] #835 — ledger/simulation: implement placeholder PQ signature validation in the simulator (split from #816)

**Test-gap sweeps:**
- [ ] #823 — testing: close AVM/assembler missing-test gaps; theme 1 partial (match opcode execution-level tests, also fixed a real op_match bug) via PR #848 — assembler-level TestAssembleMatch/TestDisassembleBad* sub-items are the only remaining scope; theme 2 (JSON parser edge cases) via PR #851; theme 3 (box budget, all scenarios) via PR #852 + PR #878; theme 4 (assembler diagnostics, all scenarios — found+fixed 2 real gaps: intc/bytec out-of-range acceptance, disassembler silently printing unresolvable field bytes; split TestAssembleTxna's real multi-arity-dispatch gap to #877) via PR #854 + PR #878; theme 5 (EC/pairing, all scenarios — found+fixed a real consensus-affecting bug: BLS12-381 ec_map_to never cleared the cofactor, producing points outside the prime-order subgroup) via PR #853 + PR #878
- [x] #824 — testing: close ledger missing-test gaps; PQ-rekeying theme's core security gap (authorizer-vs-AuthAddr check was entirely unenforced) fixed via PR #850; theme 1 (app-call lifecycle, found+fixed a real cross-product resource-availability bug for top-level group siblings) via PR #867 (also split off #866, a real tx.Access version-gate bug, fixed via PR #871); theme 2 (account/resource lookups) via PR #872; theme 3 (catchpoint/archival, found+fixed a real resource-count-mismatch validation gap in catchpoint import) via PR #875; theme 5 (msgpack edge cases, found+fixed a real AccountTotals omitempty encoding bug) via PR #864; theme 6 (tracker/commit robustness, found+fixed 2 real bugs: missing lastCatchpoint persistence, and an offline-account stake/key leak into agreement's OnlineAccountData) via PR #869 — all 6 themes done, closed
- [ ] #825 — testing: close agreement missing-test gaps; theme 4's `TestProposalCarriesOversizedTxnGroup` fixed via PR #857 (a real bug, not just a missing test), `TestProposalManagerRejectsUnknownEvent` via PR #858, `TestSampleIndexIsValid`/`TestLowerBound` constant invariants via PR #859; theme 2 DONE (all 14 credential-arrival-history scenarios) via PR #868 + PR #880 — 2 real bugs found+fixed (`Vote.validated_at` and `Proposal.received_at` were both always `Duration::ZERO`, silently defeating the dynamic-filter-timeout feature and zeroing `BlockAcceptedEvent.ReceivedAt` telemetry); theme 1 partial (6 named regressions + 2 network-hardening scenarios) via PR #876. `TestSortProposalValueLess`, `TestPseudonodeNonEnqueuedTasks`, theme 1's offset-start/late-proposal/ISV-ICV/pipelined-threshold scenarios, and theme 3 (service-level fast-recovery) remain open
- [x] #826 — testing: close crypto missing-test gaps; theme 1 (tamper vectors) via PR #855, theme 2 (KAT coverage, found real go-derived + independently cross-verified vectors) via PR #863, theme 3 (randomized-encoding property tests, shared driver) via PR #873 — closed
- [ ] #827 — testing: close REST/kmd/multi-node-cluster negative-path missing-test gaps; theme 1 (REST negative-path coverage) via PR #861; themes 2/3/5 via PR #874 (found+fixed a real msgpack decode bug: 10 `Option` fields missing `#[serde(default)]`); theme 4 (multi-node cluster, needs a node-orchestration test harness algod-rust doesn't have) remains genuinely open

## Reproducing this audit

`scripts/list_go_tests.sh` and `scripts/list_rust_tests.sh` regenerate
the raw test inventories; re-run both and rebuild
`docs/phase17/parity_*.md` after any future go-algorand version bump.
