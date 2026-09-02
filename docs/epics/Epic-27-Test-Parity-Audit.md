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

**Net-new subsystems:**
- [ ] #814 — stateproof: implement a signing/proving worker
- [ ] #817 — networking: implement vpack vote-compression codec
- [ ] #818 — networking: implement libp2p stream manager, p2pMetainfo exchange, and IdentityTracker
- [ ] #819 — sync: implement catchup peer-selection/ranking layer
- [ ] #829 — avm: implement static stack-type-tracking pass in the TEAL assembler
- [ ] #821 — pool/networking: implement application-call excessive-rate-limiter (ERL) subsystem
- [ ] #820 — tools: add algokey pq CLI, autonomous heartbeat service, and libgoal app-call resource resolution
- [ ] #828 — util: consider porting db Accessor/Migration framework, pagedqueue, and rateLimit ElasticRateLimiter
- [x] #835 — ledger/simulation: implement placeholder PQ signature validation in the simulator (split from #816)

**Test-gap sweeps:**
- [ ] #823 — testing: close AVM/assembler missing-test gaps; theme 1 (match opcode execution-level tests, also fixed a real op_match bug) via PR #848; theme 2 (JSON parser edge cases) via PR #851; theme 3 (box write-budget/dirty-tracking core scenarios) via PR #852; theme 5 partial (hash/ecdsa cost tests) via PR #853; theme 4 partial (duplicate-label/branch-args/arg/several-errors) via PR #854; theme 3's remaining scenarios, theme 4's remaining scenarios (found a likely real txn/gtxn multi-arity assembler gap — `TestAssembleTxna` — not just a test gap), and theme 5's BLS12-381 gaps remain
- [ ] #824 — testing: close ledger missing-test gaps; PQ-rekeying theme's core security gap (authorizer-vs-AuthAddr check was entirely unenforced) fixed via PR #850, other 5 themes remain
- [ ] #825 — testing: close agreement missing-test gaps; theme 4's `TestProposalCarriesOversizedTxnGroup` fixed via PR #857 (a real bug, not just a missing test — see above), `TestProposalManagerRejectsUnknownEvent` via PR #858, and `TestSampleIndexIsValid`/`TestLowerBound` constant invariants via PR #859; `TestSortProposalValueLess` (needs investigation), `TestPseudonodeNonEnqueuedTasks` (needs an async execpool harness), and themes 1-3 remain
- [ ] #826 — testing: close crypto missing-test gaps; theme 1 (merkle-signature-scheme tamper vectors) via PR #855; theme 2 (golden/KAT vector coverage) and theme 3 (randomized-encoding property tests) remain
- [ ] #827 — testing: close REST/kmd/multi-node-cluster negative-path missing-test gaps

## Reproducing this audit

`scripts/list_go_tests.sh` and `scripts/list_rust_tests.sh` regenerate
the raw test inventories; re-run both and rebuild
`docs/phase17/parity_*.md` after any future go-algorand version bump.
