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
- [ ] #808 — avm: implement transaction-group resource-availability enforcement — **highest priority**
- [ ] #809 — avm/ledger: fix app-call guard correctness bugs
- [ ] #810 — avm: add per-field version gating for global/txn/gtxn/asset_params_get/acct_params_get/block
- [ ] #811 — avm: implement RekeyTo/ApplicationCall minimum-AVM-version rule
- [ ] #812 — validate: add per-type WellFormed() mempool validation
- [ ] #813 — consensus: reconcile Falcon-512 vs Falcon-1024 parameter-set naming
- [ ] #815 — ledger: implement absentee/suspension computation and FirstValidTime
- [ ] #816 — rest-api: add PQ authorizer/LogicSig-curve compliance checks and stateproof-for-round polling
- [ ] #822 — crypto: enforce decode-time allocation bounds in merklearray proof decoder

**Net-new subsystems:**
- [ ] #814 — stateproof: implement a signing/proving worker
- [ ] #817 — networking: implement vpack vote-compression codec
- [ ] #818 — networking: implement libp2p stream manager, p2pMetainfo exchange, and IdentityTracker
- [ ] #819 — sync: implement catchup peer-selection/ranking layer
- [ ] #829 — avm: implement static stack-type-tracking pass in the TEAL assembler
- [ ] #821 — pool/networking: implement application-call excessive-rate-limiter (ERL) subsystem
- [ ] #820 — tools: add algokey pq CLI, autonomous heartbeat service, and libgoal app-call resource resolution
- [ ] #828 — util: consider porting db Accessor/Migration framework, pagedqueue, and rateLimit ElasticRateLimiter

**Test-gap sweeps:**
- [ ] #823 — testing: close AVM/assembler missing-test gaps
- [ ] #824 — testing: close ledger missing-test gaps
- [ ] #825 — testing: close agreement missing-test gaps
- [ ] #826 — testing: close crypto missing-test gaps
- [ ] #827 — testing: close REST/kmd/multi-node-cluster negative-path missing-test gaps

## Reproducing this audit

`scripts/list_go_tests.sh` and `scripts/list_rust_tests.sh` regenerate
the raw test inventories; re-run both and rebuild
`docs/phase17/parity_*.md` after any future go-algorand version bump.
