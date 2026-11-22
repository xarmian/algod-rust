# Phase 26 Proposal — go-algorand v5.1.1-stable parity

Phase 26 moves algod-rust's parity target from go-algorand `v5.0.5-stable`
to `v5.1.1-stable`, per the `algod-version-upgrade` skill, and keeps the
Phase 17 test-parity map complete at the new pin.

Tracking epic: [#2559](https://github.com/xarmian/algod-rust/issues/2559) (`docs/epics/Epic-34-Go-Algorand-v5.1.1-Parity.md`).

## Motivation

`v5.1.1-stable` is the first minor release since 5.0: lower RAM/disk IO on the
default config, the foundation for post-quantum accounts (Falcon-512, salted
keys, `ed` and `ls` schemes), AVM v14 arithmetic (`bmodexp`, unconstrained byte
math, length-based costs, `mldsa_verify`), stricter LogicSig argument rules,
DNSSEC hardening and many networking/agreement fixes. It contains **no protocol
upgrade**: every new consensus rule is enabled only in `vFuture`.

## Scope

`OLD` = `v5.0.5-stable` (`31186e99a69e74483ad95e9ce872903b74758abf`)
`NEW` = `v5.1.1-stable` (`0cb826e3fb62ccb5666cbb1552d840585ac3cfe5`)

`TAGS_IN_RANGE` = `{v5.1.0-beta, v5.1.1-beta, v5.1.1-stable}` (there is no
`v5.1.0-stable`). `v5.1.1-beta` is one commit (`11f6cc2ea`, "Bug Fixes: update,
refactor, and enhance code", 97 files) whose release notes list nothing but
which carries the agreement, tx-handler, state-proof path-length, simulate
decoding and network changes; it was analysed from the diff.

### Classified inventory

| Area | Classification | Sub-issue |
|---|---|---|
| New `ConsensusParams`, `fnet5`, vFuture LogicSigVersion 14 | consensus-critical | #2543 |
| Grouped heartbeats, duplicate-txn group rejection, removed obsolete group checks | consensus-critical | #2544 |
| Inner ClearState delta discard, kvCow no-op delete, created-app resources, generate-only cross-type guard | consensus-critical | #2545 |
| SigScheme registry (SaltedKeySig, salted addresses, `f5` Falcon-512, `ed`) | consensus-critical | #2546 |
| `ls` scheme, LogicSigArgs, pricing | consensus-critical | #2547 |
| `RequireLogicSigArgAccess` | consensus-critical | #2548 |
| AVM v14 (`falcon_verify` immediate, `mldsa_verify`, full byte-math, length costs) | consensus-critical / avm | #2549 |
| TEAL corpus parity for the v14 langspec | avm | #2550 |
| verifiedTxnCache, pool statusCache, txHandler | behavioral-other | #2551 |
| Agreement (stale cert bundle, payload deferral, proposal store/queue) | consensus-critical | #2552 |
| State-proof `CheckMerklePathLengths` | consensus-critical | #2553 |
| DNSSEC, P2P bootstrap DNS, peer/throttle, compressor, streams | network | #2554 |
| GetBlockHash, KV sort, simulate decoding, group-decode bound | api | #2555 |
| algokey, goal, kmd, participation registry, util/db | behavioral-other | #2556 |
| Residual test-parity sweep + removed rows | testing | #2557 |
| Version-pin sweep + `repin` | infrastructure | #2558 |

### Non-goals (`not-applicable`)

Go toolchain/dependency bumps (Go 1.27.3, oapi-codegen, gorilla/mux removal,
msgp codegen), `encoding/json/v2` streaming (output unchanged; covered by the
REST conformance run in #2555), CI/codecov/dependabot/lint changes,
`SECURITY.md`/AGENTS.md, SDK x-repo-types lag, 32-bit-`int` test fixes, Go-only
test race/flake fixes, version/buildnumber bumps. Each is re-checked in the
close-out completeness pass.

`docs/DIVERGENCES.md` was consulted. DIV-001 (pure-Rust Falcon-1024) is
directly in range: Falcon-512 (`det512`) must be added to
`crates/core/algo-falcon/src/rs/` and its vector corpus extended from go; the
register entry's "How parity is proven" evidence is re-verified, not re-ported.
No new `DIV-` entries (project rule).

### Test parity (Pass C)

`docs/phase26/test_parity_delta.md`: 3,194 -> 3,397 Go tests; **294 added,
91 removed, 0 moved, 234 body-changed**. Package ownership is in each
sub-issue's *Owned Go tests*; #2557 owns the remainder.

## Success criteria

- [ ] No `phase:26` issue open.
- [ ] `python3 scripts/phase17_parity_delta.py check --tag v5.1.1-stable --go-algorand ../go-algorand` exits 0 (map pinned to v5.1.1-stable, complete, not-implemented = missing-test = partial = unclassified = 0; the standing `--allow-partial 3` sign-off from earlier phases is the only permitted exception).
- [ ] Live dual-node REST conformance and mixed-cluster soak green against go `v5.1.1-stable`.
- [ ] `docs/PHASE26_VALIDATION.md` evidence map written.
