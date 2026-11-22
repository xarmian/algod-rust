# Epic: go-algorand v5.1.1-stable parity

Tracks moving algod-rust's parity target from go-algorand `v5.0.5-stable` to
`v5.1.1-stable`, per the `algod-version-upgrade` skill. GitHub epic issue:
[#2559](https://github.com/xarmian/algod-rust/issues/2559).

## Stage 1 — Tags in range

- `OLD` = `v5.0.5-stable` (`31186e99a69e74483ad95e9ce872903b74758abf`)
- `NEW` = `v5.1.1-stable` (`0cb826e3fb62ccb5666cbb1552d840585ac3cfe5`)
- `TAGS_IN_RANGE` = `{v5.1.0-beta, v5.1.1-beta, v5.1.1-stable}`

## Stage 2 — Classified inventory

See `docs/PHASE26_PROPOSAL.md`. Test-parity delta: 294 added / 91 removed /
234 body-changed (`docs/phase26/test_parity_delta.md`).

## Stage 6 — Sub-issues (dependency order)

- [ ] #2558 — pin sweep + `repin`
- [ ] #2543 — ConsensusParams / fnet5
- [ ] #2544 — grouped heartbeats, group duplicates
- [ ] #2546 — SigScheme registry (Falcon-512, `ed`)
- [ ] #2547 — `ls` scheme
- [ ] #2548 — RequireLogicSigArgAccess
- [ ] #2545 — ledger eval changes
- [ ] #2549 — AVM v14
- [ ] #2550 — TEAL corpus parity
- [ ] #2553 — state-proof path lengths
- [ ] #2552 — agreement
- [ ] #2551 — verified-txn cache / pool / txHandler
- [ ] #2554 — network
- [ ] #2555 — REST API / simulate
- [ ] #2556 — tools
- [ ] #2557 — residual test-parity sweep

## Epic-level acceptance criteria

- [ ] No `phase:26` issue open.
- [ ] `python3 scripts/phase17_parity_delta.py check --tag v5.1.1-stable --go-algorand ../go-algorand` exits 0.
- [ ] Full gate + live mixed-cluster against v5.1.1-stable Go nodes.
- [ ] `docs/PHASE26_VALIDATION.md` written.
- [ ] Close-out completeness re-check of the upstream releases page.
