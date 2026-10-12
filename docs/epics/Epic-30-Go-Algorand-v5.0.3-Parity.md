# Epic: go-algorand v5.0.3-stable parity

Tracks moving algod-rust's parity target from go-algorand `v5.0.2-stable` to
`v5.0.3-stable`, per the `algod-version-upgrade` skill. GitHub epic issue:
[#1864](https://github.com/xarmian/algod-rust/issues/1864).

## Stage 1 — Tags in range

- `OLD` = `v5.0.2-stable` (`fe1308bd3c669c806facfd34e5eb2873e6c4aa93`)
- `NEW` = `v5.0.3-stable` (`2dc9524e9e9b7f4cd9234659d45ac42b283c4ae3`)
- `TAGS_IN_RANGE` = `{v5.0.3-stable}`; `v5.0.3-beta` only merges the stable
  branch back and carries no separate behavior.

## Stage 2 — Classified inventory

See `docs/PHASE20_PROPOSAL.md`. One functional change (root KSK-2024 DNSSEC
trust anchor, #1863) and one `not-applicable` (build metadata). Test-parity
delta: 0 added / 0 removed / 2 body-changed (`docs/phase20/test_parity_delta.md`).

## Stage 6 — Sub-issues (dependency order)

- [ ] #1863 — dnssec: trust the IANA root KSK-2024 anchor

## Epic-level acceptance criteria

- [ ] #1863 closed.
- [ ] Pin swept to `v5.0.3-stable`.
- [ ] `python3 scripts/phase17_parity_delta.py check --tag v5.0.3-stable --go-algorand ../go-algorand` exits 0.
- [ ] Full gate + live mixed-cluster against v5.0.3-stable Go nodes.
- [ ] `docs/PHASE20_VALIDATION.md` written.
- [ ] Hard gate: `gh issue list --label "phase:20" --state open` empty before close.
