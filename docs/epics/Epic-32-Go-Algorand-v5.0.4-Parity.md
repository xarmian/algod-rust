# Epic: go-algorand v5.0.4-stable parity

Tracks moving algod-rust's parity target from go-algorand `v5.0.3-stable` to
`v5.0.4-stable`, per the `algod-version-upgrade` skill. GitHub epic issue:
[#2025](https://github.com/xarmian/algod-rust/issues/2025).

## Stage 1 — Tags in range

- `OLD` = `v5.0.3-stable` (`2dc9524e9e9b7f4cd9234659d45ac42b283c4ae3`)
- `NEW` = `v5.0.4-stable` (`927ae0863cbb4cf29c6845c088a4ea4c439b10bb`)
- `TAGS_IN_RANGE` = `{v5.0.4-stable}`; `v5.0.4-beta` only merges the stable branch.

## Stage 2 — Classified inventory

See `docs/PHASE22_PROPOSAL.md`. Test-parity delta: 3 added / 0 removed /
3 body-changed (`docs/phase22/test_parity_delta.md`).

## Stage 6 — Sub-issues (dependency order)

- [ ] #2022 — consensus v43 / CloseRequiresBaseMinBalance
- [ ] #2023 — generate-only close-out min-balance guard
- [ ] #2024 — zstd-compressed agreement crash snapshots (decode)

## Epic-level acceptance criteria

- [ ] #2022, #2023, #2024 closed.
- [ ] Pin swept to `v5.0.4-stable`.
- [ ] `python3 scripts/phase17_parity_delta.py check --tag v5.0.4-stable --go-algorand ../go-algorand` exits 0.
- [ ] Full gate + live mixed-cluster against v5.0.4-stable Go nodes.
- [ ] `docs/PHASE22_VALIDATION.md` written.
- [ ] Hard gate: `gh issue list --label "phase:22" --state open` empty before close.
