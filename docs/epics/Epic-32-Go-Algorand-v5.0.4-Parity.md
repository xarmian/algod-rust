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

- [x] #2022 — consensus v43 / CloseRequiresBaseMinBalance (PR #2030)
- [x] #2023 — generate-only close-out min-balance guard (PR #2031)
- [x] #2024 — zstd-compressed agreement crash snapshots (decode) (PR #2032)

## Epic-level acceptance criteria

- [x] #2022, #2023, #2024 closed (PRs #2030, #2031, #2032).
- [x] Pin swept to `v5.0.4-stable` (PR #2028).
- [x] `python3 scripts/phase17_parity_delta.py check --tag v5.0.4-stable --go-algorand ../go-algorand` exits 0. (with the standing `--allow-partial 3` sign-off; see `docs/PHASE22_VALIDATION.md`)
- [x] Full gate + live mixed-cluster against v5.0.4-stable Go nodes (see `docs/PHASE22_VALIDATION.md`).
- [x] `docs/PHASE22_VALIDATION.md` written.
- [x] Hard gate: `gh issue list --label "phase:22" --state open` empty before close (checked 2026-10-22).
