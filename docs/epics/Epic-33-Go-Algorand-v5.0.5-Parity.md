# Epic: go-algorand v5.0.5-stable parity

Tracks moving algod-rust's parity target from go-algorand `v5.0.4-stable` to
`v5.0.5-stable`, per the `algod-version-upgrade` skill. GitHub epic issue:
[#2308](https://github.com/xarmian/algod-rust/issues/2308).

## Stage 1 — Tags in range

- `OLD` = `v5.0.4-stable` (`927ae0863cbb4cf29c6845c088a4ea4c439b10bb`)
- `NEW` = `v5.0.5-stable` (`31186e99a69e74483ad95e9ce872903b74758abf`)
- `TAGS_IN_RANGE` = `{v5.0.5-beta, v5.0.5-stable}`; the beta carries the identical change.

## Stage 2 — Classified inventory

See `docs/PHASE24_PROPOSAL.md`. Test-parity delta: 1 added / 0 removed /
1 body-changed (`docs/phase24/test_parity_delta.md`).

## Stage 6 — Sub-issues (dependency order)

- [ ] #2309 — generate-only decode-after-encode check for transactions in blocks

## Epic-level acceptance criteria

- [ ] #2309 closed.
- [ ] Pin swept to `v5.0.5-stable`.
- [ ] `python3 scripts/phase17_parity_delta.py check --tag v5.0.5-stable --go-algorand ../go-algorand` exits 0.
- [ ] Full gate + live mixed-cluster against v5.0.5-stable Go nodes.
- [ ] `docs/PHASE24_VALIDATION.md` written.
- [ ] Hard gate: `gh issue list --label "phase:24" --state open` empty before close.
