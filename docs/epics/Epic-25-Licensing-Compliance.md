# Epic: Licensing and legal-framework compliance

Tracks bringing algod-rust into full compliance with the legal framework
it operates under. GitHub epic issue:
[#732](https://github.com/xarmian/algod-rust/issues/732). Full scope and
rationale: [`docs/PHASE15_PROPOSAL.md`](../PHASE15_PROPOSAL.md).

## Problem

The repository is currently **unlicensed** (no `COPYING`/`LICENSE`, no
`Cargo.toml` `license` fields, no source-file headers — verified
2026-08-29), while go-algorand's own published licensing rules
(`COPYING`, `COPYING_FAQ` in the reference checkout) state that
reimplementing the node/APIs/consensus produces a work automatically
licensed under the AGPL.

## Decisions being implemented (project owner, 2026-08-29)

1. algod-rust as a whole = **modified work based on go-algorand,
   AGPL-3.0-or-later**, preserving go-algorand's section 7e Additional
   Terms (Algorand trademark reservation).
2. **MIT wherever legally possible** for files not derived from AGPL
   material; when in doubt, AGPL.
3. Legal entity for all algod-rust copyright/attribution: **`Algod DAO`**.
4. Deriving from go-algorand's AGPL source is accepted and intended (and
   is what conveys the Algorand patent license per `COPYING_FAQ` item 6).

## Key upstream facts

| Material | License |
|---|---|
| go-algorand node software | AGPL-3.0-or-later + section 7e Additional Terms |
| Algorand SDKs/helper libs (e.g. `go-sumhash`) | MIT |
| `algorand/sortition` v1.1.1 (f128 port source, #667) | AGPL-3.0 + 7e terms |
| `algorand/falcon` | AGPL headers (underlying Falcon C reference: permissive — audit) |
| gnark-crypto v0.18.1 (poseidon2 source, #665) | Apache-2.0 (attribution/NOTICE obligations) |
| go-algorand vendored `libsodium-fork` / `secp256k1` / `util/bloom` | ISC / BSD-style |

## Sub-issues

- [ ] #731 — legal: resolve repository licensing (full-file AGPL/MIT
      audit, repo license files, per-file modified-work headers, Cargo
      metadata, `docs/LICENSING.md`, skills/CLAUDE.md header rules,
      dependency-tree check, CI header check). Filed analysis-first — no
      file modifications until picked up for implementation.

Additional sub-issues may be added if the audit surfaces
separately-scoped work (e.g. the node-visible source-availability
pointer, or trademark-permission follow-ups requiring project-owner
action).

## Epic-level acceptance criteria

- [ ] #731 closed (merged or honestly disposed).
- [ ] `COPYING` (AGPL-3.0 + preserved 7e Additional Terms) and
      `LICENSE-MIT` (Copyright (c) 2026 Algod DAO) at repo root; README
      licensing section.
- [ ] Every source file carries the correct header with SPDX identifier
      and `Algod DAO` attribution; AGPL-derived files state they are
      modified work based on go-algorand.
- [ ] `docs/LICENSING.md` + checked-in per-file audit table exist.
- [ ] `CLAUDE.md` and all `.claude/skills/*` enforce the header logic for
      future files.
- [ ] Full gate green on `main` after the (behavior-neutral) sweep.
- [ ] `docs/PHASE15_VALIDATION.md` evidence map written at close-out.
- [ ] Hard gate: `gh issue list --label "phase:15" --state open` empty
      before this epic closes.
