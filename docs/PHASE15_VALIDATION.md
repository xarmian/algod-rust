# Phase 15 Validation — Licensing and Legal-Framework Compliance

_Completed: 2026-08-29_

Phase 15 brought algod-rust from **unlicensed** to full compliance with
the legal framework it operates under: correct AGPL/MIT classification,
repo-level license files, per-file headers, crate metadata, third-party
attributions, an in-node AGPL §13 source pointer, and standing process
rules so future work stays compliant.

This document is the evidence map for
[`docs/PHASE15_PROPOSAL.md`](PHASE15_PROPOSAL.md) and
[`docs/epics/Epic-25-Licensing-Compliance.md`](epics/Epic-25-Licensing-Compliance.md).
Every claim below cites a specific file/test/tool in this repo.

Tracking epic: [#732](https://github.com/xarmian/algod-rust/issues/732).

---

## Decisions implemented

1. algod-rust as a whole is classified as a **modified work based on
   go-algorand, licensed AGPL-3.0-or-later**, preserving go-algorand's
   AGPL section 7e Additional Terms (Algorand trademark reservation).
2. **MIT wherever legally possible** — files not derived from AGPL
   material are MIT; when in doubt, AGPL.
3. Legal entity for all copyright/attribution statements: **`Algod DAO`**.
4. Deriving from go-algorand's AGPL source is accepted and intended (and
   is what conveys the Algorand patent license per go-algorand's own
   `COPYING_FAQ` item 6).

## Sub-issue disposition

| Sub-issue | PR(s) | Evidence |
|---|---|---|
| [#731](https://github.com/xarmian/algod-rust/issues/731) legal: resolve repository licensing | [#734](https://github.com/xarmian/algod-rust/pull/734), [#735](https://github.com/xarmian/algod-rust/pull/735), [#736](https://github.com/xarmian/algod-rust/pull/736), [#737](https://github.com/xarmian/algod-rust/pull/737), [#738](https://github.com/xarmian/algod-rust/pull/738), [#739](https://github.com/xarmian/algod-rust/pull/739), [#740](https://github.com/xarmian/algod-rust/pull/740), [#741](https://github.com/xarmian/algod-rust/pull/741) | See parts A–E below. |
| [#742](https://github.com/xarmian/algod-rust/issues/742) rest-api: in-node AGPL §13 source pointer (follow-up, found while closing out #731) | [#743](https://github.com/xarmian/algod-rust/pull/743) | See "AGPL §13 compliance" below. |

Issue #731 was briefly, incorrectly auto-closed after Part A/B1 merged
(despite every PR body using "Part of #731", not "Fixes #731") — caught
and reopened before Parts B2–E landed, then closed for real once every
part was genuinely complete, per this document's audit below.

### Part A — audit + repo license files (PR #734)

- `docs/LICENSING_AUDIT.md`: directory/crate-level classification of all
  1,457 tracked files at the time of writing into (a) AGPL-derived, (b)
  MIT-eligible, (c) third-party-derived, with the "when in doubt, AGPL"
  rule stated explicitly and every exception to a directory's default
  called out by file.
- `COPYING`: full AGPL-3.0-or-later text with go-algorand's section 7e
  Additional Terms preserved **verbatim** (diffed byte-for-byte against
  `../go-algorand/COPYING`; only the introductory framing paragraph was
  adapted).
- `LICENSE-MIT`: Copyright (c) 2026 Algod DAO.
- `README.md` "Licensing" section describing the dual structure.
- `docs/LICENSING.md`: classification rationale (quoting go-algorand's
  own `COPYING_FAQ` item 2), trademark posture, patent rationale
  (`COPYING_FAQ` item 6), third-party attributions.
- **Key finding**: the Phase 15 proposal's working assumption that
  `github.com/algorand/falcon` carries AGPL headers throughout was
  corrected — the AGPL header applies to the Go wrapper module, but the
  vendored C sources in `crates/core/algo-falcon/falcon-c/` are
  separately, correctly MIT-licensed with their own `LICENSE` file.

### Parts B1–B3 — per-file headers (PRs #735, #736, #738; fixup #739)

- **B1** (PR #735): 435 `.rs` files under `crates/core/*`, `crates/node/*`,
  `bin/*` — all AGPL, pure insertions (8,722 insertions, 0 deletions,
  verified via `git diff --stat`). `crypto.rs` (poseidon2) and
  `sumhash.rs` got localized third-party attribution blocks in addition
  to the file-top AGPL header.
- **B2** (PR #736): 132 files (91 Rust AGPL under `crates/tools/*`, 7
  Rust MIT under `algo-bench`, 27 Go AGPL under `tools/*` and the
  parity-asserting Go programs elsewhere in the tree) — pure insertions
  (2,535 insertions, 0 deletions).
- **B3** (PR #738): 70 MIT files — `.github/workflows/*.yml`, `docker/`,
  `ops/`, `scripts/*.sh`, `fuzz/*` — pure insertions (325 insertions, 0
  deletions), with every shell script's shebang line verified to remain
  byte 0 of the file.
- **PR #739**: small addendum recording the deliberate decision NOT to
  header prose Markdown docs (README, CLAUDE.md, `docs/*.md`) — standard
  OSS practice doesn't header documentation, and doing so here would add
  no attribution value beyond what the repo-root license files and the
  audit table already provide.

Total: 637 source/config files headered across Parts B1–B3, all as pure
insertions — confirmed behavior-neutral (see "Full gate" below).

### Part C — Cargo.toml license metadata (PR #737)

- Root `Cargo.toml`'s `[workspace.package]` sets
  `license = "AGPL-3.0-or-later"`; 26 crates inherit it via
  `license.workspace = true`.
- 2 crates explicitly override to MIT: `algo-bench`, `fuzz` (its own
  standalone workspace).
- `cargo metadata` confirms all 27 members resolve to the expected
  license.

### Part D — standing process enforcement (PR #740)

- `CLAUDE.md` gained a "## Licensing" section: classification summary,
  `Algod DAO` as the legal entity, and the mandatory rule that every new
  source file must carry the correct header at creation time (AGPL
  default, MIT only for genuinely original files, third-party attribution
  layered on top when applicable).
- `.claude/skills/algod-issue-fix/SKILL.md`: license-header check added
  to both the self-review step and the pre-merge acceptance-criteria
  audit, as a first-class blocking item.
- `.claude/skills/algod-issue-create/SKILL.md`: acceptance-criteria
  checklist template gained a conditional license-header line.
- `.claude/skills/algod-version-upgrade/SKILL.md`: Stage 6 implementation
  loop guidance now notes new source files need the same header
  treatment (Stage 4's proposal-doc Markdown stays exempt).
- `go-algorand-version-lookup/SKILL.md`: explicitly confirmed out of
  scope (pure lookup skill, creates no files) rather than edited
  unnecessarily.

### Part E — CI enforcement (PR #741)

- `.github/scripts/check-license-headers.py` + a new
  `.github/workflows/license-compliance.yml` workflow: fails CI if any
  in-scope tracked file is missing `SPDX-License-Identifier:` in its
  first ~20 lines. Verified against a real negative case (a throwaway
  unheadered file was flagged and removed before commit) and against the
  real repo state: **626 in-scope files, zero missing headers**, no
  fixup needed.
- `docs/DEPENDENCY_LICENSES.md`: manual `cargo metadata`-based audit of
  all 588 external dependencies — all permissive (MIT/Apache-2.0/BSD/ISC
  or an available permissive OR-branch), no GPL-family incompatibilities
  found.
- `cargo-deny` (via `EmbarkStudios/cargo-deny-action`) wired into the same
  workflow as a real, blocking check (not left advisory) — its first real
  CI run surfaced and this PR fixed two genuine bugs in the pre-existing,
  previously-unused `deny.toml` (written against an outdated schema, and
  missing an allow-list entry for algod-rust's own AGPL workspace crates).

## AGPL §13 compliance (issue #742, PR #743)

Part A's `docs/LICENSING.md` honestly recorded that no in-node mechanism
existed yet to satisfy go-algorand's own `COPYING_FAQ` item 3 (operators
of a modified AGPL node must prominently offer the exact corresponding
source to anyone interacting with it over a network). Rather than touch
the `/versions` JSON response body (which is byte-for-byte parity-tested
against go-algorand via `bin/algod-rust/tests/live_go_parity.rs`'s
`versions_match_except_build_metadata`), this was implemented as:

- A global `X-Algod-Rust-Source: https://github.com/xarmian/algod-rust`
  HTTP response header (`crates/node/algo-rest-api/src/source_header.rs`),
  registered as the outermost middleware layer so it covers every
  response including CORS preflights and unmatched routes, without
  touching any response body.
- A one-line startup log banner (`crates/node/algo-rest-api/src/server.rs`).
- Live-verified: `bin/algod-rust/tests/live_headers_parity.rs` confirms
  the header's presence/value on algod-rust and its absence on go (as
  expected — go-algorand doesn't need this, it isn't a further
  derivative), with no regression to the existing allowlisted-header
  parity assertions.
- `docs/LICENSING.md` updated to record the mechanism as implemented.

## Full gate on `main`

Re-run at close-out (2026-08-29):

- `cargo fmt --all --check` — one pre-existing diff in
  `crates/core/algo-avm/src/assembler.rs`, confirmed by multiple PRs in
  this epic (via `git stash` against unmodified `main`) to predate and be
  unrelated to any licensing-sweep change (a rustfmt-version drift issue).
- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `cargo test --workspace` — every crate green except the pre-existing,
  documented `algo-network` `peer_features.rs` doctest flake (CLAUDE.md's
  known local-environment issue).
- `.github/scripts/check-license-headers.py` run locally — 626/626
  in-scope files headered, zero missing.

## Behavior-neutrality confirmation

Every header-sweep PR (B1, B2, B3) was verified via `git diff --stat`/
`--shortstat` to be pure insertions (0 deletions) before merge, and the
full workspace test suite (including golden fixture tests, doctests, and
the live dual-node conformance suite) stayed green throughout — the
licensing sweep changed no runtime behavior.

## Outcome

All of issue #731's original 9 acceptance criteria are met, plus the
follow-up #742 (in-node AGPL §13 pointer) filed and resolved during
close-out. `gh issue list --label "phase:15" --state open` returns only
the epic issue itself, confirmed immediately before this document was
written. The repository is now fully licensed: AGPL-3.0-or-later as a
whole (with preserved section 7e Additional Terms), MIT for
non-AGPL-derived files, third-party attributions recorded, `Algod DAO` as
the copyright entity throughout, and CI enforcement in place so this
stays true going forward.
