# Phase 15 Proposal — Licensing and Legal-Framework Compliance

Phase 15 brings algod-rust into full compliance with the legal framework
it operates under: correct license classification, repo-level license
files, per-file headers, crate metadata, third-party attributions, and
standing process rules so all future work stays compliant.

Tracking epic: [#732](https://github.com/xarmian/algod-rust/issues/732).

## Motivation

The repository is currently **unlicensed** — no `COPYING`/`LICENSE` file
at the root, no `license` field in any `Cargo.toml`, and no license
header in any source file (verified 2026-08-29). Meanwhile the governing
upstream, go-algorand, publishes explicit licensing rules that apply to
this project directly.

## Upstream licensing facts (verified against the pinned v5.0.0-stable checkout)

- **go-algorand node software** is licensed under the GNU Affero General
  Public License v3 or later, **with Additional Terms under AGPL
  section 7e** (`COPYING` in the go-algorand repo root). The Additional
  Terms reserve all rights in the Algorand trademarks to Algorand
  Foundation Ltd. — the license grants no trademark rights.
- **go-algorand's `COPYING_FAQ`** (item 2) states that modifying the node
  software, *reimplementing its APIs*, *using Algorand's consensus
  mechanism in other software*, or otherwise creating a new work based on
  AGPL-licensed Algorand materials produces a work automatically licensed
  under the AGPL. algod-rust — a full Rust reimplementation of the node,
  its REST API, and its consensus protocol, developed file-by-file
  against the go-algorand source as its authoritative reference — is
  squarely in this category.
- **Some Algorand materials are MIT** (FAQ item 1: SDKs, example
  applications, helper libraries — verified example:
  `github.com/algorand/go-sumhash`). Vendored third-party code inside
  go-algorand carries its own licenses: `crypto/libsodium-fork` (ISC),
  `crypto/secp256k1` (BSD-style), `util/bloom` (BSD-style).
- **`github.com/algorand/sortition` v1.1.1** (the f128/SelectF128 port
  source for #667) ships the same AGPL-3.0 `COPYING` + section 7e terms
  as the node — that port is AGPL-derived.
- **`github.com/algorand/falcon`** carries AGPL headers; the underlying
  Falcon reference C implementation is permissively licensed —
  `algo-falcon`'s provenance is audited as part of this phase.
- **gnark-crypto v0.18.1** (poseidon2 source for #665) is Apache-2.0,
  which carries attribution/NOTICE obligations for the ported file.
- **Patents** (FAQ item 6): using Algorand source code under the AGPL
  conveys a patent license; clean-room reimplementations without Algorand
  source would require a separate patent license. algod-rust's
  AGPL-derivative classification is therefore also what carries the
  patent license — a reason the classification is desirable, not just
  obligatory.
- **AGPL section 13** (FAQ item 3): operators of a modified node that
  users interact with over a network must prominently offer the exact
  corresponding source for download.

## Decisions (project owner, 2026-08-29)

1. **algod-rust as a whole is classified as a modified work based on
   go-algorand, licensed AGPL-3.0-or-later**, preserving go-algorand's
   section 7e Additional Terms as inherited additional terms.
2. **MIT is preferred wherever legally possible** — files not derived
   from AGPL-licensed material are licensed MIT.
3. **The legal entity for all algod-rust copyright/attribution statements
   is `Algod DAO`.**
4. Deriving from go-algorand's AGPL source is accepted and intended.

## Scope

Sub-issue [#731](https://github.com/xarmian/algod-rust/issues/731)
carries the full work contract (filed analysis-first — no file
modifications until it is picked up for implementation):

- Full-repo per-file audit into three buckets — **(a) AGPL-derived**
  (ports/derivations from go-algorand or the AGPL `sortition`/`falcon`
  modules; the expected default for `crates/core/*`, the REST API,
  networking, CLI reimplementations, and parity tests), **(b)
  MIT-eligible** (genuinely original infra/tooling/docs with no AGPL
  derivation; when in doubt, classify as AGPL — over-claiming MIT is the
  legal risk), **(c) third-party-derived** (poseidon2/gnark-crypto
  Apache-2.0, go-sumhash MIT, libsodium ISC, etc., each attributed
  compatibly within the AGPL whole). Audit table checked in.
- Repo-level `COPYING` (full AGPL-3.0 text + preserved section 7e
  Additional Terms) and `LICENSE-MIT` (Copyright (c) 2026 Algod DAO);
  README licensing section describing the dual structure.
- Per-file headers with SPDX identifiers: AGPL-derived files state they
  are part of algod-rust, **a modified work based on go-algorand**, with
  upstream copyright acknowledged and modifications Copyright (C) 2026
  Algod DAO, mirroring go-algorand's own `scripts/LICENSE_HEADER`
  structure; MIT files get a standard MIT header; third-party-derived
  files add the required upstream attribution.
- `license` SPDX field in every `Cargo.toml` matching the file-level
  classification (one AGPL file makes the crate AGPL).
- `docs/LICENSING.md`: classification rationale, AGPL section 13
  network-source obligation and the implemented source pointer, trademark
  posture under the 7e terms, patent rationale, third-party attributions.
- `CLAUDE.md` and every skill under `.claude/skills/` updated so all
  future files created by the standing workflows get the correct header
  at creation time, with `Algod DAO` as the legal entity, and PR
  self-review checklists include a license-header check.
- Dependency-tree license-compatibility check (cargo-deny/cargo-about or
  documented audit) and a lightweight CI header-presence check.

## Non-goals

- No trademark rights are assumed or claimed; anything requiring
  Algorand's permission (per the 7e terms) is documented for the project
  owner to pursue, not decided unilaterally.
- No behavior changes: the licensing sweep is header/metadata/docs-only
  and must leave the full workspace suite green.
- No re-licensing of upstream material — inherited terms are preserved,
  not altered.

## Success criteria

- Issue #731 merged (or honestly disposed per this repo's
  issue-disposition rules).
- Repo root license files, per-file headers, crate metadata, and
  `docs/LICENSING.md` in place; full gate green on `main`.
- `docs/PHASE15_VALIDATION.md` written at close-out.
- Hard gate: `gh issue list --label "phase:15" --state open` empty before
  the epic closes.
