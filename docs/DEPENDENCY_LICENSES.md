# Dependency license audit — crates.io dependency tree

Part of the Phase 15 licensing-compliance epic
([#732](https://github.com/xarmian/algod-rust/issues/732)), implementing
[issue #731](https://github.com/xarmian/algod-rust/issues/731) parts D/E.
Confirms the Rust dependency tree stays compatible with algod-rust being
redistributed as an AGPL-3.0-or-later work (see
[`docs/LICENSING.md`](LICENSING.md) for why the project as a whole is
AGPL-derived).

## Tooling status

`deny.toml` (repo root) already configures
[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny)'s `[licenses]`
allow-list (MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode-3.0, Zlib,
MPL-2.0, OpenSSL, and a couple of Apache-2.0-with-exception variants), and
`.github/workflows/license-compliance.yml` now runs `cargo-deny check
licenses` on every PR via `EmbarkStudios/cargo-deny-action` (which
downloads a prebuilt `cargo-deny` binary rather than compiling one).

That CI job is marked **advisory** (`continue-on-error: true`) rather than
blocking, for one honest reason: **`cargo-deny` itself could not be built
or run in this authoring session** to pre-confirm the full dependency tree
passes `deny.toml`'s allow-list before landing the check. This session
runs on a Windows sandbox with a broken VS "18" toolchain install (see
`CLAUDE.md`'s Windows environment notes) and, independently, a hard
`Access is denied` sandbox restriction on executing freshly-built binaries
out of the temp directory `cargo install` uses — confirmed by two
different failure modes on two separate `cargo install cargo-deny
--locked` attempts (build-script execution denied from `%TEMP%`, then a
`link.exe`/`msvcrt.lib` failure once redirected to an in-repo build
directory, tracing back to the same broken VS "18" install). Neither
failure is specific to `cargo-deny`'s dependencies or to this repo's own
code — GitHub Actions' `ubuntu-latest` runners don't share either
constraint — but it means this PR cannot say "we ran cargo-deny locally
and it's clean," only "the manual audit below, done via `cargo metadata`,
found nothing incompatible." The job stays advisory until a real CI run
(or a working local install) confirms a clean pass, at which point
`continue-on-error` should be dropped.

## Manual audit (this PR's actual verification)

Performed via `cargo metadata --format-version 1` (enumerates the full
resolved dependency graph including transitive deps, with each package's
own `Cargo.toml` `license` field — no `cargo-deny`/`cargo-tree` build
required) against the workspace `Cargo.lock` as of this PR:

- **616** total resolved packages, of which **28** are algod-rust's own
  workspace crates and **588** are external (crates.io) dependencies.
- License-field breakdown across all 588 external dependencies (grouped by
  the exact `license` string; most crates are dual/triple-licensed with
  `OR`, meaning a downstream user — algod-rust — may choose any one of the
  listed licenses):

  | License expression | Count |
  |---|---|
  | `MIT OR Apache-2.0` | 275 |
  | `MIT` | 123 |
  | `Apache-2.0 OR MIT` | 57 |
  | `MIT/Apache-2.0` | 42 |
  | `Unicode-3.0` | 18 |
  | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 14 |
  | `Apache-2.0` | 12 |
  | `BSD-3-Clause` | 6 |
  | `Unlicense OR MIT` | 4 |
  | `Zlib OR Apache-2.0 OR MIT` | 4 |
  | `ISC` | 4 |
  | `Apache-2.0 OR ISC OR MIT` | 3 |
  | `MIT OR Apache-2.0 OR Zlib` | 2 |
  | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | 2 |
  | `Unlicense/MIT` | 2 |
  | `BSD-2-Clause OR Apache-2.0 OR MIT` | 2 |
  | `0BSD OR MIT OR Apache-2.0` | 1 |
  | `BSD-2-Clause` | 1 |
  | `MPL-2.0` | 1 |
  | `ISC AND (Apache-2.0 OR ISC)` | 1 |
  | `ISC AND (Apache-2.0 OR ISC) AND OpenSSL` | 1 |
  | `CC0-1.0 OR MIT-0 OR Apache-2.0` | 1 |
  | `MIT OR Apache-2.0 OR BSD-1-Clause` | 1 |
  | `Apache-2.0 / MIT` | 1 |
  | `Zlib` | 1 |
  | `MIT OR BSD-3-Clause` | 1 |
  | `MIT AND BSD-3-Clause` | 1 |
  | `MIT OR Zlib OR Apache-2.0` | 1 |
  | `(MIT OR Apache-2.0) AND Apache-2.0` | 1 |
  | `Apache-2.0 AND ISC` | 1 |
  | `Apache-2.0 OR BSL-1.0` | 1 |
  | `(MIT OR Apache-2.0) AND Unicode-3.0` | 1 |
  | `CDLA-Permissive-2.0` | 1 |
  | *(no `license` field)* | 1 |

  Every one of these is either a pure permissive license already on
  `deny.toml`'s allow-list (MIT, Apache-2.0, BSD-2/3-Clause, ISC,
  Unicode-3.0, Zlib, 0BSD, Unlicense, CC0-1.0, MIT-0, BSD-1-Clause), an
  `OR` expression where at least one branch is on that allow-list (so
  algod-rust can and does rely on the permissive option — this is true of
  every multi-license entry above, including the two `... OR
  LGPL-2.1-or-later` packages, where the LGPL branch is never the one
  relied on), or one of the two entries flagged individually below.

### Entries that needed individual attention

- **`attohttpc 0.24.1` — `MPL-2.0` (no `OR` alternative).** MPL-2.0 is a
  *file-level* weak-copyleft license: modifications to MPL-2.0-licensed
  files must stay MPL-2.0/available, but the license's own section 3.3
  explicitly permits combining MPL-2.0 files with a larger work under a
  different license (including AGPL) — this is the standard, FSF- and
  OSI-recognized "GPL/AGPL-compatible" copyleft case, distinct from
  GPL-family licenses that are *not* combination-compatible. No issue for
  redistributing algod-rust as a whole under AGPL-3.0-or-later.
- **`aws-lc-sys 0.38.0` — `ISC AND (Apache-2.0 OR ISC) AND OpenSSL`.**
  All three components (ISC, Apache-2.0, the OpenSSL license) are
  permissive; `AND` here means all three notices must be preserved
  (an attribution/notice obligation, same shape as the rest of this
  audit's Apache-2.0 entries), not that any copyleft term applies.
- **`webpki-roots 1.0.6` — `CDLA-Permissive-2.0`.** This crate ships only
  a compiled-in copy of the Mozilla root CA certificate data (not
  algod-rust source or logic); CDLA-Permissive-2.0 is a permissive *data*
  license (imposes only attribution/notice-preservation, no copyleft),
  used here for exactly the kind of "redistributed reference data" case
  it's designed for.
- **`ring 0.16.20` — no `license` field, ships its own `LICENSE` file
  instead.** `ring` is a long-standing, widely-used crate (a transitive
  dependency here, pulled in via the TLS/crypto stack) that has never
  published a Cargo.toml `license` field; its own `LICENSE` file states
  its terms as a mix of an ISC-style license (for original `ring` code)
  and the OpenSSL license (for code derived from BoringSSL/OpenSSL) —
  both permissive, no copyleft. This is well-documented upstream and is
  exactly why cargo-deny configs across the ecosystem commonly need an
  explicit allow-list entry for `ring` by name; **this session could not
  re-read `ring`'s vendored `LICENSE` file directly** (it isn't present in
  this machine's local cargo registry cache), so this entry is recorded
  as a spot-check based on `ring`'s well-documented public licensing
  terms, not a fresh read of the vendored file — flagged here rather than
  silently assumed, per this audit's own honesty standard. A newer `ring
  0.17.14` (also in the tree, presumably via a different dependency's
  pinned version) does carry a `license` field (`Apache-2.0 AND ISC`),
  consistent with this reading.
- **`r-efi 5.3.0` / `r-efi 6.0.0` — `MIT OR Apache-2.0 OR
  LGPL-2.1-or-later`.** Triple-licensed; algod-rust relies on the MIT or
  Apache-2.0 branch, so the LGPL option is available but not the one in
  effect. (UEFI target support crate — `r-efi` is not on any of
  algod-rust's normal build/runtime paths in practice, but it does appear
  in the resolved lock file.)
- **`ryu 1.0.23` — `Apache-2.0 OR BSL-1.0`.** Apache-2.0 branch relied on;
  Boost Software License 1.0 is itself permissive and would also be fine
  on its own.

### Completeness caveat

This is a **spot-checked, not exhaustively hand-verified** audit: it
trusts each package's self-reported Cargo.toml `license` field (the same
source `cargo-deny` itself uses) rather than opening all 588 dependencies'
actual `LICENSE`/`COPYING` files to confirm the metadata is accurate. That
is the standard level of diligence `cargo-deny`-based license gating
provides across the Rust ecosystem, and it is why the CI job wiring
`cargo-deny check licenses` (not just this document) is the durable,
maintained version of this check going forward — this document is the
one-time manual confirmation that let the check land honestly in a
session where the tool itself couldn't be run. No entry was found that is
GPL-family copyleft in a way that would be incompatible with combination
into an AGPL-3.0-or-later work, and no entry was found unlicensed in the
sense of lacking any redistribution terms at all.

## Reproducing this audit

```
cargo metadata --format-version 1 > cargo-metadata.json
```

then parse `.packages[] | select(.id as $id | ($.workspace_members |
index($id)) == null) | {name, version, license}` (e.g. via `jq`, or the
inline Python used to produce the table above) to get the external
dependency license list. Re-run whenever `Cargo.lock` changes
significantly, or rely on the CI `dependency-licenses` job once it is
promoted from advisory to blocking.
