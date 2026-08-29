# Licensing Audit — per-directory/crate classification

Part of the Phase 15 licensing-compliance epic
([#732](https://github.com/xarmian/algod-rust/issues/732)), implementing
[issue #731](https://github.com/xarmian/algod-rust/issues/731). This is the
single source of truth every later part of the licensing work (per-file
headers, `Cargo.toml` `license` fields, CI header check) builds on.

## The rule

Every file in this repository is classified into exactly one of three
buckets:

- **(a) AGPL-derived** — ported from, translated from, or structurally
  derived from go-algorand (or the AGPL `github.com/algorand/sortition` /
  `github.com/algorand/falcon` Go modules). go-algorand's own
  `COPYING_FAQ` (item 2) states that modifying the node software,
  reimplementing its APIs, using its consensus mechanism, or otherwise
  creating a new work based on AGPL-licensed Algorand materials produces a
  work automatically licensed under the AGPL. Most of this repository —
  a full Rust reimplementation of the node, its REST API, its wire
  protocol, and its consensus mechanism, developed file-by-file against
  the go-algorand source as the authoritative reference — falls in this
  bucket.
- **(b) MIT-eligible** — genuinely original work with no AGPL derivation.
- **(c) Third-party-derived** — ported from an identifiable third-party
  source that is neither algod-rust's own original work nor go-algorand
  itself (e.g. gnark-crypto, Apache-2.0). A (c) file is classified (c) *in
  addition to* (a) or (b) depending on whether the surrounding crate/file
  is itself an AGPL modified work — the third-party attribution is layered
  on top, not a replacement for the AGPL/MIT call.

**When in doubt, classify as (a) AGPL.** Over-claiming MIT is the legal
risk (it would misrepresent a derivative work as unencumbered); classifying
a genuinely original file as AGPL out of caution costs nothing but a
slightly broader copyleft footprint on our own code, which the project
owner has already accepted as the default posture (decision 4 in
`docs/PHASE15_PROPOSAL.md`).

This document classifies at **directory/crate granularity**, which is more
practical than a 1,457-file table for a repository this size. Every
exception to a directory's default classification is called out
explicitly by file. Per-file license *headers* implementing this
classification are out of scope for this PR — see "What's deferred" below.

## Repository-root files

| Path | Classification | Rationale |
|---|---|---|
| `Cargo.toml`, `Cargo.lock` (workspace) | (b) MIT | Build manifest / lockfile; no derived content. |
| `rustfmt.toml`, `rust-toolchain.toml`, `clippy.toml`, `deny.toml`, `codecov.yml`, `.gitattributes`, `.gitignore`, `.pad.toml`, `.cargo/*` | (b) MIT | Tooling configuration, original to this project. |
| `Makefile` | (b) MIT | Original build/test/localnet orchestration; drives both algod-rust and go-algorand binaries but embeds no ported source. |
| `README.md`, `CLAUDE.md` | (b) MIT | Project documentation. |
| `COPYING` | N/A (license text itself) | Full AGPL-3.0-or-later text + go-algorand's section 7e Additional Terms, preserved verbatim as inherited terms (see repo root `COPYING`). |
| `LICENSE-MIT` | N/A (license text itself) | Standard MIT text, Copyright (c) 2026 Algod DAO. |

## `crates/core/*` — consensus-critical Rust crates

| Crate | Classification | Rationale |
|---|---|---|
| `algo-error` | (a) AGPL | Error taxonomy mirrors go-algorand's error surfaces used throughout the reimplementation; small crate, but consumed only by AGPL-derived crates. |
| `algo-types` | (a) AGPL | Ports `data/basics`, `data/transactions`, block/account/transaction structures bit-for-bit from go-algorand. |
| `algo-codec` | (a) AGPL | Canonical msgpack encode/decode reimplementing go-algorand's exact wire format (`github.com/algorand/msgp`-compatible canonical encoding rules). |
| `algo-avm` | (a) AGPL | TEAL/AVM interpreter — direct port of `data/transactions/logic/eval.go` and the opcode table. **Exception:** see "Third-party-derived exceptions" below for the poseidon2 opcode. |
| `algo-ledger` | (a) AGPL | Ledger state, block-apply, simulation engine — ports `ledger/`, `ledger/apply/`, `ledger/simulation/`. |
| `algo-validate` | (a) AGPL | Transaction/block/signature validation reimplementing go-algorand's validation rules. |
| `algo-agreement` | (a) AGPL | Agreement (consensus) protocol types and certificate verification, reimplementing `agreement/`. |
| `algo-consensus-crypto` | (a) AGPL | VRF, one-time signatures, Merkle signature scheme reimplementing `crypto/`. **Exception:** see `sumhash.rs` below. |
| `algo-falcon` | (a) AGPL (Rust integration layer) | `src/lib.rs`, `build.rs`, `Cargo.toml` — the FFI wrapper and wire-format constants are written to match go-algorand's *deterministic* Falcon-1024 consensus usage exactly (custom salt/header scheme used on-chain), which is consensus-critical integration work. **Exception:** the vendored C sources under `falcon-c/` are third-party — see below. |
| `algo-pool` | (a) AGPL | Transaction pool reimplementing `data/pools/`. |

### Third-party-derived exceptions inside `crates/core`

| File(s) | Classification | Upstream source |
|---|---|---|
| `crates/core/algo-avm/src/ops/crypto.rs` — specifically the `poseidon2_*` functions (`op_poseidon2`, `poseidon2_bn254`, `poseidon2_bls12_381`, `poseidon2_merkle_damgard`, `poseidon2_permutation`, `poseidon2_sbox`, `poseidon2_mat_mul_external`, `poseidon2_mat_mul_internal`, `poseidon2_round_keys`, and the MiMC-derived round-key/constant derivation referenced in the surrounding doc comments) — added in PR #689/#697 (issue #665) | (a) AGPL *as part of* `algo-avm`, **plus** (c) third-party attribution | Hand-ported from **gnark-crypto v0.18.1** (`github.com/consensys/gnark-crypto`), Copyright ConsenSys Software Inc., **Apache License 2.0**. Apache-2.0 carries attribution/NOTICE-retention obligations for the derived portion; see `docs/LICENSING.md` for the specific attribution text. |
| `crates/core/algo-consensus-crypto/src/sumhash.rs` (all of it — the file's own doc comment states it matches go-algorand's `go-sumhash`) | (a) AGPL *as part of* `algo-consensus-crypto`, **plus** (c) third-party attribution | Reimplements the Sumhash-512 algorithm and parameters (seed `b"Algorand"`, n=8, m=1024) matching **`github.com/algorand/go-sumhash`**, which go-algorand's own `COPYING_FAQ` (item 1) identifies as one of Algorand's **MIT**-licensed SDK/helper libraries. Classified AGPL as part of algod-rust because it is consensus-critical code inside an otherwise-AGPL crate (drives the sumhash-based state proof / AVM opcode paths that are integration points with go-algorand's protocol), but the upstream algorithm source itself is MIT and is attributed as such. |
| `crates/core/algo-falcon/falcon-c/*.c`, `*.h` (the vendored C library) | (c) Third-party, standalone MIT | Vendored verbatim from **`github.com/algorand/falcon` v0.1.0**. The vendored C sources carry their own MIT license header (Copyright (c) 2017–2019 Falcon Project; deterministic-mode extensions Copyright (c) Algorand, Inc.) and their own `falcon-c/LICENSE` file, already present and correct — **no changes needed**. Note this is narrower than `docs/PHASE15_PROPOSAL.md`'s working assumption that "`algorand/falcon` carries AGPL headers": that AGPL header applies to the *Go wrapper module* `github.com/algorand/falcon`, not to the vendored C sources themselves, which state MIT plainly in both the file headers and `falcon-c/LICENSE`. |

## `crates/node/*`

| Crate | Classification | Rationale |
|---|---|---|
| `algo-rest-api` | (a) AGPL | Full REST API v2 reimplementation (`daemon/algod/api/server/v2/`) — API reimplementation is explicitly AGPL-triggering per `COPYING_FAQ` item 2. |
| `algo-rest-client` | (a) AGPL | Client for the above wire protocol, parallel block fetching mirroring go-algorand's catchup/fetcher behavior. |
| `algo-network` | (a) AGPL | Gossip/P2P wire-protocol reimplementation (`network/`), block/cert/vote propagation. |
| `algo-p2p` | (a) AGPL | libp2p transport — its own doc comment states it is "the Rust counterpart to go-algorand's `network/p2p/` package." |
| `algo-kmd` | (a) AGPL | Its own doc comment states it is a "Rust port of go-algorand's `daemon/kmd`." |
| `algo-kmd-api-types` | (a) AGPL | Its own doc comment states the wire shapes are "Ported from `../go-algorand/daemon/kmd/lib/kmdapi/...`." |
| `algo-kmd-client` | (a) AGPL | Its own doc comment states it "Mirrors `../go-algorand/daemon/kmd/client/`." |
| `algo-txn-pipeline` | (a) AGPL | Composes `algo-rest-client` and `algo-kmd-client` (both AGPL) into the build→sign→submit→confirm path used by the CLI reimplementations; the pipeline's transaction-construction/signing semantics mirror go-algorand/goal's own txn-building rules. |

## `crates/tools/*` (Rust)

| Crate | Classification | Rationale |
|---|---|---|
| `algo-fixtures` | (a) AGPL | Fixture capture directly against a running go-algorand node's block stream, used to assert byte-for-byte parity. |
| `algo-conformance` | (a) AGPL | Conformance comparison engine (Rust vs Go), comparing block/state output field-by-field against go-algorand semantics. |
| `algo-cert-crossverify` | (a) AGPL | Certificate cross-verification against `algo_agreement::Certificate::authenticate`, an AGPL-derived module. |
| `algo-fork-detector` | (a) AGPL | Mixed-cluster fork detection comparing algod-rust and go-algorand node state. |
| `algo-agreement-fuzz` | (a) AGPL | Constructs agreement (consensus) protocol messages to test against go-algorand's own conformance acceptance — inherently structured around go-algorand's wire semantics. |
| `algokey-rust` | (a) AGPL | Its own doc comment states it is a "Rust port of `../go-algorand/cmd/algokey`." |
| `goal-rust` | (a) AGPL | CLI reimplementation of `goal`'s command surface and output formatting, parity-tested against go-algorand's `goal` binary output. |
| `algo-bench` | (b) MIT | Benchmark metrics collection, JSON output, and comparison-table rendering. Original tooling: it formats and compares numbers produced by other (AGPL) crates and by go-algorand's own binaries, but embeds no ported algorithm or protocol logic itself. |

## `crates/tools/*-oracle` / `*-capture` (Go helper programs under `tools/`)

All 21 programs under `tools/` (see list below) exist specifically to
generate or verify byte-for-byte parity fixtures against go-algorand's
behavior — the exact category the issue calls out ("any test/tool that
ports go-algorand logic or asserts parity against it"). Classification:
**(a) AGPL for all of them**, including the two that do not directly
`import` the `github.com/algorand/go-algorand` Go module, because each one
exists to replicate or verify a specific piece of go-algorand's protocol
behavior:

| Program | Imports go-algorand/sortition/falcon directly? | Classification | Note |
|---|---|---|---|
| `agreement-wire-capture`, `avm-opcode-capture`, `cert-authenticate`, `checktxngroup-oracle`, `go-trie-replay-bench`, `kmd-api-wire-capture`, `kmd-rest-interop`, `kmd-wallet-fixture-capture`, `kmd-wallet-interop`, `kmd-wallet-multisig-fixture-capture`, `kmd-wallet-with-keys-fixture-capture`, `lookback-vector-capture`, `merkle-page-capture`, `merkle-trie-root-capture`, `required-field-decode-oracle`, `trie-element-capture`, `vfuture-consensus-override`, `vrf-vector-capture` (18 programs) | Yes (`go.mod` requires `github.com/algorand/go-algorand`) | (a) AGPL | Direct AGPL-module dependency. |
| `sortition-vector-capture` | Imports `github.com/algorand/sortition` directly (AGPL module, same `COPYING` + 7e terms as the node) | (a) AGPL | Direct AGPL-module dependency (sortition, not go-algorand itself). |
| `kmd-crypto-vector-capture` | No — only imports `github.com/algorand/go-codec/codec` (MIT) | (a) AGPL | Its own doc comment states the goal is producing "the same bytes as go-algorand" and cites the exact upstream file (`daemon/kmd/wallet/driver/sqlite_crypto.go`) it replicates — a structural port of go-algorand's key-derivation logic even though it only links an MIT dependency to do the byte-level work. |
| `v13-vector-capture` | No — only imports `github.com/algorand/go-sumhash` (MIT) | (a) AGPL | Exists to produce vectors asserting parity with go-algorand's `opSHA512`/`opSumhash512` opcode behavior; same "asserts parity against go-algorand" criterion as above. |

`docker/scripts/canonical-extract/main.go` (a separate Go module under
`docker/scripts/`, not `tools/`) is the one exception in the opposite
direction: it imports only `github.com/algorand/go-algorand-sdk/v2`, the
**MIT**-licensed SDK go-algorand's own FAQ (item 1) identifies as
permissively licensed, to extract data via the algod REST API. It does
not import go-algorand itself and does not port node logic — see the
"docker/, ops/" section below.

## `bin/*` (Rust binaries)

| Crate | Classification | Rationale |
|---|---|---|
| `bin/algod-rust` | (a) AGPL | The node binary itself — CLI, `sync`/`serve`/`participate`/etc. commands, node-interface implementation. The live parity tests under `bin/algod-rust/tests/live_*` assert byte-for-byte parity against a running go-algorand node. |
| `bin/kmd-rust` | (a) AGPL | KMD daemon binary wrapping the AGPL `algo-kmd` crate. |

## `fuzz/*`

| Path | Classification | Rationale |
|---|---|---|
| `fuzz/fuzz_targets/*.rs`, `fuzz/Cargo.toml` | (b) MIT | Each fuzz harness is a few lines of original glue calling into this project's own (AGPL) library crates (`algo_ledger::apply_transaction`, etc.) with arbitrary input. The harness itself doesn't port or assert parity against go-algorand — it fuzzes our own code. Classified separately from the AGPL crates it exercises, consistent with the proposal's "a script that drives \[something\] isn't itself AGPL-derived just by proximity" guidance. |

## `benchmarks/*`

| Path | Classification | Rationale |
|---|---|---|
| `benchmarks/go-decode/*` | (a) AGPL | Its own doc comment states it "benchmarks go-algorand's msgpack block decoding," and its `go.mod` requires `github.com/algorand/go-algorand` directly to invoke the node's own decode path for a head-to-head comparison. |

## `tests/*`, `scripts/*` (repo-root)

| Path | Classification | Rationale |
|---|---|---|
| `tests/golden/gen_agreement_vectors.go` | (a) AGPL | Its own header states it references unexported types from go-algorand's `agreement`/`committee` packages and is run *inside* the go-algorand source tree to produce golden vectors — a structural extension of go-algorand's own test code. |
| `scripts/build-phase-b-fixtures.go` | (a) AGPL | Produces Go-signed transaction fixtures for `algokey-rust` parity tests; drives go-algorand's own signing code paths for comparison. |
| `scripts/capture-algokey-fixtures.sh`, `scripts/capture-phase-b-fixtures.sh`, `scripts/capture-pqsig-fixtures.sh` | (b) MIT | Shell orchestration (build/run the above Go programs, arrange output) with no ported logic of its own. Note these scripts *invoke* AGPL-classified Go programs but are themselves thin process orchestration, matching the "isn't itself AGPL-derived just by proximity" carve-out — the substantive logic lives in the `.go` file, not the `.sh` wrapper. |

## `docker/`, `ops/` — infra and operational tooling

Verified individually per the proposal's instruction not to assume:

| Path | Classification | Rationale |
|---|---|---|
| `docker/Dockerfile`, `docker/docker-compose*.yml` | (b) MIT | Original container/orchestration definitions written for this project. |
| `docker/config/*.json` (e.g. `vfuture-consensus.json`, `relay-template.json`) | (b) MIT | Node configuration *data* (network parameters, endpoint templates) — not source code, and not a copyrightable expression of go-algorand's implementation; several values are necessarily identical to go-algorand's own defaults because they are protocol-level facts (e.g. consensus-version strings), not original creative expression. |
| `docker/localnet-rust/data/*` | (b) MIT | Generated/template genesis and config data for the local devnet. |
| `docker/scripts/*.sh` (`bench-cluster.sh`, `gen-localnet-genesis.sh`, `generate-txns.sh`, `stress-bootstrap.sh`, `vfuture-entrypoint.sh`, etc.) | (b) MIT | Original CI/ops shell scripts driving containers; none embed ported go-algorand algorithmic logic (verified individually — they call binaries and format arguments). |
| `docker/scripts/stress-report.py` | (b) MIT | Original Python report formatting. |
| `docker/scripts/canonical-extract/*.go` | (b) MIT | Imports only the MIT-licensed `go-algorand-sdk/v2` (per `COPYING_FAQ` item 1's own MIT classification of Algorand's SDKs) to pull data over the REST API; comments reference go-algorand schema paths for documentation but no go-algorand source is imported or ported. |
| `ops/mixed-cluster*/docker-compose.yml`, `template.json`, `README.md` | (b) MIT | Original cluster-topology definitions and docs. |
| `ops/mixed-cluster*/scripts/*.sh` | (b) MIT | Original orchestration (start/stop/status/soak) shell scripts. |
| `ops/mixed-cluster*/scripts/*.py` (`metrics.py`, `analyze.py`, `equivocation.py`, `analyze_test.py`, `equivocation_test.py`) | (b) MIT | Original monitoring/analysis tooling. These scripts *describe* go-algorand's semantics in comments (e.g. citing `agreement/bundle.go`'s equivocation-vote handling as rationale for what the detector looks for) but implement their own independent log-parsing and detection logic, not a port of go-algorand's algorithm. |

## `.github/workflows/*`

| Path | Classification | Rationale |
|---|---|---|
| All workflow YAML | (b) MIT | CI orchestration (checkout, build, run tests/tools, upload artifacts) — original to this project. Several workflows build and run go-algorand binaries as a comparison oracle, which is proximity, not derivation. |

## `.claude/*`

| Path | Classification | Rationale |
|---|---|---|
| `.claude/commands/*.md`, `.claude/skills/*/SKILL.md` | (b) MIT | Project-specific workflow instructions for the Claude Code agent harness; original process documentation, not derived from go-algorand source. (Updating these to enforce the header logic for *future* files is separately scoped — see "What's deferred" below; that update itself will also be MIT.) |

## `docs/*`

| Path | Classification | Rationale |
|---|---|---|
| All of `docs/*.md`, `docs/epics/*.md` | (b) MIT | Planning/proposal/validation/architecture documentation. These describe go-algorand's behavior extensively (as they must, to specify parity work) but are original prose analysis and project records, not verbatim reproductions of go-algorand source or documentation. None were found to quote ported algorithms closely enough to themselves be derivative. |
| `docs/LICENSING_AUDIT.md` (this file), `docs/LICENSING.md` | (b) MIT | Original to this phase. |

**File-level headers are deliberately NOT added to prose Markdown docs**
(`README.md`, `CLAUDE.md`, all of `docs/*.md`, `.claude/**/*.md`) — this
diverges from the per-file header sweep applied to every other
MIT-classified file in the repository, so the decision and its rationale
are recorded explicitly here rather than left implicit. A per-file
copyright/SPDX comment block is standard practice for source and config
files (compilers/linters and tooling like `cargo-license`/REUSE scanners
read them), but is not standard or expected practice for a project's own
prose documentation — no mainstream open-source project headers its
README or design docs this way, and doing so here would add no
verification/attribution value beyond what the repo-root `COPYING` /
`LICENSE-MIT` files and this audit table already provide for every file
in the tree, including the unheadered docs. If this decision needs
revisiting, it is a small, contained follow-up (a handful of files), not
a re-audit.

## `crates/tools/goal-rust/tests/fixtures/license.txt`

This file is a **test fixture** — captured output used to assert that
`goal-rust`'s license-display subcommand parity-matches go-algorand's
`goal license` output byte-for-byte (verified: it lives under
`tests/fixtures/`, alongside other parity-fixture files in that crate).
It is **not** a project license file and is unaffected by this audit's
license-file additions (`COPYING`, `LICENSE-MIT`) at the repo root. Its
own classification follows its parent crate, `goal-rust`: (a) AGPL (test
fixture asserting parity, per the same rule as the rest of `goal-rust`'s
tests).

## Summary counts (directory/crate level)

- **(a) AGPL-derived**: all 10 `crates/core/*` crates, all 8 `crates/node/*`
  crates, 7 of 8 `crates/tools/*` Rust crates (all but `algo-bench`), both
  `bin/*` binaries, all 21 Go programs under `tools/`,
  `benchmarks/go-decode`, `tests/golden/gen_agreement_vectors.go`,
  `scripts/build-phase-b-fixtures.go`.
- **(b) MIT-eligible**: repo-root tooling/config files, `README.md`,
  `CLAUDE.md`, all of `docs/*`, all of `.github/workflows/*`, all of
  `.claude/*`, all of `docker/*` except none (all verified MIT — including
  `canonical-extract`), all of `ops/*`, `fuzz/*`, `algo-bench`, the shell
  wrappers under `scripts/*.sh`.
- **(c) Third-party-derived** (layered on top of (a) classification):
  poseidon2 functions in `crates/core/algo-avm/src/ops/crypto.rs`
  (gnark-crypto v0.18.1, Apache-2.0); `crates/core/algo-consensus-crypto/src/sumhash.rs`
  (go-sumhash, MIT); `crates/core/algo-falcon/falcon-c/*` (algorand/falcon
  v0.1.0 C sources, MIT, standalone — not layered on (a), already has its
  own correct `LICENSE` file).

No file was found where the audit's outcome was genuinely ambiguous after
inspection; every close call above (the two `tools/*-capture` programs
without a direct go-algorand import, `algo-falcon`'s Rust wrapper vs. its
vendored C sources, `docker/scripts/canonical-extract`) is resolved and
explained with its specific evidence, per the "when in doubt, AGPL" rule
applied to genuine ambiguity rather than to settle every case.

## What's deferred to later parts of #731 / epic #732

This PR (Part A) is scoped to the audit above plus the repo-level license
files, `README.md` licensing section, and `docs/LICENSING.md`. The
following are explicitly **not** done here and are left for later parts,
per the calling workflow's PR-scoping instruction:

- Per-file SPDX license headers (using the classification in this table).
- `license` SPDX fields in every `Cargo.toml`.
- `CLAUDE.md` / `.claude/skills/*` updates enforcing header logic for new
  files.
- A CI header-presence check.
- The Rust dependency-tree license-compatibility check (`cargo-deny` /
  `cargo-about` or documented audit).
