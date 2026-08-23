---
name: algod-version-upgrade
description: Upgrade algod-rust's parity target to a newer go-algorand version. Given a target version tag (e.g. v4.6.0-stable), analyze every change between the current pin and the target, create one GitHub issue per addition (grouped by feature), open a new epic/phase, sweep the version pin across the whole project, re-checkout the go-algorand reference, then implement every issue via the algod-issue-fix skill. Use when asked to "upgrade to algod version X" or "move to go-algorand vX".
---

# algod-rust version-upgrade workflow

Input: a target go-algorand version tag, e.g. `v4.6.0-stable`. The current pin is recorded in `CLAUDE.md` ("pinned to `<tag>`") — read it there, do not assume. Everything below refers to `OLD` (current pin) and `NEW` (target).

This is a large, multi-session effort. Work through the stages in order; stages 1–5 are analysis/setup (one sitting), stage 6 is the long implementation loop (one `algod-issue-fix` run per issue), stage 7 is close-out.

## Stage 1 — Preflight and reference checkout

1. `git -C ../go-algorand fetch --tags` and verify `NEW` exists (`git -C ../go-algorand tag -l 'NEW'`). If the user gave a bare version ("4.6"), resolve it to the real stable tag and confirm the resolution with them before proceeding.
2. Record the exact commit of `OLD` and `NEW` (`git -C ../go-algorand rev-parse OLD NEW`).
3. Checkout the reference to `NEW` (detached HEAD, matching the existing convention): `git -C ../go-algorand checkout NEW`. Do this **now**, at the start — all subsequent parity reading, fixture regeneration, and `algod-issue-fix` runs must read the NEW source, and a half-updated reference is worse than either endpoint. The analysis in stage 2 uses git ranges, which work regardless of what is checked out.
4. Warn the user explicitly: until stage 6 completes, live conformance against `../go-algorand` binaries built from `NEW` may legitimately fail where behavior changed — that is the gap list from stage 2, not a regression.

## Stage 2 — Change analysis (OLD..NEW)

Goal: an exhaustive, classified list of behavioral changes. Two complementary passes:

**Pass A — merge-level history** (feature granularity, ≈ one entry per upstream PR):

```bash
git -C ../go-algorand log --first-parent --oneline OLD..NEW
```

Also read the upstream release notes for every release in the range (`gh release view NEW -R algorand/go-algorand`, and intermediate releases if OLD..NEW spans several).

**Pass B — parity-surface diffs** (catches behavior changes whose commit message undersells them). Diff each of these and read every hunk:

| go-algorand path | what changes here means |
|---|---|
| `config/consensus.go`, `protocol/consensus.go` | new consensus version(s), new/changed params → `crates/core/algo-types/src/consensus.rs` |
| `data/transactions/logic/opcodes.go`, `eval.go`, `langspec*.json` | new AVM version/opcodes/semantics → `crates/core/algo-avm` |
| `data/transactions/*.go`, `data/bookkeeping/*.go` | new txn types/fields, block header fields, encoding → `algo-types`, `algo-codec`, golden fixtures |
| `ledger/**` (eval, apply, trackers, catchpoint format versions, store schema) | ledger apply/state semantics → `algo-ledger` |
| `agreement/**` | consensus protocol logic → `algo-agreement` |
| `network/**` (protocol version constants, tags, topics) | wire compatibility → `algo-network` |
| `daemon/algod/api/**` (`algod.oas2.json`, handlers, models, routes) | REST surface → `algo-rest-api` |
| `crypto/**` | signature/VRF/state-proof primitives → `algo-consensus-crypto`, `algo-falcon` |
| `data/pools/**` | pool behavior → `algo-pool` |

**Classify every change** into exactly one bucket, and keep the full list (it becomes the epic's inventory):

- `consensus-critical` — changes block validity, state transitions, agreement, or canonical encoding. Highest priority, needs live mixed-cluster verification.
- `api` — REST endpoints/models/fields.
- `avm` — opcodes/versions.
- `network` — wire protocol.
- `behavioral-other` — pool, catchup, metrics, node behavior visible from outside.
- `not-applicable` — go build tooling, internal refactors with zero behavior change, CI, docs. **Do not silently drop these**: list them in the epic doc with a one-line justification each, so "we skipped it" is a reviewed decision, not an accident.

## Stage 3 — Issue creation

One issue per *feature-level* change (group the commits that implement one feature; never one issue per commit — upstream features routinely span several commits, and commit-level issues create artificial ordering problems). For each issue use this template:

```
Title: <area>: <what changes> (go-algorand NEW)

## Upstream change
- go-algorand commits/PRs: <SHAs / PR links from stage 2>
- Files: <go paths>
- Release: NEW

## What algod-rust must do
- Affected crates: <crates>
- <precise description of the behavior delta, citing the go source>

## Acceptance criteria
- [ ] TDD: failing test first, pinned to the NEW behavior
- [ ] Parity: fixtures/oracle comparison against go-algorand NEW where byte-level
- [ ] `cargo fmt` / `clippy -D warnings` / full workspace suite green
- [ ] (consensus-critical only) live mixed-cluster verification against NEW Go nodes

Part of epic #<epic-number>.
```

**Labels are mandatory, on every issue** (`gh label list` for the taxonomy; create missing ones with `gh label create`):

- the new `phase:<N>` label (create it: `gh label create "phase:<N>" --description "Phase <N>: go-algorand NEW parity" --color 0E8A16`),
- one domain label: `consensus` / `ledger` / `avm` / `networking` / `rest-api` / `sync` / `infrastructure`,
- one effort label: `effort:small` / `effort:medium` / `effort:large`,
- `conformance` for parity-verification work, `enhancement` for new features.

Then create the **epic issue** itself (label `epic` + `phase:<N>`): the full classified inventory from stage 2 (including the justified `not-applicable` list), all sub-issue numbers in **dependency order** (consensus params and encoding first — everything else reads them; then ledger/AVM; then agreement/network; API last), and the epic-level acceptance criteria. Follow the structure of issue #107's decomposition comment.

## Stage 4 — Docs: new implementation phase

Determine the next phase number `N` from `docs/PHASE*_PROPOSAL.md`. Create:

- `docs/PHASE<N>_PROPOSAL.md` — scope (the stage-2 inventory), success criteria, the sub-issue list, explicitly listed non-goals (the `not-applicable` bucket with justifications).
- `docs/epics/Epic-<M>-Go-Algorand-<NEW>-Parity.md` — next `M` from `docs/epics/`; mirrors the epic issue.
- Update `docs/PROJECT_SCOPE.md` to mention the new phase.
- Plan for `docs/PHASE<N>_VALIDATION.md` at close-out (stage 7) — the Layer-9-style evidence map: which test/tool proves which criterion, following `docs/PHASE6_VALIDATION.md`.

## Stage 5 — Version-pin sweep

The old tag string is referenced in **40+ files**. Sweep it deliberately — `grep -rn "OLD"` (both with and without the `v`/`-stable` decorations) and update every hit that *means* "the parity target". Known hot spots:

- `CLAUDE.md` — the pin statement ("pinned to `OLD`").
- `README.md`, `docs/**` (CONFORMANCE_STRATEGY, MIXED_CLUSTER_HARNESS, SOAK_METHODOLOGY, phase docs).
- `.github/workflows/consensus-cluster.yml` — `GO_ALGORAND_REV: "OLD"`.
- `tools/cert-authenticate/run-in-docker.sh` — `GO_ALGORAND_PIN="OLD"`; also `tools/cert-authenticate/go.mod`'s go-algorand requirement.
- `Makefile` help text, `ops/mixed-cluster/**` (compose images, scripts, README — the Go node containers must run NEW), `docker/docker-compose.*.yml`, `docker/scripts/*.sh`.
- Code comments citing "@ OLD" in `crates/**` and `bin/**` — update the ones that state the pin; leave historical ones ("was measured on OLD") alone.

**Do not** blind sed the whole repo: each hit is either "the pin" (update), "history" (leave), or "a doc explaining a version-specific behavior" (update the reference AND re-verify the described behavior still holds under NEW — if it changed, that's a stage-2/3 issue, make sure one exists).

Golden fixtures (`crates/**/fixtures/`) are generated from go-algorand binaries: any fixture whose upstream generator changed behavior must be **regenerated from NEW** (see `docs/DEV_WORKFLOW.md`), as part of the issue that implements that behavior change — never regenerate wholesale up front, or every not-yet-implemented change turns into an undiagnosable red suite.

Ship stages 3–5's repo changes (docs, pin sweep, labels) as the epic's first PR — label it `phase:<N>` + `documentation` — via `algod-issue-fix` steps 4–9.

## Stage 6 — Implementation loop

For each sub-issue **in the epic's dependency order**, run the full `algod-issue-fix` skill (all nine steps: investigate → TDD → fix → PR → self-review → fix findings → CI → fix CI → merge-with-confirmation). Additional rules for this loop:

- **Sequential, not parallel** — these issues share consensus surfaces; parallel branches here have repeatedly produced conflicts. One issue merged before the next begins.
- **Every PR gets labels** matching its issue: `phase:<N>` + the domain label + `conformance`/`enhancement` (`gh pr create --label ... --label ...`, or `gh pr edit <n> --add-label ...` immediately after creation). A PR with no labels is not done.
- PR bodies say `Fixes #<sub-issue>` and `Part of #<epic>`.
- After each merge, tick the sub-issue off in the epic issue body (`gh issue edit <epic> --body ...` or a progress comment) so the epic always reflects reality.
- If implementing one issue uncovers an upstream change stage 2 missed, file it as a new sub-issue in the epic immediately (same template/labels) — do not absorb it silently into the current PR.

## Stage 7 — Close-out

1. Write `docs/PHASE<N>_VALIDATION.md` citing evidence per criterion (follow `docs/PHASE6_VALIDATION.md`).
2. Full gate on `main`: fmt, clippy, `/test-full`, plus a live mixed-cluster soak against NEW Go nodes (`make consensus-cluster-test` / nightly workflow) and the conformance suite.
3. Close the epic issue with an honest audit comment (met / unmet-and-why), following the `algod-issue-fix` disposition rules — an unreachable criterion gets its own follow-up issue, not a shrug.
4. Verify no stray `OLD` references remain (`grep -rn "OLD"` — remaining hits must all be deliberate history).
