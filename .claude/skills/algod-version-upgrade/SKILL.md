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

Also read the upstream release notes for **every** release in the range — not just NEW. `gh release view NEW -R algorand/go-algorand` pulls the same data as the releases page (<https://github.com/algorand/go-algorand/releases>), but if OLD..NEW spans several tags, each intermediate release has its own "What's New"/Changelog section and some of those entries never make it into NEW's own notes verbatim (a feature can ship in an intermediate release and only get a passing "carried forward" mention, or none at all, in the final one). List every tag in range (`git -C ../go-algorand tag --contains OLD --list '*-stable' | sort -V`) and run `gh release view <tag> -R algorand/go-algorand` for each.

**Completeness check (mandatory, not optional):** build a line-by-line checklist from every bullet in every release's "What's New"/"Enhancements"/"Bugfixes" section across the whole range, and cross off each one against the classified inventory (stage below) as `api`/`avm`/`network`/`behavioral-other`/`not-applicable` — a bullet that isn't accounted for anywhere is a miss, not a shrug. Do this even when Pass B's file-level diff already "obviously" covers an area; a release-notes bullet is the upstream team's own claim about user-visible behavior, and Pass B can miss a change whose diff touches a file outside the parity-surface table below (e.g. a new CLI-facing default, a doc-only clarification of existing behavior that turns out to describe undocumented prior behavior). If a version-upgrade epic is later revisited (e.g. to close out remaining work), re-run this completeness check against the *current* upstream releases page before declaring the epic done — release notes are occasionally corrected/expanded after initial publication.

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
- First released in: <the exact go-algorand release where this feature first appeared>

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
- an **upstream-version label naming the release where the feature first appeared** — `algod:<tag>` (e.g. `algod:v4.6.0-stable`); create one per release in the OLD..NEW range as needed (`gh label create "algod:<tag>" --description "Introduced in go-algorand <tag>" --color 8250DF`). When OLD..NEW spans several releases, do NOT blanket-tag everything with NEW: find each feature's true origin release (`git -C ../go-algorand tag --contains <sha> --list '*-stable' | sort -V | head -1`, cross-checked against the release notes) and tag with that,
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

**Land this stage's docs on `main` first, as their own dedicated PR** (`docs(phase<N>): add Phase <N> proposal and epic for go-algorand NEW parity`, labels `phase:<N>` + `documentation`), before the stage-5 pin sweep and before stage 6 begins — do not bundle it into the pin-sweep PR. The proposal/epic docs are pure planning artifacts with no code risk, and every later PR in this epic benefits from being able to link a already-merged proposal/epic doc rather than one still in flight.

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

Ship the pin sweep as its own PR (`chore(phase<N>): sweep go-algorand pin from OLD to NEW`, labels `phase:<N>` + `documentation`) via `algod-issue-fix` steps 4–9 — stage 4's docs already landed separately (see above), so this PR is the pin-string changes alone (plus whatever live-parity CI carve-outs stage 5a below requires).

### Stage 5a — Resolving live-parity CI after the pin bump

Bumping the pin means every workflow that boots a real go-algorand container now runs **NEW**, not OLD — `Dual-Node REST Conformance` (`.github/workflows/validate-api.yml`, `docker/docker-compose.validate-api.yml`'s `algorand/algod:<tag>` image), `algokey-e2e.yml`, and `consensus-cluster.yml` all diff live behavior byte-for-byte against it. This means the pin-sweep PR's own CI will legitimately fail on every stage-2 gap that's observable live — a brand-new field, a newly-unconditional endpoint, a changed status code — **before** stage 6 has implemented any of it. This is expected, not a sign the sweep is broken; do not chase it by implementing features early inside the sweep PR (that reintroduces the "no wholesale-regenerate-fixtures-up-front" problem stage 5 already warns about, just for live tests instead of fixtures).

For each live-parity failure the pin bump surfaces:

1. **Read the actual failure** (dumped node logs, the diff assertion) and match it against stage 2's classified inventory. It should map cleanly onto one specific `api`/`avm`/`network`/`behavioral-other` sub-issue already created in stage 3.
   - If it doesn't map to anything in the inventory, stage 2 missed something real — stop and file a new sub-issue in the epic immediately (per stage 6's "uncovers a missed upstream change" rule) rather than papering over it.
   - If the failure looks like an actual regression (not an added/changed NEW behavior at all — e.g. a previously-passing, version-independent assertion now fails), that's a real bug; fix it for real, it is not a carve-out candidate.
2. **Carve out only that specific gap**, citing the tracking sub-issue in a code comment, using whatever exclusion mechanism the test already has for implementation-specific differences (e.g. `strip_implementation_specific_fields(go, &["online-stake"])` for a single new response field — see `bin/algod-rust/tests/live_go_parity.rs`; or deleting just the one now-invalid assertion line — see `bin/algod-rust/tests/live_endpoint_sweep.rs`'s `account_assets_list_and_experimental_disabled_on_both`). Concrete precedent from the `v4.5.1-stable`→`v4.6.0-stable` sweep: `fbd2b26` stripped `GetSupply`'s new `online-stake` field pending #508; `a376b3d` dropped a single status-parity assertion for an endpoint go-algorand un-gated pending #506. Both left every other assertion in the same test file intact.
3. **Never blanket-skip or `#[ignore]` a whole test/workflow** to get around this — that hides real regressions in everything else the test covers, not just the known gap.
4. **The carve-out is temporary and belongs to the corresponding sub-issue, not the pin-sweep PR.** When that sub-issue is implemented in stage 6, removing the carve-out (restoring full live-parity enforcement for that surface) is part of its acceptance criteria / self-review — add it explicitly if the issue template didn't already cover it.

## Stage 6 — Implementation loop

For each sub-issue **in the epic's dependency order**, run the full `algod-issue-fix` skill (all nine steps: investigate → TDD → fix → PR → self-review → fix findings → CI → fix CI → merge-with-confirmation). Additional rules for this loop:

- **Sequential, not parallel** — these issues share consensus surfaces; parallel branches here have repeatedly produced conflicts. One issue merged before the next begins.
- **Every PR gets labels** matching its issue: `phase:<N>` + the `algod:<tag>` upstream-version label + the domain label + `conformance`/`enhancement` (`gh pr create --label ... --label ...`, or `gh pr edit <n> --add-label ...` immediately after creation). A PR with no labels is not done.
- PR bodies say `Fixes #<sub-issue>` and `Part of #<epic>`.
- After each merge, tick the sub-issue off in the epic issue body (`gh issue edit <epic> --body ...` or a progress comment) so the epic always reflects reality.
- **Every open topic a merge leaves behind becomes a sub-issue of this epic, and gets WORKED, not just filed.** `algod-issue-fix` step 9's pre-merge acceptance-criteria audit and open-topics sweep (deferred findings, out-of-scope bugs, introduced TODOs, admitted limitations, unmet or moved criteria) apply to every PR in this loop. When a follow-up issue is genuinely in scope for the release being tracked (a bug or gap the release's own changes surfaced or require, as opposed to unrelated pre-existing tech debt this epic happens to have noticed), it does not get to sit open as "tracked but not blocking" — treat it exactly like a stage-3 sub-issue:
  - Add it to the epic issue's dependency-ordered sub-issue list (`gh issue edit <epic> --body ...`), give it the stage-3 issue template **including its own acceptance criteria** (a criterion moved out of another issue arrives here verbatim, with a back-link to where it came from), the full label set (`phase:<N>`, `algod:<tag>`, domain, effort, kind), and note in the epic which merged PR spawned it.
  - **Run it through `algod-issue-fix` before the epic is allowed to close** (see Stage 7's hard gate below) — the same nine-step process as any other sub-issue, in the same sequential loop.
  - The only legitimate way for a release-scoped follow-up to NOT block epic close-out is if it is honestly disposed per the `algod-issue-fix` "issue disposition" rules (structurally unreachable, or explicitly deferred by the user with their own sign-off) — never by silent omission from the loop.
  - Judgment call on "in scope for this release" vs "pre-existing tech debt noticed along the way": if the bug/gap only became reachable or newly relevant because of *this release's* changes (e.g. a new field now exposes a pre-existing computation gap), it's in scope. If it's a wholly unrelated finding the release work happened to walk past, file it labeled appropriately but do **not** add it to this epic's blocking list — note in the epic comment why it was excluded.
  - The loop is not finished when the stage-3 list is empty — it is finished when the epic's list is empty, *including* everything merges added to it along the way, *and* every item on that list is actually closed (merged or honestly disposed), not just filed.
- If implementing one issue uncovers an upstream change stage 2 missed, file it as a new sub-issue in the epic immediately (same template/labels) and work it in this same loop — do not absorb it silently into the current PR, and do not leave it for "later."

## Stage 7 — Close-out

**Hard gate before doing anything else in this stage:**

```bash
gh issue list --repo <owner>/<repo> --label "phase:<N>" --state open
```

This MUST return empty before the epic can close. If it returns anything — including a follow-up filed mid-loop, including one that feels minor — go back to Stage 6 and work it (or honestly dispose it per the `algod-issue-fix` disposition rules) before proceeding. **Never close the epic issue while any issue carrying this phase's label is still open**, and never re-run this check only once at the start of a session — if the epic was reopened or revisited after a gap, re-run it fresh; issues filed by a different session or by the user in the interim still count. A completeness re-check also means re-doing Stage 2's release-notes pass against the *current* upstream releases page (not just trusting the original pass) before signing off — upstream notes are occasionally corrected/expanded, and this repo's own review of a "done" epic has previously found gaps on a second pass.

1. Write `docs/PHASE<N>_VALIDATION.md` citing evidence per criterion (follow `docs/PHASE6_VALIDATION.md`).
2. Full gate on `main`: fmt, clippy, `/test-full`, plus a live mixed-cluster soak against NEW Go nodes (`make consensus-cluster-test` / nightly workflow) and the conformance suite.
3. Re-run the hard gate above. If still empty, close the epic issue with an honest audit comment (met / unmet-and-why per criterion, and explicit confirmation the open-issues gate was checked and clean) following the `algod-issue-fix` disposition rules — an unreachable criterion gets its own follow-up issue, not a shrug.
4. Verify no stray `OLD` references remain (`grep -rn "OLD"` — remaining hits must all be deliberate history).
