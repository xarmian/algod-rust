---
name: algod-version-upgrade
description: Upgrade algod-rust's parity target to a newer go-algorand version. Given a target version tag (e.g. v4.6.0-stable), analyze every change between the current pin and the target — including every intermediate pre-release (beta, rc, and other semver-suffixed tags), not just the final stable tags — create one GitHub issue per addition (grouped by feature), open a new epic/phase, sweep the version pin across the whole project, re-checkout the go-algorand reference, then implement every issue via the algod-issue-fix skill — and keep the Phase 17 go-algorand↔algod-rust test-parity map (`docs/PHASE17_TEST_PARITY.md`) complete at the new pin, with `not-implemented`, `missing-test` and `partial` all at zero, by classifying every Go test the new version added or changed and implementing whatever Rust tests/features that needs. Use when asked to "upgrade to algod version X" or "move to go-algorand vX".
---

# algod-rust version-upgrade workflow

Input: a target go-algorand version tag, e.g. `v4.6.0-stable`. The current pin is recorded in `CLAUDE.md` ("pinned to `<tag>`") — read it there, do not assume. Everything below refers to `OLD` (current pin) and `NEW` (target).

This is a large, multi-session effort. Work through the stages in order; stages 1–5 are analysis/setup (one sitting), stage 6 is the long implementation loop (one `algod-issue-fix` run per issue), stage 7 is close-out.

**Two invariants this skill exists to preserve, and that stage 7's hard gates check mechanically:** (1) no `phase:<N>` issue is open when the epic closes; (2) the Phase 17 test-parity map (`docs/PHASE17_TEST_PARITY.md` + `docs/phase17/parity_*.md`, one row per go-algorand `func TestXxx`) is complete at `NEW` — every Go test in the `NEW` checkout has a row pinned to `NEW`, and `not-implemented`, `missing-test`, `partial` and `unclassified` are all **zero**. An upgrade that ships the features but leaves the parity map at `OLD`, or leaves gap rows behind "for later", is not done. `scripts/phase17_parity_delta.py` (`report` / `repin` / `check`) is the tool for (2); stages 1, 2 (Pass C), 5, 6 and 7 below say when to run which subcommand.

## Stage 1 — Preflight and reference checkout

1. `git -C ../go-algorand fetch --tags` and verify `NEW` exists (`git -C ../go-algorand tag -l 'NEW'`). If the user gave a bare version ("4.6"), resolve it to the real stable tag and confirm the resolution with them before proceeding.
2. Record the exact commit of `OLD` and `NEW` (`git -C ../go-algorand rev-parse OLD NEW`).
3. Enumerate **every** tag in the `OLD..NEW` range, not just final `-stable` releases — go-algorand also ships `-beta`, `-rc`, and other pre-release/semver-suffixed tags that carry their own real behavior changes ahead of the next stable: `git -C ../go-algorand tag --contains OLD --list | sort -V`, then drop anything not reachable from `NEW` (`git -C ../go-algorand tag --contains OLD --merged NEW --list | sort -V` if the tags are on the mainline; otherwise filter by `git merge-base --is-ancestor <tag> NEW`). This full list — stable and pre-release alike — is `TAGS_IN_RANGE` and drives stage 2's Pass A, the completeness check, and stage 3's `algod:<tag>` labeling. A beta/rc tag is in scope exactly like a stable one: if it shipped a behavior change, that change gets an issue and an `algod:<tag>` label naming the beta/rc tag itself, not just the stable release it eventually landed in.
3. Checkout the reference to `NEW` (detached HEAD, matching the existing convention): `git -C ../go-algorand checkout NEW`. Do this **now**, at the start — all subsequent parity reading, fixture regeneration, and `algod-issue-fix` runs must read the NEW source, and a half-updated reference is worse than either endpoint. The analysis in stage 2 uses git ranges, which work regardless of what is checked out.
4. Snapshot the `OLD` test inventory before anything else touches it: `git show main:docs/phase17/go_tests.tsv > <scratchpad>/go_tests_OLD.tsv`. Stage 2's Pass C diffs against this file, and stage 5's `repin` overwrites the committed copy with `NEW`'s — once that has happened, the only way back to `OLD`'s inventory is `git show <pre-sweep-sha>:docs/phase17/go_tests.tsv`.
5. Warn the user explicitly: until stage 6 completes, live conformance against `../go-algorand` binaries built from `NEW` may legitimately fail where behavior changed — that is the gap list from stage 2, not a regression.

## Stage 2 — Change analysis (OLD..NEW)

Goal: an exhaustive, classified list of behavioral changes. Two complementary passes:

**Pass A — merge-level history** (feature granularity, ≈ one entry per upstream PR):

```bash
git -C ../go-algorand log --first-parent --oneline OLD..NEW
```

Also read the upstream release notes for **every** release in the range — not just NEW, and not just the `-stable` tags. `gh release view NEW -R algorand/go-algorand` pulls the same data as the releases page (<https://github.com/algorand/go-algorand/releases>), but if OLD..NEW spans several tags, each intermediate release has its own "What's New"/Changelog section and some of those entries never make it into NEW's own notes verbatim (a feature can ship in an intermediate release and only get a passing "carried forward" mention, or none at all, in the final one). This applies just as much to pre-releases: a `-beta`/`-rc` tag frequently ships (and documents) a feature days or weeks before the stable tag that contains it, and GitHub marks these releases `prerelease: true` rather than omitting them — `gh release list -R algorand/go-algorand --limit 200` shows them alongside stable releases. Run `gh release view <tag> -R algorand/go-algorand` for **every** tag in `TAGS_IN_RANGE` from stage 1 (stable and pre-release alike) — do not filter the list down to `-stable` before reading notes. A tag with no published release notes (some pre-releases are tag-only, no GitHub Release object) still needs its commit range read directly (`git -C ../go-algorand log --oneline <prev-tag>..<tag>`) so its changes aren't silently skipped.

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

**Pass C — test-parity delta (mandatory, same sitting as A and B).** go-algorand's own tests are the most precise statement of what `NEW` actually does: every test upstream added or changed in `OLD..NEW` is a concrete, checkable claim algod-rust must match. Phase 17 (`docs/PHASE17_TEST_PARITY.md`, epic #830) mapped every Go test at the old pin with `not-implemented`/`missing-test` at zero; this pass is how the map stays complete and gap-free at `NEW` instead of silently rotting into a stale snapshot. It is also an independent completeness check on Passes A and B — a behavior change whose commit message and diff both undersold it still shows up as a changed assertion in a `_test.go` file.

1. Generate the delta report from the stage-1 snapshot and the `NEW` checkout:

   ```bash
   mkdir -p docs/phase<N>
   python3 scripts/phase17_parity_delta.py report \
     --old-tag OLD --new-tag NEW \
     --old-tsv <scratchpad>/go_tests_OLD.tsv \
     --go-algorand ../go-algorand \
     --out docs/phase<N>/test_parity_delta.md
   ```

   It walks `NEW` for every `func Test*` (same rules as `scripts/list_go_tests.sh`), diffs that inventory against `OLD`'s, and `git diff`s every changed `_test.go` to attribute hunks to the test functions they touch. The report has four sections — **added**, **removed**, **moved**, **body changed** — each listing the exact `parity_<area>.md` row (or the area file a new row belongs in). Commit the report with stage 4's docs PR: it is the epic's test-level inventory, the counterpart of Pass A/B's feature inventory.

2. Work every line of the report into the classified inventory, so each Go test ends up owned by exactly one stage-3 issue (or is honestly disposed):
   - **Added** — read the Go test; find the Rust test(s) that prove the same behavior. If they exist, the row will be `matched-*` (mechanical, can be classified in the stage-5 sweep PR). If they don't, decide *why*: the test exercises a Pass A/B feature → that feature's issue gets an acceptance criterion naming the Go test ("parity row for `TestXxx` is `matched-*`, linking the new Rust test"); the test hardens a **pre-existing** behavior upstream only now tests (a test-only upstream change with no Pass A/B item) → a standalone test-parity sub-issue (stage 3). Either way it is a real sub-issue of this epic, worked in stage 6 — never a row left at `missing-test`/`not-implemented` with "tracked" as its note.
   - **Removed** — the row goes away in stage 5's `repin` clean-up. But first ask *why* upstream deleted the test: if it proved behavior `NEW` deliberately dropped or changed, that is a behavioral change for Pass A/B's inventory (make sure an issue exists to change algod-rust to match — a Rust test still asserting the old behavior is now a parity bug, not coverage); if the test was merely folded into another test, note which one absorbed it.
   - **Moved** — file rename only; `repin` re-links it. Nothing to decide.
   - **Body changed** — the mapped Rust test may no longer prove the same thing. For each: `git -C ../go-algorand diff OLD NEW -- <file>` around the function. If upstream added or changed an assertion, the Rust test must gain the same assertion — attach that to the owning feature issue's acceptance criteria, or to a test-parity sub-issue. If the change is cosmetic (renamed helper, lint, reformatting), the row's notes get one sentence saying it was re-verified at `NEW` and why nothing changed. A body-changed row nobody re-verified is a silent `partial`.
   - **`out-of-scope` is a classification, not an escape hatch.** Use it only under Phase 17's bar (Go-runtime specifics, CLI tooling with no Rust equivalent concept, structurally meaningless in Rust) with a note that would satisfy a reviewer asking "so where *is* this behavior tested?". An `out-of-scope` that exists to keep the counts at zero is a `missing-test` in disguise, and the stage-7 audit treats it as one.

3. Cross-check Pass C against Passes A and B in both directions: every `consensus-critical`/`api`/`avm`/`network`/`behavioral-other` item should have at least one added or body-changed Go test (if it doesn't, upstream shipped a behavior change without a test — say so in the issue, and the Rust side still gets one, per `algod-issue-fix`'s TDD rule); and every added/body-changed Go test should trace to a Pass A/B item or be explained as test-only hardening. A test that fits neither is a Pass A/B miss.

## Stage 3 — Issue creation

One issue per *feature-level* change (group the commits that implement one feature; never one issue per commit — upstream features routinely span several commits, and commit-level issues create artificial ordering problems). Create each one with the **`algod-issue-create`** skill — it owns the body template and the mandatory label set (`phase:<N>`, domain, effort, kind). Feed it, per issue: the upstream commits/PRs and files from stage 2, the affected algod-rust crates, and `Part of epic #<epic-number>` to insert into the body.

**Upstream-version labeling is where this loop differs from a one-off `algod-issue-create` call**, because stage 2 already enumerated `TAGS_IN_RANGE` and every issue here is parity work by construction — every issue gets at least one `algod:<tag>` label, always including `algod:NEW`. Run `go-algorand-version-lookup` per issue (not once for the whole batch — different issues in the same epic can have different origins) rather than re-deriving the tag logic inline:

- The lookup's `ORIGIN_TAG` is the earliest tag in `TAGS_IN_RANGE` (pre-releases included) whose history contains the change — label `algod:<origin-tag>`. Do not collapse a beta/rc-only feature onto a later stable tag as its *only* label — the origin label is what makes pre-release-exclusive work visible.
- The lookup's pin-reachability check tells you whether `NEW` also ships the feature (go-algorand's stable release notes typically re-list every change since the last stable, including ones that first landed in an intermediate pre-release). If so, **add `algod:NEW` as a second label** (`gh issue edit <n> --add-label "algod:NEW"`). A feature that reached `NEW` should never end up with only a pre-release label and no `algod:NEW` label — `algod:NEW` is the label a future reader filters by to see "everything that shipped in this pin."
- The two labels can be identical when the origin tag already *is* `NEW` — the common case for a range with no intermediate pre-release, or for work with no upstream origin at all (the new-scope P2P transport work, labeled by domain/effort only, no `algod:` label needed since it doesn't map to a single upstream commit — `go-algorand-version-lookup` reports this as "not applicable").
- Create missing `algod:<tag>` labels as needed: `gh label create "algod:<tag>" --description "Introduced in go-algorand <tag>" --color 8250DF`.

**Test-parity sub-issues (from Pass C).** Two shapes, both created via `algod-issue-create` like everything else here:

- **Folded into a feature issue** — the default when the Go test exercises a Pass A/B feature. The feature issue's acceptance criteria name every such Go test explicitly (`- [ ] docs/phase17/parity_<area>.md row for TestXxx is matched-* and links the Rust test`), so `algod-issue-fix`'s step-9 audit checks the row, not just the code.
- **Standalone test-parity issue** — for test-only upstream changes (added or strengthened tests of pre-existing behavior) with no feature issue to attach to. Group by area file and behavior cluster, not one issue per Go test, but never span more than one `parity_<area>.md` in a single issue (keeps the tracking-doc diff reviewable). Title `test-parity(NEW): <area> — <behavior cluster>`; body lists each Go test by name with its `NEW` blob link and what it asserts; labels `phase:<N>` + `algod:<tag>` (per the lookup — the origin tag of the *test*, which for a hardening test may differ from the feature it tests) + domain + effort + kind `testing`; acceptance criteria: one `- [ ]` per Go test row reaching `matched-*` (or an explicitly argued `out-of-scope`), plus `scripts/update_phase17_summary.py` re-run in the same PR.

The epic issue's inventory gets a **Test parity** section: a link to `docs/phase<N>/test_parity_delta.md`, the added/removed/body-changed counts, and which sub-issue owns each added/body-changed Go test. The epic-level acceptance criteria always include: `- [ ] python3 scripts/phase17_parity_delta.py check --tag NEW --go-algorand ../go-algorand exits 0 (map pinned to NEW, complete, not-implemented = missing-test = partial = unclassified = 0)`.

Also create the new `phase:<N>` label if it doesn't exist yet: `gh label create "phase:<N>" --description "Phase <N>: go-algorand NEW parity" --color 0E8A16`.

Then create the **epic issue** itself (label `epic` + `phase:<N>`): the full classified inventory from stage 2 (including the justified `not-applicable` list), all sub-issue numbers in **dependency order** (consensus params and encoding first — everything else reads them; then ledger/AVM; then agreement/network; API last), and the epic-level acceptance criteria. Follow the structure of issue #107's decomposition comment.

## Stage 4 — Docs: new implementation phase

Determine the next phase number `N` from `docs/PHASE*_PROPOSAL.md`. Create:

- `docs/PHASE<N>_PROPOSAL.md` — scope (the stage-2 inventory), success criteria, the sub-issue list, explicitly listed non-goals (the `not-applicable` bucket with justifications). Its success criteria include the test-parity invariant (the `check` command from stage 3's epic criteria) verbatim.
- `docs/phase<N>/test_parity_delta.md` — the Pass C report as generated (do not hand-edit it; regenerate if the range changes).
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

**The test-parity map is re-pinned by tool, not by hand.** `docs/phase17/parity_*.md` carry 3,000+ GitHub blob links to `OLD` with `OLD`'s line numbers; every one of them must point at `NEW` with `NEW`'s line numbers, and every Go test `NEW` added must acquire a row. In the pin-sweep PR run:

```bash
python3 scripts/phase17_parity_delta.py repin --old-tag OLD --new-tag NEW --go-algorand ../go-algorand
```

It rewrites every row link (resolving file renames by unique test name), regenerates `docs/phase17/go_tests.tsv` and `docs/phase17/batches/*.tsv` from `NEW`, updates the "Generated … against" line in `docs/PHASE17_TEST_PARITY.md`, and appends one placeholder row with status **`unclassified`** per added Go test under a "Tests added in go-algorand `NEW`" heading at the end of the right `parity_<area>.md`. Then act on what it prints:

- **Stale rows** (Go test no longer exists in `NEW` — Pass C's "removed" list): delete the row, or remap it by hand if `repin` couldn't resolve a rename (same test name in several files). Record any deleted row whose Rust test now asserts dropped upstream behavior in the owning stage-3 issue.
- **Re-tagged non-row links** (blob links inside notes cells or prose, re-pointed at `NEW` textually): re-open each and confirm the line anchor still lands on the cited code; fix the `#L` if it drifted.
- **Prose claims** in `docs/phase17/*.md` such as "confirmed dead code in go-algorand `OLD`" follow the normal pin-vs-history rule above — a "verified at `OLD`" statement that stays in a notes cell must be re-verified at `NEW`, not merely re-tagged.
- **Leave the `unclassified` placeholder rows in place** — they are the visible, machine-checked to-do list stage 6 works down (`scripts/update_phase17_summary.py` refuses to run and `check` fails while any remain, on purpose). The one thing you *may* do in the sweep PR is the purely mechanical classification: an added Go test that an **existing** Rust test already provably covers becomes `matched-*` here, with the same evidence standard (working relative link, note if 1:many/many:1) as any other row. Anything that needs new Rust code or a new Rust test stays `unclassified` until its stage-6 issue lands — classifying it early inside the sweep PR is the same mistake as regenerating fixtures wholesale up front.
- Body-changed rows are **not** touched by `repin` (nothing mechanical to do); their re-verification is stage-6 work owned by the issue Pass C assigned them to.

`python3 scripts/phase17_parity_delta.py check --tag NEW` at the end of the sweep PR will fail (that is expected — it lists exactly the `unclassified` rows stage 6 owes) but must report **no** stale rows, **no** `OLD`-pinned links, and **no** Go test without a row. Include that output in the PR description.

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

- **Licensing headers apply here too.** This loop creates real new Rust/Go source files implementing parity features (proposal docs from stage 4 are exempt Markdown, these are not) — every new source file a sub-issue's implementation creates must carry the correct license header per `CLAUDE.md`'s Licensing section, exactly per `algod-issue-fix`'s own self-review (step 5) and pre-merge acceptance-criteria audit (step 9), since that's the skill actually doing the implementation work in this loop.
- **Sequential, not parallel** — these issues share consensus surfaces; parallel branches here have repeatedly produced conflicts. One issue merged before the next begins.
- **Every PR gets labels** matching its issue: `phase:<N>` + every `algod:<tag>` upstream-version label the issue carries (usually including `algod:NEW`, per stage 3) + the domain label + `conformance`/`enhancement` (`gh pr create --label ... --label ...`, or `gh pr edit <n> --add-label ...` immediately after creation). A PR with no labels is not done.
- PR bodies say `Fixes #<sub-issue>` and `Part of #<epic>`.
- After each merge, tick the sub-issue off in the epic issue body (`gh issue edit <epic> --body ...` or a progress comment) so the epic always reflects reality.
- **Every open topic a merge leaves behind becomes a sub-issue of this epic, and gets WORKED, not just filed.** `algod-issue-fix` step 9's pre-merge acceptance-criteria audit and open-topics sweep (deferred findings, out-of-scope bugs, introduced TODOs, admitted limitations, unmet or moved criteria) apply to every PR in this loop. When a follow-up issue is genuinely in scope for the release being tracked (a bug or gap the release's own changes surfaced or require, as opposed to unrelated pre-existing tech debt this epic happens to have noticed), it does not get to sit open as "tracked but not blocking" — treat it exactly like a stage-3 sub-issue:
  - Add it to the epic issue's dependency-ordered sub-issue list (`gh issue edit <epic> --body ...`), give it the stage-3 issue template **including its own acceptance criteria** (a criterion moved out of another issue arrives here verbatim, with a back-link to where it came from), the full label set (`phase:<N>`, `algod:<tag>`, domain, effort, kind), and note in the epic which merged PR spawned it.
  - **Run it through `algod-issue-fix` before the epic is allowed to close** (see Stage 7's hard gate below) — the same nine-step process as any other sub-issue, in the same sequential loop.
  - The only legitimate way for a release-scoped follow-up to NOT block epic close-out is if it is honestly disposed per the `algod-issue-fix` "issue disposition" rules (structurally unreachable, or explicitly deferred by the user with their own sign-off) — never by silent omission from the loop.
  - Judgment call on "in scope for this release" vs "pre-existing tech debt noticed along the way": if the bug/gap only became reachable or newly relevant because of *this release's* changes (e.g. a new field now exposes a pre-existing computation gap), it's in scope. If it's a wholly unrelated finding the release work happened to walk past, file it labeled appropriately but do **not** add it to this epic's blocking list — note in the epic comment why it was excluded.
  - The loop is not finished when the stage-3 list is empty — it is finished when the epic's list is empty, *including* everything merges added to it along the way, *and* every item on that list is actually closed (merged or honestly disposed), not just filed.
- If implementing one issue uncovers an upstream change stage 2 missed, file it as a new sub-issue in the epic immediately (same template/labels) and work it in this same loop — do not absorb it silently into the current PR, and do not leave it for "later."
- **Every sub-issue closes its own parity rows, in its own PR.** When a feature issue or a test-parity issue merges, the same PR turns every `docs/phase17/parity_<area>.md` row it owns from `unclassified` into a final status with a working relative link to the Rust test (`matched-1:1` / `matched-1:many` / `matched-many:1`, or an argued `out-of-scope`), adds a one-sentence re-verification note to every body-changed row it owns, and re-runs `python3 scripts/update_phase17_summary.py` so the index tables match. `algod-issue-fix`'s step-9 acceptance-criteria audit treats a row named in the issue that is still `unclassified` / `missing-test` / `not-implemented` / `partial` as an **unmet criterion** — the PR does not merge over it. The loop's progress gauge is `python3 scripts/phase17_parity_delta.py check --tag NEW`: its `unclassified` count is the number of Go tests still unaccounted for, and it must go monotonically down.
- **`partial` is a way-station, never a resting state.** If a PR can only partly match a Go test, the row may read `partial` *only* with a note naming the follow-up sub-issue that closes the rest — filed per the open-topics rule above, added to the epic's list, and worked in this same loop. This applies equally to the `partial` rows the map carried into this upgrade from before (at the time of writing, 4 in `docs/phase17/parity_agreement.md`): they are in scope for every upgrade epic until closed, and `check` fails on them by default. `--allow-partial N` exists solely to record an explicit, per-row user sign-off that a given `partial` is being deliberately excluded (cite the sign-off in the epic close-out comment) — never to make the gate pass quietly.
- **Do not lower the bar to hit zero.** A Rust test that "matches" a Go test must exercise the same behavior with equivalent assertions — the Phase 17 standard, re-stated in `docs/PHASE17_TEST_PARITY.md`'s legend. A smoke test that merely calls the same function is `partial`, and gets the follow-up above.

## Stage 7 — Close-out

**Hard gate before doing anything else in this stage:**

```bash
gh issue list --repo <owner>/<repo> --label "phase:<N>" --state open
```

and

```bash
python3 scripts/phase17_parity_delta.py check --tag NEW --go-algorand ../go-algorand
```

The first MUST return empty and the second MUST exit 0 (it verifies: `../go-algorand` is checked out at `NEW`; `docs/phase17/go_tests.tsv` matches a fresh walk of the checkout; every row links `blob/NEW/`; every Go test has a row and every row's Go test exists; no `unclassified`, `not-implemented` or `missing-test` rows; no `partial` rows beyond an explicitly signed-off `--allow-partial N`). If either fails — a `phase:<N>` issue still open, including a follow-up filed mid-loop, including one that feels minor; or a Go test still unaccounted for — go back to Stage 6 and work it (or honestly dispose it per the `algod-issue-fix` disposition rules) before proceeding. **Never close the epic issue while any issue carrying this phase's label is still open or while `check` is red**, and never re-run this check only once at the start of a session — if the epic was reopened or revisited after a gap, re-run it fresh; issues filed by a different session or by the user in the interim still count. A completeness re-check also means re-doing Stage 2's release-notes pass against the *current* upstream releases page (not just trusting the original pass) before signing off — upstream notes are occasionally corrected/expanded, and this repo's own review of a "done" epic has previously found gaps on a second pass. Re-derive `TAGS_IN_RANGE` fresh at this point too (`git -C ../go-algorand fetch --tags` then the stage-1 listing command) — a beta/rc tag can land upstream after the epic's original stage 1 ran, and it is in scope exactly like any other tag in the range.

1. Write `docs/PHASE<N>_VALIDATION.md` citing evidence per criterion (follow `docs/PHASE6_VALIDATION.md`). The test-parity criterion's evidence is the verbatim clean output of the `check` command above plus the final aggregate-totals table from `docs/PHASE17_TEST_PARITY.md`; also refresh the Phase 17 sentence in `CLAUDE.md`'s project summary (test count, remaining `partial` count, pin) so it states the new truth.
2. Full gate on `main`: fmt, clippy, `/test-full`, plus a live mixed-cluster soak against NEW Go nodes (`make consensus-cluster-test` / nightly workflow) and the conformance suite.
3. Re-run the hard gate above. If still empty, close the epic issue with an honest audit comment (met / unmet-and-why per criterion, and explicit confirmation the open-issues gate was checked and clean) following the `algod-issue-fix` disposition rules — an unreachable criterion gets its own follow-up issue, not a shrug.
4. Verify no stray `OLD` references remain (`grep -rn "OLD"` — remaining hits must all be deliberate history). `blob/OLD/` under `docs/phase17/` and in `docs/PHASE17_TEST_PARITY.md` is never history — `check` already fails on it, but confirm here too.
