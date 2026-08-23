---
name: algod-issue-fix
description: Standard workflow for implementing/fixing a GitHub issue in xarmian/algod-rust — investigate, TDD, fix, PR, self-review, CI, merge. Use whenever asked to "continue with issue N" or "fix issue N" in this repo.
---

# algod-rust issue-fix workflow

This repo (Rust reimplementation of go-algorand, pinned to `../go-algorand` @ v4.5.1-stable) has an established, TDD-first, live-verification-first culture. Read `CLAUDE.md` at the repo root before starting — it has mandatory environment quirks (Windows cargo/MSVC wrapper, the known `algo-network` doctest flake, "never chain retries hoping for a different result"). Use `/cargo`, `/test-full`, and `/pr-ship` (this repo's slash commands) rather than re-deriving those invocations from scratch each time.

## The process

Every issue goes through these nine steps, in order. Do not skip a step because it "looks fine" — the whole point of this workflow is that each step catches a class of mistake the previous one can't.

### 1. Investigate the issue

- Read the full issue (`gh issue view N --comments`) — including prior comments; don't re-investigate something already ruled out.
- **Every issue must have explicit acceptance criteria as a `- [ ]` checklist in its body.** If the issue you're picking up doesn't have them, write them now (`gh issue edit N --body ...`, preserving the original text) and note in a comment that you added them — they are the contract that step 9's pre-merge audit checks against, so an issue without them cannot be verifiably finished. The same applies to every issue *you* create (follow-ups, spin-offs): no issue leaves your hands without acceptance criteria.
- Read `../go-algorand`'s real behavior for the relevant area before forming a hypothesis — this repo's bar is byte-level/behavioral parity with go-algorand v4.5.1-stable, not "something reasonable." Cite the specific go file/function once you have a root-cause theory.
- Identify where to start reading in this repo, but treat it as a starting point, not a conclusion — don't anchor on the first suspicious function.
- For consensus/ledger/network issues, decide up front whether a live multi-node repro is needed (`ops/mixed-cluster/`, `docker/scripts/bench-stress.sh`) to actually observe the bug, rather than guessing from code reading alone.

### 2. TDD: write a failing test first

- Write the test(s) that pin the *correct* behavior before touching the fix. The test must fail for the right reason against the current code (verify this — a test that passes by accident proves nothing).
- Prefer a fast, deterministic, Docker-free unit/integration test that runs in default `cargo test --workspace`. If a live cluster run is what's needed to find the root cause, still land the final regression as a fast local test — the cluster run is for discovery, not for CI.
- When changing behavior at a trust boundary (dup detection windows, round advancement, encoding), add an oracle test against the *old* implementation's behavior where practical, not just a fresh assertion — this repo has been burned by "obviously correct" replacements that silently changed edge-case semantics.

### 3. Fix the code, make all tests pass

Idiomatic-Rust bar for this repo, in priority order:

- **Correctness and parity over cleverness.** Match go-algorand's semantics exactly, including its edge cases (off-by-one windows, saturating vs wrapping arithmetic, `omitempty`/canonical encoding rules). Cite the go source in a comment only when the *why* isn't obvious from reading the code — no restating what the code does.
- **`Result`, not panics, on any path reachable from untrusted input** (REST handlers, gossip messages, pool submissions, deserialization). `.unwrap()`/`.expect()`/`panic!` are for invariants that are truly unreachable except via a programming bug — and even then prefer `.expect("reason")` over bare `.unwrap()` so a panic is diagnosable.
- **No new `unsafe`** unless the issue specifically requires it; if it does, justify it in a comment and keep the unsafe block minimal.
- **Don't hold a lock across an operation that doesn't need it** — this repo has a real history of single-mutex ledger contention becoming a measured bottleneck (see #492, #495). Prefer snapshotting what you need and releasing the lock over widening a critical section.
- **Avoid gratuitous clones/allocations on hot paths** (per-transaction, per-round). If profiling isn't warranted for this issue, at least don't introduce an obviously avoidable one.
- **No new dependency for something a few dozen lines can do** (this repo's Prometheus exporter and its stress-test load generator are both hand-rolled for exactly this reason) — but don't hand-roll something a workspace dependency already provides correctly.
- **Minimal public surface change.** Don't widen a trait, add a pub field, or change a signature beyond what the fix requires.
- Run the fast, targeted test(s) first (`cargo test -p <crate> <test_name>` via `/cargo`), then the full gate before moving on:
  - `cargo fmt --all`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `/test-full` (full workspace suite; only the known local `algo-network` `peer_features.rs` doctest flake is an acceptable failure)
- If the change touches the participation/agreement/network path, re-verify live against `ops/mixed-cluster/` or `docker/scripts/bench-stress.sh` — a passing unit test alone does not close a consensus-critical issue in this repo.

### 4. Create the PR

- Branch name `fix/issue-N-<slug>` or `feat/issue-N-<slug>` / `perf/issue-N-<slug>` as appropriate.
- Commit message explains the **root cause**, not just the symptom, and cites measured numbers where the issue is about performance/behavior under load — see recent history (`git log`) for the bar.
- `gh pr create` with `Fixes #N` (or `addresses #N` if the issue has other unmet criteria that will stay open) in the body, including what was tested and why it's sufficient.
- **Label every PR** — a PR with no labels is not done. Use the repo's taxonomy (`gh label list`): the issue's `phase:<n>` label, one domain label (`consensus` / `ledger` / `avm` / `networking` / `rest-api` / `sync` / `infrastructure`), and the kind (`bug` / `enhancement` / `conformance` / `documentation` / `testing`). Pass them at creation (`gh pr create --label ... --label ...`) or immediately after (`gh pr edit <n> --add-label ...`); mirror the labels the issue itself carries.

### 5. Self code review

Before treating the PR as ready, review your own diff as if it were someone else's:

- `git diff origin/main...<branch>` — read every hunk. Does it match the stated root cause, or did something unrelated sneak in?
- Check the diffstat for surprises: stray fixture/benchmark output, accidental formatting-only churn in unrelated files, files that shouldn't exist (temp scratch, `bench-results/*.json`).
- Re-read the new tests: do they actually exercise the fix, or would they pass even without it? (Temporarily revert the fix locally and confirm the new test fails, if there's any doubt.)
- Check for the idiomatic-Rust bar in step 3 as if reviewing a stranger's PR — it's easy to wave through your own shortcuts.

### 6. Fix self-review findings

Address anything found in step 5 before moving on — don't defer "minor" findings to a follow-up unless they're genuinely out of scope for this issue, in which case file them as a new issue (see "Creating a new issue" below) rather than letting them evaporate.

### 7. Wait for PR checks

Use `/pr-ship <pr-number>` (or its polling loop directly) to wait for CI in the background rather than polling manually in a sleep loop yourself.

### 8. Fix CI findings

If a check fails, read its actual logs (`gh run view <run-id> --log-failed`) before changing anything — don't guess-and-retry. Distinguish a real regression from an unrelated flake or a path-filtered workflow firing on an unrelated change (see `CLAUDE.md`'s CI guidance) before deciding what to fix.

### 9. Merge to main

- **Acceptance-criteria audit first.** Walk the issue's `- [ ]` checklist item by item against what the PR actually delivers, and leave the issue reflecting the truth of each item *before* the merge:
  - **Fixed** → mark it checked (`- [x]`) in the issue body (`gh issue edit N --body ...`), citing the evidence (test name, PR, measurement) in the tick or in an accompanying comment.
  - **Obsolete** (the criterion no longer makes sense — requirements changed, the approach made it moot, upstream removed the need) → do NOT silently delete or tick it: strike it through (`- [x] ~~criterion~~`) and post a comment explaining *why* it is obsolete and on whose call (user decision, upstream change, superseded design).
  - **Moved to a different issue** (out of scope here, deferred, structurally unreachable in this PR) → post a comment naming the destination issue number (which the open-topics sweep below just created), and annotate the item in the body (`- [ ] criterion — moved to #M`) so nobody re-implements or double-counts it.
  - Only when every item is checked, struck-with-comment, or moved-with-comment is the issue mergeable. A checklist item left silently unaddressed blocks the merge.
- **Open-topics sweep — no open topic survives a merge untracked.** Before merging, inventory everything this PR leaves unresolved: deferred self-review findings (step 6), bugs found but fixed out-of-scope, `TODO`/`FIXME` comments the diff introduced, known limitations admitted in the PR body, unmet acceptance criteria of the underlying issue, and follow-up work the investigation surfaced. For **each one**, create a dedicated GitHub issue per "Creating a new issue" above (labels, root cause, TDD instruction, acceptance criteria, epic insertion) — and reference the new issue numbers in a PR comment or the merge summary so the trail is navigable both ways.
- Merging is a shared-state action: confirm with the user (`AskUserQuestion`) before merging, even if a similar merge was approved earlier in the same session — auto-mode blocks it by default for a reason.
- `/pr-ship <pr-number>` handles the confirm → `gh pr merge --squash --delete-branch` → sync-local-`main` sequence.
- If the PR said `Fixes #N`, verify the issue actually closed (`gh issue view N --json state`) rather than assuming.

## Creating a new issue (follow-ups, spin-offs, open-topics)

Every issue you file from this workflow — a deferred self-review finding (step 6), an out-of-scope bug, or an open-topics-sweep item (step 9) — must be created with `gh issue create`, never left as a bare comment or TODO. Before running `gh issue create`:

- **Labels are mandatory, not optional.** Apply the same taxonomy as PRs (step 4): a `phase:<n>` label matching the epic/phase it belongs to, one domain label (`consensus` / `ledger` / `avm` / `networking` / `rest-api` / `sync` / `infrastructure`), and the kind (`bug` / `enhancement` / `conformance` / `documentation` / `testing`). Check `gh label list` if unsure a label exists — don't invent one. Pass them at creation (`gh issue create --label ... --label ...`); an unlabeled issue is not done.
- **State root cause, not just symptom, in the body.** Don't file "X is broken" — file what you know or suspect about *why*, citing the go-algorand file/function if the investigation already got that far. An issue that only restates the symptom forces the next person to redo the investigation from zero.
- **Instruct TDD explicitly in the body.** Every new issue's body must tell whoever picks it up to write a failing test that pins the correct behavior *before* touching the fix (mirroring step 2 of this workflow) — don't assume the assignee will independently rediscover this repo's TDD-first culture.
- **Acceptance criteria as a `- [ ]` checklist** (per step 1) — no issue leaves your hands without them.
- If the issue belongs to an active version-upgrade epic, insert it into that epic's working plan (per step 9), not just file it loose.

## When to delegate to a background agent

Delegate to a background `Agent` (subagent_type `general-purpose`) when the fix requires deep investigation across consensus/ledger/network internals, live multi-node verification, or is otherwise large enough to burn significant context. Do it directly yourself for small, localized changes. A delegation prompt should walk the agent through all nine steps above, plus:

- **Repo path, pinned go-algorand version, and "read CLAUDE.md first."**
- **The anti-pause instruction — the single biggest cost seen in this repo's sessions so far:**

  > Do not pause mid-task to "wait for the next monitor event," a notification, or anything else that isn't a tool call you are making right now. Nothing resumes you automatically when a background shell command you started finishes — only a human/coordinator nudging you does, and each such nudge costs a full round trip. If you start a background command and need its result to proceed, either poll it synchronously in a loop within the same turn, or just run it in the foreground. Do not return control until you have an artifact to show: a passing test result, a pushed branch, a PR URL. "I'll wait and report back" is not an acceptable stopping point.

  Without this, agents in this repo have repeatedly stopped and emitted content like "I'll wait for the next monitor event," each surfacing as a separate `task-notification` that looks like progress but is not.
- **Do not merge the PR yourself** (step 9 is the coordinator's, gated on user confirmation); **finish by running `git checkout main`** — the working directory is shared with the user and other agents.

### Reviewing a delegated agent's work (steps 5-6, from the coordinator's side)

- **Never trust a garbled or suspiciously short final report.** Independently verify with `git status`, `git log --oneline -5`, `git diff --stat` against the branch before assuming anything landed.
- Re-run `/test-full` and clippy yourself even if the agent reports them clean — cheap insurance, has caught real drift before.
- Actually read the diff before opening/approving a PR — don't just relay the agent's own summary of its own work.
- If you need to send an agent a follow-up, **use `SendMessage` to its existing agent ID/name to resume it** — never call the `Agent` tool again for "the same" task. A fresh `Agent` call has zero memory of the prior run and either duplicates work or conflicts with it. If unsure whether an agent is still the right one to resume, check `ListAgents` first.
- A stale/duplicate `task-notification` from an agent you've already released or already incorporated the result of needs no action — this repo's agents can emit several near-identical notifications in a row. Treat these like the documented "same task-id may notify more than once" behavior, not new information.

## Issue disposition — don't force-close on partial success

If an issue's acceptance criteria are only partially met, or one criterion is structurally unreachable at the current architecture/topology (see issue #107's stake-split example), post an honest comment stating exactly what's met, what isn't, and why — then leave the issue open rather than closing it over an unmet criterion, UNLESS the remaining gap is itself out of scope for this codebase (e.g. a host-environment resource ceiling that reproduces identically on go-algorand — see issue #100's 1000+ TPS disk-I/O finding), in which case close it with that explanation. If a real new bug is found while working an issue but is out of scope to fix inline, file it as its own follow-up issue (see "Creating a new issue" above) rather than leaving it undocumented in a comment thread.
