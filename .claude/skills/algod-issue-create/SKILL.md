---
name: algod-issue-create
description: Create a single, correctly-templated and correctly-labeled GitHub issue in xarmian/algod-rust — the shared issue-creation step used by algod-issue-fix (follow-ups, spin-offs, open-topics) and algod-version-upgrade (one issue per upstream feature). Always determines and applies the `algod:<tag>` upstream-version label when the issue is parity-related. Use whenever a new issue needs to be filed in this repo, not just when working those two skills directly.
---

# algod-rust issue creation

One issue, created once, with the full mandatory shape this repo expects. Both `algod-issue-fix` (filing a follow-up/spin-off/open-topic) and `algod-version-upgrade` (filing one issue per upstream feature in stage 3) call into this rather than reimplementing it — if you're filing an issue in this repo for any other reason, use this too.

## 1. Decide whether this is a parity issue, and which lookup mode applies

Before writing the body, decide: does this issue describe algod-rust needing to match a specific behavior that exists (or changed) in `../go-algorand`? Examples that are parity issues: a missing opcode, an API field mismatch, a consensus-param gap, a byte-level encoding difference, or algod-rust producing the wrong result for something go-algorand already handles correctly. Examples that are **not**: CI/infrastructure bugs with no upstream behavioral counterpart (e.g. a script losing its execute bit), this repo's own tooling, doc fixes, refactors, performance work not tied to a specific upstream change.

**A `bug`-kind issue in this repo is parity-related by default** — this codebase's whole premise is byte-level/behavioral parity with go-algorand, so "algod-rust does X wrong" almost always means "go-algorand already does X correctly, in some specific way, at some specific commit." Only treat a bug as non-parity when you've actually confirmed there's no upstream behavior to diverge from at all (pure algod-rust-internal tooling/CI/build issues) — don't assume non-applicability just because the issue doesn't cite a go-algorand commit yet.

Run `go-algorand-version-lookup`, picking its mode deliberately:
- **New feature / addition** (algod-rust has no code path for this yet): addition mode — the lookup finds the commit that *introduced* the thing.
- **Bug / behavioral divergence** (algod-rust has code here but it disagrees with go-algorand): **divergence mode** — the lookup finds the commit that shaped go-algorand's *current* correct logic for this specific behavior (via `git log -L`/`git log -p` on the relevant lines, not just "first commit that touched the file"), which may be old and unrelated to when the surrounding feature was first added. This is the common case for bug reports and needs its own targeted search — never label a bug issue with a guessed or convenient tag; ground it in the actual commit that produced the correct behavior.
- **Genuinely not parity-related**: skip the lookup. No `algod:<tag>` label. Don't force one.

Do this even when the issue originated from a release-notes bullet, a code diff, or a live-parity test failure you've already read — the lookup is what turns "algod-rust disagrees with go-algorand here" into a citable commit and tag, not just a description. Never skip this step because the issue "obviously" is or isn't parity-related — the whole reason this exists is that a batch of issues filed without it drifts into inconsistent labeling that's expensive to reconstruct later.

## 2. Body template

```
Title: <area>: <what changes> [(go-algorand <tag>)]   ← version suffix only if parity-related

## Root cause / Upstream change
- <what's wrong today, or what upstream changed>
- go-algorand commits/PRs: <SHAs / PR links>              ← parity issues only
- Files: <go paths>                                        ← parity issues only
- First released in: <ORIGIN_TAG from go-algorand-version-lookup>   ← parity issues only

## What algod-rust must do
- Affected crates: <crates>
- <precise description of the behavior delta, citing source>

## Acceptance criteria
- [ ] TDD: failing test first, pinned to the correct behavior
- [ ] Parity: fixtures/oracle comparison against go-algorand where byte-level   ← parity issues only
- [ ] `cargo fmt` / `clippy -D warnings` / full workspace suite green
- [ ] (consensus-critical only) live mixed-cluster verification
```

Every issue this skill creates must:
- **State root cause, not just symptom.** Cite the go-algorand file/function if the investigation got that far.
- **Instruct TDD explicitly** — tell the assignee to write a failing test pinning the correct behavior before touching the fix.
- **Carry acceptance criteria as a `- [ ]` checklist** — no issue leaves this skill without them; they're the contract `algod-issue-fix` step 9 audits against.
- If it belongs to an active epic/phase, note that (`Part of epic #<n>` / insert into the epic's working plan) — don't leave it floating loose when it clearly belongs somewhere.

## 3. Labels (mandatory — an unlabeled issue is not done)

Check `gh label list` first; create anything missing (`gh label create "<name>" --description "..." --color <hex>`) rather than inventing an untracked label.

- **`phase:<n>`** — matching the active epic/phase this issue belongs to, if any.
- **`algod:<tag>`** — from step 1's lookup, when applicable:
  - Origin tag always: `algod:<ORIGIN_TAG>`.
  - If the lookup found the change also reaches the current pin and `PIN_TAG != ORIGIN_TAG`, add `algod:<PIN_TAG>` too (`gh issue edit <n> --add-label "algod:<PIN_TAG>"`) — a future reader filtering by the pin tag must be able to find this issue.
  - Not applicable → no `algod:<tag>` label. Do not fabricate one to make an issue "look" parity-related.
- **One domain label**: `consensus` / `ledger` / `avm` / `networking` / `rest-api` / `sync` / `infrastructure`.
- **One effort label**: `effort:small` / `effort:medium` / `effort:large`.
- **Kind**: `bug` / `enhancement` / `conformance` / `documentation` / `testing` (`conformance` specifically for parity-verification work).

Create with `gh issue create --title "..." --body "..." --label ... --label ...` (pass every label at creation where possible; `gh issue edit <n> --add-label ...` for anything added after, like a second `algod:<tag>` discovered mid-review).

## 4. Report back

State the created issue number, its full label set, and — for parity issues — the origin/pin tags from the lookup, so the caller (a skill or a person) can link it into whatever epic or PR it belongs to.
