---
name: algod-issue-fix
description: Standard workflow for implementing/fixing a GitHub issue in xarmian/algod-rust — delegating deep consensus/ledger investigation to a background agent, reviewing its work, and shipping the PR. Use whenever asked to "continue with issue N" or "fix issue N" in this repo.
---

# algod-rust issue-fix workflow

This repo (Rust reimplementation of go-algorand, pinned to `../go-algorand` @ v4.5.1-stable) has an established, TDD-first, live-verification-first culture. Read `CLAUDE.md` at the repo root before starting — it has mandatory environment quirks (Windows cargo/MSVC wrapper, the known `algo-network` doctest flake, "never chain retries hoping for a different result"). Use `/cargo`, `/test-full`, and `/pr-ship` (this repo's slash commands) rather than re-deriving those invocations from scratch each time.

## When to delegate vs. do it yourself

Delegate to a background `Agent` (subagent_type `general-purpose`) when the fix requires deep investigation across consensus/ledger/network internals, live multi-node verification, or is otherwise large enough to burn significant context. Do it directly yourself for small, localized changes.

## The delegation prompt — required contents

A prompt that omits any of these reliably wastes a full agent run:

1. **Repo path, pinned go-algorand version, and "read CLAUDE.md first".**
2. **The issue number and its full text** (`gh issue view N`), plus a summary of why it matters and what's already been tried/ruled out, if anything.
3. **Where to start reading** — file paths, but explicitly flagged as "start here, not necessarily the root cause" so the agent doesn't anchor on a wrong guess.
4. **Required approach**: write a failing test first; find the actual root cause (compare against `../go-algorand`'s real behavior, cite the file); fix it; if the change touches the participation/agreement/network path, re-verify live against `ops/mixed-cluster/` or `docker/scripts/bench-stress.sh` before declaring done — a passing unit test alone does not close consensus-critical issues in this repo.
5. **The verification gate**: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (only the known `peer_features.rs` doctest flake is an acceptable failure — see `/test-full`).
6. **PR instructions**: commit message must explain the root cause, not just the symptom; branch name `fix/issue-N-<slug>` or `feat/issue-N-<slug>`; `gh pr create` with `Fixes #N` in the body; **do not merge it yourself**; **finish by running `git checkout main`** — the working directory is shared with the user and other agents.
7. **The anti-pause instruction — the single biggest cost seen in this repo's sessions so far:**

   > Do not pause mid-task to "wait for the next monitor event," a notification, or anything else that isn't a tool call you are making right now. Nothing resumes you automatically when a background shell command you started finishes — only a human/coordinator nudging you does, and each such nudge costs a full round trip. If you start a background command and need its result to proceed, either poll it synchronously in a loop within the same turn, or just run it in the foreground. Do not return control until you have an artifact to show: a passing test result, a pushed branch, a PR URL. "I'll wait and report back" is not an acceptable stopping point.

   Without this, agents in this repo have repeatedly stopped and emitted content like "I'll wait for the next monitor event" or "I'll continue waiting for the sustained/cooldown/report phases," each of which surfaces as a separate `task-notification` that looks like progress but is not — burning many turns for zero new information.

## Reviewing a delegated agent's work

- **Never trust a garbled or suspiciously short final report.** Independently verify with `git status`, `git log --oneline -5`, `git diff --stat` against the branch before assuming anything landed.
- Re-run `/test-full` and clippy yourself even if the agent reports them clean — it's cheap insurance and has caught real drift before.
- Actually read the diff (`git show <sha>` or `git diff origin/main...<branch>`) before opening/approving a PR — don't just relay the agent's own summary of its own work.
- If you need to send an agent a follow-up, **use `SendMessage` to its existing agent ID/name to resume it** — never call the `Agent` tool again for "the same" task. A fresh `Agent` call has zero memory of the prior run and either duplicates work or conflicts with it. If unsure whether an agent is still the right one to resume, check `ListAgents` first.
- A stale/duplicate `task-notification` from an agent you've already released or already incorporated the result of needs no action — this repo's agents can emit several near-identical notifications in a row (e.g. re-confirming a live cluster run finished). Treat these like the documented "same task-id may notify more than once" behavior, not new information.

## Shipping

Use `/pr-ship <pr-number>` once the PR is open — it handles the CI-poll-then-confirm-then-merge sequence and syncs local `main` afterward.

## Issue disposition — don't force-close on partial success

If an issue's acceptance criteria are only partially met, or one criterion is structurally unreachable at the current architecture/topology (see issue #107's stake-split example), post an honest comment stating exactly what's met, what isn't, and why — then leave the issue open rather than closing it over an unmet criterion. If a real new bug is found while working an issue but is out of scope to fix inline, file it as its own follow-up issue rather than leaving it undocumented in a comment thread.
