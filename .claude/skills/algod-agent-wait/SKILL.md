# algod-rust: waiting on a dispatched issue-fix agent

**MANDATORY, not optional: every single time you dispatch an `Agent` for an
algod-issue-fix task in this repo, your very next tool call — same turn —
is launching the matching `wait_for_issue_pr.sh`/`wait_for_pr_checks.sh`
background script.** Session history shows this rule getting silently
dropped mid-session more than once: the coordinator falls back to just
replying to each of the *dispatched agent's own* internal task-notifications
("waiting for the CI poll", "still waiting on the build") with a fresh
one-line reply each time. That is the exact anti-pattern this skill exists
to eliminate, just one level removed — the dispatched agent's own internal
polling-and-pausing cycle bubbles a notification up to the coordinator on
every pause, and mirroring each one back with "Waiting." is indistinguishable
from the nudge-loop this file already forbids. **Do not narrate a dispatched
agent's internal progress. Ever.** If you notice yourself writing "Waiting"
or "Continuing to wait" in response to a task-notification from an agent
whose PR you don't yet have a coordinator-side wait script running against,
stop and launch the script instead of replying again.

Use this whenever you (the coordinator) have dispatched a background `Agent`
to work an issue via the `algod-issue-fix` workflow, and need to know when
it has produced a mergeable PR. Do **not** wait for the dispatched agent to
narrate its own completion — this repo's session history shows agents
routinely stop mid-task saying "I'll wait for the monitor/notification
before continuing," which is never true: nothing wakes an agent
automatically except a `SendMessage` from the coordinator, and each such
nudge costs a full round trip. Repeatedly nudging a stalled agent one
notification at a time is the anti-pattern this skill replaces.

## The pattern

1. Dispatch the agent as usual (`Agent` tool, `isolation: "worktree"`,
   anti-pause instructions in the prompt, "never call `gh pr merge`
   yourself").
2. Immediately — in the same turn, without waiting for the agent's first
   notification — kick off a **coordinator-side** background wait: either
   `scripts/wait_for_issue_pr.sh` (Bash tool) or `scripts/wait_for_issue_pr.ps1`
   (PowerShell tool) — both do the identical poll, use whichever shell is
   working reliably in the moment (Bash's `cmd.exe` invocation has been
   flaky on this Windows machine before; fall back to PowerShell if so):

   ```bash
   cd "c:\Users\ludovit.scholtz\source\repos\scholtz\algod-rust" && \
   bash scripts/wait_for_issue_pr.sh <issue-number> 1800 20
   ```
   ```powershell
   Set-Location "c:\Users\ludovit.scholtz\source\repos\scholtz\algod-rust"
   pwsh -File scripts/wait_for_issue_pr.ps1 -IssueNumber <issue-number> -TimeoutSeconds 1800 -PollIntervalSeconds 20
   ```

   Run this with `run_in_background: true` on whichever tool you used.
   The tool's own `timeout` parameter caps out at 600000ms (600s)
   parameter caps out at 600000ms (600s) regardless of what you pass — it
   is NOT the same budget as the script's own internal timeout argument.
   Always pass the script an internal timeout of ≤570 (leaving headroom
   under the tool's 600s ceiling) so the script prints its `RESULT:` line
   and exits cleanly before the tool would kill it. If a dispatched agent's
   real work plausibly takes longer than that (most `algod-issue-fix` runs
   do), the single script call will most likely end in `NO_PR` or
   `CHECKS_TIMEOUT` well before the agent is actually done — that's
   expected and fine, NOT a failure to fix: just re-issue the same script
   call again (same args) rather than switching to manual polling. Each
   relaunch is one more full-budget wait; treat this as chained
   session-length waits, not as "it timed out, escalate." This script polls GitHub directly for the PR that
   closes the given issue (via `closingIssuesReferences`, not fragile title
   matching) and then polls that PR's checks — the coordinator does not
   need to interpret anything the dispatched agent says to know when real
   work has landed.
3. You will get exactly one `task-notification` when the script exits, with
   a `RESULT: ...` line you can act on directly:
   - `RESULT: CHECKS_GREEN` → audit the issue's acceptance criteria, tick
     them, and merge (`gh pr merge <n> --squash --delete-branch`), same as
     the normal `algod-issue-fix` step 9.
   - `RESULT: CHECKS_FAILED` → read the printed check list, then the failing
     run's logs (`gh run view <run-id> --log-failed`); either fix it
     yourself in the agent's worktree or nudge the agent with the specific
     failure.
   - `RESULT: NO_PR` (timed out before any PR appeared) → the agent is
     genuinely stuck (not just narrating a false wait — no branch/PR exists
     at all). Inspect its worktree directly (`git status`, `git log
     --oneline -3` in `.claude/worktrees/agent-<id>`) rather than sending
     another vague nudge. If it has uncommitted work that looks basically
     done, finish the mechanical steps yourself (fmt/clippy/commit/push/PR)
     — this has repeatedly been faster than continuing to prompt a stuck
     agent. If it has nothing, treat it as stalled and either resume it
     with a concrete, specific instruction (not "please continue") or
     abandon and relaunch fresh.
   - `RESULT: CHECKS_TIMEOUT` (PR exists but checks never resolved) — check
     for a GitHub webhook-dispatch stall (compare against
     `gh run list --limit 5`: if `pull_request`-triggered runs are missing
     repo-wide even for other branches, it's not this PR's fault). A
     `git merge origin/main && git push` on the PR's branch often
     retriggers real `pull_request` CI; `gh workflow run <workflow> --ref
     <branch>` (`workflow_dispatch`) is a fallback that produces valid
     check-runs but only for workflows whose path filters match the diff.

## Do not manually peek while a wait script is running

Once `wait_for_issue_pr.sh` (or `wait_for_pr_checks.sh`) is running in the
background, do not spend additional tool calls checking on it early —
no `gh pr checks`, no `cat`-ing its output file, no re-running the same
query "just to see." Each such peek is a wasted round trip identical in
kind to the nudge-loop this skill replaces, just aimed at the script
instead of the agent. Launch the wait script once, then stop and let the
single `task-notification` at its actual completion drive the next
action. If you genuinely need to change the plan mid-wait (the user asks
something else), that's fine — but return to relying on the pending
notification rather than adding a parallel manual poll.

## Waiting on a *known* PR number: `wait_for_pr_checks.sh` / `.ps1`

Once a PR already exists (you have its number — from a merge-conflict
rebase you just pushed, from an agent's own report, from `gh pr list`),
use `scripts/wait_for_pr_checks.sh <pr-number> [timeout] [poll-interval]`
(Bash tool) or `scripts/wait_for_pr_checks.ps1 -PrNumber <n> [-TimeoutSeconds ...] [-PollIntervalSeconds ...]`
(PowerShell tool) the same way: one `run_in_background: true` call, one
`RESULT:` line, one `task-notification`. It skips `wait_for_issue_pr`'s
phase 1 (finding the PR) since you already know the number.

```bash
cd "c:\Users\ludovit.scholtz\source\repos\scholtz\algod-rust" && \
bash scripts/wait_for_pr_checks.sh 1036 570 20
```
```powershell
Set-Location "c:\Users\ludovit.scholtz\source\repos\scholtz\algod-rust"
pwsh -File scripts/wait_for_pr_checks.ps1 -PrNumber 1036 -TimeoutSeconds 570 -PollIntervalSeconds 20
```

Use whichever shell is working reliably in the moment — the goal is one
backgrounded call and one notification, not narrating progress in either
shell.

**Never wait for CI by repeatedly calling `ScheduleWakeup` (or any other
"check now, reschedule for N minutes later" loop) instead.** Each firing
re-invokes a full agent turn — from the user's side this looks identical
to the agent nudge-loop this skill exists to replace, just retargeted at
a GitHub API call instead of a stalled agent. `ScheduleWakeup` is for
open-ended/dynamic pacing where there is no single bounded condition to
wait on; "is this PR's CI done yet" is exactly the kind of bounded
condition a background shell loop already expresses correctly, so express
it that way and let the one notification drive the next action.

## Why not just poll `gh pr checks` yourself inline, turn after turn

You can technically re-run `gh pr checks <n>` by hand each turn, but don't
— it costs one full round trip per check, identical in kind to the
disallowed `ScheduleWakeup` loop above. Always prefer backgrounding
`wait_for_pr_checks.sh` (known PR number) or `wait_for_issue_pr.sh`
(PR not yet known) over any manual or scheduled re-polling.

## Merge-conflict note

The script only observes GitHub state — it never touches git itself. If
`docs/PHASE17_TEST_PARITY.md` or `docs/epics/Epic-27-Test-Parity-Audit.md`
conflicts block a PR from even being mergeable, that still needs the usual
manual resolution (`git checkout --theirs docs/PHASE17_TEST_PARITY.md` +
`python scripts/update_phase17_summary.py` for the aggregate file; manual
bullet-combination for the epic file) — CI green does not imply
merge-conflict-free at merge time, so a `gh pr merge` after a
`CHECKS_GREEN` result can still fail on conflicts if `main` moved again in
between; retry the merge, and if it fails, resolve conflicts in the PR's
branch and let this script's phase 2 re-poll after you push.
