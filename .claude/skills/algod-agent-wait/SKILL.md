# algod-rust: waiting on a dispatched issue-fix agent

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
   notification — kick off `scripts/wait_for_issue_pr.sh` as a **coordinator
   -side** background Bash command:

   ```bash
   cd "c:\Users\ludovit.scholtz\source\repos\scholtz\algod-rust" && \
   bash scripts/wait_for_issue_pr.sh <issue-number> 1800 20
   ```

   Run this with `run_in_background: true`. The Bash tool's own `timeout`
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

## Why not just poll `gh pr checks` yourself inline

You can — for a single already-known PR number this is often simpler (see
`/pr-ship`'s inline loop). This skill's script exists specifically for the
**dispatch-and-wait** case, where you don't yet know the PR number and the
alternative is depending on the agent to tell you, which is exactly the
unreliable step this replaces.

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
