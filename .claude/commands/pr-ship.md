---
description: Poll a PR's CI to green, confirm with the user, then squash-merge and sync local main
argument-hint: <pr-number>
allowed-tools: Bash(*)
---

PR number: $ARGUMENTS

1. Poll CI in the background until every check is out of `PENDING`/`IN_PROGRESS`/`QUEUED`:

```bash
while true; do
  states=$(gh pr checks $ARGUMENTS --json state -q '.[].state' 2>/dev/null)
  if [ -z "$states" ]; then echo "no checks yet"; sleep 15; continue; fi
  echo "$states" | sort | uniq -c
  if echo "$states" | grep -qv "SUCCESS\|SKIPPED\|NEUTRAL"; then
    if echo "$states" | grep -q "PENDING\|IN_PROGRESS\|QUEUED"; then
      sleep 20; continue
    else
      echo "FAILURE_DETECTED"; break
    fi
  else
    echo "ALL_GREEN"; break
  fi
done
```

Run this with `run_in_background: true` (it can take many minutes) — do not block the conversation on it, do not poll it manually in a sleep loop yourself, just wait for its own completion notification.

2. If `FAILURE_DETECTED`, stop and investigate the failing check's logs (`gh pr checks $ARGUMENTS` then `gh run view <run-id> --log-failed`) — do not merge, do not retry blindly.

3. If `ALL_GREEN`, merging is a shared-state action the auto-mode classifier blocks by default — use `AskUserQuestion` to confirm before merging (recommend "Yes, merge it" as the default option), even if this has been approved for other PRs earlier in the session. Once confirmed:

```bash
gh pr merge $ARGUMENTS --squash --delete-branch
```

4. Sync the local shared checkout back onto `main` (other agents/the user share this working directory):

```bash
git checkout main -q && git pull -q && git status --short
```

5. If the PR referenced "Fixes #N" / "Closes #N", GitHub auto-closes that issue on merge — verify with `gh issue view N --json state -q .state` rather than assuming.
