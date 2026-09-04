#!/usr/bin/env bash
# Poll GitHub for the PR that closes a given issue, then poll that PR's CI
# checks until they all resolve. Prints a single-line machine-readable
# summary at the end and exits non-zero on timeout/failure so a caller can
# branch on it without re-parsing prose.
#
# Usage: wait_for_issue_pr.sh <issue-number> [timeout-seconds] [poll-interval-seconds]
#
# Exit codes:
#   0  PR found, all checks SUCCESS/SKIPPED/NEUTRAL
#   1  PR found, at least one check FAILURE/CANCELLED/TIMED_OUT
#   2  timed out waiting for a PR to appear referencing this issue
#   3  PR found but timed out waiting for checks to leave PENDING/QUEUED/IN_PROGRESS
#
# Designed to be run with run_in_background:true from the coordinator so it
# does one long synchronous wait and reports back exactly once, instead of
# the coordinator repeatedly nudging a dispatched agent that stalls out
# saying "I'll wait for a monitor event" (there is no such event).

set -u

ISSUE="${1:?usage: wait_for_issue_pr.sh <issue-number> [timeout-seconds] [poll-interval-seconds]}"
TIMEOUT="${2:-1800}"
INTERVAL="${3:-20}"

start_ts=$(date +%s)
pr_number=""

echo "[wait_for_issue_pr] watching for a PR closing #${ISSUE} (timeout=${TIMEOUT}s, poll=${INTERVAL}s)"

while true; do
  now=$(date +%s)
  elapsed=$(( now - start_ts ))
  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "RESULT: NO_PR issue=${ISSUE} elapsed=${elapsed}s"
    exit 2
  fi

  # gh's closingIssuesReferences is the reliable way to find "Fixes #N" links,
  # independent of PR title/body wording.
  pr_number=$(gh pr list --state open --json number,closingIssuesReferences \
    --jq ".[] | select(.closingIssuesReferences[]?.number == ${ISSUE}) | .number" 2>/dev/null | head -1)

  if [ -n "$pr_number" ]; then
    echo "[wait_for_issue_pr] found PR #${pr_number} for issue #${ISSUE} after ${elapsed}s"
    break
  fi

  sleep "$INTERVAL"
done

# Phase 2: poll that PR's checks until none are pending/queued/in-progress.
while true; do
  now=$(date +%s)
  elapsed=$(( now - start_ts ))
  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "RESULT: CHECKS_TIMEOUT issue=${ISSUE} pr=${pr_number} elapsed=${elapsed}s"
    exit 3
  fi

  states=$(gh pr checks "$pr_number" --json state -q '.[].state' 2>/dev/null)

  if [ -z "$states" ]; then
    # No checks reported yet at all (can happen right after push, or during
    # a webhook-dispatch stall) -- keep waiting, don't treat as done.
    sleep "$INTERVAL"
    continue
  fi

  if echo "$states" | grep -q "PENDING\|IN_PROGRESS\|QUEUED"; then
    sleep "$INTERVAL"
    continue
  fi

  if echo "$states" | grep -qv "SUCCESS\|SKIPPED\|NEUTRAL"; then
    echo "RESULT: CHECKS_FAILED issue=${ISSUE} pr=${pr_number} elapsed=${elapsed}s"
    gh pr checks "$pr_number" 2>&1
    exit 1
  fi

  echo "RESULT: CHECKS_GREEN issue=${ISSUE} pr=${pr_number} elapsed=${elapsed}s"
  exit 0
done
