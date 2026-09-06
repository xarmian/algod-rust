#!/usr/bin/env bash
#
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Poll a *known* PR number's CI checks until they all resolve. Sibling to
# wait_for_issue_pr.sh: use this one when the PR already exists (you have its
# number) and there's nothing to look up -- just a CI settle to wait for.
#
# Usage: wait_for_pr_checks.sh <pr-number> [timeout-seconds] [poll-interval-seconds]
#
# Exit codes:
#   0  all checks SUCCESS/SKIPPED/NEUTRAL
#   1  at least one check FAILURE/CANCELLED/TIMED_OUT
#   3  timed out waiting for checks to leave PENDING/QUEUED/IN_PROGRESS
#
# Designed to be run with run_in_background:true so it does one long
# synchronous wait and reports back exactly once, instead of the coordinator
# re-polling `gh pr checks` (or rescheduling a wakeup) every few minutes.

set -u

PR="${1:?usage: wait_for_pr_checks.sh <pr-number> [timeout-seconds] [poll-interval-seconds]}"
TIMEOUT="${2:-1800}"
INTERVAL="${3:-20}"

start_ts=$(date +%s)

echo "[wait_for_pr_ci] watching PR #${PR}'s checks (timeout=${TIMEOUT}s, poll=${INTERVAL}s)"

while true; do
  now=$(date +%s)
  elapsed=$(( now - start_ts ))
  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "RESULT: CHECKS_TIMEOUT pr=${PR} elapsed=${elapsed}s"
    exit 3
  fi

  states=$(gh pr checks "$PR" --json state -q '.[].state' 2>/dev/null)

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
    echo "RESULT: CHECKS_FAILED pr=${PR} elapsed=${elapsed}s"
    gh pr checks "$PR" 2>&1
    exit 1
  fi

  echo "RESULT: CHECKS_GREEN pr=${PR} elapsed=${elapsed}s"
  exit 0
done
