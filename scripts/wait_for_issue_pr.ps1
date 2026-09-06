# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# PowerShell equivalent of wait_for_issue_pr.sh. Poll GitHub for the PR that
# closes a given issue, then poll that PR's CI checks until they all
# resolve. Prints a single-line machine-readable RESULT summary at the end
# and exits non-zero on timeout/failure so a caller can branch on it
# without re-parsing prose.
#
# Usage: pwsh -File wait_for_issue_pr.ps1 -IssueNumber <n> [-TimeoutSeconds 1800] [-PollIntervalSeconds 20]
#
# Exit codes:
#   0  PR found, all checks SUCCESS/SKIPPED/NEUTRAL
#   1  PR found, at least one check FAILURE/CANCELLED/TIMED_OUT
#   2  timed out waiting for a PR to appear referencing this issue
#   3  PR found but timed out waiting for checks to leave PENDING/QUEUED/IN_PROGRESS
#
# Designed to be run with run_in_background:true (PowerShell tool) so it
# does one long synchronous wait and reports back exactly once, instead of
# the coordinator repeatedly nudging a dispatched agent that stalls out
# saying "I'll wait for a monitor event" (there is no such event), or
# replying to that agent's own internal progress notifications turn by turn.

param(
    [Parameter(Mandatory = $true)][int]$IssueNumber,
    [int]$TimeoutSeconds = 1800,
    [int]$PollIntervalSeconds = 20
)

$ErrorActionPreference = 'SilentlyContinue'
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)

Write-Output "[wait_for_issue_pr] watching for a PR closing #$IssueNumber (timeout=${TimeoutSeconds}s, poll=${PollIntervalSeconds}s)"

$prNumber = $null
while ((Get-Date) -lt $deadline) {
    $prs = gh pr list --state open --json number,closingIssuesReferences 2>$null | ConvertFrom-Json
    foreach ($pr in $prs) {
        if ($pr.closingIssuesReferences.number -contains $IssueNumber) {
            $prNumber = $pr.number
            break
        }
    }
    if ($prNumber) { break }
    Start-Sleep -Seconds $PollIntervalSeconds
}

if (-not $prNumber) {
    Write-Output "RESULT: NO_PR issue=$IssueNumber"
    exit 2
}

Write-Output "[wait_for_issue_pr] found PR #$prNumber for issue #$IssueNumber"

while ((Get-Date) -lt $deadline) {
    $statesRaw = gh pr checks $prNumber --json state -q '.[].state' 2>$null
    if (-not $statesRaw) {
        Start-Sleep -Seconds $PollIntervalSeconds
        continue
    }
    $states = $statesRaw -split "`r?`n" | Where-Object { $_ -ne '' }
    if ($states -match 'PENDING|IN_PROGRESS|QUEUED') {
        Start-Sleep -Seconds $PollIntervalSeconds
        continue
    }
    $bad = $states | Where-Object { $_ -notin @('SUCCESS', 'SKIPPED', 'NEUTRAL') }
    if ($bad) {
        Write-Output "RESULT: CHECKS_FAILED issue=$IssueNumber pr=$prNumber"
        gh pr checks $prNumber
        exit 1
    }
    Write-Output "RESULT: CHECKS_GREEN issue=$IssueNumber pr=$prNumber"
    exit 0
}

Write-Output "RESULT: CHECKS_TIMEOUT issue=$IssueNumber pr=$prNumber"
exit 3
