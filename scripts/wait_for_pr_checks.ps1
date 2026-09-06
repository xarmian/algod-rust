# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# PowerShell equivalent of wait_for_pr_checks.sh. Poll a *known* PR number's
# CI checks until they all resolve. Use this one when the PR already exists
# (you have its number) and there's nothing to look up -- just a CI settle
# to wait for.
#
# Usage: pwsh -File wait_for_pr_checks.ps1 -PrNumber <n> [-TimeoutSeconds 1800] [-PollIntervalSeconds 20]
#
# Exit codes:
#   0  all checks SUCCESS/SKIPPED/NEUTRAL
#   1  at least one check FAILURE/CANCELLED/TIMED_OUT
#   3  timed out waiting for checks to leave PENDING/QUEUED/IN_PROGRESS
#
# Designed to be run with run_in_background:true (PowerShell tool) so it
# does one long synchronous wait and reports back exactly once, instead of
# the coordinator re-polling `gh pr checks` every few minutes.

param(
    [Parameter(Mandatory = $true)][int]$PrNumber,
    [int]$TimeoutSeconds = 1800,
    [int]$PollIntervalSeconds = 20
)

$ErrorActionPreference = 'SilentlyContinue'
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)

Write-Output "[wait_for_pr_checks] watching PR #$PrNumber's checks (timeout=${TimeoutSeconds}s, poll=${PollIntervalSeconds}s)"

while ((Get-Date) -lt $deadline) {
    $statesRaw = gh pr checks $PrNumber --json state -q '.[].state' 2>$null
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
        Write-Output "RESULT: CHECKS_FAILED pr=$PrNumber"
        gh pr checks $PrNumber
        exit 1
    }
    Write-Output "RESULT: CHECKS_GREEN pr=$PrNumber"
    exit 0
}

Write-Output "RESULT: CHECKS_TIMEOUT pr=$PrNumber"
exit 3
