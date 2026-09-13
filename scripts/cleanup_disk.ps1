<#
.SYNOPSIS
    Periodic disk-space maintenance for the algod-rust working copy.

.DESCRIPTION
    Dispatched agents in this repo occasionally leave behind git worktrees
    under .claude/worktrees/ (each with its own checkout + cargo `target/`
    build directory). These accumulate silently and can consume hundreds
    of gigabytes over time. This script:

      1. Removes every registered git worktree except the main one.
         `git worktree remove` refuses to touch a worktree that is locked
         (i.e. genuinely in use by a running agent), so this is safe to
         run at any time, even while agents are active.
      2. Runs `git worktree prune` to drop stale metadata for worktrees
         whose directories are already gone.
      3. Deletes any leftover empty/orphaned directories under
         .claude/worktrees/ that git no longer tracks.
      4. Optionally runs `cargo clean` on the main target/ directory if
         free disk space drops below -MinFreeGB (default 40 GB) --
         target/ is fully regenerable, just slower to rebuild.
      5. Removes session-temp subdirectories under the Claude temp root
         older than -TempRetentionDays (default 14 days).
      6. Logs a timestamped summary (space freed, before/after free space)
         to logs/cleanup_disk.log next to this script.

.PARAMETER MinFreeGB
    If free space on the drive holding the repo drops below this many GB,
    also run `cargo clean` on target/. Default 40.

.PARAMETER TempRetentionDays
    Delete Claude session temp subdirectories older than this many days.
    Default 14.

.EXAMPLE
    pwsh -File scripts/cleanup_disk.ps1
    pwsh -File scripts/cleanup_disk.ps1 -MinFreeGB 60 -TempRetentionDays 7
#>
param(
    [int]$MinFreeGB = 40,
    [int]$TempRetentionDays = 14
)

$ErrorActionPreference = 'Continue'
$repoRoot = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $repoRoot 'logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$logFile = Join-Path $logDir 'cleanup_disk.log'

function Write-Log($msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Write-Output $line
    Add-Content -Path $logFile -Value $line
}

function Get-FreeGB {
    $drive = (Get-Item $repoRoot).PSDrive.Name
    $free = (Get-PSDrive $drive).Free
    return [math]::Round($free / 1GB, 2)
}

Write-Log "=== cleanup_disk.ps1 starting ==="
$freeBefore = Get-FreeGB
Write-Log "Free space before: $freeBefore GB"

Push-Location $repoRoot
try {
    # 1. Remove all worktrees except the main one.
    $mainPath = (git rev-parse --show-toplevel).Trim() -replace '/', '\'
    $worktrees = git worktree list --porcelain 2>$null |
        Select-String '^worktree (.+)$' |
        ForEach-Object { $_.Matches[0].Groups[1].Value -replace '/', '\' }

    $removed = 0
    $skipped = 0
    foreach ($wt in $worktrees) {
        if ($wt -ieq $mainPath) { continue }
        $result = git worktree remove --force "$wt" 2>&1
        if ($LASTEXITCODE -eq 0) {
            $removed++
        } else {
            $skipped++
            Write-Log "  skipped (in use or locked): $wt"
        }
    }
    Write-Log "Worktrees removed: $removed, skipped (in use/locked): $skipped"

    # 2. Prune stale worktree metadata.
    git worktree prune -v 2>&1 | ForEach-Object { Write-Log "  prune: $_" }

    # 3. Delete orphaned directories under .claude/worktrees not tracked by git.
    $wtDir = Join-Path $repoRoot '.claude\worktrees'
    if (Test-Path $wtDir) {
        $tracked = (git worktree list --porcelain 2>$null |
            Select-String '^worktree (.+)$' |
            ForEach-Object { Split-Path -Leaf ($_.Matches[0].Groups[1].Value) })
        Get-ChildItem $wtDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $dirName = $_.Name
            $dirPath = $_.FullName
            if ($tracked -notcontains $dirName) {
                try {
                    Remove-Item $dirPath -Recurse -Force -ErrorAction Stop
                    Write-Log "  removed orphaned dir: $dirName"
                } catch {
                    Write-Log "  could not remove (busy/locked, left in place): $dirName"
                }
            }
        }
    }

    # 4. Conditionally clean target/ if disk space is still tight.
    $freeNow = Get-FreeGB
    if ($freeNow -lt $MinFreeGB) {
        Write-Log "Free space ($freeNow GB) below threshold ($MinFreeGB GB) -- running cargo clean"
        cargo clean 2>&1 | ForEach-Object { Write-Log "  cargo clean: $_" }
    } else {
        Write-Log "Free space ($freeNow GB) above threshold ($MinFreeGB GB) -- leaving target/ alone"
    }
} finally {
    Pop-Location
}

# 5. Trim old Claude session temp directories.
$claudeTemp = Join-Path $env:LOCALAPPDATA 'Temp\claude'
if (Test-Path $claudeTemp) {
    $cutoff = (Get-Date).AddDays(-$TempRetentionDays)
    Get-ChildItem $claudeTemp -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        ForEach-Object {
            $dirName = $_.Name
            $dirPath = $_.FullName
            try {
                Remove-Item $dirPath -Recurse -Force -ErrorAction Stop
                Write-Log "  removed stale temp session dir: $dirName"
            } catch {
                Write-Log "  could not remove temp dir (busy): $dirName"
            }
        }
}

$freeAfter = Get-FreeGB
Write-Log "Free space after: $freeAfter GB (freed ~$([math]::Round($freeAfter - $freeBefore, 2)) GB)"
Write-Log "=== cleanup_disk.ps1 done ==="
