---
description: Run a cargo command through the Windows MSVC environment this repo needs
argument-hint: <cargo subcommand and args, e.g. "test --workspace">
allowed-tools: Bash(*), PowerShell(*)
---

Run the following exactly, substituting `$ARGUMENTS` for the cargo subcommand/args given. Do not modify the wrapper — bare `cargo` fails on this machine (`vswhere.exe not recognized` / `LNK1104: cannot open file 'msvcrt.lib'`) because the MSVC environment isn't loaded and `cargo` isn't on the default PATH.

```
cmd /c 'call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul && cd /d c:\Users\ludovit.scholtz\source\repos\scholtz\algod-rust && set PATH=%PATH%;%USERPROFILE%\.cargo\bin&& cargo $ARGUMENTS 2>&1'
```

For anything that takes more than ~30s (`test --workspace`, `clippy --workspace --all-targets`, a release build), run it via the Bash/PowerShell tool with `run_in_background: true` and a generous timeout rather than foreground — do not chain retries hoping for a different result if it fails; diagnose first.

If the command is `test --workspace` or otherwise runs the full suite, do NOT dump the raw output back into the conversation — pipe/grep for `^test result:` lines that aren't `: ok.` and for `FAILED`/`error\[`, per `/algod-test-full` instead of reading the whole log.
