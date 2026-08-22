---
description: Run cargo test --workspace and report only real failures, filtering the known local doctest flake
allowed-tools: Bash(*), PowerShell(*)
---

Run the full workspace test suite through the Windows MSVC wrapper (see `/cargo`), in the background since it takes minutes:

```
cmd /c 'call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul && cd /d c:\Users\ludovit.scholtz\source\repos\scholtz\algod-rust && set PATH=%PATH%;%USERPROFILE%\.cargo\bin&& cargo test --workspace 2>&1'
```

Launch with `run_in_background: true` and a timeout of at least 480000ms. Do NOT read the raw output file directly — it is tens of thousands of lines and will blow the context budget for no benefit. Once it completes, extract only the signal:

```bash
grep -n "^test result:" <output-file> | grep -v ": ok\."
grep -n "FAILED\|panicked\|error\[" <output-file>
```

**Known, expected, harmless failure**: `algo-network`'s `peer_features.rs` doctests (`decode_peer_features`, `encode_peer_features`) fail locally on this machine with a "tempdir mounted with noexec" style error. This reproduces on every full run on this machine and NEVER on Linux CI. If this is the ONLY failure shown, treat the suite as clean — do not investigate it, do not attempt to fix it, do not report it as a regression.

Any other failure is real and must be diagnosed from its actual output (use `grep -B5 -A30` around the failing test name in the output file to pull just that section into context) — never re-run hoping it passes the second time.
