// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression guard for issue #568: debug builds of `algod-rust.exe`
//! stack-overflow on Windows before `main()` even runs.
//!
//! ## Root cause
//!
//! On Windows, an OS thread's initial stack is a *reservation* baked into
//! the executable's PE header at link time (`/STACK:<reserve>,<commit>`,
//! default `0x100000` = 1 MiB via the MSVC linker), not something a
//! `std::thread::Builder::stack_size` call inside `main()` can change for
//! the process's own main thread -- by the time user code runs, the OS has
//! already allocated that fixed-size stack.
//!
//! `algod-rust`'s dependency graph (tokio, reqwest/hyper/rustls, libp2p)
//! is unusually deep, and in **debug** builds rustc does not perform the
//! MIR-level storage-coalescing optimization that lets non-overlapping
//! locals across a large `async fn`'s `match` arms (here, `main`'s
//! subcommand dispatch) share stack space. That inflates the generated
//! state machine for `async fn main()` enough to blow the default 1 MiB
//! Windows main-thread stack *before a single line of `main`'s body
//! executes* -- confirmed by instrumenting the very first statement of
//! `main()` with `eprintln!` and observing zero output before the
//! `STATUS_STACK_OVERFLOW` crash. `--release` builds are unaffected
//! because optimized builds *do* coalesce that storage. A
//! `std::thread::Builder::stack_size`-based fix was tried and confirmed
//! ineffective for exactly this reason (the crash predates any user code,
//! including the thread-spawn call itself).
//!
//! ## Fix
//!
//! `.cargo/config.toml` passes `/STACK:8388608` (8 MiB) to the MSVC
//! linker for the `x86_64-pc-windows-msvc` target, raising the *reserved*
//! main-thread stack baked into the PE header itself -- the one lever that
//! actually applies before `main()` starts. This is a link-time
//! reservation of address space, not committed memory, so it has no
//! runtime cost. It is a bounded, compile-time-determined stack ceiling
//! (the generated state machine's size is fixed by the crate's dependency
//! graph, not by any unbounded/data-dependent recursion), so raising the
//! reservation is the correct fix rather than a workaround -- unlike a
//! runtime `RUST_MIN_STACK`/thread-spawn approach, it applies uniformly to
//! every thread the OS creates for the process, including the one thread
//! (main) that cannot be resized after the fact.
//!
//! Manually verified (see PR description for the full transcript): built
//! `target\debug\algod-rust.exe` before and after this fix on Windows and
//! ran `capture`/`validate` against a block fixture server. Before: zero
//! output, `STATUS_STACK_OVERFLOW`. After: clean completion, exit code 0.
//!
//! This test can't reproduce a Windows-only, debug-only OS stack overflow
//! inside `cargo test` (a real crash can't be caught in-process, and CI
//! runs on Linux). Instead it pins the fix's config so a future edit can't
//! silently drop it.

use std::path::Path;

/// The `.cargo/config.toml` must keep raising the MSVC-linked stack
/// reservation for the Windows target; dropping it would silently
/// reintroduce #568 (only reproducible manually on a Windows debug build,
/// so nothing else in the automated suite would catch a regression here).
#[test]
fn cargo_config_raises_windows_msvc_stack_reserve() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let config_path = Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join(".cargo")
        .join("config.toml");
    let contents = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", config_path.display()));

    assert!(
        contents.contains("[target.x86_64-pc-windows-msvc]"),
        ".cargo/config.toml must configure the windows-msvc target, got:\n{contents}"
    );
    assert!(
        contents.contains("/STACK:"),
        ".cargo/config.toml must pass an MSVC linker /STACK reservation \
         for windows-msvc (see issue #568 -- debug builds overflow the \
         default 1 MiB main-thread stack before main() even runs), got:\n{contents}"
    );

    // The reserve must be strictly larger than the MSVC linker default of
    // 0x100000 (1 MiB) -- otherwise the flag is present but a no-op. Only
    // look at the active `rustflags = [...]` line, not comment lines that
    // may mention the default value for context.
    let stack_value = contents
        .lines()
        .find(|line| line.trim_start().starts_with("rustflags"))
        .and_then(|line| line.split_once("/STACK:"))
        .map(|(_, rest)| rest)
        .expect("expected a `rustflags = [...]` line containing /STACK:<bytes>");
    let digits: String = stack_value
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let reserve_bytes: u64 = digits
        .parse()
        .unwrap_or_else(|e| panic!("failed to parse /STACK reserve value {digits:?}: {e}"));
    const MSVC_DEFAULT_STACK_RESERVE: u64 = 0x100000; // 1 MiB
    assert!(
        reserve_bytes > MSVC_DEFAULT_STACK_RESERVE,
        "/STACK reserve ({reserve_bytes} bytes) must exceed the MSVC default \
         ({MSVC_DEFAULT_STACK_RESERVE} bytes) to actually fix #568"
    );
}
