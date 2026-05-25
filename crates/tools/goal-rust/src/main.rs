//! Thin binary entry — delegates to [`goal_rust::run`] in the library
//! so integration tests can drive the same code path without
//! spawning a subprocess. The Cli definition + dispatch table live
//! in `src/lib.rs`.

fn main() -> std::process::ExitCode {
    goal_rust::run()
}
