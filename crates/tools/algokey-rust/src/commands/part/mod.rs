//! `algokey part` subcommand implementations.
//!
//! Mirrors `../go-algorand/cmd/algokey/part.go`:
//! - `info` — read partkey + print fields (TASK-179, this PR).
//! - `generate` — full keygen + persist (TASK-180, follow-up).
//! - `reparent` — UPDATE parent column (TASK-181, follow-up).
//!
//! Until TASK-180 / TASK-181 land, dispatch for `generate` / `reparent`
//! still routes through `main.rs`'s `not_implemented` stub.

pub mod info;
pub mod print_partkey;
