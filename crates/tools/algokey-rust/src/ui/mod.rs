//! CLI UI helpers for the algokey-rust binary.
//!
//! `run_with_spinner` is not invoked from `main` yet — TASK-180
//! (`algokey part generate`) wires it in. Marking the module as
//! allow(dead_code) keeps the warning-free build until then.

#![allow(dead_code)]

pub mod spinner;
