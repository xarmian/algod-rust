# Epic 0 — Project Bootstrap and Guardrails

## Goal
Establish a clean Rust workspace and repo structure that will scale with future phases.

## Deliverables
- Rust workspace with modular crates
- CI-ready structure
- Clear Phase 0 interfaces

## Tasks
- Create workspace layout:
  - crates/algo_types
  - crates/algo_codec
  - crates/algo_rest_client
  - crates/algo_conformance
  - bin/algod-rust
- Add tooling (fmt, clippy, Makefile/justfile)
- Define BlockSource trait
- Define Comparator interface

## Acceptance Criteria
- cargo test runs clean
- algod-rust --help works
- Repo structure supports future expansion