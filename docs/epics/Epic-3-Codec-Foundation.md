# Epic 3 — Codec Foundation

## Goal
Decode and re-encode blocks deterministically in Rust.

## Deliverables
- algo_codec crate
- Fixture capture tool
- Golden tests

## Tasks
- Define minimal Block + Txn structs
- Decode msgpack blocks
- Implement capture command
- Add fixture-based tests

## Acceptance Criteria
- Can decode 200+ rounds from fixtures
- cargo test validates deterministic decoding