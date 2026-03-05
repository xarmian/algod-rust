# Epic 4 — Conformance v1 (Structural)

## Goal
Compare structural fields between Go and Rust representations.

## Deliverables
- Diff reporting crate
- Round-based pass/fail output

## Tasks
- Compare round numbers
- Compare protocol/version
- Compare txn count
- Implement fail-fast behavior

## Acceptance Criteria
- 500+ rounds validate cleanly
- Intentional corruption triggers mismatch detection