# Epic 5 — Conformance v2 (Canonical + Hashing)

## Goal
Validate canonical encoding and digest equivalence.

## Deliverables
- Canonical encoding implementation
- Hash computation
- Checkpoint reporting

## Tasks
- Implement canonical msgpack re-encoding
- Compute txn IDs
- Compute block header digest
- Compare against Go values

## Acceptance Criteria
- Rust matches Go txn IDs
- Rust matches block-level digest/checkpoint values