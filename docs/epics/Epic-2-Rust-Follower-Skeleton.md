# Epic 2 — Rust REST Client + Follower Skeleton

## Goal
Rust connects to Go node and follows rounds deterministically.

## Deliverables
- REST client crate
- algod-rust binary following rounds

## Tasks
- Implement status endpoint
- Implement block fetch endpoint (prefer msgpack)
- Add retry/backoff
- Implement --follow mode

## Acceptance Criteria
- Rust logs processing rounds
- Processes first 100+ rounds successfully