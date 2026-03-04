# Epic 1 — Deterministic Go Localnet Environment

## Goal
Create a reproducible Go localnet environment accessible by Rust.

## Deliverables
- docker compose setup
- Exposed REST port
- Persistent data dir volume

## Tasks
- Containerize go-algorand localnet
- Expose REST (4001)
- Mount genesis + token files
- Add make localnet-up command

## Acceptance Criteria
- Localnet starts reliably
- curl status + block endpoints work