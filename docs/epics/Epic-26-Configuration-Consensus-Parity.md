# Epic: Node configuration and consensus-parameter parity audit

Tracks auditing algod-rust's node-configuration surface and
consensus-parameter struct against go-algorand's, field by field, and
closing every real divergence found. GitHub epic issue:
[#745](https://github.com/xarmian/algod-rust/issues/745). Full scope and
audit findings: [`docs/PHASE16_PROPOSAL.md`](../PHASE16_PROPOSAL.md).

## Why this phase exists

Phases 9–14 tracked *version-delta* parity — what changed between two
go-algorand pins. They were never scoped to re-audit the **absolute**
shape of `config.Local`/`config.ConsensusParams` from scratch, so a gap
present since the original phase 0–3 port, untouched by any later
version delta, would never surface through that process.

## Headline findings

1. **No `config.json` ingestion mechanism at all** — algod-rust reads
   only a small `algod-rust.toml` (two sections); go-algorand's ~97 real
   `Local` fields are ~9 matching, ~20 different, ~10 not-applicable, and
   **~58 with no equivalent**.
2. **23 consensus-parameter fields absent** from `consensus.rs` (which
   otherwise correctly covers ~118 of 141 fields back to v7) — 8
   self-documented as skipped, **15 silently missing**, several of which
   are historical-replay-correctness risks (unconditional-vs-version-gated
   bugfix-activation flags).
3. **No custom consensus.json load/merge/save mechanism** — a real
   go-algorand-authored file already sits unused in the repo
   (`docker/config/vfuture-consensus.json`).

All three predate the version-delta sweeps.

## Sub-issues (dependency order, priority-first)

- [ ] Consensus-critical historical-replay param gaps (highest priority)
- [ ] Custom consensus.json load/merge/save mechanism
- [ ] Remaining medium-priority consensus param gaps
- [ ] config.json load/migration mechanism (foundational plumbing)
- [ ] Networking config field gaps
- [ ] Storage/data-dir config field gaps
- [ ] REST/API config field gaps
- [ ] Catchup/sync config field gaps
- [ ] Agreement/queue/vote-compression config field gaps
- [ ] Telemetry/metrics/logging config field gaps
- [ ] Dead-file cleanup: `docker/localnet-rust/data/config.json`

(Filled in with issue numbers once created — see `docs/PHASE16_PROPOSAL.md`
and the epic issue itself for the live list.)

## Epic-level acceptance criteria

- [ ] All sub-issues above closed (merged or honestly disposed).
- [ ] `docs/PHASE16_PROPOSAL.md`, this doc, `docs/PROJECT_SCOPE.md` updated.
- [ ] Full gate green on `main`.
- [ ] `docs/PHASE16_VALIDATION.md` evidence map written at close-out.
- [ ] Hard gate: `gh issue list --label "phase:16" --state open` empty
      before this epic closes.
