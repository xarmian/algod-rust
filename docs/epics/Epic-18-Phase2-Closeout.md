We are building algod-rust — a Rust reimplementation of go-algorand. Phase 1
is complete. Epics 13-17a (and optionally 17b) implement ledger execution with
persistent storage and conformance testing.

## Epic 18 — Phase 2 Closeout & Validation

This epic performs end-to-end validation of the ledger execution implementation,
documents results and known gaps, and adds fuzz testing targets.

### Background

Phase 2 closeout follows the same pattern as Phase 0 and Phase 1: comprehensive
validation against Go reference, documentation of what was achieved and what gaps
remain, and preparation for the next phase.

### Deliverables

1. **Large-scale mainnet replay**
   - Replay 1000+ consecutive mainnet blocks with stateful validation
   - Compare account state against archival Go node after each block
   - Target: zero balance/asset/status mismatches
   - Document any blocks that require special handling (edge cases)

2. **Edge case validation**
   - Rewards recalculation rounds: verify correct behavior when reward rate changes
   - Zero-balance accounts: verify correct handling (min-balance enforcement)
   - Account closure and re-creation: close account, then re-open with new transaction
   - Fee pooling + stateful: atomic groups where fee=0 txns are correctly applied
   - Rekey chains: A rekeys to B, B rekeys to C, verify auth_addr tracking
   - Asset close-out with rewards: verify both asset and Algo state are correct

3. **Fuzz targets**
   - `cargo-fuzz` target for `apply_transaction`: random transactions against random state
   - `cargo-fuzz` target for state serialization: roundtrip AccountData through storage
   - Configure in `fuzz/` directory with Cargo.toml
   - Run for at least 1 hour without crashes

4. **PHASE2_VALIDATION.md**
   - Epics completed with summary of each
   - Test count and all-pass confirmation
   - Conformance layer 5 validation results:
     - Blocks replayed, transactions processed
     - Accounts compared, mismatches found
     - Edge cases tested
   - Known gaps:
     - Full TEAL execution (Phase 3)
     - Independent EvalDelta computation (Phase 3)
     - State root verification status (if 17b was deferred)
     - Any min-balance edge cases discovered
   - How to reproduce (build, test, replay commands)
   - Feeds into Phase 3 (AVM Execution)

5. **Phase 3 preparation**
   - Identify specific Phase 3 requirements based on Phase 2 experience
   - Document EvalDelta fields that need full modeling
   - Document inner transaction patterns encountered during mainnet replay
   - Estimate AVM opcode coverage needed

### Key context
- Phase 0 closeout: docs/PHASE0_VALIDATION.md (follow same structure)
- Phase 1 closeout: docs/PHASE1_VALIDATION.md (follow same structure)
- Current test count: 208 (Phase 1 end), expect 250+ after Phase 2
- Mainnet replay endpoint: mainnet-api.4160.nodely.dev (for blocks)
- Historical state: requires local archival Go node (from Epic 17a)
- cargo-fuzz: `cargo install cargo-fuzz`, then `cargo fuzz run target_name`

### What success looks like
- 1000+ mainnet blocks replayed with stateful validation, zero mismatches
- PHASE2_VALIDATION.md documents comprehensive results
- 2+ fuzz targets run without crashes
- Known gaps are clearly documented with Phase 3 assignments
- All workspace tests pass (`cargo test --workspace`)
- Clippy clean (`cargo clippy --workspace --all-targets -- -D warnings`)

Read docs/ for architecture and conformance strategy.
Run the full validation suite, document results, then write PHASE2_VALIDATION.md.
