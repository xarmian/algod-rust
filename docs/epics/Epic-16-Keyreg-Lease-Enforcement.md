We are building algod-rust — a Rust reimplementation of go-algorand. Phase 1
is complete. Epics 13-15 establish the account model, payment, and asset state
transitions.

## Epic 16 — Participation & Key Registration State + Cross-Block Lease Enforcement

This epic applies keyreg transactions to track participation state and implements
cross-block lease enforcement, which was deferred from Phase 1 because it requires
persistent state across blocks.

### Background

Key registration transactions change an account's participation status:
- **Online**: account has vote/selection keys, participates in consensus, earns rewards
- **Offline**: no active keys, does not participate, still earns rewards
- **NotParticipating**: permanently opted out, cannot earn rewards (irreversible in
  current protocol)

Leases prevent duplicate transactions: a (sender, lease) pair must be unique within the
transaction's validity window (first_valid to last_valid). Phase 1 validates leases within
a single block's transaction group. This epic extends enforcement across blocks, rejecting
transactions whose (sender, lease) pair was already seen in a recent block within the
validity window.

### Deliverables

1. **Online keyreg** handler
   - Store vote key (votekey), selection key (selkey), state proof key (sprfkey)
     on account
   - Store vote_first_valid, vote_last_valid, vote_key_dilution
   - Set account status to Online

2. **Offline keyreg** handler (nonpart=false, empty keys)
   - Clear all participation keys from account
   - Set account status to Offline
   - Account continues to earn rewards

3. **Nonparticipation keyreg** handler (nonpart=true)
   - Set account status to NotParticipating
   - Account can never earn rewards again
   - This is effectively irreversible (go-algorand enforces this)

4. **Reward eligibility integration**
   - Connect to rewards.rs from Epic 14
   - NotParticipating accounts: pending_rewards = 0 regardless of balance
   - Online and Offline accounts earn rewards normally
   - Verify reward distribution respects status after keyreg changes

5. **Cross-block lease enforcement** in `algo-ledger/src/lease.rs`
   - Data structure: track recently seen (sender, lease) pairs with their last_valid round
   - On transaction application: if lease is non-empty, check that (sender, lease)
     is not already in the lease table with a last_valid >= current round
   - If duplicate found: reject transaction
   - Cleanup: purge expired leases (last_valid < current round) periodically
   - Storage: in-memory BTreeMap or HashMap for now, SQLite-backed in Epic 17a

6. **Unit tests**
   - Keyreg online: verify keys stored, status changes to Online
   - Keyreg offline: verify keys cleared, status changes to Offline
   - Keyreg nonpart: verify status changes to NotParticipating, rewards stop
   - Lease enforcement: same (sender, lease) in consecutive blocks rejected
   - Lease expiry: (sender, lease) accepted after last_valid passes
   - Reward eligibility: verify NotParticipating gets 0 rewards

### Key context
- Transaction keyreg fields already decoded: votekey, selkey, sprfkey, votefst, votelst,
  votekd, nonpart
- AccountData from Epic 13 has fields for all participation keys and status
- Reward distribution from Epic 14 already computes pending_rewards
- Phase 1 validates lease size (0 or 32 bytes) and intra-block uniqueness
- go-algorand lease tracking: `ledger/lruaccts.go` and `ledger/eval.go`
- MaxTxnLife = 1000 rounds (lease validity window upper bound)

### What success looks like
- Keyreg transactions correctly transition account status
- Participation keys are stored and cleared correctly
- NotParticipating accounts receive zero rewards
- Cross-block lease enforcement rejects duplicate (sender, lease) pairs
- Expired leases are cleaned up and no longer block new transactions
- All existing tests still pass, new keyreg/lease tests added

Read docs/ for architecture and conformance strategy.
Start by implementing keyreg handlers (simpler), then add lease enforcement.
