We are building algod-rust — a Rust reimplementation of go-algorand. Phase 1
(stateless block validation) is complete. Epic 13 establishes the account model
and genesis state loader.

## Epic 14 — Payment & Close-Remainder State Transitions

This epic implements `apply_transaction()` and `apply_block()` in algo-ledger,
starting with payment transactions. It also implements reward distribution —
the mechanism by which pending rewards are applied to accounts when they
participate in transactions.

### Background

When a payment transaction executes in go-algorand:
1. Pending rewards are applied to sender, receiver, and close-to accounts
2. Sender is debited (amount + fee)
3. Receiver is credited (amount)
4. Fee sink is credited (fee)
5. If close-remainder-to is set, remaining balance (minus min-balance) transfers out
6. If rekey_to is set, sender's auth_addr is updated
7. Account rewards_base is updated to current rewards_level

Reward calculation (from `data/basics/userBalance.go`):
```
pending_rewards = (rewards_level - account.rewards_base) * account.microalgos / reward_units
```
Where `reward_units` is typically 1,000,000 (1 Algo in microAlgos). Rewards accrue
to all Online accounts (not NotParticipating).

### Deliverables

1. **`apply_transaction()` dispatcher** in `algo-ledger/src/apply.rs`
   - Match on `txn.txn_type` and dispatch to type-specific handlers
   - Common pre-apply: compute and apply pending rewards to all touched accounts
   - Common post-apply: update rewards_base, handle rekey_to, debit fee from sender,
     credit fee to fee_sink

2. **Payment handler** (`apply_pay`)
   - Debit sender: amount + fee (after rewards applied)
   - Credit receiver: amount
   - Close-remainder-to: if set, transfer (sender.balance - min_balance) to close-to address
   - Account closure semantics: when closing, clear rewards_base, verify no remaining
     opted-in assets or apps (fail if so)

3. **Reward distribution** in `algo-ledger/src/rewards.rs`
   - `apply_rewards(account, rewards_level) -> u64` — compute and add pending rewards
   - Handle edge cases: rewards_base > rewards_level (should not happen but guard),
     zero balance (no rewards), NotParticipating status (no rewards)
   - Rewards pool balance tracking: the rewards pool account balance decreases as
     rewards are distributed
   - Rewards recalculation: at RewardsRateRefreshInterval boundaries, new rate is
     computed from remaining pool balance

4. **`apply_block()` orchestrator** in `algo-ledger/src/lib.rs`
   - Process all transactions in block order
   - Update ledger rewards state from block header (rewards_level, rewards_rate,
     rewards_residue, rewards_recalculation_round)
   - Track round number progression

5. **Rekey state tracking**
   - When any transaction has `rekey_to` set, update the sender's `auth_addr`
   - Clear auth_addr if rekey_to equals sender (rekey back to self)

6. **REST client extension**
   - Add `get_account(addr: &Address) -> AccountData` to AlgodClient
   - Uses `/v2/accounts/{addr}` endpoint
   - JSON response parsing for balance, status, rewards fields

7. **Conformance tests**
   - Replay localnet blocks with payment transactions
   - After each block, compare sender/receiver balances against Go node via REST
   - Verify fee sink balance increases by sum of fees
   - Verify rewards distribution matches ApplyData fields (rs, rr, rc)

### Key context
- ApplyData fields on SignedTransaction: closing_amount (ca), sender_rewards (rs),
  receiver_rewards (rr), close_rewards (rc) — these are the Go-computed values we
  can compare against
- Fee sink and rewards pool addresses come from genesis (Epic 13)
- Block header rewards fields: earn (rewards_level), rate (rewards_rate),
  frac (rewards_residue), rwcalr (rewards_recalculation_round)
- Asset/app IDs from block ApplyData: caid, apid — trust recorded values, don't re-derive
- go-algorand payment logic: `ledger/apply.go` and `ledger/eval.go`

### What success looks like
- `apply_block()` processes payment blocks and produces correct balances
- Reward distribution matches ApplyData rs/rr/rc fields from block
- Fee sink balance matches expected sum of fees
- Close-remainder-to transfers correct amounts
- Rekey updates auth_addr correctly
- Conformance tests pass against localnet Go node
- All existing tests still pass

Read docs/ for architecture and conformance strategy.
Start by studying go-algorand's apply.go and eval.go for payment handling,
then implement apply_transaction and reward distribution.
