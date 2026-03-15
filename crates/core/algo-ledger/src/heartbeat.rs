//! Challenge helpers for heartbeat fee exemption.
//!
//! Implements the challenge mechanism from go-algorand's `ledger/apply/challenge.go`.
//! When an account is "challenged" (its address matches the block seed's leading bits),
//! it must heartbeat within a grace period or risk suspension. Heartbeats responding
//! to an active challenge are fee-exempt ("cheap" heartbeats).

use algo_codec::decode_block;
use algo_error::AlgoError;
use algo_types::consensus::{consensus_params_for_version, ConsensusParams};

/// Indicates which part of the challenge period is under discussion.
///
/// Mirrors Go's `ChallengePeriod` in `ledger/apply/challenge.go`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengePeriod {
    /// The challenge is in effect and the initial grace period is running out.
    /// Used when validating heartbeat transactions — accounts in this window
    /// can submit fee-exempt heartbeats.
    Risky,
    /// The challenge is in effect and the grace period has run out, so
    /// accounts can be suspended. Used during block evaluation for suspension.
    Active,
}

/// A challenge issued at a particular round.
///
/// Mirrors Go's `challenge` struct in `ledger/apply/challenge.go`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Challenge {
    /// The round at which the challenge was issued. 0 means no challenge.
    pub round: u64,
    /// The block seed at the challenge round. Accounts whose address matches
    /// the first `bits` of this seed must heartbeat or propose.
    pub seed: [u8; 32],
    /// Number of leading bits that must match.
    pub bits: u32,
}

impl Challenge {
    /// Returns true if this is a zero/empty challenge (no challenge in effect).
    ///
    /// Mirrors Go's `challenge.IsZero()`.
    pub fn is_zero(&self) -> bool {
        self.round == 0 && self.seed == [0u8; 32] && self.bits == 0
    }

    /// Returns true if the given address fails this challenge — i.e., the address
    /// matches the challenge seed bits AND the account hasn't been seen since before
    /// the challenge round.
    ///
    /// `last_seen` is `max(last_proposed, last_heartbeat)` matching Go's `LastSeen()`.
    ///
    /// Mirrors Go's `challenge.Failed(address, lastSeen)`.
    pub fn failed(&self, address: &[u8], last_seen: u64) -> bool {
        self.round != 0 && bits_match(&self.seed, address, self.bits) && last_seen < self.round
    }
}

/// Trait for looking up block header data by round.
///
/// This abstracts the header provider needed by `find_challenge`, mirroring
/// Go's `hdrProvider` interface.
pub trait HeaderProvider {
    /// Returns the raw block header data (msgpack bytes) for the given round,
    /// or an error if unavailable.
    fn block_header_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError>;
}

/// Adapter that wraps a `LedgerStore` reference to implement `HeaderProvider`.
pub struct StoreHeaderProvider<'a, L: crate::store_trait::LedgerStore> {
    pub store: &'a L,
}

impl<'a, L: crate::store_trait::LedgerStore> HeaderProvider for StoreHeaderProvider<'a, L> {
    fn block_header_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.store.get_block_header_data(round)
    }
}

/// Find the active challenge for the given round, if any.
///
/// Looks back `challenge_interval` rounds to find the challenge round, then checks
/// whether the current round falls within the specified challenge period window.
///
/// Mirrors Go's `FindChallenge` in `ledger/apply/challenge.go`.
pub fn find_challenge(
    params: &ConsensusParams,
    current_round: u64,
    headers: &dyn HeaderProvider,
    period: ChallengePeriod,
) -> Challenge {
    let interval = params.payouts_challenge_interval;

    // Are challenges active?
    if interval == 0 || current_round < interval {
        return Challenge::default();
    }

    let last_challenge = current_round - (current_round % interval);
    let grace = params.payouts_challenge_grace_period;

    // Check whether the current round is within the requested period window.
    // Go: FindChallenge avoids calling BlockHdr unnecessarily by checking the
    // period window first.
    match period {
        ChallengePeriod::Risky => {
            // Risky window: (lastChallenge + grace/2, lastChallenge + grace]
            if current_round <= last_challenge + grace / 2 || current_round > last_challenge + grace
            {
                return Challenge::default();
            }
        }
        ChallengePeriod::Active => {
            // Active window: (lastChallenge + grace, lastChallenge + 2*grace]
            if current_round <= last_challenge + grace || current_round > last_challenge + 2 * grace
            {
                return Challenge::default();
            }
        }
    }

    // Get the block header at the challenge round.
    let hdr_data = match headers.block_header_data(last_challenge) {
        Ok(Some(data)) => data,
        _ => return Challenge::default(),
    };

    // Decode the block header to get the seed and protocol version.
    // NOTE: `decode_block` is used on header-only data because `Block` is a flat
    // struct — the payset fields simply default to empty. There is no separate
    // `BlockHeader` deserialization type; the encoding-only `BlockHeader` in
    // algo-codec cannot be used for decoding.
    let block = match decode_block(&hdr_data) {
        Ok(b) => b,
        Err(_) => return Challenge::default(),
    };

    // Check that the challenge-round's protocol has the same payout rules.
    // Go: `challengeProto.Payouts != rules` — if the rules changed, ignore.
    // This comparison mirrors Go's `ProposerPayoutRules` struct equality.
    // If new payout-related fields are added to ConsensusParams, they must
    // be included here to maintain conformance.
    if let Some(challenge_params) = consensus_params_for_version(&block.current_protocol) {
        if challenge_params.payouts_challenge_interval != params.payouts_challenge_interval
            || challenge_params.payouts_challenge_grace_period
                != params.payouts_challenge_grace_period
            || challenge_params.payouts_challenge_bits != params.payouts_challenge_bits
            || challenge_params.payouts_max_mark_absent != params.payouts_max_mark_absent
            || challenge_params.payouts_enabled != params.payouts_enabled
            || challenge_params.payouts_go_online_fee != params.payouts_go_online_fee
            || challenge_params.payouts_percent != params.payouts_percent
            || challenge_params.payouts_min_balance != params.payouts_min_balance
            || challenge_params.payouts_max_balance != params.payouts_max_balance
        {
            return Challenge::default();
        }
    } else {
        // Unknown protocol version at challenge round — no challenge.
        return Challenge::default();
    }

    // Extract the seed from the block header (now always [u8; 32]).
    let seed = block.seed;

    Challenge {
        round: last_challenge,
        seed,
        bits: params.payouts_challenge_bits,
    }
}

/// Check if the first `n` bits of two byte slices match.
///
/// Written to work on arbitrary slices, but we expect that `n` is small.
/// The only user today calls with n=5.
///
/// Mirrors Go's `bitsMatch` in `ledger/apply/challenge.go`.
pub fn bits_match(a: &[u8], b: &[u8], n: u32) -> bool {
    let n = n as usize;

    // Ensure n is a valid number of bits to compare.
    if n > a.len() * 8 || n > b.len() * 8 {
        return false;
    }

    // n == 0 means no bits to compare — trivially matches.
    if n == 0 {
        return true;
    }

    // Compare entire bytes for the full-byte portion.
    let full_bytes = n / 8;
    if a[..full_bytes] != b[..full_bytes] {
        return false;
    }

    // Compare remaining bits in the partial byte.
    let remaining = n % 8;
    if remaining == 0 {
        return true;
    }

    // Check that the top `remaining` bits of the next byte match.
    // Go uses `bits.LeadingZeros8(a[n/8] ^ b[n/8]) >= remaining`.
    let xor = a[full_bytes] ^ b[full_bytes];
    xor.leading_zeros() >= remaining as u32
}

/// Compute the "last seen" round for an account, matching Go's `AccountData.LastSeen()`.
/// Returns `max(last_proposed, last_heartbeat)`.
pub fn last_seen(last_proposed: u64, last_heartbeat: u64) -> u64 {
    std::cmp::max(last_proposed, last_heartbeat)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── bits_match tests ─────────────────────────────────────────

    #[test]
    fn bits_match_zero_bits() {
        // n=0 always matches regardless of content.
        assert!(bits_match(&[0xFF], &[0x00], 0));
        assert!(bits_match(&[], &[], 0));
    }

    #[test]
    fn bits_match_one_bit_match() {
        // 0b1000_0000 vs 0b1111_1111 — first bit matches.
        assert!(bits_match(&[0x80], &[0xFF], 1));
    }

    #[test]
    fn bits_match_one_bit_no_match() {
        // 0b0000_0000 vs 0b1000_0000 — first bit differs.
        assert!(!bits_match(&[0x00], &[0x80], 1));
    }

    #[test]
    fn bits_match_five_bits_match() {
        // First 5 bits of 0xF8 (1111_1000) and 0xFF (1111_1111) match.
        assert!(bits_match(&[0xF8], &[0xFF], 5));
    }

    #[test]
    fn bits_match_five_bits_no_match() {
        // First 5 bits of 0xF0 (1111_0000) and 0xF8 (1111_1000) — 5th bit differs.
        assert!(!bits_match(&[0xF0], &[0xF8], 5));
    }

    #[test]
    fn bits_match_eight_bits() {
        // Exactly one full byte.
        assert!(bits_match(&[0xAB, 0x00], &[0xAB, 0xFF], 8));
        assert!(!bits_match(&[0xAB, 0x00], &[0xAC, 0xFF], 8));
    }

    #[test]
    fn bits_match_nine_bits() {
        // First 8 bits match, 9th bit (MSB of second byte) must also match.
        // 0xAB 0x80 vs 0xAB 0xFF — 9th bit is 1 in both.
        assert!(bits_match(&[0xAB, 0x80], &[0xAB, 0xFF], 9));
        // 0xAB 0x00 vs 0xAB 0x80 — 9th bit is 0 vs 1.
        assert!(!bits_match(&[0xAB, 0x00], &[0xAB, 0x80], 9));
    }

    #[test]
    fn bits_match_full_match() {
        let a = [0xDE, 0xAD, 0xBE, 0xEF];
        let b = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(bits_match(&a, &b, 32));
    }

    #[test]
    fn bits_match_n_exceeds_slice_length() {
        // If n requires more bits than available, return false.
        assert!(!bits_match(&[0xFF], &[0xFF], 9));
        assert!(!bits_match(&[0xFF], &[0xFF, 0xFF], 9));
    }

    #[test]
    fn bits_match_empty_slices_nonzero_n() {
        assert!(!bits_match(&[], &[], 1));
    }

    // ── Challenge::is_zero tests ─────────────────────────────────

    #[test]
    fn challenge_default_is_zero() {
        assert!(Challenge::default().is_zero());
    }

    #[test]
    fn challenge_with_round_is_not_zero() {
        let ch = Challenge {
            round: 1000,
            seed: [0u8; 32],
            bits: 5,
        };
        assert!(!ch.is_zero());
    }

    #[test]
    fn challenge_with_seed_is_not_zero() {
        let mut seed = [0u8; 32];
        seed[0] = 1;
        let ch = Challenge {
            round: 0,
            seed,
            bits: 0,
        };
        assert!(!ch.is_zero());
    }

    // ── Challenge::failed tests ──────────────────────────────────

    #[test]
    fn challenge_failed_matching_address_no_heartbeat() {
        // Create a challenge where the seed matches the address in the first 5 bits.
        let seed = [0xF8; 32]; // 1111_1000...
        let address = [0xFF; 32]; // 1111_1111... — first 5 bits match.
        let ch = Challenge {
            round: 1000,
            seed,
            bits: 5,
        };
        // last_seen (999) < challenge round (1000) — failed.
        assert!(ch.failed(&address, 999));
    }

    #[test]
    fn challenge_failed_matching_address_with_recent_heartbeat() {
        let seed = [0xF8; 32];
        let address = [0xFF; 32];
        let ch = Challenge {
            round: 1000,
            seed,
            bits: 5,
        };
        // last_seen (1000) >= challenge round (1000) — not failed.
        assert!(!ch.failed(&address, 1000));
        // last_seen (1001) > challenge round — not failed.
        assert!(!ch.failed(&address, 1001));
    }

    #[test]
    fn challenge_failed_non_matching_address() {
        let seed = [0xF8; 32]; // 1111_1000...
        let address = [0x00; 32]; // 0000_0000... — first bit differs.
        let ch = Challenge {
            round: 1000,
            seed,
            bits: 5,
        };
        // Address doesn't match — not failed regardless of last_seen.
        assert!(!ch.failed(&address, 0));
    }

    #[test]
    fn challenge_failed_zero_challenge() {
        let ch = Challenge::default();
        let address = [0x00; 32];
        // Zero challenge never fails.
        assert!(!ch.failed(&address, 0));
    }

    // ── last_seen tests ──────────────────────────────────────────

    #[test]
    fn last_seen_picks_max() {
        assert_eq!(last_seen(100, 200), 200);
        assert_eq!(last_seen(300, 200), 300);
        assert_eq!(last_seen(0, 0), 0);
    }

    // ── find_challenge tests (with mock header provider) ─────────

    struct MockHeaderProvider {
        headers: std::collections::HashMap<u64, Vec<u8>>,
    }

    impl HeaderProvider for MockHeaderProvider {
        fn block_header_data(&self, round: u64) -> Result<Option<Vec<u8>>, AlgoError> {
            Ok(self.headers.get(&round).cloned())
        }
    }

    /// Helper to build a minimal msgpack-encoded block header with a given seed
    /// and protocol version. Uses a small serde struct that produces a msgpack
    /// map with just the fields we need — `decode_block` will default the rest.
    fn make_header_data(seed: &[u8; 32], proto: &str) -> Vec<u8> {
        use serde::Serialize;
        use serde_bytes::ByteBuf;

        #[derive(Serialize)]
        struct MinHeader {
            #[serde(rename = "seed")]
            seed: ByteBuf,
            #[serde(rename = "proto")]
            proto: String,
            #[serde(rename = "rnd")]
            rnd: u64,
        }

        let hdr = MinHeader {
            seed: ByteBuf::from(seed.to_vec()),
            proto: proto.to_string(),
            rnd: 0,
        };
        rmp_serde::to_vec_named(&hdr).expect("encode block header")
    }

    /// V41 protocol version string.
    const V41_PROTO: &str =
        "https://github.com/algorandfoundation/specs/tree/953304de35264fc3ef91bcd05c123242015eeaed";

    fn make_v41_params() -> ConsensusParams {
        // Use actual V41 params which have challenges enabled.
        consensus_params_for_version(V41_PROTO).expect("V41 params")
    }

    #[test]
    fn find_challenge_no_interval() {
        let mut params = make_v41_params();
        params.payouts_challenge_interval = 0;
        let provider = MockHeaderProvider {
            headers: std::collections::HashMap::new(),
        };
        let ch = find_challenge(&params, 5000, &provider, ChallengePeriod::Risky);
        assert!(ch.is_zero());
    }

    #[test]
    fn find_challenge_current_round_too_small() {
        let params = make_v41_params();
        // Current round < interval (1000).
        let provider = MockHeaderProvider {
            headers: std::collections::HashMap::new(),
        };
        let ch = find_challenge(&params, 500, &provider, ChallengePeriod::Risky);
        assert!(ch.is_zero());
    }

    #[test]
    fn find_challenge_risky_window() {
        let params = make_v41_params();
        // interval=1000, grace=200
        // last_challenge = 2000 (for round 2100..2200 in risky window)
        // Risky window: (last_challenge + grace/2, last_challenge + grace]
        //             = (2100, 2200]
        let seed = [0xAB; 32];
        let proto = V41_PROTO;
        let mut headers = std::collections::HashMap::new();
        headers.insert(2000, make_header_data(&seed, proto));
        let provider = MockHeaderProvider { headers };

        // Round 2100 — at boundary, NOT in window (<=).
        let ch = find_challenge(&params, 2100, &provider, ChallengePeriod::Risky);
        assert!(ch.is_zero());

        // Round 2101 — in risky window.
        let ch = find_challenge(&params, 2101, &provider, ChallengePeriod::Risky);
        assert!(!ch.is_zero());
        assert_eq!(ch.round, 2000);
        assert_eq!(ch.seed, seed);
        assert_eq!(ch.bits, 5);

        // Round 2200 — at end of window, still in.
        let ch = find_challenge(&params, 2200, &provider, ChallengePeriod::Risky);
        assert!(!ch.is_zero());

        // Round 2201 — outside window.
        let ch = find_challenge(&params, 2201, &provider, ChallengePeriod::Risky);
        assert!(ch.is_zero());
    }

    #[test]
    fn find_challenge_active_window() {
        let params = make_v41_params();
        // interval=1000, grace=200
        // last_challenge = 2000
        // Active window: (last_challenge + grace, last_challenge + 2*grace]
        //              = (2200, 2400]
        let seed = [0xCD; 32];
        let proto = V41_PROTO;
        let mut headers = std::collections::HashMap::new();
        headers.insert(2000, make_header_data(&seed, proto));
        let provider = MockHeaderProvider { headers };

        // Round 2200 — at boundary, NOT in window (<=).
        let ch = find_challenge(&params, 2200, &provider, ChallengePeriod::Active);
        assert!(ch.is_zero());

        // Round 2201 — in active window.
        let ch = find_challenge(&params, 2201, &provider, ChallengePeriod::Active);
        assert!(!ch.is_zero());
        assert_eq!(ch.round, 2000);
        assert_eq!(ch.seed, seed);

        // Round 2400 — at end of window, still in.
        let ch = find_challenge(&params, 2400, &provider, ChallengePeriod::Active);
        assert!(!ch.is_zero());

        // Round 2401 — outside window.
        let ch = find_challenge(&params, 2401, &provider, ChallengePeriod::Active);
        assert!(ch.is_zero());
    }

    #[test]
    fn find_challenge_missing_header_returns_zero() {
        let params = make_v41_params();
        // No header at challenge round — should return zero.
        let provider = MockHeaderProvider {
            headers: std::collections::HashMap::new(),
        };
        let ch = find_challenge(&params, 2150, &provider, ChallengePeriod::Risky);
        assert!(ch.is_zero());
    }

    #[test]
    fn find_challenge_different_protocol_returns_zero() {
        let params = make_v41_params();
        let seed = [0xAB; 32];
        // Use V39 protocol which has different (zero) payout rules.
        let proto = "https://github.com/algorandfoundation/specs/tree/925a46433742afb0b51bb939354bd907fa88bf95";
        let mut headers = std::collections::HashMap::new();
        headers.insert(2000, make_header_data(&seed, proto));
        let provider = MockHeaderProvider { headers };

        // Round 2150 would be in risky window, but protocol rules differ.
        let ch = find_challenge(&params, 2150, &provider, ChallengePeriod::Risky);
        assert!(ch.is_zero());
    }

    // ── Integration: challenge + failed ──────────────────────────

    #[test]
    fn integration_challenged_account_detected() {
        let params = make_v41_params();
        // Create a seed where the first 5 bits are 1111_1.
        let seed = [0xF8; 32]; // 1111_1000
        let proto = V41_PROTO;
        let mut headers = std::collections::HashMap::new();
        headers.insert(2000, make_header_data(&seed, proto));
        let provider = MockHeaderProvider { headers };

        // Round 2150 is in risky window.
        let ch = find_challenge(&params, 2150, &provider, ChallengePeriod::Risky);
        assert!(!ch.is_zero());

        // Address with first 5 bits matching: 1111_1xxx.
        let matching_addr = [0xFF; 32]; // 1111_1111 — first 5 bits match.
        let non_matching_addr = [0x00; 32]; // 0000_0000 — first bit differs.

        // Account that hasn't heartbeated since before the challenge.
        assert!(ch.failed(&matching_addr, 1999));
        // Account that heartbeated at the challenge round.
        assert!(!ch.failed(&matching_addr, 2000));
        // Non-matching account — never fails.
        assert!(!ch.failed(&non_matching_addr, 0));
    }
}
