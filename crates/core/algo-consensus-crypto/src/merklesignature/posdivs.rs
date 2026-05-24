//! Round ↔ key-index arithmetic for the Merkle Signature Scheme.
//!
//! Mirrors `../go-algorand/crypto/merklesignature/posdivs.go` byte-for-byte.
//! The helpers are reused by the leaf-hashing adapter (which needs the round
//! corresponding to each leaf index) and by future signer-side code.

/// Round of the first index produced for a given `first_valid` / `interval`.
///
/// Mirrors `merklesignature.roundOfFirstIndex`.
#[inline]
pub fn round_of_first_index(first_valid: u64, interval: u64) -> u64 {
    // Go writes this as `((firstValid + interval - 1) / interval) * interval`;
    // `first_valid.div_ceil(interval) * interval` is mathematically identical
    // and avoids the `manual_div_ceil` clippy lint without changing semantics.
    first_valid.div_ceil(interval) * interval
}

/// Translate a leaf index back to the round it covers.
///
/// Mirrors `merklesignature.indexToRound`.
#[inline]
pub fn index_to_round(first_valid: u64, interval: u64, pos: u64) -> u64 {
    round_of_first_index(first_valid, interval) + pos * interval
}

/// Translate a round back to its leaf index in the ephemeral-key array.
///
/// Mirrors `merklesignature.roundToIndex`.
#[inline]
#[allow(dead_code)] // exposed for downstream signer-side code (TASK-180)
pub fn round_to_index(first_valid: u64, current_round: u64, interval: u64) -> u64 {
    let rofi = round_of_first_index(first_valid, interval);
    (current_round - rofi) / interval
}

/// First round of the key lifetime containing `round`.
///
/// Mirrors `merklesignature.firstRoundInKeyLifetime`.
#[inline]
#[allow(dead_code)]
pub fn first_round_in_key_lifetime(round: u64, key_lifetime: u64) -> u64 {
    round - (round % key_lifetime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_of_first_index_aligns_up_to_interval() {
        // first_valid=1, interval=256 → 256 (next multiple ≥ 1)
        assert_eq!(round_of_first_index(1, 256), 256);
        // first_valid=256, interval=256 → 256 (already aligned)
        assert_eq!(round_of_first_index(256, 256), 256);
        // first_valid=257, interval=256 → 512
        assert_eq!(round_of_first_index(257, 256), 512);
    }

    #[test]
    fn index_to_round_inverts_round_to_index() {
        let first_valid = 1u64;
        let interval = 256u64;
        for idx in 0..10u64 {
            let round = index_to_round(first_valid, interval, idx);
            assert_eq!(round_to_index(first_valid, round, interval), idx);
        }
    }

    #[test]
    fn first_round_in_key_lifetime_floors_to_interval() {
        assert_eq!(first_round_in_key_lifetime(300, 256), 256);
        assert_eq!(first_round_in_key_lifetime(256, 256), 256);
        assert_eq!(first_round_in_key_lifetime(511, 256), 256);
        assert_eq!(first_round_in_key_lifetime(512, 256), 512);
    }
}
