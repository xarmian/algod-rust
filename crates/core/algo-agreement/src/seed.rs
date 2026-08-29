// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Seed type and derivation, matching go-algorand/data/committee/committee.go
// and go-algorand/agreement/proposal.go (deriveNewSeed).
//
// `Seed` is a 32-byte value containing cryptographic entropy used to
// determine a committee via VRF sortition.

use serde::{Deserialize, Serialize};

use algo_types::{Address, Digest};

use crate::hashable::{hash_obj, Hashable};

/// A 32-byte cryptographic seed used for committee sortition.
///
/// Mirrors Go's `committee.Seed` (`[32]byte`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Seed(pub [u8; 32]);

impl From<Digest> for Seed {
    fn from(d: Digest) -> Self {
        Self(d.0)
    }
}

impl From<[u8; 32]> for Seed {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Seed {
    /// Returns the inner bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Implements `Hashable` for `Seed` with HashID `"SD"`.
///
/// Mirrors Go's `committee.Seed.ToBeHashed()`:
/// ```go
/// func (s Seed) ToBeHashed() (protocol.HashID, []byte) {
///     return protocol.Seed, s[:]
/// }
/// ```
impl Hashable for Seed {
    fn hash_id() -> &'static [u8] {
        b"SD"
    }

    fn to_be_hashed(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// ---------------------------------------------------------------------------
// proposerSeed — period-0 seed derivation input
// ---------------------------------------------------------------------------

/// VRF output (64 bytes), matching Go's `crypto.VrfOutput`.
pub type VrfOutput = [u8; 64];

/// Input to proposer seed derivation (period 0).
///
/// Mirrors Go's `agreement.proposerSeed`:
/// ```go
/// type proposerSeed struct {
///     Addr basics.Address   `codec:"addr"`
///     VRF  crypto.VrfOutput `codec:"vrf"`
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ProposerSeed {
    pub addr: Address,
    pub vrf: VrfOutput,
}

/// Canonical msgpack encoding of `ProposerSeed`.
///
/// Layout (non-omitempty, alphabetical by codec tag):
/// ```text
/// fixmap(2)
///   fixstr("addr") -> bin(32)
///   fixstr("vrf")  -> bin(64)
/// ```
fn encode_proposer_seed(ps: &ProposerSeed) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + 5 + 34 + 4 + 66);

    // fixmap(2)
    buf.push(0x82);

    // fixstr("addr") = 0xa4, 'a','d','d','r'
    buf.extend_from_slice(&[0xa4, b'a', b'd', b'd', b'r']);
    // bin8(32) for Address
    rmp::encode::write_bin(&mut buf, &ps.addr.0).unwrap();

    // fixstr("vrf") = 0xa3, 'v','r','f'
    buf.extend_from_slice(&[0xa3, b'v', b'r', b'f']);
    // bin8(64) for VrfOutput
    rmp::encode::write_bin(&mut buf, &ps.vrf).unwrap();

    buf
}

impl Hashable for ProposerSeed {
    /// HashID = `"PS"` (protocol.ProposerSeed).
    fn hash_id() -> &'static [u8] {
        b"PS"
    }

    fn to_be_hashed(&self) -> Vec<u8> {
        encode_proposer_seed(self)
    }
}

// ---------------------------------------------------------------------------
// seedInput — seed rerandomization input
// ---------------------------------------------------------------------------

/// Input to seed rerandomization, used by both period-0 and period->0 paths.
///
/// Mirrors Go's `agreement.seedInput`:
/// ```go
/// type seedInput struct {
///     Alpha   crypto.Digest `codec:"alpha"`
///     History crypto.Digest `codec:"hist"`
/// }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SeedInput {
    pub alpha: Digest,
    pub history: Digest,
}

impl Default for SeedInput {
    fn default() -> Self {
        Self {
            alpha: Digest([0u8; 32]),
            history: Digest([0u8; 32]),
        }
    }
}

/// Canonical msgpack encoding of `SeedInput`.
///
/// Layout (non-omitempty, alphabetical by codec tag):
/// ```text
/// fixmap(2)
///   fixstr("alpha") -> bin(32)
///   fixstr("hist")  -> bin(32)
/// ```
fn encode_seed_input(si: &SeedInput) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + 6 + 34 + 5 + 34);

    // fixmap(2)
    buf.push(0x82);

    // fixstr("alpha") = 0xa5, 'a','l','p','h','a'
    buf.extend_from_slice(&[0xa5, b'a', b'l', b'p', b'h', b'a']);
    // bin8(32) for Alpha digest
    rmp::encode::write_bin(&mut buf, &si.alpha.0).unwrap();

    // fixstr("hist") = 0xa4, 'h','i','s','t'
    buf.extend_from_slice(&[0xa4, b'h', b'i', b's', b't']);
    // bin8(32) for History digest
    rmp::encode::write_bin(&mut buf, &si.history.0).unwrap();

    buf
}

impl Hashable for SeedInput {
    /// HashID = `"PS"` (protocol.ProposerSeed) — same as `ProposerSeed`.
    fn hash_id() -> &'static [u8] {
        b"PS"
    }

    fn to_be_hashed(&self) -> Vec<u8> {
        encode_seed_input(self)
    }
}

// ---------------------------------------------------------------------------
// Seed derivation
// ---------------------------------------------------------------------------

/// Derives a new seed for period 0 (normal proposal).
///
/// Mirrors Go's `deriveNewSeed` when `period == 0`.
///
/// Algorithm:
/// 1. `alpha = HashObj(ProposerSeed{addr, vrf_output})`
/// 2. Build `SeedInput{Alpha: alpha, History: ...}` with optional history mixing
/// 3. `new_seed = Seed(HashObj(input))`
///
/// The `history` parameter should be `Some(digest)` when history mixing applies,
/// i.e., when `rnd % (seed_lookback * seed_refresh_interval) < seed_lookback`.
pub fn derive_seed_period_zero(
    addr: &Address,
    vrf_output: &VrfOutput,
    history: Option<Digest>,
) -> Seed {
    let alpha = hash_obj(&ProposerSeed {
        addr: *addr,
        vrf: *vrf_output,
    });

    let mut input = SeedInput {
        alpha,
        ..Default::default()
    };
    if let Some(h) = history {
        input.history = h;
    }

    Seed::from(hash_obj(&input))
}

/// Derives a new seed for period > 0 (timeout/recovery).
///
/// Mirrors Go's `deriveNewSeed` when `period != 0`.
///
/// Algorithm:
/// 1. `alpha = HashObj(prevSeed)` — Seed's HashID is `"SD"`
/// 2. Build `SeedInput{Alpha: alpha, History: ...}` with optional history mixing
/// 3. `new_seed = Seed(HashObj(input))`
///
/// The `history` parameter should be `Some(digest)` when history mixing applies.
pub fn derive_seed_period_nonzero(prev_seed: &Seed, history: Option<Digest>) -> Seed {
    let alpha = hash_obj(prev_seed);

    let mut input = SeedInput {
        alpha,
        ..Default::default()
    };
    if let Some(h) = history {
        input.history = h;
    }

    Seed::from(hash_obj(&input))
}

/// Returns whether history mixing should be applied for the given round,
/// and if so, the round from which to look up the old block digest.
///
/// Mirrors Go's logic:
/// ```go
/// rerand := rnd % (SeedLookback * SeedRefreshInterval)
/// if rerand < SeedLookback {
///     digrnd := rnd.SubSaturate(SeedLookback * SeedRefreshInterval)
///     // use ledger.LookupDigest(digrnd)
/// }
/// ```
///
/// Returns `Some(digest_round)` if history mixing applies, `None` otherwise.
pub fn history_mix_round(rnd: u64, seed_lookback: u64, seed_refresh_interval: u64) -> Option<u64> {
    let cycle = seed_lookback * seed_refresh_interval;
    if cycle == 0 {
        return None;
    }
    let rerand = rnd % cycle;
    if rerand < seed_lookback {
        Some(rnd.saturating_sub(cycle))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Seed basics ────────────────────────────────────────────

    #[test]
    fn default_is_zero() {
        let s = Seed::default();
        assert_eq!(s.0, [0u8; 32]);
    }

    #[test]
    fn from_digest() {
        let bytes = [42u8; 32];
        let digest = Digest(bytes);
        let seed = Seed::from(digest);
        assert_eq!(seed.0, bytes);
    }

    #[test]
    fn from_bytes() {
        let bytes = [7u8; 32];
        let seed = Seed::from(bytes);
        assert_eq!(seed.0, bytes);
    }

    #[test]
    fn as_bytes_roundtrip() {
        let bytes = [99u8; 32];
        let seed = Seed(bytes);
        assert_eq!(seed.as_bytes(), &bytes);
    }

    // ── Seed Hashable ──────────────────────────────────────────

    #[test]
    fn seed_hash_id_is_sd() {
        assert_eq!(Seed::hash_id(), b"SD");
    }

    #[test]
    fn seed_to_be_hashed_is_raw_bytes() {
        let bytes = [0xab; 32];
        let seed = Seed(bytes);
        assert_eq!(seed.to_be_hashed(), bytes.to_vec());
    }

    // ── ProposerSeed ───────────────────────────────────────────

    #[test]
    fn proposer_seed_hash_id_is_ps() {
        assert_eq!(ProposerSeed::hash_id(), b"PS");
    }

    #[test]
    fn proposer_seed_encoding_field_order() {
        let ps = ProposerSeed {
            addr: Address([0u8; 32]),
            vrf: [0u8; 64],
        };
        let encoded = encode_proposer_seed(&ps);

        // fixmap(2) = 0x82
        assert_eq!(encoded[0], 0x82);

        // Check field order: "addr" before "vrf"
        let encoded_str = String::from_utf8_lossy(&encoded);
        let addr_pos = encoded_str.find("addr").unwrap();
        let vrf_pos = encoded_str.find("vrf").unwrap();
        assert!(addr_pos < vrf_pos, "addr must come before vrf");
    }

    #[test]
    fn proposer_seed_encoding_zero_values() {
        let ps = ProposerSeed {
            addr: Address([0u8; 32]),
            vrf: [0u8; 64],
        };
        let encoded = encode_proposer_seed(&ps);

        let mut expected: Vec<u8> = Vec::new();
        // fixmap(2)
        expected.push(0x82);
        // fixstr("addr")
        expected.extend_from_slice(&[0xa4, b'a', b'd', b'd', b'r']);
        // bin8, length 32, 32 zero bytes
        expected.push(0xc4);
        expected.push(0x20);
        expected.extend_from_slice(&[0u8; 32]);
        // fixstr("vrf")
        expected.extend_from_slice(&[0xa3, b'v', b'r', b'f']);
        // bin8, length 64, 64 zero bytes
        expected.push(0xc4);
        expected.push(0x40);
        expected.extend_from_slice(&[0u8; 64]);

        assert_eq!(encoded, expected);
    }

    // ── SeedInput ──────────────────────────────────────────────

    #[test]
    fn seed_input_hash_id_is_ps() {
        assert_eq!(SeedInput::hash_id(), b"PS");
    }

    #[test]
    fn seed_input_encoding_field_order() {
        let si = SeedInput::default();
        let encoded = encode_seed_input(&si);

        // fixmap(2) = 0x82
        assert_eq!(encoded[0], 0x82);

        // Check field order: "alpha" before "hist"
        let encoded_str = String::from_utf8_lossy(&encoded);
        let alpha_pos = encoded_str.find("alpha").unwrap();
        let hist_pos = encoded_str.find("hist").unwrap();
        assert!(alpha_pos < hist_pos, "alpha must come before hist");
    }

    #[test]
    fn seed_input_encoding_zero_values() {
        let si = SeedInput::default();
        let encoded = encode_seed_input(&si);

        let mut expected: Vec<u8> = Vec::new();
        // fixmap(2)
        expected.push(0x82);
        // fixstr("alpha")
        expected.extend_from_slice(&[0xa5, b'a', b'l', b'p', b'h', b'a']);
        // bin8, length 32, 32 zero bytes
        expected.push(0xc4);
        expected.push(0x20);
        expected.extend_from_slice(&[0u8; 32]);
        // fixstr("hist")
        expected.extend_from_slice(&[0xa4, b'h', b'i', b's', b't']);
        // bin8, length 32, 32 zero bytes
        expected.push(0xc4);
        expected.push(0x20);
        expected.extend_from_slice(&[0u8; 32]);

        assert_eq!(encoded, expected);
    }

    // ── Seed derivation: period 0 ──────────────────────────────

    #[test]
    fn derive_period_zero_deterministic() {
        let addr = Address([1u8; 32]);
        let vrf_output = [2u8; 64];
        let s1 = derive_seed_period_zero(&addr, &vrf_output, None);
        let s2 = derive_seed_period_zero(&addr, &vrf_output, None);
        assert_eq!(s1, s2);
    }

    #[test]
    fn derive_period_zero_different_addr_gives_different_seed() {
        let addr1 = Address([1u8; 32]);
        let addr2 = Address([2u8; 32]);
        let vrf_output = [3u8; 64];
        let s1 = derive_seed_period_zero(&addr1, &vrf_output, None);
        let s2 = derive_seed_period_zero(&addr2, &vrf_output, None);
        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_period_zero_different_vrf_gives_different_seed() {
        let addr = Address([1u8; 32]);
        let vrf1 = [3u8; 64];
        let vrf2 = [4u8; 64];
        let s1 = derive_seed_period_zero(&addr, &vrf1, None);
        let s2 = derive_seed_period_zero(&addr, &vrf2, None);
        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_period_zero_with_history_differs_from_without() {
        let addr = Address([1u8; 32]);
        let vrf_output = [2u8; 64];
        let history = Digest([0xaa; 32]);
        let s_no_hist = derive_seed_period_zero(&addr, &vrf_output, None);
        let s_with_hist = derive_seed_period_zero(&addr, &vrf_output, Some(history));
        assert_ne!(s_no_hist, s_with_hist);
    }

    #[test]
    fn derive_period_zero_known_value() {
        // Verify step-by-step computation matches expected output.
        let addr = Address([0x11; 32]);
        let vrf_output = [0x22; 64];

        // Step 1: alpha = HashObj(ProposerSeed{addr, vrf})
        let ps = ProposerSeed {
            addr,
            vrf: vrf_output,
        };
        let alpha = hash_obj(&ps);

        // Step 2: input = SeedInput{Alpha: alpha, History: zero}
        let input = SeedInput {
            alpha,
            history: Digest([0u8; 32]),
        };

        // Step 3: new_seed = HashObj(input)
        let expected = Seed::from(hash_obj(&input));

        let result = derive_seed_period_zero(&addr, &vrf_output, None);
        assert_eq!(result, expected);
    }

    // ── Seed derivation: period > 0 ────────────────────────────

    #[test]
    fn derive_period_nonzero_deterministic() {
        let prev = Seed([0xbb; 32]);
        let s1 = derive_seed_period_nonzero(&prev, None);
        let s2 = derive_seed_period_nonzero(&prev, None);
        assert_eq!(s1, s2);
    }

    #[test]
    fn derive_period_nonzero_different_prev_gives_different_seed() {
        let prev1 = Seed([0xbb; 32]);
        let prev2 = Seed([0xcc; 32]);
        let s1 = derive_seed_period_nonzero(&prev1, None);
        let s2 = derive_seed_period_nonzero(&prev2, None);
        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_period_nonzero_with_history_differs() {
        let prev = Seed([0xbb; 32]);
        let history = Digest([0xdd; 32]);
        let s1 = derive_seed_period_nonzero(&prev, None);
        let s2 = derive_seed_period_nonzero(&prev, Some(history));
        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_period_nonzero_known_value() {
        // Verify step-by-step computation.
        let prev = Seed([0x33; 32]);

        // Step 1: alpha = HashObj(prevSeed) — HashID="SD", raw bytes
        let alpha = hash_obj(&prev);

        // Step 2: input = SeedInput{Alpha: alpha}
        let input = SeedInput {
            alpha,
            history: Digest([0u8; 32]),
        };

        // Step 3: new_seed = HashObj(input)
        let expected = Seed::from(hash_obj(&input));

        let result = derive_seed_period_nonzero(&prev, None);
        assert_eq!(result, expected);
    }

    #[test]
    fn derive_period_nonzero_differs_from_period_zero() {
        // Even with same "underlying" data, period 0 and period > 0
        // use different alpha computation paths.
        let prev = Seed([0x44; 32]);
        let addr = Address([0x44; 32]);
        let vrf_output = [0x44; 64];

        let s0 = derive_seed_period_zero(&addr, &vrf_output, None);
        let sn = derive_seed_period_nonzero(&prev, None);
        assert_ne!(s0, sn);
    }

    // ── History mixing logic ───────────────────────────────────

    #[test]
    fn history_mix_round_no_mixing() {
        // seed_lookback=2, seed_refresh_interval=80 → cycle=160
        // rnd=5 → rerand = 5 % 160 = 5, 5 >= 2, no mixing
        assert_eq!(history_mix_round(5, 2, 80), None);
    }

    #[test]
    fn history_mix_round_mixing_at_zero() {
        // rnd=160 → rerand = 160 % 160 = 0, 0 < 2, mixing applies
        // digrnd = 160 - 160 = 0
        assert_eq!(history_mix_round(160, 2, 80), Some(0));
    }

    #[test]
    fn history_mix_round_mixing_at_one() {
        // rnd=161 → rerand = 161 % 160 = 1, 1 < 2, mixing applies
        // digrnd = 161 - 160 = 1
        assert_eq!(history_mix_round(161, 2, 80), Some(1));
    }

    #[test]
    fn history_mix_round_no_mixing_at_boundary() {
        // rnd=162 → rerand = 162 % 160 = 2, 2 >= 2, no mixing
        assert_eq!(history_mix_round(162, 2, 80), None);
    }

    #[test]
    fn history_mix_round_saturates_at_zero() {
        // rnd=0 → rerand = 0 % 160 = 0, 0 < 2, mixing applies
        // digrnd = 0.saturating_sub(160) = 0
        assert_eq!(history_mix_round(0, 2, 80), Some(0));
    }

    #[test]
    fn history_mix_round_second_cycle() {
        // rnd=320 → rerand = 320 % 160 = 0, 0 < 2, mixing applies
        // digrnd = 320 - 160 = 160
        assert_eq!(history_mix_round(320, 2, 80), Some(160));
    }

    #[test]
    fn history_mix_round_zero_cycle() {
        // Edge case: zero seed_lookback or seed_refresh_interval
        assert_eq!(history_mix_round(100, 0, 80), None);
        assert_eq!(history_mix_round(100, 2, 0), None);
    }
}
