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

// Selector struct, matching go-algorand/agreement/selector.go.
//
// A Selector deterministically defines a cryptographic sortition committee.
// It contains the input to the sortition VRF and the size of the committee.

use serde::{Deserialize, Serialize};

use algo_types::{ConsensusParams, Round};

use crate::hashable::Hashable;
use crate::seed::Seed;
use crate::step::{Period, Step};

/// Agreement selector — the input used to define proposers and members of
/// voting committees.
///
/// Mirrors Go's `agreement.selector` struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selector {
    pub seed: Seed,
    pub round: Round,
    pub period: Period,
    pub step: Step,
}

impl Selector {
    /// Returns the committee size for this selector's step.
    ///
    /// Delegates to `Step::committee_size`.
    pub fn committee_size(&self, params: &ConsensusParams) -> u64 {
        self.step.committee_size(params)
    }

    /// Returns the committee threshold for this selector's step.
    ///
    /// Delegates to `Step::committee_threshold`.
    pub fn committee_threshold(&self, params: &ConsensusParams) -> u64 {
        self.step.committee_threshold(params)
    }
}

/// Canonical msgpack encoding of a `Selector`, matching Go's generated
/// `selector.MarshalMsg` in `agreement/msgp_gen.go`.
///
/// Layout (fields sorted alphabetically by codec tag, non-omitempty):
/// ```text
/// fixmap(4)
///   fixstr("per")  -> uint64(period)
///   fixstr("rnd")  -> uint64(round)
///   fixstr("seed") -> bin(seed_bytes)
///   fixstr("step") -> uint64(step)
/// ```
fn encode_selector(sel: &Selector) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // fixmap(4) + fixstr("per")
    buf.extend_from_slice(&[0x84, 0xa3, b'p', b'e', b'r']);
    // uint64(period) — compact encoding
    rmp::encode::write_uint(&mut buf, sel.period.0).unwrap();

    // fixstr("rnd")
    buf.extend_from_slice(&[0xa3, b'r', b'n', b'd']);
    // uint64(round) — compact encoding
    rmp::encode::write_uint(&mut buf, sel.round.0).unwrap();

    // fixstr("seed")
    buf.extend_from_slice(&[0xa4, b's', b'e', b'e', b'd']);
    // bin(seed_bytes) — bin format (with length prefix)
    rmp::encode::write_bin(&mut buf, &sel.seed.0).unwrap();

    // fixstr("step")
    buf.extend_from_slice(&[0xa4, b's', b't', b'e', b'p']);
    // uint64(step) — compact encoding
    rmp::encode::write_uint(&mut buf, sel.step.0).unwrap();

    buf
}

impl Hashable for Selector {
    /// HashID = `"AS"` (protocol.AgreementSelector).
    fn hash_id() -> &'static [u8] {
        b"AS"
    }

    /// Canonical msgpack encoding of the selector.
    fn to_be_hashed(&self) -> Vec<u8> {
        encode_selector(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashable::hash_obj;
    use algo_types::consensus::consensus_params_for_version;

    fn v41_params() -> ConsensusParams {
        consensus_params_for_version(algo_types::CONSENSUS_V41).expect("v41 params must exist")
    }

    #[test]
    fn selector_encoding_field_order() {
        // Verify the encoding starts with fixmap(4) and fields are in
        // alphabetical order: per, rnd, seed, step
        let sel = Selector {
            seed: Seed::default(),
            round: Round(0),
            period: Period(0),
            step: Step(0),
        };
        let encoded = encode_selector(&sel);

        // First byte: fixmap(4) = 0x84
        assert_eq!(encoded[0], 0x84);

        // Find field name positions in the encoded bytes
        let encoded_str = String::from_utf8_lossy(&encoded);
        let per_pos = encoded_str.find("per").unwrap();
        let rnd_pos = encoded_str.find("rnd").unwrap();
        let seed_pos = encoded_str.find("seed").unwrap();
        let step_pos = encoded_str.find("step").unwrap();

        // Fields must appear in alphabetical order
        assert!(per_pos < rnd_pos, "per must come before rnd");
        assert!(rnd_pos < seed_pos, "rnd must come before seed");
        assert!(seed_pos < step_pos, "seed must come before step");
    }

    #[test]
    fn selector_encoding_zero_values() {
        // Selector with all zeros should produce a deterministic encoding
        let sel = Selector {
            seed: Seed::default(),
            round: Round(0),
            period: Period(0),
            step: Step(0),
        };
        let encoded = encode_selector(&sel);

        // Expected:
        // fixmap(4)              = 0x84
        // fixstr("per")          = 0xa3, "per"
        // uint 0                 = 0x00
        // fixstr("rnd")          = 0xa3, "rnd"
        // uint 0                 = 0x00
        // fixstr("seed")         = 0xa4, "seed"
        // bin32([0;32])          = 0xc4, 0x20, [0;32]
        // fixstr("step")         = 0xa4, "step"
        // uint 0                 = 0x00
        let expected: Vec<u8> = vec![
            0x84, // fixmap(4)
            0xa3, b'p', b'e', b'r', // fixstr("per")
            0x00, // uint 0
            0xa3, b'r', b'n', b'd', // fixstr("rnd")
            0x00, // uint 0
            0xa4, b's', b'e', b'e', b'd', // fixstr("seed")
            0xc4, 0x20, // bin8, length 32
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 zero bytes
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 zero bytes
            0xa4, b's', b't', b'e', b'p', // fixstr("step")
            0x00, // uint 0
        ];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn selector_encoding_nonzero_values() {
        let sel = Selector {
            seed: Seed([0xff; 32]),
            round: Round(42),
            period: Period(1),
            step: Step(2),
        };
        let encoded = encode_selector(&sel);

        // Verify it starts correctly
        assert_eq!(encoded[0], 0x84); // fixmap(4)

        // Verify "per" field
        assert_eq!(&encoded[1..5], &[0xa3, b'p', b'e', b'r']);
        // period=1 encoded as positive fixint
        assert_eq!(encoded[5], 0x01);
    }

    #[test]
    fn selector_hash_obj_deterministic() {
        let sel = Selector {
            seed: Seed::default(),
            round: Round(100),
            period: Period(0),
            step: Step(1),
        };
        let d1 = hash_obj(&sel);
        let d2 = hash_obj(&sel);
        assert_eq!(d1, d2);
    }

    #[test]
    fn selector_hash_obj_different_inputs() {
        let sel1 = Selector {
            seed: Seed::default(),
            round: Round(100),
            period: Period(0),
            step: Step(1),
        };
        let sel2 = Selector {
            seed: Seed::default(),
            round: Round(101),
            period: Period(0),
            step: Step(1),
        };
        assert_ne!(hash_obj(&sel1), hash_obj(&sel2));
    }

    #[test]
    fn selector_hash_id_is_as() {
        assert_eq!(Selector::hash_id(), b"AS");
    }

    #[test]
    fn committee_size_delegates_to_step() {
        let p = v41_params();
        let sel = Selector {
            seed: Seed::default(),
            round: Round(100),
            period: Period(0),
            step: Step(1), // soft
        };
        assert_eq!(sel.committee_size(&p), p.soft_committee_size);
    }

    #[test]
    fn committee_threshold_delegates_to_step() {
        let p = v41_params();
        let sel = Selector {
            seed: Seed::default(),
            round: Round(100),
            period: Period(0),
            step: Step(2), // cert
        };
        assert_eq!(sel.committee_threshold(&p), p.cert_committee_threshold);
    }
}
