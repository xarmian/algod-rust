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

//! ed25519 malleability-acceptance parity vectors, ported from go-algorand's
//! `crypto/gobatchverifier_test.go` (issue #1136). Every vector here is run
//! through [`super::ed25519_bv_compatible_verify`] -- the SAME function
//! `signature.rs`'s production single-sig/multisig/logicsig/heartbeat verify
//! call sites use -- and its accept/reject result is compared against
//! go-algorand's documented expectation for that exact `(pk, msg, sig)`
//! triple. This is a permanent regression suite: it guards against a future
//! `ed25519-dalek`/`curve25519-dalek` version bump, or an accidental future
//! refactor back to `ed25519_dalek::Verifier::verify()`, silently drifting
//! algod-rust's single-signature malleability-acceptance ruleset away from
//! go-algorand's `crypto_sign_ed25519_bv_compatible_verify_detached`.

use super::ed25519_bv_compatible_verify;

fn pk(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("valid hex");
    bytes.try_into().expect("32-byte public key")
}

fn sig(hex_str: &str) -> [u8; 64] {
    let bytes = hex::decode(hex_str).expect("valid hex");
    bytes.try_into().expect("64-byte signature")
}

fn msg(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str).expect("valid hex")
}

/// Port of go-algorand's `tamingEdDSAsTestVectors`
/// (`crypto/gobatchverifier_test.go`), exercised by
/// `TestBatchVerifierTamingEdDSAsEdgeCases`. These are the 12 edge cases
/// from Appendix C of "Taming the many EdDSAs" (https://eprint.iacr.org/2020/1244),
/// hand-constructed so that cofactored-vs-cofactorless verification,
/// canonical-S enforcement, and non-canonical R/A encoding handling
/// disagree between implementations. `expected_fail` is go-algorand's
/// documented (Algorand-specific) criteria.
struct TamingVector {
    desc: &'static str,
    msg_hex: &'static str,
    pk_hex: &'static str,
    sig_hex: &'static str,
    expected_fail: bool,
}

const TAMING_EDDSAS_VECTORS: &[TamingVector] = &[
    TamingVector {
        desc: "S = 0, small-order A, small-order R",
        msg_hex: "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        pk_hex: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        sig_hex: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
        expected_fail: true,
    },
    TamingVector {
        desc: "0 < S < L, small-order A, mixed-order R",
        msg_hex: "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        pk_hex: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        sig_hex: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        expected_fail: true,
    },
    TamingVector {
        desc: "0 < S < L, mixed-order A, small-order R",
        msg_hex: "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        pk_hex: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        sig_hex: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        expected_fail: false,
    },
    TamingVector {
        desc: "0 < S < L, mixed-order A, mixed-order R",
        msg_hex: "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        pk_hex: "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        sig_hex: "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        expected_fail: false,
    },
    TamingVector {
        desc: "0 < S < L, mixed-order A, mixed-order R, SB != R + hA",
        msg_hex: "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        pk_hex: "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        sig_hex: "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        expected_fail: false,
    },
    TamingVector {
        desc: "0 < S < L, mixed-order A, L-order R, SB != R + hA (\"#5 fails any cofactored verification that pre-reduces scalar 8h\")",
        msg_hex: "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        pk_hex: "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        sig_hex: "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        expected_fail: false,
    },
    TamingVector {
        desc: "S > L, L-order A, L-order R",
        msg_hex: "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        pk_hex: "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        sig_hex: "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        expected_fail: true,
    },
    TamingVector {
        desc: "S >> L, L-order A, L-order R (\"#7 fails bitwise tests that S > L\")",
        msg_hex: "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        pk_hex: "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        sig_hex: "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a4734e74f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c2",
        expected_fail: true,
    },
    TamingVector {
        desc: "0 < S < L, mixed-order A, small-order R (\"#8-9 have non-canonical R; implementations that reduce R before hashing will accept #8 and reject #9, while those that do not will reject #8 and accept #9\")",
        msg_hex: "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        pk_hex: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        sig_hex: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        expected_fail: true,
    },
    TamingVector {
        desc: "0 < S < L, mixed-order A, small-order R (\"#8-9 have non-canonical R; implementations that reduce R before hashing will accept #8 and reject #9, while those that do not will reject #8 and accept #9\")",
        msg_hex: "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        pk_hex: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        sig_hex: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        expected_fail: true,
    },
    TamingVector {
        desc: "0 < S < L, small-order A, mixed-order R (\"#10-11 have a non-canonical A; implementations that reduce A before hashing will accept #10 and reject #11, while those that do not will reject #10 and accept #11\")",
        msg_hex: "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        pk_hex: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        sig_hex: "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        expected_fail: true,
    },
    TamingVector {
        desc: "0 < S < L, small-order A, mixed-order R (\"#10-11 have a non-canonical A; implementations that reduce A before hashing will accept #10 and reject #11, while those that do not will reject #10 and accept #11\")",
        msg_hex: "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
        pk_hex: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        sig_hex: "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        expected_fail: true,
    },
];

#[test]
fn taming_eddsas_edge_cases() {
    for tv in TAMING_EDDSAS_VECTORS {
        let accepted =
            ed25519_bv_compatible_verify(&pk(tv.pk_hex), &msg(tv.msg_hex), &sig(tv.sig_hex));
        assert_eq!(
            accepted, !tv.expected_fail,
            "vector {:?}: expected accept={}, got accept={}",
            tv.desc, !tv.expected_fail, accepted
        );
    }
}

/// Port of go-algorand's `ed25519consensusCases`
/// (`crypto/gobatchverifier_test.go`), exercised by
/// `TestBatchVerifierEd25519ConsensusTestData`: the 14x14 = 196 (pk, sig)
/// combinations from the "It's 255:19AM" ZIP-215 blog post
/// (https://hdevalence.ca/blog/2020-10-04-its-25519am), used to build the
/// post's 14x14 visualization of accept/reject criteria across
/// implementations. Every one of these 196 combinations is expected to be
/// REJECTED under go-algorand's strict criteria (all constructed from
/// small-order/non-canonical building blocks) with the fixed message
/// b"Zcash" (0x5a63617368) used for every signature in this test.
const ED25519_CONSENSUS_PKS: &[&str] = &[
    "0100000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

const ED25519_CONSENSUS_SIGS: &[&str] = &[
    "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc050000000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc850000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa0000000000000000000000000000000000000000000000000000000000000000",
    "01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
];

#[test]
fn ed25519_consensus_test_data_all_reject() {
    const MSG_HEX: &str = "5a63617368"; // b"Zcash"
    let message = msg(MSG_HEX);
    for pk_hex in ED25519_CONSENSUS_PKS {
        for sig_hex in ED25519_CONSENSUS_SIGS {
            let accepted = ed25519_bv_compatible_verify(&pk(pk_hex), &message, &sig(sig_hex));
            assert!(
                !accepted,
                "pk={pk_hex} sig={sig_hex}: expected reject under go-algorand's strict criteria, but bv_compatible verify accepted it"
            );
        }
    }
}

/// Representative subset of go-algorand's `TestBatchVerifierFilippoVectors`
/// (`crypto/testdata/ed25519vectors.json.gz`, based on filippo.io's
/// `mostly-harmless/ed25519vectors`, in turn based on `TestEd25519Vectors`
/// from `go/src/crypto/ed25519/ed25519vectors_test.go`): one vector per
/// distinct `Flags` combination present in the full 768-vector corpus (54
/// distinct combinations), covering every LowOrderA/LowOrderR/
/// LowOrderComponentA/LowOrderComponentR/LowOrderResidue/NonCanonicalA/
/// NonCanonicalR flag combination that corpus exercises.
/// `expected_fail` mirrors go's test logic exactly: reject iff `LowOrderA`,
/// `NonCanonicalA`, or `NonCanonicalR` is present (the other flags --
/// LowOrderR, LowOrderComponentA/R, LowOrderResidue -- describe properties
/// go-algorand's bv_compatible criteria explicitly ALLOWS).
struct FilippoVector {
    flags: &'static [&'static str],
    pk_hex: &'static str,
    sig_hex: &'static str,
    msg_hex: &'static str,
    expected_fail: bool,
}

const FILIPPO_VECTORS: &[FilippoVector] = &[
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "LowOrderR", "LowOrderResidue"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f323535",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "LowOrderR"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f323535203134",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "LowOrderResidue"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56b05ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f3235352032",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56b05ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f3235352035",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderComponentR", "LowOrderR", "LowOrderResidue"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "000000000000000000000000000000000000000000000000000000000000000037277d9335d380291ae2006fd4a07ba4ad582cb8d15e1f6ba48989cff3cca805",
        msg_hex: "7573652072697374726574746f3235352032",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderComponentR", "LowOrderR"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "0000000000000000000000000000000000000000000000000000000000000000bf189c9ab4c04e8cc8d1460102a9aa7d8c4fcd20a8acd085289774c218f93103",
        msg_hex: "7573652072697374726574746f3235352035",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderComponentR", "LowOrderResidue"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56bf46326ed9059dbe9d56b405e4f0474120d279ef694a23727ad207a27ae80f80b",
        msg_hex: "7573652072697374726574746f3235352032",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderComponentR"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56b0f472298eb30eee3b820b5b7890b34c2e989090d8a7a75a1e98a5603f348c405",
        msg_hex: "7573652072697374726574746f3235352033",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "LowOrderR", "LowOrderResidue", "NonCanonicalA"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352034",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "LowOrderR", "NonCanonicalA"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352031",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "LowOrderResidue", "NonCanonicalA"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56b05ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f3235352032",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "NonCanonicalA"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56b05ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f3235352037",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "LowOrderR", "LowOrderResidue", "NonCanonicalR"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352034",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "LowOrderR", "NonCanonicalR"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352035",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderComponentR", "LowOrderR", "LowOrderResidue", "NonCanonicalR"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f3b783f06abcd1e468359e1b95fe503d11c5d76b25a65906e76f39ae7a09d8e0f",
        msg_hex: "7573652072697374726574746f3235352035",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderComponentR", "LowOrderR", "NonCanonicalR"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fa442b812628d6f13163deb30f1e2fa9668b96d9f4e70e03fe65ff1b981c80b0b",
        msg_hex: "7573652072697374726574746f3235352032",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "LowOrderR", "LowOrderResidue", "NonCanonicalA", "NonCanonicalR"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352039",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderComponentR", "LowOrderR", "NonCanonicalA", "NonCanonicalR"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352031",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderR"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f323535203130",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderR", "LowOrderResidue"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352039",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a350605ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f3235352031",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderResidue"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a350605ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f323535203136",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderR"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "010000000000000000000000000000000000000000000000000000000000000007d6ac846ac7eb9a448d3f10e52fc4e3d2e74f415133c9a2789a6e041d78240b",
        msg_hex: "7573652072697374726574746f3235352035",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderR", "LowOrderResidue"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "0100000000000000000000000000000000000000000000000000000000000000413e3b2241c54d7f8a7d8d69a2148931ba0d9f45ab2dbe59ee6adb3ba737c609",
        msg_hex: "7573652072697374726574746f323535203135",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderComponentA"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a3506c71981ccb483f28da111b0190352746e022db9c9afb4b0816d2961ec75475802",
        msg_hex: "7573652072697374726574746f323535203238",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderResidue"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a35063e3f17582928fdeaf7749f91e0fe9cc5235651dba7954469815347e695be3b00",
        msg_hex: "7573652072697374726574746f3235352033",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderR", "NonCanonicalA"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352035",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderR", "LowOrderResidue", "NonCanonicalA"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352034",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "NonCanonicalA"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a350605ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f323535203231",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderResidue", "NonCanonicalA"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a350605ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f3235352039",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderR", "NonCanonicalR"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f323535",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderR", "LowOrderResidue", "NonCanonicalR"],
        pk_hex: "0000000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352035",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderR", "NonCanonicalR"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "010000000000000000000000000000000000000000000000000000000000008051bdbb2e023a8f2a6ae3edcd3a204ce99e8630583ddb8ea23ec61c9deac32208",
        msg_hex: "7573652072697374726574746f323535203133",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderComponentA", "LowOrderR", "LowOrderResidue", "NonCanonicalR"],
        pk_hex: "10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f",
        sig_hex: "0100000000000000000000000000000000000000000000000000000000000080f28a6f6e60f223b04abf911f7abd4736341e8900328a770dee1180cf00f27b07",
        msg_hex: "7573652072697374726574746f323535",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderR", "NonCanonicalA", "NonCanonicalR"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f323535203132",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentA", "LowOrderR", "LowOrderResidue", "NonCanonicalA", "NonCanonicalR"],
        pk_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352035",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentR", "LowOrderR", "LowOrderResidue"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352031",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentR", "LowOrderResidue"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56b05ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f323535203330",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderComponentR", "LowOrderR", "LowOrderResidue"],
        pk_hex: "ef75b20e7540e3dff77404193652ba2bd13df99c1508eee1515e27ae25f28076",
        sig_hex: "00000000000000000000000000000000000000000000000000000000000000004092d2f6deebc4a04b7c2cf989ca624d77c3512692a818650ab1093145a0d20a",
        msg_hex: "7573652072697374726574746f3235352033",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderComponentR", "LowOrderResidue"],
        pk_hex: "ef75b20e7540e3dff77404193652ba2bd13df99c1508eee1515e27ae25f28076",
        sig_hex: "36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56bbd2406f459f828a042c5832972f189f9223c17eb6c75cdce86a162e5efb1240a",
        msg_hex: "7573652072697374726574746f3235352034",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentR", "LowOrderR", "LowOrderResidue", "NonCanonicalA"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000080",
        sig_hex: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352032",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentR", "LowOrderResidue", "NonCanonicalA"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000080",
        sig_hex: "36684ea91032ba5b1dbab2d02f4debc74c3327f2b3802e2e4d371aa42b12b56b05ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f323535",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentR", "LowOrderR", "LowOrderResidue", "NonCanonicalR"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f323535",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderComponentR", "LowOrderR", "LowOrderResidue", "NonCanonicalR"],
        pk_hex: "ef75b20e7540e3dff77404193652ba2bd13df99c1508eee1515e27ae25f28076",
        sig_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f560a20326dc24df68d6f24c2906958cf9fe96ed0fadf921497354d0176239206",
        msg_hex: "7573652072697374726574746f3235352036",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderComponentR", "LowOrderR", "LowOrderResidue", "NonCanonicalA", "NonCanonicalR"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000080",
        sig_hex: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352031",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderR"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f323535203330",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a350605ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f3235352034",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderR"],
        pk_hex: "ef75b20e7540e3dff77404193652ba2bd13df99c1508eee1515e27ae25f28076",
        sig_hex: "0100000000000000000000000000000000000000000000000000000000000000243f9957780c6701deb70384a9846ba548b8cd3147251baf356e878424465f00",
        msg_hex: "7573652072697374726574746f323535203235",
        expected_fail: false,
    },
    FilippoVector {
        flags: &[],
        pk_hex: "ef75b20e7540e3dff77404193652ba2bd13df99c1508eee1515e27ae25f28076",
        sig_hex: "b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a3506e765a9b6f121a36646a202ee936550996384c27bf0a6661aed1410a04a657501",
        msg_hex: "7573652072697374726574746f3235352032",
        expected_fail: false,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderR", "NonCanonicalA"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000080",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352032",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "NonCanonicalA"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000080",
        sig_hex: "b62cf890de42c413b11b1411c9f01f1c4d77aa87ef182258d1251f69af2a350605ba9a796274d80437afa36f1236563f2f3b0aa84cecddc3d20914615ba4fe02",
        msg_hex: "7573652072697374726574746f3235352033",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderR", "NonCanonicalR"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000000",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f323535203130",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderR", "NonCanonicalR"],
        pk_hex: "ef75b20e7540e3dff77404193652ba2bd13df99c1508eee1515e27ae25f28076",
        sig_hex: "0100000000000000000000000000000000000000000000000000000000000080ec5acaa3711508388c273078fef0efd7a70a54c404587d95aabf56f7ac612300",
        msg_hex: "7573652072697374726574746f323535203339",
        expected_fail: true,
    },
    FilippoVector {
        flags: &["LowOrderA", "LowOrderR", "NonCanonicalA", "NonCanonicalR"],
        pk_hex: "0100000000000000000000000000000000000000000000000000000000000080",
        sig_hex: "01000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
        msg_hex: "7573652072697374726574746f3235352036",
        expected_fail: true,
    },
];

#[test]
fn filippo_vectors_representative_subset() {
    for fv in FILIPPO_VECTORS {
        let accepted =
            ed25519_bv_compatible_verify(&pk(fv.pk_hex), &msg(fv.msg_hex), &sig(fv.sig_hex));
        assert_eq!(
            accepted, !fv.expected_fail,
            "vector flags={:?}: expected accept={}, got accept={}",
            fv.flags, !fv.expected_fail, accepted
        );
    }
}

/// Sanity subset (first 10 of 1025) of go-algorand's libsodium/ed25519-donna
/// batch-verification test vectors introduced in PR #3031
/// (`crypto/libsodium-fork/test/default/batch.c`), exercised by
/// `TestBatchVerifierLibsodiumTestData`. These are ordinary, validly-signed
/// (pk, msg, sig) triples with growing message sizes -- unlike the edge-case
/// suites above, every one of these MUST be accepted; this is a basic
/// correctness sanity check that the bv_compatible reimplementation didn't
/// break ordinary signature verification while adding the stricter
/// small-order-A / non-canonical-encoding / cofactored-equation handling.
struct LibsodiumVector {
    pk_hex: &'static str,
    sig_hex: &'static str,
    msg_hex: &'static str,
}

const LIBSODIUM_SANITY_VECTORS: &[LibsodiumVector] = &[
    LibsodiumVector {
        pk_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        sig_hex: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        msg_hex: "",
    },
    LibsodiumVector {
        pk_hex: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        sig_hex: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        msg_hex: "72",
    },
    LibsodiumVector {
        pk_hex: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        sig_hex: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        msg_hex: "af82",
    },
    LibsodiumVector {
        pk_hex: "e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057",
        sig_hex: "d9868d52c2bebce5f3fa5a79891970f309cb6591e3e1702a70276fa97c24b3a8e58606c38c9758529da50ee31b8219cba45271c689afa60b0ea26c99db19b00c",
        msg_hex: "cbc77b",
    },
    LibsodiumVector {
        pk_hex: "c0dac102c4533186e25dc43128472353eaabdb878b152aeb8e001f92d90233a7",
        sig_hex: "124f6fc6b0d100842769e71bd530664d888df8507df6c56dedfdb509aeb93416e26b918d38aa06305df3095697c18b2aa832eaa52edc0ae49fbae5a85e150c07",
        msg_hex: "5f4c8989",
    },
    LibsodiumVector {
        pk_hex: "e253af0766804b869bb1595be9765b534886bbaab8305bf50dbc7f899bfb5f01",
        sig_hex: "b2fc46ad47af464478c199e1f8be169f1be6327c7f9a0a6689371ca94caf04064a01b22aff1520abd58951341603faed768cf78ce97ae7b038abfe456aa17c09",
        msg_hex: "18b6bec097",
    },
    LibsodiumVector {
        pk_hex: "fbcfbfa40505d7f2be444a33d185cc54e16d615260e1640b2b5087b83ee3643d",
        sig_hex: "6ed629fc1d9ce9e1468755ff636d5a3f40a5d9c91afd93b79d241830f7e5fa29854b8f20cc6eecbb248dbd8d16d14e99752194e4904d09c74d639518839d2300",
        msg_hex: "89010d855972",
    },
    LibsodiumVector {
        pk_hex: "98a5e3a36e67aaba89888bf093de1ad963e774013b3902bfab356d8b90178a63",
        sig_hex: "6e0af2fe55ae377a6b7a7278edfb419bd321e06d0df5e27037db8812e7e3529810fa5552f6c0020985ca17a0e02e036d7b222a24f99b77b75fdd16cb05568107",
        msg_hex: "b4a8f381e70e7a",
    },
    LibsodiumVector {
        pk_hex: "f81fb54a825fced95eb033afcd64314075abfb0abd20a970892503436f34b863",
        sig_hex: "d6addec5afb0528ac17bb178d3e7f2887f9adbb1ad16e110545ef3bc57f9de2314a5c8388f723b8907be0f3ac90c6259bbe885ecc17645df3db7d488f805fa08",
        msg_hex: "4284abc51bb67235",
    },
    LibsodiumVector {
        pk_hex: "c1a49c66e617f9ef5ec66bc4c6564ca33de2a5fb5e1464062e6d6c6219155efd",
        sig_hex: "2c76a04af2391c147082e33faacdbe56642a1e134bd388620b852b901a6bc16ff6c9cc9404c41dea12ed281da067a1513866f9d964f8bdd24953856c50042901",
        msg_hex: "672bf8965d04bc5146",
    },
];

#[test]
fn libsodium_test_data_sanity_subset_all_accept() {
    for lv in LIBSODIUM_SANITY_VECTORS {
        let accepted =
            ed25519_bv_compatible_verify(&pk(lv.pk_hex), &msg(lv.msg_hex), &sig(lv.sig_hex));
        assert!(
            accepted,
            "pk={} sig={}: ordinary valid signature was rejected",
            lv.pk_hex, lv.sig_hex
        );
    }
}

/// Concrete proof of the divergence documented in `signature.rs`'s module
/// doc comment (issue #1136): `ed25519_dalek::Verifier::verify()`'s default
/// (cofactorless) ruleset disagrees with [`ed25519_bv_compatible_verify`]
/// (and therefore with go-algorand's `ed25519Verify`) on the exact same
/// `(pk, msg, sig)` triples from [`TAMING_EDDSAS_VECTORS`]. This is
/// deliberately NOT part of the production verify path -- it exists solely
/// to pin the reason the custom `bv_compatible` reimplementation exists, so
/// a future reader (or a future refactor attempt) can see the divergence
/// reproduced directly rather than having to trust the doc comment's prose.
///
/// Vectors #5 and #6 (0-indexed #4 and #5) are explicitly constructed (per
/// go-algorand's own vector descriptions) so `S*B != R + h*A` exactly, yet
/// go-algorand's cofactored criteria ACCEPTS them (the small-order torsion
/// in `R`/`A` cancels out under cofactor multiplication) --
/// `ed25519_dalek::verify()`'s cofactorless equation REJECTS both of them.
/// (Vectors #3-#4, 0-indexed #2-#3, are also cofactored-accept vectors, but
/// their descriptions don't guarantee `S*B != R + h*A`, and empirically at
/// least one of them still happens to satisfy the cofactorless equation --
/// so only the two vectors with the explicit "SB != R + hA" marker are used
/// here as guaranteed divergence witnesses.)
#[test]
fn dalek_default_verify_diverges_from_bv_compatible_on_cofactored_vectors() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let cofactored_accept_indices = [4usize, 5];
    for &i in &cofactored_accept_indices {
        let tv = &TAMING_EDDSAS_VECTORS[i];
        assert!(
            !tv.expected_fail,
            "test setup error: vector {:?} is not one of go's cofactored-accept vectors",
            tv.desc
        );

        // Our bv_compatible reimplementation agrees with go: accepts.
        assert!(
            ed25519_bv_compatible_verify(&pk(tv.pk_hex), &msg(tv.msg_hex), &sig(tv.sig_hex)),
            "vector {:?}: bv_compatible verify should accept (matches go-algorand)",
            tv.desc
        );

        // Plain ed25519_dalek::Verifier::verify() -- the crate default this
        // module used BEFORE issue #1136's fix -- disagrees: it rejects.
        let vk = VerifyingKey::from_bytes(&pk(tv.pk_hex)).expect("valid ZIP-215 point");
        let signature = Signature::from_bytes(&sig(tv.sig_hex));
        assert!(
            vk.verify(&msg(tv.msg_hex), &signature).is_err(),
            "vector {:?}: expected ed25519_dalek::verify() to REJECT (proving the divergence \
             this module's custom bv_compatible verify exists to close) but it accepted",
            tv.desc
        );
    }
}
