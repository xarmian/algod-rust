//! Byte-for-byte parity vs go-algorand `crypto/passphrase`.
//!
//! Fixtures were captured against `../go-algorand` pinned to
//! `v4.6.0-stable` by running `passphrase.KeyToMnemonic` over a
//! reproducible mix of seeds (all-zero, all-ones, then SHA-256 of each
//! NATO phonetic-alphabet name). If a future change makes these diverge,
//! the change is a compatibility regression — stop and investigate.

use algo_consensus_crypto::passphrase::{key_to_mnemonic, mnemonic_to_key};

/// `(hex-seed, mnemonic)` pairs captured from go-algorand.
const FIXTURES: &[(&str, &str)] = &[
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo abstract adapt",
    ),
    (
        "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8",
        "impact swap finger repair click guilt lyrics carbon sketch health knee man color dignity guard language fluid kiwi tube theme business silly scissors abstract festival",
    ),
    (
        "f144a6907dc4284d1f9fe6a7d9b9ff53c02c1d07ba68f24d413d7ff7f757a782",
        "owner october sign elephant face spy wedding track crunch trash zone ahead flower shrug south hamster salad ahead pact jewel useful sting benefit above throw",
    ),
    (
        "b9dd960c1753459a78115d3cb845a57d924b6877e805b08bd01086ccdf34433c",
        "rescue fork main cousin melt charge mesh fringe always black sport chief now sure dry album invite drama anchor silent sauce snake tilt ability blue",
    ),
    (
        "4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398",
        "enemy eye marriage that various century hotel reward quote kangaroo evidence still pear royal limb junior liar spirit airport physical nuclear scorpion secret above mimic",
    ),
    (
        "092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d",
        "license tool injury usage present chest foam soon mimic cage keen release soft hello wool belt awesome suspect disease spider route worth tube abandon bind",
    ),
    (
        "9533327a239046b9fb62ee9b412bcd93a098721f6b4f72095b2612e4eedea38e",
        "increase silver rug acquire minor unusual blind unveil cricket public track ankle course syrup flight exhaust comic history basket donkey tape waste insect above move",
    ),
    (
        "625fe74cad4600b5e8b76a9283333eb79052ae50d6af7f660feb4831d87af5d2",
        "unable output please hello above coil satisfy height inch sock pair arena pioneer clog raw quit soup diesel intact behind race gadget nut absorb kitten",
    ),
    (
        "8d53a3e3672946bd802cd2037f1d5da8a61081910cb4054a882b905a51550125",
        "immune minute vault nose middle consider goat split there invest company hedgehog candy gate goose reduce doll cancel beyond poverty pencil fetch chimney ability come",
    ),
];

fn hex_to_seed(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("valid hex");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn encode_matches_go() {
    for (seed_hex, expected) in FIXTURES {
        let seed = hex_to_seed(seed_hex);
        let got = key_to_mnemonic(&seed).expect("encode");
        assert_eq!(
            &got, expected,
            "key_to_mnemonic divergence for seed {seed_hex}"
        );
    }
}

#[test]
fn decode_matches_go() {
    for (seed_hex, mnemonic) in FIXTURES {
        let expected_seed = hex_to_seed(seed_hex);
        let got = mnemonic_to_key(mnemonic).expect("decode");
        assert_eq!(
            got, expected_seed,
            "mnemonic_to_key divergence for {mnemonic}"
        );
    }
}
