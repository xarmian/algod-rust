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

//! `data/basics/salted_address_test.go` (go-algorand v5.1.1, issue #2546):
//! the salted-address preimage, the known-answer addresses of the three key
//! schemes and of the `ls` scheme, and `CanonicalAddressSalt`.
//!
//! The expected addresses are the literals of go's own test (go computes them
//! from `crypto.FalconSeed{firstSeedByte}` / `crypto.Seed{firstSeedByte}`).

use algo_types::{canonical_address_salt, salted_address, Address, AddressSalt};
use sha2::{Digest, Sha512_256};

/// go's `publicKeyForSaltedAddressTest`: the seed is `firstSeedByte` followed
/// by zeros.
fn public_key_for(scheme: [u8; 2], first_seed_byte: u8) -> Vec<u8> {
    let mut seed = [0u8; 32];
    seed[0] = first_seed_byte;
    match &scheme {
        b"f1" => algo_falcon::falcon_keygen(&seed).expect("keygen f1").0,
        b"f5" => algo_falcon::falcon512_keygen(&seed).expect("keygen f5").0,
        b"ed" => ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec(),
        _ => panic!("unknown scheme"),
    }
}

/// go's `TestSaltedAddressPreimage`: the hash input is
/// `"PQA" || scheme || salt || pk`.
#[test]
fn salted_address_preimage() {
    for (name, scheme, payload) in [
        ("falcon-1024", *b"f1", [b'f', b'1', 0x7f, 0xab, 0xcd, 0xef]),
        ("falcon-512", *b"f5", [b'f', b'5', 0x7f, 0xab, 0xcd, 0xef]),
        ("ed25519", *b"ed", [b'e', b'd', 0x7f, 0xab, 0xcd, 0xef]),
    ] {
        let mut hasher = Sha512_256::new();
        hasher.update(b"PQA");
        hasher.update(payload);
        let expected = Address(hasher.finalize().into());
        assert_eq!(
            salted_address(scheme, AddressSalt(0x7f), &[0xab, 0xcd, 0xef]),
            expected,
            "{name}"
        );
    }
}

/// go's `TestSaltedAddressKnownAnswers`.
#[test]
fn salted_address_known_answers() {
    // (scheme, case, firstSeedByte, salt, address, offCurve)
    type Answer = ([u8; 2], &'static str, u8, u8, &'static str, bool);
    let answers: &[Answer] = &[
        (
            *b"f1",
            "zero salt",
            3,
            0,
            "KJGJA2DTCQH6LT2I2OH2YO5GIIBFC6JHX5O6UPA5ZZ5ZURFT3LHKMTRCEM",
            true,
        ),
        (
            *b"f1",
            "nonzero salt",
            1,
            1,
            "GYBWVYVQIQF6CO7BUMG4UQ66DQYHASFOCA2P7PBYOIPKGWUZIBX4KA3TP4",
            true,
        ),
        (
            *b"f1",
            "max salt",
            0,
            255,
            "YJFADDEP6Z3WAWY6ZMLN6MF4T4NK3BXKCVLPCYB6C4SQHE76LLQSZ5JG7Q",
            true,
        ),
        (
            *b"f1",
            "different seed",
            2,
            2,
            "II4DO6IIP3EAEQMWJEOLOUU3VBRVCH3WF4MX6UCRUD36DOQJ3YSHA2DV5A",
            true,
        ),
        (
            *b"f1",
            "max seed and salt",
            255,
            255,
            "3JXWI6BYYEO6WO6M7TC4SOZAZUWAD4RQO5GJ2ED6MYIEVVLOVJOETMGG4A",
            true,
        ),
        (
            *b"f1",
            "on-curve address",
            1,
            0,
            "FLX4VRWXQ65HD5G5BI2EPHJWMERHA2EBBQ7XMTZLATXH4XEOWPQSIYVIF4",
            false,
        ),
        (
            *b"f5",
            "zero salt",
            3,
            0,
            "L3E466XEV24FAQ3GYW4NDWNVVQG5SKNW4P7FO7JB72AL35WU4BYIUBWFLQ",
            true,
        ),
        (
            *b"f5",
            "nonzero salt",
            1,
            1,
            "NQHOCVCR45XKZ5LMJSBDWGPZ6QZQIDKQU26KNQ3O4A3EGIRR7BPIX4CW3A",
            true,
        ),
        (
            *b"f5",
            "max salt",
            0,
            255,
            "6SNBFGF6MKPQZMP5QFTXJQVMNB2VYT4DCKVTGH3UN3KDSF3BXSNX75ZTJE",
            true,
        ),
        (
            *b"f5",
            "different seed",
            2,
            2,
            "WZMDFDVTJIFGANZKOIHUDI2TIATEIMGA7RPGAOGURFWOH6KTN3DHTLXCBU",
            false,
        ),
        (
            *b"f5",
            "max seed and salt",
            255,
            255,
            "HIUU22OZWNLI6MBXNQ4DFUUXMG4ASF7CIUIWRLQC4WDTUGNCAXSCRUHUME",
            true,
        ),
        (
            *b"f5",
            "on-curve address",
            1,
            0,
            "AFNGS72MUDN72N5MQREE57URNHIH3MSDZZS42WGNPAXKTC3JZSC22S7CBA",
            false,
        ),
        (
            *b"ed",
            "zero salt",
            3,
            0,
            "BS24KS3PNANVECBJECXBRKSCEYCHY2KUQFAAGX6DR2JMYITDN3W5A3M3M4",
            false,
        ),
        (
            *b"ed",
            "nonzero salt",
            1,
            1,
            "76X26JCOZ6KBTLL4LLIYHBGM5THQPWVNOMRFBVK43MWTWRFBYCLZHACW2M",
            false,
        ),
        (
            *b"ed",
            "max salt",
            0,
            255,
            "RVYDADZDRDSIHWI4R4TTALJPGGBO4ZWGK2R4YTGQGUMKJCVKHQETODHA5Q",
            true,
        ),
        (
            *b"ed",
            "different seed",
            2,
            2,
            "JDIRZBWHK6SDOXKRGSNRCO7I4BF6ACVN4ACPHLNGINQNKFZOMHC2YY5TQM",
            false,
        ),
        (
            *b"ed",
            "max seed and salt",
            255,
            255,
            "XVNRCMCRAYGJ3RUGN57YX2SKDLAJ6DNBO2LE5YLVG4OGQEC6SXMSO7V7EE",
            true,
        ),
        (
            *b"ed",
            "different salt",
            1,
            0,
            "52TWNOHFPAIAQPARIGBF3SXBHZ6NEX6QURSOTXYBUI5JXIO4DEBMZEF5AQ",
            true,
        ),
    ];
    for &(scheme, name, first_seed_byte, salt, expected, off_curve) in answers {
        let pk = public_key_for(scheme, first_seed_byte);
        let addr = salted_address(scheme, AddressSalt(salt), &pk);
        let case = format!("{} {name}", String::from_utf8_lossy(&scheme));
        assert_eq!(addr.to_string(), expected, "{case}");
        assert_eq!(addr.is_off_ed25519_curve(), off_curve, "{case}");
        assert_eq!(
            salted_address(scheme, AddressSalt(salt), &pk),
            addr,
            "{case}"
        );
    }
}

/// go's `TestCanonicalAddressSalt`.
#[test]
fn canonical_address_salt_known_answers() {
    for (scheme, expected_salt, expected_address) in [
        (
            *b"f1",
            1u8,
            "GYBWVYVQIQF6CO7BUMG4UQ66DQYHASFOCA2P7PBYOIPKGWUZIBX4KA3TP4",
        ),
        (
            *b"f5",
            1,
            "NQHOCVCR45XKZ5LMJSBDWGPZ6QZQIDKQU26KNQ3O4A3EGIRR7BPIX4CW3A",
        ),
        (
            *b"ed",
            0,
            "52TWNOHFPAIAQPARIGBF3SXBHZ6NEX6QURSOTXYBUI5JXIO4DEBMZEF5AQ",
        ),
    ] {
        let pk = public_key_for(scheme, 1);
        let (salt, addr) = canonical_address_salt(scheme, &pk).unwrap();
        assert_eq!(salt, AddressSalt(expected_salt));
        assert_eq!(addr.to_string(), expected_address);
        assert!(addr.is_off_ed25519_curve());
        for lower in 0..salt.0 {
            assert!(!salted_address(scheme, AddressSalt(lower), &pk).is_off_ed25519_curve());
        }
    }
}

/// go's `TestLogicSigSaltedAddress`.
#[test]
fn logic_sig_salted_address() {
    let program = [0x02u8, 0x81, 0x01]; // #pragma version 2; int 1
    let (salt, addr) = canonical_address_salt(*b"ls", &program).unwrap();
    assert!(addr.is_off_ed25519_curve());
    assert_eq!(salted_address(*b"ls", salt, &program), addr);
    // The salt is derived from the program alone.
    assert_eq!(
        canonical_address_salt(*b"ls", &program).unwrap(),
        (salt, addr)
    );
    for lower in 0..salt.0 {
        assert!(!salted_address(*b"ls", AddressSalt(lower), &program).is_off_ed25519_curve());
    }
    // The scheme is part of the preimage.
    assert_ne!(salted_address(*b"f1", salt, &program), addr);

    let open_sesame: Vec<u8> = [&[0x0eu8, 0x80, 0x0b][..], b"open sesame", &[0x2d, 0x12]].concat();
    for (name, program, salt, address) in [
        (
            "salt 0",
            vec![0x02u8, 0x81, 0x00],
            0u8,
            "ZTVEN2GVT6W3DYVZT5KO4PSY7AXRSFGUIKLH4YD4KGZTFYKBP2RWDRXDIQ",
        ),
        (
            "salt 1",
            vec![0x02, 0x81, 0x01],
            1,
            "7YFBCWMMRGDBDM6VRV7YSK4TNOJK46BJHT26DKBOQALMSW6LC4PT2JVDRQ",
        ),
        (
            "salt 2",
            open_sesame,
            2,
            "X27OL4EPK5EQO6BAINO3NSJ7IRYP4JL4R4FGEINIABZIVOZBLS2WFHRTTM",
        ),
    ] {
        let (got_salt, got) = canonical_address_salt(*b"ls", &program).unwrap();
        assert_eq!(got_salt, AddressSalt(salt), "{name}");
        assert_eq!(got.to_string(), address, "{name}");
    }
}

/// go's `TestCanonicalAddressSaltDoesNotRequireRegisteredSchemeOrValidatedKey`.
#[test]
fn canonical_address_salt_needs_no_registered_scheme_or_valid_key() {
    let pk = [0xabu8, 0xcd, 0xef];
    let scheme = *b"x1";
    let (salt, addr) = canonical_address_salt(scheme, &pk).unwrap();
    assert_eq!(salted_address(scheme, salt, &pk), addr);
    assert!(addr.is_off_ed25519_curve());
    for lower in 0..salt.0 {
        assert!(!salted_address(scheme, AddressSalt(lower), &pk).is_off_ed25519_curve());
    }
}
