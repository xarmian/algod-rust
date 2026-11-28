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

//! Ports of go-algorand v5.1.1-stable's `cmd/algokey/salted_test.go` and
//! `msgp_gen_test.go` (`saltedPublicMaterial`/`saltedSigningMaterial`). Each
//! test carries the go test's name in its doc comment; the byte-for-byte and
//! error-text comparison against go is `oracle_tests.rs`.

use std::path::Path;

use algo_codec::canonical_encode_signed_transaction;
use algo_types::consensus::{consensus_params_for_version, CONSENSUS_FUTURE};
use algo_types::{
    Address, AddressSalt, LogicSig, SKsigDelegatedProgram, SignedTransaction, Transaction, TxnType,
    SIG_SCHEME_ED25519, SIG_SCHEME_FALCON1024, SIG_SCHEME_FALCON512,
};
use algo_validate::signature::{verify_pqsig, verify_transaction_signature};
use clap::{CommandFactory, Parser};
use sha2::{Digest, Sha512_256};

use super::check_address::run_salted_check_address;
use super::context::resolve_salted_signing_context;
use super::import::run_salted_import_with_options;
use super::key::{
    decode_salted_private_key_file_bytes, decode_salted_public_material,
    encode_salted_public_material_bytes, encode_salted_signing_material,
    read_salted_signing_material, write_salted_private_key_file, SaltedPublicMaterial,
    SaltedSigningMaterial,
};
use super::scheme::{
    derive_salted_signing_material_from_entropy, derive_sig_scheme_key_seed, format_sig_scheme,
    generate_salted_signing_material_with, ops_for, parse_sig_scheme, REGISTERED_SCHEMES,
};
use super::sign::{run_salted_sign_with_options, SaltedSignOptions};
use super::sign_program::{run_salted_sign_program_with_options, SaltedSignProgramOptions};
use super::{
    print_salted_mnemonic, ERR_SALTED_KEY_MALFORMED, ERR_SALT_ON_CURVE, ERR_SCHEME_REQUIRED,
    ERR_SCHEME_WITH_KEYFILE, ERR_SIG_SCHEME_NOT_SUPPORTED, ERR_TXN_ALREADY_SIGNED,
};
use crate::cli::{Cli, Command, SaltedSub};

fn mnemonic_of(entropy: &[u8; 32]) -> String {
    algo_consensus_crypto::key_to_mnemonic(entropy).unwrap()
}

fn salted_test_signing(first_entropy_byte: u8) -> SaltedSigningMaterial {
    let mut entropy = [0u8; 32];
    entropy[0] = first_entropy_byte;
    derive_salted_signing_material_from_entropy(SIG_SCHEME_FALCON1024, &entropy).unwrap()
}

fn salted_test_txn(sender: Address) -> SignedTransaction {
    SignedTransaction {
        txn: Transaction {
            txn_type: TxnType::Pay,
            sender,
            receiver: sender,
            ..Transaction::default()
        },
        ..SignedTransaction::default()
    }
}

fn on_curve_salted_public(public: &SaltedPublicMaterial) -> SaltedPublicMaterial {
    for i in 0..=255u8 {
        let mut candidate = public.clone();
        candidate.salt = AddressSalt(i);
        if !candidate.address().is_off_ed25519_curve() {
            return candidate;
        }
    }
    panic!("expected at least one address salt that puts the address on the Ed25519 curve");
}

fn write_txn(path: &Path, stxn: &SignedTransaction) {
    std::fs::write(path, canonical_encode_signed_transaction(stxn)).unwrap();
}

fn sign_options(txfile: &Path, outfile: &Path) -> SaltedSignOptions {
    SaltedSignOptions {
        txfile: txfile.to_path_buf(),
        outfile: outfile.to_path_buf(),
        ..SaltedSignOptions::default()
    }
}

fn decode_signed(path: &Path) -> SignedTransaction {
    let data = std::fs::read(path).unwrap();
    let (stxn, used) = super::sign::decode_signed_txn_like_go(&data).unwrap();
    assert_eq!(used, data.len());
    stxn
}

fn future() -> algo_types::consensus::ConsensusParams {
    consensus_params_for_version(CONSENSUS_FUTURE).expect("future")
}

fn verify_txn(stxn: &SignedTransaction) -> Result<(), String> {
    let sksig = stxn.pqsig.clone().expect("SKsig");
    verify_pqsig(stxn, &sksig, &future()).map_err(|e| e.to_string())
}

/// go `TestMarshalUnmarshalsaltedPublicMaterial` and
/// `TestRandomizedEncodingsaltedPublicMaterial`.
#[test]
fn marshal_unmarshal_salted_public_material() {
    use rand::Rng;
    let mut rng = rand::rng();
    for _ in 0..100 {
        let mut public_key = vec![0u8; (rng.next_u32() % 64) as usize];
        rng.fill_bytes(&mut public_key);
        let mut scheme = [0u8; 2];
        rng.fill_bytes(&mut scheme);
        let p = SaltedPublicMaterial {
            scheme,
            salt: AddressSalt((rng.next_u32() & 0xff) as u8),
            public_key,
        };
        let bytes = encode_salted_public_material_bytes(&p);
        assert_eq!(decode_salted_public_material(&bytes).unwrap(), p);
        // Re-encoding the decoded value gives the same bytes.
        assert_eq!(encode_salted_public_material_bytes(&p), bytes);
    }
    let zero = SaltedPublicMaterial::default();
    let bytes = encode_salted_public_material_bytes(&zero);
    assert_eq!(decode_salted_public_material(&bytes).unwrap(), zero);
}

/// go `TestMarshalUnmarshalsaltedSigningMaterial` and
/// `TestRandomizedEncodingsaltedSigningMaterial`.
#[test]
fn marshal_unmarshal_salted_signing_material() {
    use rand::Rng;
    let mut rng = rand::rng();
    for _ in 0..100 {
        let mut public_key = vec![0u8; (rng.next_u32() % 64) as usize];
        rng.fill_bytes(&mut public_key);
        let mut private_key = vec![0u8; (rng.next_u32() % 64) as usize];
        rng.fill_bytes(&mut private_key);
        let mut scheme = [0u8; 2];
        rng.fill_bytes(&mut scheme);
        let m = SaltedSigningMaterial {
            public: SaltedPublicMaterial {
                scheme,
                salt: AddressSalt((rng.next_u32() & 0xff) as u8),
                public_key,
            },
            private_key,
        };
        let bytes = encode_salted_signing_material(&m);
        let decoded = super::key::decode_salted_signing_material(&bytes).unwrap();
        assert_eq!(decoded, m);
        assert_eq!(encode_salted_signing_material(&decoded), bytes);
    }
    let zero = SaltedSigningMaterial::default();
    let bytes = encode_salted_signing_material(&zero);
    assert_eq!(
        super::key::decode_salted_signing_material(&bytes).unwrap(),
        zero
    );
}

/// go `TestSaltedKeySeedDerivationUsesDomainSchemeAndEntropy`.
#[test]
fn salted_key_seed_derivation_uses_domain_scheme_and_entropy() {
    let mut entropy = [0u8; 32];
    for (i, b) in entropy.iter_mut().enumerate() {
        *b = i as u8;
    }
    let seed = derive_sig_scheme_key_seed(SIG_SCHEME_FALCON1024, &entropy);

    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"PQK");
    preimage.extend_from_slice(&SIG_SCHEME_FALCON1024);
    preimage.extend_from_slice(&entropy);
    let expected: [u8; 32] = Sha512_256::digest(&preimage).into();
    assert_eq!(seed, expected);

    let other_scheme_seed = derive_sig_scheme_key_seed(SIG_SCHEME_FALCON512, &entropy);
    assert_ne!(seed, other_scheme_seed);
}

/// go `TestSaltedGenerateUsesMnemonicSizedEntropy`: known answers pin the
/// entropy -> seed -> key -> salt derivation (a change would break existing
/// mnemonic imports), and each key is rederived straight from the scheme's
/// keygen seed.
#[test]
fn salted_generate_uses_mnemonic_sized_entropy() {
    type Rederive = fn(&[u8; 32]) -> (Vec<u8>, Vec<u8>);
    let cases: [(&str, [u8; 2], &str, Rederive); 3] = [
        (
            "falcon-1024",
            SIG_SCHEME_FALCON1024,
            "ZEJ4BLG3XWAUUZQGCEDJLYIC6D2NCWHRSX5DJMDPE54PXXR7G3PCQTARXU",
            |seed| algo_falcon::falcon_keygen(seed).unwrap(),
        ),
        (
            "falcon-512",
            SIG_SCHEME_FALCON512,
            "6XJVA45MCHLBBACBGN6ENAXFBDXCEYE5QIWA4R4LO5EY3UNAIP2UGP7ANI",
            |seed| algo_falcon::falcon512_keygen(seed).unwrap(),
        ),
        (
            "ed25519",
            SIG_SCHEME_ED25519,
            "K7CZGXXPN6X2OXEU72FOATH333H3MR4QFSIX462VVVO7FIVTH43XHMH2G4",
            |seed| {
                let sk = ed25519_dalek::SigningKey::from_bytes(seed);
                let pk = sk.verifying_key().to_bytes();
                let mut private = seed.to_vec();
                private.extend_from_slice(&pk);
                (pk.to_vec(), private)
            },
        ),
    ];
    for (name, scheme, address, rederive) in cases {
        let mut calls = 0usize;
        let mut filled = 0usize;
        let (entropy, signing) = generate_salted_signing_material_with(scheme, |buf| {
            calls += 1;
            filled += buf.len();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i + 1) as u8;
            }
        })
        .unwrap();
        assert_eq!(calls, 1, "{name}");
        assert_eq!(filled, 32, "{name}");
        assert_eq!(signing.public.scheme, scheme, "{name}");
        let want: Vec<u8> = (1..=32).collect();
        assert_eq!(entropy.to_vec(), want, "{name}");
        assert!(signing.public.address().is_off_ed25519_curve(), "{name}");
        assert_eq!(signing.public.address().to_string(), address, "{name}");

        let seed = derive_sig_scheme_key_seed(scheme, &entropy);
        let (public_key, private_key) = rederive(&seed);
        assert_eq!(public_key, signing.public.public_key, "{name}");
        assert_eq!(private_key, signing.private_key, "{name}");
    }
}

/// go `TestSigSchemeRegistriesConsistent`.
#[test]
fn sig_scheme_registries_consistent() {
    let future = future();
    for scheme in REGISTERED_SCHEMES {
        assert!(
            future.sig_scheme_enabled(scheme),
            "algokey scheme {:?} missing from the transactions scheme table",
            String::from_utf8_lossy(&scheme)
        );
    }
    for scheme in [
        SIG_SCHEME_FALCON1024,
        SIG_SCHEME_FALCON512,
        SIG_SCHEME_ED25519,
    ] {
        assert!(
            ops_for(scheme).is_some(),
            "basics scheme {:?} missing from algokey ops registry",
            String::from_utf8_lossy(&scheme)
        );
    }
}

/// go `TestSigSchemeKeySizes`.
#[test]
fn sig_scheme_key_sizes() {
    for scheme in REGISTERED_SCHEMES {
        let ops = ops_for(scheme).unwrap();
        let signing = ops.derive_signing([0u8; 32]).unwrap();
        assert_eq!(ops.public_key_size(), signing.public.public_key.len());
        assert_eq!(ops.private_key_size(), signing.private_key.len());
    }
}

/// go `TestParseSigSchemeAcceptsLongName`.
#[test]
fn parse_sig_scheme_accepts_long_name() {
    for (value, want) in [
        ("falcon-1024", SIG_SCHEME_FALCON1024),
        ("f1", SIG_SCHEME_FALCON1024),
        ("falcon-512", SIG_SCHEME_FALCON512),
        ("f5", SIG_SCHEME_FALCON512),
        ("ed25519", SIG_SCHEME_ED25519),
        ("ed", SIG_SCHEME_ED25519),
    ] {
        assert_eq!(parse_sig_scheme(value).unwrap(), want, "{value}");
    }
}

/// go `TestFormatSigScheme`.
#[test]
fn format_sig_scheme_names_the_registered_schemes() {
    assert_eq!(format_sig_scheme(&SIG_SCHEME_FALCON1024), "falcon-1024");
    assert_eq!(format_sig_scheme(&SIG_SCHEME_FALCON512), "falcon-512");
    assert_eq!(format_sig_scheme(&SIG_SCHEME_ED25519), "ed25519");
    assert_eq!(format_sig_scheme(b"zz"), "zz");
}

/// go `TestSaltedPrivateKeyFileStoresKeysNotEntropy`.
#[test]
fn salted_private_key_file_stores_keys_not_entropy() {
    let mut entropy = [0u8; 32];
    for (i, b) in entropy.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    let signing =
        derive_salted_signing_material_from_entropy(SIG_SCHEME_FALCON1024, &entropy).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.pq");

    write_salted_private_key_file(&keyfile, &signing).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&keyfile).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // The file holds the scheme's keys: never the mnemonic entropy or the
    // derived keygen seed, which would compromise keys of other schemes.
    let data = std::fs::read(&keyfile).unwrap();
    let contains = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);
    assert!(!contains(&entropy));
    assert!(!contains(&derive_sig_scheme_key_seed(
        SIG_SCHEME_FALCON1024,
        &entropy
    )));

    assert_eq!(read_salted_signing_material(&keyfile).unwrap(), signing);
}

/// go `TestSaltedKeyFileRejectsMalformedInputs`.
#[test]
fn salted_key_file_rejects_malformed_inputs() {
    let signing = salted_test_signing(0);

    let err = decode_salted_private_key_file_bytes(&[0u8; 32]).unwrap_err();
    assert!(err.contains(ERR_SALTED_KEY_MALFORMED), "{err}");

    let mut bad_scheme = signing.clone();
    bad_scheme.public.scheme = *b"zz";
    let err = decode_salted_private_key_file_bytes(&encode_salted_signing_material(&bad_scheme))
        .unwrap_err();
    assert!(err.contains(ERR_SIG_SCHEME_NOT_SUPPORTED), "{err}");

    let mut bad_key = signing.clone();
    bad_key.public.public_key.pop();
    let err = decode_salted_private_key_file_bytes(&encode_salted_signing_material(&bad_key))
        .unwrap_err();
    assert!(err.contains(ERR_SALTED_KEY_MALFORMED), "{err}");

    let mut bad_sk = signing.clone();
    bad_sk.private_key.pop();
    let err =
        decode_salted_private_key_file_bytes(&encode_salted_signing_material(&bad_sk)).unwrap_err();
    assert!(err.contains(ERR_SALTED_KEY_MALFORMED), "{err}");

    let mut tampered_salt = signing.clone();
    tampered_salt.public = on_curve_salted_public(&signing.public);
    let err = decode_salted_private_key_file_bytes(&encode_salted_signing_material(&tampered_salt))
        .unwrap_err();
    assert!(err.contains(ERR_SALT_ON_CURVE), "{err}");
}

/// go `TestSaltedMnemonicImport`.
#[test]
fn salted_mnemonic_import() {
    let mut entropy = [0u8; 32];
    entropy[0] = 3;
    let signing =
        derive_salted_signing_material_from_entropy(SIG_SCHEME_FALCON1024, &entropy).unwrap();
    let mnemonic = mnemonic_of(&entropy);

    let dir = tempfile::tempdir().unwrap();
    let imported_keyfile = dir.path().join("imported.pq");
    run_salted_import_with_options(&mnemonic, "falcon-1024", &imported_keyfile, &mut Vec::new())
        .unwrap();
    assert_eq!(
        read_salted_signing_material(&imported_keyfile).unwrap(),
        signing
    );
}

/// go `TestSaltedImportRejectsMalformedMnemonic`.
#[test]
fn salted_import_rejects_malformed_mnemonic() {
    let dir = tempfile::tempdir().unwrap();
    let imported_keyfile = dir.path().join("imported.pq");
    run_salted_import_with_options(
        "not a valid mnemonic",
        "falcon-1024",
        &imported_keyfile,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(!imported_keyfile.exists());
}

/// go `TestSaltedImportRejectsUnknownScheme`.
#[test]
fn salted_import_rejects_unknown_scheme() {
    let mut entropy = [0u8; 32];
    entropy[0] = 5;
    let mnemonic = mnemonic_of(&entropy);

    // An unknown scheme is rejected, never silently deriving a different key.
    let dir = tempfile::tempdir().unwrap();
    let imported_keyfile = dir.path().join("imported.pq");
    let err = run_salted_import_with_options(&mnemonic, "zz", &imported_keyfile, &mut Vec::new())
        .unwrap_err();
    assert!(err.contains(ERR_SIG_SCHEME_NOT_SUPPORTED), "{err}");
    assert!(!imported_keyfile.exists());
}

/// go `TestSaltedPrintMnemonic`.
#[test]
fn salted_print_mnemonic() {
    let mut entropy = [0u8; 32];
    entropy[0] = 6;
    let mnemonic = mnemonic_of(&entropy);

    let mut out = Vec::new();
    print_salted_mnemonic(&mut out, &entropy).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!(
            "Private key mnemonic: {mnemonic}\nWrite these words down: they cannot be recovered from the key file.\n"
        )
    );
}

fn salted_subcommand(name: &str) -> clap::Command {
    let root = Cli::command();
    let salted = root.find_subcommand("salted").expect("salted").clone();
    salted.find_subcommand(name).expect(name).clone()
}

fn short_of(cmd: &clap::Command, long: &str) -> Option<char> {
    cmd.get_arguments()
        .find(|a| a.get_long() == Some(long))
        .unwrap_or_else(|| panic!("no --{long}"))
        .get_short()
}

/// go `TestSaltedCommandFlagShorthands`.
#[test]
fn salted_command_flag_shorthands() {
    let generate = salted_subcommand("generate");
    assert_eq!(short_of(&generate, "scheme"), Some('S'));
    assert_eq!(short_of(&generate, "keyfile"), Some('k'));

    assert_eq!(short_of(&salted_subcommand("info"), "keyfile"), Some('k'));

    let import = salted_subcommand("import");
    assert_eq!(short_of(&import, "mnemonic"), Some('m'));
    assert_eq!(short_of(&import, "scheme"), Some('S'));
    assert_eq!(short_of(&import, "keyfile"), Some('k'));

    let sign = salted_subcommand("sign");
    assert_eq!(short_of(&sign, "keyfile"), Some('k'));
    assert_eq!(short_of(&sign, "mnemonic"), Some('m'));
    assert_eq!(short_of(&sign, "scheme"), Some('S'));
    assert_eq!(short_of(&sign, "txfile"), Some('t'));
    assert_eq!(short_of(&sign, "outfile"), Some('o'));

    let sign_program = salted_subcommand("sign-program");
    assert_eq!(short_of(&sign_program, "keyfile"), Some('k'));
    assert_eq!(short_of(&sign_program, "mnemonic"), Some('m'));
    assert_eq!(short_of(&sign_program, "scheme"), Some('S'));
    assert_eq!(short_of(&sign_program, "program"), Some('p'));
    assert_eq!(short_of(&sign_program, "outfile"), Some('o'));
}

/// go `TestSaltedCommandKeepsPQAlias`: the name the group shipped with still
/// reaches it, so scripts written against `algokey pq` keep working.
#[test]
fn salted_command_keeps_pq_alias() {
    for group in ["salted", "pq"] {
        let cli = Cli::try_parse_from([
            "algokey-rust",
            group,
            "generate",
            "--scheme",
            "f1",
            "--keyfile",
            "k",
        ])
        .unwrap_or_else(|e| panic!("{group}: {e}"));
        match cli.command {
            Command::Salted(s) => {
                assert!(matches!(s.command, Some(SaltedSub::Generate(_))), "{group}")
            }
            other => panic!("{group}: {other:?}"),
        }
    }
}

/// go `TestSigSchemeFlagHasNoDefault`.
#[test]
fn sig_scheme_flag_has_no_default() {
    for name in ["generate", "import", "sign", "sign-program"] {
        let cmd = salted_subcommand(name);
        let arg = cmd
            .get_arguments()
            .find(|a| a.get_long() == Some("scheme"))
            .unwrap();
        assert!(arg.get_default_values().is_empty(), "{name}");
    }
}

/// go `TestSigSchemeMustMatchKeySource`.
#[test]
fn sig_scheme_must_match_key_source() {
    let mnemonic = mnemonic_of(&[0u8; 32]);

    let err = resolve_salted_signing_context(None, Some(&mnemonic), "").unwrap_err();
    assert_eq!(err, ERR_SCHEME_REQUIRED);
    let dir = tempfile::tempdir().unwrap();
    let err = run_salted_import_with_options(
        &mnemonic,
        "",
        &dir.path().join("imported.pq"),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(err, ERR_SCHEME_REQUIRED);

    let keyfile = dir.path().join("account.pq");
    write_salted_private_key_file(&keyfile, &salted_test_signing(0)).unwrap();

    let err = resolve_salted_signing_context(Some(&keyfile), None, "falcon-1024").unwrap_err();
    assert_eq!(err, ERR_SCHEME_WITH_KEYFILE);

    let ctx = resolve_salted_signing_context(Some(&keyfile), None, "").unwrap();
    assert_eq!(ctx.signing.public.scheme, SIG_SCHEME_FALCON1024);
}

/// go `TestSaltedSignProducesVerifiableSaltedKeySig`.
#[test]
fn salted_sign_produces_verifiable_salted_key_sig() {
    for (name, scheme) in [
        ("falcon-1024", SIG_SCHEME_FALCON1024),
        ("falcon-512", SIG_SCHEME_FALCON512),
        ("ed25519", SIG_SCHEME_ED25519),
    ] {
        let signing = derive_salted_signing_material_from_entropy(scheme, &[0u8; 32]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keyfile = dir.path().join("account.pq");
        let txfile = dir.path().join("txn.msgp");
        let outfile = dir.path().join("signed.msgp");
        write_salted_private_key_file(&keyfile, &signing).unwrap();

        write_txn(&txfile, &salted_test_txn(signing.public.address()));
        run_salted_sign_with_options(&SaltedSignOptions {
            keyfile: Some(keyfile),
            ..sign_options(&txfile, &outfile)
        })
        .unwrap();

        let signed = decode_signed(&outfile);
        assert_eq!(signed.sig, [0u8; 64], "{name}");
        assert!(signed.msig.is_none(), "{name}");
        assert!(signed.lsig.is_none(), "{name}");
        assert!(signed.auth_addr.is_none(), "{name}");
        let sksig = signed.pqsig.clone().expect("SKsig set");
        assert_eq!(sksig.scheme, signing.public.scheme, "{name}");
        assert_eq!(sksig.salt, signing.public.salt, "{name}");
        assert_eq!(
            sksig.public_key.as_ref(),
            signing.public.public_key.as_slice(),
            "{name}"
        );
        verify_txn(&signed).unwrap_or_else(|e| panic!("{name}: {e}"));

        let mut changed = signed.clone();
        changed.txn.note = serde_bytes::ByteBuf::from(b"changed".to_vec());
        assert!(verify_txn(&changed).is_err(), "{name}");
    }
}

/// go `TestSaltedSignAcceptsMnemonic`.
#[test]
fn salted_sign_accepts_mnemonic() {
    let entropy = [0u8; 32];
    let mnemonic = mnemonic_of(&entropy);
    for scheme in REGISTERED_SCHEMES {
        let signing = derive_salted_signing_material_from_entropy(scheme, &entropy).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let txfile = dir.path().join("txn.msgp");
        let outfile = dir.path().join("signed.msgp");
        write_txn(&txfile, &salted_test_txn(signing.public.address()));

        run_salted_sign_with_options(&SaltedSignOptions {
            mnemonic: Some(mnemonic.clone()),
            scheme: format_sig_scheme(&scheme),
            ..sign_options(&txfile, &outfile)
        })
        .unwrap();

        let signed = decode_signed(&outfile);
        let sksig = signed.pqsig.clone().unwrap();
        assert_eq!(
            sksig.public_key.as_ref(),
            signing.public.public_key.as_slice()
        );
        verify_txn(&signed).unwrap();
    }
}

/// go `TestSaltedSignRejectsUnsupportedMnemonicScheme`.
#[test]
fn salted_sign_rejects_unsupported_mnemonic_scheme() {
    let err = run_salted_sign_with_options(&SaltedSignOptions {
        mnemonic: Some(mnemonic_of(&[0u8; 32])),
        scheme: "zz".to_string(),
        txfile: "unsigned.msgp".into(),
        outfile: "signed.msgp".into(),
        ..SaltedSignOptions::default()
    })
    .unwrap_err();
    assert!(err.contains(ERR_SIG_SCHEME_NOT_SUPPORTED), "{err}");
}

/// go `TestSaltedSignRejectsEmptyInputFile`.
#[test]
fn salted_sign_rejects_empty_input_file() {
    let signing = salted_test_signing(0);
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.pq");
    let txfile = dir.path().join("empty.msgp");
    let outfile = dir.path().join("signed.msgp");
    write_salted_private_key_file(&keyfile, &signing).unwrap();
    std::fs::write(&txfile, []).unwrap();

    let err = run_salted_sign_with_options(&SaltedSignOptions {
        keyfile: Some(keyfile),
        ..sign_options(&txfile, &outfile)
    })
    .unwrap_err();
    assert!(err.contains("no transactions found"), "{err}");
    assert!(!outfile.exists());
}

/// go `TestSaltedSignSetsAndClearsAuthAddr`.
#[test]
fn salted_sign_sets_and_clears_auth_addr() {
    let signing = salted_test_signing(0);
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.pq");
    write_salted_private_key_file(&keyfile, &signing).unwrap();
    let opts = |tx: &Path, out: &Path, overwrite: bool| SaltedSignOptions {
        keyfile: Some(keyfile.clone()),
        overwrite,
        ..sign_options(tx, out)
    };

    // A sender that is not the key's address is rekeyed to it.
    let sender = Address([9u8; 32]);
    let txfile = dir.path().join("rekey.msgp");
    let outfile = dir.path().join("rekey-signed.msgp");
    write_txn(
        &txfile,
        &SignedTransaction {
            txn: salted_test_txn(sender).txn,
            ..Default::default()
        },
    );
    run_salted_sign_with_options(&opts(&txfile, &outfile, false)).unwrap();
    assert_eq!(
        decode_signed(&outfile).auth_addr,
        Some(signing.public.address())
    );

    // A stale AuthAddr on a transaction from the key's own address is kept.
    let stale = Address([10u8; 32]);
    let txfile = dir.path().join("stale.msgp");
    let stale_out = dir.path().join("stale-signed.msgp");
    let mut stxn = salted_test_txn(signing.public.address());
    stxn.auth_addr = Some(stale);
    write_txn(&txfile, &stxn);
    run_salted_sign_with_options(&opts(&txfile, &stale_out, false)).unwrap();
    assert_eq!(decode_signed(&stale_out).auth_addr, Some(stale));

    // Overwriting clears the previous authorization, including AuthAddr.
    let resigned_out = dir.path().join("stale-resigned.msgp");
    run_salted_sign_with_options(&opts(&stale_out, &resigned_out, true)).unwrap();
    let resigned = decode_signed(&resigned_out);
    assert!(resigned.auth_addr.is_none());
    assert!(resigned.pqsig.is_some());
}

/// go `TestSaltedSignRejectsMixedSignaturesUnlessOverwrite`.
#[test]
fn salted_sign_rejects_mixed_signatures_unless_overwrite() {
    let signing = salted_test_signing(0);
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.pq");
    let txfile = dir.path().join("txn.msgp");
    let outfile = dir.path().join("signed.msgp");
    write_salted_private_key_file(&keyfile, &signing).unwrap();

    let mut stxn = salted_test_txn(signing.public.address());
    stxn.sig[0] = 1;
    write_txn(&txfile, &stxn);

    let err = run_salted_sign_with_options(&SaltedSignOptions {
        keyfile: Some(keyfile.clone()),
        ..sign_options(&txfile, &outfile)
    })
    .unwrap_err();
    assert_eq!(err, ERR_TXN_ALREADY_SIGNED);

    run_salted_sign_with_options(&SaltedSignOptions {
        keyfile: Some(keyfile),
        overwrite: true,
        ..sign_options(&txfile, &outfile)
    })
    .unwrap();
    let signed = decode_signed(&outfile);
    assert_eq!(signed.sig, [0u8; 64]);
    assert!(signed.pqsig.is_some());
}

/// go `TestSaltedSignRejectsOnCurveSalt`: a key file tampered with a salt that
/// puts the address on the Ed25519 curve is refused at sign.
#[test]
fn salted_sign_rejects_on_curve_salt() {
    let mut signing = salted_test_signing(1);
    signing.public = on_curve_salted_public(&signing.public);

    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.pq");
    let txfile = dir.path().join("txn.msgp");
    let outfile = dir.path().join("signed.msgp");
    write_salted_private_key_file(&keyfile, &signing).unwrap();
    write_txn(&txfile, &salted_test_txn(signing.public.address()));

    let err = run_salted_sign_with_options(&SaltedSignOptions {
        keyfile: Some(keyfile),
        ..sign_options(&txfile, &outfile)
    })
    .unwrap_err();
    assert!(err.contains(ERR_SALT_ON_CURVE), "{err}");
}

/// go `TestSaltedDecodePrivateKeyRejectsMnemonic`.
#[test]
fn salted_decode_private_key_rejects_mnemonic() {
    let err = decode_salted_private_key_file_bytes(
        b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap_err();
    assert!(err.contains(ERR_SALTED_KEY_MALFORMED), "{err}");
}

/// The compiled program of go's `AssembleStringWithVersion("int 1", 1)`:
/// version 1, `intcblock 1 1`, `intc_0`.
const INT_1_PROGRAM: [u8; 5] = [0x01, 0x20, 0x01, 0x01, 0x22];

fn decode_lsig(path: &Path) -> LogicSig {
    rmp_serde::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// go `TestSaltedSignProgramProducesVerifiableDelegatedLogicSig`.
#[test]
fn salted_sign_program_produces_verifiable_delegated_logic_sig() {
    let signing = salted_test_signing(0);
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.pq");
    let program_file = dir.path().join("program.teal.tok");
    let lsig_file = dir.path().join("program.lsig");
    write_salted_private_key_file(&keyfile, &signing).unwrap();
    std::fs::write(&program_file, INT_1_PROGRAM).unwrap();

    run_salted_sign_program_with_options(&SaltedSignProgramOptions {
        keyfile: Some(keyfile),
        program: program_file,
        outfile: lsig_file.clone(),
        ..SaltedSignProgramOptions::default()
    })
    .unwrap();

    let lsig = decode_lsig(&lsig_file);
    assert_eq!(lsig.logic.as_ref(), INT_1_PROGRAM.as_slice());
    assert_eq!(lsig.sig, [0u8; 64]);
    assert!(lsig.msig.is_none());
    assert!(lsig.lmsig.is_none());
    let sksig = lsig.pqsig.clone().expect("SKsig set");
    assert_eq!(sksig.scheme, signing.public.scheme);
    assert_eq!(sksig.salt, signing.public.salt);
    assert_eq!(
        sksig.public_key.as_ref(),
        signing.public.public_key.as_slice()
    );

    // The delegation payload verifies under the scheme's own verifier.
    let payload = SKsigDelegatedProgram {
        addr: signing.public.address(),
        program: lsig.logic.to_vec(),
    };
    assert!(algo_falcon::falcon_verify(
        &sksig.public_key,
        &sksig.signature,
        &payload.to_be_signed()
    )
    .unwrap());

    let mut stxn = salted_test_txn(signing.public.address());
    stxn.lsig = Some(lsig);
    let consensus = future();
    let mut budget = algo_avm::group::GroupBudget::for_logicsig(1);
    verify_transaction_signature(
        &stxn,
        std::slice::from_ref(&stxn),
        0,
        &mut budget,
        &consensus,
    )
    .unwrap();

    let mut wrong = stxn.clone();
    wrong.txn.sender.0[0] ^= 1;
    let mut budget = algo_avm::group::GroupBudget::for_logicsig(1);
    let err = verify_transaction_signature(
        &wrong,
        std::slice::from_ref(&wrong),
        0,
        &mut budget,
        &consensus,
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("salted-key signature authorizer mismatch"),
        "{err}"
    );
}

/// go `TestSaltedSignProgramAcceptsMnemonic`.
#[test]
fn salted_sign_program_accepts_mnemonic() {
    let entropy = [0u8; 32];
    let mnemonic = mnemonic_of(&entropy);
    for scheme in REGISTERED_SCHEMES {
        let signing = derive_salted_signing_material_from_entropy(scheme, &entropy).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let program_file = dir.path().join("program.teal.tok");
        let lsig_file = dir.path().join("program.lsig");
        std::fs::write(&program_file, INT_1_PROGRAM).unwrap();

        run_salted_sign_program_with_options(&SaltedSignProgramOptions {
            mnemonic: Some(mnemonic.clone()),
            scheme: format_sig_scheme(&scheme),
            program: program_file,
            outfile: lsig_file.clone(),
            ..SaltedSignProgramOptions::default()
        })
        .unwrap();

        let lsig = decode_lsig(&lsig_file);
        let sksig = lsig.pqsig.clone().unwrap();
        assert_eq!(
            sksig.public_key.as_ref(),
            signing.public.public_key.as_slice()
        );
        let stxn = {
            let mut s = salted_test_txn(signing.public.address());
            s.lsig = Some(lsig);
            s
        };
        let mut budget = algo_avm::group::GroupBudget::for_logicsig(1);
        verify_transaction_signature(
            &stxn,
            std::slice::from_ref(&stxn),
            0,
            &mut budget,
            &future(),
        )
        .unwrap();
    }
}

/// go `TestSaltedSignProgramRejectsMixedKeySources`.
#[test]
fn salted_sign_program_rejects_mixed_key_sources() {
    let signing = salted_test_signing(0);
    let mnemonic = mnemonic_of(&[0u8; 32]);
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.pq");
    write_salted_private_key_file(&keyfile, &signing).unwrap();

    let err = run_salted_sign_program_with_options(&SaltedSignProgramOptions {
        keyfile: Some(keyfile),
        mnemonic: Some(mnemonic),
        program: "program.teal.tok".into(),
        outfile: "program.lsig".into(),
        ..SaltedSignProgramOptions::default()
    })
    .unwrap_err();
    assert!(
        err.contains("cannot specify both --keyfile and --mnemonic"),
        "{err}"
    );
}

/// go `TestSaltedSignProgramRejectsEmptyInputFile`.
#[test]
fn salted_sign_program_rejects_empty_input_file() {
    let signing = salted_test_signing(0);
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.pq");
    let program_file = dir.path().join("empty.tok");
    write_salted_private_key_file(&keyfile, &signing).unwrap();
    std::fs::write(&program_file, []).unwrap();

    let err = run_salted_sign_program_with_options(&SaltedSignProgramOptions {
        keyfile: Some(keyfile),
        program: program_file,
        outfile: dir.path().join("empty.lsig"),
        ..SaltedSignProgramOptions::default()
    })
    .unwrap_err();
    assert!(err.contains("program is empty"), "{err}");
}

/// go `TestSaltedSignProgramRejectsTealSource`.
#[test]
fn salted_sign_program_rejects_teal_source() {
    let signing = salted_test_signing(0);
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.pq");
    write_salted_private_key_file(&keyfile, &signing).unwrap();

    for (name, content, want) in [
        ("program.teal", "int 1", "looks like TEAL source"),
        (
            "program.tok",
            "#pragma version 1\nint 1",
            "not compiled bytecode",
        ),
        ("pragmaless.tok", "int 1", "not compiled bytecode"),
    ] {
        let file = dir.path().join(name);
        std::fs::write(&file, content).unwrap();
        let err = run_salted_sign_program_with_options(&SaltedSignProgramOptions {
            keyfile: Some(keyfile.clone()),
            program: file,
            outfile: dir.path().join("program.lsig"),
            ..SaltedSignProgramOptions::default()
        })
        .unwrap_err();
        assert!(err.contains(want), "{name}: {err}");
    }
}

/// go `TestSaltedCheckAddress`.
#[test]
fn salted_check_address() {
    let signing = salted_test_signing(0);
    run_salted_check_address(&signing.public.address().to_string(), &mut Vec::new()).unwrap();

    let on_curve = Address(
        ed25519_dalek::SigningKey::from_bytes(&[0u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let err = run_salted_check_address(&on_curve.to_string(), &mut Vec::new()).unwrap_err();
    assert!(err.contains("on the Ed25519 curve"), "{err}");

    let err = run_salted_check_address("not-an-address", &mut Vec::new()).unwrap_err();
    assert!(err.contains("cannot parse address"), "{err}");
}
