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

//! Replay of `tests/fixtures/salted_oracle.jsonl`: go v5.1.1-stable's
//! `algokey salted` on fixed inputs (`tools/salted-oracle/oracle_test.go`, the
//! header there has the regeneration command). Every row is a go verdict
//! (output bytes, stdout text or the full error text) that algod-rust must
//! reproduce exactly.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::check_address::run_salted_check_address;
use super::generate::run_salted_generate;
use super::import::run_salted_import_with_options;
use super::info::run_salted_info;
use super::key::{decode_salted_private_key_file_bytes, encode_salted_signing_material};
use super::scheme::{
    derive_salted_signing_material_from_entropy, derive_sig_scheme_key_seed, format_sig_scheme,
    parse_sig_scheme,
};
use super::sign::{run_salted_sign_with_options, SaltedSignOptions};
use super::sign_program::{run_salted_sign_program_with_options, SaltedSignProgramOptions};
use super::{print_salted_key_info, print_salted_mnemonic};

const FIXTURE: &str = include_str!("../../../tests/fixtures/salted_oracle.jsonl");

fn s<'a>(row: &'a Value, key: &str) -> &'a str {
    row[key].as_str().unwrap_or("")
}

fn unhex(row: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(row, key)).unwrap_or_else(|e| panic!("{key}: {e}"))
}

fn scheme2(text: &str) -> [u8; 2] {
    let b = text.as_bytes();
    assert_eq!(b.len(), 2, "{text:?}");
    [b[0], b[1]]
}

/// A go error text with the temp dir stood in for by `<DIR>`.
fn norm(err: &str, dir: &Path) -> String {
    let d = dir.display().to_string();
    if err.contains(&d) {
        err.replace(&d, "<DIR>").replace('\\', "/")
    } else {
        err.to_string()
    }
}

fn norm_result(res: Result<(), String>, dir: &Path) -> String {
    match res {
        Ok(()) => String::new(),
        Err(e) => norm(&e, dir),
    }
}

/// OS error wording differs off unix; those rows are go-on-linux texts.
fn os_text_row(row: &Value) -> bool {
    !cfg!(unix) && s(row, "err").contains("no such file or directory")
}

fn check(row: &Value, what: &str, got: &str, want: &str) {
    assert_eq!(got, want, "{what}: row {}", row["name"]);
}

fn replay_derive(row: &Value) {
    let scheme = scheme2(s(row, "scheme"));
    let entropy: [u8; 32] = unhex(row, "entropy").try_into().unwrap();
    let signing = derive_salted_signing_material_from_entropy(scheme, &entropy).unwrap();
    assert_eq!(
        hex::encode(derive_sig_scheme_key_seed(scheme, &entropy)),
        s(row, "seed")
    );
    assert_eq!(
        hex::encode(encode_salted_signing_material(&signing)),
        s(row, "keyfile")
    );
    assert_eq!(
        algo_consensus_crypto::key_to_mnemonic(&entropy).unwrap(),
        s(row, "mnemonic")
    );
    let mut info = Vec::new();
    print_salted_key_info(&mut info, &signing.public).unwrap();
    assert_eq!(String::from_utf8(info).unwrap(), s(row, "info"));
    let mut mn = Vec::new();
    print_salted_mnemonic(&mut mn, &entropy).unwrap();
    assert_eq!(String::from_utf8(mn).unwrap(), s(row, "mnemonic_text"));
    assert_eq!(signing.public.address().to_string(), s(row, "address"));
}

fn replay_scheme_parse(row: &Value) {
    match parse_sig_scheme(s(row, "value")) {
        Ok(scheme) => {
            assert!(row.get("err").is_none(), "{row}");
            assert_eq!(hex::encode(scheme), s(row, "scheme"), "{row}");
            assert_eq!(format_sig_scheme(&scheme), s(row, "format"), "{row}");
        }
        Err(e) => assert_eq!(e, s(row, "err"), "{row}"),
    }
}

fn replay_scheme_format(row: &Value) {
    let raw = unhex(row, "scheme");
    assert_eq!(
        format_sig_scheme(&[raw[0], raw[1]]),
        s(row, "format"),
        "{row}"
    );
}

fn replay_keyfile(row: &Value) {
    let data = unhex(row, "hex");
    match decode_salted_private_key_file_bytes(&data) {
        Ok(signing) => {
            assert!(row.get("err").is_none(), "{row}");
            let mut info = Vec::new();
            print_salted_key_info(&mut info, &signing.public).unwrap();
            check(
                row,
                "info",
                &String::from_utf8(info).unwrap(),
                s(row, "info"),
            );
            check(
                row,
                "reencoded",
                &hex::encode(encode_salted_signing_material(&signing)),
                s(row, "reencoded"),
            );
        }
        Err(e) => {
            assert!(row.get("err").is_some(), "go accepted {row}, rust: {e}");
            check(row, "err", &e, s(row, "err"));
        }
    }
}

fn replay_info(row: &Value, dir: &Path) {
    if os_text_row(row) {
        return;
    }
    let path = dir.join(format!("info-{}", s(row, "name")));
    if !row["missing"].as_bool().unwrap() {
        std::fs::write(&path, unhex(row, "hex")).unwrap();
    }
    let mut out = Vec::new();
    let res = run_salted_info(&path, &mut out);
    check(
        row,
        "stdout",
        &String::from_utf8(out).unwrap(),
        s(row, "stdout"),
    );
    check(row, "err", &norm_result(res, dir), s(row, "err"));
}

fn opt_hex(row: &Value, key: &str) -> Option<Vec<u8>> {
    row.get(key).map(|_| unhex(row, key))
}

fn replay_sign(row: &Value, dir: &Path) {
    let name = s(row, "name");
    let keyfile = opt_hex(row, "keyfile").map(|k| {
        let p = dir.join(format!("sign-{name}.key"));
        std::fs::write(&p, k).unwrap();
        p
    });
    let txfile = dir.join(format!("sign-{name}.tx"));
    std::fs::write(&txfile, unhex(row, "txfile")).unwrap();
    let outfile = dir.join(format!("sign-{name}.out"));
    let mnemonic = s(row, "mnemonic");
    let res = run_salted_sign_with_options(&SaltedSignOptions {
        keyfile,
        mnemonic: (!mnemonic.is_empty()).then(|| mnemonic.to_string()),
        scheme: s(row, "scheme").to_string(),
        txfile,
        outfile: outfile.clone(),
        overwrite: row["overwrite"].as_bool().unwrap(),
    });
    let err = norm_result(res, dir);
    check(row, "err", &err, s(row, "err"));
    if row.get("out").is_some() {
        check(
            row,
            "out",
            &hex::encode(std::fs::read(&outfile).unwrap()),
            s(row, "out"),
        );
    } else {
        assert!(!outfile.exists(), "rust wrote an output file: {row}");
    }
}

fn replay_sign_program(row: &Value, dir: &Path) {
    let name = s(row, "name");
    let keyfile = opt_hex(row, "keyfile").map(|k| {
        let p = dir.join(format!("prog-{name}.key"));
        std::fs::write(&p, k).unwrap();
        p
    });
    let program = dir.join(s(row, "file_name"));
    std::fs::write(&program, unhex(row, "program")).unwrap();
    let outfile = dir.join(format!("prog-{name}.lsig"));
    let mnemonic = s(row, "mnemonic");
    let res = run_salted_sign_program_with_options(&SaltedSignProgramOptions {
        keyfile,
        mnemonic: (!mnemonic.is_empty()).then(|| mnemonic.to_string()),
        scheme: s(row, "scheme").to_string(),
        program,
        outfile: outfile.clone(),
    });
    check(row, "err", &norm_result(res, dir), s(row, "err"));
    if row.get("out").is_some() {
        check(
            row,
            "out",
            &hex::encode(std::fs::read(&outfile).unwrap()),
            s(row, "out"),
        );
    } else {
        assert!(!outfile.exists(), "rust wrote an output file: {row}");
    }
}

fn replay_import(row: &Value, dir: &Path) {
    if os_text_row(row) {
        return;
    }
    let name = s(row, "name");
    let path: PathBuf = if row["dir_ok"].as_bool().unwrap() {
        dir.join(format!("import-{name}.key"))
    } else {
        dir.join("no-such-dir").join("import.key")
    };
    let mut out = Vec::new();
    let res = run_salted_import_with_options(s(row, "mnemonic"), s(row, "scheme"), &path, &mut out);
    check(
        row,
        "stdout",
        &String::from_utf8(out).unwrap(),
        s(row, "stdout"),
    );
    check(row, "err", &norm_result(res, dir), s(row, "err"));
    match row.get("keyfile") {
        Some(_) => check(
            row,
            "keyfile",
            &hex::encode(std::fs::read(&path).unwrap()),
            s(row, "keyfile"),
        ),
        None => assert!(!path.exists(), "rust wrote a key file: {row}"),
    }
}

fn replay_generate(row: &Value, dir: &Path) {
    if os_text_row(row) {
        return;
    }
    let name = s(row, "name");
    let path: PathBuf = if row["dir_ok"].as_bool().unwrap() {
        dir.join(format!("gen-{name}.key"))
    } else {
        dir.join("no-such-dir").join("gen.key")
    };
    let mut out = Vec::new();
    let res = run_salted_generate(s(row, "scheme"), &path, &mut out);
    assert_eq!(
        out.is_empty(),
        row["stdout_empty"].as_bool().unwrap(),
        "{row}"
    );
    check(row, "err", &norm_result(res, dir), s(row, "err"));
}

fn replay_check_address(row: &Value, dir: &Path) {
    let mut out = Vec::new();
    let res = run_salted_check_address(s(row, "address"), &mut out);
    assert_eq!(
        String::from_utf8(out).unwrap(),
        s(row, "stdout"),
        "address {:?}",
        row["address"]
    );
    assert_eq!(
        norm_result(res, dir),
        s(row, "err"),
        "address {:?}",
        row["address"]
    );
}

#[test]
fn algokey_salted_matches_go_on_every_oracle_row() {
    let dir = tempfile::tempdir().unwrap();
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for line in FIXTURE.lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        let kind = s(&row, "kind").to_string();
        match kind.as_str() {
            "derive" => replay_derive(&row),
            "scheme_parse" => replay_scheme_parse(&row),
            "scheme_format" => replay_scheme_format(&row),
            "keyfile" => replay_keyfile(&row),
            "info" => replay_info(&row, dir.path()),
            "sign" => replay_sign(&row, dir.path()),
            "sign_program" => replay_sign_program(&row, dir.path()),
            "import" => replay_import(&row, dir.path()),
            "generate" => replay_generate(&row, dir.path()),
            "check_address" => replay_check_address(&row, dir.path()),
            other => panic!("unknown oracle row kind {other}"),
        }
        *counts.entry(kind).or_default() += 1;
    }
    // The fixture must keep covering every kind.
    for kind in [
        "derive",
        "scheme_parse",
        "scheme_format",
        "keyfile",
        "info",
        "sign",
        "sign_program",
        "import",
        "generate",
        "check_address",
    ] {
        assert!(counts.get(kind).copied().unwrap_or(0) > 0, "no {kind} rows");
    }
}
