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

//! Issue #2390: `algo_codec::decode_logicsig_go` is go's `protocol.Decode` into
//! a `transactions.LogicSig`, and the consensus path's hand-written reader
//! (`LogicSig::decode_from_reader`, what a gossiped / submitted / proposed
//! `SignedTxn` goes through) never accepts a record go rejects.
//!
//! The records are the ones of `common/lsig_cases.rs`, which
//! goal-rust's `clerk_compile_e2e.rs` also runs through a real go `goal clerk
//! compile -D` (outcomes committed in
//! `crates/tools/goal-rust/tests/fixtures/clerk_lsig_decode.jsonl`).

#[path = "common/lsig_cases.rs"]
mod lsig_cases;

use algo_codec::{decode_logicsig, decode_logicsig_go, GoLogicSig};
use algo_types::{strict_unknown_fields, LogicSig};
use lsig_cases::{lsig_decode_cases, lsig_mutant_cases, mp};

/// The consensus path's reader, in the strict mode of `POST /v2/transactions`
/// and the gossip `TX` handler (go's `ErrorIfNoField`).
fn hand_strict(b: &[u8]) -> Option<LogicSig> {
    let _g = strict_unknown_fields(b);
    LogicSig::decode_from_bytes(b).ok()
}

/// Both sides as comparable values: absent and blank members are the same.
fn norm_hand(l: &LogicSig) -> String {
    let blank_msig = |m: &Option<algo_types::MultisigSig>| m.clone().filter(|m| !m.blank());
    let pq = l.pqsig.clone().filter(|p| !p.blank());
    let args: Vec<Option<Vec<u8>>> = l
        .args
        .iter()
        .flatten()
        .map(|a| a.as_ref().map(|a| a.to_vec()))
        .collect();
    format!(
        "{:?}",
        (
            l.logic.to_vec(),
            l.sig.to_vec(),
            blank_msig(&l.msig),
            blank_msig(&l.lmsig),
            pq,
            args
        )
    )
}

fn norm_port(g: &GoLogicSig) -> String {
    let m = |m: &algo_types::MultisigSig| Some(m.clone()).filter(|m| !m.blank());
    let pq = Some(g.pqsig.clone()).filter(|p| !p.blank());
    let args: Vec<Option<Vec<u8>>> = g.args.clone();
    format!(
        "{:?}",
        (
            g.logic.clone(),
            g.sig.to_vec(),
            m(&g.msig),
            m(&g.lmsig),
            pq,
            args
        )
    )
}

/// Records the hand-written readers decode differently on purpose: struct-from-array
/// and repeated keys (the retired `docs/DIVERGENCES.md` DIV-004).
fn is_div004(name: &str) -> bool {
    name.contains("array form")
        || name.contains("as array")
        || name.contains("both array form")
        || name.contains("record then")
        || name.starts_with("array16 record")
        || name.starts_with("array32 record")
        || name.contains("duplicate")
        || name.contains("empty array record")
}

#[test]
fn go_decode_accepts_and_rejects_what_go_does() {
    let ok = |b: &[u8]| decode_logicsig_go(b).is_ok();
    let l = |n: usize| mp::rec(&[("l", mp::bin(&vec![8u8; n]))]);
    // The bounds are go's `allocbound`s; both sides of each were measured with
    // go v5.0.5-stable's `goal clerk compile -D`.
    assert!(ok(&l(16_000)) && !ok(&l(16_001)) && !ok(&l(100_000)));
    let arg =
        |n: usize, len: usize| mp::rec(&[("arg", mp::arr(&vec![mp::bin(&vec![1u8; len]); n]))]);
    assert!(ok(&arg(255, 1)) && !ok(&arg(256, 1)));
    assert!(ok(&arg(1, 4096)) && !ok(&arg(1, 4097)));
    let pq = |k: &str, n: usize| mp::rec(&[("pqsig", mp::rec(&[(k, mp::bin(&vec![1u8; n]))]))]);
    // go v5.1 bounds: the largest key/signature over all schemes (`ls`).
    assert!(ok(&pq("pk", 16_000)) && !ok(&pq("pk", 16_001)));
    assert!(ok(&pq("sig", 17_280)) && !ok(&pq("sig", 17_281)));
    // `msig` needs v, thr and subsig; an unknown key fails anywhere.
    let by_name: std::collections::HashMap<_, _> = lsig_decode_cases().into_iter().collect();
    for rejected in [
        "unknown key",
        "msig explicit v 0 thr 0",
        "msig thr 0 v 1",
        "msig v 0 thr 1",
        "subsig unknown key",
        "msig nil",
        "msig empty subsig",
        "msig 256 subsigs",
        "key upper case",
        "pqsig unknown key",
        "pqsig salt 256",
        // go v5.1's generated decoders read maps only (msgp 1.1.66, #6774).
        "array form all six",
    ] {
        assert!(!ok(&by_name[rejected]), "{rejected} must be rejected");
    }
    // A subsignature's zero key is written without `pk`; go decodes it as zero.
    for accepted in [
        "subsig zero pk written without pk",
        "msig ok",
        "msig 255 subsigs",
        "subsig pk short",
        "sig str",
        "duplicate l",
    ] {
        assert!(ok(&by_name[accepted]), "{accepted} must be accepted");
    }
    let g = decode_logicsig_go(&by_name["subsig zero pk written without pk"]).unwrap();
    assert_eq!(g.msig.subsigs.len(), 1);
    assert_eq!(g.msig.subsigs[0].public_key, [0u8; 32]);
    // Repeated keys decode into what is there: the first subsignature keeps its `pk`.
    let g = decode_logicsig_go(&by_name["duplicate msig merges the first subsig"]).unwrap();
    assert_eq!(g.msig.subsigs.len(), 1);
    assert_eq!(g.msig.subsigs[0].public_key[1], 3);
    assert_eq!(g.msig.subsigs[0].signature, [9u8; 64]);
    // ... and a re-grown list sees the elements its backing array still holds.
    let g =
        decode_logicsig_go(&by_name["duplicate msig regrows over the old backing array"]).unwrap();
    assert_eq!(g.msig.subsigs.len(), 2);
    assert_eq!(g.msig.subsigs[1].public_key[1], 7);
}

/// The consensus-path reader must reject whatever go's decoder rejects (a
/// record go refuses at txn decode must not reach evaluation here), and agree
/// on the value wherever both decode a canonical (map form, unique keys)
/// record.
#[test]
fn consensus_reader_never_accepts_what_go_rejects() {
    let named = lsig_decode_cases();
    let mutants = lsig_mutant_cases();
    let mut accepts_rejected = Vec::new();
    let mut differs = Vec::new();
    for (name, bytes) in named.iter().chain(mutants.iter()) {
        let go = decode_logicsig_go(bytes);
        let hand = hand_strict(bytes);
        match (&go, &hand) {
            (Err(_), Some(_)) => accepts_rejected.push(name.clone()),
            (Ok(g), Some(h))
                if !is_div004(name)
                    && !name.starts_with("mutant")
                    && norm_port(g) != norm_hand(h) =>
            {
                differs.push(name.clone());
            }
            _ => {}
        }
    }
    assert!(
        accepts_rejected.is_empty(),
        "the consensus reader accepts records go rejects: {accepts_rejected:#?}"
    );
    assert!(differs.is_empty(), "decoded values differ: {differs:#?}");
}

/// The records of the issue, through the plain-serde `decode_logicsig` that
/// goal used before: the reason for the strict port.
#[test]
fn serde_decode_is_not_go() {
    let by_name: std::collections::HashMap<_, _> = lsig_decode_cases().into_iter().collect();
    // serde accepts an unknown key, go does not.
    assert!(decode_logicsig(&by_name["unknown key"]).is_ok());
    assert!(decode_logicsig_go(&by_name["unknown key"]).is_err());
    // serde rejects a subsignature without `pk`, go decodes it.
    assert!(decode_logicsig(&by_name["subsig zero pk written without pk"]).is_err());
    assert!(decode_logicsig_go(&by_name["subsig zero pk written without pk"]).is_ok());
}

fn pay_txn() -> Vec<u8> {
    mp::rec(&[("type", mp::str_(b"pay")), ("snd", mp::bin(&[1u8; 32]))])
}

/// What reaches evaluation is a `SignedTxn`: the same classes, nested in one.
#[test]
fn signed_txn_carrying_such_a_logicsig_is_rejected() {
    let decode = |lsig: &[u8]| {
        let stxn = mp::rec(&[("lsig", lsig.to_vec()), ("txn", pay_txn())]);
        let _g = strict_unknown_fields(&stxn);
        algo_types::SignedTransaction::decode_from_bytes(&stxn).is_ok()
    };
    let by_name: std::collections::HashMap<_, _> = lsig_decode_cases().into_iter().collect();
    // The control: a record go accepts decodes inside a SignedTxn.
    assert!(decode(&by_name["msig ok"]));
    assert!(decode(&by_name["subsig zero pk written without pk"]));
    for rejected in [
        "unknown key",
        "msig nil",
        "lmsig nil",
        "msig thr 0 v 1",
        "msig 256 subsigs",
        "l 16001 bytes",
        "arg 256 elements",
        "arg element 4097",
        "pqsig pk 16001",
        "pqsig sig 17281",
    ] {
        assert!(!decode(&by_name[rejected]), "{rejected} must be rejected");
    }
    // A `nil` top-level `msig` is as invalid as a nested one.
    let stxn = mp::rec(&[("msig", mp::nil()), ("txn", pay_txn())]);
    let _g = strict_unknown_fields(&stxn);
    assert!(algo_types::SignedTransaction::decode_from_bytes(&stxn).is_err());
}

/// A rejection carries go's `err.Error()`: msgp's error kind and the context
/// path `msgp.WrapError` adds (issue #2404). The fixture of
/// `goal-rust/tests/clerk_sign_lsig_e2e.rs` checks every record against go's
/// own output; these pin the rules by name.
#[test]
fn rejections_carry_go_msgp_error_text() {
    use algo_types::go_msgp::{MAX_LOGIC_SIG_ARG_SIZE, MAX_LOGIC_SIG_MAX_SIZE};
    let by_name: std::collections::HashMap<_, _> = lsig_decode_cases().into_iter().collect();
    let text = |name: &str| decode_logicsig_go(&by_name[name]).unwrap_err().text();
    for (name, want) in [
        // an `errWrapped` wraps again: one " at " per level
        ("subsig unknown key", "Unknown field: zzz at Subsigs/0 at Msig"),
        ("msig 256 subsigs", "msgp: length overflow: 256 > 255 at Subsigs at Msig"),
        // go v5.1: a struct is a map; an array is `ReadMapHeaderBytes`'s TypeError
        (
            "subsig as array of three",
            "msgp: attempted to decode type \"array\" with method for \"map\" at Msig/Subsigs/0",
        ),
        (
            "array form nil fields",
            "msgp: attempted to decode type \"array\" with method for \"map\"",
        ),
        // a `TypeError` / `UintOverflow` prepends to its context
        ("msig v 256", "msgp: 256 overflows uint8 at Msig/Version"),
        (
            "msig subsig as map",
            "msgp: attempted to decode type \"str\" with method for \"map\" at Msig/Subsigs/0",
        ),
        // an `UintBelowZero` replaces it
        ("msig v negative", "msgp: attempted to cast int -1 to unsigned at Msig"),
        ("pqsig salt negative", "msgp: attempted to cast int -1 to unsigned at SKsig"),
        // `ErrShortBytes` never gets one
        ("l truncated", "msgp: too few bytes left to read object"),
        ("reserved marker", "msgp: unrecognized type prefix 0xc1"),
        ("pqsig pk 16001", "msgp: length overflow: 16001 > 16000 at SKsig"),
    ] {
        assert_eq!(String::from_utf8(text(name)).unwrap(), want, "{name}");
    }
    // The generated code returns the program and argument size overflows unwrapped.
    assert_eq!(
        String::from_utf8(text("l 16001 bytes")).unwrap(),
        format!("msgp: length overflow: 16001 > {MAX_LOGIC_SIG_MAX_SIZE}")
    );
    assert_eq!(
        String::from_utf8(text("arg element 4097")).unwrap(),
        format!("msgp: length overflow: 4097 > {MAX_LOGIC_SIG_ARG_SIZE}")
    );
    // An unknown key is printed as its raw bytes.
    assert_eq!(text("key l then nul"), b"Unknown field: l\0");
}
