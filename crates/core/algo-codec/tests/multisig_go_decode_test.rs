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

//! Issue #2393: `algo_codec::decode_multisig_go` is go's
//! `protocol.Decode(blob, &crypto.MultisigSig)` (what `libgoal` runs on kmd's
//! `multisig/sign` and `multisig/signprogram` responses). go's generated
//! `MultisigSig.UnmarshalMsg` is the very function `LogicSig`'s decoder calls
//! for `msig`/`lmsig`, so every record must decode exactly as the same record
//! under `{"msig": ...}` does in `decode_logicsig_go` (whose outcomes are the
//! go-generated fixture `clerk_lsig_decode.jsonl`).

#[path = "common/lsig_cases.rs"]
mod lsig_cases;

use algo_codec::{decode_logicsig, decode_logicsig_go, decode_multisig, decode_multisig_go};
use lsig_cases::mp;

fn sub(pk: Option<Vec<u8>>, s: Option<Vec<u8>>) -> Vec<u8> {
    let mut e = vec![];
    if let Some(pk) = pk {
        e.push(("pk", pk));
    }
    if let Some(s) = s {
        e.push(("s", s));
    }
    mp::rec(&e)
}

fn msig(v: Option<u64>, thr: Option<u64>, subs: Option<Vec<u8>>) -> Vec<u8> {
    let mut e = vec![];
    if let Some(v) = v {
        e.push(("v", mp::uint(v)));
    }
    if let Some(t) = thr {
        e.push(("thr", mp::uint(t)));
    }
    if let Some(s) = subs {
        e.push(("subsig", s));
    }
    mp::rec(&e)
}

fn good_subs() -> Vec<u8> {
    mp::arr(&[sub(Some(mp::bin(&[7; 32])), Some(mp::bin(&[9; 64])))])
}

fn records() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("ok", msig(Some(1), Some(1), Some(good_subs()))),
        ("v 0", msig(Some(0), Some(1), Some(good_subs()))),
        ("thr 0", msig(Some(1), Some(0), Some(good_subs()))),
        ("no v", msig(None, Some(1), Some(good_subs()))),
        ("no subsig", msig(Some(1), Some(1), None)),
        ("empty subsig", msig(Some(1), Some(1), Some(mp::arr(&[])))),
        (
            "subsig without pk",
            msig(
                Some(1),
                Some(1),
                Some(mp::arr(&[sub(None, Some(mp::bin(&[9; 64])))])),
            ),
        ),
        (
            "subsig unknown key",
            msig(
                Some(1),
                Some(1),
                Some(mp::arr(&[mp::rec(&[("zz", mp::uint(1))])])),
            ),
        ),
        (
            "unknown key",
            mp::rec(&[
                ("v", mp::uint(1)),
                ("thr", mp::uint(1)),
                ("subsig", good_subs()),
                ("zzz", mp::uint(1)),
            ]),
        ),
        ("nil", mp::nil()),
        (
            "array form",
            mp::arr(&[mp::uint(1), mp::uint(1), good_subs()]),
        ),
        (
            "256 subsigs",
            msig(Some(1), Some(1), Some(mp::arr(&vec![sub(None, None); 256]))),
        ),
        (
            "255 subsigs",
            msig(Some(1), Some(1), Some(mp::arr(&vec![sub(None, None); 255]))),
        ),
        (
            "str pk",
            msig(
                Some(1),
                Some(1),
                Some(mp::arr(&[sub(Some(mp::str_(&[7; 32])), None)])),
            ),
        ),
        ("v 256", msig(Some(256), Some(1), Some(good_subs()))),
    ]
}

#[test]
fn multisig_decode_is_the_logicsig_members_decode() {
    for (name, rec) in records() {
        let wrapped = mp::rec(&[("msig", rec.clone())]);
        let via_lsig = decode_logicsig_go(&wrapped);
        let direct = decode_multisig_go(&rec);
        assert_eq!(
            direct.is_ok(),
            via_lsig.is_ok(),
            "{name}: direct {direct:?} vs via LogicSig {via_lsig:?}"
        );
        if let (Ok(d), Ok(l)) = (direct, via_lsig) {
            assert_eq!(d, l.msig, "{name}");
        }
    }
}

/// A top-level `MultisigSig` failure has no `Msig` context: go's text for
/// libgoal's `protocol.Decode(resp.Multisig, &msig)` (issue #2404).
#[test]
fn multisig_rejection_carries_go_msgp_error_text() {
    let rec = |n: &str| records().into_iter().find(|r| r.0 == n).unwrap().1;
    let text =
        |n: &str| String::from_utf8(decode_multisig_go(&rec(n)).unwrap_err().text()).unwrap();
    assert_eq!(text("v 256"), "msgp: 256 overflows uint8 at Version");
    assert_eq!(text("unknown key"), "Unknown field: zzz");
}

#[test]
fn serde_multisig_decode_is_not_go() {
    let unknown = records()
        .into_iter()
        .find(|r| r.0 == "unknown key")
        .unwrap()
        .1;
    assert!(decode_multisig(&unknown).is_ok());
    assert!(decode_multisig_go(&unknown).is_err());
    let nopk = records()
        .into_iter()
        .find(|r| r.0 == "subsig without pk")
        .unwrap()
        .1;
    assert!(decode_multisig(&nopk).is_err());
    assert!(decode_multisig_go(&nopk).is_ok());
}

/// `GoLogicSig::into_logicsig` keeps what go keeps: blank members are absent,
/// a decoded `msig`/`args` survive.
#[test]
fn go_logicsig_converts_to_the_serde_value() {
    let rec = mp::rec(&[
        ("arg", mp::arr(&[mp::bin(b"q"), mp::nil()])),
        ("l", mp::bin(&[8, 0x81, 1])),
        ("msig", msig(Some(1), Some(1), Some(good_subs()))),
    ]);
    let l = decode_logicsig_go(&rec).unwrap().into_logicsig();
    assert_eq!(l.logic.as_ref(), &[8, 0x81, 1]);
    assert!(l.lmsig.is_none() && l.pqsig.is_none());
    assert_eq!(l.msig.as_ref().unwrap().subsigs.len(), 1);
    let args = l.args.unwrap();
    assert_eq!(args.len(), 2);
    assert_eq!(args[0].as_deref().map(Vec::as_slice), Some(&b"q"[..]));
    // go keeps a nil element nil (issue #2430)
    assert!(args[1].is_none());
    // Where both decoders accept, the values agree.
    let plain = mp::rec(&[
        ("l", mp::bin(&[8, 0x81, 1])),
        ("msig", msig(Some(1), Some(1), Some(good_subs()))),
    ]);
    assert_eq!(
        decode_logicsig_go(&plain).unwrap().into_logicsig(),
        decode_logicsig(&plain).unwrap()
    );
}
