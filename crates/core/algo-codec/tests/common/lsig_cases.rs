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

//! Hand-made and damaged `LogicSig` msgpack records (issue #2390), shared by
//! `logicsig_go_decode_test.rs` and goal-rust's `clerk_compile_e2e.rs`.
//!
//! Every record is run through go's `protocol.Decode(bytes, &lsig)` (via
//! `goal clerk compile -D`, see `crates/tools/goal-rust/tests/clerk_compile_e2e.rs`),
//! and the outcome is committed in
//! `crates/tools/goal-rust/tests/fixtures/clerk_lsig_decode.jsonl`.

#![allow(dead_code)]

const PROGRAM: [u8; 3] = [8, 0x81, 1];

fn sig64() -> [u8; 64] {
    std::array::from_fn(|i| i as u8)
}

fn pk32(mul: usize) -> [u8; 32] {
    std::array::from_fn(|i| (i * mul % 256) as u8)
}

// ---- strict `LogicSig` decode (issue #2390) ---------------------------------
//
// `disassembleFile` runs `protocol.Decode(program, &lsig)`: the msgp-generated
// `LogicSig.UnmarshalMsg`, which is strict where go-codec was not (an unknown
// key, the `codec:",required"` fields of `MultisigSig`) and lenient where
// serde is strict (a `str`, `nil` or array for a byte string, a map as an
// array, a struct as an array, an omitted zero field). The records below are
// hand-made or damaged files no go tool writes; each one is run through the real
// go `goal` (`compile_matches_go_goal`) and its expected output is committed in
// `fixtures/clerk_lsig_decode.tsv`.

/// Raw msgpack, so that records can carry encodings no encoder here emits.
pub mod mp {
    pub const NIL: &[u8] = &[0xc0];

    pub fn nil() -> Vec<u8> {
        NIL.to_vec()
    }

    pub fn uint(n: u64) -> Vec<u8> {
        match n {
            0..=0x7f => vec![n as u8],
            0x80..=0xff => vec![0xcc, n as u8],
            0x100..=0xffff => [&[0xcd][..], &(n as u16).to_be_bytes()].concat(),
            0x1_0000..=0xffff_ffff => [&[0xce][..], &(n as u32).to_be_bytes()].concat(),
            _ => [&[0xcf][..], &n.to_be_bytes()].concat(),
        }
    }

    pub fn str_(s: &[u8]) -> Vec<u8> {
        match s.len() {
            0..=31 => [&[0xa0 | s.len() as u8][..], s].concat(),
            32..=255 => [&[0xd9, s.len() as u8][..], s].concat(),
            n => [&[0xda][..], &(n as u16).to_be_bytes(), s].concat(),
        }
    }

    pub fn bin(b: &[u8]) -> Vec<u8> {
        match b.len() {
            0..=255 => [&[0xc4, b.len() as u8][..], b].concat(),
            n if n <= 0xffff => [&[0xc5][..], &(n as u16).to_be_bytes(), b].concat(),
            n => [&[0xc6][..], &(n as u32).to_be_bytes(), b].concat(),
        }
    }

    pub fn ints(b: &[u8]) -> Vec<u8> {
        arr(&b.iter().map(|x| uint(*x as u64)).collect::<Vec<_>>())
    }

    pub fn arr(items: &[Vec<u8>]) -> Vec<u8> {
        let head = match items.len() {
            0..=15 => vec![0x90 | items.len() as u8],
            n if n <= 0xffff => [&[0xdc][..], &(n as u16).to_be_bytes()].concat(),
            n => [&[0xdd][..], &(n as u32).to_be_bytes()].concat(),
        };
        [head, items.concat()].concat()
    }

    pub fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let head = match entries.len() {
            0..=15 => vec![0x80 | entries.len() as u8],
            n if n <= 0xffff => [&[0xde][..], &(n as u16).to_be_bytes()].concat(),
            n => [&[0xdf][..], &(n as u32).to_be_bytes()].concat(),
        };
        let body: Vec<u8> = entries
            .iter()
            .flat_map(|(k, v)| [k.clone(), v.clone()].concat())
            .collect();
        [head, body].concat()
    }

    /// A map with string keys.
    pub fn rec(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let e: Vec<_> = entries
            .iter()
            .map(|(k, v)| (str_(k.as_bytes()), v.clone()))
            .collect();
        map(&e)
    }
}

fn pk_bytes() -> Vec<u8> {
    pk32(3).to_vec()
}

fn sig_bytes() -> Vec<u8> {
    sig64().to_vec()
}

fn program() -> Vec<u8> {
    mp::bin(&PROGRAM)
}

/// `{"pk": ..., "s": ...}` of one subsignature; `None` omits the key.
fn subsig(pk: Option<Vec<u8>>, s: Option<Vec<u8>>) -> Vec<u8> {
    let mut e = vec![];
    if let Some(pk) = pk {
        e.push(("pk", pk));
    }
    if let Some(s) = s {
        e.push(("s", s));
    }
    mp::rec(&e)
}

/// `{"v","thr","subsig"}`, each as given.
fn msig_rec(v: Option<u64>, thr: Option<u64>, subs: Option<Vec<u8>>) -> Vec<u8> {
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
    mp::arr(&[subsig(
        Some(mp::bin(&pk_bytes())),
        Some(mp::bin(&sig_bytes())),
    )])
}

/// A record with one `msig` whose `subsig` list is `subs`.
fn with_subs(subs: Vec<u8>) -> Vec<u8> {
    lsig_with(&[("msig", msig_rec(Some(1), Some(1), Some(subs)))])
}

/// `{"l": program, ...extra}`.
fn lsig_with(extra: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut e = vec![("l", program())];
    e.extend(extra.iter().cloned());
    mp::rec(&e)
}

/// `{"l": program, "msig": {"v": v, "thr": thr, "subsig": good}}` with `v` and
/// `thr` as raw msgpack values.
fn msig_with_raw(v: Vec<u8>, thr: Vec<u8>) -> Vec<u8> {
    lsig_with(&[(
        "msig",
        mp::rec(&[("v", v), ("thr", thr), ("subsig", good_subs())]),
    )])
}

/// Records that probe where go's generated decoder and serde part ways.
pub fn lsig_decode_cases() -> Vec<(String, Vec<u8>)> {
    let ok_msig = msig_rec(Some(1), Some(1), Some(good_subs()));
    let mut v: Vec<(String, Vec<u8>)> = vec![];
    let mut add = |name: &str, b: Vec<u8>| v.push((name.to_string(), b));

    // The five records of the issue, and the canonical happy paths.
    add("unknown key", lsig_with(&[("zzz", mp::uint(1))]));
    add(
        "msig explicit v 0 thr 0",
        lsig_with(&[("msig", msig_rec(Some(0), Some(0), Some(good_subs())))]),
    );
    add(
        "msig thr 0 v 1",
        lsig_with(&[("msig", msig_rec(Some(1), Some(0), Some(good_subs())))]),
    );
    add(
        "msig v 0 thr 1",
        lsig_with(&[("msig", msig_rec(Some(0), Some(1), Some(good_subs())))]),
    );
    add(
        "subsig zero pk written without pk",
        with_subs(mp::arr(&[subsig(None, Some(mp::bin(&sig_bytes())))])),
    );
    add("msig ok", lsig_with(&[("msig", ok_msig.clone())]));
    add("lmsig ok", lsig_with(&[("lmsig", ok_msig.clone())]));
    add(
        "subsig neither pk nor s",
        with_subs(mp::arr(&[subsig(None, None)])),
    );
    add(
        "subsig pk only",
        with_subs(mp::arr(&[subsig(Some(mp::bin(&pk_bytes())), None)])),
    );
    add(
        "subsig unknown key",
        with_subs(mp::arr(&[mp::rec(&[
            ("pk", mp::bin(&pk_bytes())),
            ("zzz", mp::uint(1)),
        ])])),
    );
    add(
        "msig unknown key",
        lsig_with(&[(
            "msig",
            mp::rec(&[
                ("v", mp::uint(1)),
                ("thr", mp::uint(1)),
                ("subsig", good_subs()),
                ("zzz", mp::uint(1)),
            ]),
        )]),
    );
    add(
        "msig no subsig",
        lsig_with(&[("msig", msig_rec(Some(1), Some(1), None))]),
    );
    add("msig empty subsig", with_subs(mp::arr(&[])));
    add("msig nil subsig", with_subs(mp::nil()));
    add("msig empty map", lsig_with(&[("msig", mp::rec(&[]))]));
    add("msig nil", lsig_with(&[("msig", mp::nil())]));
    add("lmsig nil", lsig_with(&[("lmsig", mp::nil())]));
    add("msig as int", lsig_with(&[("msig", mp::uint(1))]));
    add(
        "msig v 2",
        lsig_with(&[("msig", msig_rec(Some(2), Some(1), Some(good_subs())))]),
    );
    add(
        "msig thr above subsigs",
        lsig_with(&[("msig", msig_rec(Some(1), Some(9), Some(good_subs())))]),
    );
    add("msig v 256", msig_with_raw(mp::uint(256), mp::uint(1)));
    add("msig v as int8", msig_with_raw(vec![0xd0, 1], mp::uint(1)));
    add("msig v negative", msig_with_raw(vec![0xff], mp::uint(1)));
    add(
        "msig v as uint64 form",
        msig_with_raw(vec![0xcf, 0, 0, 0, 0, 0, 0, 0, 1], mp::uint(1)),
    );
    add("msig v nil", msig_with_raw(mp::nil(), mp::uint(1)));
    add("msig v str", msig_with_raw(mp::str_(b"1"), mp::uint(1)));
    add(
        "msig v float",
        msig_with_raw(vec![0xca, 0x3f, 0x80, 0, 0], mp::uint(1)),
    );
    add("msig v bool", msig_with_raw(vec![0xc3], mp::uint(1)));
    add("msig thr nil", msig_with_raw(mp::uint(1), mp::nil()));
    add(
        "msig 256 subsigs",
        with_subs(mp::arr(&vec![subsig(None, None); 256])),
    );
    add(
        "msig 255 subsigs",
        with_subs(mp::arr(&vec![subsig(None, None); 255])),
    );
    add(
        "msig subsig as map",
        with_subs(mp::map(&[(mp::str_(b"pk"), mp::bin(&pk_bytes()))])),
    );
    add(
        "subsig as array",
        with_subs(mp::arr(&[mp::arr(&[
            mp::bin(&pk_bytes()),
            mp::bin(&sig_bytes()),
        ])])),
    );
    add(
        "subsig as array of three",
        with_subs(mp::arr(&[mp::arr(&[
            mp::bin(&pk_bytes()),
            mp::bin(&sig_bytes()),
            mp::uint(1),
        ])])),
    );
    add("subsig nil", with_subs(mp::arr(&[mp::nil()])));
    add(
        "msig as array",
        lsig_with(&[("msig", mp::arr(&[mp::uint(1), mp::uint(1), good_subs()]))]),
    );
    add(
        "msig as array of four",
        lsig_with(&[(
            "msig",
            mp::arr(&[mp::uint(1), mp::uint(1), good_subs(), mp::uint(1)]),
        )]),
    );
    add(
        "msig as array of one",
        lsig_with(&[("msig", mp::arr(&[mp::uint(1)]))]),
    );

    // Subsignature byte strings.
    let pk_cases: Vec<(&str, Vec<u8>)> = vec![
        ("pk short", mp::bin(&pk_bytes()[..31])),
        ("pk long", mp::bin(&[pk_bytes(), vec![1]].concat())),
        ("pk str", mp::str_(&pk_bytes())),
        ("pk nil", mp::nil()),
        ("pk empty", mp::bin(&[])),
        ("pk array", mp::ints(&pk_bytes())),
        ("pk short array", mp::arr(&[mp::uint(7), mp::uint(8)])),
        ("pk long array", mp::arr(&vec![mp::uint(1); 33])),
        ("pk array of str", mp::arr(&[mp::str_(b"a")])),
        ("pk int", mp::uint(5)),
        ("pk map", mp::map(&[(mp::uint(1), mp::uint(2))])),
        ("pk bin32", [vec![0xc6, 0, 0, 0, 32], pk_bytes()].concat()),
    ];
    for (name, pk) in pk_cases {
        add(
            &format!("subsig {name}"),
            with_subs(mp::arr(&[subsig(Some(pk), None)])),
        );
    }

    // `l`, `sig` and `arg` byte strings.
    let l_cases: Vec<(&str, Vec<u8>)> = vec![
        ("l str", mp::str_(&PROGRAM)),
        ("l nil", mp::nil()),
        ("l empty", mp::bin(&[])),
        ("l array", mp::ints(&PROGRAM)),
        ("l array of str", mp::arr(&[mp::str_(b"a")])),
        ("l array of 256", mp::arr(&[mp::uint(256)])),
        ("l map", mp::map(&[(mp::uint(8), mp::uint(1))])),
        ("l int", mp::uint(8)),
        ("l bool", vec![0xc3]),
        (
            "l bin32",
            [vec![0xc6, 0, 0, 0, 3], PROGRAM.to_vec()].concat(),
        ),
        ("l truncated", vec![0xc4, 9, 8, 0x81]),
        ("l 16000 bytes", mp::bin(&vec![8u8; 16000])),
        ("l 16001 bytes", mp::bin(&vec![8u8; 16001])),
        ("l 100000 bytes", mp::bin(&vec![8u8; 100000])),
    ];
    for (name, l) in l_cases {
        add(name, mp::rec(&[("l", l)]));
    }
    let sig_cases: Vec<(&str, Vec<u8>)> = vec![
        ("sig str", mp::str_(&sig_bytes())),
        ("sig nil", mp::nil()),
        ("sig short", mp::bin(&sig_bytes()[..10])),
        ("sig long", mp::bin(&[sig_bytes(), vec![1, 2]].concat())),
        ("sig empty", mp::bin(&[])),
        ("sig array", mp::ints(&sig_bytes())),
        ("sig int", mp::uint(7)),
    ];
    for (name, sg) in sig_cases {
        add(name, lsig_with(&[("sig", sg)]));
    }
    let arg_cases: Vec<(&str, Vec<u8>)> = vec![
        ("arg nil", mp::nil()),
        ("arg empty", mp::arr(&[])),
        ("arg str element", mp::arr(&[mp::str_(b"hi")])),
        ("arg nil element", mp::arr(&[mp::nil(), mp::bin(b"x")])),
        ("arg array element", mp::arr(&[mp::ints(&[1, 2])])),
        ("arg int element", mp::arr(&[mp::uint(1)])),
        ("arg not an array", mp::bin(b"xy")),
        ("arg map", mp::rec(&[("a", mp::bin(b"x"))])),
        ("arg 255 elements", mp::arr(&vec![mp::bin(b"a"); 255])),
        ("arg 256 elements", mp::arr(&vec![mp::bin(b"a"); 256])),
        ("arg element 4096", mp::arr(&[mp::bin(&vec![1u8; 4096])])),
        ("arg element 4097", mp::arr(&[mp::bin(&vec![1u8; 4097])])),
        (
            "arg 8 elements of 4096",
            mp::arr(&vec![mp::bin(&vec![1u8; 4096]); 8]),
        ),
    ];
    for (name, a) in arg_cases {
        add(name, lsig_with(&[("arg", a)]));
    }

    // Duplicate keys, key types and map headers.
    add(
        "duplicate l",
        mp::rec(&[("l", mp::bin(&[9, 1])), ("l", program())]),
    );
    add(
        "duplicate sig",
        lsig_with(&[("sig", mp::bin(&sig_bytes())), ("sig", mp::bin(&[1, 2]))]),
    );
    add(
        "duplicate sig nil",
        lsig_with(&[("sig", mp::bin(&sig_bytes())), ("sig", mp::nil())]),
    );
    add(
        "duplicate msig",
        lsig_with(&[("msig", ok_msig.clone()), ("msig", mp::nil())]),
    );
    add(
        "duplicate arg",
        lsig_with(&[
            ("arg", mp::arr(&[mp::bin(b"a")])),
            ("arg", mp::arr(&[mp::bin(b"b"), mp::bin(b"c")])),
        ]),
    );
    add(
        "duplicate subsig pk",
        with_subs(mp::arr(&[mp::map(&[
            (mp::str_(b"pk"), mp::bin(&pk_bytes())),
            (mp::str_(b"pk"), mp::bin(&[1, 2])),
        ])])),
    );
    add("key as bin", mp::map(&[(mp::bin(b"l"), program())]));
    add("key as int", mp::map(&[(mp::uint(1), program())]));
    add("key nil", mp::map(&[(mp::nil(), program())]));
    add("key str8", mp::map(&[(vec![0xd9, 1, b'l'], program())]));
    add("key l then nul", mp::map(&[(mp::str_(b"l\0"), program())]));
    add("key upper case", mp::map(&[(mp::str_(b"L"), program())]));
    add(
        "map16 header",
        [vec![0xde, 0, 1], mp::str_(b"l"), program()].concat(),
    );
    add(
        "map32 header",
        [vec![0xdf, 0, 0, 0, 1], mp::str_(b"l"), program()].concat(),
    );
    add(
        "map header says two",
        [vec![0x82], mp::str_(b"l"), program()].concat(),
    );
    add("nil record", mp::nil());
    add("string record", mp::str_(b"hello"));
    add("int record", mp::uint(8));
    add("bin record", mp::bin(&PROGRAM));
    add("empty array record", mp::arr(&[]));
    add(
        "record then reserved byte",
        [lsig_with(&[]), vec![0xc1]].concat(),
    );
    add(
        "record then second record",
        [lsig_with(&[]), lsig_with(&[("zzz", mp::uint(1))])].concat(),
    );
    add(
        "record with sig then trailing",
        [lsig_with(&[("sig", mp::bin(&sig_bytes()))]), vec![0]].concat(),
    );
    add(
        "record truncated",
        lsig_with(&[("sig", mp::bin(&sig_bytes()))])[..20].to_vec(),
    );
    add("reserved marker", vec![0xc1]);

    // A record as an array (field order of the generated decoder).
    add("array form l", mp::arr(&[program()]));
    add(
        "array form l sig",
        mp::arr(&[program(), mp::bin(&sig_bytes())]),
    );
    add(
        "array form l sig msig",
        mp::arr(&[program(), mp::bin(&sig_bytes()), ok_msig.clone()]),
    );
    add(
        "array form fourth is lmsig",
        mp::arr(&[program(), mp::bin(&[]), mp::nil(), ok_msig.clone()]),
    );
    add(
        "array form all six",
        mp::arr(&[
            program(),
            mp::bin(&[]),
            ok_msig.clone(),
            ok_msig.clone(),
            mp::rec(&[]),
            mp::arr(&[mp::bin(b"zz")]),
        ]),
    );
    add(
        "array form fourth is arg",
        mp::arr(&[
            program(),
            mp::bin(&[]),
            mp::nil(),
            mp::arr(&[mp::bin(b"zz")]),
        ]),
    );
    add(
        "array form too many",
        mp::arr(&[
            program(),
            mp::bin(&[]),
            mp::nil(),
            mp::nil(),
            mp::rec(&[]),
            mp::arr(&[]),
            mp::uint(1),
        ]),
    );
    add(
        "array form nil fields",
        mp::arr(&[program(), mp::nil(), mp::nil()]),
    );
    add("array form 16 fields", mp::arr(&vec![mp::uint(1); 16]));

    // The post-quantum envelope.
    let pq_ok: Vec<(&str, Vec<u8>)> = vec![
        ("sch", mp::bin(b"fn")),
        ("slt", mp::uint(3)),
        ("pk", mp::bin(&(0..20).collect::<Vec<u8>>())),
        ("sig", mp::bin(&(0..30).collect::<Vec<u8>>())),
    ];
    add("pqsig ok", lsig_with(&[("pqsig", mp::rec(&pq_ok))]));
    add("pqsig empty", lsig_with(&[("pqsig", mp::rec(&[]))]));
    add("pqsig nil", lsig_with(&[("pqsig", mp::nil())]));
    #[allow(clippy::type_complexity)]
    let pq_cases: Vec<(&str, Vec<(&str, Vec<u8>)>)> = vec![
        (
            "pqsig unknown key",
            vec![("sch", mp::bin(b"fn")), ("zzz", mp::uint(1))],
        ),
        ("pqsig salt 255", vec![("slt", mp::uint(255))]),
        ("pqsig salt 256", vec![("slt", mp::uint(256))]),
        ("pqsig scheme short", vec![("sch", mp::bin(b"f"))]),
        ("pqsig scheme long", vec![("sch", mp::bin(b"fnx"))]),
        ("pqsig pk 1793", vec![("pk", mp::bin(&vec![1u8; 1793]))]),
        ("pqsig pk 1794", vec![("pk", mp::bin(&vec![1u8; 1794]))]),
        ("pqsig sig 1538", vec![("sig", mp::bin(&vec![1u8; 1538]))]),
        ("pqsig sig 1539", vec![("sig", mp::bin(&vec![1u8; 1539]))]),
        ("pqsig only a scheme", vec![("sch", mp::bin(b"fn"))]),
        (
            "pqsig key order",
            vec![
                ("sig", mp::bin(b"s")),
                ("slt", mp::uint(1)),
                ("pk", mp::bin(b"p")),
                ("sch", mp::bin(b"fn")),
            ],
        ),
    ];
    for (name, e) in pq_cases {
        add(name, lsig_with(&[("pqsig", mp::rec(&e))]));
    }
    add(
        "pqsig as array",
        lsig_with(&[(
            "pqsig",
            mp::arr(&[mp::bin(b"fn"), mp::uint(3), mp::bin(b"pk"), mp::bin(b"sig")]),
        )]),
    );
    add(
        "pqsig as array of five",
        lsig_with(&[(
            "pqsig",
            mp::arr(&[
                mp::bin(b"fn"),
                mp::uint(3),
                mp::bin(b"pk"),
                mp::bin(b"sig"),
                mp::uint(1),
            ]),
        )]),
    );

    // Key order and which members count as an authorization.
    add(
        "sig key before l",
        mp::rec(&[("sig", mp::bin(&sig_bytes())), ("l", program())]),
    );
    add(
        "every key",
        mp::rec(&[
            ("pqsig", mp::rec(&pq_ok)),
            ("lmsig", ok_msig.clone()),
            ("msig", ok_msig.clone()),
            ("arg", mp::arr(&[mp::bin(b"q")])),
            ("sig", mp::bin(&sig_bytes())),
            ("l", program()),
        ]),
    );
    add("arg only empty", lsig_with(&[("arg", mp::arr(&[]))]));
    add(
        "arg one empty element",
        lsig_with(&[("arg", mp::arr(&[mp::bin(&[])]))]),
    );
    add(
        "zero sig and empty arg",
        lsig_with(&[("sig", mp::bin(&[0; 64])), ("arg", mp::arr(&[]))]),
    );
    add("no l", mp::rec(&[("sig", mp::bin(&sig_bytes()))]));
    add("only unknown", mp::rec(&[("zzz", mp::uint(1))]));

    // Repeated keys decode into what is already there (go merges, serde replaces).
    let two_subs = mp::arr(&[
        subsig(Some(mp::bin(&pk_bytes())), Some(mp::bin(&sig_bytes()))),
        subsig(Some(mp::bin(&pk32(7))), None),
    ]);
    add(
        "duplicate msig merges the first subsig",
        lsig_with(&[
            ("msig", msig_rec(Some(1), Some(1), Some(two_subs.clone()))),
            (
                "msig",
                msig_rec(
                    Some(1),
                    Some(1),
                    Some(mp::arr(&[subsig(None, Some(mp::bin(&[9; 64])))])),
                ),
            ),
        ]),
    );
    add(
        "duplicate msig regrows over the old backing array",
        lsig_with(&[
            ("msig", msig_rec(Some(1), Some(1), Some(two_subs.clone()))),
            ("msig", msig_rec(None, None, Some(mp::arr(&[mp::rec(&[])])))),
            (
                "msig",
                msig_rec(None, None, Some(mp::arr(&[mp::rec(&[]), mp::rec(&[])]))),
            ),
        ]),
    );
    add(
        "duplicate msig nil subsig then regrow",
        lsig_with(&[
            ("msig", msig_rec(Some(1), Some(1), Some(two_subs.clone()))),
            ("msig", msig_rec(None, None, Some(mp::nil()))),
            (
                "msig",
                msig_rec(None, None, Some(mp::arr(&[mp::rec(&[]), mp::rec(&[])]))),
            ),
        ]),
    );
    add(
        "duplicate pqsig merges",
        lsig_with(&[
            (
                "pqsig",
                mp::rec(&[("sch", mp::bin(b"fn")), ("pk", mp::bin(b"pk"))]),
            ),
            (
                "pqsig",
                mp::rec(&[("sig", mp::bin(b"sg")), ("slt", mp::uint(4))]),
            ),
        ]),
    );
    add(
        "duplicate pqsig nil",
        lsig_with(&[
            ("pqsig", mp::rec(&[("sch", mp::bin(b"fn"))])),
            ("pqsig", mp::nil()),
        ]),
    );
    add(
        "duplicate sig keeps the tail",
        lsig_with(&[("sig", mp::bin(&sig_bytes())), ("sig", mp::bin(&[7; 5]))]),
    );
    add(
        "duplicate arg nil",
        lsig_with(&[("arg", mp::arr(&[mp::bin(b"a")])), ("arg", mp::nil())]),
    );

    // Odd encodings of keys and byte strings.
    add(
        "key as array of ints",
        mp::map(&[(mp::ints(b"l"), program())]),
    );
    add(
        "key as array with nil",
        mp::map(&[(mp::arr(&[mp::uint(108), mp::nil()]), program())]),
    );
    add(
        "key as array of str",
        mp::map(&[(mp::arr(&[mp::str_(b"l")]), program())]),
    );
    add(
        "key as map",
        mp::map(&[(mp::map(&[(mp::uint(108), mp::uint(1))]), program())]),
    );
    add("key bin16", mp::map(&[(vec![0xc5, 0, 1, b'l'], program())]));
    add("key truncated", vec![0x81, 0xa5, b'l']);
    add(
        "sig as map",
        lsig_with(&[("sig", mp::map(&[(mp::uint(1), mp::uint(2))]))]),
    );
    add(
        "sig as map of 32 pairs",
        lsig_with(&[("sig", mp::map(&vec![(mp::uint(5), mp::uint(6)); 32]))]),
    );
    add(
        "sig as map of 33 pairs",
        lsig_with(&[("sig", mp::map(&vec![(mp::uint(5), mp::uint(6)); 33]))]),
    );
    add(
        "sig bin16 header",
        lsig_with(&[("sig", [vec![0xc5, 0, 64], sig_bytes()].concat())]),
    );
    add(
        "sig str32 header",
        lsig_with(&[("sig", [vec![0xdb, 0, 0, 0, 64], sig_bytes()].concat())]),
    );
    add(
        "sig truncated body",
        lsig_with(&[("sig", [vec![0xc4, 64], sig_bytes()[..10].to_vec()].concat())]),
    );
    add(
        "sig array nil elements",
        lsig_with(&[("sig", mp::arr(&[mp::nil(), mp::uint(3)]))]),
    );
    add(
        "sig array negative element",
        lsig_with(&[("sig", mp::arr(&[vec![0xff]]))]),
    );
    add(
        "l map of pairs",
        mp::rec(&[(
            "l",
            mp::map(&[(mp::uint(8), mp::uint(0x81)), (mp::uint(1), mp::uint(0x43))]),
        )]),
    );
    add(
        "l array16 header",
        mp::rec(&[(
            "l",
            [vec![0xdc, 0, 3], mp::uint(8), mp::uint(0x81), mp::uint(1)].concat(),
        )]),
    );
    add(
        "l array of int8 forms",
        mp::rec(&[(
            "l",
            mp::arr(&[vec![0xd0, 8], vec![0xcc, 0x81], vec![0xd1, 0, 1]]),
        )]),
    );
    add(
        "arg element map",
        lsig_with(&[("arg", mp::arr(&[mp::map(&[(mp::uint(1), mp::uint(2))])]))]),
    );
    add(
        "arg element array of 4097",
        lsig_with(&[("arg", mp::arr(&[mp::arr(&vec![mp::uint(1); 4097])]))]),
    );
    add(
        "arg element array of 4096",
        lsig_with(&[("arg", mp::arr(&[mp::arr(&vec![mp::uint(1); 4096])]))]),
    );
    add(
        "arg as flattened map of 2",
        lsig_with(&[(
            "arg",
            mp::map(&[
                (mp::bin(b"a"), mp::bin(b"b")),
                (mp::bin(b"c"), mp::bin(b"d")),
            ]),
        )]),
    );
    add(
        "arg elements of every kind",
        lsig_with(&[(
            "arg",
            mp::arr(&[
                mp::bin(b"b"),
                mp::str_(b"s"),
                mp::nil(),
                mp::ints(&[1, 2]),
                mp::bin(&[]),
                mp::str_(&[]),
            ]),
        )]),
    );
    add(
        "pqsig salt nil",
        lsig_with(&[("pqsig", mp::rec(&[("slt", mp::nil())]))]),
    );
    add(
        "pqsig salt negative",
        lsig_with(&[("pqsig", mp::rec(&[("slt", vec![0xff])]))]),
    );
    add(
        "pqsig salt str",
        lsig_with(&[("pqsig", mp::rec(&[("slt", mp::str_(b"1"))]))]),
    );
    add(
        "pqsig scheme as ints",
        lsig_with(&[("pqsig", mp::rec(&[("sch", mp::ints(b"fn"))]))]),
    );
    add(
        "pqsig pk as ints",
        lsig_with(&[("pqsig", mp::rec(&[("pk", mp::ints(b"pk"))]))]),
    );
    add(
        "pqsig pk nil",
        lsig_with(&[("pqsig", mp::rec(&[("pk", mp::nil()), ("slt", mp::uint(1))]))]),
    );
    add(
        "pqsig sig str",
        lsig_with(&[("pqsig", mp::rec(&[("sig", mp::str_(b"sg"))]))]),
    );
    add(
        "pqsig only zeros",
        lsig_with(&[(
            "pqsig",
            mp::rec(&[("sch", mp::bin(&[0, 0])), ("slt", mp::uint(0))]),
        )]),
    );
    add(
        "msig subsig array16",
        lsig_with(&[(
            "msig",
            mp::rec(&[
                ("v", mp::uint(1)),
                ("thr", mp::uint(1)),
                (
                    "subsig",
                    [vec![0xdc, 0, 1], subsig(Some(mp::bin(&pk_bytes())), None)].concat(),
                ),
            ]),
        )]),
    );
    add(
        "msig subsig array32",
        lsig_with(&[(
            "msig",
            mp::rec(&[
                ("v", mp::uint(1)),
                ("thr", mp::uint(1)),
                (
                    "subsig",
                    [
                        vec![0xdd, 0, 0, 0, 1],
                        subsig(None, Some(mp::bin(&sig_bytes()))),
                    ]
                    .concat(),
                ),
            ]),
        )]),
    );
    add(
        "msig keys reordered",
        lsig_with(&[(
            "msig",
            mp::rec(&[
                ("subsig", good_subs()),
                ("thr", mp::uint(1)),
                ("v", mp::uint(1)),
            ]),
        )]),
    );
    add(
        "msig and lmsig both array form",
        mp::arr(&[
            program(),
            mp::bin(&[]),
            mp::arr(&[
                mp::uint(1),
                mp::uint(1),
                mp::arr(&[mp::arr(&[mp::bin(&pk_bytes())])]),
            ]),
            mp::arr(&[
                mp::uint(1),
                mp::uint(2),
                mp::arr(&[mp::arr(&[]), mp::arr(&[])]),
            ]),
        ]),
    );
    add(
        "array form in array form",
        mp::arr(&[mp::arr(&[program()])]),
    );
    add(
        "array form of nils",
        mp::arr(&[
            program(),
            mp::nil(),
            mp::nil(),
            mp::nil(),
            mp::nil(),
            mp::nil(),
        ]),
    );
    add("array16 record", [vec![0xdc, 0, 1], program()].concat());
    add(
        "array32 record",
        [vec![0xdd, 0, 0, 0, 2], program(), mp::bin(&sig_bytes())].concat(),
    );
    v
}

/// Single-byte and truncation mutants of a few rich records, from a fixed seed:
/// every one is run through go.
pub fn lsig_mutant_cases() -> Vec<(String, Vec<u8>)> {
    lsig_mutant_cases_with(70)
}

/// [`lsig_mutant_cases`] with `per_base` mutants of each base record.
pub fn lsig_mutant_cases_with(per_base: usize) -> Vec<(String, Vec<u8>)> {
    let ok_msig = msig_rec(
        Some(1),
        Some(2),
        Some(mp::arr(&[
            subsig(Some(mp::bin(&pk_bytes())), Some(mp::bin(&sig_bytes()))),
            subsig(None, Some(mp::bin(&[3; 64]))),
        ])),
    );
    let bases = [
        mp::rec(&[
            ("arg", mp::arr(&[mp::bin(b"q"), mp::bin(b"rs")])),
            ("l", program()),
            ("msig", ok_msig.clone()),
            ("sig", mp::bin(&sig_bytes())),
        ]),
        mp::rec(&[
            ("l", program()),
            ("lmsig", ok_msig),
            (
                "pqsig",
                mp::rec(&[
                    ("pk", mp::bin(&[5; 12])),
                    ("sch", mp::bin(b"fn")),
                    ("sig", mp::bin(&[6; 9])),
                    ("slt", mp::uint(3)),
                ]),
            ),
        ]),
        mp::arr(&[
            program(),
            mp::bin(&sig_bytes()),
            mp::nil(),
            mp::nil(),
            mp::rec(&[("slt", mp::uint(2))]),
            mp::arr(&[mp::bin(b"z")]),
        ]),
    ];
    // Bytes that change how a value is read: markers, lengths, small ints.
    const PICKS: [u8; 22] = [
        0x00, 0x01, 0x02, 0x7f, 0x80, 0x81, 0x90, 0x91, 0xa0, 0xa1, 0xc0, 0xc1, 0xc4, 0xc5, 0xcc,
        0xd0, 0xd9, 0xdc, 0xde, 0xdf, 0xe0, 0xff,
    ];
    let mut x: u64 = 0x2390_2390_2390_2391;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut v = vec![];
    for (bi, base) in bases.iter().enumerate() {
        for i in 0..per_base {
            let mut m = base.clone();
            let pos = (next() % m.len() as u64) as usize;
            match i % 7 {
                // truncation
                0 => m.truncate(pos),
                // a marker-like byte
                1..=4 => m[pos] = PICKS[(next() % PICKS.len() as u64) as usize],
                // any byte
                5 => m[pos] = next() as u8,
                // drop a byte
                _ => {
                    m.remove(pos);
                }
            }
            v.push((format!("mutant {bi}.{i}"), m));
        }
    }
    v
}
