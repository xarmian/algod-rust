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

//! What go-algorand v5.1.1-stable's `SignedTxn.UnmarshalMsg` does with a byte
//! string (issue #2555): the msgp-generated decoders of `data/transactions/
//! msgp_gen.go` (`SignedTxn`, `Transaction`, `ResourceRef`, `HeartbeatTxnFields`),
//! `data/basics` (`AssetParams`, `StateSchema`, `Participant`), `crypto`
//! (`HeartbeatProof`, `HashFactory`, `Falcon1024*`), `crypto/merklearray`,
//! `crypto/merklesignature`, `crypto/stateproof` and `data/stateproofmsg`, on
//! the read primitives of `logicsig_go.rs`.
//!
//! The REST submit (`decodeTxGroup`) is the caller: it reads one `SignedTxn`
//! after another from the body, and answers a failure with the error's text,
//! context path included (`... at Access at Txn`). This port reports how many
//! bytes the value took, or that text; the value itself is read afterwards by
//! algod-rust's own strict reader, which accepts and rejects the same bytes (the
//! reader is compared with go on every body of `raw_submit_texts.jsonl`).
//!
//! The generated code wraps the error of an *inline* struct (`Boxes` elements,
//! `ResourceRef.h/l/b`, `Reveal.s`) with the whole context path in one
//! `WrapError`, but the error of a struct reached through its own
//! `UnmarshalMsg` once per level; for the errors that carry their context in a
//! text suffix (`Wrapped`) the two differ, so each struct below is read as go's
//! generated code reads it. A byte or string field with an `allocbound` fails
//! with an unwrapped `ErrOverflow` (no field name); an array or map with one
//! fails with the field name.

use algo_types::go_msgp::{
    bounds, ENCODED_MAX_ACCOUNTS, ENCODED_MAX_APPLICATION_ARGS, ENCODED_MAX_BOXES,
    ENCODED_MAX_FOREIGN_APPS, ENCODED_MAX_FOREIGN_ASSETS, FALCON1024_MAX_SIGNATURE_SIZE,
    FALCON1024_PUBLIC_KEY_SIZE, MAX_GENESIS_ID_LEN, MAX_HASH_DIGEST_SIZE, MAX_PROOF_PATH_LEN,
    MAX_REVEALS, SHA256_SIZE, SUMHASH_DIGEST_SIZE, TX_TYPE_MAX_LEN,
};

use super::{
    lead, map_header_strict, overflow, read_array_header, read_bounded_bytes, read_exact,
    read_map_key, read_string, read_u64, read_u8, w, GoMsgpError, LsigState, MsigState, PqState, E,
    R,
};

/// How many bytes of `bytes` go's `SignedTxn.UnmarshalMsg` reads, or its error.
pub fn decode_signed_txn_go(bytes: &[u8]) -> Result<usize, GoMsgpError> {
    let mut b = bytes;
    signed_txn(&mut b).map_err(GoMsgpError)?;
    Ok(bytes.len() - b.len())
}

/// `ctx` joined with the member name: the context of an inline struct's member.
fn cx(ctx: &str, name: &str) -> String {
    if ctx.is_empty() {
        name.to_string()
    } else {
        format!("{ctx}/{name}")
    }
}

/// Reads the value of a known key; `false` for a key the struct lacks.
type FieldReader<'a> = dyn FnMut(&[u8], &mut &[u8]) -> R<bool> + 'a;

/// One generated map decoder. A failure of the header or of a key, and an
/// unknown key, is wrapped with `ctx` (empty for a struct read through its own
/// `UnmarshalMsg`, the path of an inline struct). `nil` runs for a `nil`
/// header (the struct is zeroed); `field` reads the value of a known key.
fn map_struct(
    b: &mut &[u8],
    ctx: &str,
    nil: &mut dyn FnMut(),
    field: &mut FieldReader<'_>,
) -> R<()> {
    let (n, is_nil) = w(map_header_strict(b), ctx)?;
    if is_nil {
        nil();
    }
    for _ in 0..n {
        let key = w(read_map_key(b), ctx)?;
        if !field(&key, b)? {
            return Err(E::NoField(key).wrap(ctx));
        }
    }
    Ok(())
}

/// A struct whose members are all plain: `table` maps a key to its Go field
/// name and kind.
fn table_struct(b: &mut &[u8], ctx: &str, table: &[(&[u8], &str, Kind)]) -> R<()> {
    map_struct(b, ctx, &mut || {}, &mut |key, b| {
        let Some((_, name, kind)) = table.iter().find(|(k, _, _)| *k == key) else {
            return Ok(false);
        };
        kind.read(b, &cx(ctx, name))?;
        Ok(true)
    })
}

/// The decode of one member, as the generated code does it.
#[derive(Clone, Copy)]
enum Kind {
    /// `msgp.ReadUint64Bytes` (also every `uint64`-based named type).
    U64,
    U32,
    U8,
    Bool,
    /// `msgp.ReadExactBytes` into an array of this size.
    Exact(usize),
    /// A `[]byte` with an `allocbound`; the overflow carries no field name.
    Bytes(fn() -> usize),
    /// A `string` with an `allocbound`.
    Str(fn() -> usize),
}

impl Kind {
    fn read(self, b: &mut &[u8], c: &str) -> R<()> {
        match self {
            Kind::U64 => w(read_u64(b).map(|_| ()), c),
            Kind::U32 => w(read_u32(b), c),
            Kind::U8 => w(read_u8(b).map(|_| ()), c),
            Kind::Bool => w(read_bool(b), c),
            Kind::Exact(n) => w(read_exact_n(b, n).map(|_| ()), c),
            Kind::Bytes(bound) => read_bounded_bytes(b, bound(), c).map(|_| ()),
            Kind::Str(bound) => read_bounded_str(b, bound(), c).map(|_| ()),
        }
    }
}

fn read_u32(b: &mut &[u8]) -> R<()> {
    let v = read_u64(b)?;
    if v > u64::from(u32::MAX) {
        return Err(E::UintOverflow {
            value: v,
            bits: 32,
            ctx: String::new(),
        });
    }
    Ok(())
}

/// `msgp.ReadBoolBytes`.
fn read_bool(b: &mut &[u8]) -> R<()> {
    match lead(b)? {
        0xc2 | 0xc3 | 0xc0 => {
            *b = &b[1..];
            Ok(())
        }
        l => Err(super::bad_prefix(super::Ty::Bool, l)),
    }
}

/// `msgp.ReadExactBytes` into a fresh array of `n` bytes.
fn read_exact_n(b: &mut &[u8], n: usize) -> R<Vec<u8>> {
    let mut v = vec![0u8; n];
    read_exact(b, &mut v)?;
    Ok(v)
}

/// A string whose claimed size is checked against `bound` first (the generated
/// `ReadBytesBytesHeader` check): the header and the read carry `ctx`, the
/// overflow does not.
fn read_bounded_str(b: &mut &[u8], bound: usize, ctx: &str) -> R<Vec<u8>> {
    let n = w(super::bytes_header_size(b), ctx)?;
    if n > bound {
        return Err(overflow(n, bound));
    }
    w(read_string(b), ctx)
}

/// The header of an array with an `allocbound`: both failures carry the name.
fn bounded_array(b: &mut &[u8], bound: usize, name: &str) -> R<usize> {
    let (n, _) = w(read_array_header(b, true), name)?;
    if n > bound {
        return Err(overflow(n, bound).wrap(name));
    }
    Ok(n)
}

/// `Address.UnmarshalMsg`, `crypto.Digest.UnmarshalMsg`, ...: an exact array
/// read through the type's own method (wrapped once with no context).
fn digest(b: &mut &[u8], n: usize) -> R<Vec<u8>> {
    w(read_exact_n(b, n), "")
}

fn addr(b: &mut &[u8]) -> R<Vec<u8>> {
    digest(b, 32)
}

/// A slice of `n` elements, each read by `elem` and wrapped with `name/i`.
fn slice_of(
    b: &mut &[u8],
    name: &str,
    bound: usize,
    elem: &mut dyn FnMut(&mut &[u8]) -> R<()>,
) -> R<()> {
    let n = bounded_array(b, bound, name)?;
    for i in 0..n {
        w(elem(b), &format!("{name}/{i}"))?;
    }
    Ok(())
}

// --- SignedTxn -------------------------------------------------------------

fn signed_txn(b: &mut &[u8]) -> R<()> {
    let sig = std::cell::RefCell::new([0u8; 64]);
    let msig = std::cell::RefCell::new(MsigState::default());
    let lsig = std::cell::RefCell::new(LsigState::default());
    let sksig = std::cell::RefCell::new(PqState::default());
    let txn_read = std::cell::Cell::new(false);
    map_struct(
        b,
        "",
        &mut || {
            *sig.borrow_mut() = [0u8; 64];
            *msig.borrow_mut() = MsigState::default();
            *lsig.borrow_mut() = LsigState::default();
            *sksig.borrow_mut() = PqState::default();
            txn_read.set(false);
        },
        &mut |key, b| {
            match key {
                b"sig" => w(w(read_exact(b, &mut sig.borrow_mut()[..]), ""), "Sig")?,
                b"msig" => w(msig.borrow_mut().decode(b), "Msig")?,
                b"lsig" => w(lsig.borrow_mut().decode(b), "Lsig")?,
                b"pqsig" => w(sksig.borrow_mut().decode(b), "SKsig")?,
                b"txn" => {
                    w(transaction(b), "Txn")?;
                    txn_read.set(true);
                }
                b"sgnr" => w(addr(b).map(|_| ()), "AuthAddr")?,
                _ => return Ok(false),
            }
            Ok(true)
        },
    )?;
    // `codec:"txn,required"`: `Txn.MsgIsZero()`. A decoded `Transaction` has a
    // type (its own required check), so it is zero only when never read.
    if !txn_read.get() {
        return Err(E::Required("missing required field: txn").wrap(""));
    }
    Ok(())
}

// --- Transaction -----------------------------------------------------------

fn transaction(b: &mut &[u8]) -> R<()> {
    let ty = std::cell::RefCell::new(Vec::<u8>::new());
    let snd = std::cell::RefCell::new([0u8; 32]);
    map_struct(
        b,
        "",
        &mut || {
            ty.borrow_mut().clear();
            *snd.borrow_mut() = [0u8; 32];
        },
        &mut |key, b| {
            match key {
                b"type" => {
                    // `TxType.UnmarshalMsg`: its own wrapping, then the field's
                    let v = w(read_bounded_str(b, TX_TYPE_MAX_LEN, ""), "Type")?;
                    *ty.borrow_mut() = v;
                }
                b"snd" => w(w(read_exact(b, &mut snd.borrow_mut()[..]), ""), "Sender")?,
                b"fee" => Kind::U64.read(b, "Fee")?,
                b"fv" => Kind::U64.read(b, "FirstValid")?,
                b"lv" => Kind::U64.read(b, "LastValid")?,
                b"note" => Kind::Bytes(|| bounds::MAX_TXN_NOTE_BYTES.get()).read(b, "Note")?,
                b"gen" => Kind::Str(|| MAX_GENESIS_ID_LEN).read(b, "GenesisID")?,
                b"gh" => w(digest(b, 32).map(|_| ()), "GenesisHash")?,
                b"grp" => w(digest(b, 32).map(|_| ()), "Group")?,
                b"lx" => Kind::Exact(32).read(b, "Lease")?,
                b"rekey" => w(addr(b).map(|_| ()), "RekeyTo")?,
                b"votekey" => w(digest(b, 32).map(|_| ()), "VotePK")?,
                b"selkey" => w(digest(b, 32).map(|_| ()), "SelectionPK")?,
                b"sprfkey" => w(digest(b, 64).map(|_| ()), "StateProofPK")?,
                b"votefst" => w(w(read_u64(b).map(|_| ()), ""), "VoteFirst")?,
                b"votelst" => w(w(read_u64(b).map(|_| ()), ""), "VoteLast")?,
                b"votekd" => Kind::U64.read(b, "VoteKeyDilution")?,
                b"nonpart" => Kind::Bool.read(b, "Nonparticipation")?,
                b"rcv" => w(addr(b).map(|_| ()), "Receiver")?,
                b"amt" => Kind::U64.read(b, "Amount")?,
                b"close" => w(addr(b).map(|_| ()), "CloseRemainderTo")?,
                b"caid" => Kind::U64.read(b, "ConfigAsset")?,
                b"apar" => w(asset_params(b), "AssetParams")?,
                b"xaid" => Kind::U64.read(b, "XferAsset")?,
                b"aamt" => Kind::U64.read(b, "AssetAmount")?,
                b"asnd" => w(addr(b).map(|_| ()), "AssetSender")?,
                b"arcv" => w(addr(b).map(|_| ()), "AssetReceiver")?,
                b"aclose" => w(addr(b).map(|_| ()), "AssetCloseTo")?,
                b"fadd" => w(addr(b).map(|_| ()), "FreezeAccount")?,
                b"faid" => Kind::U64.read(b, "FreezeAsset")?,
                b"afrz" => Kind::Bool.read(b, "AssetFrozen")?,
                b"apid" => Kind::U64.read(b, "ApplicationID")?,
                b"apan" => Kind::U64.read(b, "OnCompletion")?,
                b"apaa" => {
                    let name = "ApplicationArgs";
                    let n = bounded_array(b, ENCODED_MAX_APPLICATION_ARGS, name)?;
                    for i in 0..n {
                        w(super::read_bytes(b).map(|_| ()), &format!("{name}/{i}"))?;
                    }
                }
                b"apat" => slice_of(b, "Accounts", ENCODED_MAX_ACCOUNTS, &mut |b| {
                    addr(b).map(|_| ())
                })?,
                b"apas" => slice_of(b, "ForeignAssets", ENCODED_MAX_FOREIGN_ASSETS, &mut |b| {
                    read_u64(b).map(|_| ())
                })?,
                b"apfa" => slice_of(b, "ForeignApps", ENCODED_MAX_FOREIGN_APPS, &mut |b| {
                    read_u64(b).map(|_| ())
                })?,
                b"al" => slice_of(b, "Access", bounds::MAX_APP_ACCESS.get(), &mut |b| {
                    resource_ref(b)
                })?,
                b"apbx" => {
                    let name = "Boxes";
                    let n = bounded_array(b, ENCODED_MAX_BOXES, name)?;
                    for i in 0..n {
                        // an inline struct: every error carries the whole path
                        let ctx = format!("{name}/{i}");
                        table_struct(
                            b,
                            &ctx,
                            &[
                                (b"i", "Index", Kind::U64),
                                (
                                    b"n",
                                    "Name",
                                    Kind::Bytes(|| bounds::MAX_BYTES_KEY_VALUE_LEN.get()),
                                ),
                            ],
                        )?;
                    }
                }
                b"apls" => w(state_schema(b), "LocalStateSchema")?,
                b"apgs" => w(state_schema(b), "GlobalStateSchema")?,
                b"apap" => Kind::Bytes(|| bounds::MAX_AVAILABLE_APP_PROGRAM_LEN.get())
                    .read(b, "ApprovalProgram")?,
                b"apsu" => Kind::Bytes(|| bounds::MAX_AVAILABLE_APP_PROGRAM_LEN.get())
                    .read(b, "ClearStateProgram")?,
                b"apep" => Kind::U32.read(b, "ExtraProgramPages")?,
                b"aprv" => Kind::U64.read(b, "RejectVersion")?,
                b"sptype" => w(w(read_u64(b).map(|_| ()), ""), "StateProofType")?,
                b"sp" => w(state_proof(b), "StateProof")?,
                b"spmsg" => w(state_proof_message(b), "Message")?,
                b"hb" => {
                    if lead(b)? == 0xc0 {
                        *b = &b[1..];
                    } else {
                        w(heartbeat(b), "HeartbeatTxnFields")?;
                    }
                }
                _ => return Ok(false),
            }
            Ok(true)
        },
    )?;
    if ty.borrow().is_empty() {
        return Err(E::Required("missing required field: type").wrap(""));
    }
    if *snd.borrow() == [0u8; 32] {
        return Err(E::Required("missing required field: snd").wrap(""));
    }
    Ok(())
}

fn asset_params(b: &mut &[u8]) -> R<()> {
    table_struct(
        b,
        "",
        &[
            (b"t", "Total", Kind::U64),
            (b"dc", "Decimals", Kind::U32),
            (b"df", "DefaultFrozen", Kind::Bool),
            (
                b"un",
                "UnitName",
                Kind::Str(|| bounds::MAX_ASSET_UNIT_NAME_BYTES.get()),
            ),
            (
                b"an",
                "AssetName",
                Kind::Str(|| bounds::MAX_ASSET_NAME_BYTES.get()),
            ),
            (
                b"au",
                "URL",
                Kind::Str(|| bounds::MAX_ASSET_URL_BYTES.get()),
            ),
            (b"am", "MetadataHash", Kind::Exact(32)),
            (b"m", "Manager", Kind::Exact(32)),
            (b"r", "Reserve", Kind::Exact(32)),
            (b"f", "Freeze", Kind::Exact(32)),
            (b"c", "Clawback", Kind::Exact(32)),
        ],
    )
}

fn state_schema(b: &mut &[u8]) -> R<()> {
    table_struct(
        b,
        "",
        &[
            (b"nui", "NumUint", Kind::U64),
            (b"nbs", "NumByteSlice", Kind::U64),
        ],
    )
}

fn resource_ref(b: &mut &[u8]) -> R<()> {
    map_struct(b, "", &mut || {}, &mut |key, b| {
        match key {
            b"d" => w(addr(b).map(|_| ()), "Address")?,
            b"s" => Kind::U64.read(b, "Asset")?,
            b"p" => Kind::U64.read(b, "App")?,
            b"h" => table_struct(
                b,
                "Holding",
                &[(b"d", "Address", Kind::U64), (b"s", "Asset", Kind::U64)],
            )?,
            b"l" => table_struct(
                b,
                "Locals",
                &[(b"d", "Address", Kind::U64), (b"p", "App", Kind::U64)],
            )?,
            b"b" => table_struct(
                b,
                "Box",
                &[
                    (b"i", "Index", Kind::U64),
                    (
                        b"n",
                        "Name",
                        Kind::Bytes(|| bounds::MAX_BYTES_KEY_VALUE_LEN.get()),
                    ),
                ],
            )?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

// --- heartbeat -------------------------------------------------------------

fn heartbeat(b: &mut &[u8]) -> R<()> {
    map_struct(b, "", &mut || {}, &mut |key, b| {
        match key {
            b"a" => w(addr(b).map(|_| ()), "HbAddress")?,
            b"prf" => w(
                table_struct(
                    b,
                    "",
                    &[
                        (b"s", "Sig", Kind::Exact(64)),
                        (b"p", "PK", Kind::Exact(32)),
                        (b"p2", "PK2", Kind::Exact(32)),
                        (b"p1s", "PK1Sig", Kind::Exact(64)),
                        (b"p2s", "PK2Sig", Kind::Exact(64)),
                    ],
                ),
                "HbProof",
            )?,
            b"sd" => w(digest(b, 32).map(|_| ()), "HbSeed")?,
            b"vid" => w(digest(b, 32).map(|_| ()), "HbVoteID")?,
            b"kd" => Kind::U64.read(b, "HbKeyDilution")?,
            b"c" => Kind::Bool.read(b, "HbChallengeDiscount")?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

// --- state proof -----------------------------------------------------------

/// `crypto.GenericDigest.UnmarshalMsg`.
fn generic_digest(b: &mut &[u8]) -> R<()> {
    read_bounded_bytes(b, MAX_HASH_DIGEST_SIZE, "").map(|_| ())
}

/// `merklearray.Proof`.
fn merkle_proof(b: &mut &[u8]) -> R<()> {
    map_struct(b, "", &mut || {}, &mut |key, b| {
        match key {
            b"pth" => slice_of(b, "Path", MAX_PROOF_PATH_LEN, &mut |b| generic_digest(b))?,
            b"hsh" => w(hash_factory(b), "HashFactory")?,
            b"td" => Kind::U8.read(b, "TreeDepth")?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

/// `crypto.HashFactory`: after its members, `Validate` refuses a hash type
/// from `MaxHashType` on (`protocol.ErrInvalidObject`, returned unwrapped).
fn hash_factory(b: &mut &[u8]) -> R<()> {
    const MAX_HASH_TYPE: u64 = 4;
    let hash_type = std::cell::Cell::new(0u64);
    map_struct(b, "", &mut || hash_type.set(0), &mut |key, b| {
        match key {
            b"t" => {
                let v = w(read_u64(b), "HashType")?;
                if v > u64::from(u16::MAX) {
                    return Err(E::UintOverflow {
                        value: v,
                        bits: 16,
                        ctx: "HashType".to_string(),
                    });
                }
                hash_type.set(v);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    if hash_type.get() >= MAX_HASH_TYPE {
        return Err(E::Required("unmarshalled object is invalid"));
    }
    Ok(())
}

/// `merklesignature.Verifier`; `state` is its (commitment, key lifetime).
fn merkle_verifier(b: &mut &[u8], state: &mut ([u8; 64], u64)) -> R<()> {
    let st = std::cell::RefCell::new(state);
    map_struct(
        b,
        "",
        &mut || **st.borrow_mut() = ([0u8; 64], 0),
        &mut |key, b| {
            let mut s = st.borrow_mut();
            match key {
                b"cmt" => w(read_exact(b, &mut s.0[..]), "Commitment")?,
                b"lf" => {
                    s.1 = w(read_u64(b), "KeyLifetime")?;
                }
                _ => return Ok(false),
            }
            Ok(true)
        },
    )
}

/// `basics.Participant`.
fn participant(b: &mut &[u8]) -> R<()> {
    let pk = std::cell::RefCell::new(([0u8; 64], 0u64));
    map_struct(
        b,
        "",
        &mut || *pk.borrow_mut() = ([0u8; 64], 0),
        &mut |key, b| {
            match key {
                b"p" => w(merkle_verifier(b, &mut pk.borrow_mut()), "PK")?,
                b"w" => Kind::U64.read(b, "Weight")?,
                _ => return Ok(false),
            }
            Ok(true)
        },
    )?;
    let (cmt, lf) = *pk.borrow();
    if cmt == [0u8; 64] && lf == 0 {
        return Err(E::Required("missing required field: p").wrap(""));
    }
    Ok(())
}

/// `merklesignature.Signature`.
fn merkle_signature(b: &mut &[u8]) -> R<()> {
    map_struct(b, "", &mut || {}, &mut |key, b| {
        match key {
            b"sig" => w(
                read_bounded_bytes(b, FALCON1024_MAX_SIGNATURE_SIZE, "").map(|_| ()),
                "Signature",
            )?,
            b"idx" => Kind::U64.read(b, "VectorCommitmentIndex")?,
            b"prf" => w(merkle_proof(b), "Proof")?,
            b"vkey" => w(
                table_struct(
                    b,
                    "",
                    &[(b"k", "PublicKey", Kind::Exact(FALCON1024_PUBLIC_KEY_SIZE))],
                ),
                "VerifyingKey",
            )?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

/// `stateproof.Reveal`.
fn reveal(b: &mut &[u8]) -> R<()> {
    let part = std::cell::Cell::new(false);
    map_struct(b, "", &mut || part.set(false), &mut |key, b| {
        match key {
            // an inline struct: every error carries the whole path
            b"s" => map_struct(b, "SigSlot", &mut || {}, &mut |key, b| {
                match key {
                    b"s" => w(merkle_signature(b), "SigSlot/Sig")?,
                    b"l" => Kind::U64.read(b, "SigSlot/L")?,
                    _ => return Ok(false),
                }
                Ok(true)
            })?,
            b"p" => {
                w(participant(b), "Part")?;
                part.set(true);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    // `Part.MsgIsZero()`: a decoded `Participant` has a non-zero key
    if !part.get() {
        return Err(E::Required("missing required field: p").wrap(""));
    }
    Ok(())
}

/// `stateproof.StateProof`.
fn state_proof(b: &mut &[u8]) -> R<()> {
    map_struct(b, "", &mut || {}, &mut |key, b| {
        match key {
            b"c" => w(generic_digest(b), "SigCommit")?,
            b"w" => Kind::U64.read(b, "SignedWeight")?,
            b"S" => w(merkle_proof(b), "SigProofs")?,
            b"P" => w(merkle_proof(b), "PartProofs")?,
            b"v" => Kind::U8.read(b, "MerkleSignatureSaltVersion")?,
            b"r" => {
                let (n, _) = w(map_header_strict(b), "Reveals")?;
                if n > MAX_REVEALS {
                    return Err(overflow(n, MAX_REVEALS).wrap("Reveals"));
                }
                for _ in 0..n {
                    let k = w(read_u64(b), "Reveals")?;
                    w(reveal(b), &format!("Reveals/{k}"))?;
                }
            }
            b"pr" => slice_of(b, "PositionsToReveal", MAX_REVEALS, &mut |b| {
                read_u64(b).map(|_| ())
            })?,
            _ => return Ok(false),
        }
        Ok(true)
    })
}

/// `stateproofmsg.Message`.
fn state_proof_message(b: &mut &[u8]) -> R<()> {
    table_struct(
        b,
        "",
        &[
            (b"b", "BlockHeadersCommitment", Kind::Bytes(|| SHA256_SIZE)),
            (
                b"v",
                "VotersCommitment",
                Kind::Bytes(|| SUMHASH_DIGEST_SIZE),
            ),
            (b"P", "LnProvenWeight", Kind::U64),
            (b"f", "FirstAttestedRound", Kind::U64),
            (b"l", "LastAttestedRound", Kind::U64),
        ],
    )
}
