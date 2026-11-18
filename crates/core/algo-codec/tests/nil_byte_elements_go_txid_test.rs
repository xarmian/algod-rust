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

//! Issue #2430: a nil element of a `[][]byte` list (`apaa`, LogicSig `arg`)
//! is kept nil by go and re-encoded as msgpack `nil`, so it is part of the
//! TxID and of the signed transaction's canonical bytes.
//!
//! The expected values are go v5.0.5-stable's, printed by a throwaway test in
//! `data/transactions` for
//! `Transaction{Type: appl, Sender: 0x01*32, Fee: 1000, FirstValid: 1,
//! LastValid: 100, ApplicationID: 5, ApplicationArgs: {nil, {}, "a"}}` and a
//! `SignedTxn` wrapping it with `Lsig{Logic: 01200101 22, Args: {nil, {}, "b"}}`:
//! `protocol.Encode(&tx)`, `tx.ID()`, `protocol.Encode(&stx)`.

use algo_codec::{
    canonical_encode_signed_transaction, canonical_encode_transaction, compute_txn_id,
};
use algo_types::{SignedTransaction, Transaction};

const GO_TXN_HEX: &str = "87a46170616193c0c400c40161a46170696405a3666565cd03e8a2667601a26c7664\
a3736e64c4200101010101010101010101010101010101010101010101010101010101010101a474797065a46170706c";
const GO_TXID: &str = "WI36GGAOCYXXCVIV5HM3FGYRDQ7UB3C2WZ6HTASSFNHSP3RJEJWQ";
const GO_STXN_HEX: &str = "82a46c73696782a361726793c0c400c40162a16cc4050120010122a374786e87a46170\
616193c0c400c40161a46170696405a3666565cd03e8a2667601a26c7664a3736e64c42001010101010101010101010101\
01010101010101010101010101010101010101a474797065a46170706c";

#[test]
fn nil_app_arg_keeps_gos_txid() {
    let raw = hex::decode(GO_TXN_HEX).unwrap();
    let tx = Transaction::decode_from_bytes(&raw).unwrap();
    let args = tx.app_arguments.as_ref().unwrap();
    assert_eq!(args[0], None, "nil element stays nil");
    assert_eq!(
        args[1].as_ref().map(|a| a.len()),
        Some(0),
        "bin0 stays empty"
    );
    assert_eq!(hex::encode(canonical_encode_transaction(&tx)), GO_TXN_HEX);
    assert_eq!(compute_txn_id(&tx).to_string(), GO_TXID);
}

#[test]
fn nil_app_arg_and_lsig_arg_keep_gos_signed_txn_bytes() {
    let raw = hex::decode(GO_STXN_HEX).unwrap();
    let stx = SignedTransaction::decode_from_reader(&mut &raw[..]).unwrap();
    let lsig = stx.lsig.as_ref().unwrap();
    assert_eq!(lsig.args.as_ref().unwrap()[0], None);
    assert_eq!(
        hex::encode(canonical_encode_signed_transaction(&stx)),
        GO_STXN_HEX
    );
    assert_eq!(compute_txn_id(&stx.txn).to_string(), GO_TXID);
    // the serde fallback decoder agrees
    let serde: SignedTransaction = rmp_serde::from_slice(&raw).unwrap();
    assert_eq!(
        hex::encode(canonical_encode_signed_transaction(&serde)),
        GO_STXN_HEX
    );
}
