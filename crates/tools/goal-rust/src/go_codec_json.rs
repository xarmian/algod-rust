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

//! The Go answer types goal decodes with go-codec's JSON decoder (issue
//! #2466); the decoder itself is [`algo_codec::go_codec_json`].

pub use algo_codec::go_codec_json::{decode, decode_reading, Error, Field, Ty};

// ---- the Go types goal reads ----------------------------------------------

const ROUND: Ty = Ty::U64;

/// `model.ApplicationStateSchema`.
pub const APPLICATION_STATE_SCHEMA: Ty =
    Ty::Struct(&[Field("num-byte-slice", Ty::U64), Field("num-uint", Ty::U64)]);

/// `model.TealValue`.
const TEAL_VALUE: Ty = Ty::Struct(&[
    Field("bytes", Ty::Str),
    Field("type", Ty::U64),
    Field("uint", Ty::U64),
]);

/// `model.TealKeyValueStore` (`[]model.TealKeyValue`).
const TEAL_KEY_VALUE_STORE: Ty = Ty::Slice(
    &Ty::Struct(&[Field("key", Ty::Str), Field("value", TEAL_VALUE)]),
    "[]model.TealKeyValue",
);

/// `model.ApplicationLocalState`.
const APPLICATION_LOCAL_STATE: Ty = Ty::Struct(&[
    Field("id", Ty::U64),
    Field("key-value", Ty::Ptr(&TEAL_KEY_VALUE_STORE)),
    Field("schema", APPLICATION_STATE_SCHEMA),
]);

/// `model.AssetHolding`.
const ASSET_HOLDING: Ty = Ty::Struct(&[
    Field("amount", Ty::U64),
    Field("asset-id", Ty::U64),
    Field("is-frozen", Ty::Bool),
]);

/// `model.ApplicationParams`.
const APPLICATION_PARAMS: Ty = Ty::Struct(&[
    Field("approval-program", Ty::Bytes),
    Field("clear-state-program", Ty::Bytes),
    Field("creator", Ty::Str),
    Field("extra-program-pages", Ty::Ptr(&Ty::U64)),
    Field("family-box-access", Ty::Ptr(&Ty::Bool)),
    Field("foreign-box-reads", Ty::Ptr(&Ty::Bool)),
    Field("global-state", Ty::Ptr(&TEAL_KEY_VALUE_STORE)),
    Field("global-state-schema", Ty::Ptr(&APPLICATION_STATE_SCHEMA)),
    Field("local-state-schema", Ty::Ptr(&APPLICATION_STATE_SCHEMA)),
    Field("size-sponsor", Ty::Ptr(&Ty::Str)),
    Field("version", Ty::Ptr(&Ty::U64)),
]);

/// `model.AssetParams`.
const ASSET_PARAMS: Ty = Ty::Struct(&[
    Field("clawback", Ty::Ptr(&Ty::Str)),
    Field("creator", Ty::Str),
    Field("decimals", Ty::U64),
    Field("default-frozen", Ty::Ptr(&Ty::Bool)),
    Field("freeze", Ty::Ptr(&Ty::Str)),
    Field("manager", Ty::Ptr(&Ty::Str)),
    Field("metadata-hash", Ty::Ptr(&Ty::Bytes)),
    Field("name", Ty::Ptr(&Ty::Str)),
    Field("name-b64", Ty::Ptr(&Ty::Bytes)),
    Field("reserve", Ty::Ptr(&Ty::Str)),
    Field("total", Ty::U64),
    Field("unit-name", Ty::Ptr(&Ty::Str)),
    Field("unit-name-b64", Ty::Ptr(&Ty::Bytes)),
    Field("url", Ty::Ptr(&Ty::Str)),
    Field("url-b64", Ty::Ptr(&Ty::Bytes)),
]);

/// `model.AccountParticipation`.
const ACCOUNT_PARTICIPATION: Ty = Ty::Struct(&[
    Field("selection-participation-key", Ty::Bytes),
    Field("state-proof-key", Ty::Ptr(&Ty::Bytes)),
    Field("vote-first-valid", ROUND),
    Field("vote-key-dilution", Ty::U64),
    Field("vote-last-valid", ROUND),
    Field("vote-participation-key", Ty::Bytes),
]);

/// `model.Account` (`GET /v2/accounts/{address}`).
pub const ACCOUNT: Ty = Ty::Struct(&[
    Field("address", Ty::Str),
    Field("amount", Ty::U64),
    Field("amount-without-pending-rewards", Ty::U64),
    Field(
        "apps-local-state",
        Ty::Ptr(&Ty::Slice(
            &APPLICATION_LOCAL_STATE,
            "[]model.ApplicationLocalState",
        )),
    ),
    Field("apps-total-extra-pages", Ty::Ptr(&Ty::U64)),
    Field("apps-total-schema", Ty::Ptr(&APPLICATION_STATE_SCHEMA)),
    Field(
        "assets",
        Ty::Ptr(&Ty::Slice(&ASSET_HOLDING, "[]model.AssetHolding")),
    ),
    Field("auth-addr", Ty::Ptr(&Ty::Str)),
    Field(
        "created-apps",
        Ty::Ptr(&Ty::Slice(
            &Ty::Struct(&[
                Field("id", Ty::U64),
                Field("params", Ty::Ptr(&APPLICATION_PARAMS)),
            ]),
            "[]model.Application",
        )),
    ),
    Field(
        "created-assets",
        Ty::Ptr(&Ty::Slice(
            &Ty::Struct(&[
                Field("index", Ty::U64),
                Field("params", Ty::Ptr(&ASSET_PARAMS)),
            ]),
            "[]model.Asset",
        )),
    ),
    Field("incentive-eligible", Ty::Ptr(&Ty::Bool)),
    Field("last-heartbeat", Ty::Ptr(&ROUND)),
    Field("last-proposed", Ty::Ptr(&ROUND)),
    Field("min-balance", Ty::U64),
    Field("participation", Ty::Ptr(&ACCOUNT_PARTICIPATION)),
    Field("pending-rewards", Ty::U64),
    Field("reward-base", Ty::Ptr(&Ty::U64)),
    Field("rewards", Ty::U64),
    Field("round", ROUND),
    Field("sig-type", Ty::Ptr(&Ty::Str)),
    Field("status", Ty::Str),
    Field("total-apps-opted-in", Ty::U64),
    Field("total-assets-opted-in", Ty::U64),
    Field("total-box-bytes", Ty::Ptr(&Ty::U64)),
    Field("total-boxes", Ty::Ptr(&Ty::U64)),
    Field("total-created-apps", Ty::U64),
    Field("total-created-assets", Ty::U64),
]);

/// `common.Version` (`GET /versions`).
pub const VERSION: Ty = Ty::Struct(&[
    Field("versions", Ty::Strings),
    Field("genesis_id", Ty::Str),
    Field("genesis_hash_b64", Ty::Bytes),
    Field(
        "build",
        Ty::Struct(&[
            Field("major", Ty::I64),
            Field("minor", Ty::I64),
            Field("build_number", Ty::I64),
            Field("commit_hash", Ty::Str),
            Field("branch", Ty::Str),
            Field("channel", Ty::Str),
        ]),
    ),
]);

/// `model.NodeStatusResponse` (`GET /v2/status`).
pub const NODE_STATUS: Ty = Ty::Struct(&[
    Field("catchpoint", Ty::Ptr(&Ty::Str)),
    Field("catchpoint-acquired-blocks", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-processed-accounts", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-processed-kvs", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-total-accounts", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-total-blocks", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-total-kvs", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-verified-accounts", Ty::Ptr(&Ty::U64)),
    Field("catchpoint-verified-kvs", Ty::Ptr(&Ty::U64)),
    Field("catchup-time", Ty::I64),
    Field("last-catchpoint", Ty::Ptr(&Ty::Str)),
    Field("last-round", ROUND),
    Field("last-version", Ty::Str),
    Field("next-version", Ty::Str),
    Field("next-version-round", ROUND),
    Field("next-version-supported", Ty::Bool),
    Field("stopped-at-unsupported-round", Ty::Bool),
    Field("time-since-last-round", Ty::I64),
    Field("upgrade-delay", Ty::Ptr(&ROUND)),
    Field("upgrade-next-protocol-vote-before", Ty::Ptr(&ROUND)),
    Field("upgrade-no-votes", Ty::Ptr(&ROUND)),
    Field("upgrade-node-vote", Ty::Ptr(&Ty::Bool)),
    Field("upgrade-vote-rounds", Ty::Ptr(&ROUND)),
    Field("upgrade-votes", Ty::Ptr(&ROUND)),
    Field("upgrade-votes-required", Ty::Ptr(&ROUND)),
    Field("upgrade-yes-votes", Ty::Ptr(&ROUND)),
]);

/// `model.SupplyResponse` (`GET /v2/ledger/supply`).
pub const SUPPLY: Ty = Ty::Struct(&[
    Field("current_round", ROUND),
    Field("online-money", Ty::U64),
    Field("online-stake", Ty::U64),
    Field("total-money", Ty::U64),
]);

/// `model.Asset` (`GET /v2/assets/{asset-id}`).
pub const ASSET: Ty = Ty::Struct(&[
    Field("index", Ty::U64),
    Field("params", Ty::Ptr(&ASSET_PARAMS)),
]);

/// `model.Application` (`GET /v2/applications/{application-id}`).
pub const APPLICATION: Ty = Ty::Struct(&[
    Field("id", Ty::U64),
    Field("params", Ty::Ptr(&APPLICATION_PARAMS)),
]);

/// `model.AccountAssetsInformationResponse` (`GET
/// /v2/accounts/{address}/assets`).
pub const ACCOUNT_ASSETS_INFORMATION: Ty = Ty::Struct(&[
    Field(
        "asset-holdings",
        Ty::Ptr(&Ty::Slice(
            &Ty::Struct(&[
                Field("asset-holding", ASSET_HOLDING),
                Field("asset-params", Ty::Ptr(&ASSET_PARAMS)),
            ]),
            "[]model.AccountAssetHolding",
        )),
    ),
    Field("next-token", Ty::Ptr(&Ty::Str)),
    Field("round", ROUND),
]);

/// `model.AccountAssetResponse` (`GET
/// /v2/accounts/{address}/assets/{asset-id}`).
pub const ACCOUNT_ASSET: Ty = Ty::Struct(&[
    Field("asset-holding", Ty::Ptr(&ASSET_HOLDING)),
    Field("created-asset", Ty::Ptr(&ASSET_PARAMS)),
    Field("round", ROUND),
]);

/// `model.ParticipationKeysResponse` (`GET /v2/participation`).
pub const PARTICIPATION_KEYS: Ty = Ty::Slice(
    &Ty::Struct(&[
        Field("address", Ty::Str),
        Field("effective-first-valid", Ty::Ptr(&ROUND)),
        Field("effective-last-valid", Ty::Ptr(&ROUND)),
        Field("id", Ty::Str),
        Field("key", ACCOUNT_PARTICIPATION),
        Field("last-block-proposal", Ty::Ptr(&ROUND)),
        Field("last-state-proof", Ty::Ptr(&ROUND)),
        Field("last-vote", Ty::Ptr(&ROUND)),
    ]),
    "[]model.ParticipationKey",
);

/// `model.PostParticipationResponse` (`POST /v2/participation`).
pub const POST_PARTICIPATION: Ty = Ty::Struct(&[Field("partId", Ty::Str)]);

/// `model.CatchpointStartResponse` / `model.CatchpointAbortResponse`
/// (`POST` / `DELETE /v2/catchup/{catchpoint}`).
pub const CATCHPOINT_RESPONSE: Ty = Ty::Struct(&[Field("catchup-message", Ty::Str)]);

/// `model.TransactionParametersResponse` (`GET /v2/transactions/params`).
pub const TRANSACTION_PARAMETERS: Ty = Ty::Struct(&[
    Field("consensus-version", Ty::Str),
    Field("fee", Ty::U64),
    Field("genesis-hash", Ty::Bytes),
    Field("genesis-id", Ty::Str),
    Field("last-round", ROUND),
    Field("min-fee", Ty::U64),
]);

/// `model.BoxResponse` (`GET /v2/applications/{application-id}/box`).
pub const BOX: Ty = Ty::Struct(&[
    Field("name", Ty::Bytes),
    Field("round", ROUND),
    Field("value", Ty::Bytes),
]);

/// `model.BoxesResponse` (`GET /v2/applications/{application-id}/boxes`).
pub const BOXES: Ty = Ty::Struct(&[
    Field(
        "boxes",
        Ty::Slice(
            &Ty::Struct(&[
                Field("name", Ty::Bytes),
                Field("value", Ty::Ptr(&Ty::Bytes)),
            ]),
            "[]model.BoxDescriptor",
        ),
    ),
    Field("next-token", Ty::Ptr(&Ty::Str)),
    Field("round", Ty::Ptr(&ROUND)),
]);

/// `libgoal.PendingTransactions` (`GET /v2/transactions/pending?format=msgpack`,
/// go-codec's msgpack decode: its `json` tags name the keys).
pub const PENDING_TRANSACTIONS: Ty = Ty::Struct(&[
    Field(
        "top-transactions",
        Ty::Slice(
            &algo_rest_api::simulate_request_schema::TRANSACTIONS_SIGNEDTXN,
            "[]transactions.SignedTxn",
        ),
    ),
    Field("total-transactions", Ty::U64),
]);

/// `model.PostTransactionsResponse` (`POST /v2/transactions`).
pub const POST_TRANSACTIONS: Ty = Ty::Struct(&[Field("txId", Ty::Str)]);

/// `model.StateDelta` (`[]model.EvalDeltaKeyValue`).
const STATE_DELTA: Ty = Ty::Slice(
    &Ty::Struct(&[
        Field("key", Ty::Str),
        Field(
            "value",
            Ty::Struct(&[
                Field("action", Ty::U64),
                Field("bytes", Ty::Ptr(&Ty::Str)),
                Field("uint", Ty::Ptr(&Ty::U64)),
            ]),
        ),
    ]),
    "[]model.EvalDeltaKeyValue",
);

/// `model.PendingTransactionResponse` (`GET
/// /v2/transactions/pending/{txid}`); its `inner-txns` are of the same type.
pub static PENDING_TRANSACTION: Ty = Ty::Struct(&[
    Field("application-index", Ty::Ptr(&Ty::U64)),
    Field("asset-closing-amount", Ty::Ptr(&Ty::U64)),
    Field("asset-index", Ty::Ptr(&Ty::U64)),
    Field("close-rewards", Ty::Ptr(&Ty::I64)),
    Field("closing-amount", Ty::Ptr(&Ty::U64)),
    Field("confirmed-round", Ty::Ptr(&ROUND)),
    Field("global-state-delta", Ty::Ptr(&STATE_DELTA)),
    Field(
        "inner-txns",
        Ty::Ptr(&Ty::Slice(
            &PENDING_TRANSACTION,
            "[]model.PendingTransactionResponse",
        )),
    ),
    Field(
        "local-state-delta",
        Ty::Ptr(&Ty::Slice(
            &Ty::Struct(&[Field("address", Ty::Str), Field("delta", STATE_DELTA)]),
            "[]model.AccountStateDelta",
        )),
    ),
    Field("logs", Ty::Ptr(&Ty::Slice(&Ty::Bytes, "[][]uint8"))),
    Field("pool-error", Ty::Str),
    Field("receiver-rewards", Ty::Ptr(&Ty::U64)),
    Field("sender-rewards", Ty::Ptr(&Ty::U64)),
    Field("txn", Ty::Map(&Ty::Str, &Ty::Any)),
]);

#[cfg(test)]
mod tests {
    use super::*;

    fn err(body: &str, ty: &'static Ty) -> String {
        decode(body.as_bytes(), ty).unwrap_err().to_string()
    }

    #[test]
    fn errors_read_like_go_codec() {
        assert_eq!(
            err(r#"{"amount":5,"foo":1}"#, &ACCOUNT),
            "json decode error [pos 18]: no matching struct field found when decoding stream map with key foo"
        );
        assert_eq!(err(r#"{"address":"abc"#, &ACCOUNT), "EOF");
        assert_eq!(
            err(r#"{"amount":"#, &ACCOUNT),
            "json decode error [pos 10]: read map key - expect char ',' but got char ':'"
        );
        assert_eq!(
            err(r#"{"address":"\u12"}"#, &ACCOUNT),
            "json decode error [pos 17]: runtime error: index out of range [6] with length 5"
        );
        assert_eq!(
            err("", &ACCOUNT),
            "json decode error [pos 0]: only encoded map or array can be decoded into a struct"
        );
        assert_eq!(
            err(r#"{"":1}"#, &ACCOUNT),
            "json decode error [pos 4]: runtime error: index out of range [0] with length 0"
        );
        // go-codec never returns from these (the slice grows until the
        // process runs out of memory)
        assert_eq!(err(r#"{"versions":[1,"#, &VERSION), "EOF");
        assert_eq!(
            err(
                r#"{"created-apps":[{"id":1,"params":{"approval-program":[1,"#,
                &ACCOUNT
            ),
            "EOF"
        );
    }

    #[test]
    fn go_codec_accepts_what_json_does_not() {
        let v = decode(br#"{"amount":"42","address":true}xyz"#, &ACCOUNT).unwrap();
        assert_eq!(v["amount"], 42);
        assert_eq!(v["address"], "true");
        let v = decode(b"[1,2]", &ACCOUNT).unwrap();
        assert_eq!(
            (v["address"].as_str(), v["amount"].as_u64()),
            (Some("1"), Some(2))
        );
        assert_eq!(decode(b"null", &ACCOUNT).unwrap()["amount"], 0);
        assert_eq!(
            decode(br#"{"amount":1e3}"#, &ACCOUNT).unwrap()["amount"],
            1000
        );
    }
}
