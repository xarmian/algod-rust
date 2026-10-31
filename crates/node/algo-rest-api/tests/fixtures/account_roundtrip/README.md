# Account / asset / application roundtrip fixtures

go-algorand v5.0.4-stable reference responses, used by
`tests/account_roundtrip_test.rs` to verify the Rust REST responses match Go.

- `<name>.account.json` — `model.Account` via `AccountDataToAccount` +
  `encoding/json` (what echo's `ctx.JSON` writes, i.e. the JSON endpoint body;
  keeps non-nil empty `*[]T` / zero-struct pointers, see #2156).
- `<name>.accountdata.msgpack` — the raw `basics.AccountData` via `CodecHandle`
  (the msgpack endpoint body; the account endpoint returns the raw record for
  msgpack, not the model).
- `<name>.meta.json` — address, round, amount-without-pending-rewards.
- `asset.json` / `application.json` — standalone `model.Asset` /
  `model.Application` via `AssetParamsToAsset` / `AppParamsToApplication`.

The Rust side constructs the same `AccountData` / params (the msgpack test
confirms construction parity byte-for-byte), builds the response, and compares
JSON field-for-field (order-independent) and msgpack byte-for-byte.

## Regenerating

The generators import go-algorand packages, so they must run inside a
`../go-algorand` checkout at `v5.0.4-stable` (the repo's reference pin) with
`make libsodium` done (cgo). Copy each into a scratch `main` package there:

    mkdir tmpgen && cp gen_accounts.go tmpgen/main.go && go run ./tmpgen <out-dir>
    mkdir tmpgen2 && cp gen_asset_app.go tmpgen2/main.go && go run ./tmpgen2 <out-dir>

Last regenerated against `v5.0.4-stable` with Go 1.25.3 (#2156): the output is
byte-identical to the committed files (`.gitattributes` pins them to LF; never
let autocrlf rewrite them).
