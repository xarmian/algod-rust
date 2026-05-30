# Account / asset / application roundtrip fixtures

go-algorand v4.5.1-stable reference responses, used by
`tests/account_roundtrip_test.rs` to verify the Rust REST responses match Go.

- `<name>.account.json` — `model.Account` via `AccountDataToAccount` +
  `JSONStrictHandle` (the JSON endpoint body).
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

With `../go-algorand` at `v4.5.1-stable`:

    go run gen_accounts.go <out-dir>      # account fixtures
    go run gen_asset_app.go <out-dir>     # standalone asset/app fixtures
