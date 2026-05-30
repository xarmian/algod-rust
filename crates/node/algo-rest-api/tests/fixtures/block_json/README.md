# Block JSON golden fixtures

Byte-for-byte references for `GET /v2/blocks/{round}?format=json`, produced by
go-algorand v4.5.1-stable's `protocol.JSONStrictHandle` (the encoder its
`GetBlock` handler uses). `<name>.json` is the canonical JSON for the block in
`<name>.msgpack` (a raw `{block, cert}` response). `algo_rest_api::block_json::
encode_block_json` must reproduce these exactly; see `tests/block_json_test.rs`.

The `block*.msgpack` inputs are copied from
`crates/core/algo-codec/tests/fixtures/`. `synthetic_appl.{msgpack,json}` is a
block with a rich app-call eval-delta (global/local deltas, logs incl. a binary
log, app args/accounts, and a nested inner transaction), generated to exercise
the eval-delta and inner-transaction paths.

## Regenerating

With `../go-algorand` checked out at `v4.5.1-stable`, run the Go programs in
this directory's git history (`gen_golden.go` / `gen_synthetic.go`) against the
msgpack inputs:

    go run gen_golden.go <input.msgpack>            # prints canonical JSON
    go run gen_synthetic.go <base.msgpack> <out.msgpack> <out.json>
