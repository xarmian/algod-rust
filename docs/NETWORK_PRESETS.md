# Network presets

`--network <name>` is backed by one table, `PRESETS` in
`bin/algod-rust/src/commands/network_common.rs` (`NetworkPreset`). Adding a chain
is one row plus its fixtures; nothing else matches on network-name strings.

| Field | Meaning |
|---|---|
| `name` | the `--network` value |
| `genesis_id` / `fixed_genesis_id` | full genesis id (`{network}-{id}`); `fixed_genesis_id` is false for `devnet` |
| `genesis_json` | byte-exact vendored genesis, served on `/genesis` when no `--genesis-path` is found |
| `rest_url` | default public algod REST endpoint for catchup/follow (`resolve_network`) |
| `dns_bootstrap_id` | chain-specific `DNSBootstrapID`; used when `config.json` still has go's stock default and no `--dns-bootstrap` is given |
| `catchpoint_index_url` | static `latest.catchpoint` index; `None` falls back to the peer's `/v2/status.last-catchpoint` |
| `consensus_json` | bundled custom consensus protocols (reserved, aramidmain #2070) |

The genesis hash is not duplicated in the table: it comes from
`algo_types::Network` (the algokey keyreg table, which also accepts the preset
names) and is pinned against the fixture by
`crates/core/algo-ledger/tests/genesis_test.rs` and
`network_common::tests::presets_are_internally_consistent`.

## voimain (Voi mainnet)

- Genesis id `voimain-v1.0`, genesis hash `r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk=`.
- Vendored genesis: `crates/core/algo-ledger/tests/fixtures/voimain-genesis.json`
  (provenance in `voimain-genesis.README.md`).
- REST: `https://mainnet-api.voi.nodely.dev` (go-algorand 5.0.4-based build,
  standard Algorand consensus versions).
- Relay discovery: Voi publishes SRV records (not under `voi.network`); the
  template was found in the Voi node image's config
  (`VoiNetwork/voi-node`, `configuration/mainnet/participation/config.json`):
  `<network>.mainnet-voi.network?backup=<network>.mainnet-voi.net&dedup=<name>.mainnet-voi.(network|net)`,
  which for network `voimain` resolves `_algobootstrap._tcp.voimain.mainnet-voi.network`
  to `r-eu-*.mainnet-voi.network:5011`. Verified with `nslookup -type=SRV`.
  `--relay-addr`/`--peers` still override DNS discovery.
- Catchup: no static catchpoint index; use the label from
  `GET https://mainnet-api.voi.nodely.dev/v2/status` (`last-catchpoint`).
  The public gateway answers `HEAD /v1/voimain-v1.0/ledger/<r>` with 204 but
  `GET` with 404, so the catchpoint file must come from a relay, e.g.:

  ```
  algod-rust sync --network voimain --catchpoint <label> --follow \
    --catchpoint-peer-url http://r-na-1f40f6f89767.mainnet-voi.network:5011
  ```

  (Use the REST backend, i.e. without `--gossip`: the gossip backend ignores
  `--catchpoint-peer-url`, tracked in #2076. Relays that return 404 for the
  catchpoint are simply ranked down.)
- Live evidence (2026-10-25): catchup from `23900000#KFAWCWWDOOSID3YYDJZOWIYYVW2KEKLMVPF5BHBLY6CFRCARJFMA`,
  replay of 4388 blocks, then follow mode with zero apply failures (see the
  PR for the log excerpt).
