# Network presets

`--network <name>` is backed by one table, `PRESETS` in
`bin/algod-rust/src/commands/network_common.rs` (`NetworkPreset`). Adding a chain
is one row plus its fixtures. Network-name strings are still matched in a few
places outside the table; a new chain must review each:

- `crates/node/algo-network/src/dns_bootstrap.rs` (`network_bootstrap_override`:
  hardcoded devnet/betanet/alphanet bootstrap hosts, bypassed when a template
  is overridden, which presets with their own `dns_bootstrap_id` do).
- `crates/core/algo-types/src/consensus.rs` (`SHORTER_UPGRADE_ROUNDS_NETWORKS`:
  devnet/betanet/fnet upgrade-delay shortening).
- `docker/algod/run.sh` (`NETWORK` -> `DNSBootstrapID`) and `docs/DOCKER_MIGRATION.md`.
- `crates/core/algo-types/src/networks.rs` (`Network`, algokey hash table).

The preset -> `Network` hash linkage is currently enforced by tests only
(`presets_are_internally_consistent`), not by the type system.

| Field | Meaning |
|---|---|
| `name` | the `--network` value |
| `genesis_id` / `fixed_genesis_id` | full genesis id (`{network}-{id}`); `fixed_genesis_id` is false for `devnet` |
| `genesis_json` | byte-exact vendored genesis, served on `/genesis` when no `--genesis-path` is found |
| `rest_url` | default public algod REST endpoint for catchup/follow (`resolve_network`) |
| `dns_bootstrap_id` | chain-specific `DNSBootstrapID`; used when `config.json` still has go's stock default and no `--dns-bootstrap` is given |
| `catchpoint_index_url` | static `latest.catchpoint` index; `None` falls back to the peer's `/v2/status.last-catchpoint` |
| `consensus_json` | bundled custom consensus protocols (aramidmain, #2070); only versions the binary does not already define are merged (DIV-006), a `<data_dir>/consensus.json` is merged on top |

The genesis hash is not duplicated in the table: it comes from
`algo_types::Network` (the algokey keyreg table, which also accepts the preset
names) and is pinned against the fixture by
`crates/core/algo-ledger/tests/genesis_test.rs` and
`network_common::tests::presets_are_internally_consistent`.

## voimain (Voi mainnet)

- Genesis id `voimain-v1.0`, genesis hash `r20fSQI8gWe/kFZziNonSPCXLwcQmH/nxROvnnueWOk=`.
- Vendored genesis: `bin/algod-rust/genesis/voimain-genesis.json`
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
- Voi's catchpoints are file version V7 (no `onlineaccounts` data). The importer
  rebuilds `onlineaccounts` from `accountbase` at cutover, as go-algorand's
  v7 DB migration does (#2088); without it every post-catchpoint vote failed
  `OTS signature verification failed`.
- Docker image (issue #2074): `ghcr.io/xarmian/algod-rust:<tag>-voimain` follows Voi out
  of the box with fast catchup from the gateway's `last-catchpoint`; see
  `docs/DOCKER_MIGRATION.md`.
- Nightly soak (issue #2072): `.github/workflows/voimain-node-soak.yml`
  (05:40 UTC daily, plus `workflow_dispatch`; staggered after the 04:20
  mainnet soak) calls the reusable `network-node-soak.yml` with
  `probe_catchpoint_file: "true"`. Only some SRV relays serve the catchpoint
  file (2 of 8 on 2026-10-25: r-na-1f40f6f89767, r-eu-6b7963e1f2ab), so the
  soak probes each relay for `GET /v1/voimain-v1.0/ledger/<round base36>` and
  uses the first 200 as `--catchup-peer`; the label comes from the gateway's
  `/v2/status`. Voi block time measured at ~2.8 s, so mainnet's 5 min halt
  threshold (~107 blocks) is unchanged. Auto-filed halt issues carry the
  `voimain-soak` label and dedup only against it. Override the gateway with
  the `VOIMAIN_ALGOD_URL` repo variable.
- Live evidence (2026-10-25): catchup from `23900000#KFAWCWWDOOSID3YYDJZOWIYYVW2KEKLMVPF5BHBLY6CFRCARJFMA`,
  replay of 4388 blocks, then follow mode with zero apply failures (see the
  PR for the log excerpt).

## Scope of the preset behaviours (read before adding a chain)

- **Vendored genesis** (`genesis_json`) is used only by `participate`
  (`vendored_genesis_json`): it serves `/genesis`, and seeds a fresh ledger
  when `--genesis-json` is not given. It is used only when the genesis id
  resolved from the ledger equals the preset's id. `sync`, `replay`,
  `relay` and `catchpoint` do not use it (they take genesis from the peer or
  an explicit `--genesis`/`--genesis-json`).
- **DNS bootstrap** (`effective_dns_bootstrap`) decides "operator did not
  customise `DNSBootstrapID`" by string equality with go's stock template.
  This is a heuristic: an operator who explicitly sets the stock value in
  `config.json` still gets the preset's template. `--dns-bootstrap` always wins.

## aramidmain (Aramid mainnet)

- Genesis id `aramidmain-v1.0` (proto `aramidmain-v1.0/1`), genesis hash
  `PgeQVJJgx/LYKJfIEz7dbfNPuXmDyJ+O7FwQ4XL9tE8=`. Vendored genesis:
  `bin/algod-rust/genesis/aramidmain-genesis.json` (provenance in
  `aramidmain-genesis.README.md`).
- Custom consensus protocols `aramidmain-v1.0/1..3` exist only in the vendored
  `bin/algod-rust/consensus/aramidmain-consensus.json` (provenance README next
  to it). `load_consensus_table` / `install_consensus_for_network` merge them
  at startup for `node`, `participate`, `sync`, `replay` and `relay`; a
  `<data_dir>/consensus.json` is merged on top (DIV-006).
- REST: `https://algod.aramidmain.a-wallet.net` (go-algorand 4.7.3 build).
- Relay discovery: `DNSBootstrapID` `aramidmain.a-wallet.net`
  (`_algobootstrap._tcp.aramidmain.a-wallet.net` SRV -> `de-k4-s1.a-wallet.net:14161`,
  `fi-k1-s3.biatec.io:14160`). `--relay-addr`/`--peers` override.
- Catchup: no static catchpoint index; the public gateway does not serve the
  catchpoint file (`HEAD /v1/aramidmain-v1.0/ledger/<r>` -> 404), so give relays:

  ```
  algod-rust sync --network aramidmain --catchpoint <last-catchpoint from /v2/status> --follow     --catchpoint-peer-url http://de-k4-s1.a-wallet.net:14161     --catchpoint-peer-url http://fi-k1-s3.biatec.io:14160
  ```

- Docker image (issue #2075): `ghcr.io/xarmian/algod-rust:<tag>-aramidmain` embeds the
  genesis; the consensus protocols and DNS bootstrap come from the preset in the binary;
  fast catchup via the gateway's `last-catchpoint` and SRV-pinned relays. See
  `docs/DOCKER_MIGRATION.md` (incl. migration from `scholtz2/aramid-algo-node`).
- Nightly soak (issue #2073): `.github/workflows/aramidmain-node-soak.yml`
  (07:20 UTC daily, plus `workflow_dispatch`; staggered after the mainnet
  04:20 and voimain 05:40 soaks) calls the reusable `network-node-soak.yml`
  with the bundled `consensus_json`, SRV relay discovery and
  `probe_catchpoint_file: "true"` (relays de-k4-s1.a-wallet.net:14161 and
  fi-k1-s3.biatec.io:14160 both answered 200 for the catchpoint file on
  2026-10-26; the gateway answers 404). Block time ~3.0 s, so the 5 min halt
  threshold (~100 blocks) is unchanged. Halt issues carry the
  `aramidmain-soak` label and dedup only against it. Override the gateway
  with the `ARAMIDMAIN_ALGOD_URL` repo variable.
