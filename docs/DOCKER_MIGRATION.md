# Switching from `algorand/algod` to the algod-rust image

The algod-rust `algod` image is built to be a drop-in for go-algorand's
`algorand/algod`: change the image name, keep everything else. This page lists
what is the same, what is not supported yet and the intentional differences.
It grows with the epic [#1989](https://github.com/xarmian/algod-rust/issues/1989);
the side-by-side parity test and the published tags are tracked in
[#1994](https://github.com/xarmian/algod-rust/issues/1994).

Build it with `docker build -f docker/Dockerfile --target algod .`.

## What is the same

| | algorand/algod | algod-rust `algod` image |
|---|---|---|
| data directory | `/algod/data` (`ALGORAND_DATA`) | same |
| REST API / kmd / gossip | 8080 / 7833 / `GOSSIP_PORT` | same (`EXPOSE 8080 7833 4160 4161`) |
| user | `algorand` (UID/GID 999); the entrypoint fixes the ownership of a mounted data directory, then drops root | same |
| commands on `PATH` | `algod goal kmd algokey algocfg diagcfg` | same names (Rust implementations) |
| override files | `/etc/algorand/{config.json,algod.token,algod.admin.token,logging.config,kmd_config.json}` | same |
| `docker exec <c> goal node status` | works | works; also `start`, `stop`, `restart`, `catchup`, `wait`, `pendingtxns`, `lastround`, `generatetoken` |

### Environment variables

| Variable | Supported |
|---|---|
| `NETWORK` (`mainnet`, `testnet`, `betanet`, `devnet`, `alphanet`, `fnet`) | yes; the genesis file is installed from the image |
| `GENESIS_ADDRESS` | yes (downloaded with `curl`) |
| `PEER_ADDRESS` | yes (`algod -p`, and the network's DNS bootstrap ID as in go) |
| `FAST_CATCHUP` | yes (`goal node catchup --force --min 1000000`) |
| `PROFILE` | yes (`algocfg profile set`) |
| `TOKEN`, `ADMIN_TOKEN` | yes |
| `GOSSIP_PORT` | yes (`NetAddress`, networking enabled, 1000 incoming connections) |
| `ALGOD_PORT` | yes (default 8080) |
| `START_KMD`, `KMD_TOKEN`, `KMD_PORT` | yes: `kmd-rust serve` on `0.0.0.0:${KMD_PORT}` with the same `kmd-v0.5` directory layout |
| `TELEMETRY_NAME`, `TELEMETRY_URL` | accepted and ignored: algod-rust has no telemetry (`diagcfg` is a no-op) |
| `DEV_MODE`, `NUM_ROUNDS`, a missing `NETWORK` (private network), `/etc/algorand/template.json`, `/etc/algorand/keys` | yes for single-node templates (the image's `template.json` and `devmode_template.json`, `goal network create/start` inside the container, wallets imported into kmd). **Multi-node templates are not supported yet**: starting them needs the relay listening address, tracked in [#2002](https://github.com/xarmian/algod-rust/issues/2002). `docker stop` stops the network cleanly (go just `tail -f`s `node.log`) |
| `DEBUG=1` | yes (`set -x`) |

## Intentional differences

* `algod` is `exec`ed by the entrypoint so that `docker stop`'s SIGTERM reaches
  it (go's script keeps bash as PID 1). The node shuts down on SIGTERM and
  removes `algod.pid`.
* The startup banner prints `Set` / `Not Set` for `TOKEN`, `ADMIN_TOKEN` and `KMD_TOKEN`
  instead of their values (go logs them in clear text; `docker logs` is routinely shipped).
* The entrypoint calls `algocfg set -p KEY -v VALUE -d DIR` (data directory
  last); the `algocfg` on `PATH` also accepts go's `algocfg -d DIR set ...`.
* `kmd` started as `kmd -d DIR` is translated to `kmd-rust serve -d DIR`.
* `NodeExporterPath` is not configured (algod-rust has no node exporter).
* `goal node pendingtxns` prints each transaction in the REST API's JSON form
  ([DIV-002](DIVERGENCES.md)).
* `goal node start|restart -H` (algoh) is rejected: there is no `algoh`.
* The data directory has no `consensus.json`, `goal.cache` or `logging.config`
  (no consensus overrides, no goal cache, no telemetry).
* `goal kmd start` right after `goal kmd stop` starts kmd and says
  `Successfully started kmd` (go's says `kmd is already running` because its new
  kmd loses a race against the exiting one).
* `goal node stop` in a `DEV_MODE` container stops the node (go's fails with
  `Cannot kill node: node was killed`).
* `FAST_CATCHUP=1` waits until the node answers (algod-rust resolves its peers before
  its REST API is up; go's answers at once) and retries a refused `goal node catchup`.
* Multi-node private-network templates are not supported yet
  ([#2002](https://github.com/xarmian/algod-rust/issues/2002)).

## Published tags

The go-compatible image is published next to the `follow` image with go's tag
scheme and an `-algod` suffix: `latest-algod`, `stable-algod`, `5.0.3-stable-algod`
(the pinned go-algorand version), `beta-algod`, `nightly-algod`, and
`<X.Y.Z>-algod` for releases, on `ghcr.io/xarmian/algod-rust` (and Docker Hub when
configured). To switch from go, change `algorand/algod:5.0.3-stable` to
`ghcr.io/xarmian/algod-rust:5.0.3-stable-algod`.

## Checking parity

`docker/scripts/algod-image-parity.sh <algod-rust-image> [go-image]` runs both
images side by side (`DEV_MODE=1`, `START_KMD=1`) and diffs the data layout,
`goal node/network status`, `goal account list`, the REST status shapes, the
lifecycle messages and `docker restart`/`docker stop` behaviour. The known
differences above live in `docker/scripts/algod-image-parity.known`; the
`Docker image parity vs algorand/algod` workflow runs it on every relevant PR
and nightly.

See [DIVERGENCES.md](DIVERGENCES.md) for the register of intended differences
and `docker/algod/run.sh` for the entrypoint itself.
