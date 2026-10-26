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
| `DEV_MODE`, `NUM_ROUNDS`, a missing `NETWORK` (private network), `/etc/algorand/template.json`, `/etc/algorand/keys` | yes (the image's `template.json` and `devmode_template.json`, `goal network create/start` inside the container, wallets imported into kmd; relays are started first and write `algod-listen.net`, which wires the other nodes). `docker stop` stops the network cleanly (go just `tail -f`s `node.log`) |
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

## Published tags

The go-compatible image is published next to the `follow` image with go's tag
scheme and an `-algod` suffix: `latest-algod`, `stable-algod`, `5.0.4-stable-algod`
(the pinned go-algorand version), `beta-algod`, `nightly-algod`, and
`<X.Y.Z>-algod` for releases, on `ghcr.io/xarmian/algod-rust` (and Docker Hub when
configured). To switch from go, change `algorand/algod:5.0.4-stable` to
`ghcr.io/xarmian/algod-rust:5.0.4-stable-algod`.

## Network images: `-voimain` (issue #2074)

`ghcr.io/xarmian/algod-rust:<tag>-voimain` (`latest-voimain`, `stable-voimain`,
`5.0.4-stable-voimain`, `nightly-voimain`, ...; multi-arch, Docker Hub mirror when
configured) is the `algod` image with Voi mainnet baked in: `NETWORK=voimain`, the
vendored genesis (`voimain-v1.0`), `FAST_CATCHUP=1`. Same ports (8080 REST, 4160/4161
gossip, 7833 kmd) and environment variables as the `-algod` image:

```
docker run -d --name voi -p 8080:8080 -v voi-data:/algod/data   -e TOKEN=<token> ghcr.io/xarmian/algod-rust:latest-voimain
curl -H "X-Algo-API-Token: <token>" localhost:8080/v2/status
```

* Relays come from the preset's DNS bootstrap (`_algobootstrap._tcp.voimain.mainnet-voi.network`);
  `PEER_ADDRESS` is handed to `algod -p` and leaves the preset's bootstrap in place.
* The fast catchup needs a label, and Voi has no S3 index: the entrypoint reads
  `last-catchpoint` from `https://mainnet-api.voi.nodely.dev/v2/status`
  (`CATCHPOINT_STATUS_URL` overrides the gateway) and calls
  `goal node catchup --force --min ${CATCHUP_MIN:-1000000} <label>`; the file itself is
  downloaded from the relays the node discovered (only some Voi relays serve it; the
  node ranks the others down). `CATCHPOINT=<label>` pins a label, `FAST_CATCHUP=0`
  syncs block by block, and if the gateway advertises no label the node starts without a
  catchup (and says so).
* Mount `/algod/data` to keep the ledger. A restart asks for the catchup again, but the node
  only accepts it when it is more than `CATCHUP_MIN` rounds behind the label, so a ledger
  that is close to the head just resumes.
* The image is the `voimain` stage of `docker/Dockerfile` (3 lines on top of `algod`; the
  genesis is copied from `bin/algod-rust/genesis/`, so it cannot drift from the binary's).
  Another network image is one more stage, one `docker-image.yml` matrix row per job and
  an entry in `default_catchpoint_status_url` (`docker/algod/run.sh`).
* CI: the PR build runs `docker/scripts/network-image-smoke.sh <image> voimain-v1.0`
  (container up, `/health`, `/versions` `genesis_id=voimain-v1.0`, the round advances,
  `docker stop` is prompt) and writes the image size to the job summary.

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
