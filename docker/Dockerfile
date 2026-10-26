# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Stage 1: Build
FROM rust:1.93-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY bin/ bin/
# Short git ref this image is built from. `.git` isn't copied into the build
# context above, so a plain `git describe` inside the container always falls
# back to "unknown" (see crates/node/algo-rest-client/build.rs); the CI
# workflow (.github/workflows/docker-image.yml) computes this from the real
# checkout and passes it in, so `algod-rust`'s User-Agent header identifies
# the exact build a peer is talking to. Declared after the COPY layers above
# (rather than at the top of the stage) so a rebuild of the same source with
# a different GIT_TAG (e.g. a release tag pushed for an already-built main
# commit) only busts the compile layer below, not the — otherwise
# content-addressed and cacheable — COPY layers.
ARG GIT_TAG=unknown
ENV ALGO_BUILD_GIT_TAG=${GIT_TAG}
RUN cargo build --release --bin algod-rust

# Stage 2: Runtime (conformance / follow / relay / observe — the default)
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl sqlite3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/algod-rust /usr/local/bin/algod-rust
# glibc creates up to 8*ncores malloc arenas under multithreaded load
# (tokio workers + blocking pool); freed memory is retained per-arena, so
# RSS grows monotonically under sustained transaction load (issue #100
# measured ~10 MB/round on participation nodes, peaking ~1 GB where Go
# stays ~450 MB). Capping the arena count returns the node to Go-like
# resident behavior; it does not affect node semantics.
ENV MALLOC_ARENA_MAX=2
WORKDIR /app
ENTRYPOINT ["algod-rust"]
CMD ["follow", "--algod-url", "http://algod-go:8080"]

# Stage 3: Localnet dev node (TASK-268)
#
# A drop-in `algod-go` alternative: boots a single-node dev-mode network from a
# baked-in `genesis.json` (devmode:true) + a funded dev account, and serves the
# algod v2 REST API. Each submitted transaction group produces a block, so a
# fresh `up` is immediately ready to accept transactions over REST (e.g. from a
# host-side `goal` / `goal-rust` pointed at the published port). The image ships
# only the daemon, not a client.
#
# The data dir ships genesis.json / config.json / algod.token /
# algod.admin.token; the per-genesis ledger subdirectory is created on first
# boot by seeding genesis state, so the image carries no pre-built database.
FROM runtime AS localnet
COPY docker/localnet-rust/data/ /algod/data/
EXPOSE 8080
ENTRYPOINT ["algod-rust"]
# `node start` now genuinely parses /algod/data/config.json (issue #757:
# EndpointAddress, DNSBootstrapID, EnableDeveloperAPI). The explicit
# `-l 0.0.0.0:8080` / `--dev` flags below are kept as an override layered on
# top of it rather than removed, mirroring go-algorand's own
# CLI-flag-overrides-config-file precedent — they currently agree with the
# file's `EndpointAddress`/`EnableDeveloperAPI` values (pinned by
# bin/algod-rust/src/commands/node.rs's
# `resolve_listen_addr_matches_docker_config_when_no_cli_override` test), so
# either could be dropped without changing behavior, but keeping both makes
# the CLI invocation self-documenting without depending on the data dir's
# contents.
CMD ["node", "start", "-d", "/algod/data", "--dev", "-l", "0.0.0.0:8080"]

# Stage 4: the go-compatible `algod` image (issue #1991, epic #1989)
#
# A drop-in for `algorand/algod`: same environment variables (NETWORK, TOKEN,
# ADMIN_TOKEN, FAST_CATCHUP, PEER_ADDRESS, GOSSIP_PORT, START_KMD, ...), same
# `/etc/algorand` override files, same `/algod/data` data directory and ports
# (8080 REST, 7833 kmd, 4160/4161 gossip), the `algorand` user (UID/GID 999),
# and the same commands on PATH: `algod`, `goal`, `kmd`, `algokey`, `algocfg`,
# `diagcfg` -- so `docker exec <container> goal node status` works. The
# entrypoint is docker/algod/run.sh (see docs/DOCKER_MIGRATION.md).
#
# Opt-in via `--target algod`; the harness images keep using `runtime`.
FROM builder AS builder-tools
# the node, the CLI tools and kmd in one invocation so cargo unifies features
# once and reuses everything the `builder` stage already compiled
RUN cargo build --release --bin algod-rust --bin goal-rust --bin algokey-rust --bin kmd-rust

FROM debian:bookworm-slim AS algod
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl sqlite3 gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 999 algorand \
    && useradd -u 999 -g 999 -d /algod -s /bin/bash algorand \
    && mkdir -p /algod/data /node/bin /node/run/genesis \
    && chown -R algorand:algorand /algod
COPY --from=builder-tools /build/target/release/algod-rust /node/bin/algod-rust
COPY --from=builder-tools /build/target/release/goal-rust /node/bin/goal-rust
COPY --from=builder-tools /build/target/release/algokey-rust /node/bin/algokey-rust
COPY --from=builder-tools /build/target/release/kmd-rust /node/bin/kmd-rust
COPY docker/algod/bin/ /node/bin/
COPY docker/algod/genesis/ /node/run/genesis/
COPY docker/algod/run.sh /node/run/run.sh
COPY docker/algod/templates/ /node/run/
# (private networks: the entrypoint rewrites the template and copies keys here)
RUN chmod +x /node/bin/* /node/run/run.sh && chown -R algorand:algorand /node/run
ENV PATH=/node/bin:$PATH \
    ALGORAND_DATA=/algod/data \
    ALGOD_PORT=8080 \
    KMD_PORT=7833 \
    MALLOC_ARENA_MAX=2
WORKDIR /algod
EXPOSE 8080 7833 4160 4161
ENTRYPOINT ["/node/run/run.sh"]

# Stage 5: network images (issue #2074, epic #2068): `algod` with a public
# network baked in. The only per-network parts are NETWORK, the genesis file
# (copied from the vendored preset genesis, so the image can't drift from the
# binary's) and the entrypoint's per-network defaults (docker/algod/run.sh:
# `default_catchpoint_status_url`). A further network (aramidmain, #2075) is
# one more stage of the same three lines.
#
# `FAST_CATCHUP=1` is the default: Voi is >20M rounds, so a node that replays
# from genesis is not "ready to run". The label comes from the network's REST
# gateway (`last-catchpoint` of /v2/status; Voi has no S3 index), the file from
# the relays the node discovers through the preset's DNS bootstrap. Override
# with `-e FAST_CATCHUP=0`, `-e CATCHPOINT=<label>` or `-e PEER_ADDRESS=...`.
# Opt-in via `--target voimain`.
FROM algod AS voimain
COPY bin/algod-rust/genesis/voimain-genesis.json /node/run/genesis/voimain/genesis.json
ENV NETWORK=voimain
ENV FAST_CATCHUP=1

# Final stage: keep `runtime` (the `follow` default) as the image a plain
# `docker build -f docker/Dockerfile .` produces. The `localnet` stage is opt-in
# via `--target localnet` (see docker-compose.localnet-rust.yml).
FROM runtime AS default
