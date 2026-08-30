# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Stage 1: Build
FROM rust:1.93-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY bin/ bin/
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

# Final stage: keep `runtime` (the `follow` default) as the image a plain
# `docker build -f docker/Dockerfile .` produces. The `localnet` stage is opt-in
# via `--target localnet` (see docker-compose.localnet-rust.yml).
FROM runtime AS default
