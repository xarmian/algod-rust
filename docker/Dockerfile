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
WORKDIR /app
ENTRYPOINT ["algod-rust"]
CMD ["follow", "--algod-url", "http://algod-go:8080"]

# Stage 3: Localnet dev node (TASK-268)
#
# A drop-in `algod-go` alternative: boots a single-node dev-mode network from a
# baked-in `genesis.json` (devmode:true) + a funded dev account, and serves the
# algod v2 REST API. Each submitted transaction group produces a block, so a
# fresh `up` is immediately ready for `goal -d <datadir> clerk send`.
#
# The data dir ships genesis.json / config.json / algod.token /
# algod.admin.token; the per-genesis ledger subdirectory is created on first
# boot by seeding genesis state, so the image carries no pre-built database.
FROM runtime AS localnet
COPY docker/localnet-rust/data/ /algod/data/
EXPOSE 8080
ENTRYPOINT ["algod-rust"]
CMD ["node", "start", "-d", "/algod/data", "--dev", "-l", "0.0.0.0:8080"]

# Final stage: keep `runtime` (the `follow` default) as the image a plain
# `docker build -f docker/Dockerfile .` produces. The `localnet` stage is opt-in
# via `--target localnet` (see docker-compose.localnet-rust.yml).
FROM runtime AS default
