# Stage 1: Build
FROM rust:1.93-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY bin/ bin/
RUN cargo build --release --bin algod-rust

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl sqlite3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/algod-rust /usr/local/bin/algod-rust
WORKDIR /app
ENTRYPOINT ["algod-rust"]
CMD ["follow", "--algod-url", "http://algod-go:8080"]
