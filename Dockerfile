# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM rust:1-bookworm AS builder

WORKDIR /usr/src/rrm

# Copy manifests and build script first to cache dependency layer
COPY Cargo.toml build.rs ./
COPY proto ./proto
COPY src ./src

# Build release binary (uses protoc-bin-vendored so no external protoc needed)
RUN cargo build --release --locked || cargo build --release

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled binary and configuration directory
COPY --from=builder /usr/src/rrm/target/release/rrm /app/rrm
COPY config /app/config
COPY proto /app/proto

EXPOSE 50051

ENV RRM_SERVER__LISTEN_ADDR="0.0.0.0:50051"

ENTRYPOINT ["/app/rrm"]
