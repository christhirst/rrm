# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM rust:1-bookworm AS builder

WORKDIR /usr/src/rrm

# Copy manifests and build script first to cache dependency layer
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src

# Build release binary (uses protoc-bin-vendored so no external protoc needed)
RUN cargo build --release --locked || cargo build --release

# ============================================================================
# Stage 2: Runtime (Distroless)
# ============================================================================
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

WORKDIR /app

# Copy compiled binary, config, and proto with nonroot ownership
COPY --chown=nonroot:nonroot --from=builder /usr/src/rrm/target/release/rrm /app/rrm
COPY --chown=nonroot:nonroot config /app/config
COPY --chown=nonroot:nonroot proto /app/proto

USER nonroot:nonroot

EXPOSE 50051 8080
STOPSIGNAL SIGTERM

ENV RRM_SERVER__LISTEN_ADDR="0.0.0.0:50051"
ENV RRM_SERVER__HTTP_LISTEN_ADDR="0.0.0.0:8080"

ENTRYPOINT ["/app/rrm"]

