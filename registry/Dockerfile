# AgentMesh Registry API
# Multi-stage build for minimal final image

FROM rust:1.83-alpine AS builder

# Use SQLx offline mode - no database needed during build
ENV SQLX_OFFLINE=true

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Create dummy source to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Pin problematic crates to versions compatible with Rust 1.83 (avoid edition2024)
RUN cargo update base64ct --precise 1.6.0 2>/dev/null || true
RUN cargo update time --precise 0.3.36 2>/dev/null || true
RUN cargo update home --precise 0.5.9 2>/dev/null || true

RUN cargo build --release
RUN rm -rf src

# Copy actual source, migrations, and SQLx cache
COPY src ./src
COPY migrations ./migrations
COPY .sqlx ./.sqlx

# Build release binary
RUN touch src/main.rs && cargo build --release

# Final stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Copy binary and migrations from builder
COPY --from=builder /app/target/release/agentmesh-registry /app/registry
COPY --from=builder /app/migrations /app/migrations

# Create non-root user
RUN adduser -D -u 1000 agentmesh
USER agentmesh

# Expose HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget -q --spider http://localhost:8080/v1/health || exit 1

ENV RUST_LOG=agentmesh_registry=info,actix_web=info
ENV HOST=0.0.0.0
ENV PORT=8080

CMD ["/app/registry"]
