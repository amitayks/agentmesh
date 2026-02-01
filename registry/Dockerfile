# AgentMesh Registry API
# Multi-stage build for minimal final image

FROM rust:1.83-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Create dummy source to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy actual source
COPY src ./src
COPY migrations ./migrations

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
