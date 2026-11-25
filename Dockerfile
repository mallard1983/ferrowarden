# Dockerfile for Ferrowarden
#
# Multi-stage build: compile in a full Rust image, run in a minimal Debian
# slim image. This keeps the final image small and reduces attack surface —
# the compiler, cargo, and all build tooling are absent at runtime.

# ── Build stage ──────────────────────────────────────────────────────────────
# Builder and runtime are pinned to the same Debian release (trixie) so the
# binary is never linked against a newer glibc than the runtime provides.
FROM rust:1.100-slim-trixie AS builder

WORKDIR /build

# Cache dependency compilation separately from application code.
# Cargo fetches and compiles dependencies on the first build; subsequent
# builds with only source changes skip this layer.
COPY Cargo.toml Cargo.lock ./
# The manifest also declares the ferrowarden-mcp binary (docs/mcp.md), so a
# stub for it must exist; only the proxy binary is built and shipped here.
RUN mkdir -p src/bin && echo "fn main() {}" > src/main.rs && echo "fn main() {}" > src/bin/ferrowarden-mcp.rs
RUN cargo build --release --bin ferrowarden
RUN rm -r src

# Build the actual application
COPY src ./src
# Admin UI page templates (compiled into the binary by askama).
COPY templates ./templates
# The OpenAPI description, embedded in the binary (include_str!) and served
# at GET /v1/openapi.json. Only this one file of docs/ is needed.
COPY docs/openapi.yaml ./docs/openapi.yaml
# Touch main.rs so cargo knows to recompile (the dummy above changed mtime)
RUN touch src/main.rs
RUN cargo build --release --bin ferrowarden


# ── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:trixie-slim

# Install only what is needed at runtime:
# - ca-certificates: TLS when ferrowarden makes outbound HTTPS calls
# - curl: Docker health check (GET /health)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user. The process has no need for elevated privileges.
# Create /data for the agent key file and own it before switching users —
# Docker named volumes copy the image directory's ownership on first creation,
# so this ensures the ferrowarden user can write to the volume mount.
#
# UID/GID are pinned to 999 (what --system assigned in earlier images, so
# existing volumes stay writable). On a Linux host, the files Compose mounts
# into this container (secrets/ferrowarden_admin_key,
# secrets/bw_master_password, certs/server.key) keep their host owner and
# mode, so they must be readable by UID 999 — see docs/setup.md.
RUN groupadd --system --gid 999 ferrowarden \
    && useradd --system --uid 999 --gid 999 --no-create-home --shell /bin/false ferrowarden \
    && mkdir /data \
    && chown ferrowarden:ferrowarden /data
USER ferrowarden

WORKDIR /app

COPY --from=builder /build/target/release/ferrowarden ./ferrowarden

# Docker secrets are mounted at /run/secrets/<name> by the runtime.
# The FERROWARDEN_ADMIN_KEY_FILE env var tells ferrowarden where to read
# the admin key — set it in docker-compose.yml or override here.
#
# We use a minimal entrypoint script to read Docker secrets into environment
# variables before exec-ing the binary, keeping secret values out of the
# process environment table where possible.
COPY docker/ferrowarden-entrypoint.sh /entrypoint.sh

EXPOSE 3000

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
