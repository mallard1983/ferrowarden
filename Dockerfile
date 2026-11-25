# Dockerfile for Ferrowarden
#
# Multi-stage build: compile a statically linked musl binary in a Rust image,
# then ship it on `scratch`. The runtime image holds the binary, a two-line
# /etc/passwd and /etc/group for the fixed UID/GID 999, and an empty /data
# owned by that user. There is no shell, no package manager, no curl and no
# libc: a shell that is not there cannot be used. docs/deployment-profiles.md
# explains what that does and does not protect against.
#
# The base image is pinned by digest (the multi-arch index, so amd64 and arm64
# builds both work). Dependabot's docker ecosystem proposes updates.

# ── Build stage ──────────────────────────────────────────────────────────────
# rust:alpine's host target is x86_64/aarch64-unknown-linux-musl, which links
# statically by default. Everything in the crypto stack is ring-based, so the
# only native code is C compiled with the Alpine toolchain below.
FROM rust:1.100-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS builder

# A C compiler and the musl headers: ring compiles C and assembly.
RUN apk add --no-cache gcc musl-dev

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

# The few files the runtime image needs besides the binary. UID/GID are pinned
# to 999 (what --system assigned in earlier images, so existing volumes stay
# writable). The user has no home and no login shell.
RUN mkdir -p /rootfs/etc /rootfs/data \
    && echo 'ferrowarden:x:999:999:ferrowarden:/nonexistent:/sbin/nologin' > /rootfs/etc/passwd \
    && echo 'ferrowarden:x:999:' > /rootfs/etc/group


# ── Runtime stage ────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /rootfs/etc /etc

# Docker named volumes copy the image directory's ownership on first creation,
# so this empty, user-owned /data is what lets the ferrowarden user write the
# agent key file (and the optional event file) on the volume mounted there.
# It is the only directory in the image that is not root's.
COPY --from=builder --chown=999:999 /rootfs/data /data

# Static binary: no dynamic loader, no libc, no CA bundle (rustls embeds the
# webpki roots; an operator CA is mounted and named in the settings).
COPY --from=builder /build/target/release/ferrowarden /app/ferrowarden

# Everything else is configuration. On a Linux host, the files Compose mounts
# into this container (secrets/ferrowarden_admin_key,
# secrets/bw_master_password, certs/server.key) keep their host owner and
# mode, so they must be readable by UID 999 — see docs/setup.md.
#
# Secrets are read by the binary itself from the files that
# FERROWARDEN_ADMIN_KEY_FILE and the *_TOKEN_FILE variables name. They are
# never put in the process environment.
USER 999:999
WORKDIR /app

EXPOSE 3000

# `ferrowarden healthcheck` is the container health check (see the compose
# files): there is no curl here.
ENTRYPOINT ["/app/ferrowarden"]
